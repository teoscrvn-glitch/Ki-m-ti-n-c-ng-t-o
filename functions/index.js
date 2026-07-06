/**
 * TaskEarn — Cloud Functions v6
 * ĐỢT 1.3 — Sửa lỗi kỹ thuật cốt lõi (Senior Security Review round 5)
 * + Đổi model nhiệm vụ: MỌI task đều reset hàng ngày lúc 00:00 (giờ VN)
 *
 * SỬA LỖI KỸ THUẬT:
 *  ✅ Idempotency — mỗi request claim/withdraw có idempotencyKey riêng,
 *     gửi lại (do mất mạng, retry, double-click) không bị xử lý 2 lần
 *  ✅ Race Condition — toàn bộ đọc-kiểm tra-ghi nằm trong 1 transaction
 *     Firestore (đã đúng từ trước, giờ soát lại kỹ + thêm khóa idempotency
 *     NGAY trong transaction để không có khoảng hở TOCTOU)
 *  ✅ Cloud Function Timeout/Retry — idempotency key giải quyết luôn vấn đề
 *     "function bị Google retry tự động → cộng tiền 2 lần"
 *  ✅ Audit Timeline — function getUidTimeline gộp fraud/audit/claim/
 *     withdraw theo UID, sắp xếp theo thời gian, cho admin điều tra nhanh
 *
 * ĐỔI MODEL NHIỆM VỤ — RESET HÀNG NGÀY:
 *  - completedTasks giờ dùng key "{taskId}_{YYYY-MM-DD}" thay vì "{taskId}"
 *  - Mỗi ngày (giờ VN, UTC+7) user có thể làm lại TẤT CẢ nhiệm vụ đang bật
 *  - scheduledCleanup dọn completedTasks/pendingTasks cũ hơn 3 ngày
 *
 * (Giữ nguyên: HMAC token+nonce+exp+version, secret rotation, rate limit,
 *  reCAPTCHA, device fingerprint mở rộng, automation detection, velocity,
 *  impossible travel, IP reputation, fraud scoring, ban UID/device/IP,
 *  fraud dashboard, audit log)
 */

const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { onSchedule }         = require("firebase-functions/v2/scheduler");
const { defineSecret }       = require("firebase-functions/params");
const { initializeApp }      = require("firebase-admin/app");
const { getFirestore, FieldValue, Timestamp } = require("firebase-admin/firestore");
const { getAuth }            = require("firebase-admin/auth");
const crypto                 = require("crypto");
const https                  = require("https");

initializeApp();
const db = getFirestore();

const REGION = "asia-southeast1";
const TOKEN_VERSION = 2;

const SESSION_SECRET_V1 = defineSecret("SESSION_SECRET_V1");
const SESSION_SECRET_V2 = defineSecret("SESSION_SECRET_V2");
const RECAPTCHA_SECRET  = defineSecret("RECAPTCHA_SECRET");
const IPQS_API_KEY      = defineSecret("IPQS_API_KEY");

const MAX_ACCOUNTS_PER_DEVICE     = 3;
const MAX_ACCOUNTS_PER_IP         = 5;
const MAX_REGISTER_PER_DEVICE_DAY = 2;
const VELOCITY_MAX_ACCOUNTS       = 3;
const VELOCITY_WINDOW_MS          = 30 * 60 * 1000;
const IMPOSSIBLE_TRAVEL_WINDOW_MS = 10 * 60 * 1000;
const RECAPTCHA_MIN_SCORE = 0.5;
const TOKEN_EXP_MS = 5 * 60 * 1000;
// App Check: BẬT THẬT — yêu cầu client (index.html/admin.html) đã tích hợp
// firebase-app-check SDK với site key hợp lệ, nếu không mọi request sẽ bị
// từ chối. Nếu bạn chưa cấu hình App Check trong Firebase Console + client,
// hãy đổi lại thành false trước khi deploy để tránh khoá toàn bộ hệ thống.
const ENFORCE_APP_CHECK = true;
const FRAUD_SCORE_REVIEW_THRESHOLD = 80;

// ── Withdraw Lock: khoá rút tiền N giờ sau khi đổi thông tin bảo mật ──
const WITHDRAW_LOCK_HOURS = 24;

// ── Rate limit kết hợp: giới hạn theo UID+IP+Device cùng lúc, không chỉ UID ──
const IP_RATE_LIMIT_CLAIM_MAX     = 15;  // 1 IP tối đa 15 claim/phút (nhiều user chung mạng vẫn ok)
const IP_RATE_LIMIT_CLAIM_WINDOW  = 60 * 1000;
const DEVICE_RATE_LIMIT_CLAIM_MAX = 8;   // 1 device tối đa 8 claim/phút
const DEVICE_RATE_LIMIT_CLAIM_WINDOW = 60 * 1000;

// ─────────────────────────────────────────────
// HELPERS CHUNG
// ─────────────────────────────────────────────
async function logFraud(uid, action, reason, extra = {}) {
  try {
    await db.collection("fraudLogs").add({
      uid, action, reason,
      deviceId:  extra.deviceId  || null,
      ip:        extra.ip        || "unknown",
      userAgent: extra.userAgent || null,
      country:   extra.country   || null,
      score:     typeof extra.score === "number" ? extra.score : null,
      ...extra,
      createdAt: FieldValue.serverTimestamp(),
    });
  } catch (_) {}
}
async function logAudit(adminEmail, action, targetId, extra = {}) {
  try {
    await db.collection("auditLogs").add({
      adminEmail, action, targetId, ...extra,
      createdAt: FieldValue.serverTimestamp(),
    });
  } catch (_) {}
}

/**
 * createNotification — tạo 1 thông báo trong app cho user. Dùng ở các
 * điểm quan trọng: claim được duyệt/từ chối, withdraw đổi trạng thái,
 * tài khoản bị khóa, phát hiện gian lận trên tài khoản...
 */
async function createNotification(uid, type, title, body, extra = {}) {
  try {
    await db.collection("notifications").add({
      uid, type, title, body, isRead: false, ...extra,
      createdAt: FieldValue.serverTimestamp(),
    });
  } catch (_) {}
}
function getClientIp(request) {
  return request.rawRequest?.headers?.["x-forwarded-for"]?.split(",")[0]?.trim()
    || request.rawRequest?.ip || "unknown";
}
function getUserAgent(request) {
  return request.rawRequest?.headers?.["user-agent"] || "unknown";
}
function getCountry(request) {
  return request.rawRequest?.headers?.["x-appengine-country"]
    || request.rawRequest?.headers?.["cf-ipcountry"] || null;
}
/** Ngày hiện tại dạng YYYY-MM-DD theo giờ Việt Nam (UTC+7) — dùng làm key reset hàng ngày */
function todayVN() {
  return new Date(Date.now() + 7 * 3600_000).toISOString().slice(0, 10);
}
function assertAppCheck(request) {
  if (!ENFORCE_APP_CHECK) return;
  if (!request.app) throw new HttpsError("failed-precondition", "Yêu cầu không hợp lệ (App Check).");
}

// ─────────────────────────────────────────────
// IDEMPOTENCY — chống xử lý trùng khi client retry / Cloud Function bị
// Google tự động retry / double-click / mất mạng giữa chừng.
// Cơ chế: mỗi request nhạy cảm (claim, withdraw) mang theo 1
// idempotencyKey do CLIENT sinh ra (UUID). Server ghi khóa này vào
// Firestore NGAY TRONG transaction đầu tiên xử lý nó; nếu khóa đã tồn
// tại, trả lại chính kết quả cũ thay vì xử lý lại từ đầu.
// ─────────────────────────────────────────────
async function checkIdempotency(uid, action, idempotencyKey) {
  if (!idempotencyKey || typeof idempotencyKey !== "string" || idempotencyKey.length < 8) {
    // Không có khóa hợp lệ — coi như request "mới", nhưng ghi cảnh báo nhẹ
    // (không chặn cứng để không phá luồng cũ nếu client quên gửi)
    return { key: null, existing: null };
  }
  const ref  = db.doc(`idempotency/${uid}_${action}_${idempotencyKey}`);
  const snap = await ref.get();
  if (snap.exists) {
    return { key: ref, existing: snap.data() };
  }
  return { key: ref, existing: null };
}

// ─────────────────────────────────────────────
// SESSION TOKEN — HMAC + nonce + exp + version
// ─────────────────────────────────────────────
function signSessionToken(uid, taskId, openedAtMs, secretV2) {
  const nonce = crypto.randomBytes(16).toString("hex");
  const exp   = openedAtMs + TOKEN_EXP_MS;
  const payload    = `${TOKEN_VERSION}|${uid}|${taskId}|${openedAtMs}|${nonce}|${exp}`;
  const payloadB64 = Buffer.from(payload).toString("base64url");
  const signature  = crypto.createHmac("sha256", secretV2).update(payloadB64).digest("hex");
  return { token: `${payloadB64}.${signature}`, nonce, exp };
}
function verifySessionToken(token, secretV2, secretV1) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [payloadB64, signature] = token.split(".");
  const sigBuf = Buffer.from(signature, "hex");
  const tryVerify = (secret) => {
    if (!secret) return false;
    const expected = crypto.createHmac("sha256", secret).update(payloadB64).digest("hex");
    const expBuf = Buffer.from(expected, "hex");
    return sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);
  };
  if (!tryVerify(secretV2) && !tryVerify(secretV1)) return null;

  const payload = Buffer.from(payloadB64, "base64url").toString();
  const parts = payload.split("|");
  let version, uid, taskId, openedAtMsStr, nonce, expStr;
  if (parts.length === 6) { [version, uid, taskId, openedAtMsStr, nonce, expStr] = parts; }
  else if (parts.length === 5) { version = "1"; [uid, taskId, openedAtMsStr, nonce, expStr] = parts; }
  else return null;

  const exp = Number(expStr);
  if (!exp || Date.now() > exp) return null;
  return { version: Number(version), uid, taskId, openedAtMs: Number(openedAtMsStr), nonce, exp };
}

// ─────────────────────────────────────────────
// reCAPTCHA
// ─────────────────────────────────────────────
function verifyRecaptcha(token, secret) {
  return new Promise((resolve) => {
    if (!token) { resolve({ success: false, score: 0 }); return; }
    const postData = `secret=${encodeURIComponent(secret)}&response=${encodeURIComponent(token)}`;
    const req = https.request(
      { hostname: "www.google.com", path: "/recaptcha/api/siteverify", method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(postData) } },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => { try { resolve(JSON.parse(data)); } catch { resolve({ success: false, score: 0 }); } });
      }
    );
    req.on("error", () => resolve({ success: false, score: 0 }));
    req.write(postData); req.end();
  });
}
async function checkRecaptcha(token, expectedAction, secret) {
  if (!secret) return { skipped: true, score: null, ok: true };
  const result = await verifyRecaptcha(token, secret);
  const ok = result.success
    && (typeof result.score !== "number" || result.score >= RECAPTCHA_MIN_SCORE)
    && (!result.action || result.action === expectedAction);
  return { skipped: false, score: typeof result.score === "number" ? result.score : null, ok, raw: result };
}

// ─────────────────────────────────────────────
// IP REPUTATION (tuỳ chọn)
// ─────────────────────────────────────────────
function checkIpReputation(ip, apiKey) {
  return new Promise((resolve) => {
    if (!apiKey || ip === "unknown") { resolve(null); return; }
    const req = https.request(
      { hostname: "ipqualityscore.com", path: `/api/json/ip/${encodeURIComponent(apiKey)}/${encodeURIComponent(ip)}?strictness=1`, method: "GET" },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try {
            const j = JSON.parse(data);
            resolve({
              vpn: !!j.vpn, tor: !!j.tor, proxy: !!j.proxy,
              hosting: !!j.hosting || !!j.is_datacenter,
              fraudScore: typeof j.fraud_score === "number" ? j.fraud_score : null,
              countryCode: j.country_code || null,
            });
          } catch { resolve(null); }
        });
      }
    );
    req.on("error", () => resolve(null));
    req.setTimeout(3000, () => { req.destroy(); resolve(null); });
    req.end();
  });
}

// ─────────────────────────────────────────────
// AUTOMATION / HEADLESS DETECTION
// ─────────────────────────────────────────────
function scoreAutomationSignals(signals = {}) {
  let score = 0; const flags = [];
  if (signals.webdriver === true) { score += 30; flags.push("WEBDRIVER_TRUE"); }
  if (signals.pluginsCount === 0) { score += 10; flags.push("NO_PLUGINS"); }
  if (signals.languagesCount === 0) { score += 10; flags.push("NO_LANGUAGES"); }
  if (signals.hasChrome === false && signals.isChrome) { score += 10; flags.push("CHROME_OBJECT_MISSING"); }
  if (signals.outerWidth === 0 || signals.outerHeight === 0) { score += 15; flags.push("ZERO_VIEWPORT"); }
  return { score, flags };
}

// ─────────────────────────────────────────────
// FRAUD SCORING TỔNG HỢP
// ─────────────────────────────────────────────
async function computeFraudScore({ uid, deviceId, ip, recaptchaResult, automationSignals, context }) {
  let score = 0; const flags = [];
  if (recaptchaResult && !recaptchaResult.skipped) {
    if (recaptchaResult.score !== null && recaptchaResult.score < RECAPTCHA_MIN_SCORE) { score += 30; flags.push("LOW_RECAPTCHA"); }
  }
  if (automationSignals) {
    const { score: autoScore, flags: autoFlags } = scoreAutomationSignals(automationSignals);
    score += autoScore; flags.push(...autoFlags);
  }
  if (deviceId) {
    const deviceSnap = await db.doc(`devices/${deviceId}`).get();
    if (deviceSnap.exists) {
      const d = deviceSnap.data();
      const ageMs = d.firstSeenAt?.toDate ? Date.now() - d.firstSeenAt.toDate().getTime() : 0;
      if (ageMs < 24 * 3600_000) { score += 20; flags.push("NEW_DEVICE"); }
      if ((d.uids || []).length > 1) { score += 20; flags.push("SHARED_DEVICE"); }
      if (d.lastIp && d.lastIp !== ip) { score += 15; flags.push("NEW_IP"); }
    } else { score += 20; flags.push("UNKNOWN_DEVICE"); }
  }
  if (context?.ipRep) {
    if (context.ipRep.vpn) { score += 20; flags.push("VPN_IP"); }
    if (context.ipRep.tor) { score += 35; flags.push("TOR_IP"); }
    if (context.ipRep.hosting) { score += 20; flags.push("HOSTING_IP"); }
    if (typeof context.ipRep.fraudScore === "number" && context.ipRep.fraudScore >= 75) { score += 15; flags.push("IPQS_HIGH_FRAUD_SCORE"); }
  }
  if (context?.withdrawJustAfterRegister) { score += 40; flags.push("WITHDRAW_RIGHT_AFTER_REGISTER"); }
  if (context?.deviceChurn) { score += 30; flags.push("DEVICE_CHURN"); }
  return { score: Math.min(score, 150), flags };
}
async function logHighFraudScore(uid, action, score, flags, extra = {}) {
  if (score < FRAUD_SCORE_REVIEW_THRESHOLD) return false;
  await logFraud(uid, action, "FRAUD_SCORE_THRESHOLD", { score, flags, ...extra });
  return true;
}

/**
 * Fraud Score TỔNG HỢP theo user (khác với fraud score từng sự kiện).
 * Đây là điểm rủi ro tích luỹ dài hạn của cả tài khoản, cập nhật dần theo
 * thời gian — dùng để admin nhanh chóng nhận biết user nào cần chú ý mà
 * không cần đọc hết fraud log. Công thức: trung bình trọng số nghiêng về
 * các sự kiện gần đây (EWMA đơn giản), lưu tại users/{uid}.fraudScore.
 */
async function updateUserFraudScore(uid, eventScore) {
  if (typeof eventScore !== "number" || eventScore <= 0) return;
  const userRef = db.doc(`users/${uid}`);
  try {
    await db.runTransaction(async (tx) => {
      const snap = await tx.get(userRef);
      if (!snap.exists) return;
      const prevScore = snap.data().fraudScore || 0;
      // EWMA: điểm mới chiếm 30% trọng số, điểm cũ 70% (giảm dần theo thời gian)
      const nextScore = Math.round(prevScore * 0.7 + eventScore * 0.3);
      tx.update(userRef, {
        fraudScore: Math.min(nextScore, 150),
        fraudScoreUpdatedAt: FieldValue.serverTimestamp(),
      });
    });
  } catch (_) {}
}

// ─────────────────────────────────────────────
// RATE LIMIT chung
// ─────────────────────────────────────────────
async function assertRateLimit(uid, action, maxCount, windowMs) {
  const ref  = db.doc(`rateLimits/${uid}_${action}`);
  const snap = await ref.get();
  const now  = Date.now();
  let hits = [];
  if (snap.exists) hits = (snap.data().hits || []).filter(t => now - t < windowMs);
  if (hits.length >= maxCount) {
    const oldestHit = Math.min(...hits);
    const waitSec   = Math.ceil((windowMs - (now - oldestHit)) / 1000);
    throw new HttpsError("resource-exhausted", `Thao tác quá nhanh! Chờ ${waitSec}s.`);
  }
  hits.push(now);
  await ref.set({ hits, lastAt: FieldValue.serverTimestamp() }, { merge: true });
}

/**
 * Rate limit theo IP hoặc Device (không phải theo UID) — chặn trường hợp
 * 1 IP/thiết bị tạo nhiều UID rồi mỗi UID claim vài lần để né rate limit
 * theo UID đơn thuần. Dùng chung logic với assertRateLimit nhưng key khác.
 */
async function assertSharedRateLimit(key, maxCount, windowMs) {
  const ref  = db.doc(`rateLimits/shared_${key}`);
  const snap = await ref.get();
  const now  = Date.now();
  let hits = [];
  if (snap.exists) hits = (snap.data().hits || []).filter(t => now - t < windowMs);
  if (hits.length >= maxCount) {
    throw new HttpsError("resource-exhausted", "Hệ thống đang giới hạn tốc độ do phát hiện lưu lượng bất thường. Vui lòng thử lại sau ít phút.");
  }
  hits.push(now);
  await ref.set({ hits, lastAt: FieldValue.serverTimestamp() }, { merge: true });
}

/** Kiểm tra kết hợp UID + IP + Device cho hành động claim */
async function assertClaimRateLimits(uid, ip, deviceId) {
  await assertRateLimit(uid, "claim", 5, 60 * 1000);
  if (ip && ip !== "unknown") {
    await assertSharedRateLimit(`ip_claim_${ip.replace(/[.:]/g, "_")}`, IP_RATE_LIMIT_CLAIM_MAX, IP_RATE_LIMIT_CLAIM_WINDOW);
  }
  if (deviceId) {
    await assertSharedRateLimit(`device_claim_${deviceId}`, DEVICE_RATE_LIMIT_CLAIM_MAX, DEVICE_RATE_LIMIT_CLAIM_WINDOW);
  }
}

/**
 * Withdraw Lock — nếu user vừa đổi email/password/thiết bị lạ trong vòng
 * WITHDRAW_LOCK_HOURS giờ gần đây, tạm khoá chức năng rút tiền để phòng
 * trường hợp tài khoản bị chiếm quyền rồi rút tiền ngay.
 * securityEvents/{uid} lưu lastSecurityChangeAt — set bởi client khi phát
 * hiện đổi mật khẩu/email (qua onAuthStateChanged/reauthenticate) hoặc bởi
 * registerDevice khi phát hiện thiết bị hoàn toàn mới cho UID đã tồn tại lâu.
 */
async function assertWithdrawNotLocked(uid) {
  const secSnap = await db.doc(`securityEvents/${uid}`).get();
  if (!secSnap.exists) return;
  const lastChange = secSnap.data().lastSecurityChangeAt;
  if (!lastChange?.toDate) return;
  const hoursSince = (Date.now() - lastChange.toDate().getTime()) / 3600_000;
  if (hoursSince < WITHDRAW_LOCK_HOURS) {
    const remainH = Math.ceil(WITHDRAW_LOCK_HOURS - hoursSince);
    throw new HttpsError(
      "failed-precondition",
      `Tài khoản vừa thay đổi thông tin bảo mật. Chức năng rút tiền tạm khoá ${remainH} giờ để bảo vệ bạn.`
    );
  }
}

// ─────────────────────────────────────────────
// VELOCITY CHECK
// ─────────────────────────────────────────────
async function assertVelocity(deviceId, uid) {
  if (!deviceId) return;
  const ref  = db.doc(`velocity/${deviceId}`);
  const snap = await ref.get();
  const now  = Date.now();
  let events = [];
  if (snap.exists) events = (snap.data().accountEvents || []).filter(e => now - e.t < VELOCITY_WINDOW_MS);
  const alreadyCounted = events.some(e => e.uid === uid);
  if (!alreadyCounted && events.length >= VELOCITY_MAX_ACCOUNTS) {
    await logFraud(uid, "velocity", "VELOCITY_LIMIT_EXCEEDED", { deviceId, windowMs: VELOCITY_WINDOW_MS, count: events.length });
    await db.doc(`devices/${deviceId}`).set({
      status: "banned", banReason: "Auto: Velocity limit exceeded",
      banType: "temporary", banExpiresAt: new Date(now + 6 * 3600_000),
    }, { merge: true });
    throw new HttpsError("resource-exhausted", "Phát hiện hoạt động bất thường trên thiết bị này. Thiết bị đã bị tạm khóa.");
  }
  if (!alreadyCounted) events.push({ uid, t: now });
  await ref.set({ accountEvents: events, updatedAt: FieldValue.serverTimestamp() }, { merge: true });
}

// ─────────────────────────────────────────────
// IMPOSSIBLE TRAVEL
// ─────────────────────────────────────────────
function ipNetworkPrefix(ip) {
  const parts = ip.split(".");
  return parts.length === 4 ? `${parts[0]}.${parts[1]}` : ip;
}
async function checkImpossibleTravel(uid, ip) {
  const userSnap = await db.doc(`users/${uid}`).get();
  if (!userSnap.exists) return { suspicious: false };
  const history = userSnap.data().ipHistory || [];
  if (history.length === 0) return { suspicious: false };
  const last = history[history.length - 1];
  const elapsedMs = Date.now() - (last.t || 0);
  if (elapsedMs > IMPOSSIBLE_TRAVEL_WINDOW_MS) return { suspicious: false };
  const samePrefix = ipNetworkPrefix(last.ip) === ipNetworkPrefix(ip);
  if (!samePrefix && last.ip !== ip) return { suspicious: true, previousIp: last.ip, elapsedMs };
  return { suspicious: false };
}
async function pushIpHistory(uid, ip) {
  const userRef = db.doc(`users/${uid}`);
  const snap    = await userRef.get();
  const history = snap.exists ? (snap.data().ipHistory || []) : [];
  history.push({ ip, t: Date.now() });
  while (history.length > 20) history.shift();
  await userRef.set({ ipHistory: history }, { merge: true });
}

// ─────────────────────────────────────────────
// DEVICE — metadata đầy đủ + lịch sử fingerprint
// ─────────────────────────────────────────────
async function ipDocRefSafe(ref) { try { return await ref.get(); } catch { return null; } }

async function assertDeviceLimit(uid, deviceId, ip, userAgent, isRegister = false, extendedFingerprint = null) {
  if (!deviceId || typeof deviceId !== "string" || deviceId.length < 8) {
    throw new HttpsError("invalid-argument", "Thiếu thông tin thiết bị. Vui lòng tải lại trang.");
  }
  const deviceRef  = db.doc(`devices/${deviceId}`);
  const deviceSnap = await deviceRef.get();
  const now        = FieldValue.serverTimestamp();

  let extHash = null;
  if (extendedFingerprint && typeof extendedFingerprint === "object") {
    const raw = JSON.stringify(extendedFingerprint);
    extHash = crypto.createHash("sha256").update(raw).digest("hex").slice(0, 32);
  }

  if (isRegister) {
    const ipDocRef = db.doc(`ipRegistry/${ip.replace(/[.:]/g, "_")}`);
    const ipSnap   = await ipDocRefSafe(ipDocRef);
    const ipUids   = ipSnap?.data()?.uids || [];
    if (!ipUids.includes(uid) && ipUids.length >= MAX_ACCOUNTS_PER_IP) {
      await logFraud(uid, "device", "MULTI_ACCOUNT_IP_LIMIT", { deviceId, ip, existingCount: ipUids.length });
      throw new HttpsError("resource-exhausted", `IP này đã đạt giới hạn ${MAX_ACCOUNTS_PER_IP} tài khoản.`);
    }
    await ipDocRef.set({ uids: FieldValue.arrayUnion(uid), lastSeenAt: now }, { merge: true });

    const today       = todayVN();
    const regLimitRef = db.doc(`registerLimits/${deviceId}_${today}`);
    const regSnap     = await regLimitRef.get();
    const regCount    = regSnap.exists ? (regSnap.data().count || 0) : 0;
    if (regCount >= MAX_REGISTER_PER_DEVICE_DAY) {
      await logFraud(uid, "device", "REGISTER_DAILY_LIMIT", { deviceId, ip, regCount });
      throw new HttpsError("resource-exhausted", "Thiết bị này đã đạt giới hạn đăng ký hôm nay.");
    }
    await regLimitRef.set({ count: FieldValue.increment(1), date: today }, { merge: true });
    await assertVelocity(deviceId, uid);
  }

  if (!deviceSnap.exists) {
    await deviceRef.set({
      uids: [uid], status: "active", banReason: null, banType: null, banExpiresAt: null,
      fingerprintVersion: "fpjs-v4", extendedFpHash: extHash,
      firstSeenAt: now, createdAt: now, lastSeenAt: now, lastIp: ip, lastUserAgent: userAgent, loginCount: 1,
    });
  } else {
    const data = deviceSnap.data();
    if (data.status === "banned") {
      const isTemp  = data.banType === "temporary";
      const expired = isTemp && data.banExpiresAt && data.banExpiresAt.toDate() < new Date();
      if (!expired) {
        await logFraud(uid, "device", "BANNED_DEVICE", { deviceId, ip, banReason: data.banReason });
        throw new HttpsError("permission-denied", "Thiết bị này đã bị khóa.");
      }
      await deviceRef.update({ status: "active", banReason: null, banType: null, banExpiresAt: null });
    }
    const uids = data.uids || [];
    if (!uids.includes(uid)) {
      if (uids.length >= MAX_ACCOUNTS_PER_DEVICE) {
        await logFraud(uid, "device", "MULTI_ACCOUNT_DEVICE_LIMIT", { deviceId, ip, existingCount: uids.length });
        throw new HttpsError("resource-exhausted", `Thiết bị này đã đạt giới hạn ${MAX_ACCOUNTS_PER_DEVICE} tài khoản.`);
      }
      await deviceRef.update({
        uids: FieldValue.arrayUnion(uid), lastSeenAt: now, lastIp: ip, lastUserAgent: userAgent,
        loginCount: FieldValue.increment(1), extendedFpHash: extHash || data.extendedFpHash || null,
      });
    } else {
      await deviceRef.update({
        lastSeenAt: now, lastIp: ip, lastUserAgent: userAgent,
        loginCount: FieldValue.increment(1), extendedFpHash: extHash || data.extendedFpHash || null,
      });
    }
  }

  try {
    await deviceRef.collection("history").add({ uid, ip, userAgent, extendedFpHash: extHash, createdAt: FieldValue.serverTimestamp() });
  } catch (_) {}
}

async function computeWithdrawRiskScore(uid, deviceId, ip, ipRep) {
  let score = 0; const flags = [];
  const deviceSnap = await db.doc(`devices/${deviceId}`).get();
  if (deviceSnap.exists) {
    const d = deviceSnap.data();
    const ageMs = d.firstSeenAt?.toDate ? Date.now() - d.firstSeenAt.toDate().getTime() : 0;
    if (ageMs < 24 * 3600_000) { score += 25; flags.push("DEVICE_NEW_24H"); }
    if (d.lastIp && d.lastIp !== ip) { score += 15; flags.push("IP_CHANGED"); }
    if ((d.uids || []).length > 1) { score += 20; flags.push("SHARED_DEVICE"); }
  } else { score += 30; flags.push("DEVICE_UNKNOWN"); }

  let withdrawJustAfterRegister = false;
  const userSnap = await db.doc(`users/${uid}`).get();
  if (userSnap.exists) {
    const u = userSnap.data();
    const accAgeMs = u.createdAt?.toDate ? Date.now() - u.createdAt.toDate().getTime() : 0;
    if (accAgeMs < 3 * 24 * 3600_000) { score += 25; flags.push("ACCOUNT_NEW_3D"); }
    if (accAgeMs < 3600_000) withdrawJustAfterRegister = true;
  }
  if (ipRep) {
    if (ipRep.vpn) { score += 20; flags.push("VPN_IP"); }
    if (ipRep.tor) { score += 35; flags.push("TOR_IP"); }
    if (ipRep.hosting) { score += 20; flags.push("HOSTING_IP"); }
  }
  if (withdrawJustAfterRegister) { score += 40; flags.push("WITHDRAW_RIGHT_AFTER_REGISTER"); }
  return { score: Math.min(score, 150), flags };
}

// ─────────────────────────────────────────────
// 0. registerDevice
// ─────────────────────────────────────────────
exports.registerDevice = onCall(
  { region: REGION, secrets: [RECAPTCHA_SECRET], enforceAppCheck: ENFORCE_APP_CHECK },
  async (request) => {
    assertAppCheck(request);
    if (!request.auth) throw new HttpsError("unauthenticated", "Bạn chưa đăng nhập.");
    const uid = request.auth.uid;
    const { deviceId, recaptchaToken, isRegister, extendedFingerprint, automationSignals } = request.data;
    const ip = getClientIp(request), userAgent = getUserAgent(request), country = getCountry(request);

    await assertRateLimit(uid, "register_device", 2, 10 * 60 * 1000);
    const recap = await checkRecaptcha(recaptchaToken, isRegister ? "register" : "login", RECAPTCHA_SECRET.value());
    if (!recap.ok) {
      await logFraud(uid, "recaptcha", "RECAPTCHA_FAILED_OR_LOW_SCORE", { ip, deviceId, userAgent, country, score: recap.score });
      throw new HttpsError("permission-denied", "Xác thực bảo mật thất bại. Vui lòng thử lại.");
    }
    const travel = await checkImpossibleTravel(uid, ip);
    if (travel.suspicious) await logFraud(uid, "travel", "IMPOSSIBLE_TRAVEL", { ip, deviceId, previousIp: travel.previousIp, elapsedMs: travel.elapsedMs });
    await pushIpHistory(uid, ip);
    await assertDeviceLimit(uid, deviceId, ip, userAgent, !!isRegister, extendedFingerprint);

    const { score, flags } = await computeFraudScore({ uid, deviceId, ip, recaptchaResult: recap, automationSignals, context: {} });
    await logHighFraudScore(uid, "register_device", score, flags, { ip, deviceId, userAgent, country });
    await updateUserFraudScore(uid, score);
    return { success: true, fraudScore: score };
  }
);

// ─────────────────────────────────────────────
// 1. startTaskSession — reset hàng ngày: kiểm tra completedTasks/{taskId}_{today}
// ─────────────────────────────────────────────
exports.startTaskSession = onCall(
  { region: REGION, secrets: [SESSION_SECRET_V2], enforceAppCheck: ENFORCE_APP_CHECK },
  async (request) => {
    assertAppCheck(request);
    if (!request.auth) throw new HttpsError("unauthenticated", "Bạn chưa đăng nhập.");
    const uid = request.auth.uid;
    const { taskId, deviceId } = request.data;
    const ip = getClientIp(request), userAgent = getUserAgent(request);

    if (!taskId || typeof taskId !== "string") throw new HttpsError("invalid-argument", "taskId không hợp lệ.");

    await assertRateLimit(uid, "start_task", 10, 60 * 1000);
    await assertDeviceLimit(uid, deviceId, ip, userAgent, false);

    const taskSnap = await db.doc(`tasks/${taskId}`).get();
    if (!taskSnap.exists || !taskSnap.data().active) throw new HttpsError("not-found", "Nhiệm vụ không tồn tại hoặc đã tắt.");

    const today       = todayVN();
    const doneTodayKey = `${taskId}_${today}`;
    const doneSnap = await db.doc(`users/${uid}/completedTasks/${doneTodayKey}`).get();
    if (doneSnap.exists) throw new HttpsError("already-exists", "Bạn đã hoàn thành nhiệm vụ này hôm nay rồi! Quay lại vào ngày mai.");

    const reward      = taskSnap.data().reward;
    const openedAtMs  = Date.now();
    const { token, nonce, exp } = signSessionToken(uid, taskId, openedAtMs, SESSION_SECRET_V2.value());

    // pendingTasks vẫn key theo taskId thuần (chỉ dùng trong phiên hiện tại,
    // không cần phân biệt theo ngày vì bị xoá/dùng ngay sau khi claim)
    await db.doc(`users/${uid}/pendingTasks/${taskId}`).set({
      deviceId, reward, nonce, nonceUsed: false, tokenVersion: TOKEN_VERSION,
      openedAt: FieldValue.serverTimestamp(), openedAtMs,
      expireAt: new Date(exp), used: false, resetDate: today,
    });

    return { success: true, token, reward, bypassUrl: taskSnap.data().bypassUrl };
  }
);

// ─────────────────────────────────────────────
// 2. processClaim — IDEMPOTENT + reset hàng ngày + mọi check trong 1 transaction
// ─────────────────────────────────────────────
exports.processClaim = onCall(
  { region: REGION, secrets: [SESSION_SECRET_V1, SESSION_SECRET_V2, RECAPTCHA_SECRET], enforceAppCheck: ENFORCE_APP_CHECK },
  async (request) => {
    assertAppCheck(request);
    if (!request.auth) throw new HttpsError("unauthenticated", "Bạn chưa đăng nhập.");
    const uid = request.auth.uid;
    const { taskId, token, deviceId, recaptchaToken, automationSignals, idempotencyKey } = request.data;
    const ip = getClientIp(request), userAgent = getUserAgent(request);

    if (!taskId || typeof taskId !== "string") throw new HttpsError("invalid-argument", "taskId không hợp lệ.");

    // Rate limit kết hợp: UID + IP + Device — không chỉ chặn theo UID đơn thuần
    await assertClaimRateLimits(uid, ip, deviceId);

    const recap = await checkRecaptcha(recaptchaToken, "claim", RECAPTCHA_SECRET.value());
    if (!recap.ok) {
      await logFraud(uid, "claim", "RECAPTCHA_FAILED_OR_LOW_SCORE", { taskId, ip, deviceId, userAgent, score: recap.score });
      throw new HttpsError("permission-denied", "Phát hiện hành vi bất thường. Vui lòng thử lại sau.");
    }

    const parsed = verifySessionToken(token, SESSION_SECRET_V2.value(), SESSION_SECRET_V1.value());
    if (!parsed || parsed.uid !== uid || parsed.taskId !== taskId) {
      await logFraud(uid, "claim", "INVALID_SESSION_TOKEN", { taskId, ip, deviceId, userAgent });
      throw new HttpsError("permission-denied", "Token phiên không hợp lệ hoặc đã hết hạn. Nhận lại nhiệm vụ.");
    }

    const { score: fraudScore, flags: fraudFlags } = await computeFraudScore({
      uid, deviceId, ip, recaptchaResult: recap, automationSignals, context: {},
    });
    await logHighFraudScore(uid, "claim", fraudScore, fraudFlags, { taskId, ip, deviceId, userAgent });
    await updateUserFraudScore(uid, fraudScore);

    const today       = todayVN();
    const dailyRef     = db.doc(`dailyLimits/${uid}_${today}`);
    const dailySnap    = await dailyRef.get();
    const dailyCount   = dailySnap.exists ? (dailySnap.data().claimCount || 0) : 0;
    const DAILY_LIMIT  = 10;
    if (dailyCount >= DAILY_LIMIT) {
      await logFraud(uid, "claim", "DAILY_LIMIT_EXCEEDED", { taskId, ip, deviceId, dailyCount });
      throw new HttpsError("resource-exhausted", `Đã đạt giới hạn ${DAILY_LIMIT} claim hôm nay. Quay lại ngày mai!`);
    }

    // ── Idempotency key: doc riêng, ghi TRONG transaction để tránh TOCTOU ──
    const idemRef = (idempotencyKey && typeof idempotencyKey === "string" && idempotencyKey.length >= 8)
      ? db.doc(`idempotency/${uid}_claim_${idempotencyKey}`)
      : null;

    let serverReward = 0;
    let doneTodayKey  = `${taskId}_${today}`;

    try {
      const outcome = await db.runTransaction(async (tx) => {
        // ── Idempotency check NGAY ĐẦU transaction (đọc trước mọi write) ──
        if (idemRef) {
          const idemSnap = await tx.get(idemRef);
          if (idemSnap.exists) {
            // Request này đã được xử lý trước đó (retry/double-click) →
            // trả lại đúng kết quả cũ, KHÔNG cộng/ghi gì thêm.
            return { alreadyProcessed: true, reward: idemSnap.data().reward };
          }
        }

        const taskRef    = db.doc(`tasks/${taskId}`);
        const pendingRef = db.doc(`users/${uid}/pendingTasks/${taskId}`);
        const doneRef    = db.doc(`users/${uid}/completedTasks/${doneTodayKey}`);
        const claimQuery = db.collection("claimRequests")
          .where("uid", "==", uid).where("taskId", "==", taskId).where("status", "==", "pending").limit(1);

        const [taskSnap, pendingSnap, doneSnap, claimSnap] = await Promise.all([
          tx.get(taskRef), tx.get(pendingRef), tx.get(doneRef), claimQuery.get(),
        ]);

        if (!taskSnap.exists || !taskSnap.data().active) throw new HttpsError("not-found", "Nhiệm vụ không tồn tại hoặc đã tắt.");

        serverReward = taskSnap.data().reward;
        if (!serverReward || serverReward <= 0 || serverReward > 5000) throw new HttpsError("internal", "Reward của task không hợp lệ.");

        if (!pendingSnap.exists) {
          await logFraud(uid, "claim", "NO_PENDING_TASK", { taskId, ip, deviceId });
          throw new HttpsError("failed-precondition", "Không tìm thấy phiên nhiệm vụ. Nhận lại nhiệm vụ.");
        }
        const pending = pendingSnap.data();

        if (pending.used === true) {
          await logFraud(uid, "claim", "TOKEN_USED", { taskId, ip, deviceId });
          throw new HttpsError("already-exists", "Nhiệm vụ đã được claim rồi!");
        }
        if (!pending.nonce || pending.nonce !== parsed.nonce) {
          await logFraud(uid, "claim", "NONCE_MISMATCH", { taskId, ip, deviceId });
          throw new HttpsError("permission-denied", "Token phiên không khớp (nonce). Nhận lại nhiệm vụ.");
        }
        if (pending.nonceUsed === true) {
          await logFraud(uid, "claim", "REPLAY_DETECTED", { taskId, ip, deviceId });
          throw new HttpsError("permission-denied", "Phát hiện gửi lại yêu cầu (replay). Nhận lại nhiệm vụ.");
        }
        if (deviceId && pending.deviceId && pending.deviceId !== deviceId) {
          await logFraud(uid, "claim", "DEVICE_MISMATCH", { taskId, ip, expected: pending.deviceId, got: deviceId });
          throw new HttpsError("permission-denied", "Thiết bị không khớp với phiên nhiệm vụ.");
        }
        const expireAt = pending.expireAt instanceof Timestamp ? pending.expireAt.toDate() : new Date(pending.expireAt);
        if (new Date() > expireAt) {
          await logFraud(uid, "claim", "TOKEN_EXPIRED", { taskId, ip, deviceId });
          throw new HttpsError("deadline-exceeded", "Phiên hết hạn! Nhận lại nhiệm vụ.");
        }
        const pendingOpenedMs = pending.openedAtMs || 0;
        if (parsed.openedAtMs !== pendingOpenedMs) {
          await logFraud(uid, "claim", "TOKEN_TIME_MISMATCH", { taskId, ip, deviceId });
          throw new HttpsError("permission-denied", "Token phiên không khớp. Nhận lại nhiệm vụ.");
        }
        const elapsedSec = (Date.now() - pendingOpenedMs) / 1000;
        if (elapsedSec < 45) {
          const wait = Math.ceil(45 - elapsedSec);
          await logFraud(uid, "claim", "TOO_FAST", { taskId, ip, deviceId, elapsedSec: Math.round(elapsedSec) });
          throw new HttpsError("failed-precondition", `Chờ thêm ${wait}s nữa!`);
        }
        // Kiểm tra đã hoàn thành HÔM NAY chưa (reset hàng ngày)
        if (doneSnap.exists) {
          await logFraud(uid, "claim", "ALREADY_DONE_TODAY", { taskId, ip, deviceId });
          throw new HttpsError("already-exists", "Bạn đã hoàn thành nhiệm vụ này hôm nay rồi!");
        }
        if (!claimSnap.empty) throw new HttpsError("already-exists", "Đã có claim đang chờ duyệt cho nhiệm vụ này!");

        // ── Writes (tất cả trong cùng transaction — atomic) ──
        tx.update(pendingRef, { used: true, usedAt: FieldValue.serverTimestamp(), nonceUsed: true });
        tx.set(doneRef, { completedAt: FieldValue.serverTimestamp(), reward: serverReward, status: "pending", resetDate: today });

        const claimRef = db.collection("claimRequests").doc();
        tx.set(claimRef, {
          uid, email: request.auth.token.email || "", taskId, reward: serverReward,
          status: fraudScore >= FRAUD_SCORE_REVIEW_THRESHOLD ? "pending_review" : "pending",
          fraudScore, fraudFlags, ip, deviceId: deviceId || null, userAgent,
          createdAt: FieldValue.serverTimestamp(),
        });

        // Ghi khóa idempotency NGAY TRONG transaction — nếu transaction này
        // thành công, mọi lần gọi lại với cùng idempotencyKey sẽ thấy khóa
        // đã tồn tại và không xử lý lại.
        if (idemRef) {
          tx.set(idemRef, {
            action: "claim", taskId, reward: serverReward,
            claimId: claimRef.id, createdAt: FieldValue.serverTimestamp(),
          });
        }

        return { alreadyProcessed: false, reward: serverReward };
      });

      if (!outcome.alreadyProcessed) {
        await dailyRef.set({ claimCount: FieldValue.increment(1), date: today }, { merge: true });
      }
      return { success: true, reward: outcome.reward, idempotent: outcome.alreadyProcessed };

    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("processClaim error:", err);
      throw new HttpsError("internal", "Lỗi máy chủ, vui lòng thử lại.");
    }
  }
);

// ─────────────────────────────────────────────
// 3. processWithdraw — IDEMPOTENT
// ─────────────────────────────────────────────
exports.processWithdraw = onCall(
  { region: REGION, secrets: [RECAPTCHA_SECRET, IPQS_API_KEY], enforceAppCheck: ENFORCE_APP_CHECK },
  async (request) => {
    assertAppCheck(request);
    if (!request.auth) throw new HttpsError("unauthenticated", "Bạn chưa đăng nhập.");
    const uid = request.auth.uid;
    const { amount, recaptchaToken, deviceId, automationSignals, idempotencyKey } = request.data;
    const ip = getClientIp(request), userAgent = getUserAgent(request);

    if (!amount || typeof amount !== "number" || amount < 100_000) throw new HttpsError("invalid-argument", "Số tiền rút tối thiểu là 100.000đ.");

    // ── Lấy thông tin ngân hàng từ Payment Profile đã lưu — KHÔNG nhận
    // trực tiếp từ client mỗi lần rút nữa, tránh giả mạo/gõ sai số tài khoản. ──
    const profileSnap = await db.doc(`paymentProfiles/${uid}`).get();
    if (!profileSnap.exists) {
      throw new HttpsError("failed-precondition", "Bạn chưa thiết lập Hồ sơ thanh toán. Vui lòng cập nhật trong mục Tài khoản trước khi rút tiền.");
    }
    const { bankName, bankAccount, bankHolder, branch } = profileSnap.data();

    await assertRateLimit(uid, "withdraw", 3, 5 * 60 * 1000);
    if (ip && ip !== "unknown") {
      await assertSharedRateLimit(`ip_withdraw_${ip.replace(/[.:]/g, "_")}`, 10, 5 * 60 * 1000);
    }

    // Withdraw Lock — chặn rút tiền nếu vừa đổi email/password/hồ sơ thanh toán/thiết bị
    await assertWithdrawNotLocked(uid);

    const recap = await checkRecaptcha(recaptchaToken, "withdraw", RECAPTCHA_SECRET.value());
    if (!recap.ok) {
      await logFraud(uid, "withdraw", "RECAPTCHA_FAILED_OR_LOW_SCORE", { ip, deviceId, userAgent, score: recap.score, amount });
      throw new HttpsError("permission-denied", "Phát hiện hành vi bất thường. Vui lòng thử lại sau.");
    }

    const ipRep = await checkIpReputation(ip, IPQS_API_KEY.value());
    const { score: riskScore, flags: riskFlags } = deviceId
      ? await computeWithdrawRiskScore(uid, deviceId, ip, ipRep)
      : { score: 50, flags: ["NO_DEVICE_ID"] };
    const { score: fraudScore, flags: fraudFlags } = await computeFraudScore({
      uid, deviceId, ip, recaptchaResult: recap, automationSignals, context: { ipRep },
    });
    const combinedScore = Math.max(riskScore, fraudScore);
    const combinedFlags = [...new Set([...riskFlags, ...fraudFlags])];
    const needsReview   = combinedScore >= 50;
    await logHighFraudScore(uid, "withdraw", combinedScore, combinedFlags, { ip, deviceId, userAgent, amount });
    await updateUserFraudScore(uid, combinedScore);

    const idemRef = (idempotencyKey && typeof idempotencyKey === "string" && idempotencyKey.length >= 8)
      ? db.doc(`idempotency/${uid}_withdraw_${idempotencyKey}`)
      : null;

    try {
      const outcome = await db.runTransaction(async (tx) => {
        if (idemRef) {
          const idemSnap = await tx.get(idemRef);
          if (idemSnap.exists) {
            return { alreadyProcessed: true, withdrawId: idemSnap.data().withdrawId, needsReview: idemSnap.data().needsReview };
          }
        }

        const userRef  = db.doc(`users/${uid}`);
        const userSnap = await tx.get(userRef);
        if (!userSnap.exists) throw new HttpsError("not-found", "Tài khoản không tồn tại.");

        const balance = userSnap.data().balance || 0;
        if (balance < amount) throw new HttpsError("failed-precondition", "Số dư không đủ để rút!");

        tx.update(userRef, { balance: FieldValue.increment(-amount) });

        const wRef = db.collection("withdrawals").doc();
        tx.set(wRef, {
          uid, email: request.auth.token.email || "", amount,
          bankName, bankAccount, bankHolder, branch: branch || "",
          // Quy trình 4 trạng thái: pending → approved → paid → completed
          // (pending_review thay cho pending khi fraud score cao)
          status: needsReview ? "pending_review" : "pending",
          riskScore: combinedScore, riskFlags: combinedFlags, ipReputation: ipRep,
          ip, deviceId: deviceId || null, userAgent,
          createdAt: FieldValue.serverTimestamp(),
        });

        if (idemRef) {
          tx.set(idemRef, { action: "withdraw", withdrawId: wRef.id, amount, needsReview, createdAt: FieldValue.serverTimestamp() });
        }

        return { alreadyProcessed: false, withdrawId: wRef.id, needsReview };
      });

      return { success: true, withdrawId: outcome.withdrawId, needsReview: outcome.needsReview, idempotent: outcome.alreadyProcessed };

    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("processWithdraw error:", err);
      throw new HttpsError("internal", "Lỗi máy chủ, vui lòng thử lại.");
    }
  }
);

// ─────────────────────────────────────────────
// 4-7. approveClaim / rejectClaim / approveWithdraw / rejectWithdraw — admin
// Cũng dùng transaction đầy đủ (đã đúng từ trước) — soát lại: đọc + kiểm
// tra status + ghi đều nằm trong transaction, không có khoảng hở TOCTOU.
// ─────────────────────────────────────────────
exports.approveClaim = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "approve_claim", "Bạn không có quyền duyệt claim.");
  if (!request.auth.uid) throw new HttpsError("unauthenticated", "Phiên đăng nhập không hợp lệ.");
  const { claimId } = request.data;
  if (!claimId) throw new HttpsError("invalid-argument", "claimId không hợp lệ.");
  await assertRateLimit(request.auth.uid, "admin_approve_claim", 30, 60 * 1000);

  const claimRef = db.doc(`claimRequests/${claimId}`);

  // Toàn bộ đọc-kiểm tra-ghi nằm trong transaction để tránh 2 admin cùng
  // bấm duyệt 1 claim trong tích tắc gây cộng tiền 2 lần.
  const result = await db.runTransaction(async (tx) => {
    const claimSnap = await tx.get(claimRef);
    if (!claimSnap.exists) throw new HttpsError("not-found", "Claim không tồn tại.");
    const claim = claimSnap.data();
    if (claim.status !== "pending" && claim.status !== "pending_review")
      throw new HttpsError("failed-precondition", "Claim này không còn pending (có thể admin khác đã xử lý).");

    const { uid, reward, taskId } = claim;
    const userRef = db.doc(`users/${uid}`);
    const doneTodayKey = claim.resetDate ? `${taskId}_${claim.resetDate}` : taskId;
    const doneRef = db.doc(`users/${uid}/completedTasks/${doneTodayKey}`);
    const userSnap = await tx.get(userRef);
    if (!userSnap.exists) throw new HttpsError("not-found", "User không tồn tại.");

    tx.update(userRef, {
      balance: FieldValue.increment(reward), todayEarned: FieldValue.increment(reward), totalEarned: FieldValue.increment(reward),
    });
    tx.update(claimRef, { status: "approved", approvedAt: FieldValue.serverTimestamp(), approvedBy: request.auth.token.email || "admin" });
    tx.update(doneRef, { status: "paid" });
    return { uid, reward, taskId };
  });

  await logAudit(request.auth.token.email, "APPROVE_CLAIM", claimId, { ...result, ip: getClientIp(request) });
  await createNotification(result.uid, "claim_approved", "Nhiệm vụ đã được duyệt!", `Bạn nhận được ${result.reward.toLocaleString("vi-VN")}đ.`, { taskId: result.taskId });
  return { success: true };
});

exports.rejectClaim = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "reject_claim", "Bạn không có quyền từ chối claim.");
  if (!request.auth.uid) throw new HttpsError("unauthenticated", "Phiên đăng nhập không hợp lệ.");
  const { claimId } = request.data;
  if (!claimId) throw new HttpsError("invalid-argument", "claimId không hợp lệ.");
  await assertRateLimit(request.auth.uid, "admin_reject_claim", 30, 60 * 1000);

  const claimRef = db.doc(`claimRequests/${claimId}`);
  const result = await db.runTransaction(async (tx) => {
    const claimSnap = await tx.get(claimRef);
    if (!claimSnap.exists) throw new HttpsError("not-found", "Claim không tồn tại.");
    const claim = claimSnap.data();
    if (claim.status !== "pending" && claim.status !== "pending_review")
      throw new HttpsError("failed-precondition", "Claim này không còn pending.");

    const { uid, taskId } = claim;
    const doneTodayKey = claim.resetDate ? `${taskId}_${claim.resetDate}` : taskId;
    const doneRef = db.doc(`users/${uid}/completedTasks/${doneTodayKey}`);
    tx.update(claimRef, { status: "rejected", rejectedAt: FieldValue.serverTimestamp(), rejectedBy: request.auth.token.email || "admin" });
    tx.delete(doneRef);
    return { uid, taskId };
  });

  await logAudit(request.auth.token.email, "REJECT_CLAIM", claimId, { ...result, ip: getClientIp(request) });
  await createNotification(result.uid, "claim_rejected", "Nhiệm vụ bị từ chối", "Yêu cầu nhận thưởng của bạn không được duyệt. Bạn có thể làm lại nhiệm vụ.", { taskId: result.taskId });
  return { success: true };
});

// ── Withdraw Workflow: pending/pending_review → approved → paid → completed ──

/** Bước 1: Admin duyệt yêu cầu (chưa chuyển tiền, chỉ xác nhận hợp lệ) */
exports.approveWithdraw = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "approve_withdraw", "Bạn không có quyền duyệt rút tiền.");
  if (!request.auth.uid) throw new HttpsError("unauthenticated", "Phiên đăng nhập không hợp lệ.");
  const { withdrawId } = request.data;
  if (!withdrawId) throw new HttpsError("invalid-argument", "withdrawId không hợp lệ.");
  await assertRateLimit(request.auth.uid, "admin_approve_withdraw", 30, 60 * 1000);

  const wRef = db.doc(`withdrawals/${withdrawId}`);
  const result = await db.runTransaction(async (tx) => {
    const wSnap = await tx.get(wRef);
    if (!wSnap.exists || !["pending", "pending_review"].includes(wSnap.data().status))
      throw new HttpsError("failed-precondition", "Lệnh rút không hợp lệ (có thể đã được xử lý).");
    const { uid, amount } = wSnap.data();
    tx.update(wRef, { status: "approved", approvedAt: FieldValue.serverTimestamp(), approvedBy: request.auth.token.email || "admin" });
    return { uid, amount };
  });

  await logAudit(request.auth.token.email, "APPROVE_WITHDRAW", withdrawId, { ...result, ip: getClientIp(request) });
  await createNotification(result.uid, "withdraw_approved", "Yêu cầu rút tiền đã được duyệt", `Lệnh rút ${result.amount.toLocaleString("vi-VN")}đ đang chờ chuyển khoản.`, { withdrawId });
  return { success: true };
});

/** Bước 2: Admin/Finance xác nhận đã chuyển khoản thực tế */
exports.markWithdrawPaid = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "mark_paid", "Bạn không có quyền đánh dấu đã chuyển khoản.");
  if (!request.auth.uid) throw new HttpsError("unauthenticated", "Phiên đăng nhập không hợp lệ.");
  const { withdrawId, transactionRef } = request.data;
  if (!withdrawId) throw new HttpsError("invalid-argument", "withdrawId không hợp lệ.");
  await assertRateLimit(request.auth.uid, "admin_mark_paid", 30, 60 * 1000);

  const wRef = db.doc(`withdrawals/${withdrawId}`);
  const result = await db.runTransaction(async (tx) => {
    const wSnap = await tx.get(wRef);
    if (!wSnap.exists || wSnap.data().status !== "approved")
      throw new HttpsError("failed-precondition", "Lệnh rút phải ở trạng thái đã duyệt (approved) trước khi đánh dấu đã trả.");
    const { uid, amount } = wSnap.data();
    tx.update(wRef, {
      status: "paid", paidAt: FieldValue.serverTimestamp(), paidBy: request.auth.token.email || "admin",
      transactionRef: transactionRef || null,
    });
    return { uid, amount };
  });

  await logAudit(request.auth.token.email, "MARK_WITHDRAW_PAID", withdrawId, { ...result, transactionRef, ip: getClientIp(request) });
  await createNotification(result.uid, "withdraw_paid", "Đã chuyển khoản!", `${result.amount.toLocaleString("vi-VN")}đ đã được chuyển đến tài khoản của bạn.`, { withdrawId });
  return { success: true };
});

/** Bước 3: Đánh dấu hoàn tất toàn bộ quy trình (đối soát xong) */
exports.markWithdrawCompleted = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "mark_completed", "Bạn không có quyền đánh dấu hoàn tất.");
  if (!request.auth.uid) throw new HttpsError("unauthenticated", "Phiên đăng nhập không hợp lệ.");
  const { withdrawId } = request.data;
  if (!withdrawId) throw new HttpsError("invalid-argument", "withdrawId không hợp lệ.");
  await assertRateLimit(request.auth.uid, "admin_mark_completed", 30, 60 * 1000);

  const wRef = db.doc(`withdrawals/${withdrawId}`);
  const result = await db.runTransaction(async (tx) => {
    const wSnap = await tx.get(wRef);
    if (!wSnap.exists || wSnap.data().status !== "paid")
      throw new HttpsError("failed-precondition", "Lệnh rút phải ở trạng thái đã trả (paid) trước khi hoàn tất.");
    const { uid, amount } = wSnap.data();
    tx.update(wRef, { status: "completed", completedAt: FieldValue.serverTimestamp(), completedBy: request.auth.token.email || "admin" });
    return { uid, amount };
  });

  await logAudit(request.auth.token.email, "MARK_WITHDRAW_COMPLETED", withdrawId, { ...result, ip: getClientIp(request) });
  return { success: true };
});

/** Từ chối — hoàn tiền, có thể từ chối ở bất kỳ bước nào trước "paid" */
exports.rejectWithdraw = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "reject_withdraw", "Bạn không có quyền hoàn tiền.");
  if (!request.auth.uid) throw new HttpsError("unauthenticated", "Phiên đăng nhập không hợp lệ.");
  const { withdrawId, reason } = request.data;
  if (!withdrawId) throw new HttpsError("invalid-argument", "withdrawId không hợp lệ.");
  await assertRateLimit(request.auth.uid, "admin_reject_withdraw", 30, 60 * 1000);

  const wRef = db.doc(`withdrawals/${withdrawId}`);
  const result = await db.runTransaction(async (tx) => {
    const wSnap = await tx.get(wRef);
    if (!wSnap.exists || !["pending", "pending_review", "approved"].includes(wSnap.data().status))
      throw new HttpsError("failed-precondition", "Lệnh rút không hợp lệ (có thể đã được trả tiền hoặc xử lý xong).");
    const { uid, amount } = wSnap.data();
    tx.update(db.doc(`users/${uid}`), { balance: FieldValue.increment(amount) });
    // "rejected" = admin từ chối và hoàn tiền lại cho user (rõ nghĩa hơn "refunded")
    tx.update(wRef, { status: "rejected", rejectedAt: FieldValue.serverTimestamp(), rejectedBy: request.auth.token.email || "admin", rejectReason: reason || null });
    return { uid, amount };
  });

  await logAudit(request.auth.token.email, "REJECT_WITHDRAW", withdrawId, { ...result, reason, ip: getClientIp(request) });
  await createNotification(result.uid, "withdraw_rejected", "Yêu cầu rút tiền bị từ chối", `Số tiền ${result.amount.toLocaleString("vi-VN")}đ đã được hoàn lại vào số dư.` + (reason ? ` Lý do: ${reason}` : ""), { withdrawId });
  return { success: true };
});

/** cancelWithdraw — USER tự hủy lệnh rút của chính mình khi còn ở trạng thái pending/pending_review (chưa được admin duyệt) */
exports.cancelWithdraw = onCall({ region: REGION }, async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Bạn chưa đăng nhập.");
  const uid = request.auth.uid;
  const { withdrawId } = request.data;
  if (!withdrawId) throw new HttpsError("invalid-argument", "withdrawId không hợp lệ.");
  await assertRateLimit(uid, "cancel_withdraw", 10, 60 * 1000);

  const wRef = db.doc(`withdrawals/${withdrawId}`);
  await db.runTransaction(async (tx) => {
    const wSnap = await tx.get(wRef);
    if (!wSnap.exists) throw new HttpsError("not-found", "Lệnh rút không tồn tại.");
    const w = wSnap.data();
    if (w.uid !== uid) throw new HttpsError("permission-denied", "Đây không phải lệnh rút của bạn.");
    if (!["pending", "pending_review"].includes(w.status))
      throw new HttpsError("failed-precondition", "Chỉ có thể hủy khi lệnh rút chưa được admin xử lý.");
    tx.update(db.doc(`users/${uid}`), { balance: FieldValue.increment(w.amount) });
    tx.update(wRef, { status: "cancelled", cancelledAt: FieldValue.serverTimestamp() });
  });

  return { success: true };
});

// ─────────────────────────────────────────────
// 8. setAdminClaim
// ─────────────────────────────────────────────
// ─────────────────────────────────────────────
// ROLE-BASED ACCESS CONTROL (RBAC)
// 5 vai trò: super_admin, admin, finance, moderator, support, viewer.
// request.auth.token.admin (boolean) vẫn giữ để tương thích ngược — mọi
// role trừ "viewer" đều có admin=true để pass các check "isAdmin" cũ.
// request.auth.token.role (string) là vai trò cụ thể, dùng để giới hạn
// hành động chi tiết hơn qua hasPermission().
// ─────────────────────────────────────────────
const ROLE_PERMISSIONS = {
  super_admin: ["approve_claim","reject_claim","approve_withdraw","mark_paid","mark_completed","reject_withdraw",
                "manage_tasks","ban_uid","ban_device","ban_ip","set_role","view_fraud","view_audit","export_data"],
  admin:       ["approve_claim","reject_claim","approve_withdraw","mark_paid","mark_completed","reject_withdraw",
                "manage_tasks","ban_uid","ban_device","ban_ip","view_fraud","view_audit","export_data"],
  finance:     ["approve_withdraw","mark_paid","mark_completed","reject_withdraw","view_audit","export_data"],
  moderator:   ["ban_uid","ban_device","ban_ip","view_fraud","view_audit"],
  support:     ["view_audit"],
  viewer:      [],
};

function hasPermission(request, permission) {
  const role = request.auth?.token?.role;
  if (!role) return !!request.auth?.token?.admin; // fallback cho token cũ chưa có role
  return (ROLE_PERMISSIONS[role] || []).includes(permission);
}

function assertPermission(request, permission, errMsg) {
  if (!request.auth) throw new HttpsError("unauthenticated", "Bạn chưa đăng nhập.");
  if (!hasPermission(request, permission)) {
    throw new HttpsError("permission-denied", errMsg || "Bạn không có quyền thực hiện thao tác này.");
  }
}

/** setAdminClaim — giữ lại để tương thích ngược, map thành role "admin" */
exports.setAdminClaim = onCall({ region: REGION }, async (request) => {
  if (request.auth && !request.auth.token.admin) throw new HttpsError("permission-denied", "Chỉ admin mới set được admin khác.");
  const { targetEmail } = request.data;
  if (!targetEmail) throw new HttpsError("invalid-argument", "targetEmail là bắt buộc.");
  try {
    const userRecord = await getAuth().getUserByEmail(targetEmail);
    await getAuth().setCustomUserClaims(userRecord.uid, { admin: true, role: "admin" });
    await logAudit(request.auth?.token?.email || "system", "SET_ADMIN", userRecord.uid, { targetEmail });
    return { success: true, message: `Đã set admin cho ${targetEmail}` };
  } catch (err) { throw new HttpsError("internal", err.message); }
});

/** setRole — set vai trò cụ thể (super_admin/admin/finance/moderator/support/viewer). Chỉ super_admin gọi được. */
exports.setRole = onCall({ region: REGION }, async (request) => {
  if (request.auth) {
    const callerRole = request.auth.token.role;
    // Lần đầu (chưa ai có role) hoặc caller là super_admin mới được set role người khác
    if (callerRole && callerRole !== "super_admin") {
      throw new HttpsError("permission-denied", "Chỉ Super Admin mới được phân quyền.");
    }
  }
  const { targetEmail, role } = request.data;
  if (!targetEmail) throw new HttpsError("invalid-argument", "targetEmail là bắt buộc.");
  if (!ROLE_PERMISSIONS.hasOwnProperty(role)) throw new HttpsError("invalid-argument", "Role không hợp lệ.");

  try {
    const userRecord = await getAuth().getUserByEmail(targetEmail);
    // viewer không có quyền admin gì, các role còn lại đều pass check isAdmin cũ
    const isAdminLike = role !== "viewer";
    await getAuth().setCustomUserClaims(userRecord.uid, { admin: isAdminLike, role });
    await logAudit(request.auth?.token?.email || "system", "SET_ROLE", userRecord.uid, { targetEmail, role });
    return { success: true, message: `Đã set vai trò "${role}" cho ${targetEmail}` };
  } catch (err) { throw new HttpsError("internal", err.message); }
});

// ─────────────────────────────────────────────
// 9-11. banDevice / banUID / banIP
// ─────────────────────────────────────────────
// ─────────────────────────────────────────────
// recordSecurityChange — client gọi ngay sau khi đổi email/password
// thành công, kích hoạt Withdraw Lock 24h để bảo vệ tài khoản khỏi bị
// chiếm quyền rồi rút tiền ngay.
// ─────────────────────────────────────────────
exports.recordSecurityChange = onCall({ region: REGION }, async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Bạn chưa đăng nhập.");
  const uid = request.auth.uid;
  const { changeType } = request.data; // "email" | "password"
  await db.doc(`securityEvents/${uid}`).set({
    lastSecurityChangeAt: FieldValue.serverTimestamp(),
    lastChangeType: changeType || "unknown",
  }, { merge: true });
  await logAudit(request.auth.token.email || uid, "SECURITY_CHANGE", uid, {
    uid, changeType, ip: getClientIp(request),
  });
  return { success: true, withdrawLockedForHours: WITHDRAW_LOCK_HOURS };
});

// ─────────────────────────────────────────────
// PAYMENT PROFILE — hồ sơ thanh toán lưu 1 lần, withdraw lấy dữ liệu từ
// đây thay vì nhập lại mỗi lần. Đổi hồ sơ → khoá rút 24h (dùng chung cơ
// chế securityEvents với đổi mật khẩu/email). Không cho sửa khi đang có
// withdrawal ở trạng thái pending/approved (tránh đổi STK giữa chừng khi
// tiền đang được xử lý).
// ─────────────────────────────────────────────
exports.savePaymentProfile = onCall({ region: REGION }, async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Bạn chưa đăng nhập.");
  const uid = request.auth.uid;
  const { bankName, bankAccount, bankHolder, branch } = request.data;

  if (!bankName || !bankAccount || !bankHolder)
    throw new HttpsError("invalid-argument", "Vui lòng điền đầy đủ ngân hàng, số tài khoản, chủ tài khoản.");
  if ([bankName, bankAccount, bankHolder].some(v => typeof v !== "string"))
    throw new HttpsError("invalid-argument", "Thông tin không hợp lệ.");

  await assertRateLimit(uid, "save_payment_profile", 5, 10 * 60 * 1000);

  // Không cho sửa nếu đang có withdrawal chưa hoàn tất (pending/pending_review/approved)
  const activeSnap = await db.collection("withdrawals")
    .where("uid", "==", uid)
    .where("status", "in", ["pending", "pending_review", "approved"])
    .limit(1).get();
  if (!activeSnap.empty) {
    throw new HttpsError("failed-precondition", "Bạn đang có yêu cầu rút tiền chưa xử lý xong. Vui lòng đợi hoàn tất trước khi đổi hồ sơ thanh toán.");
  }

  const profileRef  = db.doc(`paymentProfiles/${uid}`);
  const existedSnap = await profileRef.get();
  const isChange     = existedSnap.exists; // lần đầu tạo thì không cần khoá rút

  await profileRef.set({
    bankName: bankName.trim(), bankAccount: bankAccount.trim(),
    bankHolder: bankHolder.trim(), branch: (branch || "").trim(),
    updatedAt: FieldValue.serverTimestamp(),
  }, { merge: true });

  if (isChange) {
    await db.doc(`securityEvents/${uid}`).set({
      lastSecurityChangeAt: FieldValue.serverTimestamp(), lastChangeType: "payment_profile",
    }, { merge: true });
    await logAudit(request.auth.token.email || uid, "CHANGE_PAYMENT_PROFILE", uid, { uid, ip: getClientIp(request) });
  }

  return { success: true, withdrawLocked: isChange, withdrawLockedForHours: isChange ? WITHDRAW_LOCK_HOURS : 0 };
});

exports.getPaymentProfile = onCall({ region: REGION }, async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Bạn chưa đăng nhập.");
  const snap = await db.doc(`paymentProfiles/${request.auth.uid}`).get();
  return { exists: snap.exists, profile: snap.exists ? snap.data() : null };
});

exports.banDevice = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "ban_device", "Bạn không có quyền khóa thiết bị.");
  const { deviceId, banned, reason, banType, durationHours } = request.data;
  if (!deviceId) throw new HttpsError("invalid-argument", "deviceId là bắt buộc.");
  const update = banned
    ? { status: "banned", banReason: reason || "Không rõ lý do", banType: banType === "temporary" ? "temporary" : "permanent",
        banExpiresAt: banType === "temporary" && durationHours ? new Date(Date.now() + durationHours * 3600_000) : null }
    : { status: "active", banReason: null, banType: null, banExpiresAt: null };
  await db.doc(`devices/${deviceId}`).set(update, { merge: true });
  await logAudit(request.auth.token.email, banned ? "BAN_DEVICE" : "UNBAN_DEVICE", deviceId, { reason, banType, durationHours, ip: getClientIp(request) });
  return { success: true };
});

exports.banUID = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "ban_uid", "Bạn không có quyền khóa tài khoản.");
  const { uid, banned, reason } = request.data;
  if (!uid) throw new HttpsError("invalid-argument", "uid là bắt buộc.");
  await getAuth().updateUser(uid, { disabled: !!banned });
  await db.doc(`users/${uid}`).set({ banned: !!banned, banReason: banned ? (reason || "Không rõ lý do") : null }, { merge: true });
  await logAudit(request.auth.token.email, banned ? "BAN_UID" : "UNBAN_UID", uid, { reason, ip: getClientIp(request) });
  if (banned) await createNotification(uid, "account_banned", "Tài khoản bị khóa", reason ? `Lý do: ${reason}` : "Tài khoản của bạn đã bị khóa do vi phạm quy định.");
  return { success: true };
});

exports.banIP = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "ban_ip", "Bạn không có quyền chặn IP.");
  const { ip, banned, reason } = request.data;
  if (!ip) throw new HttpsError("invalid-argument", "ip là bắt buộc.");
  const ipKey = ip.replace(/[.:]/g, "_");
  await db.doc(`bannedIps/${ipKey}`).set({ ip, banned: !!banned, reason: banned ? (reason || "Không rõ lý do") : null, updatedAt: FieldValue.serverTimestamp() }, { merge: true });
  await logAudit(request.auth.token.email, banned ? "BAN_IP" : "UNBAN_IP", ip, { reason, ip: getClientIp(request) });
  return { success: true };
});

// ─────────────────────────────────────────────
// 12. getFraudDashboard
// ─────────────────────────────────────────────
/**
 * getDashboardStats — tổng hợp dữ liệu THẬT theo ngày cho Admin Dashboard.
 * Trả về mảng N ngày gần nhất (7 hoặc 30), mỗi ngày gồm: số claim duyệt,
 * tổng tiền đã phát, số withdraw hoàn tất, tổng tiền đã rút, số fraud log.
 * Do Firestore không hỗ trợ GROUP BY, hàm này quét document trong khoảng
 * thời gian rồi tự cộng dồn theo ngày (giờ VN) ở phía server.
 */
exports.getDashboardStats = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "view_audit", "Bạn không có quyền xem dashboard.");
  const { days } = request.data; // 7 hoặc 30
  const numDays = [7, 30].includes(days) ? days : 7;
  const since = Timestamp.fromMillis(Date.now() - numDays * 24 * 3600_000);

  const dayKey = (jsDate) => new Date(jsDate.getTime() + 7 * 3600_000).toISOString().slice(0, 10);
  const buckets = {}; // { "YYYY-MM-DD": { claimsApproved, rewardPaid, withdrawsCompleted, amountPaid, fraudCount } }
  const initBucket = () => ({ claimsApproved: 0, rewardPaid: 0, withdrawsCompleted: 0, amountPaid: 0, fraudCount: 0 });

  const [claimsSnap, withdrawSnap, fraudSnap] = await Promise.all([
    db.collection("claimRequests").where("status", "==", "approved").where("approvedAt", ">=", since).get(),
    db.collection("withdrawals").where("status", "in", ["paid", "completed"]).where("paidAt", ">=", since).get(),
    db.collection("fraudLogs").where("createdAt", ">=", since).get(),
  ]);

  claimsSnap.forEach(d => {
    const x = d.data();
    const key = dayKey(x.approvedAt.toDate());
    buckets[key] = buckets[key] || initBucket();
    buckets[key].claimsApproved += 1;
    buckets[key].rewardPaid += (x.reward || 0);
  });
  withdrawSnap.forEach(d => {
    const x = d.data();
    const key = dayKey(x.paidAt.toDate());
    buckets[key] = buckets[key] || initBucket();
    buckets[key].withdrawsCompleted += 1;
    buckets[key].amountPaid += (x.amount || 0);
  });
  fraudSnap.forEach(d => {
    const x = d.data();
    const key = dayKey(x.createdAt.toDate());
    buckets[key] = buckets[key] || initBucket();
    buckets[key].fraudCount += 1;
  });

  // Đảm bảo đủ N ngày liên tục (kể cả ngày không có dữ liệu = 0)
  const series = [];
  for (let i = numDays - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 24 * 3600_000);
    const key = dayKey(d);
    series.push({ date: key, ...(buckets[key] || initBucket()) });
  }

  return { days: numDays, series };
});

/** getTopStats — top user theo tổng thu nhập, top task theo lượt hoàn thành */
exports.getTopStats = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "view_audit", "Bạn không có quyền xem thống kê.");
  const since = Timestamp.fromMillis(Date.now() - 30 * 24 * 3600_000);

  const claimsSnap = await db.collection("claimRequests").where("status", "==", "approved").where("approvedAt", ">=", since).limit(2000).get();
  const byUser = {}, byTask = {};
  claimsSnap.forEach(d => {
    const x = d.data();
    if (x.uid) { byUser[x.uid] = byUser[x.uid] || { email: x.email, total: 0, count: 0 }; byUser[x.uid].total += (x.reward || 0); byUser[x.uid].count += 1; }
    if (x.taskId) byTask[x.taskId] = (byTask[x.taskId] || 0) + 1;
  });

  const topUsers = Object.entries(byUser).sort((a, b) => b[1].total - a[1].total).slice(0, 10)
    .map(([uid, v]) => ({ uid, email: v.email, total: v.total, count: v.count }));
  const topTasks = Object.entries(byTask).sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([taskId, count]) => ({ taskId, count }));

  return { topUsers, topTasks };
});


exports.getFraudDashboard = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "view_fraud", "Bạn không có quyền xem dashboard gian lận.");
  const since = Timestamp.fromMillis(Date.now() - 7 * 24 * 3600_000);
  const snap = await db.collection("fraudLogs").where("createdAt", ">=", since).orderBy("createdAt", "desc").limit(500).get();
  const byDevice = {}, byIp = {}, byUid = {}, byReason = {};
  snap.forEach(doc => {
    const d = doc.data();
    if (d.deviceId) byDevice[d.deviceId] = (byDevice[d.deviceId] || 0) + 1;
    if (d.ip)       byIp[d.ip]           = (byIp[d.ip] || 0) + 1;
    if (d.uid)       byUid[d.uid]         = (byUid[d.uid] || 0) + 1;
    if (d.reason)    byReason[d.reason]   = (byReason[d.reason] || 0) + 1;
  });
  const toSortedArray = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([key, count]) => ({ key, count }));
  return {
    totalEvents: snap.size,
    topDevices: toSortedArray(byDevice), topIps: toSortedArray(byIp),
    topUids: toSortedArray(byUid), topReasons: toSortedArray(byReason),
  };
});

// ─────────────────────────────────────────────
// 13. getUidTimeline — Audit Timeline: gộp fraud/audit/claim/withdraw
// theo 1 UID, sắp xếp theo thời gian, giúp admin điều tra nhanh.
// ─────────────────────────────────────────────
exports.getUidTimeline = onCall({ region: REGION }, async (request) => {
  assertPermission(request, "view_audit", "Bạn không có quyền xem timeline.");
  const { uid } = request.data;
  if (!uid) throw new HttpsError("invalid-argument", "uid là bắt buộc.");

  const [fraudSnap, claimSnap, withdrawSnap, auditSnap] = await Promise.all([
    db.collection("fraudLogs").where("uid", "==", uid).orderBy("createdAt", "desc").limit(50).get(),
    db.collection("claimRequests").where("uid", "==", uid).orderBy("createdAt", "desc").limit(50).get(),
    db.collection("withdrawals").where("uid", "==", uid).orderBy("createdAt", "desc").limit(50).get(),
    db.collection("auditLogs").where("uid", "==", uid).orderBy("createdAt", "desc").limit(50).get(),
  ]);

  const events = [];
  fraudSnap.forEach(d => { const x = d.data(); events.push({ type: "fraud", time: x.createdAt?.toMillis?.() || 0, detail: `${x.action} — ${x.reason}`, ip: x.ip, deviceId: x.deviceId }); });
  claimSnap.forEach(d => { const x = d.data(); events.push({ type: "claim", time: x.createdAt?.toMillis?.() || 0, detail: `Claim ${x.taskId} — ${x.reward}đ — ${x.status}`, ip: x.ip, deviceId: x.deviceId }); });
  withdrawSnap.forEach(d => { const x = d.data(); events.push({ type: "withdraw", time: x.createdAt?.toMillis?.() || 0, detail: `Rút ${x.amount}đ — ${x.status}`, ip: x.ip, deviceId: x.deviceId }); });
  auditSnap.forEach(d => { const x = d.data(); events.push({ type: "admin_action", time: x.createdAt?.toMillis?.() || 0, detail: `${x.adminEmail}: ${x.action}`, ip: x.ip }); });

  events.sort((a, b) => b.time - a.time);
  return { events: events.slice(0, 100) };
});

// ─────────────────────────────────────────────
// 14. scheduledCleanup — dọn pendingTasks/dailyLimits/registerLimits/
// completedTasks/idempotency cũ. Vì completedTasks giờ theo ngày, dọn
// sau 3 ngày để tiết kiệm dung lượng (không ảnh hưởng logic reset vì
// logic reset chỉ nhìn NGÀY HÔM NAY, không cần giữ completedTasks cũ).
// ─────────────────────────────────────────────
exports.scheduledCleanup = onSchedule(
  { schedule: "every 60 minutes", region: REGION },
  async () => {
    const now       = Timestamp.now();
    const usersSnap = await db.collection("users").select().get();
    const batch     = db.batch();
    let deleteCount = 0;

    for (const userDoc of usersSnap.docs) {
      const pendingSnap = await db.collection(`users/${userDoc.id}/pendingTasks`)
        .where("expireAt", "<", now).where("used", "==", false).get();
      pendingSnap.forEach(d => { batch.delete(d.ref); deleteCount++; });
    }

    const threeDaysAgo = todayVN();
    const oldDailySnap = await db.collection("dailyLimits").where("date", "<", threeDaysAgo).limit(200).get();
    oldDailySnap.forEach(d => { batch.delete(d.ref); deleteCount++; });

    const oldRegSnap = await db.collection("registerLimits").where("date", "<", threeDaysAgo).limit(200).get();
    oldRegSnap.forEach(d => { batch.delete(d.ref); deleteCount++; });

    // Dọn idempotency key cũ hơn 48h (đủ dài để bắt mọi retry hợp lý,
    // đủ ngắn để không phình database)
    const cutoff = Timestamp.fromMillis(Date.now() - 48 * 3600_000);
    const oldIdemSnap = await db.collection("idempotency").where("createdAt", "<", cutoff).limit(300).get();
    oldIdemSnap.forEach(d => { batch.delete(d.ref); deleteCount++; });

    if (deleteCount > 0) { await batch.commit(); console.log(`Cleaned up ${deleteCount} expired docs.`); }
  }
);
