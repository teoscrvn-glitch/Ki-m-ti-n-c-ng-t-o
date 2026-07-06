# TaskEarn — Hướng dẫn Deploy

## 1. Cài Firebase CLI (nếu chưa có)
```bash
npm install -g firebase-tools
firebase login
```

## 2. Khởi tạo project (chạy trong thư mục này)
```bash
firebase use --add     # chọn Firebase project của bạn
```

## 3. Set các Secret bắt buộc cho Cloud Functions
```bash
# Secret ký session token (chuỗi random dài, tự tạo bằng lệnh dưới)
firebase functions:secrets:set SESSION_SECRET_V2
# → dán giá trị random, ví dụ tạo bằng: openssl rand -hex 32

# Lúc đầu deploy, SESSION_SECRET_V1 có thể set giống V2 (chưa cần rotation)
firebase functions:secrets:set SESSION_SECRET_V1

# reCAPTCHA v3 Secret Key — lấy tại https://www.google.com/recaptcha/admin
# Nếu CHƯA có, để trống (nhấn Enter) — Cloud Function tự bỏ qua verify reCAPTCHA
firebase functions:secrets:set RECAPTCHA_SECRET

# (Tuỳ chọn) IPQualityScore API key — chống VPN/TOR/Hosting IP.
# Nếu CHƯA có tài khoản IPQualityScore, để trống — hệ thống tự bỏ qua
# bước kiểm tra IP reputation, KHÔNG bịa kết quả.
firebase functions:secrets:set IPQS_API_KEY
```

## 3.1. Set Super Admin đầu tiên (bắt buộc để dùng tính năng phân quyền)
Sau khi deploy, gọi function `setRole` với role `super_admin` cho email
của bạn — vì `setRole` yêu cầu người gọi đã là `super_admin` nên LẦN ĐẦU
TIÊN phải set thủ công qua Firebase Admin SDK từ máy local:
```js
const admin = require("firebase-admin");
admin.initializeApp();
admin.auth().getUserByEmail("your-email@example.com")
  .then(u => admin.auth().setCustomUserClaims(u.uid, { admin: true, role: "super_admin" }));
```
Sau đó đăng xuất/đăng nhập lại ở `admin.html` để nhận quyền Super Admin,
từ đó có thể phân quyền cho người khác qua giao diện Cài đặt.

### Xoay vòng secret sau này (không cần logout hàng loạt user)
```bash
# 1. Copy giá trị hiện tại của V2 → set lại làm V1
firebase functions:secrets:set SESSION_SECRET_V1
# 2. Set V2 = giá trị mới hoàn toàn
firebase functions:secrets:set SESSION_SECRET_V2
# 3. Deploy lại — token cũ (ký bằng V1) vẫn được chấp nhận trong lúc
#    người dùng đang có phiên dở dang, token mới ký bằng V2.
```

## 4. Điền Firebase Config vào file client
Mở `index.html` và `admin.html`, tìm khối:
```js
const firebaseConfig = {
  apiKey: "THAY_API_KEY",
  ...
};
```
Thay bằng config thật lấy từ Firebase Console → Project Settings → Web App.

## 5. (Tuỳ chọn) Điền reCAPTCHA v3 Site Key
Trong `index.html`, tìm và thay:
```html
<script src="https://www.google.com/recaptcha/api.js?render=YOUR_RECAPTCHA_SITE_KEY"></script>
```
và
```js
const RECAPTCHA_SITE_KEY = "YOUR_RECAPTCHA_SITE_KEY";
```
Nếu chưa có site key, cứ để nguyên placeholder — hệ thống vẫn hoạt động,
chỉ là chưa có lớp bảo vệ reCAPTCHA.

## 6. (Tuỳ chọn) Bật Firebase App Check
Mặc định App Check đang **tắt** (`ENFORCE_APP_CHECK = false` trong
`functions/index.js`). Để bật:
1. Vào Firebase Console → App Check → đăng ký Web App với reCAPTCHA
   v3 hoặc Enterprise provider, lấy site key riêng cho App Check.
2. Trong `index.html`, bỏ comment 2 dòng import `firebase-app-check.js`
   và khối `initializeAppCheck(...)`, điền site key.
3. Trong `functions/index.js`, đổi `ENFORCE_APP_CHECK = true`.
4. Deploy lại cả hosting và functions.

⚠️ Không bật App Check ở bước 3 trước khi hoàn thành bước 2 — nếu không
mọi request từ client sẽ bị Cloud Functions từ chối.

## 7. Deploy theo đúng thứ tự
```bash
# Bước 1: Deploy Firestore indexes trước, đợi build xong (vài phút,
# theo dõi tại Firebase Console → Firestore → Indexes)
firebase deploy --only firestore:indexes

# Bước 2: Deploy rules
firebase deploy --only firestore:rules

# Bước 3: Deploy Cloud Functions
firebase deploy --only functions

# Bước 4: Deploy Hosting (index.html, admin.html)
firebase deploy --only hosting

# Hoặc deploy tất cả 1 lần (sau khi indexes đã build xong lần đầu):
firebase deploy
```

## 8. Set admin đầu tiên
Sau khi deploy xong, đăng ký 1 tài khoản qua `index.html`, sau đó gọi
function `setAdminClaim` để cấp quyền admin cho tài khoản đó — cách dễ
nhất là dùng Firebase Console → Functions → chạy thử `setAdminClaim`
với `{ "targetEmail": "your-email@example.com" }`, hoặc dùng
Firebase Admin SDK từ máy local:
```js
const admin = require("firebase-admin");
admin.initializeApp();
admin.auth().getUserByEmail("your-email@example.com")
  .then(u => admin.auth().setCustomUserClaims(u.uid, { admin: true }));
```
Sau đó đăng xuất/đăng nhập lại ở `admin.html` để nhận quyền.

## Cấu trúc thư mục
```
taskearn/
├── firebase.json          # Cấu hình deploy
├── firestore.rules        # Bảo mật Firestore
├── firestore.indexes.json # Composite indexes cần thiết
├── index.html              # App người dùng (client)
├── admin.html               # App quản trị (admin)
└── functions/
    ├── index.js            # Cloud Functions (toàn bộ logic backend)
    └── package.json
```

## Tóm tắt các lớp bảo mật đã có
- Session token ký HMAC (nonce + exp 5 phút, chống replay + giả token, có version)
- Secret rotation cho session token (V1/V2)
- **Idempotency** — mỗi claim/withdraw có idempotencyKey, gửi lại (retry,
  mất mạng, double-click) không bị xử lý/cộng tiền 2 lần
- **Toàn bộ thao tác tiền đều trong 1 Firestore Transaction** (đọc-kiểm
  tra-ghi atomic, không có khoảng hở race condition/TOCTOU)
- reCAPTCHA v3 (verify theo score, tự bỏ qua nếu chưa cấu hình)
- Device Fingerprint (FingerprintJS v4) + entropy mở rộng (UA, platform,
  hardwareConcurrency, deviceMemory, screen, timezone, language)
- Automation/headless detection (navigator.webdriver, plugin count...)
- Giới hạn theo Device (3 acc), IP (5 acc), đăng ký/thiết bị/ngày (2 lần)
- Velocity check — quá nhiều tài khoản mới/thiết bị/30 phút → tự khóa 6 giờ
- Impossible travel — đổi IP "xa" quá nhanh → ghi fraud log
- Rate limit: claim 5 lần/phút, withdraw 3 lần/5 phút, admin 30 lần/phút
- Fraud Scoring tổng hợp có trọng số — ngưỡng >80 tự pending_review
- IP Reputation (IPQualityScore) — tuỳ chọn, tự bỏ qua nếu chưa có API key
- Risk Score cho rút tiền
- Ban UID / Ban Device (tạm thời hoặc vĩnh viễn) / Ban IP
- Lịch sử fingerprint/IP (devices/{id}/history, users/{uid}.ipHistory)
- Fraud Dashboard (top device/IP/UID/lý do 7 ngày gần nhất)
- **Audit Timeline theo UID** — tab Gian Lận trong admin.html, dán UID
  vào là thấy toàn bộ lịch sử claim/rút/fraud/hành động admin theo dòng
  thời gian, phục vụ điều tra nhanh
- Audit log (mọi hành động admin) + Fraud log chi tiết
- Firestore Rules chặn client sửa balance/banned trực tiếp
- App Check placeholder (sẵn sàng bật khi cần)

## Model nhiệm vụ: RESET HÀNG NGÀY
Từ bản này, MỌI nhiệm vụ admin tạo đều tự động cho phép người dùng làm
lại **1 lần/ngày**, reset lúc **0h00 giờ Việt Nam**. Cơ chế:
- `completedTasks` lưu theo key `{taskId}_{YYYY-MM-DD}` thay vì `{taskId}`
- Khi qua ngày mới, key hôm qua không còn khớp "hôm nay" → nhiệm vụ tự
  hiện lại nút "NHẬN NHIỆM VỤ" mà không cần admin thao tác gì
- Task card hiển thị đếm ngược "Mở lại sau Xh0Yp" khi đã hoàn thành hôm nay
- `scheduledCleanup` dọn dữ liệu cũ hơn 3 ngày để tiết kiệm dung lượng

## Payment Profile (Hồ sơ thanh toán)
- Người dùng thiết lập 1 lần trong mục Tài khoản: ngân hàng, số tài
  khoản, chủ tài khoản, chi nhánh (tuỳ chọn)
- Khi rút tiền, hệ thống tự lấy dữ liệu từ hồ sơ — không nhập lại
- Đổi hồ sơ thanh toán → tự khoá rút tiền 24h (dùng chung cơ chế với
  đổi mật khẩu, qua `securityEvents/{uid}`)
- Không cho đổi hồ sơ khi đang có withdrawal ở trạng thái pending/
  pending_review/approved (tránh đổi STK giữa lúc tiền đang xử lý)

## Withdraw Workflow — 4 trạng thái
```
pending (hoặc pending_review nếu fraud score cao)
   │  admin bấm "Duyệt"
   ▼
approved
   │  admin bấm "Đã chuyển khoản" (có thể ghi mã giao dịch)
   ▼
paid
   │  admin bấm "Đối soát xong"
   ▼
completed
```
Có thể "Hoàn tiền" (reject) ở bất kỳ bước nào trước `paid` — tiền tự
động cộng lại vào balance của user.

## Chuẩn bị cấu trúc cho tính năng tương lai
Đã đặt sẵn Firestore Rules cho các collection sau (chưa có UI, sẽ thêm
UI ở đợt sau mà không cần sửa lại cấu trúc dữ liệu gốc):
- `referrals/{uid}` — mã giới thiệu + hoa hồng
- `dailyRewards/{uid}_{date}` — điểm danh hàng ngày
- `banners/{id}` — banner/thông báo do admin đăng, không cần sửa code
- `tickets/{id}` — hệ thống ticket hỗ trợ (user tạo, admin trả lời)
- `notifications/{id}` — thông báo trong app (đã có rules, UI sẽ thêm sau)

## Support Center & Điều khoản
Trong app (mục Tài khoản → Hỗ trợ / Điều khoản) đã có:
- FAQ cơ bản (rút tiền, khoá bảo mật, reset nhiệm vụ, claim bị từ chối)
- Kênh liên hệ (Telegram/Facebook/Email — cần điền link thật)
- Điều khoản sử dụng, Quy định rút tiền, Chính sách chống gian lận
  (nội dung mẫu — bạn nên tự viết lại nội dung pháp lý phù hợp)

## Notification Center
- Chuông 🔔 trên header app, badge đỏ hiện số thông báo chưa đọc
- Realtime qua `onSnapshot` — không cần F5
- Tự động tạo thông báo khi: claim được duyệt/từ chối, withdraw đổi
  trạng thái (duyệt/đã chuyển/từ chối), tài khoản bị khóa
- Bấm vào 1 thông báo để đánh dấu đã đọc, hoặc "Đánh dấu đã đọc hết"

## Admin Dashboard — dữ liệu thật
- `getDashboardStats` Cloud Function tổng hợp THẬT theo ngày (không còn
  placeholder minh họa), toggle xem 7 ngày / 30 ngày
- `getTopStats` — top 10 user theo tổng thu nhập, top 10 task theo lượt
  hoàn thành (trong 30 ngày gần nhất)
- Các số liệu tổng quan (users, pending claims/withdraws, fraud hôm
  nay...) vẫn đếm trực tiếp từ Firestore mỗi khi bấm "Làm mới Dashboard"

## Phân quyền theo vai trò (RBAC)
6 vai trò với custom claims `role` trên Firebase Auth:
- **Super Admin** — toàn quyền + phân quyền cho người khác
- **Admin** — duyệt claim/rút tiền, quản lý task, ban UID/device/IP
- **Finance** — chỉ xử lý rút tiền (duyệt/chuyển khoản/đối soát/hoàn tiền)
- **Moderator** — chỉ ban UID/device/IP + xem gian lận
- **Support** — chỉ xem audit log
- **Viewer** — không có quyền thao tác

Backend luôn tự kiểm tra quyền qua `assertPermission()` trong mọi Cloud
Function bất kể giao diện có ẩn nút hay không. `admin.html` cũng ẩn bớt
tab/nút theo vai trò đang đăng nhập để tránh nhầm lẫn, nhưng đây chỉ là
UX — an toàn thực sự nằm ở phía server.

Set vai trò: vào tab Cài đặt → "Phân quyền theo vai trò" → nhập email +
chọn vai trò. Người được set cần đăng xuất/đăng nhập lại.

## Withdraw Workflow — 5 trạng thái
```
pending (hoặc pending_review nếu fraud score cao)
   │  admin bấm "Duyệt"                    │  user tự bấm "Hủy" (chỉ khi còn pending)
   ▼                                        ▼
approved                                 cancelled (hoàn tiền tự động)
   │  admin bấm "Đã chuyển khoản"
   ▼
paid
   │  admin bấm "Đối soát xong"
   ▼
completed
```
Admin có thể "Từ chối" (rejected, hoàn tiền tự động) ở bất kỳ bước nào
trước `paid`. User có thể tự hủy (`cancelWithdraw`) khi lệnh rút còn ở
`pending`/`pending_review`, chưa được admin xử lý.

## Search / Filter nâng cao trong Admin
- Tìm theo email/UID/TaskID/DeviceID/IP (claims) hoặc email/UID/STK/
  ngân hàng (withdrawals)
- Lọc theo mức độ rủi ro: Mọi mức / Từ Medium (30+) / Từ High (60+) /
  Chỉ Critical (90+)
- Lọc withdrawals theo tên ngân hàng
- Risk Level hiển thị màu: 🟢 Low (<30) · 🟡 Medium (30-59) ·
  🟠 High (60-89) · 🔴 Critical (≥90) thay vì chỉ số thô

## Theme — giảm animation/glow (phong cách Stripe/Linear)
Đã giảm bớt hiệu ứng nảy (bounce), shadow neon, animation fadeUp trên
mọi trang/card để cảm giác phẳng, nhanh, chuyên nghiệp hơn — gần với
Stripe/Linear/GitHub Dark thay vì hiệu ứng "gaming" nặng.

```
