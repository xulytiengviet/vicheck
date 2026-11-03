# ViCheck Dashboard — Website Risk Intelligence

**Giao diện:** https://xulytiengviet.github.io/vicheck/

Dashboard SOC tiếng Việt, thiết kế responsive, nhập URL và xem kết quả theo bốn nhóm màu:

- Xanh lá: tiêu chí quan sát được phù hợp (KHÔNG phải giấy chứng nhận).
- Vàng: cần cải thiện/xác minh.
- Đỏ: dấu hiệu có thể phát sinh nghĩa vụ pháp lý, cần ưu tiên thẩm định.
- Xanh dương: tín hiệu điểm yếu bảo mật/cấu hình HTTP, không đồng nghĩa chứng minh khai thác.
- Xám: giới hạn phạm vi kiểm tra.

Chức năng: lọc màu, bằng chứng và hướng xử lý, xuất JSON/CSV, in PDF bằng chức năng in của trình duyệt, chế độ demo gắn nhãn rõ.

## Kiến trúc

`index.html`: dashboard tĩnh chạy trên GitHub Pages.

`server.js`: API Node.js (không dependency), endpoint `POST /api/audit` nhận JSON `{"url":"https://example.com"}`, trả `observed` + `findings`. Endpoint `GET /health`.

GitHub Pages **không thể tự tải HTML từ website bất kỳ** do CORS. Cần triển khai `server.js` trên Render hoặc máy chủ được kiểm soát. Đường dẫn API nhập trong nút **Cấu hình API** tại dashboard, chỉ lưu trong `sessionStorage` phiên trình duyệt. Trang không lưu URL đã quét hay nội dung báo cáo lên máy chủ. Dịch vụ API chỉ giữ kết quả trong RAM trong lúc xử lý, không ghi database / access log ứng dụng.

## Chạy local

```bash
npm test
npm start
# http://localhost:3000
```

## Render

Có thể triển khai Web Service Node.js từ repo này, runtime Node >=20, build `npm install --ignore-scripts`, start `npm start`, health path `/health`, plan free. Có mẫu `render.yaml`; sau khi triển khai nhập URL backend HTTPS vào phần **Cấu hình API** ở GitHub Pages. Chỉ CORS từ `https://xulytiengviet.github.io` và local dev.

## Giới hạn và an toàn

- Chỉ GET **một** tài liệu HTML công khai và response headers; không quét port, không khai thác, không brute-force, không chạy JavaScript trang đích.
- Bảo vệ SSRF: chỉ domain công khai, chặn IP/localhost/port lạ/private DNS, pin địa chỉ IP phân giải; chỉ cho redirect trong cùng domain, giới hạn 3 lượt, timeout, kích thước phản hồi, số lần gọi.
- Không phát hiện CVE, malware, SQLi, XSS, SSRF từ audit này. Thiếu CSP/HSTS chỉ là khuyến nghị hardening.
- Không suy ra vi phạm pháp luật từ việc thiếu liên kết ở **trang chủ**. Xem `references/` và `sources/legal-references.md` để phân loại và tham khảo, xác minh văn bản gốc tại `vbpl.vn`.
- Chỉ quét website mình sở hữu hoặc có quyền rà soát. Thực thi thêm chính sách tần suất và chống lạm dụng nếu triển khai công khai quy mô lớn.

Bộ checklist mã nguồn `vn-law-check` gốc không bị thay đổi.
