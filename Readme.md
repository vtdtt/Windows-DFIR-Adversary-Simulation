# Dự án Phản ứng Sự cố Windows & Mô phỏng Tấn công (Windows IR & Adversary Simulation)

## 🎯 Giới thiệu Dự án
Dự án thực tế mô phỏng quy trình phòng thủ, tấn công (Adversary Simulation) và phản ứng sự cố (DFIR) trên hệ thống Windows. Dự án được thực hiện nhằm xây dựng năng lực thực chiến cho vị trí **SOC Analyst**.

---

## 🛠️ 1. Cấu hình Giám sát (Blue Team)
- Kích hoạt **PowerShell Script Block Logging (Event ID 4104)** qua Registry để theo dõi toàn bộ kịch bản thực thi trên bộ nhớ (RAM).
- Triển khai **Sysmon** để kiểm soát tiến trình hệ thống chi tiết.

---

## ⚔️ 2. Mô phỏng Kẻ tấn công (Red Team / MITRE ATT&CK)
- Thực thi kịch bản PowerShell giả lập kết nối ngược (Reverse Shell / C2 Beacon) sử dụng thư viện `.NET TCPClient`.

---

## 🔍 3. Điều tra & Phát hiện (DFIR)
- Sử dụng **Windows Event Viewer** để trích xuất bằng chứng số.
- Phát hiện và bóc trần payload độc hại thông qua trường `ScriptBlockText` trong Event ID 4104.

---

## 📄 4. Báo cáo Chi tiết
Xem toàn bộ báo cáo phân tích sự cố tại: [report/Incident-Report.md](report/Incident-Report.md)