# Dự án Phản ứng Sự cố Windows & Mô phỏng Tấn công (Windows IR & Adversary Simulation)

## 🎯 Giới thiệu Dự án
Dự án thực tế mô phỏng quy trình phòng thủ, tấn công (Adversary Simulation) và phản ứng sự cố (DFIR) trên hệ thống Windows. Dự án được thực hiện nhằm xây dựng năng lực thực chiến cho vị trí **SOC Analyst**.

---

## 🛠️ 1. Cấu hình Giám sát (Blue Team)
- Kích hoạt **PowerShell Script Block Logging (Event ID 4104)** qua Registry để theo dõi toàn bộ kịch bản thực thi trên bộ nhớ (RAM).
- Triển khai **Sysmon** để giám sát chi tiết hành vi khởi tạo tệp (`Event ID 11`), thực thi tiến trình (`Event ID 1`) và kết nối mạng (`Event ID 3`).

---

## ⚔️ 2. Mô phỏng Kẻ tấn công (Red Team / MITRE ATT&CK)
- **Kịch bản 01 (Fileless C2):** Thực thi kịch bản PowerShell giả lập kết nối ngược (Reverse Shell / C2 Beacon) sử dụng thư viện `.NET TCPClient` (`T1059.001`).
- **Kịch bản 02 (Meterpreter Reverse TCP):** Phát tán và thực thi payload nhị phân giả danh tệp cập nhật (`update.exe`), thiết lập kênh điều khiển từ xa về máy chủ C2 Kali Linux qua cổng `4444` (`T1204.002`, `T1036.005`, `T1571`).

---

## 🔍 3. Điều tra & Phát hiện (DFIR)
- Sử dụng **Windows Event Viewer** để trích xuất nhật ký gốc (`.evtx`, `.xml`) và dựng dòng thời gian sự cố (Incident Timeline).
- Bóc trần payload độc hại qua trường `ScriptBlockText` (Event ID 4104) và truy vết chuỗi hành vi từ luồng *Mark of the Web* (`Zone.Identifier`) đến kết nối C2.
- Xây dựng **luật phát hiện Sigma (Sigma Rule)** và thực hiện quy trình ứng cứu sự cố (Containment, Eradication, Network Blocking).

---

## 📄 4. Danh sách Báo cáo Chi tiết

| Case | Ngày | Kịch bản Sự cố | Kỹ thuật MITRE ATT&CK | Nguồn Log & Bằng chứng | Báo cáo |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Case 01** | 11/11/2026 | Phát hiện thực thi PowerShell đáng ngờ | `T1059.001` | PowerShell (`4104`) | [Xem báo cáo](report/Incident-Report.md) |
| **Case 02** | 13/11/2026 | Phát hiện Payload Meterpreter Reverse TCP | `T1204.002`, `T1036.005`, `T1571` | Sysmon (`11`, `1`, `3`), Screenshots | [Xem báo cáo](report/Meterpreter-Incident-Report.md) |