# Phòng lab quét CSDL

Thư mục này chỉ chứa cấu hình để dựng môi trường quét **trên máy của bạn**, phục vụ
việc lấy dữ liệu đầu vào thật cho đồ án. Hướng dẫn đầy đủ từng bước, kèm lệnh quét và
cách đưa file vào project: [../docs/lab-quet-csdl.md](../docs/lab-quet-csdl.md).

| Service | Vai trò | Cổng trên host |
|---|---|---|
| `dvwa` | Ứng dụng có lỗ hổng để quét tầng app (SQLi) | `127.0.0.1:4280` |
| `db` | CSDL riêng của DVWA, không mở ra host | — |
| `weak-mysql` | CSDL yếu: root không mật khẩu, cho phép từ xa | `127.0.0.1:3306` |
| `weak-postgres` | CSDL yếu: `trust` trong `pg_hba.conf` | `127.0.0.1:5432` |

Chạy và dọn dẹp:

```bash
docker compose up -d          # dựng lab
docker compose ps             # xem trạng thái
docker compose down -v        # dọn sạch, kể cả dữ liệu
```

Ba việc cần nhớ:

1. **Cố ý không an toàn.** `weak-mysql` và `weak-postgres` không có mật khẩu; DVWA có
   lỗ hổng. Không chạy lab trên máy chủ công khai, không mở cổng ra Internet, không
   quét IP của người khác. Xong việc thì `docker compose down -v`.
2. **Cổng chỉ mở trên 127.0.0.1.** Người quét chạy trên cùng máy thì được; nếu quét từ
   máy ảo (Kali trong host-only network) thì đổi `127.0.0.1` thành IP host-only của máy
   bạn trong `docker-compose.yml`, và chỉ trong mạng nội bộ đó.
3. **Không commit dữ liệu quét.** `data/raw/scans/*` đã bị ignore; file export có thể
   chứa cookie phiên, hostname và đường dẫn riêng.
