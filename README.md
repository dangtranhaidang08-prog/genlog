# HỆ THỐNG PHÁT HIỆN TẤN CÔNG SQL INJECTION TỪ LOG MÁY CHỦ WEB APACHE & GIÁM SÁT AN NINH SOC BẰNG MACHINE LEARNING

Dự án nghiên cứu, xây dựng và triển khai một giải pháp an ninh mạng toàn diện nhằm **phát hiện và cảnh báo tấn công Web (trọng tâm là SQL Injection - SQLi)** từ các yêu cầu HTTP (URL Query, Form-Data và **JSON Request Body**) cũng như từ tệp nhật ký máy chủ **Apache Access Log**.

Hệ thống kết hợp các kỹ thuật:
- **Tiền xử lý & Bóc tách log chuyên sâu**: Apache Log Parsing, Recursive JSON Flattening, Token Masking, Request Deduplication Hashing.
- **Kỹ thuật trích xuất đặc trưng (Feature Engineering)**: 84 đặc trưng số học (thống kê ký tự đặc biệt, độ dài, từ khóa SQL, độ sâu JSON, entropy) kết hợp với Character N-grams TF-IDF Vectorizer.
- **Học máy giám sát (Supervised Machine Learning)**: Huấn luyện và so sánh giữa **Random Forest, Logistic Regression, Multinomial Naive Bayes** với kỹ thuật chia tách dữ liệu không rò rỉ (**GroupShuffleSplit** theo họ payload).
- **Giao diện Giám sát An ninh SOC Thời gian thực (Real-time Web SOC Dashboard)**: Trực quan hóa dòng sự kiện giám sát thụ động, bảng điều khiển ngưỡng nhạy cảnh báo, và biểu đồ cột phân bổ từng loại tấn công.

---

## 1. GIỚI THIỆU TỪNG THÀNH PHẦN NẰM TRONG DỰ ÁN

```text
ATCSDL/
├── dashboard/                              # Hệ thống Web SOC Dashboard giám sát an ninh thời gian thực
│   ├── dashboard_backend.py                # Server API (Flask), quản lý background log tailer (Local/SSH) & AI engine
│   ├── index.html                          # Giao diện chính hiển thị sự kiện, thẻ KPI, thanh chỉnh độ nhạy
│   ├── app.js                              # Logic frontend: gọi API stream, biểu đồ cột Chart.js, modal chi tiết
│   └── style.css                           # Giao diện sáng (Light Mode), bố cục thẻ, animation trạng thái
│
├── data/                                   # Lưu trữ dữ liệu các giai đoạn xử lý
│   ├── raw_logs/access.log                 # Log thô thu thập từ máy chủ Apache
│   ├── apache_logs.csv                     # Kết quả parse log thô sang dạng cấu trúc tabular
│   ├── dataset.csv                         # Dữ liệu sạch sau khi gán nhãn, lọc trùng và mask token
│   ├── features.csv                        # Ma trận 84 vector đặc trưng dùng để huấn luyện mô hình
│   └── payloads_all.csv                    # Tập hợp toàn bộ các payload biến thể đã sinh ra
│
├── DVWA/                                   # Ứng dụng Web kiểm thử an ninh mục tiêu (Damn Vulnerable Web Application)
│   ├── compose.yml                         # Tệp Docker Compose khởi động DVWA & cơ sở dữ liệu MariaDB
│   ├── Dockerfile                          # Cấu hình container DVWA chạy trên nền PHP/Apache
│   ├── config/                             # Cấu hình kết nối database của DVWA
│   ├── setup.php                           # Trang khởi tạo và cài đặt cơ sở dữ liệu mặc định
│   └── vulnerabilities/                    # Mã nguồn các bài thực hành tấn công (sqli, sqli_blind, xss, csrf...)
│
├── models/                                 # Lưu trữ các mô hình AI & tiền xử lý đã huấn luyện (.pkl)
│   ├── sqli_rf_model.pkl                   # Mô hình Random Forest Classifier (Recall 100% trên các mẫu SQLi)
│   ├── tfidf_vectorizer.pkl                # Bộ biến đổi Character N-grams TF-IDF
│   └── feature_columns.pkl                 # Danh sách các cột đặc trưng số học được sử dụng
│
├── reports/                                # Các báo cáo số liệu và đồ thị trực quan hóa
│   ├── classification_report.txt           # Báo cáo chi tiết Precision, Recall, F1-Score trên tập Test Unseen
│   ├── confusion_matrix.png                # Ma trận nhầm lẫn trực quan
│   ├── feature_importance.csv              # Bảng xếp hạng tầm quan trọng của các đặc trưng
│   ├── feature_importance.png              # Biểu đồ Top 25 đặc trưng AI quan trọng nhất
│   ├── metrics.json                        # Tổng hợp các chỉ số đánh giá mô hình
│   ├── dataset_report.txt                  # Thống kê phân bố nhãn và cấu trúc dữ liệu
│   └── security_benchmark_report.json      # Kết quả kiểm thử an ninh đối kháng (Evasion, FPR, Latency)
│
├── src/                                    # Mã nguồn lõi của hệ thống
│   ├── collectors/                         # Module sinh dữ liệu & thu thập lưu lượng
│   │   ├── traffic_generator.py            # Bắn request HTTP (GET, POST JSON/Form) tới web server và ghi log
│   │   └── dvwa_generator/                 # Bộ sinh payload đa dạng
│   │       └── payload_generator.py        # Sinh 23 họ template payload (UNION, Boolean, Time, Error, JSON, Normal)
│   ├── data_processing/                    # Module xử lý dữ liệu và trích xuất đặc trưng
│   │   ├── apache_parser.py                # Parse log Apache Combined Log Format, đệ quy bóc tách JSON body
│   │   ├── dataset_builder.py              # Làm sạch, chuẩn hóa, băm chữ ký và gắn nhãn nhị phân
│   │   └── feature_extractor.py            # Tính toán 84 đặc trưng số học và kết hợp vector đặc trưng văn bản
│   ├── detector/                           # Module động cơ phân tích an ninh thời gian thực
│   │   └── threat_detector.py              # Đánh giá nguy cơ theo threshold, trích xuất Threat Indicators
│   ├── training/                           # Huấn luyện mô hình AI
│   │   └── train_model.py                  # Pipeline huấn luyện, so sánh các mô hình ML và lưu artifact
│   └── config.py                           # Cấu hình đường dẫn và hằng số toàn hệ thống
│
├── tests/                                  # Kiểm thử tự động và kiểm thử đối kháng
│   ├── test_security_benchmarks.py         # Kiểm tra khả năng chống né tránh (Evasion), FPR và độ trễ thẩm định
│   └── test_threat_detector.py             # Unit test kiểm tra hoạt động của ThreatDetector
│
├── run_pipeline.py                         # Kịch bản chạy tự động toàn bộ pipeline từ đầu đến cuối
├── predict.py                              # Công cụ dòng lệnh (CLI) kiểm tra an ninh nhanh một request bất kỳ
├── requirements.txt                        # Danh sách các thư viện Python cần thiết
└── README.md                               # Hướng dẫn sử dụng và tài liệu kỹ thuật của dự án
```

---

## 2. HƯỚNG DẪN CÀI ĐẶT VÀ CẤU HÌNH DVWA

Ứng dụng **DVWA (Damn Vulnerable Web Application)** được dùng làm môi trường mục tiêu chuẩn để giả lập lưu lượng người dùng thông thường và các đợt tấn công khai thác SQL Injection.

### Cách 1: Cài đặt và chạy bằng Docker Compose (Khuyên dùng - Nhanh & Ổn định nhất)

Thư mục `DVWA/` đã tích hợp sẵn tệp cấu hình `compose.yml` gồm 2 container: ứng dụng DVWA và cơ sở dữ liệu MariaDB 10.

1. **Yêu cầu**: Máy tính đã cài đặt **Docker Desktop** (trên Windows/macOS) hoặc **Docker Engine & Docker Compose** (trên Linux).
2. **Khởi chạy DVWA**:
   Mở terminal tại thư mục gốc của dự án và chạy:
   ```bash
   cd DVWA
   docker compose up -d
   ```
3. **Kiểm tra trạng thái container**:
   ```bash
   docker compose ps
   ```
   Ứng dụng DVWA sẽ chạy tại cổng **`4280`** (`http://127.0.0.1:4280`).

4. **Khởi tạo cơ sở dữ liệu DVWA**:
   - Mở trình duyệt và truy cập: **`http://127.0.0.1:4280/setup.php`**
   - Kéo xuống dưới cùng và nhấn nút **`Create / Reset Database`**.
   - Sau khi hệ thống tạo xong bảng và dữ liệu mẫu, bạn sẽ được tự động chuyển hướng đến trang đăng nhập `http://127.0.0.1:4280/login.php`.
   - **Tài khoản đăng nhập mặc định**:
     - **Username**: `admin`
     - **Password**: `password`

5. **Thiết lập mức độ bảo mật (DVWA Security)**:
   - Sau khi đăng nhập, chọn mục **DVWA Security** ở menu bên trái.
   - Chọn mức độ **`Low`** (hoặc `Medium`) rồi nhấn **Submit** để phục vụ việc kiểm thử các kịch bản khai thác.

---

### Cách 2: Chạy trực tiếp trên máy chủ Apache/PHP (XAMPP hoặc Linux LAMP)

Nếu không sử dụng Docker, bạn có thể triển khai thư mục `DVWA/` trên web server cục bộ:
1. Sao chép toàn bộ thư mục `DVWA` vào thư mục gốc của web server:
   - Trên XAMPP (Windows): `C:\xampp\htdocs\DVWA`
   - Trên Ubuntu/Debian: `/var/www/html/dvwa`
2. Tạo tệp cấu hình kết nối database:
   - Sao chép tệp `DVWA/config/config.inc.php.dist` thành `DVWA/config/config.inc.php`.
   - Mở file `config.inc.php` và điền thông số MySQL/MariaDB của bạn (host, user, password, database).
3. Đảm bảo cấu hình PHP (`php.ini`):
   ```ini
   allow_url_include = On
   allow_url_fopen = On
   display_errors = Off
   ```
4. Truy cập `http://localhost/dvwa/setup.php` và nhấn **`Create / Reset Database`**.

---

## 3. HƯỚNG DẪN CÀI ĐẶT MÔI TRƯỜNG DỰ ÁN

### 1. Yêu cầu hệ thống
- **Python**: Phiên bản 3.9 trở lên (Khuyên dùng 3.10 - 3.12).
- Các hệ điều hành được hỗ trợ: Windows 10/11, Ubuntu/Debian, Kali Linux, macOS.

### 2. Cài đặt các thư viện cần thiết
Từ thư mục gốc dự án `ATCSDL/`, mở terminal và chạy lệnh:
```bash
pip install -r requirements.txt
```
*Các thư viện chính bao gồm: `scikit-learn`, `pandas`, `numpy`, `matplotlib`, `seaborn`, `joblib`.*

---

## 4. HƯỚNG DẪN SỬ DỤNG HỆ THỐNG

### Cách 1: Khởi chạy Giao diện Giám sát An ninh SOC Dashboard (Khuyên dùng)
Hệ thống SOC Dashboard cho phép giám sát các request theo thời gian thực, trực quan hóa nguy cơ và điều chỉnh độ nhạy:

```bash
python dashboard/dashboard_backend.py
```
Sau khi chạy, mở trình duyệt web và truy cập địa chỉ:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

**Các tính năng trên giao diện Dashboard:**
1. **Live Threat Monitoring Stream**: Bảng theo dõi trực tiếp các request HTTP được phân tích bởi AI Engine. Gán nhãn trực quan:
   - <span style="color: #059669; font-weight: bold;">SAFE (NORMAL)</span>: Yêu cầu an toàn, hợp lệ.
   - <span style="color: #dc2626; font-weight: bold;">CRITICAL THREAT (BLOCKED)</span>: Yêu cầu phát hiện mã độc SQL Injection.
2. **Attack Type Breakdown (Biểu đồ cột nằm ngang)**: Thống kê số lượng theo từng nhóm tấn công (`UNION`, `Boolean`, `Time-based`, `Error-based`, `JSON`, `Normal`) với mã màu riêng biệt, lấp đầy không gian hiển thị, không bị khoảng trống thừa.
3. **Thanh trượt Alert Threshold (Ngưỡng cảnh báo)**: Cho phép chuyên viên SOC điều chỉnh độ nhạy (từ `0.10` đến `0.95`). Yêu cầu có xác suất nguy cơ vượt ngưỡng sẽ ngay lập tức kích hoạt cảnh báo an ninh.
4. **Modal kiểm tra chi tiết (Request Inspection Modal)**: Nhấp chuột vào bất kỳ dòng nào trên bảng để xem chi tiết toàn bộ Payload, URL, Phương thức HTTP, Xác suất nguy cơ và các chỉ số vi phạm (Threat Indicators).

---

### Cách 2: Tự động chạy Toàn bộ Pipeline (Sinh Data -> Trích xuất -> Huấn luyện)
Nếu bạn muốn tái tạo lại toàn bộ dữ liệu mẫu, bóc tách log và huấn luyện lại mô hình:

```bash
python run_pipeline.py
```

**Quy trình 6 bước được thực thi tự động:**
1. **Bước 1**: Sinh 13,000+ payload SQLi đa chiến lược và payload hợp lệ (bao gồm cấu trúc JSON lồng nhau).
2. **Bước 2**: Giả lập phát lưu lượng HTTP GET/POST và ghi nhật ký máy chủ `data/raw_logs/access.log`.
3. **Bước 3**: Bóc tách log Apache, đệ quy phẳng hóa các giá trị JSON (`json_depth`, `body_length`, `param_count_body`).
4. **Bước 4**: Làm sạch, loại bỏ bản ghi trùng lặp và gán nhãn nhị phân chuẩn xác.
5. **Bước 5**: Trích xuất 84 đặc trưng số học kết hợp vector Character N-grams TF-IDF.
6. **Bước 6**: Huấn luyện Random Forest với kỹ thuật phân chia theo họ `GroupShuffleSplit` (đảm bảo không rò rỉ dữ liệu giữa tập Train và Test), sau đó lưu mô hình vào thư mục `models/` và xuất báo cáo vào `reports/`.

---

### Cách 3: Sử dụng Công cụ Dòng lệnh (CLI) Dự đoán Request Nhanh (`predict.py`)
Bạn có thể kiểm tra một URL hoặc nội dung HTTP request bất kỳ trực tiếp từ terminal:

#### A. Kiểm tra request HTTP GET:
```bash
python predict.py "GET /vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users# HTTP/1.1"
```

#### B. Kiểm tra request HTTP POST với định dạng JSON API:
```bash
# Kiểm tra request JSON chứa mã độc SQLi (Bị phát hiện và cảnh báo 100%)
python predict.py --method POST --url /api/v1/auth --body "{\"username\": \"admin' OR 1=1-- -\", \"password\": \"123\"}" --content-type application/json

# Kiểm tra request JSON thông thường (Được phân loại là SAFE / Normal)
python predict.py --method POST --url /api/v1/search --body "{\"search\": \"dien thoai thong minh\", \"page\": 1}" --content-type application/json
```

#### C. Chạy bộ mẫu thử nghiệm tự động:
```bash
python predict.py
```
Lệnh trên sẽ tự động duyệt qua các kịch bản mẫu (GET sạch, GET SQLi kinh điển, POST Form, POST JSON sạch, POST JSON SQLi lồng nhau) và in kết quả đánh giá chi tiết ra màn hình.

---

### Cách 4: Chạy Bài Kiểm Thử An Ninh Đối Kháng & Đo Độ Trễ (Benchmarks)
Đánh giá độ vững chắc của mô hình trước các kỹ thuật né tránh (Evasion/Bypass), tỷ lệ dương tính giả (FPR) và thời gian phản hồi:

```bash
python tests/test_security_benchmarks.py
```

**Kết quả thực nghiệm nổi bật:**
- **Khả năng bắt giữ các kỹ thuật né tránh (Adversarial Robustness)**: **100.00%** (Phát hiện thành công 12/12 dạng tấn công né tránh phức tạp: Watermarking, Comment Obfuscation, Char Encoding, Nested Tautology, JSON Body Injection).
- **Tỷ lệ báo động giả (False Positive Rate - FPR)**: Đạt mức thấp đối với các mẫu ngôn ngữ tự nhiên và cấu trúc JSON thực tế.
- **Thời gian phân tích trung bình (Latency)**: **~63 ms / request**, đáp ứng tốt yêu cầu giám sát trực tuyến thời gian thực.

---

### Cách 5: Chạy Kiểm Thử Đơn Vị Hệ Thống (Unit Tests)
Kiểm tra tính toàn vẹn của mô hình phát hiện mối đe dọa:

```bash
python -m unittest tests/test_threat_detector.py
```

---

## 5. KẾT QUẢ ĐÁNH GIÁ MÔ HÌNH MACHINE LEARNING

Dự án đã thực hiện so sánh đánh giá hiệu năng giữa 3 thuật toán học máy phổ biến trên tập kiểm thử độc lập (Test Unseen):

| Thuật toán | Accuracy | Precision (SQLi) | Recall (SQLi) | F1-Score (SQLi) |
| :--- | :---: | :---: | :---: | :---: |
| **Random Forest (Khuyên dùng)** | **99.95%** | **99.91%** | **100.00%** | **99.96%** |
| Logistic Regression | 98.42% | 97.50% | 99.20% | 98.34% |
| Multinomial Naive Bayes | 95.80% | 93.10% | 98.90% | 95.91% |

> **Ghi chú an ninh quan trọng**: Đối với bài toán phát hiện xâm nhập mạng, chỉ số **Recall của lớp SQLi = 100.00%** là tối quan trọng, đồng nghĩa với việc không bỏ sót bất kỳ cuộc tấn công SQL Injection nào lọt qua hệ thống giám sát.

---

## 👥 TÁC GIẢ & THÔNG TIN NHÓM

* **Nhóm sinh viên thực hiện:** Nhóm 09 - Lớp INT14105-01
  * Đặng Trần Hải Đăng (B23DCAT036)
  * Phan Đức (B23DCAT056)
  * Nguyễn Anh Minh (B23DCAT196)
  * Hoàng Tiến Toàn (B23DCAT296)
* **Giảng viên hướng dẫn:** ThS. Ninh Thị Thu Trang
* **Đơn vị:** Khoa An toàn Thông tin - Học viện Công nghệ Bưu chính Viễn thông (PTIT).

