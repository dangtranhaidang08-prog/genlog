# HỆ THỐNG PHÁT HIỆN TẤN CÔNG SQL INJECTION & GIÁM SÁT AN NINH SOC BẰNG MACHINE LEARNING

> **Giải pháp an ninh mạng toàn diện:** Tự động hóa phân tích log Apache, trích xuất đặc trưng đa tầng (Hybrid Feature Space), huấn luyện mô hình Machine Learning chống rò rỉ dữ liệu triệt để, và giám sát cảnh báo thời gian thực trên Web SOC Dashboard với cơ chế giải thích AI (Explainable AI).

---

## 📌 TỔNG QUAN HỆ THỐNG

Dự án xây dựng một hệ thống phòng thủ và phát hiện xâm nhập chuyên sâu cho ứng dụng Web, tập trung vào kỹ thuật tấn công **SQL Injection (SQLi)** — lỗ hổng thuộc Top 3 OWASP Web Application Security Risks.

Hệ thống hoạt động theo cơ chế **Pre-Execution Threat Inspection** (kiểm định và phát hiện mối đe dọa ngay từ tầng HTTP Request và Apache Access Log trước khi truy vấn chạm tới máy chủ cơ sở dữ liệu), kết hợp giữa:
1. **Engine trích xuất 64 đặc trưng cấu trúc tĩnh & cú pháp HTTP** (độ dài, entropy Shannon, ký tự đặc biệt, cấu trúc từ khóa SQL, độ lệch tỷ lệ).
2. **Bộ biểu diễn ký tự vi mô (Character N-grams TF-IDF)** nắm bắt dấu hiệu xáo trộn (obfuscation), mã hóa hex/URL encoding và các mẫu payload dị thường.
3. **Mô hình Random Forest Classifier (300 cây)** được huấn luyện qua kỹ thuật **5-Fold Grouped Cross-Validation** (phân nhóm template chống rò rỉ biến thể) kết hợp cơ chế **Validation Threshold Tuning** để tối ưu $F_1$-Score và giảm thiểu tối đa tỷ lệ báo động giả (FPR).
4. **Trung tâm giám sát an ninh SOC Web Dashboard** hỗ trợ điều tra thời gian thực, điều chỉnh ngưỡng nhạy động và minh bạch hóa quyết định của mô hình AI (Explainable Indicators).

---

## 🏗️ CẤU TRÚC THƯ MỤC DỰ ÁN

```text
ATCSDL/
├── config/                                 # Quản lý cấu hình tập trung
│   ├── settings.py                         # Single source of truth cho đường dẫn, ngưỡng và biến môi trường
│   └── __init__.py
│
├── dashboard/                              # Hệ thống Web SOC Dashboard giám sát an ninh thời gian thực
│   ├── backend/                            # Server backend & luồng xử lý sự kiện
│   │   ├── collector.py                    # Thu thập log từ file local hoặc tail qua SSH/SFTP
│   │   ├── store.py                        # Hàng đợi sự kiện Thread-safe (EventStore)
│   │   ├── dashboard_backend.py            # API Server & tích hợp engine phân tích ThreatDetector
│   │   └── __init__.py
│   └── frontend/                           # Giao diện web trực quan hóa
│       ├── css/style.css                   # Định dạng giao diện SOC Dashboard
│       ├── js/app.js                       # Stream sự kiện, đồ thị biểu đồ và gọi API
│       └── index.html                      # Bảng điều khiển KPI, danh sách cảnh báo & công cụ kiểm tra URL
│
├── data/                                   # Phân tầng quản lý dữ liệu huấn luyện
│   ├── payloads/                           # Kho payload mẫu
│   │   ├── payloads_all.csv                # Toàn bộ payload phân loại theo nhóm tấn công
│   │   ├── train.csv                       # Payload tập huấn luyện
│   │   ├── val.csv                         # Payload tập kiểm định (Validation)
│   │   └── test_unseen.csv                 # 2.250 payload tấn công mới lạ (Unseen Benchmark)
│   ├── raw/                                # Log thô từ Web Server
│   │   └── access.log                      # Apache Access Log thô
│   ├── processed/                          # Dữ liệu sạch sau tiền xử lý
│   │   ├── apache_logs.csv                 # 15.755 bản ghi log bóc tách từ access.log
│   │   ├── dataset.csv                     # 14.088 mẫu sạch sau khi khử trùng lặp & che giấu CSRF token
│   │   └── client_requests.csv             # Bản ghi lưu lượng client phục vụ kiểm thử
│   └── features/                           # Không gian đặc trưng số học
│       └── features.csv                    # Ma trận đặc trưng trích xuất phục vụ huấn luyện
│
├── models/current/                         # Artifacts của mô hình AI phục vụ dự đoán
│   ├── sqli_rf_model.pkl                   # Trọng số mô hình Random Forest (300 estimators)
│   ├── tfidf_vectorizer.pkl                # Bộ biến đổi Char TF-IDF Vectorizer (300 features)
│   ├── feature_columns.pkl                 # Whitelist 64 đặc trưng số học tiền thực thi
│   └── metadata.json                       # Siêu dữ liệu mô hình, phiên bản, ngưỡng và chỉ số đánh giá
│
├── reports/                                # Báo cáo số liệu và trực quan hóa mô hình
│   ├── classification_report.txt           # Báo cáo đánh giá chi tiết Precision, Recall, F1 trên tập Test
│   ├── metrics.json                        # Toàn bộ chỉ số CV, Validation, Test & Unseen Benchmark (JSON)
│   ├── confusion_matrix.png                # Ma trận nhầm lẫn (Confusion Matrix) trực quan
│   ├── feature_importance.png              # Biểu đồ Top 25 đặc trưng quan trọng nhất
│   ├── dataset_report.txt                  # Thống kê phân bố lớp dữ liệu
│   └── parse_stats.json                    # Báo cáo tỷ lệ parse log thành công
│
├── scripts/                                # Kịch bản tự động hóa và tiện ích dòng lệnh
│   ├── run_pipeline.py                     # Kịch bản thực thi khép kín toàn bộ 4 bước pipeline
│   ├── predict.py                          # CLI kiểm tra, dự đoán nhãn và xác suất cho URL/Payload
│   ├── start_dashboard.py                  # Khởi chạy SOC Monitoring Dashboard Server
│   └── run_tests.py                        # Chạy toàn bộ 45 unit tests tự động
│
├── src/                                    # Mã nguồn lõi (Clean Architecture)
│   ├── collectors/                         # Sinh payload và tạo lưu lượng mô phỏng
│   │   ├── payload_generator.py            # Sinh 20 nhóm payload (UNION, Blind Time, Error, Auth Bypass...)
│   │   └── traffic_generator.py            # Gửi HTTP request tới target DVWA và ghi log
│   ├── data_processing/                    # Tiền xử lý dữ liệu và trích xuất đặc trưng
│   │   ├── apache_parser.py                # Phân tích cú pháp Apache Combined Log Format
│   │   ├── dataset_builder.py              # Che giấu CSRF token, khử trùng lặp và gán nhãn
│   │   └── feature_extractor.py            # Trích xuất 64 đặc trưng số học + TF-IDF
│   ├── detector/                           # Module phát hiện và suy luận thời gian thực
│   │   └── threat_detector.py              # Lớp ThreatDetector tích hợp XAI Indicators
│   └── training/                           # Huấn luyện và đánh giá mô hình học máy
│       └── train_model.py                  # 5-Fold Grouped CV, Validation Threshold Tuning, Test Benchmark
│
├── tests/                                  # Hệ thống kiểm thử tự động (Unit & Integration Tests)
│   ├── unit/                               # 45 Unit Tests kiểm thử độc lập từng module
│   │   ├── test_apache_parser.py           # Kiểm thử độ chịu lỗi cú pháp log
│   │   ├── test_collectors.py              # Kiểm thử sinh payload, chia nhóm và kiểm soát rò rỉ
│   │   ├── test_feature_extractor.py       # Kiểm thử trích xuất 64 đặc trưng số học
│   │   ├── test_threat_detector.py         # Kiểm thử suy luận, điều chỉnh ngưỡng và XAI
│   │   └── test_train_pipeline.py          # Kiểm thử phân nhóm template, CV và load artifact
│   └── integration/                        # Kiểm thử tích hợp toàn bộ pipeline
│
├── .env.example                            # File cấu hình mẫu cho các biến môi trường
├── .gitignore                              # Danh sách file và thư mục loại trừ khỏi Git
├── pyproject.toml                          # Cấu hình dự án Python
├── pyrightconfig.json                      # Cấu hình Type-checker (Pyright)
└── requirements.txt                        # Danh sách các thư viện phụ thuộc
```

---

## ⚙️ PIPELINE XỬ LÝ DỮ LIỆU & HUẤN LUYỆN KHÉP KÍN

Hệ thống được thiết kế theo luồng xử lý tự động 4 bước tuần tự:

```
[ access.log ] 
      │
      ▼ (Bước 1: apache_parser.py)
[ apache_logs.csv ] (15.755 bản ghi cấu trúc hóa)
      │
      ▼ (Bước 2: dataset_builder.py)
[ dataset.csv ] (14.088 mẫu sạch - Masking CSRF Token, deduplication)
      │
      ▼ (Bước 3: feature_extractor.py)
[ features.csv ] (Ma trận 64 đặc trưng số + 300 TF-IDF vi mô)
      │
      ▼ (Bước 4: train_model.py)
[ models/current/ ] & [ reports/ ] (Random Forest, Grouped CV, Val Tuning, Reports)
```

1. **Bước 1 — Phân tích cú pháp Apache Access Log (`apache_parser.py`):**
   - Đọc tệp nhật ký `data/raw/access.log` định dạng Apache Combined Log Format kèm Response Time.
   - Bóc tách chuẩn xác: IP, Timestamp, Method, URL path, Query string, Protocol, Status code, Response size, Referer, User-Agent.
   - Xử lý triệt để ký tự escape, dấu ngoặc kép lồng nhau và mã hóa URL.

2. **Bước 2 — Tiền xử lý, bảo mật dữ liệu & gán nhãn (`dataset_builder.py`):**
   - Loại bỏ các request tĩnh (.css, .js, .ico, .png, .jpg).
   - Che giấu tự động các token nhạy cảm (`user_token=[MASKED]`) để chống mô hình học vẹt (overfitting) các chuỗi bảo mật ngẫu nhiên.
   - Gán nhãn tự động (`label = 1` cho SQLi, `label = 0` cho Normal).

3. **Bước 3 — Trích xuất vector đặc trưng đa tầng (`feature_extractor.py`):**
   - **Whitelist 64 đặc trưng số học tiền thực thi:**
     - Đặc trưng chiều dài & tỷ lệ (URL length, query length, path length, digit ratio, letter ratio, uppercase ratio).
     - Đặc trưng entropy Shannon (đo mức độ ngẫu nhiên/mã hóa của chuỗi payload).
     - Đặc trưng ký tự đặc biệt nguy hiểm (số lượng dấu `'`, `"`, `--`, `#`, `/*`, `;`, `=`, `(`, `)`, `%`, `+`).
     - Đặc trưng từ khóa SQL trọng yếu (`UNION`, `SELECT`, `FROM`, `WHERE`, `AND`, `OR`, `SLEEP`, `BENCHMARK`, `SCHEMA`, `CONCAT`, v.v.).
     - Dấu hiệu HTTP Form-Data và Header dị thường.
   - **300 đặc trưng chuỗi ký tự vi mô (Character N-grams TF-IDF):** Phân tích sub-word n-grams $(2, 4)$ giúp phát hiện các kỹ thuật bypass bộ lọc (case alteration như `uNiOn`, xen kẽ khoảng trắng, comment chèn giữa từ khóa).

4. **Bước 4 — Huấn luyện & Đánh giá an toàn (`train_model.py`):**
   - **Chống rò rỉ dữ liệu triệt để (Zero Data Leakage):**
     - Phân nhóm dựa trên Template băm (`extract_payload_template`) giúp các biến thể của cùng một payload không bao giờ vừa nằm ở tập Train vừa nằm ở tập Test.
     - Bộ chuyển đổi TF-IDF Vectorizer chỉ học từ điển trên tập Train của từng fold, không bao giờ fit trên toàn bộ dữ liệu.
   - **5-Fold Grouped Cross-Validation:** Đo lường độ ổn định của mô hình qua 5 lần chia nhóm độc lập.
   - **Validation Threshold Tuning:** Tinh chỉnh ngưỡng phân loại tối ưu trên tập Validation (chọn ngưỡng đạt $F_1$ cao nhất trong khi vẫn kiểm soát chặt chẽ tỷ lệ báo động giả $FPR \le 5\%$).

---

## 📊 KẾT QUẢ HIỆU NĂNG MÔ HÌNH

### 1. Phân chia tập dữ liệu huấn luyện
- **Tổng số mẫu sạch:** **14.088** bản ghi (Normal: 7.908 | SQLi: 6.180)
- **Tập Train:** 9.901 mẫu (70,3%)
- **Tập Validation:** 2.120 mẫu (15,0%)
- **Tập Test độc lập:** 2.067 mẫu (14,7%)
- **Tập Unseen Payloads:** 2.250 mẫu (độc lập hoàn toàn về cú pháp)

### 2. So sánh hiệu năng các thuật toán trên tập Test độc lập
| Thuật toán | Accuracy | Precision | Recall (SQLi) | F1-Score | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Đề xuất)** | **96.86%** | **95.26%** | **97.99%** | **96.61%** | **0.9979** |
| Logistic Regression | 97.00% | 97.42% | 95.97% | 96.69% | 0.9950 |
| Multinomial Naive Bayes | 87.57% | 80.97% | 95.13% | 87.48% | 0.9412 |

- **5-Fold Grouped Cross-Validation F1:** $0.9583 \pm 0.0134$
- **Ngưỡng quyết định tối ưu (Optimal Threshold):** `0.25`
- **Tỷ lệ báo động sai (False Positive Rate - FPR):** `4.10%`
- **PR-AUC (Precision-Recall Curve):** `0.9976`

### 3. Đánh giá trên tập Payload mới lạ (Unseen Payloads Benchmark)
Kiểm thử trên 2.250 mẫu payload tấn công zero-day/chưa từng thấy trong tập train:
- **Độ chính xác (Accuracy):** `89.29%`
- **Độ chuẩn xác (Precision):** `98.09%` (rất ít báo động sai)
- **Độ nhạy (Recall):** `82.32%`
- **F1-Score:** `89.52%`

---

## 🚀 HƯỚNG DẪN CÀI ĐẶT & SỬ DỤNG

### 1. Yêu cầu môi trường
- Python 3.10 trở lên
- Hệ điều hành: Windows, Linux hoặc macOS

### 2. Cài đặt các thư viện phụ thuộc
```bash
# Clone dự án từ GitHub
git clone https://github.com/dangtranhaidang08-prog/genlog.git
cd genlog

# Tạo và kích hoạt môi trường ảo (khuyến nghị)
python -m venv venv
# Trên Windows:
venv\Scripts\activate
# Trên Linux/macOS:
source venv/bin/activate

# Cài đặt dependencies
pip install -r requirements.txt
```

### 3. Cấu hình biến môi trường
Tạo file `.env` từ file mẫu `.env.example`:
```bash
cp .env.example .env
```
Nội dung file `.env` có thể tùy biến các thông số:
```ini
TARGET_WEB_URL=http://127.0.0.1:80/
DASHBOARD_HOST=127.0.0.1
DASHBOARD_PORT=5000
DETECTION_THRESHOLD=0.25
```

---

## 💻 HƯỚNG DẪN THỰC THI CHI TIẾT

### A. Chạy toàn bộ luồng tự động (Full Pipeline Runner)
Nếu bạn đã có sẵn file `data/raw/access.log`, thực hiện toàn bộ 4 bước phân tích, trích xuất đặc trưng và huấn luyện mô hình:
```bash
python scripts/run_pipeline.py --skip-gen
```

### B. Khởi chạy Web SOC Monitoring Dashboard
Khởi chạy giao diện giám sát an ninh thời gian thực:
```bash
python scripts/start_dashboard.py
```
- Mở trình duyệt web và truy cập: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**
- **Tính năng trên Dashboard:**
  - Theo dõi biểu đồ số lượng tấn công vs lưu lượng bình thường.
  - Phân tích chi tiết từng yêu cầu: IP, thời gian, URL, dự đoán nhãn và xác suất.
  - **Dynamic Threshold Slider:** Kéo thả để thay đổi độ nhạy của AI trong thời gian thực.
  - **URL / Payload Inspector:** Nhập thủ công một URL hoặc câu lệnh SQL để kiểm tra kết quả phân tích và nguyên nhân cảnh báo ngay lập tức.

### C. Dự đoán nhanh qua dòng lệnh (CLI Prediction)
Sử dụng công cụ `scripts/predict.py` để kiểm tra độ nguy hiểm của một URL hoặc chuỗi payload bất kỳ:

*Kiểm tra URL tấn công SQLi:*
```bash
python scripts/predict.py --url "http://127.0.0.1/vulnerabilities/sqli/?id=1' UNION SELECT 1,version()--"
```
*Kết quả:*
```text
====================================
SQL INJECTION PREDICTION
====================================
Request:      GET /vulnerabilities/sqli/?id=1' UNION SELECT 1,version()-- HTTP/1.1
Prediction:   SQL Injection
Label:        1
Probability:
  SQLi:       1.0000
  Normal:     0.0000

Detected indicators:
- Single quote (') character detected
- UNION SELECT multi-table extraction sequence
- SQL comment syntax (-- or # or /*)
====================================
```

*Kiểm tra URL hợp lệ:*
```bash
python scripts/predict.py --url "http://127.0.0.1/index.php?page=products&category=2"
```
*Kết quả:*
```text
Prediction:   Normal
Probability:  SQLi: 0.0067 | Normal: 0.9933
Detected indicators:
- Clean HTTP payload structure
```

### D. Chạy bộ kiểm thử tự động (Unit Tests)
Dự án bao gồm 45 kiểm thử đơn vị bao phủ toàn diện:
```bash
python scripts/run_tests.py
```
*Kết quả:*
```text
Ran 45 tests in 4.930s
OK (45/45 passed)
```

---

## 🛡️ NGUYÊN TẮC BẢO MẬT & CHỐNG RÒ RỈ THÔNG TIN

- **Không lưu trữ Secret/Credential trong mã nguồn:** Toàn bộ thông tin nhạy cảm (mật khẩu SSH, private IP mạng lab) được trừu tượng hóa qua biến môi trường (`os.environ`) với giá trị fallback an toàn (`127.0.0.1`).
- **Khử trùng dữ liệu huấn luyện:** Các token CSRF (`user_token`), Session Cookie được che giấu (`[MASKED]`) trước khi đưa vào mô hình học máy.
- **Tuân thủ Git standard:** File nhật ký thô lớn (`data/raw/access.log`), môi trường ảo (`venv/`), và các file tạm của IDE (`.vscode/`, `.idea/`) đều được cấu hình trong `.gitignore`.

---

## 📄 GIẤY PHÉP (LICENSE)
Dự án được phân phối dưới giấy phép mã nguồn mở MIT License. Phục vụ cho mục đích nghiên cứu, học tập và triển khai thực tế trong lĩnh vực an toàn thông tin và bảo mật ứng dụng web.
