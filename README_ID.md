# Sistem Deteksi Web Phishing Berbasis Machine Learning

[![English Version](https://img.shields.io/badge/Language-English-blue.svg)](README.md)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.3+-f89939.svg)](https://scikit-learn.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-ff4b4b.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> 📖 **Bahasa / Language**: [English Version (Main README)](README.md) | **Bahasa Indonesia**

Sistem keamanan Machine Learning *end-to-end* yang dirancang untuk mendeteksi dan mengklasifikasikan URL tautan *phishing* secara *real-time* menggunakan **ekstraksi fitur leksikal** dan algoritma **Random Forest**.

Dikembangkan berdasarkan riset terapan dan implementasi lapangan selama program magang (Kuliah Praktik) di **Dinas Komunikasi dan Informatika (KOMINFO) Kota Prabumulih** berkolaborasi dengan **Universitas Sriwijaya**.

---

## 📌 Metadata Proyek

- **Penulis**: **M. Athallah Rafif Aldera, S.Kom.**
- **Institusi**: Program Studi S1 Sistem Komputer, Fakultas Ilmu Komputer, **Universitas Sriwijaya**
- **Mitra Sektor Publik**: **Dinas Komunikasi dan Informatika (KOMINFO) Kota Prabumulih**
- **Domain**: Applied Machine Learning, Cybersecurity, Web Security, Threat Detection
- **Teknologi**: Python, Scikit-Learn, Random Forest, FastAPI, Streamlit, Joblib

---

## 📄 Latar Belakang Masalah & Urgensi

Serangan tautan tiruan (*phishing*) merupakan ancaman siber paling umum yang menyerang portal layanan pemerintah dan masyarakat umum. Metode pertahanan konvensional mengandalkan *blacklist* statis yang lambat merespons domain baru (*zero-day threats*) serta memerlukan biaya operasional tinggi.

Proyek ini menghadirkan mesin pendeteksi risiko URL instan yang bekerja secara lokal tanpa bergantung pada koneksi jaringan luar saat memindai tautan. Dengan menganalisis 9 karakteristik struktural string URL, sistem mampu menghitung probabilitas ancaman dalam waktu kurang dari 5 milidetik secara aman.

---

## 📊 Hasil Evaluasi & Profil Dataset

Model dilatih dan dievaluasi menggunakan dataset rujukan berukuran **662.591 baris data mentah**. Setelah pembersihan data dengan menghapus 32.520 data hilang (*missing values* <5%), diperoleh **630.071 URL valid**.

### Persebaran Kelas (Data Riil Tidak Seimbang / Imbalanced)
- **Non-Phishing (Website Aman)**: 84,13%
- **Phishing (Website Berbahaya)**: 15,87%

### Hasil Metrik Evaluasi (Rasio Split 80:20)

| Metrik Evaluasi | Data Pelatihan (Training) | Data Pengujian (Testing) | Analisis Riset |
| :--- | :---: | :---: | :--- |
| **Akurasi** | **91,0%** | **89,0%** | Kemampuan klasifikasi global yang konsisten dan andal |
| **Presisi** | **81,2%** | **73,2%** | Presisi tinggi menjamin minimnya alarm palsu (*false positive*) |
| **Recall** | 56,0% | 49,0% | Karakteristik alami model pada distribusi data sangat timpang |
| **F1-Score** | 94,0% | 59,0% | Penurunan pada data uji mencerminkan tantangan generalisasi data riil |

---

## 🔍 Taksonomi 9 Fitur Leksikal URL

| # | Nama Fitur | Tipe Data | Deskripsi & Indikator Risiko |
| :-: | :--- | :---: | :--- |
| 1 | `NumDots` | Integer | Jumlah titik ('.'). Phishing kerap menumpuk subdomain untuk meniru situs resmi. |
| 2 | `UrlLength` | Integer | Panjang total URL. URL berbahaya umumnya panjang karena memuat parameter sesi enkripsi. |
| 3 | `NumDash` | Integer | Jumlah tanda minus ('-'). Sering disisipkan untuk memalsukan nama merek resmi. |
| 4 | `AtSymbol` | Binary | Keberadaan simbol '@'. Browser mengabaikan string sebelum '@' dan mengarah ke host baru. |
| 5 | `IpAddress` | Binary | Penggunaan IP address langsung (IPv4/IPv6) tanpa nama domain teregistrasi. |
| 6 | `HttpsInHostname` | Binary | Sisipan teks 'https' pada subdomain untuk mengecoh pengguna awam. |
| 7 | `PathLevel` | Integer | Kedalaman hierarki direktori URL (jumlah segmen slash '/'). |
| 8 | `PathLength` | Integer | Panjang karakter dari bagian path URL. |
| 9 | `NumNumericChars` | Integer | Total jumlah karakter angka (0-9) di seluruh URL. |

---

## 🚀 Panduan Eksekusi Cepat

### 1. Menjalankan Pengujian Mandiri
```bash
python test_phishing.py
```

### 2. Menjalankan Web UI Interaktif (Streamlit)
```bash
streamlit run app.py
```

### 3. Menjalankan REST API Server (FastAPI)
```bash
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

Akses dokumentasi interaktif Swagger UI pada `http://localhost:8000/docs`.

---

## 📜 Hak Cipta & Lisensi

- Penulis: **M. Athallah Rafif Aldera, S.Kom.**
- Institusi: **Universitas Sriwijaya** & **Dinas KOMINFO Kota Prabumulih**
- Lisensi: [MIT License](LICENSE).
