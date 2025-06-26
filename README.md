# **SecureAuth API: Sistem Otentikasi & Manajemen Identitas**

**SecureAuth API** adalah sebuah API manajemen otentikasi dan identitas yang aman, siap produksi, dan kaya akan fitur. Dibangun dengan **FastAPI**, proyek ini menyediakan fondasi yang kokoh untuk mengelola pengguna, sesi, dan keamanan aplikasi modern dengan praktik terbaik di industri.

## **Fitur Utama**

Repositori ini mencakup berbagai fitur keamanan dan manajemen pengguna yang komprehensif.

### **Keamanan Inti (Core Security)**

  - **Otentikasi Berbasis JWT**: Implementasi *access token* dan *refresh token* yang aman untuk manajemen sesi.
  - **Password Hashing Kuat**: Menggunakan **Argon2** untuk hashing password yang tahan terhadap serangan modern.
  - **Kebijakan Password**: Aturan ketat untuk kekuatan password, termasuk panjang minimum, huruf besar/kecil, angka, dan karakter spesial.
  - **Riwayat Password**: Mencegah pengguna menggunakan kembali password lama untuk meningkatkan keamanan.
  - **Perlindungan CSRF**: *Double Submit Cookie pattern* untuk melindungi dari serangan Cross-Site Request Forgery.
  - **Enkripsi Data Sensitif**: Menggunakan **Fernet (Cryptography)** untuk mengenkripsi data sensitif seperti secret key 2FA.
  - **CORS & Security Headers**: Konfigurasi middleware untuk CORS yang ketat dan HTTP Security Headers (CSP, HSTS, X-XSS-Protection) untuk melindungi dari serangan web umum.

### **Manajemen Pengguna & Akun**

  - **Registrasi Pengguna**: Alur pendaftaran dengan verifikasi email otomatis.
  - **Manajemen Profil**: Pengguna dapat melihat dan memperbarui profil mereka.
  - **Reset Password**: Alur reset password yang aman melalui email dengan token sekali pakai.
  - **Verifikasi Email**: Memastikan setiap pengguna memiliki email yang valid.
  - **Perlindungan Account Lockout**: Akun akan terkunci secara otomatis setelah beberapa kali percobaan login gagal.

### **Fitur Lanjutan (Advanced Features)**

  - **Two-Factor Authentication (2FA)**: Dukungan untuk TOTP (Time-based One-Time Password) dan backup codes.
  - **Manajemen Sesi Tingkat Lanjut**: Pengguna dapat melihat dan mencabut sesi aktif dari perangkat lain.
  - **Pelacakan Perangkat (*Device Tracking*)**: Melacak perangkat yang digunakan untuk login dan fitur "Trust this device" untuk melewati 2FA.
  - **Rate Limiting**: Pembatasan permintaan per IP dan per pengguna menggunakan Redis untuk mencegah serangan *brute-force* dan penyalahgunaan.
  - **Logging Audit Komprehensif**: Mencatat semua tindakan penting terkait keamanan (login, perubahan password, dll.) untuk keperluan audit dan pemantauan.

## **Tumpukan Teknologi (Tech Stack)**

  - **Backend**: FastAPI, Python 3.11+
  - **Database**: PostgreSQL (dengan `asyncpg`)
  - **Manajemen Migrasi**: Alembic
  - **Cache & Rate Limiting**: Redis
  - **Validasi Data**: Pydantic
  - **Testing**: Pytest, pytest-asyncio, HTTPX
  - **Deployment**: Docker & Docker Compose
  - **Server**: Uvicorn, Nginx (sebagai reverse proxy)
  - **Email**: SMTP dengan Mailhog untuk development

## **Struktur Proyek**

```
.
├── app/
│   ├── api/                # Modul API dengan versi (v1)
│   │   ├── dependencies/   # Dependensi FastAPI (auth, db, rate limit)
│   │   └── v1/             # Endpoints untuk API v1 (auth, users, health)
│   ├── core/               # Konfigurasi, security, exceptions, konstanta
│   ├── db/                 # Manajemen Database (session, base model, migrasi)
│   ├── middleware/         # Custom middleware (logging, error handling, security)
│   ├── models/             # Model SQLAlchemy untuk tabel database
│   ├── schemas/            # Skema Pydantic untuk validasi request/response
│   ├── services/           # Logika bisnis (auth, user, email, token)
│   ├── utils/              # Utilitas (validators, sanitizers)
│   └── main.py             # Entrypoint aplikasi FastAPI
├── scripts/                # Skrip bantuan (init db, create admin)
├── tests/                  # Test suite menggunakan Pytest
├── alembic.ini             # Konfigurasi Alembic
├── docker-compose.yml      # Konfigurasi Docker Compose
├── Dockerfile              # Dockerfile untuk aplikasi API
└── requirements.txt        # Dependensi Python
```

## **Memulai (Getting Started)**

Metode yang direkomendasikan untuk menjalankan proyek ini adalah menggunakan Docker.

### **Prasyarat**

  - Docker
  - Docker Compose

### **Instalasi dengan Docker**

1.  **Clone Repositori**

    ```bash
    git clone https://github.com/GratiaManullang03/login.git
    cd login
    ```

2.  **Konfigurasi Environment**
    Buat file `.env` di root direktori. Anda dapat menyalin dari `app/core/config.py` sebagai template atau membuat yang baru. Jalankan skrip `generate_keys.py` untuk menghasilkan semua kunci keamanan yang diperlukan.

    ```bash
    # Membuat file .env kosong (jika belum ada)
    touch .env

    # Menjalankan skrip untuk mengisi .env dengan kunci keamanan
    python3 scripts/generate_keys.py
    ```

    Skrip ini akan mengisi variabel seperti `SECRET_KEY`, `ENCRYPTION_KEY`, dll. di dalam file `.env` Anda.

3.  **Jalankan dengan Docker Compose**
    Dari direktori root, jalankan perintah berikut untuk membangun dan menjalankan semua layanan:

    ```bash
    docker-compose up --build
    ```

    Perintah ini akan menjalankan container di *foreground* dan menampilkan log secara langsung.

4.  **Akses Aplikasi**

      - **API**: `http://localhost:8000`
      - **Dokumentasi API (Swagger)**: `http://localhost:8000/docs`
      - **Mailhog (Testing Email)**: `http://localhost:8025`

### **Perintah Docker Umum**

Berikut adalah beberapa perintah `docker-compose` yang berguna:

  - **Menjalankan di Latar Belakang (Detached Mode)**:
    Untuk membangun dan menjalankan container di latar belakang.

    ```bash
    docker-compose up -d --build
    ```

  - **Melihat Log Layanan**:
    Untuk melihat log dari layanan API secara *real-time*.

    ```bash
    docker-compose logs -f api
    ```

  - **Menghentikan dan Menghapus Semua**:
    Untuk menghentikan semua layanan dan menghapus container beserta volumenya (termasuk data di database).

    ```bash
    docker-compose down -v
    ```

### **Membuat Admin User Pertama**

Setelah container berjalan, Anda dapat membuat pengguna admin pertama dengan skrip interaktif:

```bash
docker-compose exec api python scripts/create_admin.py
```

Ikuti petunjuk di terminal untuk memasukkan email, username, dan password.

## **Menjalankan Tes**

Untuk menjalankan test suite, gunakan perintah berikut:

```bash
docker-compose exec api pytest
```