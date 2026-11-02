# 🔧 Troubleshooting: FieldCryptError - Master Key Mismatch

Jika Anda melihat error seperti ini saat menjalankan aplikasi:
```
utils.fieldcrypt.FieldCryptError: This app has encountered an error...
Kolom terenkripsi tidak dapat dibuka dengan master key yang tersedia.
```

## 🔍 Diagnosis Cepat

Jalankan command diagnosis CLI:
```powershell
python -m tools.manage diagnose-key
```

Command ini akan:
- Memeriksa apakah file database ada
- Menampilkan semua master keys yang tersedia
- Mencoba dekripsi data sample
- Memberikan solusi spesifik sesuai masalah

## 💡 Solusi Berdasarkan Skenario

### Skenario 1: Database Baru (Development/Demo)
**Gejala:** Database baru dibuat, tapi error muncul saat access
**Penyebab:** Kunci enkripsi berubah atau inkonsisten dengan data lama

**Solusi Cepat:**
```powershell
# Hapus database lama dan kunci
Remove-Item -Path "D:\csmcd\SeMediChain\data\stegomed.db" -Force
Remove-Item -Path "D:\csmcd\SeMediChain\data\.master_key" -Force

# Jalankan ulang aplikasi - database akan di-generate ulang
streamlit run app.py
```

### Skenario 2: Pindah Perangkat / Ganti Folder
**Gejala:** Database dari perangkat/folder lama tidak bisa dibuka

**Penyebab:** Master key lama tidak tersedia

**Solusi:**
```powershell
# Jika Anda masih punya file .master_key lama:
# 1. Copy file .master_key lama ke data/
# 2. Atau set di .env:
# MEDICRYPT_MASTER_KEY=<kunci_lama>

# Lalu jalankan rotasi kunci:
python -m tools.manage rotate-master
```

### Skenario 3: Production - Data Penting
**Gejala:** Database besar dengan data real yang penting

**Penyebab:** Master key lama hilang atau tidak cocok

**Solusi Aman:**
```powershell
# 1. Backup database terlebih dahulu
python -m tools.manage backup --out backup_$(date +%Y%m%d_%H%M%S).tar.gz

# 2. Diagnose untuk confirm masalah
python -m tools.manage diagnose-key

# 3. Hubungi DevOps/Admin dengan laporan diagnosis
# Atau jika ada backup dari saat kunci masih cocok:
python -m tools.manage restore --file backup_xxxx.tar.gz
```

## 🚀 Untuk Development (Rekomendasi)

Gunakan environment variable `.env` agar kunci tetap konsisten:

```env
APP_ENV=demo
DATABASE_URL=sqlite:///data/demo_v2.db
MEDICRYPT_MASTER_KEY=my-demo-key-12345678901234567890
ALLOW_DEV_WALLET=1
AUTO_APPROVE_DOCTORS=1
```

Dengan ini, kunci selalu sama meski aplikasi di-restart berkali-kali.

## 📋 Checklist Ketika Error

- [ ] Jalankan `python -m tools.manage diagnose-key` untuk confirm masalah
- [ ] Periksa file `.master_key` ada di folder `data/`
- [ ] Periksa env var `MEDICRYPT_MASTER_KEY` di `.env` (jika ada)
- [ ] Pastikan database `stegomed.db` atau `demo_v2.db` ada
- [ ] Jika data lama tidak penting: hapus database dan kunci, jalankan ulang
- [ ] Jika data penting: hubungi admin dengan output dari `diagnose-key`

## ✅ Cara Cegah Error Di Masa Depan

1. **Gunakan `.env` dengan MEDICRYPT_MASTER_KEY yang fixed** (jangan auto-generated)
2. **Backup database secara berkala** dengan `python -m tools.manage backup`
3. **Catat master key Anda** di tempat aman (vault/password manager)
4. **Test recovery procedure** sebelum production

---

**Butuh bantuan lebih lanjut?** Lihat output dari `python -m tools.manage diagnose-key` untuk instruksi spesifik.
