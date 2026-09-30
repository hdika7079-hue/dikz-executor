DIKZ CENTRAL SERVER
===================

Isi folder:
- index.html  -> halaman yang dibuka semua teman
- server.js   -> backend/server pusat
- package.json
- .env.example -> contoh konfigurasi

CARA MENJALANKAN
1. Install Node.js 18+ di VPS/komputer server.
2. Copy .env.example menjadi .env atau set environment variable langsung.
3. Ganti ADMIN_PASS dengan password kuat.
4. Isi REYCLOUD_API_KEY di environment server jika backend perlu memanggil provider.
5. Jalankan:
   npm start
6. Buka:
   http://IP-SERVER:3000

PENTING:
- API key TIDAK dimasukkan ke index.html.
- User dan log disimpan bersama di data.json pada server.
- Teman yang membuka alamat server yang sama akan memakai database yang sama.
- Untuk internet publik, pasang HTTPS/reverse proxy dan firewall.
- Jika API key yang lama sudah pernah dibagikan, sebaiknya buat key baru dan cabut key lama.
