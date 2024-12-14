# Cuman-Bisa-File-Scanner
Aplikasi ini dibuat untuk mempermudah pengguna memindai file menggunakan layanan VirusTotal API secara interaktif melalui antarmuka grafis yang ramah pengguna. 

Fitur Utama:

Pemindaian File dengan VirusTotal API:

Aplikasi memungkinkan pengguna untuk memilih file secara lokal dan memindainya melalui VirusTotal.

Informasi deteksi mencakup analisis dari berbagai mesin antivirus.

Antarmuka Grafis (GUI) yang Menarik:

Dibangun dengan tkinter untuk menyediakan pengalaman pengguna yang mudah dan intuitif.

Desain modern dengan tema warna yang konsisten.

Grafik Lingkaran untuk Community Score:

Menampilkan persentase suara "malicious" dan "harmless" dalam format visual menggunakan matplotlib.
Tabel Analisis Antivirus:

Menampilkan hasil deteksi dari mesin antivirus, termasuk nama mesin, kategori, dan hasilnya.

Dukungan untuk File Besar:

Secara otomatis mengunggah file besar (>32 MB) ke VirusTotal untuk analisis mendalam.

Teknologi yang Digunakan:

Python: Bahasa pemrograman utama untuk aplikasi.

tkinter: Untuk antarmuka pengguna grafis.

matplotlib: Untuk visualisasi data berupa grafik lingkaran.

VirusTotal API v3: Untuk pemindaian dan analisis file secara online.

Cara Kerja Aplikasi:

Pengguna memasukkan API key VirusTotal.

Memilih file untuk dipindai dari komputer lokal.

Aplikasi menghitung hash file (SHA-256) dan memeriksa hasil analisis di VirusTotal.
Jika file belum pernah dianalisis, file akan diunggah untuk diproses.
Hasil analisis ditampilkan dalam bentuk tabel (hasil antivirus) dan grafik lingkaran (community score).

![image](https://github.com/user-attachments/assets/fe2d0b0d-a244-4913-915b-7b4303d7054e)
