[README.md](https://github.com/user-attachments/files/23301744/README.md)
# 🔐 FaceLock – Biometric File Encryption System

FaceLock is an AI-powered file encryption application that uses facial recognition for authentication instead of passwords.  
Built with Python, PyQt5, OpenCV, and InsightFace, it encrypts and decrypts files using AES-256 keys derived from a user’s unique facial embedding.

---

## 🚀 Features

- Biometric Authentication – Lock and unlock files using your face  
- AES-256 Encryption – Military-grade encryption derived from facial embeddings  
- Tamper Detection – Verifies file integrity using SHA-256 hash and size checks  
- Secure Storage – Hidden, access-restricted storage for encrypted data and face encodings  
- Windows File Protection – Uses ACLs to make locked files undeletable  
- Modern GUI – Responsive PyQt5 interface with real-time status updates  
- Multithreading – Background threads for smooth user experience  

---

## 🧰 Tech Stack

| Category | Technologies |
|-----------|--------------|
| Language | Python 3.8+ |
| GUI | PyQt5 |
| Computer Vision | OpenCV |
| Face Recognition | InsightFace (ArcFace model) |
| Encryption | cryptography (AES-256 + PBKDF2) |
| Threading | PyQt5 QThread |
| OS Integration | Windows ACLs (icacls, ctypes) |

---

## 🧩 System Architecture

📂 FaceLock  
│  
├── file_lock_enhanced.py — Main application script  
├── requirements.txt — Dependencies  
├── README.md — Project documentation  
│  
├── 🔒 Lock Workflow  
│   1. Select file  
│   2. Capture face  
│   3. Derive AES key from facial embedding  
│   4. Encrypt file → .locked  
│   5. Save face data securely (.npz)  
│  
└── 🔓 Unlock Workflow  
    1. Capture face again  
    2. Verify embedding similarity  
    3. Decrypt file if match ≥ threshold  
    4. Delete stored face data  

---

## 🖥️ Installation & Setup

1. Clone the repository  
   ```bash
   git clone https://github.com/Jashan-Sood/FaceLock-Biometric-File-Encryption-System.git
   cd FaceLock
   ```

2. Create a virtual environment  
   ```bash
   python -m venv venv
   venv\Scripts\activate  # On Windows
   ```

3. Install dependencies  
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application  
   ```bash
   python file_lock_enhanced.py
   ```

---

## 🎯 Usage

### To Lock a File
1. Open the app → “Lock Files” tab  
2. Browse and select a file  
3. Capture your face (press **s** to capture)  
4. Wait for encryption to complete  

### To Unlock a File
1. Switch to the “Unlock Files” tab  
2. Select your locked file  
3. Capture your face again  
4. The file decrypts automatically if your face matches  

---

## ⚠️ Security Notes

- Each encryption key is unique to the user’s facial embedding  
- Face data (.npz) is stored in a hidden, system-protected directory  
- If face data is lost or modified, the file cannot be decrypted  
- Works best on Windows 10/11 with a functioning camera  

---

## 👨‍💻 Author

**Jashan Sood**  
Department of Data Science and Engineering  
Manipal University Jaipur  

📧 Email: [jashansood1711@gmail.com](mailto:jashansood1711@gmail.com)  
🔗 LinkedIn: https://www.linkedin.com/in/jashan-sood/

---

## 🧾 License

Licensed under the **MIT License** – see the LICENSE file for details.

---

## ⭐ Acknowledgements

- InsightFace – Face recognition engine  
- PyQt5 – GUI framework  
- cryptography – AES-256 encryption library  

---

## 💡 Future Enhancements

- Multi-user profile support  
- Cross-platform compatibility (Linux/macOS)  
- Cloud backup integration  

---
