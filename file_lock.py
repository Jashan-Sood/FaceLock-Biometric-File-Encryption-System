import os
import cv2
import hashlib
import numpy as np
import sys
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
import insightface
from insightface.app import FaceAnalysis
import ctypes
import subprocess
import time


# =========================================================
# 🎨 MODERN UI STYLES
# =========================================================

CLEAN_STYLESHEET = """
/* Main Window */
QWidget {
    background-color: #f5f7fa;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 14px;
    color: #2c3e50;
}

/* Tab Widget */
QTabWidget::pane {
    border: 2px solid #e0e4e8;
    background-color: white;
    border-radius: 10px;
    top: -2px;
}

QTabBar::tab {
    background: #ecf0f1;
    border: none;
    padding: 16px 32px;
    margin-right: 6px;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
    font-weight: 600;
    font-size: 15px;
    color: #7f8c8d;
    min-width: 150px;
}

QTabBar::tab:selected {
    background: white;
    color: #2980b9;
    font-weight: 700;
}

QTabBar::tab:hover:!selected {
    background: #d5dbdb;
    color: #34495e;
}

/* Large Prominent Buttons */
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #3498db, stop:1 #2980b9);
    color: white;
    border: none;
    border-radius: 8px;
    padding: 16px 28px;
    font-size: 15px;
    font-weight: 700;
    min-height: 50px;
    text-align: left;
    padding-left: 20px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #5dade2, stop:1 #3498db);
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #2874a6, stop:1 #21618c);
}

QPushButton:disabled {
    background: #bdc3c7;
    color: #95a5a6;
}

/* Browse Button */
QPushButton[class="browse"] {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #95a5a6, stop:1 #7f8c8d);
    min-height: 50px;
    font-size: 15px;
}

QPushButton[class="browse"]:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #a8b4b5, stop:1 #95a5a6);
}

/* Lock Button */
QPushButton[class="lock"] {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #27ae60, stop:1 #229954);
    min-height: 60px;
    font-size: 17px;
}

QPushButton[class="lock"]:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #52d68b, stop:1 #27ae60);
}

/* Unlock Button */
QPushButton[class="unlock"] {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #e67e22, stop:1 #d35400);
    min-height: 60px;
    font-size: 17px;
}

QPushButton[class="unlock"]:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #f39c12, stop:1 #e67e22);
}

/* Refresh Button */
QPushButton[class="refresh"] {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #3498db, stop:1 #2980b9);
    min-height: 45px;
    font-size: 14px;
    max-width: 150px;
}

/* Input Fields */
QLineEdit {
    background-color: white;
    border: 2px solid #e0e4e8;
    border-radius: 8px;
    padding: 14px 16px;
    font-size: 14px;
    color: #2c3e50;
    min-height: 50px;
}

QLineEdit:focus {
    border: 2px solid #3498db;
    background-color: #f8fbfd;
}

/* List Widget */
QListWidget {
    background-color: white;
    border: 2px solid #e0e4e8;
    border-radius: 10px;
    padding: 10px;
    outline: none;
    font-size: 14px;
}

QListWidget::item {
    padding: 18px;
    border-radius: 8px;
    margin: 4px;
    border: 2px solid transparent;
}

QListWidget::item:hover {
    background-color: #ecf7fe;
    border: 2px solid #d4ebf7;
}

QListWidget::item:selected {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #d6eaf8, stop:1 #aed6f1);
    border: 2px solid #3498db;
    color: #1f618d;
    font-weight: 700;
}

/* Labels */
QLabel[class="status"] {
    padding: 14px 20px;
    border-radius: 8px;
    font-weight: 600;
    font-size: 14px;
}

QLabel[class="status-success"] {
    background-color: #d5f4e6;
    color: #27ae60;
    border: 2px solid #a9dfbf;
}

QLabel[class="status-error"] {
    background-color: #fadbd8;
    color: #c0392b;
    border: 2px solid #f1948a;
}

QLabel[class="status-info"] {
    background-color: #d6eaf8;
    color: #2980b9;
    border: 2px solid #aed6f1;
}
"""


# =========================================================
# 🛡️ FILE PROTECTION FUNCTIONS
# =========================================================

def make_file_undeletable_with_acl(file_path):
    if sys.platform == 'win32':
        try:
            ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x05)
            time.sleep(0.2)
            subprocess.run(f'icacls "{file_path}" /reset /T /Q', shell=True, capture_output=True, timeout=5)
            subprocess.run(f'icacls "{file_path}" /grant:r "*S-1-5-18:F" /Q', shell=True, capture_output=True, timeout=5)
            subprocess.run(f'icacls "{file_path}" /inheritance:r /Q', shell=True, capture_output=True, timeout=5)
            username = os.getenv('USERNAME')
            domain = os.getenv('USERDOMAIN')
            subprocess.run(f'icacls "{file_path}" /grant "{domain}\\{username}:R" /Q', shell=True, capture_output=True, timeout=5)
        except Exception as e:
            try:
                ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x05)
            except:
                pass

def remove_all_protection(file_path):
    if sys.platform == 'win32':
        try:
            subprocess.run(f'icacls "{file_path}" /reset /Q', shell=True, capture_output=True, timeout=5)
            username = os.getenv('USERNAME')
            domain = os.getenv('USERDOMAIN')
            subprocess.run(f'icacls "{file_path}" /grant "{domain}\\{username}:F" /Q', shell=True, capture_output=True, timeout=5)
            ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x80)
        except:
            pass

def make_face_data_maximally_protected(file_path):
    if sys.platform == 'win32':
        try:
            ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x07)
            subprocess.run(f'icacls "{file_path}" /reset /T /Q', shell=True, capture_output=True, timeout=5)
            subprocess.run(f'icacls "{file_path}" /grant:r "*S-1-5-18:F" /Q', shell=True, capture_output=True, timeout=5)
        except:
            pass

def hide_directory(dir_path):
    if sys.platform == 'win32':
        try:
            ctypes.windll.kernel32.SetFileAttributesW(dir_path, 0x06)
        except:
            pass

def get_secure_storage_path():
    if sys.platform == 'win32':
        base_path = os.path.join(os.environ['LOCALAPPDATA'], '.facelock_secure')
    else:
        base_path = os.path.join(os.path.expanduser('~'), '.facelock_secure')
    if not os.path.exists(base_path):
        os.makedirs(base_path, mode=0o700)
        hide_directory(base_path)
    return base_path

def get_database_path():
    return os.path.join(get_secure_storage_path(), 'file_mapping.db')

def compute_file_size_and_hash(file_path):
    sha256 = hashlib.sha256()
    file_size = 0
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
            file_size += len(chunk)
    return file_size, sha256.digest()

def verify_file_integrity(file_path, stored_hash, stored_size):
    current_size, current_hash = compute_file_size_and_hash(file_path)
    if current_size != stored_size:
        return False, "File size changed"
    if current_hash != stored_hash:
        return False, "File hash mismatch"
    return True, "OK"

def obfuscate_filename(original_path):
    abs_path = os.path.abspath(original_path).replace('\\', '/')
    path_hash = hashlib.sha256(abs_path.encode()).hexdigest()[:16]
    return f"face_{path_hash}.dat"

def save_file_mapping(locked_file_path, face_data_filename, locked_file_size, locked_file_hash):
    db_path = get_database_path()
    if os.path.exists(db_path):
        remove_all_protection(db_path)
        try:
            with open(db_path, 'r') as f:
                mappings = json.load(f)
        except:
            mappings = {}
    else:
        mappings = {}
    abs_locked_path = os.path.abspath(locked_file_path).replace('\\', '/')
    if not face_data_filename.endswith('.npz'):
        face_data_filename = face_data_filename + '.npz'
    mappings[abs_locked_path] = {
        'face_data': face_data_filename,
        'locked_size': locked_file_size,
        'locked_hash': locked_file_hash.hex()
    }
    with open(db_path, 'w') as f:
        json.dump(mappings, f, indent=2)
    make_face_data_maximally_protected(db_path)

def get_file_metadata(locked_file_path):
    db_path = get_database_path()
    if not os.path.exists(db_path):
        raise Exception("Database not found")
    remove_all_protection(db_path)
    try:
        with open(db_path, 'r') as f:
            mappings = json.load(f)
    finally:
        make_face_data_maximally_protected(db_path)
    abs_locked_path = os.path.abspath(locked_file_path).replace('\\', '/')
    if abs_locked_path not in mappings:
        for key in mappings.keys():
            if os.path.basename(key) == os.path.basename(locked_file_path):
                return mappings[key]
        raise Exception("File not in database")
    return mappings[abs_locked_path]

def remove_file_mapping(locked_file_path):
    db_path = get_database_path()
    if not os.path.exists(db_path):
        return
    remove_all_protection(db_path)
    with open(db_path, 'r') as f:
        mappings = json.load(f)
    abs_locked_path = os.path.abspath(locked_file_path).replace('\\', '/')
    if abs_locked_path in mappings:
        del mappings[abs_locked_path]
    with open(db_path, 'w') as f:
        json.dump(mappings, f, indent=2)
    make_face_data_maximally_protected(db_path)

def get_all_locked_files():
    locked_files = []
    db_path = get_database_path()
    if not os.path.exists(db_path):
        return locked_files
    remove_all_protection(db_path)
    try:
        with open(db_path, 'r') as f:
            mappings = json.load(f)
    except:
        return locked_files
    finally:
        make_face_data_maximally_protected(db_path)
    for locked_path, info in mappings.items():
        if os.path.exists(locked_path):
            locked_files.append({
                'path': locked_path,
                'name': os.path.basename(locked_path),
                'size': os.path.getsize(locked_path),
                'exists': True
            })
    return locked_files

def derive_key_from_face_encoding(encoding, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(encoding.tobytes())

def encrypt_file(file_path, key):
    IV = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    locked_path = file_path + ".locked"
    with open(file_path, 'rb') as fin, open(locked_path, 'wb') as fout:
        fout.write(IV)
        while chunk := fin.read(4096):
            fout.write(encryptor.update(chunk))
        fout.write(encryptor.finalize())
    os.remove(file_path)
    make_file_undeletable_with_acl(locked_path)
    return locked_path

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as fin:
        IV = fin.read(16)
        if len(IV) != 16:
            raise Exception("Invalid IV")
        cipher = Cipher(algorithms.AES(key), modes.CFB(IV), backend=default_backend())
        decryptor = cipher.decryptor()
        original_path = file_path.replace(".locked", "")
        with open(original_path, 'wb') as fout:
            while chunk := fin.read(4096):
                fout.write(decryptor.update(chunk))
            fout.write(decryptor.finalize())
    remove_all_protection(file_path)
    os.remove(file_path)
    return original_path


# =========================================================
# 📸 FACE RECOGNITION
# =========================================================

class FaceEncoder:
    def __init__(self):
        self.app = FaceAnalysis(name='buffalo_l', providers=['CPUExecutionProvider'])
        self.app.prepare(ctx_id=0, det_size=(640, 640))
    def get_embedding(self, image):
        faces = self.app.get(image)
        if len(faces) == 0:
            raise Exception("No face detected")
        if len(faces) > 1:
            faces = sorted(faces, key=lambda x: x.det_score, reverse=True)
        return faces[0].normed_embedding
    def compare_embeddings(self, emb1, emb2, threshold=0.35):
        similarity = np.dot(emb1, emb2)
        distance = 1.0 - similarity
        return distance, distance < threshold

face_encoder = None
def get_face_encoder():
    global face_encoder
    if face_encoder is None:
        face_encoder = FaceEncoder()
    return face_encoder

def capture_face_embedding():
    """Capture face from camera - ALWAYS ON TOP"""
    cam = cv2.VideoCapture(0)
    if not cam.isOpened():
        raise Exception("Camera error")
    
    encoder = get_face_encoder()
    
    # Create window and bring to front
    window_name = "Face Capture"
    cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)
    cv2.setWindowProperty(window_name, cv2.WND_PROP_TOPMOST, 1)  # Always on top
    
    while True:
        ret, frame = cam.read()
        if not ret:
            break
        
        display = frame.copy()
        
        try:
            faces = encoder.app.get(frame)
            for face in faces:
                bbox = face.bbox.astype(int)
                cv2.rectangle(display, (bbox[0], bbox[1]), (bbox[2], bbox[3]), (0, 255, 0), 2)
                cv2.putText(display, f"{face.det_score:.2f}", (bbox[0], bbox[1]-10), 
                          cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)
        except:
            pass
        
        cv2.putText(display, "Press 's' to capture your face", (10, 30),
                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
        cv2.imshow(window_name, display)
        
        if cv2.waitKey(1) & 0xFF == ord('s'):
            embedding = encoder.get_embedding(frame)
            break
    
    cam.release()
    cv2.destroyAllWindows()
    
    return embedding


# =========================================================
# 🚀 MULTITHREADING WORKERS
# =========================================================

class LockFileWorker(QThread):
    """Worker thread for locking files"""
    status_update = pyqtSignal(str, str)  # message, status_class
    finished_success = pyqtSignal(str)  # locked_file_path
    finished_error = pyqtSignal(str)  # error_message
    
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
    
    def run(self):
        try:
            # Step 1: Capture face
            self.status_update.emit("📸 Capturing your face...", "status-info")
            embedding = capture_face_embedding()
            
            # Step 2: Encrypt
            self.status_update.emit("🔐 Encrypting file...", "status-info")
            salt = os.urandom(16)
            key = derive_key_from_face_encoding(embedding, salt)
            
            with open(self.file_path, 'rb') as f:
                original_hash = hashlib.sha256(f.read()).digest()
            
            locked_path = encrypt_file(self.file_path, key)
            locked_size, locked_hash = compute_file_size_and_hash(locked_path)
            
            # Step 3: Save face data
            self.status_update.emit("💾 Saving face data...", "status-info")
            obfuscated_name = obfuscate_filename(self.file_path)
            secure_folder = get_secure_storage_path()
            secure_path = os.path.join(secure_folder, obfuscated_name)
            
            np.savez(secure_path, embedding=embedding, salt=salt, original_hash=original_hash)
            
            actual_path = secure_path + '.npz'
            make_face_data_maximally_protected(actual_path)
            save_file_mapping(locked_path, obfuscated_name, locked_size, locked_hash)
            
            self.finished_success.emit(locked_path)
            
        except Exception as e:
            self.finished_error.emit(str(e))


class UnlockFileWorker(QThread):
    """Worker thread for unlocking files"""
    status_update = pyqtSignal(str, str)  # message, status_class
    finished_success = pyqtSignal(str, float)  # original_path, match_quality
    finished_error = pyqtSignal(str)  # error_message
    
    def __init__(self, locked_file_path):
        super().__init__()
        self.locked_file_path = locked_file_path
    
    def run(self):
        try:
            # Step 1: Check integrity
            self.status_update.emit("🔍 Checking file integrity...", "status-info")
            metadata = get_file_metadata(self.locked_file_path)
            stored_size = metadata['locked_size']
            stored_hash = bytes.fromhex(metadata['locked_hash'])
            
            is_intact, message = verify_file_integrity(self.locked_file_path, stored_hash, stored_size)
            
            if not is_intact:
                raise Exception(f"FILE TAMPERED! {message}")
            
            # Step 2: Load face data
            self.status_update.emit("📂 Loading face data...", "status-info")
            secure_folder = get_secure_storage_path()
            face_file = os.path.join(secure_folder, metadata['face_data'])
            
            if not os.path.exists(face_file):
                raise Exception("Face data missing")
            
            remove_all_protection(face_file)
            with np.load(face_file, allow_pickle=False) as data:
                stored_embedding = data["embedding"].copy()
                salt = data["salt"].tobytes()
            make_face_data_maximally_protected(face_file)
            
            # Step 3: Verify face
            self.status_update.emit("📸 Verifying your face...", "status-info")
            current_embedding = capture_face_embedding()
            
            encoder = get_face_encoder()
            distance, is_match = encoder.compare_embeddings(stored_embedding, current_embedding, threshold=0.35)
            
            if not is_match:
                raise Exception(f"Face mismatch! Distance: {distance:.4f}")
            
            # Step 4: Decrypt
            self.status_update.emit("🔓 Decrypting file...", "status-info")
            key = derive_key_from_face_encoding(stored_embedding, salt)
            original_path = decrypt_file(self.locked_file_path, key)
            
            # Step 5: Cleanup
            remove_all_protection(face_file)
            os.remove(face_file)
            remove_file_mapping(self.locked_file_path)
            
            match_quality = (1 - distance) * 100
            self.finished_success.emit(original_path, match_quality)
            
        except Exception as e:
            self.finished_error.emit(str(e))


# =========================================================
# 🖥️ GUI APPLICATION WITH MULTITHREADING
# =========================================================

class FileLockerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 FaceLock - Biometric File Encryption")
        self.setStyleSheet(CLEAN_STYLESHEET)
        
        self.lock_worker = None
        self.unlock_worker = None
        
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)
        
        header = QLabel("🔐 FaceLock - Biometric File Encryption")
        header.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                      stop:0 #667eea, stop:1 #764ba2);
            border-radius: 12px;
            padding: 25px;
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        header.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(header)
        
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_lock_tab(), "🔒  Lock Files")
        self.tabs.addTab(self.create_unlock_tab(), "🔓  Unlock Files")
        main_layout.addWidget(self.tabs)

    def create_lock_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(24)
        
        title = QLabel("Lock File with Your Face")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50; padding: 10px 0;")
        layout.addWidget(title)
        
        file_label = QLabel("📄 Selected File:")
        file_label.setStyleSheet("font-weight: 600; font-size: 15px; margin-top: 10px;")
        layout.addWidget(file_label)
        
        self.lock_input = QLineEdit()
        self.lock_input.setPlaceholderText("No file selected yet...")
        self.lock_input.setReadOnly(True)
        layout.addWidget(self.lock_input)
        
        self.lock_browse = QPushButton("📁  BROWSE FILES")
        self.lock_browse.setProperty("class", "browse")
        self.lock_browse.clicked.connect(self.browse_file)
        layout.addWidget(self.lock_browse)
        
        layout.addSpacing(20)
        
        self.lock_button = QPushButton("🔒  LOCK FILE WITH FACE")
        self.lock_button.setProperty("class", "lock")
        self.lock_button.clicked.connect(self.lock_file)
        layout.addWidget(self.lock_button)
        
        self.lock_status = QLabel("Ready to lock files")
        self.lock_status.setProperty("class", "status-info")
        layout.addWidget(self.lock_status)
        
        layout.addStretch()
        return widget

    def create_unlock_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(24)
        
        title_layout = QHBoxLayout()
        title = QLabel("Unlock Your Files")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50;")
        title_layout.addWidget(title)
        title_layout.addStretch()
        
        refresh_btn = QPushButton("🔄  REFRESH")
        refresh_btn.setProperty("class", "refresh")
        refresh_btn.clicked.connect(self.refresh_file_list)
        title_layout.addWidget(refresh_btn)
        
        layout.addLayout(title_layout)
        
        list_label = QLabel("📋 Your Locked Files:")
        list_label.setStyleSheet("font-weight: 600; font-size: 15px; margin-top: 10px;")
        layout.addWidget(list_label)
        
        self.file_list = QListWidget()
        self.file_list.setMinimumHeight(280)
        self.file_list.itemSelectionChanged.connect(self.on_file_selected)
        layout.addWidget(self.file_list)
        
        layout.addSpacing(10)
        
        self.unlock_button = QPushButton("🔓  UNLOCK SELECTED FILE")
        self.unlock_button.setProperty("class", "unlock")
        self.unlock_button.clicked.connect(self.unlock_file)
        self.unlock_button.setEnabled(False)
        layout.addWidget(self.unlock_button)
        
        self.unlock_status = QLabel("Select a file to unlock")
        self.unlock_status.setProperty("class", "status-info")
        layout.addWidget(self.unlock_status)
        
        self.refresh_file_list()
        return widget

    def refresh_file_list(self):
        self.file_list.clear()
        self.selected_file = None
        locked_files = get_all_locked_files()
        
        if not locked_files:
            item = QListWidgetItem("📭 No locked files found")
            item.setFlags(Qt.NoItemFlags)
            item.setForeground(Qt.gray)
            self.file_list.addItem(item)
            return
        
        for f in locked_files:
            size_kb = f['size'] / 1024
            size_mb = size_kb / 1024
            size_str = f"{size_mb:.2f} MB" if size_mb >= 1 else f"{size_kb:.1f} KB"
            item_text = f"📄  {f['name']}    •    {size_str}"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, f['path'])
            self.file_list.addItem(item)

    def on_file_selected(self):
        items = self.file_list.selectedItems()
        if items and items[0].flags() != Qt.NoItemFlags:
            self.selected_file = items[0].data(Qt.UserRole)
            self.unlock_button.setEnabled(True)
            self.unlock_status.setText(f"✅ Selected: {os.path.basename(self.selected_file)}")
            self.unlock_status.setProperty("class", "status-success")
            self.unlock_status.setStyle(self.unlock_status.style())

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Lock", "", "All Files (*)")
        if path:
            self.lock_input.setText(path)
            self.lock_status.setText(f"✅ File selected: {os.path.basename(path)}")
            self.lock_status.setProperty("class", "status-success")
            self.lock_status.setStyle(self.lock_status.style())

    def lock_file(self):
        path = self.lock_input.text().strip()
        
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "❌ No File Selected", 
                "Please click the BROWSE FILES button first.")
            return
        
        QMessageBox.information(self, "📸 Face Capture", 
            "Position your face in front of the camera.\nPress 's' when ready to capture.")
        
        # Disable buttons
        self.lock_button.setEnabled(False)
        self.lock_browse.setEnabled(False)
        
        # Start worker thread
        self.lock_worker = LockFileWorker(path)
        self.lock_worker.status_update.connect(self.update_lock_status)
        self.lock_worker.finished_success.connect(self.on_lock_success)
        self.lock_worker.finished_error.connect(self.on_lock_error)
        self.lock_worker.start()

    def update_lock_status(self, message, status_class):
        self.lock_status.setText(message)
        self.lock_status.setProperty("class", status_class)
        self.lock_status.setStyle(self.lock_status.style())

    def on_lock_success(self, locked_path):
        self.lock_status.setText("✅ File locked successfully!")
        self.lock_status.setProperty("class", "status-success")
        self.lock_status.setStyle(self.lock_status.style())
        self.lock_input.clear()
        
        QMessageBox.information(self, "✅ Success",
            f"File Locked Successfully!\n\n📄 {os.path.basename(locked_path)}\n\n"
            f"Your file is now encrypted and protected.")
        
        self.lock_button.setEnabled(True)
        self.lock_browse.setEnabled(True)
        self.refresh_file_list()

    def on_lock_error(self, error_msg):
        self.lock_status.setText("❌ Lock failed")
        self.lock_status.setProperty("class", "status-error")
        self.lock_status.setStyle(self.lock_status.style())
        
        QMessageBox.critical(self, "❌ Error", f"Failed to lock file:\n\n{error_msg}")
        
        self.lock_button.setEnabled(True)
        self.lock_browse.setEnabled(True)

    def unlock_file(self):
        if not hasattr(self, 'selected_file'):
            QMessageBox.warning(self, "❌ No File Selected", "Please select a file first.")
            return
        
        QMessageBox.information(self, "📸 Face Verification",
            "Position your face in front of the camera.\nPress 's' when ready to verify.")
        
        # Disable buttons
        self.unlock_button.setEnabled(False)
        
        # Start worker thread
        self.unlock_worker = UnlockFileWorker(self.selected_file)
        self.unlock_worker.status_update.connect(self.update_unlock_status)
        self.unlock_worker.finished_success.connect(self.on_unlock_success)
        self.unlock_worker.finished_error.connect(self.on_unlock_error)
        self.unlock_worker.start()

    def update_unlock_status(self, message, status_class):
        self.unlock_status.setText(message)
        self.unlock_status.setProperty("class", status_class)
        self.unlock_status.setStyle(self.unlock_status.style())

    def on_unlock_success(self, original_path, match_quality):
        self.unlock_status.setText("✅ File unlocked successfully!")
        self.unlock_status.setProperty("class", "status-success")
        self.unlock_status.setStyle(self.unlock_status.style())
        
        QMessageBox.information(self, "✅ Success",
            f"File Unlocked Successfully!\n\n"
            f"📄 {os.path.basename(original_path)}\n"
            f"Face Match: {match_quality:.1f}%")
        
        self.refresh_file_list()

    def on_unlock_error(self, error_msg):
        if "TAMPERED" in error_msg:
            self.unlock_status.setText("🚨 FILE TAMPERED!")
            QMessageBox.critical(self, "🚨 SECURITY ALERT",
                f"{error_msg}\n\nThe file cannot be unlocked for security.")
        else:
            self.unlock_status.setText("❌ Unlock failed")
            QMessageBox.critical(self, "❌ Error", f"Failed to unlock:\n\n{error_msg}")
        
        self.unlock_status.setProperty("class", "status-error")
        self.unlock_status.setStyle(self.unlock_status.style())


# =========================================================
# 🚀 MAIN - LAUNCH MAXIMIZED
# =========================================================

if __name__ == "__main__":
    print("🚀 FaceLock - Biometric File Encryption (MULTITHREADED)")
    print("="*60)
    print("✅ Background processing - UI stays responsive")
    print("✅ Camera window always on top")
    print("✅ Launches maximized (resizable)")
    print("✅ InsightFace ArcFace (99.86% accuracy)")
    print("✅ AES-256 encryption")
    print("✅ Tamper detection")
    print(f"✅ Secure storage: {get_secure_storage_path()}")
    print("="*60)
    
    app = QApplication(sys.argv)
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = FileLockerApp()
    window.showMaximized()  # Launch maximized (can still minimize/resize)
    
    sys.exit(app.exec_())
