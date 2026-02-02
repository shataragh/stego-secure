import sys
import os
import hashlib
import json
import base64
import qrcode
import time
from datetime import datetime
from pathlib import Path
from typing import Tuple, List, Dict, Optional
import warnings
warnings.filterwarnings('ignore', category=RuntimeWarning)

import numpy as np
np.set_printoptions(legacy='1.13')

from PIL import Image
from scipy.ndimage import gaussian_filter
from scipy.fftpack import dct, idct

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTabWidget, QLabel, QLineEdit, QTextEdit, QPushButton, QProgressBar,
    QFileDialog, QMessageBox, QGroupBox, QFormLayout, QSlider, QCheckBox,
    QTextBrowser
)
from PyQt5.QtGui import QPixmap, QImage, QFont, QPalette, QColor, QPainter, QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# =============================================================================
#  BACKEND - Military-grade-ish Steganography (DCT-based, JPEG resistant)
# =============================================================================
class StegoEngine:
    def __init__(self, password: str, salt: Optional[bytes] = None):
        if salt is not None:
            # Receiver mode - use provided salt
            self.salt = salt
        else:
            # Sender mode - generate fresh salt
            self.salt = os.urandom(32)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=600_000,
            backend=default_backend()
        )
        self.key = kdf.derive(password.encode())

    def _rgb_to_ycbcr(self, rgb: np.ndarray) -> np.ndarray:
        transform = np.array([
            [0.299,   0.587,   0.114],
            [-0.168736, -0.331264, 0.5],
            [0.5,     -0.418688, -0.081312]
        ], dtype=np.float64)
        ycbcr = np.dot(rgb.astype(np.float64), transform.T)
        ycbcr[:, :, 1:] += 128
        return ycbcr

    def _ycbcr_to_rgb(self, ycbcr: np.ndarray) -> np.ndarray:
        transform = np.array([
            [1.0, 0.0,      1.402],
            [1.0, -0.344136, -0.714136],
            [1.0, 1.772,    0.0]
        ], dtype=np.float64)
        ycbcr_copy = ycbcr.copy()
        ycbcr_copy[:, :, 1:] -= 128
        rgb = np.dot(ycbcr_copy, transform.T)
        return np.clip(rgb, 0, 255).astype(np.uint8)

    def _encrypt_payload(self, message: str) -> bytes:
        nonce = os.urandom(12)
        aead = ChaCha20Poly1305(self.key)
        ciphertext = aead.encrypt(nonce, message.encode('utf-8'), None)
        # Format: salt || nonce || length(4) || ciphertext+tag
        length_bytes = len(ciphertext).to_bytes(4, "big")
        return self.salt + nonce + length_bytes + ciphertext

    def hide_jpeg_resistant(self, cover_path: str, message: str, output_path: str) -> Dict:
        img = Image.open(cover_path).convert('RGB')
        width, height = img.size

        blocks_w = width // 8
        blocks_h = height // 8
        max_bits = blocks_w * blocks_h * 6

        encrypted = self._encrypt_payload(message)
        bits = [int(b) for byte in encrypted for b in f'{byte:08b}']

        if len(bits) > max_bits * 0.85:
            max_safe_chars = int(max_bits * 0.85 * 0.7 / 8)
            raise ValueError(
                f"Message too long ({len(message)} chars). "
                f"Recommended max ~{max_safe_chars} chars for this image."
            )

        pixels = np.array(img, dtype=np.float64)
        ycbcr = self._rgb_to_ycbcr(pixels)
        y = ycbcr[:, :, 0]

        bit_idx = 0
        for i in range(0, height - 7, 8):
            for j in range(0, width - 7, 8):
                if bit_idx >= len(bits):
                    break
                block = y[i:i+8, j:j+8]
                dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')

                positions = [(0,2), (1,1), (1,2), (2,0), (2,1), (3,0)]
                for pos in positions:
                    if bit_idx >= len(bits):
                        break
                    val = dct_block[pos]
                    dct_block[pos] = (val // 1) * 1 + bits[bit_idx]   # LSB embed
                    bit_idx += 1

                idct_block = idct(idct(dct_block.T, norm='ortho').T, norm='ortho')
                y[i:i+8, j:j+8] = idct_block

        ycbcr[:, :, 0] = y
        result_img = Image.fromarray(self._ycbcr_to_rgb(ycbcr), 'RGB')
        result_img.save(output_path, format='JPEG', quality=82, optimize=True, progressive=True)
        result_img.close()
        img.close()

        return {
            "status": "success",
            "output_path": output_path,
            "payload_bits": len(bits),
            "image_size": f"{width}x{height}",
            "format": "JPEG (DCT mid-freq)",
            "salt_base64": base64.b64encode(self.salt).decode('ascii')
        }

    def reveal(self, stego_path: str) -> Dict:
        img = Image.open(stego_path).convert('RGB')
        pixels = np.array(img, dtype=np.float64)
        ycbcr = self._rgb_to_ycbcr(pixels)
        y = ycbcr[:, :, 0]

        bits = []
        h, w = y.shape
        for i in range(0, h-7, 8):
            for j in range(0, w-7, 8):
                block = y[i:i+8, j:j+8]
                dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                positions = [(0,2), (1,1), (1,2), (2,0), (2,1), (3,0)]
                for pos in positions:
                    val = int(round(dct_block[pos]))
                    bits.append(val & 1)

        if len(bits) < 32*8 + 12*8 + 4*8:
            raise ValueError("Image too small or no payload found")

        bytes_data = bytearray()
        for i in range(0, len(bits)-7, 8):
            byte_str = ''.join(str(bits[k]) for k in range(i, i+8))
            bytes_data.append(int(byte_str, 2))

        extracted_salt = bytes(bytes_data[:32])
        if extracted_salt != self.salt:
            raise ValueError("Salt mismatch - wrong password or wrong image")

        nonce = bytes(bytes_data[32:44])
        length = int.from_bytes(bytes(bytes_data[44:48]), "big")
        start = 48
        end = start + length

        if end + 16 > len(bytes_data):  # tag is 16 bytes
            raise ValueError("Payload truncated - image may be damaged")

        ciphertext_tag = bytes(bytes_data[start:end+16])

        aead = ChaCha20Poly1305(self.key)
        try:
            plaintext = aead.decrypt(nonce, ciphertext_tag, None)
            return {
                "message": plaintext.decode('utf-8'),
                "status": "success"
            }
        except Exception as e:
            raise ValueError(f"Decryption failed - likely wrong password: {str(e)}")


# =============================================================================
#  WORKER THREADS
# =============================================================================
class HideWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, cover_path: str, message: str, output_path: str, password: str):
        super().__init__()
        self.cover_path = cover_path
        self.message = message
        self.output_path = output_path
        self.password = password

    def run(self):
        try:
            self.progress.emit(10)
            engine = StegoEngine(self.password)  # generates salt
            self.progress.emit(40)
            result = engine.hide_jpeg_resistant(
                self.cover_path, self.message, self.output_path
            )
            self.progress.emit(90)
            result["salt_base64"] = base64.b64encode(engine.salt).decode('ascii')
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class ExtractWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, stego_path: str, password: str, salt_b64: str):
        super().__init__()
        self.stego_path = stego_path
        self.password = password
        self.salt_b64 = salt_b64

    def run(self):
        try:
            self.progress.emit(20)
            salt = base64.b64decode(self.salt_b64)
            engine = StegoEngine(self.password, salt=salt)
            self.progress.emit(60)
            result = engine.reveal(self.stego_path)
            self.progress.emit(100)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


# =============================================================================
#  MAIN GUI (simplified - removed traffic generator, metadata sanitizer, etc.)
# =============================================================================
class StegoGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureStego 2026 — DCT-based JPEG resistant")
        self.setMinimumSize(1000, 780)
        self.current_salt_b64 = None
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        layout = QVBoxLayout(central)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_hide_tab(), "Hide")
        self.tabs.addTab(self.create_extract_tab(), "Extract")
        self.tabs.addTab(self.create_help_tab(), "Help / OPSEC")

        layout.addWidget(self.tabs)

        self.status = QLabel("Ready")
        self.status.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status)

        self.setCentralWidget(central)

    def create_hide_tab(self):
        tab = QWidget()
        ly = QVBoxLayout(tab)

        # Cover
        g_cover = QGroupBox("1. Cover image (high texture recommended)")
        ly_cover = QVBoxLayout()
        self.lbl_cover = QLabel("Select JPEG/PNG with complex texture\n(forests, cities, water, etc.)")
        self.lbl_cover.setAlignment(Qt.AlignCenter)
        self.lbl_cover.setMinimumHeight(180)
        self.lbl_cover.setStyleSheet("border: 2px dashed #555; background: #222; color: #aaa;")
        btn_cover = QPushButton("Browse cover image")
        btn_cover.clicked.connect(self.browse_cover)
        ly_cover.addWidget(self.lbl_cover)
        ly_cover.addWidget(btn_cover)
        g_cover.setLayout(ly_cover)

        # Message
        g_msg = QGroupBox("2. Message (keep short — 1–2 KB max recommended)")
        ly_msg = QVBoxLayout()
        self.txt_msg = QTextEdit()
        self.txt_msg.setPlaceholderText("Coordinates, codes, short text...\nAvoid long natural language sentences.")
        ly_msg.addWidget(self.txt_msg)
        g_msg.setLayout(ly_msg)

        # Password
        g_pwd = QGroupBox("3. Strong passphrase")
        ly_pwd = QFormLayout()
        self.txt_pwd = QLineEdit()
        self.txt_pwd.setEchoMode(QLineEdit.Password)
        ly_pwd.addRow("Passphrase:", self.txt_pwd)
        g_pwd.setLayout(ly_pwd)

        # Buttons
        btn_hide = QPushButton("HIDE MESSAGE → JPEG")
        btn_hide.setStyleSheet("background:#2a6; color:white; font-weight:bold; padding:12px;")
        btn_hide.clicked.connect(self.start_hide)

        self.bar = QProgressBar()
        self.bar.setVisible(False)

        self.lbl_result = QLabel("")
        self.lbl_result.setWordWrap(True)
        self.lbl_result.setVisible(False)

        ly.addWidget(g_cover)
        ly.addWidget(g_msg)
        ly.addWidget(g_pwd)
        ly.addWidget(btn_hide)
        ly.addWidget(self.bar)
        ly.addWidget(self.lbl_result)
        ly.addStretch()

        return tab

    def create_extract_tab(self):
        tab = QWidget()
        ly = QVBoxLayout(tab)

        g_file = QGroupBox("1. Stego image")
        ly_file = QVBoxLayout()
        self.lbl_stego = QLabel("Drag & drop or browse JPEG containing hidden message")
        self.lbl_stego.setAlignment(Qt.AlignCenter)
        self.lbl_stego.setMinimumHeight(180)
        self.lbl_stego.setStyleSheet("border: 2px dashed #555; background: #222; color: #aaa;")
        btn_stego = QPushButton("Browse stego image")
        btn_stego.clicked.connect(self.browse_stego)
        ly_file.addWidget(self.lbl_stego)
        ly_file.addWidget(btn_stego)
        g_file.setLayout(ly_file)

        g_key = QGroupBox("2. Credentials (from sender)")
        ly_key = QFormLayout()
        self.txt_pwd_ext = QLineEdit()
        self.txt_pwd_ext.setEchoMode(QLineEdit.Password)
        self.txt_salt_ext = QLineEdit()
        ly_key.addRow("Passphrase:", self.txt_pwd_ext)
        ly_key.addRow("Salt (base64):", self.txt_salt_ext)
        g_key.setLayout(ly_key)

        btn_extract = QPushButton("EXTRACT MESSAGE")
        btn_extract.setStyleSheet("background:#c63; color:white; font-weight:bold; padding:12px;")
        btn_extract.clicked.connect(self.start_extract)

        self.bar_ext = QProgressBar()
        self.bar_ext.setVisible(False)

        self.txt_result = QTextEdit()
        self.txt_result.setReadOnly(True)
        self.txt_result.setVisible(False)

        ly.addWidget(g_file)
        ly.addWidget(g_key)
        ly.addWidget(btn_extract)
        ly.addWidget(self.bar_ext)
        ly.addWidget(self.txt_result)
        ly.addStretch()

        return tab

    def create_help_tab(self):
        tab = QWidget()
        ly = QVBoxLayout(tab)
        text = QTextBrowser()
        text.setHtml("""
        <h2>SecureStego — OPSEC Quick Reference 2026</h2>
        <ul>
          <li><b>Cover</b>: high entropy JPEGs (>7.5 bit/pixel), nature/crowd photos</li>
          <li><b>Payload</b>: keep < 1.5–2 KB for 1080p images</li>
          <li><b>NEVER</b> send password or salt together with image</li>
          <li><b>Recommended</b>: Signal / Session / Matrix for key exchange</li>
          <li><b>Transmission pattern</b>: send 10–20 normal images first, insert stego randomly</li>
          <li><b>Warning</b>: modern steganalysis (deep learning) can detect DCT-LSB even at low rates</li>
        </ul>
        <p><b>Real security comes from OPSEC — not from the tool alone.</b></p>
        """)
        ly.addWidget(text)
        return tab

    def browse_cover(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select cover", "", "Images (*.jpg *.jpeg *.png)")
        if path:
            self.cover_path = path
            pix = QPixmap(path).scaled(320, 240, Qt.KeepAspectRatio)
            self.lbl_cover.setPixmap(pix)

    def browse_stego(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select stego", "", "Images (*.jpg *.jpeg *.png)")
        if path:
            self.stego_path = path
            pix = QPixmap(path).scaled(320, 240, Qt.KeepAspectRatio)
            self.lbl_stego.setPixmap(pix)

    def start_hide(self):
        if not hasattr(self, 'cover_path'):
            QMessageBox.warning(self, "Error", "Select cover image first")
            return
        msg = self.txt_msg.toPlainText().strip()
        if not msg:
            QMessageBox.warning(self, "Error", "Enter message")
            return
        pwd = self.txt_pwd.text()
        if len(pwd) < 10:
            QMessageBox.warning(self, "Error", "Passphrase too short")
            return

        out_dir = os.path.dirname(self.cover_path)
        fname = f"stego_{datetime.now():%Y%m%d_%H%M%S}.jpg"
        out_path = os.path.join(out_dir, fname)

        self.bar.setVisible(True)
        self.bar.setValue(0)
        self.lbl_result.setVisible(False)

        self.worker = HideWorker(self.cover_path, msg, out_path, pwd)
        self.worker.progress.connect(self.bar.setValue)
        self.worker.finished.connect(self.on_hide_finished)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_hide_finished(self, result: Dict):
        self.bar.setValue(100)
        self.current_salt_b64 = result["salt_base64"]

        text = f"""<b>Success!</b><br>
Output: <code>{os.path.basename(result['output_path'])}</code><br><br>
<b>Salt (base64) — SEND VIA SECURE CHANNEL ONLY:</b><br>
<code style="background:#111; padding:6px;">{self.current_salt_b64}</code><br><br>
Copy salt and share it separately (Signal / Session / in person).<br>
Never send it with the image!
"""
        self.lbl_result.setText(text)
        self.lbl_result.setVisible(True)
        self.status.setText("Hiding complete — salt copied to clipboard")
        QApplication.clipboard().setText(self.current_salt_b64)

    def start_extract(self):
        if not hasattr(self, 'stego_path'):
            QMessageBox.warning(self, "Error", "Select stego image first")
            return
        pwd = self.txt_pwd_ext.text()
        salt_b64 = self.txt_salt_ext.text().strip()
        if not pwd or not salt_b64:
            QMessageBox.warning(self, "Error", "Passphrase and salt required")
            return

        self.bar_ext.setVisible(True)
        self.bar_ext.setValue(0)
        self.txt_result.setVisible(False)

        self.ext_worker = ExtractWorker(self.stego_path, pwd, salt_b64)
        self.ext_worker.progress.connect(self.bar_ext.setValue)
        self.ext_worker.finished.connect(self.on_extract_finished)
        self.ext_worker.error.connect(self.on_error)
        self.ext_worker.start()

    def on_extract_finished(self, result: Dict):
        self.bar_ext.setValue(100)
        self.txt_result.setPlainText("Extracted message:\n\n" + result["message"])
        self.txt_result.setVisible(True)
        self.status.setText("Message extracted")

    def on_error(self, msg: str):
        self.bar.setVisible(False)
        self.bar_ext.setVisible(False)
        QMessageBox.critical(self, "Error", msg)
        self.status.setText("Operation failed")

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = StegoGUI()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
