# SecureStego – JPEG-Resistant Steganography Tool

<p align="center">
  <img src="https://i.postimg.cc/HkBpZ2fy/wewe.png" alt="SecureStego main interface" width="720">
  <br>
  <em>Main window – Hide tab (example)</em>
</p>

<p align="center">
  <a href="https://www.python.org">
    <img src="https://img.shields.io/badge/python-3.9+-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54" alt="Python">
  </a>
  <img src="https://img.shields.io/badge/GUI-PyQt5-41CD52?style=for-the-badge" alt="GUI">
  <img src="https://img.shields.io/badge/Encryption-ChaCha20--Poly1305-2ea44f?style=for-the-badge" alt="Encryption">
  <img src="https://img.shields.io/badge/JPEG--resistant-✓-brightgreen?style=for-the-badge" alt="JPEG resistant">
</p>

**SecureStego** is a desktop application that lets you **embed short encrypted messages** inside JPEG images using **mid-frequency DCT coefficients**.  
The method is reasonably robust against moderate JPEG recompression (quality 75–92), making it more practical for messengers, email attachments and cloud storage than classic spatial LSB techniques.

The payload is protected with **ChaCha20-Poly1305** authenticated encryption (256-bit key derived via PBKDF2).

> ⚠️ **2026 security reality check**  
> No consumer steganography tool is undetectable against modern deep-learning steganalysis (SRNet, XuNet, Zhu-Net, etc.). Detection rates often exceed **90–95%** even at low embedding rates.  
> **Real security depends far more on strong OPSEC** than on the technical hiding method.

## ✨ Features

- Embedding in mid-frequency DCT coefficients of the luminance (Y) channel  
- Survives JPEG recompression at quality 75–90 in most realistic cases  
- ChaCha20-Poly1305 AEAD encryption & authentication  
- Per-message random 32-byte salt + 12-byte nonce  
- Fixed-length prefix → reliable, blind extraction  
- Modern, clean PyQt5 graphical user interface  
- Basic payload capacity estimation & password strength feedback  
- Salt shown as base64 (easy secure sharing)

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the application
python main.py
# or replace main.py with your actual entry-point filename

