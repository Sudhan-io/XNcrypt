# XCrypt - Advanced Encryption Tool

**XCrypt** is a Python-based GUI application that enables users to encrypt and decrypt text using multiple classical and modern cipher algorithms.  
It is built with `Tkinter` and supports 10 encryption methods including Caesar, Vigenère, AES, RSA (simulated), Base64, and more.

---

## Features

- Graphical User Interface using Python's Tkinter
- Support for 10 encryption and decryption algorithms
- Auto key generation for AES and RSA methods
- File input and output support (.txt)
- Clipboard copy functionality
- Dynamic key field adjustments based on selected cipher
- Input validation and exception handling

---

## Supported Encryption Methods

| Cipher       | Key Required | Description                             |
|--------------|--------------|-----------------------------------------|
| Caesar       | Yes (Integer) | Shifts letters by a fixed number        |
| Vigenère     | Yes (String)  | Shifts letters using a keyword          |
| Base64       | No            | Encodes text in Base64 format           |
| ROT13        | No            | Caesar cipher variant (shift 13)        |
| Atbash       | No            | Reverses the alphabet                   |
| AES          | Yes (Password) | Symmetric encryption (Fernet based)     |
| RSA (Simulated) | Yes (Two primes) | Basic educational RSA implementation |
| XOR          | Yes (String)  | Character-wise XOR transformation       |
| Morse Code   | No            | Converts text to Morse and vice versa   |
| Binary       | No            | Converts text to 8-bit binary and back  |

---

## Installation

### Requirements

- Python 3.8+
- Required packages:

```bash
pip install cryptography