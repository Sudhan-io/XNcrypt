
# XCrypt - Advanced Encryption Tool

---

## Topic

**XCrypt** is a beginner-friendly, Python-based GUI tool that helps users encrypt and decrypt text using both classical and modern cipher algorithms. Whether youâ€™re exploring cryptography or need to encode information securely, this tool provides you a sleek, functional interface with 10 different cipher options â€” all in one place.

---

##Explanation

XCrypt is built using Pythonâ€™s Tkinter library for the GUI and the `cryptography` library for secure methods like AES.  
The tool is designed to make encryption easy to understand and use for both students and developers.  
Users can select an encryption method, input text and a key (if required), and instantly encrypt or decrypt the message. It supports file handling and password/key generation too.

---

##Features

- Simple and modern GUI (Tkinter-based)
- 10 built-in encryption and decryption algorithms
- Auto key generation (AES and RSA)
- Keyless algorithms supported (Base64, ROT13, etc.)
- File operations: Load from and Save to `.txt`
- Copy to clipboard support
- Input validation and beginner-friendly error handling

---

##Supported Encryption Methods

| Cipher           | Key Required       | Description                                      |
|------------------|--------------------|--------------------------------------------------|
| Caesar           | Yes (Integer)      | Shifts each letter by a fixed number             |
| VigenÃ¨re         | Yes (String)       | Uses a keyword to shift characters               |
| Base64           | No                 | Converts plain text to base64 format             |
| ROT13            | No                 | Caesar variant with fixed shift of 13           |
| Atbash           | No                 | Reverses the alphabet (Aâ†”Z, Bâ†”Y, etc.)           |
| AES              | Yes (Password)     | Strong symmetric encryption (Fernet-based)       |
| RSA (Simulated)  | Yes (Two primes)   | Basic educational public-key encryption          |
| XOR              | Yes (String)       | XORs each character with repeating key           |
| Morse Code       | No                 | Translates to dots & dashes                      |
| Binary           | No                 | Converts text to 8-bit binary                    |

---

##Installation

### Requirements

- Python 3.8 or higher

### Install the required library:

```bash
pip install cryptography
```

---

##How to Use Each Encryption Method

### Caesar Cipher
- **Input Text:** Alphabetic message like `HELLO`
- **Key:** An integer between 0â€“25 (e.g., `3`)
- **Example:**
  - Input: `HELLO`
  - Key: `3`
  - Output: `KHOOR`

---

### VigenÃ¨re Cipher
- **Input Text:** Alphabetic text like `HELLOWORLD`
- **Key:** A word or string (e.g., `KEY`)
- **Example:**
  - Input: `HELLO`
  - Key: `KEY`
  - Output: `RIJVS`

---

### Base64
- **Input Text:** Any plain text (e.g., `hello123`)
- **Key:** Not required
- **Example:**
  - Input: `hello123`
  - Output: `aGVsbG8xMjM=`

---

### ROT13
- **Input Text:** Alphabetic text (e.g., `HELLO`)
- **Key:** Not required
- **Example:**
  - Input: `HELLO`
  - Output: `URYYB`
- **Note:** ROT13 is self-reversible â€” same for encrypt and decrypt

---

### Atbash
- **Input Text:** Alphabetic text (e.g., `HELLO`)
- **Key:** Not required
- **Example:**
  - Input: `HELLO`
  - Output: `SVOOL`

---

### AES (Advanced Encryption Standard)
- **Input Text:** Any text (e.g., `My secret data`)
- **Key:** A password like `StrongPass123` or use `Generate Key`
- **Example:**
  - Input: `secret`
  - Key: `StrongKey2024`
  - Output: Encrypted base64 string
- **Note:** Decryption requires the exact same password

---

### RSA (Simulated)
- **Input Text:** Any short text (e.g., `HELLO`)
- **Key:** Two comma-separated primes (e.g., `17,23`) or use `Generate Key`
- **Example:**
  - Input: `HELLO`
  - Key: `17,23`
  - Output: `n=391,d=169;65 99 212...`
- **Note:** Only for educational use

---

### XOR Cipher
- **Input Text:** Any text (e.g., `DATA`)
- **Key:** A word (e.g., `pass`)
- **Example:**
  - Input: `HELLO`
  - Key: `key`
  - Output: Encrypted string (may look like symbols)
- **Note:** Use the same key to decrypt

---

### Morse Code
- **Input Text:** Letters or numbers (e.g., `SOS`)
- **Key:** Not required
- **Example:**
  - Input: `SOS`
  - Output: `... --- ...`

---

### Binary Encoding
- **Input Text:** Any short word (e.g., `A`)
- **Key:** Not required
- **Example:**
  - Input: `ABC`
  - Output: `01000001 01000010 01000011`