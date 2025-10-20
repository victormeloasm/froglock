Absolutely — here’s a **fully fleshed-out README** with a detailed, plain-English user manual for Ghost v5.3. It’s written so a newcomer can install, use, and troubleshoot without asking you anything.

---

# 🐸 FROGLock — Ghost-Level Hybrid Encryption (v5.3)

**AES-256-GCM + Argon2id + ECCFrog522PP (KEM) — single-file, Windows-focused**

![Screenshot](screen.png)

[![Release](https://img.shields.io/badge/Release-5.3-green)](https://github.com/victormeloasm/froglock/releases/tag/5.3)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2B-blue)](#)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Ops](https://img.shields.io/badge/Ghost-Logs%20Off%20%7C%20No%20Telemetry-black)](#)
[![Security](https://img.shields.io/badge/Security-Military--Grade-red)](#)

---

## 📥 Download (Windows)

**Ghost Build (portable):**
`FROGLock-GHOST_v5_3.zip` → unzip → run `FROGLock_GHOST_v5_3.exe`
Direct link: **[https://github.com/victormeloasm/froglock/releases/download/5.2/FROGLock-GHOST_v5_3.zip](https://github.com/victormeloasm/froglock/releases/download/5.2/FROGLock-GHOST_v5_3.zip)**

* No installer, no admin required.
* Runs in *ghost mode*: no logs, no registry writes by design.
* All cryptographic state lives in memory and is wiped best-effort.

> ⚠️ If SmartScreen or AV warns (common for new portable tools): click **More info → Run anyway** after verifying the file came from the official repo.

---

## 📚 What FROGLock Does (in one paragraph)

* It encrypts files using **AES-256-GCM** with a random 256-bit **DEK**.
* That DEK is sealed using **hybrid 2-of-2**:
  **(1) your password via Argon2id KDF** and **(2) ECCFrog522PP KEM** to the recipient’s public key(s).
* To decrypt, both are required: **correct password + matching FROG private key**. No pass-only or KEM-only mode.

---

## 🧠 Quick Start (10 steps, first time)

1. **Launch** the app (`FROGLock_GHOST_v5_3.exe`).
2. At the top-right, leave **Paranoid Mode** ON (recommended).
3. Click **Generate FROG Keypair**.

   * Creates `frog522pp.sk` (private) and `frog522pp.pub` (public, Base64) in the app folder.
   * Your public key is copied to clipboard automatically.
4. **Share your public key** (the Base64 string from clipboard) with people who should send you encrypted files.
5. To add recipients you want to encrypt **for**:

   * Click **Recipients…**, paste their Base64 public keys (one per line), click **Save**.
6. **Choose a file**:

   * In Paranoid Mode, paste the full path in **Manual Path**.
   * Or temporarily toggle Paranoid off and use **Browse**.
7. **Enter a strong password** (or **Generate Password**).
8. Click **Encrypt**.

   * Output name is random in Paranoid Mode (example: `file_ab12cd34.aesc`), or `<file>.aesc` in Standard Mode.
   * Clipboard is sanitized automatically.
9. **Send the `.aesc` file** to recipients — they’ll need their FROG private key plus the correct password.
10. When closing the app, your local `frog522pp.sk` in the app folder is **secure-wiped**.

---

## 🖥️ UI Walkthrough

### Header

* **Title + Version + Mode:** shows **Paranoid** (recommended) or **Standard**.
* **Paranoid Mode (checkbox or F9)**

  * Disables **Browse** dialog (less shell traces).
  * Encourages **Manual Path**.
  * Uses **randomized output names**.
  * Suggests/deletes originals (if you uncheck “Keep original”).

### Card 1 — File & Password

* **File (dialog):** Normal file picker (disabled in Paranoid).
* **Manual Path:** Paste a full path like `C:\Users\me\Desktop\photo.jpg`.
* **Password (hybrid):** The passphrase used by Argon2id to derive your KEK.

  * **Show** toggles masking.
  * **Generate Password** creates a 45-char strong pass.
  * **Copy Password** puts it in the clipboard (clipboard is auto-cleared on encrypt).
* **Keep original after encrypt:** If unchecked, the app **tries** to delete the plaintext after a successful encrypt.

### Card 2 — Key Management (FROG)

* **Recipients…**: Paste **other people’s** FROG public keys (Base64, one per line).
* **Generate FROG Keypair**: Saves your new `frog522pp.sk` and `frog522pp.pub`.
* **Upload FROG .sk…**: Import your existing private key for decrypting.
* **Copy Public Key**: Copies your `frog522pp.pub` (Base64 canonical) to share.
* **Open Keys Folder**: Opens the app directory (where keys live).
* On exit, `frog522pp.sk` in the app folder is **securely wiped**. Keep your **backup** elsewhere!

### Card 3 — Actions & Status

* **Encrypt / Decrypt** buttons
* **Clear All**: resets inputs and recipient list for this session.
* **Progress bar** & percent indicator.

---

## 🔐 Encryption Flow (step-by-step)

1. **Inputs required**:

   * File path (Manual Path in Paranoid mode recommended)
   * Password (non-empty)
   * ≥1 valid recipient public key (Base64 ECCFrog522PP)

2. **Internals**:

   * Generate random **DEK (32 bytes)** for AES-GCM.
   * **Argon2id (autotuned)** derives a pass-KEK from your password.
   * For each recipient pubkey, **ECCFrog522PP KEM** produces a kem-KEK.
   * The **final wrap KEK = blake3(pass-KEK || kem-KEK || header-stub)**.
   * The DEK is sealed and stored in **hybrid-wrap entries** inside the header.
   * The file is chunk-encrypted with **AES-256-GCM**, random padding is appended, and the **tag** is written.

3. **Outputs**:

   * One `.aesc` file with:

     * A compact JSON header (algorithm info + hybrid entries),
     * AES-GCM ciphertext + tag.

> **Note:** Clipboard is overwritten, DEK is zeroized, sensitive buffers are locked/cleared best-effort via Windows APIs when available.

---

## 🔓 Decryption Flow

1. **Inputs required**:

   * `.aesc` file
   * Correct password
   * **Your matching** `frog522pp.sk` (private key) present in the app folder (or uploaded).

2. **Internals**:

   * Reads header, recomputes pass-KEK via Argon2id using stored parameters.
   * Tries each hybrid-wrap with your private key; once one unwraps the DEK, it decrypts the file.
   * Removes random padding at the end.

3. **Outputs**:

   * The original filename if free; otherwise `filename.dec`.
   * If the password or key doesn’t match **any** wrap, you get:
     **“Hybrid unlock failed (password or FROG key mismatch).”**

> **Anti-bruteforce:** The app limits attempts per file within a time window.

---

## 👁️ Paranoid Mode (recommended)

* **ON by default**. Toggle with the checkbox or **F9**.
* Disables **Browse**, encourages **Manual Path** (fewer shell MRU traces).
* Produces **randomized output names** like `file_a1b2c3d4.aesc`.
* Makes it easy to delete originals after successful encryption.

---

## 🧾 Key Files & Locations

* **`frog522pp.pub`** — your public key (Base64 canonical). Share this.
* **`frog522pp.sk`** — your private key. Never share this.

  * **Stored in the app directory.**
  * Protected with **owner-only ACLs** (if `pywin32` installed) or `0600` permissions fallback.
  * **Auto-wiped on exit** (multi-pass overwrite + delete best-effort).
* Back up `frog522pp.sk` **elsewhere** securely. If you lose it, you **cannot** decrypt hybrid files.

---

## ⚙️ Advanced Options

* **Adaptive chunk size**: 64 KiB → up to **4 MiB** based on file size and available RAM.
* **Memory-mapped I/O** for huge files (≥ 1 GiB): set env var **`FROG_MMAP=1`**.

  * Optional threshold override: **`FROG_MMAP_MIN_MB=1024`** (default 1024 = 1 GiB).
* **Attempt limiting**: per-file rate limit to slow brute-force.
* **Anti-debug** checks and Windows hardening (SetErrorMode, VirtualLock/Unlock, SecureZeroMemory).

---

## 🏗️ Build from Source (Windows)

**Requirements:** Python 3.11+, `pip`

```bash
git clone https://github.com/victormeloasm/froglock.git
cd froglock
pip install -r requirements.txt
# Optional speedups
pip install numpy gmpy2 pywin32
python FROGLock_GHOST_v5_3.py
```

### Portable EXE (PyInstaller, **no UPX**)

One-liner (PowerShell/CMD):

```bash
pyinstaller --noconfirm --onefile --clean --noupx --noconsole ^
  --name FROGLock_GHOST_v5_3 ^
  --hidden-import argon2.low_level --hidden-import blake3 ^
  --runtime-tmpdir "%TEMP%\frog_%USERNAME%" FROGLock_GHOST_v5_3.py
```

Tips:

* `--noupx` ensures **no UPX** is used.
* You can `--exclude-module numpy --exclude-module gmpy2` if you want the smallest build.

---

## 🧪 Security Model (short)

* **Confidentiality & integrity**: AES-256-GCM with 96-bit nonce and 128-bit tag.
* **Hybrid secrecy**: DEK unwrap requires both **password (Argon2id)** and **FROG private key**.
* **Zero-trust**: No telemetry, no network, no background services.
* **Memory hygiene**: VirtualLock/Unlock, SecureZeroMemory, buffer zeroization best-effort.
* **Disk hygiene**: Temporary files created with owner-only ACL; private key secure-wiped on exit.
* **Header**: JSON with minimal metadata, includes Argon2 parameters and hybrid wraps; no plaintext filenames or paths.

---

## 🚑 Troubleshooting & Common Errors

* **“Invalid path.”**
  Path contains `..` or invalid segments. Paste a clean absolute path.

* **“Hybrid is mandatory: add at least one FROG recipient.”**
  You tried to encrypt without recipients. Open **Recipients…**, paste Base64 public key(s), **Save**.

* **“Missing FROG secret key (.sk).”**
  For decryption, you must have your private key (`frog522pp.sk`) in the app folder (or upload it).

* **“Hybrid unlock failed (password or FROG key mismatch).”**
  Either the password is wrong **or** your private key doesn’t match any wrap in the file header.

* **“Too many attempts. Wait a bit.”**
  The anti-bruteforce window is active. Wait a few minutes.

* **SmartScreen / AV warning**
  Verify you downloaded from the official repo, then **More info → Run anyway**.

* **“No valid FROG recipients. Check the public keys.”**
  One or more pasted public keys were invalid (bad Base64 or not on curve). Paste canonical Base64 only.

---

## 📈 Performance Notes

* AES-GCM encryption runs at NVMe speeds; KEM wraps are parallelized.
* `gmpy2` speeds up ECC; `numpy` accelerates buffer XOR ops.
* Argon2id is **autotuned** for the host — expect 64–512 MiB memory use by default.

---

## 🔄 Changelog (v5.3 — 2025-10-20)

* **SecureEntry**: password handled as `bytearray`, zeroized; entry cleared on read.
* **Parallel KEM** for multiple recipients (dynamic thread pool).
* **Adaptive chunk size** (up to 4 MiB) and optional **mmap** for huge files.
* **Windows hardening**: SetErrorMode, anti-debug checks, VirtualLock/Unlock, SecureZeroMemory.
* **Owner-only ACL** for key/temp files (pywin32 if available).
* **Clipboard wipe** on encrypt; **auto-clear password** after 5 minutes idle.
* **UI**: Dark theme, tooltips, progress, virtual keyboard; **Paranoid Mode** refined.
* **Anti-bruteforce** per file; safer path validation and atomic writes.

---

## ❓ FAQ

**Q: Can I decrypt with just the password?**
No. Hybrid is **mandatory**: password **and** your FROG private key must match.

**Q: Where should I store my private key?**
Keep `frog522pp.sk` in the app folder only while using the app, and store a **backup** in a secure location offline.

**Q: What if I lose `.sk`?**
You cannot recover hybrid-encrypted files. That’s by design.

**Q: Does it leave traces?**
FROGLock avoids logs and registry writes; Paranoid Mode reduces shell traces by disabling Browse and favoring Manual Path. As always, OS and third-party tools may still leave indirect traces (recent files, AV caches, etc.).

---

## 📜 License & Disclaimer

**MIT License** — see [LICENSE](LICENSE).
This software is provided **“as is”** without warranty. Use responsibly. The authors are **not liable** for data loss, misuse, or outcome of cryptographic decisions.

---

If you want, I can also generate a **separate `USER_GUIDE.md`** (same content, printer-friendly) or a **cheatsheet** you can ship alongside the EXE.
