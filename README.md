# 🔐 JWTScout

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go-00ADD8?style=for-the-badge&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-000000?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge" alt="Version">
</p>

**JWTScout** is a production-ready, high-performance command-line interface (CLI) tool designed for security researchers, penetration testers, and bug bounty hunters. It provides a comprehensive suite for analyzing, auditing, and exploiting vulnerabilities in JSON Web Tokens (JWT).

---

## 🚀 Key Features

- **🔍 Intelligent Analysis**: Automatically decodes and audits tokens for common misconfigurations, weak algorithms, and sensitive data leakage.
- **🛡️ Algorithm Attack Suite**:
  - **alg: none**: Automated generation of unsigned tokens.
  - **Algorithm Confusion**: RS256 to HS256 conversion attacks.
  - **Algorithm Downgrade**: Testing resistance against weaker algorithm enforcement.
- **⚡ High-Speed HMAC Brute Forcer**: Multi-threaded secret recovery with support for custom wordlists and early termination.
- **🛠️ Advanced Token Forging**:
  - Manipulate any claim (role, permissions, timestamps).
  - Support for Integer, Boolean, and String claim values.
  - Real-time re-signing with known secrets.
- **💉 Header Injection Engine**: Generates payloads for `kid` header vulnerabilities (Path Traversal, SQLi, Command Injection).
- **🎨 Premium UX**: Beautiful, colorized, severity-based terminal reporting with clear actionable findings.

---

## 🛠️ Installation

### Prerequisites

- [Go](https://golang.org/doc/install) 1.18 or higher.

### Quick Install (Recommended)

If you have Go installed, you can install JWTScout directly:

```bash
go install -v github.com/ismailtsdln/JWTScout@latest
```

This will automatically download, compile, and install the `JWTScout` binary to your `$GOPATH/bin` directory.

### Build from Source

```bash
# Clone the repository
git clone https://github.com/ismailtsdln/JWTScout.git

# Navigate to the project directory
cd JWTScout

# Build the binary
go build -o jwtscout main.go

# (Optional) Move to your path
sudo mv jwtscout /usr/local/bin/
```

---

## 📖 Usage Guide

### 1. Security Analysis

Audit a token for vulnerabilities and misconfigurations.

```bash
jwtscout analyze --token <JWT>
```

### 2. HMAC Brute Forcing

Attempt to recover the signing secret using a wordlist.

```bash
jwtscout brute --token <JWT> --wordlist common-secrets.txt --workers 50
```

### 3. Algorithm Vulnerability Testing

Generate test cases for `alg:none` and confusion attacks.

```bash
jwtscout alg-test --token <JWT>
```

### 4. Professional Token Forging

Modify claims and re-sign a token.

```bash
jwtscout forge --token <JWT> --claim role=admin --claim admin=true --secret "mysecret123"
```

### 5. Header Injection Testing

Generate injection payloads for the `kid` header.

```bash
jwtscout kid-test --token <JWT>
```

---

## 🏗️ Architecture

The project follows a clean, modular design focused on extensibility:

- `internal/parser`: Robust JWT decoding and validation engine.
- `internal/validator`: Security logic and finding generators.
- `internal/brute`: Thread-safe, context-aware brute force engine.
- `internal/forge`: High-level API for token manipulation and signing.
- `internal/attacker`: Implementation of specific attack vectors.
- `internal/reporter`: Aesthetic terminal output management.

---

## ⚠️ Ethical & Legal Disclaimer

**JWTScout is intended for authorized security testing and educational purposes only.**

Illegal use of this tool against targets without prior written consent is strictly prohibited. The developer assumes no liability and is not responsible for any misuse or damage caused by this program. Users are expected to comply with all applicable local, state, and federal laws.

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Developed with ❤️ by <b>Ismail Tasdelen</b><br>
  <i>Empowering security professionals through better tools.</i>
</p>
