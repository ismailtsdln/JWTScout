# 🔐 JWTScout

JWTScout is a production-ready CLI-based JWT security testing tool written in Go. It is designed for offensive security professionals, penetration testers, and bug bounty hunters to analyze, audit, and exploit weaknesses in JSON Web Tokens (JWT).

## 🚀 Features

- **Token Analysis**: Decodes and inspects JWT headers and payloads for insecure configurations.
- **Algorithm Testing**: Automatically tests for `alg: none`, algorithm confusion (RS256 ↔ HS256), and algorithm downgrades.
- **HMAC Brute Forcing**: High-performance HMAC secret brute-forcing using concurrent workers and custom wordlists.
- **Token Forging**: Modify claims (e.g., privilege escalation) and re-sign tokens if the secret is known, or generate unsigned (`alg: none`) tokens.
- **`kid` Header Injection**: Generates payloads for common `kid` header vulnerabilities, including path traversal, SQL injection, and URL references.
- **Severity-Based Reporting**: Beautiful, colorized CLI output with clear security findings and severity levels.

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/ismailtsdln/JWTScout.git

# Navigate to directory
cd JWTScout

# Build the binary
go build -o jwtscout main.go
```

## 📖 Usage Examples

### Analyze a Token

```bash
jwtscout analyze --token <JWT>
```

### Test Algorithms

```bash
jwtscout alg-test --token <JWT>
```

### Brute Force HMAC Secret

```bash
jwtscout brute --token <JWT> --wordlist payloads/common-secrets.txt --workers 20
```

### Forge a Token (Privilege Escalation)

```bash
jwtscout forge --token <JWT> --claim role=admin --secret "my-secret"
```

### Generate `kid` Injection Payloads

```bash
jwtscout kid-test --token <JWT>
```

## 🏗️ Architecture

The tool follows a modular, clean architecture:

- `cmd/`: CLI command definitions using Cobra.
- `internal/parser/`: JWT decoding and parsing logic.
- `internal/validator/`: Security rules and finding generation.
- `internal/attacker/`: Core attack logic (analyzer, alg-test, kid-test).
- `internal/brute/`: HMAC brute-force engine.
- `internal/forge/`: Token manipulation and signing.
- `internal/reporter/`: Formatted CLI output.

## ⚠️ Ethical & Legal Disclaimer

**JWTScout is for authorized security testing only.**

Testing JWT tokens on systems you do not own or have explicit permission to test is illegal. The developers of JWTScout are not responsible for any misuse of this tool. Use it ethically and responsibly.

## 📄 License

MIT License. See `LICENSE` for details.
