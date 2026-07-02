# lead‑debounce

> Red Team Email Validation Framework – FOR AUTHORIZED TESTING ONLY

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-UNLICENSED-red)

## ⚠️ LEGAL WARNING

**Unauthorized use of this tool is a FEDERAL CRIME.**  
Use **only** against systems you own or have explicit written permission to test.

---

## 📦 Installation

```bash
git clone <your-repo>
cd lead-debounce
npm install
```

## 🚀 Quick Start

```bash
export REDTEAM_MODE=1
npm start
```

Or directly:

```bash
node lead-debounce.js
```

## 🧰 Features

- **Interactive CLI** with a beautiful figlet banner
- **Multi-threaded** email validation (configurable concurrency)
- **SMTP direct verification** with retry logic
- **Catch‑all detection** per domain
- **Proxy support** (SOCKS5/HTTP) for IP rotation
- **Debug mode** to inspect SMTP dialogue
- **Persistent configuration** (saves settings)
- **Export results** to JSON and plain text

## 📋 Menu Options

| Option | Description |
|--------|-------------|
| 1 | Load targets from a text file (one email per line) |
| 2 | Add a single email manually |
| 3 | Set concurrency (parallel connections) |
| 4 | Set proxy list file path |
| 5 | Toggle debug mode |
| 6 | Run the validation engine |
| 7 | Export results (valid/invalid lists + JSON) |
| 8 | Configure Telegram C2 (stub) |
| 9 | Clean logs (remove exported files) |
| 0 | Exit |

## 📁 File Outputs

- `valid_emails.txt` – list of verified addresses
- `invalid_emails.txt` – list of invalid or unreachable addresses
- `results.json` – full detailed results (includes status per email)
- `lead-debounce-config.json` – your saved settings (auto‑created)

## 🔧 Dependencies

- [chalk](https://www.npmjs.com/package/chalk) – terminal styling
- [figlet](https://www.npmjs.com/package/figlet) – ASCII banners
- [socks-proxy-agent](https://www.npmjs.com/package/socks-proxy-agent) – proxy support (optional)

## 🙏 Disclaimer

This tool is provided **as‑is** for educational and red‑team purposes.  
The authors assume **no liability** for misuse.  
**Obtain proper authorisation before use.**

---

**Made with** ❤️ **by </>**