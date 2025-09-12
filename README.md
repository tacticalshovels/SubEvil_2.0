# SubEvil 2.0

**SubEvil 2.0** is a fast, stdlib-only subdomain reconnaissance tool based on [SubEvil](https://github.com/Evil-Twins-X/SubEvil).
It enumerates subdomains from multiple passive sources, probes them to check if they’re alive, and optionally resolves their IPs.
---

## ✨ Features

- 🔍 **Subdomain enumeration** from 20+ passive sources (AlienVault, Censys, Shodan, VirusTotal, etc.)
- 🌐 **Automatic probing** (HTTP + HTTPS) — only **alive** subdomains are output
- 🖥️ **IP resolution** (enabled by default)  
  - Prints IPs below each subdomain in text mode  
  - Can be disabled with `--no-resolve`
- 🏷️ **Optional details** with `--details`  
  - HTTP status code  
  - Page `<title>` tag
- 💾 Multiple output formats:  
  - `text` (default, clean for stdout)  
  - `json`  
  - `csv`  
  - `ndjson`
- 🔧 Options:  
  - `--with-sources` → include source attribution  
  - `--timeout` → set probe timeout (default 4s)  
  - `--max-workers` → concurrency (default 24)  
  - `--quiet` → suppress logs/banners  
  - `--version` → show version
- 🎡 **Spinner-based progress updates** for sources, probing, and resolution (in human text mode)

---

## 🔄 Comparison

| Feature                  | **SubEvil** | Sublist3r | Amass |
|---------------------------|-------------|-----------|-------|
| Passive sources included  | ✅ (20+)    | ✅ (few)  | ✅ (many) |
| Active probing (HTTP/HTTPS)| ✅ Always alive-only | ❌ No | ✅ Optional |
| IP resolution             | ✅ Default  | ❌ No     | ✅ Optional |
| Output formats            | text, json, csv, ndjson | text | text, json, graph |
| Page title / status codes | ✅ (`--details`) | ❌ No | ✅ Optional |
| Spinner progress          | ✅ Yes      | ❌ No     | ❌ No |
| Dependencies              | ❌ None (stdlib only) | ✅ Requires `requests` etc. | ✅ Requires many |
| Setup complexity          | ⭐ Easy     | ⭐ Easy   | ⚠️ Heavy |
| Speed (default config)    | ⚡ Fast     | ⚡ Fast   | 🐢 Slower (deep scans) |

👉 SubEvil focuses on **simplicity + speed**, making it ideal for quick reconnaissance where you only want **alive, resolvable subdomains** in clean output.

---

## 🚀 Usage

# Basic: print alive subdomains + IPs
python subevil.py example.com

# Just subdomains (no IPs)
python subevil.py example.com --no-resolve

# Include HTTP status and page title
python subevil.py example.com --details

# JSON output with sources
python subevil.py example.com --format json --with-sources | jq .

login.example.com
93.184.216.34
api.example.com
2606:2800:220:1:248:1893:25c8:1946




# Save results to CSV
python subevil.py example.com --format csv -o alive.csv
