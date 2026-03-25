# converter-
This Python script leverages the VirusTotal API to convert MD5 hashes into SHA-256 format.
# Features
| Feature                    | Description                                                               |
| -------------------------- | ------------------------------------------------------------------------- |
| **🔒 Double Verification** | Validates that VT-returned MD5 matches original before extracting SHA-256 |
| **⏯️ Resume Support**      | Interrupt and resume without re-processing completed hashes               |
| **⏱️ Rate Limiting**       | Configurable delays to respect API tiers (free/paid)                      |
| **📊 Progress Tracking**   | Real-time console output with success/failure counters                    |
| **✅ Input Validation**     | Validates MD5 format (32 hex characters) before API calls                 |
| **🛡️ Error Resilience**   | Handles network errors, rate limits, and missing hashes gracefully        |
| **💾 Auto-Save**           | Flushes results to disk after each entry (crash-safe)                     |
| **📈 Batch Processing**    | Efficiently processes thousands of hashes with single session             |
| **🔧 Flexible I/O**        | Custom column mapping for non-standard CSV formats                        |
| **📝 Detailed Logging**    | Status codes: `success`, `not_found`, `hash_mismatch_or_missing`          |

# Quick Start
## 🚀 Quick Start

| Step | Command |
|------|---------|
| **1. Install dependencies** | `git clone ` |
| **2. Run (free tier - ~15s delay)** | `python md5convet.py hashes.csv output.csv --api-key YOUR_VT_API_KEY` |
| **3. Resume interrupted job** | `python md5convet.py hashes.csv output.csv --api-key KEY --resume` |
| **4. Paid tier (faster)** | `python md5convet.py hashes.csv output.csv --api-key KEY --rate-limit 1.0` |

# Command Line Options
## ⚙️ Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--api-key` | VirusTotal API key (required) | - |
| `--md5-column` | Column name for MD5 hashes | `md5` |
| `--rate-limit` | Seconds between requests | `15.0` |
| `--resume` | Resume from existing output file | `False` |

🎯 Use Cases
- Threat Intelligence: Enrich legacy MD5 indicators with SHA-256
- SIEM Migration: Convert hash formats for compatibility
- Malware Research: Build comprehensive hash databases
- IOC Enrichment: Augment threat feeds with additional hash types

# Performance Estimates
| API Tier   | Rate Limit   | 5000 Hashes Est. Time |
| ---------- | ------------ | --------------------- |
| Free       | 4 req/min    | ~21 hours             |
| Premium    | 60 req/min   | ~1.5 hours            |
| Enterprise | 600+ req/min | ~10 minutes           |

# 📜 License
MIT License



