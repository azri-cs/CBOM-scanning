# CBOM-SCANNER

Standalone Python scanners for finding cryptography-related assets on hosts you administer. This repo is a flat set of scripts (not an installable package). **Primary target: Linux.** Several scripts also run on Windows with reduced or alternate behavior; macOS and other Unix variants are not fully validated (for example, Linux-oriented tools such as `ldd` may not apply).

This fork: [azri-cs/CBOM-scanning](https://github.com/azri-cs/CBOM-scanning). Upstream: [msaufyrohmad/CBOM-scanning](https://github.com/msaufyrohmad/CBOM-scanning).

### Cryptography in the system
<img width="1003" height="565" alt="Cryptography in the system" src="https://github.com/user-attachments/assets/a51c4196-c402-45d9-8ea4-e5295a0c9be9" />

### Cryptography in all layers
<img width="1003" height="565" alt="Cryptography in all layers" src="https://github.com/user-attachments/assets/4d13abde-fb15-461e-b5dd-041594ee7dc0" />

### Types of cryptographic sources
<img width="931" height="472" alt="Types of cryptographic sources" src="https://github.com/user-attachments/assets/16be887d-f637-4f00-bf61-d47e9137841a" />

## 1. Dependencies

Use Python 3.8+ recommended. This repo does not ship a committed `requirements.txt`; generate it from the scripts’ imports, then install.

```bash
git clone https://github.com/azri-cs/CBOM-scanning.git
cd CBOM-scanning
python3 -m pip install pipreqs
pipreqs . --encoding=utf-8
python3 -m pip install -r requirements.txt
```

`pipreqs` writes `requirements.txt` in the project root. Typical packages include `cryptography`, `psutil`, and `xmltodict`. If `DISCOVERY.py` fails on `import nmap`, install the binding explicitly (PyPI package name **`python-nmap`**, import name `nmap`). Re-run `pipreqs` after changing imports if you want the file to stay in sync.

**Optional / script-specific (install separately):**

| Need | Used by |
|------|---------|
| System `strings`, `nm`, `ldd`, `find` | `1BinariesUsed.py`, `2BinariesDisk.py`, `3Libraries.py`, `4Kernel_mod.py` (as applicable) |
| `sslscan` | `9NetworkProtocol.py` |
| System `nmap` + Python package `python-nmap` (`import nmap`) | `DISCOVERY.py` |

Elevated privileges (`sudo` on Linux) improve completeness for process, socket, kernel, and deep filesystem scans. Network scripts may require root for raw scans or full OS detection.

### Environment self-check

Run `python3 scanner_env.py` to print JSON describing the current OS, Python version, whether `/proc` is available (Linux), and which optional CLI tools (`strings`, `nm`, `ldd`, `dumpbin`, `otool`, `sslscan`, `nmap`, `find`) are on `PATH`. Use this before interpreting scan results on an unfamiliar host.

## 2. Scripts, outputs, and notes

Run scripts from the repo root; most write CSV/JSON into the **current working directory** with fixed filenames.

| Script | Role | Default output | Notes |
|--------|------|----------------|-------|
| `scanner_env.py` | Print OS and tool availability (JSON to stdout) | — | Not a scanner; use for troubleshooting |
| `scanner_platform.py` | Shared helpers (`psutil` executables, `ldd` / `otool` / `dumpbin`) | — | Imported by other scripts |
| `1BinariesUsed.py` | Running executables + crypto heuristics | `binaries_used.csv` | Uses `strings` / `ldd` on Unix-like systems |
| `2BinariesDisk.py` | Binaries on disk | `binaries_at_disk.csv` | Same tooling assumptions as (1) |
| `3Libraries.py` | Shared libraries | `library.csv` | Success message may still say `library_crypto_inventory.csv` |
| `4Kernel_mod.py` | Kernel modules (`.ko`) | `kernel_modules.csv` | **Linux only**; Windows prints a stub message |
| `5CertKeys.py` | Cert/key discovery (heavy FS scan) | `crypto_cert_key.csv` | PEM-focused; many `.der`/PKCS#12 files are skipped |
| `6ExeCodes.py` | Script-like crypto in executables | `exec_script.csv` | |
| `7Web_App.py` | Web roots | `web_app.csv` | Fixed OS web roots only (not arbitrary paths without edits) |
| `8NetworkApp.py` | TLS/listening processes | `network_app.csv` | |
| `9NetworkProtocol.py` | Remote TLS via `sslscan` | Directory per target + `combined_results.json` under `--out-dir` | See section 3 |
| `DISCOVERY.py` | LAN port/OS scan | `scan_results.json`, `DISCOVERY_results.csv` | Subnet is **hardcoded** in the file; change before use |
| `read_cert.py` | Single-file PEM check | stdout (JSON) | `python3 read_cert.py <file>` |

## 3. Script 9 (TLS targets file)

The targets file is the **first** argument. The output directory is created automatically if missing.

```bash
python3 9NetworkProtocol.py targets.txt --out-dir result --workers 6 --timeout 90
```

`targets.txt` should list one `host` or `host:port` per line. `sslscan` must be on `PATH`.

## 4. Roadmap (upstream)

Planned improvements mentioned by the original project include CycloneDX v1.7 output, PTPKM-related properties, and deeper configuration inspection.

## 5. Contact (original project)

Muhammad Saufy Rohmad — Malaysia Cryptology Technology and Management Center — saufy@uitm.edu.my
