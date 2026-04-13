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

**Minimal Python install (if you prefer not to run `pipreqs` first):**

```bash
python3 -m pip install --user 'cryptography>=41' 'psutil>=5.9' 'xmltodict>=0.13' 'python-nmap>=0.7'
```

Omit `python-nmap` if you will not run `DISCOVERY.py`.

### Optional system tools (script-specific)

| Need | Used by |
|------|---------|
| `strings`, `nm`, `ldd`, `find` | `1BinariesUsed.py`, `2BinariesDisk.py`, `3Libraries.py`, `4Kernel_mod.py` (as applicable) |
| `sslscan` | `9NetworkProtocol.py` |
| `nmap` (system) + Python `python-nmap` | `DISCOVERY.py` |

Elevated privileges (`sudo` on Linux) improve completeness for process, socket, kernel, and full-filesystem scans. Network scripts may require root for raw SYN scans or full OS fingerprinting.

### Install commands by Linux distribution (optional packages)

Pick the block that matches the server. These install **system** tools only; install Python packages separately (see above).

**Debian / Ubuntu**

```bash
# Core helpers used by most local scanners (strings, nm, ldd, find)
sudo apt-get update
sudo apt-get install -y binutils findutils libc-bin

# Only if you run DISCOVERY.py (system nmap; still need: pip install python-nmap)
sudo apt-get install -y nmap

# Only if you run 9NetworkProtocol.py (package may be in universe; enable in sources.list if needed)
sudo apt-get install -y sslscan
```

**RHEL / Rocky Linux / AlmaLinux / Fedora (dnf)**

```bash
sudo dnf install -y binutils findutils glibc-common

# DISCOVERY.py
sudo dnf install -y nmap

# 9NetworkProtocol.py (enable CRB/PowerTools or use EPEL if the package is missing)
sudo dnf install -y sslscan
```

**Older RHEL / CentOS 7 (yum)**

```bash
sudo yum install -y binutils findutils glibc-common
sudo yum install -y nmap
# sslscan: use EPEL or build from source if not packaged
```

**SUSE / openSUSE (zypper)**

```bash
sudo zypper install -y binutils findutils glibc
sudo zypper install -y nmap
sudo zypper install -y sslscan
```

**Alpine (minimal images)**

```bash
apk add --no-cache binutils findutils musl-utils
apk add --no-cache nmap
# sslscan: often unavailable as package; build from source or run 9NetworkProtocol elsewhere
```

**Containers or air-gapped hosts:** Install the same logical tools in the image; if something is missing, `scanner_env.py` and the `scanner_limits` column in CSV output will show gaps.

### Environment self-check

Run `python3 scanner_env.py` to print JSON describing the current OS, Python version, whether `/proc` is available (Linux), and which optional CLI tools (`strings`, `nm`, `ldd`, `dumpbin`, `otool`, `sslscan`, `nmap`, `find`) are on `PATH`. Use this before interpreting scan results on an unfamiliar host.

### Optional environment variables

| Variable | Used by |
|----------|---------|
| `CBOM_EXTRA_LIB_DIRS` | `3Libraries.py` — additional library root directories to scan (same separator as `PATH` on your OS). Use for vendor trees under `/opt`, Flatpak/Snap exposure, or Nix store paths when a full walk is acceptable. |
| `CBOM_WEB_ROOTS` | `7Web_App.py` — override default web document roots (same separator as `PATH`). |

## 2. Using on a Linux server (recommended workflow)

**Best practice** is to run scanners **on the host being inventoried** (or in a privileged sidecar with the same filesystem and process namespace), from a **dedicated clone**, with outputs written to a **single staging directory** you can copy away. Use a **virtual environment** if you do not want project dependencies on system Python.

**One-time setup on the server**

```bash
cd /opt   # or your home directory, e.g. cd ~
sudo git clone https://github.com/azri-cs/CBOM-scanning.git cbom-scanning
sudo chown -R "$USER": cbom-scanning
cd cbom-scanning

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install pipreqs
pipreqs . --encoding=utf-8
python3 -m pip install -r requirements.txt
```

**Before every scan session**

```bash
cd /opt/cbom-scanning   # adjust path if you cloned elsewhere
source .venv/bin/activate
mkdir -p ~/cbom-out && cd ~/cbom-out
python3 /opt/cbom-scanning/scanner_env.py
```

**Typical local inventory (run from an output directory; use `sudo` when you need full process, socket, and kernel visibility)**

```bash
cd ~/cbom-out
sudo python3 /opt/cbom-scanning/1BinariesUsed.py
sudo python3 /opt/cbom-scanning/2BinariesDisk.py
sudo python3 /opt/cbom-scanning/3Libraries.py
sudo python3 /opt/cbom-scanning/4Kernel_mod.py
sudo python3 /opt/cbom-scanning/5CertKeys.py
sudo python3 /opt/cbom-scanning/6ExeCodes.py
sudo python3 /opt/cbom-scanning/7Web_App.py
sudo python3 /opt/cbom-scanning/8NetworkApp.py
```

Adjust `/opt/cbom-scanning` if your clone path differs. Scripts write CSV files into the **current working directory** (`~/cbom-out` here), not next to the scripts.

**Heavy or intrusive scans:** `5CertKeys.py` walks the filesystem from `/` by default; scope and runtime depend on disk size. Run it in a maintenance window or point it at a narrower subtree by editing the script or running only after other scans.

**Afterwards:** copy `~/cbom-out/*.csv` (and any JSON) off the server for analysis. For optional network tools:

```bash
cd ~/cbom-out
sudo python3 /opt/cbom-scanning/DISCOVERY.py 192.168.0.0/24 --nmap-args "-sT -sV -T4"
python3 /opt/cbom-scanning/9NetworkProtocol.py targets.txt --out-dir tls-results --workers 4 --timeout 90
```

Use `DISCOVERY` / `9NetworkProtocol` only where network scanning is authorized; they target **remote** hosts, not only localhost.

## 3. Scripts, outputs, and notes

Run scripts from the repo root; most write CSV/JSON into the **current working directory** with fixed filenames.

Scanner CSVs include **`os_fingerprint`** (concise OS/kernel/machine summary) and **`scanner_limits`** (which optional CLI tools were on `PATH` when the scan ran) on each row so results from different servers can be compared downstream.

| Script | Role | Default output | Notes |
|--------|------|----------------|-------|
| `scanner_env.py` | Print OS and tool availability (JSON to stdout) | — | Not a scanner; use for troubleshooting |
| `scanner_platform.py` | Shared helpers (`psutil` executables, `ldd` / `otool` / `dumpbin`) | — | Imported by other scripts |
| `1BinariesUsed.py` | Running executables + crypto heuristics | `binaries_used.csv` | Uses `strings` / `ldd` on Unix-like systems |
| `2BinariesDisk.py` | Binaries on disk | `binaries_at_disk.csv` | Same tooling assumptions as (1) |
| `3Libraries.py` | Shared libraries | `library.csv` | Debian multiarch and musl paths included; extend with `CBOM_EXTRA_LIB_DIRS` |
| `4Kernel_mod.py` | Kernel modules (`.ko`) | `kernel_modules.csv` | **Linux only**; Windows prints a stub message |
| `5CertKeys.py` | Cert/key discovery (heavy FS scan) | `crypto_cert_key.csv` | PEM-focused; many `.der`/PKCS#12 files are skipped |
| `6ExeCodes.py` | Script-like crypto in executables | `exec_script.csv` | |
| `7Web_App.py` | Web roots | `web_app.csv` | Defaults for common layouts; override with `CBOM_WEB_ROOTS` |
| `8NetworkApp.py` | TLS/listening processes | `network_app.csv` | |
| `9NetworkProtocol.py` | Remote TLS via `sslscan` | Directory per target + `combined_results.json` under `--out-dir` | See section 4 |
| `DISCOVERY.py` | LAN port/OS scan | `scan_results.json`, `DISCOVERY_results.csv` | CLI: optional `network` arg, `--nmap-args`, `--json-out`, `--csv-out` |
| `read_cert.py` | Single-file PEM check | stdout (JSON) | `python3 read_cert.py <file>` |

## 4. Script 9 (TLS targets file)

The targets file is the **first** argument. The output directory is created automatically if missing.

```bash
python3 9NetworkProtocol.py targets.txt --out-dir result --workers 6 --timeout 90
```

`targets.txt` should list one `host` or `host:port` per line. `sslscan` must be on `PATH`.

### DISCOVERY (nmap)

```bash
python3 DISCOVERY.py 192.168.1.0/24 --nmap-args "-sT -sV -T4"
```

The first positional argument is the nmap target (default `10.220.27.0/24` if omitted). Use `--nmap-args` for a lighter TCP connect scan when raw SYN (`-sS`) is not available.

## 5. Roadmap (upstream)

Planned improvements mentioned by the original project include CycloneDX v1.7 output, PTPKM-related properties, and deeper configuration inspection.

## 6. Contact (original project)

Muhammad Saufy Rohmad — Malaysia Cryptology Technology and Management Center — saufy@uitm.edu.my
