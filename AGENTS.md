# CBOM-scanning

- Ignore `.venv/` during search and review; it is a checked-in virtualenv, not project source.
- This repo is a flat set of standalone Python scanners, not a package or service. There is no test suite, CI, lint, or typecheck config; do not invent repo commands beyond running the scripts directly.
- `requirements.txt` is the only manifest and only declares `cryptography`, `psutil`, and `xmltodict`. Some scripts also need undeclared runtime dependencies: system `strings`, `nm`, `ldd`, `sslscan`, `nmap`, plus the Python `nmap` binding for `DISCOVERY.py`.
- Basic setup: `python3 -m pip install -r requirements.txt`. For `DISCOVERY.py`, also install system `nmap` and the Python `nmap` binding. For `9NetworkProtocol.py`, install `sslscan`.

## Script layout

- Root scripts are the product surface: `1BinariesUsed.py` through `9NetworkProtocol.py`, plus `DISCOVERY.py` and `read_cert.py`.
- Thin shared helpers (not a package): `scanner_env.py` (OS/tool snapshot, CSV fingerprints), `scanner_platform.py` (psutil executables, `ldd`/`otool`/`dumpbin` dependency text). Crypto rule tables and cert parsing remain duplicated across scripts.

## Run-from-root outputs

- Run scanners from the repo root; most write fixed filenames into the current working directory:
  - `1BinariesUsed.py` → `binaries_used.csv`
  - `2BinariesDisk.py` → `binaries_at_disk.csv`
  - `3Libraries.py` → `library.csv` (its final print message still says `library_crypto_inventory.csv`)
  - `4Kernel_mod.py` → `kernel_modules.csv`
  - `5CertKeys.py` → `crypto_cert_key.csv`
  - `6ExeCodes.py` → `exec_script.csv`
  - `7Web_App.py` → `web_app.csv`
  - `8NetworkApp.py` → `network_app.csv`
  - `DISCOVERY.py` → `scan_results.json` and `DISCOVERY_results.csv` (paths overridable via CLI)
- Most scanner CSVs duplicate **`os_fingerprint`** and **`scanner_limits`** on each row (from `scanner_env.py`).

## Important execution quirks

- `9NetworkProtocol.py` is the only real CLI-style scanner: `python3 9NetworkProtocol.py targets.txt --out-dir result --workers 6 --timeout 90`
  - It creates `--out-dir` itself; the README `mkdir result` step is unnecessary.
  - It writes one subdirectory per target plus `combined_results.json`.
- `DISCOVERY.py` accepts an optional positional network target (default `10.220.27.0/24`), `--nmap-args`, `--json-out`, and `--csv-out`.
- Most scripts scan the live host by default (`/`, PATH entries, standard web roots, `/lib/modules`, running processes, active sockets). Avoid broad verification runs unless you intend a real machine inventory.
- Privileges matter: the README expects `sudo`, and process, socket, kernel, and full-filesystem scans may return partial data without elevated access.
- `4Kernel_mod.py` is Linux-only; Windows support is a placeholder.
- `7Web_App.py` defaults to standard web roots (`/var/www`, `/usr/share/nginx`, `/srv/www` on Unix; IIS/XAMPP/WAMP under `%SystemDrive%` on Windows). Override with env **`CBOM_WEB_ROOTS`** (same separator as `PATH`).
- **`CBOM_EXTRA_LIB_DIRS`**: extra roots for `3Libraries.py` (e.g. `/opt`, Nix, Flatpak paths when you accept scan cost).
- `5CertKeys.py` is the expensive recursive filesystem scan. `read_cert.py` is the narrow verifier: `python3 read_cert.py <file>` prints JSON for one file.
- `5CertKeys.py` and `read_cert.py` only parse PEM certificate/private-key bodies even though `.der`, `.p12`, and `.pfx` are listed as candidate extensions; those formats are usually skipped.

## Editing guidance

- Crypto detection coverage is duplicated, not centralized:
  - `1BinariesUsed.py` and `2BinariesDisk.py` each keep their own large `CRYPTO_RULES`
  - `3Libraries.py` has a separate smaller ruleset
  - `5CertKeys.py` and `read_cert.py` duplicate certificate parsing
- If you change detection logic in one scanner, inspect the sibling script too or behavior will drift.
- Treat checked-in `*.csv`, `scan_results.json`, and `result/` contents as generated artifacts or samples, not source of truth.
