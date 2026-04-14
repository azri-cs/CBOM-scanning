#!/usr/bin/env python3

import os
import re
import csv
import platform
from pathlib import Path

from scanner_env import get_os_fingerprint, get_scanner_limits
from scanner_progress import maybe_report_progress

OUTPUT_CSV = "web_app.csv"

# =====================================================
# WEB SOURCE FILE TYPES
# =====================================================
WEB_EXTENSIONS = (
    ".php",
    ".py",
    ".js",
    ".ts",
    ".java",
    ".go",
    ".rb",
    ".jsp",
    ".cs",
    ".scala",
)

# =====================================================
# CRYPTO DETECTION RULES
# =====================================================
CRYPTO_RULES = {
    "AES": {
        "primitive": "block-cipher",
        "patterns": [
            r"AES-(128|192|256)",
            r"openssl_encrypt",
            r"CryptoJS\.AES",
            r"Cipher\.getInstance\(\"AES",
            r"EVP_aes_(128|192|256)",
        ],
    },
    "RSA": {
        "primitive": "public-key",
        "patterns": [
            r"RSA_generate_key",
            r"new\s+RSA",
            r"KeyPairGenerator\.getInstance\(\"RSA\"",
            r"openssl_pkey_new",
            r"ssh-rsa",
        ],
    },
    "ECC": {
        "primitive": "public-key",
        "patterns": [
            r"secp256r1",
            r"prime256v1",
            r"X25519",
            r"Ed25519",
            r"EllipticCurve",
        ],
    },
    "SHA": {
        "primitive": "hash",
        "patterns": [
            r"SHA-?(1|224|256|384|512)",
            r"hashlib\.sha(1|224|256|384|512)",
            r"MessageDigest\.getInstance\(\"SHA",
        ],
    },
    "HMAC": {
        "primitive": "MAC",
        "patterns": [
            r"HmacSHA(1|256|384|512)",
            r"hmac\.new",
            r"hash_hmac",
        ],
    },
    "PBKDF2": {
        "primitive": "KDF",
        "patterns": [
            r"PBKDF2",
            r"hash_pbkdf2",
            r"SecretKeyFactory\.getInstance\(\"PBKDF2",
        ],
    },
    "TLS": {
        "primitive": "protocol",
        "patterns": [
            r"TLSv1\.2",
            r"TLSv1\.3",
            r"https://",
            r"SSLContext",
        ],
    },
}

COMPILED_CRYPTO_RULES = {
    algo: {
        "primitive": meta["primitive"],
        "compiled_patterns": [
            re.compile(pattern, re.IGNORECASE) for pattern in meta["patterns"]
        ],
    }
    for algo, meta in CRYPTO_RULES.items()
}


# =====================================================
# OS DETECTION
# =====================================================
def detect_os():
    return platform.system().lower()


def default_web_roots():
    raw = os.environ.get("CBOM_WEB_ROOTS", "").strip()
    if raw:
        return [p.strip() for p in raw.split(os.pathsep) if p.strip()]

    os_type = detect_os()
    if os_type == "windows":
        drive = os.environ.get("SystemDrive", "C:")
        base = drive + "\\"
        return [
            os.path.join(base, "inetpub", "wwwroot"),
            os.path.join(base, "xampp", "htdocs"),
            os.path.join(base, "wamp64", "www"),
        ]
    return [
        "/var/www",
        "/usr/share/nginx",
        "/srv/www",
    ]


# =====================================================
# FILE SCANNING
# =====================================================
def scan_file(path):
    try:
        text = Path(path).read_text(errors="ignore")
    except Exception:
        return []

    findings = []

    for algo, meta in COMPILED_CRYPTO_RULES.items():
        for pattern in meta["compiled_patterns"]:
            matches = pattern.findall(text)
            for m in matches:
                key_size = "unknown"
                if isinstance(m, tuple):
                    for x in m:
                        if x.isdigit():
                            key_size = x
                elif isinstance(m, str) and m.isdigit():
                    key_size = m

                findings.append(
                    {
                        "algorithm": algo,
                        "primitive": meta["primitive"],
                        "library": pattern.pattern,
                        "key_size": key_size,
                    }
                )

    return findings


# =====================================================
# MAIN
# =====================================================
def main(roots=None):
    roots = roots or default_web_roots()
    os_type = detect_os()
    fp = get_os_fingerprint()
    limits = get_scanner_limits()

    print(f"[i] Detected OS: {os_type}")
    print("[i] Web roots:")
    for r in roots:
        print(f"    - {r}")

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            [
                "file_path",
                "language",
                "algorithm",
                "primitive",
                "library_or_api",
                "key_size",
                "detection_pattern",
                "os_fingerprint",
                "scanner_limits",
            ]
        )

        for root in roots:
            if not os.path.isdir(root):
                continue

            processed = 0
            for dirpath, _, filenames in os.walk(root):
                for name in filenames:
                    processed += 1
                    maybe_report_progress(f"web files under {root}", processed)
                    if not name.lower().endswith(WEB_EXTENSIONS):
                        continue

                    path = os.path.join(dirpath, name)
                    findings = scan_file(path)

                    if not findings:
                        continue

                    lang = Path(name).suffix.lstrip(".")

                    for f in findings:
                        writer.writerow(
                            [
                                path,
                                lang,
                                f["algorithm"],
                                f["primitive"],
                                f["library"],
                                f["key_size"],
                                f["library"],
                                fp,
                                limits,
                            ]
                        )

    print(f"[+] Web crypto scan complete → {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
