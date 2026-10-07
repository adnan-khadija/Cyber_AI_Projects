#!/usr/bin/env python3
import os
import sys

# Binaires SUID/SGID légitimes autorisés
ALLOWED_SUID = {
    "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/newgrp",
    "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/bin/umount", "/usr/bin/mount"
}

def scan_suid_sgid():
    suspicious = []
    print("[*] Scan des fichiers SUID/SGID en cours...")
    for root, _, files in os.walk("/"):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                if os.path.islink(filepath):
                    continue
                stat = os.stat(filepath)
                # Vérification bit SUID (0o4000) ou SGID (0o2000)
                if stat.st_mode & 0o6000:
                    if filepath not in ALLOWED_SUID:
                        suspicious.append(filepath)
            except (PermissionError, FileNotFoundError):
                continue
    return suspicious

if __name__ == "__main__":
    findings = scan_suid_sgid()
    if findings:
        print(f"[!] Binaires non autorisés détectés ({len(findings)}) :")
        for f in findings:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("[+] Aucun binaire SUID/SGID suspect détecté.")
        sys.exit(0)
