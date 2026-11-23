#!/usr/bin/env python3
"""
KAAO ECDSA-P256 Threat & DNS Definition Bundle Signing Utility.

Generates a NIST P-256 (secp256r1) keypair or signs a KAAO SignedDefinitionBundle JSON
file using SHA256withECDSA in canonical KAAO-DEF-V1 format.

Usage:
  python3 scripts/sign_definitions.py genkey --out-dir ./keys
  python3 scripts/sign_definitions.py sign --private-key ./keys/kaao_p256_private.pem \
      --input unsigned_bundle.json --output signed_bundle.json
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile


def canonical_payload(bundle: dict) -> str:
    sigs = sorted(bundle.get("sha256Signatures", []), key=lambda e: e["sha256"].lower())
    domains = sorted(bundle.get("blockedDomains", []), key=lambda e: e["domain"].lower())

    parts = [
        f"KAAO-DEF-V1|{bundle['version']}|{bundle['issuedAtEpochSec']}|",
        "".join(
            f"{s['sha256'].lower()}:{s['family']}:{s['category']}:{s['severity']};"
            for s in sigs
        ),
        "|",
        "".join(f"{d['domain'].lower()}:{d['category']};" for d in domains),
    ]
    return "".join(parts)


def cmd_genkey(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    priv_path = os.path.join(out_dir, "kaao_p256_private.pem")
    pub_pem = os.path.join(out_dir, "kaao_p256_public.pem")
    pub_der = os.path.join(out_dir, "kaao_p256_public.der")

    subprocess.run(
        ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", priv_path],
        check=True,
    )
    subprocess.run(
        ["openssl", "ec", "-in", priv_path, "-pubout", "-out", pub_pem],
        check=True,
    )
    subprocess.run(
        ["openssl", "ec", "-in", priv_path, "-pubout", "-outform", "DER", "-out", pub_der],
        check=True,
    )
    with open(pub_der, "rb") as f:
        spki_b64 = base64.b64encode(f.read()).decode("ascii")
    print(f"Private key (KEEP SECRET): {priv_path}")
    print(f"Public key PEM: {pub_pem}")
    print(f"Pinned X.509 SPKI Base64 for SignatureBundleVerifier:\n{spki_b64}")


def cmd_sign(private_key: str, input_path: str, output_path: str) -> None:
    with open(input_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    payload = canonical_payload(bundle).encode("utf-8")
    with tempfile.NamedTemporaryFile(delete=False) as payload_file:
        payload_file.write(payload)
        payload_path = payload_file.name

    sig_path = payload_path + ".sig"
    try:
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", private_key, "-out", sig_path, payload_path],
            check=True,
        )
        with open(sig_path, "rb") as f:
            sig_b64 = base64.b64encode(f.read()).decode("ascii")
    finally:
        for p in (payload_path, sig_path):
            if os.path.exists(p):
                os.remove(p)

    bundle["ecdsaP256SignatureBase64"] = sig_b64
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    print(f"Signed bundle v{bundle['version']} written to {output_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="KAAO ECDSA-P256 Definition Signing CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("genkey", help="Generate a NIST P-256 keypair")
    p_gen.add_argument("--out-dir", required=True)

    p_sign = sub.add_parser("sign", help="Sign a KAAO threat/DNS definition JSON bundle")
    p_sign.add_argument("--private-key", required=True)
    p_sign.add_argument("--input", required=True)
    p_sign.add_argument("--output", required=True)

    args = parser.parse_args()
    if args.cmd == "genkey":
        cmd_genkey(args.out_dir)
    elif args.cmd == "sign":
        cmd_sign(args.private_key, args.input, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
