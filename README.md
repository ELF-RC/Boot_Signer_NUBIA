# Boot Signer For NUBIA

**English | [中文](README_ZH.md)**

A single-binary Rust replacement for `boot_signer.jar` (AOSP `com.android.verity.BootSignature`), used to sign boot.img for devices such as Nubia NX563J / NX595J (Android Verified Boot v8.3 signature block).

No Java dependency, no runtime dependency — use it directly from the command line.

## Usage

```bash
# Sign (built-in AOSP test key, ready to use out of the box)
./boot_signer /boot boot_unsigned.img boot_signed.img

# Sign (with your own key and certificate)
./boot_signer /boot boot_unsigned.img my.pk8 my.x509.pem boot_signed.img

# Keep trailing bytes beyond signableSize (truncated by default)
./boot_signer /boot boot.img out.img --no-truncate

# Strip signature (restore the unsigned image; also reversible for --no-truncate output)
./boot_signer -strip boot_signed.img boot_unsigned.img

# Verify (optionally use a specified certificate instead of the embedded one)
./boot_signer -verify boot_signed.img
./boot_signer -verify boot_signed.img -certificate my.x509.pem

# Print the built-in certificate
./boot_signer -print-cert
```

**Two argument forms:**
- `boot_signer <target> <image> <out>` — uses the AOSP verity test key pair compiled into the binary
- `boot_signer <target> <image> <key> <cert> <out>` — explicit key and certificate

| Argument | Description |
|---|---|
| `target` | Target partition name (e.g. `/boot`), written into the signature metadata |
| `image` | boot.img to sign (truncated to the signable length by default) |
| `key` | Private key: PKCS#8 DER or PEM (unencrypted; RSA / P-256 / P-384 / P-521) |
| `cert` | X.509 certificate, PEM or DER; must match the private key |
| `out` | Output (image + signature block) |

**Options:**
- `--no-truncate` — do not discard bytes after signableSize; keep them after the signature block
- `-certificate X` — (verify) verify with the given certificate instead of the embedded one
- `-print-cert` — print the built-in certificate (PEM) and exit

The embedded key is the public AOSP test key, identical to the original jar project. To use your own, replace the two files under `keys/` and rebuild, or pass them explicitly at runtime.

## Signature format (byte-for-byte compatible with jar)

```
signed = image[0..signableSize] || BootSignature-DER

BootSignature ::= SEQUENCE {
    formatVersion           INTEGER (1),
    certificate             <X.509 cert DER, verbatim>,
    algorithmIdentifier     SEQUENCE { OID },      -- no NULL parameters
    authenticatedAttributes SEQUENCE {
        target  PrintableString,                   -- e.g. "/boot"
        length  INTEGER                            -- signableSize
    },
    signature               OCTET STRING
}

Signed data = image[0..signableSize] || DER(authenticatedAttributes)
```

- RSA: PKCS#1 v1.5 + SHA-256 (deterministic, byte-for-byte identical to jar)
- ECDSA: DER-encoded (r,s)
- `signableSize` computation supports boot header v0 (dt_size@40) / v1 (recovery_dtbo) / v2 (+dtb), including page alignment
- Algorithm selection: RSA→SHA256withRSA; EC by curve 256/384/512-bit → SHA256/384/512withECDSA

## Error handling and exit codes

Exit codes: `0` success/valid, `1` failure/invalid, `2` usage error. `-verify` results are printed to stderr (same as jar).

Errors match jar behavior (image header/length/version anomalies, etc.), and additionally cover: wrong argument count / unknown options, missing / unreadable / empty files, truncated images / bad magic / malformed header fields / integer overflow, **key–certificate mismatch (signing is refused)**, bad PKCS#8 / bad certificate / PEM encoding errors. All report a clear path and reason.

## Build

```bash
cargo build --release
# Static single-file version (runs on any distro):
cargo build --release --target x86_64-unknown-linux-musl
```

## Compatibility

For boot header v0/v1/v2 images, bidirectional verification against the original jar as the golden reference passes: byte-for-byte identical output, jar↔rust cross-verification, and single-byte tamper detection. `-strip`, `--no-truncate`, and error handling are covered by an additional 36 checks.

> Implementation uses a hand-written DER codec (`src/der.rs`) and a branch-by-branch replica of the `signableSize` computation. The signed input is `image || DER(attrs)`, and `AlgorithmIdentifier` carries no NULL parameters — all validated against actual jar output.

## Acknowledgements

This project's implementation references [boot_signer_for_nubia_nx563j](https://github.com/kindle4jerry/boot_signer_for_nubia_nx563j). Thanks to the original author for the open-source work.

## Community

- QQ group: `1045530205`
- Telegram: [ELF-RC Group](https://t.me/ELFRCGroup)
