//! boot_signer — sign/verify Android boot images.
//!
//! Single-binary replacement for boot_signer.jar (AOSP com.android.verity.BootSignature).
//!
//! usage:
//!   boot_signer <target> <image> <key> <cert> <out>
//!   boot_signer -verify <image> [-certificate <cert.x509.pem>]
//!//! Signed layout:   image[0..signableSize] || BootSignature-DER
//! BootSignature ::= SEQUENCE {
//!     formatVersion            INTEGER (1),
//!     certificate              <X.509 cert DER>,
//!     algorithmIdentifier      SEQUENCE { OID },          -- NO parameters
//!     authenticatedAttributes  SEQUENCE { target PrintableString, length INTEGER },
//!     signature                OCTET STRING
//! }
//! Signed data = image[0..signableSize] || DER(authenticatedAttributes)

mod bootimg;
mod crypto;
mod der;

use std::io::{Read, Write};
use std::process::exit;

const FORMAT_VERSION: i64 = 1;

const USAGE: &str = "\
boot_signer - sign/verify Android boot images (AOSP BootSignature)

usage:
  boot_signer <target> <image> <key> <cert> <out>
  boot_signer -verify <image> [-certificate <cert>]
  boot_signer -h | --help

commands:
  (default)   sign <image>, write result to <out>
  -verify     verify a signed image (exit 0 = VALID, 1 = INVALID or error)

arguments (sign):
  target  partition target recorded in the signature (e.g. /boot)
  image   boot image to sign (ANDROID! header; extra trailing bytes are
          discarded)
  key     private key: PKCS#8 DER or PEM (RSA-2048/4096, P-256/P-384/P-521)
  cert    X.509 certificate, PEM or DER
  out     output file (image + signature block)

options:
  -certificate X  (verify) verify against certificate X instead of the
                  certificate embedded in the signature

exit codes: 0 = success/valid, 1 = failure/invalid, 2 = usage error";

// ---------------------------------------------------------------------------
// small utilities
// ---------------------------------------------------------------------------

/// Print a fatal error (with usage hint) and exit with code 2.
fn usage_err(msg: &str) -> ! {
    eprintln!("error: {msg}");
    eprintln!();
    eprintln!("{USAGE}");
    exit(2);
}

/// Print a runtime error and exit with code 1 (same spirit as the jar, which
/// exits 1 after printing the exception).
fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    exit(1);
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let mut f =
        std::fs::File::open(path).map_err(|e| format!("cannot open '{path}': {e}"))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(|e| format!("cannot read '{path}': {e}"))?;
    Ok(buf)
}

fn write_file(path: &str, data: &[u8]) -> Result<(), String> {
    let mut f = std::fs::File::create(path)
        .map_err(|e| format!("cannot create '{path}': {e}"))?;
    f.write_all(data)
        .map_err(|e| format!("cannot write '{path}': {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// BootSignature structure
// ---------------------------------------------------------------------------

/// SEQUENCE { target: PrintableString, length: INTEGER }
fn encode_auth_attrs(target: &str, length: i64) -> Vec<u8> {
    der::seq(&[&der::printable_string(target), &der::der_i64(length)])
}

/// Full BootSignature DER.
fn encode_boot_signature(
    cert_der: &[u8],
    alg_oid: &str,
    target: &str,
    length: i64,
    signature: &[u8],
) -> Vec<u8> {
    let alg_id = der::seq(&[&der::oid(alg_oid)]); // AlgorithmIdentifier(OID), no params
    der::seq(&[
        &der::der_i64(FORMAT_VERSION),
        cert_der,
        &alg_id,
        &encode_auth_attrs(target, length),
        &der::octet_string(signature),
    ])
}

struct ParsedSig {
    cert_der: Vec<u8>,
    alg_oid: String,
    target: String,
    length: i64,
    signature: Vec<u8>,
}

/// Parse BootSignature DER. Any bytes after the block are ignored.
fn parse_boot_signature(data: &[u8]) -> Result<ParsedSig, String> {
    let elems = der::parse_seq(data)?;
    if elems.len() != 5 {
        return Err(format!(
            "signature block: expected 5 elements, got {}",
            elems.len()
        ));
    }

    // [0] formatVersion INTEGER
    let fv = der::int_to_bytes(elems[0].content)?;
    let mut format_version: i64 = 0;
    for b in &fv {
        format_version = (format_version << 8) | *b as i64;
    }
    if format_version != FORMAT_VERSION {
        return Err("Unsupported format version".to_string());
    }

    // [1] certificate (embedded DER)
    let cert_der = der::full_bytes(data, &elems[1]).to_vec();

    // [2] algorithmIdentifier SEQUENCE { OID, ... }
    let alg_raw = der::full_bytes(data, &elems[2]);
    let alg_elems = der::parse_seq(alg_raw)?;
    if alg_elems.is_empty() {
        return Err("signature block: bad AlgorithmIdentifier".to_string());
    }
    let alg_oid = der::oid_to_string(alg_elems[0].content);

    // [3] authenticatedAttributes SEQUENCE { target, length }
    let attrs_raw = der::full_bytes(data, &elems[3]);
    let attr_elems = der::parse_seq(attrs_raw)?;
    if attr_elems.len() != 2 {
        return Err("signature block: bad authenticatedAttributes".to_string());
    }
    let target = String::from_utf8(attr_elems[0].content.to_vec())
        .map_err(|_| "signature block: target is not a printable string".to_string())?;
    let len_bytes = der::int_to_bytes(attr_elems[1].content)?;
    let mut length: i64 = 0;
    for b in &len_bytes {
        length = (length << 8) | *b as i64;
    }

    // [4] signature OCTET STRING
    let signature = elems[4].content.to_vec();

    Ok(ParsedSig {
        cert_der,
        alg_oid,
        target,
        length,
        signature,
    })
}

/// generateSignableImage: image || DER(authenticatedAttributes)
fn generate_signable_image(image: &[u8], target: &str, length: i64) -> Vec<u8> {
    let attrs = encode_auth_attrs(target, length);
    let mut out = Vec::with_capacity(image.len() + attrs.len());
    out.extend_from_slice(image);
    out.extend_from_slice(&attrs);
    out
}

/// Load a certificate (PEM or DER).
fn load_cert(path: &str) -> Result<Vec<u8>, String> {
    der::pem_or_der(&read_file(path)?, "certificate")
}

/// Load a private key (PKCS#8, DER or PEM).
fn load_key(path: &str) -> Result<crypto::PrivKey, String> {
    let der = der::pem_or_der(&read_file(path)?, "private key")?;
    crypto::load_pkcs8_private_key(&der)
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

fn do_signature(
    target: &str,
    image_path: &str,
    key_path: &str,
    cert_path: &str,
    out_path: &str,
) {
    if target.is_empty() {
        fail("Invalid argument: empty target");
    }
    let result = (|| -> Result<(), String> {
        let mut image = read_file(image_path)?;
        if image.is_empty() {
            return Err("Invalid image: empty file".to_string());
        }
        let signable_size = bootimg::get_signable_image_size(&image)?;

        if signable_size < image.len() {
            eprintln!(
                "NOTE: truncating file {} from {} to {} bytes",
                image_path,
                image.len(),
                signable_size
            );
            image.truncate(signable_size);
        } else if signable_size > image.len() {
            return Err(format!(
                "Invalid image: too short, expected {} bytes",
                signable_size
            ));
        }

        let length = image.len() as i64;
        let key = load_key(key_path)?;
        let cert_der = load_cert(cert_path)?;

        let (_alg_name, alg_oid) = crypto::signature_algorithm_for_priv(&key);
        let signable = generate_signable_image(&image, target, length);
        let signature = crypto::sign(&key, &signable)?;
        let bootsig = encode_boot_signature(&cert_der, alg_oid, target, length, &signature);

        let mut out = Vec::with_capacity(image.len() + bootsig.len());
        out.extend_from_slice(&image);
        out.extend_from_slice(&bootsig);

        write_file(out_path, &out)
    })();

    if let Err(e) = result {
        fail(&e);
    }
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn verify_signature(image_path: &str, cert_path: &str) -> ! {
    let result = (|| -> Result<bool, String> {
        let data = read_file(image_path)?;
        if data.is_empty() {
            return Err("Invalid image: empty file".to_string());
        }
        let signable_size = bootimg::get_signable_image_size(&data)?;

        if signable_size >= data.len() {
            return Err("Invalid image: not signed".to_string());
        }

        let metadata = &data[signable_size..];
        let mut sig = parse_boot_signature(metadata)?;

        if !cert_path.is_empty() {
            eprintln!("NOTE: verifying using public key from {}", cert_path);
            sig.cert_der = load_cert(cert_path)?;
        }

        let image = &data[..signable_size];
        if sig.length != image.len() as i64 {
            return Err("Invalid image length".to_string());
        }

        let signable = generate_signable_image(image, &sig.target, sig.length);
        let pub_key = crypto::public_key_from_cert(&sig.cert_der)?;
        crypto::verify_with_oid(&pub_key, &signable, &sig.signature, &sig.alg_oid)
    })();

    match result {
        Ok(true) => {
            eprintln!("Signature is VALID");
            exit(0);
        }
        Ok(false) => {
            eprintln!("Signature is INVALID");
            exit(1);
        }
        Err(e) => fail(&e),
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage_err("missing command");
    }

    match args[0].as_str() {
        "-h" | "--help" => {
            println!("{USAGE}");
            exit(0);
        }
        "-verify" => {
            // -verify <image> [-certificate <cert>]
            let mut image: Option<&str> = None;
            let mut cert: Option<&str> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-certificate" => {
                        i += 1;
                        let p = args
                            .get(i)
                            .unwrap_or_else(|| usage_err("-certificate requires a path"));
                        if cert.is_some() {
                            usage_err("-certificate given twice");
                        }
                        cert = Some(p);
                    }
                    s if s.starts_with('-') => usage_err(&format!("unknown option '{s}'")),
                    s => {
                        if image.is_some() {
                            usage_err("too many arguments for -verify");
                        }
                        image = Some(s);
                    }
                }
                i += 1;
            }
            let image = image.unwrap_or_else(|| usage_err("missing <image>"));
            verify_signature(image, cert.unwrap_or(""));
        }
        s if s.starts_with('-') => usage_err(&format!("unknown command '{s}'")),
        _ => {
            // sign: <target> <image> <key> <cert> <out>
            if args.len() != 5 {
                usage_err(&format!(
                    "sign expects <target> <image> <key> <cert> <out>, got {} arguments",
                    args.len()
                ));
            }
            do_signature(&args[0], &args[1], &args[2], &args[3], &args[4]);
        }
    }
}
