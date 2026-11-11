//! Key loading + sign/verify — mirrors com.android.verity.Utils semantics.
//!
//! Algorithm selection (Utils.getSignatureAlgorithm):
//!   EC key  -> SHA256/384/512withECDSA by curve field size (<=256/<=384/else)
//!   RSA key -> SHA256withRSA
//!
//! OID table (Utils.<clinit>):
//!   ecdsa_with_SHA256        1.2.840.10045.4.3.2   <-> SHA256withECDSA
//!   ecdsa_with_SHA384        1.2.840.10045.4.3.3   <-> SHA384withECDSA
//!   ecdsa_with_SHA512        1.2.840.10045.4.3.4   <-> SHA512withECDSA
//!   sha1WithRSAEncryption    1.2.840.113549.1.1.5  <-> SHA1withRSA
//!   sha256WithRSAEncryption  1.2.840.113549.1.1.11 <-> SHA256withRSA
//!   sha512WithRSAEncryption  1.2.840.113549.1.1.13 <-> SHA512withRSA

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha1::{Digest as _, Sha1};
use sha2::{Sha256, Sha512};

pub const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
pub const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
pub const OID_ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
pub const OID_SHA1_RSA: &str = "1.2.840.113549.1.1.5";
pub const OID_SHA256_RSA: &str = "1.2.840.113549.1.1.11";
pub const OID_SHA512_RSA: &str = "1.2.840.113549.1.1.13";

pub enum PrivKey {
    Rsa(RsaPrivateKey),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

pub enum PubKey {
    Rsa(RsaPublicKey),
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    P521(p521::PublicKey),
}

/// Utils.getSignatureAlgorithm(Key) + getSignatureAlgorithmIdentifier(Key):
/// (JCE algorithm name, algorithm OID).
pub fn signature_algorithm_for_priv(k: &PrivKey) -> (&'static str, &'static str) {
    match k {
        PrivKey::Rsa(_) => ("SHA256withRSA", OID_SHA256_RSA),
        PrivKey::P256(_) => ("SHA256withECDSA", OID_ECDSA_SHA256),
        PrivKey::P384(_) => ("SHA384withECDSA", OID_ECDSA_SHA384),
        PrivKey::P521(_) => ("SHA512withECDSA", OID_ECDSA_SHA512),
    }
}

/// Utils.ID_TO_ALG — signature algorithm OID -> JCE name.
pub fn alg_name_for_oid(oid: &str) -> Option<&'static str> {
    match oid {
        x if x == OID_ECDSA_SHA256 => Some("SHA256withECDSA"),
        x if x == OID_ECDSA_SHA384 => Some("SHA384withECDSA"),
        x if x == OID_ECDSA_SHA512 => Some("SHA512withECDSA"),
        x if x == OID_SHA1_RSA => Some("SHA1withRSA"),
        x if x == OID_SHA256_RSA => Some("SHA256withRSA"),
        x if x == OID_SHA512_RSA => Some("SHA512withRSA"),
        _ => None,
    }
}

/// Load an unencrypted PKCS#8 private key (RSA or EC).
/// Mirrors Utils.loadDERPrivateKey (minus the encrypted-key path).
pub fn load_pkcs8_private_key(der: &[u8]) -> Result<PrivKey, String> {
    use crate::der;
    use rsa::pkcs8::DecodePrivateKey;

    // PrivateKeyInfo ::= SEQ { version, algId SEQ, key OCTET STRING, [0]? }
    let elems = der::parse_seq(der)?;
    if elems.len() < 3 {
        return Err("PKCS#8: short PrivateKeyInfo".to_string());
    }
    let alg_raw = der::full_bytes(der, &elems[1]);
    let alg_elems = der::parse_seq(alg_raw)?;
    if alg_elems.is_empty() {
        return Err("PKCS#8: bad AlgorithmIdentifier".to_string());
    }
    let alg_oid = der::oid_to_string(alg_elems[0].content);

    if alg_oid == "1.2.840.113549.1.1.1" {
        RsaPrivateKey::from_pkcs8_der(der)
            .map(PrivKey::Rsa)
            .map_err(|e| format!("PKCS#8 RSA parse failed: {e}"))
    } else if alg_oid == "1.2.840.10045.2.1" {
        let params_oid = if alg_elems.len() > 1 {
            der::oid_to_string(alg_elems[1].content)
        } else {
            String::new()
        };
        match params_oid.as_str() {
            "1.2.840.10045.3.1.7" => p256::SecretKey::from_pkcs8_der(der)
                .map(PrivKey::P256)
                .map_err(|e| format!("PKCS#8 P-256 parse failed: {e}")),
            "1.3.132.0.34" => p384::SecretKey::from_pkcs8_der(der)
                .map(PrivKey::P384)
                .map_err(|e| format!("PKCS#8 P-384 parse failed: {e}")),
            "1.3.132.0.35" => p521::SecretKey::from_pkcs8_der(der)
                .map(PrivKey::P521)
                .map_err(|e| format!("PKCS#8 P-521 parse failed: {e}")),
            _ => Err(format!("Unsupported EC curve OID {params_oid}")),
        }
    } else {
        Err(format!("Unsupported key type {alg_oid}"))
    }
}

/// Extract the public key from an X.509 certificate DER
/// (CertificateFactory "X.509" + X509Certificate.getPublicKey()).
pub fn public_key_from_cert(cert_der: &[u8]) -> Result<PubKey, String> {
    use crate::der;
    use rsa::pkcs8::DecodePublicKey;

    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| format!("X.509 parse failed: {e}"))?;
    let spki = cert.public_key().raw;

    let elems = der::parse_seq(spki)?;
    if elems.is_empty() {
        return Err("X.509: bad SPKI".to_string());
    }
    let alg_elems = der::parse_seq(der::full_bytes(spki, &elems[0]))?;
    let alg_oid = der::oid_to_string(alg_elems[0].content);

    if alg_oid == "1.2.840.113549.1.1.1" {
        RsaPublicKey::from_public_key_der(spki)
            .map(PubKey::Rsa)
            .map_err(|e| format!("RSA public key parse failed: {e}"))
    } else if alg_oid == "1.2.840.10045.2.1" {
        let params_oid = if alg_elems.len() > 1 {
            der::oid_to_string(alg_elems[1].content)
        } else {
            String::new()
        };
        match params_oid.as_str() {
            "1.2.840.10045.3.1.7" => p256::PublicKey::from_public_key_der(spki)
                .map(PubKey::P256)
                .map_err(|e| format!("P-256 public key parse failed: {e}")),
            "1.3.132.0.34" => p384::PublicKey::from_public_key_der(spki)
                .map(PubKey::P384)
                .map_err(|e| format!("P-384 public key parse failed: {e}")),
            "1.3.132.0.35" => p521::PublicKey::from_public_key_der(spki)
                .map(PubKey::P521)
                .map_err(|e| format!("P-521 public key parse failed: {e}")),
            _ => Err(format!("Unsupported EC curve OID {params_oid}")),
        }
    } else {
        Err(format!("Unsupported key type {alg_oid}"))
    }
}

/// Utils.sign(PrivateKey, byte[]).
/// RSA: PKCS#1 v1.5 (deterministic). ECDSA: DER-encoded (r,s), random k.
pub fn sign(key: &PrivKey, msg: &[u8]) -> Result<Vec<u8>, String> {
    match key {
        PrivKey::Rsa(k) => {
            // JCE SHA256withRSA = EMSA-PKCS1-v1_5(DigestInfo(SHA256, msg))
            let digest = Sha256::digest(msg);
            k.sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
                .map_err(|e| format!("RSA sign failed: {e}"))
        }
        PrivKey::P256(k) => {
            use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
            let sk = SigningKey::from(k.clone());
            let sig: Signature = sk.sign(msg);
            Ok(sig.to_der().as_bytes().to_vec())
        }
        PrivKey::P384(k) => {
            use p384::ecdsa::{signature::Signer as _, Signature, SigningKey};
            let sk = SigningKey::from(k.clone());
            let sig: Signature = sk.sign(msg);
            Ok(sig.to_der().as_bytes().to_vec())
        }
        PrivKey::P521(k) => {
            use p521::ecdsa::{signature::Signer as _, Signature, SigningKey};
            let sk = SigningKey::from_bytes(&k.to_bytes())
                .map_err(|e| format!("P-521 signing key: {e}"))?;
            let sig: Signature = sk.sign(msg);
            Ok(sig.to_der().as_bytes().to_vec())
        }
    }
}

/// Utils.verify(PublicKey, byte[] data, byte[] sig, AlgorithmIdentifier).
/// Algorithm chosen by the identifier's OID.
pub fn verify_with_oid(key: &PubKey, msg: &[u8], sig: &[u8], alg_oid: &str) -> Result<bool, String> {
    let alg = alg_name_for_oid(alg_oid)
        .ok_or_else(|| format!("Unsupported algorithm {alg_oid}"))?;
    verify_named(key, msg, sig, alg)
}

fn verify_named(key: &PubKey, msg: &[u8], sig: &[u8], alg: &str) -> Result<bool, String> {
    match (key, alg) {
        (PubKey::Rsa(k), "SHA256withRSA") => {
            let digest = Sha256::digest(msg);
            Ok(k.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, sig)
                .is_ok())
        }
        (PubKey::Rsa(k), "SHA1withRSA") => {
            let digest = Sha1::digest(msg);
            Ok(k.verify(Pkcs1v15Sign::new::<Sha1>(), &digest, sig).is_ok())
        }
        (PubKey::Rsa(k), "SHA512withRSA") => {
            let digest = Sha512::digest(msg);
            Ok(k.verify(Pkcs1v15Sign::new::<Sha512>(), &digest, sig)
                .is_ok())
        }
        (PubKey::P256(k), "SHA256withECDSA") => {
            use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
            let vk = VerifyingKey::from(*k);
            let s = Signature::from_der(sig).map_err(|e| format!("ECDSA sig parse: {e}"))?;
            Ok(vk.verify(msg, &s).is_ok())
        }
        (PubKey::P384(k), "SHA384withECDSA") => {
            use p384::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
            let vk = VerifyingKey::from(*k);
            let s = Signature::from_der(sig).map_err(|e| format!("ECDSA sig parse: {e}"))?;
            Ok(vk.verify(msg, &s).is_ok())
        }
        (PubKey::P521(k), "SHA512withECDSA") => {
            use p521::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(&k.to_sec1_bytes())
                .map_err(|e| format!("P-521 verifying key: {e}"))?;
            let s = Signature::from_der(sig).map_err(|e| format!("ECDSA sig parse: {e}"))?;
            Ok(vk.verify(msg, &s).is_ok())
        }
        _ => Err(format!("Unsupported algorithm {alg} for this key type")),
    }
}
