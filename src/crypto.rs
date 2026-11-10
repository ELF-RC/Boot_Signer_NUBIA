//! Key loading + sign/verify — mirrors com.android.verity.Utils semantics.
//!
//! Algorithm selection (Utils.getSignatureAlgorithm):
//!   RSA key -> SHA256withRSA
//!
//! OID table (Utils.<clinit>):
//!   sha1WithRSAEncryption    1.2.840.113549.1.1.5  <-> SHA1withRSA
//!   sha256WithRSAEncryption  1.2.840.113549.1.1.11 <-> SHA256withRSA
//!   sha512WithRSAEncryption  1.2.840.113549.1.1.13 <-> SHA512withRSA


use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha1::{Digest as _, Sha1};
use sha2::{Sha256, Sha512};

pub const OID_SHA1_RSA: &str = "1.2.840.113549.1.1.5";
pub const OID_SHA256_RSA: &str = "1.2.840.113549.1.1.11";
pub const OID_SHA512_RSA: &str = "1.2.840.113549.1.1.13";

pub enum PrivKey {
    Rsa(RsaPrivateKey),
}

pub enum PubKey {
    Rsa(RsaPublicKey),
}

/// Utils.getSignatureAlgorithm(Key) + getSignatureAlgorithmIdentifier(Key):
/// (JCE algorithm name, algorithm OID).
pub fn signature_algorithm_for_priv(k: &PrivKey) -> (&'static str, &'static str) {
    match k {
        PrivKey::Rsa(_) => ("SHA256withRSA", OID_SHA256_RSA),
    }
}

/// Utils.ID_TO_ALG — signature algorithm OID -> JCE name.
pub fn alg_name_for_oid(oid: &str) -> Option<&'static str> {
    match oid {
        x if x == OID_SHA1_RSA => Some("SHA1withRSA"),
        x if x == OID_SHA256_RSA => Some("SHA256withRSA"),
        x if x == OID_SHA512_RSA => Some("SHA512withRSA"),
        _ => None,
    }
}

/// Load an unencrypted PKCS#8 private key (RSA).
/// Mirrors Utils.loadDERPrivateKey (minus the encrypted-key path).
pub fn load_pkcs8_private_key(der: &[u8]) -> Result<PrivKey, String> {
    use rsa::pkcs8::DecodePrivateKey;
    RsaPrivateKey::from_pkcs8_der(der)
        .map(PrivKey::Rsa)
        .map_err(|e| format!("PKCS#8 parse failed: {e}"))
}

/// Extract the public key from an X.509 certificate DER
/// (CertificateFactory "X.509" + X509Certificate.getPublicKey()).
pub fn public_key_from_cert(cert_der: &[u8]) -> Result<PubKey, String> {
    use rsa::pkcs8::DecodePublicKey;
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| format!("X.509 parse failed: {e}"))?;
    RsaPublicKey::from_public_key_der(cert.public_key().raw)
        .map(PubKey::Rsa)
        .map_err(|e| format!("RSA public key parse failed: {e}"))
}

/// Utils.sign(PrivateKey, byte[]).
/// RSA: PKCS#1 v1.5 (deterministic).
pub fn sign(key: &PrivKey, msg: &[u8]) -> Result<Vec<u8>, String> {
    match key {
        PrivKey::Rsa(k) => {
            // JCE SHA256withRSA = EMSA-PKCS1-v1_5(DigestInfo(SHA256, msg))
            let digest = Sha256::digest(msg);
            k.sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
                .map_err(|e| format!("RSA sign failed: {e}"))
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
        _ => Err(format!("Unsupported algorithm {alg} for this key type")),
    }
}
