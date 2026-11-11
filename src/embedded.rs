//! Embedded default signing material (AOSP verity test keys).
//!
//! These are the *publicly known* AOSP test keys (also shipped in the original
//! boot_signer.jar project and the AOSP source tree) for custom-ROM development
//! on the developer's own device. Embedding them lets the tool work as a true
//! single binary. Override at runtime by passing explicit <key> <cert>.

/// PKCS#8 DER private key.
pub static DEFAULT_KEY: &[u8] = include_bytes!("../keys/verity.pk8");

/// X.509 certificate (PEM).
pub static DEFAULT_CERT: &[u8] = include_bytes!("../keys/verity.x509.pem");
