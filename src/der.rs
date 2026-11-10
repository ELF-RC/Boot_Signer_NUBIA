//! Minimal DER (ASN.1) encoder + parser.
//! Byte-compatible with BouncyCastle DER encoding as used by AOSP BootSignature.

pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub total: usize, // bytes consumed including tag+length
}

/// Parse one TLV. Returns tag, content slice, total consumed length.
pub fn parse_tlv(data: &[u8]) -> Result<Tlv<'_>, String> {
    if data.len() < 2 {
        return Err("DER: truncated".to_string());
    }
    let tag = data[0];
    let mut idx = 1usize;
    let len_byte = data[idx];
    idx += 1;
    let len: usize = if len_byte < 0x80 {
        len_byte as usize
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < idx + n {
            return Err("DER: bad length".to_string());
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | data[idx + i] as usize;
        }
        idx += n;
        l
    };
    if data.len() < idx + len {
        return Err("DER: truncated content".to_string());
    }
    Ok(Tlv {
        tag,
        content: &data[idx..idx + len],
        total: idx + len,
    })
}

/// Parse the contents of a SEQUENCE into its element TLVs.
pub fn parse_seq(data: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let outer = parse_tlv(data)?;
    if outer.tag != 0x30 {
        return Err("DER: expected SEQUENCE".to_string());
    }
    let mut out = Vec::new();
    let mut rest = outer.content;
    while !rest.is_empty() {
        let t = parse_tlv(rest)?;
        out.push(Tlv {
            tag: t.tag,
            content: t.content,
            total: t.total,
        });
        rest = &rest[t.total..];
    }
    Ok(out)
}

/// Full TLV bytes of a parsed Tlv relative to its containing buffer.
pub fn full_bytes<'a>(buf: &'a [u8], t: &Tlv<'_>) -> &'a [u8] {
    // find offset: content is a subslice of buf
    let off = t.content.as_ptr() as usize - buf.as_ptr() as usize;
    &buf[off - (t.total - t.content.len())..off + t.content.len()]
}

fn encode_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap();
        out.push(0x80 | (bytes.len() - start) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(content.len() + 6);
    v.push(tag);
    encode_len(content.len(), &mut v);
    v.extend_from_slice(content);
    v
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for p in parts {
        content.extend_from_slice(p);
    }
    tlv(0x30, &content)
}

/// INTEGER from big-endian magnitude (non-negative), minimal encoding.
pub fn der_uint(mag: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = mag
        .iter()
        .skip_while(|&&b| b == 0)
        .copied()
        .collect();
    if v.is_empty() {
        v.push(0);
    }
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    tlv(0x02, &v)
}

pub fn der_i64(v: i64) -> Vec<u8> {
    if v >= 0 {
        der_uint(&v.to_be_bytes())
    } else {
        // negative not needed for this tool
        let mut b = v.to_be_bytes().to_vec();
        while b.len() > 1 && b[0] == 0xff && b[1] & 0x80 != 0 {
            b.remove(0);
        }
        tlv(0x02, &b)
    }
}

fn encode_base128(mut v: u64, out: &mut Vec<u8>) {
    let mut tmp = vec![(v & 0x7f) as u8];
    v >>= 7;
    while v > 0 {
        tmp.push(0x80 | (v & 0x7f) as u8);
        v >>= 7;
    }
    tmp.reverse();
    out.extend(tmp);
}

pub fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|s| s.parse().expect("bad OID arc"))
        .collect();
    assert!(arcs.len() >= 2);
    let mut content = Vec::new();
    content.push((arcs[0] * 40 + arcs[1]) as u8);
    for &a in &arcs[2..] {
        encode_base128(a, &mut content);
    }
    tlv(0x06, &content)
}

pub fn octet_string(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

pub fn printable_string(s: &str) -> Vec<u8> {
    tlv(0x13, s.as_bytes())
}

/// Parse an OID TLV content into dotted string.
pub fn oid_to_string(content: &[u8]) -> String {
    if content.is_empty() {
        return String::new();
    }
    let first = content[0] as u64;
    let mut parts = vec![(first / 40).to_string(), (first % 40).to_string()];
    let mut v: u64 = 0;
    for &b in &content[1..] {
        v = (v << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            parts.push(v.to_string());
            v = 0;
        }
    }
    parts.join(".")
}

/// Parse INTEGER TLV content as non-negative big-endian magnitude.
pub fn int_to_bytes(content: &[u8]) -> Result<Vec<u8>, String> {
    if content.is_empty() {
        return Err("DER: empty INTEGER".to_string());
    }
    if content[0] & 0x80 != 0 {
        return Err("DER: negative INTEGER not supported".to_string());
    }
    let mut v = content.to_vec();
    while v.len() > 1 && v[0] == 0 {
        v.remove(0);
    }
    Ok(v)
}

/// Base64 decode (standard alphabet, ignores whitespace/line breaks).
pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut rev = [0u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        rev[c as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut nbits = 0;
    for c in s.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' || c == b' ' || c == b'\t' {
            continue;
        }
        let v = rev[c as usize];
        if v == 0 && c != b'A' {
            return Err("base64: bad char".to_string());
        }
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    Ok(out)
}

/// Decode PEM block (BEGIN..END) into DER.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let mut b64 = String::new();
    let mut inside = false;
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN") {
            inside = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if inside {
            b64.push_str(line);
        }
    }
    if b64.is_empty() {
        return Err("PEM: no data".to_string());
    }
    base64_decode(&b64)
}

/// Accept either a PEM or raw DER blob and return DER bytes.
pub fn pem_or_der(raw: &[u8], what: &str) -> Result<Vec<u8>, String> {
    const BEGIN: &[u8] = b"-----BEGIN"; // 10 bytes
    let is_pem = raw.windows(BEGIN.len()).any(|w| w == BEGIN);
    if is_pem {
        let s = std::str::from_utf8(raw)
            .map_err(|_| format!("{what}: invalid PEM (not UTF-8)"))?;
        pem_to_der(s)
    } else if raw.is_empty() {
        Err(format!("{what}: empty file"))
    } else {
        Ok(raw.to_vec())
    }
}
