//! Boot image header parsing — byte-compatible with AOSP BootSignature.getSignableImageSize().
//!
//! Layout (little-endian), boot_img_hdr:
//!   0   magic[8] = "ANDROID!"
//!   8   kernel_size u32
//!   12  kernel_addr u32
//!   16  ramdisk_size u32
//!   20  ramdisk_addr u32
//!   24  second_size u32
//!   28  second_addr u32
//!   32  tags_addr u32
//!   36  page_size u32
//!   40  header_version u32   (v0: dt_size field re-used)
//!   v1/v2 extension:
//!   1632  recovery_dtbo_size u32
//!   1636  recovery_dtbo_offset u64
//!   1644  header_size u32
//!   1648  dtb_size u32   (v2 only)
//!   1652  dtb_addr u64   (v2 only)

pub const BOOT_IMAGE_HEADER_V1_RECOVERY_DTBO_SIZE_OFFSET: usize = 1632;
pub const BOOT_IMAGE_HEADER_V2_DTB_SIZE_OFFSET: usize = 1648;

fn u32_at(buf: &[u8], off: usize) -> Result<u32, String> {
    if buf.len() < off + 4 {
        return Err(format!(
            "Invalid image header: truncated (need offset {}, have {} bytes)",
            off + 4,
            buf.len()
        ));
    }
    Ok(u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()))
}

/// roundUp(n, page) with overflow protection.
fn round_up(n: u64, page: u64) -> Result<u64, String> {
    if page == 0 {
        return Err("Invalid image header: zero page size".to_string());
    }
    n.checked_add(page - 1)
        .map(|v| v / page * page)
        .ok_or_else(|| "Invalid image header: length overflow".to_string())
}

/// Mirrors BootSignature.getSignableImageSize(byte[]).
pub fn get_signable_image_size(image: &[u8]) -> Result<usize, String> {
    let magic = image.get(0..8).unwrap_or(&[]);
    if magic != b"ANDROID!" {
        return Err("Invalid image header: missing magic".to_string());
    }

    let kernel_size = u32_at(image, 8)? as u64;
    let ramdisk_size = u32_at(image, 16)? as u64;
    let second_size = u32_at(image, 24)? as u64;
    let page_size = u32_at(image, 36)? as u64;
    if page_size == 0 {
        return Err("Invalid image header: invalid length".to_string());
    }

    let mut signable_size = page_size;
    for part in [kernel_size, ramdisk_size, second_size] {
        signable_size = signable_size
            .checked_add(round_up(part, page_size)?)
            .ok_or_else(|| "Invalid image header: length overflow".to_string())?;
    }

    let header_version = u32_at(image, 40)?;

    if header_version > 0 && header_version <= 4 {
        // v1..v4 header extensions
        let recovery_dtbo_size =
            u32_at(image, BOOT_IMAGE_HEADER_V1_RECOVERY_DTBO_SIZE_OFFSET)? as u64;
        signable_size = signable_size
            .checked_add(round_up(recovery_dtbo_size, page_size)?)
            .ok_or_else(|| "Invalid image header: length overflow".to_string())?;
        // skip recovery_dtbo_offset (u64 @1636)
        let header_size = u32_at(image, 1644)?;
        if header_version == 2 {
            let dtb_size = u32_at(image, BOOT_IMAGE_HEADER_V2_DTB_SIZE_OFFSET)? as u64;
            signable_size = signable_size
                .checked_add(round_up(dtb_size, page_size)?)
                .ok_or_else(|| "Invalid image header: length overflow".to_string())?;
            // skip dtb_addr (u64 @1652)
        }
        // Bytecode: position must equal header_size, else "invalid header length"
        let pos: u32 = if header_version == 2 { 1660 } else { 1648 };
        if pos != header_size {
            return Err("Invalid image header: invalid header length".to_string());
        }
    } else if header_version > 4 {
        signable_size = signable_size
            .checked_add(round_up(header_version as u64, page_size)?)
            .ok_or_else(|| "Invalid image header: length overflow".to_string())?;
    }

    signable_size = round_up(signable_size, page_size)?;

    if signable_size == 0 || signable_size > u32::MAX as u64 {
        return Err("Invalid image header: invalid length".to_string());
    }
    Ok(signable_size as usize)
}
