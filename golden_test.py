#!/usr/bin/env python3
"""
golden_test.py — 用原版 boot_signer.jar 做金标准，验证 Rust 版字节级一致。

流程:
  1. 生成伪造 boot.img (v0/v1/v2 头 + 随机内核/ramdisk)
  2. jar 签名 -> jar.img ;  rust 签名 -> rs.img
  3. cmp 两个产物 (RSA PKCS#1v1.5 是确定性签名, 必须逐字节一致)
  4. jar -verify 验 rs.img ;  rust -verify 验 jar.img (交叉验证)
  5. 篡改一字节 -> 双方都必须报 INVALID
"""
import os, struct, subprocess, sys, random

WORK = os.path.dirname(os.path.abspath(__file__))
ORIG = os.path.join(WORK, "orig")
JAVA = os.path.expanduser("~/.local/jdk/bin/java")
JAR = os.path.join(ORIG, "boot_signer.jar")
KEY = os.path.join(ORIG, "verity.pk8")
CERT = os.path.join(ORIG, "verity.x509.pem")
RS = os.path.join(WORK, "boot_signer")

def make_boot_img(path, version):
    page = 2048
    kernel = random.randbytes(0x1234)
    ramdisk = random.randbytes(0x2000)
    second = random.randbytes(0x100) if version == 0 else b""
    hdr = bytearray(page)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<I", hdr, 8, len(kernel))    # kernel_size
    struct.pack_into("<I", hdr, 12, 0x8000)        # kernel_addr
    struct.pack_into("<I", hdr, 16, len(ramdisk))  # ramdisk_size
    struct.pack_into("<I", hdr, 20, 0x1000000)     # ramdisk_addr
    struct.pack_into("<I", hdr, 24, len(second))   # second_size
    struct.pack_into("<I", hdr, 28, 0x8f000)       # second_addr
    struct.pack_into("<I", hdr, 32, 0x8f000)       # tags_addr
    struct.pack_into("<I", hdr, 36, page)          # page_size
    recovery_dtbo = b""
    dtb = b""
    if version == 0:
        struct.pack_into("<I", hdr, 40, 0x1000)    # dt_size (v0 legacy)
    elif version == 1:
        struct.pack_into("<I", hdr, 40, 1)         # header_version
        recovery_dtbo = random.randbytes(0x800)
        struct.pack_into("<I", hdr, 1632, len(recovery_dtbo))
        struct.pack_into("<Q", hdr, 1636, 0x2000)
        struct.pack_into("<I", hdr, 1644, 1648)    # header_size (v1)
    elif version == 2:
        struct.pack_into("<I", hdr, 40, 2)         # header_version
        recovery_dtbo = random.randbytes(0x800)
        struct.pack_into("<I", hdr, 1632, len(recovery_dtbo))
        struct.pack_into("<Q", hdr, 1636, 0x2000)
        struct.pack_into("<I", hdr, 1644, 1660)    # header_size (v2)
        dtb = random.randbytes(0x4000)
        struct.pack_into("<I", hdr, 1648, len(dtb))
        struct.pack_into("<Q", hdr, 1652, 0x3000)

    def pad(b):
        return b + b"\0" * ((page - len(b) % page) % page)

    out = bytearray()
    out += hdr
    out += pad(kernel)
    out += pad(ramdisk)
    out += pad(second)
    if version == 0:
        out += pad(b"\0" * 0x1000)   # dt blob
    out += pad(recovery_dtbo)
    out += pad(dtb)
    with open(path, "wb") as f:
        f.write(out)
    return len(out)

def run(cmd, expect_rc=None):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if expect_rc is not None and p.returncode != expect_rc:
        print(f"FAIL rc={p.returncode} (want {expect_rc}): {' '.join(cmd)}")
        print("stdout:", p.stdout)
        print("stderr:", p.stderr)
        sys.exit(1)
    return p

def main():
    random.seed(42)
    failures = 0
    for ver in (0, 1, 2):
        print(f"=== boot header v{ver} ===")
        img = os.path.join(WORK, f"test_v{ver}.img")
        size = make_boot_img(img, ver)
        jar_out = os.path.join(WORK, f"jar_v{ver}.img")
        rs_out = os.path.join(WORK, f"rs_v{ver}.img")

        # 1. sign with both
        p = run([JAVA, "-jar", JAR, "/boot", img, KEY, CERT, jar_out])
        if p.stderr.strip():
            print(f"  jar stderr: {p.stderr.strip()}")
        p = run([RS, "/boot", img, KEY, CERT, rs_out])
        if p.stderr.strip():
            print(f"  rs  stderr: {p.stderr.strip()}")

        # 2. byte-compare
        jb = open(jar_out, "rb").read()
        rb = open(rs_out, "rb").read()
        if jb == rb:
            print(f"  [PASS] 输出逐字节一致 ({len(jb)} bytes, input {size})")
        else:
            failures += 1
            print(f"  [FAIL] 输出不一致: jar={len(jb)} rs={len(rb)}")
            for i in range(min(len(jb), len(rb))):
                if jb[i] != rb[i]:
                    print(f"    first diff at 0x{i:x}: jar={jb[i]:02x} rs={rb[i]:02x}")
                    print(f"    jar[..]: {jb[max(0,i-8):i+24].hex()}")
                    print(f"    rs [..]: {rb[max(0,i-8):i+24].hex()}")
                    break

        # 3. cross verify
        p = run([JAVA, "-jar", JAR, "-verify", rs_out], expect_rc=0)
        ok = "Signature is VALID" in p.stderr
        print(f"  [{'PASS' if ok else 'FAIL'}] jar 验证 rust 签名: {p.stderr.strip()}")
        if not ok:
            failures += 1

        p = run([RS, "-verify", jar_out], expect_rc=0)
        ok = "Signature is VALID" in p.stderr
        print(f"  [{'PASS' if ok else 'FAIL'}] rust 验证 jar 签名: {p.stderr.strip()}")
        if not ok:
            failures += 1

        # 4. tamper test
        tampered = os.path.join(WORK, f"tamper_v{ver}.img")
        tb = bytearray(rb)
        tb[0x100] ^= 0xff
        open(tampered, "wb").write(tb)
        p = run([JAVA, "-jar", JAR, "-verify", tampered])
        ok = "Signature is INVALID" in p.stderr
        print(f"  [{'PASS' if ok else 'FAIL'}] jar 检测篡改: {p.stderr.strip()}")
        if not ok:
            failures += 1
        p = run([RS, "-verify", tampered])
        ok = "Signature is INVALID" in p.stderr
        print(f"  [{'PASS' if ok else 'FAIL'}] rust 检测篡改: {p.stderr.strip()}")
        if not ok:
            failures += 1

    print()
    if failures:
        print(f"RESULT: {failures} failure(s)")
        sys.exit(1)
    print("RESULT: ALL PASS")

if __name__ == "__main__":
    main()
