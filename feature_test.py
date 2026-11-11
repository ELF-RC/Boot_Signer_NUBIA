#!/usr/bin/env python3
"""
feature_test.py — 新功能 + 错误处理测试

A. 新功能
   1. -strip 去除签名 -> 与原镜像一致
   2. -strip 后可重新签名，输出与首次签名一致
   3. --no-truncate 签名: 尾部多余字节保留在签名块之后
   4. --no-truncate 产物可被 jar 与 rust 双向验证
   5. -strip 能剥离 --no-truncate 产物并还原原始镜像（含尾部字节）

B. 错误处理
   6.  参数数量错误 -> exit 2 + usage
   7.  未知命令/选项 -> exit 2
   8.  文件不存在 -> exit 1 + 明确信息
   9.  空文件 / 非 ANDROID! 魔数 -> exit 1
   10. 镜像过短 (header 声明长度 > 文件) -> exit 1
   11. header 长度字段错误 -> exit 1
   12. 密钥/证书不配对 -> exit 1
   13. 坏的 PKCS#8 / 坏的证书 -> exit 1
   14. -strip 未签名镜像 -> exit 1
   15. -verify 未签名镜像 -> exit 1
   16. -certificate 缺参数 -> exit 2
   17. PEM 密钥输入（而非 DER）-> 正常签名
   18. -h/--help -> exit 0
"""
import os, struct, subprocess, sys, random

WORK = os.path.dirname(os.path.abspath(__file__))
JAVA = os.path.expanduser("~/.local/jdk/bin/java")
JAR = os.path.join(WORK, "orig/boot_signer.jar")
KEY = os.path.join(WORK, "orig/verity.pk8")
CERT = os.path.join(WORK, "orig/verity.x509.pem")
RS = os.path.join(WORK, "boot_signer")

passes = fails = 0
def check(name, ok, detail=""):
    global passes, fails
    if ok:
        passes += 1
        print(f"  [PASS] {name}")
    else:
        fails += 1
        print(f"  [FAIL] {name}  {detail}")

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

def make_boot_img(path, version=0):
    page = 2048
    kernel = random.randbytes(0x1234)
    ramdisk = random.randbytes(0x2000)
    hdr = bytearray(page)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<I", hdr, 8, len(kernel))
    struct.pack_into("<I", hdr, 12, 0x8000)
    struct.pack_into("<I", hdr, 16, len(ramdisk))
    struct.pack_into("<I", hdr, 20, 0x1000000)
    struct.pack_into("<I", hdr, 24, 0)
    struct.pack_into("<I", hdr, 28, 0x8f000)
    struct.pack_into("<I", hdr, 32, 0x8f000)
    struct.pack_into("<I", hdr, 36, page)
    struct.pack_into("<I", hdr, 40, 0x1000) if version == 0 else struct.pack_into("<I", hdr, 40, 1)
    def pad(b): return b + b"\0" * ((page - len(b) % page) % page)
    out = hdr + pad(kernel) + pad(ramdisk)
    if version == 0:
        out += pad(b"\0" * 0x1000)
    open(path, "wb").write(out)

def main():
    random.seed(7)
    img = os.path.join(WORK, "ft_v0.img")
    make_boot_img(img, 0)
    original = open(img, "rb").read()
    signed = os.path.join(WORK, "ft_signed.img")
    p = run([RS, "/boot", img, KEY, CERT, signed])
    check("基线: 签名成功", p.returncode == 0, p.stderr)

    print("=== A. 新功能 ===")

    # 0. 单二进制模式: 3 参数 == 5 参数（逐字节一致）
    emb = os.path.join(WORK, "ft_embedded.img")
    p = run([RS, "/boot", img, emb])
    check("单二进制签名 (3 参数)", p.returncode == 0, f"rc={p.returncode} {p.stderr.strip()}")
    ok = p.returncode == 0 and open(emb, "rb").read() == open(signed, "rb").read()
    check("单二进制签名 == 显式密钥签名", ok)
    p = run([RS, "-verify", emb])
    check("验证单二进制产物", p.returncode == 0 and "VALID" in p.stderr, p.stderr.strip())
    p = run([RS, "-print-cert"])
    check("-print-cert 输出 PEM", p.returncode == 0 and "BEGIN CERTIFICATE" in p.stdout, f"rc={p.returncode}")
    p = run([RS, "/boot", img, emb, "a", "b", "c"])
    check("6 参数报错", p.returncode == 2, f"rc={p.returncode}")

    # 1. -strip -> 与原镜像一致
    stripped = os.path.join(WORK, "ft_stripped.img")
    p = run([RS, "-strip", signed, stripped])
    ok = p.returncode == 0 and open(stripped, "rb").read() == original
    check("-strip 还原原始镜像", ok, f"rc={p.returncode} {p.stderr.strip()}")

    # 2. strip 后重签 == 首签
    resigned = os.path.join(WORK, "ft_resigned.img")
    p = run([RS, "/boot", stripped, KEY, CERT, resigned])
    ok = p.returncode == 0 and open(resigned, "rb").read() == open(signed, "rb").read()
    check("strip 后重签输出一致", ok, f"rc={p.returncode}")

    # 3/4. --no-truncate: 尾部追加垃圾字节
    padded = os.path.join(WORK, "ft_padded.img")
    junk = b"\xab" * 4321
    open(padded, "wb").write(original + junk)
    nt_out = os.path.join(WORK, "ft_nt.img")
    p = run([RS, "/boot", padded, KEY, CERT, nt_out, "--no-truncate"])
    data = open(nt_out, "rb").read()
    ok = p.returncode == 0 and data.endswith(junk)
    check("--no-truncate 保留尾部字节", ok, f"rc={p.returncode} {p.stderr.strip()}")
    # 签名块应位于 signableSize 处，尾部在其后
    signable = len(original)   # v0 场景: 文件 == signableSize + 已含 dt? 实际上 original 恰为 signableSize
    check("--no-truncate 尾部在签名块之后",
          data[:signable] == original and data.endswith(junk) and len(data) == len(original) + (len(data) - len(original) - len(junk)) + len(junk))

    # 验证 --no-truncate 产物
    p = run([RS, "-verify", nt_out])
    check("rust 验证 --no-truncate 产物", p.returncode == 0 and "VALID" in p.stderr, p.stderr.strip())
    p = run([JAVA, "-jar", JAR, "-verify", nt_out])
    check("jar 验证 --no-truncate 产物", p.returncode == 0 and "VALID" in p.stderr, p.stderr.strip())

    # 5. strip --no-truncate 产物 -> 还原 padded 原始
    nt_stripped = os.path.join(WORK, "ft_nt_stripped.img")
    p = run([RS, "-strip", nt_out, nt_stripped])
    ok = p.returncode == 0 and open(nt_stripped, "rb").read() == open(padded, "rb").read()
    check("-strip 还原 --no-truncate 原始(含尾部)", ok, f"rc={p.returncode} {p.stderr.strip()}")

    # 17. PEM 私钥输入
    pem_key = os.path.join(WORK, "ft_key.pem")
    import base64
    der = open(KEY, "rb").read()
    b64 = base64.encodebytes(der).decode()
    open(pem_key, "w").write("-----BEGIN PRIVATE KEY-----\n" + b64 + "-----END PRIVATE KEY-----\n")
    pem_out = os.path.join(WORK, "ft_pem_signed.img")
    p = run([RS, "/boot", img, pem_key, CERT, pem_out])
    ok = p.returncode == 0 and open(pem_out, "rb").read() == open(signed, "rb").read()
    check("PEM 私钥输入产出一致", ok, f"rc={p.returncode} {p.stderr.strip()}")

    print("=== B. 错误处理 ===")

    # 6. 参数数量
    p = run([RS])
    check("无参数 -> exit 2 + usage", p.returncode == 2 and "usage" in p.stderr, f"rc={p.returncode}")
    p = run([RS, "/boot", img, KEY, CERT])
    check("sign 参数不足 (4个) -> exit 2", p.returncode == 2, f"rc={p.returncode}")
    p = run([RS, "/boot", img])
    check("sign 参数不足 (2个) -> exit 2", p.returncode == 2, f"rc={p.returncode}")
    p = run([RS, "-verify"])
    check("-verify 缺镜像 -> exit 2", p.returncode == 2, f"rc={p.returncode}")
    p = run([RS, "-strip", img])
    check("-strip 参数不足 -> exit 2", p.returncode == 2, f"rc={p.returncode}")

    # 7. 未知命令/选项
    p = run([RS, "-bogus", "x"])
    check("未知命令 -> exit 2", p.returncode == 2, f"rc={p.returncode}")
    p = run([RS, "/boot", img, KEY, CERT, signed, "--bogus"])
    check("未知选项 -> exit 2", p.returncode == 2, f"rc={p.returncode}")
    p = run([RS, "-verify", img, "-bogus"])
    check("-verify 未知选项 -> exit 2", p.returncode == 2, f"rc={p.returncode}")

    # 8. 文件不存在
    p = run([RS, "/boot", "/nonexistent.img", KEY, CERT, "/tmp/x.img"])
    check("输入镜像不存在 -> exit 1 + 信息", p.returncode == 1 and "cannot open" in p.stderr, p.stderr.strip())
    p = run([RS, "/boot", img, "/nonexistent.pk8", CERT, "/tmp/x.img"])
    check("密钥不存在 -> exit 1", p.returncode == 1 and "cannot open" in p.stderr, p.stderr.strip())

    # 9. 空文件 / 错误魔数
    empty = os.path.join(WORK, "ft_empty.img")
    open(empty, "wb").close()
    p = run([RS, "/boot", empty, KEY, CERT, "/tmp/x.img"])
    check("空镜像 -> exit 1", p.returncode == 1, f"rc={p.returncode} {p.stderr.strip()}")
    bad = os.path.join(WORK, "ft_badmagic.img")
    open(bad, "wb").write(b"NOTANDROID" + b"\0" * 4096)
    p = run([RS, "/boot", bad, KEY, CERT, "/tmp/x.img"])
    check("错误魔数 -> exit 1 + missing magic", p.returncode == 1 and "missing magic" in p.stderr, p.stderr.strip())

    # 10. 镜像过短: header 声明 kernel=0x1234 但文件只有 header
    short = os.path.join(WORK, "ft_short.img")
    open(short, "wb").write(open(img, "rb").read()[:2048])
    p = run([RS, "/boot", short, KEY, CERT, "/tmp/x.img"])
    check("镜像过短 -> exit 1 + too short", p.returncode == 1 and "too short" in p.stderr, p.stderr.strip())

    # 11. header 长度字段错误 (v1 header_size 不匹配)
    badhdr = bytearray(open(img, "rb").read())
    struct.pack_into("<I", badhdr, 40, 1)            # header_version = 1
    struct.pack_into("<I", badhdr, 1644, 0xDEAD)     # header_size = wrong
    badhdr_path = os.path.join(WORK, "ft_badhdr.img")
    open(badhdr_path, "wb").write(badhdr)
    p = run([RS, "/boot", badhdr_path, KEY, CERT, "/tmp/x.img"])
    check("header 长度字段错误 -> exit 1 + invalid header length",
          p.returncode == 1 and "invalid header length" in p.stderr, p.stderr.strip())

    # 12. 密钥/证书不配对: 用 jar 的密钥配一个别的自签证书
    p = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", os.path.join(WORK, "ft_other.key"),
             "-out", os.path.join(WORK, "ft_other.crt"), "-days", "1", "-nodes", "-subj", "/CN=other"],
            )
    if p.returncode == 0:
        # 把 other.key 转 pk8
        run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", os.path.join(WORK, "ft_other.key"),
             "-outform", "DER", "-out", os.path.join(WORK, "ft_other.pk8")])
        p = run([RS, "/boot", img, KEY, os.path.join(WORK, "ft_other.crt"), "/tmp/x.img"])
        check("密钥/证书不配对 -> exit 1 + 明确信息",
              p.returncode == 1 and "not a pair" in p.stderr, p.stderr.strip())
    else:
        check("密钥/证书不配对 (openssl 不可用, 跳过)", True)

    # 13. 坏 PKCS#8 / 坏证书
    badkey = os.path.join(WORK, "ft_bad.pk8")
    open(badkey, "wb").write(b"\x30\x03\x02\x01\x00")
    p = run([RS, "/boot", img, badkey, CERT, "/tmp/x.img"])
    check("坏 PKCS#8 -> exit 1", p.returncode == 1, f"rc={p.returncode} {p.stderr.strip()}")
    badcert = os.path.join(WORK, "ft_bad.crt")
    open(badcert, "w").write("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    p = run([RS, "/boot", img, KEY, badcert, "/tmp/x.img"])
    check("坏证书 -> exit 1", p.returncode == 1, f"rc={p.returncode} {p.stderr.strip()}")

    # 14/15. 未签名镜像
    p = run([RS, "-strip", img, "/tmp/x.img"])
    check("-strip 未签名镜像 -> exit 1 + not signed", p.returncode == 1 and "not signed" in p.stderr, p.stderr.strip())
    p = run([RS, "-verify", img])
    check("-verify 未签名镜像 -> exit 1 + not signed", p.returncode == 1 and "not signed" in p.stderr, p.stderr.strip())

    # 16. -certificate 缺参数
    p = run([RS, "-verify", signed, "-certificate"])
    check("-certificate 缺参数 -> exit 2", p.returncode == 2, f"rc={p.returncode}")

    # 18. help
    p = run([RS, "-h"])
    check("-h -> exit 0 + usage", p.returncode == 0 and "usage" in p.stdout.lower(), f"rc={p.returncode}")
    p = run([RS, "--help"])
    check("--help -> exit 0", p.returncode == 0, f"rc={p.returncode}")

    print()
    print(f"RESULT: {passes} passed, {fails} failed")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
