# boot_signer_rs

`boot_signer.jar`（AOSP `com.android.verity.BootSignature`）的 Rust 单二进制替代，
用于给 Nubia NX563J / NX595J 等设备的 boot.img 签名（Android Verified Boot v8.3 签名块）。

无 Java 依赖、无运行时依赖，直接命令行使用。

## 用法

```bash
# 签名（单二进制模式：密钥证书已内置，开箱即用）
./boot_signer /boot boot_unsigned.img boot_signed.img

# 签名（指定自己的密钥证书）
./boot_signer /boot boot_unsigned.img my.pk8 my.x509.pem boot_signed.img

# 签名但保留镜像尾部多余字节（默认会裁切到 signableSize）
./boot_signer /boot boot.img out.img --no-truncate

# 去除签名（还原未签名镜像；对 --no-truncate 产物同样可逆）
./boot_signer -strip boot_signed.img boot_unsigned.img

# 验证
./boot_signer -verify boot_signed.img
./boot_signer -verify boot_signed.img -certificate my.x509.pem

# 查看内置证书
./boot_signer -print-cert
```

参数（两种形式）：
- `boot_signer <target> <image> <out>` —— **单二进制模式**，使用编译进二进制的 AOSP verity 测试密钥对
- `boot_signer <target> <image> <key> <cert> <out>` —— 显式指定密钥证书

- `target`    目标分区名（如 `/boot`），写入签名元数据
- `image`     待签名的 boot.img（默认自动裁切到可签名长度，超出部分打印 NOTE）
- `key`       私钥：PKCS#8 DER 或 PEM（未加密；RSA / P-256 / P-384 / P-521）
- `cert`      X.509 证书，PEM 或 DER（必须与私钥配对，不配对会拒绝签名）
- `out`       输出（镜像 + 签名块）

选项：
- `--no-truncate`  不丢弃 signableSize 之后的字节，将它们保留在签名块后方
- `-certificate X`  (verify) 用指定证书验证，替代签名内嵌证书
- `-print-cert`     输出内置证书（PEM）后退出

内置密钥说明：`src/embedded.rs` 通过 `include_bytes!` 编译进 `keys/verity.pk8` +
`keys/verity.x509.pem`（即 AOSP 公开测试密钥，与原 jar 项目一致）。
换自己的密钥：替换 `keys/` 下两个文件重新编译，或运行时显式传参。

退出码：`0` 成功/有效  `1` 失败/无效  `2` 用法错误。`-verify` 结果打印到 stderr（与 jar 一致）。

### 错误处理

与 jar 一致的报错（`Invalid image header: missing magic / invalid header length /
invalid length`、`Invalid image: too short, expected N bytes / not signed /
Invalid image length`、`Unsupported format version`）之外，覆盖更多场景：
- 参数数量/未知选项/缺参数 → exit 2 + usage 提示
- 文件不存在/不可读写/空文件 → exit 1 + 明确路径与原因
- 截断镜像/魔数错误/头字段异常/整型溢出 → exit 1 + 具体位置
- **密钥与证书不配对 → 拒绝签名**（产物必无法验证；jar 不查，这里查）
- 坏 PKCS#8 / 坏证书 / PEM 编码错误 → exit 1
- 私钥支持 PEM/DER 自动识别（jar 仅 DER）

## 签名格式（与 jar 字节级兼容）

```
signed = image[0..signableSize] || BootSignature-DER

BootSignature ::= SEQUENCE {
    formatVersion           INTEGER (1),
    certificate             <X.509 cert DER 原样>,
    algorithmIdentifier     SEQUENCE { OID },      -- 无 NULL 参数
    authenticatedAttributes SEQUENCE {
        target  PrintableString,                   -- e.g. "/boot"
        length  INTEGER                            -- signableSize
    },
    signature               OCTET STRING
}

被签数据 = image[0..signableSize] || DER(authenticatedAttributes)
```

- RSA：PKCS#1 v1.5 + SHA-256（确定性签名 → 与 jar 输出逐字节一致）
- ECDSA：DER 编码 (r,s)
- `signableSize` 计算兼容 boot header v0（dt_size@40）/ v1（recovery_dtbo）/ v2（+dtb），
  含页对齐逻辑，与 `BootSignature.getSignableImageSize()` 逐分支一致

算法选择与 `Utils.getSignatureAlgorithm()` 相同：
RSA→SHA256withRSA；EC 按曲线 256/384/512 位 → SHA256/384/512withECDSA。

## 验证结果

对 boot header v0/v1/v2 三种镜像（与原 jar 金标准对照）：

| 测试 | 结果 |
|---|---|
| 与原 jar 输出逐字节一致 | ✅ ×3 |
| jar 验证 rust 签名 | ✅ ×3 |
| rust 验证 jar 签名 | ✅ ×3 |
| jar 检测篡改（改 1 字节）| ✅ ×3 |
| rust 检测篡改 | ✅ ×3 |

新功能与错误处理（36 项检查）：

| 类别 | 覆盖 |
|---|---|
| `-strip` | 还原原始镜像 / 剥离后重签一致 / 可逆 `--no-truncate` 产物 / 未签名镜像报错 |
| `--no-truncate` | 尾部字节保留、位置正确、jar+rust 双向验证 |
| 错误处理 | 参数错误×8、文件/镜像损坏×5、密钥证书不配对、坏密钥证书、缺参数、help |

## 构建

```bash
cargo build --release
# 真·单文件静态版本（任意发行版可跑）：
cargo build --release --target x86_64-unknown-linux-musl
```

## 移植到 Rust 的实现要点（与 Java 版的对应）

| Java | Rust |
|---|---|
| `BootSignature` ASN.1 (BouncyCastle DER) | `src/der.rs` 手写 DER 编解码 |
| `getSignableImageSize()` | `src/bootimg.rs` 逐分支复刻（含 v0 dt_size 兼容） |
| `Utils.sign/verify/getSignatureAlgorithm` | `src/crypto.rs`（rsa + sha1/sha2 + p256/384/521） |
| `Utils.loadDERPrivateKey / loadPEMCertificate` | PKCS#8 / X.509 解析（x509-parser） |
| `doSignature / verifySignature / main` | `src/main.rs` |

细节：`AlgorithmIdentifier` 编码为 `SEQUENCE{OID}` **不带 NULL 参数**（已对原 jar 产物
十六进制确认）；`authenticatedAttributes` 是 `SEQUENCE`（非 SET）；签名输入是
`镜像 || DER(attrs)` 而非仅 attrs——这些坑都按字节码/产物实测对齐过。
