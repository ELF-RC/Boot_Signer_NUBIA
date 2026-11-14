# Boot Signer For NUBIA

**[English](README.md) | 中文**

`boot_signer.jar`（AOSP `com.android.verity.BootSignature`）的 Rust 单二进制替代，用于给 Nubia NX563J / NX595J 等设备的 boot.img 签名（Android Verified Boot v8.3 签名块）。

无 Java 依赖、无运行时依赖，直接命令行使用。

## 用法

```bash
# 签名（内置 AOSP 测试密钥，开箱即用）
./boot_signer /boot boot_unsigned.img boot_signed.img

# 签名（指定自己的密钥证书）
./boot_signer /boot boot_unsigned.img my.pk8 my.x509.pem boot_signed.img

# 保留镜像尾部多余字节（默认裁切到 signableSize）
./boot_signer /boot boot.img out.img --no-truncate

# 去除签名（还原未签名镜像，对 --no-truncate 产物同样可逆）
./boot_signer -strip boot_signed.img boot_unsigned.img

# 验证（可选用指定证书替代内嵌证书）
./boot_signer -verify boot_signed.img
./boot_signer -verify boot_signed.img -certificate my.x509.pem

# 查看内置证书
./boot_signer -print-cert
```

**两种参数形式：**
- `boot_signer <target> <image> <out>` — 使用编译进二进制的 AOSP verity 测试密钥对
- `boot_signer <target> <image> <key> <cert> <out>` — 显式指定密钥证书

| 参数 | 说明 |
|---|---|
| `target` | 目标分区名（如 `/boot`），写入签名元数据 |
| `image` | 待签名 boot.img（默认裁切到可签名长度） |
| `key` | 私钥：PKCS#8 DER 或 PEM（未加密；RSA / P-256 / P-384 / P-521） |
| `cert` | X.509 证书，PEM 或 DER，必须与私钥配对 |
| `out` | 输出（镜像 + 签名块） |

**选项：**
- `--no-truncate` — 不丢弃 signableSize 之后的字节，保留在签名块后方
- `-certificate X` — （verify）用指定证书验证，替代签名内嵌证书
- `-print-cert` — 输出内置证书（PEM）后退出

内置密钥为 AOSP 公开测试密钥，与原 jar 项目一致；替换 `keys/` 下两个文件重编译，或运行时显式传参即可。

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

- RSA：PKCS#1 v1.5 + SHA-256（确定性签名，与 jar 逐字节一致）
- ECDSA：DER 编码 (r,s)
- `signableSize` 计算兼容 boot header v0（dt_size@40）/ v1（recovery_dtbo）/ v2（+dtb），含页对齐逻辑
- 算法选择：RSA→SHA256withRSA；EC 按曲线 256/384/512 位 → SHA256/384/512withECDSA

## 错误处理与退出码

退出码：`0` 成功/有效，`1` 失败/无效，`2` 用法错误。`-verify` 结果打印到 stderr（与 jar 一致）。

报错与 jar 一致（镜像头/长度/版本异常等），并额外覆盖：参数数量/未知选项、文件不存在/不可读写/空文件、截断镜像/魔数/头字段/整型溢出、**密钥与证书不配对（拒绝签名）**、坏 PKCS#8 / 坏证书 / PEM 编码错误。均给出明确路径与原因。

## 构建

```bash
cargo build --release
# 静态单文件版本（任意发行版可跑）：
cargo build --release --target x86_64-unknown-linux-musl
```

## 兼容性

对 boot header v0/v1/v2 三种镜像，与原 jar 金标准双向验证通过：输出逐字节一致、jar↔rust 双向验签、单字节篡改检测。`-strip`、`--no-truncate`、错误处理另有 36 项检查覆盖。

> 实现为手写 DER 编解码（`src/der.rs`）与逐分支复刻的 `signableSize` 计算，签名输入为 `镜像 || DER(attrs)`，`AlgorithmIdentifier` 不带 NULL 参数，均按原 jar 产物实测对齐。

## 致谢

本项目实现参考了 [boot_signer_for_nubia_nx563j](https://github.com/kindle4jerry/boot_signer_for_nubia_nx563j)，感谢原作者的开源工作。

## 交流群

- QQ 群：`1045530205`
- Telegram：[ELF-RC Group](https://t.me/ELFRCGroup)
