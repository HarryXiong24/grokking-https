# Grokking Https

## Outline

1. http的痛点
2. SSL/TLS
3. 对称加密（AES、DES）
4. 非对称加密（RSA、ECC）
5. 哈希（MD5、SHA1、SHA256、加盐）
6. 数字签名（私钥签名，公钥验证签名）
7. 数字证书
8. Diffie-Hellman 算法（大质数分解质因数）
9. ECC（椭圆曲线加密算法）
10. ECDHE
11. 秘钥协商（RSA、ECDHE）

## 1. 现有http的痛点及https解决方案

| 痛点 | 解决方案 | 描述 |
| - | - | - |
| 窃听 | 加密 | 对称加密AES |
| 秘钥传递 | 秘钥协商 | 非对称加密（RSA和ECDHE） |
| 篡改 | 完整性校验 | 散列算法（md5、sha256）签名 |
| 身份冒充 | CA权威机构 | 散列算法（md5、sha256） + RSA签名 |

## 2. HTTPS 中的 S 到底是什么

![image.png](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/d4bc6f7928db43c1946372b59d961687~tplv-k3u1fbpfcp-watermark.image?)

## 3. 对称加密

- 对称加密是最快速、最简单的一种加密方式,加密(encryption)与解密(decryption)用的是同样的密钥(secret key)
- 主流的有`AES`和`DES`

### 简单实现

- 消息 `abc`
- 密钥 3
- 密文 def

![image.png](https://p1-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/fd30b0712ff64450873a929389897ca8~tplv-k3u1fbpfcp-watermark.image?)

### 代码实现

``` ts
// symmetric-encryption

// encrypt key and decrypt key are the same
const secret = 3;

export function symmetricEncrypt(message: string): string {
  // convert message to buffer
  const buffer = Buffer.from(message);

  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = buffer[i] + secret;
  }

  return buffer.toString();
}

export function symmetricDecrypt(message: string): string {
  // convert message to buffer
  const buffer = Buffer.from(message);

  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = buffer[i] - secret;
  }

  return buffer.toString();
}
```
