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

### DES

DES（数据加密标准，Data Encryption Standard）是一种对称密钥加密算法，于1977年被美国国家标准局（现为国家标准与技术研究院，NIST）正式采纳为联邦信息处理标准（FIPS PUB 46）。DES的设计基于一种名为Feistel网络的结构，它将64位的明文输入转换成64位的密文输出，通过执行一系列复杂的加密过程。DES使用56位的密钥进行加密和解密，加上8位用于奇偶校验，总共是64位。

尽管DES在推出时被认为是相当安全的，但随着计算能力的增长，其56位的密钥长度逐渐显示出安全性不足。到了1990年代末，通过专门的硬件攻击，DES加密可以在几个小时内被破解。这导致了对DES安全性的广泛关注和对替代加密标准的需求。

为了应对DES安全性不足的问题，NIST启动了一个用于选择DES后继者的程序，最终导致了AES（高级加密标准）的采用。尽管如此，DES的一个增强版本——3DES（也称为Triple DES）在一段时间内仍被广泛使用。3DES通过连续使用三个56位密钥对数据进行三次DES加密，从而提高了加密强度。

### MD5 & SHA-1

MD5 (消息摘要算法5)：

类型：散列函数（或哈希函数）。
用途：用于生成数据（如文件或消息）的固定大小的散列值（或哈希值）。MD5主要用于确保数据完整性，验证数据是否被修改。它产生一个128位的哈希值，通常表示为32个十六进制字符。
密钥：MD5不使用密钥。它对输入数据生成一个固定长度的散列值，但这个过程不可逆，也就是说，从散列值无法恢复原始数据。

SHA-1 (安全哈希算法1)：

类型：散列函数。
用途：与MD5类似，SHA-1用于生成数据的散列值，以确保数据的完整性。SHA-1产生一个160位的哈希值，通常表示为40个十六进制字符。
密钥：SHA-1同样不使用密钥，并且也是不可逆的。

随着时间的推移，MD5和SHA-1由于其弱点而变得越来越不安全，不再推荐用于安全敏感的应用。相比之下，AES被认为是非常安全的加密标准。

在实际应用中，AES、MD5和SHA-1可以根据需要组合使用，例如，可以使用AES加密数据，同时使用SHA-1生成数据的散列值来验证数据的完整性。但重要的是要注意，MD5和SHA-1已经被认为是不安全的，推荐使用更安全的散列函数，如SHA-256。

### AES

AES（高级加密标准，Advanced Encryption Standard）是一种广泛使用的对称加密算法，用于安全地加密和解密信息。AES是在1997年由美国国家标准与技术研究院（NIST）发起的，旨在找到一种替代旧的数据加密标准（DES）的加密算法。经过公开的竞赛和评估后，2001年，一个名为Rijndael的算法被选为AES。

AES设计为具有高强度的安全性和快速的加密速度，同时能够高效地在各种硬件和软件平台上运行。它支持多种加密密钥长度：128位、192位和256位加密，这些数字代表加密密钥的长度。加密过程中，数据被分割成块（通常是128位大小的块），然后对每个块应用多轮加密操作。

AES的使用非常广泛，包括但不限于文件和文件夹加密、安全通信协议（如SSL/TLS用于安全的网页浏览）、无线网络安全（如WPA2）以及许多其他安全敏感的应用场合。

由于其强大的安全性和广泛的适用性，AES已成为当今世界上最重要的加密标准之一。

### AES 应用

``` ts
import crypto from 'crypto';

/**
 *
 * @param {*} data 数据
 * @param {*} key 秘钥
 * @param {*} iv 向量，相当于加盐
 */
export function encrypt(data: string, key: string, iv: string) {
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  cipher.update(data); // 把内容传给实例
  return cipher.final('hex'); // 把结果输出成16进制的字符串
}

export function decrypt(data: string, key: string, iv: string) {
  const cipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  cipher.update(data, 'hex'); // 加密是16进制，解密也需要16进制
  return cipher.final('utf8'); // 原来是utf-8
}
```

### 加密和加盐

在计算机安全领域，加密（Encryption）和加盐（Salting）是两种常见的数据保护方法。虽然它们的目的相同——保护数据不被未经授权的人访问或理解，但它们的应用场景、原理和方法有所不同。

加密
加密是一种通过使用算法（加密算法）和密钥将明文（原始数据）转换为密文（加密数据）的过程，以防止未经授权的访问。加密的数据只能通过使用相应的密钥进行解密后才能恢复到其原始格式。加密主要用于数据传输和存储的安全。

加密算法通常分为两类：

对称加密：加密和解密使用相同的密钥。例子有AES和DES。
非对称加密：加密和解密使用不同的密钥，通常称为公钥和私钥。例子有RSA和ECC。
加盐
加盐是一种增加密码或其他敏感数据保护强度的技术，通过在原始数据（如用户密码）中添加一个随机值（称为“盐”）来实现。这样，即使两个用户的原始密码相同，加盐后的结果也会不同，这增加了破解的难度。加盐通常与散列（Hashing）一起使用，以存储密码的散列值而不是实际的密码本身。

加盐的过程大致如下：

生成一个随机的盐值。
将盐值与原始数据（如密码）结合。
对结合后的数据进行散列处理。
将盐值和散列值一起存储。
当需要验证数据（如用户登录时的密码）时，系统将采取相同的盐值和散列过程来验证输入的数据是否与存储的散列值匹配。

加盐（Salting）主要是为了防止以下几种安全威胁和攻击方式：

彩虹表攻击（Rainbow Table Attack）：彩虹表是一种预先计算好的散列值对照表，包含了大量常用密码及其散列值。如果密码存储没有加盐，攻击者可以使用彩虹表来快速查找相应的密码。加盐通过向每个密码添加一个唯一的随机值来使得即使相同的密码也会产生不同的散列值，这样就大大增加了使用彩虹表攻击的难度和成本。

字典攻击和暴力攻击（Dictionary and Brute Force Attacks）：这些攻击方法试图通过尝试可能的密码组合来猜测密码。加盐使得每个散列值的计算都基于原始密码加上一个独特的盐值，即使是相同的密码，由于盐值的不同，也会导致不同的存储散列值。这意味着攻击者无法仅通过猜测原始密码来匹配散列值，因为他们还需要知道盐值。

避免密码重复性（Avoid Password Reuse）：在没有加盐的情况下，两个用户如果使用相同的密码，那么他们的密码散列值也会是相同的。这使得攻击者可以轻易地识别出使用相同密码的账户。加盐通过为每个密码添加一个唯一的盐值，即使是相同的密码，最终存储的散列值也会不同，从而避免了这种情况。

增加破解难度（Increase Cracking Difficulty）：即使攻击者能够获得到数据库中的散列值，加盐也使得他们必须对每个盐值和密码组合单独进行攻击，而不能一次性攻击所有账户。这极大地增加了破解密码所需的时间和资源。

总结来说，加盐是为了提高存储密码时的安全性，通过使每个用户的密码散列值唯一，来防止彩虹表攻击、字典攻击、暴力攻击，并减少密码重用的风险。这是一种有效的增加攻击成本和难度的方法，保护用户数据不被未授权访问。

加密与加盐的区别
目的：加密是为了保证数据的保密性，使数据只能被拥有密钥的人理解；而加盐主要是为了增强密码或其他敏感数据在存储时的安全性，使得即使在数据泄露的情况下，也不容易被破解。
逆向操作：加密是可逆的，意味着加密的数据可以被解密恢复原始数据；加盐与散列结合使用时，是不可逆的，即无法从散列值恢复原始数据。
应用场景：加密广泛应用于数据的传输和存储保护；加盐则主要用于增强存储在数据库中的密码或其他敏感数据的安全性。
