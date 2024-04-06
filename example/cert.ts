import { generateKeyPairSync, createHash } from 'crypto';
import { getSign, verifySign } from '../src/cert';

/**
 * 实现数字证书的原理
 */
export function certTest() {
  // 服务器生成的公钥和私钥
  const serverRSA = generateKeyPairSync('rsa', {
    modulusLength: 1024,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem', // base64格式的私钥
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: 'passphrase', // 私钥的密码, 提高窃取成本
    },
  });

  // CA 的公钥和私钥
  const caRSA = generateKeyPairSync('rsa', {
    modulusLength: 1024,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem', // base64格式的私钥
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: 'passphrase', // 私钥的密码, 提高窃取成本
    },
  });

  // 网站的信息
  const info = {
    domain: 'http://127.0.0.1:8080',
    publicKey: serverRSA.publicKey,
  };

  // 把申请信息发给CA机构请求颁发证书
  // 真正实现的时候，签名的不是info，而是它的hash
  // 签名算法性能很差，一般不能计算大量的数据
  const hash = createHash('sha256').update(JSON.stringify(info)).digest('hex'); // hex生成16进制的一个字符串

  // 使用CA的私钥进行签名
  const sign = getSign(hash, caRSA.privateKey, 'passphrase');

  // 证书
  const cert = {
    info,
    hash,
    sign, // CA的签名
  };

  // 验证证书合法性
  const isValid = verifySign(cert.hash, cert.sign, caRSA.publicKey);
  console.log('验证证书合法性', isValid);

  // 拿到服务器的公钥 serverPublicKey，可进行加密数据传输
  const serverPublicKey = cert.info.publicKey;
}
