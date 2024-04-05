import { generateKeyPairSync, createSign, createVerify } from 'crypto';

/**
 * 数字签名和数字证书的过程
 * 1、先拿到文件file
 * 2、用 publicKey 计算签名 sign
 * 3、如果跟对方的 sign 匹配，验证通过
 */
export function signTest() {
  const rsa = generateKeyPairSync('rsa', {
    modulusLength: 1024,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: 'passphrase', // 私钥的密码
    },
  });

  const file = 'file';
  // 创建签名对象
  const signObj = createSign('RSA-SHA256');
  // 放入内容
  signObj.update(file);
  // 用rsa私钥签名，输出一个16进制的字符串
  const sign = signObj.sign({
    key: rsa.privateKey,
    format: 'pem',
    passphrase: 'passphrase',
  });

  console.log(sign);

  // 创建验证签名对象
  const verifyObj = createVerify('RSA-SHA256');
  // 放入文件内容
  verifyObj.update(file);
  // 验证签名是否合法
  const isValid = verifyObj.verify(rsa.publicKey, sign);

  console.log(isValid);
}
