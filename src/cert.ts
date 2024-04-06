import { createSign, createVerify } from 'crypto';

// 获取签名
export function getSign(
  content: string,
  privateKey: string,
  passphrase: string
) {
  // 创建签名对象
  var signObj = createSign('RSA-SHA256');
  // 放入内容
  signObj.update(content);
  // 签名算法
  return signObj.sign(
    {
      key: privateKey,
      format: 'pem',
      passphrase,
    },
    'hex'
  );
}

// 验证签名
export function verifySign(content: string, sign: string, publicKey: string) {
  const verifyObj = createVerify('RSA-SHA256');
  verifyObj.update(content);
  return verifyObj.verify(publicKey, sign, 'hex');
}
