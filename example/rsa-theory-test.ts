import { RSADecrypt, RSAEncrypt } from '../src/rsa-theory';

export function RSATheoryTest() {
  const data = 5;
  console.log('original', data);

  // 加密
  const secret = RSAEncrypt(data);
  console.log('RSAEncrypt', secret);

  // 解密
  const originData = RSADecrypt(secret);
  console.log('RSADecrypt', originData);
}
