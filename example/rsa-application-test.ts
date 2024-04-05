import { generateKeyPairSync, publicEncrypt, privateDecrypt } from 'crypto';

export function RSAApplicationTest() {
  // 生成一对秘钥：公钥 + 私钥
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
      passphrase: 'passphrase',
    },
  });

  const message = 'hello';
  console.log('original', message);

  // 公钥加密后的数据
  const encryptMessage = publicEncrypt(
    rsa.publicKey,
    Buffer.from(message, 'utf8')
  );

  console.log('privateEncrypt', encryptMessage);

  // 私钥解密后的数据
  const decryptedMessage = privateDecrypt(
    {
      key: rsa.privateKey,
      passphrase: 'passphrase',
    },
    encryptMessage
  );
  console.log('publicDecrypt', decryptedMessage.toString());
}
