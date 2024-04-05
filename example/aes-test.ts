import { AESEncrypt, AESDecrypt } from '../src/aes';

export function AESTest() {
  const message = 'abc';
  const key = '1234567890123456';
  const iv = '6543210987654321';

  console.log('original', message);

  const data = AESEncrypt(message, key, iv);
  console.log('encrypt', data);

  const decryptData = AESDecrypt(data, key, iv);
  console.log('decrypt', decryptData);
}
