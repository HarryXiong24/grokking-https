import {
  symmetricDecrypt,
  symmetricEncrypt,
} from '../src/symmetric-encryption';

export function symmetricEncryptionTest() {
  const message = 'abc';
  console.log('original message:', message);

  const encrypt_res = symmetricEncrypt(message);
  console.log('encrypt message:', encrypt_res);

  const decrypt_res = symmetricDecrypt(encrypt_res);
  console.log('decrypt message:', decrypt_res);
}
