import { AESTest } from './aes-test';
import { RSAApplicationTest } from './rsa-application-test';
import { RSATheoryTest } from './rsa-theory-test';
import { symmetricEncryptionTest } from './symmetric-encryption-test';

console.log('-------------------');
console.log('symmetricEncryptionTest');
symmetricEncryptionTest();
console.log('-------------------');
console.log('AESTest');
AESTest();
console.log('-------------------');
console.log('RSATheoryTest');
RSATheoryTest();
console.log('-------------------');
console.log('RSAApplicationTest');
RSAApplicationTest();
