import { AESTest } from './aes-test';
import { RSAApplicationTest } from './rsa-application-test';
import { RSATheoryTest } from './rsa-theory-test';
import { symmetricEncryptionTest } from './symmetric-encryption-test';
import { simpleHashTest } from './simple-hash-test';
import { md5_sha256_Test } from './md5-sha256-test';
import { signTest } from './sign-test';
import { certTest } from './cert';

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
console.log('-------------------');
console.log('simpleHashTest');
simpleHashTest();
console.log('-------------------');
console.log('md5Test');
md5_sha256_Test();
console.log('-------------------');
console.log('signTest');
signTest();
console.log('-------------------');
console.log('certTest');
certTest();
