import crypto from 'crypto';

export function md5_sha256_Test() {
  const data = 'hello';
  // update(data + data) 等于 update(data).update(data)
  const md5Hash = crypto
    .createHash('md5')
    .update(data + data)
    .digest('hex'); // 把结果输出成16进制的字符串

  // 一个md5hash值长度为32位，不是很安全
  console.log('md5Hash', md5Hash, md5Hash.length);

  // 盐值，为了更加安全，不容易预测
  const salt = '666';
  // 把结果输出成16进制的字符串
  const sha256Hash = crypto
    .createHmac('sha256', salt)
    .update(data)
    .digest('hex');
  console.log('sha256Hash', sha256Hash, sha256Hash.length);
}
