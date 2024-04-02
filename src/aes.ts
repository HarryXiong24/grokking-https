import crypto from 'crypto';

/**
 *
 * @param {*} data 数据
 * @param {*} key 秘钥
 * @param {*} iv 向量，相当于加盐
 */
export function encrypt(data: string, key: string, iv: string) {
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  cipher.update(data); // 把内容传给实例
  return cipher.final('hex'); // 把结果输出成16进制的字符串
}

export function decrypt(data: string, key: string, iv: string) {
  const cipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  cipher.update(data, 'hex'); // 加密是16进制，解密也需要16进制
  return cipher.final('utf8'); // 原来是utf-8
}
