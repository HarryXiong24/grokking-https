// 两个大质数，这里为了便于理解，选择小的，实际是1024位或者2048位的大质数
const p = 3;
const q = 11;
const N = p * q; // 数学上无法实现根据 N 求出 p 和 q
const r = (p - 1) * (q - 1); // 欧拉公式
const e = 7; // 挑选一个指数

// 秘钥是怎么来的，其中的一个算法
let d = 1;
while ((e * d) % r !== 1) {
  d++;
}
// console.log('求出私钥中的d', d); // 3

// 公钥 + 私钥
const publicKey = { e, N };
const privateKey = { d, N };

// 加密方法
export function RSAEncrypt(data: number) {
  return Math.pow(data, publicKey.e) % publicKey.N;
}

// 解密方法
export function RSADecrypt(data: number) {
  return Math.pow(data, privateKey.d) % privateKey.N;
}
