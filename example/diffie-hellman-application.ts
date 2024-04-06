import { createDiffieHellman } from 'crypto';

export function diffieHellmanApplication() {
  // 客户端
  const client = createDiffieHellman(512); // 512字节
  // 生成一个秘钥对
  const clientKeys = client.generateKeys();
  // 生成一个质数
  const prime = client.getPrime();
  const generator = client.getGenerator();

  // 服务器端
  const server = createDiffieHellman(prime as unknown as number, generator);
  // 生成一个秘钥对
  const serverKeys = server.generateKeys();

  // 双方生成秘钥
  let client_secret = client.computeSecret(serverKeys);
  let server_secret = server.computeSecret(clientKeys);

  console.log('client_secret', client_secret.toString('hex'));
  console.log('server_secret', server_secret.toString('hex'));
}
