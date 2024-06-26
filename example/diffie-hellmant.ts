export function diffieHellmanTest() {
  const N = 23; // 公共
  const p = 5;
  const secret1 = 6;

  const A = Math.pow(p, secret1) % N;
  console.log(`p=${p}; N=${N}; A=${A};`);

  const secret2 = 15;
  const B = Math.pow(p, secret2) % N;
  console.log(`p=${p}; N=${N}; B=${B};`);

  // A将A、p、N给B
  // B计算后将B给A
  // 这样A拥有，A、B、p、N、secret1
  // 这样B拥有，A、B、p、N、secret2

  // A这样计算的
  console.log(Math.pow(B, secret1) % N);
  // B这样计算的
  console.log(Math.pow(A, secret2) % N);
}
