import { simpleHash } from '../src/simple-hash';

export function simpleHashTest() {
  console.log(simpleHash(1)); // 0001;
  console.log(simpleHash(234)); // 0234;
  console.log(simpleHash(1025)); // 0001;
}
