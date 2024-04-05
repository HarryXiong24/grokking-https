export function simpleHash(num: number) {
  // padStart() 方法用另一个字符串填充当前字符串，以便产生的字符串达到给定的长度。填充从当前字符串的开始（左侧）应用。
  return ((num % 1024) + '').padStart(4, '0');
}
