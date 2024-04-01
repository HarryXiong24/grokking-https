// symmetric-encryption

// encrypt key and decrypt key are the same
const secret = 3;

export function symmetricEncrypt(message: string): string {
  // convert message to buffer
  const buffer = Buffer.from(message);

  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = buffer[i] + secret;
  }

  return buffer.toString();
}

export function symmetricDecrypt(message: string): string {
  // convert message to buffer
  const buffer = Buffer.from(message);

  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = buffer[i] - secret;
  }

  return buffer.toString();
}
