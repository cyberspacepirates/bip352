import { Outpoint, PrivateKey } from "./interface";
import secp256k1 from "secp256k1";
import { Buffer } from "buffer";
import crypto from "crypto";

export const createInputHash = (
  sumOfInputPublicKeys: Buffer,
  outpoint: Outpoint
): Buffer => {
  return Buffer.from(
    createTaggedHash(
      "BIP0352/Inputs",
      Buffer.concat([
        Buffer.concat([
          Buffer.from(outpoint.txid, "hex").reverse(),
          serialiseUint32LE(outpoint.vout),
        ]),
        sumOfInputPublicKeys,
      ])
    )
  );
};

export function createTaggedHash(tag: string, data: Uint8Array): Uint8Array {
  const hash = crypto.createHash("sha256");
  const tagHash = hash.update(tag, "utf-8").digest();
  const ss = Buffer.concat([tagHash, tagHash, data]) as Uint8Array;
  return crypto.createHash("sha256").update(ss).digest();
}

export const calculateSumOfPrivateKeys = (keys: PrivateKey[]): Buffer => {
  const negatedKeys = keys.map((key) => {
    const privateKey = Buffer.from(key.key, "hex");
    if (
      key.isXOnly &&
      secp256k1.publicKeyCreate(privateKey, true)[0] === 0x03
    ) {
      return secp256k1.privateKeyNegate(privateKey);
    }
    return privateKey;
  });

  return Buffer.from(
    negatedKeys.slice(1).reduce((acc, key) => {
      return secp256k1.privateKeyTweakAdd(acc, key);
    }, negatedKeys[0])
  );
};

/**
 * Serializes a 32-bit unsigned integer i as a 4-byte big-endian
 * @param i {number} The number to serialize
 * @returns {Uint8Array} The serialized number
 * @private
 * */
export function _ser32(i: number): Uint8Array {
  const returnValue = new Uint8Array(4);
  returnValue[0] = (i >> 24) & 0xff;
  returnValue[1] = (i >> 16) & 0xff;
  returnValue[2] = (i >> 8) & 0xff;
  returnValue[3] = i & 0xff;
  return returnValue;
}

const serialiseUint32LE = (n: number): Buffer => {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(n);
  return buf;
};

export const readVarInt = (buffer: Buffer, offset: number = 0): number => {
  const first = buffer.readUInt8(offset);

  // 8 bit
  if (first < 0xfd) return first;
  // 16 bit
  else if (first === 0xfd) return buffer.readUInt16LE(offset + 1);
  // 32 bit
  else if (first === 0xfe) return buffer.readUInt32LE(offset + 1);
  // 64 bit
  else {
    const lo = buffer.readUInt32LE(offset + 1);
    const hi = buffer.readUInt32LE(offset + 5);
    return hi * 0x0100000000 + lo;
  }
};

export const encodingLength = (n: number) => {
  return n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9;
};

export const isPubKey = (testVector: Buffer): boolean => {
  return (
    (testVector.length == 33 || testVector.length == 65) &&
    secp256k1.publicKeyVerify(testVector)
  );
};
