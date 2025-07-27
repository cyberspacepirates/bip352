import { _ser32, createTaggedHash } from "./utility";
import { LabelMap } from "./interface";
import secp256k1 from "./noble_ecc";
import { Buffer } from "buffer";
import { _outpointsHash } from "./output";

// Handle additional label-related logic
const handleLabels = (
  output: Buffer,
  tweakedPublicKey: Uint8Array,
  tweak: Buffer,
  labels: LabelMap
): Uint8Array | null => {
  const negatedPublicKey = secp256k1.publicKeyNegate(tweakedPublicKey, true);

  let mG = secp256k1.pointAdd(output, negatedPublicKey, true);

  let labelHex = labels[Buffer.from(mG!).toString("hex")];
  if (!labelHex) {
    mG = secp256k1.pointAdd(
      secp256k1.publicKeyNegate(output, true),
      negatedPublicKey,
      true
    );
    labelHex = labels[Buffer.from(mG!).toString("hex")];
  }

  if (labelHex) {
    return secp256k1.privateAdd(tweak, Buffer.from(labelHex, "hex"));
  }

  return null;
};

const processTweak = (
  spendPublicKey: Buffer,
  tweak: Buffer,
  outputs: Buffer[],
  matches: Map<string, Buffer>,
  labels?: LabelMap
): number => {
  const tweakedPublicKey = secp256k1.pointAddScalar(
    spendPublicKey,
    tweak,
    true
  );
  //const tweakedPublicKey = ecc.publicKeyTweakAdd(spendPublicKey, tweak, true);

  for (let i = 0; i < outputs.length; i++) {
    const output = outputs[i];

    if (output.subarray(1).equals(tweakedPublicKey!.subarray(1))) {
      matches.set(output.toString("hex"), tweak);
      outputs.splice(i, 1);
      return 1; // Increment counter
    } else if (labels) {
      // Additional logic if labels are provided
      const privateKeyTweak = handleLabels(
        output,
        tweakedPublicKey!,
        tweak,
        labels
      );
      if (privateKeyTweak) {
        matches.set(output.toString("hex"), Buffer.from(privateKeyTweak));
        return 1; // Increment counter
      }
    }
  }

  return 0; // No counter increment
};

export function scanOutputsUsingSecret(
  ecdhSecret: Uint8Array,
  spendPublicKey: Buffer,
  outputs: Buffer[],
  labels?: LabelMap
): Map<string, Buffer> {
  const matches = new Map<string, Buffer>();
  let n = 0;
  let counterIncrement = 0;
  do {
    const tweak = createTaggedHash(
      "BIP0352/SharedSecret",
      Buffer.concat([ecdhSecret, _ser32(n)])
    );
    counterIncrement = processTweak(
      spendPublicKey,
      tweak as Buffer,
      outputs,
      matches,
      labels
    );
    n += counterIncrement;
  } while (counterIncrement > 0 && outputs.length > 0);

  return matches;
}

type TransactionInput = {
  publicKey: Buffer;
  txid: string;
  vout: number;
  wif: null;
};

export const scanTransaction = (
  scanPrivateKey: Buffer,
  spendPublicKey: Buffer,
  inputs: TransactionInput[],
  outputs: Buffer[],
  labels?: LabelMap
) => {
  let publicKeySum = null;
  for (let i = 0; i < inputs.length; i++) {
    if (i == 0) {
      publicKeySum = inputs[0].publicKey;
      continue;
    }
    publicKeySum = secp256k1.pointAdd(publicKeySum!, inputs[i].publicKey!);
  }
  //@ts-ignore
  const inputHash = _outpointsHash(inputs, publicKeySum);

  console.log(
    Buffer.from(inputHash).toString("hex"),
    Buffer.from(publicKeySum!).toString("hex")
  );
  return scanOutputs(
    scanPrivateKey,
    spendPublicKey,
    publicKeySum as Buffer,
    inputHash as Buffer,
    outputs,
    labels
  );
};

export const scanOutputs = (
  scanPrivateKey: Buffer,
  spendPublicKey: Buffer,
  sumOfInputPublicKeys: Buffer,
  inputHash: Buffer,
  outputs: Buffer[],
  labels?: LabelMap
): Map<string, Buffer> => {
  const ecdhSecret = secp256k1.getSharedSecret(
    secp256k1.privateMultiply(scanPrivateKey, inputHash)!,
    sumOfInputPublicKeys,
    true
  );

  return scanOutputsUsingSecret(ecdhSecret, spendPublicKey, outputs, labels);
};

export const scanOutputsWithTweak = (
  scanPrivateKey: Buffer,
  spendPublicKey: Buffer,
  scanTweak: Buffer,
  outputs: Buffer[],
  labels?: LabelMap
): Map<string, Buffer> => {
  if (scanTweak.length === 33) {
    // Use publicKeyTweakMul for compressed pubkey
    const ecdhSecret = secp256k1.pointMultiply(scanTweak, scanPrivateKey, true);
    return scanOutputsUsingSecret(ecdhSecret!, spendPublicKey, outputs, labels);
  } else {
    throw new Error(
      `Expected scanTweak to be either 33-byte compressed public key, got ${scanTweak.length}`
    );
  }
};
