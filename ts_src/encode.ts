import { bech32m } from "bech32";
import secp256k1 from "./noble_ecc";
import { Buffer } from "buffer";
import { Network } from "bitcoinjs-lib";
import { bitcoin } from "bitcoinjs-lib/src/networks";
import { _ser32, createTaggedHash } from "./utility";

export const encodeSilentPaymentAddress = (
  scanPubKey: Uint8Array,
  spendPubKey: Uint8Array,
  network: Network = bitcoin,
  version: number = 0
): string => {
  if (scanPubKey.length !== 33 && spendPubKey.length !== 33) {
    throw new Error(
      "Expected length of scanPubkey and spendPubKey must to be 33 bytes"
    );
  }

  const data = bech32m.toWords(Buffer.concat([scanPubKey, spendPubKey]));
  data.unshift(version);
  // the character limit is 1023 character due to the recommendation for future updates
  // it should work fine with just 117 characters
  return bech32m.encode(hrpFromNetwork(network), data, 1023);
};

export const decodeSilentPaymentAddress = (
  address: string,
  network: Network = bitcoin
): { scanKey: Buffer; spendKey: Buffer } => {
  const { prefix, words } = bech32m.decode(address, 1023);
  if (prefix != hrpFromNetwork(network)) throw new Error("Invalid prefix!");

  const version = words.shift();
  if (version != 0) throw new Error("Invalid version!");

  const key = Buffer.from(bech32m.fromWords(words));

  return {
    scanKey: key.slice(0, 33),
    spendKey: key.slice(33),
  };
};

export const createLabeledSilentPaymentAddress = (
  scanPrivKey: Uint8Array,
  spendPubKey: Uint8Array,
  m: number,
  network: Network = bitcoin,
  version: number = 0
) => {
  const label = createTaggedHash(
    "BIP0352/Label",
    Buffer.concat([scanPrivKey, _ser32(m)])
  );
  const scanPubKey = secp256k1.pointFromScalar(scanPrivKey);
  const tweakedSpendPubKey = secp256k1.pointAddScalar(spendPubKey, label, true);

  return encodeSilentPaymentAddress(
    scanPubKey!,
    tweakedSpendPubKey!,
    network,
    version
  );
};

export const hrpFromNetwork = (network: Network): string => {
  return network.bech32 === "bc" ? "sp" : "tsp";
};

export function isPaymentCodeValid(pc: string) {
  try {
    const result = bech32m.decode(pc, 118);
    const version = result.words.shift();

    // if the version is 0, returns true, else false
    return version === 0;
  } catch (_) {
    return false;
  }
}
