import { ECPairFactory } from "ecpair";
import * as bitcoin from "bitcoinjs-lib";
import { UTXO, Target, SilentPaymentGroup } from "./interface";
import secp256k1 from "./noble_ecc";

import {
  compareUint8Arrays,
  concatUint8Arrays,
  hexToUint8Array,
  uint8ArrayToHex,
} from "uint8array-extras";

import { _ser32, createTaggedHash } from "./utility";
import { decodeSilentPaymentAddress, hrpFromNetwork } from "./encode";

const ECPair = ECPairFactory(secp256k1);
bitcoin.initEccLib(secp256k1);

export function createTransaction(
  utxos: UTXO[],
  targets: Target[],
  config: { network: bitcoin.Network } = { network: bitcoin.networks.bitcoin }
): Target[] {
  const ret: Target[] = new Array(targets.length);

  const silentPaymentGroups: Array<SilentPaymentGroup> = [];
  for (let i = 0; i < targets.length; i++) {
    const target = targets[i];

    const prefix = hrpFromNetwork(config.network);

    if (!target.address?.startsWith(prefix)) {
      ret[i] = target; // passthrough
      continue;
    }

    const { scanKey: Bscan, spendKey: Bm } = decodeSilentPaymentAddress(
      target.address,
      config.network
    );

    // Addresses with the same Bscan key all belong to the same recipient
    const recipient = silentPaymentGroups.find(
      (group) => compareUint8Arrays(group.Bscan, Bscan) === 0
    );
    if (recipient) {
      recipient.BmValues.push([Bm, target.value, i]);
    } else {
      silentPaymentGroups.push({
        Bscan: Bscan,
        BmValues: [[Bm, target.value, i]],
      });
    }
  }
  if (silentPaymentGroups.length === 0) return ret; // passthrough

  const a = _sumPrivkeys(utxos);

  // Get X and Y coordinate, public key, form the private key a
  const A = new Uint8Array(secp256k1.pointFromScalar(a, true)!);
  const outpoint_hash = _outpointsHash(utxos, A);

  // Bscan * a * outpoint_hash
  const ecdh_shared_secret_step1 = new Uint8Array(
    secp256k1.privateMultiply(a, outpoint_hash)!
  );

  // Generating Pmk for each Bm in the group
  for (const group of silentPaymentGroups) {
    const ecdh_shared_secret = new Uint8Array(
      secp256k1.getSharedSecret(
        ecdh_shared_secret_step1 as Uint8Array,
        group.Bscan as Uint8Array,
        true
      ) as Uint8Array
    );
    let k = 0;
    for (const [Bm, amount, i] of group.BmValues) {
      const tk = createTaggedHash(
        "BIP0352/SharedSecret",
        concatUint8Arrays([ecdh_shared_secret, _ser32(k)])
      );

      // Let Pmk = tk·G + Bm
      const Pmk = new Uint8Array(
        secp256k1.pointAdd(
          Bm,
          secp256k1.pointFromScalar(tk, true)!,
          true
        ) as Uint8Array
      );

      // Encode Pmk as a BIP341 taproot output
      const address = pubkeyToAddress(
        uint8ArrayToHex(Pmk.slice(1)),
        config.network
      );
      const newTarget: Target = { address };
      newTarget.value = amount;
      ret[i] = newTarget;
      k = k + 1;
    }
  }
  return ret;
}
export function getSmallestOuput(parameters: UTXO[]) {
  const outpoints: Array<Uint8Array> = [];
  for (const parameter of parameters) {
    const txidBuffer = hexToUint8Array(parameter.txid).reverse();
    const voutBuffer = new Uint8Array(_ser32(parameter.vout).reverse());
    outpoints.push(concatUint8Arrays([txidBuffer, voutBuffer]));
  }
  outpoints.sort((a, b) => compareUint8Arrays(a, b));
  const smallest_outpoint = outpoints[0];
  return smallest_outpoint;
}

export function _outpointsHash(parameters: UTXO[], A: Uint8Array): Uint8Array {
  const smallest_outpoint = getSmallestOuput(parameters);

  return createTaggedHash(
    "BIP0352/Inputs",
    concatUint8Arrays([smallest_outpoint, A])
  );
}

/**
 * Sums the private keys of the UTXOs
 * @param utxos {UTXO[]}
 * @returns {Uint8Array} The sum of the private keys
 * @private
 **/
function _sumPrivkeys(utxos: UTXO[]): Uint8Array {
  if (utxos.length === 0) {
    throw new Error("No UTXOs provided");
  }

  const keys: Array<Uint8Array> = [];
  for (const utxo of utxos) {
    let key = ECPair.fromWIF(utxo.wif).privateKey as Uint8Array;
    switch (utxo.utxoType) {
      case "non-eligible":
        // Non-eligible UTXOs can be spent in the transaction, but are not used for the
        // shared secret derivation. Note: we don't check that the private key is valid
        // for non-eligible utxos because its possible the sender is following a different
        // signing protocol for these utxos. For silent payments eligible utxos, we require
        // access to the private key.
        break;
      case "p2tr":
        if (key === undefined) {
          throw new Error("No private key found for eligible UTXO");
        }

        // For taproot, check if the seckey results in an odd y-value and negate if so
        if (secp256k1.pointFromScalar(key, true)![0] === 0x03) {
          key = new Uint8Array(secp256k1.privateNegate(key)) as Uint8Array;
        }
      case "p2wpkh":
      case "p2sh-p2wpkh":
      case "p2pkh":
        if (key === undefined) {
          throw new Error("No private key found for eligible UTXO");
        }
        keys.push(key);
        break;
    }
  }

  if (keys.length === 0) {
    throw new Error("No eligible UTXOs with private keys found");
  }

  // summary of every item in array
  const ret = keys.reduce((acc, key) => {
    return new Uint8Array(secp256k1.privateAdd(acc, key) as Uint8Array);
  });

  return ret;
}

export function pubkeyToAddress(
  hex: string,
  network = bitcoin.networks.bitcoin
): string {
  const publicKey = hexToUint8Array("5120" + hex);
  return bitcoin.address.fromOutputScript(Buffer.from(publicKey), network);
}

export function addressToPubkey(
  address: string,
  network = bitcoin.networks.bitcoin
): string {
  return uint8ArrayToHex(
    bitcoin.address.toOutputScript(address, network).subarray(2)
  );
}
