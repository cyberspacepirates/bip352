# Examples

## Instalation

```sh
npm install github:cyberspacepirates/bip352
```

## Encodes silent payment address

```js
import silentPayment from "bip352";
import { BIP32Factory } from "bip32";
import * as bip39 from "bip39";
import * as ecc from "tiny-secp256k1";
import { regtest as network } from "bitcoinjs-lib/src/networks";

const bip32 = BIP32Factory(ecc);

const mnemonics =
  "praise you muffin lion enable neck grocery crumble super myself license ghost";

const seed = bip39.mnemonicToSeedSync(mnemonics);
const root = BIP32.fromSeed(seed);

const spendKey = root.derivePath("m/352'/1'/0'/0'/0");

const scanKey = root.derivePath("m/352'/1'/0'/1'/0");

const silentAddress = silentPayment.encodeSilentPaymentAddress(
  scanKey.publicKey,
  spendKey.publicKey,
  network
);
```

## Decodes Silent payment address

```ts
silentPayment.decodeSilentPaymentAddress(
  "tsp1qqd5zuqlj4rl87h5ec6d0pzramrhxadfcc5h34p9kmu4md93e7we7xq3dm368e8w20kxe2xra8p8e50kheta6fjxz0lphl8rulqv600ck7cedn2h2",
  network
);
```

## Sending to Silent payment address

```ts
const inputs = [
  {
    txid: "403c9bfe07384b3c7e13ce3ca6693a30759608fa1873dc0c5cb37aa1d9ca4339",
    vout: 1,
    wif: "Kx4wVLQSSk53omXH693Kaj8VTjGwh9VLMHAVtsuf6T9oN6VoVU2Z", // m/84'/1'/0'/0/0
    utxoType: "p2wpkh",
    value: 100_000_000,
  },
  {
    txid: "9ff3f8c004905753525c5c325bde4550d5a0b0588320106e510b092258b5c12c",
    vout: 1,
    wif: "L3fbrH8EUAKyysn3xAMhMSawzCQVsyfegQbhWzRk3er6F5Y1FYgA", //  m/84'/1'/0'/0/1
    utxoType: "p2wpkh",
    value: 1_000_000,
  },
];

const output = [
  {
    address: silentAddress,
    value: 100_990_000,
  },
];

const silentOutput = silentPayment.createTransaction(inputs, output, {
  network,
});
```

## Scanning transaction

```ts
const scanning = scanTransaction(
  scanKey.privateKey!,
  spendKey.publicKey,
  inputs, // should omit the WIF ofc
  silentOutput,
  network
);
```

# Tweaks the scanning with spending key

```ts
let tweak = scanning.get(
  "022e3f118b5ccd6c47100912eb638d07a64ff307a2481f835cba79c0f24f6b7243"
);

let tweakedKey = ecc.privateAdd(spending.privateKey, tweak);
```
