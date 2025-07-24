export type UTXOType =
  | "p2wpkh"
  | "p2sh-p2wpkh"
  | "p2pkh"
  | "p2tr"
  | "non-eligible";

export type UTXO = {
  txid: string;
  vout: number;
  wif: string;
  utxoType: UTXOType;
  value?: number;
  witnessUtxo?: object;
};

export type Target = {
  address?: string; // either address or payment code
  value?: number;
};

export type SilentPaymentGroup = {
  Bscan: Uint8Array;
  BmValues: Array<[Uint8Array, number | undefined, number]>;
};

export type Outpoint = {
  txid: string;
  vout: number;
};

export type PrivateKey = {
  key: string;
  isXOnly: boolean;
};
