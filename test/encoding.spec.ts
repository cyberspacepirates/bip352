import {
  createLabeledSilentPaymentAddress,
  decodeSilentPaymentAddress,
  encodeSilentPaymentAddress,
} from "../ts_src/encode";
import { Buffer } from "buffer";
import { unlabelled, labelled } from "./fixtures/encoding";
import { describe, it, expect } from "vitest";

describe("Encoding", () => {
  describe.each(unlabelled)("Encode/Decode SP", (data) => {
    it("should encode scan and spend key to silent payment address", () => {
      expect(
        encodeSilentPaymentAddress(
          Buffer.from(data.scanKey, "hex"),
          Buffer.from(data.spendKey, "hex")
        )
      ).toBe(data.address);
    });

    it("should decode scan and spend key from silent payment address", () => {
      expect(decodeSilentPaymentAddress(data.address)).toStrictEqual({
        scanKey: Buffer.from(data.scanKey, "hex"),
        spendKey: Buffer.from(data.spendKey, "hex"),
      });
    });
  });

  it.each(labelled)(
    "should create a labeled silent payment address",
    ({ scanPrivKey, spendPubKey, label, address }) => {
      expect(
        createLabeledSilentPaymentAddress(
          Buffer.from(scanPrivKey, "hex"),
          Buffer.from(spendPubKey, "hex"),
          label
        )
      ).toBe(address);
    }
  );
});
