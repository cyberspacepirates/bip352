export default [
  {
    comment: "Simple send: two inputs",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac",
                },
              },
              private_key:
                "93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac",
                },
              },
            },
          ],
          outputs: [
            "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "f438b40179a3c4262de12986c0e6cce0634007cdc79c1dcd3e20b9ebc2e7eef6",
              pub_key:
                "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1",
              signature:
                "74f85b856337fbe837643b86f462118159f93ac4acc2671522f27e8f67b079959195ccc7a5dbee396d2909f5d680d6e30cda7359aa2755822509b70d6b0687a1",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Simple send: two inputs, order reversed",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac",
                },
              },
              private_key:
                "93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac",
                },
              },
            },
          ],
          outputs: [
            "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "f438b40179a3c4262de12986c0e6cce0634007cdc79c1dcd3e20b9ebc2e7eef6",
              pub_key:
                "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1",
              signature:
                "74f85b856337fbe837643b86f462118159f93ac4acc2671522f27e8f67b079959195ccc7a5dbee396d2909f5d680d6e30cda7359aa2755822509b70d6b0687a1",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Simple send: two inputs from the same transaction",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 3,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 7,
              scriptSig:
                "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac",
                },
              },
              private_key:
                "93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "79e71baa2ba3fc66396de3a04f168c7bf24d6870ec88ca877754790c1db357b6",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 3,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 7,
              scriptSig:
                "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac",
                },
              },
            },
          ],
          outputs: [
            "79e71baa2ba3fc66396de3a04f168c7bf24d6870ec88ca877754790c1db357b6",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "4851455bfbe1ab4f80156570aa45063201aa5c9e1b1dcd29f0f8c33d10bf77ae",
              pub_key:
                "79e71baa2ba3fc66396de3a04f168c7bf24d6870ec88ca877754790c1db357b6",
              signature:
                "10332eea808b6a13f70059a8a73195808db782012907f5ba32b6eae66a2f66b4f65147e2b968a1678c5f73d57d5d195dbaf667b606ff80c8490eac1f3b710657",
            },
          ],
        },
      },
    ],
  },
  {
    comment:
      "Simple send: two inputs from the same transaction, order reversed",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 7,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 3,
              scriptSig:
                "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac",
                },
              },
              private_key:
                "93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "f4c2da807f89cb1501f1a77322a895acfb93c28e08ed2724d2beb8e44539ba38",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 7,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 3,
              scriptSig:
                "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac",
                },
              },
            },
          ],
          outputs: [
            "f4c2da807f89cb1501f1a77322a895acfb93c28e08ed2724d2beb8e44539ba38",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "ab0c9b87181bf527879f48db9f14a02233619b986f8e8f2d5d408ce68a709f51",
              pub_key:
                "f4c2da807f89cb1501f1a77322a895acfb93c28e08ed2724d2beb8e44539ba38",
              signature:
                "398a9790865791a9db41a8015afad3a47d60fec5086c50557806a49a1bc038808632b8fe679a7bb65fc6b455be994502eed849f1da3729cd948fc7be73d67295",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Outpoint ordering byte-lexicographically vs. vout-integer",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 1,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 256,
              scriptSig:
                "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac",
                },
              },
              private_key:
                "93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "a85ef8701394b517a4b35217c4bd37ac01ebeed4b008f8d0879f9e09ba95319c",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 1,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 256,
              scriptSig:
                "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac",
                },
              },
            },
          ],
          outputs: [
            "a85ef8701394b517a4b35217c4bd37ac01ebeed4b008f8d0879f9e09ba95319c",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "c8ac0292997b5bca98b3ebd99a57e253071137550f270452cd3df8a3e2266d36",
              pub_key:
                "a85ef8701394b517a4b35217c4bd37ac01ebeed4b008f8d0879f9e09ba95319c",
              signature:
                "c036ee38bfe46aba03234339ae7219b31b824b52ef9d5ce05810a0d6f62330dedc2b55652578aa5bdabf930fae941acd839d5a66f8fce7caa9710ccb446bddd1",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Single recipient: multiple UTXOs from the same public key",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "548ae55c8eec1e736e8d3e520f011f1f42a56d166116ad210b3937599f87f566",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
          ],
          outputs: [
            "548ae55c8eec1e736e8d3e520f011f1f42a56d166116ad210b3937599f87f566",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "f032695e2636619efa523fffaa9ef93c8802299181fd0461913c1b8daf9784cd",
              pub_key:
                "548ae55c8eec1e736e8d3e520f011f1f42a56d166116ad210b3937599f87f566",
              signature:
                "f238386c5d5e5444f8d2c75aabbcb28c346f208c76f60823f5de3b67b79e0ec72ea5de2d7caec314e0971d3454f122dda342b3eede01b3857e83654e36b25f76",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Single recipient: taproot only inputs with even y-values",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b",
              prevout: {
                scriptPubKey: {
                  hex: "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0140bd1e708f92dbeaf24a6b8dd22e59c6274355424d62baea976b449e220fd75b13578e262ab11b7aa58e037f0c6b0519b66803b7d9decaa1906dedebfb531c56c1",
              prevout: {
                scriptPubKey: {
                  hex: "5120782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
                },
              },
              private_key:
                "fc8716a97a48ba9a05a98ae47b5cd201a25a7fd5d8b73c203c5f7b6b6b3b6ad7",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b",
              prevout: {
                scriptPubKey: {
                  hex: "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0140bd1e708f92dbeaf24a6b8dd22e59c6274355424d62baea976b449e220fd75b13578e262ab11b7aa58e037f0c6b0519b66803b7d9decaa1906dedebfb531c56c1",
              prevout: {
                scriptPubKey: {
                  hex: "5120782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
                },
              },
            },
          ],
          outputs: [
            "de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "3fb9ce5ce1746ced103c8ed254e81f6690764637ddbc876ec1f9b3ddab776b03",
              pub_key:
                "de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb",
              signature:
                "c5acd25a8f021a4192f93bc34403fd8b76484613466336fb259c72d04c169824f2690ca34e96cee86b69f376c8377003268fda56feeb1b873e5783d7e19bcca5",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Single recipient: taproot only with mixed even/odd y-values",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b",
              prevout: {
                scriptPubKey: {
                  hex: "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "01400a4d0dca6293f40499394d7eefe14a1de11e0e3454f51de2e802592abf5ee549042a1b1a8fb2e149ee9dd3f086c1b69b2f182565ab6ecf599b1ec9ebadfda6c5",
              prevout: {
                scriptPubKey: {
                  hex: "51208c8d23d4764feffcd5e72e380802540fa0f88e3d62ad5e0b47955f74d7b283c4",
                },
              },
              private_key:
                "1d37787c2b7116ee983e9f9c13269df29091b391c04db94239e0d2bc2182c3bf",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "77cab7dd12b10259ee82c6ea4b509774e33e7078e7138f568092241bf26b99f1",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b",
              prevout: {
                scriptPubKey: {
                  hex: "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "01400a4d0dca6293f40499394d7eefe14a1de11e0e3454f51de2e802592abf5ee549042a1b1a8fb2e149ee9dd3f086c1b69b2f182565ab6ecf599b1ec9ebadfda6c5",
              prevout: {
                scriptPubKey: {
                  hex: "51208c8d23d4764feffcd5e72e380802540fa0f88e3d62ad5e0b47955f74d7b283c4",
                },
              },
            },
          ],
          outputs: [
            "77cab7dd12b10259ee82c6ea4b509774e33e7078e7138f568092241bf26b99f1",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "f5382508609771068ed079b24e1f72e4a17ee6d1c979066bf1d4e2a5676f09d4",
              pub_key:
                "77cab7dd12b10259ee82c6ea4b509774e33e7078e7138f568092241bf26b99f1",
              signature:
                "ff65833b8fd1ed3ef9d0443b4f702b45a3f2dd457ba247687e8207745c3be9d2bdad0ab3f07118f8b2efc6a04b95f7b3e218daf8a64137ec91bd2fc67fc137a5",
            },
          ],
        },
      },
    ],
  },
  {
    comment:
      "Single recipient: taproot input with even y-value and non-taproot input",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b",
              prevout: {
                scriptPubKey: {
                  hex: "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "463044021f24e010c6e475814740ba24c8cf9362c4db1276b7f46a7b1e63473159a80ec30221008198e8ece7b7f88e6c6cc6bb8c86f9f00b7458222a8c91addf6e1577bcf7697e2103e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9148cbc7dfe44f1579bff3340bbef1eddeaeb1fc97788ac",
                },
              },
              private_key:
                "8d4751f6e8a3586880fb66c19ae277969bd5aa06f61c4ee2f1e2486efdf666d3",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "30523cca96b2a9ae3c98beb5e60f7d190ec5bc79b2d11a0b2d4d09a608c448f0",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b",
              prevout: {
                scriptPubKey: {
                  hex: "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "463044021f24e010c6e475814740ba24c8cf9362c4db1276b7f46a7b1e63473159a80ec30221008198e8ece7b7f88e6c6cc6bb8c86f9f00b7458222a8c91addf6e1577bcf7697e2103e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9148cbc7dfe44f1579bff3340bbef1eddeaeb1fc97788ac",
                },
              },
            },
          ],
          outputs: [
            "30523cca96b2a9ae3c98beb5e60f7d190ec5bc79b2d11a0b2d4d09a608c448f0",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "b40017865c79b1fcbed68896791be93186d08f47e416b289b8c063777e14e8df",
              pub_key:
                "30523cca96b2a9ae3c98beb5e60f7d190ec5bc79b2d11a0b2d4d09a608c448f0",
              signature:
                "d1edeea28cf1033bcb3d89376cabaaaa2886cbd8fda112b5c61cc90a4e7f1878bdd62180b07d1dfc8ffee1863c525a0c7b5bcd413183282cfda756cb65787266",
            },
          ],
        },
      },
    ],
  },
  {
    comment:
      "Single recipient: taproot input with odd y-value and non-taproot input",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "01400a4d0dca6293f40499394d7eefe14a1de11e0e3454f51de2e802592abf5ee549042a1b1a8fb2e149ee9dd3f086c1b69b2f182565ab6ecf599b1ec9ebadfda6c5",
              prevout: {
                scriptPubKey: {
                  hex: "51208c8d23d4764feffcd5e72e380802540fa0f88e3d62ad5e0b47955f74d7b283c4",
                },
              },
              private_key:
                "1d37787c2b7116ee983e9f9c13269df29091b391c04db94239e0d2bc2182c3bf",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "463044021f24e010c6e475814740ba24c8cf9362c4db1276b7f46a7b1e63473159a80ec30221008198e8ece7b7f88e6c6cc6bb8c86f9f00b7458222a8c91addf6e1577bcf7697e2103e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9148cbc7dfe44f1579bff3340bbef1eddeaeb1fc97788ac",
                },
              },
              private_key:
                "8d4751f6e8a3586880fb66c19ae277969bd5aa06f61c4ee2f1e2486efdf666d3",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "359358f59ee9e9eec3f00bdf4882570fd5c182e451aa2650b788544aff012a3a",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "01400a4d0dca6293f40499394d7eefe14a1de11e0e3454f51de2e802592abf5ee549042a1b1a8fb2e149ee9dd3f086c1b69b2f182565ab6ecf599b1ec9ebadfda6c5",
              prevout: {
                scriptPubKey: {
                  hex: "51208c8d23d4764feffcd5e72e380802540fa0f88e3d62ad5e0b47955f74d7b283c4",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "463044021f24e010c6e475814740ba24c8cf9362c4db1276b7f46a7b1e63473159a80ec30221008198e8ece7b7f88e6c6cc6bb8c86f9f00b7458222a8c91addf6e1577bcf7697e2103e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9148cbc7dfe44f1579bff3340bbef1eddeaeb1fc97788ac",
                },
              },
            },
          ],
          outputs: [
            "359358f59ee9e9eec3f00bdf4882570fd5c182e451aa2650b788544aff012a3a",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "a2f9dd05d1d398347c885d9c61a64d18a264de6d49cea4326bafc2791d627fa7",
              pub_key:
                "359358f59ee9e9eec3f00bdf4882570fd5c182e451aa2650b788544aff012a3a",
              signature:
                "96038ad233d8befe342573a6e54828d863471fb2afbad575cc65271a2a649480ea14912b6abbd3fbf92efc1928c036f6e3eef927105af4ec1dd57cb909f360b8",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Multiple outputs: multiple outputs, same recipient",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "e976a58fbd38aeb4e6093d4df02e9c1de0c4513ae0c588cef68cda5b2f8834ca",
              "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
            },
          ],
          outputs: [
            "e976a58fbd38aeb4e6093d4df02e9c1de0c4513ae0c588cef68cda5b2f8834ca",
            "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "d97e442d110c0bdd31161a7bb6e7862e038d02a09b1484dfbb463f2e0f7c9230",
              pub_key:
                "e976a58fbd38aeb4e6093d4df02e9c1de0c4513ae0c588cef68cda5b2f8834ca",
              signature:
                "29bd25d0f808d7fcd2aa6d5ed206053899198397506c301b218a9e47a3d7070af03e903ff718978d50d1b6b9af8cc0e313d84eda5d5b1e8e85e5516d630bbeb9",
            },
            {
              priv_key_tweak:
                "33ce085c3c11eaad13694aae3c20301a6c83382ec89a7cde96c6799e2f88805a",
              pub_key:
                "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
              signature:
                "335667ca6cae7a26438f5cfdd73b3d48fa832fa9768521d7d5445f22c203ab0d74ed85088f27d29959ba627a4509996676f47df8ff284d292567b1beef0e3912",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Multiple outputs: multiple outputs, multiple recipients",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            "sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn",
            "sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn",
          ],
        },
        expected: {
          outputs: [
            [
              "2e847bb01d1b491da512ddd760b8509617ee38057003d6115d00ba562451323a",
              "841792c33c9dc6193e76744134125d40add8f2f4a96475f28ba150be032d64e8",
              "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
            },
          ],
          outputs: [
            "2e847bb01d1b491da512ddd760b8509617ee38057003d6115d00ba562451323a",
            "841792c33c9dc6193e76744134125d40add8f2f4a96475f28ba150be032d64e8",
            "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
          ],
          key_material: {
            spend_priv_key:
              "9902c3c56e84002a7cd410113a9ab21d142be7f53cf5200720bb01314c5eb920",
            scan_priv_key:
              "060b751d7892149006ed7b98606955a29fe284a1e900070c0971f5fb93dbf422",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn",
          ],
          outputs: [
            {
              priv_key_tweak:
                "72cd082cccb633bf85240a83494b32dc943a4d05647a6686d23ad4ca59c0ebe4",
              pub_key:
                "2e847bb01d1b491da512ddd760b8509617ee38057003d6115d00ba562451323a",
              signature:
                "38745f3d9f5eef0b1cfb17ca314efa8c521efab28a23aa20ec5e3abb561d42804d539906dce60c4ee7977966184e6f2cab1faa0e5377ceb7148ec5218b4e7878",
            },
            {
              priv_key_tweak:
                "2f17ea873a0047fc01ba8010fef0969e76d0e4283f600d48f735098b1fee6eb9",
              pub_key:
                "841792c33c9dc6193e76744134125d40add8f2f4a96475f28ba150be032d64e8",
              signature:
                "c26f4e3cf371b90b840f48ea0e761b5ec31883ed55719f9ef06a90e282d85f565790ab780a3f491bc2668cc64e944dca849d1022a878cdadb8d168b8da4a6da3",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Receiving with labels: label with even parity",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq",
          ],
        },
        expected: {
          outputs: [
            [
              "d014d4860f67d607d60b1af70e0ee236b99658b61bb769832acbbe87c374439a",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
            },
          ],
          outputs: [
            "d014d4860f67d607d60b1af70e0ee236b99658b61bb769832acbbe87c374439a",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [2, 3, 1001337],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqsg59z2rppn4qlkx0yz9sdltmjv3j8zgcqadjn4ug98m3t6plujsq9qvu5n",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5",
          ],
          outputs: [
            {
              priv_key_tweak:
                "51d4e9d0d482b5700109b4b2e16ff508269b03d800192a043d61dca4a0a72a52",
              pub_key:
                "d014d4860f67d607d60b1af70e0ee236b99658b61bb769832acbbe87c374439a",
              signature:
                "c30fa63bad6f0a317f39a773a5cbf0b0f8193c71dfebba05ee6ae4ed28e3775e6e04c3ea70a83703bb888122855dc894cab61692e7fd10c9b3494d479a60785e",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Receiving with labels: label with odd parity",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqsg59z2rppn4qlkx0yz9sdltmjv3j8zgcqadjn4ug98m3t6plujsq9qvu5n",
          ],
        },
        expected: {
          outputs: [
            [
              "67626aebb3c4307cf0f6c39ca23247598fabf675ab783292eb2f81ae75ad1f8c",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
            },
          ],
          outputs: [
            "67626aebb3c4307cf0f6c39ca23247598fabf675ab783292eb2f81ae75ad1f8c",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [2, 3, 1001337],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqsg59z2rppn4qlkx0yz9sdltmjv3j8zgcqadjn4ug98m3t6plujsq9qvu5n",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5",
          ],
          outputs: [
            {
              priv_key_tweak:
                "6024ae214876356b8d917716e7707d267ae16a0fdb07de2a786b74a7bbcddead",
              pub_key:
                "67626aebb3c4307cf0f6c39ca23247598fabf675ab783292eb2f81ae75ad1f8c",
              signature:
                "a86d554d0d6b7aa0907155f7e0b47f0182752472fffaeddd68da90e99b9402f166fd9b33039c302c7115098d971c1399e67c19e9e4de180b10ea0b9d6f0db832",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Receiving with labels: large label integer",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5",
          ],
        },
        expected: {
          outputs: [
            [
              "7efa60ce78ac343df8a013a2027c6c5ef29f9502edcbd769d2c21717fecc5951",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
            },
          ],
          outputs: [
            "7efa60ce78ac343df8a013a2027c6c5ef29f9502edcbd769d2c21717fecc5951",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [2, 3, 1001337],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqsg59z2rppn4qlkx0yz9sdltmjv3j8zgcqadjn4ug98m3t6plujsq9qvu5n",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5",
          ],
          outputs: [
            {
              priv_key_tweak:
                "e336b92330c33030285ce42e4115ad92d5197913c88e06b9072b4a9b47c664a2",
              pub_key:
                "7efa60ce78ac343df8a013a2027c6c5ef29f9502edcbd769d2c21717fecc5951",
              signature:
                "c9e80dd3bdd25ca2d352ce77510f1aed37ba3509dc8cc0677f2d7c2dd04090707950ce9dd6c83d2a428063063aff5c04f1744e334f661f2fc01b4ef80b50f739",
            },
          ],
        },
      },
    ],
  },
  {
    comment:
      "Multiple outputs with labels: un-labeled and labeled address; same recipient",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqaxww2fnhrx05cghth75n0qcj59e3e2anscr0q9wyknjxtxycg07y3pevyj",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c",
              "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
            ],
            [
              "83dc944e61603137294829aed56c74c9b087d80f2c021b98a7fae5799000696c",
              "e976a58fbd38aeb4e6093d4df02e9c1de0c4513ae0c588cef68cda5b2f8834ca",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
            },
          ],
          outputs: [
            "39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c",
            "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [1],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqaxww2fnhrx05cghth75n0qcj59e3e2anscr0q9wyknjxtxycg07y3pevyj",
          ],
          outputs: [
            {
              priv_key_tweak:
                "43100f89f1a6bf10081c92b473ffc57ceac7dbed600b6aba9bb3976f17dbb914",
              pub_key:
                "39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c",
              signature:
                "15c92509b67a6c211ebb4a51b7528d0666e6720de2343b2e92cfb97942ca14693c1f1fdc8451acfdb2644039f8f5c76114807fdc3d3a002d8a46afab6756bd75",
            },
            {
              priv_key_tweak:
                "33ce085c3c11eaad13694aae3c20301a6c83382ec89a7cde96c6799e2f88805a",
              pub_key:
                "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
              signature:
                "335667ca6cae7a26438f5cfdd73b3d48fa832fa9768521d7d5445f22c203ab0d74ed85088f27d29959ba627a4509996676f47df8ff284d292567b1beef0e3912",
            },
          ],
        },
      },
    ],
  },
  {
    comment:
      "Multiple outputs with labels: multiple outputs for labeled address; same recipient",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqaxww2fnhrx05cghth75n0qcj59e3e2anscr0q9wyknjxtxycg07y3pevyj",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqaxww2fnhrx05cghth75n0qcj59e3e2anscr0q9wyknjxtxycg07y3pevyj",
          ],
        },
        expected: {
          outputs: [
            [
              "39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c",
              "83dc944e61603137294829aed56c74c9b087d80f2c021b98a7fae5799000696c",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
            },
          ],
          outputs: [
            "39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c",
            "83dc944e61603137294829aed56c74c9b087d80f2c021b98a7fae5799000696c",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [1],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqaxww2fnhrx05cghth75n0qcj59e3e2anscr0q9wyknjxtxycg07y3pevyj",
          ],
          outputs: [
            {
              priv_key_tweak:
                "43100f89f1a6bf10081c92b473ffc57ceac7dbed600b6aba9bb3976f17dbb914",
              pub_key:
                "39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c",
              signature:
                "15c92509b67a6c211ebb4a51b7528d0666e6720de2343b2e92cfb97942ca14693c1f1fdc8451acfdb2644039f8f5c76114807fdc3d3a002d8a46afab6756bd75",
            },
            {
              priv_key_tweak:
                "9d5fd3b91cac9ddfea6fc2e6f9386f680e6cee623cda02f53706306c081de87f",
              pub_key:
                "83dc944e61603137294829aed56c74c9b087d80f2c021b98a7fae5799000696c",
              signature:
                "db0dfacc98b6a6fcc67cc4631f080b1ca38c60d8c397f2f19843f8f95ec91594b24e47c5bd39480a861c1209f7e3145c440371f9191fb96e324690101eac8e8e",
            },
          ],
        },
      },
    ],
  },
  {
    comment:
      "Multiple outputs with labels: un-labeled, labeled, and multiple outputs for labeled address; same recipients",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqaxww2fnhrx05cghth75n0qcj59e3e2anscr0q9wyknjxtxycg07y3pevyj",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjyh2ju7hd5gj57jg5r9lev3pckk4n2shtzaq34467erzzdfajfggty6aa5",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjyh2ju7hd5gj57jg5r9lev3pckk4n2shtzaq34467erzzdfajfggty6aa5",
          ],
        },
        expected: {
          outputs: [
            [
              "006a02c308ccdbf3ac49f0638f6de128f875db5a213095cf112b3b77722472ae",
              "39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c",
              "ae1a780c04237bd577283c3ddb2e499767c3214160d5a6b0767e6b8c278bd701",
              "ca64abe1e0f737823fb9a94f597eed418fb2df77b1317e26b881a14bb594faaa",
            ],
            [
              "006a02c308ccdbf3ac49f0638f6de128f875db5a213095cf112b3b77722472ae",
              "3edf1ff6657c6e69568811bd726a7a7f480493aa42161acfe8dd4f44521f99ed",
              "7ee1543ed5d123ffa66fbebc128c020173eb490d5fa2ba306e0c9573a77db8f3",
              "ca64abe1e0f737823fb9a94f597eed418fb2df77b1317e26b881a14bb594faaa",
            ],
            [
              "006a02c308ccdbf3ac49f0638f6de128f875db5a213095cf112b3b77722472ae",
              "7ee1543ed5d123ffa66fbebc128c020173eb490d5fa2ba306e0c9573a77db8f3",
              "83dc944e61603137294829aed56c74c9b087d80f2c021b98a7fae5799000696c",
              "ae1a780c04237bd577283c3ddb2e499767c3214160d5a6b0767e6b8c278bd701",
            ],
            [
              "39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c",
              "3c54444944d176437644378c23efb999ab6ab1cacdfe1dc1537b607e3df330e2",
              "ca64abe1e0f737823fb9a94f597eed418fb2df77b1317e26b881a14bb594faaa",
              "f4569fc5f69c10f0082cfbb8e072e6266ec55f69fba8cffca4cbb4c144b7e59b",
            ],
            [
              "39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c",
              "ae1a780c04237bd577283c3ddb2e499767c3214160d5a6b0767e6b8c278bd701",
              "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
              "f4569fc5f69c10f0082cfbb8e072e6266ec55f69fba8cffca4cbb4c144b7e59b",
            ],
            [
              "3c54444944d176437644378c23efb999ab6ab1cacdfe1dc1537b607e3df330e2",
              "602e10e6944107c9b48bd885b493676578c935723287e0ab2f8b7f136862568e",
              "7ee1543ed5d123ffa66fbebc128c020173eb490d5fa2ba306e0c9573a77db8f3",
              "ca64abe1e0f737823fb9a94f597eed418fb2df77b1317e26b881a14bb594faaa",
            ],
            [
              "3c54444944d176437644378c23efb999ab6ab1cacdfe1dc1537b607e3df330e2",
              "7ee1543ed5d123ffa66fbebc128c020173eb490d5fa2ba306e0c9573a77db8f3",
              "83dc944e61603137294829aed56c74c9b087d80f2c021b98a7fae5799000696c",
              "f4569fc5f69c10f0082cfbb8e072e6266ec55f69fba8cffca4cbb4c144b7e59b",
            ],
            [
              "3edf1ff6657c6e69568811bd726a7a7f480493aa42161acfe8dd4f44521f99ed",
              "7ee1543ed5d123ffa66fbebc128c020173eb490d5fa2ba306e0c9573a77db8f3",
              "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
              "f4569fc5f69c10f0082cfbb8e072e6266ec55f69fba8cffca4cbb4c144b7e59b",
            ],
            [
              "3edf1ff6657c6e69568811bd726a7a7f480493aa42161acfe8dd4f44521f99ed",
              "ca64abe1e0f737823fb9a94f597eed418fb2df77b1317e26b881a14bb594faaa",
              "e976a58fbd38aeb4e6093d4df02e9c1de0c4513ae0c588cef68cda5b2f8834ca",
              "f4569fc5f69c10f0082cfbb8e072e6266ec55f69fba8cffca4cbb4c144b7e59b",
            ],
            [
              "602e10e6944107c9b48bd885b493676578c935723287e0ab2f8b7f136862568e",
              "7ee1543ed5d123ffa66fbebc128c020173eb490d5fa2ba306e0c9573a77db8f3",
              "ae1a780c04237bd577283c3ddb2e499767c3214160d5a6b0767e6b8c278bd701",
              "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
            ],
            [
              "602e10e6944107c9b48bd885b493676578c935723287e0ab2f8b7f136862568e",
              "ae1a780c04237bd577283c3ddb2e499767c3214160d5a6b0767e6b8c278bd701",
              "ca64abe1e0f737823fb9a94f597eed418fb2df77b1317e26b881a14bb594faaa",
              "e976a58fbd38aeb4e6093d4df02e9c1de0c4513ae0c588cef68cda5b2f8834ca",
            ],
            [
              "83dc944e61603137294829aed56c74c9b087d80f2c021b98a7fae5799000696c",
              "ae1a780c04237bd577283c3ddb2e499767c3214160d5a6b0767e6b8c278bd701",
              "e976a58fbd38aeb4e6093d4df02e9c1de0c4513ae0c588cef68cda5b2f8834ca",
              "f4569fc5f69c10f0082cfbb8e072e6266ec55f69fba8cffca4cbb4c144b7e59b",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
            },
          ],
          outputs: [
            "006a02c308ccdbf3ac49f0638f6de128f875db5a213095cf112b3b77722472ae",
            "39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c",
            "ae1a780c04237bd577283c3ddb2e499767c3214160d5a6b0767e6b8c278bd701",
            "ca64abe1e0f737823fb9a94f597eed418fb2df77b1317e26b881a14bb594faaa",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [1, 1337],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqaxww2fnhrx05cghth75n0qcj59e3e2anscr0q9wyknjxtxycg07y3pevyj",
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjyh2ju7hd5gj57jg5r9lev3pckk4n2shtzaq34467erzzdfajfggty6aa5",
          ],
          outputs: [
            {
              priv_key_tweak:
                "4e3352fbe0505c25e718d96007c259ef08db34f8c844e4ff742d9855ff03805a",
              pub_key:
                "006a02c308ccdbf3ac49f0638f6de128f875db5a213095cf112b3b77722472ae",
              signature:
                "6eeae1ea9eb826e3d0e812f65937100e0836ea188c04f36fabc4981eda29de8d3d3529390a0a8b3d830f7bca4f5eae5994b9788ddaf05ad259ffe26d86144b4b",
            },
            {
              priv_key_tweak:
                "43100f89f1a6bf10081c92b473ffc57ceac7dbed600b6aba9bb3976f17dbb914",
              pub_key:
                "39f42624d5c32a77fda80ff0acee269afec601d3791803e80252ae04e4ffcf4c",
              signature:
                "15c92509b67a6c211ebb4a51b7528d0666e6720de2343b2e92cfb97942ca14693c1f1fdc8451acfdb2644039f8f5c76114807fdc3d3a002d8a46afab6756bd75",
            },
            {
              priv_key_tweak:
                "bf709f98d4418f8a67e738154ae48818dad44689cd37fbc070891a396dd1c633",
              pub_key:
                "ae1a780c04237bd577283c3ddb2e499767c3214160d5a6b0767e6b8c278bd701",
              signature:
                "42a19fd8a63dde1824966a95d65a28203e631e49bf96ca5dae1b390e7a0ace2cc8709c9b0c5715047032f57f536a3c80273cbecf4c05be0b5456c183fa122c06",
            },
            {
              priv_key_tweak:
                "736f05e4e3072c3b8656bedef2e9bf54cbcaa2b6fe5320d3e86f5b96874dda71",
              pub_key:
                "ca64abe1e0f737823fb9a94f597eed418fb2df77b1317e26b881a14bb594faaa",
              signature:
                "2e61bb3d79418ecf55f68847cf121bfc12d397b39d1da8643246b2f0a9b96c3daa4bfe9651beb5c9ce20e1f29282c4566400a4b45ee6657ec3b18fdc554da0b4",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Single recipient: use silent payments for sender change",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            "sp1qqw6vczcfpdh5nf5y2ky99kmqae0tr30hgdfg88parz50cp80wd2wqqlv6saelkk5snl4wfutyxrchpzzwm8rjp3z6q7apna59z9huq4x754e5atr",
          ],
        },
        expected: {
          outputs: [
            [
              "be368e28979d950245d742891ae6064020ba548c1e2e65a639a8bb0675d95cff",
              "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
            },
          ],
          outputs: [
            "be368e28979d950245d742891ae6064020ba548c1e2e65a639a8bb0675d95cff",
            "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
          ],
          key_material: {
            spend_priv_key:
              "b8f87388cbb41934c50daca018901b00070a5ff6cc25a7e9e716a9d5b9e4d664",
            scan_priv_key:
              "11b7a82e06ca2648d5fded2366478078ec4fc9dc1d8ff487518226f229d768fd",
          },
          labels: [0],
        },
        expected: {
          addresses: [
            "sp1qqw6vczcfpdh5nf5y2ky99kmqae0tr30hgdfg88parz50cp80wd2wqqauj52ymtc4xdkmx3tgyhrsemg2g3303xk2gtzfy8h8ejet8fz8jcw23zua",
            "sp1qqw6vczcfpdh5nf5y2ky99kmqae0tr30hgdfg88parz50cp80wd2wqqlv6saelkk5snl4wfutyxrchpzzwm8rjp3z6q7apna59z9huq4x754e5atr",
          ],
          outputs: [
            {
              priv_key_tweak:
                "80cd767ed20bd0bb7d8ea5e803f8c381293a62e8a073cf46fb0081da46e64e1f",
              pub_key:
                "be368e28979d950245d742891ae6064020ba548c1e2e65a639a8bb0675d95cff",
              signature:
                "7fbd5074cf1377273155eefafc7c330cb61b31da252f22206ac27530d2b2567040d9af7808342ed4a09598c26d8307446e4ed77079e6a2e61fea736e44da5f5a",
            },
          ],
        },
      },
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
            },
          ],
          outputs: [
            "be368e28979d950245d742891ae6064020ba548c1e2e65a639a8bb0675d95cff",
            "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "33ce085c3c11eaad13694aae3c20301a6c83382ec89a7cde96c6799e2f88805a",
              pub_key:
                "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
              signature:
                "335667ca6cae7a26438f5cfdd73b3d48fa832fa9768521d7d5445f22c203ab0d74ed85088f27d29959ba627a4509996676f47df8ff284d292567b1beef0e3912",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Single recipient: taproot input with NUMS point",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0440c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b22205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5ac21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00150",
              prevout: {
                scriptPubKey: {
                  hex: "5120da6f0595ecb302bbe73e2f221f05ab10f336b06817d36fd28fc6691725ddaa85",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0140bd1e708f92dbeaf24a6b8dd22e59c6274355424d62baea976b449e220fd75b13578e262ab11b7aa58e037f0c6b0519b66803b7d9decaa1906dedebfb531c56c1",
              prevout: {
                scriptPubKey: {
                  hex: "5120782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
                },
              },
              private_key:
                "fc8716a97a48ba9a05a98ae47b5cd201a25a7fd5d8b73c203c5f7b6b6b3b6ad7",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 1,
              scriptSig: "",
              txinwitness:
                "0340268d31a9276f6380107d5321cafa6d9e8e5ea39204318fdc8206b31507c891c3bbcea3c99e2208d73bd127a8e8c5f1e45a54f1bd217205414ddb566ab7eda0092220e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85dac21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
              prevout: {
                scriptPubKey: {
                  hex: "51200a3c9365ceb131f89b0a4feb6896ebd67bb15a98c31eaa3da143bb955a0f3fcb",
                },
              },
              private_key:
                "8d4751f6e8a3586880fb66c19ae277969bd5aa06f61c4ee2f1e2486efdf666d3",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "79e79897c52935bfd97fc6e076a6431a0c7543ca8c31e0fc3cf719bb572c842d",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0440c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b22205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5ac21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00150",
              prevout: {
                scriptPubKey: {
                  hex: "5120da6f0595ecb302bbe73e2f221f05ab10f336b06817d36fd28fc6691725ddaa85",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0140bd1e708f92dbeaf24a6b8dd22e59c6274355424d62baea976b449e220fd75b13578e262ab11b7aa58e037f0c6b0519b66803b7d9decaa1906dedebfb531c56c1",
              prevout: {
                scriptPubKey: {
                  hex: "5120782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 1,
              scriptSig: "",
              txinwitness:
                "0340268d31a9276f6380107d5321cafa6d9e8e5ea39204318fdc8206b31507c891c3bbcea3c99e2208d73bd127a8e8c5f1e45a54f1bd217205414ddb566ab7eda0092220e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85dac21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
              prevout: {
                scriptPubKey: {
                  hex: "51200a3c9365ceb131f89b0a4feb6896ebd67bb15a98c31eaa3da143bb955a0f3fcb",
                },
              },
            },
          ],
          outputs: [
            "79e79897c52935bfd97fc6e076a6431a0c7543ca8c31e0fc3cf719bb572c842d",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "3ddec3232609d348d6b8b53123b4f40f6d4f5398ca586f087b0416ec3b851496",
              pub_key:
                "79e79897c52935bfd97fc6e076a6431a0c7543ca8c31e0fc3cf719bb572c842d",
              signature:
                "d7d06e3afb68363031e4eb18035c46ceae41bdbebe7888a4754bc9848c596436869aeaecff0527649a1f458b71c9ceecec10b535c09d01d720229aa228547706",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Pubkey extraction from malleated p2pkh",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 1,
              scriptSig:
                "0075473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 2,
              scriptSig:
                "5163473045022100e7d26e77290b37128f5215ade25b9b908ce87cc9a4d498908b5bb8fd6daa1b8d022002568c3a8226f4f0436510283052bfb780b76f3fe4aa60c4c5eb118e43b187372102e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d67483046022100c0d3c851d3bd562ae93d56bcefd735ea57c027af46145a4d5e9cac113bfeb0c2022100ee5b2239af199fa9b7aa1d98da83a29d0a2cf1e4f29e2f37134ce386d51c544c2102ad0f26ddc7b3fcc340155963b3051b85289c1869612ecb290184ac952e2864ec68",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914c82c5ec473cbc6c86e5ef410e36f9495adcf979988ac",
                },
              },
              private_key:
                "72b8ae09175ca7977f04993e651d88681ed932dfb92c5158cdf0161dd23fda6e",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "4612cdbf845c66c7511d70aab4d9aed11e49e48cdb8d799d787101cdd0d53e4f",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 1,
              scriptSig:
                "0075473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 2,
              scriptSig:
                "5163473045022100e7d26e77290b37128f5215ade25b9b908ce87cc9a4d498908b5bb8fd6daa1b8d022002568c3a8226f4f0436510283052bfb780b76f3fe4aa60c4c5eb118e43b187372102e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d67483046022100c0d3c851d3bd562ae93d56bcefd735ea57c027af46145a4d5e9cac113bfeb0c2022100ee5b2239af199fa9b7aa1d98da83a29d0a2cf1e4f29e2f37134ce386d51c544c2102ad0f26ddc7b3fcc340155963b3051b85289c1869612ecb290184ac952e2864ec68",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914c82c5ec473cbc6c86e5ef410e36f9495adcf979988ac",
                },
              },
            },
          ],
          outputs: [
            "4612cdbf845c66c7511d70aab4d9aed11e49e48cdb8d799d787101cdd0d53e4f",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "10bde9781def20d7701e7603ef1b1e5e71c67bae7154818814e3c81ef5b1a3d3",
              pub_key:
                "4612cdbf845c66c7511d70aab4d9aed11e49e48cdb8d799d787101cdd0d53e4f",
              signature:
                "6137969f810e9e8ef6c9755010e808f5dd1aed705882e44d7f0ae64eb0c509ec8b62a0671bee0d5914ac27d2c463443e28e999d82dc3d3a4919f093872d947bb",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "P2PKH and P2WPKH Uncompressed Keys are skipped",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b974104782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c3799373233387c5343bf58e23269e903335b958a12182f9849297321e8d710e49a8727129cab",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9144b92ac4ac6fe6212393894addda332f2e47a315688ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 1,
              scriptSig: "",
              txinwitness:
                "02473045022100e7d26e77290b37128f5215ade25b9b908ce87cc9a4d498908b5bb8fd6daa1b8d022002568c3a8226f4f0436510283052bfb780b76f3fe4aa60c4c5eb118e43b187374104e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d6fe8190e189be57d0d5bcd17dbcbcd04c9b4a1c5f605b10d5c90abfcc0d12884",
              prevout: {
                scriptPubKey: {
                  hex: "00140423f731a07491364e8dce98b7c00bda63336950",
                },
              },
              private_key:
                "72b8ae09175ca7977f04993e651d88681ed932dfb92c5158cdf0161dd23fda6e",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "67fee277da9e8542b5d2e6f32d660a9bbd3f0e107c2d53638ab1d869088882d6",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
                },
              },
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b974104782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c3799373233387c5343bf58e23269e903335b958a12182f9849297321e8d710e49a8727129cab",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9144b92ac4ac6fe6212393894addda332f2e47a315688ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 1,
              scriptSig: "",
              txinwitness:
                "02473045022100e7d26e77290b37128f5215ade25b9b908ce87cc9a4d498908b5bb8fd6daa1b8d022002568c3a8226f4f0436510283052bfb780b76f3fe4aa60c4c5eb118e43b187374104e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d6fe8190e189be57d0d5bcd17dbcbcd04c9b4a1c5f605b10d5c90abfcc0d12884",
              prevout: {
                scriptPubKey: {
                  hex: "00140423f731a07491364e8dce98b7c00bda63336950",
                },
              },
            },
          ],
          outputs: [
            "67fee277da9e8542b5d2e6f32d660a9bbd3f0e107c2d53638ab1d869088882d6",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "688fa3aeb97d2a46ae87b03591921c2eaf4b505eb0ddca2733c94701e01060cf",
              pub_key:
                "67fee277da9e8542b5d2e6f32d660a9bbd3f0e107c2d53638ab1d869088882d6",
              signature:
                "72e7ad573ac23255d4651d5b0326a200496588acb7a4894b22092236d5eda6a0a9a4d8429b022c2219081fefce5b33795cae488d10f5ea9438849ed8353624f2",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Skip invalid P2SH inputs",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "16001419c2f3ae0ca3b642bd3e49598b8da89f50c14161",
              txinwitness:
                "02483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              prevout: {
                scriptPubKey: {
                  hex: "a9148629db5007d5fcfbdbb466637af09daf9125969387",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 1,
              scriptSig: "1600144b92ac4ac6fe6212393894addda332f2e47a3156",
              txinwitness:
                "02473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b974104782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c3799373233387c5343bf58e23269e903335b958a12182f9849297321e8d710e49a8727129cab",
              prevout: {
                scriptPubKey: {
                  hex: "a9146c9bf136fbb7305fd99d771a95127fcf87dedd0d87",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 2,
              scriptSig:
                "00493046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d601483045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b97014c695221025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be52103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c3799373233382102e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d53ae",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "a9141044ddc6cea09e4ac40fbec2ba34ad62de6db25b87",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [
            [
              "67fee277da9e8542b5d2e6f32d660a9bbd3f0e107c2d53638ab1d869088882d6",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "16001419c2f3ae0ca3b642bd3e49598b8da89f50c14161",
              txinwitness:
                "02483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
              prevout: {
                scriptPubKey: {
                  hex: "a9148629db5007d5fcfbdbb466637af09daf9125969387",
                },
              },
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 1,
              scriptSig: "1600144b92ac4ac6fe6212393894addda332f2e47a3156",
              txinwitness:
                "02473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b974104782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c3799373233387c5343bf58e23269e903335b958a12182f9849297321e8d710e49a8727129cab",
              prevout: {
                scriptPubKey: {
                  hex: "a9146c9bf136fbb7305fd99d771a95127fcf87dedd0d87",
                },
              },
            },
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 2,
              scriptSig:
                "00493046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d601483045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b97014c695221025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be52103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c3799373233382102e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d53ae",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "a9141044ddc6cea09e4ac40fbec2ba34ad62de6db25b87",
                },
              },
            },
          ],
          outputs: [
            "67fee277da9e8542b5d2e6f32d660a9bbd3f0e107c2d53638ab1d869088882d6",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [
            {
              priv_key_tweak:
                "688fa3aeb97d2a46ae87b03591921c2eaf4b505eb0ddca2733c94701e01060cf",
              pub_key:
                "67fee277da9e8542b5d2e6f32d660a9bbd3f0e107c2d53638ab1d869088882d6",
              signature:
                "72e7ad573ac23255d4651d5b0326a200496588acb7a4894b22092236d5eda6a0a9a4d8429b022c2219081fefce5b33795cae488d10f5ea9438849ed8353624f2",
            },
          ],
        },
      },
    ],
  },
  {
    comment: "Recipient ignores unrelated outputs",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b",
              prevout: {
                scriptPubKey: {
                  hex: "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
          ],
          recipients: [
            "sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn",
          ],
        },
        expected: {
          outputs: [
            [
              "841792c33c9dc6193e76744134125d40add8f2f4a96475f28ba150be032d64e8",
            ],
          ],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig: "",
              txinwitness:
                "0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b",
              prevout: {
                scriptPubKey: {
                  hex: "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
                },
              },
            },
          ],
          outputs: [
            "841792c33c9dc6193e76744134125d40add8f2f4a96475f28ba150be032d64e8",
            "782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [],
        },
      },
    ],
  },
  {
    comment: "No valid inputs, sender generates no outputs",
    sending: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d641045a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5c61836c9b1688ba431f7ea3039742251f62f0dca3da1bee58a47fa9b456c2d52",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914460e8b41545d2dbe7e0671f0f573e2232814260a88ac",
                },
              },
              private_key:
                "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1",
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b974104782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c3799373233387c5343bf58e23269e903335b958a12182f9849297321e8d710e49a8727129cab",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9144b92ac4ac6fe6212393894addda332f2e47a315688ac",
                },
              },
              private_key:
                "0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a",
            },
          ],
          recipients: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
        },
        expected: {
          outputs: [[]],
        },
      },
    ],
    receiving: [
      {
        given: {
          vin: [
            {
              txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
              vout: 0,
              scriptSig:
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d641045a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5c61836c9b1688ba431f7ea3039742251f62f0dca3da1bee58a47fa9b456c2d52",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a914460e8b41545d2dbe7e0671f0f573e2232814260a88ac",
                },
              },
            },
            {
              txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
              vout: 0,
              scriptSig:
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b974104782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c3799373233387c5343bf58e23269e903335b958a12182f9849297321e8d710e49a8727129cab",
              txinwitness: "",
              prevout: {
                scriptPubKey: {
                  hex: "76a9144b92ac4ac6fe6212393894addda332f2e47a315688ac",
                },
              },
            },
          ],
          outputs: [
            "782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
            "e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d",
          ],
          key_material: {
            spend_priv_key:
              "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
            scan_priv_key:
              "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
          },
          labels: [],
        },
        expected: {
          addresses: [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          ],
          outputs: [],
        },
      },
    ],
  },
];
