{
  "variables": {
    "enable_asan%": 0
  },
  "target_defaults": {
    "msvs_settings": {
      "VCCLCompilerTool": {
        "AdditionalOptions": [
          "/std:c++20"
        ],
        "DisableSpecificWarnings": [
          "4146"
        ]
      }
    },
    "conditions": [
      [
        "OS=='linux'",
        {
          "cflags_cc!": [
            "-std=gnu++17",
            "-std=c++17",
            "-std=gnu++14",
            "-std=c++14"
          ],
          "cflags_cc": [
            "-std=c++20",
            "-O2"
          ]
        }
      ],
      [
        "OS=='linux' and enable_asan==1",
        {
          "cflags": [
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all"
          ],
          "cflags_cc": [
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all"
          ],
          "ldflags": [
            "-fsanitize=address,undefined"
          ]
        }
      ]
    ]
  },
  "targets": [
    {
      "target_name": "lattice_wire_native",
      "sources": [
        "src/addon.cpp",
        "src/secure_alloc.c",
        "src/lattice_wire.cpp",
        "src/anti_replay.cpp",
        "src/aead_chacha20poly1305.cpp",
        "src/lattice_kdf.cpp",
        "src/mlkem512_wrapper.cpp",
        "src/zero_rtt_engine.cpp",
        "deps/monocypher/monocypher.c",
        "deps/mlkem512/clean/cbd.c",
        "deps/mlkem512/clean/indcpa.c",
        "deps/mlkem512/clean/kem.c",
        "deps/mlkem512/clean/ntt.c",
        "deps/mlkem512/clean/poly.c",
        "deps/mlkem512/clean/polyvec.c",
        "deps/mlkem512/clean/reduce.c",
        "deps/mlkem512/clean/symmetric-shake.c",
        "deps/mlkem512/clean/verify.c",
        "deps/mlkem512/common/fips202.c",
        "deps/mlkem512/common/randombytes.c"
      ],
      "include_dirs": [
        "include",
        "deps/monocypher",
        "deps/mlkem512/clean",
        "deps/mlkem512/common"
      ],
      "msvs_settings": {
        "VCCLCompilerTool": {
          "Optimization": 3,
          "FavorSizeOrSpeed": 1
        }
      },
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": [
              "Advapi32.lib"
            ]
          }
        ]
      ]
    },
    {
      "target_name": "anti_replay_test",
      "type": "executable",
      "sources": [
        "src/anti_replay.cpp",
        "test/anti_replay_test.cpp"
      ],
      "include_dirs": [
        "include"
      ],
      "msvs_settings": {
        "VCCLCompilerTool": {
          "Optimization": 2
        }
      }
    },
    {
      "target_name": "aead_test",
      "type": "executable",
      "sources": [
        "src/aead_chacha20poly1305.cpp",
        "deps/monocypher/monocypher.c",
        "test/aead_test.cpp"
      ],
      "include_dirs": [
        "include",
        "deps/monocypher"
      ],
      "msvs_settings": {
        "VCCLCompilerTool": {
          "Optimization": 2
        }
      }
    },
    {
      "target_name": "mlkem512_test",
      "type": "executable",
      "sources": [
        "src/mlkem512_wrapper.cpp",
        "deps/monocypher/monocypher.c",
        "deps/mlkem512/clean/cbd.c",
        "deps/mlkem512/clean/indcpa.c",
        "deps/mlkem512/clean/kem.c",
        "deps/mlkem512/clean/ntt.c",
        "deps/mlkem512/clean/poly.c",
        "deps/mlkem512/clean/polyvec.c",
        "deps/mlkem512/clean/reduce.c",
        "deps/mlkem512/clean/symmetric-shake.c",
        "deps/mlkem512/clean/verify.c",
        "deps/mlkem512/common/fips202.c",
        "deps/mlkem512/common/randombytes.c",
        "test/mlkem512_test.cpp"
      ],
      "include_dirs": [
        "include",
        "deps/monocypher",
        "deps/mlkem512/clean",
        "deps/mlkem512/common"
      ],
      "msvs_settings": {
        "VCCLCompilerTool": {
          "Optimization": 2
        }
      },
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": [
              "Advapi32.lib"
            ]
          }
        ]
      ]
    },
    {
      "target_name": "mlkem512_bench",
      "type": "executable",
      "sources": [
        "src/mlkem512_wrapper.cpp",
        "deps/monocypher/monocypher.c",
        "deps/mlkem512/clean/cbd.c",
        "deps/mlkem512/clean/indcpa.c",
        "deps/mlkem512/clean/kem.c",
        "deps/mlkem512/clean/ntt.c",
        "deps/mlkem512/clean/poly.c",
        "deps/mlkem512/clean/polyvec.c",
        "deps/mlkem512/clean/reduce.c",
        "deps/mlkem512/clean/symmetric-shake.c",
        "deps/mlkem512/clean/verify.c",
        "deps/mlkem512/common/fips202.c",
        "deps/mlkem512/common/randombytes.c",
        "test/mlkem512_bench.cpp"
      ],
      "include_dirs": [
        "include",
        "deps/monocypher",
        "deps/mlkem512/clean",
        "deps/mlkem512/common"
      ],
      "msvs_settings": {
        "VCCLCompilerTool": {
          "Optimization": 2
        }
      },
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": [
              "Advapi32.lib"
            ]
          }
        ]
      ]
    },
    {
      "target_name": "zero_rtt_engine_test",
      "type": "executable",
      "sources": [
        "src/anti_replay.cpp",
        "src/aead_chacha20poly1305.cpp",
        "src/lattice_kdf.cpp",
        "src/lattice_wire.cpp",
        "src/mlkem512_wrapper.cpp",
        "src/zero_rtt_engine.cpp",
        "deps/monocypher/monocypher.c",
        "deps/mlkem512/clean/cbd.c",
        "deps/mlkem512/clean/indcpa.c",
        "deps/mlkem512/clean/kem.c",
        "deps/mlkem512/clean/ntt.c",
        "deps/mlkem512/clean/poly.c",
        "deps/mlkem512/clean/polyvec.c",
        "deps/mlkem512/clean/reduce.c",
        "deps/mlkem512/clean/symmetric-shake.c",
        "deps/mlkem512/clean/verify.c",
        "deps/mlkem512/common/fips202.c",
        "deps/mlkem512/common/randombytes.c",
        "test/zero_rtt_engine_test.cpp"
      ],
      "include_dirs": [
        "include",
        "deps/monocypher",
        "deps/mlkem512/clean",
        "deps/mlkem512/common"
      ],
      "msvs_settings": {
        "VCCLCompilerTool": {
          "Optimization": 2
        }
      },
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": [
              "Advapi32.lib"
            ]
          }
        ]
      ]
    }
  ]
}
