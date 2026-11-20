Launch cost by policy, size and load, no attacker. Data: `run4_overhead.csv`, `run4_openssl_overhead.csv`. p99 is nearest-rank, so with n = 50 it is the slowest launch. Copy share is the copy's part of a sealed launch, not the sealed policy's extra cost over another policy.

| Hash | Policy | Size | Load | n | hash median ms | copy median ms | total median ms | total p99 ms | copy share | bytes copied |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| plain-C SHA-256 | pathname | 64k | idle | 50 | 0.23 | 0.00 | 0.46 | 0.76 | - | 0 |
| plain-C SHA-256 | open descriptor | 64k | idle | 50 | 0.23 | 0.00 | 0.45 | 0.81 | - | 0 |
| plain-C SHA-256 | sealed copy | 64k | idle | 50 | 0.25 | 0.05 | 0.58 | 1.04 | 8% | 74424 |
| plain-C SHA-256 | pathname | 1m | idle | 50 | 3.12 | 0.00 | 3.39 | 3.82 | - | 0 |
| plain-C SHA-256 | open descriptor | 1m | idle | 50 | 3.13 | 0.00 | 3.40 | 3.72 | - | 0 |
| plain-C SHA-256 | sealed copy | 1m | idle | 50 | 3.08 | 0.32 | 3.75 | 6.36 | 9% | 1057464 |
| plain-C SHA-256 | pathname | 8m | idle | 50 | 25.21 | 0.00 | 25.61 | 27.47 | - | 0 |
| plain-C SHA-256 | open descriptor | 8m | idle | 50 | 25.15 | 0.00 | 25.63 | 27.39 | - | 0 |
| plain-C SHA-256 | sealed copy | 8m | idle | 50 | 24.87 | 2.68 | 28.07 | 30.54 | 10% | 8397496 |
| plain-C SHA-256 | pathname | 32m | idle | 50 | 99.84 | 0.00 | 100.30 | 107.84 | - | 0 |
| plain-C SHA-256 | open descriptor | 32m | idle | 50 | 99.55 | 0.00 | 100.03 | 107.24 | - | 0 |
| plain-C SHA-256 | sealed copy | 32m | idle | 50 | 99.63 | 10.06 | 109.93 | 117.73 | 9% | 33563320 |
| plain-C SHA-256 | pathname | 64k | stress | 50 | 0.45 | 0.00 | 3.88 | 7.16 | - | 0 |
| plain-C SHA-256 | open descriptor | 64k | stress | 50 | 0.43 | 0.00 | 3.86 | 7.30 | - | 0 |
| plain-C SHA-256 | sealed copy | 64k | stress | 50 | 0.39 | 0.07 | 2.90 | 7.54 | 2% | 74424 |
| plain-C SHA-256 | pathname | 1m | stress | 50 | 9.64 | 0.00 | 13.19 | 21.95 | - | 0 |
| plain-C SHA-256 | open descriptor | 1m | stress | 50 | 9.60 | 0.00 | 13.08 | 21.91 | - | 0 |
| plain-C SHA-256 | sealed copy | 1m | stress | 50 | 9.64 | 0.55 | 14.15 | 21.04 | 4% | 1057464 |
| plain-C SHA-256 | pathname | 8m | stress | 50 | 77.35 | 0.00 | 78.90 | 113.73 | - | 0 |
| plain-C SHA-256 | open descriptor | 8m | stress | 50 | 93.63 | 0.00 | 97.50 | 144.02 | - | 0 |
| plain-C SHA-256 | sealed copy | 8m | stress | 50 | 80.09 | 3.56 | 83.92 | 140.75 | 4% | 8397496 |
| plain-C SHA-256 | pathname | 32m | stress | 50 | 250.25 | 0.00 | 252.50 | 406.59 | - | 0 |
| plain-C SHA-256 | open descriptor | 32m | stress | 50 | 263.36 | 0.00 | 264.76 | 413.47 | - | 0 |
| plain-C SHA-256 | sealed copy | 32m | stress | 50 | 250.12 | 27.47 | 280.60 | 441.84 | 10% | 33563320 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 64k | idle | 50 | 0.09 | 0.00 | 0.31 | 0.86 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 64k | idle | 50 | 0.09 | 0.00 | 0.30 | 0.84 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 64k | idle | 50 | 0.08 | 0.05 | 0.44 | 0.85 | 11% | 74424 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 1m | idle | 50 | 0.63 | 0.00 | 0.91 | 1.49 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 1m | idle | 50 | 0.62 | 0.00 | 0.90 | 1.51 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 1m | idle | 50 | 0.62 | 0.29 | 1.27 | 1.59 | 23% | 1057464 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 8m | idle | 50 | 4.87 | 0.00 | 5.29 | 5.93 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 8m | idle | 50 | 4.83 | 0.00 | 5.27 | 5.86 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 8m | idle | 50 | 5.06 | 2.74 | 8.37 | 9.10 | 33% | 8397496 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 32m | idle | 50 | 19.35 | 0.00 | 19.74 | 21.03 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 32m | idle | 50 | 19.08 | 0.00 | 19.50 | 21.12 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 32m | idle | 50 | 19.73 | 9.89 | 30.17 | 32.65 | 33% | 33563320 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 64k | stress | 50 | 0.12 | 0.00 | 3.85 | 7.58 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 64k | stress | 50 | 0.13 | 0.00 | 3.93 | 7.59 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 64k | stress | 50 | 0.10 | 0.07 | 2.99 | 8.90 | 2% | 74424 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 1m | stress | 50 | 0.72 | 0.00 | 4.21 | 8.91 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 1m | stress | 50 | 0.70 | 0.00 | 3.91 | 12.94 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 1m | stress | 50 | 0.73 | 0.44 | 5.67 | 8.90 | 8% | 1057464 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 8m | stress | 50 | 9.52 | 0.00 | 13.56 | 26.62 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 8m | stress | 50 | 9.43 | 0.00 | 14.34 | 23.00 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 8m | stress | 50 | 13.89 | 3.92 | 24.32 | 62.50 | 16% | 8397496 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 32m | stress | 50 | 42.19 | 0.00 | 46.84 | 92.65 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 32m | stress | 50 | 42.39 | 0.00 | 47.34 | 66.59 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 32m | stress | 50 | 46.99 | 25.00 | 75.06 | 107.50 | 33% | 33563320 |
