Launch cost by policy, size and load, no attacker. Data: `run2b_overhead.csv`, `run3b_openssl_overhead.csv`.

| Hash | Policy | Size | Load | n | hash median ms | copy median ms | total median ms | total p99 ms | copy share | bytes copied |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| plain-C SHA-256 | pathname | 64k | idle | 50 | 0.31 | 0.00 | 0.65 | 1.08 | - | 0 |
| plain-C SHA-256 | open descriptor | 64k | idle | 50 | 0.33 | 0.00 | 0.78 | 1.41 | - | 0 |
| plain-C SHA-256 | sealed copy | 64k | idle | 50 | 0.30 | 0.08 | 0.88 | 1.65 | 10% | 74424 |
| plain-C SHA-256 | pathname | 1m | idle | 50 | 4.62 | 0.00 | 5.16 | 9.73 | - | 0 |
| plain-C SHA-256 | open descriptor | 1m | idle | 50 | 4.57 | 0.00 | 5.17 | 8.04 | - | 0 |
| plain-C SHA-256 | sealed copy | 1m | idle | 50 | 4.71 | 0.50 | 6.04 | 8.73 | 8% | 1057464 |
| plain-C SHA-256 | pathname | 8m | idle | 50 | 31.50 | 0.00 | 32.00 | 58.22 | - | 0 |
| plain-C SHA-256 | open descriptor | 8m | idle | 50 | 30.24 | 0.00 | 30.71 | 47.19 | - | 0 |
| plain-C SHA-256 | sealed copy | 8m | idle | 50 | 30.25 | 3.06 | 33.84 | 50.15 | 9% | 8397496 |
| plain-C SHA-256 | pathname | 32m | idle | 50 | 106.56 | 0.00 | 107.18 | 135.17 | - | 0 |
| plain-C SHA-256 | open descriptor | 32m | idle | 50 | 111.17 | 0.00 | 111.75 | 162.16 | - | 0 |
| plain-C SHA-256 | sealed copy | 32m | idle | 50 | 118.77 | 11.66 | 131.69 | 160.71 | 9% | 33563320 |
| plain-C SHA-256 | pathname | 64k | stress | 50 | 0.60 | 0.00 | 3.89 | 7.88 | - | 0 |
| plain-C SHA-256 | open descriptor | 64k | stress | 50 | 0.59 | 0.00 | 3.99 | 7.16 | - | 0 |
| plain-C SHA-256 | sealed copy | 64k | stress | 50 | 0.53 | 0.12 | 3.39 | 10.11 | 3% | 74424 |
| plain-C SHA-256 | pathname | 1m | stress | 50 | 16.96 | 0.00 | 23.14 | 45.95 | - | 0 |
| plain-C SHA-256 | open descriptor | 1m | stress | 50 | 16.91 | 0.00 | 21.55 | 48.20 | - | 0 |
| plain-C SHA-256 | sealed copy | 1m | stress | 50 | 16.90 | 0.67 | 23.32 | 40.47 | 3% | 1057464 |
| plain-C SHA-256 | pathname | 8m | stress | 50 | 137.98 | 0.00 | 141.40 | 211.77 | - | 0 |
| plain-C SHA-256 | open descriptor | 8m | stress | 50 | 145.94 | 0.00 | 151.32 | 249.67 | - | 0 |
| plain-C SHA-256 | sealed copy | 8m | stress | 50 | 147.69 | 10.07 | 156.97 | 281.29 | 6% | 8397496 |
| plain-C SHA-256 | pathname | 32m | stress | 50 | 386.51 | 0.00 | 387.00 | 977.59 | - | 0 |
| plain-C SHA-256 | open descriptor | 32m | stress | 50 | 414.13 | 0.00 | 417.36 | 788.40 | - | 0 |
| plain-C SHA-256 | sealed copy | 32m | stress | 50 | 396.19 | 37.11 | 443.42 | 916.73 | 8% | 33563320 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 64k | idle | 50 | 0.10 | 0.00 | 0.35 | 1.09 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 64k | idle | 50 | 0.09 | 0.00 | 0.31 | 0.99 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 64k | idle | 50 | 0.09 | 0.06 | 0.49 | 1.12 | 11% | 74424 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 1m | idle | 50 | 0.65 | 0.00 | 1.00 | 1.40 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 1m | idle | 50 | 0.66 | 0.00 | 1.04 | 1.68 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 1m | idle | 50 | 0.64 | 0.37 | 1.49 | 2.01 | 25% | 1057464 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 8m | idle | 50 | 4.88 | 0.00 | 5.38 | 6.10 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 8m | idle | 50 | 4.87 | 0.00 | 5.41 | 9.22 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 8m | idle | 50 | 5.39 | 2.93 | 9.02 | 10.69 | 32% | 8397496 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 32m | idle | 50 | 19.47 | 0.00 | 20.04 | 21.89 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 32m | idle | 50 | 19.23 | 0.00 | 19.77 | 21.50 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 32m | idle | 50 | 20.26 | 10.43 | 31.60 | 39.63 | 33% | 33563320 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 64k | stress | 50 | 0.15 | 0.00 | 4.00 | 7.86 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 64k | stress | 50 | 0.17 | 0.00 | 4.05 | 8.36 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 64k | stress | 50 | 0.12 | 0.10 | 2.94 | 10.14 | 4% | 74424 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 1m | stress | 50 | 0.78 | 0.00 | 4.30 | 11.34 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 1m | stress | 50 | 0.78 | 0.00 | 5.67 | 11.55 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 1m | stress | 50 | 0.76 | 0.51 | 5.64 | 9.76 | 9% | 1057464 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 8m | stress | 50 | 10.22 | 0.00 | 14.42 | 23.27 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 8m | stress | 50 | 9.39 | 0.00 | 13.66 | 23.87 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 8m | stress | 50 | 13.82 | 4.09 | 23.22 | 38.01 | 18% | 8397496 |
| OpenSSL SHA-256 (SHA-NI) | pathname | 32m | stress | 50 | 43.56 | 0.00 | 50.45 | 105.03 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | open descriptor | 32m | stress | 50 | 44.59 | 0.00 | 52.19 | 89.02 | - | 0 |
| OpenSSL SHA-256 (SHA-NI) | sealed copy | 32m | stress | 50 | 48.62 | 26.70 | 81.41 | 122.42 | 33% | 33563320 |
