Outcomes per policy and attack under free timing, CPU stress, all sizes and gaps pooled. Data: `run4_uncontrolled.csv`.

| Policy | Attack | n | CORRECT | MISMATCH | REJECT | EXEC_ERROR | HARNESS_ERROR | torn | mismatch rate (95% CI) |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| pathname | replace | 1200 | 302 | 284 | 614 | 0 | 0 | 0 | 23.67% (21.35-26.15) |
| pathname | rewrite text | 1200 | 267 | 297 | 628 | 8 | 0 | 0 | 24.75% (22.39-27.27) |
| pathname | rewrite tail | 1200 | 112 | 75 | 1010 | 3 | 0 | 0 | 6.25% (5.02-7.76) |
| open descriptor | replace | 1200 | 616 | 0 | 584 | 0 | 0 | 0 | 0.00% (0.00-0.32) |
| open descriptor | rewrite text | 1200 | 293 | 315 | 590 | 2 | 0 | 0 | 26.25% (23.84-28.81) |
| open descriptor | rewrite tail | 1200 | 138 | 83 | 975 | 4 | 0 | 0 | 6.92% (5.61-8.49) |
| sealed copy | replace | 1200 | 570 | 0 | 630 | 0 | 0 | 0 | 0.00% (0.00-0.32) |
| sealed copy | rewrite text | 1200 | 600 | 0 | 600 | 0 | 0 | 0 | 0.00% (0.00-0.32) |
| sealed copy | rewrite tail | 1200 | 556 | 0 | 644 | 0 | 0 | 67 | 0.00% (0.00-0.32) |
