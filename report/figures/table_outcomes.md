Outcomes per policy and attack under free timing, CPU stress, all sizes and gaps pooled. Data: `run2_uncontrolled.csv`.

| Policy | Attack | n | CORRECT | MISMATCH | REJECT | EXEC_ERROR | HARNESS_ERROR | torn | mismatch rate (95% CI) |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| pathname | replace | 1200 | 342 | 288 | 570 | 0 | 0 | 0 | 24.00% (21.67-26.50) |
| pathname | rewrite text | 1200 | 299 | 282 | 609 | 10 | 0 | 0 | 23.50% (21.19-25.98) |
| pathname | rewrite tail | 1200 | 206 | 141 | 838 | 15 | 0 | 0 | 11.75% (10.05-13.70) |
| open descriptor | replace | 1200 | 597 | 0 | 603 | 0 | 0 | 0 | 0.00% (0.00-0.32) |
| open descriptor | rewrite text | 1200 | 278 | 275 | 634 | 13 | 0 | 0 | 22.92% (20.63-25.38) |
| open descriptor | rewrite tail | 1200 | 184 | 140 | 855 | 21 | 0 | 0 | 11.67% (9.97-13.61) |
| sealed copy | replace | 1200 | 560 | 0 | 640 | 0 | 0 | 0 | 0.00% (0.00-0.32) |
| sealed copy | rewrite text | 1200 | 625 | 0 | 575 | 0 | 0 | 0 | 0.00% (0.00-0.32) |
| sealed copy | rewrite tail | 1200 | 558 | 0 | 642 | 0 | 0 | 95 | 0.00% (0.00-0.32) |
