# RaceProof top-level Makefile. Run inside WSL (Ubuntu).
#   make            build fixtures, broker, updater (whatever sources exist yet)
#   make check-env  verify kernel support for executable sealed memfds; writes results/env.txt
#   make fixtures   build prog_a / prog_b at four sizes, allowlist.txt, layout.txt
#   make experiment run every matrix in harness/config.json into results/
#   make plots      regenerate figures from results/*.csv (report versions in report/figures/paper/)
#   make broker HASH=openssl   broker with OpenSSL SHA-256 (SHA-NI) instead of the vendored one
#   make clean

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
LDFLAGS ?=

BROKER_SRCS  := $(wildcard broker/*.c)
UPDATER_SRCS := $(wildcard updater/*.c)

# HASH=vendored (default) hashes with broker/sha256.c; HASH=openssl links libcrypto and uses
# EVP SHA-256, which runs on SHA-NI where the CPU has it (needs libssl-dev). Same digests,
# different speed; every record names the implementation in hash_impl. Rebuild when switching.
HASH ?= vendored
ifeq ($(HASH),openssl)
  BROKER_SRCS := $(filter-out broker/sha256.c,$(BROKER_SRCS))
  BROKER_CFLAGS := -DRP_HASH_OPENSSL
  BROKER_LIBS   := -lcrypto
endif

.PHONY: all check-env fixtures broker updater experiment plots clean

all: fixtures broker updater

check-env:
	bash tools/check_env.sh

fixtures:
	bash fixtures/build.sh

broker: $(if $(BROKER_SRCS),broker/broker,)
updater: $(if $(UPDATER_SRCS),updater/updater,)

# The stamp makes a change of HASH rebuild the broker even when no source changed.
broker/.hash_$(HASH):
	rm -f broker/.hash_*
	touch $@

broker/broker: $(BROKER_SRCS) $(wildcard broker/*.h) Makefile broker/.hash_$(HASH)
	$(CC) $(CFLAGS) $(BROKER_CFLAGS) -o $@ $(BROKER_SRCS) $(LDFLAGS) $(BROKER_LIBS)

updater/updater: $(UPDATER_SRCS)
	$(CC) $(CFLAGS) -o $@ $(UPDATER_SRCS) $(LDFLAGS)

RUN ?= $(shell date +run%Y%m%dT%H%M)

experiment: all
	python3 harness/run_trials.py --all --run-id $(RUN)

quick: all
	rm -f results/quick.csv
	python3 harness/run_trials.py --matrix controlled --quick --out results/quick.csv
	python3 analysis/summarize.py results/quick.csv

# Draws the published dataset (run 4, made by tools/full_run.sh from a committed tree), not whatever ran
# last. For another run:  python3 analysis/plots.py --run <run_id> --out <dir>
# Run 2 as it was published before run 4:
#   python3 analysis/plots.py --run run2 --overhead results/run2b_overhead.csv \
#       --overhead-fast results/run3b_openssl_overhead.csv --paper --out <dir>
plots:
	python3 analysis/plots.py --run run4 --overhead-fast results/run4_openssl_overhead.csv --paper

clean:
	rm -rf fixtures/bin broker/broker broker/.hash_* updater/updater
	find . -name '*.o' -delete
	find . -name '__pycache__' -type d -exec rm -rf {} +
