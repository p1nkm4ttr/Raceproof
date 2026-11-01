# RaceProof top-level Makefile. Run inside WSL (Ubuntu).
#   make            build fixtures, broker, updater (whatever sources exist yet)
#   make check-env  verify kernel support for executable sealed memfds; writes results/env.txt
#   make fixtures   build prog_a / prog_b at four sizes, allowlist.txt, layout.txt
#   make experiment run every matrix in harness/config.yaml into results/
#   make plots      regenerate figures from results/*.csv
#   make clean

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
LDFLAGS ?=

BROKER_SRCS  := $(wildcard broker/*.c)
UPDATER_SRCS := $(wildcard updater/*.c)

.PHONY: all check-env fixtures broker updater experiment plots clean

all: fixtures broker updater

check-env:
	bash tools/check_env.sh

fixtures:
	bash fixtures/build.sh

broker: $(if $(BROKER_SRCS),broker/broker,)
updater: $(if $(UPDATER_SRCS),updater/updater,)

broker/broker: $(BROKER_SRCS) $(wildcard broker/*.h)
	$(CC) $(CFLAGS) -o $@ $(BROKER_SRCS) $(LDFLAGS)

updater/updater: $(UPDATER_SRCS)
	$(CC) $(CFLAGS) -o $@ $(UPDATER_SRCS) $(LDFLAGS)

experiment: all
	python3 harness/run_trials.py --all

plots:
	python3 analysis/plots.py

clean:
	rm -rf fixtures/bin broker/broker updater/updater
	find . -name '*.o' -delete
	find . -name '__pycache__' -type d -exec rm -rf {} +
