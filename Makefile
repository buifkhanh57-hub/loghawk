# loghawk - Makefile
# Core Perl only; no external dependencies to install.

PERL      ?= perl
PROVE     ?= prove
PERL5LIB  := lib
export PERL5LIB

BIN       := bin/loghawk
LIBS      := $(wildcard lib/LogHawk/*.pm) lib/LogHawk.pm
TESTS     := $(wildcard t/*.t)
SAMPLE    := examples/sample_access.log

.PHONY: all test tests verbose smoke smoke-stats smoke-spikes smoke-report \
        parse-diag compile clean help

all: compile test

help:
	@echo "loghawk make targets:"
	@echo "  make test          run the test suite (prove)"
	@echo "  make verbose       run tests with full TAP output"
	@echo "  make compile       syntax-check bin + all modules"
	@echo "  make smoke         run every subcommand on the sample log"
	@echo "  make smoke-stats   quick stats run"
	@echo "  make smoke-spikes  anomaly detection run"
	@echo "  make smoke-report  render text + html reports to /tmp"
	@echo "  make clean         remove generated reports/artifacts"

compile:
	@set -e; for f in $(BIN) $(LIBS); do \
		$(PERL) -c $$f >/dev/null || exit 1; \
		echo "ok  $$f"; \
	done

test tests:
	$(PROVE) -Ilib $(TESTS)

verbose:
	$(PERL) -Ilib -MTest::Harness -e 'runtests(@ARGV)' $(TESTS)

smoke: smoke-stats smoke-spikes smoke-report
	@echo "smoke: all subcommand checks passed"

smoke-stats:
	$(PERL) -Ilib $(BIN) stats $(SAMPLE) | head -30

smoke-spikes:
	$(PERL) -Ilib $(BIN) spikes --sensitivity medium $(SAMPLE)

smoke-report: 
	$(PERL) -Ilib $(BIN) report --format text  --output /tmp/loghawk_report.txt  $(SAMPLE)
	$(PERL) -Ilib $(BIN) report --format html  --output /tmp/loghawk_report.html $(SAMPLE)
	$(PERL) -Ilib $(BIN) report --format md    --output /tmp/loghawk_report.md   $(SAMPLE)
	@wc -l /tmp/loghawk_report.txt /tmp/loghawk_report.html /tmp/loghawk_report.md

parse-diag:
	$(PERL) -Ilib $(BIN) parse --diag --limit 10 $(SAMPLE)

clean:
	rm -f /tmp/loghawk_report.txt /tmp/loghawk_report.html /tmp/loghawk_report.md
	rm -f examples/*.out examples/report.*
