PYTHON ?= python3
UNSHARE ?= unshare

.PHONY: all check test test-nfq test-engine test-dns test-config test-guard test-zapret install uninstall clean

all: check

check:
	$(PYTHON) -m compileall -q nadejda tests run.py
	@echo "syntax ok"

test-nfq:
	$(UNSHARE) -Urn $(PYTHON) tests/netns_nfq_smoke.py

test-engine:
	$(UNSHARE) -Urn $(PYTHON) tests/netns_engine_test.py

test-dns:
	$(UNSHARE) -Urn $(PYTHON) tests/netns_dns_test.py

test-config:
	$(PYTHON) tests/config_test.py

test-guard:
	$(PYTHON) tests/guard_test.py

test-zapret:
	$(PYTHON) tests/zapret_test.py

test: check test-config test-guard test-zapret test-nfq test-engine test-dns
	@echo "all tests passed"

install:
	sudo ./install.sh

uninstall:
	sudo ./install.sh --uninstall

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache
