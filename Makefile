CC ?= cc
CFLAGS ?= -Wall -Wextra -Werror -std=c11 -g -D_POSIX_C_SOURCE=200809L
BUILD ?= build
# A checkout of drimotta/nfse, built with `cargo build --lib`.
NFSE_DIR ?= ../../nfse
NFSE_LIB ?= $(NFSE_DIR)/target/debug
CJSON_CFLAGS := $(shell pkg-config --cflags libcjson)
CJSON_LIBS := $(shell pkg-config --libs libcjson)
AGENT_CFLAGS := $(CFLAGS) -I$(NFSE_DIR)/include $(CJSON_CFLAGS)
AGENT_LIBS := -L$(NFSE_LIB) -lnfse $(CJSON_LIBS) -Wl,-rpath,$(abspath $(NFSE_LIB))
CORE := src/agent.c src/http.c src/pairing.c
# Tests run with AddressSanitizer and UBSan.
SAN ?= -fsanitize=address,undefined -fno-omit-frame-pointer

UNIT_TESTS := $(patsubst tests/unit/%.c,$(BUILD)/%,$(wildcard tests/unit/test_*.c))

.PHONY: test unit
test: unit integration

unit: $(UNIT_TESTS)
	@for t in $(UNIT_TESTS); do echo "== $$t"; $$t || exit 1; done

$(BUILD)/test_http: tests/unit/test_http.c src/http.c src/http.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(SAN) -o $@ tests/unit/test_http.c src/http.c

$(BUILD)/test_pairing: tests/unit/test_pairing.c src/pairing.c src/pairing.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(SAN) -o $@ tests/unit/test_pairing.c src/pairing.c

$(BUILD)/test_agent: tests/unit/test_agent.c $(CORE) src/ui_fake.c src/*.h
	@mkdir -p $(BUILD)
	$(CC) $(AGENT_CFLAGS) $(SAN) -o $@ tests/unit/test_agent.c $(CORE) src/ui_fake.c $(AGENT_LIBS)

# The agent with scripted dialogs, for the integration tests.
$(BUILD)/cascalho-agent-test: src/main.c $(CORE) src/ui_fake.c src/*.h
	@mkdir -p $(BUILD)
	$(CC) $(AGENT_CFLAGS) $(SAN) -o $@ src/main.c $(CORE) src/ui_fake.c $(AGENT_LIBS)

.PHONY: integration
integration: $(BUILD)/cascalho-agent-test
	NFSE_DIR=$(abspath $(NFSE_DIR)) NFSE_LIB=$(abspath $(NFSE_LIB)) AGENT_BIN=$(abspath $<) \
		python3 -m unittest -v tests/integration/test_agent.py

# The agent with the platform's dialogs: Cocoa on macOS, GTK 4 elsewhere.
ifeq ($(shell uname),Darwin)
UI_SRC := src/ui_cocoa.m
UI_FLAGS := -fobjc-arc
UI_LIBS := -framework Cocoa
else
UI_SRC := src/ui_gtk.c
UI_FLAGS := $(shell pkg-config --cflags gtk4)
UI_LIBS := $(shell pkg-config --libs gtk4)
endif

.PHONY: agent
agent: $(BUILD)/cascalho-agent

$(BUILD)/cascalho-agent: src/main.c $(CORE) $(UI_SRC) src/*.h
	@mkdir -p $(BUILD)
	$(CC) $(AGENT_CFLAGS) $(UI_FLAGS) -O2 -o $@ src/main.c $(CORE) $(UI_SRC) $(AGENT_LIBS) $(UI_LIBS)
