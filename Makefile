.DEFAULT_GOAL := help
.PHONY: help build test clean

help:
	@printf '%s\n' \
		'Usage: make <target>' \
		'' \
		'Targets:' \
		'  help   Show this help message' \
		'  build  Build the release binary' \
		'  test   Run the test suite' \
		'  clean  Remove build artifacts'

build:
	@mkdir -p bin
	@rm -f bin/tap
	@cargo build --release
	@cp target/release/tap bin/tap

test:
	@cargo test

clean:
	@cargo clean
	@rm -rf bin
