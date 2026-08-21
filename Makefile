.PHONY: build clean

build:
	@mkdir -p bin
	@rm -f bin/tap
	@cargo build --release
	@cp target/release/tap bin/tap

clean:
	@cargo clean
	@rm -rf bin
