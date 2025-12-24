.PHONY: build install clean

build:
	rm -rf target
	cargo build --release
	upx --best --lzma target/release/nyapass

install: build
	cp target/release/nyapass ~/.cargo/bin/

clean:
	cargo clean
