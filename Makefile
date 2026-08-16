# Host binary
.PHONY: test host node derp
test:            ; cargo test
host:            ; cargo run -p lando-host
node:            ; cargo run -p lando-host -- node
derp:            ; cargo run -p lando-host -- derp

# no_std check: the protocol core must always build for the target.
.PHONY: check-nostd
check-nostd:     ; cargo build --target thumbv8m.main-none-eabihf -p tailscale-core

# Firmware. Its own workspace, so its own cargo invocations.
.PHONY: fw flash cyw43-firmware
fw:              ; cd crates/lando-fw && cargo build --release
flash:           ; cd crates/lando-fw && cargo run --release

# Radio firmware is redistributable under its own permissive binary licence,
# not this repo's MIT, so it is fetched rather than vendored.
cyw43-firmware:
	@mkdir -p crates/lando-fw/cyw43-firmware
	@for f in 43439A0.bin 43439A0_clm.bin LICENSE-permissive-binary-license-1.0.txt; do \
	  curl -sL -o crates/lando-fw/cyw43-firmware/$$f \
	    https://raw.githubusercontent.com/embassy-rs/embassy/main/cyw43-firmware/$$f; \
	done
	@echo "fetched cyw43 firmware"
