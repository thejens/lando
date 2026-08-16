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
.PHONY: fw flash console reboot cyw43-firmware
fw:              ; cd crates/lando-fw && cargo build --release

# Flash. Reboots the running firmware into the bootloader first, so no one has
# to hold BOOTSEL: the board takes `b` on its console as "hand yourself back".
flash:
	@$(MAKE) -s reboot || true
	@sleep 3
	@cd crates/lando-fw && cargo run --release

reboot:
	@port=$$(ioreg -w0 -l -r -c IOSerialBSDClient 2>/dev/null | grep '"IOCalloutDevice"' \
	   | grep -oE '/dev/cu\.usbmodem[A-Za-z0-9_]+' | head -1); \
	 if [ -n "$$port" ]; then printf 'b' > "$$port" && echo "rebooting $$port into bootloader"; \
	 else echo "no lando console found; board may already be in BOOTSEL"; fi

console:
	@port=$$(ioreg -w0 -l -r -c IOSerialBSDClient 2>/dev/null | grep '"IOCalloutDevice"' \
	   | grep -oE '/dev/cu\.usbmodem[A-Za-z0-9_]+' | head -1); \
	 echo "attaching to $$port"; stty -f "$$port" 115200 2>/dev/null; cat "$$port"

# Radio firmware is redistributable under its own permissive binary licence,
# not this repo's MIT, so it is fetched rather than vendored.
cyw43-firmware:
	@mkdir -p crates/lando-fw/cyw43-firmware
	@for f in 43439A0.bin 43439A0_clm.bin nvram_rp2040.bin LICENSE-permissive-binary-license-1.0.txt; do \
	  curl -sL -o crates/lando-fw/cyw43-firmware/$$f \
	    https://raw.githubusercontent.com/embassy-rs/embassy/main/cyw43-firmware/$$f; \
	done
	@echo "fetched cyw43 firmware"
