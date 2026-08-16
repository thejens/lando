/* RP2350 memory layout for the Pico 2 W: 4 MB of external flash and 520 KB of
   SRAM, of which the 512 KB main bank is contiguous (the remaining 8 KB is two
   separate scratch banks, not usable as one region). */
MEMORY {
    FLASH : ORIGIN = 0x10000000, LENGTH = 4096K
    RAM   : ORIGIN = 0x20000000, LENGTH = 512K
}

/* The RP2350 bootloader looks for a signed image block near the start of the
   image and refuses to run anything without one, so it has to be placed
   explicitly rather than left to the default section ordering. */
SECTIONS {
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH
} INSERT AFTER .vector_table;

_stext = ADDR(.start_block) + SIZEOF(.start_block);

/* Binary info: what `picotool info` reads back out of a flashed image. */
SECTIONS {
    .bi_entries : ALIGN(4)
    {
        __bi_entries_start = .;
        KEEP(*(.bi_entries));
        . = ALIGN(4);
        __bi_entries_end = .;
    } > FLASH
} INSERT AFTER .text;

SECTIONS {
    .end_block : ALIGN(4)
    {
        __end_block_addr = .;
        KEEP(*(.end_block));
    } > FLASH
} INSERT AFTER .bi_entries;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);
