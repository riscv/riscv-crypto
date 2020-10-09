
ENTRY(_start)

MEMORY {
    rom ( rx)    : ORIGIN = 0x00001000, LENGTH = 16K
    ram (wrx)    : ORIGIN = 0x80000000, LENGTH = 128M
}

SECTIONS {

    . = ORIGIN(ram);

    .text : {
        *(.text.*)
        *(.text)
    } > ram
    .data  : { *(.data.*) } > ram
    .bss   : { *(.bss)    } > ram
    .sbss  : { *(.sbss)    } > ram

    /DISCARD/ : { *(.comment) }

}

