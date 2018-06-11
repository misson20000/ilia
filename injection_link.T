OUTPUT_FORMAT(elf64-littleaarch64)
ENTRY(main)

SECTIONS {
  .text : {
    LONG(mitm0)
    LONG(mitm1)
    LONG(mitm2)
    LONG(mitm3)
    LONG(mitm4)
    LONG(mitm5)
    LONG(mitm6)
    LONG(mitm7)
    LONG(mitm8)
    LONG(mitm9)
    LONG(mitm10)
    LONG(mitm11)
    LONG(mitm12)
    LONG(mitm13)
    LONG(mitm14)
    LONG(mitm15)
    
    KEEP(*(.text.main))
    *(.text .text*)
    *(.plt .plt*)
    *(.rodata .rodata*)
  }
}
