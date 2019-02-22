OUTPUT_FORMAT(elf64-littleaarch64)
ENTRY(main)

PHDRS {
  text PT_LOAD FLAGS(5);
}

SECTIONS {
  . = 0;
  
  .text : {
/*    . = 0; */
    LONG(mitm0)
    LONG(mitm1)
    LONG(mitm2)
    LONG(mitm3)
    LONG(mitm4)
    LONG(mitm5)
    LONG(mitm6)
    LONG(mitm7)
    
    KEEP(*(.text.main))
    *(.text .text*)
    *(.plt .plt*)
    *(.rodata .rodata*)
  } :text

	/* ==================
	   ==== Metadata ====
	   ================== */

	/* Discard sections that difficult post-processing */
	/DISCARD/ : { *(.group .comment .note) }

	.eh_frame_hdr     : { __eh_frame_hdr_start = .; *(.eh_frame_hdr) *(.eh_frame_entry .eh_frame_entry.*) __eh_frame_hdr_end = .; }
	.eh_frame         : ONLY_IF_RO { KEEP (*(.eh_frame)) *(.eh_frame.*) }
	.gcc_except_table : ONLY_IF_RO { *(.gcc_except_table .gcc_except_table.*) }
	.gnu_extab        : ONLY_IF_RO { *(.gnu_extab*) }

	/* Stabs debugging sections. */
	.stab          0 : { *(.stab) }
	.stabstr       0 : { *(.stabstr) }
	.stab.excl     0 : { *(.stab.excl) }
	.stab.exclstr  0 : { *(.stab.exclstr) }
	.stab.index    0 : { *(.stab.index) }
	.stab.indexstr 0 : { *(.stab.indexstr) }

	/* DWARF debug sections.
	   Symbols in the DWARF debugging sections are relative to the beginning
	   of the section so we begin them at 0. */

	/* DWARF 1 */
	.debug          0 : { *(.debug) }
	.line           0 : { *(.line) }

	/* GNU DWARF 1 extensions */
	.debug_srcinfo  0 : { *(.debug_srcinfo) }
	.debug_sfnames  0 : { *(.debug_sfnames) }

	/* DWARF 1.1 and DWARF 2 */
	.debug_aranges  0 : { *(.debug_aranges) }
	.debug_pubnames 0 : { *(.debug_pubnames) }

	/* DWARF 2 */
	.debug_info     0 : { *(.debug_info) }
	.debug_abbrev   0 : { *(.debug_abbrev) }
	.debug_line     0 : { *(.debug_line) }
	.debug_frame    0 : { *(.debug_frame) }
	.debug_str      0 : { *(.debug_str) }
	.debug_loc      0 : { *(.debug_loc) }
	.debug_macinfo  0 : { *(.debug_macinfo) }
}
