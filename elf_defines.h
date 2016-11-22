#ifndef _ELF_DEFINES_H_
#define _ELF_DEFINES_H_

#define STB_GLOBAL      1
#define ELF32_ST_BIND(x)    ((x) >> 4)

#define DF_ORIGIN     0x00000001
#define DF_SYMBOLIC   0x00000002
#define DF_TEXTREL    0x00000004
#define DF_BIND_NOW   0x00000008
#define DF_STATIC_TLS 0x00000010


/* Processor specific relocation types */

#define R_ARM_NONE		0
#define R_ARM_PC24		1
#define R_ARM_ABS32		2
#define R_ARM_REL32		3
#define R_ARM_PC13		4
#define R_ARM_ABS16		5
#define R_ARM_ABS12		6
#define R_ARM_THM_ABS5		7
#define R_ARM_ABS8		8
#define R_ARM_SBREL32		9
#define R_ARM_THM_PC22		10
#define R_ARM_THM_PC8		11
#define R_ARM_AMP_VCALL9	12
#define R_ARM_SWI24		13
#define R_ARM_THM_SWI8		14
#define R_ARM_XPC25		15
#define R_ARM_THM_XPC22		16

/* TLS relocations */
#define R_ARM_TLS_DTPMOD32	17	/* ID of module containing symbol */
#define R_ARM_TLS_DTPOFF32	18	/* Offset in TLS block */
#define R_ARM_TLS_TPOFF32	19	/* Offset in static TLS block */

/* 20-31 are reserved for ARM Linux. */
#define R_ARM_COPY		20
#define R_ARM_GLOB_DAT		21
#define	R_ARM_JUMP_SLOT		22
#define R_ARM_RELATIVE		23
#define	R_ARM_GOTOFF		24
#define R_ARM_GOTPC		25
#define R_ARM_GOT32		26
#define R_ARM_PLT32		27

#define R_ARM_ALU_PCREL_7_0	32
#define R_ARM_ALU_PCREL_15_8	33
#define R_ARM_ALU_PCREL_23_15	34
#define R_ARM_ALU_SBREL_11_0	35
#define R_ARM_ALU_SBREL_19_12	36
#define R_ARM_ALU_SBREL_27_20	37

/* 96-111 are reserved to G++. */
#define R_ARM_GNU_VTENTRY	100
#define R_ARM_GNU_VTINHERIT	101
#define R_ARM_THM_PC11		102
#define R_ARM_THM_PC9		103

/* More TLS relocations */
#define R_ARM_TLS_GD32		104	/* PC-rel 32 bit for global dynamic */
#define R_ARM_TLS_LDM32		105	/* PC-rel 32 bit for local dynamic */
#define R_ARM_TLS_LDO32		106	/* 32 bit offset relative to TLS */
#define R_ARM_TLS_IE32		107	/* PC-rel 32 bit for GOT entry of */
#define R_ARM_TLS_LE32		108
#define R_ARM_TLS_LDO12		109
#define R_ARM_TLS_LE12		110
#define R_ARM_TLS_IE12GP	111

/* 112-127 are reserved for private experiments. */

#define R_ARM_RXPC25		249
#define R_ARM_RSBREL32		250
#define R_ARM_THM_RPC22		251
#define R_ARM_RREL32		252
#define R_ARM_RABS32		253
#define R_ARM_RPC24		254
#define R_ARM_RBASE		255

#define R_386_NONE 0
#define R_386_32 1
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
#define R_386_PC32 2
#define R_386_GOT32 3
#define R_386_PLT32 4
#define R_386_COPY 5
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
#define R_386_GLOB_DAT 6
#define R_386_JMP_SLOT 7
#define R_386_RELATIVE 8
#define R_386_GOTOFF 9
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
#define R_386_GOTPC 10
#define R_386_NUM 11
#define ELF_CLASS ELFCLASS32
#define ELF_DATA ELFDATA2LSB
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
#define ELF_ARCH EM_386

#define R_TYPE(name)		__CONCAT(R_ARM_,name)

/* Processor specific program header flags */
#define PF_ARM_SB		0x10000000
#define PF_ARM_PI		0x20000000
#define PF_ARM_ENTRY		0x80000000

/* Processor specific section header flags */
#define SHF_ENTRYSECT		0x10000000
#define SHF_COMDEF		0x80000000

/* Processor specific symbol types */
#define STT_ARM_TFUNC		STT_LOPROC

/* d_tag */
#define DT_NULL		0	/* Marks end of dynamic array */
#define DT_NEEDED	1	/* Name of needed library (DT_STRTAB offset) */
#define DT_PLTRELSZ	2	/* Size, in bytes, of relocations in PLT */
#define DT_PLTGOT	3	/* Address of PLT and/or GOT */
#define DT_HASH		4	/* Address of symbol hash table */
#define DT_STRTAB	5	/* Address of string table */
#define DT_SYMTAB	6	/* Address of symbol table */
#define DT_RELA		7	/* Address of Rela relocation table */
#define DT_RELASZ	8	/* Size, in bytes, of DT_RELA table */
#define DT_RELAENT	9	/* Size, in bytes, of one DT_RELA entry */
#define DT_STRSZ	10	/* Size, in bytes, of DT_STRTAB table */
#define DT_SYMENT	11	/* Size, in bytes, of one DT_SYMTAB entry */
#define DT_INIT		12	/* Address of initialization function */
#define DT_FINI		13	/* Address of termination function */
#define DT_SONAME	14	/* Shared object name (DT_STRTAB offset) */
#define DT_RPATH	15	/* Library search path (DT_STRTAB offset) */
#define DT_SYMBOLIC	16	/* Start symbol search within local object */
#define DT_REL		17	/* Address of Rel relocation table */
#define DT_RELSZ	18	/* Size, in bytes, of DT_REL table */
#define DT_RELENT	19	/* Size, in bytes, of one DT_REL entry */
#define DT_PLTREL	20	/* Type of PLT relocation entries */
#define DT_DEBUG	21	/* Used for debugging; unspecified */
#define DT_TEXTREL	22	/* Relocations might modify non-writable seg */
#define DT_JMPREL	23	/* Address of relocations associated with PLT */
#define DT_BIND_NOW	24	/* Process all relocations at load-time */
#define DT_INIT_ARRAY	25	/* Address of initialization function array */
#define DT_FINI_ARRAY	26	/* Size, in bytes, of DT_INIT_ARRAY array */
#define DT_INIT_ARRAYSZ 27	/* Address of termination function array */
#define DT_FINI_ARRAYSZ 28	/* Size, in bytes, of DT_FINI_ARRAY array*/
#define DT_NUM		29
#define DT_FLAGS 30
/* glibc and BSD disagree for DT_ENCODING; glibc looks wrong. */
#define DT_PREINIT_ARRAY 32
#define DT_PREINIT_ARRAYSZ 33

#define DT_LOOS		0x60000000	/* Operating system specific range */
#define DT_VERSYM	0x6ffffff0	/* Symbol versions */
#define DT_FLAGS_1	0x6ffffffb	/* ELF dynamic flags */
#define DT_VERDEF	0x6ffffffc	/* Versions defined by file */
#define DT_VERDEFNUM	0x6ffffffd	/* Number of versions defined by file */
#define DT_VERNEED	0x6ffffffe	/* Versions needed by file */
#define DT_VERNEEDNUM	0x6fffffff	/* Number of versions needed by file */
#define DT_HIOS		0x6fffffff
#define DT_LOPROC	0x70000000	/* Processor-specific range */
#define DT_HIPROC	0x7fffffff

/* p_type */
#define PT_NULL		0		/* Program header table entry unused */
#define PT_LOAD		1		/* Loadable program segment */
#define PT_DYNAMIC	2		/* Dynamic linking information */
#define PT_INTERP	3		/* Program interpreter */
#define PT_NOTE		4		/* Auxiliary information */
#define PT_SHLIB	5		/* Reserved, unspecified semantics */
#define PT_PHDR		6		/* Entry for header table itself */
#define PT_TLS		7		/* TLS initialisation image */
#define PT_NUM		8

#define PT_LOOS		0x60000000	/* OS-specific range */

/* GNU-specific */
#define PT_GNU_EH_FRAME 0x6474e550	/* EH frame segment */
#define PT_GNU_STACK	0x6474e551	/* Indicate executable stack */
#define PT_GNU_RELRO	0x6474e552	/* Make read-only after relocation */

/* r_info utility macros */
#define ELF32_R_SYM(info)	((info) >> 8)
#define ELF32_R_TYPE(info)	((info) & 0xff)
#define ELF32_R_INFO(sym, type) (((sym) << 8) + (unsigned char)(type))

/* st_info: Symbol Bindings */
#define STB_LOCAL		0	/* local symbol */
#define STB_GLOBAL		1	/* global symbol */
#define STB_WEAK		2	/* weakly defined global symbol */
#define STB_NUM			3

/* p_flags */
#define PF_R		0x4		/* Segment is readable */
#define PF_W		0x2		/* Segment is writable */
#define PF_X		0x1		/* Segment is executable */
/*
 * Special section indexes
 */
#define SHN_UNDEF	0		/* Undefined section */

#define SHN_LORESERVE	0xff00		/* Reserved range */
#define SHN_ABS		0xfff1		/*  Absolute symbols */
#define SHN_COMMON	0xfff2		/*  Common symbols */
#define SHN_XINDEX	0xffff		/* Escape -- index stored elsewhere */
#define SHN_HIRESERVE	0xffff

#define SHN_LOPROC	0xff00		/* Processor-specific range */
#define SHN_HIPROC	0xff1f
#define SHN_LOOS	0xff20		/* Operating system specific range */
#define SHN_HIOS	0xff3f

#define SHN_MIPS_ACOMMON 0xff00
#define SHN_MIPS_TEXT	0xff01
#define SHN_MIPS_DATA	0xff02
#define SHN_MIPS_SCOMMON 0xff03

/* e_ident offsets */
#define EI_MAG0		0	/* '\177' */
#define EI_MAG1		1	/* 'E'	  */
#define EI_MAG2		2	/* 'L'	  */
#define EI_MAG3		3	/* 'F'	  */
#define EI_CLASS	4	/* File class */
#define EI_DATA		5	/* Data encoding */
#define EI_VERSION	6	/* File version */
#define EI_OSABI	7	/* Operating system/ABI identification */
#define EI_ABIVERSION	8	/* ABI version */
#define EI_PAD		9	/* Start of padding bytes up to EI_NIDENT*/
#define EI_NIDENT	16	/* First non-ident header byte */

/* e_ident[EI_MAG0,EI_MAG3] */
#define ELFMAG0		0x7f
#define ELFMAG1		'E'
#define ELFMAG2		'L'
#define ELFMAG3		'F'
#define ELFMAG		"\177ELF"
#define SELFMAG		4

/* e_ident[EI_CLASS] */
#define ELFCLASSNONE	0	/* Invalid class */
#define ELFCLASS32	1	/* 32-bit objects */
#define ELFCLASS64	2	/* 64-bit objects */
#define ELFCLASSNUM	3

/* e_ident[EI_DATA] */
#define ELFDATANONE	0	/* Invalid data encoding */
#define ELFDATA2LSB	1	/* 2's complement values, LSB first */
#define ELFDATA2MSB	2	/* 2's complement values, MSB first */

/* e_ident[EI_VERSION] */
#define EV_NONE		0	/* Invalid version */
#define EV_CURRENT	1	/* Current version */
#define EV_NUM		2

#define EM_386      3
#define EM_MIPS     8
#define EM_ARM		40	/* Advanced RISC Machines ARM */

/* e_type */
#define ET_NONE		0	/* No file type */
#define ET_REL		1	/* Relocatable file */
#define ET_EXEC		2	/* Executable file */
#define ET_DYN		3	/* Shared object file */
#define ET_CORE		4	/* Core file */
#define ET_NUM		5

#endif
