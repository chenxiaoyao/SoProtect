#ifndef _LINKER_H_
#define _LINKER_H_

#include <unistd.h>
#include <sys/types.h>
#include <elf.h>
#include <android/log.h>

#include <link.h>

#include "elf_defines.h"

#define TRACE(...) __android_log_print(ANDROID_LOG_INFO, "linker", __VA_ARGS__)
#define DEBUG(...) __android_log_print(ANDROID_LOG_DEBUG, "linker", __VA_ARGS__)
#define DL_ERR(...) __android_log_print(ANDROID_LOG_ERROR, "linker", __VA_ARGS__)

// Returns the address of the page containing address 'x'.
#define PAGE_START(x)  ((x) & PAGE_MASK)

// Returns the offset of address 'x' in its page.
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)

// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))

// Magic shared structures that GDB knows about.

struct link_map_t {
  uintptr_t l_addr;
  char*  l_name;
  uintptr_t l_ld;
  link_map_t* l_next;
  link_map_t* l_prev;
};

#define FLAG_LINKED     0x00000001
#define FLAG_EXE        0x00000004 // The main executable
#define FLAG_LINKER     0x00000010 // The linker itself

#define SOINFO_NAME_LEN 128

typedef void (*linker_function_t)();

struct soinfo {
 public:
  char name[SOINFO_NAME_LEN];
  const Elf32_Phdr* phdr;
  size_t phnum;
  Elf32_Addr entry;
  Elf32_Addr base;
  unsigned size;

  uint32_t unused1;  // DO NOT USE, maintained for compatibility.

  Elf32_Dyn* dynamic;

  uint32_t unused2; // DO NOT USE, maintained for compatibility
  uint32_t unused3; // DO NOT USE, maintained for compatibility

  soinfo* next;
  unsigned flags;

  const char* strtab;
  Elf32_Sym* symtab;

  size_t nbucket;
  size_t nchain;
  unsigned* bucket;
  unsigned* chain;

  unsigned* plt_got;

  Elf32_Rel* plt_rel;
  size_t plt_rel_count;

  Elf32_Rel* rel;
  size_t rel_count;

  linker_function_t* preinit_array;
  size_t preinit_array_count;

  linker_function_t* init_array;
  size_t init_array_count;
  linker_function_t* fini_array;
  size_t fini_array_count;

  linker_function_t init_func;
  linker_function_t fini_func;

#if defined(ANDROID_ARM_LINKER)
  // ARM EABI section used for stack unwinding.
  unsigned* ARM_exidx;
  size_t ARM_exidx_count;
#elif defined(ANDROID_MIPS_LINKER)
  unsigned mips_symtabno;
  unsigned mips_local_gotno;
  unsigned mips_gotsym;
#endif

  size_t ref_count;
  link_map_t link_map;

  bool constructors_called;

  // When you read a virtual address from the ELF file, add this
  // value to get the corresponding address in the process' address space.
  Elf32_Addr load_bias;

  bool has_text_relocations;
  bool has_DT_SYMBOLIC;

  void CallConstructors();
  void CallDestructors();
  void CallPreInitConstructors();

 private:
  void CallArray(const char* array_name, linker_function_t* functions, size_t count, bool reverse);
  void CallFunction(const char* function_name, linker_function_t function);
};

extern soinfo libdl_info;

// These aren't defined in <sys/exec_elf.h>.
#ifndef DT_PREINIT_ARRAY
#define DT_PREINIT_ARRAY   32
#endif
#ifndef DT_PREINIT_ARRAYSZ
#define DT_PREINIT_ARRAYSZ 33
#endif

void do_android_update_LD_LIBRARY_PATH(const char* ld_library_path);
soinfo* do_dlopen(const char* name, int flags);
int do_dlclose(soinfo* si);

Elf32_Sym* dlsym_linear_lookup(const char* name, soinfo** found, soinfo* start);
soinfo* find_containing_library(const void* addr);

Elf32_Sym* dladdr_find_symbol(soinfo* si, const void* addr);
Elf32_Sym* dlsym_handle_lookup(soinfo* si, const char* name);

void debuggerd_init();

char* linker_get_error_buffer();
size_t linker_get_error_buffer_size();

#ifdef __arm__
typedef long unsigned int* _Unwind_Ptr;
extern "C" _Unwind_Ptr dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount);
#else
extern "C" int dl_iterate_phdr(int (*cb)(struct dl_phdr_info*, size_t, void*), void*);
#endif

#endif
