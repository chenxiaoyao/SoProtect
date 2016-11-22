#include "linker.h"
#include "gdlfcn.h"
#include "Log.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static void __bionic_format_dlerror(const char* msg, const char* detail) {
    GLogError("gdlfcn", "Message: %s, Detail: %s", msg, detail);
}

const char* gdlerror() {
  return 0;
}

void* gdlopen(const char* filename, int flags, unsigned long offset) {
  soinfo* result = do_dlopen(filename, flags, NULL, offset);
  if (result == NULL) {
    __bionic_format_dlerror("gdlopen failed", linker_get_error_buffer());
    return NULL;
  }
  return result;
}

void* gdlsym(void* handle, const char* symbol) {

#if !defined(__LP64__)
  if (handle == NULL) {
    __bionic_format_dlerror("gdlsym library handle is null", NULL);
    return NULL;
  }
#endif

  if (symbol == NULL) {
    __bionic_format_dlerror("gdlsym symbol name is null", NULL);
    return NULL;
  }

  soinfo* found = NULL;
  ElfW(Sym)* sym = NULL;
  if (handle == RTLD_DEFAULT) {
    sym = dlsym_linear_lookup(symbol, &found, NULL);
  } else if (handle == RTLD_NEXT) {
      void* caller_addr = __builtin_return_address(0);
      soinfo* si = find_containing_library(caller_addr);

    sym = NULL;
    if (si && si->next) {
      sym = dlsym_linear_lookup(symbol, &found, si->next);
    }
  } else {
      sym = dlsym_handle_lookup(reinterpret_cast<soinfo*>(handle), &found, symbol);
  }

  if (sym != NULL) {
    unsigned bind = ELF32_ST_BIND(sym->st_info);

    if ((bind == STB_GLOBAL || bind == STB_WEAK) && sym->st_shndx != 0) {
      return reinterpret_cast<void*>(sym->st_value + found->load_bias);
    }

    __bionic_format_dlerror("symbol found but not global", symbol);
    return NULL;
  } else {
    __bionic_format_dlerror("undefined symbol", symbol);
    return NULL;
  }
}

int gdladdr(const void* addr, Dl_info* info) {
  // Determine if this address can be found in any library currently mapped.
  soinfo* si = find_containing_library(addr);
  if (si == NULL) {
    return 0;
  }

  memset(info, 0, sizeof(Dl_info));

  info->dli_fname = si->name;
  // Address at which the shared object is loaded.
  info->dli_fbase = reinterpret_cast<void*>(si->base);

  // Determine if any symbol in the library contains the specified address.
  ElfW(Sym)* sym = dladdr_find_symbol(si, addr);
  if (sym != NULL) {
    info->dli_sname = si->strtab + sym->st_name;
    info->dli_saddr = reinterpret_cast<void*>(si->load_bias + sym->st_value);
  }

  return 1;
}

int gdlclose(void* handle) {
    do_dlclose(reinterpret_cast<soinfo*>(handle));
    // dlclose has no defined errors.
    return 0;
}

// name_offset: starting index of the name in libdl_info.strtab
#define ELF32_SYM_INITIALIZER(name_offset, value, shndx) \
    { name_offset, \
      reinterpret_cast<ElfW(Addr)>(reinterpret_cast<void*>(value)), \
      /* st_size */ 0, \
      (shndx == 0) ? 0 : (STB_GLOBAL << 4), \
      /* st_other */ 0, \
      shndx, \
    }

#define ELF64_SYM_INITIALIZER(name_offset, value, shndx) \
    { name_offset, \
      (shndx == 0) ? 0 : (STB_GLOBAL << 4), \
      /* st_other */ 0, \
      shndx, \
      reinterpret_cast<Elf64_Addr>(reinterpret_cast<void*>(value)), \
      /* st_size */ 0, \
    }


#if defined(__arm__)
//   0000000 00011111 111112 22222222 2333333 3333444444444455 555555556666666 6667
//   0123456 78901234 567890 12345678 9012345 6789012345678901 234567890123456 7890
#define ANDROID_LIBDL_STRTAB \
    "dlopen\0dlclose\0dlsym\0dlerror\0dladdr\0dl_iterate_phdr\0dl_unwind_find_exidx\0"

#elif defined(__aarch64__) || defined(__i386__) || defined(__mips__) || defined(__x86_64__)
//   0000000 00011111 111112 22222222 2333333 3333444444444455555555556666666 6667
//   0123456 78901234 567890 12345678 9012345 6789012345678901234567890123456 7890
#define ANDROID_LIBDL_STRTAB \
    "dlopen\0dlclose\0dlsym\0dlerror\0dladdr\0dl_iterate_phdr\0"
#else
#error Unsupported architecture. Only arm, arm64, mips, mips64, x86 and x86_64 are presently supported.
#endif

static ElfW(Sym) g_libdl_symtab[] = {
  // Total length of libdl_info.strtab, including trailing 0.
  // This is actually the STH_UNDEF entry. Technically, it's
  // supposed to have st_name == 0, but instead, it points to an index
  // in the strtab with a \0 to make iterating through the symtab easier.
  ELFW(SYM_INITIALIZER)(sizeof(ANDROID_LIBDL_STRTAB) - 1, NULL, 0),
  ELFW(SYM_INITIALIZER)( 0, &gdlopen, 1),
  ELFW(SYM_INITIALIZER)( 7, &gdlclose, 1),
  ELFW(SYM_INITIALIZER)(15, &gdlsym, 1),
  ELFW(SYM_INITIALIZER)(21, &gdlerror, 1),
  ELFW(SYM_INITIALIZER)(29, &gdladdr, 1),
  ELFW(SYM_INITIALIZER)(36, &dl_iterate_phdr, 1),
#if defined(__arm__)
  ELFW(SYM_INITIALIZER)(52, &dl_unwind_find_exidx, 1),
#endif
};

// Fake out a hash table with a single bucket.
//
// A search of the hash table will look through g_libdl_symtab starting with index 1, then
// use g_libdl_chains to find the next index to look at. g_libdl_chains should be set up to
// walk through every element in g_libdl_symtab, and then end with 0 (sentinel value).
//
// That is, g_libdl_chains should look like { 0, 2, 3, ... N, 0 } where N is the number
// of actual symbols, or nelems(g_libdl_symtab)-1 (since the first element of g_libdl_symtab is not
// a real symbol). (See soinfo_elf_lookup().)
//
// Note that adding any new symbols here requires stubbing them out in libdl.
static unsigned g_libdl_buckets[1] = { 1 };
#if defined(__arm__)
static unsigned g_libdl_chains[] = { 0, 2, 3, 4, 5, 6, 7, 0 };
#else
static unsigned g_libdl_chains[] = { 0, 2, 3, 4, 5, 6, 0 };
#endif

// Defined as global because we do not yet have access
// to synchronization functions __cxa_guard_* needed
// to define statics inside functions.
static soinfo __libdl_info;

// This is used by the dynamic linker. Every process gets these symbols for free.
soinfo* get_libdl_info() {
  if (__libdl_info.name[0] == '\0') {
    // initialize
    strncpy(__libdl_info.name, "libdl.so", sizeof(__libdl_info.name));
    __libdl_info.flags = FLAG_LINKED | FLAG_NEW_SOINFO;
    __libdl_info.strtab = ANDROID_LIBDL_STRTAB;
    __libdl_info.symtab = g_libdl_symtab;
    __libdl_info.nbucket = sizeof(g_libdl_buckets)/sizeof(unsigned);
    __libdl_info.nchain = sizeof(g_libdl_chains)/sizeof(unsigned);
    __libdl_info.bucket = g_libdl_buckets;
    __libdl_info.chain = g_libdl_chains;
    __libdl_info.has_DT_SYMBOLIC = true;
  }

  return &__libdl_info;
}

