#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <android/log.h>

#include "linker.h"
#include "linker_phdr.h"
#include "linker_allocator.h"
#include "extra_defines.h"
#include "ScopedFd.h"
#include "gdlfcn.h"

/* >>> IMPORTANT NOTE - READ ME BEFORE MODIFYING <<<
 *
 * Do NOT use malloc() and friends or pthread_*() code here.
 * Don't use printf() either; it's caused mysterious memory
 * corruption in the past.
 * The linker runs before we bring up libc and it's easiest
 * to make sure it does not depend on any complex libc features
 *
 * open issues / todo:
 *
 * - cleaner error reporting
 * - after linking, set as much stuff as possible to READONLY
 *   and NOEXEC
 */

#if defined(__LP64__)
#define SEARCH_NAME(x) x
#else
// Nvidia drivers are relying on the bug:
// http://code.google.com/p/android/issues/detail?id=6670
// so we continue to use base-name lookup for lp32
static const char* get_base_name(const char* name) {
  const char* bname = strrchr(name, '/');
  return bname ? bname + 1 : name;
}
#define SEARCH_NAME(x) get_base_name(x)
#endif

static bool soinfo_link_image(soinfo* si, const android_dlextinfo* extinfo);
static ElfW(Addr) get_elf_exec_load_bias(const ElfW(Ehdr)* elf);

static LinkerAllocator<soinfo> g_soinfo_allocator;
static LinkerAllocator<LinkedListEntry<soinfo>> g_soinfo_links_allocator;

static soinfo* solist = get_libdl_info();
static soinfo* sonext = solist;
static soinfo* somain; /* main process, always the one after libdl_info */

static const char* const kDefaultLdPaths[] = {
#if defined(__LP64__)
  "/vendor/lib64",
  "/system/lib64",
#else
  "/vendor/lib",
  "/system/lib",
#endif
  NULL
};

#define LDPATH_BUFSIZE (LDPATH_MAX*64)
#define LDPATH_MAX 8

#define LDPRELOAD_BUFSIZE (LDPRELOAD_MAX*64)
#define LDPRELOAD_MAX 8

static char g_ld_library_paths_buffer[LDPATH_BUFSIZE];
static const char* g_ld_library_paths[LDPATH_MAX + 1];

static char g_ld_preloads_buffer[LDPRELOAD_BUFSIZE];
static const char* g_ld_preload_names[LDPRELOAD_MAX + 1];

static soinfo* g_ld_preloads[LDPRELOAD_MAX + 1];

__LIBC_HIDDEN__ int g_ld_debug_verbosity;

enum RelocationKind {
    kRelocAbsolute = 0,
    kRelocRelative,
    kRelocCopy,
    kRelocSymbol,
    kRelocMax
};

#if STATS
struct linker_stats_t {
    int count[kRelocMax];
};

static linker_stats_t linker_stats;

static void count_relocation(RelocationKind kind) {
    ++linker_stats.count[kind];
}
#else
static void count_relocation(RelocationKind) {
}
#endif

#if COUNT_PAGES
static unsigned bitmask[4096];
#if defined(__LP64__)
#define MARK(offset) \
    do { \
        if ((((offset) >> 12) >> 5) < 4096) \
            bitmask[((offset) >> 12) >> 5] |= (1 << (((offset) >> 12) & 31)); \
    } while (0)
#else
#define MARK(offset) \
    do { \
        bitmask[((offset) >> 12) >> 3] |= (1 << (((offset) >> 12) & 7)); \
    } while (0)
#endif
#else
#define MARK(x) do {} while (0)
#endif

// You shouldn't try to call memory-allocating functions in the dynamic linker.
// Guard against the most obvious ones.
#define DISALLOW_ALLOCATION(return_type, name, ...) \
    return_type name __VA_ARGS__ \
    { \
        __libc_fatal("ERROR: " #name " called from the dynamic linker!\n"); \
    }
DISALLOW_ALLOCATION(void*, malloc, (size_t u __unused));
DISALLOW_ALLOCATION(void, free, (void* u __unused));
DISALLOW_ALLOCATION(void*, realloc, (void* u1 __unused, size_t u2 __unused));
DISALLOW_ALLOCATION(void*, calloc, (size_t u1 __unused, size_t u2 __unused));

static char tmp_err_buf[768];
static char __linker_dl_err_buf[768];

char* linker_get_error_buffer() {
  return &__linker_dl_err_buf[0];
}

size_t linker_get_error_buffer_size() {
  return sizeof(__linker_dl_err_buf);
}

LinkedListEntry<soinfo>* SoinfoListAllocator::alloc() {
  return g_soinfo_links_allocator.alloc();
}

void SoinfoListAllocator::free(LinkedListEntry<soinfo>* entry) {
  g_soinfo_links_allocator.free(entry);
}

static void protect_data(int protection) {
  g_soinfo_allocator.protect_all(protection);
  g_soinfo_links_allocator.protect_all(protection);
}

static soinfo* soinfo_alloc(const char* name, struct stat* file_stat) {
  if (strlen(name) >= SOINFO_NAME_LEN) {
    DL_ERR("library name \"%s\" too long", name);
    return NULL;
  }

  soinfo* si = g_soinfo_allocator.alloc();

  // Initialize the new element.
  memset(si, 0, sizeof(soinfo));
  strlcpy(si->name, name, sizeof(si->name));
  si->flags = FLAG_NEW_SOINFO;

  if (file_stat != NULL) {
    si->set_st_dev(file_stat->st_dev);
    si->set_st_ino(file_stat->st_ino);
  }

  sonext->next = si;
  sonext = si;

  TRACE("name %s: allocated soinfo @ %p", name, si);
  return si;
}

static void soinfo_free(soinfo* si) {
    if (si == NULL) {
        return;
    }

    if (si->base != 0 && si->size != 0) {
      munmap(reinterpret_cast<void*>(si->base), si->size);
    }

    soinfo *prev = NULL, *trav;

    TRACE("name %s: freeing soinfo @ %p", si->name, si);

    for (trav = solist; trav != NULL; trav = trav->next) {
        if (trav == si)
            break;
        prev = trav;
    }
    if (trav == NULL) {
        /* si was not in solist */
        DL_ERR("name \"%s\" is not in solist!", si->name);
        return;
    }

    // clear links to/from si
    si->remove_all_links();

    /* prev will never be NULL, because the first entry in solist is
       always the static libdl_info.
    */
    prev->next = si->next;
    if (si == sonext) {
        sonext = prev;
    }

    g_soinfo_allocator.free(si);
}


static void parse_path(const char* path, const char* delimiters,
                       const char** array, char* buf, size_t buf_size, size_t max_count) {
  if (path == NULL) {
    return;
  }

  size_t len = strlcpy(buf, path, buf_size);

  size_t i = 0;
  char* buf_p = buf;
  while (i < max_count && (array[i] = strsep(&buf_p, delimiters))) {
    if (*array[i] != '\0') {
      ++i;
    }
  }

  // Forget the last path if we had to truncate; this occurs if the 2nd to
  // last char isn't '\0' (i.e. wasn't originally a delimiter).
  if (i > 0 && len >= buf_size && buf[buf_size - 2] != '\0') {
    array[i - 1] = NULL;
  } else {
    array[i] = NULL;
  }
}

#if defined(__arm__)

/* For a given PC, find the .so that it belongs to.
 * Returns the base address of the .ARM.exidx section
 * for that .so, and the number of 8-byte entries
 * in that section (via *pcount).
 *
 * Intended to be called by libc's __gnu_Unwind_Find_exidx().
 *
 * This function is exposed via dlfcn.cpp and libdl.so.
 */
_Unwind_Ptr dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount) {
    unsigned addr = (unsigned)pc;

    for (soinfo* si = solist; si != 0; si = si->next) {
        if ((addr >= si->base) && (addr < (si->base + si->size))) {
            *pcount = si->ARM_exidx_count;
            return (_Unwind_Ptr)si->ARM_exidx;
        }
    }
    *pcount = 0;
    return NULL;
}

#endif

/* Here, we only have to provide a callback to iterate across all the
 * loaded libraries. gcc_eh does the rest. */
int dl_iterate_phdr(int (*cb)(dl_phdr_info* info, size_t size, void* data), void* data) {
    int rv = 0;
    for (soinfo* si = solist; si != NULL; si = si->next) {
        dl_phdr_info dl_info;
        dl_info.dlpi_addr = si->link_map_head.l_addr;
        dl_info.dlpi_name = si->link_map_head.l_name;
        dl_info.dlpi_phdr = si->phdr;
        dl_info.dlpi_phnum = si->phnum;
        rv = cb(&dl_info, sizeof(dl_phdr_info), data);
        if (rv != 0) {
            break;
        }
    }
    return rv;
}

static ElfW(Sym)* soinfo_elf_lookup(soinfo* si, unsigned hash, const char* name) {
  ElfW(Sym)* symtab = si->symtab;
  const char* strtab = si->strtab;

  TRACE("SEARCH %s in %s@%p %x %zd",
             name, si->name, reinterpret_cast<void*>(si->base), hash, hash % si->nbucket);

  for (unsigned n = si->bucket[hash % si->nbucket]; n != 0; n = si->chain[n]) {
    ElfW(Sym)* s = symtab + n;
    if (strcmp(strtab + s->st_name, name)) continue;

    /* only concern ourselves with global and weak symbol definitions */
    switch (ELF_ST_BIND(s->st_info)) {
      case STB_GLOBAL:
      case STB_WEAK:
        if (s->st_shndx == SHN_UNDEF) {
          continue;
        }

        TRACE("FOUND %s in %s (%p) %zd",
                 name, si->name, reinterpret_cast<void*>(s->st_value),
                 static_cast<size_t>(s->st_size));
        return s;
      case STB_LOCAL:
        continue;
      default:
        __libc_fatal("ERROR: Unexpected ST_BIND value: %d for '%s' in '%s'",
            ELF_ST_BIND(s->st_info), name, si->name);
    }
  }

  TRACE("NOT FOUND %s in %s@%p %x %zd",
             name, si->name, reinterpret_cast<void*>(si->base), hash, hash % si->nbucket);


  return NULL;
}

static unsigned elfhash(const char* _name) {
    const unsigned char* name = reinterpret_cast<const unsigned char*>(_name);
    unsigned h = 0, g;

    while (*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

static ElfW(Sym)* soinfo_do_lookup(soinfo* si, const char* name, soinfo** lsi, soinfo* needed[]) {
    unsigned elf_hash = elfhash(name);
    ElfW(Sym)* s = NULL;

    if (si != NULL && somain != NULL) {
        /*
         * Local scope is executable scope. Just start looking into it right away
         * for the shortcut.
         */

        if (si == somain) {
            s = soinfo_elf_lookup(si, elf_hash, name);
            if (s != NULL) {
                *lsi = si;
                goto done;
            }

            /* Next, look for it in the preloads list */
            for (int i = 0; g_ld_preloads[i] != NULL; i++) {
                s = soinfo_elf_lookup(g_ld_preloads[i], elf_hash, name);
                if (s != NULL) {
                    *lsi = g_ld_preloads[i];
                    goto done;
                }
            }
        } else {
            /* Order of symbol lookup is controlled by DT_SYMBOLIC flag */

            /*
             * If this object was built with symbolic relocations disabled, the
             * first place to look to resolve external references is the main
             * executable.
             */

            if (!si->has_DT_SYMBOLIC) {
                DEBUG("%s: looking up %s in executable %s",
                      si->name, name, somain->name);
                s = soinfo_elf_lookup(somain, elf_hash, name);
                if (s != NULL) {
                    *lsi = somain;
                    goto done;
                }

                /* Next, look for it in the preloads list */
                for (int i = 0; g_ld_preloads[i] != NULL; i++) {
                    s = soinfo_elf_lookup(g_ld_preloads[i], elf_hash, name);
                    if (s != NULL) {
                        *lsi = g_ld_preloads[i];
                        goto done;
                    }
                }
            }

            /* Look for symbols in the local scope (the object who is
             * searching). This happens with C++ templates on x86 for some
             * reason.
             *
             * Notes on weak symbols:
             * The ELF specs are ambiguous about treatment of weak definitions in
             * dynamic linking.  Some systems return the first definition found
             * and some the first non-weak definition.   This is system dependent.
             * Here we return the first definition found for simplicity.  */

            s = soinfo_elf_lookup(si, elf_hash, name);
            if (s != NULL) {
                *lsi = si;
                goto done;
            }

            /*
             * If this object was built with -Bsymbolic and symbol is not found
             * in the local scope, try to find the symbol in the main executable.
             */

            if (si->has_DT_SYMBOLIC) {
                DEBUG("%s: looking up %s in executable %s after local scope",
                      si->name, name, somain->name);
                s = soinfo_elf_lookup(somain, elf_hash, name);
                if (s != NULL) {
                    *lsi = somain;
                    goto done;
                }

                /* Next, look for it in the preloads list */
                for (int i = 0; g_ld_preloads[i] != NULL; i++) {
                    s = soinfo_elf_lookup(g_ld_preloads[i], elf_hash, name);
                    if (s != NULL) {
                        *lsi = g_ld_preloads[i];
                        goto done;
                    }
                }
            }
        }
    }

    for (int i = 0; needed[i] != NULL; i++) {
        DEBUG("%s: looking up %s in %s",
              si->name, name, needed[i]->name);
        s = soinfo_elf_lookup(needed[i], elf_hash, name);
        if (s != NULL) {
            *lsi = needed[i];
            goto done;
        }
    }

done:
    if (s != NULL) {
        TRACE("si %s sym %s s->st_value = %p, "
                   "found in %s, base = %p, load bias = %p",
                   si->name, name, reinterpret_cast<void*>(s->st_value),
                   (*lsi)->name, reinterpret_cast<void*>((*lsi)->base),
                   reinterpret_cast<void*>((*lsi)->load_bias));
        return s;
    }

    return NULL;
}

// Another soinfo list allocator to use in dlsym. We don't reuse
// SoinfoListAllocator because it is write-protected most of the time.
static LinkerAllocator<LinkedListEntry<soinfo>> g_soinfo_list_allocator_rw;
class SoinfoListAllocatorRW {
 public:
  static LinkedListEntry<soinfo>* alloc() {
    return g_soinfo_list_allocator_rw.alloc();
  }

  static void free(LinkedListEntry<soinfo>* ptr) {
    g_soinfo_list_allocator_rw.free(ptr);
  }
};

// This is used by dlsym(3).  It performs symbol lookup only within the
// specified soinfo object and its dependencies in breadth first order.
ElfW(Sym)* dlsym_handle_lookup(soinfo* si, soinfo** found, const char* name) {
  LinkedList<soinfo, SoinfoListAllocatorRW> visit_list;
  LinkedList<soinfo, SoinfoListAllocatorRW> visited;
  visit_list.push_back(si);
  soinfo* current_soinfo;
  while ((current_soinfo = visit_list.pop_front()) != nullptr) {
    if (visited.contains(current_soinfo)) {
      continue;
    }

    ElfW(Sym)* result = soinfo_elf_lookup(current_soinfo, elfhash(name), name);

    if (result != nullptr) {
      *found = current_soinfo;
      visit_list.clear();
      visited.clear();
      return result;
    }
    visited.push_back(current_soinfo);

    current_soinfo->get_children().for_each([&](soinfo* child) {
      visit_list.push_back(child);
    });
  }

  visit_list.clear();
  visited.clear();
  return nullptr;
}

/* This is used by dlsym(3) to performs a global symbol lookup. If the
   start value is null (for RTLD_DEFAULT), the search starts at the
   beginning of the global solist. Otherwise the search starts at the
   specified soinfo (for RTLD_NEXT).
 */
ElfW(Sym)* dlsym_linear_lookup(const char* name, soinfo** found, soinfo* start) {
  unsigned elf_hash = elfhash(name);

  if (start == NULL) {
    start = solist;
  }

  ElfW(Sym)* s = NULL;
  for (soinfo* si = start; (s == NULL) && (si != NULL); si = si->next) {
    s = soinfo_elf_lookup(si, elf_hash, name);
    if (s != NULL) {
      *found = si;
      break;
    }
  }

  if (s != NULL) {
    TRACE("%s s->st_value = %p, found->base = %p",
               name, reinterpret_cast<void*>(s->st_value), reinterpret_cast<void*>((*found)->base));
  }

  return s;
}

soinfo* find_containing_library(const void* p) {
  ElfW(Addr) address = reinterpret_cast<ElfW(Addr)>(p);
  for (soinfo* si = solist; si != NULL; si = si->next) {
    if (address >= si->base && address - si->base < si->size) {
      return si;
    }
  }
  return NULL;
}

ElfW(Sym)* dladdr_find_symbol(soinfo* si, const void* addr) {
  ElfW(Addr) soaddr = reinterpret_cast<ElfW(Addr)>(addr) - si->base;

  // Search the library's symbol table for any defined symbol which
  // contains this address.
  for (size_t i = 0; i < si->nchain; ++i) {
    ElfW(Sym)* sym = &si->symtab[i];
    if (sym->st_shndx != SHN_UNDEF &&
        soaddr >= sym->st_value &&
        soaddr < sym->st_value + sym->st_size) {
      return sym;
    }
  }

  return NULL;
}

static int open_library_on_path(const char* name, const char* const paths[]) {
  char buf[512];
  for (size_t i = 0; paths[i] != NULL; ++i) {
    int n = snprintf(buf, sizeof(buf), "%s/%s", paths[i], name);
    if (n < 0 || n >= static_cast<int>(sizeof(buf))) {
      DEBUG("Warning: ignoring very long library path: %s/%s", paths[i], name);
      continue;
    }
    int fd = open(buf, O_RDONLY | O_CLOEXEC);
    if (fd != -1) {
      return fd;
    }
  }
  return -1;
}

static int open_library(const char* name) {
  TRACE("[ opening %s ]", name);

  // If the name contains a slash, we should attempt to open it directly and not search the paths.
  if (strchr(name, '/') != NULL) {
    int fd = open(name, O_RDONLY | O_CLOEXEC);
    if (fd != -1) {
      return fd;
    }
    // ...but nvidia binary blobs (at least) rely on this behavior, so fall through for now.
#if defined(__LP64__)
    return -1;
#endif
  }

  // Otherwise we try LD_LIBRARY_PATH first, and fall back to the built-in well known paths.
  int fd = open_library_on_path(name, g_ld_library_paths);
  if (fd == -1) {
    fd = open_library_on_path(name, kDefaultLdPaths);
  }
  return fd;
}

static soinfo* load_library(const char* name, int dlflags, const android_dlextinfo* extinfo, ElfW(Off) offset) {
    int fd = -1;
    ScopedFd file_guard(-1);

    if (extinfo != NULL && (extinfo->flags & ANDROID_DLEXT_USE_LIBRARY_FD) != 0) {
      fd = extinfo->library_fd;
    } else {
      // Open the file.
      fd = open_library(name);
      if (fd == -1) {
        DL_ERR("library \"%s\" not found", name);
        return NULL;
      }

      file_guard.reset(fd);
    }

    ElfReader elf_reader(name, fd, offset);

    struct stat file_stat;
    if (fstat(fd, &file_stat) != 0) {
      DL_ERR("unable to stat file for the library %s: %s", name, strerror(errno));
      return NULL;
    }

    // Check for symlink and other situations where
    // file can have different names.
    for (soinfo* si = solist; si != NULL; si = si->next) {
      if (si->get_st_dev() != 0 &&
          si->get_st_ino() != 0 &&
          si->get_st_dev() == file_stat.st_dev &&
          si->get_st_ino() == file_stat.st_ino) {
        TRACE("library \"%s\" is already loaded under different name/path \"%s\" - will return existing soinfo", name, si->name);
        return si;
      }
    }

    if ((dlflags & RTLD_NOLOAD) != 0) {
      return NULL;
    }

    TRACE("---------here1");
    // Read the ELF header and load the segments.
    if (!elf_reader.Load(extinfo)) {
        return NULL;
    }
    TRACE("---------here1");

    soinfo* si = soinfo_alloc(SEARCH_NAME(name), &file_stat);
    if (si == NULL) {
        return NULL;
    }
    si->base = elf_reader.load_start();
    si->size = elf_reader.load_size();
    si->load_bias = elf_reader.load_bias();
    si->phnum = elf_reader.phdr_count();
    si->phdr = elf_reader.loaded_phdr();

    // At this point we know that whatever is loaded @ base is a valid ELF
    // shared library whose segments are properly mapped in.
    TRACE("[ load_library base=%p size=%zu name='%s' ]",
          reinterpret_cast<void*>(si->base), si->size, si->name);

    if (!soinfo_link_image(si, extinfo)) {
      soinfo_free(si);
      return NULL;
    }

    return si;
}

static soinfo *find_loaded_library_by_name(const char* name) {
  const char* search_name = SEARCH_NAME(name);
  for (soinfo* si = solist; si != NULL; si = si->next) {
    if (!strcmp(search_name, si->name)) {
      return si;
    }
  }
  return NULL;
}

static soinfo* find_library_internal(const char* name, int dlflags, const android_dlextinfo* extinfo, ElfW(Off) offset) {
  if (name == NULL) {
    return somain;
  }

  soinfo* si = find_loaded_library_by_name(name);

  // Library might still be loaded, the accurate detection
  // of this fact is done by load_library
  if (si == NULL) {
    TRACE("[ '%s' has not been found by name.  Trying harder...]", name);
    si = load_library(name, dlflags, extinfo, offset);
  }

  if (si != NULL && (si->flags & FLAG_LINKED) == 0) {
    DL_ERR("recursive link to \"%s\"", si->name);
    return NULL;
  }

  return si;
}

static soinfo* find_library(const char* name, int dlflags, const android_dlextinfo* extinfo, ElfW(Off) offset) {
  soinfo* si = find_library_internal(name, dlflags, extinfo, offset);
  if (si != NULL) {
    si->ref_count++;
  }
  return si;
}

static void soinfo_unload(soinfo* si) {
  if (si->ref_count == 1) {
    TRACE("unloading '%s'", si->name);
    si->CallDestructors();

    si->get_children().for_each([&] (soinfo* child) {
      TRACE("%s needs to unload %s", si->name, child->name);
      dlclose(child);
    });
    si->ref_count = 0;
    soinfo_free(si);
  } else {
    si->ref_count--;
    TRACE("not unloading '%s', decrementing ref_count to %d", si->name, si->ref_count);
  }
}

soinfo* do_dlopen(const char* name, int flags, const android_dlextinfo* extinfo, ElfW(Off) offset) {
  if ((flags & ~(RTLD_NOW|RTLD_LAZY|RTLD_LOCAL|RTLD_GLOBAL|RTLD_NOLOAD)) != 0) {
    DL_ERR("invalid flags to dlopen: %x", flags);
    return NULL;
  }
  if (extinfo != NULL && ((extinfo->flags & ~(ANDROID_DLEXT_VALID_FLAG_BITS)) != 0)) {
    DL_ERR("invalid extended flags to android_dlopen_ext: %x", extinfo->flags);
    return NULL;
  }
  protect_data(PROT_READ | PROT_WRITE);
    TRACE("---------here1");
  soinfo* si = find_library(name, flags, extinfo, offset);
  if (si != NULL) {
    si->CallConstructors();
  }
  protect_data(PROT_READ);
  return si;
}

void do_dlclose(soinfo* si) {
  protect_data(PROT_READ | PROT_WRITE);
  soinfo_unload(si);
  protect_data(PROT_READ);
}

#if defined(USE_RELA)
static int soinfo_relocate(soinfo* si, ElfW(Rela)* rela, unsigned count, soinfo* needed[]) {
  ElfW(Sym)* s;
  soinfo* lsi;

  for (size_t idx = 0; idx < count; ++idx, ++rela) {
    unsigned type = ELFW(R_TYPE)(rela->r_info);
    unsigned sym = ELFW(R_SYM)(rela->r_info);
    ElfW(Addr) reloc = static_cast<ElfW(Addr)>(rela->r_offset + si->load_bias);
    ElfW(Addr) sym_addr = 0;
    const char* sym_name = NULL;

    DEBUG("Processing '%s' relocation at index %zd", si->name, idx);
    if (type == 0) { // R_*_NONE
      continue;
    }
    if (sym != 0) {
      sym_name = reinterpret_cast<const char*>(si->strtab + si->symtab[sym].st_name);
      s = soinfo_do_lookup(si, sym_name, &lsi, needed);
      if (s == NULL) {
        // We only allow an undefined symbol if this is a weak reference...
        s = &si->symtab[sym];
        if (ELF_ST_BIND(s->st_info) != STB_WEAK) {
          DL_ERR("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name, si->name);
          return -1;
        }

        /* IHI0044C AAELF 4.5.1.1:

           Libraries are not searched to resolve weak references.
           It is not an error for a weak reference to remain unsatisfied.

           During linking, the value of an undefined weak reference is:
           - Zero if the relocation type is absolute
           - The address of the place if the relocation is pc-relative
           - The address of nominal base address if the relocation
             type is base-relative.
         */

        switch (type) {
#if defined(__aarch64__)
        case R_AARCH64_JUMP_SLOT:
        case R_AARCH64_GLOB_DAT:
        case R_AARCH64_ABS64:
        case R_AARCH64_ABS32:
        case R_AARCH64_ABS16:
        case R_AARCH64_RELATIVE:
          /*
           * The sym_addr was initialized to be zero above, or the relocation
           * code below does not care about value of sym_addr.
           * No need to do anything.
           */
          break;
#elif defined(__x86_64__)
        case R_X86_64_JUMP_SLOT:
        case R_X86_64_GLOB_DAT:
        case R_X86_64_32:
        case R_X86_64_64:
        case R_X86_64_RELATIVE:
          // No need to do anything.
          break;
        case R_X86_64_PC32:
          sym_addr = reloc;
          break;
#endif
        default:
          DL_ERR("unknown weak reloc type %d @ %p (%zu)", type, rela, idx);
          return -1;
        }
      } else {
        // We got a definition.
        sym_addr = static_cast<ElfW(Addr)>(s->st_value + lsi->load_bias);
      }
      count_relocation(kRelocSymbol);
    } else {
      s = NULL;
    }

    switch (type) {
#if defined(__aarch64__)
    case R_AARCH64_JUMP_SLOT:
        count_relocation(kRelocAbsolute);
        MARK(rela->r_offset);
        TRACE("RELO JMP_SLOT %16llx <- %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + rela->r_addend);
        break;
    case R_AARCH64_GLOB_DAT:
        count_relocation(kRelocAbsolute);
        MARK(rela->r_offset);
        TRACE("RELO GLOB_DAT %16llx <- %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + rela->r_addend);
        break;
    case R_AARCH64_ABS64:
        count_relocation(kRelocAbsolute);
        MARK(rela->r_offset);
        TRACE("RELO ABS64 %16llx <- %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) += (sym_addr + rela->r_addend);
        break;
    case R_AARCH64_ABS32:
        count_relocation(kRelocAbsolute);
        MARK(rela->r_offset);
        TRACE("RELO ABS32 %16llx <- %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), sym_name);
        if ((static_cast<ElfW(Addr)>(INT32_MIN) <= (*reinterpret_cast<ElfW(Addr)*>(reloc) + (sym_addr + rela->r_addend))) &&
            ((*reinterpret_cast<ElfW(Addr)*>(reloc) + (sym_addr + rela->r_addend)) <= static_cast<ElfW(Addr)>(UINT32_MAX))) {
            *reinterpret_cast<ElfW(Addr)*>(reloc) += (sym_addr + rela->r_addend);
        } else {
            DL_ERR("0x%016llx out of range 0x%016llx to 0x%016llx",
                   (*reinterpret_cast<ElfW(Addr)*>(reloc) + (sym_addr + rela->r_addend)),
                   static_cast<ElfW(Addr)>(INT32_MIN),
                   static_cast<ElfW(Addr)>(UINT32_MAX));
            return -1;
        }
        break;
    case R_AARCH64_ABS16:
        count_relocation(kRelocAbsolute);
        MARK(rela->r_offset);
        TRACE("RELO ABS16 %16llx <- %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), sym_name);
        if ((static_cast<ElfW(Addr)>(INT16_MIN) <= (*reinterpret_cast<ElfW(Addr)*>(reloc) + (sym_addr + rela->r_addend))) &&
            ((*reinterpret_cast<ElfW(Addr)*>(reloc) + (sym_addr + rela->r_addend)) <= static_cast<ElfW(Addr)>(UINT16_MAX))) {
            *reinterpret_cast<ElfW(Addr)*>(reloc) += (sym_addr + rela->r_addend);
        } else {
            DL_ERR("0x%016llx out of range 0x%016llx to 0x%016llx",
                   (*reinterpret_cast<ElfW(Addr)*>(reloc) + (sym_addr + rela->r_addend)),
                   static_cast<ElfW(Addr)>(INT16_MIN),
                   static_cast<ElfW(Addr)>(UINT16_MAX));
            return -1;
        }
        break;
    case R_AARCH64_PREL64:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        TRACE("RELO REL64 %16llx <- %16llx - %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), rela->r_offset, sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) += (sym_addr + rela->r_addend) - rela->r_offset;
        break;
    case R_AARCH64_PREL32:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        TRACE("RELO REL32 %16llx <- %16llx - %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), rela->r_offset, sym_name);
        if ((static_cast<ElfW(Addr)>(INT32_MIN) <= (*reinterpret_cast<ElfW(Addr)*>(reloc) + ((sym_addr + rela->r_addend) - rela->r_offset))) &&
            ((*reinterpret_cast<ElfW(Addr)*>(reloc) + ((sym_addr + rela->r_addend) - rela->r_offset)) <= static_cast<ElfW(Addr)>(UINT32_MAX))) {
            *reinterpret_cast<ElfW(Addr)*>(reloc) += ((sym_addr + rela->r_addend) - rela->r_offset);
        } else {
            DL_ERR("0x%016llx out of range 0x%016llx to 0x%016llx",
                   (*reinterpret_cast<ElfW(Addr)*>(reloc) + ((sym_addr + rela->r_addend) - rela->r_offset)),
                   static_cast<ElfW(Addr)>(INT32_MIN),
                   static_cast<ElfW(Addr)>(UINT32_MAX));
            return -1;
        }
        break;
    case R_AARCH64_PREL16:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        TRACE("RELO REL16 %16llx <- %16llx - %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), rela->r_offset, sym_name);
        if ((static_cast<ElfW(Addr)>(INT16_MIN) <= (*reinterpret_cast<ElfW(Addr)*>(reloc) + ((sym_addr + rela->r_addend) - rela->r_offset))) &&
            ((*reinterpret_cast<ElfW(Addr)*>(reloc) + ((sym_addr + rela->r_addend) - rela->r_offset)) <= static_cast<ElfW(Addr)>(UINT16_MAX))) {
            *reinterpret_cast<ElfW(Addr)*>(reloc) += ((sym_addr + rela->r_addend) - rela->r_offset);
        } else {
            DL_ERR("0x%016llx out of range 0x%016llx to 0x%016llx",
                   (*reinterpret_cast<ElfW(Addr)*>(reloc) + ((sym_addr + rela->r_addend) - rela->r_offset)),
                   static_cast<ElfW(Addr)>(INT16_MIN),
                   static_cast<ElfW(Addr)>(UINT16_MAX));
            return -1;
        }
        break;

    case R_AARCH64_RELATIVE:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        if (sym) {
            DL_ERR("odd RELATIVE form...");
            return -1;
        }
        TRACE("RELO RELATIVE %16llx <- %16llx\n",
                   reloc, (si->base + rela->r_addend));
        *reinterpret_cast<ElfW(Addr)*>(reloc) = (si->base + rela->r_addend);
        break;

    case R_AARCH64_COPY:
        /*
         * ET_EXEC is not supported so this should not happen.
         *
         * http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044d/IHI0044D_aaelf.pdf
         *
         * Section 4.7.1.10 "Dynamic relocations"
         * R_AARCH64_COPY may only appear in executable objects where e_type is
         * set to ET_EXEC.
         */
        DL_ERR("%s R_AARCH64_COPY relocations are not supported", si->name);
        return -1;
    case R_AARCH64_TLS_TPREL64:
        TRACE("RELO TLS_TPREL64 *** %16llx <- %16llx - %16llx\n",
                   reloc, (sym_addr + rela->r_addend), rela->r_offset);
        break;
    case R_AARCH64_TLS_DTPREL32:
        TRACE("RELO TLS_DTPREL32 *** %16llx <- %16llx - %16llx\n",
                   reloc, (sym_addr + rela->r_addend), rela->r_offset);
        break;
#elif defined(__x86_64__)
    case R_X86_64_JUMP_SLOT:
      count_relocation(kRelocAbsolute);
      MARK(rela->r_offset);
      TRACE("RELO JMP_SLOT %08zx <- %08zx %s", static_cast<size_t>(reloc),
                 static_cast<size_t>(sym_addr + rela->r_addend), sym_name);
      *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + rela->r_addend;
      break;
    case R_X86_64_GLOB_DAT:
      count_relocation(kRelocAbsolute);
      MARK(rela->r_offset);
      TRACE("RELO GLOB_DAT %08zx <- %08zx %s", static_cast<size_t>(reloc),
                 static_cast<size_t>(sym_addr + rela->r_addend), sym_name);
      *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + rela->r_addend;
      break;
    case R_X86_64_RELATIVE:
      count_relocation(kRelocRelative);
      MARK(rela->r_offset);
      if (sym) {
        DL_ERR("odd RELATIVE form...");
        return -1;
      }
      TRACE("RELO RELATIVE %08zx <- +%08zx", static_cast<size_t>(reloc),
                 static_cast<size_t>(si->base));
      *reinterpret_cast<ElfW(Addr)*>(reloc) = si->base + rela->r_addend;
      break;
    case R_X86_64_32:
      count_relocation(kRelocRelative);
      MARK(rela->r_offset);
      TRACE("RELO R_X86_64_32 %08zx <- +%08zx %s", static_cast<size_t>(reloc),
                 static_cast<size_t>(sym_addr), sym_name);
      *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + rela->r_addend;
      break;
    case R_X86_64_64:
      count_relocation(kRelocRelative);
      MARK(rela->r_offset);
      TRACE("RELO R_X86_64_64 %08zx <- +%08zx %s", static_cast<size_t>(reloc),
                 static_cast<size_t>(sym_addr), sym_name);
      *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + rela->r_addend;
      break;
    case R_X86_64_PC32:
      count_relocation(kRelocRelative);
      MARK(rela->r_offset);
      TRACE("RELO R_X86_64_PC32 %08zx <- +%08zx (%08zx - %08zx) %s",
                 static_cast<size_t>(reloc), static_cast<size_t>(sym_addr - reloc),
                 static_cast<size_t>(sym_addr), static_cast<size_t>(reloc), sym_name);
      *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + rela->r_addend - reloc;
      break;
#endif

    default:
      DL_ERR("unknown reloc type %d @ %p (%zu)", type, rela, idx);
      return -1;
    }
  }
  return 0;
}

#else // REL, not RELA.

static int soinfo_relocate(soinfo* si, ElfW(Rel)* rel, unsigned count, soinfo* needed[]) {
    ElfW(Sym)* s;
    soinfo* lsi;

    for (size_t idx = 0; idx < count; ++idx, ++rel) {
        unsigned type = ELFW(R_TYPE)(rel->r_info);
        // TODO: don't use unsigned for 'sym'. Use uint32_t or ElfW(Addr) instead.
        unsigned sym = ELFW(R_SYM)(rel->r_info);
        ElfW(Addr) reloc = static_cast<ElfW(Addr)>(rel->r_offset + si->load_bias);
        ElfW(Addr) sym_addr = 0;
        const char* sym_name = NULL;

        DEBUG("Processing '%s' relocation at index %zd", si->name, idx);
        if (type == 0) { // R_*_NONE
            continue;
        }
        if (sym != 0) {
            sym_name = reinterpret_cast<const char*>(si->strtab + si->symtab[sym].st_name);
            s = soinfo_do_lookup(si, sym_name, &lsi, needed);
            if (s == NULL) {
                // We only allow an undefined symbol if this is a weak reference...
                s = &si->symtab[sym];
                if (ELF_ST_BIND(s->st_info) != STB_WEAK) {
                    DL_ERR("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name, si->name);
                    return -1;
                }

                /* IHI0044C AAELF 4.5.1.1:

                   Libraries are not searched to resolve weak references.
                   It is not an error for a weak reference to remain
                   unsatisfied.

                   During linking, the value of an undefined weak reference is:
                   - Zero if the relocation type is absolute
                   - The address of the place if the relocation is pc-relative
                   - The address of nominal base address if the relocation
                     type is base-relative.
                  */

                switch (type) {
#if defined(__arm__)
                case R_ARM_JUMP_SLOT:
                case R_ARM_GLOB_DAT:
                case R_ARM_ABS32:
                case R_ARM_RELATIVE:    /* Don't care. */
                    // sym_addr was initialized to be zero above or relocation
                    // code below does not care about value of sym_addr.
                    // No need to do anything.
                    break;
#elif defined(__i386__)
                case R_386_JMP_SLOT:
                case R_386_GLOB_DAT:
                case R_386_32:
                case R_386_RELATIVE:    /* Don't care. */
                    // sym_addr was initialized to be zero above or relocation
                    // code below does not care about value of sym_addr.
                    // No need to do anything.
                    break;
                case R_386_PC32:
                    sym_addr = reloc;
                    break;
#endif

#if defined(__arm__)
                case R_ARM_COPY:
                    // Fall through. Can't really copy if weak symbol is not found at run-time.
#endif
                default:
                    DL_ERR("unknown weak reloc type %d @ %p (%zu)", type, rel, idx);
                    return -1;
                }
            } else {
                // We got a definition.
                sym_addr = static_cast<ElfW(Addr)>(s->st_value + lsi->load_bias);
            }
            count_relocation(kRelocSymbol);
        } else {
            s = NULL;
        }

        switch (type) {
#if defined(__arm__)
        case R_ARM_JUMP_SLOT:
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE("RELO JMP_SLOT %08x <- %08x %s", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
            break;
        case R_ARM_GLOB_DAT:
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE("RELO GLOB_DAT %08x <- %08x %s", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
            break;
        case R_ARM_ABS32:
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE("RELO ABS %08x <- %08x %s", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr;
            break;
        case R_ARM_REL32:
            count_relocation(kRelocRelative);
            MARK(rel->r_offset);
            TRACE("RELO REL32 %08x <- %08x - %08x %s",
                       reloc, sym_addr, rel->r_offset, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr - rel->r_offset;
            break;
        case R_ARM_COPY:
            /*
             * ET_EXEC is not supported so this should not happen.
             *
             * http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044d/IHI0044D_aaelf.pdf
             *
             * Section 4.7.1.10 "Dynamic relocations"
             * R_ARM_COPY may only appear in executable objects where e_type is
             * set to ET_EXEC.
             */
            DL_ERR("%s R_ARM_COPY relocations are not supported", si->name);
            return -1;
#elif defined(__i386__)
        case R_386_JMP_SLOT:
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE("RELO JMP_SLOT %08x <- %08x %s", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
            break;
        case R_386_GLOB_DAT:
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE("RELO GLOB_DAT %08x <- %08x %s", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
            break;
        case R_386_32:
            count_relocation(kRelocRelative);
            MARK(rel->r_offset);
            TRACE("RELO R_386_32 %08x <- +%08x %s", reloc, sym_addr, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr;
            break;
        case R_386_PC32:
            count_relocation(kRelocRelative);
            MARK(rel->r_offset);
            TRACE("RELO R_386_PC32 %08x <- +%08x (%08x - %08x) %s",
                       reloc, (sym_addr - reloc), sym_addr, reloc, sym_name);
            *reinterpret_cast<ElfW(Addr)*>(reloc) += (sym_addr - reloc);
            break;
#elif defined(__mips__)
        case R_MIPS_REL32:
#if defined(__LP64__)
            // MIPS Elf64_Rel entries contain compound relocations
            // We only handle the R_MIPS_NONE|R_MIPS_64|R_MIPS_REL32 case
            if (ELF64_R_TYPE2(rel->r_info) != R_MIPS_64 ||
                ELF64_R_TYPE3(rel->r_info) != R_MIPS_NONE) {
                DL_ERR("Unexpected compound relocation type:%d type2:%d type3:%d @ %p (%zu)",
                       type, (unsigned)ELF64_R_TYPE2(rel->r_info),
                       (unsigned)ELF64_R_TYPE3(rel->r_info), rel, idx);
                return -1;
            }
#endif
            count_relocation(kRelocAbsolute);
            MARK(rel->r_offset);
            TRACE("RELO REL32 %08zx <- %08zx %s", static_cast<size_t>(reloc),
                       static_cast<size_t>(sym_addr), sym_name ? sym_name : "*SECTIONHDR*");
            if (s) {
                *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr;
            } else {
                *reinterpret_cast<ElfW(Addr)*>(reloc) += si->base;
            }
            break;
#endif

#if defined(__arm__)
        case R_ARM_RELATIVE:
#elif defined(__i386__)
        case R_386_RELATIVE:
#endif
            count_relocation(kRelocRelative);
            MARK(rel->r_offset);
            if (sym) {
                DL_ERR("odd RELATIVE form...");
                return -1;
            }
            TRACE("RELO RELATIVE %p <- +%p",
                       reinterpret_cast<void*>(reloc), reinterpret_cast<void*>(si->base));
            *reinterpret_cast<ElfW(Addr)*>(reloc) += si->base;
            break;

        default:
            DL_ERR("unknown reloc type %d @ %p (%zu)", type, rel, idx);
            return -1;
        }
    }
    return 0;
}
#endif

void soinfo::CallArray(const char* array_name __unused, linker_function_t* functions, size_t count, bool reverse) {
  if (functions == NULL) {
    return;
  }

  TRACE("[ Calling %s (size %zd) @ %p for '%s' ]", array_name, count, functions, name);

  int begin = reverse ? (count - 1) : 0;
  int end = reverse ? -1 : count;
  int step = reverse ? -1 : 1;

  for (int i = begin; i != end; i += step) {
    TRACE("[ %s[%d] == %p ]", array_name, i, functions[i]);
    CallFunction("function", functions[i]);
  }

  TRACE("[ Done calling %s for '%s' ]", array_name, name);
}

void soinfo::CallFunction(const char* function_name __unused, linker_function_t function) {
  if (function == NULL || reinterpret_cast<uintptr_t>(function) == static_cast<uintptr_t>(-1)) {
    return;
  }

  TRACE("[ Calling %s @ %p for '%s' ]", function_name, function, name);
  function();
  TRACE("[ Done calling %s @ %p for '%s' ]", function_name, function, name);

  // The function may have called dlopen(3) or dlclose(3), so we need to ensure our data structures
  // are still writable. This happens with our debug malloc (see http://b/7941716).
  protect_data(PROT_READ | PROT_WRITE);
}

void soinfo::CallPreInitConstructors() {
  // DT_PREINIT_ARRAY functions are called before any other constructors for executables,
  // but ignored in a shared library.
  CallArray("DT_PREINIT_ARRAY", preinit_array, preinit_array_count, false);
}

void soinfo::CallConstructors() {
  if (constructors_called) {
    return;
  }

  // We set constructors_called before actually calling the constructors, otherwise it doesn't
  // protect against recursive constructor calls. One simple example of constructor recursion
  // is the libc debug malloc, which is implemented in libc_malloc_debug_leak.so:
  // 1. The program depends on libc, so libc's constructor is called here.
  // 2. The libc constructor calls dlopen() to load libc_malloc_debug_leak.so.
  // 3. dlopen() calls the constructors on the newly created
  //    soinfo for libc_malloc_debug_leak.so.
  // 4. The debug .so depends on libc, so CallConstructors is
  //    called again with the libc soinfo. If it doesn't trigger the early-
  //    out above, the libc constructor will be called again (recursively!).
  constructors_called = true;

  if ((flags & FLAG_EXE) == 0 && preinit_array != NULL) {
    // The GNU dynamic linker silently ignores these, but we warn the developer.
    DEBUG("\"%s\": ignoring %zd-entry DT_PREINIT_ARRAY in shared library!",
          name, preinit_array_count);
  }

  get_children().for_each([] (soinfo* si) {
    si->CallConstructors();
  });

  TRACE("\"%s\": calling constructors", name);

  // DT_INIT should be called before DT_INIT_ARRAY if both are present.
  CallFunction("DT_INIT", init_func);
  CallArray("DT_INIT_ARRAY", init_array, init_array_count, false);
}

void soinfo::CallDestructors() {
  TRACE("\"%s\": calling destructors", name);

  // DT_FINI_ARRAY must be parsed in reverse order.
  CallArray("DT_FINI_ARRAY", fini_array, fini_array_count, true);

  // DT_FINI should be called after DT_FINI_ARRAY if both are present.
  CallFunction("DT_FINI", fini_func);

  // This is needed on second call to dlopen
  // after library has been unloaded with RTLD_NODELETE
  constructors_called = false;
}

void soinfo::add_child(soinfo* child) {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return;
  }

  this->children.push_front(child);
  //child->parents.push_front(this);
}

void soinfo::remove_all_links() {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return;
  }

  // 1. Untie connected soinfos from 'this'.
  /*children.for_each([&] (soinfo* child) {
    child->parents.remove_if([&] (const soinfo* parent) {
      return parent == this;
    });
  });

  parents.for_each([&] (soinfo* parent) {
    parent->children.remove_if([&] (const soinfo* child) {
      return child == this;
    });
  });*/

  // 2. Once everything untied - clear local lists.
  parents.clear();
  children.clear();
}

void soinfo::set_st_dev(dev_t dev) {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return;
  }

  st_dev = dev;
}

void soinfo::set_st_ino(ino_t ino) {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return;
  }

  st_ino = ino;
}

dev_t soinfo::get_st_dev() {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return 0;
  }

  return st_dev;
};

ino_t soinfo::get_st_ino() {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return 0;
  }

  return st_ino;
}

// This is a return on get_children() in case
// 'this->flags' does not have FLAG_NEW_SOINFO set.
static soinfo::soinfo_list_t g_empty_list;

soinfo::soinfo_list_t& soinfo::get_children() {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return g_empty_list;
  }

  return this->children;
}

/* Force any of the closed stdin, stdout and stderr to be associated with
   /dev/null. */
static int nullify_closed_stdio() {
    int dev_null, i, status;
    int return_value = 0;

    dev_null = open("/dev/null", O_RDWR);
    if (dev_null < 0) {
        DL_ERR("cannot open /dev/null: %s", strerror(errno));
        return -1;
    }
    TRACE("[ Opened /dev/null file-descriptor=%d]", dev_null);

    /* If any of the stdio file descriptors is valid and not associated
       with /dev/null, dup /dev/null to it.  */
    for (i = 0; i < 3; i++) {
        /* If it is /dev/null already, we are done. */
        if (i == dev_null) {
            continue;
        }

        TRACE("[ Nullifying stdio file descriptor %d]", i);
        status = fcntl(i, F_GETFL);

        /* If file is opened, we are good. */
        if (status != -1) {
            continue;
        }

        /* The only error we allow is that the file descriptor does not
           exist, in which case we dup /dev/null to it. */
        if (errno != EBADF) {
            DL_ERR("fcntl failed: %s", strerror(errno));
            return_value = -1;
            continue;
        }

        /* Try dupping /dev/null to this stdio file descriptor and
           repeat if there is a signal.  Note that any errors in closing
           the stdio descriptor are lost.  */
        status = dup2(dev_null, i);
        if (status < 0) {
            DL_ERR("dup2 failed: %s", strerror(errno));
            return_value = -1;
            continue;
        }
    }

    /* If /dev/null is not one of the stdio file descriptors, close it. */
    if (dev_null > 2) {
        TRACE("[ Closing /dev/null file-descriptor=%d]", dev_null);
        status = close(dev_null);
        if (status == -1) {
            DL_ERR("close failed: %s", strerror(errno));
            return_value = -1;
        }
    }

    return return_value;
}

static bool soinfo_link_image(soinfo* si, const android_dlextinfo* extinfo) {
    /* "base" might wrap around UINT32_MAX. */
    ElfW(Addr) base = si->load_bias;
    const ElfW(Phdr)* phdr = si->phdr;
    int phnum = si->phnum;
    bool relocating_linker = (si->flags & FLAG_LINKER) != 0;

    /* We can't debug anything until the linker is relocated */
    if (!relocating_linker) {
        TRACE("[ linking %s ]", si->name);
        DEBUG("si->base = %p si->flags = 0x%08x", reinterpret_cast<void*>(si->base), si->flags);
    }

    /* Extract dynamic section */
    size_t dynamic_count;
    ElfW(Word) dynamic_flags;
    phdr_table_get_dynamic_section(phdr, phnum, base, &si->dynamic,
                                   &dynamic_count, &dynamic_flags);
    if (si->dynamic == NULL) {
        if (!relocating_linker) {
            DL_ERR("missing PT_DYNAMIC in \"%s\"", si->name);
        }
        return false;
    } else {
        if (!relocating_linker) {
            DEBUG("dynamic = %p", si->dynamic);
        }
    }

#if defined(__arm__)
    (void) phdr_table_get_arm_exidx(phdr, phnum, base,
                                    &si->ARM_exidx, &si->ARM_exidx_count);
#endif

    // Extract useful information from dynamic section.
    uint32_t needed_count = 0;
    for (ElfW(Dyn)* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
        DEBUG("d = %p, d[0](tag) = %p d[1](val) = %p",
              d, reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
        switch (d->d_tag) {
        case DT_HASH:
            si->nbucket = reinterpret_cast<uint32_t*>(base + d->d_un.d_ptr)[0];
            si->nchain = reinterpret_cast<uint32_t*>(base + d->d_un.d_ptr)[1];
            si->bucket = reinterpret_cast<uint32_t*>(base + d->d_un.d_ptr + 8);
            si->chain = reinterpret_cast<uint32_t*>(base + d->d_un.d_ptr + 8 + si->nbucket * 4);
            break;
        case DT_STRTAB:
            si->strtab = reinterpret_cast<const char*>(base + d->d_un.d_ptr);
            break;
        case DT_SYMTAB:
            si->symtab = reinterpret_cast<ElfW(Sym)*>(base + d->d_un.d_ptr);
            break;
#if !defined(__LP64__)
        case DT_PLTREL:
            if (d->d_un.d_val != DT_REL) {
                DL_ERR("unsupported DT_RELA in \"%s\"", si->name);
                return false;
            }
            break;
#endif
        case DT_JMPREL:
#if defined(USE_RELA)
            si->plt_rela = reinterpret_cast<ElfW(Rela)*>(base + d->d_un.d_ptr);
#else
            si->plt_rel = reinterpret_cast<ElfW(Rel)*>(base + d->d_un.d_ptr);
#endif
            break;
        case DT_PLTRELSZ:
#if defined(USE_RELA)
            si->plt_rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
#else
            si->plt_rel_count = d->d_un.d_val / sizeof(ElfW(Rel));
#endif
            break;
#if defined(__mips__)
        case DT_PLTGOT:
            // Used by mips and mips64.
            si->plt_got = reinterpret_cast<ElfW(Addr)**>(base + d->d_un.d_ptr);
            break;
#endif
#if defined(USE_RELA)
         case DT_RELA:
            si->rela = reinterpret_cast<ElfW(Rela)*>(base + d->d_un.d_ptr);
            break;
         case DT_RELASZ:
            si->rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
            break;
        case DT_REL:
            DL_ERR("unsupported DT_REL in \"%s\"", si->name);
            return false;
        case DT_RELSZ:
            DL_ERR("unsupported DT_RELSZ in \"%s\"", si->name);
            return false;
#else
        case DT_REL:
            si->rel = reinterpret_cast<ElfW(Rel)*>(base + d->d_un.d_ptr);
            break;
        case DT_RELSZ:
            si->rel_count = d->d_un.d_val / sizeof(ElfW(Rel));
            break;
         case DT_RELA:
            DL_ERR("unsupported DT_RELA in \"%s\"", si->name);
            return false;
#endif
        case DT_INIT:
            si->init_func = reinterpret_cast<linker_function_t>(base + d->d_un.d_ptr);
            DEBUG("%s constructors (DT_INIT) found at %p", si->name, si->init_func);
            break;
        case DT_FINI:
            si->fini_func = reinterpret_cast<linker_function_t>(base + d->d_un.d_ptr);
            DEBUG("%s destructors (DT_FINI) found at %p", si->name, si->fini_func);
            break;
        case DT_INIT_ARRAY:
            si->init_array = reinterpret_cast<linker_function_t*>(base + d->d_un.d_ptr);
            DEBUG("%s constructors (DT_INIT_ARRAY) found at %p", si->name, si->init_array);
            break;
        case DT_INIT_ARRAYSZ:
            si->init_array_count = ((unsigned)d->d_un.d_val) / sizeof(ElfW(Addr));
            break;
        case DT_FINI_ARRAY:
            si->fini_array = reinterpret_cast<linker_function_t*>(base + d->d_un.d_ptr);
            DEBUG("%s destructors (DT_FINI_ARRAY) found at %p", si->name, si->fini_array);
            break;
        case DT_FINI_ARRAYSZ:
            si->fini_array_count = ((unsigned)d->d_un.d_val) / sizeof(ElfW(Addr));
            break;
        case DT_PREINIT_ARRAY:
            si->preinit_array = reinterpret_cast<linker_function_t*>(base + d->d_un.d_ptr);
            DEBUG("%s constructors (DT_PREINIT_ARRAY) found at %p", si->name, si->preinit_array);
            break;
        case DT_PREINIT_ARRAYSZ:
            si->preinit_array_count = ((unsigned)d->d_un.d_val) / sizeof(ElfW(Addr));
            break;
        case DT_TEXTREL:
#if defined(__LP64__)
            DL_ERR("text relocations (DT_TEXTREL) found in 64-bit ELF file \"%s\"", si->name);
            return false;
#else
            si->has_text_relocations = true;
            break;
#endif
        case DT_SYMBOLIC:
            si->has_DT_SYMBOLIC = true;
            break;
        case DT_NEEDED:
            ++needed_count;
            break;
        case DT_FLAGS:
            if (d->d_un.d_val & DF_TEXTREL) {
#if defined(__LP64__)
                DL_ERR("text relocations (DF_TEXTREL) found in 64-bit ELF file \"%s\"", si->name);
                return false;
#else
                si->has_text_relocations = true;
#endif
            }
            if (d->d_un.d_val & DF_SYMBOLIC) {
                si->has_DT_SYMBOLIC = true;
            }
            break;
#if defined(__mips__)
        case DT_STRSZ:
        case DT_SYMENT:
        case DT_RELENT:
             break;
        case DT_MIPS_RLD_MAP:
            // Set the DT_MIPS_RLD_MAP entry to the address of _r_debug for GDB.
            {
              r_debug** dp = reinterpret_cast<r_debug**>(base + d->d_un.d_ptr);
              *dp = &_r_debug;
            }
            break;
        case DT_MIPS_RLD_VERSION:
        case DT_MIPS_FLAGS:
        case DT_MIPS_BASE_ADDRESS:
        case DT_MIPS_UNREFEXTNO:
            break;

        case DT_MIPS_SYMTABNO:
            si->mips_symtabno = d->d_un.d_val;
            break;

        case DT_MIPS_LOCAL_GOTNO:
            si->mips_local_gotno = d->d_un.d_val;
            break;

        case DT_MIPS_GOTSYM:
            si->mips_gotsym = d->d_un.d_val;
            break;
#endif

        default:
            DEBUG("Unused DT entry: type %p arg %p",
                  reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
            break;
        }
    }

    DEBUG("si->base = %p, si->strtab = %p, si->symtab = %p",
          reinterpret_cast<void*>(si->base), si->strtab, si->symtab);

    // Sanity checks.
    if (relocating_linker && needed_count != 0) {
        DL_ERR("linker cannot have DT_NEEDED dependencies on other libraries");
        return false;
    }
    if (si->nbucket == 0) {
        DL_ERR("empty/missing DT_HASH in \"%s\" (built with --hash-style=gnu?)", si->name);
        return false;
    }
    if (si->strtab == 0) {
        DL_ERR("empty/missing DT_STRTAB in \"%s\"", si->name);
        return false;
    }
    if (si->symtab == 0) {
        DL_ERR("empty/missing DT_SYMTAB in \"%s\"", si->name);
        return false;
    }

    // If this is the main executable, then load all of the libraries from LD_PRELOAD now.
    if (si->flags & FLAG_EXE) {
        memset(g_ld_preloads, 0, sizeof(g_ld_preloads));
        size_t preload_count = 0;
        for (size_t i = 0; g_ld_preload_names[i] != NULL; i++) {
            soinfo* lsi = find_library(g_ld_preload_names[i], 0, NULL, 0);
            if (lsi != NULL) {
                g_ld_preloads[preload_count++] = lsi;
            } else {
                // As with glibc, failure to load an LD_PRELOAD library is just a warning.
                DL_WARN("could not load library \"%s\" from LD_PRELOAD for \"%s\"; caused by %s",
                        g_ld_preload_names[i], si->name, linker_get_error_buffer());
            }
        }
    }

    soinfo** needed = reinterpret_cast<soinfo**>(alloca((1 + needed_count) * sizeof(soinfo*)));
    soinfo** pneeded = needed;

    for (ElfW(Dyn)* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
        if (d->d_tag == DT_NEEDED) {
            const char* library_name = si->strtab + d->d_un.d_val;
            DEBUG("%s needs %s", si->name, library_name);
            soinfo* lsi = reinterpret_cast<soinfo *>(dlopen(library_name, RTLD_LAZY));
            if (lsi == NULL) {
                strlcpy(tmp_err_buf, linker_get_error_buffer(), sizeof(tmp_err_buf));
                DL_ERR("could not load library \"%s\" needed by \"%s\"; caused by %s",
                       library_name, si->name, tmp_err_buf);
                return false;
            }

            si->add_child(lsi);
            *pneeded++ = lsi;
        }
    }
    *pneeded = NULL;

    somain = si;

#if !defined(__LP64__)
    if (si->has_text_relocations) {
        // Make segments writable to allow text relocations to work properly. We will later call
        // phdr_table_protect_segments() after all of them are applied and all constructors are run.
        DL_WARN("%s has text relocations. This is wasting memory and prevents "
                "security hardening. Please fix.", si->name);
        if (phdr_table_unprotect_segments(si->phdr, si->phnum, si->load_bias) < 0) {
            DL_ERR("can't unprotect loadable segments for \"%s\": %s",
                   si->name, strerror(errno));
            return false;
        }
    }
#endif

#if defined(USE_RELA)
    if (si->plt_rela != NULL) {
        DEBUG("[ relocating %s plt ]\n", si->name);
        if (soinfo_relocate(si, si->plt_rela, si->plt_rela_count, needed)) {
            return false;
        }
    }
    if (si->rela != NULL) {
        DEBUG("[ relocating %s ]\n", si->name);
        if (soinfo_relocate(si, si->rela, si->rela_count, needed)) {
            return false;
        }
    }
#else
    if (si->plt_rel != NULL) {
        DEBUG("[ relocating %s plt ]", si->name);
        if (soinfo_relocate(si, si->plt_rel, si->plt_rel_count, needed)) {
            return false;
        }
    }
    if (si->rel != NULL) {
        DEBUG("[ relocating %s ]", si->name);
        if (soinfo_relocate(si, si->rel, si->rel_count, needed)) {
            return false;
        }
    }
#endif

#if defined(__mips__)
    if (!mips_relocate_got(si, needed)) {
        return false;
    }
#endif

    si->flags |= FLAG_LINKED;
    DEBUG("[ finished linking %s ]", si->name);

#if !defined(__LP64__)
    if (si->has_text_relocations) {
        // All relocations are done, we can protect our segments back to read-only.
        if (phdr_table_protect_segments(si->phdr, si->phnum, si->load_bias) < 0) {
            DL_ERR("can't protect segments for \"%s\": %s",
                   si->name, strerror(errno));
            return false;
        }
    }
#endif

    /* We can also turn on GNU RELRO protection */
    if (phdr_table_protect_gnu_relro(si->phdr, si->phnum, si->load_bias) < 0) {
        DL_ERR("can't enable GNU RELRO protection for \"%s\": %s",
               si->name, strerror(errno));
        return false;
    }

    /* Handle serializing/sharing the RELRO segment */
    if (extinfo && (extinfo->flags & ANDROID_DLEXT_WRITE_RELRO)) {
      if (phdr_table_serialize_gnu_relro(si->phdr, si->phnum, si->load_bias,
                                         extinfo->relro_fd) < 0) {
        DL_ERR("failed serializing GNU RELRO section for \"%s\": %s",
               si->name, strerror(errno));
        return false;
      }
    } else if (extinfo && (extinfo->flags & ANDROID_DLEXT_USE_RELRO)) {
      if (phdr_table_map_gnu_relro(si->phdr, si->phnum, si->load_bias,
                                   extinfo->relro_fd) < 0) {
        DL_ERR("failed mapping GNU RELRO section for \"%s\": %s",
               si->name, strerror(errno));
        return false;
      }
    }

    return true;
}

/* Compute the load-bias of an existing executable. This shall only
 * be used to compute the load bias of an executable or shared library
 * that was loaded by the kernel itself.
 *
 * Input:
 *    elf    -> address of ELF header, assumed to be at the start of the file.
 * Return:
 *    load bias, i.e. add the value of any p_vaddr in the file to get
 *    the corresponding address in memory.
 */
static ElfW(Addr) get_elf_exec_load_bias(const ElfW(Ehdr)* elf) {
  ElfW(Addr) offset = elf->e_phoff;
  const ElfW(Phdr)* phdr_table = reinterpret_cast<const ElfW(Phdr)*>(reinterpret_cast<uintptr_t>(elf) + offset);
  const ElfW(Phdr)* phdr_end = phdr_table + elf->e_phnum;

  for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_end; phdr++) {
    if (phdr->p_type == PT_LOAD) {
      return reinterpret_cast<ElfW(Addr)>(elf) + phdr->p_offset - phdr->p_vaddr;
    }
  }
  return 0;
}

