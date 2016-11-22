#ifndef __EXTRA_DEFINES_H__
#define __EXTRA_DEFINES_H__

#include<link.h>

// This is only supported by Android kernels, so it's not in the uapi headers.
#define PR_SET_VMA   0x53564d41
#define PR_SET_VMA_ANON_NAME    0

#define UINT32_MAX       (4294967295U)
#define UINT64_MAX       (UINT64_C(18446744073709551615))

#if defined(__LP64__)
#  define INTPTR_MIN     INT64_MIN
#  define INTPTR_MAX     INT64_MAX
#  define UINTPTR_MAX    UINT64_MAX
#  define PTRDIFF_MIN    INT64_MIN
#  define PTRDIFF_MAX    INT64_MAX
#  define SIZE_MAX       UINT64_MAX
#else
#  define INTPTR_MIN     INT32_MIN
#  define INTPTR_MAX     INT32_MAX
#  define UINTPTR_MAX    UINT32_MAX
#  define PTRDIFF_MIN    INT32_MIN
#  define PTRDIFF_MAX    INT32_MAX
#  define SIZE_MAX       UINT32_MAX
#endif


// DISALLOW_COPY_AND_ASSIGN disallows the copy and operator= functions.
// It goes in the private: declarations in a class.
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&);               \
  void operator=(const TypeName&)

// A macro to disallow all the implicit constructors, namely the
// default constructor, copy constructor and operator= functions.
//
// This should be used in the private: declarations for a class
// that wants to prevent anyone from instantiating it. This is
// especially useful for classes containing only static methods.
#define DISALLOW_IMPLICIT_CONSTRUCTORS(TypeName) \
  TypeName();                                    \
  DISALLOW_COPY_AND_ASSIGN(TypeName)

#ifdef __arm__
typedef long unsigned int* _Unwind_Ptr;
_Unwind_Ptr dl_unwind_find_exidx(_Unwind_Ptr, int*);
#endif

int dl_iterate_phdr(int (*cb)(dl_phdr_info* info, size_t size, void* data), void* data);

#ifndef __LP64__
/* Used by the dynamic linker to communicate with the debugger. */
struct link_map {
  ElfW(Addr) l_addr;
  char* l_name;
  ElfW(Dyn)* l_ld;
  struct link_map* l_next;
  struct link_map* l_prev;
};
#endif

/* bitfield definitions for android_dlextinfo.flags */
enum {
  /* When set, the reserved_addr and reserved_size fields must point to an
   * already-reserved region of address space which will be used to load the
   * library if it fits. If the reserved region is not large enough, the load
   * will fail.
   */
  ANDROID_DLEXT_RESERVED_ADDRESS      = 0x1,

  /* As DLEXT_RESERVED_ADDRESS, but if the reserved region is not large enough,
   * the linker will choose an available address instead.
   */
  ANDROID_DLEXT_RESERVED_ADDRESS_HINT = 0x2,

  /* When set, write the GNU RELRO section of the mapped library to relro_fd
   * after relocation has been performed, to allow it to be reused by another
   * process loading the same library at the same address. This implies
   * ANDROID_DLEXT_USE_RELRO.
   */
  ANDROID_DLEXT_WRITE_RELRO           = 0x4,

  /* When set, compare the GNU RELRO section of the mapped library to relro_fd
   * after relocation has been performed, and replace any relocated pages that
   * are identical with a version mapped from the file.
   */
  ANDROID_DLEXT_USE_RELRO             = 0x8,

  /* Instruct dlopen to use library_fd instead of opening file by name.
   * The filename parameter is still used to identify the library.
   */
  ANDROID_DLEXT_USE_LIBRARY_FD        = 0x10,

  /* Mask of valid bits */
  ANDROID_DLEXT_VALID_FLAG_BITS       = ANDROID_DLEXT_RESERVED_ADDRESS |
                                        ANDROID_DLEXT_RESERVED_ADDRESS_HINT |
                                        ANDROID_DLEXT_WRITE_RELRO |
                                        ANDROID_DLEXT_USE_RELRO |
                                        ANDROID_DLEXT_USE_LIBRARY_FD,
};

typedef struct {
  uint64_t flags;
  void*   reserved_addr;
  size_t  reserved_size;
  int     relro_fd;
  int     library_fd;
} android_dlextinfo;


#endif
