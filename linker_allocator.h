#ifndef __LINKER_ALLOCATOR_H
#define __LINKER_ALLOCATOR_H

#include <stdlib.h>
#include <limits.h>

#include "extra_defines.h"

struct LinkerAllocatorPage;

/*
 * This class is a non-template version of the LinkerAllocator
 * It keeps code inside .cpp file by keeping the interface
 * template-free.
 *
 * Please use LinkerAllocator<type> where possible (everywhere).
 */
class LinkerBlockAllocator {
 public:
  explicit LinkerBlockAllocator(size_t block_size);

  void* alloc();
  void free(void* block);
  void protect_all(int prot);

 private:
  void create_new_page();
  LinkerAllocatorPage* find_page(void* block);

  size_t block_size_;
  LinkerAllocatorPage* page_list_;
  void* free_block_list_;

  DISALLOW_COPY_AND_ASSIGN(LinkerBlockAllocator);
};

/*
 * We can't use malloc(3) in the dynamic linker.
 *
 * A simple allocator for the dynamic linker. An allocator allocates instances
 * of a single fixed-size type. Allocations are backed by page-sized private
 * anonymous mmaps.
 */
template<typename T>
class LinkerAllocator {
 public:
  LinkerAllocator() : block_allocator_(sizeof(T)) {}
  T* alloc() { return reinterpret_cast<T*>(block_allocator_.alloc()); }
  void free(T* t) { block_allocator_.free(t); }
  void protect_all(int prot) { block_allocator_.protect_all(prot); }
 private:
  LinkerBlockAllocator block_allocator_;
  DISALLOW_COPY_AND_ASSIGN(LinkerAllocator);
};
#endif // __LINKER_ALLOCATOR_H
