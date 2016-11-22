#ifndef LINKER_PHDR_H
#define LINKER_PHDR_H

/* Declarations related to the ELF program header table and segments.
 *
 * The design goal is to provide an API that is as close as possible
 * to the ELF spec, and does not depend on linker-specific data
 * structures (e.g. the exact layout of struct soinfo).
 */

#include "linker.h"

class ElfReader {
 public:
  ElfReader(const char* name, int fd, ElfW(Off) offset);
  ~ElfReader();

  bool Load(const android_dlextinfo* extinfo);

  size_t phdr_count() { return phdr_num_; }
  ElfW(Addr) load_start() { return reinterpret_cast<ElfW(Addr)>(load_start_); }
  size_t load_size() { return load_size_; }
  ElfW(Addr) load_bias() { return load_bias_; }
  const ElfW(Phdr)* loaded_phdr() { return loaded_phdr_; }

 private:
  bool ReadElfHeader();
  bool VerifyElfHeader();
  bool ReadProgramHeader();
  bool ReserveAddressSpace(const android_dlextinfo* extinfo);
  bool LoadSegments();
  bool FindPhdr();
  bool CheckPhdr(ElfW(Addr));

  const char* name_;
  int fd_;
  ElfW(Off) offset_;

  ElfW(Ehdr) header_;
  size_t phdr_num_;

  void* phdr_mmap_;
  ElfW(Phdr)* phdr_table_;
  ElfW(Addr) phdr_size_;

  // First page of reserved address space.
  void* load_start_;
  // Size in bytes of reserved address space.
  size_t load_size_;
  // Load bias.
  ElfW(Addr) load_bias_;

  // Loaded phdr.
  const ElfW(Phdr)* loaded_phdr_;
};

size_t phdr_table_get_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                ElfW(Addr)* min_vaddr = NULL, ElfW(Addr)* max_vaddr = NULL);

int phdr_table_protect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias);

int phdr_table_unprotect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias);

int phdr_table_protect_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias);

int phdr_table_serialize_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias,
                                   int fd);

int phdr_table_map_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias,
                             int fd);

#if defined(__arm__)
int phdr_table_get_arm_exidx(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias,
                             ElfW(Addr)** arm_exidx, unsigned* arm_exidix_count);
#endif

void phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                    ElfW(Addr) load_bias,
                                    ElfW(Dyn)** dynamic, size_t* dynamic_count, ElfW(Word)* dynamic_flags);

#endif /* LINKER_PHDR_H */
