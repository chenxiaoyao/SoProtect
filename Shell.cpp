#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include "gdlfcn.h"
#include "Shell.h"
#include "Utils.h"
#include "Log.h"
#include "linker.h"

#define MAX_COUNT 64

extern "C" void init() {
    GLogInfo("Shell", "So shell library init....");
    Shell *shell = new Shell();
    shell->loadClientLibrary();
    shell->syncSoInfo();
    delete shell;
}

Shell::Shell() {
    MemoryMap map[MAX_COUNT];
    int count = 0;
    int ret = 0;

    ret = loadMemoryMap(getpid(), map, &count);
    if (ret < 0) {
        GLogError("Shell", "Load process memory map failed. ");
        return;
    }
    char *libName = NULL;
    unsigned long initAddr = reinterpret_cast<unsigned long>(init);
    for (int i = 0; i < count; i++) {
        if (initAddr >= map[i].start && initAddr < map[i].end) {
            libName = map[i].name;
            break;
        }
    }
    if (libName == NULL) {
        GLogError("Shell", "Find current shell library failed. ");
        return;
    }
    strncpy(this->libraryName, libName, sizeof(this->libraryName));
    this->shellSoInfo = reinterpret_cast<soinfo *>(dlopen(libName, RTLD_LAZY));
    this->backupShellSoInfo = *shellSoInfo;
}

void Shell::loadClientLibrary() {
    GLogInfo("Shell", "Start to load client library...");
    Elf_Ehdr *ehdr = reinterpret_cast<Elf_Ehdr *>(shellSoInfo->base);
    Elf_Off clientLibOffset = ~ehdr->e_shoff;
    GLogInfo("Shell", "Client so offset: %x", clientLibOffset);
    this->clientSoInfo = reinterpret_cast<soinfo *>(gdlopen(this->libraryName, RTLD_LAZY, clientLibOffset));
    GLogInfo("Shell", "Finish to load client library...");
}

void Shell::setSoInfoProtection(void *addr, int protection) {
    if (mprotect(addr, PAGE_SIZE, protection) == -1) {
      abort(); // Can't happen.
    }
}

void Shell::syncSoInfo() {
    void *siPageStart = (void *) PAGE_START((Elf_Addr) this->shellSoInfo);
    this->setSoInfoProtection(siPageStart, PROT_READ | PROT_WRITE);

    this->shellSoInfo->load_bias = this->clientSoInfo->load_bias;
    this->shellSoInfo->base = this->clientSoInfo->base;
    this->shellSoInfo->size = this->clientSoInfo->size;
    this->shellSoInfo->strtab = this->clientSoInfo->strtab;
    this->shellSoInfo->symtab = this->clientSoInfo->symtab;
    this->shellSoInfo->nbucket = this->clientSoInfo->nbucket;
    this->shellSoInfo->nchain = this->clientSoInfo->nchain;
    this->shellSoInfo->bucket = this->clientSoInfo->bucket;
    this->shellSoInfo->chain = this->clientSoInfo->chain;
    this->shellSoInfo->init_array = this->clientSoInfo->init_array;
    this->shellSoInfo->init_array_count = this->clientSoInfo->init_array_count;
    this->shellSoInfo->fini_array = this->clientSoInfo->fini_array;
    this->shellSoInfo->fini_array_count = this->clientSoInfo->fini_array_count;
    this->shellSoInfo->init_func = this->clientSoInfo->init_func;
    this->shellSoInfo->fini_func = this->clientSoInfo->fini_func;
#ifdef ANDROID_ARM_LINKER
    this->shellSoInfo->ARM_exidx = this->clientSoInfo->ARM_exidx;
    this->shellSoInfo->ARM_exidx_count = this->clientSoInfo->ARM_exidx_count;
#endif
    this->shellSoInfo->load_bias = this->clientSoInfo->load_bias;

    this->setSoInfoProtection(siPageStart, PROT_READ);
}

Shell::~Shell() {

}
