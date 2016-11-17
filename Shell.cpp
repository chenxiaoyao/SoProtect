#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include "gdlfcn.h"
#include "Shell.h"
#include "Utils.h"
#include "Log.h"
#include "linker.h"

#define MAX_COUNT 64

static Shell *gshell = NULL;
void init() {
    GLogInfo("Shell", "So shell library init....");
    gshell = new Shell();
    gshell->loadClientLibrary();
    gshell->updateSoInfo();
}

void fini() {
    GLogInfo("Shell", "So shell library finalize....");
    if (gshell != NULL) {
        gshell->restoreSoInfo();
        delete gshell;
        gshell = NULL;
    }
}

Shell::Shell() {
    MemoryMap map[MAX_COUNT];
    int count = 0;
    int ret = 0;

    ret = loadMemoryMap(getpid(), map, &count);
    if (ret < 0) {
        GLogError("Shell", "Load process memory map failed. ");
        abort();
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
        abort();
        return;
    }
    strncpy(this->libraryName, libName, sizeof(this->libraryName));
    this->shellSoInfo = reinterpret_cast<soinfo *>(dlopen(libName, RTLD_LAZY));
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
    void *pageStart = (void *) PAGE_START((Elf_Addr) addr);
    if (mprotect(pageStart, PAGE_SIZE, protection) == -1) {
      abort(); // Can't happen.
    }
}

static void copyImportantSoInfo(soinfo *dest, soinfo *src) {
    dest->load_bias = src->load_bias;
    dest->base = src->base;
    dest->size = src->size;
    dest->strtab = src->strtab;
    dest->symtab = src->symtab;
    dest->nbucket = src->nbucket;
    dest->nchain = src->nchain;
    dest->bucket = src->bucket;
    dest->chain = src->chain;
#ifdef ANDROID_ARM_LINKER
    dest->ARM_exidx = src->ARM_exidx;
    dest->ARM_exidx_count = src->ARM_exidx_count;
#endif
}

void Shell::updateSoInfo() {
    this->backupShellSoInfo = *shellSoInfo;

    this->setSoInfoProtection(this->shellSoInfo, PROT_READ | PROT_WRITE);
    copyImportantSoInfo(this->shellSoInfo, this->clientSoInfo);
    // restore soinfo reference count
    if (this->shellSoInfo->ref_count > 1) {
        this->shellSoInfo->ref_count--;
    }

    this->setSoInfoProtection(this->shellSoInfo, PROT_READ);
}

void Shell::restoreSoInfo() {
    if (this->shellSoInfo == NULL || this->clientSoInfo == NULL) {
        return;
    }
    this->setSoInfoProtection(this->shellSoInfo, PROT_READ | PROT_WRITE);
    copyImportantSoInfo(this->shellSoInfo, &(this->backupShellSoInfo));
    this->setSoInfoProtection(this->shellSoInfo, PROT_READ);
}

Shell::~Shell() {
    gdlclose(this->clientSoInfo);
    this->shellSoInfo = NULL;
    this->clientSoInfo = NULL;
}
