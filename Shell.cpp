#include <elf.h>
#include <sys/mman.h>

#include "gdlfcn.h"
#include "Shell.h"
#include "Utils.h"
#include "Log.h"
#include "linker.h"

#ifdef __LP64__
#define MAX_COUNT 512
#else
#define MAX_COUNT 128
#endif

static Shell *gshell = NULL;
void init() {
    GLogInfo("Shell", "So shell library init....");
    gshell = new Shell();
    gshell->loadClientLibrary();
    gshell->updateSoInfo();
}

void fini() {
    if (gshell != NULL) {
        GLogInfo("Shell", "So shell library finalize....");
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
    TRACE("----------init func addr: %lx, unsigned long length: %d", initAddr, sizeof(unsigned long));
    for (int i = 0; i < count; i++) {
        TRACE("-------map start: %lx, end: %lx, name: %s", map[i].start, map[i].end, map[i].name);
        if (initAddr >= map[i].start && initAddr < map[i].end) {
            libName = map[i].name;
            TRACE("-------find: %s, addr: %lx, between %lx and %lx", map[i].name, initAddr, map[i].start, map[i].end);
            break;
        }
    }
    if (libName == NULL) {
        GLogError("Shell", "Find current library name failed. ");
        abort();
        return;
    }
    strncpy(this->libraryName, libName, sizeof(this->libraryName));
    this->shellSoInfo = reinterpret_cast<soinfo *>(dlopen(libName, RTLD_LAZY));
    TRACE("--------libName: %s, base addr: %lx", libName, this->shellSoInfo);
}

void Shell::loadClientLibrary() {
    GLogInfo("Shell", "Start to load client library...");
    ElfW(Ehdr) *ehdr = reinterpret_cast<ElfW(Ehdr) *>(shellSoInfo->base);
    ElfW(Off) clientLibOffset = ~ehdr->e_shoff;
    GLogInfo("Shell", "Client so offset: %x", clientLibOffset);
    this->clientSoInfo = reinterpret_cast<soinfo *>(gdlopen(this->libraryName, RTLD_LAZY, clientLibOffset));
    GLogInfo("Shell", "Finish to load client library...");
}

void Shell::setSoInfoProtection(void *addr, int protection) {
    void *pageStart = (void *) PAGE_START((ElfW(Addr)) addr);
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
    memcpy(&(this->backupShellSoInfo), shellSoInfo, sizeof(soinfo));

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
