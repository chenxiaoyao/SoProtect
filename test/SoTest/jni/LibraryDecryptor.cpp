#include <string.h>
#include <stdio.h>
#include <linux/elf.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <android/log.h>
#include "LibraryDecryptor.h"

static unsigned elfhash(const char* name) {
    const unsigned char *uname = (const unsigned char *) name;
    unsigned h = 0, g;

    while (*uname) {
        h = (h << 4) + *uname++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

LibraryDecryptor::LibraryDecryptor(const std::string& name) :
    libraryName(name) {

}

void LibraryDecryptor::getLibraryAddr() {
    char libName[] = "libmathc.so";
    char buffer[4096] = {0};
    char *token;
    int pid;
    FILE *fp;

    pid = getpid();
    sprintf(buffer, "/proc/%d/maps", pid);
    fp = fopen(buffer, "r");
    if (fp == NULL) {
        puts("open process map file failed. ");
        return;
    }
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, libName)) {
            token = strtok(buffer, "-");
            this->baseAddr = strtoul(token, NULL, 16);
            break;
        }
    }
    fclose(fp);
}

bool LibraryDecryptor::findSymbolAddr(const char *methodName) {
    Elf32_Ehdr *elfHeader;
    Elf32_Phdr *programHeader;

    elfHeader = reinterpret_cast<Elf32_Ehdr*>(baseAddr);
    programHeader = reinterpret_cast<Elf32_Phdr*>(baseAddr + elfHeader->e_phoff);
    for (int i = 0; i < elfHeader->e_phnum; i++) {
        if (programHeader->p_type == PT_DYNAMIC) {
            break;
        }
        programHeader++;
    }

    Elf32_Addr dynamicAddr = programHeader->p_vaddr + baseAddr;
    int dynamicCount = programHeader->p_filesz / sizeof(Elf32_Dyn);
    for (int i = 0; i < dynamicCount; i++) {
        Elf32_Dyn *dynamic = reinterpret_cast<Elf32_Dyn *>(dynamicAddr) + i;
        if (dynamic->d_tag == DT_SYMTAB) {
            symtabAddr = baseAddr + dynamic->d_un.d_ptr;
        } else if (dynamic->d_tag == DT_HASH) {
            hashAddr = baseAddr + dynamic->d_un.d_ptr;
        } else if (dynamic->d_tag == DT_STRTAB) {
            strtabAddr = baseAddr + dynamic->d_un.d_ptr;
        } else if (dynamic->d_tag == DT_STRSZ) {
            strtabSize = dynamic->d_un.d_val;
        }
    }
    Elf32_Sym *symbol = reinterpret_cast<Elf32_Sym*>(symtabAddr);
    char *strtab = reinterpret_cast<char *>(strtabAddr);
    nbucket = *reinterpret_cast<Elf32_Word *>(hashAddr);
    bucketAddr = hashAddr + 2 * sizeof(Elf32_Word);
    chainAddr = bucketAddr + nbucket * sizeof(Elf32_Word);

    int methodIndex = elfhash(methodName) % nbucket;
    for (int i = reinterpret_cast<int *>(bucketAddr)[methodIndex]; i != 0; i = reinterpret_cast<int *>(chainAddr)[i]) {
        Elf32_Sym *currentSymbol = symbol + i;
        if (strcmp(strtab + currentSymbol->st_name, methodName) == 0) {
            methodAddr = baseAddr + currentSymbol->st_value;
            methodSize = currentSymbol->st_size;
            __android_log_print(ANDROID_LOG_INFO, "LibraryDecryptor", "Find symbol %s at: %x(Relative), size: %d", strtab + currentSymbol->st_name, currentSymbol->st_value, currentSymbol->st_size);
            return true;
        }
    }

    __android_log_print(ANDROID_LOG_ERROR, "LibraryDecryptor", "Find symbol \'%s\' failed. ", methodName);
    return false;
}

void LibraryDecryptor::decryptSymbol(const std::string& methodName) {
    this->findSymbolAddr(methodName.c_str());
    int pageCount = methodSize / PAGE_SIZE + (methodSize % PAGE_SIZE == 0 ? 0 : 1);
    if (mprotect((void *) (methodAddr / PAGE_SIZE * PAGE_SIZE), 4096 * pageCount, PROT_READ | PROT_EXEC | PROT_WRITE) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, "LibraryDecryptor", "Change memory privilege failed. ");
    }

    __android_log_print(ANDROID_LOG_INFO, "LibraryDecryptor", "Base address is: %x, Method address is: %x", baseAddr, methodAddr);
    for (int i = 0; i < methodSize; i++) {
        char *addr = reinterpret_cast<char *>(methodAddr + i);
        *addr = ~(*addr);
    }

    if (mprotect((void *) (methodAddr / PAGE_SIZE * PAGE_SIZE), 4096 * pageCount, PROT_READ | PROT_EXEC) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, "LibraryDecryptor", "Change memory privilege failed. ");
    }
}

void LibraryDecryptor::process() {
    this->getLibraryAddr();
    this->decryptSymbol(std::string("Java_com_goodix_sotest_NativeMath_add"));
}
