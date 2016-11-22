#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "Generator.h"

#define MAX_LEN 256

#if defined(__LP64__)
#define ElfW(what) Elf64_ ## what
#else
#define ElfW(what) Elf32_ ## what
#endif


Generator::Generator(const char *clientSo, const char *shellSo) {
    strncpy(this->clientSoPath, clientSo, sizeof(this->clientSoPath));
    strncpy(this->shellSoPath, shellSo, sizeof(this->shellSoPath));
}

void Generator::checkElfClass(const char *soPath, int fd) {
    lseek(fd, 0, SEEK_SET);
    char eident[16] = {0};
    read(fd, eident, sizeof(eident));
#ifdef __LP64__
    if (eident[EI_CLASS] == ELFCLASS32) {
        printf("So library: %s is not 64 bit, but current generator is 64 bit, please use correct version. ", soPath);
        abort();
    }
#else
    if (eident[EI_CLASS] == ELFCLASS64) {
        printf("So library: %s is not 32 bit, but current generator is 32 bit, please use correct version. ", soPath);
    }
#endif
    if (eident[EI_CLASS] != ELFCLASS32 && eident[EI_CLASS] != ELFCLASS64) {
        printf("So library: %s is not 32 bit or 64 bit, can not be operated. ", soPath);
        abort();
    }
    lseek(fd, 0, SEEK_SET);
}

void Generator::generate() {
    char packedSoPath[MAX_PATH_LENGTH] = {0};
    char *pos = strrchr(this->clientSoPath, '.');
    if (pos == NULL) {
        return;
    }

    *pos = '\0';
    sprintf(packedSoPath, "%s_packed.so", this->clientSoPath);
    *pos = '.';

    int clientFd, shellFd, packedFd;
    clientFd = open(this->clientSoPath, O_RDONLY);
    shellFd = open(this->shellSoPath, O_RDONLY);
    packedFd = open(packedSoPath, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

    checkElfClass(this->clientSoPath, clientFd);
    checkElfClass(this->shellSoPath, shellFd);

    ElfW(Ehdr) ehdr = {0};
    read(shellFd, &ehdr, sizeof(ehdr));
    lseek(shellFd, 0, SEEK_SET);
    int size = this->copyFileContent(packedFd, shellFd);
    int pageAlignedSize = PAGE_END(size);
    int zero = 0;
    for (int i = size; i < pageAlignedSize; i++) {
        write(packedFd, &zero, 1);
    }

    ElfW(Off) clientSoOffset = pageAlignedSize;
    this->copyFileContent(packedFd, clientFd);

    ehdr.e_shoff = ~ clientSoOffset;
    lseek(packedFd, 0, SEEK_SET);
    write(packedFd, &ehdr, sizeof(ehdr));

    close(clientFd);
    close(shellFd);
    close(packedFd);
}

int Generator::copyFileContent(int destFd, int srcFd) {
    char buffer[MAX_LEN];
    int len = 0;
    int size = 0;
    while ((len = read(srcFd, buffer, MAX_LEN)) > 0) {
        write(destFd, buffer, len);
        size += len;
    }
    return size;
}
