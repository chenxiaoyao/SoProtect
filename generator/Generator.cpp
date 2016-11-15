#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "Generator.h"

#define MAX_LEN 256

Generator::Generator(const char *clientSo, const char *shellSo) {
    strncpy(this->clientSoPath, clientSo, sizeof(this->clientSoPath));
    strncpy(this->shellSoPath, shellSo, sizeof(this->shellSoPath));
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
    printf("Packed so path: %s\n", packedSoPath);

    int clientFd, shellFd, packedFd;
    clientFd = open(this->clientSoPath, O_RDONLY);
    shellFd = open(this->shellSoPath, O_RDONLY);
    packedFd = open(packedSoPath, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

    Elf32_Ehdr ehdr = {0};
    read(shellFd, &ehdr, sizeof(ehdr));
    lseek(shellFd, 0, SEEK_SET);
    int size = this->copyFileContent(packedFd, shellFd);
    int pageAlignedSize = PAGE_END(size);
    int zero = 0;
    for (int i = size; i < pageAlignedSize; i++) {
        write(packedFd, &zero, 1);
    }

    int clientSoOffset = pageAlignedSize;
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
