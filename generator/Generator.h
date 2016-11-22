#ifndef _GENERATOR_H_
#define _GENERATOR_H_

#include <elf.h>

#define MAX_PATH_LENGTH 256

#ifndef PAGE_SIZE

#define PAGE_SIZE 4096
#define PAGE_MASK (~(PAGE_SIZE - 1))

#endif

// Returns the address of the page containing address 'x'.
#define PAGE_START(x)  ((x) & PAGE_MASK)

// Returns the offset of address 'x' in its page.
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)

// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))


class Generator {
private:
    char clientSoPath[MAX_PATH_LENGTH];
    char shellSoPath[MAX_PATH_LENGTH];
    int copyFileContent(int destFd, int srcFd);
    void checkElfClass(const char *soPath, int fd);
public:
    Generator(const char *clientSo, const char *shellSo);
    void generate();
};

#endif
