#include <elf.h>

#include "linker.h"

#ifndef _SHELL_H_
#define _SHELL_H_

#define MAX_NAME_LENGTH 256

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((constructor)) void init();
__attribute__((destructor)) void fini();

#ifdef __cplusplus
}
#endif

class Shell {
private:
    char libraryName[MAX_NAME_LENGTH];
    soinfo backupShellSoInfo;
    soinfo *shellSoInfo;
    soinfo *clientSoInfo;

    void setSoInfoProtection(void *addr, int protection);

public:
    Shell();
    ~Shell();
    void loadClientLibrary();
    void updateSoInfo();
    void restoreSoInfo();
};

#endif
