#ifndef _LIBRARYDECODER_H_
#define _LIBRARYDECODER_H_


#include <linux/elf.h>
#include <string>

class LibraryDecryptor {
private:
    std::string libraryName;

    Elf32_Addr baseAddr;
    Elf32_Addr hashAddr;
    Elf32_Addr symtabAddr;
    Elf32_Addr strtabAddr;
    Elf32_Word strtabSize;
    Elf32_Word nbucket;
    Elf32_Word nchain;
    Elf32_Addr bucketAddr;
    Elf32_Addr chainAddr;
    Elf32_Addr methodAddr;
    Elf32_Word methodSize;

    void getLibraryAddr();
    bool findSymbolAddr(const char *methodName);
    void decryptSymbol(const std::string& methodName);
public:
    LibraryDecryptor(const std::string& libraryName);
    void process();
};

#endif
