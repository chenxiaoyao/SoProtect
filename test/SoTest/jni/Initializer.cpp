#include "Initializer.h"
#include "LibraryDecryptor.h"

void doInitialize() {
    LibraryDecryptor *decryptor = new LibraryDecryptor(std::string("libmathc.so"));
    decryptor->process();
    delete decryptor;
}
