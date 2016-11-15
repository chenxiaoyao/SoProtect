#include "Generator.h"

int main(int argc, char *argv[]) {
    Generator *gen = new Generator(argv[1], argv[2]);
    gen->generate();
    delete gen;
    return 0;
}
