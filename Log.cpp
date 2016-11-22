#include <stdlib.h>

#include "Log.h"

void __libc_fatal(const char* format, ...) {
  va_list args;
  va_start(args, format);
  GLogError("Fatal", format, args);
  va_end(args);
  abort();
}

