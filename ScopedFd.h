#ifndef SCOPED_FD_H
#define SCOPED_FD_H

#include <unistd.h>
#include "extra_defines.h"

// A smart pointer that closes the given fd on going out of scope.
// Use this when the fd is incidental to the purpose of your function,
// but needs to be cleaned up on exit.
class ScopedFd {
public:
    explicit ScopedFd(int fd) : fd(fd) {
    }

    ~ScopedFd() {
      reset();
    }

    int get() const {
        return fd;
    }

    int release() __attribute__((warn_unused_result)) {
        int localFd = fd;
        fd = -1;
        return localFd;
    }

    void reset(int new_fd = -1) {
      if (fd != -1) {
          TEMP_FAILURE_RETRY(close(fd));
      }
      fd = new_fd;
    }

private:
    int fd;

    // Disallow copy and assignment.
    DISALLOW_COPY_AND_ASSIGN(ScopedFd);
};

#endif  // SCOPED_FD_H
