#include <elf.h>
#include <dlfcn.h>
#include <android/log.h>

#include "com_goodix_sotest_NativeMath.h"

JNIEXPORT void JNICALL Java_com_goodix_sotest_NativeMath_unload
(JNIEnv *env, jclass cls) {
    void *si = dlopen("libmathc.so", RTLD_LAZY);
    if (si == 0) {
        __android_log_print(ANDROID_LOG_INFO, "unload", "dlopen libmathc failed. ");
        return;
    }
    __android_log_print(ANDROID_LOG_INFO, "unload", "libmathc reference count: %d", ((unsigned *)si)[62]);
    dlclose(si);
    dlclose(si);
}
