#include <android/log.h>
#include "com_goodix_sotest_NativeMath.h"
#include "Initializer.h"
//#include "LibraryDecryptor.h"

JNIEXPORT jint JNICALL Java_com_goodix_sotest_NativeMath_add
  (JNIEnv *env, jclass cls, jint a, jint b) {
    return a + b;
}

/*__attribute__((constructor))*/ extern "C" void init() {
    __android_log_print(ANDROID_LOG_DEBUG, "test", "Shared library init func. ");
    __android_log_print(ANDROID_LOG_INFO, "test", "init function addr: %x", init);
    //doInitialize();
    /*LibraryDecryptor *decryptor = new LibraryDecryptor(std::string("libmathc.so"));
    decryptor->process();
    delete decryptor;*/
}
