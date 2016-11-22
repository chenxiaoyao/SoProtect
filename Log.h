#ifndef _LOG_H_
#define _LOG_H_

#define debug 1

#if debug

#if __ANDROID__
#include <android/log.h>
#define GLogError(tag, ...) __android_log_print(ANDROID_LOG_ERROR, tag, __VA_ARGS__)
#define GLogWarn(tag, ...) __android_log_print(ANDROID_LOG_WARN, tag, __VA_ARGS__)
#define GLogInfo(tag, ...) __android_log_print(ANDROID_LOG_INFO, tag, __VA_ARGS__)
#else
#include <stdio.h>
#define GLogError(tag, ...) printf(__VA_ARGS__)
#define GLogWarn(tag, ...) printf(__VA_ARGS__)
#define GLogInfo(tag, ...) printf(__VA_ARGS__)
#endif

void __libc_fatal(const char* format, ...);

#endif

#endif
