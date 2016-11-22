LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)


LOCAL_SRC_FILES:= \
    gdlfcn.cpp \
    linker.cpp \
    linker_allocator.cpp \
    linker_phdr.cpp \
	Shell.cpp \
	Log.cpp \
	Utils.cpp

LOCAL_LDFLAGS := \
    -shared \
    -Wl,-Bsymbolic \
    -Wl,--exclude-libs,ALL \

LOCAL_CFLAGS += \
    -fno-stack-protector \
    -Wstrict-overflow=5 \
    -fvisibility=hidden \
    -Wall -Wextra -Wunused

LOCAL_CONLYFLAGS += \
    -std=gnu99 \

LOCAL_CPPFLAGS += \
    -std=gnu++11 \


LOCAL_MODULE:= gshell

TARGET_PLATFORM := android-16
LOCAL_LDLIBS    := -llog
APP_PLATFORM    := android-19

include $(BUILD_SHARED_LIBRARY)
