LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)


LOCAL_SRC_FILES:= \
    gdlfcn.cpp \
    linker.cpp \
    linker_phdr.cpp \
	Shell.cpp \
	Utils.cpp

LOCAL_LDFLAGS := -shared -Wl,--exclude-libs,ALL

LOCAL_CFLAGS += -fno-stack-protector \
        -Wstrict-overflow=5 \
        -fvisibility=hidden \
        -Wall -Wextra


ifeq ($(TARGET_ARCH),arm)
    LOCAL_CFLAGS += -DANDROID_ARM_LINKER
endif

ifeq ($(TARGET_ARCH),x86)
    LOCAL_CFLAGS += -DANDROID_X86_LINKER
endif

ifeq ($(TARGET_ARCH),mips)
    LOCAL_CFLAGS += -DANDROID_MIPS_LINKER
endif

LOCAL_MODULE:= gshell

TARGET_PLATFORM := android-3
LOCAL_LDLIBS    := -llog -Wl,-init=init
APP_PLATFORM    := android-19

include $(BUILD_SHARED_LIBRARY)
