NAME   := Kharon

BUILD_PATH ?= .

CCX64  := clang++ -target x86_64-w64-mingw32
CCX86  := clang++ -target i686-w64-mingw32

CFLAGS := -Os -nostdlib -fno-asynchronous-unwind-tables -std=c++20 -w -s -I./ -mwindows
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup -masm=intel -fno-exceptions

SRC    := $(wildcard ./*.cc)

OBJ64  := $(SRC:%.cc=%.x64.obj) 
OBJ86  := $(SRC:%.cc=%.x86.obj) 

all: release debug
release: x64 x86
debug: 	 x64-debug x86-debug

x64-debug: CFLAGS += -D DEBUG
x64-debug: x64

x86-debug: CFLAGS += -D DEBUG
x86-debug: x86

x64: $(OBJ64)
	@ echo "compiling x64 project"
	@ $(CCX64) $(BUILD_PATH)/Bin/obj/*.x64.obj -o $(BUILD_PATH)/Bin/$(NAME).x64.exe $(CFLAGS) 

x86: $(OBJ86)
	@ echo "compiling x86 project"
	@ $(CCX86) $(BUILD_PATH)Bin//obj/*.x86.obj -o $(BUILD_PATH)/$(NAME).x86.exe $(CFLAGS)

%.x64.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX64) -o $(BUILD_PATH)/Bin/obj/$(notdir $@) -c $< $(CFLAGS)

%.x86.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX86) -o $(BUILD_PATH)/Bin/obj/$(notdir $@) -c $< $(CFLAGS) $(DEFS)

clean:
	@ rm -f $(BUILD_PATH)/obj/*.x64.obj
	@ rm -f $(BUILD_PATH)/obj/*.x86.obj
	@ rm -f $(BUILD_PATH)/*.exe
	@ rm -f $(BUILD_PATH)/*.Bin
	@ echo "removed object files"