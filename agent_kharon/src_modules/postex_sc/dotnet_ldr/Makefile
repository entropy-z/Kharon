NAME   := dotnet_assembly

BUILD_PATH ?= .

CCX64  := clang++ -target x86_64-w64-mingw32
CCX86  := clang++ -target i686-w64-mingw32
ASMCC  := nasm

CFLAGS := -Os -nostdlib -fno-asynchronous-unwind-tables -std=c++20 -fPIC 
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1 -w -mno-sse -s -Wno-error=nested-anon-types
CFLAGS += -ffunction-sections -falign-jumps=1 -falign-labels=1 -mrdrnd -fno-builtin -ffreestanding
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup -masm=intel -fno-exceptions
CFLAGS += -fms-extensions -Iinclude -Wl,-TLinker.ld -Wno-error=anonymous-struct

SRC    := $(wildcard src/*.cc)
OBJ64  := $(SRC:%.cc=%.x64.obj) 
OBJ86  := $(SRC:%.cc=%.x86.obj)

all: release debug
release: x64 x86
debug: 	 x64-debug x86-debug

x64-release: x64
x86-release: x86

x64-debug: CFLAGS += -D DEBUG
x64-debug: x64

x86-debug: CFLAGS += -D DEBUG
x86-debug: x86

x64: nasm64 $(OBJ64)
	@ echo "compiling x64 project"
	@ $(CCX64) $(BUILD_PATH)/bin/obj/*.x64.obj -o $(BUILD_PATH)/bin/$(NAME).x64.exe $(CFLAGS) 
	@ objcopy --dump-section .text=$(BUILD_PATH)/Bin/$(NAME).x64.bin $(BUILD_PATH)/Bin/$(NAME).x64.exe
	@ rm $(BUILD_PATH)/bin/$(NAME).x64.exe

%.x64.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX64) -o $(BUILD_PATH)/bin/obj/$(notdir $@) -c $< $(CFLAGS) $(DEFS)

%.x86.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX86) -o $(BUILD_PATH)/bin/obj/$(notdir $@) -c $< $(CFLAGS) $(DEFS)

nasm64:
	@ $(ASMCC) -f win64 src/asm/start.x64.s -o $(BUILD_PATH)/bin/obj/start.x64.obj
	@ $(ASMCC) -f win64 src/asm/spoof.x64.s -o $(BUILD_PATH)/bin/obj/spf.x64.obj

clean:
	@ rm -f $(BUILD_PATH)/obj/*.x64.obj
	@ rm -f $(BUILD_PATH)/obj/*.x86.obj
	@ rm -f $(BUILD_PATH)/*.exe
	@ rm -f $(BUILD_PATH)/*.bin
	@ echo "removed object files"