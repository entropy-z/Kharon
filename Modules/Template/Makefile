NAME   := Kharon

BUILD_PATH ?= .

CCX64  := clang -target x86_64-w64-mingw32
CCX86  := clang -target i686-w64-mingw32
ASMCC  := nasm

CFLAGS := -Os -nostdlib -fno-asynchronous-unwind-tables -std=c++20
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1 -w -mno-sse -s
CFLAGS += -ffunction-sections -falign-jumps=1 -falign-labels=1 -mrdrnd
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup -masm=intel -fno-exceptions
CFLAGS += -fms-extensions -fPIC -IInclude -Wl,-TLinker.ld

SRC    := $(wildcard Source/*.cc)

OBJ64  := $(SRC:%.cc=%.x64.obj)
OBJ86  := $(SRC:%.cc=%.x86.obj) 

all: release debug
release: x64 x86
debug: 	 x64-debug x86-debug

x64-debug: CFLAGS += -D DEBUG
x64-debug: x64

x86-debug: CFLAGS += -D DEBUG
x86-debug: x86

x64: nasm64 $(OBJ64)
	@ echo "compiling x64 project"
	@ $(CCX64) $(BUILD_PATH)/Bin/obj/*.x64.obj -o $(BUILD_PATH)/Bin/$(NAME).x64.exe $(CFLAGS)
	@ objcopy --dump-section .text=$(BUILD_PATH)/Bin/$(NAME).x64.bin $(BUILD_PATH)/Bin/$(NAME).x64.exe
	# @ rm $(BUILD_PATH)/$(NAME).x64.exe

x86: nasm86 $(OBJ86)
	@ echo "compiling x86 project"
	@ $(CCX86) $(BUILD_PATH)/obj/*.x86.obj -o $(BUILD_PATH)/$(NAME).x86.exe $(CFLAGS)
	@ objcopy --dump-section .text=$(BUILD_PATH)/Bin/$(NAME).x86.bin $(BUILD_PATH)/Bin/$(NAME).x86.exe
	@ rm $(BUILD_PATH)/Bin/$(NAME).x86.exe

%.x64.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX64) -o $(BUILD_PATH)/Bin/obj/$(notdir $@) -c $< $(CFLAGS) $(DEFS)

%.x86.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX86) -o $(BUILD_PATH)/Bin/obj/$(notdir $@) -c $< $(CFLAGS) $(DEFS)

nasm64:
	@ $(ASMCC) -f win64 Source/Asm/Entry.x64.asm -o $(BUILD_PATH)/Bin/obj/entry.x64.obj

nasm86:
	@ $(ASMCC) -f win32 Source/Asm/Entry.x64.asm -o $(BUILD_PATH)/Bin/obj/entry.x86.obj

clean:
	@ rm -f $(BUILD_PATH)/obj/*.x64.obj
	@ rm -f $(BUILD_PATH)/obj/*.x86.obj
	@ rm -f $(BUILD_PATH)/*.exe
	@ rm -f $(BUILD_PATH)/*.Bin
	@ echo "removed object files"