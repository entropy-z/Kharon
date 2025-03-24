NAME   := Kharon

CCX64  := clang -target x86_64-w64-mingw32
CCX86  := clang -target i686-w64-mingw32
ASMCC  := nasm

CFLAGS := -Os -nostdlib -fno-asynchronous-unwind-tables -std=c++20
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1 -s -w -mno-sse
CFLAGS += -ffunction-sections -falign-jumps=1 -falign-labels=1 
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup -masm=intel -fno-exceptions
CFLAGS += -fms-extensions -fPIC -Iinclude -Wl,-TLinker.ld

SRC    := $(wildcard Source/*.cc)
MISC   := $(wildcard Source/Misc/*.cc)
COMM   := $(wildcard Source/Communication/*.cc)
OBJ64  := $(SRC:%.cc=%.x64.obj) $(MISC:%.cc=%.x64.obj) $(COMM:%.cc=%.x64.obj)
OBJ86  := $(SRC:%.cc=%.x86.obj) $(MISC:%.cc=%.x86.obj) $(COMM:%.cc=%.x86.obj)

all: release debug
release: x64 x86
debug: 	 x64-debug x86-debug

x64-debug: CFLAGS += -D DEBUG
x64-debug: x64

x86-debug: CFLAGS += -D DEBUG
x86-debug: x86

x64: nasm64 $(OBJ64)
	@ echo "compiling x64 project"
	@ $(CCX64) Bin/obj/*.x64.obj -o Bin/$(NAME).x64.exe $(CFLAGS)
	@ objcopy --dump-section .text=Bin/$(NAME).x64.Bin Bin/$(NAME).x64.exe
	@ rm Bin/$(NAME).x64.exe

x86: nasm86 $(OBJ86)
	@ echo "compiling x86 project"
	@ $(CCX86) Bin/obj/*.x86.obj -o Bin/$(NAME).x86.exe $(CFLAGS)
	@ objcopy --dump-section .text=Bin/$(NAME).x86.Bin Bin/$(NAME).x86.exe
	@ rm Bin/$(NAME).x86.exe

%.x64.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX64) -o Bin/obj/$(notdir $@) -c $< $(CFLAGS)

%.x86.obj: %.cc
	@ echo "-> compiling $< to $(notdir $@)"
	@ $(CCX86) -o Bin/obj/$(notdir $@) -c $< $(CFLAGS)

nasm64:
	@ $(ASMCC) -f win64 Source/Asm/Entry.x64.asm -o Bin/obj/entry.x64.obj

nasm86:
	@ $(ASMCC) -f win32 Source/Asm/Entry.x64.asm -o Bin/obj/entry.x86.obj

stomper:
	@ $(CCX64) test/stomper.cc -o test/stomper.x64.exe -w
	@ $(CCX86) test/stomper.cc -o test/stomper.x86.exe -w

clean:
	@ rm -f Bin/obj/*.x64.obj
	@ rm -f Bin/obj/*.x86.obj
	@ rm -f Bin/*.exe
	@ rm -f Bin/*.Bin
	@ echo "removed object files"