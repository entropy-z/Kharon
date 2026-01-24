# Compiler and flags
CC = x86_64-w64-mingw32-g++
CFLAGS = -c -Wall -O2 -w
INCFLAGS = -I Include

# Output directory
DIST_DIR = dist

# Source files - File System
FS_SRCS = file_system/cat.cc \
          file_system/cp.cc \
          file_system/ls.cc \
          file_system/mkdir.cc \
          file_system/mv.cc \
          file_system/pwd.cc \
          file_system/rm.cc

# Source files - Hardware Breakpoint Force
HWBP_SRCS = hwbp_force/disable.cc \
            hwbp_force/enable.cc

# Source files - Injection
INJ_SRCS = injection/explicit_classic.cc \
           injection/spawn_classic.cc

# Source files - Process
PROC_SRCS = process/creation.cc \
            process/grep.cc \
            process/kill.cc \
            process/list.cc

# Source files - Remote BOF
RBOF_SRCS = remote_bof/entry.cc \
            remote_bof/rpc.cc

# All source files
ALL_SRCS = $(FS_SRCS) $(HWBP_SRCS) $(INJ_SRCS) $(PROC_SRCS) $(RBOF_SRCS)

# Convert source files to object files in dist directory
OBJS = $(patsubst %.cc,$(DIST_DIR)/%.x64.o,$(ALL_SRCS))

# Default target
all: $(DIST_DIR) $(OBJS)

# Create dist directory
$(DIST_DIR):
	@mkdir -p $(DIST_DIR)/file_system
	@mkdir -p $(DIST_DIR)/hwbp_force
	@mkdir -p $(DIST_DIR)/injection
	@mkdir -p $(DIST_DIR)/process
	@mkdir -p $(DIST_DIR)/remote_bof

# Compile each .cc to .o
$(DIST_DIR)/%.x64.o: %.cc
	$(CC) $(CFLAGS) $(INCFLAGS) -o $@ $<

# Clean target
clean:
	rm -rf $(DIST_DIR)

# Help target
help:
	@echo Available targets:
	@echo   all   - Build all object files in dist/
	@echo   clean - Remove dist/ directory
	@echo   help  - Show this help message

.PHONY: all clean help