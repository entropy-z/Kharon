# Compiler and flags
CC = x86_64-w64-mingw32-g++
CFLAGS = -c -Os -w -mno-stack-arg-probe
INCFLAGS = -I Include

# Output directory
DIST_DIR = dist

# Source files with full paths
FS_SRCS = file_system/cat.cc file_system/cp.cc file_system/ls.cc \
          file_system/mkdir.cc file_system/mv.cc file_system/pwd.cc \
          file_system/rm.cc file_system/cd.cc

HWBP_SRCS = hwbp_force/disable.cc hwbp_force/enable.cc
INJ_SRCS  = injection/scinject.cc
PROC_SRCS = process/create.cc process/grep.cc process/kill.cc process/list.cc

# All source files
ALL_SRCS = $(FS_SRCS) $(HWBP_SRCS) $(INJ_SRCS) $(PROC_SRCS) $(RBOF_SRCS)

# Object files (extract basename and add to dist/)
OBJS = $(addprefix $(DIST_DIR)/,$(notdir $(ALL_SRCS:.cc=.x64.o)))

# Default target
all: $(DIST_DIR) $(OBJS)

# Create dist directory
$(DIST_DIR):
	@mkdir -p $(DIST_DIR)

# Pattern rules for each subdirectory
$(DIST_DIR)/%.x64.o: file_system/%.cc
	$(CC) $(CFLAGS) $(INCFLAGS) -o $@ $<

$(DIST_DIR)/%.x64.o: hwbp_force/%.cc
	$(CC) $(CFLAGS) $(INCFLAGS) -o $@ $<

$(DIST_DIR)/%.x64.o: injection/%.cc
	$(CC) $(CFLAGS) $(INCFLAGS) -o $@ $<

$(DIST_DIR)/%.x64.o: process/%.cc
	$(CC) $(CFLAGS) $(INCFLAGS) -o $@ $<

$(DIST_DIR)/%.x64.o: remote_bof/%.cc
	$(CC) $(CFLAGS) $(INCFLAGS) -o $@ $<

# Clean target
clean:
	rm -rf $(DIST_DIR)

# Help target
help:
	@echo "Available targets:"
	@echo "  all   - Build all object files in dist/"
	@echo "  clean - Remove dist/ directory"
	@echo "  help  - Show this help message"

.PHONY: all clean help