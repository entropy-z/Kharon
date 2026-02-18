CC = x86_64-w64-mingw32-g++
CFLAGS = -c -Os -w -fno-exceptions -fno-rtti -mno-stack-arg-probe -fpermissive
INCFLAGS = -I include

DIST_DIR = dist

ALL_SRCS := $(shell find active_script az dotnet_list lateralmov stealer -name '*.cc')
OBJS := $(addprefix $(DIST_DIR)/,$(notdir $(ALL_SRCS:.cc=.x64.o)))

all: $(DIST_DIR) $(OBJS)

$(DIST_DIR):
	@mkdir -p $(DIST_DIR)

$(DIST_DIR)/%.x64.o:
	$(CC) $(CFLAGS) $(INCFLAGS) -o $@ $(shell find . -name $*.cc)

clean:
	rm -rf $(DIST_DIR)

.PHONY: all clean
