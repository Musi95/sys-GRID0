# sys-zerotier Ultrahand/Tesla overlay
.SUFFIXES:

ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO (for example /opt/devkitpro)")
endif

# The parent sysmodule Makefile exports TOPDIR. Recompute it from this file so
# `make bundle` cannot accidentally look for libultrahand in the repo root.
TOPDIR := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))
include $(DEVKITPRO)/libnx/switch_rules

APP_TITLE   := sys-zerotier
APP_AUTHOR  := sys-zerotier contributors
APP_VERSION := 1.0.1
TARGET      := sys-zerotier
BUILD       := build
SOURCES     := source
INCLUDES    := source include
NO_ICON     := 1

include $(TOPDIR)/lib/libultrahand/ultrahand.mk

ARCH := -march=armv8-a+simd+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE
CFLAGS := -g -Wall -O2 -ffunction-sections -fdata-sections -flto \
	-fuse-linker-plugin -fomit-frame-pointer -fno-strict-aliasing $(ARCH) $(DEFINES)
CFLAGS += $(INCLUDE) -D__SWITCH__ -DAPP_VERSION="\"$(APP_VERSION)\"" \
	-DUI_OVERRIDE_PATH="\"/config/sys-zerotier/overlay/\"" \
	-DUSE_EXCEPTION_WRAP=1 -D_FORTIFY_SOURCE=2
CXXFLAGS := $(CFLAGS) -std=gnu++23 -fno-exceptions -fno-rtti \
	-fno-unwind-tables -fno-asynchronous-unwind-tables
ASFLAGS := $(ARCH)
LDFLAGS := -specs=$(DEVKITPRO)/libnx/switch.specs $(ARCH) \
	-Wl,-Map,$(notdir $*.map) -Wl,--gc-sections -Wl,--as-needed \
	-Wl,-wrap,__cxa_throw -Wl,-wrap,_Unwind_Resume -Wl,-wrap,__gxx_personality_v0
LIBS := -lcurl -lz -lminizip -lmbedtls -lmbedx509 -lmbedcrypto -lnx
LIBDIRS := $(PORTLIBS) $(LIBNX)

ifneq ($(BUILD),$(notdir $(CURDIR)))

export OUTPUT := $(CURDIR)/$(TARGET)
export TOPDIR := $(CURDIR)
export VPATH := $(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR := $(CURDIR)/$(BUILD)

CFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))

export LD := $(CXX)
export OFILES := $(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)
export INCLUDE := $(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
	$(foreach dir,$(LIBDIRS),-I$(dir)/include) -I$(CURDIR)/$(BUILD)
export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib)

# Ultrahand's overlay scanner reads the title and version from the NACP asset.
# Merely building the .nacp is not enough: elf2nro only embeds it when this flag
# is present. Without it, getOverlayInfo() rejects the .ovl and silently omits
# it from the Overlays page even though the file and ULTR signature are valid.
ifeq ($(strip $(NO_NACP)),)
	export NROFLAGS += --nacp=$(CURDIR)/$(TARGET).nacp
endif

.PHONY: all clean $(BUILD)
all: $(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

clean:
	@rm -rf $(BUILD) $(TARGET).ovl $(TARGET).nro $(TARGET).nacp $(TARGET).elf

else

DEPENDS := $(OFILES:.o=.d)
.PHONY: all
all: $(OUTPUT).ovl

$(OUTPUT).ovl: $(OUTPUT).elf $(OUTPUT).nacp
	@elf2nro $< $@ $(NROFLAGS)
	@printf 'ULTR' >> $@
	@echo built ... $(notdir $@)

$(OUTPUT).elf: $(OFILES)

-include $(DEPENDS)

endif
