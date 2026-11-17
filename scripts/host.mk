# The host's build environment, included by the Makefiles after they set ROOT.
#
# A macOS host takes its tools and build folders from scripts/host-env.sh: GNU tools
# ahead of the system's, bash 5 for recipes, and the caches on the case-sensitive volume.
# A sub-make finds GEX_HOST_ENV set and keeps what its parent exported.
ifeq ($(shell uname -s),Darwin)
ifeq ($(filter 4.%,$(MAKE_VERSION)),)
$(error GNU make 4 or later is needed, this make is $(MAKE_VERSION): run gmake)
endif
ifndef GEX_HOST_ENV
GEX_HOST_SETTINGS := $(shell bash $(ROOT)/scripts/host-env.sh --make)
ifneq ($(.SHELLSTATUS),0)
$(error scripts/host-env.sh failed)
endif
$(foreach s,$(GEX_HOST_SETTINGS),$(eval export $(s)))
export PATH := $(GEX_PATH):$(PATH)
endif
SHELL := $(GEX_BASH)
endif
