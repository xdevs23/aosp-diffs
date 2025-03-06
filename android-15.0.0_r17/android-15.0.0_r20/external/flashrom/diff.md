```diff
diff --git a/.gitignore b/.gitignore
index 4e387392..d1cf656d 100644
--- a/.gitignore
+++ b/.gitignore
@@ -1,5 +1,4 @@
 *.d
-!Makefile.d/
 *.o
 /.doctrees
 /.features
diff --git a/Android.bp b/Android.bp
index 41482b54..12e4ca50 100644
--- a/Android.bp
+++ b/Android.bp
@@ -94,6 +94,7 @@ cc_library {
     host_supported: true,
     vendor_available: true,
     visibility: ["//external/vboot_reference"],
+    init_rc: ["flashrom.rc"],
 
     target: {
         linux: {
diff --git a/MAINTAINERS b/MAINTAINERS
index 7f859b7c..c54eceb7 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -79,13 +79,9 @@ Maintainers List (try to look for most precise areas first)
 BUILD SYSTEM
 M:	Peter Marheine <pmarheine@chromium.org>
 S:	Maintained
-F:	Makefile*
 F:	meson*
-F:	Makefile*/
 F:	*/meson*
-F:	*/Makefile*
 F:	util/ich_descriptors_tool/meson*
-F:	util/ich_descriptors_tool/Makefile*
 
 ERASE/WRITE ALGORITHM
 M:	Aarya Chaumal <aarya.chaumal@gmail.com>
@@ -137,6 +133,11 @@ M:	Martin Roth <gaumless@tutanota.com>
 S:	Maintained
 F:	sb600spi.c
 
+BUS PIRATE
+M:	David Reguera <regueragarciadavid@gmail.com>
+S:	Maintained
+F:	buspirate_spi.c
+
 CH347
 M:	Nicholas Chin <nic.c3.14@gmail.com>
 S:	Maintained
diff --git a/METADATA b/METADATA
index 7cb4fba9..6ee71fdf 100644
--- a/METADATA
+++ b/METADATA
@@ -1,24 +1,21 @@
-name: "flashrom"
-description:
-    "flashrom is a utility for detecting, reading, writing, verifying and "
-    "erasing flash chips. It is often used to flash BIOS/EFI/coreboot/firmware "
-    "images in-system using a supported mainboard, but it also supports "
-    "flashing of network cards (NICs), SATA controller cards, and other "
-    "external devices which can program flash chips. "
-    " "
-    "It supports a wide range of flash chips (most commonly found in SOIC8, "
-    "DIP8, SOIC16, WSON8, PLCC32,  IP32, TSOP32, and TSOP40 packages), which "
-    "use various protocols such as LPC, FWH, parallel flash, or SPI."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/flashrom
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "flashrom"
+description: "flashrom is a utility for detecting, reading, writing, verifying and erasing flash chips. It is often used to flash BIOS/EFI/coreboot/firmware images in-system using a supported mainboard, but it also supports flashing of network cards (NICs), SATA controller cards, and other external devices which can program flash chips.  It supports a wide range of flash chips (most commonly found in SOIC8, DIP8, SOIC16, WSON8, PLCC32,  IP32, TSOP32, and TSOP40 packages), which use various protocols such as LPC, FWH, parallel flash, or SPI."
 third_party {
+  license_type: RESTRICTED
+  last_upgrade_date {
+    year: 2024
+    month: 11
+    day: 13
+  }
   homepage: "https://flashrom.org/"
   identifier {
     type: "Git"
     value: "https://chromium.googlesource.com/chromiumos/third_party/flashrom/"
+    version: "c08865ab385d8aea6abea48850892e32bb45d5e8"
     primary_source: true
-    version: "main-cros"
   }
-  license_type: RESTRICTED
-  version: "main-cros"
-  last_upgrade_date { year: 2024 month: 6 day: 14 }
 }
diff --git a/Makefile b/Makefile
deleted file mode 100644
index 97f56b83..00000000
--- a/Makefile
+++ /dev/null
@@ -1,1150 +0,0 @@
-#
-# This file is part of the flashrom project.
-#
-# Copyright (C) 2005 coresystems GmbH <stepan@coresystems.de>
-# Copyright (C) 2009,2010,2012 Carl-Daniel Hailfinger
-#
-# This program is free software; you can redistribute it and/or modify
-# it under the terms of the GNU General Public License as published by
-# the Free Software Foundation; version 2 of the License.
-#
-# This program is distributed in the hope that it will be useful,
-# but WITHOUT ANY WARRANTY; without even the implied warranty of
-# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-# GNU General Public License for more details.
-#
-
-PROGRAM = flashrom
-
-###############################################################################
-# Defaults for the toolchain.
-
-# If you want to cross-compile, just run e.g.
-# make CC=i586-pc-msdosdjgpp-gcc
-# You may have to specify STRIP/AR/RANLIB as well.
-#
-# Note for anyone editing this Makefile: gnumake will happily ignore any
-# changes in this Makefile to variables set on the command line.
-STRIP   ?= strip
-STRIP_ARGS = -s
-INSTALL = install
-PREFIX  ?= /usr/local
-MANDIR  ?= $(PREFIX)/share/man
-BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
-CFLAGS  ?= -Os -Wall -Wextra -Wno-unused-parameter -Wshadow -Wmissing-prototypes -Wwrite-strings
-EXPORTDIR ?= .
-RANLIB  ?= ranlib
-PKG_CONFIG ?= pkg-config
-BUILD_DETAILS_FILE ?= build_details.txt
-SPHINXBUILD ?= sphinx-build
-
-# The following parameter changes the default programmer that will be used if there is no -p/--programmer
-# argument given when running flashrom. The predefined setting does not enable any default so that every
-# user has to declare the programmer he wants to use on every run. The rationale for this to be not set
-# (to e.g. the internal programmer) is that forgetting to specify this when working with another programmer
-# easily puts the system attached to the default programmer at risk (e.g. you want to flash coreboot to another
-# system attached to an external programmer while the default programmer is set to the internal programmer, and
-# you forget to use the -p parameter. This would (try to) overwrite the existing firmware of the computer
-# running flashrom). Please do not enable this without thinking about the possible consequences. Possible
-# values can be found when running 'flashrom --list-supported' under the 'Supported programmers' section.
-CONFIG_DEFAULT_PROGRAMMER_NAME ?=
-# The following adds a default parameter for the default programmer set above (only).
-CONFIG_DEFAULT_PROGRAMMER_ARGS ?=
-# Example: compiling with
-#   make CONFIG_DEFAULT_PROGRAMMER_NAME=serprog CONFIG_DEFAULT_PROGRAMMER_ARGS="dev=/dev/ttyUSB0:1500000"
-# would make executing './flashrom' (almost) equivialent to './flashrom -p serprog:dev=/dev/ttyUSB0:1500000'.
-
-# The user can provide CPP, C and LDFLAGS and the Makefile will extend these
-override CPPFLAGS := $(CPPFLAGS)
-override CFLAGS   := $(CFLAGS)
-override LDFLAGS  := $(LDFLAGS)
-
-# If your compiler spits out excessive warnings, run make WARNERROR=no
-# You shouldn't have to change this flag.
-WARNERROR ?= yes
-
-ifeq ($(WARNERROR), yes)
-override CFLAGS += -Werror
-endif
-
-ifdef LIBS_BASE
-PKG_CONFIG_LIBDIR ?= $(LIBS_BASE)/lib/pkgconfig
-override CPPFLAGS += -I$(LIBS_BASE)/include
-override LDFLAGS += -L$(LIBS_BASE)/lib -Wl,-rpath -Wl,$(LIBS_BASE)/lib
-endif
-
-ifeq ($(CONFIG_STATIC),yes)
-override LDFLAGS += -static
-endif
-
-# Set LC_ALL=C to minimize influences of the locale.
-# However, this won't work for the majority of relevant commands because they use the $(shell) function and
-# GNU make does not relay variables exported within the makefile to their environment.
-LC_ALL=C
-export LC_ALL
-
-dummy_for_make_3_80:=$(shell printf "Build started on %s\n\n" "$$(date)" >$(BUILD_DETAILS_FILE))
-
-# Provide an easy way to execute a command, print its output to stdout and capture any error message on stderr
-# in the build details file together with the original stdout output.
-debug_shell = $(shell export LC_ALL=C ; { echo 'exec: export LC_ALL=C ; { $(subst ','\'',$(1)) ; }' >&2; \
-    { $(1) ; } | tee -a $(BUILD_DETAILS_FILE) ; echo >&2 ; } 2>>$(BUILD_DETAILS_FILE))
-
-include Makefile.include
-
-###############################################################################
-# Dependency handling.
-
-DEPENDS_ON_SERIAL := \
-	CONFIG_BUSPIRATE_SPI \
-	CONFIG_PONY_SPI \
-	CONFIG_SERPROG \
-
-DEPENDS_ON_SOCKETS := \
-	CONFIG_SERPROG \
-
-DEPENDS_ON_BITBANG_SPI := \
-	CONFIG_DEVELOPERBOX_SPI \
-	CONFIG_INTERNAL_X86 \
-	CONFIG_NICINTEL_SPI \
-	CONFIG_OGP_SPI \
-	CONFIG_PONY_SPI \
-	CONFIG_RAYER_SPI \
-
-DEPENDS_ON_RAW_MEM_ACCESS := \
-	CONFIG_ATAPROMISE \
-	CONFIG_DRKAISER \
-	CONFIG_GFXNVIDIA \
-	CONFIG_INTERNAL \
-	CONFIG_INTERNAL_X86 \
-	CONFIG_IT8212 \
-	CONFIG_NICINTEL \
-	CONFIG_NICINTEL_EEPROM \
-	CONFIG_NICINTEL_SPI \
-	CONFIG_OGP_SPI \
-	CONFIG_SATAMV \
-	CONFIG_SATASII \
-
-DEPENDS_ON_X86_MSR := \
-	CONFIG_INTERNAL_X86 \
-
-DEPENDS_ON_X86_PORT_IO := \
-	CONFIG_ATAHPT \
-	CONFIG_ATAPROMISE \
-	CONFIG_INTERNAL_X86 \
-	CONFIG_NIC3COM \
-	CONFIG_NICNATSEMI \
-	CONFIG_NICREALTEK \
-	CONFIG_RAYER_SPI \
-	CONFIG_SATAMV \
-
-DEPENDS_ON_LIBPCI := \
-	CONFIG_ASM106X \
-	CONFIG_ATAHPT \
-	CONFIG_ATAPROMISE \
-	CONFIG_ATAVIA \
-	CONFIG_DRKAISER \
-	CONFIG_GFXNVIDIA \
-	CONFIG_INTERNAL \
-	CONFIG_IT8212 \
-	CONFIG_NIC3COM \
-	CONFIG_NICINTEL \
-	CONFIG_NICINTEL_EEPROM \
-	CONFIG_NICINTEL_SPI \
-	CONFIG_NICNATSEMI \
-	CONFIG_NICREALTEK \
-	CONFIG_OGP_SPI \
-	CONFIG_SATAMV \
-	CONFIG_SATASII \
-
-DEPENDS_ON_LIBUSB1 := \
-	CONFIG_CH341A_SPI \
-	CONFIG_CH347_SPI \
-	CONFIG_DEDIPROG \
-	CONFIG_DEVELOPERBOX_SPI \
-	CONFIG_DIGILENT_SPI \
-	CONFIG_PICKIT2_SPI \
-	CONFIG_RAIDEN_DEBUG_SPI \
-	CONFIG_STLINKV3_SPI \
-	CONFIG_DIRTYJTAG_SPI \
-
-DEPENDS_ON_LIBFTDI1 := \
-	CONFIG_FT2232_SPI \
-	CONFIG_USBBLASTER_SPI \
-
-DEPENDS_ON_LIBJAYLINK := \
-	CONFIG_JLINK_SPI \
-
-DEPENDS_ON_LIB_NI845X := \
-	CONFIG_NI845X_SPI \
-
-DEPENDS_ON_LINUX_I2C := \
-	CONFIG_MSTARDDC_SPI \
-	CONFIG_PARADE_LSPCON \
-	CONFIG_REALTEK_MST_I2C_SPI \
-	CONFIG_MEDIATEK_I2C_SPI \
-
-ifeq ($(CONFIG_ENABLE_LIBUSB1_PROGRAMMERS), no)
-$(call disable_all,$(DEPENDS_ON_LIBUSB1))
-endif
-
-ifeq ($(CONFIG_ENABLE_LIBPCI_PROGRAMMERS), no)
-$(call disable_all,$(DEPENDS_ON_LIBPCI))
-endif
-
-###############################################################################
-# General OS-specific settings.
-# 1. Prepare for later by gathering information about host and target OS
-# 2. Set compiler flags and parameters according to OSes
-# 3. Likewise verify user-supplied CONFIG_* variables.
-
-# HOST_OS is only used to work around local toolchain issues.
-HOST_OS ?= $(shell uname)
-ifeq ($(findstring MINGW, $(HOST_OS)), MINGW)
-# Explicitly set CC = gcc on MinGW, otherwise: "cc: command not found".
-CC = gcc
-endif
-
-CC_WORKING := $(call c_compile_test, Makefile.d/cc_test.c)
-
-# Configs for dependencies. Can be overwritten by commandline
-CONFIG_LIBFTDI1_VERSION    := $(call dependency_version, libftdi1)
-CONFIG_LIBFTDI1_CFLAGS     := $(call dependency_cflags, libftdi1)
-CONFIG_LIBFTDI1_LDFLAGS    := $(call dependency_ldflags, libftdi1)
-
-CONFIG_NI845X_LIBRARY_PATH := 'C:\Program Files (x86)\National Instruments\NI-845x\MS Visual C'
-CONFIG_LIB_NI845X_CFLAGS   := -I$(CONFIG_NI845X_LIBRARY_PATH)
-CONFIG_LIB_NI845X_LDFLAGS  := -L$(CONFIG_NI845X_LIBRARY_PATH) -lni845x
-
-CONFIG_LIBJAYLINK_VERSION  := $(call dependency_version, libjaylink)
-CONFIG_LIBJAYLINK_CFLAGS   := $(call dependency_cflags, libjaylink)
-CONFIG_LIBJAYLINK_LDFLAGS  := $(call dependency_ldflags, libjaylink)
-
-CONFIG_LIBUSB1_VERSION     := $(call dependency_version, libusb-1.0)
-CONFIG_LIBUSB1_CFLAGS      := $(call dependency_cflags, libusb-1.0)
-CONFIG_LIBUSB1_LDFLAGS     := $(call dependency_ldflags, libusb-1.0)
-
-CONFIG_LIBPCI_VERSION      := $(call dependency_version, libpci)
-CONFIG_LIBPCI_CFLAGS       := $(call dependency_cflags, libpci)
-CONFIG_LIBPCI_LDFLAGS      := $(call dependency_ldflags, libpci)
-
-CONFIG_SPHINXBUILD_VERSION :=
-CONFIG_SPHINXBUILD_MAJOR   := 0
-
-
-# Determine the destination OS, architecture and endian
-# IMPORTANT: The following lines must be placed before TARGET_OS, ARCH or ENDIAN
-# is ever used (of course), but should come after any lines setting CC because
-# the lines below use CC itself.
-override TARGET_OS  := $(call c_macro_test, Makefile.d/os_test.h)
-override ARCH       := $(call c_macro_test, Makefile.d/arch_test.h)
-override ENDIAN     := $(call c_macro_test, Makefile.d/endian_test.h)
-
-
-HAS_LIBFTDI1        := $(call find_dependency, libftdi1)
-HAS_LIB_NI845X      := no
-HAS_LIBJAYLINK      := $(call find_dependency, libjaylink)
-HAS_LIBUSB1         := $(call find_dependency, libusb-1.0)
-HAS_LIBPCI          := $(call find_dependency, libpci)
-
-HAS_GETOPT          := $(call c_compile_test, Makefile.d/getopt_test.c)
-HAS_FT232H          := $(call c_compile_test, Makefile.d/ft232h_test.c, $(CONFIG_LIBFTDI1_CFLAGS))
-HAS_UTSNAME         := $(call c_compile_test, Makefile.d/utsname_test.c)
-HAS_CLOCK_GETTIME   := $(call c_compile_test, Makefile.d/clock_gettime_test.c)
-HAS_EXTERN_LIBRT    := $(call c_link_test, Makefile.d/clock_gettime_test.c, , -lrt)
-HAS_LINUX_MTD       := $(call c_compile_test, Makefile.d/linux_mtd_test.c)
-HAS_LINUX_SPI       := $(call c_compile_test, Makefile.d/linux_spi_test.c)
-HAS_LINUX_I2C       := $(call c_compile_test, Makefile.d/linux_i2c_test.c)
-HAS_PCIUTILS        := $(call c_compile_test, Makefile.d/pciutils_test.c)
-HAS_SERIAL          := $(strip $(if $(filter $(TARGET_OS), DOS libpayload), no, yes))
-HAS_SPHINXBUILD     := $(shell command -v $(SPHINXBUILD) >/dev/null 2>/dev/null && echo yes || echo no)
-EXEC_SUFFIX         := $(strip $(if $(filter $(TARGET_OS), DOS MinGW), .exe))
-
-override CFLAGS += -Iinclude
-
-ifeq ($(TARGET_OS), DOS)
-# DJGPP has odd uint*_t definitions which cause lots of format string warnings.
-override CFLAGS += -Wno-format
-override LDFLAGS += -lgetopt
-endif
-
-ifeq ($(TARGET_OS), $(filter $(TARGET_OS), MinGW Cygwin))
-$(call mark_unsupported,$(DEPENDS_ON_RAW_MEM_ACCESS))
-$(call mark_unsupported,$(DEPENDS_ON_X86_PORT_IO))
-$(call mark_unsupported,$(DEPENDS_ON_X86_MSR))
-FEATURE_FLAGS += -D'IS_WINDOWS=1'
-else
-FEATURE_FLAGS += -D'IS_WINDOWS=0'
-endif
-
-# FIXME: Should we check for Cygwin/MSVC as well?
-ifeq ($(TARGET_OS), MinGW)
-# MinGW doesn't have the ffs() function, but we can use gcc's __builtin_ffs().
-FLASHROM_CFLAGS += -Dffs=__builtin_ffs
-# Some functions provided by Microsoft do not work as described in C99 specifications. This macro fixes that
-# for MinGW. See http://sourceforge.net/p/mingw-w64/wiki2/printf%20and%20scanf%20family/ */
-FLASHROM_CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
-
-# For now we disable all PCI-based programmers on Windows/MinGW (no libpci).
-$(call mark_unsupported,$(DEPENDS_ON_LIBPCI))
-# And programmers that need raw access.
-$(call mark_unsupported,$(DEPENDS_ON_RAW_MEM_ACCESS))
-
-else # No MinGW
-
-# NI USB-845x only supported on Windows at the moment
-$(call mark_unsupported,CONFIG_NI845X_SPI)
-
-endif
-
-ifeq ($(TARGET_OS), libpayload)
-ifeq ($(MAKECMDGOALS),)
-.DEFAULT_GOAL := libflashrom.a
-$(info Setting default goal to libflashrom.a)
-endif
-$(call mark_unsupported,CONFIG_DUMMY)
-# libpayload does not provide the romsize field in struct pci_dev that the atapromise code requires.
-$(call mark_unsupported,CONFIG_ATAPROMISE)
-# Dediprog, Developerbox, USB-Blaster, PICkit2, CH341A and FT2232 are not supported with libpayload (missing libusb support).
-$(call mark_unsupported,$(DEPENDS_ON_LIBUSB1) $(DEPENDS_ON_LIBFTDI) $(DEPENDS_ON_LIBJAYLINK))
-endif
-
-ifeq ($(HAS_LINUX_MTD), no)
-$(call mark_unsupported,CONFIG_LINUX_MTD)
-endif
-
-ifeq ($(HAS_LINUX_SPI), no)
-$(call mark_unsupported,CONFIG_LINUX_SPI)
-endif
-
-ifeq ($(HAS_LINUX_I2C), no)
-$(call mark_unsupported,DEPENDS_ON_LINUX_I2C)
-endif
-
-ifeq ($(TARGET_OS), Android)
-# Android on x86 (currently) does not provide raw PCI port I/O operations.
-$(call mark_unsupported,$(DEPENDS_ON_X86_PORT_IO))
-endif
-
-# Disable the internal programmer on unsupported architectures or systems
-ifeq ($(or $(filter $(ARCH), x86), $(filter $(TARGET_OS), Linux)), )
-$(call mark_unsupported,CONFIG_INTERNAL)
-endif
-
-ifeq ($(HAS_LIBPCI), no)
-$(call mark_unsupported,$(DEPENDS_ON_LIBPCI))
-endif
-
-ifeq ($(HAS_LIBFTDI1), no)
-$(call mark_unsupported,$(DEPENDS_ON_LIBFTDI1))
-endif
-
-ifeq ($(HAS_LIB_NI845X), no)
-$(call mark_unsupported,$(DEPENDS_ON_LIB_NI845X))
-endif
-
-ifeq ($(HAS_LIBJAYLINK), no)
-$(call mark_unsupported,$(DEPENDS_ON_LIBJAYLINK))
-endif
-
-ifeq ($(HAS_LIBUSB1), no)
-$(call mark_unsupported,$(DEPENDS_ON_LIBUSB1))
-endif
-
-ifeq ($(HAS_SERIAL), no)
-$(call mark_unsupported, $(DEPENDS_ON_SERIAL))
-endif
-
-ifeq ($(ENDIAN), little)
-FEATURE_FLAGS += -D'__FLASHROM_LITTLE_ENDIAN__=1'
-endif
-ifeq ($(ENDIAN), big)
-FEATURE_FLAGS += -D'__FLASHROM_BIG_ENDIAN__=1'
-endif
-
-# PCI port I/O support is unimplemented on PPC/MIPS/SPARC and unavailable on ARM.
-# Right now this means the drivers below only work on x86.
-ifneq ($(ARCH), x86)
-$(call mark_unsupported,$(DEPENDS_ON_X86_MSR))
-$(call mark_unsupported,$(DEPENDS_ON_X86_PORT_IO))
-endif
-
-# Additionally disable all drivers needing raw access (memory, PCI, port I/O)
-# on architectures with unknown raw access properties.
-# Right now those architectures are alpha hppa m68k sh s390
-ifneq ($(ARCH), $(filter $(ARCH), x86 mips ppc arm sparc arc e2k))
-$(call mark_unsupported,$(DEPENDS_ON_RAW_MEM_ACCESS))
-endif
-
-###############################################################################
-# Flash chip drivers and bus support infrastructure.
-
-CHIP_OBJS = jedec.o printlock.o stm50.o w39.o w29ee011.o \
-	sst28sf040.o 82802ab.o \
-	sst49lfxxxc.o sst_fwhub.o edi.o flashchips.o spi.o spi25.o spi25_statusreg.o \
-	spi95.o opaque.o sfdp.o en29lv640b.o at45db.o s25f.o \
-	writeprotect.o writeprotect_ranges.o
-
-###############################################################################
-# Library code.
-
-LIB_OBJS = libflashrom.o layout.o erasure_layout.o flashrom.o parallel.o programmer.o programmer_table.o \
-	helpers.o helpers_fileio.o ich_descriptors.o fmap.o platform/endian_$(ENDIAN).o platform/memaccess.o
-
-ifeq ($(TARGET_OS), DOS)
-  LIB_OBJS += udelay_dos.o
-else
-  LIB_OBJS += udelay.o
-endif
-
-###############################################################################
-# Frontend related stuff.
-
-CLI_OBJS = cli_classic.o cli_output.o cli_common.o print.o
-
-VERSION ?= $(shell cat ./VERSION)
-VERSION_GIT ?= $(shell git describe 2>/dev/null)
-ifneq ($(VERSION_GIT),)
-  VERSION := "$(VERSION) (git:$(VERSION_GIT))"
-else
-  VERSION := "$(VERSION)"
-endif
-
-# No spaces in release names unless set explicitly
-RELEASENAME ?= $(shell echo "$(VERSION)" | sed -e 's/ /_/')
-
-###############################################################################
-# Default settings of CONFIG_* variables.
-
-# Always enable internal/onboard support for now.
-CONFIG_INTERNAL ?= yes
-CONFIG_INTERNAL_X86 ?= yes
-
-# Always enable serprog for now.
-CONFIG_SERPROG ?= yes
-
-# RayeR SPIPGM hardware support
-CONFIG_RAYER_SPI ?= yes
-
-# ChromiumOS servo DUT debug board hardware support
-CONFIG_RAIDEN_DEBUG_SPI ?= yes
-
-# PonyProg2000 SPI hardware support
-CONFIG_PONY_SPI ?= yes
-
-# Always enable 3Com NICs for now.
-CONFIG_NIC3COM ?= yes
-
-# Enable NVIDIA graphics cards. Note: write and erase do not work properly.
-CONFIG_GFXNVIDIA ?= yes
-
-# Always enable SiI SATA controllers for now.
-CONFIG_SATASII ?= yes
-
-# ASMedia ASM106x
-CONFIG_ASM106X ?= yes
-
-# Highpoint (HPT) ATA/RAID controller support.
-# IMPORTANT: This code is not yet working!
-CONFIG_ATAHPT ?= no
-
-# VIA VT6421A LPC memory support
-CONFIG_ATAVIA ?= yes
-
-# Promise ATA controller support.
-CONFIG_ATAPROMISE ?= no
-
-# Always enable FT2232 SPI dongles for now.
-CONFIG_FT2232_SPI ?= yes
-
-# Always enable Altera USB-Blaster dongles for now.
-CONFIG_USBBLASTER_SPI ?= yes
-
-# MSTAR DDC support needs more tests/reviews/cleanups.
-CONFIG_MSTARDDC_SPI ?= no
-
-# Always enable PICkit2 SPI dongles for now.
-CONFIG_PICKIT2_SPI ?= yes
-
-# Always enable STLink V3
-CONFIG_STLINKV3_SPI ?= yes
-
-# Disables Parade LSPCON support until the i2c helper supports multiple systems.
-CONFIG_PARADE_LSPCON ?= no
-
-# Disables MediaTek support until the i2c helper supports multiple systems.
-CONFIG_MEDIATEK_I2C_SPI ?= no
-
-# Disables REALTEK_MST support until the i2c helper supports multiple systems.
-CONFIG_REALTEK_MST_I2C_SPI ?= no
-
-# Always enable dummy tracing for now.
-CONFIG_DUMMY ?= yes
-
-# Always enable Dr. Kaiser for now.
-CONFIG_DRKAISER ?= yes
-
-# Always enable Realtek NICs for now.
-CONFIG_NICREALTEK ?= yes
-
-# Disable National Semiconductor NICs until support is complete and tested.
-CONFIG_NICNATSEMI ?= no
-
-# Always enable Intel NICs for now.
-CONFIG_NICINTEL ?= yes
-
-# Always enable SPI on Intel NICs for now.
-CONFIG_NICINTEL_SPI ?= yes
-
-# Always enable EEPROM on Intel NICs for now.
-CONFIG_NICINTEL_EEPROM ?= yes
-
-# Always enable SPI on OGP cards for now.
-CONFIG_OGP_SPI ?= yes
-
-# Always enable Bus Pirate SPI for now.
-CONFIG_BUSPIRATE_SPI ?= yes
-
-# Always enable Dediprog SF100 for now.
-CONFIG_DEDIPROG ?= yes
-
-# Always enable Developerbox emergency recovery for now.
-CONFIG_DEVELOPERBOX_SPI ?= yes
-
-# Always enable Marvell SATA controllers for now.
-CONFIG_SATAMV ?= yes
-
-# Enable Linux spidev and MTD interfaces by default. We disable them on non-Linux targets.
-CONFIG_LINUX_MTD ?= yes
-CONFIG_LINUX_SPI ?= yes
-
-# Always enable ITE IT8212F PATA controllers for now.
-CONFIG_IT8212 ?= yes
-
-# Winchiphead CH341A
-CONFIG_CH341A_SPI ?= yes
-
-# Winchiphead CH347
-CONFIG_CH347_SPI ?= yes
-
-# Digilent Development board JTAG
-CONFIG_DIGILENT_SPI ?= yes
-
-# DirtyJTAG
-CONFIG_DIRTYJTAG_SPI ?= yes
-
-# Disable J-Link for now.
-CONFIG_JLINK_SPI ?= no
-
-# National Instruments USB-845x is Windows only and needs a proprietary library.
-CONFIG_NI845X_SPI ?= no
-
-# Disable wiki printing by default. It is only useful if you have wiki access.
-CONFIG_PRINT_WIKI ?= no
-
-# Minimum time in microseconds to suspend execution for (rather than polling)
-# when a delay is required. Larger values may perform better on machines with
-# low timer resolution, at the cost of increased power.
-CONFIG_DELAY_MINIMUM_SLEEP_US ?= 100000
-
-# Disable all features if CONFIG_NOTHING=yes is given unless CONFIG_EVERYTHING was also set
-ifeq ($(CONFIG_NOTHING), yes)
-  ifeq ($(CONFIG_EVERYTHING), yes)
-    $(error Setting CONFIG_NOTHING=yes and CONFIG_EVERYTHING=yes does not make sense)
-  endif
-  $(foreach var, $(filter CONFIG_%, $(.VARIABLES)),\
-    $(if $(filter yes, $($(var))),\
-      $(eval $(var)=no)))
-endif
-
-# Enable all features if CONFIG_EVERYTHING=yes is given
-ifeq ($(CONFIG_EVERYTHING), yes)
-$(foreach var, $(filter CONFIG_%, $(.VARIABLES)),\
-	$(if $(filter no, $($(var))),\
-		$(eval $(var)=yes)))
-endif
-
-###############################################################################
-# Handle CONFIG_* variables that depend on others set (and verified) above.
-
-# The external DMI decoder (dmidecode) does not work in libpayload. Bail out if the internal one got disabled.
-ifeq ($(TARGET_OS), libpayload)
-ifeq ($(CONFIG_INTERNAL), yes)
-ifeq ($(CONFIG_INTERNAL_DMI), no)
-UNSUPPORTED_FEATURES += CONFIG_INTERNAL_DMI=no
-else
-override CONFIG_INTERNAL_DMI = yes
-endif
-endif
-endif
-
-# Use internal DMI/SMBIOS decoder by default instead of relying on dmidecode.
-CONFIG_INTERNAL_DMI ?= yes
-
-###############################################################################
-# Programmer drivers and programmer support infrastructure.
-# Depending on the CONFIG_* variables set and verified above we set compiler flags and parameters below.
-
-ifdef CONFIG_DEFAULT_PROGRAMMER_NAME
-FEATURE_FLAGS += -D'CONFIG_DEFAULT_PROGRAMMER_NAME=&programmer_$(CONFIG_DEFAULT_PROGRAMMER_NAME)'
-else
-FEATURE_FLAGS += -D'CONFIG_DEFAULT_PROGRAMMER_NAME=NULL'
-endif
-
-FEATURE_FLAGS += -D'CONFIG_DEFAULT_PROGRAMMER_ARGS="$(CONFIG_DEFAULT_PROGRAMMER_ARGS)"'
-FEATURE_FLAGS += -D'CONFIG_DELAY_MINIMUM_SLEEP_US=$(CONFIG_DELAY_MINIMUM_SLEEP_US)'
-
-################################################################################
-
-ifeq ($(ARCH), x86)
-ifeq ($(CONFIG_INTERNAL) $(CONFIG_INTERNAL_X86), yes yes)
-FEATURE_FLAGS += -D'CONFIG_INTERNAL=1'
-PROGRAMMER_OBJS += processor_enable.o chipset_enable.o board_enable.o cbtable.o \
-	internal.o internal_par.o it87spi.o sb600spi.o superio.o amd_imc.o wbsio_spi.o mcp6x_spi.o \
-	ichspi.o dmi.o known_boards.o
-ACTIVE_PROGRAMMERS += internal
-endif
-else
-ifeq ($(CONFIG_INTERNAL), yes)
-FEATURE_FLAGS += -D'CONFIG_INTERNAL=1'
-PROGRAMMER_OBJS += processor_enable.o chipset_enable.o board_enable.o cbtable.o internal.o internal_par.o known_boards.o
-ACTIVE_PROGRAMMERS += internal
-endif
-endif
-
-ifeq ($(CONFIG_INTERNAL_DMI), yes)
-FEATURE_FLAGS += -D'CONFIG_INTERNAL_DMI=1'
-endif
-
-ifeq ($(CONFIG_SERPROG), yes)
-FEATURE_FLAGS += -D'CONFIG_SERPROG=1'
-PROGRAMMER_OBJS += serprog.o
-ACTIVE_PROGRAMMERS += serprog
-endif
-
-ifeq ($(CONFIG_RAYER_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_RAYER_SPI=1'
-PROGRAMMER_OBJS += rayer_spi.o
-ACTIVE_PROGRAMMERS += rayer_spi
-endif
-
-ifeq ($(CONFIG_RAIDEN_DEBUG_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_RAIDEN_DEBUG_SPI=1'
-PROGRAMMER_OBJS += raiden_debug_spi.o
-ACTIVE_PROGRAMMERS += raiden_debug_spi
-endif
-
-ifeq ($(CONFIG_PONY_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_PONY_SPI=1'
-PROGRAMMER_OBJS += pony_spi.o
-ACTIVE_PROGRAMMERS += pony_spi
-endif
-
-ifeq ($(CONFIG_NIC3COM), yes)
-FEATURE_FLAGS += -D'CONFIG_NIC3COM=1'
-PROGRAMMER_OBJS += nic3com.o
-ACTIVE_PROGRAMMERS += nic3com
-endif
-
-ifeq ($(CONFIG_GFXNVIDIA), yes)
-FEATURE_FLAGS += -D'CONFIG_GFXNVIDIA=1'
-PROGRAMMER_OBJS += gfxnvidia.o
-ACTIVE_PROGRAMMERS += gfxnvidia
-endif
-
-ifeq ($(CONFIG_SATASII), yes)
-FEATURE_FLAGS += -D'CONFIG_SATASII=1'
-PROGRAMMER_OBJS += satasii.o
-ACTIVE_PROGRAMMERS += satasii
-endif
-
-ifeq ($(CONFIG_ASM106X), yes)
-FEATURE_FLAGS += -D'CONFIG_ASM106X=1'
-PROGRAMMER_OBJS += asm106x.o
-ACTIVE_PROGRAMMERS += asm106x
-endif
-
-ifeq ($(CONFIG_ATAHPT), yes)
-FEATURE_FLAGS += -D'CONFIG_ATAHPT=1'
-PROGRAMMER_OBJS += atahpt.o
-ACTIVE_PROGRAMMERS += atahpt
-endif
-
-ifeq ($(CONFIG_ATAVIA), yes)
-FEATURE_FLAGS += -D'CONFIG_ATAVIA=1'
-PROGRAMMER_OBJS += atavia.o
-ACTIVE_PROGRAMMERS += atavia
-endif
-
-ifeq ($(CONFIG_ATAPROMISE), yes)
-FEATURE_FLAGS += -D'CONFIG_ATAPROMISE=1'
-PROGRAMMER_OBJS += atapromise.o
-ACTIVE_PROGRAMMERS += atapromise
-endif
-
-ifeq ($(CONFIG_IT8212), yes)
-FEATURE_FLAGS += -D'CONFIG_IT8212=1'
-PROGRAMMER_OBJS += it8212.o
-ACTIVE_PROGRAMMERS += it8212
-endif
-
-ifeq ($(CONFIG_FT2232_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_FT2232_SPI=1'
-PROGRAMMER_OBJS += ft2232_spi.o
-ACTIVE_PROGRAMMERS += ft2232_spi
-endif
-
-ifeq ($(CONFIG_USBBLASTER_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_USBBLASTER_SPI=1'
-PROGRAMMER_OBJS += usbblaster_spi.o
-ACTIVE_PROGRAMMERS += usbblaster_spi
-endif
-
-ifeq ($(CONFIG_PICKIT2_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_PICKIT2_SPI=1'
-PROGRAMMER_OBJS += pickit2_spi.o
-ACTIVE_PROGRAMMERS += pickit2_spi
-endif
-
-ifeq ($(CONFIG_STLINKV3_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_STLINKV3_SPI=1'
-PROGRAMMER_OBJS += stlinkv3_spi.o
-ACTIVE_PROGRAMMERS += stlinkv3_spi
-endif
-
-ifeq ($(CONFIG_PARADE_LSPCON), yes)
-FEATURE_FLAGS += -D'CONFIG_PARADE_LSPCON=1'
-PROGRAMMER_OBJS += parade_lspcon.o
-ACTIVE_PROGRAMMERS += parade_lspcon
-endif
-
-ifeq ($(CONFIG_MEDIATEK_I2C_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_MEDIATEK_I2C_SPI=1'
-PROGRAMMER_OBJS += mediatek_i2c_spi.o
-ACTIVE_PROGRAMMERS += mediatek_i2c_spi
-endif
-
-ifeq ($(CONFIG_REALTEK_MST_I2C_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_REALTEK_MST_I2C_SPI=1'
-PROGRAMMER_OBJS += realtek_mst_i2c_spi.o
-ACTIVE_PROGRAMMERS += realtek_mst_i2c_spi
-endif
-
-ifeq ($(CONFIG_DUMMY), yes)
-FEATURE_FLAGS += -D'CONFIG_DUMMY=1'
-PROGRAMMER_OBJS += dummyflasher.o
-ACTIVE_PROGRAMMERS += dummyflasher
-endif
-
-ifeq ($(CONFIG_DRKAISER), yes)
-FEATURE_FLAGS += -D'CONFIG_DRKAISER=1'
-PROGRAMMER_OBJS += drkaiser.o
-ACTIVE_PROGRAMMERS += drkaiser
-endif
-
-ifeq ($(CONFIG_NICREALTEK), yes)
-FEATURE_FLAGS += -D'CONFIG_NICREALTEK=1'
-PROGRAMMER_OBJS += nicrealtek.o
-ACTIVE_PROGRAMMERS += nicrealtek
-endif
-
-ifeq ($(CONFIG_NICNATSEMI), yes)
-FEATURE_FLAGS += -D'CONFIG_NICNATSEMI=1'
-PROGRAMMER_OBJS += nicnatsemi.o
-ACTIVE_PROGRAMMERS += nicnatsemi
-endif
-
-ifeq ($(CONFIG_NICINTEL), yes)
-FEATURE_FLAGS += -D'CONFIG_NICINTEL=1'
-PROGRAMMER_OBJS += nicintel.o
-ACTIVE_PROGRAMMERS += nicintel
-endif
-
-ifeq ($(CONFIG_NICINTEL_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_NICINTEL_SPI=1'
-PROGRAMMER_OBJS += nicintel_spi.o
-ACTIVE_PROGRAMMERS += nicintel_spi
-endif
-
-ifeq ($(CONFIG_NICINTEL_EEPROM), yes)
-FEATURE_FLAGS += -D'CONFIG_NICINTEL_EEPROM=1'
-PROGRAMMER_OBJS += nicintel_eeprom.o
-ACTIVE_PROGRAMMERS += nicintel_eeprom
-endif
-
-ifeq ($(CONFIG_OGP_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_OGP_SPI=1'
-PROGRAMMER_OBJS += ogp_spi.o
-ACTIVE_PROGRAMMERS += ogp_spi
-endif
-
-ifeq ($(CONFIG_BUSPIRATE_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_BUSPIRATE_SPI=1'
-PROGRAMMER_OBJS += buspirate_spi.o
-ACTIVE_PROGRAMMERS += buspirate_spi
-endif
-
-ifeq ($(CONFIG_DEDIPROG), yes)
-FEATURE_FLAGS += -D'CONFIG_DEDIPROG=1'
-PROGRAMMER_OBJS += dediprog.o
-ACTIVE_PROGRAMMERS += dediprog
-endif
-
-ifeq ($(CONFIG_DEVELOPERBOX_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_DEVELOPERBOX_SPI=1'
-PROGRAMMER_OBJS += developerbox_spi.o
-ACTIVE_PROGRAMMERS += developerbox_spi
-endif
-
-ifeq ($(CONFIG_SATAMV), yes)
-FEATURE_FLAGS += -D'CONFIG_SATAMV=1'
-PROGRAMMER_OBJS += satamv.o
-ACTIVE_PROGRAMMERS += satamv
-endif
-
-ifeq ($(CONFIG_LINUX_MTD), yes)
-FEATURE_FLAGS += -D'CONFIG_LINUX_MTD=1'
-PROGRAMMER_OBJS += linux_mtd.o
-ACTIVE_PROGRAMMERS += linux_mtd
-endif
-
-ifeq ($(CONFIG_LINUX_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_LINUX_SPI=1'
-PROGRAMMER_OBJS += linux_spi.o
-ACTIVE_PROGRAMMERS += linux_spi
-endif
-
-ifeq ($(CONFIG_MSTARDDC_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_MSTARDDC_SPI=1'
-PROGRAMMER_OBJS += mstarddc_spi.o
-ACTIVE_PROGRAMMERS += mstarddc_spi
-endif
-
-ifeq ($(CONFIG_CH341A_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_CH341A_SPI=1'
-PROGRAMMER_OBJS += ch341a_spi.o
-ACTIVE_PROGRAMMERS += ch341a_spi
-endif
-
-ifeq ($(CONFIG_CH347_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_CH347_SPI=1'
-PROGRAMMER_OBJS += ch347_spi.o
-endif
-
-ifeq ($(CONFIG_DIGILENT_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_DIGILENT_SPI=1'
-PROGRAMMER_OBJS += digilent_spi.o
-ACTIVE_PROGRAMMERS += digilent_spi
-endif
-
-ifeq ($(CONFIG_DIRTYJTAG_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_DIRTYJTAG_SPI=1'
-PROGRAMMER_OBJS += dirtyjtag_spi.o
-ACTIVE_PROGRAMMERS += dirtyjtag_spi
-endif
-
-ifeq ($(CONFIG_JLINK_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_JLINK_SPI=1'
-PROGRAMMER_OBJS += jlink_spi.o
-ACTIVE_PROGRAMMERS += jlink_spi
-endif
-
-ifeq ($(CONFIG_NI845X_SPI), yes)
-FEATURE_FLAGS += -D'CONFIG_NI845X_SPI=1'
-PROGRAMMER_OBJS += ni845x_spi.o
-ACTIVE_PROGRAMMERS += ni845x_spi
-endif
-
-USE_BITBANG_SPI := $(if $(call filter_deps,$(DEPENDS_ON_BITBANG_SPI)),yes,no)
-ifeq ($(USE_BITBANG_SPI), yes)
-LIB_OBJS += bitbang_spi.o
-endif
-
-USE_LINUX_I2C := $(if $(call filter_deps,$(DEPENDS_ON_LINUX_I2C)),yes,no)
-ifeq ($(USE_LINUX_I2C), yes)
-LIB_OBJS += i2c_helper_linux.o
-endif
-
-USE_SERIAL := $(if $(call filter_deps,$(DEPENDS_ON_SERIAL)),yes,no)
-ifeq ($(USE_SERIAL), yes)
-LIB_OBJS += serial.o
-ifeq ($(TARGET_OS), Linux)
-LIB_OBJS += custom_baud_linux.o
-else
-ifeq ($(TARGET_OS), Darwin)
-LIB_OBJS += custom_baud_darwin.o
-else
-LIB_OBJS += custom_baud.o
-endif
-endif
-endif
-
-USE_SOCKETS := $(if $(call filter_deps,$(DEPENDS_ON_SOCKETS)),yes,no)
-ifeq ($(USE_SOCKETS), yes)
-ifeq ($(TARGET_OS), SunOS)
-override LDFLAGS += -lsocket -lnsl
-endif
-endif
-
-USE_X86_MSR := $(if $(call filter_deps,$(DEPENDS_ON_X86_MSR)),yes,no)
-ifeq ($(USE_X86_MSR), yes)
-PROGRAMMER_OBJS += hwaccess_x86_msr.o
-endif
-
-USE_X86_PORT_IO := $(if $(call filter_deps,$(DEPENDS_ON_X86_PORT_IO)),yes,no)
-ifeq ($(USE_X86_PORT_IO), yes)
-FEATURE_FLAGS += -D'__FLASHROM_HAVE_OUTB__=1'
-PROGRAMMER_OBJS += hwaccess_x86_io.o
-endif
-
-USE_RAW_MEM_ACCESS := $(if $(call filter_deps,$(DEPENDS_ON_RAW_MEM_ACCESS)),yes,no)
-ifeq ($(USE_RAW_MEM_ACCESS), yes)
-PROGRAMMER_OBJS += hwaccess_physmap.o
-endif
-
-ifeq (Darwin yes, $(TARGET_OS) $(filter $(USE_X86_MSR) $(USE_X86_PORT_IO) $(USE_RAW_MEM_ACCESS), yes))
-override LDFLAGS += -framework IOKit -framework DirectHW
-endif
-
-ifeq (NetBSD yes, $(TARGET_OS) $(filter $(USE_X86_MSR) $(USE_X86_PORT_IO), yes))
-override LDFLAGS += -l$(shell uname -p)
-endif
-
-ifeq (OpenBSD yes, $(TARGET_OS) $(filter $(USE_X86_MSR) $(USE_X86_PORT_IO), yes))
-override LDFLAGS += -l$(shell uname -m)
-endif
-
-USE_LIBPCI := $(if $(call filter_deps,$(DEPENDS_ON_LIBPCI)),yes,no)
-ifeq ($(USE_LIBPCI), yes)
-PROGRAMMER_OBJS += pcidev.o
-override CFLAGS  += $(CONFIG_LIBPCI_CFLAGS)
-override LDFLAGS += $(CONFIG_LIBPCI_LDFLAGS)
-endif
-
-USE_LIBUSB1 := $(if $(call filter_deps,$(DEPENDS_ON_LIBUSB1)),yes,no)
-ifeq ($(USE_LIBUSB1), yes)
-override CFLAGS  += $(CONFIG_LIBUSB1_CFLAGS)
-override LDFLAGS += $(CONFIG_LIBUSB1_LDFLAGS)
-PROGRAMMER_OBJS +=usbdev.o usb_device.o
-endif
-
-USE_LIBFTDI1 := $(if $(call filter_deps,$(DEPENDS_ON_LIBFTDI1)),yes,no)
-ifeq ($(USE_LIBFTDI1), yes)
-override CFLAGS  += $(CONFIG_LIBFTDI1_CFLAGS)
-override LDFLAGS += $(CONFIG_LIBFTDI1_LDFLAGS)
-ifeq ($(HAS_FT232H), yes)
-FEATURE_FLAGS += -D'HAVE_FT232H=1'
-endif
-endif
-
-USE_LIB_NI845X := $(if $(call filter_deps,$(DEPENDS_ON_LIB_NI845X)),yes,no)
-ifeq ($(USE_LIB_NI845X), yes)
-override CFLAGS += $(CONFIG_LIB_NI845X_CFLAGS)
-override LDFLAGS += $(CONFIG_LIB_NI845X_LDFLAGS)
-endif
-
-USE_LIBJAYLINK := $(if $(call filter_deps,$(DEPENDS_ON_LIBJAYLINK)),yes,no)
-ifeq ($(USE_LIBJAYLINK), yes)
-override CFLAGS  += $(CONFIG_LIBJAYLINK_CFLAGS)
-override LDFLAGS += $(CONFIG_LIBJAYLINK_LDFLAGS)
-endif
-
-ifeq ($(CONFIG_PRINT_WIKI), yes)
-FEATURE_FLAGS += -D'CONFIG_PRINT_WIKI=1'
-CLI_OBJS += print_wiki.o
-endif
-
-ifeq ($(HAS_UTSNAME), yes)
-FEATURE_FLAGS += -D'HAVE_UTSNAME=1'
-endif
-
-ifeq ($(HAS_CLOCK_GETTIME), yes)
-FEATURE_FLAGS += -D'HAVE_CLOCK_GETTIME=1'
-ifeq ($(HAS_EXTERN_LIBRT), yes)
-override LDFLAGS += -lrt
-endif
-endif
-
-ifeq ($(HAS_GETOPT), yes)
-override CFLAGS  += -D'HAVE_GETOPT_H=1'
-endif
-
-ifeq ($(HAS_PCIUTILS), yes)
-override CFLAGS  += -D'HAVE_PCIUTILS_PCI_H=1'
-endif
-
-OBJS = $(CHIP_OBJS) $(PROGRAMMER_OBJS) $(LIB_OBJS)
-
-ifeq ($(HAS_SPHINXBUILD), yes)
-override CONFIG_SPHINXBUILD_VERSION := $(shell $(SPHINXBUILD) --version | cut -d' ' -f2 )
-override CONFIG_SPHINXBUILD_MAJOR   := $(shell echo "$(CONFIG_SPHINXBUILD_VERSION)" | cut -d'.' -f1 )
-endif
-
-
-all: $(PROGRAM)$(EXEC_SUFFIX) $(call has_dependency, $(HAS_SPHINXBUILD), man8/$(PROGRAM).8)
-ifeq ($(ARCH), x86)
-	@+$(MAKE) -C util/ich_descriptors_tool/ HOST_OS=$(HOST_OS) TARGET_OS=$(TARGET_OS)
-endif
-
-config:
-	@echo Building flashrom version $(VERSION)
-	@printf "C compiler found: "
-	@if [ $(CC_WORKING) = yes ]; \
-		then $(CC) --version 2>/dev/null | head -1; \
-		else echo no; echo Aborting.; exit 1; fi
-	@echo "Target arch: $(ARCH)"
-	@if [ $(ARCH) = unknown ]; then echo Aborting.; exit 1; fi
-	@echo "Target OS: $(TARGET_OS)"
-	@if [ $(TARGET_OS) = unknown ]; then echo Aborting.; exit 1; fi
-	@if [ $(TARGET_OS) = libpayload ] && ! $(CC) --version 2>&1 | grep -q coreboot; then \
-		echo "  Warning: It seems you are not using coreboot's reference compiler."; \
-		echo "  This might work but usually does not, please beware."; fi
-	@echo "Target endian: $(ENDIAN)"
-	@if [ $(ENDIAN) = unknown ]; then echo Aborting.; exit 1; fi
-	@echo Dependency libpci found: $(HAS_LIBPCI) $(CONFIG_LIBPCI_VERSION)
-	@if [ $(HAS_LIBPCI) = yes ]; then			\
-		echo "  CFLAGS: $(CONFIG_LIBPCI_CFLAGS)";	\
-		echo "  LDFLAGS: $(CONFIG_LIBPCI_LDFLAGS)";	\
-	fi
-	@echo Dependency libusb1 found: $(HAS_LIBUSB1) $(CONFIG_LIBUSB1_VERSION)
-	@if [ $(HAS_LIBUSB1) = yes ]; then			\
-		echo "  CFLAGS: $(CONFIG_LIBUSB1_CFLAGS)";	\
-		echo "  LDFLAGS: $(CONFIG_LIBUSB1_LDFLAGS)";	\
-	fi
-	@echo Dependency libjaylink found: $(HAS_LIBJAYLINK) $(CONFIG_LIBJAYLINK_VERSION)
-	@if [ $(HAS_LIBJAYLINK) = yes ]; then			\
-		echo "  CFLAGS: $(CONFIG_LIBJAYLINK_CFLAGS)";	\
-		echo "  LDFLAGS: $(CONFIG_LIBJAYLINK_LDFLAGS)";	\
-	fi
-	@echo Dependency NI-845x found: $(HAS_LIB_NI845X)
-	@if [ $(HAS_LIB_NI845X) = yes ]; then			\
-		echo "  CFLAGS: $(CONFIG_LIB_NI845X_CFLAGS)";	\
-		echo "  LDFLAGS: $(CONFIG_LIB_NI845X_LDFLAGS)";	\
-	fi
-	@echo Dependency libftdi1 found: $(HAS_LIBFTDI1) $(CONFIG_LIBFTDI1_VERSION)
-	@if [ $(HAS_LIBFTDI1) = yes ]; then 			\
-		echo "  Checking for \"TYPE_232H\" in \"enum ftdi_chip_type\": $(HAS_FT232H)"; \
-		echo "  CFLAGS: $(CONFIG_LIBFTDI1_CFLAGS)";	\
-		echo "  LDFLAGS: $(CONFIG_LIBFTDI1_LDFLAGS)";	\
-	fi
-	@echo "Checking for header \"getopt.h\": $(HAS_GETOPT)"
-	@echo "Checking for header \"mtd/mtd-user.h\": $(HAS_LINUX_MTD)"
-	@echo "Checking for header \"linux/spi/spidev.h\": $(HAS_LINUX_SPI)"
-	@echo "Checking for header \"linux/i2c-dev.h\": $(HAS_LINUX_I2C)"
-	@echo "Checking for header \"linux/i2c.h\": $(HAS_LINUX_I2C)"
-	@echo "Checking for header \"sys/utsname.h\": $(HAS_UTSNAME)"
-	@echo "Checking for header \"pciutils/pci.h\": $(HAS_PCIUTILS)"
-	@echo "Checking for function \"clock_gettime\": $(HAS_CLOCK_GETTIME)"
-	@echo "Checking for external \"librt\": $(HAS_EXTERN_LIBRT)"
-	@if ! [ "$(PROGRAMMER_OBJS)" ]; then					\
-		echo "You have to enable at least one programmer driver!";	\
-		exit 1;								\
-	fi
-	@if [ "$(UNSUPPORTED_FEATURES)" ]; then					\
-		echo "The following features are unavailable on your machine: $(UNSUPPORTED_FEATURES)" \
-		exit 1;								\
-	fi
-	@echo "Checking for program \"sphinx-build\": $(HAS_SPHINXBUILD) $(CONFIG_SPHINXBUILD_VERSION)"
-
-%.o: %.c | config
-	$(CC) -MMD $(CFLAGS) $(CPPFLAGS) $(FLASHROM_CFLAGS) $(FEATURE_FLAGS) -D'FLASHROM_VERSION=$(VERSION)'  -o $@ -c $<
-
-$(PROGRAM)$(EXEC_SUFFIX): $(CLI_OBJS) libflashrom.a
-	$(CC) -o $@ $^ $(LDFLAGS)
-
-libflashrom.a: $(OBJS)
-	$(AR) rcs $@ $^
-	$(RANLIB) $@
-
-man8/$(PROGRAM).8: doc/*
-#	When using sphinx-build prior to version 4.x, man pages are output
-#	to a directory named "8" instead of expected "man8". We fix that
-#	by renaming "8" to "man8" and creating symlink "8" pointing to "man8".
-	@if [ "$(HAS_SPHINXBUILD)" = "yes" ]; then			\
-		$(SPHINXBUILD) -Drelease=$(VERSION) -b man doc .;	\
-		if [ "$(CONFIG_SPHINXBUILD_MAJOR)" -lt 4 ]; then	\
-			if [ -d 8 -a ! -L 8 ]; then			\
-				rm -rf man8;				\
-				mv 8 man8;				\
-				ln -s man8 8;				\
-			fi						\
-		fi							\
-	else								\
-		echo "$(SPHINXBUILD) not found. Can't build man-page";	\
-		exit 1;							\
-	fi
-
-$(PROGRAM).bash: util/$(PROGRAM).bash-completion.tmpl
-	@# Add to the bash completion file a list of enabled programmers.
-	sed -e 's/@PROGRAMMERS@/$(ACTIVE_PROGRAMMERS)/g' <$< >$@
-
-strip: $(PROGRAM)$(EXEC_SUFFIX)
-	$(STRIP) $(STRIP_ARGS) $(PROGRAM)$(EXEC_SUFFIX)
-
-# Make sure to add all names of generated binaries here.
-# This includes all frontends and libflashrom.
-# We don't use EXEC_SUFFIX here because we want to clean everything.
-clean:
-	rm -rf $(PROGRAM) $(PROGRAM).exe libflashrom.a $(filter-out Makefile.d, $(wildcard *.d *.o platform/*.d platform/*.o)) \
-		man8 8 .doctrees $(PROGRAM).bash $(BUILD_DETAILS_FILE)
-	@+$(MAKE) -C util/ich_descriptors_tool/ clean
-
-install: $(PROGRAM)$(EXEC_SUFFIX) $(call has_dependency, $(HAS_SPHINXBUILD), man8/$(PROGRAM).8) $(PROGRAM).bash
-	mkdir -p $(DESTDIR)$(PREFIX)/sbin
-	$(INSTALL) -m 0755 $(PROGRAM)$(EXEC_SUFFIX) $(DESTDIR)$(PREFIX)/sbin
-	mkdir -p $(DESTDIR)$(BASHCOMPDIR)
-	$(INSTALL) -m 0644 $(PROGRAM).bash $(DESTDIR)$(BASHCOMPDIR)
-ifeq ($(HAS_SPHINXBUILD), yes)
-	mkdir -p $(DESTDIR)$(MANDIR)/man8
-	$(INSTALL) -m 0644 man8/$(PROGRAM).8 $(DESTDIR)$(MANDIR)/man8
-endif
-
-libinstall: libflashrom.a include/libflashrom.h
-	mkdir -p $(DESTDIR)$(PREFIX)/lib
-	$(INSTALL) -m 0644 libflashrom.a $(DESTDIR)$(PREFIX)/lib
-	mkdir -p $(DESTDIR)$(PREFIX)/include
-	$(INSTALL) -m 0644 include/libflashrom.h $(DESTDIR)$(PREFIX)/include
-
-_export: man8/$(PROGRAM).8
-	@rm -rf "$(EXPORTDIR)/flashrom-$(RELEASENAME)"
-	@mkdir -p "$(EXPORTDIR)/flashrom-$(RELEASENAME)"
-	@git archive HEAD | tar -x -C "$(EXPORTDIR)/flashrom-$(RELEASENAME)"
-#	Generate versioninfo.inc containing metadata that would not be available in exported sources otherwise.
-	@echo "VERSION = $(VERSION)" > "$(EXPORTDIR)/flashrom-$(RELEASENAME)/versioninfo.inc"
-#	Restore modification date of all tracked files not marked 'export-ignore' in .gitattributes.
-#	sed is required to filter out file names having the attribute set.
-#	The sed program saves the file name in the hold buffer and then checks if the respective value is 'set'.
-#	If so it ignores the rest of the program, which otherwise restores the file name and prints it.
-	@git ls-tree -r -z -t --full-name --name-only HEAD | \
-		git check-attr -z --stdin export-ignore | \
-		sed -zne 'x;n;n;{/^set$$/b;};x;p;' | \
-		xargs -0 sh -c 'for f; do \
-			touch -d $$(git log --pretty=format:%cI -1 HEAD -- "$$f") \
-				"$(EXPORTDIR)/flashrom-$(RELEASENAME)/$$f"; \
-		done' dummy_arg0
-
-export: _export
-	@echo "Exported $(EXPORTDIR)/flashrom-$(RELEASENAME)/"
-
-
-# TAROPTIONS reduces information leakage from the packager's system.
-# If other tar programs support command line arguments for setting uid/gid of
-# stored files, they can be handled here as well.
-TAROPTIONS = $(shell LC_ALL=C tar --version|grep -q GNU && echo "--owner=root --group=root")
-
-tarball: _export
-	@tar -cj --format=ustar -f "$(EXPORTDIR)/flashrom-$(RELEASENAME).tar.bz2" -C $(EXPORTDIR)/ \
-		$(TAROPTIONS) "flashrom-$(RELEASENAME)/"
-#	Delete the exported directory again because it is most likely what's expected by the user.
-	@rm -rf "$(EXPORTDIR)/flashrom-$(RELEASENAME)"
-	@echo Created "$(EXPORTDIR)/flashrom-$(RELEASENAME).tar.bz2"
-
-libpayload: clean
-	make CC="CC=i386-elf-gcc lpgcc" AR=i386-elf-ar RANLIB=i386-elf-ranlib
-
-.PHONY: all install clean distclean config _export export tarball libpayload
-
-# Disable implicit suffixes and built-in rules (for performance and profit)
-.SUFFIXES:
-
--include $(OBJS:.o=.d)
diff --git a/Makefile.d/arch_test.h b/Makefile.d/arch_test.h
deleted file mode 100644
index 654f8e56..00000000
--- a/Makefile.d/arch_test.h
+++ /dev/null
@@ -1,55 +0,0 @@
-/*
- * This file is part of the flashrom project.
- *
- * Copyright (C) 2011 Carl-Daniel Hailfinger
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License as published by
- * the Free Software Foundation; version 2 of the License.
- *
- * This program is distributed in the hope that it will be useful,
- * but WITHOUT ANY WARRANTY; without even the implied warranty of
- * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
- * GNU General Public License for more details.
- */
-
-/*
- * This file determinate the target architecture. It should only be used
- * by the Makefile
- */
-
-#if defined (__i386__) || defined (__x86_64__) || defined(__amd64__)
-	#define __FLASHROM_ARCH__ "x86"
-#elif defined (__mips) || defined (__mips__) || defined (__MIPS__) || defined (mips)
-	#define __FLASHROM_ARCH__ "mips"
-#elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || \
-      defined(__ppc__) || defined(__ppc64__) || defined(_M_PPC) || defined(_ARCH_PPC) || \
-      defined(_ARCH_PPC64) || defined(__ppc)
-	#define __FLASHROM_ARCH__ "ppc"
-#elif defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(_ARM) || defined(_M_ARM) || defined(__arm) || \
-      defined(__aarch64__)
-	#define __FLASHROM_ARCH__ "arm"
-#elif defined (__sparc__) || defined (__sparc)
-	#define __FLASHROM_ARCH__ "sparc"
-#elif defined (__alpha__)
-	#define __FLASHROM_ARCH__ "alpha"
-#elif defined (__hppa__) || defined (__hppa)
-	#define __FLASHROM_ARCH__ "hppa"
-#elif defined (__m68k__)
-	#define __FLASHROM_ARCH__ "m68k"
-#elif defined (__riscv)
-	#define __FLASHROM_ARCH__ "riscv"
-#elif defined (__sh__)
-	#define __FLASHROM_ARCH__ "sh"
-#elif defined(__s390__) || defined(__s390x__) || defined(__zarch__)
-	#define __FLASHROM_ARCH__ "s390"
-#elif defined(__arc__)
-	#define __FLASHROM_ARCH__ "arc"
-#elif defined(__ARC64__)
-	#define __FLASHROM_ARCH__ "arc64"
-#elif defined(__e2k__)
-	#define __FLASHROM_ARCH__ "e2k"
-#else
-	#define __FLASHROM_ARCH__ "unknown"
-#endif
-__FLASHROM_ARCH__
diff --git a/Makefile.d/cc_test.c b/Makefile.d/cc_test.c
deleted file mode 100644
index 0610964d..00000000
--- a/Makefile.d/cc_test.c
+++ /dev/null
@@ -1,6 +0,0 @@
-int main(int argc, char **argv)
-{
-	(void)argc;
-	(void)argv;
-	return 0;
-}
diff --git a/Makefile.d/clock_gettime_test.c b/Makefile.d/clock_gettime_test.c
deleted file mode 100644
index 000aa425..00000000
--- a/Makefile.d/clock_gettime_test.c
+++ /dev/null
@@ -1,9 +0,0 @@
-#include <time.h>
-int main(int argc, char **argv)
-{
-	(void)argc;
-	(void)argv;
-	struct timespec res;
-	clock_gettime(CLOCK_REALTIME, &res);
-	return 0;
-}
diff --git a/Makefile.d/endian_test.h b/Makefile.d/endian_test.h
deleted file mode 100644
index 36658b31..00000000
--- a/Makefile.d/endian_test.h
+++ /dev/null
@@ -1,89 +0,0 @@
-/*
- * This file is part of the flashrom project.
- *
- * Copyright (C) 2011 Carl-Daniel Hailfinger
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License as published by
- * the Free Software Foundation; version 2 of the License.
- *
- * This program is distributed in the hope that it will be useful,
- * but WITHOUT ANY WARRANTY; without even the implied warranty of
- * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
- * GNU General Public License for more details.
- */
-
-/*
- * This file determinate the target endian. It should only be used my the Makefile
- */
-
-#if defined (__i386__) || defined (__x86_64__) || defined(__amd64__)
-/* All x86 is little-endian. */
-#define __FLASHROM_LITTLE_ENDIAN__ 1
-#elif defined (__mips) || defined (__mips__) || defined (__MIPS__) || defined (mips)
-/* MIPS can be either endian. */
-#if defined (__MIPSEL) || defined (__MIPSEL__) || defined (_MIPSEL) || defined (MIPSEL)
-#define __FLASHROM_LITTLE_ENDIAN__ 1
-#elif defined (__MIPSEB) || defined (__MIPSEB__) || defined (_MIPSEB) || defined (MIPSEB)
-#define __FLASHROM_BIG_ENDIAN__ 1
-#endif
-#elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || \
-      defined(__ppc__) || defined(__ppc64__) || defined(_M_PPC) || defined(_ARCH_PPC) || \
-      defined(_ARCH_PPC64) || defined(__ppc)
-/* PowerPC can be either endian. */
-#if defined (_BIG_ENDIAN) || defined (__BIG_ENDIAN__)
-#define __FLASHROM_BIG_ENDIAN__ 1
-#elif defined (_LITTLE_ENDIAN) || defined (__LITTLE_ENDIAN__)
-#define __FLASHROM_LITTLE_ENDIAN__ 1
-#endif
-#elif defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(_ARM) || defined(_M_ARM) || defined(__arm) || \
-      defined(__aarch64__)
-/* ARM can be either endian. */
-#if defined (__ARMEB__) || defined (__BIG_ENDIAN__)
-#define __FLASHROM_BIG_ENDIAN__ 1
-#elif defined (__ARMEL__) || defined (__LITTLE_ENDIAN__)
-#define __FLASHROM_LITTLE_ENDIAN__ 1
-#endif
-#elif defined (__sparc__) || defined (__sparc)
-/* SPARC is big endian in general (but allows to access data in little endian too). */
-#define __FLASHROM_BIG_ENDIAN__ 1
-#elif defined(__arc__)
-#if defined(__BIG_ENDIAN__)
-#define __FLASHROM_BIG_ENDIAN__ 1
-#else
-#define __FLASHROM_LITTLE_ENDIAN__ 1
-#endif
-#endif
-
-#if !defined (__FLASHROM_BIG_ENDIAN__) && !defined (__FLASHROM_LITTLE_ENDIAN__)
-/* If architecture-specific approaches fail try generic variants. First: BSD (works about everywhere). */
-#if !(defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(__WINDOWS__))
-#include <sys/param.h>
-#if defined (__BYTE_ORDER)
-#if __BYTE_ORDER == __LITTLE_ENDIAN
-#define __FLASHROM_LITTLE_ENDIAN__
-#elif __BYTE_ORDER == __BIG_ENDIAN
-#define __FLASHROM_BIG_ENDIAN__
-#else
-#error Unknown byte order!
-#endif
-#endif /* defined __BYTE_ORDER */
-#endif /* !IS_WINDOWS */
-#if !defined (__FLASHROM_BIG_ENDIAN__) && !defined (__FLASHROM_LITTLE_ENDIAN__)
-/* Nonstandard libc-specific macros for determining endianness. */
-/* musl provides an endian.h as well... but it can not be detected from within C. */
-#if defined(__GLIBC__)
-#include <endian.h>
-#if BYTE_ORDER == LITTLE_ENDIAN
-#define __FLASHROM_LITTLE_ENDIAN__ 1
-#elif BYTE_ORDER == BIG_ENDIAN
-#define __FLASHROM_BIG_ENDIAN__ 1
-#endif
-#endif
-#endif
-#endif
-#if defined(__FLASHROM_LITTLE_ENDIAN__)
-"little"
-#else
-"big"
-#endif
diff --git a/Makefile.d/ft232h_test.c b/Makefile.d/ft232h_test.c
deleted file mode 100644
index 21bc9958..00000000
--- a/Makefile.d/ft232h_test.c
+++ /dev/null
@@ -1,3 +0,0 @@
-#include <ftdi.h>
-
-enum ftdi_chip_type type = TYPE_232H;
\ No newline at end of file
diff --git a/Makefile.d/getopt_test.c b/Makefile.d/getopt_test.c
deleted file mode 100644
index 9f726080..00000000
--- a/Makefile.d/getopt_test.c
+++ /dev/null
@@ -1,8 +0,0 @@
-#include <getopt.h>
-
-int main(int argc, char **argv)
-{
-	(void)argc;
-	(void)argv;
-	return 0;
-}
diff --git a/Makefile.d/linux_i2c_test.c b/Makefile.d/linux_i2c_test.c
deleted file mode 100644
index 768226ba..00000000
--- a/Makefile.d/linux_i2c_test.c
+++ /dev/null
@@ -1,9 +0,0 @@
-#include <linux/i2c-dev.h>
-#include <linux/i2c.h>
-
-int main(int argc, char **argv)
-{
-	(void)argc;
-	(void)argv;
-	return 0;
-}
diff --git a/Makefile.d/linux_mtd_test.c b/Makefile.d/linux_mtd_test.c
deleted file mode 100644
index d254e242..00000000
--- a/Makefile.d/linux_mtd_test.c
+++ /dev/null
@@ -1,8 +0,0 @@
-#include <mtd/mtd-user.h>
-
-int main(int argc, char **argv)
-{
-	(void)argc;
-	(void)argv;
-	return 0;
-}
diff --git a/Makefile.d/linux_spi_test.c b/Makefile.d/linux_spi_test.c
deleted file mode 100644
index a4d26578..00000000
--- a/Makefile.d/linux_spi_test.c
+++ /dev/null
@@ -1,9 +0,0 @@
-#include <linux/types.h>
-#include <linux/spi/spidev.h>
-
-int main(int argc, char **argv)
-{
-	(void)argc;
-	(void)argv;
-	return 0;
-}
diff --git a/Makefile.d/os_test.h b/Makefile.d/os_test.h
deleted file mode 100644
index 17045b25..00000000
--- a/Makefile.d/os_test.h
+++ /dev/null
@@ -1,67 +0,0 @@
-/*
- * This file is part of the flashrom project.
- *
- * Copyright (C) 2011 Carl-Daniel Hailfinger
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License as published by
- * the Free Software Foundation; version 2 of the License.
- *
- * This program is distributed in the hope that it will be useful,
- * but WITHOUT ANY WARRANTY; without even the implied warranty of
- * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
- * GNU General Public License for more details.
- */
-
-/*
- * This file determinate the target os. It should only be used my the Makefile
- */
-
-// Solaris
-#if defined (__sun) && (defined(__i386) || defined(__amd64))
-#define __FLASHROM_OS__ "SunOS"
-// OS X
-#elif defined(__MACH__) && defined(__APPLE__)
-#define __FLASHROM_OS__ "Darwin"
-// FreeBSD
-#elif defined(__FreeBSD__)
-#define __FLASHROM_OS__ "FreeBSD"
-// FreeBSD with glibc-based userspace (e.g. Debian/kFreeBSD)
-#elif defined(__FreeBSD_kernel__) && defined(__GLIBC__)
-#define __FLASHROM_OS__ "FreeBSD-glibc"
-// DragonFlyBSD
-#elif defined(__DragonFly__)
-#define __FLASHROM_OS__ "DragonFlyBSD"
-// NetBSD
-#elif defined(__NetBSD__)
-#define __FLASHROM_OS__ "NetBSD"
-// OpenBSD
-#elif defined(__OpenBSD__)
-#define __FLASHROM_OS__ "OpenBSD"
-// DJGPP
-#elif defined(__DJGPP__)
-#define __FLASHROM_OS__ "DOS"
-// MinGW (always has _WIN32 available)
-#elif defined(__MINGW32__)
-#define __FLASHROM_OS__ "MinGW"
-// Cygwin (usually without _WIN32)
-#elif defined( __CYGWIN__)
-#define __FLASHROM_OS__ "Cygwin"
-// libpayload
-#elif defined(__LIBPAYLOAD__)
-#define __FLASHROM_OS__ "libpayload"
-// GNU Hurd
-#elif defined(__gnu_hurd__)
-#define __FLASHROM_OS__ "Hurd"
-// Linux
-#elif defined(__linux__)
-	// There are various flags in use on Android apparently. __ANDROID__ seems to be the most trustworthy.
-	#if defined(__ANDROID__)
-		#define __FLASHROM_OS__ "Android"
-	#else
-		#define __FLASHROM_OS__ "Linux"
-	#endif
-#else
-#define __FLASHROM_OS__ "unknown"
-#endif
-__FLASHROM_OS__
diff --git a/Makefile.d/pciutils_test.c b/Makefile.d/pciutils_test.c
deleted file mode 100644
index 3d67c292..00000000
--- a/Makefile.d/pciutils_test.c
+++ /dev/null
@@ -1,8 +0,0 @@
-#include <pciutils/pci.h>
-
-int main(int argc, char **argv)
-{
-	(void)argc;
-	(void)argv;
-	return 0;
-}
diff --git a/Makefile.d/utsname_test.c b/Makefile.d/utsname_test.c
deleted file mode 100644
index 7bc66652..00000000
--- a/Makefile.d/utsname_test.c
+++ /dev/null
@@ -1,9 +0,0 @@
-#include <sys/utsname.h>
-struct utsname osinfo;
-int main(int argc, char **argv)
-{
-	(void)argc;
-	(void)argv;
-	uname(&osinfo);
-	return 0;
-}
diff --git a/Makefile.include b/Makefile.include
deleted file mode 100644
index 5f81ccc9..00000000
--- a/Makefile.include
+++ /dev/null
@@ -1,65 +0,0 @@
-#
-# This file is part of the flashrom project.
-#
-# This program is free software; you can redistribute it and/or modify
-# it under the terms of the GNU General Public License as published by
-# the Free Software Foundation; version 2 of the License.
-#
-# This program is distributed in the hope that it will be useful,
-# but WITHOUT ANY WARRANTY; without even the implied warranty of
-# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-# GNU General Public License for more details.
-#
-
-# Here are functions and macros defined for the Makefile
-
-define mark_unsupported
-$(foreach p,$1, \
-	$(if $(filter $($(p)),yes), \
-		$(eval UNSUPPORTED_FEATURES += $(p)=yes), \
-		$(eval override $(p) := no)))
-endef
-
-define filter_deps
-$(strip $(foreach p,$1, \
-	$(if $(filter $($(p)),yes), \
-		$(p))))
-endef
-
-define disable_all
-$(foreach p,$1, \
-	$(eval override $(p) := no))
-endef
-
-# Run the C Preprocessor with file $1 and return the last line, removing quotes.
-define c_macro_test
-$(strip $(call debug_shell, $(CC) -E $1 | tail -1 | tr -d '"'))
-endef
-
-define c_compile_test # $1: files to compile, $2: cflags
-$(call debug_shell, $(CC) -c -Wall -Werror $2 $1 -o /dev/null && echo yes || echo no)
-endef
-
-define c_link_test # $1: file to compile and link, $2: cflags, $3: ldflags
-$(call debug_shell, $(CC) -Wall -Werror $2 $1 $3 -o /dev/null && echo yes || echo no)
-endef
-
-define find_dependency
-$(call debug_shell, $(if $(PKG_CONFIG_LIBDIR),PKG_CONFIG_LIBDIR=$(PKG_CONFIG_LIBDIR),) $(PKG_CONFIG) --exists $1 && echo yes || echo no)
-endef
-
-define dependency_version
-$(call debug_shell, $(if $(PKG_CONFIG_LIBDIR),PKG_CONFIG_LIBDIR=$(PKG_CONFIG_LIBDIR),) $(PKG_CONFIG) --modversion $1 2>/dev/null)
-endef
-
-define has_dependency # $1: dependency, $2: action/target
-$(if $(findstring $(strip $1),yes), $(strip $2))
-endef
-
-define dependency_cflags
-$(call debug_shell, $(if $(PKG_CONFIG_LIBDIR),PKG_CONFIG_LIBDIR=$(PKG_CONFIG_LIBDIR),) $(PKG_CONFIG) --cflags $1 2>/dev/null)
-endef
-
-define dependency_ldflags
-$(call debug_shell, $(if $(PKG_CONFIG_LIBDIR),PKG_CONFIG_LIBDIR=$(PKG_CONFIG_LIBDIR),) $(PKG_CONFIG) --libs --static $1 2>/dev/null)
-endef
diff --git a/OWNERS.android b/OWNERS.android
index cff4fcda..b578b5de 100644
--- a/OWNERS.android
+++ b/OWNERS.android
@@ -1,3 +1,4 @@
 include platform/system/core:main:/janitors/OWNERS
 
 czapiga@google.com
+bernacki@google.com
diff --git a/README.rst b/README.rst
index 371fd617..29005172 100644
--- a/README.rst
+++ b/README.rst
@@ -23,10 +23,7 @@ Please see the flashrom(8) manpage :doc:`classic_cli_manpage`.
 Building / installing / packaging
 ---------------------------------
 
-flashrom supports building with **make** and **meson**.
-
-TLDR, building with meson
-"""""""""""""""""""""""""
+flashrom is built with **meson**. TLDR:
 
 ::
 
@@ -38,17 +35,6 @@ TLDR, building with meson
 For full detailed instructions, follow the information in
 :doc:`dev_guide/building_from_source`
 
-TLDR, building with make
-""""""""""""""""""""""""
-
-::
-
-	make
-	make install
-
-For full detailed instructions, follow the information in
-:doc:`dev_guide/building_with_make`
-
 Contact
 -------
 
diff --git a/VERSION b/VERSION
index 32809333..bd033f42 100644
--- a/VERSION
+++ b/VERSION
@@ -1 +1 @@
-1.4.0-rc1
+v1.5.0-devel
diff --git a/ch347_spi.c b/ch347_spi.c
index 21dcabbb..34f2741e 100644
--- a/ch347_spi.c
+++ b/ch347_spi.c
@@ -51,6 +51,11 @@ struct ch347_spi_data {
 	int interface;
 };
 
+struct device_speeds {
+	const char *name;
+	const int divisor;
+};
+
 /* TODO: Add support for HID mode */
 static const struct dev_entry devs_ch347_spi[] = {
 	{0x1A86, 0x55DB, OK, "QinHeng Electronics", "USB To UART+SPI+I2C"},   /* CH347T */
@@ -63,6 +68,18 @@ static int ch347_interface[] = {
 	CH347F_IFACE,
 };
 
+static const struct device_speeds spispeeds[] = {
+	{"60M",     0},
+	{"30M",     1},
+	{"15M",     2},
+	{"7.5M",    3},
+	{"3.75M",   4},
+	{"1.875M",  5},
+	{"937.5K",  6},
+	{"468.75K", 7},
+	{NULL,      0}
+};
+
 static int ch347_spi_shutdown(void *data)
 {
 	struct ch347_spi_data *ch347_data = data;
@@ -266,9 +283,11 @@ static const struct spi_master spi_master_ch347_spi = {
 /* Largely copied from ch341a_spi.c */
 static int ch347_spi_init(const struct programmer_cfg *cfg)
 {
+	char *arg;
 	uint16_t vid = devs_ch347_spi[0].vendor_id;
 	uint16_t pid = 0;
 	int index = 0;
+	int speed_index = 2;
 	struct ch347_spi_data *ch347_data = calloc(1, sizeof(*ch347_data));
 	if (!ch347_data) {
 		msg_perr("Could not allocate space for SPI data\n");
@@ -332,9 +351,25 @@ static int ch347_spi_init(const struct programmer_cfg *cfg)
 		(desc.bcdDevice >> 4) & 0x000F,
 		(desc.bcdDevice >> 0) & 0x000F);
 
-	/* TODO: add programmer cfg for things like CS pin and divisor */
-	if (ch347_spi_config(ch347_data, 2) < 0)
+	/* set CH347 clock division */
+	arg = extract_programmer_param_str(cfg, "spispeed");
+	if (arg) {
+		for (speed_index = 0; spispeeds[speed_index].name; speed_index++) {
+			if (!strncasecmp(spispeeds[speed_index].name, arg, strlen(spispeeds[speed_index].name))) {
+				break;
+			}
+		}
+	}
+	if (!spispeeds[speed_index].name || !arg) {
+		msg_perr("Unknown value of spispeed parameter, using default 15MHz clock spi.\n");
+		speed_index = 2;
+	}
+	free(arg);
+	if (ch347_spi_config(ch347_data, spispeeds[speed_index].divisor) < 0) {
 		goto error_exit;
+	} else {
+		msg_pinfo("CH347 SPI clock set to %sHz.\n", spispeeds[speed_index].name);
+	}
 
 	return register_spi_master(&spi_master_ch347_spi, ch347_data);
 
@@ -348,4 +383,4 @@ const struct programmer_entry programmer_ch347_spi = {
 	.type		= USB,
 	.devs.dev	= devs_ch347_spi,
 	.init		= ch347_spi_init,
-};
+};
\ No newline at end of file
diff --git a/chipset_enable.c b/chipset_enable.c
index 67443a05..9aa727eb 100644
--- a/chipset_enable.c
+++ b/chipset_enable.c
@@ -606,6 +606,7 @@ static enum chipbustype enable_flash_ich_report_gcs(
 	case CHIPSET_400_SERIES_COMET_POINT:
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_METEOR_LAKE:
 	case CHIPSET_PANTHER_LAKE:
 	case CHIPSET_ELKHART_LAKE:
@@ -714,6 +715,7 @@ static enum chipbustype enable_flash_ich_report_gcs(
 		break;
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_C740_SERIES_EMMITSBURG:
 	case CHIPSET_METEOR_LAKE:
 	case CHIPSET_PANTHER_LAKE:
@@ -751,6 +753,7 @@ static enum chipbustype enable_flash_ich_report_gcs(
 	case CHIPSET_400_SERIES_COMET_POINT:
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_METEOR_LAKE:
 	case CHIPSET_PANTHER_LAKE:
 	case CHIPSET_APOLLO_LAKE:
@@ -938,7 +941,13 @@ static int enable_flash_pch100_or_c620(const struct programmer_cfg *cfg,
 		msg_perr("Can't allocate PCI accessor.\n");
 		return ret;
 	}
+#if CONFIG_USE_LIBPCI_ECAM == 1
+	pci_acc->method = PCI_ACCESS_ECAM;
+	msg_pdbg("Using libpci PCI_ACCESS_ECAM\n");
+#else
 	pci_acc->method = PCI_ACCESS_I386_TYPE1;
+	msg_pdbg("Using libpci PCI_ACCESS_I386_TYPE1\n");
+#endif
 	pci_init(pci_acc);
 	register_shutdown(enable_flash_pch100_shutdown, pci_acc);
 
@@ -1017,6 +1026,11 @@ static int enable_flash_pch600(const struct programmer_cfg *cfg, struct pci_dev
 	return enable_flash_pch100_or_c620(cfg, dev, name, 0x1f, 5, CHIPSET_600_SERIES_ALDER_POINT);
 }
 
+static int enable_flash_pch700(const struct programmer_cfg *cfg, struct pci_dev *const dev, const char *const name)
+{
+	return enable_flash_pch100_or_c620(cfg, dev, name, 0x1f, 5, CHIPSET_700_SERIES_RAPTOR_POINT);
+}
+
 static int enable_flash_mtl(const struct programmer_cfg *cfg, struct pci_dev *const dev, const char *const name)
 {
 	return enable_flash_pch100_or_c620(cfg, dev, name, 0x1f, 5, CHIPSET_METEOR_LAKE);
@@ -2190,9 +2204,19 @@ const struct penable chipset_enables[] = {
 	{0x8086, 0x7a83, B_S,    NT,  "Intel", "Q670",				enable_flash_pch600},
 	{0x8086, 0x7a84, B_S,    DEP, "Intel", "Z690",				enable_flash_pch600},
 	{0x8086, 0x7a88, B_S,    NT,  "Intel", "W680",				enable_flash_pch600},
-	{0x8086, 0x7a8a, B_S,    NT,  "Intel", "W685",				enable_flash_pch600},
 	{0x8086, 0x7a8d, B_S,    NT,  "Intel", "WM690",				enable_flash_pch600},
 	{0x8086, 0x7a8c, B_S,    NT,  "Intel", "HM670",				enable_flash_pch600},
+	{0x8086, 0x7a90, B_S,    NT,  "Intel", "R680E",				enable_flash_pch600},
+	{0x8086, 0x7a91, B_S,    NT,  "Intel", "Q670E",				enable_flash_pch600},
+	{0x8086, 0x7a92, B_S,    NT,  "Intel", "H610E",				enable_flash_pch600},
+	{0x8086, 0x7a8a, B_S,    NT,  "Intel", "W790",				enable_flash_pch700},
+	{0x8086, 0x7a04, B_S,    DEP, "Intel", "Z790",				enable_flash_pch700},
+	{0x8086, 0x7a05, B_S,    NT,  "Intel", "H770",				enable_flash_pch700},
+	{0x8086, 0x7a06, B_S,    NT,  "Intel", "B760",				enable_flash_pch700},
+	{0x8086, 0x7a0c, B_S,    NT,  "Intel", "HM770",				enable_flash_pch700},
+	{0x8086, 0x7a0d, B_S,    NT,  "Intel", "WM790",				enable_flash_pch700},
+	{0x8086, 0x7a14, B_S,    NT,  "Intel", "C262",				enable_flash_pch700},
+	{0x8086, 0x7a13, B_S,    NT,  "Intel", "C266",				enable_flash_pch700},
 	{0x8086, 0x7e23, B_S,    DEP, "Intel", "Meteor Lake-P/M",		enable_flash_mtl},
 	{0x8086, 0xe323, B_S,    DEP, "Intel", "Panther Lake-U/H 12Xe",		enable_flash_ptl},
 	{0x8086, 0xe423, B_S,    DEP, "Intel", "Panther Lake-H 4Xe",		enable_flash_ptl},
diff --git a/dediprog.c b/dediprog.c
index 734fcfa1..aa3a1cf0 100644
--- a/dediprog.c
+++ b/dediprog.c
@@ -593,7 +593,7 @@ err:
 static int dediprog_spi_bulk_write(struct flashctx *flash, const uint8_t *buf, unsigned int chunksize,
 				   unsigned int start, unsigned int len, uint8_t dedi_spi_cmd)
 {
-	/* USB transfer size must be 512, other sizes will NOT work at all.
+	/* USB transfer size must be 256, other sizes will NOT work at all.
 	 * chunksize is the real data size per USB bulk transfer. The remaining
 	 * space in a USB bulk transfer must be filled with 0xff padding.
 	 */
diff --git a/doc/about_flashrom/team.rst b/doc/about_flashrom/team.rst
index 215d9309..cbcef458 100644
--- a/doc/about_flashrom/team.rst
+++ b/doc/about_flashrom/team.rst
@@ -6,7 +6,7 @@ flashrom development process is happening in Gerrit.
 All contributors and users who have a Gerrit account can send patches,
 add comments to patches and vote +1..-1 on patches.
 
-All contributors and users are expected to follow Development guidelines and
+All contributors and users are expected to follow :doc:`/dev_guide/development_guide` and
 :doc:`code_of_conduct`.
 
 There are two special groups in Gerrit.
@@ -18,7 +18,7 @@ Members of the group (see `flashrom reviewers <https://review.coreboot.org/admin
 can do full approval of patches (i.e. vote +2).
 
 In general, members of the group have some area of responsibility in the
-`MAINTAINERS <https://review.coreboot.org/plugins/gitiles/flashrom/+/refs/heads/main/MAINTAINERS>`_ file,
+`MAINTAINERS <https://github.com/flashrom/flashrom/blob/main/MAINTAINERS>`_ file,
 and are automatically added as reviewers to patches when the patch touches this area.
 
 The responsibilities are the following.
diff --git a/doc/classic_cli_manpage.rst b/doc/classic_cli_manpage.rst
index 19c804a9..b66dc2ec 100644
--- a/doc/classic_cli_manpage.rst
+++ b/doc/classic_cli_manpage.rst
@@ -622,6 +622,18 @@ Example::
         syntax where ``state`` is ``yes`` or ``no`` (default value). ``yes`` means active state of the pin implies that chip is
         write-protected (on real hardware the pin is usually negated, but not here).
 
+**Frequency**
+	Frequency can be specified in ``Hz`` (default), ``KHz``, or ``MHz`` (not case sensitive).
+	If ``freq`` parameter is passed in from command line, commands will delay for certain time before returning,
+	so that to emulate the requested frequency.
+
+	Valid range is [1Hz, 8000Mhz] and there is no delay by default.
+
+	The delay of an SPI command is proportional to the number of bits send over SPI bus in both directions
+	and is calculated based on the assumption that we transfer at 1 bit/Hz::
+
+		flashrom -p dummy:emulate=W25Q128FV,freq=64mhz
+
 
 nic3com, nicrealtek, nicnatsemi, nicintel, nicintel_eeprom, nicintel_spi, gfxnvidia, ogp_spi, drkaiser, satasii, satamv, atahpt, atavia, atapromise, it8212 programmers
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
@@ -636,6 +648,7 @@ is the PCI function number of the desired device. Example::
 
         flashrom -p nic3com:pci=05:04.0
 
+Some of these programmers have more info below.
 
 atavia programmer
 ^^^^^^^^^^^^^^^^^
@@ -655,6 +668,18 @@ This programmer is currently limited to 32 kB, regardless of the actual size of
 fact that, on the tested device (a Promise Ultra100), not all of the chip's address lines were actually connected.
 You may use this programmer to flash firmware updates, since these are only 16 kB in size (padding to 32 kB is required).
 
+nic3com programmer
+^^^^^^^^^^^^^^^^^^
+
+flashrom supports some 3Com network cards to reflash the (parallel) flash attached to these cards,
+but it is also possible to use these cards to reflash other chips which fit in there electrically.
+Please note that the small number of address lines connected to the chip may make accessing large chips impossible.
+The maximum supported chip size is 128KB.
+
+nicintel_spi programmer
+^^^^^^^^^^^^^^^^^^^^^^^
+
+Programmer for SPI flash ROMs on Intel Gigabit network cards. Tested on 32-bit hardware/PCI only.
 
 nicintel_eeprom programmer
 ^^^^^^^^^^^^^^^^^^^^^^^^^^
@@ -666,6 +691,18 @@ themselves to be identified, the controller relies on correct size values writte
 Intel specifies following EEPROMs to be compatible:
 Atmel AT25128, AT25256, Micron (ST) M95128, M95256 and OnSemi (Catalyst) CAT25CS128.
 
+gfxnvidia programmer
+^^^^^^^^^^^^^^^^^^^^
+
+Flashrom supports some Nvidia graphic cards to reflash the (parallel) flash attached to these cards,
+but it is also possible to use these cards to reflash other chips which fit in there electrically.
+
+satasii programmer
+^^^^^^^^^^^^^^^^^^
+
+Flashrom supports some SiI ATA/SATA controllers to reflash the flash attached to these controller cards,
+but it is also possible to use these cards to reflash other chips which fit in there electrically.
+Please note that the small number of address lines connected to the chip may make accessing large chips impossible.
 
 ft2232_spi programmer
 ^^^^^^^^^^^^^^^^^^^^^
@@ -1021,8 +1058,14 @@ as per the device.
 ch347_spi programmer
 ^^^^^^^^^^^^^^^^^^^^
 
-The WCH CH347 programmer does not currently support any parameters. SPI frequency is fixed at 2 MHz, and CS0 is used
-as per the device.
+An optional ``spispeed`` parameter could be used to specify the SPI speed. This parameter is available for the CH347T and CH347F device.
+The default SPI speed is 15MHz if no value is specified.
+Syntax is::
+
+        flashrom -p ch347_spi:spispeed=value
+
+where ``value`` can be ``60M``, ``30M``, ``15M``, ``7.5M``, ``3.75M``, ``1.875M``, ``937.5K``, ``468.75K``.
+
 
 ni845x_spi programmer
 ^^^^^^^^^^^^^^^^^^^^^
diff --git a/doc/contact.rst b/doc/contact.rst
index 79cdb918..38888fbb 100644
--- a/doc/contact.rst
+++ b/doc/contact.rst
@@ -43,8 +43,8 @@ Most of the discussion is about flashrom development, contributions, tech talk a
 
 You are welcome to join and discuss current and future flashrom development, ideas and contributions.
 
-If you have a problem and would like to get help, don't ask for help. Instead, just **explain** your problem right away,
-and make sure to **describe** the situation as much as possible, so that other people can understand you and provide meaningful answers.
+If you have a problem and would like to get help, don't ask for help. Instead, just explain your problem right away,
+and make sure to describe the situation as much as possible, so that other people can understand you and provide meaningful answers.
 Otherwise, others have to ask or guess the details of your problem, which is frustrating for both parties.
 
 Should you need to paste lots of text (more than three lines), please use a `paste service <https://en.wikipedia.org/wiki/Pastebin>`_.
@@ -54,6 +54,12 @@ Other good paste services are `ix.io <http://ix.io/>`_, `paste.rs <https://paste
 
 Questions on `coreboot <https://coreboot.org>`_, `OpenBIOS <http://www.openbios.info/>`_, firmware and related topics are welcome in **#coreboot** on the same server.
 
+Discord
+"""""""
+
+Flashrom Discord channel is hosted on coreboot's server. Once you join, you will be able to see all coreboot's and flashrom's channels in one place.
+To join, use the `invite link <https://discord.gg/dgcrkwVyeR>`_.
+
 IRC
 """
 
@@ -68,10 +74,10 @@ Do note that IRC's nature has a significant effect on conversations. People from
 with many different cultures and timezones. Most people are in the `CET timezone <https://en.wikipedia.org/wiki/Central_European_Time>`_,
 so the channel may be very quiet during `CET nighttime <https://time.is/CET>`_.
 
-If you receive no replies, **please be patient**.
+If you receive no replies, *please be patient*.
 After all, silence is better than getting replied with `"IDK" <https://en.wiktionary.org/wiki/IDK>`_.
-Frequently, somebody knows the answer, but hasn't checked IRC yet. In any case, please **do not leave the channel while waiting for an answer!**
-Since IRC does not store messages, replying to somebody who left the channel is **impossible**.
+Frequently, somebody knows the answer, but hasn't checked IRC yet. In any case, please *do not leave the channel while waiting for an answer!*
+Since IRC does not store messages, replying to somebody who left the channel is *impossible*.
 
 To have persistence on IRC, you can set up an `IRC bouncer <https://en.wikipedia.org/wiki/Internet_Relay_Chat#Bouncer>`_
 like `ZNC <https://en.wikipedia.org/wiki/ZNC>`_, or use `IRCCloud <https://www.irccloud.com/>`_.
@@ -81,11 +87,7 @@ Most of the time, people use IRC on wider-than-tall screens. Because of this, co
 Instead of sending lots of tiny messages with only about two words, prefer using longer sentences, spaces and punctuation symbols.
 If reading and understanding your messages is easy, replying to them is also easy.
 
-Discord
-"""""""
-
-Flashrom Discord channel is hosted on coreboot's server. Once you join, you will be able to see all coreboot's and flashrom's channels in one place.
-To join, use the `invite link <https://discord.gg/dgcrkwVyeR>`_.
+*Note: the channel is not moderated or monitored by any of the current active maintainers.*
 
 Dev meeting
 -----------
diff --git a/doc/contrib_howtos/how_to_add_new_chip.rst b/doc/contrib_howtos/how_to_add_new_chip.rst
index b046ac36..8aad3241 100644
--- a/doc/contrib_howtos/how_to_add_new_chip.rst
+++ b/doc/contrib_howtos/how_to_add_new_chip.rst
@@ -96,12 +96,36 @@ Properties
 * ``.page_size`` is really hard.
   Please read this `long explanation <https://mail.coreboot.org/pipermail/flashrom/2013-April/010817.html>`_,
   or ignore it for now and set it to 256.
-* We encode various features of flash chips in a bitmask named ``.feature_bits``.
-  Available options can be found in ``include/flash.h``, look for macros defined by the pattern ``#define FEATURE_XXX``.
 * ``.tested`` is used to indicate if the code was tested to work with real hardware, its possible values are defined
   in ``include/flash.h``. Without any tests it should be set to ``TEST_UNTESTED``.
   See also another doc :doc:`how_to_mark_chip_tested`.
 
+Feature Bits
+============
+
+We encode various features of flash chips in a bitmask named ``.feature_bits``.
+Available options can be found in ``include/flash.h``, look for macros defined by the pattern ``#define FEATURE_XXX``.
+
+Some of the feature bits have more detailed docs, see below.
+
+Write-Status-Register (WRSR) Handling
+-------------------------------------
+
+The Write Status Register (WRSR) is used exclusively in SPI flash chips to configure various settings within the flash chip,
+including write protection and other features.
+The way WRSR is accessed varies between SPI flash chips, leading to the need for these feature bits.
+
+* ``FEATURE_WRSR_EWSR``
+  indicates that we need an **Enable-Write-Status-Register** (EWSR) instruction which opens the status register for the
+  immediately-followed next WRSR instruction. Usually, the opcode is **0x50**.
+
+* ``FEATURE_WRSR_WREN``
+  indicates that we need an **Write-Enable** (WREN) instruction to set the Write Enable Latch (WEL) bit. The WEL bit
+  must be set prior to every WRSR command. Usually, the opcode is **0x06**.
+
+* ``FEATURE_WRSR_EITHER``
+  indicates that either EWSR or WREN is supported in this chip.
+
 Operations
 ==========
 
diff --git a/doc/dev_guide/building_with_make.rst b/doc/dev_guide/building_with_make.rst
deleted file mode 100644
index 710aad3d..00000000
--- a/doc/dev_guide/building_with_make.rst
+++ /dev/null
@@ -1,195 +0,0 @@
-Building with make
-==================
-
-TLDR
-----
-
-::
-
-	make
-	make install
-
-Build instructions
-------------------
-
-**To build flashrom you need to install the following software:**
-
- * C compiler (GCC / clang)
- * pkg-config
-
- * pciutils+libpci (if you want support for mainboard or PCI device flashing)
- * libusb (if you want FT2232, Dediprog or USB-Blaster support)
- * libftdi (if you want FT2232 or USB-Blaster support)
- * libjaylink (if you want support for SEGGER J-Link and compatible devices)
- * NI-845x driver & library package (if you want support for NI-845x devices; uses a proprietary driver)
-
-**Linux et al:**
-
- * pciutils / libpci
- * pciutils-devel / pciutils-dev / libpci-dev
- * zlib-devel / zlib1g-dev (needed if libpci was compiled with libz support)
-
-**On FreeBSD, you need the following ports:**
-
- * devel/gmake
- * devel/libpci
-
-**On OpenBSD, you need the following ports:**
-
- * devel/gmake
- * sysutils/pciutils
-
-**To compile on Linux, use**::
-
-	make
-
-**To compile on FreeBSD, OpenBSD or DragonFly BSD, use**::
-
-	gmake
-
-**To compile on Nexenta, use**::
-
-	make
-
-**To compile on Solaris, use**::
-
-	gmake LDFLAGS="-L$pathtolibpci" CC="gcc -I$pathtopciheaders" CFLAGS=-O2
-
-**To compile on NetBSD (with pciutils, libftdi, libusb installed in /usr/pkg/), use**::
-
-	gmake
-
-**To compile and run on Darwin/Mac OS X:**
-
-Install DirectHW from coresystems GmbH.
-DirectHW is available at https://www.coreboot.org/DirectHW .
-
-**To compile on Windows:**
-
-Install MSYS tools (and the NI-845x drivers if desired) as described in
-:ref:`installing-dependencies`.
-
-To build with support for NI-845x::
-
-	make HAS_LIB_NI845X=yes CONFIG_NI845X_SPI=yes
-
-**To cross-compile on Linux for DOS:**
-
-Get packages of the DJGPP cross compiler and install them:
-
- * djgpp-filesystem djgpp-gcc djgpp-cpp djgpp-runtime djgpp-binutils
-
-As an alternative, the DJGPP web site offers packages for download as well:
-
- * djcross-binutils-2.29.1-1ap.x86_64.rpm
- * djcross-gcc-7.2.0-1ap.x86_64.rpm
- * djcrx-2.05-5.x86_64.rpm
-
-The cross toolchain packages for your distribution may have slightly different
-names (look for packages named *djgpp*).
-
-Alternatively, you could use a script to build it from scratch:
-https://github.com/andrewwutw/build-djgpp
-
-You will need the libpci and libgetopt library source trees and
-their compiled static libraries and header files installed in some
-directory say libpci-libgetopt/, which will be later specified with
-LIBS_BASE parameter during flashrom compilation. Easiest way to
-handle it is to put pciutils, libgetopt and flashrom directories
-in one subdirectory. There will be an extra subdirectory libpci-libgetopt
-created, which will contain compiled libpci and libgetopt.
-
-Download pciutils 3.5.6 and apply https://flashrom.org/File:Pciutils-3.5.6.patch.gz
-Compile pciutils, using following command line::
-
-	make ZLIB=no DNS=no HOST=i386-djgpp-djgpp CROSS_COMPILE=i586-pc-msdosdjgpp- \
-		PREFIX=/ DESTDIR=$PWD/../libpci-libgetopt  \
-		STRIP="--strip-program=i586-pc-msdosdjgpp-strip -s" install install-lib
-
-Download and compile with 'make' https://flashrom.org/File:Libgetopt.tar.gz
-
-Copy the libgetopt.a to ../libpci-libgetopt/lib and
-getopt.h to ../libpci-libgetopt/include
-
-Enter the flashrom directory::
-
-	make CC=i586-pc-msdosdjgpp-gcc STRIP=i586-pc-msdosdjgpp-strip LIBS_BASE=../libpci-libgetopt/ strip
-
-If you like, you can compress the resulting executable with UPX::
-
-	upx -9 flashrom.exe
-
-To run flashrom.exe, download https://flashrom.org/File:Csdpmi7b.zip and
-unpack CWSDPMI.EXE into the current directory or one in PATH.
-
-**To cross-compile on Linux for Windows:**
-
-Get packages of the MinGW cross compiler and install them::
-
-	mingw32-filesystem mingw32-cross-cpp mingw32-cross-binutils mingw32-cross-gcc
-	mingw32-runtime mingw32-headers
-
-The cross toolchain packages for your distribution may have slightly different
-names (look for packages named *mingw*).
-PCI-based programmers (internal etc.) are not supported on Windows.
-Run (change CC= and STRIP= settings where appropriate)::
-
-	make CC=i686-w64-mingw32-gcc STRIP=i686-w64-mingw32-strip
-
-**Processor architecture dependent features:**
-
-On non-x86 architectures a few programmers don't work (yet) because they
-use port-based I/O which is not directly available on non-x86. Those
-programmers will be disabled automatically if you run "make".
-
-**Compiler quirks:**
-
-If you are using clang and if you want to enable only one driver, you may hit an
-overzealous compiler warning from clang. Compile with "make WARNERROR=no" to
-force it to continue and enjoy.
-
-**Bindings:**
-
-Foreign function interface bindings for the rust language are included in the
-bindings folder. These are not compiled as part of the normal build process.
-See the readme under bindings/rust for more information.
-
-
-Installation
-------------
-
-In order to install flashrom and the manpage into /usr/local, type::
-
-	make install
-
-For installation in a different directory use DESTDIR, e.g. like this::
-
-	make DESTDIR=/usr install
-
-If you have insufficient permissions for the destination directory, use sudo
-by adding sudo in front of the commands above.
-
-
-Packaging
----------
-
-To package flashrom and remove dependencies on Git, either use::
-
-	make export
-
-or::
-
-	make tarball
-
-``make export`` will export all flashrom files from the Git repository at
-revision HEAD into a directory named ``$EXPORTDIR/flashrom-$RELEASENAME``
-and will additionally add a ``versioninfo.inc`` file in that directory to
-contain the Git revision of the exported tree and a date for the manual
-page.
-
-``make tarball`` will simply tar up the result of make export and compress
-it with bzip2.
-
-The snapshot tarballs are the result of ``make tarball`` and require no
-further processing. Some git files (for example the rust bindings) are omitted
-from the tarball, as controlled by the .gitattributes files.
diff --git a/doc/dev_guide/index.rst b/doc/dev_guide/index.rst
index 57cd8468..dcd7bd28 100644
--- a/doc/dev_guide/index.rst
+++ b/doc/dev_guide/index.rst
@@ -5,5 +5,5 @@ Developers documentation
     :maxdepth: 1
 
     building_from_source
-    building_with_make
     development_guide
+    release_process
diff --git a/doc/dev_guide/release_process.rst b/doc/dev_guide/release_process.rst
new file mode 100644
index 00000000..15eaf6ca
--- /dev/null
+++ b/doc/dev_guide/release_process.rst
@@ -0,0 +1,106 @@
+===============
+Release process
+===============
+
+The document describes the technical aspect of making a flashrom release,
+and it assumes that the team of active core maintainers is in agreement to commence the process.
+
+To go through the process, at least two maintainers are needed to be closely involved,
+because it includes sending and approving patches in Gerrit.
+
+Set up the timeline and announce on the mailing list
+====================================================
+
+Decide on the bug-fixing and testing window (3-4 weeks), decide exact dates of start and end of the window,
+and announce it on the mailing list. Ideally make an announcement a few weeks in advance.
+
+During the testing and bug-fixing window only bug fixes are merged, and no new features are added.
+Typically it's fine to push new features for review, and reviews are fine too,
+but merging new features will be delayed until the release is done.
+*This should be very clearly explained in the announcement.*
+
+Start testing and bug-fixing window
+===================================
+
+* Double-check and merge all the patches that are fully ready (see also :ref:`merge-checklist`)
+
+* Update VERSION file to first release candidate. The name pattern is: ``v{version_number}-rc{rc_number}``.
+
+  * As an example, the version name of the first release candidate can be ``v1.4.0-rc1``.
+  * To update the VERSION file, push a patch to Gerrit, and another maintainer should review and approve.
+
+* After submitting the change to the VERSION file, tag this commit. Tag name should be the same as
+  version name, for example above ``v1.4.0-rc1``.
+
+* Write an announcement on the mailing list. Be very clear about:
+
+  * start and end date of the window, and what does it mean
+  * any help with :ref:`building-and-testing` is very much appreciated
+
+**From this moment and until the release cut, the highest priority is for building and testing on various environments, and bug-fixing.**
+
+Release candidates
+==================
+
+If any bugs are found and fixed (or reverted), then the second, or third release candidate will be needed.
+The process is the same as with the first candidate:
+
+* Update the VERSION file, and submit this
+* Tag the commit which updates the VERSION file
+* Post an announcement on mailing list
+
+Release notes
+=============
+
+During the time in-between releases, ideally most updates are accumulated in the doc :doc:`/release_notes/devel`.
+While this doc is helpful, it is not a replacement for a human to go through all development history
+since the previous release and prepare release notes. One maintainer is preparing the release notes
+and sending them for review, and at least one other maintainer needs to review that (it can be more than one reviewer).
+
+Ideally the patch with release notes should be prepared, reviewed and approved before the release cut,
+so that it can be published by the time of final release announcement.
+
+For inspiration to write release notes, have a look at prior art :doc:`/release_notes/index`.
+
+There is one section in release notes, Download, which is not possible to complete before the actual release cut.
+Leave it as TODO, but complete the rest.
+
+Cut the release
+===============
+
+Wait for at least a week (or two) since the last release candidate. if everything is alright:
+
+* Submit the release notes, and in the same patch restart :doc:`/release_notes/devel` document.
+  This way everyone who is syncing the repository by the release tag will have release notes in the tree.
+
+* Update VERSION file to release version, name pattern is: ``v{version_name}``
+  (for example, it can be ``v1.4.0``), and submit this.
+
+* Tag the commit which updates the VERSION file. Tag name should be the same as version name,
+  for example above ``v1.4.0``.
+
+* Create the tarball:
+
+  * At the moment of writing, the command we use ``meson dist --include-subprojects``,
+    more details are in `meson docs <https://mesonbuild.com/Creating-releases.html#creating-releases>`_.
+  * Check that tarball name follows the pattern ``flashrom-v{version_name}.tar.xz``, for example ``flashrom-v1.4.0.tar.xz``.
+
+* Sign the tarball, and upload to the server together with the signature.
+
+* Update release notes with the link to download tarball, signature, and fingerprint. Submit this and check that final release notes are published on the website.
+
+* Write the release announcement, don't forget to:
+
+  * Link to download the tarball, signature and fingerprint.
+  * Say thank you to everyone who is helping and supporting flashrom
+  * Add link to published release notes on the website
+
+Start the next cycle of development
+===================================
+
+* Update the VERSION file to the development version. For example, the name pattern is: ``v{version_name}-devel``,
+  for example ``v1.5.0-devel``, and submit this.
+
+* Submit all the patches that have been ready and waiting.
+
+* Celebrate :)
diff --git a/doc/how_to_support_flashrom.rst b/doc/how_to_support_flashrom.rst
index 372ef383..7fdfdf84 100644
--- a/doc/how_to_support_flashrom.rst
+++ b/doc/how_to_support_flashrom.rst
@@ -63,6 +63,8 @@ in the reviewed patch. Approving the patch is much easier when the code reviews
 You can check pending patches under review `in Gerrit <https://review.coreboot.org/q/status:open+project:flashrom>`_
 and help with code review if a patch looks useful, you understand what it is about, and want to have it submitted.
 
+.. _building-and-testing:
+
 Building and testing
 ====================
 
diff --git a/doc/intro.rst b/doc/intro.rst
index b9a2c972..92bcac53 100644
--- a/doc/intro.rst
+++ b/doc/intro.rst
@@ -7,7 +7,7 @@ network/graphics/storage controller cards, and various other programmer devices.
   For more information, see the pages under :doc:`/supported_hw/index`.
 
 * Supports parallel, LPC, FWH and SPI flash interfaces and various chip packages (DIP32,
-  PLCC32, DIP8, SO8/SOIC8, TSOP32, TSOP40, TSOP48, BGA and more).
+  PLCC32, DIP8, SO8/SOIC8, TSOP32, TSOP40, TSOP48, BGA and more), see :doc:`user_docs/overview`.
 
 * No physical access needed, root access is sufficient (not needed for some programmers).
 
diff --git a/doc/release_notes/devel.rst b/doc/release_notes/devel.rst
new file mode 100644
index 00000000..80218990
--- /dev/null
+++ b/doc/release_notes/devel.rst
@@ -0,0 +1,82 @@
+===============================
+Recent development (unreleased)
+===============================
+
+This document describes the major changes that are expected to be included in
+the next release of flashrom and which are currently only available by source
+code checkout (see :doc:`../dev_guide/building_from_source`). These changes
+may be further revised before the next release.
+
+Known issues
+============
+
+AMD-based PCs with FCH are unable to read flash contents for internal (BIOS
+flash) chips larger than 16 MB, and attempting to do so may crash the system.
+Systems with AMD "Promontory" IO extenders (mostly "Zen" desktop platforms) are
+not currently supported.
+
+https://ticket.coreboot.org/issues/370
+
+Build only supported with Meson
+===============================
+
+As documented in the :doc:`v1.4 release notes <v_1_4>`, support for building
+flashrom with make has been removed; all Makefiles have been deleted. Meson is
+now the only supported tool for building flashrom from source.
+
+New Feature
+===========
+
+Libpci 3.13.0 and onwards support ECAM to access pci registers. Flashrom will
+be moved to ECAM from IO port 0xcf8/0xcfc if the libpci version is >= 3.13.0.
+The ECAM has been supported for a very long time, most platforms should support
+it. For those platforms don't support ECAM, libpci will terminate the process by
+exit.
+
+Chipset support
+===============
+
+Added Raptor Point PCH support.
+
+Chip model support added
+========================
+
+* FM25Q04
+* FM25Q64
+* FM25Q128
+
+* GD25B128E
+* GD25B256E
+* GD25B512MF
+* GD25F64F
+* GD25F256F
+* GD25R128E
+* GD25R256E
+* GD25R512MF
+* GD25LB256F
+* GD25LB512ME
+* GD25LB512MF
+* GD25LR256F
+* GD25LR512MF
+* GD25LF256F
+* GD25LF512MF
+
+* MX25U25645G
+* MX77U51250F
+
+* W25Q32JV_M
+
+* XM25LU64C
+* XM25QH32C
+* XM25QH32D
+* XM25QH64D
+* XM25QH128D
+* XM25QH256D
+* XM25QH512C
+* XM25QH512D
+* XM25QU16C
+* XM25QU32C
+* XM25QU128D
+* XM25QU256D
+* XM25QU512C
+* XM25QU512D
diff --git a/doc/release_notes/index.rst b/doc/release_notes/index.rst
index a8ef58f5..fe12d346 100644
--- a/doc/release_notes/index.rst
+++ b/doc/release_notes/index.rst
@@ -4,4 +4,6 @@ Release notes
 .. toctree::
     :maxdepth: 1
 
+    devel
+    v_1_4
     v_1_3
diff --git a/doc/release_notes/v_1_4.rst b/doc/release_notes/v_1_4.rst
new file mode 100644
index 00000000..d0542052
--- /dev/null
+++ b/doc/release_notes/v_1_4.rst
@@ -0,0 +1,329 @@
+================
+v1.4 (July 2024)
+================
+
+This document describes the major changes in flashrom version 1.4.0,
+from more than 400 patches contributed by more than 70 authors (thank you!)
+in the 18 months since version 1.3.0 was branched.
+
+Download
+========
+
+flashrom 1.4 can be downloaded in various ways:
+
+Anonymous checkout from the git repository at https://review.coreboot.org/flashrom.git
+(tag v1.4.0)
+
+A tarball is available for download at
+https://download.flashrom.org/releases/flashrom-1.4.0.tar.xz
+(signature https://download.flashrom.org/releases/flashrom-1.4.0.tar.xz.asc)
+
+fingerprint: 6E6E F9A0 BA47 8006 E277 6E4C C037 BB41 3134 D111
+
+Known issue
+===========
+
+AMD-based PCs with FCH are unable to read flash contents for internal (BIOS flash)
+chips larger than 16 MB, and attempting to do so may crash the system.
+Systems with AMD "Promontory" IO extenders (mostly "Zen" desktop platforms) are not currently
+supported.
+
+https://ticket.coreboot.org/issues/370
+
+Major updates
+=============
+
+Optimised erase and write logic
+-------------------------------
+
+Significant performance improvements with new logic which is based on:
+the optimal selection of erase blocks for the given logical layout,
+available erase functions, and size of memory area to erase/write.
+
+**Legacy code path still exists in the source tree, but it will be deleted by the next release.**
+
+Optimised delays logic
+----------------------
+
+Optimised logic and refactorings of delays functionality, in particular for SPI chips.
+
+* Flashrom now sleeps more aggressively when a delay is required, rather than
+  polling in a loop. This should reduce power consumption significantly, but
+  may require more time to complete operations on systems experiencing high
+  CPU load.
+* An unconditional 1-second delay was removed for SPI flashes. This is not
+  believed to be needed for any SPI flashes, but may be needed for some old
+  parallel flashes (where it remains in use).
+* Cycle-counting busy loops are now only used on DOS builds of flashrom. All
+  other platforms use OS timers for timed delays, which are expected to be
+  more accurate.
+* Tree-wide refactorings around programmer_delay and internal_delay
+
+Documentation is in the git tree
+--------------------------------
+
+Docs are available in the same repository as the code, in ``doc/`` directory.
+
+Website content is automatically generated from docs in the git tree.
+
+**Patches with code changes and new features can (and should) update documentation
+in the same patch, which makes it a lot easier to maintain up-to-date docs.**
+
+Note: the migration process for documents from flashrom wiki to the git tree is half way.
+Wiki is deprecated now, and will go away once the migration process complete.
+
+Makefile scheduled for removal
+------------------------------
+
+**Future versions of flashrom will drop support for building via Makefile**:
+Meson will become the only supported build system.
+
+The Makefile and meson build systems are currently at feature parity,
+except automated testing is supported only with meson.
+To reduce the maintenance burden, we plan to remove the Makefile after this release.
+
+Write-protect updates
+---------------------
+
+* Support reading security register
+* Support reading/writing configuration register
+* More range functions (with different block sizes and handling of CMP bit)
+
+Protected regions support
+-------------------------
+
+* Support to allow programmers to handle protected regions on the flash.
+* get_region() function is added so that programmers can expose access permissions
+  for multiple regions within the flash.
+* A get_region() implementation is added for the ichspi driver
+
+Chipset support added
+=====================
+
+* Tiger Lake
+* Emmitsburg Chipset SKU
+* Meteor Lake-P/M
+* Panther Lake-U/H 12Xe
+* Panther Lake-H 4Xe
+
+Chip models support added or updated
+====================================
+
+New models support
+------------------
+
+* AT25DF011
+
+* B.25D80A
+* B25Q64AS
+
+* GD25LB128E/GD25LR128E
+* GD25LB256E
+* GD25LF128E
+* GD25Q127C/GD25Q128E
+* GD25LQ255E
+* GD25LR256E
+* GD251R512ME
+
+* IS25LP016
+* IS25LQ016
+* IS25WP016
+* IS25WP020
+* IS25WP040
+* IS25WP080
+* IS25WQ040
+
+* MX25L1633E
+* MX25L1636E
+* MX25L3239E
+* MX25L3255E
+* MX25L3273F
+* MX25L6473F
+* MX25L6436E/MX25L6445E/MX25L6465E
+* MX25L6473E
+* MX25L12850F
+* MX77L25650F
+* MX25R2035F
+* MX25R4035F
+* MX25R8035F
+* MX25U25643G
+* MX25V16066
+
+* P25Q06H
+* P25Q11H
+* P25Q21H
+
+* W25Q16JV_M
+
+* XM25QH128A
+* XM25QH80B
+* XM25QH16C/XM25QH16D
+* XM25QU80B
+* XM25RU256C
+
+* XT25F02E
+* XT25F64B
+* XT25F128B
+
+* ZD25D20
+
+Added write-protect support
+---------------------------
+
+* EN25QH32
+* EN25QH64
+
+* MX25L3206E/MX25L3208E
+* MX25L6405
+* MX25L6405D
+* MX25L6406E/MX25L6408E
+* MX25L12833F
+* MT25QL512
+* MX25R1635F
+* MX25R1635F
+* MX25U25643G
+* MX25V1635F
+* MX25V4035F
+* MX25V8035F
+
+* N25Q032..1E
+* N25Q032..3E
+* N25Q064..1E
+* N25Q064..3E
+
+* W25Q16.V
+* W25Q32BV/W25Q32CV/W25Q32DV
+* W25Q32FV
+* W25Q32JV
+* W25Q32BW/W25Q32CW/W25Q32DW
+* W25Q32FW
+* W25Q32JW...Q
+* W25Q32JW...M
+* W25Q64JW...M
+* W25Q256JW_DTR
+* W25Q512NW-IM
+* W25X05
+* W25X10
+* W25X16
+* W25X20
+* W25X32
+* W25X40
+* W25X64
+* W25X80
+
+Marked as tested
+----------------
+
+* AM29LV040B
+
+* AT29C010A
+
+* FM25F01
+* FM25Q16
+
+* MT25QL128
+
+* S25FL128L
+
+* W25Q128.V
+
+* XM25QH64C
+* XM25QH256C
+* XM25QU256C
+
+Programmers support added or updated
+====================================
+
+* New programmer for ASM106x SATA controllers
+* New programmer for WCH CH347, supports CH347T and CH347F packaging.
+
+* buspirate: Add option for setting the aux pin
+* jlink_spi: add cs=tms option to jlink_spi programmer
+* raiden: Support target index with generic REQ_ENABLE
+* buspirate_spi: add support for hiz output with pullups=off
+* serprog: Add support for multiple SPI chip selects
+
+Utilities
+=========
+
+* Bash completion (enabled by default with command line interface)
+
+* CI checks for Signed-off-by line in commit message
+
+* CI builds documentation
+
+Unit tests
+==========
+
+Added coverage for erase and write logic
+----------------------------------------
+
+20 test cases for each operation, with various logical layouts and chip memory states,
+and additional 6 for each, with protected regions configured.
+The test for erase and write is set up so that new test cases can be added whenever needed.
+
+selfcheck
+---------
+
+selfcheck is now also implemented as a unit test.
+
+selfcheck provides critical sanity checks for the programmer table, board matches table,
+and array of flashchip definitions.
+
+Note that selfcheck currently, by default, still runs on flashrom init,
+because at the moment we can't run unit tests on all supported platforms,
+and we don't have continuous integration for all platforms.
+
+This gives an opportunity for performance improvement for developers or companies
+who build their own flashrom binary and, importantly,
+can run unit tests with the build (Linux, BSD).
+For their own binary, it is possible to disable selfcheck on init and save some time
+(**under their own responsibility to run unit tests**).
+
+Coverage report
+---------------
+
+Unit tests coverage report can be generated with gcov or lcov / llvm.
+
+ch341a_spi test
+---------------
+
+Unit test which covers initialization-probing-shutdown of ch341a_spi.
+
+Reduces the risk of breakage for the very popular programmer.
+
+Write-protect
+-------------
+
+Added coverage for write-protect operation
+
+Some of the other misc fixes and improvements
+=============================================
+
+* bitbang_spi.c: Fix unchecked heap allocation
+* writeprotect.c: skip unnecessary writes
+* writeprotect.c: refuse to work with chip if OTP WPS == 1
+* flashrom.c: Drop redundant chip read validation in verify_range()
+* ichspi: Clear Fast SPI HSFC register before HW seq operation
+* ichspi: Fix number of bytes for HW seq operations
+* writeprotect,ichspi,spi25: handle register access constraints
+* tree/: Make heap alloc checks err msg consistent
+* flashrom.c: Replace 'exit(1)' leaks with return codes on err paths
+* flashrom: Check for flash access restricitons in read_flash()
+* flashrom: Check for flash access restricitons in verify_range()
+* flashrom: Check for flash access restricitons in write_flash()
+* flashrom: Check for flash access restrictions in erase path
+* flashrom: Use WP-based unlocking on opaque masters
+* ni845x_spi: Fix signed - unsigned comparisons
+* flashrom: only perform WP unlock for write/erase operations
+* tree: Rename master branch to main
+* serial: Fix sp_flush_incoming for serprog TCP connections
+* Makefile,meson.build: Add support for Sphinx versions prior to 4.x
+* Makefile: Fix cleanup for Sphinx versions prior to 4.x
+* Makefile: Fix version string for non-Git builds
+* serprog protocol: Add SPI Mode and CS Mode commands
+* util/list_yet_unsupported_chips.h: Fix path
+* flashrom_udev.rules: Add rule for CH347
+* Add documentation for pico-serprog
+* cli_classic: Defer flashrom_init calibration until after options parsing
+* hwaccess_x86_io: Fix Android compilation with bionic libc
diff --git a/doc/supported_hw/supported_prog/ARM-USB-TINY_pinout.png b/doc/supported_hw/supported_prog/ARM-USB-TINY_pinout.png
new file mode 100644
index 00000000..aa95a59b
Binary files /dev/null and b/doc/supported_hw/supported_prog/ARM-USB-TINY_pinout.png differ
diff --git a/doc/supported_hw/supported_prog/Buspirate_v3_back.jpg b/doc/supported_hw/supported_prog/Buspirate_v3_back.jpg
new file mode 100644
index 00000000..3afb9745
Binary files /dev/null and b/doc/supported_hw/supported_prog/Buspirate_v3_back.jpg differ
diff --git a/doc/supported_hw/supported_prog/Buspirate_v3_front.jpg b/doc/supported_hw/supported_prog/Buspirate_v3_front.jpg
new file mode 100644
index 00000000..3c4fa9c2
Binary files /dev/null and b/doc/supported_hw/supported_prog/Buspirate_v3_front.jpg differ
diff --git a/doc/supported_hw/supported_prog/Dlp_usb1232h_bottom.jpg b/doc/supported_hw/supported_prog/Dlp_usb1232h_bottom.jpg
new file mode 100644
index 00000000..5ebf9b72
Binary files /dev/null and b/doc/supported_hw/supported_prog/Dlp_usb1232h_bottom.jpg differ
diff --git a/doc/supported_hw/supported_prog/Dlp_usb1232h_side.jpg b/doc/supported_hw/supported_prog/Dlp_usb1232h_side.jpg
new file mode 100644
index 00000000..0a17f6e0
Binary files /dev/null and b/doc/supported_hw/supported_prog/Dlp_usb1232h_side.jpg differ
diff --git a/doc/supported_hw/supported_prog/Dlp_usb1232h_spi_programmer.jpg b/doc/supported_hw/supported_prog/Dlp_usb1232h_spi_programmer.jpg
new file mode 100644
index 00000000..94eecb1f
Binary files /dev/null and b/doc/supported_hw/supported_prog/Dlp_usb1232h_spi_programmer.jpg differ
diff --git a/doc/supported_hw/supported_prog/Dlp_usb1232h_spi_programmer_breadboard_1.jpg b/doc/supported_hw/supported_prog/Dlp_usb1232h_spi_programmer_breadboard_1.jpg
new file mode 100644
index 00000000..61a7a18f
Binary files /dev/null and b/doc/supported_hw/supported_prog/Dlp_usb1232h_spi_programmer_breadboard_1.jpg differ
diff --git a/doc/supported_hw/supported_prog/Dlp_usb1232h_spi_programmer_breadboard_2.jpg b/doc/supported_hw/supported_prog/Dlp_usb1232h_spi_programmer_breadboard_2.jpg
new file mode 100644
index 00000000..92e143a6
Binary files /dev/null and b/doc/supported_hw/supported_prog/Dlp_usb1232h_spi_programmer_breadboard_2.jpg differ
diff --git a/doc/supported_hw/supported_prog/Ft2232spi_programer.jpg b/doc/supported_hw/supported_prog/Ft2232spi_programer.jpg
new file mode 100644
index 00000000..84f618c8
Binary files /dev/null and b/doc/supported_hw/supported_prog/Ft2232spi_programer.jpg differ
diff --git a/doc/supported_hw/supported_prog/Lycom-pe115-flashrom-buspirate-2.jpg b/doc/supported_hw/supported_prog/Lycom-pe115-flashrom-buspirate-2.jpg
new file mode 100644
index 00000000..5962fa9a
Binary files /dev/null and b/doc/supported_hw/supported_prog/Lycom-pe115-flashrom-buspirate-2.jpg differ
diff --git a/doc/supported_hw/supported_prog/Openmoko_0001.jpeg b/doc/supported_hw/supported_prog/Openmoko_0001.jpeg
new file mode 100644
index 00000000..7ea79685
Binary files /dev/null and b/doc/supported_hw/supported_prog/Openmoko_0001.jpeg differ
diff --git a/doc/supported_hw/supported_prog/Openmoko_0002.jpeg b/doc/supported_hw/supported_prog/Openmoko_0002.jpeg
new file mode 100644
index 00000000..be60d565
Binary files /dev/null and b/doc/supported_hw/supported_prog/Openmoko_0002.jpeg differ
diff --git a/doc/supported_hw/supported_prog/Openmoko_0003.jpeg b/doc/supported_hw/supported_prog/Openmoko_0003.jpeg
new file mode 100644
index 00000000..74109de5
Binary files /dev/null and b/doc/supported_hw/supported_prog/Openmoko_0003.jpeg differ
diff --git a/doc/supported_hw/supported_prog/Via_epia_m700_bios.jpg b/doc/supported_hw/supported_prog/Via_epia_m700_bios.jpg
new file mode 100644
index 00000000..6103838e
Binary files /dev/null and b/doc/supported_hw/supported_prog/Via_epia_m700_bios.jpg differ
diff --git a/doc/supported_hw/supported_prog/Via_epia_m700_programer.jpg b/doc/supported_hw/supported_prog/Via_epia_m700_programer.jpg
new file mode 100644
index 00000000..bc69bcb9
Binary files /dev/null and b/doc/supported_hw/supported_prog/Via_epia_m700_programer.jpg differ
diff --git a/doc/supported_hw/supported_prog/buspirate.rst b/doc/supported_hw/supported_prog/buspirate.rst
new file mode 100644
index 00000000..3d064701
--- /dev/null
+++ b/doc/supported_hw/supported_prog/buspirate.rst
@@ -0,0 +1,78 @@
+==========
+Bus Pirate
+==========
+
+The `Bus Pirate <http://dangerousprototypes.com/docs/Bus_Pirate>`_ is an open source design
+for a multi-purpose chip-level serial protocol transceiver and debugger.
+flashrom supports the Bus Pirate for `SPI programming <http://dangerousprototypes.com/docs/SPI>`_.
+It also has `SPI sniffing <http://dangerousprototypes.com/docs/Bus_Pirate_binary_SPI_sniffer_utility>`_
+functionality, which may come in useful for analysing chip or programmer behaviour.
+
+They are available for around US$30 from various sources.
+
+Connections
+===========
+
+The table below shows how a typical SPI flash chip (sitting in the center of the table)
+needs to be connected (NB: not all flash chips feature all of the pins below, but in general
+you should always connect all input pins of ICs to some defined potential (usually GND or VCC),
+ideally with a pull-up/down resistor in between). Most SPI flash chips require a 3.3V supply voltage,
+but there exist some models that use e.g. 1.8V. Make sure the device in question is compatible
+before connecting any wires.
+
+*NB: Some rather rare SPI flash chips (e.g. Atmel AT45DB series) have a completely different layout, please beware.*
+
++----------------------+------------+------+---------------------------------+------+------------+-----------------------------+
+|  Description	       | Bus Pirate | Dir. | Flash chip			     | Dir. | Bus Pirate | Description		       |
++======================+============+======+===+===========+=============+===+======+============+=============================+
+| (not) Chip Select    | CS	    | →	   | 1 | /CS	   | VCC	 | 8 | ←    | +3.3v	 | Supply		       |
++----------------------+------------+------+---+-----------+-------------+---+------+------------+-----------------------------+
+| Master In, Slave Out | MISO	    | ←	   | 2 | DO (IO1)  | /HOLD (IO3) | 7 | ←    | +3.3v	 | (not) hold (see datasheets) |
++----------------------+------------+------+---+-----------+-------------+---+------+------------+-----------------------------+
+| (not) Write Protect  | +3.3v	    | →    | 3 | /WP (IO2) | CLK	 | 6 | ←    | CLK	 | The SPI clock               |
++----------------------+------------+------+---+-----------+-------------+---+------+------------+-----------------------------+
+| Ground	       | GND	    | →	   | 4 | GND	   | DI (IO0)    | 5 | ←    | MOSI	 | Master Out, Slave In        |
++----------------------+------------+------+---+-----------+-------------+---+------+------------+-----------------------------+
+
+Usage
+=========
+
+::
+
+  $ flashrom -p buspirate_spi:dev=/dev/device,spispeed=frequency
+
+Example::
+
+  $ flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M
+
+Troubleshooting
+===============
+
+In case of problems probing the chip with flashrom - especially when connecting chips
+still soldered in a system - please take a look at the doc :doc:`/user_docs/in_system`. In-system programming is often possible
+**only as long as no other devices on the SPI bus are trying to access the device**.
+
+Speedup
+=========
+
+A beta firmware build exists, to speed up the buspirate.
+`See this post on dangerousprototypes.com <http://dangerousprototypes.com/forum/viewtopic.php?f=40&t=3864&start=15#p41505>`_
+
+See also: http://dangerousprototypes.com/docs/Bus_Pirate#Firmware_upgrades
+
+Images
+==========
+
+Bus Pirate v3, front.
+
+.. image:: Buspirate_v3_front.jpg
+
+Bus Pirate v3, back.
+
+.. image:: Buspirate_v3_back.jpg
+
+Recovering a bricked Lycom PE-115 88SE8123 PCIe to SATA adapter using flashrom and a Bus Pirate - power to the
+PE-115 is supplied by a PC. The test probes of the bus pirate are attached directly to the SOIC Atmel AT26F004 SPI flash chip.
+The other test clip is connected to GND on another device for convenience (easier than getting yet another clip onto a SOIC device).
+
+.. image:: Lycom-pe115-flashrom-buspirate-2.jpg
diff --git a/doc/supported_hw/supported_prog/ft2232_spi.rst b/doc/supported_hw/supported_prog/ft2232_spi.rst
new file mode 100644
index 00000000..8f87117f
--- /dev/null
+++ b/doc/supported_hw/supported_prog/ft2232_spi.rst
@@ -0,0 +1,308 @@
+==========
+FT2232 SPI
+==========
+
+flashrom supports the ``-p ft2232_spi`` (or ``-p ft2232spi`` in very old flashrom revisions) option
+which allows you to use an FTDI FT2232/FT4232H/FT232H based device as external SPI programmer.
+
+This is made possible by using `libftdi <http://www.intra2net.com/en/developer/libftdi/>`_.
+flashrom autodetects the presence of libftdi headers and enables FT2232/FT4232H/FT232H support if they are available.
+
+Currently known FT2232/FT4232H/FT232H based devices which can be used as SPI programmer
+together with flashrom are described below.
+
+DLP Design DLP-USB1232H
+=======================
+
+The `DLP Design DLP-USB1232H <http://www.dlpdesign.com/usb/usb1232h.shtml>`_
+(`datasheet DLP-USB1232H <http://www.dlpdesign.com/usb1232h-ds-v13.pdf>`_) can be used with flashrom
+for programming SPI chips.
+
+Where to buy: `Digikey <https://www.digikey.com/>`_,
+`Mouser <https://www.mouser.de/ProductDetail/?qs=sGAEpiMZZMt/5FJRvmqHBjWi/VTYGDW6>`_,
+`Saelig <https://www.saelig.com/product/UB068.htm>`_
+
+Setup
+-----
+
+DLP-USB1232H based SPI programmer schematics
+
+.. image:: Dlp_usb1232h_spi_programmer.jpg
+
+In order to use the DLP-USB1232H device as SPI programmer you have to setup a small circuit
+(e.g. on a breadboard). See the schematics for details (you can also
+`download the schematics as PDF <http://www.coreboot.org/images/2/26/Dlp_usb1232h_spi_programmer.pdf>`_
+for easier printing).
+
+What you will need
+------------------
+
+=============== ======================= =============   ======  ===============================================
+Quantity	Device			Footprint	Value	Comments
+=============== ======================= =============	======	===============================================
+1		DLP Design DLP-USB1232H —		—	...
+1		Breadboard		—		—	...
+many		Jumper wires		—		—	...
+1		DIP-8 SPI chip		—		—	This is the chip you want to program/read/erase
+1		3.3V voltage regulator	TO-220		3.3V	E.g. **LD33V** or **LD1117xx**
+1		Electrolytic capacitor	single ended	100nF	...
+1		Electrolytic capacitor	single ended	10uF	...
+=============== ======================= =============   ======  ===============================================
+
+Instructions and hints
+----------------------
+
+* You must connect/shorten pins 8 and 9, which configures the device to be powered by USB.
+  Without this connection it will not be powered, and thus not be detected by your OS
+  (e.g. it will not appear in the ``lsusb`` output).
+
+* You need a 3.3V voltage regulator to convert the 5V from USB to 3.3V,
+  so you can power the 3.3V SPI BIOS chip.
+
+  * You can probably use pretty much any 3.3V voltage regulator, e.g. **LD33V** or **LD1117xx**.
+    For usage on a breadboard the TO-220 packaging is probably most useful.
+  * You have to connect two capacitors (e.g. 100nF and 10uF as per datasheets,
+    but using two 10uF capacitors, or even two 47uF capacitors also works in practice) as shown in the schematics,
+    otherwise the voltage regulator will not work correctly and reliably.
+
+* Connect the following pins from the DLP-USB1232H to the SPI BIOS chip:
+
+  * **18 (SK)** to **SCLK**
+  * **16 (DO)** to **SI**
+  * **2 (DI)** to **SO**
+  * **5 (CS)** to **CS#**
+  * The **WP# and HOLD#** pins should be tied to **VCC**! If you leave them unconnected
+    you'll likely experience strange issues.
+  * All **GND** pins should be connected together (**pins 1i and 10** on the DLP-USB1232H,
+    **pin 8** on the SPI chip, **pin 1** on the voltage regulator).
+
+You have to invoke flashrom with the following parameters::
+
+  $ flashrom -p ft2232_spi:type=2232H,port=A
+
+Photos
+------
+
+Module, top
+
+.. image:: Dlp_usb1232h_side.jpg
+
+
+Module, bottom
+
+.. image:: Dlp_usb1232h_bottom.jpg
+
+
+SPI header on a mainboard
+
+.. image:: Via_epia_m700_bios.jpg
+
+
+Module on a breadboard, connected to the mainboard's SPI header
+
+.. image:: Via_epia_m700_programer.jpg
+
+
+Breadboard setup
+
+.. image:: Ft2232spi_programer.jpg
+
+
+Another breadboard setup
+
+.. image:: Dlp_usb1232h_spi_programmer_breadboard_1.jpg
+
+
+Module and parts
+
+.. image:: Dlp_usb1232h_spi_programmer_breadboard_2.jpg
+
+FTDI FT2232H Mini-Module
+========================
+
+The `FTDI FT2232H Mini-Module Evaluation Kit <http://www.ftdichip.com/Products/Modules/DevelopmentModules.htm#FT2232H%20Mini%20Module>`_
+(`the datasheet <http://www.ftdichip.com/Support/Documents/DataSheets/Modules/DS_FT2232H_Mini_Module.pdf>`_)
+can be used with flashrom for programming SPI chips.
+
+Pinout
+------
+
+=============== ======= ======= =============== ===========================
+Module Pin	FTDI	MPSSE	SPI		SPI Flash (vendor specific)
+=============== ======= ======= =============== ===========================
+CN2-7		AD0	TCK/SK	(S)CLK		(S)CLK
+CN2-10		AD1	TDI/DO	MOSI		SI / DI
+CN2-9		AD2	TDO/DI	MISO		SO / DO
+CN2-12		AD3	TMS/CS	/CS / /SS	/CS
+CN3-26		BD0	TCK/SK	(S)CLK		(S)CLK
+CN3-25		BD1	TDI/DO	MOSI		SI / DI
+CN3-24		BD2	TDO/DI	MISO		SO / DO
+CN3-23		BD3	TMS/CS	/CS / /SS	/CS
+=============== ======= ======= =============== ===========================
+
+FTDI FT4232H Mini-Module
+========================
+
+The `FTDI FT4232H Mini-Module Evaluation Kit <http://www.ftdichip.com/Products/Modules/DevelopmentModules.htm#FT4232H%20Mini%20Module>`_
+(`datasheet <http://www.ftdichip.com/Support/Documents/DataSheets/Modules/DS_FT4232H_Mini_Module.pdf>`_)
+can be used with flashrom for programming SPI chips.
+
+Olimex ARM-USB-TINY/-H and ARM-USB-OCD/-H
+=========================================
+
+The `Olimex <http://www.olimex.com/dev/index.html>`_ `ARM-USB-TINY <http://www.olimex.com/dev/arm-usb-tiny.html>`_
+(VID:PID 15BA:0004) and `ARM-USB-OCD <http://www.olimex.com/dev/arm-usb-ocd.html>`_ (15BA:0003)
+can be used with flashrom for programming SPI chips.
+The `ARM-USB-TINY-H <http://www.olimex.com/dev/arm-usb-tiny-h.html>`_ (15BA:002A)
+and `ARM-USB-OCD-H <http://www.olimex.com/dev/arm-usb-ocd-h.html>`_ (15BA:002B) should also work,
+though the tested status is unconfirmed.
+
+The following setup can then be used to flash a BIOS chip through SPI.
+
+Pinout:
+
+ .. image:: ARM-USB-TINY_pinout.png
+
+=============== =========================
+Pin (JTAG Name)	SPI/Voltage Source
+=============== =========================
+1 (VREF)	VCC (from Voltage Source)
+2 (VTARGET)	VCC (to SPI target)
+4 (GND)		GND (from Voltage Source)
+5 (TDI)		SI
+6 (GND)		GND (to SPI target)
+7 (TMS)		CE#
+9 (TCK)		SCK
+13 (TDO)	SO
+=============== =========================
+
+On the ARM-USB-TINY, VREF, and VTARGET are internally connected, and all the GND lines
+(even numbered pins, from 4 to 20) share the same line as well, so they can be used
+to split VCC/GND between the voltage source and the target.
+
+The voltage source should provide 3.0V to 3.3V DC but doesn't have to come from USB:
+it can be as simple as two AA or AAA batteries placed in serial (2 x 1.5V).
+
+Invoking flashrom
+-----------------
+
+You first need to add the ``-p ft2232_spi`` option, and then specify one of ``arm-usb-tiny``,
+``arm-usb-tiny-h``, ``arm-usb-ocd`` or ``arm-usb-ocd-f`` for the type.
+For instance, to use an ARM-USB-TINY, you would use::
+
+  $ flashrom -p ft2232_spi:type=arm-usb-tiny
+
+Openmoko
+========
+
+The openmoko debug board (which can also do serial+jtag for the openmoko phones, or for other phones)
+has `its shematics available here <http://people.openmoko.org/joerg/schematics/debug_board/OpenMoKo_Debug_Board_V3_MP.pdf>`_.
+
+Informations
+------------
+
+The openmoko debug board can act as an SPI programmer bitbanging the FTDI
+(no need of an openmoko phone), you just need:
+
+* a breadboard
+* some wires
+* The openmoko debug board(v2 and after,but only tested with v3)
+
+The voltage is provided by the board itself. The connector to use is the JTAG one
+(very similar to what's documented in the previous section(Olimex ARM-USB-TINY/-H and ARM-USB-OCD/-H )
+
+Building
+--------
+
+**WARNING: This was tested with 3.3v chips only.**
+
+Here's the pinout of the JTAG connector of the openmoko debug board
+(copied from ARM-USB-tiny because it's the same pinout):
+
+ .. image:: ARM-USB-TINY_pinout.png
+
+=============== =============================== ========================
+Pin (JTAG Name)	SPI/Voltage Source		BIOS Chip connector name
+=============== =============================== ========================
+1 (VREF)	VCC (from Voltage Source)	VCC (3.3v only)
+2 (VTARGET)	VCC (to SPI target)		Not connected
+4 (GND)		GND (from Voltage Source)	Ground
+5 (TDI)		SI				DIO (Data Input)
+6 (GND)		GND (to SPI target)		Not connected
+7 (TMS)		CE#				CS (Chip select)
+9 (TCK)		SCK				CLK (Clock)
+13 (TDO)	SO				DO (Data output)
+=============== =============================== ========================
+
+* Also connect the BIOS chip's write protect(WP) to VCC
+
+* Also connect the BIOS chips's HOLD to VCC
+
+Pictures
+--------
+
+.. image:: Openmoko_0001.jpeg
+
+.. image:: Openmoko_0002.jpeg
+
+.. image:: Openmoko_0003.jpeg
+
+Performances
+------------
+
+::
+
+  $ time ./flashrom/flashrom -p ft2232_spi:type=openmoko -r coreboot.rom
+  flashrom v0.9.5.2-r1545 on Linux 3.0.0-20-generic (x86_64)
+  flashrom is free software, get the source code at http://www.flashrom.org
+
+  Calibrating delay loop... OK.
+  Found Winbond flash chip "W25X80" (1024 kB, SPI) on ft2232_spi.
+  Reading flash... done.
+
+  real	0m19.459s
+  user	0m1.244s
+  sys	0m0.000s
+
+::
+
+  $ time ./flashrom/flashrom -p ft2232_spi:type=openmoko -w coreboot.rom
+  flashrom v0.9.5.2-r1545 on Linux 3.0.0-20-generic (x86_64)
+  flashrom is free software, get the source code at http://www.flashrom.org
+
+  Calibrating delay loop... OK.
+  Found Winbond flash chip "W25X80" (1024 kB, SPI) on ft2232_spi.
+  Reading old flash chip contents... done.
+  Erasing and writing flash chip... Erase/write done.
+  Verifying flash... VERIFIED.
+
+  real	1m1.366s
+  user	0m7.692s
+  sys	0m0.044s
+
+Advantages/disadvantages
+------------------------
+
+* fast(see above)
+
+* easily available (many people in the free software world have openmoko debug board
+  and they don't know what to do with them), can still be bought
+
+* stable
+
+* SPI only
+
+Generic Pinout
+==============
+
+There are many more simple modules that feature the FT*232H.
+Actual pinouts depend on each module, the FTDI names map to SPI as follows:
+
+=============== ======= =============== ===========================
+Pin Name	MPSSE	SPI		SPI Flash (vendor specific)
+=============== ======= =============== ===========================
+DBUS0		TCK/SK	(S)CLK		(S)CLK
+DBUS1		TDI/DO	MOSI		SI / DI
+DBUS2		TDO/DI	MISO		SO / DO
+DBUS3		TMS/CS	/CS / /SS	/CS
+=============== ======= =============== ===========================
diff --git a/doc/supported_hw/supported_prog/index.rst b/doc/supported_hw/supported_prog/index.rst
index 130ac201..7912f348 100644
--- a/doc/supported_hw/supported_prog/index.rst
+++ b/doc/supported_hw/supported_prog/index.rst
@@ -15,5 +15,7 @@ Patches to add/update documentation, or migrate docs from `old wiki website <htt
 .. toctree::
     :maxdepth: 1
 
+    buspirate
     dummyflasher
+    ft2232_spi
     serprog/index
diff --git a/doc/user_docs/1200px-DIP_socket_as_SOIC_clip.jpg b/doc/user_docs/1200px-DIP_socket_as_SOIC_clip.jpg
new file mode 100644
index 00000000..c3db6923
Binary files /dev/null and b/doc/user_docs/1200px-DIP_socket_as_SOIC_clip.jpg differ
diff --git a/doc/user_docs/Amd_am29f010_tsop32.jpg b/doc/user_docs/Amd_am29f010_tsop32.jpg
new file mode 100644
index 00000000..faf0982d
Binary files /dev/null and b/doc/user_docs/Amd_am29f010_tsop32.jpg differ
diff --git a/doc/user_docs/Bios_savior.jpg b/doc/user_docs/Bios_savior.jpg
new file mode 100644
index 00000000..91d5557b
Binary files /dev/null and b/doc/user_docs/Bios_savior.jpg differ
diff --git a/doc/user_docs/Dip32_chip.jpg b/doc/user_docs/Dip32_chip.jpg
new file mode 100644
index 00000000..5eede283
Binary files /dev/null and b/doc/user_docs/Dip32_chip.jpg differ
diff --git a/doc/user_docs/Dip32_chip_back.jpg b/doc/user_docs/Dip32_chip_back.jpg
new file mode 100644
index 00000000..f564505e
Binary files /dev/null and b/doc/user_docs/Dip32_chip_back.jpg differ
diff --git a/doc/user_docs/Dip32_in_socket.jpg b/doc/user_docs/Dip32_in_socket.jpg
new file mode 100644
index 00000000..38467a32
Binary files /dev/null and b/doc/user_docs/Dip32_in_socket.jpg differ
diff --git a/doc/user_docs/Dip8_chip.jpg b/doc/user_docs/Dip8_chip.jpg
new file mode 100644
index 00000000..b1afb419
Binary files /dev/null and b/doc/user_docs/Dip8_chip.jpg differ
diff --git a/doc/user_docs/Dip8_chip_back.jpg b/doc/user_docs/Dip8_chip_back.jpg
new file mode 100644
index 00000000..768e17a9
Binary files /dev/null and b/doc/user_docs/Dip8_chip_back.jpg differ
diff --git a/doc/user_docs/Dip8_in_socket.jpg b/doc/user_docs/Dip8_in_socket.jpg
new file mode 100644
index 00000000..0450cbcd
Binary files /dev/null and b/doc/user_docs/Dip8_in_socket.jpg differ
diff --git a/doc/user_docs/Dip_tool.jpg b/doc/user_docs/Dip_tool.jpg
new file mode 100644
index 00000000..60633339
Binary files /dev/null and b/doc/user_docs/Dip_tool.jpg differ
diff --git a/doc/user_docs/Dual_plcc32_soldered.jpg b/doc/user_docs/Dual_plcc32_soldered.jpg
new file mode 100644
index 00000000..7d742511
Binary files /dev/null and b/doc/user_docs/Dual_plcc32_soldered.jpg differ
diff --git a/doc/user_docs/Empty_dip32_socket.jpg b/doc/user_docs/Empty_dip32_socket.jpg
new file mode 100644
index 00000000..0c44c3aa
Binary files /dev/null and b/doc/user_docs/Empty_dip32_socket.jpg differ
diff --git a/doc/user_docs/Empty_dip8_socket.jpg b/doc/user_docs/Empty_dip8_socket.jpg
new file mode 100644
index 00000000..22e843bb
Binary files /dev/null and b/doc/user_docs/Empty_dip8_socket.jpg differ
diff --git a/doc/user_docs/Empty_plcc32_socket.jpg b/doc/user_docs/Empty_plcc32_socket.jpg
new file mode 100644
index 00000000..acd20b1d
Binary files /dev/null and b/doc/user_docs/Empty_plcc32_socket.jpg differ
diff --git a/doc/user_docs/Flash-BGA.jpg b/doc/user_docs/Flash-BGA.jpg
new file mode 100644
index 00000000..2eb059bc
Binary files /dev/null and b/doc/user_docs/Flash-BGA.jpg differ
diff --git a/doc/user_docs/Plcc32_chip.jpg b/doc/user_docs/Plcc32_chip.jpg
new file mode 100644
index 00000000..3a0193a5
Binary files /dev/null and b/doc/user_docs/Plcc32_chip.jpg differ
diff --git a/doc/user_docs/Plcc32_chip_back.jpg b/doc/user_docs/Plcc32_chip_back.jpg
new file mode 100644
index 00000000..f0169009
Binary files /dev/null and b/doc/user_docs/Plcc32_chip_back.jpg differ
diff --git a/doc/user_docs/Plcc32_in_socket.jpg b/doc/user_docs/Plcc32_in_socket.jpg
new file mode 100644
index 00000000..241794cc
Binary files /dev/null and b/doc/user_docs/Plcc32_in_socket.jpg differ
diff --git a/doc/user_docs/Plcc_tool.jpg b/doc/user_docs/Plcc_tool.jpg
new file mode 100644
index 00000000..3d3b8015
Binary files /dev/null and b/doc/user_docs/Plcc_tool.jpg differ
diff --git a/doc/user_docs/Pomona_5250_soic8.jpg b/doc/user_docs/Pomona_5250_soic8.jpg
new file mode 100644
index 00000000..83f8c3e2
Binary files /dev/null and b/doc/user_docs/Pomona_5250_soic8.jpg differ
diff --git a/doc/user_docs/Pushpin_roms_2.jpg b/doc/user_docs/Pushpin_roms_2.jpg
new file mode 100644
index 00000000..c4ce5aef
Binary files /dev/null and b/doc/user_docs/Pushpin_roms_2.jpg differ
diff --git a/doc/user_docs/Soic8_chip.jpg b/doc/user_docs/Soic8_chip.jpg
new file mode 100644
index 00000000..d103c7d2
Binary files /dev/null and b/doc/user_docs/Soic8_chip.jpg differ
diff --git a/doc/user_docs/Soic8_socket_back.jpg b/doc/user_docs/Soic8_socket_back.jpg
new file mode 100644
index 00000000..49504e2c
Binary files /dev/null and b/doc/user_docs/Soic8_socket_back.jpg differ
diff --git a/doc/user_docs/Soic8_socket_front_closed.jpg b/doc/user_docs/Soic8_socket_front_closed.jpg
new file mode 100644
index 00000000..f6aebd5b
Binary files /dev/null and b/doc/user_docs/Soic8_socket_front_closed.jpg differ
diff --git a/doc/user_docs/Soic8_socket_half_opened.jpg b/doc/user_docs/Soic8_socket_half_opened.jpg
new file mode 100644
index 00000000..f4d5730d
Binary files /dev/null and b/doc/user_docs/Soic8_socket_half_opened.jpg differ
diff --git a/doc/user_docs/Soic8_socket_open.jpg b/doc/user_docs/Soic8_socket_open.jpg
new file mode 100644
index 00000000..69b4e744
Binary files /dev/null and b/doc/user_docs/Soic8_socket_open.jpg differ
diff --git a/doc/user_docs/Soic8_socket_with_chip.jpg b/doc/user_docs/Soic8_socket_with_chip.jpg
new file mode 100644
index 00000000..322f6383
Binary files /dev/null and b/doc/user_docs/Soic8_socket_with_chip.jpg differ
diff --git a/doc/user_docs/Soic8_socket_with_chip_inserted.jpg b/doc/user_docs/Soic8_socket_with_chip_inserted.jpg
new file mode 100644
index 00000000..37af90d7
Binary files /dev/null and b/doc/user_docs/Soic8_socket_with_chip_inserted.jpg differ
diff --git a/doc/user_docs/Soldered_plcc32.jpg b/doc/user_docs/Soldered_plcc32.jpg
new file mode 100644
index 00000000..8a3a6cdc
Binary files /dev/null and b/doc/user_docs/Soldered_plcc32.jpg differ
diff --git a/doc/user_docs/Soldered_tsop40.jpg b/doc/user_docs/Soldered_tsop40.jpg
new file mode 100644
index 00000000..1fcf2efb
Binary files /dev/null and b/doc/user_docs/Soldered_tsop40.jpg differ
diff --git a/doc/user_docs/Soldered_tsop48.jpg b/doc/user_docs/Soldered_tsop48.jpg
new file mode 100644
index 00000000..3df63eef
Binary files /dev/null and b/doc/user_docs/Soldered_tsop48.jpg differ
diff --git a/doc/user_docs/Spi-socket-dscn2913-1024x768.jpg b/doc/user_docs/Spi-socket-dscn2913-1024x768.jpg
new file mode 100644
index 00000000..3b20ae09
Binary files /dev/null and b/doc/user_docs/Spi-socket-dscn2913-1024x768.jpg differ
diff --git a/doc/user_docs/Sst_39vf040_tsop32.jpg b/doc/user_docs/Sst_39vf040_tsop32.jpg
new file mode 100644
index 00000000..beefeba9
Binary files /dev/null and b/doc/user_docs/Sst_39vf040_tsop32.jpg differ
diff --git a/doc/user_docs/Top_hat_flash.jpeg b/doc/user_docs/Top_hat_flash.jpeg
new file mode 100644
index 00000000..8edd27e8
Binary files /dev/null and b/doc/user_docs/Top_hat_flash.jpeg differ
diff --git a/doc/user_docs/example_partial_wp.rst b/doc/user_docs/example_partial_wp.rst
index 67a382a7..811c772f 100644
--- a/doc/user_docs/example_partial_wp.rst
+++ b/doc/user_docs/example_partial_wp.rst
@@ -14,8 +14,8 @@ Version of flashrom
 
 Write-protect manipulation functionality is included in flashrom since release v1.3.0.
 If for any reasons you need the latest code from head, you might need to build :code:`flashrom`
-from scratch. The following docs describe how to do this :doc:`/dev_guide/building_from_source` and
-:doc:`/dev_guide/building_with_make`. See also :doc:`/dev_guide/development_guide`.
+from scratch. The following doc describe how to do this: :doc:`/dev_guide/building_from_source`.
+See also :doc:`/dev_guide/development_guide`.
 
 Alternatively, your operating system might provide development version of :code:`flashrom` as a package.
 
diff --git a/doc/user_docs/in_system.rst b/doc/user_docs/in_system.rst
new file mode 100644
index 00000000..84716d38
--- /dev/null
+++ b/doc/user_docs/in_system.rst
@@ -0,0 +1,45 @@
+=====================
+In-System Programming
+=====================
+
+**In-System Programming** (ISP) sometimes also called **in situ programming** is used to describe
+the procedure of writing a flash chip while it is (already/still) attached to the circuit
+it is to be used with. Of course any normal "BIOS flash" procedure is a kind of ISP
+but when we refer to ISP we usually mean something different: programming a flash chip by external means
+while it is mounted on a motherboard.
+
+This is usually done with SPI chips only. Some mainboards have a special header for this
+(often named "ISP", "ISP1", or "SPI") and there should be no problem with accessing the chip
+then as long as the wires are not too long.
+
+If there is no special header then using a special SO(IC) clip is an easy and reliable way
+to attach an external programmer. They are produced by different vendors (e.g. Pomona, 3M)
+and are available from many distributors (e.g. Distrelec) for 20-50$/€.
+
+Problems
+========
+
+* Check the other potential problems (:doc:`misc_notes`) with other types of programming setups first.
+* The SPI bus is not isolated enough. Often parts of the chipset are powered on partially
+  (by the voltage supplied via the Vcc pin of the flash chip). In that case
+  disconnect Vcc from the programmer and power it with its normal PSU and:
+
+  * Try powering up the board normally and holding it in reset (e.g. use a jumper instead of the reset push button).
+  * Some chipsets (e.g. Intel ICHs/PCHs) have edge triggered resets. In this case holding them in reset will not work.
+    This is especially a problem with Intel chipsets because they contain an EC (named ME by Intel, see :doc:`management_engine`),
+    which uses the flash (r/w!). In this case you can trigger the reset line in short intervals.
+    For example by connecting it to the chip select (CS) line of the SPI bus or a dedicated clock signal from the programmer.
+    This should not be too fast though! Reset lines usually require pulses with a minimum duration.
+  * On some boards, you can try disconnecting the ATX12V header (yellow/black wires only) from the motherboard,
+    or even remove the CPU or RAM - if the programmer supports SPI sniffing, you may be able to verify that the there is no SPI traffic.
+
+Images
+========
+
+Pomona 8-pin SOIC clip with attached jumper wires.
+
+.. image:: Pomona_5250_soic8.jpg
+
+A cheap, but very fragile alternative: DIP socket as clip
+
+.. image:: 1200px-DIP_socket_as_SOIC_clip.jpg
diff --git a/doc/user_docs/index.rst b/doc/user_docs/index.rst
index b61567ab..e03789eb 100644
--- a/doc/user_docs/index.rst
+++ b/doc/user_docs/index.rst
@@ -4,8 +4,14 @@ Users documentation
 .. toctree::
     :maxdepth: 1
 
+    overview
     fw_updates_vs_spi_wp
     example_partial_wp
     chromebooks
     management_engine
     misc_intel
+    in_system
+    msi_jspi1
+    misc_notes
+
+.. Keep misc notes last
diff --git a/doc/user_docs/misc_notes.rst b/doc/user_docs/misc_notes.rst
new file mode 100644
index 00000000..fcb17006
--- /dev/null
+++ b/doc/user_docs/misc_notes.rst
@@ -0,0 +1,149 @@
+=====================
+Misc notes and advice
+=====================
+
+This document contains miscellaneous and unstructured (and mostly, legacy) notes and advice about using flashrom.
+
+Command set tricks for parallel and LPC chips
+=============================================
+
+This is only mentioned in very few datasheets, but it applies to some parallel (and some LPC) chips.
+
+Upper address bits of commands are ignored if they are not mentioned explicitly. If a datasheet specifies the following sequence::
+
+   chip_writeb(0xAA, bios + 0x555);
+   chip_writeb(0x55, bios + 0x2AA);
+   chip_writeb(0x90, bios + 0x555);
+
+then it is quite likely the following sequence will work as well::
+
+   chip_writeb(0xAA, bios + 0x5555);
+   chip_writeb(0x55, bios + 0x2AAA);
+   chip_writeb(0x90, bios + 0x5555);
+
+However, if the chip datasheet specifies addresses like ``0x5555``, you can't shorten them to ``0x555``.
+
+To summarize, replacing short addresses with long addresses usually works, but the other way round usually fails.
+
+flashrom doesn't work on my board, what can I do?
+=================================================
+
+* First of all, check if your chipset, ROM chip, and mainboard are supported
+  (see :doc:`/supported_hw/index`).
+* If your board has a jumper for BIOS flash protection (check the manual), disable it.
+* Should your BIOS menu have a BIOS flash protection option, disable it.
+* If you run flashrom on Linux and see messages about ``/dev/mem``, see next section.
+* If you run flashrom on OpenBSD, you might need to obtain raw access permission by setting
+  ``securelevel = -1`` in ``/etc/rc.securelevel`` and rebooting, or rebooting into single user mode.
+
+What can I do about /dev/mem errors?
+====================================
+
+* If flashrom tells you ``/dev/mem mmap failed: Operation not permitted``:
+
+  * Most common at the time of writing is a Linux kernel option, ``CONFIG_IO_STRICT_DEVMEM``,
+    that prevents even the root user from accessing hardware from user-space if the resource is unknown
+    to the kernel or a conflicting kernel driver reserved it. On Intel systems, this is most often ``lpc_ich``,
+    so ``modprobe -r lpc_ich`` can help. A more invasive solution is to try again after rebooting
+    with ``iomem=relaxed`` in the kernel command line.
+
+  * Some systems with incorrect memory reservations (e.g. E820 map) may have the same problem
+    even with ``CONFIG_STRICT_DEVMEM``. In that case ``iomem=relaxed`` in the kernel command line may help too.
+
+* If it tells you ``/dev/mem mmap failed: Resource temporarily unavailable``:
+
+  * This may be an issue with PAT (e.g. if the memory flashrom tries to map is already mapped
+    in an incompatible mode). Try again after rebooting with nopat in the kernel command line.
+
+* If you see this message ``Can't mmap memory using /dev/mem: Invalid argument``:
+
+  * Your flashrom is very old, better update it. If the issue persists, try the kernel options mentioned above.
+
+* Generally, if your version of flashrom is very old, an update might help.
+  Flashrom has less strict requirements now and works on more systems without having to change the kernel.
+
+Connections
+===========
+
+Using In-System programming requires some means to connect the external programmer to the flash chip.
+
+Note that some external flashers (like the Openmoko debug board) lack a connector,
+so they do requires some soldering to be used. Some other don't. For instance the buspirate has a pin connector on it.
+
+Programmer <-> Removable chip connection
+----------------------------------------
+
+A breadboard can be used to connect Dual in-line 8 pins chips to the programmer, as they they fit well into it.
+
+Programmer <-> Clip connection
+------------------------------
+
+If your programmer has a pin connector, and that you want to avoid soldering, you can use
+**Short** `Jump Wires <https://en.wikipedia.org/wiki/Jump_wire>`_ to connect it to a clip.
+They usually can be found on some electronic shops.
+
+Other issues
+-------------
+
+* Wires length and connection quality: Long wires, and bad connection can create some issues, so avoid them.
+
+  * The maximum wires length is very dependent on your setup, so try to have the shortest wires possible.
+  * If you can't avoid long wires and if you're flash chip is SPI, then lowering the SPI clock could make
+    it work in some cases. Many programmers do support such option (Called spispeed with most of them, or divisor with ft2232_spi).
+
+* When soldering wires, the wire tend to break near the soldering point. To avoid such issue,
+  you have to prevent the wires from bending near the soldering point.
+  To do that `Heat-shrink_tubing <https://en.wikipedia.org/wiki/Heat-shrink_tubing>`_ or similar methods can be used.
+
+Common problems
+===============
+
+The following describes problems commonly found when trying to access flash chips in systems
+that are not designed properly for this job, e.g. ad-hoc setups to flash in-system
+(TODO add a doc for in-system-specific problems).
+
+Symptoms indicating you may have at least one of these are for example inconsistent reads or probing results.
+This happens basically because the analog electrical waveforms representing the digital information
+get too distorted to by interpreted correctly all the time. Depending on the cause different steps can be tried.
+
+* Not all input pins are connected to the correct voltage level/output pin of the programmer.
+  Always connect all input pins of ICs!
+
+* The easiest thing to try is lowering the (SPI) clock frequency if your programmer supports it.
+  That way the waveforms have more time to settle before being sampled by the receiver which might be enough.
+  Depending on the design of the driver and receiver as well as the actual communication path
+  this might not change anything as well.
+
+* Wires are too long. Shortening them to a few cm (i.e. < 20, the lesser the better) might help.
+
+* The impedances of the wires/traces do not match the impedances of the input pins
+  (of either the circuit/chip on the mainboard or the external programmer).
+  Try using shorter wires, adding small (<100 Ohm) series resistors or parallel capacitors (<20pF)
+  as near as possible to the input pins (this includes also the MISO line which ends near the programmer)\
+  and/or ask someone who has experience with high frequency electronics.
+
+* The supply voltage of the flash chip is not stable enough. Try adding a 0.1 µF - 1 µF (ceramic) capacitor
+  between the flash chip's VCC and GND pins as near as possible to the chip.
+
+Live CD
+=========
+
+A Live CD containing flashrom provides a user with a stable work environment to read, write and verify a flash device on any supported hardware.
+
+It can help avoid Linux installation issues, which can be a hassle for some users.
+
+flashrom is already shipped in some of the Live CDs, see below. *Please note, some of these ship very old versions of flashrom*.
+
+* `SystemRescueCd <http://www.sysresccd.org/>`_ has been including flashrom since about version 2.5.1.
+
+* `grml <http://grml.org/>`_
+
+  * Note: You need the full grml ISO, "small" (and "medium") ISOs do not contain flashrom.
+  * Note: Some releases (e.g. 2011.12) did not contain flashrom.
+
+* `Parted Magic <http://partedmagic.com/>`_
+
+* `Hiren's BootCD <http://www.hirensbootcd.org/>`_
+
+   * When you select "Linux based rescue environment (Parted Magic 6.7)" and then "Live with default settings",
+     you have access to a system which has flashrom.
diff --git a/doc/user_docs/msi_jspi1.rst b/doc/user_docs/msi_jspi1.rst
new file mode 100644
index 00000000..dc20866f
--- /dev/null
+++ b/doc/user_docs/msi_jspi1.rst
@@ -0,0 +1,50 @@
+=========
+MSI JSPI1
+=========
+
+JSPI1 is a 5x2 or 6x2 2.0mm pitch pin header on many MSI motherboards.
+It is used to recover from bad boot ROM images. Specifically,
+it appears to be used to connect an alternate ROM with a working image.
+Pull the #HOLD line low to deselect the onboard SPI ROM, allowing another
+SPI ROM to take its place on the bus. Pull the #WP line high to disable write-protection.
+Some boards use 1.8V flash chips, while others use 3.3V flash chips;
+Check the flash chip datasheet to determine the correct value.
+
+**JSPI1 (5x2)**
+
+======== ======== ======== ====
+name     pin      pin      name
+======== ======== ======== ====
+VCC      1        2 	   VCC
+MISO     3        4	   MOSI
+#SS      5        6	   SCLK
+GND      7        8	   GND
+#HOLD    9        10 	   NC
+======== ======== ======== ====
+
+**JSPI1 (6x2)**
+
+======== ======== ======== ============
+name     pin      pin      name
+======== ======== ======== ============
+VCC      1	  2	   VCC
+SO       3        4	   SI
+#SS      5	  6	   CLK
+GND      7        8	   GND
+NC       9        10	   NC (no pin)
+#WP      11       12	   #HOLD
+======== ======== ======== ============
+
+======== =====================================
+name	 function
+======== =====================================
+VCC	 Voltage (See flash chip datasheet)
+MISO	 SPI Master In/Slave Out
+MOSI	 SPI Master Out/Slave In
+#SS	 SPI Slave (Chip) Select (active low)
+SCLK	 SPI Clock
+GND	 ground/common
+#HOLD	 SPI hold (active low)
+#WP	 SPI write-protect (active low)
+NC	 Not Connected (or no pin)
+======== =====================================
diff --git a/doc/user_docs/overview.rst b/doc/user_docs/overview.rst
new file mode 100644
index 00000000..9825f22e
--- /dev/null
+++ b/doc/user_docs/overview.rst
@@ -0,0 +1,301 @@
+==========
+Overview
+==========
+
+Modern mainboards store the BIOS in a reprogrammable flash chip.
+There are hundreds of different flash (`EEPROM <https://en.wikipedia.org/wiki/EEPROM>`_) chips,
+with variables such as memory size, speed, communication bus (Parallel, LPC, FWH, SPI) and packaging to name just a few.
+
+Packaging/housing/form factor
+=============================
+
+DIP32: Dual In-line Package, 32 pins
+------------------------------------
+
+DIP32 top
+
+.. image:: Dip32_chip.jpg
+   :alt: DIP32 top
+
+DIP32 bottom
+
+.. image:: Dip32_chip_back.jpg
+   :alt: DIP32 bottom
+
+DIP32 in a socket
+
+.. image:: Dip32_in_socket.jpg
+   :alt: DIP32 in a socket
+
+DIP32 socket
+
+.. image:: Empty_dip32_socket.jpg
+   :alt: DIP32 socket
+
+DIP32 extractor tool
+
+.. image:: Dip_tool.jpg
+   :alt: DIP32 extractor tool
+
+A rectangular black plastic block with 16 pins along each of the two longer sides of the package
+(32 pins in total). DIP32 chips can be socketed which means they are detachable from the mainboard
+using physical force. If they haven't been moved in and out of the socket very much,
+they can appear to be quite difficult to release from the socket. One way to remove a DIP32 chip
+from a socket is by prying a **thin screwdriver** in between the plastic package and the socket,
+along the shorter sides where there are no pins, and then gently bending the screwdriver to push
+the chip upwards, away from the mainboard. Alternate between the two sides to avoid bending the pins,
+and don't touch any of the pins with the screwdriver (search about ESD, electro-static discharge).
+If the chip is **soldered directly to the mainboard**, it has to be desoldered in order to be
+reprogrammed outside the mainboard. If you do this, it's a good idea to
+`solder a socket to the mainboard <http://www.coreboot.org/Soldering_a_socket_on_your_board>`_ instead,
+to ease any future experiments.
+
+PLCC32: Plastic Leaded Chip Carrier, 32 pins
+--------------------------------------------
+
+PLCC32 top
+
+ .. image:: Plcc32_chip.jpg
+    :alt: PLCC32 top
+
+PLCC32 botto
+
+ .. image:: Plcc32_chip_back.jpg
+    :alt: PLCC32 bottom
+
+PLCC32 socket
+
+ .. image:: Plcc32_in_socket.jpg
+    :alt: PLCC32 socket
+
+PLCC32 in a socket
+
+ .. image:: Empty_plcc32_socket.jpg
+    :alt: PLCC32 in a socket
+
+Soldered PLCC3
+
+ .. image:: Soldered_plcc32.jpg
+    :alt: Soldered PLCC32
+
+Two soldered PLCC32
+
+ .. image:: Dual_plcc32_soldered.jpg
+    :alt: Two soldered PLCC32
+
+PLCC32 Bios Savior
+
+ .. image:: Bios_savior.jpg
+    :alt: PLCC32 Bios Savior
+
+PLCC32 Top-Hat-Flash adapte
+
+ .. image:: Top_hat_flash.jpeg
+    :alt: PLCC32 Top-Hat-Flash adapter
+
+PLCC32 pushpin trick
+
+ .. image:: Pushpin_roms_2.jpg
+    :alt: PLCC32 pushpin trick
+
+PLCC extractor tool
+
+ .. image:: Plcc_tool.jpg
+    :alt: PLCC extractor tool
+
+Black plastic block again, but this one is much more square.
+PLCC32 was becoming the standard for mainboards after DIP32 chips because of its smaller physical size.
+PLCC can also be **socketed** or **soldered directly to the mainboard**.
+Socketed PLCC32 chips can be removed using a special PLCC removal tool,
+or using a piece of nylon line tied in a loop around the chip and pulled swiftly straight up,
+or bending/prying using small screwdrivers if one is careful. PLCC32 sockets are often fragile
+so the screwdriver approach is not recommended. While the nylon line method sounds strange it works well.
+Desoldering PLCC32 chips and soldering on a socket can be done using either a desoldering station
+or even just a heat gun. You can also cut the chip with a sharp knife, **but it will be destroyed in the process, of course**.
+
+DIP8: Dual In-line Package, 8 pins
+----------------------------------
+
+DIP8 top
+
+ .. image:: Dip8_chip.jpg
+    :alt: DIP8 top
+
+DIP8 bottom
+
+ .. image:: Dip8_chip_back.jpg
+    :alt: DIP8 bottom
+
+DIP8 in a socket
+
+ .. image:: Dip8_in_socket.jpg
+    :alt: DIP8 in a socket
+
+DIP8 socket
+
+ .. image:: Empty_dip8_socket.jpg
+    :alt: DIP8 socket
+
+Most recent boards use DIP8 chips (which always employ the SPI protocol) or SO8/SOIC8 chips (see below).
+DIP8 chips are always **socketed**, and can thus be easily removed (and hot-swapped),
+for example using a small screwdriver. This allows for relatively simple recovery in case of an incorrectly flashed chip.
+
+SO8/SOIC8: Small-Outline Integrated Circuit, 8 pins
+---------------------------------------------------
+
+Soldered SOIC8
+
+ .. image:: Soic8_chip.jpg
+    :alt: Soldered SOIC8
+
+SOIC8 socket, front, closed
+
+ .. image:: Soic8_socket_front_closed.jpg
+    :alt: SOIC8 socket, front, closed
+
+SOIC8 socket, half open
+
+ .. image:: Soic8_socket_half_opened.jpg
+    :alt: SOIC8 socket, half open
+
+SOIC8 socket, open
+
+ .. image:: Soic8_socket_open.jpg
+    :alt: SOIC8 socket, open
+
+SOIC8 socket, back
+
+ .. image:: Soic8_socket_back.jpg
+    :alt: SOIC8 socket, back
+
+SOIC8 socket, chip nearby
+
+ .. image:: Soic8_socket_with_chip.jpg
+    :alt: SOIC8 socket, chip nearby
+
+SOIC8 socket, chip inserted
+
+ .. image:: Soic8_socket_with_chip_inserted.jpg
+    :alt: SOIC8 socket, chip inserted
+
+Another type of SOIC8 adapter
+
+ .. image:: Spi-socket-dscn2913-1024x768.jpg
+    :alt: Another type of SOIC8 adapter
+
+Similarly to the DIP8 chips, these always use the SPI protocol.
+However, SO8/SOIC8 chips are most often soldered onto the board directly without a socket.
+In that case a few boards have a header to allow :doc:`in_system`. You can also desolder
+a soldered SO8 chip and solder an SO8 socket/adapter in its place, or build
+a `SOIC-to-DIP adapter <http://blogs.coreboot.org/blog/2013/07/16/gsoc-2013-flashrom-week-4/>`_.
+Some of the cheapest SOIC ZIF sockets are made by `Wieson <https://www.wieson.com/go/en/wieson/index.php?lang=en>`_.
+They have 3 models available - G6179-10(0000), G6179-20(0000) and a 16 pin version named G6179-07(0000).
+They are available for example from `siliconkit <https://siliconkit.com/oc3/>`_,
+`Dediprog <https://www.dediprog.com/>`_, as well as `alibaba <http://alibaba.com/>`_.
+For the usual "BIOS" flash chips you want the G6179-10 model (look also for G6179-100000).
+Dediprog usually has them or similar ones as well but has steep shipping costs and an unpractical minimum order quantity.
+
+TSOP: Thin Small-Outline Package, 32, 40, or 48 pins
+----------------------------------------------------
+
+Soldered TSOP32
+
+  .. image:: Amd_am29f010_tsop32.jpg
+     :alt: Soldered TSOP32
+
+Soldered TSOP32
+
+  .. image:: Sst_39vf040_tsop32.jpg
+     :alt: Soldered TSOP32
+
+Soldered TSOP40
+
+  .. image:: Soldered_tsop40.jpg
+     :alt: Soldered TSOP40
+
+Soldered TSOP48
+
+  .. image:: Soldered_tsop48.jpg
+     :alt: Soldered TSOP48
+
+TSOPs are often used in embedded systems where size is important and there is no need
+for replacement in the field. It is possible to (de)solder TSOPs by hand,
+but it's not trivial and a reasonable amount of soldering skills are required.
+
+BGA: Ball Grid Array
+--------------------
+
+BGA package flash
+
+  .. image:: Flash-BGA.jpg
+     :alt: BGA package flash
+
+BGAs are often used in embedded systems where size is important and there is no need
+for replacement in the field. It is not easily possible to (de)solder BGA by hand.
+
+Communication bus protocol
+==========================
+
+There are four major communication bus protocols for flash chips,
+each with multiple subtle variants in the command set:
+
+* **SPI**: Serial Peripheral Interface, introduced ca. 2006.
+* **Parallel**: The oldest flash bus, phased out on mainboards around 2002.
+* **LPC**: Low Pin Count, a standard introduced ca. 1998.
+* **FWH**: Firmware Hub, a variant of the LPC standard introduced at the same time.
+  FWH is a special case variant of LPC with one bit set differently in the memory read/write commands.
+  That means some data sheets mention the chips speak LPC although
+  they will not respond to regular LPC read/write cycles.
+
+Here's an attempt to create a marketing language -> chip type mapping:
+
+* JEDEC Flash -> Parallel (well, mostly)
+* FWH -> FWH
+* Firmware Hub -> FWH
+* LPC Firmware -> FWH
+* Firmware Memory -> FWH
+* Low Pin Count (if Firmware/FWH is not mentioned) -> LPC
+* LPC (if Firmware is not mentioned) -> LPC
+* Serial Flash -> SPI
+
+SST data sheets have the following conventions:
+
+* LPC Memory Read -> LPC
+* Firmware Memory Read -> FWH
+
+If both are mentioned, the chip supports both.
+
+If you're not sure about whether a device is LPC or FWH, look at the read/write cycle definitions.
+
+FWH
+
+=========== ========== ============== ==========================================================
+Clock Cycle Field Name Field contents Comments
+=========== ========== ============== ==========================================================
+1	    START      1101/1110      1101 for READ, 1110 for WRITE.
+2	    IDSEL      0000 to 1111   IDSEL value to be shifted out to the chip.
+3-9	    IMADDR     YYYY	      The address to be read/written. 7 cycles total == 28 bits.
+10+	    ...	       ...	      ...
+=========== ========== ============== ==========================================================
+
+LPC
+
+=========== =================== ============== ==========================================================
+Clock Cycle Field Name	        Field contents Comments
+=========== =================== ============== ==========================================================
+1	    START	        0000	       ...
+2	    CYCLETYPE+DIRECTION	010X/011X      010X for READ, 011X for WRITE. X means "reserved".
+3-10	    ADDRESS	        YYYY	       The address to be read/written. 8 cycles total == 32 bits.
+11+	    ...	                ...	       ...
+=========== =================== ============== ==========================================================
+
+Generally, a parallel flash chip will not speak any other protocols.
+SPI flash chips also don't speak any other protocols.
+LPC flash chips sometimes speak FWH as well and vice versa,
+but they will not speak any protocols besides LPC/FWH.
+
+Hardware Redundancy
+===================
+Gigabyte's DualBios: http://www.google.com/patents/US6892323
+
+ASUS: http://www.google.com/patents/US8015449
diff --git a/dummyflasher.c b/dummyflasher.c
index cf4ca03b..ef49f48f 100644
--- a/dummyflasher.c
+++ b/dummyflasher.c
@@ -55,7 +55,7 @@ struct emu_data {
 	uint8_t emu_status_len;	/* number of emulated status registers */
 	/* If "freq" parameter is passed in from command line, commands will delay
 	 * for this period before returning. */
-	unsigned long int delay_us;
+	unsigned long long delay_ns;
 	unsigned int emu_max_byteprogram_size;
 	unsigned int emu_max_aai_size;
 	unsigned int emu_jedec_se_size;
@@ -901,7 +901,7 @@ static int dummy_spi_send_command(const struct flashctx *flash, unsigned int wri
 		msg_pspew(" 0x%02x", readarr[i]);
 	msg_pspew("\n");
 
-	default_delay((writecnt + readcnt) * emu_data->delay_us);
+	default_delay(((writecnt + readcnt) * emu_data->delay_ns) / 1000);
 	return 0;
 }
 
@@ -1128,7 +1128,7 @@ static int init_data(const struct programmer_cfg *cfg,
 	/* frequency to emulate in Hz (default), KHz, or MHz */
 	tmp = extract_programmer_param_str(cfg, "freq");
 	if (tmp) {
-		unsigned long int freq;
+		unsigned long long freq;
 		char *units = tmp;
 		char *end = tmp + strlen(tmp);
 
@@ -1166,13 +1166,13 @@ static int init_data(const struct programmer_cfg *cfg,
 			}
 		}
 
-		if (freq == 0) {
-			msg_perr("%s: invalid value 0 for freq parameter\n", __func__);
+		if (freq == 0 || freq > 8000000000) {
+			msg_perr("%s: invalid value %llu for freq parameter\n", __func__, freq);
 			free(tmp);
 			return 1;
 		}
 		/* Assume we only work with bytes and transfer at 1 bit/Hz */
-		data->delay_us = (1000000 * 8) / freq;
+		data->delay_ns = (1000000000ull * 8) / freq;
 	}
 	free(tmp);
 
@@ -1402,7 +1402,7 @@ static int dummy_init(const struct programmer_cfg *cfg)
 		return 1;
 	}
 	data->emu_chip = EMULATE_NONE;
-	data->delay_us = 0;
+	data->delay_ns = 0;
 	data->spi_write_256_chunksize = 256;
 
 	msg_pspew("%s\n", __func__);
diff --git a/en29lv640b.c b/en29lv640b.c
index 8a8d6411..4d938442 100644
--- a/en29lv640b.c
+++ b/en29lv640b.c
@@ -26,7 +26,7 @@
  * functions.
  */
 
-/* chunksize is 1 */
+/* chunksize is 2 */
 int write_en29lv640b(struct flashctx *flash, const uint8_t *src, unsigned int start, unsigned int len)
 {
 	unsigned int i;
diff --git a/erasure_layout.c b/erasure_layout.c
index e9bfa86c..db1e8a4b 100644
--- a/erasure_layout.c
+++ b/erasure_layout.c
@@ -52,8 +52,8 @@ static void init_eraseblock(struct erase_layout *layout, size_t idx, size_t bloc
 
 	edata->first_sub_block_index = *sub_block_index;
 	struct eraseblock_data *subedata = &layout[idx - 1].layout_list[*sub_block_index];
-	while (subedata->start_addr >= start_addr && subedata->end_addr <= end_addr &&
-		*sub_block_index < layout[idx-1].block_count) {
+	while (*sub_block_index < layout[idx-1].block_count &&
+		subedata->start_addr >= start_addr && subedata->end_addr <= end_addr) {
 		(*sub_block_index)++;
 		subedata++;
 	}
@@ -189,6 +189,27 @@ static void align_region(const struct erase_layout *layout, struct flashctx *con
 	}
 }
 
+/* Deselect all the blocks from index_to_deselect and down to the smallest. */
+static void deselect_erase_functions(const struct erase_layout *layout, size_t index_to_deselect,
+					int sub_block_start, const int sub_block_end)
+{
+	for (int j = sub_block_start; j <= sub_block_end; j++)
+		layout[index_to_deselect].layout_list[j].selected = false;
+
+	int block_start_to_deselect =
+		layout[index_to_deselect].layout_list[sub_block_start].first_sub_block_index;
+	int block_end_to_deselect =
+		layout[index_to_deselect].layout_list[sub_block_end].last_sub_block_index;
+
+	if (index_to_deselect)
+		deselect_erase_functions(layout,
+					index_to_deselect - 1,
+					block_start_to_deselect,
+					block_end_to_deselect);
+	else
+		return; // index_to_deselect has already reached 0, the smallest size of block. we are done.
+}
+
 /*
  * @brief	Function to select the list of sectors that need erasing
  *
@@ -228,10 +249,18 @@ static void select_erase_functions(struct flashctx *flashctx, const struct erase
 		}
 
 		const int total_blocks = sub_block_end - sub_block_start + 1;
-		if (count && count > total_blocks/2) {
+		if (count == total_blocks) {
+			/* We are selecting one large block instead, so send opcode once
+			 * instead of sending many smaller ones.
+			 */
 			if (ll->start_addr >= rstart && ll->end_addr <= rend) {
-				for (int j = sub_block_start; j <= sub_block_end; j++)
-					layout[findex - 1].layout_list[j].selected = false;
+				/* Deselect all smaller blocks covering the same region. */
+				deselect_erase_functions(layout,
+							findex - 1,
+							sub_block_start,
+							sub_block_end);
+
+				/* Select large block. */
 				ll->selected = true;
 			}
 		}
diff --git a/file_lock.c b/file_lock.c
index b2d53b5a..85127003 100644
--- a/file_lock.c
+++ b/file_lock.c
@@ -88,23 +88,11 @@ static int test_dir(const char *path)
 	return 0;
 }
 
-#define SYSTEM_LOCKFILE_DIR	"/run/lock"
-static int file_lock_open_or_create(struct ipc_lock *lock)
+static int file_lock_try_open_or_create(const char *dir, struct ipc_lock *lock)
 {
 	char path[PATH_MAX];
-	const char *dir = SYSTEM_LOCKFILE_DIR;
-#ifdef __ANDROID__
-	const char fallback[] = "/data/local/tmp";
-#else
-	const char fallback[] = "/tmp";
-#endif
-
-	if (test_dir(dir)) {
-		dir = fallback;
-		msg_gerr("Trying fallback directory: %s\n", dir);
-		if (test_dir(dir))
-			return -1;
-	}
+	if (test_dir(dir))
+		return -1;
 
 	if (snprintf(path, sizeof(path), "%s/%s", dir, lock->filename) < 0)
 		return -1;
@@ -124,6 +112,37 @@ static int file_lock_open_or_create(struct ipc_lock *lock)
 	return 0;
 }
 
+static int file_lock_open_or_create(struct ipc_lock *lock)
+{
+	const char *dirs[] = {
+#ifndef __ANDROID__
+	// Default modern Linux lock path.
+	"/run/lock",
+	// Fallback to temporary directory.
+	"/tmp",
+#else
+	// flashrom called as a subprocess with its own SELinux context.
+	"/data/vendor/flashrom/tmp",
+	// Same as above but for case when there is no tmpfs.
+	"/data/vendor/flashrom",
+	// flashrom called from the console/shell. Comes last as a fallback.
+	"/data/local/tmp",
+#endif
+	};
+
+	if (file_lock_try_open_or_create(dirs[0], lock) == 0)
+		return 0;
+
+	for (size_t i = 1; i < ARRAY_SIZE(dirs); ++i) {
+		msg_gwarn("Trying fallback directory: %s\n", dirs[i]);
+		if (file_lock_try_open_or_create(dirs[i], lock) == 0)
+			return 0;
+	}
+
+	msg_gerr("Failed to find usable directory for file lock\n");
+	return -1;
+}
+
 static int file_lock_get(struct ipc_lock *lock, int timeout_msecs)
 {
 	int remaining_msecs;
diff --git a/flashchips.c b/flashchips.c
index 1a7954c1..9947cfff 100644
--- a/flashchips.c
+++ b/flashchips.c
@@ -6184,6 +6184,50 @@ const struct flashchip flashchips[] = {
 		.voltage	= {2700, 3600},
 	},
 
+	{
+		.vendor		= "Fudan",
+		.name		= "FM25Q04",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= FUDAN_ID_NOPREFIX,
+		.model_id	= FUDAN_FM25Q04,
+		.total_size	= 512,
+		.page_size	= 256,
+		/* supports SFDP */
+		/* QPI enable 0x38, disable 0xFF */
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI,
+		.tested		= TEST_UNTESTED,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	= {
+			{
+				/* 128 * 4KB sectors */
+				.eraseblocks = { {4 * 1024, 128} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				/* 16 * 32KB blocks */
+				.eraseblocks = { {32 * 1024, 16} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				/* 8 * 64KB blocks  */
+				.eraseblocks = { {64 * 1024, 8} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				/* Full chip erase (0x60)  */
+				.eraseblocks = { {512 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				/* Full chip erase (0xC7)  */
+				.eraseblocks = { {512 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			},
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_BP2_TB_BPL,
+		.unlock		= SPI_DISABLE_BLOCKPROTECT_BP2_SRWD,
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ, /* Fast read (0x0B) and multi I/O supported */
+		.voltage	= {2700, 3600},
+	},
+
 	{
 		.vendor		= "Fudan",
 		.name		= "FM25Q08",
@@ -6196,7 +6240,7 @@ const struct flashchip flashchips[] = {
 		/* OTP: 1024B total; read 0x48; write 0x42, erase 0x44, read ID 0x4B */
 		/* QPI enable 0x38, disable 0xFF */
 		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI,
-		.tested		= TEST_UNTESTED,
+		.tested		= TEST_OK_PREW,
 		.probe		= PROBE_SPI_RDID,
 		.probe_timing	= TIMING_ZERO,
 		.block_erasers	= {
@@ -6304,6 +6348,94 @@ const struct flashchip flashchips[] = {
 		.voltage	= {2700, 3600},
 	},
 
+	{
+		.vendor		= "Fudan",
+		.name		= "FM25Q64",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= FUDAN_ID_NOPREFIX,
+		.model_id	= FUDAN_FM25Q64,
+		.total_size	= 8192,
+		.page_size	= 256,
+		/* supports SFDP */
+		/* QPI enable 0x38, disable 0xFF */
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI,
+		.tested		= TEST_UNTESTED,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	= {
+			{
+				/* 2048 * 4KB sectors */
+				.eraseblocks = { {4 * 1024, 2048} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				/* 256 * 32KB blocks */
+				.eraseblocks = { {32 * 1024, 256} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				/* 128 * 64KB blocks  */
+				.eraseblocks = { {64 * 1024, 128} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				/* Full chip erase (0x60)  */
+				.eraseblocks = { {8 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				/* Full chip erase (0xC7)  */
+				.eraseblocks = { {8 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			},
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_BP2_TB_BPL, /* bit6 selects size of protected blocks; TODO: SR2 */
+		.unlock		= SPI_DISABLE_BLOCKPROTECT_BP2_SRWD,
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ, /* Fast read (0x0B) and multi I/O supported */
+		.voltage	= {2700, 3600},
+	},
+
+	{
+		.vendor		= "Fudan",
+		.name		= "FM25Q128",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= FUDAN_ID_NOPREFIX,
+		.model_id	= FUDAN_FM25Q128,
+		.total_size	= 16384,
+		.page_size	= 256,
+		/* supports SFDP */
+		/* QPI enable 0x38, disable 0xFF */
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI,
+		.tested		= TEST_OK_PR,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	= {
+			{
+				/* 4096 * 4KB sectors */
+				.eraseblocks = { {4 * 1024, 4096} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				/* 512 * 32KB blocks */
+				.eraseblocks = { {32 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				/* 256 * 64KB blocks  */
+				.eraseblocks = { {64 * 1024, 256} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				/* Full chip erase (0x60)  */
+				.eraseblocks = { {16 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				/* Full chip erase (0xC7)  */
+				.eraseblocks = { {16 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			},
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_BP2_TB_BPL, /* bit6 selects size of protected blocks; TODO: SR2 */
+		.unlock		= SPI_DISABLE_BLOCKPROTECT_BP2_SRWD,
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ, /* Fast read (0x0B) and multi I/O supported */
+		.voltage	= {2700, 3600},
+	},
+
 	{
 		.vendor		= "Fujitsu",
 		.name		= "MBM29F004BC",
@@ -6585,7 +6717,120 @@ const struct flashchip flashchips[] = {
 		.decode_range	= DECODE_RANGE_SPI25,
 	},
 
-        {
+	{
+		.vendor		= "GigaDevice",
+		.name		= "GD25LF256F",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= GIGADEVICE_ID,
+		.model_id	= GIGADEVICE_GD25LF256F,
+		.total_size	= 32768,
+		.page_size	= 256,
+		/* OTP: 1024B total, 256B reserved; read 0x48; write 0x42, erase 0x44 */
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_WRSR_EXT2 | FEATURE_4BA,
+		.tested		= TEST_OK_PREWB,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 8192} },
+				.block_erase = SPI_BLOCK_ERASE_21,
+			}, {
+				.eraseblocks = { {4 * 1024, 8192} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_5C,
+			}, {
+				.eraseblocks = { {32 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_DC,
+			}, {
+				.eraseblocks = { {64 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {32 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {32 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_BP4_SRWD,
+		.unlock		= SPI_DISABLE_BLOCKPROTECT_BP4_SRWD, /* TODO: 2nd status reg (read with 0x35) */
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ, /* Fast read (0x0B) and multi I/O supported */
+		.voltage	= {1650, 2000},
+		.reg_bits	=
+		{
+			.srp    = {STATUS1, 7, RW},
+			.srl    = {STATUS2, 0, RW},
+			.bp     = {{STATUS1, 2, RW}, {STATUS1, 3, RW}, {STATUS1, 4, RW}, {STATUS1, 5, RW}},
+			.tb    = {STATUS1, 6, RW}, /* Called BP4 in datasheet, acts like TB */
+			.cmp    = {STATUS2, 6, RW},
+		},
+		.decode_range	= DECODE_RANGE_SPI25,
+	},
+
+	{
+		.vendor		= "GigaDevice",
+		.name		= "GD25LF512MF",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= GIGADEVICE_ID,
+		.model_id	= GIGADEVICE_GD25LF512MF,
+		.total_size	= 65536,
+		.page_size	= 256,
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_WRSR_EXT2 | FEATURE_4BA,
+		.tested		= TEST_OK_PREWB,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 16384} },
+				.block_erase = SPI_BLOCK_ERASE_21,
+			}, {
+				.eraseblocks = { {4 * 1024, 16384} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 2048} },
+				.block_erase = SPI_BLOCK_ERASE_5C,
+			}, {
+				.eraseblocks = { {32 * 1024, 2048} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_DC,
+			}, {
+				.eraseblocks = { {64 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {64 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {64 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_BP4_SRWD, /* TODO: 2nd status reg (read with 0x35) */
+		.unlock		= SPI_DISABLE_BLOCKPROTECT_BP4_SRWD,
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ,
+		.voltage	= {1695, 1950},
+		.reg_bits	=
+		{
+			.srp    = {STATUS1, 7, RW},
+			.bp     = {{STATUS1, 2, RW}, {STATUS1, 3, RW}, {STATUS1, 4, RW}, {STATUS1, 5, RW}},
+			.tb     = {STATUS1, 6, RW},	/* Called BP4 in datasheet, acts like TB */
+			.srl    = {STATUS2, 0, RW},
+			.cmp    = {STATUS2, 6, RW},
+		},
+		.decode_range	= DECODE_RANGE_SPI25,
+	},
+
+	{
 		.vendor		= "GigaDevice",
 		.name		= "GD25LQ128E/GD25LB128E/GD25LR128E/GD25LQ128D/GD25LQ128C",
 		.bustype	= BUS_SPI,
@@ -6912,49 +7157,162 @@ const struct flashchip flashchips[] = {
 		.block_erasers  =
 		{
 			{
-				.eraseblocks = { {4 * 1024, 8192} },
+				.eraseblocks = { {4 * 1024, 8192} },
+				.block_erase = SPI_BLOCK_ERASE_21,
+			}, {
+				.eraseblocks = { {4 * 1024, 8192} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_5C,
+			}, {
+				.eraseblocks = { {32 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_DC,
+			}, {
+				.eraseblocks = { {64 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {32 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {32 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock      = SPI_PRETTYPRINT_STATUS_REGISTER_BP4_SRWD,
+		.unlock         = SPI_DISABLE_BLOCKPROTECT_BP4_SRWD,
+		.write          = SPI_CHIP_WRITE256,
+		.read           = SPI_CHIP_READ,
+		.voltage        = {1650, 2000},
+		.reg_bits       =
+		{
+			.srp    = {STATUS1, 7, RW},
+			.bp     = {{STATUS1, 2, RW}, {STATUS1, 3, RW}, {STATUS1, 4, RW}, {STATUS1, 5, RW}},
+			.tb     = {STATUS1, 6, RW}, /* Called BP4 in datasheet, acts like TB */
+		},
+		.decode_range   = DECODE_RANGE_SPI25,
+
+	},
+
+	{
+		.vendor		= "GigaDevice",
+		.name		= "GD25LB256F/GD25LR256F",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= GIGADEVICE_ID,
+		.model_id	= GIGADEVICE_GD25LQ255E,
+		.total_size	= 32768,
+		.page_size	= 256,
+		/* OTP: 1024B total, 256B reserved; read 0x48; write 0x42, erase 0x44 */
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_WRSR_EXT2 | FEATURE_4BA,
+		.tested		= TEST_OK_PREWB,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 8192} },
+				.block_erase = SPI_BLOCK_ERASE_21,
+			}, {
+				.eraseblocks = { {4 * 1024, 8192} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_5C,
+			}, {
+				.eraseblocks = { {32 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_DC,
+			}, {
+				.eraseblocks = { {64 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {32 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {32 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_BP4_SRWD,
+		.unlock		= SPI_DISABLE_BLOCKPROTECT_BP4_SRWD, /* TODO: 2nd status reg (read with 0x35) */
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ, /* Fast read (0x0B) and multi I/O supported */
+		.voltage	= {1650, 2000},
+		.reg_bits	=
+		{
+			.srp    = {STATUS1, 7, RW},
+			.srl    = {STATUS2, 0, RW},
+			.bp     = {{STATUS1, 2, RW}, {STATUS1, 3, RW}, {STATUS1, 4, RW}, {STATUS1, 5, RW}},
+			.tb     = {STATUS1, 6, RW}, /* Called BP4 in datasheet, acts like TB */
+			.cmp    = {STATUS2, 6, RW},
+		},
+		.decode_range	= DECODE_RANGE_SPI25,
+	},
+
+	{
+		.vendor		= "GigaDevice",
+		.name		= "GD25LB512MF/GD25LR512MF",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= GIGADEVICE_ID,
+		.model_id	= GIGADEVICE_GD25LB512MF,
+		.total_size	= 65536,
+		.page_size	= 256,
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_WRSR_EXT2 | FEATURE_4BA,
+		.tested		= TEST_OK_PREWB,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 16384} },
 				.block_erase = SPI_BLOCK_ERASE_21,
 			}, {
-				.eraseblocks = { {4 * 1024, 8192} },
+				.eraseblocks = { {4 * 1024, 16384} },
 				.block_erase = SPI_BLOCK_ERASE_20,
 			}, {
-				.eraseblocks = { {32 * 1024, 1024} },
+				.eraseblocks = { {32 * 1024, 2048} },
 				.block_erase = SPI_BLOCK_ERASE_5C,
 			}, {
-				.eraseblocks = { {32 * 1024, 1024} },
+				.eraseblocks = { {32 * 1024, 2048} },
 				.block_erase = SPI_BLOCK_ERASE_52,
 			}, {
-				.eraseblocks = { {64 * 1024, 512} },
+				.eraseblocks = { {64 * 1024, 1024} },
 				.block_erase = SPI_BLOCK_ERASE_DC,
 			}, {
-				.eraseblocks = { {64 * 1024, 512} },
+				.eraseblocks = { {64 * 1024, 1024} },
 				.block_erase = SPI_BLOCK_ERASE_D8,
 			}, {
-				.eraseblocks = { {32 * 1024 * 1024, 1} },
+				.eraseblocks = { {64 * 1024 * 1024, 1} },
 				.block_erase = SPI_BLOCK_ERASE_60,
 			}, {
-				.eraseblocks = { {32 * 1024 * 1024, 1} },
+				.eraseblocks = { {64 * 1024 * 1024, 1} },
 				.block_erase = SPI_BLOCK_ERASE_C7,
 			}
 		},
 		.printlock      = SPI_PRETTYPRINT_STATUS_REGISTER_BP4_SRWD,
 		.unlock         = SPI_DISABLE_BLOCKPROTECT_BP4_SRWD,
-		.write          = SPI_CHIP_WRITE256,
-		.read           = SPI_CHIP_READ,
-		.voltage        = {1650, 2000},
-		.reg_bits       =
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ,
+		.voltage	= {1695, 1950},
+		.reg_bits	=
 		{
 			.srp    = {STATUS1, 7, RW},
 			.bp     = {{STATUS1, 2, RW}, {STATUS1, 3, RW}, {STATUS1, 4, RW}, {STATUS1, 5, RW}},
-			.tb     = {STATUS1, 6, RW}, /* Called BP4 in datasheet, acts like TB */
+			.tb     = {STATUS1, 6, RW},	/* Called BP4 in datasheet, acts like TB */
+			.srl    = {STATUS2, 0, RW},
+			.cmp    = {STATUS2, 6, RW},
 		},
-		.decode_range   = DECODE_RANGE_SPI25,
-
+		.decode_range	= DECODE_RANGE_SPI25,
 	},
 
 	{
 		.vendor         = "GigaDevice",
-		.name           = "GD25LR512ME",
+		.name           = "GD25LB512ME/GD25LR512ME",
 		.bustype        = BUS_SPI,
 		.manufacture_id = GIGADEVICE_ID,
 		.model_id       = GIGADEVICE_GD25LR512ME,
@@ -6962,7 +7320,7 @@ const struct flashchip flashchips[] = {
 		.page_size      = 256,
 		/* OTP: 4096B total; read 0x48; write 0x42, erase 0x44 */
 		.feature_bits   = FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI | FEATURE_4BA,
-		.tested         = TEST_OK_PREW,
+		.tested         = TEST_OK_PREWB,
 		.probe          = PROBE_SPI_RDID,
 		.probe_timing   = TIMING_ZERO,
 		.block_erasers  =
@@ -7726,6 +8084,153 @@ const struct flashchip flashchips[] = {
 		.voltage	= {2300, 3600},
 	},
 
+{
+		.vendor		= "GigaDevice",
+		.name		= "GD25F64F",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= GIGADEVICE_ID,
+		.model_id	= GIGADEVICE_GD25F64F,
+		.total_size	= 8192,
+		.page_size	= 256,
+		/* OTP: 1024B total, 256B reserved; read 0x48; write 0x42, erase 0x44 */
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_WRSR2 | FEATURE_WRSR3,
+		.tested		= TEST_OK_PREWB,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 2048} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 256} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 128} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {8 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {8 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_BP4_SRWD,
+		.unlock		= SPI_DISABLE_BLOCKPROTECT_BP4_SRWD, /* TODO: 2nd status reg (read with 0x35) */
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ, /* Fast read (0x0B) and multi I/O supported */
+		.voltage	= {2700, 3600},
+		.reg_bits	=
+		{
+			.srp    = {STATUS1, 7, RW},
+			.srl    = {STATUS2, 0, RW},
+			.bp     = {{STATUS1, 2, RW}, {STATUS1, 3, RW}, {STATUS1, 4, RW}},
+			.tb     = {STATUS1, 5, RW}, /* Called BP3 in datasheet, acts like TB */
+			.sec    = {STATUS1, 6, RW}, /* Called BP4 in datasheet, acts like SEC */
+			.cmp    = {STATUS3, 4, RW},
+		},
+		.decode_range	= DECODE_RANGE_SPI25,
+	},
+
+{
+		.vendor		= "GigaDevice",
+		.name		= "GD25F128F",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= GIGADEVICE_ID,
+		.model_id	= GIGADEVICE_GD25F128F,
+		.total_size	= 16384,
+		.page_size	= 256,
+		/* OTP: 3x2048B; read 0x48; write 0x42, erase 0x44 */
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_WRSR2 | FEATURE_WRSR3,
+		.tested		= TEST_OK_PREWB,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 4096} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 256} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {16 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {16 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_BP4_SRWD,
+		.unlock		= SPI_DISABLE_BLOCKPROTECT_BP4_SRWD, /* TODO: 2nd status reg (read with 0x35) */
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ, /* Fast read (0x0B) and multi I/O supported */
+		.voltage	= {2700, 3600},
+		.reg_bits	=
+		{
+			.bp     = {{STATUS1, 2, RW}, {STATUS1, 3, RW}, {STATUS1, 4, RW}, {STATUS1, 5, RW}},
+			.tb     = {STATUS1, 6, RW},	/* Called BP4 in datasheet, acts like TB */
+		},
+		.decode_range	= DECODE_RANGE_SPI25,
+	},
+
+	{
+		.vendor		= "GigaDevice",
+		.name		= "GD25F256F",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= GIGADEVICE_ID,
+		.model_id	= GIGADEVICE_GD25F256F,
+		.total_size	= 32768,
+		.page_size	= 256,
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI | FEATURE_WRSR2 | FEATURE_WRSR3 | FEATURE_4BA,
+		.tested		= TEST_OK_PREWB,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 8192} },
+				.block_erase = SPI_BLOCK_ERASE_21,
+			}, {
+				.eraseblocks = { {4 * 1024, 8192} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_5C,
+			}, {
+				.eraseblocks = { {32 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_DC,
+			}, {
+				.eraseblocks = { {64 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {32 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {32 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_BP4_SRWD,
+		.unlock		= SPI_DISABLE_BLOCKPROTECT_BP4_SRWD,
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ,
+		.voltage	= {2700, 3600},
+		.reg_bits	=
+		{
+			.bp     = {{STATUS1, 2, RW}, {STATUS1, 3, RW}, {STATUS1, 4, RW}, {STATUS1, 5, RW}},
+			.tb     = {STATUS1, 6, RW},	/* Called BP4 in datasheet, acts like TB */
+		},
+		.decode_range	= DECODE_RANGE_SPI25,
+	},
+
 	{
 		.vendor		= "GigaDevice",
 		.name		= "GD25WQ80E",
@@ -11093,6 +11598,62 @@ const struct flashchip flashchips[] = {
 		.decode_range	= DECODE_RANGE_SPI25,
 	},
 
+	{
+		.vendor		= "Macronix",
+		.name		= "MX25U25645G",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= MACRONIX_ID,
+		.model_id	= MACRONIX_MX25U25635F,
+		.total_size	= 32768,
+		.page_size	= 256,
+		/* OTP: 1024B total; enter 0xB1, exit 0xC1 */
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI | FEATURE_4BA | FEATURE_CFGR | FEATURE_SCUR,
+		.tested		= TEST_OK_PREWB,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 8192} },
+				.block_erase = SPI_BLOCK_ERASE_21,
+			}, {
+				.eraseblocks = { {4 * 1024, 8192} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_5C,
+			}, {
+				.eraseblocks = { {32 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_DC,
+			}, {
+				.eraseblocks = { {64 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {32 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {32 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_BP3_SRWD, /* bit6 is quad enable */
+		.unlock		= SPI_DISABLE_BLOCKPROTECT_BP3_SRWD,
+		.write		= SPI_CHIP_WRITE256, /* Multi I/O supported */
+		.read		= SPI_CHIP_READ, /* Fast read (0x0B) and multi I/O supported */
+		.voltage	= {1700, 2000},
+		.reg_bits	=
+		{
+			.srp    = {STATUS1, 7, RW},
+			.bp     = {{STATUS1, 2, RW}, {STATUS1, 3, RW}, {STATUS1, 4, RW}, {STATUS1, 5, RW}},
+			.tb     = {CONFIG, 3, OTP},
+			.wps    = {SECURITY, 7, OTP}, /* This bit is set by WPSEL command */
+		},
+		.decode_range	= DECODE_RANGE_SPI25,
+	},
+
 	{
 		.vendor		= "Macronix",
 		.name		= "MX25U3235E/F",
@@ -11850,7 +12411,45 @@ const struct flashchip flashchips[] = {
 		.unlock		= SPI_DISABLE_BLOCKPROTECT_BP3_SRWD,
 		.write		= SPI_CHIP_WRITE256,
 		.read		= SPI_CHIP_READ, /* Fast read (0x0B) supported */
-		.voltage	= {2700, 3600},
+		.voltage	= {2700, 3600},
+	},
+
+	{
+		.vendor		= "Macronix",
+		.name		= "MX77U51250F",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= MACRONIX_ID,
+		.model_id	= MACRONIX_MX77U51250F,
+		.total_size	= 65536,
+		.page_size	= 256,
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_CFGR | FEATURE_4BA,
+		.tested		= TEST_OK_PREW,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 16384} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 2048} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {64 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {64 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_BP3_SRWD, /* bit6 is quad enable */
+		.unlock		= SPI_DISABLE_BLOCKPROTECT_BP3_SRWD,
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ, /* Fast read (0x0B) supported */
+		.voltage	= {1650, 2000},
 	},
 
 	/* The ST M25P05 is a bit of a problem. It has the same ID as the
@@ -19877,6 +20476,58 @@ const struct flashchip flashchips[] = {
 		.decode_range	= DECODE_RANGE_SPI25,
 	},
 
+	{
+		.vendor		= "Winbond",
+		.name		= "W25Q32JV_M",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= WINBOND_NEX_ID,
+		.model_id	= WINBOND_NEX_W25Q32JV_M,
+		.total_size	= 4096,
+		.page_size	= 256,
+		/* supports SFDP */
+		/* OTP: 3x 256B total; read 0x48; write 0x42, erase 0x44, read ID 0x4B */
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI |
+				  FEATURE_WRSR2 | FEATURE_WRSR3,
+		.tested		= TEST_OK_PREW,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 128} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 64} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {4 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {4 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_SRWD_SEC_TB_BP2_WELWIP,
+		.unlock		= SPI_DISABLE_BLOCKPROTECT,
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ,
+		.voltage	= {2700, 3600},
+		.reg_bits	=
+		{
+			.srp    = {STATUS1, 7, RW},
+			.sec    = {STATUS1, 6, RW},
+			.tb     = {STATUS1, 5, RW},
+			.bp     = {{STATUS1, 2, RW}, {STATUS1, 3, RW}, {STATUS1, 4, RW}},
+			.cmp    = {STATUS2, 6, RW},
+			.srl    = {STATUS2, 0, RW},
+			.wps    = {STATUS3, 2, RW},
+		},
+		.decode_range	= DECODE_RANGE_SPI25,
+	},
+
 	{
 		.vendor		= "Winbond",
 		.name		= "W25Q32JV",
@@ -21975,7 +22626,121 @@ const struct flashchip flashchips[] = {
 
 	{
 		.vendor		= "XMC",
-		.name		= "XM25QH64C",
+		.name		= "XM25QU16C",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= ST_ID,
+		.model_id	= XMC_XM25QU16C,
+		.total_size	= 2048,
+		.page_size	= 256,
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI,
+		.tested		= TEST_OK_PREW,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 512} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 64} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 32} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {2 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {2 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_PLAIN,
+		.unlock		= SPI_DISABLE_BLOCKPROTECT,
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ,
+		.voltage	= {1650, 1950},
+	},
+
+	{
+		.vendor		= "XMC",
+		.name		= "XM25QH32C/XM25QH32D",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= ST_ID,
+		.model_id	= XMC_XM25QH32C,
+		.total_size	= 4096,
+		.page_size	= 256,
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI,
+		.tested		= TEST_OK_PREW,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 128} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 64} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {4 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {4 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_PLAIN,
+		.unlock		= SPI_DISABLE_BLOCKPROTECT,
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ,
+		.voltage	= {2700, 3600},
+	},
+
+	{
+		.vendor		= "XMC",
+		.name		= "XM25QU32C",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= ST_ID,
+		.model_id	= XMC_XM25QU32C,
+		.total_size	= 4096,
+		.page_size	= 256,
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI,
+		.tested		= TEST_OK_PREW,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 128} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 64} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {4 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {4 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_PLAIN,
+		.unlock		= SPI_DISABLE_BLOCKPROTECT,
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ,
+		.voltage	= {1650, 1950},
+	},
+
+	{
+		.vendor		= "XMC",
+		.name		= "XM25QH64C/XM25QH64D",
 		.bustype	= BUS_SPI,
 		.manufacture_id	= ST_ID,
 		.model_id	= XMC_XM25QH64C,
@@ -22013,14 +22778,14 @@ const struct flashchip flashchips[] = {
 
 	{
 		.vendor		= "XMC",
-		.name		= "XM25QU64C",
+		.name		= "XM25QU64C/XM25LU64C",
 		.bustype	= BUS_SPI,
 		.manufacture_id	= ST_ID,
 		.model_id	= XMC_XM25QU64C,
 		.total_size	= 8192,
 		.page_size	= 256,
 		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI,
-		.tested		= TEST_UNTESTED,
+		.tested		= TEST_OK_PREW,
 		.probe		= PROBE_SPI_RDID,
 		.probe_timing	= TIMING_ZERO,
 		.block_erasers	=
@@ -22099,14 +22864,14 @@ const struct flashchip flashchips[] = {
 
 	{
 		.vendor		= "XMC",
-		.name		= "XM25QH128C",
+		.name		= "XM25QH128C/XM25QH128D",
 		.bustype	= BUS_SPI,
 		.manufacture_id	= ST_ID,
 		.model_id	= XMC_XM25QH128C,
 		.total_size	= 16384,
 		.page_size	= 256,
 		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI | FEATURE_WRSR2,
-		.tested		= TEST_UNTESTED,
+		.tested		= TEST_OK_PREW,
 		.probe		= PROBE_SPI_RDID,
 		.probe_timing	= TIMING_ZERO,
 		.block_erasers	=
@@ -22147,7 +22912,7 @@ const struct flashchip flashchips[] = {
 
 	{
 		.vendor		= "XMC",
-		.name		= "XM25QU128C",
+		.name		= "XM25QU128C/XM25QU128D",
 		.bustype	= BUS_SPI,
 		.manufacture_id	= ST_ID,
 		.model_id	= XMC_XM25QU128C,
@@ -22156,7 +22921,7 @@ const struct flashchip flashchips[] = {
 		/* supports SFDP */
 		/* OTP: 1024B total, 256B reserved; read 0x48; write 0x42, erase 0x44, read ID 0x4B */
 		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_QPI,
-		.tested		= TEST_UNTESTED,
+		.tested		= TEST_OK_PREW,
 		.probe		= PROBE_SPI_RDID,
 		.probe_timing	= TIMING_ZERO,
 		.block_erasers	=
@@ -22187,7 +22952,7 @@ const struct flashchip flashchips[] = {
 
 	{
 		.vendor		= "XMC",
-		.name		= "XM25QH256C",
+		.name		= "XM25QH256C/XM25QH256D",
 		.bustype	= BUS_SPI,
 		.manufacture_id	= ST_ID,
 		.model_id	= XMC_XM25QH256C,
@@ -22198,7 +22963,7 @@ const struct flashchip flashchips[] = {
 		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_4BA_ENTER_WREN |
 				  FEATURE_4BA_EAR_C5C8 | FEATURE_4BA_READ | FEATURE_4BA_FAST_READ |
 				  FEATURE_4BA_WRITE | FEATURE_WRSR2,
-		.tested		= TEST_OK_PR,
+		.tested		= TEST_OK_PREW,
 		.probe		= PROBE_SPI_RDID,
 		.probe_timing	= TIMING_ZERO,
 		.block_erasers	=
@@ -22237,7 +23002,7 @@ const struct flashchip flashchips[] = {
 
 	{
 		.vendor		= "XMC",
-		.name		= "XM25QU256C",
+		.name		= "XM25QU256C/XM25QU256D",
 		.bustype	= BUS_SPI,
 		.manufacture_id	= ST_ID,
 		.model_id	= XMC_XM25QU256C,
@@ -22319,6 +23084,102 @@ const struct flashchip flashchips[] = {
 		.voltage	= {1650, 1950},
 	},
 
+	{
+		.vendor		= "XMC",
+		.name		= "XM25QH512C/XM25QH512D",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= ST_ID,
+		.model_id	= XMC_XM25QH512C,
+		.total_size	= 64 * 1024,
+		.page_size	= 256,
+		/* supports SFDP */
+		/* OTP: 1024B total, 256B reserved; read 0x48; write 0x42, erase 0x44, read ID 0x4B */
+		/* FOUR_BYTE_ADDR: supports 4-bytes addressing mode */
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_4BA_ENTER_WREN
+			| FEATURE_4BA_EAR_C5C8 | FEATURE_4BA_READ | FEATURE_4BA_FAST_READ,
+		.tested		= TEST_OK_PREW,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 16384} },
+				.block_erase = SPI_BLOCK_ERASE_21,
+			}, {
+				.eraseblocks = { {4 * 1024, 16384} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 2048} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_DC,
+			}, {
+				.eraseblocks = { {64 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {64 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {64 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_PLAIN, /* TODO: improve */
+		.unlock		= SPI_DISABLE_BLOCKPROTECT,
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ,
+		.voltage	= {2700, 3600},
+	},
+
+	{
+		.vendor		= "XMC",
+		.name		= "XM25QU512C/XM25QU512D",
+		.bustype	= BUS_SPI,
+		.manufacture_id	= ST_ID,
+		.model_id	= XMC_XM25QU512C,
+		.total_size	= 64 * 1024,
+		.page_size	= 256,
+		/* supports SFDP */
+		/* OTP: 1024B total, 256B reserved; read 0x48; write 0x42, erase 0x44, read ID 0x4B */
+		/* FOUR_BYTE_ADDR: supports 4-bytes addressing mode */
+		.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_4BA_ENTER_WREN
+			| FEATURE_4BA_EAR_C5C8 | FEATURE_4BA_READ | FEATURE_4BA_FAST_READ,
+		.tested		= TEST_OK_PREW,
+		.probe		= PROBE_SPI_RDID,
+		.probe_timing	= TIMING_ZERO,
+		.block_erasers	=
+		{
+			{
+				.eraseblocks = { {4 * 1024, 16384} },
+				.block_erase = SPI_BLOCK_ERASE_21,
+			}, {
+				.eraseblocks = { {4 * 1024, 16384} },
+				.block_erase = SPI_BLOCK_ERASE_20,
+			}, {
+				.eraseblocks = { {32 * 1024, 2048} },
+				.block_erase = SPI_BLOCK_ERASE_52,
+			}, {
+				.eraseblocks = { {64 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_DC,
+			}, {
+				.eraseblocks = { {64 * 1024, 1024} },
+				.block_erase = SPI_BLOCK_ERASE_D8,
+			}, {
+				.eraseblocks = { {64 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_60,
+			}, {
+				.eraseblocks = { {64 * 1024 * 1024, 1} },
+				.block_erase = SPI_BLOCK_ERASE_C7,
+			}
+		},
+		.printlock	= SPI_PRETTYPRINT_STATUS_REGISTER_PLAIN, /* TODO: improve */
+		.unlock		= SPI_DISABLE_BLOCKPROTECT,
+		.write		= SPI_CHIP_WRITE256,
+		.read		= SPI_CHIP_READ,
+		.voltage	= {1650, 1950},
+	},
+
 	{
 		.vendor		= "XTX Technology Limited",
 		.name		= "XT25F02E",
diff --git a/flashchips_crosbl.c b/flashchips_crosbl.c
index 58f25018..2b83d0cf 100644
--- a/flashchips_crosbl.c
+++ b/flashchips_crosbl.c
@@ -70,5 +70,11 @@ bool is_chipname_duplicate(const struct flashchip *chip)
 	   !strcmp(chip->name, "W25Q32JW...Q"))
 		return true;
 
+	/* The "GD25LQ255E" and "GD25LB256F/GD25LR256F" and chip entries
+	 * have the same vendor and model IDs.
+	 * Marking the latter as duplicate.
+	 */
+	if(!strcmp(chip->name, "GD25LB256F/GD25LR256F")) return true;
+
 	return false;
 }
diff --git a/flashrom.c b/flashrom.c
index c2479eed..6b93ba99 100644
--- a/flashrom.c
+++ b/flashrom.c
@@ -510,14 +510,15 @@ int check_block_eraser(const struct flashctx *flash, int k, int log)
 
 	if (flash->mst->buses_supported & BUS_SPI) {
 		const uint8_t *opcode = spi_get_opcode_from_erasefn(eraser.block_erase);
-		for (int i = 0; opcode[i]; i++) {
-			if (!spi_probe_opcode(flash, opcode[i])) {
-				if (log)
-					msg_cdbg("block erase function and layout found "
-						 "but SPI master doesn't support the function. ");
-				return 1;
+		if (opcode)
+			for (int i = 0; opcode[i]; i++) {
+				if (!spi_probe_opcode(flash, opcode[i])) {
+					if (log)
+						msg_cdbg("block erase function and layout found "
+							 "but SPI master doesn't support the function. ");
+					return 1;
+				}
 			}
-		}
 	}
 	// TODO: Once erase functions are annotated with allowed buses, check that as well.
 	return 0;
diff --git a/flashrom.rc b/flashrom.rc
new file mode 100644
index 00000000..d28c1fae
--- /dev/null
+++ b/flashrom.rc
@@ -0,0 +1,5 @@
+on post-fs-data-checkpointed
+    mkdir /data/vendor/flashrom
+    mkdir /data/vendor/flashrom/tmp
+    mount tmpfs tmpfs /data/vendor/flashrom/tmp nosuid nodev noexec rw
+    restorecon /data/vendor/flashrom
diff --git a/ich_descriptors.c b/ich_descriptors.c
index eaf44b06..c436fabd 100644
--- a/ich_descriptors.c
+++ b/ich_descriptors.c
@@ -49,6 +49,7 @@ ssize_t ich_number_of_regions(const enum ich_chipset cs, const struct ich_desc_c
 	case CHIPSET_400_SERIES_COMET_POINT:
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_METEOR_LAKE:
 	case CHIPSET_PANTHER_LAKE:
 	case CHIPSET_ELKHART_LAKE:
@@ -80,6 +81,7 @@ ssize_t ich_number_of_masters(const enum ich_chipset cs, const struct ich_desc_c
 	case CHIPSET_C740_SERIES_EMMITSBURG:
 	case CHIPSET_APOLLO_LAKE:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_METEOR_LAKE:
 	case CHIPSET_PANTHER_LAKE:
 	case CHIPSET_GEMINI_LAKE:
@@ -221,6 +223,7 @@ static const char *pprint_density(enum ich_chipset cs, const struct ich_descript
 	case CHIPSET_400_SERIES_COMET_POINT:
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_METEOR_LAKE:
 	case CHIPSET_PANTHER_LAKE:
 	case CHIPSET_APOLLO_LAKE:
@@ -320,6 +323,7 @@ static const char *pprint_freq(enum ich_chipset cs, uint8_t value)
 		return freq_str[2][value];
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_C740_SERIES_EMMITSBURG:
 	case CHIPSET_METEOR_LAKE:
 	case CHIPSET_PANTHER_LAKE:
@@ -371,6 +375,7 @@ void prettyprint_ich_descriptor_component(enum ich_chipset cs, const struct ich_
 	case CHIPSET_400_SERIES_COMET_POINT:
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_METEOR_LAKE:
 	case CHIPSET_PANTHER_LAKE:
 	case CHIPSET_APOLLO_LAKE:
@@ -512,6 +517,7 @@ void prettyprint_ich_descriptor_master(const enum ich_chipset cs, const struct i
 	    cs == CHIPSET_400_SERIES_COMET_POINT ||
 	    cs == CHIPSET_500_SERIES_TIGER_POINT ||
 	    cs == CHIPSET_600_SERIES_ALDER_POINT ||
+	    cs == CHIPSET_700_SERIES_RAPTOR_POINT ||
 	    cs == CHIPSET_C740_SERIES_EMMITSBURG ||
 	    cs == CHIPSET_JASPER_LAKE ||
 	    cs == CHIPSET_METEOR_LAKE ||
@@ -1115,6 +1121,7 @@ static enum ich_chipset guess_ich_chipset(const struct ich_desc_content *const c
 	case CHIPSET_400_SERIES_COMET_POINT:
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_METEOR_LAKE:
 	case CHIPSET_PANTHER_LAKE:
 	case CHIPSET_GEMINI_LAKE:
@@ -1277,6 +1284,7 @@ int getFCBA_component_density(enum ich_chipset cs, const struct ich_descriptors
 	case CHIPSET_400_SERIES_COMET_POINT:
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_METEOR_LAKE:
 	case CHIPSET_PANTHER_LAKE:
 	case CHIPSET_APOLLO_LAKE:
@@ -1324,6 +1332,7 @@ static uint32_t read_descriptor_reg(enum ich_chipset cs, uint8_t section, uint16
 	case CHIPSET_400_SERIES_COMET_POINT:
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_METEOR_LAKE:
 	case CHIPSET_PANTHER_LAKE:
 	case CHIPSET_APOLLO_LAKE:
diff --git a/ichspi.c b/ichspi.c
index c5cef152..dc5caee9 100644
--- a/ichspi.c
+++ b/ichspi.c
@@ -400,7 +400,7 @@ static OPCODES O_ST_M25P = {
  * It is used to reprogram the chipset OPCODE table on-the-fly if an opcode
  * is needed which is currently not in the chipset OPCODE table
  */
-static OPCODE POSSIBLE_OPCODES[] = {
+static const OPCODE POSSIBLE_OPCODES[] = {
 	 {JEDEC_BYTE_PROGRAM, SPI_OPCODE_TYPE_WRITE_WITH_ADDRESS, 0},	// Write Byte
 	 {JEDEC_READ, SPI_OPCODE_TYPE_READ_WITH_ADDRESS, 0},	// Read Data
 	 {JEDEC_BE_D8, SPI_OPCODE_TYPE_WRITE_WITH_ADDRESS, 0},	// Erase Sector
@@ -662,7 +662,7 @@ static int reprogram_opcode_on_the_fly(uint8_t opcode, unsigned int writecnt, un
 		else // we have an invalid case
 			return SPI_INVALID_LENGTH;
 	}
-	int oppos = 2;	// use original JEDEC_BE_D8 offset
+	int oppos = 4;	// use the original position of JEDEC_REMS
 	curopcodes->opcode[oppos].opcode = opcode;
 	curopcodes->opcode[oppos].spi_type = spi_type;
 	program_opcodes(curopcodes, 0, ich_generation);
@@ -1832,7 +1832,11 @@ static int ich_spi_send_multicommand(const struct flashctx *flash,
 
 static bool ich_spi_probe_opcode(const struct flashctx *flash, uint8_t opcode)
 {
-	return find_opcode(curopcodes, opcode) >= 0;
+	int ret = find_opcode(curopcodes, opcode);
+	if ((ret == -1) && (lookup_spi_type(opcode) <= 3))
+		/* opcode is in POSSIBLE_OPCODES, report supported. */
+		return true;
+	return ret >= 0;
 }
 
 #define ICH_BMWAG(x) ((x >> 24) & 0xff)
@@ -2037,18 +2041,7 @@ static void ich9_set_pr(const size_t reg_pr0, int i, int read_prot, int write_pr
 	msg_gspew("resulted in 0x%08"PRIx32".\n", mmio_readl(addr));
 }
 
-static const struct spi_master spi_master_ich7 = {
-	.max_data_read	= 64,
-	.max_data_write	= 64,
-	.command	= ich_spi_send_command,
-	.multicommand	= ich_spi_send_multicommand,
-	.map_flash_region	= physmap,
-	.unmap_flash_region	= physunmap,
-	.read		= default_spi_read,
-	.write_256	= default_spi_write_256,
-};
-
-static const struct spi_master spi_master_ich9 = {
+static const struct spi_master spi_master_ich = {
 	.max_data_read	= 64,
 	.max_data_write	= 64,
 	.command	= ich_spi_send_command,
@@ -2100,7 +2093,7 @@ static int init_ich7_spi(void *spibar, enum ich_chipset ich_gen)
 	}
 	ich_init_opcodes(ich_gen);
 	ich_set_bbar(0, ich_gen);
-	register_spi_master(&spi_master_ich7, NULL);
+	register_spi_master(&spi_master_ich, NULL);
 
 	return 0;
 }
@@ -2152,6 +2145,7 @@ static void init_chipset_properties(struct swseq_data *swseq, struct hwseq_data
 	case CHIPSET_400_SERIES_COMET_POINT:
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_APOLLO_LAKE:
 	case CHIPSET_GEMINI_LAKE:
 	case CHIPSET_JASPER_LAKE:
@@ -2193,6 +2187,7 @@ static void init_chipset_properties(struct swseq_data *swseq, struct hwseq_data
 	case CHIPSET_400_SERIES_COMET_POINT:
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_APOLLO_LAKE:
 	case CHIPSET_GEMINI_LAKE:
 	case CHIPSET_JASPER_LAKE:
@@ -2256,6 +2251,7 @@ static int init_ich_default(const struct programmer_cfg *cfg, void *spibar, enum
 	case CHIPSET_400_SERIES_COMET_POINT:
 	case CHIPSET_500_SERIES_TIGER_POINT:
 	case CHIPSET_600_SERIES_ALDER_POINT:
+	case CHIPSET_700_SERIES_RAPTOR_POINT:
 	case CHIPSET_APOLLO_LAKE:
 	case CHIPSET_GEMINI_LAKE:
 	case CHIPSET_JASPER_LAKE:
@@ -2337,6 +2333,7 @@ static int init_ich_default(const struct programmer_cfg *cfg, void *spibar, enum
 		case CHIPSET_400_SERIES_COMET_POINT:
 		case CHIPSET_500_SERIES_TIGER_POINT:
 		case CHIPSET_600_SERIES_ALDER_POINT:
+		case CHIPSET_700_SERIES_RAPTOR_POINT:
 		case CHIPSET_APOLLO_LAKE:
 		case CHIPSET_GEMINI_LAKE:
 		case CHIPSET_JASPER_LAKE:
@@ -2378,6 +2375,7 @@ static int init_ich_default(const struct programmer_cfg *cfg, void *spibar, enum
 		case CHIPSET_400_SERIES_COMET_POINT:
 		case CHIPSET_500_SERIES_TIGER_POINT:
 		case CHIPSET_600_SERIES_ALDER_POINT:
+		case CHIPSET_700_SERIES_RAPTOR_POINT:
 		case CHIPSET_APOLLO_LAKE:
 		case CHIPSET_GEMINI_LAKE:
 		case CHIPSET_JASPER_LAKE:
@@ -2417,6 +2415,7 @@ static int init_ich_default(const struct programmer_cfg *cfg, void *spibar, enum
 	     ich_gen == CHIPSET_400_SERIES_COMET_POINT ||
 	     ich_gen == CHIPSET_500_SERIES_TIGER_POINT ||
 	     ich_gen == CHIPSET_600_SERIES_ALDER_POINT ||
+	     ich_gen == CHIPSET_700_SERIES_RAPTOR_POINT ||
 	     ich_gen == CHIPSET_C740_SERIES_EMMITSBURG)) {
 		msg_pdbg("Enabling hardware sequencing by default for 100+ series PCH.\n");
 		ich_spi_mode = ich_hwseq;
@@ -2460,7 +2459,7 @@ static int init_ich_default(const struct programmer_cfg *cfg, void *spibar, enum
 		memcpy(opaque_hwseq_data, &hwseq_data, sizeof(*opaque_hwseq_data));
 		register_opaque_master(&opaque_master_ich_hwseq, opaque_hwseq_data);
 	} else {
-		register_spi_master(&spi_master_ich9, NULL);
+		register_spi_master(&spi_master_ich, NULL);
 	}
 
 	return 0;
diff --git a/include/flash.h b/include/flash.h
index b7efec1e..aa29da64 100644
--- a/include/flash.h
+++ b/include/flash.h
@@ -148,6 +148,14 @@ enum write_granularity {
  * other flash chips, such as the ENE KB9012 internal flash, work the opposite way.
  */
 #define FEATURE_ERASED_ZERO	(1 << 18)
+/*
+ * Feature indicates that the chip does not require erase before writing:
+ * write operations can set any bit to any value without first doing an erase,
+ * but bulk erase operations may still be supported.
+ *
+ * EEPROMs usually behave this way (compare to Flash, which requires erase),
+ * for example the ST M95M02.
+ */
 #define FEATURE_NO_ERASE	(1 << 19)
 
 #define FEATURE_WRSR_EXT2	(1 << 20)
diff --git a/include/flashchips.h b/include/flashchips.h
index a43a0f99..0c1a8dcb 100644
--- a/include/flashchips.h
+++ b/include/flashchips.h
@@ -344,9 +344,12 @@
 #define FUDAN_FM25F01		0x3111
 #define FUDAN_FM25F02		0x3112	/* Same as FM25F02A */
 #define FUDAN_FM25F04		0x3113	/* Same as FM25F04A */
+#define FUDAN_FM25Q04		0x4013
 #define FUDAN_FM25Q08		0x4014
 #define FUDAN_FM25Q16		0x4015
 #define FUDAN_FM25Q32		0x4016
+#define FUDAN_FM25Q64		0x4017
+#define FUDAN_FM25Q128		0x4018
 
 #define FUJITSU_ID		0x04	/* Fujitsu */
 #define FUJITSU_MBM29DL400BC	0x0F
@@ -397,6 +400,9 @@
 #define GIGADEVICE_GD25VQ41B	0x4213  /* Same as GD25VQ40C, can be distinguished by SFDP */
 #define GIGADEVICE_GD25VQ80C	0x4214
 #define GIGADEVICE_GD25VQ16C	0x4215
+#define GIGADEVICE_GD25F64F	0x4317
+#define GIGADEVICE_GD25F128F	0x4318
+#define GIGADEVICE_GD25F256F	0x4319
 #define GIGADEVICE_GD25LQ40	0x6013
 #define GIGADEVICE_GD25LQ80	0x6014
 #define GIGADEVICE_GD25LQ16	0x6015
@@ -404,9 +410,12 @@
 #define GIGADEVICE_GD25LQ64	0x6017	/* Same as GD25LQ64B (which is faster) */
 #define GIGADEVICE_GD25LQ128CD	0x6018
 #define GIGADEVICE_GD25LQ255E	0x6019
+#define GIGADEVICE_GD25LB512MF	0x601A  /* Same as GD25LR512MF */
 #define GIGADEVICE_GD25LF128E	0x6318
+#define GIGADEVICE_GD25LF256F	0x6319
+#define GIGADEVICE_GD25LF512MF	0x631A
 #define GIGADEVICE_GD25LR256E	0x6719
-#define GIGADEVICE_GD25LR512ME	0x671A
+#define GIGADEVICE_GD25LR512ME	0x671A	/*	Same as GD25LB512ME */
 #define GIGADEVICE_GD25WQ80E	0x6514
 #define GIGADEVICE_GD29GL064CAB	0x7E0601
 
@@ -534,12 +543,13 @@
 #define MACRONIX_MX25U3235E	0x2536	/* Same as MX25U6435F */
 #define MACRONIX_MX25U6435E	0x2537	/* Same as MX25U6435F */
 #define MACRONIX_MX25U12835E	0x2538	/* Same as MX25U12835F */
-#define MACRONIX_MX25U25635F	0x2539     /* Same as MX25U25643G */
+#define MACRONIX_MX25U25635F	0x2539     /* Same as MX25U25643G, MX25U25645G */
 #define MACRONIX_MX25U51245G	0x253a
 #define MACRONIX_MX25L3235D	0x5E16	/* MX25L3225D/MX25L3235D/MX25L3237D */
 #define MACRONIX_MX25L6495F	0x9517
 #define MACRONIX_MX25L3255E	0x9e16
 #define MACRONIX_MX77L25650F	0x7519
+#define MACRONIX_MX77U51250F	0x753A
 #define MACRONIX_MX25L3239E     0x2536
 
 #define MACRONIX_MX25R1635F	0x2815
@@ -845,16 +855,21 @@
 #define ST_M45PE40		0x4013
 #define ST_M45PE80		0x4014	/* Same as XM25QH80B */
 #define ST_M45PE16		0x4015
-#define XMC_XM25QH64C		0x4017
-#define XMC_XM25QU64C		0x4117
+#define XMC_XM25QH64C		0x4017	/* Same as XM25QH64D */
+#define XMC_XM25QU64C		0x4117	/* Same as XM25LU64C */
 #define XMC_XM25QU80B		0x5014
 #define XMC_XM25QH16C		0x4015	/* Same as XM25QH16D */
+#define XMC_XM25QU16C		0x5015
+#define XMC_XM25QH32C		0x4016	/* Same as XM25QH32D */
+#define XMC_XM25QU32C		0x5016
 #define XMC_XM25QH128A		0x7018
-#define XMC_XM25QH128C		0x4018
-#define XMC_XM25QU128C		0x4118
-#define XMC_XM25QH256C		0x4019
-#define XMC_XM25QU256C		0x4119
+#define XMC_XM25QH128C		0x4018	/* Same as XM25QH128D */
+#define XMC_XM25QU128C		0x4118	/* Same as XM25QU128D */
+#define XMC_XM25QH256C		0x4019	/* Same as XM25QH256D */
+#define XMC_XM25QU256C		0x4119	/* Same as XM25QU256D */
 #define XMC_XM25RU256C		0x4419
+#define XMC_XM25QH512C		0x4020	/* Same as XM25QH512D */
+#define XMC_XM25QU512C		0x4120	/* Same as XM25QU512D */
 #define ST_M25PX80		0x7114
 #define ST_M25PX16		0x7115
 #define ST_M25PX32		0x7116
@@ -1012,6 +1027,7 @@
 #define WINBOND_NEX_W25Q128_W	0x6018	/* W25Q128FW; W25Q128FV in QPI mode */
 #define WINBOND_NEX_W25Q256_W	0x6019	/* W25Q256JW */
 #define WINBOND_NEX_W25Q16JV_M	0x7015	/* W25Q16JV_M (QE=0) */
+#define WINBOND_NEX_W25Q32JV_M	0x7016	/* W25Q32JV_M (QE=0) */
 #define WINBOND_NEX_W25Q64JV	0x7017	/* W25Q64JV */
 #define WINBOND_NEX_W25Q128_V_M	0x7018	/* W25Q128JVSM */
 #define WINBOND_NEX_W25Q256JV_M	0x7019	/* W25Q256JV_M (QE=0) */
diff --git a/include/programmer.h b/include/programmer.h
index de0b76a6..bedf0e25 100644
--- a/include/programmer.h
+++ b/include/programmer.h
@@ -367,6 +367,7 @@ enum ich_chipset {
 	CHIPSET_400_SERIES_COMET_POINT,
 	CHIPSET_500_SERIES_TIGER_POINT,
 	CHIPSET_600_SERIES_ALDER_POINT,
+	CHIPSET_700_SERIES_RAPTOR_POINT,
 	CHIPSET_APOLLO_LAKE,
 	CHIPSET_GEMINI_LAKE,
 	CHIPSET_JASPER_LAKE,
diff --git a/libflashrom.map b/libflashrom.map
index f4e3b0c4..ce247f2b 100644
--- a/libflashrom.map
+++ b/libflashrom.map
@@ -1,7 +1,5 @@
 LIBFLASHROM_1.0 {
   global:
-    flashrom_board_info;
-    flashrom_chipset_info;
     flashrom_data_free;
     flashrom_flag_get;
     flashrom_flag_set;
@@ -10,7 +8,6 @@ LIBFLASHROM_1.0 {
     flashrom_flash_getinfo;
     flashrom_flash_probe;
     flashrom_flash_release;
-    flashrom_flashchip_info;
     flashrom_image_read;
     flashrom_image_verify;
     flashrom_image_write;
diff --git a/linux_mtd.c b/linux_mtd.c
index eea0cf22..0cb2330b 100644
--- a/linux_mtd.c
+++ b/linux_mtd.c
@@ -49,7 +49,7 @@ static int read_sysfs_string(const char *sysfs_path, const char *filename, char
 	int i;
 	size_t bytes_read;
 	FILE *fp;
-	char path[strlen(LINUX_MTD_SYSFS_ROOT) + 32];
+	char path[sizeof(LINUX_MTD_SYSFS_ROOT) + 31];
 
 	snprintf(path, sizeof(path), "%s/%s", sysfs_path, filename);
 
diff --git a/meson.build b/meson.build
index 2124cf0a..fb54b050 100644
--- a/meson.build
+++ b/meson.build
@@ -1,4 +1,4 @@
-project('flashromutils', 'c',
+project('flashrom', 'c',
   version : run_command('cat', 'VERSION', check: true).stdout().strip(),
   license : 'GPL-2.0',
   meson_version : '>=0.56.0',
@@ -179,6 +179,13 @@ libusb1    = dependency('libusb-1.0', required : group_usb)
 libftdi1   = dependency('libftdi1', required : group_ftdi)
 libjaylink = dependency('libjaylink', required : group_jlink, version : '>=0.3.0')
 
+# ECAM is supported in libpci after 3.13.0
+if libpci.version().version_compare('>=3.13.0')
+    add_project_arguments('-DCONFIG_USE_LIBPCI_ECAM=1', language: 'c')
+else
+    add_project_arguments('-DCONFIG_USE_LIBPCI_ECAM=0', language: 'c')
+endif
+
 if host_machine.system() == 'windows'
   # Specifying an include_path that doesn't exist is an error,
   # but we only use this if the library is found in the same directory.
diff --git a/meson_cross/i586_djgpp_dos.txt b/meson_cross/i586_djgpp_dos.txt
index 3d97aab7..a1f2401d 100644
--- a/meson_cross/i586_djgpp_dos.txt
+++ b/meson_cross/i586_djgpp_dos.txt
@@ -30,6 +30,8 @@ default_library = 'static'
 [project options]
 tests = 'disabled'
 ich_descriptors_tool = 'disabled'
+# DOS time resolution is only about 50ms
+delay_minimum_sleep_us = 50000
 
 [properties]
 sys_root = '/usr/local/djgpp'
diff --git a/meson_options.txt b/meson_options.txt
index 8a04114d..f5e2800f 100644
--- a/meson_options.txt
+++ b/meson_options.txt
@@ -22,6 +22,6 @@ option('man-pages', type : 'feature', value : 'auto', description : 'build the m
 option('documentation', type : 'feature', value : 'auto', description : 'build the html documentation')
 option('ni845x_search_path', type : 'string', value : 'C:\Program Files (x86)\National Instruments\Ni-845x\MS Visual C',
        description : 'Path to search for the proprietary ni845x library and header (32-bit Windows only)')
-option('delay_minimum_sleep_us', type : 'integer', min : 0, value : 100000,
+option('delay_minimum_sleep_us', type : 'integer', min : 0, value : 100,
        description : 'Minimum time in microseconds to suspend execution for (rather than polling) when a delay is required.'
                    + ' Larger values may perform better on machines with low timer resolution, at the cost of increased power.')
diff --git a/stlinkv3_spi.c b/stlinkv3_spi.c
index f9046df0..29aa8d3c 100644
--- a/stlinkv3_spi.c
+++ b/stlinkv3_spi.c
@@ -115,7 +115,7 @@ enum spi_nss_level {
 #define USB_TIMEOUT_IN_MS					5000
 
 static const struct dev_entry devs_stlinkv3_spi[] = {
-	{0x0483, 0x374E, NT, "STMicroelectronics", "STLINK-V3E"},
+	{0x0483, 0x374E, BAD, "STMicroelectronics", "STLINK-V3E"},
 	{0x0483, 0x374F, OK, "STMicroelectronics", "STLINK-V3S"},
 	{0x0483, 0x3753, OK, "STMicroelectronics", "STLINK-V3 dual VCP"},
 	{0x0483, 0x3754, NT, "STMicroelectronics", "STLINK-V3 no MSD"},
@@ -498,8 +498,14 @@ static int stlinkv3_spi_init(const struct programmer_cfg *cfg)
 								devs_stlinkv3_spi[devIndex].vendor_id,
 								devs_stlinkv3_spi[devIndex].device_id,
 								param_str);
-		if (stlinkv3_handle)
+		if (stlinkv3_handle) {
+			if (devs_stlinkv3_spi[devIndex].status == BAD) {
+				msg_perr("The STLINK-V3 Mini/MiniE does not support the bridge interface\n");
+				free(param_str);
+				goto init_err_exit;
+			}
 			break;
+		}
 		devIndex++;
 	}
 
diff --git a/subprojects/cmocka.wrap b/subprojects/cmocka.wrap
index 21e84f99..4d1cf272 100644
--- a/subprojects/cmocka.wrap
+++ b/subprojects/cmocka.wrap
@@ -5,6 +5,4 @@ source_url = https://cmocka.org/files/1.1/cmocka-1.1.5.tar.xz
 source_filename = cmocka-1.1.5.tar.xz
 source_hash = f0ccd8242d55e2fd74b16ba518359151f6f8383ff8aef4976e48393f77bba8b6
 
-patch_url = https://wrapdb.mesonbuild.com/v1/projects/cmocka/1.1.5/3/get_zip
-patch_filename = cmocka-1.1.5-3-wrap.zip
-patch_hash = 81ce48613680d3c3a0b396ac570c852b290adcd18202fb16aaf703a9493f4348
+patch_directory = cmocka-1.1.5
diff --git a/subprojects/packagefiles/cmocka-1.1.5/LICENSE.build b/subprojects/packagefiles/cmocka-1.1.5/LICENSE.build
new file mode 100644
index 00000000..ec288041
--- /dev/null
+++ b/subprojects/packagefiles/cmocka-1.1.5/LICENSE.build
@@ -0,0 +1,19 @@
+Copyright (c) 2018 The Meson development team
+
+Permission is hereby granted, free of charge, to any person obtaining a copy
+of this software and associated documentation files (the "Software"), to deal
+in the Software without restriction, including without limitation the rights
+to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
+copies of the Software, and to permit persons to whom the Software is
+furnished to do so, subject to the following conditions:
+
+The above copyright notice and this permission notice shall be included in all
+copies or substantial portions of the Software.
+
+THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
+AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
+OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
+SOFTWARE.
diff --git a/subprojects/packagefiles/cmocka-1.1.5/meson.build b/subprojects/packagefiles/cmocka-1.1.5/meson.build
new file mode 100644
index 00000000..16245d1c
--- /dev/null
+++ b/subprojects/packagefiles/cmocka-1.1.5/meson.build
@@ -0,0 +1,213 @@
+# Copyright © 2018 Intel Corporation
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+project(
+  'cmocka',
+  ['c'],
+  version : '1.1.5',
+  license : 'APLv2',
+  meson_version : '>= 0.48.0',
+  default_options : ['c_std=c99', 'buildtype=debugoptimized'],
+)
+
+lib_version = '0.5.0'
+
+# TODO: pkg-config
+# TODO: cmake-config
+
+inc_include = include_directories('include')
+
+#####################
+# Config Generation #
+#####################
+
+cc_dict = {
+    'compiler': meson.get_compiler('c'),
+    'machine': host_machine,
+    'config_h_subdir': 'private',
+    'native': false
+}
+
+cc_native_dict = {
+    'compiler': meson.get_compiler('c', native: true),
+    'machine': build_machine,
+    'config_h_subdir': 'private_native',
+    'native': true
+}
+
+configurations = [cc_dict, cc_native_dict]
+
+foreach entry : configurations
+  compiler = entry.get('compiler')
+  is_native = entry.get('native')
+  machine = entry.get('machine')
+
+  config = configuration_data()
+
+  if ['gcc', 'clang'].contains(compiler.get_id())
+    add_project_arguments(
+      # I've explicitly skipped the duplicated -W versions when they also test
+      # for the -Werror version
+      compiler.get_supported_arguments(
+        '-Wshadow',
+        '-Wmissing-prototypes',
+        '-Wcast-align',
+        '-Werror=address',
+        '-Werror=strict-prototypes',
+        '-Werror=write-strings',
+        '-Werror=implicit-function-declaration',
+        '-Werror=pointer-arith',
+        '-Werror=declaration-after-statement',
+        '-Werror=return-type',
+        '-Werror=uninitialized',
+        '-Wimplicit-fallthrough',
+        '-Werror=strict-overflow',
+        '-Wstrict-overflow=2',
+        '-Wno-format-zero-length',
+        '-Wformat',
+        '-Werror=format-security',
+        '-Wno-gnu-zero-variadic-macro-arguments',
+        '-fno-common',
+      ),
+      language : ['c'],
+      native: is_native
+    )
+    # We can't test the build type, so we can' add -D_FORTIFY_SOURCE=2 here
+    if machine.system() == 'darwin'
+      if compiler.has_argument('-Wno-deprecated-declarations')
+        add_project_arguments('-Wno-deprecated-declarations', language : ['c'], native: is_native)
+      endif
+    endif
+  elif compiler.get_id() == 'msvc'
+    add_project_arguments(
+      '/D_CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES=1',
+      '/D_CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES_COUNT=1',
+      '/D_CRT_NONSTDC_NO_WARNINGS=1',
+      '/D_CRT_SECURE_NO_WARNINGS=1',
+      language : ['c'],
+      native: is_native
+    )
+  endif
+
+  # TODO: solaris extensions
+
+  foreach h : ['assert.h', 'inttypes.h', 'io.h', 'malloc.h', 'memory.h',
+               'setjmp.h', 'signal.h', 'stdarg.h', 'stddef.h', 'stdint.h',
+               'stdio.h', 'stdlib.h', 'string.h', 'strings.h', 'sys/stat.h',
+               'sys/types.h', 'time.h', 'unistd.h']
+    if compiler.check_header(h)
+      config.set('HAVE_@0@'.format(h.underscorify().to_upper()), 1)
+    endif
+  endforeach
+
+  if config.get('HAVE_TIME_H', 0) == 1
+    if compiler.has_member('struct timespec', 'tv_sec', prefix : '#include <time.h>')
+      config.set('HAVE_STRUCT_TIMESPEC', 1)
+    endif
+  endif
+
+  foreach f : ['calloc', 'exit', 'fprintf', 'free', 'longjmp', 'siglongjmp',
+               'malloc', 'memcpy', 'memset', 'printf', 'setjmp', 'signal',
+               'strsignal', 'strcmp', 'clock_gettime']
+    if compiler.has_function(f)
+      config.set('HAVE_@0@'.format(f.underscorify().to_upper()), 1)
+    endif
+  endforeach
+
+  if machine.system() == 'windows'
+  foreach f : ['_vsnprintf_s', '_vsnprtinf', '_snprintf_s', '_snprintf']
+    if compiler.has_function(f)
+      config.set('HAVE_@0@'.format(f.underscorify().to_upper()), 1)
+    endif
+  endforeach
+  foreach f : ['snprintf', 'vsnprintf']
+    if compiler.has_header_symbol('stdio.h', f)
+      config.set('HAVE_@0@'.format(f.underscorify().to_upper()), 1)
+    endif
+  endforeach
+else
+  foreach f : ['snprintf', 'vsnprintf']
+    if compiler.has_function(f)
+      config.set('HAVE_@0@'.format(f.underscorify().to_upper()), 1)
+    endif
+  endforeach
+endif
+
+  if machine.system() == 'windows'
+    if compiler.compiles('''
+        __declspec(thread) int tls;
+
+        int main(void) {
+          return 0;
+        }''',
+        name : 'Thread Local Storage')
+      config.set('HAVE_MSVC_THREAD_LOCAL_STORAGE', 1)
+    endif
+  else
+    if compiler.compiles('''
+        __thread int tls;
+
+        int main(void) {
+          return 0;
+        }''',
+        name : 'Thread Local Storage')
+      config.set('HAVE_GCC_THREAD_LOCAL_STORAGE', 1)
+    endif
+  endif
+
+  if (config.get('HAVE_TIME_H', 0) == 1 and
+      config.get('HAVE_STRUCT_TIMESPEC', 0) == 1 and
+      config.get('HAVE_CLOCK_GETTIME', 0) == 1)
+    if compiler.has_header_symbol('time.h', 'CLOCK_REALTIME')
+      config.set('HAVE_CLOCK_REALTIME', 1)
+    endif
+  endif
+
+  config.set('WORDS_SIZEOF_VOID_P', compiler.sizeof('void *'))
+  if machine.endian() == 'big'
+    config.set('WORDS_BIGENDIAN', 1)
+  endif
+
+  # Execute subdir to create config.h for this pass
+  # This requires the use of the variable named "config" for configuration_data(),
+  # as this variable is used in each configuration header subdirectory.
+  subdir(entry.get('config_h_subdir'))
+
+endforeach
+
+###########################
+# Subdirectory Processing #
+###########################
+
+subdir('src')
+
+######################
+# Dependency Targets #
+######################
+
+# TODO: doc, include, tests, example
+# Since we're using this as a wrap, and it's a unit test framework we're not
+# going to install it.
+
+cmocka_dep = declare_dependency(
+  link_with : libcmocka,
+  include_directories : inc_include,
+  version : meson.project_version(),
+)
+
+cmocka_native_dep = declare_dependency(
+  link_with : libcmocka_native,
+  include_directories : inc_include,
+  version : meson.project_version(),
+)
diff --git a/subprojects/packagefiles/cmocka-1.1.5/private/meson.build b/subprojects/packagefiles/cmocka-1.1.5/private/meson.build
new file mode 100644
index 00000000..ca5bf09d
--- /dev/null
+++ b/subprojects/packagefiles/cmocka-1.1.5/private/meson.build
@@ -0,0 +1,23 @@
+# Copyright © 2018 Intel Corporation
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+## This file sets the config.h header for standard builds (e.g., not native: true)
+
+config_h = configure_file(
+  configuration : config,
+  output : 'config.h',
+)
+
+inc_private = include_directories('.')
diff --git a/subprojects/packagefiles/cmocka-1.1.5/private_native/meson.build b/subprojects/packagefiles/cmocka-1.1.5/private_native/meson.build
new file mode 100644
index 00000000..81b923cf
--- /dev/null
+++ b/subprojects/packagefiles/cmocka-1.1.5/private_native/meson.build
@@ -0,0 +1,23 @@
+# Copyright © 2018 Intel Corporation
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+## This file sets the config.h header for standard builds (e.g., not native: true)
+
+config_h_native = configure_file(
+  configuration : config,
+  output : 'config.h',
+)
+
+inc_private_native = include_directories('.')
diff --git a/subprojects/packagefiles/cmocka-1.1.5/src/meson.build b/subprojects/packagefiles/cmocka-1.1.5/src/meson.build
new file mode 100644
index 00000000..e4690490
--- /dev/null
+++ b/subprojects/packagefiles/cmocka-1.1.5/src/meson.build
@@ -0,0 +1,46 @@
+# Copyright © 2018 Intel Corporation
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# cmocka rather annoyingly uses different standards for different platforms.
+_overrides = []
+if host_machine.system() != 'windows'
+  _overrides += 'c_std=gnu99'
+endif
+
+libcmocka = library(
+  'cmocka',
+  ['cmocka.c'],
+  c_args : '-DHAVE_CONFIG_H=1',
+  include_directories : [inc_include, inc_private],
+  vs_module_defs : 'cmocka.def',
+  soversion : host_machine.system() != 'windows' ? lib_version.split('.')[0] : '',
+  version : lib_version,
+  install : false,
+  override_options : _overrides,
+  build_by_default: false,
+)
+
+libcmocka_native = library(
+  'cmocka_native',
+  ['cmocka.c'],
+  c_args : '-DHAVE_CONFIG_H=1',
+  include_directories : [inc_include, inc_private_native],
+  vs_module_defs : 'cmocka.def',
+  soversion : build_machine.system() != 'windows' ? lib_version.split('.')[0] : '',
+  version : lib_version,
+  install : false, # Cannot install native targets in cross builds
+  override_options : _overrides,
+  native: true,
+  build_by_default: false,
+)
diff --git a/test_build.sh b/test_build.sh
index ee864963..8c041f0c 100755
--- a/test_build.sh
+++ b/test_build.sh
@@ -5,13 +5,6 @@ set -e
 
 is_scan_build_env=0
 
-make_programmer_opts="INTERNAL INTERNAL_X86 SERPROG RAYER_SPI RAIDEN_DEBUG_SPI PONY_SPI NIC3COM		\
-		      GFXNVIDIA SATASII ATAHPT ATAVIA ATAPROMISE FT2232_SPI USBBLASTER_SPI MSTARDDC_SPI	\
-		      PICKIT2_SPI STLINKV3_SPI PARADE_LSPCON MEDIATEK_I2C_SPI REALTEK_MST_I2C_SPI DUMMY	\
-		      DRKAISER NICREALTEK NICNATSEMI NICINTEL NICINTEL_SPI NICINTEL_EEPROM OGP_SPI	\
-		      BUSPIRATE_SPI DEDIPROG DEVELOPERBOX_SPI SATAMV LINUX_MTD LINUX_SPI IT8212		\
-		      CH341A_SPI CH347_SPI DIGILENT_SPI DIRTYJTAG_SPI JLINK_SPI ASM106X"
-
 meson_programmer_opts="all auto group_ftdi group_i2c group_jlink group_pci group_serial group_usb	\
 			atahpt atapromise atavia buspirate_spi ch341a_spi ch347_spi dediprog		\
 			developerbox_spi digilent_spi dirtyjtag_spi drkaiser dummy ft2232_spi		\
@@ -31,24 +24,6 @@ run_linter() {
 }
 
 
-build_make () {
-	make clean
-	make -j $(nproc) CONFIG_EVERYTHING=yes
-
-	# In case of clang analyzer we don't want to run it on
-	# each programmer individually. Thus, just return here.
-	if [ ${is_scan_build_env} -eq 1 ]; then
-		return
-	fi
-
-	for option in ${make_programmer_opts}; do
-		echo "Building ${option}"
-		make clean
-		make -j $(nproc) CONFIG_NOTHING=yes CONFIG_${option}=yes
-	done
-}
-
-
 build_meson () {
 	build_dir=out
 	meson_opts="-Dtests=enabled -Dman-pages=enabled -Ddocumentation=enabled"
@@ -74,5 +49,4 @@ build_meson () {
 
 run_linter
 
-build_make
 build_meson
diff --git a/tests/chip.c b/tests/chip.c
index 114aaa3e..b3ed1ebb 100644
--- a/tests/chip.c
+++ b/tests/chip.c
@@ -27,6 +27,7 @@
 
 #include <include/test.h>
 #include <stdio.h>
+#include <stdlib.h>
 #include <string.h>
 
 #include "tests.h"
@@ -136,6 +137,25 @@ static const struct flashchip chip_8MiB = {
 	 }},
 };
 
+/* Chip expected to be processed with dummyflasher, so using real op functions. */
+static const struct flashchip chip_no_erase = {
+	.vendor		= "aklm&dummyflasher",
+	.total_size	= 16 * 1024,
+	.tested		= TEST_OK_PREW,
+	.read		= SPI_CHIP_READ,
+	.write		= SPI_CHIP_WRITE256,
+	.page_size	= 256,
+	.feature_bits   = FEATURE_NO_ERASE | FEATURE_ERASED_ZERO,
+	.block_erasers  =
+	{
+		{
+			.eraseblocks = { {16 * 1024 * 1024, 1} },
+			/* Special erase fn for chips without erase capability. */
+			.block_erase = SPI_BLOCK_ERASE_EMULATION,
+		}
+	},
+};
+
 /* Setup the struct for W25Q128.V, all values come from flashchips.c */
 static const struct flashchip chip_W25Q128_V = {
 	.vendor		= "aklm&dummyflasher",
@@ -388,6 +408,48 @@ void write_chip_with_dummyflasher_test_success(void **state)
 	free(newcontents);
 }
 
+void write_chip_feature_no_erase(void **state)
+{
+	(void) state; /* unused */
+
+	static struct io_mock_fallback_open_state data = {
+		.noc	= 0,
+		.paths	= { NULL },
+	};
+	const struct io_mock chip_io = {
+		.fallback_open_state = &data,
+	};
+
+	struct flashrom_flashctx flashctx = { 0 };
+	struct flashrom_layout *layout;
+
+	/*
+	 * Tricking the dummyflasher by asking to emulate W25Q128FV but giving to it
+	 * mock chip with FEATURE_NO_ERASE.
+	 * As long as chip size is the same, this is fine.
+	 */
+	struct flashchip mock_chip = chip_no_erase;
+	const char *param_dup = "bus=spi,emulate=W25Q128FV";
+
+	setup_chip(&flashctx, &layout, &mock_chip, param_dup, &chip_io);
+
+	/* See comment in write_chip_test_success */
+	const char *const filename = "-";
+	unsigned long size = mock_chip.total_size * 1024;
+	uint8_t *const newcontents = malloc(size);
+	assert_non_null(newcontents);
+
+	printf("Write chip operation started.\n");
+	assert_int_equal(0, read_buf_from_file(newcontents, size, filename));
+	assert_int_equal(0, flashrom_image_write(&flashctx, newcontents, size, NULL));
+	assert_int_equal(0, flashrom_image_verify(&flashctx, newcontents, size));
+	printf("Write chip operation done.\n");
+
+	teardown(&layout);
+
+	free(newcontents);
+}
+
 void write_nonaligned_region_with_dummyflasher_test_success(void **state)
 {
 	(void) state; /* unused */
diff --git a/tests/dummyflasher.c b/tests/dummyflasher.c
index a7e5f4cb..72698955 100644
--- a/tests/dummyflasher.c
+++ b/tests/dummyflasher.c
@@ -141,6 +141,25 @@ void dummy_all_buses_test_success(void **state)
 	run_basic_lifecycle(state, &dummy_io, &programmer_dummy, "bus=parallel+lpc+spi");
 }
 
+void dummy_freq_param_init(void **state)
+{
+	struct io_mock_fallback_open_state dummy_fallback_open_state = {
+		.noc = 0,
+		.paths = { NULL },
+	};
+	const struct io_mock dummy_io = {
+		.fallback_open_state = &dummy_fallback_open_state,
+	};
+
+	run_basic_lifecycle(state, &dummy_io, &programmer_dummy, "bus=spi,freq=12Hz");
+	run_basic_lifecycle(state, &dummy_io, &programmer_dummy, "bus=spi,freq=123KHz");
+	run_basic_lifecycle(state, &dummy_io, &programmer_dummy, "bus=spi,freq=345MHz");
+	run_basic_lifecycle(state, &dummy_io, &programmer_dummy, "bus=spi,freq=8000MHz");
+	/* Valid values for freq param are within the range [1Hz, 8000Mhz] */
+	run_init_error_path(state, &dummy_io, &programmer_dummy, "bus=spi,freq=0Hz", 0x1);
+	run_init_error_path(state, &dummy_io, &programmer_dummy, "bus=spi,freq=8001Mhz", 0x1);
+}
+
 #else
 	SKIP_TEST(dummy_basic_lifecycle_test_success)
 	SKIP_TEST(dummy_probe_lifecycle_test_success)
@@ -150,4 +169,5 @@ void dummy_all_buses_test_success(void **state)
 	SKIP_TEST(dummy_init_success_unhandled_param_test_success)
 	SKIP_TEST(dummy_null_prog_param_test_success)
 	SKIP_TEST(dummy_all_buses_test_success)
+	SKIP_TEST(dummy_freq_param_init)
 #endif /* CONFIG_DUMMY */
diff --git a/tests/include/test.h b/tests/include/test.h
index 13d1038f..50f9464d 100644
--- a/tests/include/test.h
+++ b/tests/include/test.h
@@ -31,6 +31,9 @@
 
 #define MOCK_FD (0x10ec)
 
+#define SKIP_TEST(name) \
+	void name (void **state) { skip(); }
+
 #define LOCK_FILE "/run/lock/firmware_utility_lock"
 #define SUSPEND_ANNOUNCED_FILE "/run/power_manager/power/suspend_announced"
 
diff --git a/tests/lifecycle.h b/tests/lifecycle.h
index 69f11196..b4c2fbed 100644
--- a/tests/lifecycle.h
+++ b/tests/lifecycle.h
@@ -28,9 +28,6 @@
 #include "programmer.h"
 #include "spi.h"
 
-#define SKIP_TEST(name) \
-	void name (void **state) { skip(); }
-
 void run_basic_lifecycle(void **state, const struct io_mock *io,
 		const struct programmer_entry *prog, const char *param);
 
diff --git a/tests/tests.c b/tests/tests.c
index 893fd0e0..f800b475 100644
--- a/tests/tests.c
+++ b/tests/tests.c
@@ -474,6 +474,7 @@ int main(int argc, char *argv[])
 		cmocka_unit_test(dummy_init_success_unhandled_param_test_success),
 		cmocka_unit_test(dummy_null_prog_param_test_success),
 		cmocka_unit_test(dummy_all_buses_test_success),
+		cmocka_unit_test(dummy_freq_param_init),
 		cmocka_unit_test(nicrealtek_basic_lifecycle_test_success),
 		cmocka_unit_test(raiden_debug_basic_lifecycle_test_success),
 		cmocka_unit_test(raiden_debug_targetAP_basic_lifecycle_test_success),
@@ -511,6 +512,7 @@ int main(int argc, char *argv[])
 		cmocka_unit_test(read_chip_with_dummyflasher_test_success),
 		cmocka_unit_test(write_chip_test_success),
 		cmocka_unit_test(write_chip_with_dummyflasher_test_success),
+		cmocka_unit_test(write_chip_feature_no_erase),
 		cmocka_unit_test(write_nonaligned_region_with_dummyflasher_test_success),
 		cmocka_unit_test(verify_chip_test_success),
 		cmocka_unit_test(verify_chip_with_dummyflasher_test_success),
diff --git a/tests/tests.h b/tests/tests.h
index 3841d20c..513b95bc 100644
--- a/tests/tests.h
+++ b/tests/tests.h
@@ -52,6 +52,7 @@ void dummy_init_success_invalid_param_test_success(void **state);
 void dummy_init_success_unhandled_param_test_success(void **state);
 void dummy_null_prog_param_test_success(void **state);
 void dummy_all_buses_test_success(void **state);
+void dummy_freq_param_init(void **state);
 void nicrealtek_basic_lifecycle_test_success(void **state);
 void raiden_debug_basic_lifecycle_test_success(void **state);
 void raiden_debug_targetAP_basic_lifecycle_test_success(void **state);
@@ -85,6 +86,7 @@ void read_chip_test_success(void **state);
 void read_chip_with_dummyflasher_test_success(void **state);
 void write_chip_test_success(void **state);
 void write_chip_with_dummyflasher_test_success(void **state);
+void write_chip_feature_no_erase(void **state);
 void write_nonaligned_region_with_dummyflasher_test_success(void **state);
 void verify_chip_test_success(void **state);
 void verify_chip_with_dummyflasher_test_success(void **state);
diff --git a/util/ich_descriptors_tool/Makefile b/util/ich_descriptors_tool/Makefile
deleted file mode 100644
index aa1b696c..00000000
--- a/util/ich_descriptors_tool/Makefile
+++ /dev/null
@@ -1,83 +0,0 @@
-#
-# This file is part of the flashrom project.
-#
-# This Makefile works standalone, but it is usually called from the main
-# Makefile in the flashrom directory.
-
-include ../../Makefile.include
-
-PROGRAM=ich_descriptors_tool
-EXTRAINCDIRS = ../../ .
-DEPPATH = .dep
-OBJATH = .obj
-SHAREDSRC = ich_descriptors.c
-SHAREDSRCDIR = ../..
-# If your compiler spits out excessive warnings, run make WARNERROR=no
-# You shouldn't have to change this flag.
-WARNERROR ?= yes
-
-SRC = $(wildcard *.c)
-
-# If the user has specified custom CFLAGS, all CFLAGS settings below will be
-# completely ignored by gnumake.
-CFLAGS ?= -Os -Wall -Wshadow
-override CFLAGS += -I$(SHAREDSRCDIR)/include
-
-# Auto determine HOST_OS and TARGET_OS if they are not set as argument
-HOST_OS ?= $(shell uname)
-TARGET_OS := $(call c_macro_test, ../../Makefile.d/os_test.h)
-
-ifeq ($(findstring MINGW, $(HOST_OS)), MINGW)
-# Explicitly set CC = gcc on MinGW, otherwise: "cc: command not found".
-CC = gcc
-endif
-
-ifeq ($(TARGET_OS), DOS)
-EXEC_SUFFIX := .exe
-# DJGPP has odd uint*_t definitions which cause lots of format string warnings.
-CFLAGS += -Wno-format
-endif
-
-ifeq ($(TARGET_OS), MinGW)
-EXEC_SUFFIX := .exe
-# Some functions provided by Microsoft do not work as described in C99 specifications. This macro fixes that
-# for MinGW. See http://sourceforge.net/p/mingw-w64/wiki2/printf%20and%20scanf%20family/
-CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
-endif
-
-ifeq ($(WARNERROR), yes)
-CFLAGS += -Werror
-endif
-
-
-FLASHROM_CFLAGS += -MMD -MP -MF $(DEPPATH)/$(@F).d
-# enables functions that populate the descriptor structs from plain binary dumps
-FLASHROM_CFLAGS += -D ICH_DESCRIPTORS_FROM_DUMP_ONLY
-FLASHROM_CFLAGS += $(patsubst %,-I%,$(EXTRAINCDIRS))
-
-OBJ = $(OBJATH)/$(SRC:%.c=%.o)
-
-SHAREDOBJ = $(OBJATH)/$(notdir $(SHAREDSRC:%.c=%.o))
-
-all:$(PROGRAM)$(EXEC_SUFFIX)
-
-$(OBJ): $(OBJATH)/%.o : %.c
-	$(CC) $(CFLAGS) $(CPPFLAGS) $(FLASHROM_CFLAGS) -o $@ -c $<
-
-# this enables us to share source files without simultaneously sharing .o files
-# with flashrom, which would lead to unexpected results (w/o running make clean)
-$(SHAREDOBJ): $(OBJATH)/%.o : $(SHAREDSRCDIR)/%.c
-	$(CC) $(CFLAGS) $(CPPFLAGS) $(FLASHROM_CFLAGS) -o $@ -c $<
-
-$(PROGRAM)$(EXEC_SUFFIX): $(OBJ) $(SHAREDOBJ)
-	$(CC) $(LDFLAGS) -o $(PROGRAM)$(EXEC_SUFFIX) $(OBJ) $(SHAREDOBJ)
-
-# We don't use EXEC_SUFFIX here because we want to clean everything.
-clean:
-	rm -f $(PROGRAM) $(PROGRAM).exe
-	rm -rf $(DEPPATH) $(OBJATH)
-
-# Include the dependency files.
--include $(shell mkdir -p $(DEPPATH) $(OBJATH) 2>/dev/null) $(wildcard $(DEPPATH)/*)
-
-.PHONY: all clean
diff --git a/util/ich_descriptors_tool/ich_descriptors_tool.c b/util/ich_descriptors_tool/ich_descriptors_tool.c
index 09587f75..ec77a882 100644
--- a/util/ich_descriptors_tool/ich_descriptors_tool.c
+++ b/util/ich_descriptors_tool/ich_descriptors_tool.c
@@ -140,6 +140,7 @@ static void usage(char *argv[], const char *error)
 "\t- \"400\" or \"comet\" for Intel's 400 series chipsets.\n"
 "\t- \"500\" or \"tiger\" for Intel's 500 series chipsets.\n"
 "\t- \"600\" or \"alder\" for Intel's 600 series chipsets.\n"
+"\t- \"700\" or \"raptor\" for Intel's 700 series chipsets.\n"
 "If '-d' is specified some regions such as the BIOS image as seen by the CPU or\n"
 "the GbE blob that is required to initialize the GbE are also dumped to files.\n",
 	argv[0], argv[0]);
@@ -237,8 +238,12 @@ int main(int argc, char *argv[])
 		else if ((strcmp(csn, "500") == 0) ||
 			 (strcmp(csn, "tiger") == 0))
 			cs = CHIPSET_500_SERIES_TIGER_POINT;
-		else if (strcmp(csn, "600") == 0)
+		else if ((strcmp(csn, "600") == 0) ||
+			 (strcmp(csn, "alder") == 0))
 			cs = CHIPSET_600_SERIES_ALDER_POINT;
+		else if ((strcmp(csn, "700") == 0) ||
+			 (strcmp(csn, "raptor") == 0))
+			cs = CHIPSET_700_SERIES_RAPTOR_POINT;
 		else if (strcmp(csn, "apollo") == 0)
 			cs = CHIPSET_APOLLO_LAKE;
 		else if (strcmp(csn, "gemini") == 0)
diff --git a/writeprotect.c b/writeprotect.c
index 411089de..964c3112 100644
--- a/writeprotect.c
+++ b/writeprotect.c
@@ -482,7 +482,7 @@ static int set_wp_mode(struct wp_bits *bits, const enum flashrom_wp_mode mode)
 
 	case FLASHROM_WP_MODE_HARDWARE:
 		if (!bits->srp_bit_present)
-			return FLASHROM_WP_ERR_CHIP_UNSUPPORTED;
+			return FLASHROM_WP_ERR_MODE_UNSUPPORTED;
 
 		bits->srl = 0;
 		bits->srp = 1;
```

