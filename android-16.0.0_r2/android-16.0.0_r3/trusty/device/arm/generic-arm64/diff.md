```diff
diff --git a/project/el3spmc/tos_fw_config.dts b/project/el3spmc/tos_fw_config.dts
index 86a0760..87b3e3b 100644
--- a/project/el3spmc/tos_fw_config.dts
+++ b/project/el3spmc/tos_fw_config.dts
@@ -17,8 +17,9 @@
 	ffa-version = <0x00010002>; /* 31:16 - Major, 15:0 - Minor */
 	id = <0x8001>;
 	uuid = <0xf025ee40 0x4c30bca2 0x73a14c8c 0xf18a7dc5>,
-	       <0x9120b8c5 0xbb48fed4 0x244de7b7 0xbe28bb6e>;
+	       <0xb52860c6 0xa14a9824 0xda77e79d 0xf0ab2261>;
 	messaging-method = <0x00000201>; /* Can receive SEND_DIRECT_REQ/DIRECT_REQ2 only */
+	vm-availability-messages = <3>;
 	exception-level = <S_EL1>;
 	execution-state = <0>;
 	execution-ctx-count = <32>; /* Must match PLATFORM_CORE_COUNT */
diff --git a/project/hafnium/trusty.dts b/project/hafnium/trusty.dts
index c405f83..176384f 100644
--- a/project/hafnium/trusty.dts
+++ b/project/hafnium/trusty.dts
@@ -22,6 +22,7 @@
     xlat-granule = <0>; /* 4KiB */
 
     messaging-method = <0x00000201>; /* DIRECT_REQ and DIRECT_REQ2 message receive only */
+    vm-availability-messages = <3>;
 
     ns-interrupts-action = <1>; /* Managed exit is supported */
     /* Trusty reschedules the current thread on an IRQ but not a FIQ */
diff --git a/project/linux-inc.mk b/project/linux-inc.mk
index 11bc797..4fee445 100644
--- a/project/linux-inc.mk
+++ b/project/linux-inc.mk
@@ -16,169 +16,76 @@
 
 # Inputs:
 # LINUX_ARCH contains the architecture to build for (Global)
+# ANDROID_HOST_BINDIR is the path to the Android host binaries
+# ANDROID_RAMDISK is the path to the Android ramdisk.img
+# KERNEL_BUILD_ARTIFACTS kernel artifacts location (Env)
+#
 # Outputs:
 # LINUX_BUILD_DIR contains the path to the built linux kernel sources
 # LINUX_IMAGE path of the final linux image target
+# LINUX_RAMDISK_IMAGE path of the final ramdisk image
 
 # This Makefile will build the Linux kernel with our configuration.
 
-LINUX_PREBUILTS_VERSION := 6.12
-LINUX_PREBUILTS_IMAGE := \
-	kernel/prebuilts/${LINUX_PREBUILTS_VERSION}/${LINUX_ARCH}/kernel-${LINUX_PREBUILTS_VERSION}
+# Save the linux kernel paths in order to rebuild if they change.
+LINUX_BUILD_DIR_DEFINES := KERNEL_BUILD_ARTIFACTS=\"$(subst $(SPACE),_,$(KERNEL_BUILD_ARTIFACTS))\"
 
-LINUX_BUILD_DIR := $(abspath $(BUILDDIR)/linux-build)
-ifndef LINUX_ARCH
-	$(error LINUX_ARCH must be specified)
-endif
+LINUX_BUILD_DIR_CONFIG = $(BUILDDIR)/linux-build.config
 
-LINUX_IMAGE := $(LINUX_BUILD_DIR)/arch/$(LINUX_ARCH)/boot/Image
-LINUX_RAMDISK_IMAGE :=
+$(LINUX_BUILD_DIR_CONFIG): LINUX_BUILD_DIR_DEFINES := $(LINUX_BUILD_DIR_DEFINES)
+$(LINUX_BUILD_DIR_CONFIG): configheader
+	@$(call INFO_DONE,linux build dir,generating config file,$@)
+	@$(call MAKECONFIGHEADER,$@,LINUX_BUILD_DIR_DEFINES)
 
-ifeq (,$(wildcard $(LINUX_PREBUILTS_IMAGE)))
-ifeq ($(LINUX_ARCH),arm)
-LINUX_CLANG_TRIPLE := $(LINUX_ARCH)-linux-gnueabi-
-else
-LINUX_CLANG_TRIPLE := $(LINUX_ARCH)-linux-gnu-
-endif
+ifneq (,$(KERNEL_BUILD_ARTIFACTS))
+# Use linux kernel build artifacts if requested (e.g. for a chained build).
 
-LINUX_SRC := $(call FIND_EXTERNAL,linux)
-LINUX_CONFIG_DIR = $(LINUX_SRC)/arch/$(LINUX_ARCH)/configs
-LINUX_TMP_DEFCONFIG := $(LINUX_CONFIG_DIR)/tmp_defconfig
+$(info Using linux kernel KERNEL_BUILD_ARTIFACTS at $(KERNEL_BUILD_ARTIFACTS))
+LINUX_PREBUILTS_IMAGE := $(KERNEL_BUILD_ARTIFACTS)/Image
+LINUX_PREBUILTS_MODULES_DIRS := \
+	$(KERNEL_BUILD_ARTIFACTS) \
 
-# Check if the Linux sources have the Trusty drivers in-tree
-LINUX_TRUSTY_INTREE := $(wildcard $(LINUX_SRC)/drivers/trusty)
-
-# Preserve compatibility with architectures without GKI
-ifeq (,$(wildcard $(LINUX_CONFIG_DIR)/gki_defconfig))
-LINUX_DEFCONFIG_FRAGMENTS := \
-	$(LINUX_CONFIG_DIR)/trusty_qemu_defconfig \
-
-else
-LINUX_DEFCONFIG_FRAGMENTS := \
-	$(LINUX_CONFIG_DIR)/gki_defconfig \
-	$(if $(LINUX_TRUSTY_INTREE),$(LINUX_CONFIG_DIR)/trusty_qemu_defconfig.fragment) \
-	trusty/device/arm/generic-arm64/project/linux/disable_sig_protect.fragment
-
-endif
-
-ifeq (,$(LINUX_TRUSTY_INTREE))
-LINUX_DEFCONFIG_FRAGMENTS += \
-	linux/common-modules/trusty/system_heap.fragment \
-	linux/common-modules/trusty/trusty_defconfig.fragment \
-	linux/common-modules/trusty/trusty_virtio_poll_vqueues.fragment \
-	linux/common-modules/virtual-device/aarch64.fragment \
-	linux/common-modules/virtual-device/virtual_device_core.fragment \
-
-ifeq (true,$(call TOBOOL,$(LIB_SM_WITH_FFA_LOOP)))
-LINUX_ENABLE_FFA_TRANSPORT ?= true
-LINUX_ENABLE_SMC_TRANSPORT ?= false
 else
-LINUX_ENABLE_FFA_TRANSPORT ?= false
-LINUX_ENABLE_SMC_TRANSPORT ?= true
-endif
+# Use linux kernel prebuilts
 
-ifeq (true,$(call TOBOOL,$(LINUX_ENABLE_FFA_TRANSPORT)))
-LINUX_DEFCONFIG_FRAGMENTS += \
-	linux/common-modules/trusty/arm_ffa.fragment \
+$(info Using linux kernel prebuilts)
+LINUX_PREBUILTS_VERSION := 6.12
+LINUX_PREBUILTS_IMAGE := \
+	kernel/prebuilts/${LINUX_PREBUILTS_VERSION}/${LINUX_ARCH}/kernel-${LINUX_PREBUILTS_VERSION}
+LINUX_PREBUILTS_MODULES_DIRS := \
+	kernel/prebuilts/$(LINUX_PREBUILTS_VERSION)/arm64 \
+	kernel/prebuilts/common-modules/trusty/$(LINUX_PREBUILTS_VERSION)/arm64 \
+	kernel/prebuilts/common-modules/virtual-device/$(LINUX_PREBUILTS_VERSION)/arm64 \
 
 endif
-ifeq (false,$(call TOBOOL,$(LINUX_ENABLE_SMC_TRANSPORT)))
-LINUX_DEFCONFIG_FRAGMENTS += \
-	linux/common-modules/trusty/disable_smc_transport.fragment \
 
+LINUX_BUILD_DIR := $(abspath $(BUILDDIR)/linux-build)
+ifndef LINUX_ARCH
+	$(error LINUX_ARCH must be specified)
 endif
-endif
-
-$(LINUX_TMP_DEFCONFIG): LINUX_SRC := $(LINUX_SRC)
-$(LINUX_TMP_DEFCONFIG): $(LINUX_DEFCONFIG_FRAGMENTS)
-	KCONFIG_CONFIG="$@" $(LINUX_SRC)/scripts/kconfig/merge_config.sh -m -r $^
-
-# tmp_defconfig lives in the source tree,
-# so we should delete it after we're done
-.INTERMEDIATE: $(LINUX_TMP_DEFCONFIG)
 
+LINUX_IMAGE := $(LINUX_BUILD_DIR)/arch/$(LINUX_ARCH)/boot/Image
 LINUX_MODULES_LOAD := $(TRUSTY_TOP)/trusty/device/arm/generic-arm64/project/linux/modules.load
-
-ifeq (,$(LINUX_TRUSTY_INTREE))
-# Make a copy of common-modules/trusty because the kernel build system
-# creates files directly in the directory passed to M=
-LINUX_TRUSTY_MODULES_SRC_DIR := linux/common-modules/trusty
-LINUX_TRUSTY_MODULES_COPY_DIR := $(abspath $(BUILDDIR)/linux-trusty-modules)
-LINUX_TRUSTY_MODULES_SRC_FILES := $(shell find $(LINUX_TRUSTY_MODULES_SRC_DIR) -type f)
-LINUX_TRUSTY_MODULES_COPY_FILES := $(patsubst $(LINUX_TRUSTY_MODULES_SRC_DIR)/%,$(LINUX_TRUSTY_MODULES_COPY_DIR)/%,$(LINUX_TRUSTY_MODULES_SRC_FILES))
-$(LINUX_TRUSTY_MODULES_COPY_FILES): $(LINUX_TRUSTY_MODULES_COPY_DIR)/%: $(LINUX_TRUSTY_MODULES_SRC_DIR)/%
-	@$(MKDIR)
-	@cp $< $@
-
-# For now, symlink the Trusty module Kconfig into Kconfig.ext
-# The kernel will import the latter into its build.
-LINUX_KCONFIG_EXT_PREFIX := $(LINUX_TRUSTY_MODULES_COPY_DIR)/
-LINUX_TRUSTY_MODULES_KCONFIG_EXT := $(LINUX_TRUSTY_MODULES_COPY_DIR)/Kconfig.ext
-$(LINUX_TRUSTY_MODULES_KCONFIG_EXT): $(LINUX_TRUSTY_MODULES_COPY_DIR)/drivers/trusty/Kconfig
-	@ln -srf $< $@
-
 LINUX_MODULES_STAGING_DIR := $(abspath $(BUILDDIR)/linux-modules-staging)
 LINUX_RAMDISK_IMAGE := $(abspath $(BUILDDIR)/ramdisk.img)
-endif # LINUX_TRUSTY_INTREE
-
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_TMP_DEFCONFIG := $(LINUX_TMP_DEFCONFIG)
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS := -C $(LINUX_SRC)
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += O=$(LINUX_BUILD_DIR)
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += ARCH=$(LINUX_ARCH)
-
-# Preserve compatibility with older linux kernel
-ifeq (,$(wildcard $(LINUX_SRC)/Documentation/kbuild/llvm.rst))
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): CLANG_BINDIR := $(CLANG_BINDIR)
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += CROSS_COMPILE=$(ARCH_$(LINUX_ARCH)_TOOLCHAIN_PREFIX)
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += CC=$(CLANG_BINDIR)/clang
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += LD=$(CLANG_BINDIR)/ld.lld
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += CLANG_TRIPLE=$(LINUX_CLANG_TRIPLE)
-else
-# Newer linux kernel versions need a newer toolchain (optionally specified in
-# LINUX_CLANG_BINDIR) than the older linux kernel needs or supports.
-LINUX_CLANG_BINDIR ?= $(CLANG_BINDIR)
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): CLANG_BINDIR := $(LINUX_CLANG_BINDIR)
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += CROSS_COMPILE=$(LINUX_CLANG_TRIPLE)
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += LLVM=1
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += LLVM_IAS=1
-endif
-
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += LEX=$(BUILDTOOLS_BINDIR)/flex
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += YACC=$(BUILDTOOLS_BINDIR)/bison
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += BISON_PKGDATADIR=$(BUILDTOOLS_COMMON)/bison
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += HOSTCFLAGS="-isystem$(LINUX_BUILD_TOOLS)/include -B$(CLANG_BINDIR) -B$(CLANG_HOST_SEARCHDIR) --sysroot=$(CLANG_HOST_SYSROOT)"
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += HOSTLDFLAGS="-L$(LINUX_BUILD_TOOLS)/lib64 -rpath $(LINUX_BUILD_TOOLS)/lib64 $(addprefix -L,$(CLANG_HOST_LDDIRS)) -B$(CLANG_BINDIR) -B$(CLANG_HOST_SEARCHDIR) --sysroot=$(CLANG_HOST_SYSROOT)"
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += LIBCLANG_PATH=$(LINUX_CLANG_BINDIR)/../lib/libclang.so
+LINUX_PREBUILTS_MODULES := \
+	$(foreach d,$(LINUX_PREBUILTS_MODULES_DIRS),$(wildcard $(d)/*.ko))
 
 # Put all the paths prepended to $PATH in one variable
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): EXTRA_PATHS := $(CLANG_BINDIR):$(PATH_TOOLS_BINDIR):$(BUILDTOOLS_BINDIR):$(LINUX_BUILD_TOOLS)/bin
-
-$(LINUX_IMAGE): $(LINUX_TMP_DEFCONFIG)
-	PATH=$(EXTRA_PATHS):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) $(notdir $(LINUX_TMP_DEFCONFIG))
-	PATH=$(EXTRA_PATHS):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS)
-
-ifneq (,$(LINUX_RAMDISK_IMAGE))
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += INSTALL_MOD_PATH=$(LINUX_MODULES_STAGING_DIR)
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += INSTALL_MOD_DIR=trusty
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += KCONFIG_EXT_PREFIX=$(LINUX_KCONFIG_EXT_PREFIX)
-
+$(LINUX_RAMDISK_IMAGE): EXTRA_PATHS := $(PATH_TOOLS_BINDIR):$(BUILDTOOLS_BINDIR):$(LINUX_BUILD_TOOLS)/bin:$(ANDROID_HOST_BINDIR)
 $(LINUX_RAMDISK_IMAGE): LINUX_MODULES_STAGING_DIR := $(LINUX_MODULES_STAGING_DIR)
-$(LINUX_RAMDISK_IMAGE): LINUX_TRUSTY_MODULES_MAKEFILE_DIR := $(LINUX_TRUSTY_MODULES_COPY_DIR)/drivers/trusty
-$(LINUX_RAMDISK_IMAGE): TRUSTY_MODULES_ORDER_HASH := $(shell echo "${LINUX_TRUSTY_MODULES_MAKEFILE_DIR}" | $(PATH_TOOLS_BINDIR)/md5sum -b)
 $(LINUX_RAMDISK_IMAGE): REPLACE_RAMDISK_MODULES := $(PY3) trusty/host/common/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
-$(LINUX_RAMDISK_IMAGE): ANDROID_RAMDISK := trusty/prebuilts/aosp/android/out/target/product/trusty/ramdisk.img
+$(LINUX_RAMDISK_IMAGE): ANDROID_RAMDISK := $(ANDROID_RAMDISK)
 $(LINUX_RAMDISK_IMAGE): LINUX_MODULES_LOAD := $(LINUX_MODULES_LOAD)
-$(LINUX_RAMDISK_IMAGE): $(LINUX_IMAGE) $(LINUX_TRUSTY_MODULES_COPY_FILES) $(LINUX_TRUSTY_MODULES_KCONFIG_EXT) $(LINUX_MODULES_LOAD)
+$(LINUX_RAMDISK_IMAGE): LINUX_PREBUILTS_MODULES := $(LINUX_PREBUILTS_MODULES)
+$(LINUX_RAMDISK_IMAGE): $(LINUX_PREBUILTS_MODULES) $(LINUX_MODULES_LOAD) $(ANDROID_RAMDISK)
 	@echo building Linux ramdisk
 	@rm -rf $(LINUX_MODULES_STAGING_DIR)
-	PATH=$(EXTRA_PATHS):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) modules_install
-	PATH=$(EXTRA_PATHS):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) M=$(LINUX_TRUSTY_MODULES_MAKEFILE_DIR) modules
-	PATH=$(EXTRA_PATHS):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) M=$(LINUX_TRUSTY_MODULES_MAKEFILE_DIR) modules_install
-	PATH=$(EXTRA_PATHS):$(PATH) $(REPLACE_RAMDISK_MODULES) --android-ramdisk $(ANDROID_RAMDISK) --kernel-ramdisk $(LINUX_MODULES_STAGING_DIR) --output-ramdisk $@ --override-modules-load $(LINUX_MODULES_LOAD) --check-modules-order --extra-modules-order "modules.order.$(TRUSTY_MODULES_ORDER_HASH)"
+	@mkdir -p $(LINUX_MODULES_STAGING_DIR)
+	@cp -n -t $(LINUX_MODULES_STAGING_DIR) $(LINUX_PREBUILTS_MODULES)
+	PATH=$(EXTRA_PATHS):$(PATH) $(REPLACE_RAMDISK_MODULES) --android-ramdisk $(ANDROID_RAMDISK) --kernel-ramdisk $(LINUX_MODULES_STAGING_DIR) --output-ramdisk $@ --override-modules-load $(LINUX_MODULES_LOAD)
 
-endif # LINUX_RAMDISK_IMAGE
-else
-$(LINUX_BUILD_DIR): $(LINUX_PREBUILTS_IMAGE)
+$(LINUX_BUILD_DIR): $(LINUX_PREBUILTS_IMAGE) $(LINUX_BUILD_DIR_CONFIG)
 	@echo copying Linux prebuilts
 	@rm -rf $@
 	@$(MKDIR)
@@ -187,24 +94,12 @@ $(LINUX_IMAGE): $(LINUX_BUILD_DIR)
 	@mkdir -p $(@D)
 	@cp -r ${LINUX_PREBUILTS_IMAGE} $@
 
-endif
-
 # Add LINUX_IMAGE to the list of project dependencies
 EXTRA_BUILDDEPS += $(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE)
 
-LINUX_DEFCONFIG_FRAGMENTS :=
-LINUX_TMP_DEFCONFIG :=
-LINUX_CONFIG_DIR :=
-LINUX_SRC :=
-LINUX_CLANG_TRIPLE :=
-LINUX_TRUSTY_INTREE :=
-LINUX_TRUSTY_MODULES_SRC_DIR :=
-LINUX_TRUSTY_MODULES_COPY_DIR :=
-LINUX_TRUSTY_MODULES_SRC_FILES :=
-LINUX_TRUSTY_MODULES_COPY_FILES :=
-LINUX_KCONFIG_EXT_PREFIX :=
-LINUX_TRUSTY_MODULES_KCONFIG_EXT :=
+LINUX_BUILD_DIR_DEFINES :=
+LINUX_BUILD_DIR_CONFIG :=
 LINUX_MODULES_STAGING_DIR :=
 LINUX_MODULES_LOAD :=
-LINUX_ENABLE_FFA_TRANSPORT :=
-LINUX_ENABLE_SMC_TRANSPORT :=
+LINUX_PREBUILTS_MODULES :=
+LINUX_PREBUILTS_MODULES_DIRS :=
diff --git a/project/linux/disable_sig_protect.fragment b/project/linux/disable_sig_protect.fragment
deleted file mode 100644
index 2ffaf98..0000000
--- a/project/linux/disable_sig_protect.fragment
+++ /dev/null
@@ -1 +0,0 @@
-CONFIG_MODULE_SIG_PROTECT=n
diff --git a/project/linux/modules.load b/project/linux/modules.load
index 2578fb3..08798b0 100644
--- a/project/linux/modules.load
+++ b/project/linux/modules.load
@@ -1,22 +1,19 @@
-kernel/net/core/failover.ko
-kernel/drivers/net/net_failover.ko
-kernel/drivers/block/virtio_blk.ko
-kernel/drivers/char/virtio_console.ko
-kernel/drivers/virtio/virtio_mmio.ko
-kernel/drivers/net/virtio_net.ko
-kernel/drivers/virtio/virtio_pci.ko
-kernel/drivers/dma-buf/heaps/system_heap.ko
-kernel/drivers/firmware/arm_ffa/ffa-core.ko
-kernel/drivers/firmware/arm_ffa/ffa-module.ko
-trusty/trusty-ffa.ko
-trusty/trusty-smc.ko
-trusty/trusty-core.ko
-trusty/trusty-ipc.ko
-trusty/trusty-log.ko
-trusty/trusty-test.ko
-trusty/trusty-virtio.ko
-kernel/drivers/virtio/virtio_pci_modern_dev.ko
-kernel/drivers/virtio/virtio_pci_legacy_dev.ko
-kernel/drivers/virtio/virtio_msg.ko
-kernel/drivers/virtio/virtio_msg_ffa_transport.ko
-kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko
+failover.ko
+net_failover.ko
+virtio_blk.ko
+virtio_console.ko
+virtio_mmio.ko
+virtio_net.ko
+virtio_pci.ko
+system_heap.ko
+ffa-core.ko
+ffa-module.ko
+trusty-ffa.ko
+trusty-smc.ko
+trusty-core.ko
+trusty-ipc.ko
+trusty-log.ko
+trusty-test.ko
+trusty-virtio.ko
+virtio_pci_modern_dev.ko
+virtio_pci_legacy_dev.ko
diff --git a/project/qemu-atf-inc.mk b/project/qemu-atf-inc.mk
index 68131ec..5cc10ca 100644
--- a/project/qemu-atf-inc.mk
+++ b/project/qemu-atf-inc.mk
@@ -77,7 +77,7 @@ $(HAFNIUM_DTBS_SRCS): $(ATF_BIN)
 
 HAFNIUM_DTBS_OUT := $(addprefix $(ATF_OUT_DIR)/, $(HAFNIUM_DTBS))
 $(HAFNIUM_DTBS_OUT): $(ATF_OUT_DIR)/%.dtb: $(ATF_OUT_DIR)/fdts/%.dtb
-	$(NOECHO)ln -rsf $< $@
+	$(NOECHO)$(PATH_TOOLS_BINDIR)/ln -rsf $< $@
 
 EXTRA_BUILDDEPS += $(HAFNIUM_DTBS_OUT)
 EXTRA_ATF_SYMLINKS += $(addprefix $(ATF_OUT_DIR)/, $(HAFNIUM_DTBS))
@@ -92,7 +92,7 @@ $(EL3SPMC_TOS_FW_CONFIG_DTB_SRC): $(ATF_BIN)
 
 EL3SPMC_TOS_FW_CONFIG_DTB_OUT := $(ATF_OUT_DIR)/tos_fw_config.dtb
 $(EL3SPMC_TOS_FW_CONFIG_DTB_OUT): $(EL3SPMC_TOS_FW_CONFIG_DTB_SRC)
-	$(NOECHO)ln -rsf $< $@
+	$(NOECHO)$(PATH_TOOLS_BINDIR)/ln -rsf $< $@
 
 EXTRA_BUILDDEPS += $(EL3SPMC_TOS_FW_CONFIG_DTB_OUT)
 EXTRA_ATF_SYMLINKS += $(ATF_OUT_DIR)/tos_fw_config.dtb
diff --git a/project/qemu-inc.mk b/project/qemu-inc.mk
index a5ee165..7fcc8fd 100644
--- a/project/qemu-inc.mk
+++ b/project/qemu-inc.mk
@@ -155,11 +155,6 @@ $(QEMU_BIN): $(QEMU_BUILD_BASE)
 EXTRA_BUILDDEPS += $(QEMU_BUILD_BASE) $(QEMU_BIN)
 endif
 
-ifneq (true,$(call TOBOOL,$(PACKAGE_TRUSTY_IMAGES_ONLY)))
-LINUX_ARCH ?= arm64
-include project/linux-inc.mk
-endif
-
 RUN_SCRIPT := $(BUILDDIR)/run
 STOP_SCRIPT := $(BUILDDIR)/stop
 ALLOC_ADB_PORTS_PY := $(BUILDDIR)/alloc_adb_ports.py
@@ -190,12 +185,12 @@ ATF_SYMLINKS := \
 $(ATF_OUT_DIR)/bl32.bin: BUILDDIR := $(BUILDDIR)
 $(ATF_OUT_DIR)/bl32.bin: ATF_OUT_DIR := $(ATF_OUT_DIR)
 $(ATF_OUT_DIR)/bl32.bin: $(BL32_BIN) $(ATF_OUT_DIR)
-	$(NOECHO)ln -rsf $< $@
+	$(NOECHO)$(PATH_TOOLS_BINDIR)/ln -rsf $< $@
 
 $(ATF_OUT_DIR)/bl33.bin: BUILDDIR := $(BUILDDIR)
 $(ATF_OUT_DIR)/bl33.bin: ATF_OUT_DIR := $(ATF_OUT_DIR)
 $(ATF_OUT_DIR)/bl33.bin: $(TEST_RUNNER_BIN) $(ATF_OUT_DIR)
-	$(NOECHO)ln -rsf $< $@
+	$(NOECHO)$(PATH_TOOLS_BINDIR)/ln -rsf $< $@
 
 ATF_GENERATED_FILES := \
 	$(ATF_OUT_DIR)/RPMB_DATA \
@@ -206,23 +201,72 @@ $(ATF_OUT_DIR)/RPMB_DATA: $(RPMB_DEV)
 	@echo Initialize rpmb device
 	$< --dev $(ATF_OUT_DIR)/RPMB_DATA --init --size 2048
 
+# Save the android src paths in order to rebuild the world if they change.
+ANDROID_OUT_BUILD_DIR_DEFINES := ANDROID_BUILD_ARTIFACTS=\"$(subst $(SPACE),_,$(ANDROID_BUILD_ARTIFACTS))\"
+ANDROID_OUT_BUILD_DIR_DEFINES += ANDROID_BUILD_TOP=\"$(subst $(SPACE),_,$(ANDROID_BUILD_TOP))\"
+
+ANDROID_OUT_BUILD_DIR_CONFIG = $(BUILDDIR)/aosp/android.config
+
+$(ANDROID_OUT_BUILD_DIR_CONFIG): ANDROID_OUT_BUILD_DIR_DEFINES := $(ANDROID_OUT_BUILD_DIR_DEFINES)
+$(ANDROID_OUT_BUILD_DIR_CONFIG): configheader
+	@$(call INFO_DONE,android build,generating config file,$@)
+	@$(call MAKECONFIGHEADER,$@,ANDROID_OUT_BUILD_DIR_DEFINES)
+
 ifeq (true,$(call TOBOOL,$(PACKAGE_TRUSTY_IMAGES_ONLY)))
 ANDROID_OUT_SRC_DIR :=
 ANDROID_OUT_SRC_FILES :=
+ANDROID_OUT_FILES :=
 else
-ifneq (,$(ANDROID_BUILD_TOP))
+
+# List of files we need from Android
+ANDROID_OUT_FILES := \
+	out/host/linux-x86/bin/adb \
+	out/host/linux-x86/bin/mkbootfs \
+	out/host/linux-x86/bin/mke2fs \
+	out/target/product/trusty/ramdisk.img \
+	out/target/product/trusty/system.img \
+	out/target/product/trusty/vendor.img \
+	out/target/product/trusty/userdata.img \
+	out/target/product/trusty/data/nativetest64 \
+
+ifneq (,$(ANDROID_BUILD_ARTIFACTS))
+# Unpack and use build artifacts if requested (e.g. for a chained build).
+$(info Using android ANDROID_BUILD_ARTIFACTS at $(ANDROID_BUILD_ARTIFACTS))
+
+ANDROID_OUT_SRC_DIR := $(BUILDDIR)/aosp/unpacked_android_artifacts
+
+# TODO: The result here gets copied to ANDROID_OUT_BUILD_DIR later. It might
+# be simpler to run the unpack script in the prebuilt case as well and skip
+# the extra copy step.
+ANDROID_OUT_SRC_FILES := $(addprefix $(ANDROID_OUT_SRC_DIR)/,$(ANDROID_OUT_FILES))
+$(ANDROID_OUT_SRC_DIR) $(ANDROID_OUT_SRC_FILES) &: ANDROID_OUT_SRC_DIR := $(ANDROID_OUT_SRC_DIR)
+$(ANDROID_OUT_SRC_DIR) $(ANDROID_OUT_SRC_FILES) &: $(ANDROID_BUILD_ARTIFACTS) $(ANDROID_OUT_BUILD_DIR_CONFIG)
+	@echo unpacking $< to $(ANDROID_OUT_SRC_DIR)
+	@rm -rf $(ANDROID_OUT_SRC_DIR)
+	trusty/prebuilts/aosp/unpack.py -o $(ANDROID_OUT_SRC_DIR) -a $<
+
+else ifneq (,$(ANDROID_BUILD_TOP))
 # We are building Trusty inside an Android environment,
 # which means we can use a fresh Android build instead of prebuilts
 ANDROID_OUT_SRC_DIR := $(ANDROID_BUILD_TOP)
+$(info Using android ANDROID_BUILD_TOP at $(ANDROID_BUILD_TOP))
 else
+# Use unpacked prebuilt out dir if build artifacts are not specified and
+# ANDROID_BUILD_TOP was not set
+$(info Using android prebuilts)
 ANDROID_OUT_SRC_DIR := trusty/prebuilts/aosp/android
 endif
 ANDROID_OUT_SRC_FILES := $(addprefix $(ANDROID_OUT_SRC_DIR)/,$(ANDROID_OUT_FILES))
-endif
+
+LINUX_ARCH ?= arm64
+ANDROID_HOST_BINDIR ?= $(ANDROID_OUT_SRC_DIR)/out/host/linux-x86/bin
+ANDROID_RAMDISK ?= $(ANDROID_OUT_SRC_DIR)/out/target/product/trusty/ramdisk.img
+include project/linux-inc.mk
+endif # PACKAGE_TRUSTY_IMAGES_ONLY
 
 MKE2FS ?= $(ANDROID_OUT_SRC_DIR)/out/host/linux-x86/bin/mke2fs
 $(ATF_OUT_DIR)/metadata.img: MKE2FS := $(MKE2FS)
-$(ATF_OUT_DIR)/metadata.img:
+$(ATF_OUT_DIR)/metadata.img: | $(ANDROID_OUT_SRC_DIR)
 	@echo Create metadata.img
 	MKE2FS_CONFIG= $(MKE2FS) -t ext4 -F $@ -O has_journal,extent,huge_file,dir_nlink,extra_isize,uninit_bg 16m
 
@@ -293,21 +337,6 @@ $(PY3_CMD): $(BUILDTOOLS_BINDIR)/py3-cmd
 
 EXTRA_BUILDDEPS += $(PY3_CMD)
 
-# List of files we need from Android
-ifeq (true,$(call TOBOOL,$(PACKAGE_TRUSTY_IMAGES_ONLY)))
-ANDROID_OUT_FILES :=
-
-else
-ANDROID_OUT_FILES := \
-	out/host/linux-x86/bin/adb \
-	out/host/linux-x86/bin/mke2fs \
-	out/target/product/trusty/ramdisk.img \
-	out/target/product/trusty/system.img \
-	out/target/product/trusty/vendor.img \
-	out/target/product/trusty/userdata.img \
-	out/target/product/trusty/data/nativetest64 \
-
-endif
 # Copy Android prebuilts into the build directory so that the build does not
 # depend on any files in the source tree. We want to package the build artifacts
 # without any dependencies on the sources.
@@ -334,7 +363,7 @@ $(ANDROID_OUT_BUILD_DIR): ANDROID_OUT_IMAGE_DIR := $(ANDROID_OUT_IMAGE_DIR)
 $(ANDROID_OUT_BUILD_DIR): ANDROID_OUT_FILES := $(ANDROID_OUT_FILES)
 $(ANDROID_OUT_BUILD_DIR): LINUX_RAMDISK_IMAGE := $(LINUX_RAMDISK_IMAGE)
 $(ANDROID_OUT_BUILD_DIR): RAMDISK_CP := $(if $(LINUX_RAMDISK_IMAGE),cp,/bin/true)
-$(ANDROID_OUT_BUILD_DIR): $(ANDROID_OUT_SRC_FILES) $(LINUX_RAMDISK_IMAGE)
+$(ANDROID_OUT_BUILD_DIR): $(ANDROID_OUT_SRC_FILES) $(LINUX_RAMDISK_IMAGE) $(ANDROID_OUT_BUILD_DIR_CONFIG)
 	@echo creating Android output directory
 	@rm -rf $@
 	@mkdir -p $@
@@ -380,7 +409,7 @@ EXTRA_BUILDDEPS += $(QEMU_CONFIG)
 # preserve backwards compatibility.
 $(RUN_SCRIPT): $(RUN_PY)
 	@echo creating $@
-	@ln -sf $(abspath $<) $@
+	@$(PATH_TOOLS_BINDIR)/ln -sf $(abspath $<) $@
 
 EXTRA_BUILDDEPS += $(RUN_SCRIPT)
 
@@ -430,7 +459,7 @@ ifeq (true,$(call TOBOOL,$(PACKAGE_TRUSTY_IMAGES)))
 QEMU_PACKAGE_FILES := \
 	$(OUTBIN) $(QEMU_SCRIPTS) $(PY3_CMD) \
 	$(STOP_SCRIPT) \
-	$(ATF_BIN) $(ATF_SYMLINKS) $(TEST_RUNNER_BIN) \
+	$(ATF_BIN) $(TEST_RUNNER_BIN) $(ATF_SYMLINKS) \
 	$(ATF_GENERATED_FILES) \
 	$(ATF_OUT_COPIED_FILES) \
 
@@ -445,10 +474,14 @@ QEMU_PACKAGE_ARCHIVE := $(BUILDDIR)/trusty_image_package.tar.gz
 include project/qemu-package-inc.mk
 endif
 
+ANDROID_HOST_BINDIR :=
 ANDROID_OUT_FILES :=
 ANDROID_OUT_BUILD_DIR :=
+ANDROID_OUT_BUILD_DIR_CONFIG :=
+ANDROID_OUT_BUILD_DIR_DEFINES :=
 ANDROID_OUT_SRC_DIR :=
 ANDROID_OUT_SRC_FILES :=
+ANDROID_RAMDISK :=
 ATF_BIN :=
 ATF_BUILD_BASE :=
 ATF_EXTRA_BINS :=
diff --git a/project/vm-arm-virt-inc.mk b/project/vm-arm-virt-inc.mk
index d523994..82479cf 100644
--- a/project/vm-arm-virt-inc.mk
+++ b/project/vm-arm-virt-inc.mk
@@ -35,6 +35,13 @@ USE_SYSTEM_BINDER := true
 # version.
 DICE_PROFILE_FOR_OPEN_DICE := android
 
+# When running trusty as a VM guest, it's likely we'll
+# want the DICE handover passed into user space. This
+# is only relevant for protected VMs, but fails
+# gracefully if the handover is not present in the
+# device tree, so we set it for all VM projects.
+MAP_RESERVED_MEM_FROM_DT ?= true
+
 include project/generic-arm-virt-inc.mk
 include project/generic-arm-tz-inc.mk
 
diff --git a/project/vm-arm64-security-inc.mk b/project/vm-arm64-security-inc.mk
index a7a16e7..fb2e1c6 100644
--- a/project/vm-arm64-security-inc.mk
+++ b/project/vm-arm64-security-inc.mk
@@ -23,8 +23,10 @@ TRUSTY_VM_INCLUDE_GATEKEEPER ?= true
 
 # compiled from source
 TRUSTY_BUILTIN_USER_TASKS := \
+	trusty/user/app/authmgr/authmgr-fe/app \
 	trusty/user/app/gatekeeper \
 	trusty/user/app/keymint/app \
+	trusty/user/app/keymint/vm/commservice/app \
 	trusty/user/base/app/device_tree \
 
 ifeq (true,$(call TOBOOL,$(USER_COVERAGE_ENABLED)))
diff --git a/project/vm-arm64-security-placeholder-trusted-hal-inc.mk b/project/vm-arm64-security-placeholder-trusted-hal-inc.mk
index a62c57a..8988f1a 100644
--- a/project/vm-arm64-security-placeholder-trusted-hal-inc.mk
+++ b/project/vm-arm64-security-placeholder-trusted-hal-inc.mk
@@ -34,7 +34,6 @@ include project/vm-arm64-security-inc.mk
 TRUSTY_BUILTIN_USER_TASKS += \
 	trusty/user/app/authmgr/authmgr-be/app \
 	trusty/user/app/sample/hwaes \
-	trusty/user/app/sample/hwbcc \
 	trusty/user/app/sample/hwcrypto \
 	trusty/user/app/sample/hwcryptohal/server/app \
 	trusty/user/app/sample/hwwsk \
diff --git a/project/vm-arm64-test-inc.mk b/project/vm-arm64-test-inc.mk
index 46954b6..09c4e77 100644
--- a/project/vm-arm64-test-inc.mk
+++ b/project/vm-arm64-test-inc.mk
@@ -15,6 +15,9 @@
 
 include project/vm-arm-virt-inc.mk
 
+# Enable Vintf TA for vts_treble_vintf_trusted_hal_test
+TRUSTY_VM_INCLUDE_VINTF_TA ?= true
+
 #
 # include list of test TAs for the Trusted HALs
 #
diff --git a/project/vm-arm64-test-placeholder-trusted-hal-inc.mk b/project/vm-arm64-test-placeholder-trusted-hal-inc.mk
index 86a9807..113dba5 100644
--- a/project/vm-arm64-test-placeholder-trusted-hal-inc.mk
+++ b/project/vm-arm64-test-placeholder-trusted-hal-inc.mk
@@ -26,18 +26,19 @@ WITH_HKDF_RPMB_KEY ?= true
 STORAGE_ENABLE_ERROR_REPORTING ?= true
 STORAGE_AIDL_ENABLED ?= true
 TRUSTY_VM_INCLUDE_SECURE_STORAGE_HAL ?= true
-AUTHMGRFE_MODE_INSECURE ?= true
+
+TEST_BUILD := true
 
 include project/vm-arm64-test-inc.mk
 
 TRUSTY_BUILTIN_USER_TASKS += \
 	trusty/user/app/authmgr/authmgr-be/app \
 	trusty/user/app/sample/hwaes \
-	trusty/user/app/sample/hwbcc \
 	trusty/user/app/sample/hwcrypto \
 	trusty/user/app/sample/hwcryptohal/server/app \
 	trusty/user/app/sample/hwwsk \
 	trusty/user/app/sample/rust-hello-world-trusted-hal/app \
+	trusty/user/app/sample/vintf/app \
 	trusty/user/app/storage \
 	trusty/user/base/app/metrics \
 	trusty/user/base/app/system_state_server_static \
diff --git a/project/vm-arm64-test_os-inc.mk b/project/vm-arm64-test_os-inc.mk
index d48421f..4d19638 100644
--- a/project/vm-arm64-test_os-inc.mk
+++ b/project/vm-arm64-test_os-inc.mk
@@ -34,6 +34,7 @@ include project/vm-arm-virt-test-inc.mk
 # disabling apploader service and rebalancing loadable test as builtin tests
 TRUSTY_BUILTIN_USER_TASKS := \
 	trusty/user/base/app/apploader \
+	trusty/user/app/authmgr/authmgr-fe/app \
 
 ifeq (true,$(call TOBOOL,$(USER_COVERAGE_ENABLED)))
 TRUSTY_ALL_USER_TASKS += \
```

