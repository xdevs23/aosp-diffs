```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 5dfd59c..a21c1bc 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -15,7 +15,8 @@ mypy = sh -c "find . -name '*.py' | xargs -I{} mypy {}"
 clang_format = true
 commit_msg_bug_field = true
 commit_msg_changeid_field = true
-pylint3 = true
+# pylint is broken without a pylintrc due to b/360445027
+# pylint3 = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
diff --git a/project/generic-arm-inc.mk b/project/generic-arm-inc.mk
index fc6e34b..2d43121 100644
--- a/project/generic-arm-inc.mk
+++ b/project/generic-arm-inc.mk
@@ -181,6 +181,7 @@ TRUSTY_BUILTIN_USER_TASKS := \
 	trusty/user/app/sample/hwaes \
 	trusty/user/app/sample/hwbcc \
 	trusty/user/app/sample/hwcrypto \
+	trusty/user/app/sample/hwcryptohal/server/app \
 	trusty/user/app/sample/hwwsk \
 	trusty/user/app/sample/secure_fb_mock_impl \
 	trusty/user/app/storage \
diff --git a/project/linux-inc.mk b/project/linux-inc.mk
index 6f6dfac..9a2f3c2 100644
--- a/project/linux-inc.mk
+++ b/project/linux-inc.mk
@@ -22,11 +22,19 @@
 
 # This Makefile will build the Linux kernel with our configuration.
 
+LINUX_VERSION := 6.6
+
 LINUX_BUILD_DIR := $(abspath $(BUILDDIR)/linux-build)
 ifndef LINUX_ARCH
 	$(error LINUX_ARCH must be specified)
 endif
 
+LINUX_PREBUILTS_IMAGE := kernel/prebuilts/${LINUX_VERSION}/${LINUX_ARCH}/kernel-${LINUX_VERSION}
+
+LINUX_IMAGE := $(LINUX_BUILD_DIR)/arch/$(LINUX_ARCH)/boot/Image
+LINUX_RAMDISK_IMAGE :=
+
+ifeq (,$(wildcard $(LINUX_PREBUILTS_IMAGE)))
 ifeq ($(LINUX_ARCH),arm)
 LINUX_CLANG_TRIPLE := $(LINUX_ARCH)-linux-gnueabi-
 else
@@ -35,6 +43,10 @@ endif
 
 LINUX_SRC := $(call FIND_EXTERNAL,linux)
 LINUX_CONFIG_DIR = $(LINUX_SRC)/arch/$(LINUX_ARCH)/configs
+LINUX_TMP_DEFCONFIG := $(LINUX_CONFIG_DIR)/tmp_defconfig
+
+# Check if the Linux sources have the Trusty drivers in-tree
+LINUX_TRUSTY_INTREE := $(wildcard $(LINUX_SRC)/drivers/trusty)
 
 # Preserve compatibility with architectures without GKI
 ifeq (,$(wildcard $(LINUX_CONFIG_DIR)/gki_defconfig))
@@ -44,49 +56,124 @@ LINUX_DEFCONFIG_FRAGMENTS := \
 else
 LINUX_DEFCONFIG_FRAGMENTS := \
 	$(LINUX_CONFIG_DIR)/gki_defconfig \
-	$(LINUX_CONFIG_DIR)/trusty_qemu_defconfig.fragment \
+	$(if $(LINUX_TRUSTY_INTREE),$(LINUX_CONFIG_DIR)/trusty_qemu_defconfig.fragment) \
 
 endif
 
-LINUX_IMAGE := $(LINUX_BUILD_DIR)/arch/$(LINUX_ARCH)/boot/Image
+ifeq (,$(LINUX_TRUSTY_INTREE))
+LINUX_DEFCONFIG_FRAGMENTS += \
+	linux/common-modules/trusty/arm_ffa.fragment \
+	linux/common-modules/trusty/trusty_defconfig.fragment \
+	linux/common-modules/trusty/trusty_test.fragment \
+	linux/common-modules/virtual-device/aarch64.fragment \
+	linux/common-modules/virtual-device/virtual_device_core.fragment \
+
+endif
+
+$(LINUX_TMP_DEFCONFIG): LINUX_SRC := $(LINUX_SRC)
+$(LINUX_TMP_DEFCONFIG): $(LINUX_DEFCONFIG_FRAGMENTS)
+	KCONFIG_CONFIG="$@" $(LINUX_SRC)/scripts/kconfig/merge_config.sh -m -r $^
+
+# tmp_defconfig lives in the source tree,
+# so we should delete it after we're done
+.INTERMEDIATE: $(LINUX_TMP_DEFCONFIG)
 
-$(LINUX_IMAGE): LINUX_TMP_DEFCONFIG := $(LINUX_CONFIG_DIR)/tmp_defconfig
-$(LINUX_IMAGE): LINUX_SRC := $(LINUX_SRC)
-$(LINUX_IMAGE): LINUX_DEFCONFIG_FRAGMENTS := $(LINUX_DEFCONFIG_FRAGMENTS)
-$(LINUX_IMAGE): LINUX_MAKE_ARGS := -C $(LINUX_SRC)
-$(LINUX_IMAGE): LINUX_MAKE_ARGS += O=$(LINUX_BUILD_DIR)
-$(LINUX_IMAGE): LINUX_MAKE_ARGS += ARCH=$(LINUX_ARCH)
+ifeq (,$(LINUX_TRUSTY_INTREE))
+# Make a copy of common-modules/trusty because the kernel build system
+# creates files directly in the directory passed to M=
+LINUX_TRUSTY_MODULES_SRC_DIR := linux/common-modules/trusty
+LINUX_TRUSTY_MODULES_COPY_DIR := $(abspath $(BUILDDIR)/linux-trusty-modules)
+LINUX_TRUSTY_MODULES_SRC_FILES := $(shell find $(LINUX_TRUSTY_MODULES_SRC_DIR) -type f)
+LINUX_TRUSTY_MODULES_COPY_FILES := $(patsubst $(LINUX_TRUSTY_MODULES_SRC_DIR)/%,$(LINUX_TRUSTY_MODULES_COPY_DIR)/%,$(LINUX_TRUSTY_MODULES_SRC_FILES))
+$(LINUX_TRUSTY_MODULES_COPY_FILES): $(LINUX_TRUSTY_MODULES_COPY_DIR)/%: $(LINUX_TRUSTY_MODULES_SRC_DIR)/%
+	@$(MKDIR)
+	@cp $< $@
+
+# For now, symlink the Trusty module Kconfig into Kconfig.ext
+# The kernel will import the latter into its build.
+LINUX_KCONFIG_EXT_PREFIX := $(LINUX_TRUSTY_MODULES_COPY_DIR)/
+LINUX_TRUSTY_MODULES_KCONFIG_EXT := $(LINUX_TRUSTY_MODULES_COPY_DIR)/Kconfig.ext
+$(LINUX_TRUSTY_MODULES_KCONFIG_EXT): $(LINUX_TRUSTY_MODULES_COPY_DIR)/drivers/trusty/Kconfig
+	@ln -srf $< $@
+
+LINUX_MODULES_STAGING_DIR := $(abspath $(BUILDDIR)/linux-modules-staging)
+LINUX_RAMDISK_IMAGE := $(abspath $(BUILDDIR)/ramdisk.img)
+endif # LINUX_TRUSTY_INTREE
+
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_TMP_DEFCONFIG := $(LINUX_TMP_DEFCONFIG)
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): PATH_TOOLS_BINDIR := $(PATH_TOOLS_BINDIR)
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS := -C $(LINUX_SRC)
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += O=$(LINUX_BUILD_DIR)
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += ARCH=$(LINUX_ARCH)
 
 # Preserve compatibility with older linux kernel
 ifeq (,$(wildcard $(LINUX_SRC)/Documentation/kbuild/llvm.rst))
-$(LINUX_IMAGE): CLANG_BINDIR := $(CLANG_BINDIR)
-$(LINUX_IMAGE): LINUX_MAKE_ARGS += CROSS_COMPILE=$(ARCH_$(LINUX_ARCH)_TOOLCHAIN_PREFIX)
-$(LINUX_IMAGE): LINUX_MAKE_ARGS += CC=$(CLANG_BINDIR)/clang
-$(LINUX_IMAGE): LINUX_MAKE_ARGS += LD=$(CLANG_BINDIR)/ld.lld
-$(LINUX_IMAGE): LINUX_MAKE_ARGS += CLANG_TRIPLE=$(LINUX_CLANG_TRIPLE)
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): CLANG_BINDIR := $(CLANG_BINDIR)
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += CROSS_COMPILE=$(ARCH_$(LINUX_ARCH)_TOOLCHAIN_PREFIX)
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += CC=$(CLANG_BINDIR)/clang
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += LD=$(CLANG_BINDIR)/ld.lld
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += CLANG_TRIPLE=$(LINUX_CLANG_TRIPLE)
 else
 # Newer linux kernel versions need a newer toolchain (optionally specified in
 # LINUX_CLANG_BINDIR) than the older linux kernel needs or supports.
 LINUX_CLANG_BINDIR ?= $(CLANG_BINDIR)
-$(LINUX_IMAGE): CLANG_BINDIR := $(LINUX_CLANG_BINDIR)
-$(LINUX_IMAGE): LINUX_MAKE_ARGS += CROSS_COMPILE=$(LINUX_CLANG_TRIPLE)
-$(LINUX_IMAGE): LINUX_MAKE_ARGS += LLVM=1
-$(LINUX_IMAGE): LINUX_MAKE_ARGS += LLVM_IAS=1
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): CLANG_BINDIR := $(LINUX_CLANG_BINDIR)
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += CROSS_COMPILE=$(LINUX_CLANG_TRIPLE)
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += LLVM=1
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += LLVM_IAS=1
 endif
 
-$(LINUX_IMAGE): LINUX_MAKE_ARGS += LEX=$(BUILDTOOLS_BINDIR)/flex
-$(LINUX_IMAGE): LINUX_MAKE_ARGS += YACC=$(BUILDTOOLS_BINDIR)/bison
-$(LINUX_IMAGE): LINUX_MAKE_ARGS += BISON_PKGDATADIR=$(BUILDTOOLS_COMMON)/bison
-$(LINUX_IMAGE): .PHONY
-	KCONFIG_CONFIG=$(LINUX_TMP_DEFCONFIG) $(LINUX_SRC)/scripts/kconfig/merge_config.sh -m -r $(LINUX_DEFCONFIG_FRAGMENTS)
-	PATH=$(CLANG_BINDIR):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) $(notdir $(LINUX_TMP_DEFCONFIG))
-	rm $(LINUX_TMP_DEFCONFIG)
-	PATH=$(CLANG_BINDIR):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS)
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += LEX=$(BUILDTOOLS_BINDIR)/flex
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += YACC=$(BUILDTOOLS_BINDIR)/bison
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += BISON_PKGDATADIR=$(BUILDTOOLS_COMMON)/bison
+$(LINUX_IMAGE): $(LINUX_TMP_DEFCONFIG)
+	PATH=$(CLANG_BINDIR):$(PATH_TOOLS_BINDIR):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) $(notdir $(LINUX_TMP_DEFCONFIG))
+	PATH=$(CLANG_BINDIR):$(PATH_TOOLS_BINDIR):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS)
+
+ifneq (,$(LINUX_RAMDISK_IMAGE))
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += INSTALL_MOD_PATH=$(LINUX_MODULES_STAGING_DIR)
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += KCONFIG_EXT_PREFIX=$(LINUX_KCONFIG_EXT_PREFIX)
+
+$(LINUX_RAMDISK_IMAGE): LINUX_MODULES_STAGING_DIR := $(LINUX_MODULES_STAGING_DIR)
+$(LINUX_RAMDISK_IMAGE): LINUX_TRUSTY_MODULES_MAKEFILE_DIR := $(LINUX_TRUSTY_MODULES_COPY_DIR)/drivers/trusty
+$(LINUX_RAMDISK_IMAGE): BUILDTOOLS_BINDIR := $(BUILDTOOLS_BINDIR)
+$(LINUX_RAMDISK_IMAGE): KERNEL_BUILDTOOLS_BINDIR := linux/prebuilts/build-tools/linux-x86/bin
+$(LINUX_RAMDISK_IMAGE): REPLACE_RAMDISK_MODULES := $(PY3) trusty/host/common/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
+$(LINUX_RAMDISK_IMAGE): ANDROID_RAMDISK := trusty/prebuilts/aosp/android/out/target/product/trusty/ramdisk.img
+$(LINUX_RAMDISK_IMAGE): $(LINUX_IMAGE) $(LINUX_TRUSTY_MODULES_COPY_FILES) $(LINUX_TRUSTY_MODULES_KCONFIG_EXT)
+	@echo building Linux ramdisk
+	@rm -rf $(LINUX_MODULES_STAGING_DIR)
+	PATH=$(CLANG_BINDIR):$(PATH_TOOLS_BINDIR):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) modules_install
+	PATH=$(CLANG_BINDIR):$(PATH_TOOLS_BINDIR):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) M=$(LINUX_TRUSTY_MODULES_MAKEFILE_DIR) modules
+	PATH=$(CLANG_BINDIR):$(PATH_TOOLS_BINDIR):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) M=$(LINUX_TRUSTY_MODULES_MAKEFILE_DIR) modules_install
+	PATH=$(BUILDTOOLS_BINDIR):$(KERNEL_BUILDTOOLS_BINDIR):$(PATH) $(REPLACE_RAMDISK_MODULES) --android-ramdisk $(ANDROID_RAMDISK) --kernel-ramdisk $(LINUX_MODULES_STAGING_DIR) --output-ramdisk $@
+
+endif # LINUX_RAMDISK_IMAGE
+else
+$(LINUX_BUILD_DIR): $(LINUX_PREBUILTS_IMAGE)
+	@echo copying Linux prebuilts
+	@rm -rf $@
+	@$(MKDIR)
+
+$(LINUX_IMAGE): $(LINUX_BUILD_DIR)
+	@mkdir -p $(@D)
+	@cp -r ${LINUX_PREBUILTS_IMAGE} $@
+
+endif
 
 # Add LINUX_IMAGE to the list of project dependencies
-EXTRA_BUILDDEPS += $(LINUX_IMAGE)
+EXTRA_BUILDDEPS += $(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE)
 
 LINUX_DEFCONFIG_FRAGMENTS :=
+LINUX_TMP_DEFCONFIG :=
 LINUX_CONFIG_DIR :=
 LINUX_SRC :=
 LINUX_CLANG_TRIPLE :=
+LINUX_TRUSTY_INTREE :=
+LINUX_TRUSTY_MODULES_SRC_DIR :=
+LINUX_TRUSTY_MODULES_COPY_DIR :=
+LINUX_TRUSTY_MODULES_SRC_FILES :=
+LINUX_TRUSTY_MODULES_COPY_FILES :=
+LINUX_KCONFIG_EXT_PREFIX :=
+LINUX_TRUSTY_MODULES_KCONFIG_EXT :=
+LINUX_MODULES_STAGING_DIR :=
diff --git a/project/qemu-inc.mk b/project/qemu-inc.mk
index 1bb8a83..861b173 100644
--- a/project/qemu-inc.mk
+++ b/project/qemu-inc.mk
@@ -120,10 +120,13 @@ else
 # We have prebuilts, copy them into the build directory
 QEMU_BIN := $(QEMU_BUILD_BASE)/bin/qemu-system-$(QEMU_ARCH)
 
+# The qemu prebuilts now contain an Android.bp file.
+# We do not want it in the build directory because Soong reads it.
 $(QEMU_BUILD_BASE): $(QEMU_PREBUILTS)
 	@echo creating qemu output directory
 	@rm -rf $@
 	@cp -r $< $@
+	@rm -f $@/Android.bp
 
 # The binary is inside the build directory, so create
 # an empty dependency between them
@@ -136,7 +139,6 @@ endif
 LINUX_ARCH ?= arm64
 include project/linux-inc.mk
 
-RUN_QEMU_SCRIPT := $(BUILDDIR)/run-qemu
 RUN_SCRIPT := $(BUILDDIR)/run
 STOP_SCRIPT := $(BUILDDIR)/stop
 QEMU_CONFIG := $(BUILDDIR)/config.json
@@ -151,20 +153,29 @@ RUN_PY := $(BUILDDIR)/run.py
 $(ATF_OUT_DIR):
 	mkdir -p $@
 
+# ATF built binaries
+ATF_BIN := $(ATF_OUT_DIR)/bl31.bin
+ATF_EXTRA_BINS := \
+	$(ATF_OUT_DIR)/bl1.bin \
+	$(ATF_OUT_DIR)/bl2.bin \
+
 # For ATF bootloader semihosting calls, bl32 and bl33 need to be in place
 ATF_SYMLINKS := \
 	$(ATF_OUT_DIR)/bl32.bin \
 	$(ATF_OUT_DIR)/bl33.bin \
 
+$(ATF_OUT_DIR)/bl32.bin: BUILDDIR := $(BUILDDIR)
+$(ATF_OUT_DIR)/bl32.bin: ATF_OUT_DIR := $(ATF_OUT_DIR)
 $(ATF_OUT_DIR)/bl32.bin: $(BL32_BIN) $(ATF_OUT_DIR)
-	ln -sf $(abspath $<) $@
+	$(NOECHO)ln -rsf $< $@
 
+$(ATF_OUT_DIR)/bl33.bin: BUILDDIR := $(BUILDDIR)
+$(ATF_OUT_DIR)/bl33.bin: ATF_OUT_DIR := $(ATF_OUT_DIR)
 $(ATF_OUT_DIR)/bl33.bin: $(TEST_RUNNER_BIN) $(ATF_OUT_DIR)
-	ln -sf $(abspath $<) $@
+	$(NOECHO)ln -rsf $< $@
 
 ATF_OUT_COPIED_FILES := \
 	$(ATF_OUT_DIR)/firmware.android.dts \
-	$(ATF_OUT_DIR)/run-qemu-helper \
 
 $(ATF_OUT_COPIED_FILES): $(ATF_OUT_DIR)/% : $(PROJECT_QEMU_INC_LOCAL_DIR)/qemu/% $(ATF_OUT_DIR)
 	@echo copying $@
@@ -232,6 +243,7 @@ EXTRA_BUILDDEPS += $(PY3_CMD)
 # List of files we need from Android
 ANDROID_OUT_FILES := \
 	out/host/linux-x86/bin/adb \
+	out/target/product/trusty/ramdisk.img \
 	out/target/product/trusty/system.img \
 	out/target/product/trusty/vendor.img \
 	out/target/product/trusty/userdata.img \
@@ -246,6 +258,9 @@ ANDROID_OUT_FILES := \
 # the target directory to the same state as with a clean build.
 ANDROID_OUT_BUILD_DIR := $(BUILDDIR)/aosp/android
 
+ANDROID_OUT_IMAGE_DIR := $(ANDROID_OUT_BUILD_DIR)/out/target/product/trusty
+ANDROID_OUT_ADB_PATH := $(ANDROID_OUT_BUILD_DIR)/out/host/linux-x86/bin/adb
+
 ifneq (,$(ANDROID_BUILD_TOP))
 # We are building Trusty inside an Android environment,
 # which means we can use a fresh Android build instead of prebuilts
@@ -260,12 +275,16 @@ ANDROID_OUT_SRC_FILES := $(addprefix $(ANDROID_OUT_SRC_DIR)/,$(ANDROID_OUT_FILES
 # ANDROID_OUT_BUILD_DIR preserving the directory structure relative to the
 # top-level ANDROID_OUT_SRC_DIR directory
 $(ANDROID_OUT_BUILD_DIR): ANDROID_OUT_SRC_DIR := $(ANDROID_OUT_SRC_DIR)
+$(ANDROID_OUT_BUILD_DIR): ANDROID_OUT_IMAGE_DIR := $(ANDROID_OUT_IMAGE_DIR)
 $(ANDROID_OUT_BUILD_DIR): ANDROID_OUT_FILES := $(ANDROID_OUT_FILES)
-$(ANDROID_OUT_BUILD_DIR): $(ANDROID_OUT_SRC_FILES)
+$(ANDROID_OUT_BUILD_DIR): LINUX_RAMDISK_IMAGE := $(LINUX_RAMDISK_IMAGE)
+$(ANDROID_OUT_BUILD_DIR): RAMDISK_CP := $(if $(LINUX_RAMDISK_IMAGE),cp,/bin/true)
+$(ANDROID_OUT_BUILD_DIR): $(ANDROID_OUT_SRC_FILES) $(LINUX_RAMDISK_IMAGE)
 	@echo creating Android output directory
 	@rm -rf $@
 	@mkdir -p $@
 	@cd $(ANDROID_OUT_SRC_DIR) && cp -r --parents -t $@ $(ANDROID_OUT_FILES)
+	@$(RAMDISK_CP) $(LINUX_RAMDISK_IMAGE) $(ANDROID_OUT_IMAGE_DIR)/ramdisk.img
 
 EXTRA_BUILDDEPS += $(ANDROID_OUT_BUILD_DIR)
 
@@ -276,7 +295,8 @@ $(QEMU_CONFIG): EXTRA_QEMU_FLAGS := ["-machine", "gic-version=$(GIC_VERSION)"]
 $(QEMU_CONFIG): ATF_OUT_DIR := $(subst $(BUILDDIR)/,,$(ATF_OUT_DIR))
 $(QEMU_CONFIG): LINUX_BUILD_DIR := $(subst $(BUILDDIR)/,,$(LINUX_BUILD_DIR))
 $(QEMU_CONFIG): LINUX_ARCH := $(LINUX_ARCH)
-$(QEMU_CONFIG): ANDROID_OUT_BUILD_DIR := $(subst $(BUILDDIR)/,,$(ANDROID_OUT_BUILD_DIR))
+$(QEMU_CONFIG): ANDROID_OUT_IMAGE_DIR := $(subst $(BUILDDIR)/,,$(ANDROID_OUT_IMAGE_DIR))
+$(QEMU_CONFIG): ANDROID_OUT_ADB_PATH := $(subst $(BUILDDIR)/,,$(ANDROID_OUT_ADB_PATH))
 $(QEMU_CONFIG): RPMB_DEV := $(subst $(BUILDDIR)/,,$(RPMB_DEV))
 $(QEMU_CONFIG): $(ATF_OUT_COPIED_FILES) $(ATF_SYMLINKS) $(ATF_OUT_DIR)/RPMB_DATA
 	@echo generating $@
@@ -285,27 +305,13 @@ $(QEMU_CONFIG): $(ATF_OUT_COPIED_FILES) $(ATF_SYMLINKS) $(ATF_OUT_DIR)/RPMB_DATA
 	@echo '  "atf": "$(ATF_OUT_DIR)", ' >> $@
 	@echo '  "qemu": "$(QEMU_BIN)", ' >> $@
 	@echo '  "extra_qemu_flags": $(EXTRA_QEMU_FLAGS), ' >> $@
-	@echo '  "android": "$(ANDROID_OUT_BUILD_DIR)", ' >> $@
+	@echo '  "android_image_dir": "$(ANDROID_OUT_IMAGE_DIR)", ' >> $@
+	@echo '  "adb": "$(ANDROID_OUT_ADB_PATH)", ' >> $@
 	@echo '  "rpmbd": "$(RPMB_DEV)", ' >> $@
 	@echo '  "arch": "$(ARCH)" }' >> $@
 
 EXTRA_BUILDDEPS += $(QEMU_CONFIG)
 
-# Create a wrapper script around run-qemu-helper which defaults arguments to
-# those needed to run this build
-$(RUN_QEMU_SCRIPT): QEMU_BIN := $(subst $(BUILDDIR)/,,$(QEMU_BIN))
-$(RUN_QEMU_SCRIPT): ATF_OUT_DIR := $(subst $(BUILDDIR)/,,$(ATF_OUT_DIR))
-$(RUN_QEMU_SCRIPT): LINUX_BUILD_DIR := $(subst $(BUILDDIR)/,,$(LINUX_BUILD_DIR))
-$(RUN_QEMU_SCRIPT): $(ATF_OUT_COPIED_FILES) $(ATF_SYMLINKS) $(ATF_OUT_DIR)/RPMB_DATA
-	@echo generating $@
-	@echo "#!/bin/sh" >$@
-	@echo 'SCRIPT_DIR=$$(dirname "$$0")' >>$@
-	@echo 'cd "$$SCRIPT_DIR/$(ATF_OUT_DIR)"' >>$@
-	@echo 'KERNEL_DIR="$$SCRIPT_DIR/$(LINUX_BUILD_DIR)" QEMU="$$SCRIPT_DIR/$(QEMU_BIN)" ./run-qemu-helper "$$@"' >>$@
-	@chmod +x $@
-
-EXTRA_BUILDDEPS += $(RUN_QEMU_SCRIPT)
-
 # The original run shell script was replaced by run.py. Create symlink to
 # preserve backwards compatibility.
 $(RUN_SCRIPT): $(RUN_PY)
@@ -328,16 +334,41 @@ ifeq (true,$(call TOBOOL,$(PACKAGE_QEMU_TRUSTY)))
 # Files & directories to copy into QEMU package archive
 QEMU_PACKAGE_FILES := \
 	$(OUTBIN) $(QEMU_SCRIPTS) $(PY3_CMD) $(QEMU_CONFIG) $(RPMB_DEV) \
-	$(RUN_SCRIPT) $(RUN_QEMU_SCRIPT) $(STOP_SCRIPT) $(ANDROID_OUT_BUILD_DIR) \
-	$(QEMU_BIN) $(ATF_SYMLINKS) $(ATF_OUT_DIR)/bl31.bin \
+	$(RUN_SCRIPT) $(STOP_SCRIPT) $(ANDROID_OUT_BUILD_DIR) \
+	$(QEMU_BIN) $(ATF_BIN) $(ATF_SYMLINKS) \
 	$(ATF_OUT_DIR)/RPMB_DATA $(ATF_OUT_COPIED_FILES) $(LINUX_IMAGE) \
 
 # Other files/directories that should be included in the package but which are
 # not make targets and therefore cannot be pre-requisites. The target that
 # creates these files must be in the QEMU_PACKAGE_FILES variable.
 QEMU_PACKAGE_EXTRA_FILES := \
-	$(LINUX_BUILD_DIR)/arch $(LINUX_BUILD_DIR)/scripts $(ATF_BUILD_BASE) \
-	$(QEMU_BUILD_BASE) \
+	$(LINUX_BUILD_DIR)/arch $(LINUX_BUILD_DIR)/scripts \
+	$(QEMU_BUILD_BASE) $(ATF_EXTRA_BINS) \
+
+QEMU_PACKAGE_ARCHIVE := $(BUILDDIR)/trusty_qemu_package.zip
+
+include project/qemu-package-inc.mk
+endif
+
+ifeq (true,$(call TOBOOL,$(PACKAGE_TRUSTY_IMAGES)))
+
+# Files & directories to copy into Trusty image archive for use with QEMU
+# emulator. This does not include the QEMU emulator itself, which is located in
+# prebuilts/android-emulator/trusty-x86_64/ and part of the trusty qemu device
+# host package built in AOSP.
+QEMU_PACKAGE_FILES := \
+	$(OUTBIN) $(QEMU_SCRIPTS) $(PY3_CMD) \
+	$(STOP_SCRIPT) \
+	$(ATF_BIN) $(ATF_SYMLINKS) $(TEST_RUNNER_BIN) \
+	$(ATF_OUT_DIR)/RPMB_DATA $(ATF_OUT_COPIED_FILES) \
+
+# Other files/directories that should be included in the package but which are
+# not make targets and therefore cannot be pre-requisites. The target that
+# creates these files must be in the QEMU_PACKAGE_FILES variable.
+QEMU_PACKAGE_EXTRA_FILES := \
+	$(ATF_EXTRA_BINS) \
+
+QEMU_PACKAGE_ARCHIVE := $(BUILDDIR)/trusty_image_package.tar.gz
 
 include project/qemu-package-inc.mk
 endif
@@ -346,14 +377,17 @@ ANDROID_OUT_FILES :=
 ANDROID_OUT_BUILD_DIR :=
 ANDROID_OUT_SRC_DIR :=
 ANDROID_OUT_SRC_FILES :=
+ATF_BIN :=
 ATF_BUILD_BASE :=
+ATF_EXTRA_BINS :=
 ATF_OUT_COPIED_FILES :=
 ATF_OUT_DIR :=
+ATF_RELATIVE_TO_BUILD_BASE :=
 ATF_SYMLINKS :=
 LINUX_ARCH :=
 LINUX_BUILD_DIR :=
 LINUX_IMAGE :=
-RUN_QEMU_SCRIPT :=
+LINUX_RAMDISK_IMAGE :=
 RUN_SCRIPT :=
 TEST_RUNNER_BIN :=
 QEMU_BIN :=
diff --git a/project/qemu-package-inc.mk b/project/qemu-package-inc.mk
index 765cd36..99816d4 100644
--- a/project/qemu-package-inc.mk
+++ b/project/qemu-package-inc.mk
@@ -16,6 +16,7 @@
 # Package binary build of Trusty, QEMU, AOSP, and scripts for standalone use
 
 # Inputs:
+# QEMU_PACKAGE_ARCHIVE: output package archive to create (.zip or .tar.gz)
 # QEMU_PACKAGE_FILES: files and folders to include in the package archive
 # 		These files/folders must be valid make targets, as they will be included
 # 		as pre-requisites to the package zip.
@@ -23,16 +24,26 @@
 # 		package archive, which are not make targets. These files must be created
 # 		by a target in QEMU_PACKAGE_FILES.
 
-QEMU_PACKAGE_ZIP := $(BUILDDIR)/trusty_qemu_package.zip
 QEMU_PACKAGE_LICENSE := $(BUILDDIR)/LICENSE
 
+ifeq (,$(QEMU_PREBUILTS))
 QEMU_PACKAGE_LICENSE_FILES := \
 	$(call FIND_EXTERNAL,qemu/LICENSE) \
 	$(call FIND_EXTERNAL,qemu/COPYING) \
 	$(call FIND_EXTERNAL,linux/COPYING) \
 	$(call FIND_EXTERNAL,linux/LICENSES/preferred/GPL-2.0) \
 	$(call FIND_EXTERNAL,linux/LICENSES/exceptions/Linux-syscall-note) \
+
+else
+QEMU_PACKAGE_LICENSE_FILES := $(QEMU_PREBUILTS)/../NOTICE
+endif
+
+QEMU_PACKAGE_LICENSE_FILES += \
 	$(call FIND_EXTERNAL,arm-trusted-firmware/docs/license.rst) \
+	prebuilts/android-emulator/NOTICE \
+
+# Some of these files might be missing
+QEMU_PACKAGE_LICENSE_FILES := $(wildcard $(QEMU_PACKAGE_LICENSE_FILES))
 
 # TODO: Unify with SDK license construction when it lands
 $(QEMU_PACKAGE_LICENSE): LOCAL_DIR := $(GET_LOCAL_DIR)
@@ -50,20 +61,37 @@ $(QEMU_PACKAGE_LICENSE): $(QEMU_PACKAGE_LICENSE_FILES)
 
 QEMU_PACKAGE_FILES += $(QEMU_PACKAGE_LICENSE)
 
-$(QEMU_PACKAGE_ZIP): BUILDDIR := $(BUILDDIR)
-$(QEMU_PACKAGE_ZIP): QEMU_PACKAGE_EXTRA_FILES := $(QEMU_PACKAGE_EXTRA_FILES)
-$(QEMU_PACKAGE_ZIP): $(QEMU_PACKAGE_FILES)
+ifneq (,$(filter %.zip,$(QEMU_PACKAGE_ARCHIVE)))
+$(QEMU_PACKAGE_ARCHIVE): BUILDDIR := $(BUILDDIR)
+$(QEMU_PACKAGE_ARCHIVE): QEMU_PACKAGE_EXTRA_FILES := $(QEMU_PACKAGE_EXTRA_FILES)
+$(QEMU_PACKAGE_ARCHIVE): $(QEMU_PACKAGE_FILES)
 	@$(MKDIR)
 	@echo Creating QEMU archive package
 	$(NOECHO)rm -f $@
 	$(NOECHO)(cd $(BUILDDIR) && zip -q -u -r $@ $(subst $(BUILDDIR)/,,$^))
 	$(NOECHO)(cd $(BUILDDIR) && zip -q -u -r $@ $(subst $(BUILDDIR)/,,$(QEMU_PACKAGE_EXTRA_FILES)))
+else
+
+ifneq (,$(filter %.tar.gz,$(QEMU_PACKAGE_ARCHIVE)))
+$(QEMU_PACKAGE_ARCHIVE): BUILDDIR := $(BUILDDIR)
+$(QEMU_PACKAGE_ARCHIVE): QEMU_PACKAGE_EXTRA_FILES := $(QEMU_PACKAGE_EXTRA_FILES)
+$(QEMU_PACKAGE_ARCHIVE): $(QEMU_PACKAGE_FILES)
+	@$(MKDIR)
+	@echo Creating QEMU archive package
+	$(NOECHO)rm -f $@
+	$(NOECHO)(cd $(BUILDDIR) && tar -c -z -f $@ $(subst $(BUILDDIR)/,,$^) $(subst $(BUILDDIR)/,,$(QEMU_PACKAGE_EXTRA_FILES)))
+
+else
+$(error QEMU_PACKAGE_ARCHIVE must end in either .zip or .tar.gz)
+endif
+
+endif
 
-EXTRA_BUILDDEPS += $(QEMU_PACKAGE_ZIP)
+EXTRA_BUILDDEPS += $(QEMU_PACKAGE_ARCHIVE)
 
 QEMU_PACKAGE_CONFIG :=
 QEMU_PACKAGE_FILES :=
 QEMU_PACKAGE_EXTRA_FILES :=
 QEMU_PACKAGE_LICENSE :=
 QEMU_PACKAGE_LICENSE_FILES :=
-QEMU_PACKAGE_ZIP :=
+QEMU_PACKAGE_ARCHIVE :=
diff --git a/project/qemu/firmware.android.dts b/project/qemu/firmware.android.dts
index 7bda369..fa21ee1 100644
--- a/project/qemu/firmware.android.dts
+++ b/project/qemu/firmware.android.dts
@@ -4,6 +4,13 @@
             compatible = "android,firmware";
             fstab {
                 compatible = "android,fstab";
+                system {
+                    compatible = "android,system";
+                    dev = "/dev/block/vda";
+                    type = "ext4";
+                    mnt_flags = "ro,barrier=1";
+                    fsmgr_flags = "wait";
+                };
                 vendor {
                     compatible = "android,vendor";
                     dev = "/dev/block/vdb";
diff --git a/project/qemu/qemu.py b/project/qemu/qemu.py
index 1fc6949..3d64560 100644
--- a/project/qemu/qemu.py
+++ b/project/qemu/qemu.py
@@ -4,6 +4,7 @@ import enum
 import errno
 import fcntl
 import json
+import logging
 import os
 from textwrap import dedent
 import re
@@ -21,35 +22,55 @@ from typing import Optional, List
 import qemu_options
 from qemu_error import AdbFailure, ConfigError, RunnerGenericError, Timeout
 
+logger = logging.getLogger(__name__)
 
 # ADB expects its first console on 5554, and control on 5555
 ADB_BASE_PORT = 5554
 
+_TRUSTY_PRODUCT_PATH = "target/product/trusty"
+_ANDROID_HOST_PATH = "host/linux-x86"
 
 def find_android_build_dir(android):
-    if os.path.exists(f"{android}/target/product/trusty"):
+    if os.path.exists(os.path.join(android, _TRUSTY_PRODUCT_PATH)):
         return android
-    if os.path.exists(f"{android}/out/target/product/trusty"):
-        return f"{android}/out"
+    if os.path.exists(os.path.join(android, "out", _TRUSTY_PRODUCT_PATH)):
+        return os.path.join(android, "out")
 
     print(f"{android} not an Android source or build directory")
     sys.exit(1)
 
 
+def find_android_image_dir(android):
+    return os.path.join(find_android_build_dir(android), _TRUSTY_PRODUCT_PATH)
+
+def find_adb_path(android):
+    return os.path.join(find_android_build_dir(android), _ANDROID_HOST_PATH, "bin/adb")
+
+
 class Config(object):
     """Stores a QEMU configuration for use with the runner
 
     Attributes:
-        android:          Path to a built Android tree or prebuilt.
-        linux:            Path to a built Linux kernel tree or prebuilt.
+        boot_android:     Boolean indicating to boot Android. Setting the
+                          "android" config option to a path containing a
+                          built Android tree or prebuilt will implicitly
+                          set this attribute to true
+        android_image_dir: Path to directory containing Android images.
+                           Can be set by providing a built Android tree
+                           or prebuilt with the "android" config option.
+                           Implies booting android.
+        linux:            Path to a built Linux kernel tree or prebuilt
+                          kernel image.
         linux_arch:       Architecture of Linux kernel.
         atf:              Path to the ATF build to use.
         qemu:             Path to the emulator to use.
         arch:             Architecture definition.
         rpmbd:            Path to the rpmb daemon to use.
+        adb:              Path to adb host tool.
         extra_qemu_flags: Extra flags to pass to QEMU.
-    Setting android or linux to None will result in a QEMU which starts
-    without those components.
+    Setting android or linux to a false value will result in a QEMU which starts
+    without those components. Only one of android and android_image_dir may be provided
+    in the config.
     """
 
     def __init__(self, config=None):
@@ -73,10 +94,20 @@ class Config(object):
                 return os.path.join(self.script_dir, config_value)
             return None
 
+        if config_dict.get("android") and config_dict.get("android_image_dir"):
+            raise ConfigError("Config may only have one of android and android_image_dir")
+
+        self.adb = abspath("adb")
         if android_path := abspath("android"):
-            self.android = find_android_build_dir(android_path)
+            logger.error("`android` config setting is deprecated. Please replace with "
+                         "`android_image_dir` and `adb` config entries.")
+            android_out = find_android_build_dir(android_path)
+            self.android_image_dir = os.path.join(android_out, _TRUSTY_PRODUCT_PATH)
+            if self.adb is None:
+                self.adb = os.path.join(android_out, _ANDROID_HOST_PATH, "bin/adb")
         else:
-            self.android = None
+            self.android_image_dir = abspath("android_image_dir")
+        self.boot_android = self.android_image_dir is not None
         self.linux = abspath("linux")
         self.linux_arch = config_dict.get("linux_arch")
         self.atf = abspath("atf")
@@ -92,7 +123,7 @@ class Config(object):
         if android_tests:
             if not self.linux:
                 raise ConfigError("Need Linux to run android tests")
-            if not self.android:
+            if not self.boot_android:
                 raise ConfigError("Need Android to run android tests")
 
         # For now, we can't run boot tests and android tests at the same time,
@@ -110,10 +141,16 @@ class Config(object):
             if interactive:
                 raise ConfigError("Cannot run boot tests interactively")
 
-        if self.android:
+        if self.boot_android:
             if not self.linux:
                 raise ConfigError("Cannot run Android without Linux")
 
+            if not self.android_image_dir:
+                raise ConfigError("Missing android_image_dir for Android")
+
+            if not self.adb:
+                raise ConfigError("Missing adb tool for Android")
+
 
 def alloc_ports():
     """Allocates 2 sequential ports above 5554 for adb"""
@@ -236,12 +273,12 @@ class QEMUCommandPipe(object):
             cmp_command["arguments"] = arguments
         return self.qmp_command(cmp_command)
 
-    def monitor_command(self, monitor_command):
+    def monitor_command(self, monitor_command, log_return=True):
         """Send a monitor command and write result to stderr."""
 
         res = self.qmp_execute("human-monitor-command",
                                {"command-line": monitor_command})
-        if res and "return" in res:
+        if log_return and res and "return" in res:
             sys.stderr.write(res["return"])
 
 
@@ -262,7 +299,7 @@ def qemu_handle_error(command_pipe, debug_on_error):
 
 
 def qemu_exit(command_pipe, qemu_proc, has_error, debug_on_error):
-    """Ensures QEMU is terminated"""
+    """Ensures QEMU is terminated. Tries to write to drive image files."""
     unclean_exit = False
 
     if command_pipe:
@@ -327,6 +364,7 @@ class Runner(object):
 
     def __init__(self,
                  config,
+                 instance_dir: os.PathLike,
                  interactive=False,
                  verbose=False,
                  rpmb=True,
@@ -349,10 +387,10 @@ class Runner(object):
         self.msg_sock_dir = None
         self.debug_on_error = debug_on_error
         self.dump_stdout_on_error = False
-        self.qemu_arch_options = None
         self.default_timeout = 60 * 10  # 10 Minutes
         self.session: Optional[RunnerSession] = None
         self.state = RunnerState.OFF
+        self.instance_dir = instance_dir
 
         # If we're not verbose or interactive, squelch command output
         if verbose or self.interactive:
@@ -370,10 +408,11 @@ class Runner(object):
             self.stdin = subprocess.DEVNULL
 
         if self.config.arch in ("arm64", "arm"):
-            self.qemu_arch_options = qemu_options.QemuArm64Options(self.config)
+            self.qemu_arch_options = qemu_options.QemuArm64Options(
+                self.config, self.instance_dir)
         elif self.config.arch == "x86_64":
             # pylint: disable=no-member
-            self.qemu_arch_options = qemu_options.QemuX86_64Options(self.config)
+            self.qemu_arch_options = qemu_options.QemuX86_64Options(self.config) # type: ignore[attr-defined]
         else:
             raise ConfigError("Architecture unspecified or unsupported!")
 
@@ -490,7 +529,7 @@ class Runner(object):
         if self.msg_sock_conn:
             self.msg_sock_conn.close()
 
-    def boottest_run(self, boot_tests, timeout=(60 * 2)):
+    def boottest_run(self, boot_tests, timeout=60 * 2):
         """Run boot test cases"""
         args = self.session.args
         has_error = False
@@ -566,7 +605,8 @@ class Runner(object):
                             break
                         except IOError as e:
                             if e.errno != errno.EAGAIN:
-                                RunnerGenericError("Failed to print message")
+                                raise RunnerGenericError(
+                                    "Failed to print message") from e
                             select.select([], [sys.stdout], [])
 
                 # Please align message structure definition in testrunner.
@@ -620,7 +660,7 @@ class Runner(object):
 
     def adb_bin(self):
         """Returns location of adb"""
-        return f"{self.config.android}/host/linux-x86/bin/adb"
+        return self.config.adb
 
     def adb(self,
             args,
@@ -782,7 +822,7 @@ class Runner(object):
         if self.config.linux:
             args += self.qemu_arch_options.linux_options()
 
-        if self.config.android:
+        if self.config.boot_android:
             args += self.qemu_arch_options.android_drives_args()
 
         # Append configured extra flags
@@ -821,8 +861,12 @@ class Runner(object):
 
         try:
             if self.use_rpmb:
+                self.qemu_arch_options.create_rpmb_data()
                 args += self.rpmb_up()
 
+            if self.config.boot_android:
+                self.qemu_arch_options.create_drives_data()
+
             if self.config.linux:
                 args += self.qemu_arch_options.gen_dtb(
                     args,
@@ -865,6 +909,7 @@ class Runner(object):
             args += forward_ports(self.session.ports)
 
             qemu_cmd = [self.config.qemu] + args
+            logger.info("qemu command: %s", qemu_cmd)
             self.session.qemu_proc = subprocess.Popen(  # pylint: disable=consider-using-with
                 qemu_cmd,
                 cwd=self.config.atf,
@@ -894,7 +939,7 @@ class Runner(object):
             self.session.has_error = True
             raise
 
-    def shutdown(self):
+    def shutdown(self, factory_reset: bool, full_wipe: bool):
         """Shut down emulator after test cases have run
 
         The launch and shutdown methods store shared state in a session object.
@@ -908,7 +953,10 @@ class Runner(object):
 
         # Clean up generated device tree
         for temp_file in self.session.temp_files:
-            os.remove(temp_file)
+            try:
+                os.remove(temp_file)
+            except OSError:
+                pass
 
         if self.session.has_error:
             self.error_dump_output()
@@ -929,19 +977,32 @@ class Runner(object):
             # Disconnect ADB and wait for our port to be released by qemu
             self.adb_down(self.session.ports[1])
 
+        # Ideally, we'd clear on launch instead, but it doesn't know whether a
+        # clear should happen. We can't change launch to take factory_reset and
+        # full_wipe args because TrustyRebootCommand doesn't call launch, only
+        # shutdown. (The next test that runs after a reboot will re-launch when
+        # it notices the runner is down, but that test doesn't have the
+        # RebootMode info from the reboot.)
+        if factory_reset:
+            self.qemu_arch_options.delete_drives_data()
+        if full_wipe:
+            assert factory_reset, (
+                "Cannot perform a full wipe without factory resetting.")
+            self.qemu_arch_options.delete_rpmb_data()
+
         self.session = None
         self.state = RunnerState.OFF
 
         if unclean_exit:
             raise RunnerGenericError("QEMU did not exit cleanly")
 
-    def reboot(self, target_state):
-        self.shutdown()
+    def reboot(self, target_state, factory_reset: bool, full_wipe: bool):
+        self.shutdown(factory_reset, full_wipe)
 
         try:
             self.launch(target_state)
         except:
-            self.shutdown()
+            self.shutdown(factory_reset, full_wipe)
             raise
 
     def run(self, boot_tests: Optional[List] = None,
@@ -1003,4 +1064,4 @@ class Runner(object):
             if self.interactive and self.session:
                 # The user is responsible for quitting QEMU
                 self.session.qemu_proc.wait()
-            self.shutdown()
+            self.shutdown(factory_reset=True, full_wipe=False)
diff --git a/project/qemu/qemu_arm64_options.py b/project/qemu/qemu_arm64_options.py
index 39ecb1b..176f49c 100644
--- a/project/qemu/qemu_arm64_options.py
+++ b/project/qemu/qemu_arm64_options.py
@@ -1,31 +1,103 @@
 """Generate QEMU options for Trusty test framework"""
 
+import logging
+import os
+import pathlib
+import shutil
 import subprocess
 import tempfile
 
 from qemu_error import RunnerGenericError
 
+logger = logging.getLogger(__name__)
+
+def _find_dtc():
+    for search_dir in ["out/host/linux-x86/bin", "prebuilts/misc/linux-x86/dtc", "bin"]:
+        path = os.path.join(search_dir, "dtc")
+        if os.path.exists(path):
+            return path
+    return None
+
+
+class QemuDrive():
+    def __init__(self, name: str, index: int, read_only: bool = True):
+        self.name = name
+        self.index = index
+        self.read_only = read_only
+
+    def index_letter(self):
+        return chr(ord('a') + self.index)
+
+    def path(self, directory: os.PathLike):
+        return f"{directory}/{self.name}.img"
+
+    def ensure_image_exists(self, image_dir: os.PathLike,
+                            instance_dir: os.PathLike):
+        if self.read_only:
+            return
+
+        path = self.path(instance_dir)
+        if not os.path.exists(path):
+            snapshot_path = self.path(image_dir)
+            shutil.copy(snapshot_path, path)
+
+    def delete_image_changes(self, instance_dir: os.PathLike):
+        if self.read_only:
+            return
+
+        try:
+            os.remove(self.path(instance_dir))
+        except FileNotFoundError:
+            pass
+
+    def args(self, image_dir: os.PathLike, instance_dir: os.PathLike):
+        path = self.path(image_dir if self.read_only else instance_dir)
+        snapshot = "on" if self.read_only else "off"
+        return [
+            "-drive",
+            (f"file={path},index={self.index},if=none,"
+             + f"id=hd{self.index_letter()},format=raw,snapshot={snapshot}"),
+            "-device",
+            f"virtio-blk-device,drive=hd{self.index_letter()}"
+        ]
 
 class QemuArm64Options(object):
 
     MACHINE = "virt,secure=on,virtualization=on"
 
     BASIC_ARGS = [
-        "-nographic", "-cpu", "cortex-a57", "-smp", "4", "-m", "1024", "-d",
+        "-nographic", "-cpu", "max,sve=off,pauth=off", "-smp", "4", "-m", "1024", "-d",
         "unimp", "-semihosting-config", "enable,target=native", "-no-acpi",
     ]
 
     LINUX_ARGS = (
         "earlyprintk console=ttyAMA0,38400 keep_bootcon "
-        "root=/dev/vda ro init=/init androidboot.hardware=qemu_trusty "
+        "root=/dev/ram0 init=/init androidboot.hardware=qemu_trusty "
         "trusty-log.log_ratelimit_interval=0 trusty-log.log_to_dmesg=always")
 
-    def __init__(self, config):
+    def __init__(self, config, instance_dir):
         self.args = []
         self.config = config
+        self.instance_dir = instance_dir
+
+    def create_rpmb_data(self):
+        """If no rpmb data image exists, copy the snapshot to create new one."""
+        os.makedirs(self.instance_dir, exist_ok=True)
+        path = self.rpmb_data_path()
+        if not os.path.exists(path):
+            shutil.copy(self.rpmb_data_snapshot_path(), path)
+
+    def delete_rpmb_data(self):
+        try:
+            os.remove(self.rpmb_data_path())
+        except FileNotFoundError:
+            pass
+
+    def rpmb_data_snapshot_path(self):
+        return f"{self.config.atf}/RPMB_DATA"
 
     def rpmb_data_path(self):
-        return f"{self.config.atf}/RPMB_DATA"
+        return f"{self.instance_dir}/RPMB_DATA"
 
     def rpmb_options(self, sock):
         return [
@@ -33,19 +105,39 @@ class QemuArm64Options(object):
             "-device", "virtserialport,chardev=rpmb0,name=rpmb0",
             "-chardev", f"socket,id=rpmb0,path={sock}"]
 
+    def get_initrd_filename(self):
+        return self.config.android_image_dir + "/ramdisk.img"
+
+    def initrd_dts(self):
+        file_stats = os.stat(self.get_initrd_filename())
+        start_addr = 0x48000000
+        end_addr = start_addr + file_stats.st_size
+
+        return f"""/ {{
+        chosen {{
+            linux,initrd-start = <0x0 0x{start_addr:08x}>;
+            linux,initrd-end = <0x0 0x{end_addr:08x}>;
+        }};
+    }};
+        """
+
     def gen_dtb(self, args, dtb_tmp_file):
         """Computes a trusty device tree, returning a file for it"""
+        dtc = _find_dtc()
+        if dtc is None:
+            raise RunnerGenericError("Could not find dtc tool")
         with tempfile.NamedTemporaryFile() as dtb_gen:
             dump_dtb_cmd = [
                 self.config.qemu, "-machine",
                 f"{self.MACHINE},dumpdtb={dtb_gen.name}"
             ] + [arg for arg in args if arg != "-S"]
+            logger.info("dump dtb command: %s", " ".join(dump_dtb_cmd))
             returncode = subprocess.call(dump_dtb_cmd)
             if returncode != 0:
                 raise RunnerGenericError(
                     f"dumping dtb failed with {returncode}")
-            dtc = f"{self.config.linux}/scripts/dtc/dtc"
             dtb_to_dts_cmd = [dtc, "-q", "-O", "dts", dtb_gen.name]
+            logger.info("dtb to dts command: %s", " ".join(dtb_to_dts_cmd))
             # pylint: disable=consider-using-with
             with subprocess.Popen(dtb_to_dts_cmd,
                                   stdout=subprocess.PIPE,
@@ -59,6 +151,8 @@ class QemuArm64Options(object):
         with open(firmware, "r", encoding="utf-8") as firmware_file:
             dts += firmware_file.read()
 
+        dts += self.initrd_dts()
+
         # Subprocess closes dtb, so we can't allow it to autodelete
         dtb = dtb_tmp_file
         dts_to_dtb_cmd = [dtc, "-q", "-O", "dtb"]
@@ -73,25 +167,29 @@ class QemuArm64Options(object):
             raise RunnerGenericError(f"dts_to_dtb failed with {dts_to_dtb_ret}")
         return ["-dtb", dtb.name]
 
-    def drive_args(self, image, index):
-        """Generates arguments for mapping a drive"""
-        index_letter = chr(ord('a') + index)
-        image_dir = f"{self.config.android}/target/product/trusty"
+    def drives(self) -> list[QemuDrive]:
         return [
-            "-drive",
-            # pylint: disable=line-too-long
-            f"file={image_dir}/{image}.img,index={index},if=none,id=hd{index_letter},format=raw,snapshot=on",
-            "-device",
-            f"virtio-blk-device,drive=hd{index_letter}"
+            QemuDrive("userdata", 2, read_only=False),
+            QemuDrive("vendor", 1),
+            QemuDrive("system", 0)
         ]
 
+    def create_drives_data(self):
+        """If drives images don't exist, create some from their snapshots."""
+        os.makedirs(self.instance_dir, exist_ok=True)
+        for drive in self.drives():
+            drive.ensure_image_exists(self.config.android_image_dir, self.instance_dir)
+
+    def delete_drives_data(self):
+        for drive in self.drives():
+            drive.delete_image_changes(self.instance_dir)
+
     def android_drives_args(self):
         """Generates arguments for mapping all default drives"""
         args = []
         # This is order sensitive due to using e.g. root=/dev/vda
-        args += self.drive_args("userdata", 2)
-        args += self.drive_args("vendor", 1)
-        args += self.drive_args("system", 0)
+        for drive in self.drives():
+            args += drive.args(self.config.android_image_dir, self.instance_dir)
         return args
 
     def machine_options(self):
@@ -103,12 +201,25 @@ class QemuArm64Options(object):
     def bios_options(self):
         return ["-bios", f"{self.config.atf}/bl1.bin"]
 
+    def find_kernel_image(self):
+        if pathlib.Path(self.config.linux).is_file():
+            return self.config.linux
+        image = f"{self.config.linux}/arch/{self.config.linux_arch}/boot/Image"
+        if os.path.exists(image):
+            return image
+        return None
+
     def linux_options(self):
+        kernel = self.find_kernel_image()
+        if kernel is None:
+            raise RunnerGenericError("Could not find kernel image")
         return [
             "-kernel",
-            f"{self.config.linux}/arch/{self.config.linux_arch}/boot/Image",
+            kernel,
+            "-initrd",
+            self.get_initrd_filename(),
             "-append", self.LINUX_ARGS
         ]
 
     def android_trusty_user_data(self):
-        return f"{self.config.android}/target/product/trusty/data"
+        return os.path.join(self.config.android_image_dir, "data")
diff --git a/project/qemu/run-qemu-helper b/project/qemu/run-qemu-helper
deleted file mode 100755
index 8701411..0000000
--- a/project/qemu/run-qemu-helper
+++ /dev/null
@@ -1,76 +0,0 @@
-#!/bin/bash
-
-set -e
-set -u
-
-if [ -v ANDROID_DIR ]; then
-    if [ ! -d "${ANDROID_DIR}" ]; then
-        echo ANDROID_DIR, "${ANDROID_DIR}", must be a directory
-        exit 1
-    fi
-    if [ ! -v ANDROID_PRODUCT ]; then
-        ANDROID_PRODUCT="trusty"
-    fi
-    ANDROID_BUILD_DIR="${ANDROID_DIR}/out/target/product/${ANDROID_PRODUCT}"
-fi
-
-if [ ! -v EXTRA_CMDLINE ]; then
-    EXTRA_CMDLINE=""
-fi
-
-QEMU_MACHINE="-machine virt,secure=on,virtualization=on"
-QEMU_FINAL_ARGS=()
-QEMU_ARGS=(
-    -nographic
-    -cpu cortex-a57
-    -smp 4
-    -m 1024
-    -bios bl1.bin
-    -d unimp
-    -semihosting-config enable,target=native
-    -no-acpi
-    )
-QEMU_SERIAL_ARGS=(
-    -serial mon:stdio
-    )
-for ARG in "$@"; do
-    if [ "${ARG}" = "-S" ]; then
-        QEMU_FINAL_ARGS+=("${ARG}")
-    else
-        QEMU_ARGS+=("${ARG}")
-    fi
-    if [ "${ARG}" = "-serial" ]; then
-        QEMU_SERIAL_ARGS=()
-    fi
-done
-QEMU_ARGS+=(${QEMU_SERIAL_ARGS[@]+${QEMU_SERIAL_ARGS[@]}})
-
-if [ -v KERNEL_DIR ]
-then
-    DTC="${KERNEL_DIR}/scripts/dtc/dtc"
-    QEMU_ARGS+=(
-        -kernel ${KERNEL_DIR}/arch/arm64/boot/Image
-        -append "earlyprintk console=ttyAMA0,38400 keep_bootcon root=/dev/vda ro init=/init androidboot.hardware=qemu_trusty ${EXTRA_CMDLINE}"
-        )
-    if [ -v ANDROID_BUILD_DIR ]; then
-        QEMU_ARGS+=(
-            -drive file=${ANDROID_BUILD_DIR}/userdata.img,index=2,if=none,id=hdc,format=raw
-            -device virtio-blk-device,drive=hdc
-            -drive file=${ANDROID_BUILD_DIR}/vendor.img,index=1,if=none,id=hdb,format=raw
-            -device virtio-blk-device,drive=hdb
-            -drive file=${ANDROID_BUILD_DIR}/system.img,index=0,if=none,id=hda,format=raw
-            -device virtio-blk-device,drive=hda
-            )
-    else
-        echo Set ANDROID_DIR to run a non-secure android build
-    fi
-    ${QEMU} ${QEMU_MACHINE},dumpdtb=qemu-gen.dtb "${QEMU_ARGS[@]}"
-    ${DTC} -q -O dts qemu-gen.dtb >qemu-gen.dts
-    cat qemu-gen.dts firmware.android.dts | ${DTC} -q -O dtb >qemu-comb.dtb
-    QEMU_ARGS+=(
-        -dtb qemu-comb.dtb
-        )
-else
-    echo Set KERNEL_DIR to run a non-secure kernel
-fi
-${QEMU} ${QEMU_MACHINE} "${QEMU_ARGS[@]}" ${QEMU_FINAL_ARGS[@]+"${QEMU_FINAL_ARGS[@]}"}
diff --git a/project/qemu/run.py b/project/qemu/run.py
index c2c706e..9a44fb4 100755
--- a/project/qemu/run.py
+++ b/project/qemu/run.py
@@ -2,6 +2,7 @@
 "exec" "`dirname $0`/py3-cmd" "$0" "-c" "`dirname $0`/config.json" "$@"
 
 import argparse
+import logging
 import os
 from typing import List, Optional
 import sys
@@ -16,17 +17,21 @@ __all__ = ["init", "run_test", "shutdown"]
 TRUSTY_PROJECT_FOLDER = os.path.dirname(os.path.realpath(__file__))
 
 
-def init(*, android=None, disable_rpmb=False, verbose=False,
-         debug_on_error=False) -> qemu.Runner:
+def init(*, android=None, instance_dir: os.PathLike, disable_rpmb=False,
+         verbose=False, debug_on_error=False
+) -> qemu.Runner:
 
     with open(f"{TRUSTY_PROJECT_FOLDER}/config.json", encoding="utf-8") as json:
         config = qemu.Config(json)
 
     if android:
-        config.android = qemu.find_android_build_dir(android)
+        config.android_image_dir = qemu.find_android_image_dir(android)
+        config.adb = qemu.find_adb_path(android)
+        config.boot_android = True
 
     runner = qemu.Runner(config,
                          interactive=False,
+                         instance_dir=instance_dir,
                          verbose=verbose,
                          rpmb=not disable_rpmb,
                          debug=False,
@@ -64,7 +69,7 @@ def _prepare_runner_for_test(runner, args):
     # Due to limitations in the test runner, always reboot between boot tests
     if (runner.state != target_state or
             runner.state == qemu.RunnerState.BOOTLOADER):
-        runner.reboot(target_state)
+        runner.reboot(target_state, factory_reset=True, full_wipe=False)
 
 
 def run_test(runner: qemu.Runner, cmd: List[str]) -> int:
@@ -82,9 +87,11 @@ def run_test(runner: qemu.Runner, cmd: List[str]) -> int:
         "Command contained neither a boot test nor an Android test to run")
 
 
-def shutdown(runner: Optional[qemu.Runner]):
+def shutdown(runner: Optional[qemu.Runner],
+             factory_reset: bool = True,
+             full_wipe: bool = False):
     if runner:
-        runner.shutdown()
+        runner.shutdown(factory_reset, full_wipe)
 
 
 def build_argparser():
@@ -98,6 +105,8 @@ def build_argparser():
     argument_parser.add_argument("--shell-command", action="append")
     argument_parser.add_argument("--android")
     argument_parser.add_argument("--linux")
+    argument_parser.add_argument("--instance-dir", type=str,
+                                 default="/tmp/trusty-qemu-generic-arm64")
     argument_parser.add_argument("--atf")
     argument_parser.add_argument("--qemu")
     argument_parser.add_argument("--arch")
@@ -109,10 +118,14 @@ def build_argparser():
 
 def main():
     args = build_argparser().parse_args()
+    log_level = logging.DEBUG if args.verbose else logging.WARN
+    logging.basicConfig(level=log_level)
 
     config = qemu.Config(args.config)
     if args.android:
-        config.android = qemu.find_android_build_dir(args.android)
+        config.android_image_dir = qemu.find_android_image_dir(args.android)
+        config.adb = qemu.find_adb_path(args.android)
+        config.boot_android = True
     if args.linux:
         config.linux = args.linux
     if args.atf:
@@ -126,6 +139,7 @@ def main():
 
     runner = qemu.Runner(config,
                          interactive=not args.headless,
+                         instance_dir=args.instance_dir,
                          verbose=args.verbose,
                          rpmb=not args.disable_rpmb,
                          debug=args.debug,
```

