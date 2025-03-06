```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..e1a8814
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_device_arm_generic-arm64",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/project/generic-arm-inc.mk b/project/generic-arm-inc.mk
index 2d43121..833e9d6 100644
--- a/project/generic-arm-inc.mk
+++ b/project/generic-arm-inc.mk
@@ -86,6 +86,11 @@ KERNEL_LTO_ENABLED ?= true
 USER_CFI_ENABLED ?= true
 KERNEL_CFI_ENABLED ?= true
 
+#TODO(b/373398295): if clang is too old to support cross-language CFI, disable it
+ifneq ($(findstring clang-r498229b,$(CLANG_BINDIR)),)
+KERNEL_CFI_ENABLED := false
+endif
+
 # Storage should send error reports to the metrics service
 STORAGE_ENABLE_ERROR_REPORTING := true
 STORAGE_AIDL_ENABLED ?= true
diff --git a/project/hafnium/trusty.dts b/project/hafnium/trusty.dts
index f0b144b..7b7b3aa 100644
--- a/project/hafnium/trusty.dts
+++ b/project/hafnium/trusty.dts
@@ -19,11 +19,8 @@
     notification-support; /* Support receipt of notifications. */
 
     ns-interrupts-action = <1>; /* Managed exit is supported */
+    /* Trusty reschedules the current thread on an IRQ but not a FIQ */
+    managed-exit-virq;
 
     boot-order = <0>;
-    gp-register-num = <0>; /* Place boot data into x0 */
-    boot-info {
-        compatible = "arm,ffa-manifest-boot-info";
-        ffa_manifest;
-    };
 };
diff --git a/project/linux-inc.mk b/project/linux-inc.mk
index 9a2f3c2..60815e8 100644
--- a/project/linux-inc.mk
+++ b/project/linux-inc.mk
@@ -62,9 +62,8 @@ endif
 
 ifeq (,$(LINUX_TRUSTY_INTREE))
 LINUX_DEFCONFIG_FRAGMENTS += \
-	linux/common-modules/trusty/arm_ffa.fragment \
+	linux/common-modules/trusty/system_heap.fragment \
 	linux/common-modules/trusty/trusty_defconfig.fragment \
-	linux/common-modules/trusty/trusty_test.fragment \
 	linux/common-modules/virtual-device/aarch64.fragment \
 	linux/common-modules/virtual-device/virtual_device_core.fragment \
 
diff --git a/project/qemu-atf-inc.mk b/project/qemu-atf-inc.mk
index 03a8fa9..ed51f05 100644
--- a/project/qemu-atf-inc.mk
+++ b/project/qemu-atf-inc.mk
@@ -65,6 +65,7 @@ ATF_MAKE_ARGS := SPD=trusty
 ATF_MAKE_ARGS += SPMD_SPM_AT_SEL2=0
 endif
 ATF_MAKE_ARGS += CC=$(CLANG_BINDIR)/clang
+ATF_MAKE_ARGS += DTC=$(TRUSTY_TOP)/prebuilts/misc/linux-x86/dtc/dtc
 ATF_MAKE_ARGS += CROSS_COMPILE=$(ATF_TOOLCHAIN_PREFIX)
 ATF_MAKE_ARGS += PLAT=$(ATF_PLAT)
 ATF_MAKE_ARGS += DEBUG=$(ATF_DEBUG)
diff --git a/project/qemu-generic-arm64-gicv3-spd-ffa-test-debug.mk b/project/qemu-generic-arm64-gicv3-spd-ffa-test-debug.mk
new file mode 100644
index 0000000..93f9341
--- /dev/null
+++ b/project/qemu-generic-arm64-gicv3-spd-ffa-test-debug.mk
@@ -0,0 +1,25 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+QEMU_TRUSTY_PROJECT := generic-arm64-gicv3-test-debug
+
+# D-cache lines are 64 bytes on QEMU arm64
+GLOBAL_DEFINES += CACHE_LINE=64
+
+# Enable the FFA loop to test compatibility
+SPMC_EL :=
+LIB_SM_WITH_FFA_LOOP := true
+
+include project/qemu-inc.mk
diff --git a/project/qemu-generic-arm64-gicv3-spd-noffa-test-debug.mk b/project/qemu-generic-arm64-gicv3-spd-noffa-test-debug.mk
new file mode 100644
index 0000000..dbead14
--- /dev/null
+++ b/project/qemu-generic-arm64-gicv3-spd-noffa-test-debug.mk
@@ -0,0 +1,25 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+QEMU_TRUSTY_PROJECT := generic-arm64-gicv3-test-debug
+
+# D-cache lines are 64 bytes on QEMU arm64
+GLOBAL_DEFINES += CACHE_LINE=64
+
+# Disable the FFA loop and SPMC explicitly
+SPMC_EL :=
+LIB_SM_WITH_FFA_LOOP := false
+
+include project/qemu-inc.mk
diff --git a/project/qemu-inc.mk b/project/qemu-inc.mk
index 861b173..8f6261f 100644
--- a/project/qemu-inc.mk
+++ b/project/qemu-inc.mk
@@ -174,13 +174,6 @@ $(ATF_OUT_DIR)/bl33.bin: ATF_OUT_DIR := $(ATF_OUT_DIR)
 $(ATF_OUT_DIR)/bl33.bin: $(TEST_RUNNER_BIN) $(ATF_OUT_DIR)
 	$(NOECHO)ln -rsf $< $@
 
-ATF_OUT_COPIED_FILES := \
-	$(ATF_OUT_DIR)/firmware.android.dts \
-
-$(ATF_OUT_COPIED_FILES): $(ATF_OUT_DIR)/% : $(PROJECT_QEMU_INC_LOCAL_DIR)/qemu/% $(ATF_OUT_DIR)
-	@echo copying $@
-	@cp $< $@
-
 $(ATF_OUT_DIR)/RPMB_DATA: ATF_OUT_DIR := $(ATF_OUT_DIR)
 $(ATF_OUT_DIR)/RPMB_DATA: $(RPMB_DEV)
 	@echo Initialize rpmb device
@@ -334,15 +327,20 @@ ifeq (true,$(call TOBOOL,$(PACKAGE_QEMU_TRUSTY)))
 # Files & directories to copy into QEMU package archive
 QEMU_PACKAGE_FILES := \
 	$(OUTBIN) $(QEMU_SCRIPTS) $(PY3_CMD) $(QEMU_CONFIG) $(RPMB_DEV) \
-	$(RUN_SCRIPT) $(STOP_SCRIPT) $(ANDROID_OUT_BUILD_DIR) \
+	$(RUN_SCRIPT) $(STOP_SCRIPT) \
 	$(QEMU_BIN) $(ATF_BIN) $(ATF_SYMLINKS) \
 	$(ATF_OUT_DIR)/RPMB_DATA $(ATF_OUT_COPIED_FILES) $(LINUX_IMAGE) \
 
+ifneq (true,$(call TOBOOL,$(PACKAGE_QEMU_WITHOUT_ANDROID)))
+# The Android prebuilts are pretty large and not all users need them
+QEMU_PACKAGE_FILES += $(ANDROID_OUT_BUILD_DIR)
+endif
+
 # Other files/directories that should be included in the package but which are
 # not make targets and therefore cannot be pre-requisites. The target that
 # creates these files must be in the QEMU_PACKAGE_FILES variable.
 QEMU_PACKAGE_EXTRA_FILES := \
-	$(LINUX_BUILD_DIR)/arch $(LINUX_BUILD_DIR)/scripts \
+	$(LINUX_BUILD_DIR)/scripts \
 	$(QEMU_BUILD_BASE) $(ATF_EXTRA_BINS) \
 
 QEMU_PACKAGE_ARCHIVE := $(BUILDDIR)/trusty_qemu_package.zip
diff --git a/project/qemu/firmware.android.dts b/project/qemu/firmware.android.dts
deleted file mode 100644
index fa21ee1..0000000
--- a/project/qemu/firmware.android.dts
+++ /dev/null
@@ -1,24 +0,0 @@
-/ {
-    firmware {
-        android {
-            compatible = "android,firmware";
-            fstab {
-                compatible = "android,fstab";
-                system {
-                    compatible = "android,system";
-                    dev = "/dev/block/vda";
-                    type = "ext4";
-                    mnt_flags = "ro,barrier=1";
-                    fsmgr_flags = "wait";
-                };
-                vendor {
-                    compatible = "android,vendor";
-                    dev = "/dev/block/vdb";
-                    type = "ext4";
-                    mnt_flags = "ro,barrier=1";
-                    fsmgr_flags = "wait";
-                };
-            };
-        };
-    };
-};
diff --git a/project/qemu/qemu.py b/project/qemu/qemu.py
index 3d64560..13fdd0c 100644
--- a/project/qemu/qemu.py
+++ b/project/qemu/qemu.py
@@ -552,12 +552,9 @@ class Runner(object):
 
         if self.interactive:
             args = ["-serial", "mon:stdio"] + args
-        elif self.verbose:
+        else:
             # This still leaves stdin connected, but doesn't connect a monitor
             args = ["-serial", "stdio", "-monitor", "none"] + args
-        else:
-            # Silence debugging output
-            args = ["-serial", "null", "-monitor", "none"] + args
 
         # Create command channel which used to quit QEMU after case execution
         command_pipe = QEMUCommandPipe()
@@ -565,7 +562,10 @@ class Runner(object):
         cmd = [self.config.qemu] + args
 
         # pylint: disable=consider-using-with
-        qemu_proc = subprocess.Popen(cmd, cwd=self.config.atf)
+        qemu_proc = subprocess.Popen(cmd, cwd=self.config.atf,
+                                     stdin=self.stdin,
+                                     stdout=self.stdout,
+                                     stderr=self.stderr)
 
         command_pipe.open()
         self.msg_channel_wait_for_connection()
@@ -625,6 +625,7 @@ class Runner(object):
         finally:
             kill_timer.cancel()
             self.msg_channel_down()
+            self.session.has_error = has_error or result != 0
             unclean_exit = qemu_exit(command_pipe, qemu_proc,
                                      has_error=has_error,
                                      debug_on_error=self.debug_on_error)
diff --git a/project/qemu/qemu_arm64_options.py b/project/qemu/qemu_arm64_options.py
index 176f49c..5dc5023 100644
--- a/project/qemu/qemu_arm64_options.py
+++ b/project/qemu/qemu_arm64_options.py
@@ -12,7 +12,7 @@ from qemu_error import RunnerGenericError
 logger = logging.getLogger(__name__)
 
 def _find_dtc():
-    for search_dir in ["out/host/linux-x86/bin", "prebuilts/misc/linux-x86/dtc", "bin"]:
+    for search_dir in ["out/host/linux-x86/bin", "prebuilts/misc/linux-x86/dtc", "bin", "linux-build/scripts/dtc"]:
         path = os.path.join(search_dir, "dtc")
         if os.path.exists(path):
             return path
@@ -147,10 +147,6 @@ class QemuArm64Options(object):
                     raise RunnerGenericError(
                         f"dtb_to_dts failed with {dtb_to_dts.returncode}")
 
-        firmware = f"{self.config.atf}/firmware.android.dts"
-        with open(firmware, "r", encoding="utf-8") as firmware_file:
-            dts += firmware_file.read()
-
         dts += self.initrd_dts()
 
         # Subprocess closes dtb, so we can't allow it to autodelete
```

