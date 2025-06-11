```diff
diff --git a/project/el3spmc/tos_fw_config.dts b/project/el3spmc/tos_fw_config.dts
new file mode 100644
index 0000000..86a0760
--- /dev/null
+++ b/project/el3spmc/tos_fw_config.dts
@@ -0,0 +1,25 @@
+/*
+ * Copyright (c) 2022, Arm Limited. All rights reserved.
+ *
+ * SPDX-License-Identifier: Apache-2.0
+ */
+/dts-v1/;
+
+#define EL1		(0x0)
+#define S_EL0		(0x1)
+#define S_EL1		(0x2)
+
+/ {
+	compatible = "arm,ffa-manifest-1.0";
+	#address-cells = <2>;
+	#size-cells = <1>;
+
+	ffa-version = <0x00010002>; /* 31:16 - Major, 15:0 - Minor */
+	id = <0x8001>;
+	uuid = <0xf025ee40 0x4c30bca2 0x73a14c8c 0xf18a7dc5>,
+	       <0x9120b8c5 0xbb48fed4 0x244de7b7 0xbe28bb6e>;
+	messaging-method = <0x00000201>; /* Can receive SEND_DIRECT_REQ/DIRECT_REQ2 only */
+	exception-level = <S_EL1>;
+	execution-state = <0>;
+	execution-ctx-count = <32>; /* Must match PLATFORM_CORE_COUNT */
+};
diff --git a/project/generic-arm-inc.mk b/project/generic-arm-inc.mk
index 833e9d6..b24b3d8 100644
--- a/project/generic-arm-inc.mk
+++ b/project/generic-arm-inc.mk
@@ -123,7 +123,7 @@ endif
 #
 # - Rust implementation:   export TRUSTY_KEYMINT_IMPL=rust
 # - C++ implementation:    (any other value of TRUSTY_KEYMINT_IMPL)
-
+TRUSTY_KEYMINT_IMPL := rust
 ifeq ($(TRUSTY_KEYMINT_IMPL),rust)
     TRUSTY_KEYMINT_USER_TASK := trusty/user/app/keymint/app
 else
@@ -177,6 +177,7 @@ TRUSTY_PREBUILT_USER_TASKS :=
 
 # compiled from source
 TRUSTY_BUILTIN_USER_TASKS := \
+	trusty/user/app/authmgr/authmgr-be/app \
 	trusty/user/app/avb \
 	trusty/user/app/cast-auth/app \
 	trusty/user/app/confirmationui \
@@ -188,6 +189,7 @@ TRUSTY_BUILTIN_USER_TASKS := \
 	trusty/user/app/sample/hwcrypto \
 	trusty/user/app/sample/hwcryptohal/server/app \
 	trusty/user/app/sample/hwwsk \
+	trusty/user/app/sample/rust-hello-world-trusted-hal/app \
 	trusty/user/app/sample/secure_fb_mock_impl \
 	trusty/user/app/storage \
 	trusty/user/base/app/apploader \
diff --git a/project/generic-arm-tz-inc.mk b/project/generic-arm-tz-inc.mk
new file mode 100644
index 0000000..5fc28da
--- /dev/null
+++ b/project/generic-arm-tz-inc.mk
@@ -0,0 +1,15 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+include project/generic-arm-inc.mk
diff --git a/project/generic-arm-test-inc.mk b/project/generic-arm-tz-test-inc.mk
similarity index 97%
rename from project/generic-arm-test-inc.mk
rename to project/generic-arm-tz-test-inc.mk
index 39fdd2e..0f2df70 100644
--- a/project/generic-arm-test-inc.mk
+++ b/project/generic-arm-tz-test-inc.mk
@@ -23,7 +23,7 @@ UBSAN_ENABLED ?= true
 
 RELEASE_BUILD ?= false
 
-include project/generic-arm-inc.mk
+include project/generic-arm-tz-inc.mk
 
 include frameworks/native/libs/binder/trusty/usertests-inc.mk
 include trusty/kernel/kerneltests-inc.mk
diff --git a/project/generic-arm-virt-inc.mk b/project/generic-arm-virt-inc.mk
index a11912f..c7cf90c 100644
--- a/project/generic-arm-virt-inc.mk
+++ b/project/generic-arm-virt-inc.mk
@@ -28,5 +28,13 @@ WITH_TRUSTY_VIRTIO_IPC_DEV := false
 GENERIC_ARM64_DEBUG := UART
 
 GIC_VERSION := 3
+# TODO(b/383197438): Disable SMP until we have code to enable secondary CPUs
+SMP_MAX_CPUS := 1
 GLOBAL_DEFINES += ARM_GIC_SELECTED_IRQ_GROUP=GRP1NS
 TIMER_ARM_GENERIC_SELECTED ?= CNTV
+
+# Enable MMIO guard
+MMIO_GUARD_ENABLED ?= true
+
+TRUSTY_VM_GUEST := true
+GLOBAL_DEFINES += TRUSTY_VM_GUEST=1
diff --git a/project/generic-arm32-debug.mk b/project/generic-arm32-debug.mk
index 9242554..90683dc 100644
--- a/project/generic-arm32-debug.mk
+++ b/project/generic-arm32-debug.mk
@@ -18,4 +18,4 @@ DEBUG := 2
 RELEASE_BUILD := false
 
 include project/debugging-inc.mk
-include project/generic-arm-inc.mk
+include project/generic-arm-tz-inc.mk
diff --git a/project/generic-arm32-gicv3-test-debug.mk b/project/generic-arm32-gicv3-test-debug.mk
index ba2af48..421267e 100644
--- a/project/generic-arm32-gicv3-test-debug.mk
+++ b/project/generic-arm32-gicv3-test-debug.mk
@@ -17,4 +17,4 @@ KERNEL_32BIT := true
 DEBUG := 2
 GIC_VERSION := 3
 
-include project/generic-arm-test-inc.mk
+include project/generic-arm-tz-test-inc.mk
diff --git a/project/generic-arm32-test-debug-inc.mk b/project/generic-arm32-test-debug-inc.mk
index 337be59..4f15aa6 100644
--- a/project/generic-arm32-test-debug-inc.mk
+++ b/project/generic-arm32-test-debug-inc.mk
@@ -17,4 +17,4 @@ KERNEL_32BIT := true
 DEBUG := 2
 
 include project/debugging-inc.mk
-include project/generic-arm-test-inc.mk
+include project/generic-arm-tz-test-inc.mk
diff --git a/project/generic-arm32-test-debug-release.mk b/project/generic-arm32-test-debug-release.mk
index cd5fe93..29923f0 100644
--- a/project/generic-arm32-test-debug-release.mk
+++ b/project/generic-arm32-test-debug-release.mk
@@ -17,4 +17,4 @@ KERNEL_32BIT := true
 DEBUG := 2
 RELEASE_BUILD := true
 
-include project/generic-arm-test-inc.mk
+include project/generic-arm-tz-test-inc.mk
diff --git a/project/generic-arm32-test.mk b/project/generic-arm32-test.mk
index e82a2e2..4104eca 100644
--- a/project/generic-arm32-test.mk
+++ b/project/generic-arm32-test.mk
@@ -16,4 +16,4 @@
 KERNEL_32BIT := true
 DEBUG := 1
 
-include project/generic-arm-test-inc.mk
+include project/generic-arm-tz-test-inc.mk
diff --git a/project/generic-arm32.mk b/project/generic-arm32.mk
index d577342..d0f85e5 100644
--- a/project/generic-arm32.mk
+++ b/project/generic-arm32.mk
@@ -16,4 +16,4 @@
 KERNEL_32BIT := true
 DEBUG := 1
 
-include project/generic-arm-inc.mk
+include project/generic-arm-tz-inc.mk
diff --git a/project/generic-arm64-debug.mk b/project/generic-arm64-debug.mk
index 319671b..e940cd2 100644
--- a/project/generic-arm64-debug.mk
+++ b/project/generic-arm64-debug.mk
@@ -18,4 +18,4 @@ DEBUG := 2
 RELEASE_BUILD := false
 
 include project/debugging-inc.mk
-include project/generic-arm-inc.mk
+include project/generic-arm-tz-inc.mk
diff --git a/project/generic-arm64-test-debug-inc.mk b/project/generic-arm64-test-debug-inc.mk
index d925fe4..b6799a7 100644
--- a/project/generic-arm64-test-debug-inc.mk
+++ b/project/generic-arm64-test-debug-inc.mk
@@ -16,4 +16,4 @@ KERNEL_32BIT := false
 DEBUG := 2
 
 include project/debugging-inc.mk
-include project/generic-arm-test-inc.mk
+include project/generic-arm-tz-test-inc.mk
diff --git a/project/generic-arm64-test.mk b/project/generic-arm64-test.mk
index 242845f..ed810a1 100644
--- a/project/generic-arm64-test.mk
+++ b/project/generic-arm64-test.mk
@@ -16,4 +16,4 @@
 KERNEL_32BIT := false
 DEBUG := 1
 
-include project/generic-arm-test-inc.mk
+include project/generic-arm-tz-test-inc.mk
diff --git a/project/generic-arm64.mk b/project/generic-arm64.mk
index cb81bf2..d09ba00 100644
--- a/project/generic-arm64.mk
+++ b/project/generic-arm64.mk
@@ -16,4 +16,4 @@
 KERNEL_32BIT := false
 DEBUG := 1
 
-include project/generic-arm-inc.mk
+include project/generic-arm-tz-inc.mk
diff --git a/project/hafnium/tos_fw_config.dts b/project/hafnium/tos_fw_config.dts
index 94311fa..4695cb5 100644
--- a/project/hafnium/tos_fw_config.dts
+++ b/project/hafnium/tos_fw_config.dts
@@ -7,7 +7,7 @@
     attribute {
         spmc_id = <0x8000>;
         maj_ver = <0x1>;
-        min_ver = <0x1>;
+        min_ver = <0x2>;
         exec_state = <0x0>;
         /* i'm not sure this is right, or whether it does anything
         the docs say that it's only used to verify that the entry
@@ -64,8 +64,8 @@
             is_ffa_partition;
             debug_name = "trusty";
             load_address = <0x10000000>;
-            vcpu_count = <4>;
-            mem_size = <0x08000000>;
+            vcpu_count = <32>;
+            mem_size = <0x20000000>;
         };
     };
 };
diff --git a/project/hafnium/trusty.dts b/project/hafnium/trusty.dts
index 7b7b3aa..c405f83 100644
--- a/project/hafnium/trusty.dts
+++ b/project/hafnium/trusty.dts
@@ -2,21 +2,26 @@
 
 / {
     compatible = "arm,ffa-manifest-1.0";
-    ffa-version = <0x00010001>; /* 31:16 - Major, 15:0 - Minor */
-    uuid = <0xf025ee40 0x4c30bca2 0x73a14c8c 0xf18a7dc5>;
+    ffa-version = <0x00010002>; /* 31:16 - Major, 15:0 - Minor */
+    uuid = <0xf025ee40 0x4c30bca2 0x73a14c8c 0xf18a7dc5>,
+           <0x9120b8c5 0xbb48fed4 0x244de7b7 0xbe28bb6e>;
     id = <1>;
     auxiliary-id = <0xaf>;
     description = "Trusty";
 
-    execution-ctx-count = <4>;
+    /*
+     * On EL3-SPMC we need to use exactly PLATFORM_CORE_COUNT.
+     * Hafnium does not have that requirement, but we still
+     * try to use the same value as SMP_MAX_CPUS.
+     */
+    execution-ctx-count = <32>;
     exception-level = <2>; /* S-EL1 */
     execution-state = <0>; /* AARCH64 */
     load-address = <0x10000000>;
     entrypoint-offset = <0x00004000>;
     xlat-granule = <0>; /* 4KiB */
 
-    messaging-method = <7>; /* Direct and indirect messages */
-    notification-support; /* Support receipt of notifications. */
+    messaging-method = <0x00000201>; /* DIRECT_REQ and DIRECT_REQ2 message receive only */
 
     ns-interrupts-action = <1>; /* Managed exit is supported */
     /* Trusty reschedules the current thread on an IRQ but not a FIQ */
diff --git a/project/host_commands/microdroid-test.py b/project/host_commands/microdroid-test.py
new file mode 100755
index 0000000..caeea0a
--- /dev/null
+++ b/project/host_commands/microdroid-test.py
@@ -0,0 +1,203 @@
+#!/bin/sh
+"exec" "`dirname $0`/../py3-cmd" "$0" "$@"
+
+import os
+import queue
+import re
+import subprocess
+import sys
+import threading
+import time
+
+try:
+    trusty_adb_port = os.environ["ADB_PORT"]
+    project_root = os.environ["PROJECT_ROOT"]
+except KeyError:
+    print("ADB_PORT and PROJECT_ROOT environment variables required.")
+    sys.exit(64)  # EX_USAGE
+
+sys.path.append(project_root)
+import alloc_adb_ports  # type: ignore
+import qemu  # type: ignore
+
+
+MIN_MICRODROID_PORT = 8000
+START_MICRODROID_COMMAND = (
+    "/apex/com.android.virt/bin/vm run-microdroid"
+    " --debug full --protected --enable-earlycon"
+    " --os microdroid_gki-android16-6.12"
+    " --vendor /vendor/etc/avf/microdroid/microdroid_vendor.img"
+)
+
+
+class Adb(object):
+    """Manage adb."""
+
+    def __init__(self, adb_bin, port=None):
+
+        self.adb_bin = adb_bin
+
+        self.port = (
+            port
+            if port
+            else alloc_adb_ports.alloc_adb_ports(
+                min_port=MIN_MICRODROID_PORT, num_ports=1
+            )[0]
+        )
+
+    def run(self, args, timeout=60, stdout=None, stderr=None):
+        """Run an adb command."""
+
+        args = [self.adb_bin, "-s", f"localhost:{self.port}"] + args
+
+        status = subprocess.run(args, stdout=stdout, stderr=stderr, timeout=timeout)
+
+        return status
+
+    def run_background(self, args):
+        """Run an adb command in the background."""
+        args = [self.adb_bin, "-s", f"localhost:{self.port}"] + args
+
+        adb_proc = subprocess.Popen(args, stdout=subprocess.PIPE)
+
+        return adb_proc
+
+    def connect(self, host):
+        """Connect to adbd."""
+        return self.run(
+            ["connect", host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
+        )
+
+    def disconnect(self, host):
+        """Disonnect from adbd."""
+        return self.run(
+            ["disconnect", host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
+        )
+
+    def is_connected(self, host):
+        """Check adb connection."""
+        out = self.run(["devices"], stdout=subprocess.PIPE)
+
+        m = re.search(f"{host}.*device", out.stdout.decode("UTF-8"))
+        if m:
+            return True
+        else:
+            return False
+
+    def forward(self, local_port, cid):
+        """Forward adb connection."""
+        return self.run(
+            ["forward", f"tcp:{local_port}", f"vsock:{cid}:{self.port}"],
+            stdout=subprocess.DEVNULL,
+            stderr=subprocess.DEVNULL,
+        )
+
+    def unforward(self, local_port):
+        """Remove forwarded adb connection."""
+        return self.run(
+            ["forward", "--remove" f"tcp:{local_port}"],
+            stdout=subprocess.DEVNULL,
+            stderr=subprocess.DEVNULL,
+        )
+
+
+class Microdroid(object):
+    """Manage Microdroid VM."""
+
+    def __init__(self, adb):
+        self.adb = adb
+        self.cid = None
+        self.cid_queue: queue.Queue = queue.Queue()
+
+    def process_output(self, pipe):
+        """Filters stdout, searching for Microdroid's CID"""
+        # this terminates when microdroid does
+        p = re.compile(
+            r"Created debuggable VM from.*with CID\s+(\d+), state is STARTING."
+        )
+        cid = None
+        for line in pipe:
+            decoded_line = line.decode("UTF-8")
+            print(decoded_line, end="")
+
+            if cid == None:
+                if m := p.search(decoded_line):
+                    cid = m.group(1)
+                    self.cid_queue.put(cid)
+
+    def start(self, command):
+        """Start Microdroid."""
+        self.microdroid_proc = self.adb.run_background(["shell"] + command.split(" "))
+        self.microdroid_output_thread = threading.Thread(
+            target=self.process_output, args=[self.microdroid_proc.stdout],
+            daemon=True
+        )
+
+        self.microdroid_output_thread.start()
+
+        self.cid = self.cid_queue.get()
+
+        return self.cid
+
+    def stop(self):
+        """Stop Microdroid."""
+        self.adb.run(
+            [
+                "shell",
+                "/apex/com.android.virt/bin/crosvm",
+                "stop",
+                f"/data/misc/virtualizationservice/{self.cid}/crosvm.sock",
+            ]
+        )
+
+        try:
+            self.microdroid_proc.kill()
+        except OSError:
+            pass
+
+
+def main():
+    status = 1
+    microdroid = None
+    microdroid_adb = None
+    try:
+        with open(f"{project_root}/config.json", encoding="utf-8") as json:
+            config = qemu.Config(json)
+
+        trusty_adb = Adb(config.adb, trusty_adb_port)
+
+        trusty_adb.run(["shell", "setprop hypervisor.pvmfw.path none"])
+
+        microdroid = Microdroid(trusty_adb)
+        microdroid.start(START_MICRODROID_COMMAND)
+
+        print("Microdroid started")
+        microdroid_adb = Adb(config.adb)
+
+        trusty_adb.forward(microdroid_adb.port, microdroid.cid)
+
+        # Wait for microdroid to finish booting
+        while not trusty_adb.is_connected(f"localhost:{microdroid_adb.port}"):
+            trusty_adb.disconnect(f"localhost:{microdroid_adb.port}")
+            trusty_adb.connect(f"localhost:{microdroid_adb.port}")
+            time.sleep(1)
+
+        microdroid_adb.run(["wait-for-device", "root"])
+
+        print("Starting microdroid test: " + " ".join(sys.argv[1:]))
+        st = microdroid_adb.run(["shell"] + sys.argv[1:])
+        status = st.returncode
+        print("Starting microdroid completed")
+
+    finally:
+        if microdroid:
+            microdroid.stop()
+
+        if microdroid_adb:
+            trusty_adb.unforward(microdroid_adb.port)
+
+    sys.exit(status)
+
+
+if __name__ == "__main__":
+    main()
diff --git a/project/linux-inc.mk b/project/linux-inc.mk
index 60815e8..11bc797 100644
--- a/project/linux-inc.mk
+++ b/project/linux-inc.mk
@@ -22,15 +22,15 @@
 
 # This Makefile will build the Linux kernel with our configuration.
 
-LINUX_VERSION := 6.6
+LINUX_PREBUILTS_VERSION := 6.12
+LINUX_PREBUILTS_IMAGE := \
+	kernel/prebuilts/${LINUX_PREBUILTS_VERSION}/${LINUX_ARCH}/kernel-${LINUX_PREBUILTS_VERSION}
 
 LINUX_BUILD_DIR := $(abspath $(BUILDDIR)/linux-build)
 ifndef LINUX_ARCH
 	$(error LINUX_ARCH must be specified)
 endif
 
-LINUX_PREBUILTS_IMAGE := kernel/prebuilts/${LINUX_VERSION}/${LINUX_ARCH}/kernel-${LINUX_VERSION}
-
 LINUX_IMAGE := $(LINUX_BUILD_DIR)/arch/$(LINUX_ARCH)/boot/Image
 LINUX_RAMDISK_IMAGE :=
 
@@ -57,6 +57,7 @@ else
 LINUX_DEFCONFIG_FRAGMENTS := \
 	$(LINUX_CONFIG_DIR)/gki_defconfig \
 	$(if $(LINUX_TRUSTY_INTREE),$(LINUX_CONFIG_DIR)/trusty_qemu_defconfig.fragment) \
+	trusty/device/arm/generic-arm64/project/linux/disable_sig_protect.fragment
 
 endif
 
@@ -64,9 +65,28 @@ ifeq (,$(LINUX_TRUSTY_INTREE))
 LINUX_DEFCONFIG_FRAGMENTS += \
 	linux/common-modules/trusty/system_heap.fragment \
 	linux/common-modules/trusty/trusty_defconfig.fragment \
+	linux/common-modules/trusty/trusty_virtio_poll_vqueues.fragment \
 	linux/common-modules/virtual-device/aarch64.fragment \
 	linux/common-modules/virtual-device/virtual_device_core.fragment \
 
+ifeq (true,$(call TOBOOL,$(LIB_SM_WITH_FFA_LOOP)))
+LINUX_ENABLE_FFA_TRANSPORT ?= true
+LINUX_ENABLE_SMC_TRANSPORT ?= false
+else
+LINUX_ENABLE_FFA_TRANSPORT ?= false
+LINUX_ENABLE_SMC_TRANSPORT ?= true
+endif
+
+ifeq (true,$(call TOBOOL,$(LINUX_ENABLE_FFA_TRANSPORT)))
+LINUX_DEFCONFIG_FRAGMENTS += \
+	linux/common-modules/trusty/arm_ffa.fragment \
+
+endif
+ifeq (false,$(call TOBOOL,$(LINUX_ENABLE_SMC_TRANSPORT)))
+LINUX_DEFCONFIG_FRAGMENTS += \
+	linux/common-modules/trusty/disable_smc_transport.fragment \
+
+endif
 endif
 
 $(LINUX_TMP_DEFCONFIG): LINUX_SRC := $(LINUX_SRC)
@@ -77,6 +97,8 @@ $(LINUX_TMP_DEFCONFIG): $(LINUX_DEFCONFIG_FRAGMENTS)
 # so we should delete it after we're done
 .INTERMEDIATE: $(LINUX_TMP_DEFCONFIG)
 
+LINUX_MODULES_LOAD := $(TRUSTY_TOP)/trusty/device/arm/generic-arm64/project/linux/modules.load
+
 ifeq (,$(LINUX_TRUSTY_INTREE))
 # Make a copy of common-modules/trusty because the kernel build system
 # creates files directly in the directory passed to M=
@@ -100,7 +122,6 @@ LINUX_RAMDISK_IMAGE := $(abspath $(BUILDDIR)/ramdisk.img)
 endif # LINUX_TRUSTY_INTREE
 
 $(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_TMP_DEFCONFIG := $(LINUX_TMP_DEFCONFIG)
-$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): PATH_TOOLS_BINDIR := $(PATH_TOOLS_BINDIR)
 $(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS := -C $(LINUX_SRC)
 $(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += O=$(LINUX_BUILD_DIR)
 $(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += ARCH=$(LINUX_ARCH)
@@ -125,27 +146,35 @@ endif
 $(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += LEX=$(BUILDTOOLS_BINDIR)/flex
 $(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += YACC=$(BUILDTOOLS_BINDIR)/bison
 $(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += BISON_PKGDATADIR=$(BUILDTOOLS_COMMON)/bison
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += HOSTCFLAGS="-isystem$(LINUX_BUILD_TOOLS)/include -B$(CLANG_BINDIR) -B$(CLANG_HOST_SEARCHDIR) --sysroot=$(CLANG_HOST_SYSROOT)"
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += HOSTLDFLAGS="-L$(LINUX_BUILD_TOOLS)/lib64 -rpath $(LINUX_BUILD_TOOLS)/lib64 $(addprefix -L,$(CLANG_HOST_LDDIRS)) -B$(CLANG_BINDIR) -B$(CLANG_HOST_SEARCHDIR) --sysroot=$(CLANG_HOST_SYSROOT)"
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += LIBCLANG_PATH=$(LINUX_CLANG_BINDIR)/../lib/libclang.so
+
+# Put all the paths prepended to $PATH in one variable
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): EXTRA_PATHS := $(CLANG_BINDIR):$(PATH_TOOLS_BINDIR):$(BUILDTOOLS_BINDIR):$(LINUX_BUILD_TOOLS)/bin
+
 $(LINUX_IMAGE): $(LINUX_TMP_DEFCONFIG)
-	PATH=$(CLANG_BINDIR):$(PATH_TOOLS_BINDIR):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) $(notdir $(LINUX_TMP_DEFCONFIG))
-	PATH=$(CLANG_BINDIR):$(PATH_TOOLS_BINDIR):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS)
+	PATH=$(EXTRA_PATHS):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) $(notdir $(LINUX_TMP_DEFCONFIG))
+	PATH=$(EXTRA_PATHS):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS)
 
 ifneq (,$(LINUX_RAMDISK_IMAGE))
 $(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += INSTALL_MOD_PATH=$(LINUX_MODULES_STAGING_DIR)
+$(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += INSTALL_MOD_DIR=trusty
 $(LINUX_IMAGE) $(LINUX_RAMDISK_IMAGE): LINUX_MAKE_ARGS += KCONFIG_EXT_PREFIX=$(LINUX_KCONFIG_EXT_PREFIX)
 
 $(LINUX_RAMDISK_IMAGE): LINUX_MODULES_STAGING_DIR := $(LINUX_MODULES_STAGING_DIR)
 $(LINUX_RAMDISK_IMAGE): LINUX_TRUSTY_MODULES_MAKEFILE_DIR := $(LINUX_TRUSTY_MODULES_COPY_DIR)/drivers/trusty
-$(LINUX_RAMDISK_IMAGE): BUILDTOOLS_BINDIR := $(BUILDTOOLS_BINDIR)
-$(LINUX_RAMDISK_IMAGE): KERNEL_BUILDTOOLS_BINDIR := linux/prebuilts/build-tools/linux-x86/bin
+$(LINUX_RAMDISK_IMAGE): TRUSTY_MODULES_ORDER_HASH := $(shell echo "${LINUX_TRUSTY_MODULES_MAKEFILE_DIR}" | $(PATH_TOOLS_BINDIR)/md5sum -b)
 $(LINUX_RAMDISK_IMAGE): REPLACE_RAMDISK_MODULES := $(PY3) trusty/host/common/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
 $(LINUX_RAMDISK_IMAGE): ANDROID_RAMDISK := trusty/prebuilts/aosp/android/out/target/product/trusty/ramdisk.img
-$(LINUX_RAMDISK_IMAGE): $(LINUX_IMAGE) $(LINUX_TRUSTY_MODULES_COPY_FILES) $(LINUX_TRUSTY_MODULES_KCONFIG_EXT)
+$(LINUX_RAMDISK_IMAGE): LINUX_MODULES_LOAD := $(LINUX_MODULES_LOAD)
+$(LINUX_RAMDISK_IMAGE): $(LINUX_IMAGE) $(LINUX_TRUSTY_MODULES_COPY_FILES) $(LINUX_TRUSTY_MODULES_KCONFIG_EXT) $(LINUX_MODULES_LOAD)
 	@echo building Linux ramdisk
 	@rm -rf $(LINUX_MODULES_STAGING_DIR)
-	PATH=$(CLANG_BINDIR):$(PATH_TOOLS_BINDIR):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) modules_install
-	PATH=$(CLANG_BINDIR):$(PATH_TOOLS_BINDIR):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) M=$(LINUX_TRUSTY_MODULES_MAKEFILE_DIR) modules
-	PATH=$(CLANG_BINDIR):$(PATH_TOOLS_BINDIR):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) M=$(LINUX_TRUSTY_MODULES_MAKEFILE_DIR) modules_install
-	PATH=$(BUILDTOOLS_BINDIR):$(KERNEL_BUILDTOOLS_BINDIR):$(PATH) $(REPLACE_RAMDISK_MODULES) --android-ramdisk $(ANDROID_RAMDISK) --kernel-ramdisk $(LINUX_MODULES_STAGING_DIR) --output-ramdisk $@
+	PATH=$(EXTRA_PATHS):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) modules_install
+	PATH=$(EXTRA_PATHS):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) M=$(LINUX_TRUSTY_MODULES_MAKEFILE_DIR) modules
+	PATH=$(EXTRA_PATHS):$(PATH) $(MAKE) $(LINUX_MAKE_ARGS) M=$(LINUX_TRUSTY_MODULES_MAKEFILE_DIR) modules_install
+	PATH=$(EXTRA_PATHS):$(PATH) $(REPLACE_RAMDISK_MODULES) --android-ramdisk $(ANDROID_RAMDISK) --kernel-ramdisk $(LINUX_MODULES_STAGING_DIR) --output-ramdisk $@ --override-modules-load $(LINUX_MODULES_LOAD) --check-modules-order --extra-modules-order "modules.order.$(TRUSTY_MODULES_ORDER_HASH)"
 
 endif # LINUX_RAMDISK_IMAGE
 else
@@ -176,3 +205,6 @@ LINUX_TRUSTY_MODULES_COPY_FILES :=
 LINUX_KCONFIG_EXT_PREFIX :=
 LINUX_TRUSTY_MODULES_KCONFIG_EXT :=
 LINUX_MODULES_STAGING_DIR :=
+LINUX_MODULES_LOAD :=
+LINUX_ENABLE_FFA_TRANSPORT :=
+LINUX_ENABLE_SMC_TRANSPORT :=
diff --git a/project/linux/disable_sig_protect.fragment b/project/linux/disable_sig_protect.fragment
new file mode 100644
index 0000000..2ffaf98
--- /dev/null
+++ b/project/linux/disable_sig_protect.fragment
@@ -0,0 +1 @@
+CONFIG_MODULE_SIG_PROTECT=n
diff --git a/project/linux/modules.load b/project/linux/modules.load
new file mode 100644
index 0000000..2578fb3
--- /dev/null
+++ b/project/linux/modules.load
@@ -0,0 +1,22 @@
+kernel/net/core/failover.ko
+kernel/drivers/net/net_failover.ko
+kernel/drivers/block/virtio_blk.ko
+kernel/drivers/char/virtio_console.ko
+kernel/drivers/virtio/virtio_mmio.ko
+kernel/drivers/net/virtio_net.ko
+kernel/drivers/virtio/virtio_pci.ko
+kernel/drivers/dma-buf/heaps/system_heap.ko
+kernel/drivers/firmware/arm_ffa/ffa-core.ko
+kernel/drivers/firmware/arm_ffa/ffa-module.ko
+trusty/trusty-ffa.ko
+trusty/trusty-smc.ko
+trusty/trusty-core.ko
+trusty/trusty-ipc.ko
+trusty/trusty-log.ko
+trusty/trusty-test.ko
+trusty/trusty-virtio.ko
+kernel/drivers/virtio/virtio_pci_modern_dev.ko
+kernel/drivers/virtio/virtio_pci_legacy_dev.ko
+kernel/drivers/virtio/virtio_msg.ko
+kernel/drivers/virtio/virtio_msg_ffa_transport.ko
+kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko
diff --git a/project/qemu-atf-inc.mk b/project/qemu-atf-inc.mk
index ed51f05..68131ec 100644
--- a/project/qemu-atf-inc.mk
+++ b/project/qemu-atf-inc.mk
@@ -45,32 +45,80 @@ ATF_BIN := $(ATF_OUT_DIR)/bl31.bin
 ATF_WITH_TRUSTY_GENERIC_SERVICES ?= false
 
 ifeq (true,$(call TOBOOL,$(HAFNIUM)))
+HAFNIUM_PROJECT_DIR := \
+       $(TRUSTY_TOP)/trusty/device/arm/generic-arm64/project/hafnium
+
+# We need to copy sp_layout.json and trusty.dts to the same directory as lk.bin
+# because TF-A parses sp_layout.json and reads the other files from the same
+# directory.
+LK_BIN_DIR := $(dir $(LK_BIN))
+HAFNIUM_SP_LAYOUT_FILES := \
+	$(LK_BIN_DIR)/sp_layout.json \
+	$(LK_BIN_DIR)/trusty.dts \
+
+$(HAFNIUM_SP_LAYOUT_FILES): $(LK_BIN_DIR)/%: $(HAFNIUM_PROJECT_DIR)/%
+	@$(MKDIR)
+	@cp $< $@
+
+# Add explicit dependencies for the layout files
+# because the TF-A build system needs them
+$(ATF_BIN): $(HAFNIUM_SP_LAYOUT_FILES)
+
 ATF_MAKE_ARGS := SPD=spmd
 ATF_MAKE_ARGS += SPMD_SPM_AT_SEL2=1
-ATF_MAKE_ARGS += BL32=$(BL32_BIN)
-ATF_MAKE_ARGS += BL33=$(TEST_RUNNER_BIN)
-ATF_MAKE_ARGS += SP_LAYOUT_FILE=$(HAFNIUM_OUT_DIR)/sp_layout.json
-ATF_MAKE_ARGS += QEMU_TOS_FW_CONFIG_DTS=$(HAFNIUM_OUT_DIR)/tos_fw_config.dts
-ATF_MAKE_ARGS += QEMU_TB_FW_CONFIG_DTS=$(HAFNIUM_OUT_DIR)/tb_fw_config.dts
-# Symlink the Hafnium DTBs to where ATF will look for them.
+ATF_MAKE_ARGS += SP_LAYOUT_FILE=$(LK_BIN_DIR)/sp_layout.json
+ATF_MAKE_ARGS += QEMU_TOS_FW_CONFIG_DTS=$(HAFNIUM_PROJECT_DIR)/tos_fw_config.dts
+ATF_MAKE_ARGS += QEMU_TB_FW_CONFIG_DTS=$(HAFNIUM_PROJECT_DIR)/tb_fw_config.dts
+
+# Symlink the Hafnium DTBs to where qemu will look for them.
 HAFNIUM_DTBS := tb_fw_config.dtb tos_fw_config.dtb
 HAFNIUM_DTBS_SRCS := $(addprefix $(ATF_OUT_DIR)/fdts/, $(HAFNIUM_DTBS))
 $(HAFNIUM_DTBS_SRCS): $(ATF_BIN)
+
 HAFNIUM_DTBS_OUT := $(addprefix $(ATF_OUT_DIR)/, $(HAFNIUM_DTBS))
 $(HAFNIUM_DTBS_OUT): $(ATF_OUT_DIR)/%.dtb: $(ATF_OUT_DIR)/fdts/%.dtb
-	ln -sf $< $@
+	$(NOECHO)ln -rsf $< $@
+
 EXTRA_BUILDDEPS += $(HAFNIUM_DTBS_OUT)
+EXTRA_ATF_SYMLINKS += $(addprefix $(ATF_OUT_DIR)/, $(HAFNIUM_DTBS))
+ATF_EXTRA_BINS += $(addprefix $(ATF_OUT_DIR)/fdts/, $(HAFNIUM_DTBS))
+
+else ifeq ($(SPMC_EL), 3)
+EL3SPMC_TOS_FW_CONFIG_DTS := \
+	$(TRUSTY_TOP)/trusty/device/arm/generic-arm64/project/el3spmc/tos_fw_config.dts
+
+EL3SPMC_TOS_FW_CONFIG_DTB_SRC := $(ATF_OUT_DIR)/fdts/tos_fw_config.dtb
+$(EL3SPMC_TOS_FW_CONFIG_DTB_SRC): $(ATF_BIN)
+
+EL3SPMC_TOS_FW_CONFIG_DTB_OUT := $(ATF_OUT_DIR)/tos_fw_config.dtb
+$(EL3SPMC_TOS_FW_CONFIG_DTB_OUT): $(EL3SPMC_TOS_FW_CONFIG_DTB_SRC)
+	$(NOECHO)ln -rsf $< $@
+
+EXTRA_BUILDDEPS += $(EL3SPMC_TOS_FW_CONFIG_DTB_OUT)
+EXTRA_ATF_SYMLINKS += $(ATF_OUT_DIR)/tos_fw_config.dtb
+ATF_EXTRA_BINS += $(ATF_OUT_DIR)/fdts/tos_fw_config.dtb
+
+ATF_MAKE_ARGS := SPD=spmd
+ATF_MAKE_ARGS += SPMC_AT_EL3=1
+ATF_MAKE_ARGS += SPMD_SPM_AT_SEL2=0
+ATF_MAKE_ARGS += QEMU_TOS_FW_CONFIG_DTS=$(EL3SPMC_TOS_FW_CONFIG_DTS)
+# The el3_spmc build system needs something in BL32, otherwise it
+# builds the TSP as the BL32 payload. The variable is not used for anything,
+# so it can be a placeholder.
+ATF_MAKE_ARGS += BL32=/dev/null
 else
 ATF_MAKE_ARGS := SPD=trusty
 ATF_MAKE_ARGS += SPMD_SPM_AT_SEL2=0
 endif
 ATF_MAKE_ARGS += CC=$(CLANG_BINDIR)/clang
 ATF_MAKE_ARGS += DTC=$(TRUSTY_TOP)/prebuilts/misc/linux-x86/dtc/dtc
+ATF_MAKE_ARGS += PYTHON=$(PY3)
 ATF_MAKE_ARGS += CROSS_COMPILE=$(ATF_TOOLCHAIN_PREFIX)
 ATF_MAKE_ARGS += PLAT=$(ATF_PLAT)
 ATF_MAKE_ARGS += DEBUG=$(ATF_DEBUG)
 ATF_MAKE_ARGS += BUILD_BASE=$(ATF_BUILD_BASE)
 ATF_MAKE_ARGS += QEMU_USE_GIC_DRIVER=QEMU_GICV$(GIC_VERSION)
+ATF_MAKE_ARGS += CTX_INCLUDE_FPREGS=1
 # On aarch32, we skip EL2, see 27d8e1e75a2f45d7c23
 ifeq (true,$(call TOBOOL,$(KERNEL_32BIT)))
 ATF_MAKE_ARGS += INIT_UNUSED_NS_EL2=1
@@ -95,3 +143,12 @@ ATF_WITH_TRUSTY_GENERIC_SERVICES:=
 ATF_TOOLCHAIN_PREFIX:=
 ATF_BIN:=
 ATF_MAKE_ARGS:=
+EL3SPMC_TOS_FW_CONFIG_DTS:=
+EL3SPMC_TOS_FW_CONFIG_DTB_SRC:=
+EL3SPMC_TOS_FW_CONFIG_DTB_OUT:=
+LK_BIN_DIR :=
+HAFNIUM_DTBS :=
+HAFNIUM_DTBS_SRCS :=
+HAFNIUM_DTBS_OUT :=
+HAFNIUM_PROJECT_DIR :=
+HAFNIUM_SP_LAYOUT_FILES :=
diff --git a/project/qemu-generic-arm64-gicv3-hafnium-test-debug.mk b/project/qemu-generic-arm64-gicv3-hafnium-test-debug.mk
index 225dbf9..05f7fa9 100644
--- a/project/qemu-generic-arm64-gicv3-hafnium-test-debug.mk
+++ b/project/qemu-generic-arm64-gicv3-hafnium-test-debug.mk
@@ -19,6 +19,7 @@ QEMU_TRUSTY_PROJECT := generic-arm64-gicv3-test-debug
 GLOBAL_DEFINES += CACHE_LINE=64
 
 HAFNIUM := 1
-TIMER_ARM_GENERIC_SELECTED := CNTV
+SPMC_EL := 2
+TIMER_ARM_GENERIC_SELECTED := CNTP
 
 include project/qemu-inc.mk
diff --git a/project/qemu-generic-arm64-gicv3-spd-ffa-test-debug.mk b/project/qemu-generic-arm64-gicv3-spd-ffa-test-debug.mk
index 93f9341..bc2d71f 100644
--- a/project/qemu-generic-arm64-gicv3-spd-ffa-test-debug.mk
+++ b/project/qemu-generic-arm64-gicv3-spd-ffa-test-debug.mk
@@ -21,5 +21,7 @@ GLOBAL_DEFINES += CACHE_LINE=64
 # Enable the FFA loop to test compatibility
 SPMC_EL :=
 LIB_SM_WITH_FFA_LOOP := true
+LINUX_ENABLE_FFA_TRANSPORT := true
+LINUX_ENABLE_SMC_TRANSPORT := true
 
 include project/qemu-inc.mk
diff --git a/project/qemu-inc.mk b/project/qemu-inc.mk
index 8f6261f..a5ee165 100644
--- a/project/qemu-inc.mk
+++ b/project/qemu-inc.mk
@@ -15,11 +15,35 @@
 
 PROJECT_QEMU_INC_LOCAL_DIR := $(GET_LOCAL_DIR)
 
+ifeq (true,$(call TOBOOL,$(PACKAGE_TRUSTY_IMAGES_ONLY)))
+PACKAGE_TRUSTY_IMAGES := true
+endif
+
 APPLOADER_ALLOW_NS_CONNECT := true
 
 # Include Secretkeeper TA
 SECRETKEEPER_ENABLED := true
 
+# All qemu-generic-arm64* builds default to SPMC_EL=3
+# while the arm32 builds use the SPD because both
+# Hafnium and EL3 SPMC only support AArch64.
+ifneq ($(filter generic-arm64%,$(QEMU_TRUSTY_PROJECT)),)
+SPMC_EL ?= 3
+endif
+
+ifneq ($(SPMC_EL),)
+LIB_SM_WITH_FFA_LOOP := true
+GENERIC_ARM64_DEBUG := FFA
+
+# Merge FIQ-IRQ to keep the FF-A implementation simpler
+ARM_MERGE_FIQ_IRQ := true
+
+# TF-A on qemu sets PLATFORM_CORE_COUNT=32 and requires that the
+# SP manifest specifies that exact number of execution contexts
+SMP_MAX_CPUS := 32
+SMP_CPU_CLUSTER_SHIFT := 4
+endif
+
 include project/$(QEMU_TRUSTY_PROJECT).mk
 
 # limit physical memory to 29 bits to make the mapping
@@ -85,15 +109,9 @@ EXTRA_BUILDRULES += external/trusty/bootloader/test-runner/test-runner-inc.mk
 TEST_RUNNER_BIN := $(BUILDDIR)/test-runner/external/trusty/bootloader/test-runner/test-runner.bin
 
 ifeq (true,$(call TOBOOL,$(HAFNIUM)))
-HAFNIUM_OUT_DIR := $(BUILDDIR)/hafnium
-HAFNIUM_PREBUILTS := trusty/prebuilts/aosp/hafnium
-HAFNIUM_MANIFESTS := trusty/device/arm/generic-arm64/project/hafnium
-$(HAFNIUM_OUT_DIR)/%: $(HAFNIUM_PREBUILTS) $(HAFNIUM_MANIFESTS)
-	mkdir -p $(HAFNIUM_OUT_DIR)
-	cp -r $(HAFNIUM_PREBUILTS)/* $(HAFNIUM_OUT_DIR)
-	cp -r $(HAFNIUM_MANIFESTS)/* $(HAFNIUM_OUT_DIR)
-	ln -sf $(LK_BIN) $(HAFNIUM_OUT_DIR)/lk.bin
-BL32_BIN := $(HAFNIUM_OUT_DIR)/hafnium.bin
+HAFNIUM_PLATFORM := secure_qemu_aarch64
+include external/hafnium/rules.mk
+BL32_BIN := $(HAFNIUM_BIN)
 else
 BL32_BIN := $(LK_BIN)
 endif
@@ -109,7 +127,8 @@ include project/qemu-atf-inc.mk
 # Try using the qemu from the prebuilts
 QEMU_BUILD_BASE := $(abspath $(BUILDDIR)/qemu-build)
 QEMU_ARCH := aarch64
-QEMU_PREBUILTS := $(wildcard prebuilts/android-emulator/trusty-x86_64)
+QEMU_PREBUILTS_DIR ?= prebuilts/android-emulator/trusty-x86_64
+QEMU_PREBUILTS := $(wildcard $(QEMU_PREBUILTS_DIR))
 
 ifeq (,$(QEMU_PREBUILTS))
 # No prebuilts, build qemu from source
@@ -136,12 +155,15 @@ $(QEMU_BIN): $(QEMU_BUILD_BASE)
 EXTRA_BUILDDEPS += $(QEMU_BUILD_BASE) $(QEMU_BIN)
 endif
 
+ifneq (true,$(call TOBOOL,$(PACKAGE_TRUSTY_IMAGES_ONLY)))
 LINUX_ARCH ?= arm64
 include project/linux-inc.mk
+endif
 
 RUN_SCRIPT := $(BUILDDIR)/run
 STOP_SCRIPT := $(BUILDDIR)/stop
-QEMU_CONFIG := $(BUILDDIR)/config.json
+ALLOC_ADB_PORTS_PY := $(BUILDDIR)/alloc_adb_ports.py
+HOST_COMMANDS_OUT_DIR := $(BUILDDIR)/host_commands
 QEMU_PY := $(BUILDDIR)/qemu.py
 QEMU_ERROR_PY := $(BUILDDIR)/qemu_error.py
 QEMU_OPTIONS_PY := $(BUILDDIR)/qemu_options.py
@@ -155,7 +177,7 @@ $(ATF_OUT_DIR):
 
 # ATF built binaries
 ATF_BIN := $(ATF_OUT_DIR)/bl31.bin
-ATF_EXTRA_BINS := \
+ATF_EXTRA_BINS += \
 	$(ATF_OUT_DIR)/bl1.bin \
 	$(ATF_OUT_DIR)/bl2.bin \
 
@@ -163,6 +185,7 @@ ATF_EXTRA_BINS := \
 ATF_SYMLINKS := \
 	$(ATF_OUT_DIR)/bl32.bin \
 	$(ATF_OUT_DIR)/bl33.bin \
+	$(EXTRA_ATF_SYMLINKS) \
 
 $(ATF_OUT_DIR)/bl32.bin: BUILDDIR := $(BUILDDIR)
 $(ATF_OUT_DIR)/bl32.bin: ATF_OUT_DIR := $(ATF_OUT_DIR)
@@ -174,22 +197,59 @@ $(ATF_OUT_DIR)/bl33.bin: ATF_OUT_DIR := $(ATF_OUT_DIR)
 $(ATF_OUT_DIR)/bl33.bin: $(TEST_RUNNER_BIN) $(ATF_OUT_DIR)
 	$(NOECHO)ln -rsf $< $@
 
+ATF_GENERATED_FILES := \
+	$(ATF_OUT_DIR)/RPMB_DATA \
+	$(ATF_OUT_DIR)/metadata.img \
+
 $(ATF_OUT_DIR)/RPMB_DATA: ATF_OUT_DIR := $(ATF_OUT_DIR)
 $(ATF_OUT_DIR)/RPMB_DATA: $(RPMB_DEV)
 	@echo Initialize rpmb device
 	$< --dev $(ATF_OUT_DIR)/RPMB_DATA --init --size 2048
 
+ifeq (true,$(call TOBOOL,$(PACKAGE_TRUSTY_IMAGES_ONLY)))
+ANDROID_OUT_SRC_DIR :=
+ANDROID_OUT_SRC_FILES :=
+else
+ifneq (,$(ANDROID_BUILD_TOP))
+# We are building Trusty inside an Android environment,
+# which means we can use a fresh Android build instead of prebuilts
+ANDROID_OUT_SRC_DIR := $(ANDROID_BUILD_TOP)
+else
+ANDROID_OUT_SRC_DIR := trusty/prebuilts/aosp/android
+endif
+ANDROID_OUT_SRC_FILES := $(addprefix $(ANDROID_OUT_SRC_DIR)/,$(ANDROID_OUT_FILES))
+endif
+
+MKE2FS ?= $(ANDROID_OUT_SRC_DIR)/out/host/linux-x86/bin/mke2fs
+$(ATF_OUT_DIR)/metadata.img: MKE2FS := $(MKE2FS)
+$(ATF_OUT_DIR)/metadata.img:
+	@echo Create metadata.img
+	MKE2FS_CONFIG= $(MKE2FS) -t ext4 -F $@ -O has_journal,extent,huge_file,dir_nlink,extra_isize,uninit_bg 16m
+
 QEMU_SCRIPTS := \
+	$(ALLOC_ADB_PORTS_PY) \
+	$(HOST_COMMANDS_OUT_DIR) \
 	$(QEMU_PY) \
 	$(QEMU_ERROR_PY) \
 	$(QEMU_OPTIONS_PY) \
 	$(QEMU_LLDB_SUPPORT_PY) \
 	$(QEMU_LLDBINIT) \
-	$(RUN_PY)
+	$(RUN_PY) \
 
 $(QEMU_SCRIPTS): .PHONY
 EXTRA_BUILDDEPS += $(QEMU_SCRIPTS)
 
+# Copied so that the resulting build tree contains all files needed to run
+$(ALLOC_ADB_PORTS_PY): $(PROJECT_QEMU_INC_LOCAL_DIR)/qemu/alloc_adb_ports.py
+	@echo copying $@
+	@cp $< $@
+
+# Copied so that the resulting build tree contains all files needed to run
+$(HOST_COMMANDS_OUT_DIR): $(PROJECT_QEMU_INC_LOCAL_DIR)/host_commands
+	@echo copying $@
+	@rm -rf $@
+	@cp -a $< $@
+
 # Copied so that the resulting build tree contains all files needed to run
 $(QEMU_PY): $(PROJECT_QEMU_INC_LOCAL_DIR)/qemu/qemu.py
 	@echo copying $@
@@ -234,14 +294,20 @@ $(PY3_CMD): $(BUILDTOOLS_BINDIR)/py3-cmd
 EXTRA_BUILDDEPS += $(PY3_CMD)
 
 # List of files we need from Android
+ifeq (true,$(call TOBOOL,$(PACKAGE_TRUSTY_IMAGES_ONLY)))
+ANDROID_OUT_FILES :=
+
+else
 ANDROID_OUT_FILES := \
 	out/host/linux-x86/bin/adb \
+	out/host/linux-x86/bin/mke2fs \
 	out/target/product/trusty/ramdisk.img \
 	out/target/product/trusty/system.img \
 	out/target/product/trusty/vendor.img \
 	out/target/product/trusty/userdata.img \
 	out/target/product/trusty/data/nativetest64 \
 
+endif
 # Copy Android prebuilts into the build directory so that the build does not
 # depend on any files in the source tree. We want to package the build artifacts
 # without any dependencies on the sources.
@@ -249,20 +315,16 @@ ANDROID_OUT_FILES := \
 # be cleared before copying in the fresh content. `rm -rf` is used to accomplish
 # this because it bypasses writing un-writeable files in addition to bringing
 # the target directory to the same state as with a clean build.
-ANDROID_OUT_BUILD_DIR := $(BUILDDIR)/aosp/android
-
-ANDROID_OUT_IMAGE_DIR := $(ANDROID_OUT_BUILD_DIR)/out/target/product/trusty
-ANDROID_OUT_ADB_PATH := $(ANDROID_OUT_BUILD_DIR)/out/host/linux-x86/bin/adb
+ifeq (true,$(call TOBOOL,$(PACKAGE_TRUSTY_IMAGES_ONLY)))
+ANDROID_OUT_BUILD_DIR :=
 
-ifneq (,$(ANDROID_BUILD_TOP))
-# We are building Trusty inside an Android environment,
-# which means we can use a fresh Android build instead of prebuilts
-ANDROID_OUT_SRC_DIR := $(ANDROID_BUILD_TOP)
 else
-ANDROID_OUT_SRC_DIR := trusty/prebuilts/aosp/android
+ANDROID_OUT_BUILD_DIR := $(BUILDDIR)/aosp/android
+
 endif
 
-ANDROID_OUT_SRC_FILES := $(addprefix $(ANDROID_OUT_SRC_DIR)/,$(ANDROID_OUT_FILES))
+ANDROID_OUT_IMAGE_DIR := $(ANDROID_OUT_BUILD_DIR)/out/target/product/trusty
+ANDROID_OUT_ADB_PATH := $(ANDROID_OUT_BUILD_DIR)/out/host/linux-x86/bin/adb
 
 # Copy the files listed in ANDROID_OUT_FILES from ANDROID_OUT_SRC_DIR into
 # ANDROID_OUT_BUILD_DIR preserving the directory structure relative to the
@@ -281,6 +343,14 @@ $(ANDROID_OUT_BUILD_DIR): $(ANDROID_OUT_SRC_FILES) $(LINUX_RAMDISK_IMAGE)
 
 EXTRA_BUILDDEPS += $(ANDROID_OUT_BUILD_DIR)
 
+ifeq (true,$(call TOBOOL,$(PACKAGE_TRUSTY_IMAGES_ONLY)))
+QEMU_CONFIG :=
+
+else
+QEMU_CONFIG := $(BUILDDIR)/config.json
+
+endif
+
 # Save variables to a json file to export paths known to the build system to
 # the test system
 $(QEMU_CONFIG): QEMU_BIN := $(subst $(BUILDDIR)/,,$(QEMU_BIN))
@@ -291,10 +361,11 @@ $(QEMU_CONFIG): LINUX_ARCH := $(LINUX_ARCH)
 $(QEMU_CONFIG): ANDROID_OUT_IMAGE_DIR := $(subst $(BUILDDIR)/,,$(ANDROID_OUT_IMAGE_DIR))
 $(QEMU_CONFIG): ANDROID_OUT_ADB_PATH := $(subst $(BUILDDIR)/,,$(ANDROID_OUT_ADB_PATH))
 $(QEMU_CONFIG): RPMB_DEV := $(subst $(BUILDDIR)/,,$(RPMB_DEV))
-$(QEMU_CONFIG): $(ATF_OUT_COPIED_FILES) $(ATF_SYMLINKS) $(ATF_OUT_DIR)/RPMB_DATA
+$(QEMU_CONFIG): $(ATF_OUT_COPIED_FILES) $(ATF_SYMLINKS) $(ATF_GENERATED_FILES)
 	@echo generating $@
 	@echo '{ "linux": "$(LINUX_BUILD_DIR)",' > $@
 	@echo '  "linux_arch": "$(LINUX_ARCH)",' >> $@
+	@echo '  "initrd": "$(ANDROID_OUT_IMAGE_DIR)/ramdisk.img",' >> $@
 	@echo '  "atf": "$(ATF_OUT_DIR)", ' >> $@
 	@echo '  "qemu": "$(QEMU_BIN)", ' >> $@
 	@echo '  "extra_qemu_flags": $(EXTRA_QEMU_FLAGS), ' >> $@
@@ -329,7 +400,9 @@ QEMU_PACKAGE_FILES := \
 	$(OUTBIN) $(QEMU_SCRIPTS) $(PY3_CMD) $(QEMU_CONFIG) $(RPMB_DEV) \
 	$(RUN_SCRIPT) $(STOP_SCRIPT) \
 	$(QEMU_BIN) $(ATF_BIN) $(ATF_SYMLINKS) \
-	$(ATF_OUT_DIR)/RPMB_DATA $(ATF_OUT_COPIED_FILES) $(LINUX_IMAGE) \
+	$(ATF_GENERATED_FILES) \
+	$(ATF_OUT_COPIED_FILES) \
+	$(LINUX_IMAGE) \
 
 ifneq (true,$(call TOBOOL,$(PACKAGE_QEMU_WITHOUT_ANDROID)))
 # The Android prebuilts are pretty large and not all users need them
@@ -358,7 +431,8 @@ QEMU_PACKAGE_FILES := \
 	$(OUTBIN) $(QEMU_SCRIPTS) $(PY3_CMD) \
 	$(STOP_SCRIPT) \
 	$(ATF_BIN) $(ATF_SYMLINKS) $(TEST_RUNNER_BIN) \
-	$(ATF_OUT_DIR)/RPMB_DATA $(ATF_OUT_COPIED_FILES) \
+	$(ATF_GENERATED_FILES) \
+	$(ATF_OUT_COPIED_FILES) \
 
 # Other files/directories that should be included in the package but which are
 # not make targets and therefore cannot be pre-requisites. The target that
@@ -382,6 +456,8 @@ ATF_OUT_COPIED_FILES :=
 ATF_OUT_DIR :=
 ATF_RELATIVE_TO_BUILD_BASE :=
 ATF_SYMLINKS :=
+EXTRA_ATF_SYMLINKS :=
+HAFNIUM_BIN :=
 LINUX_ARCH :=
 LINUX_BUILD_DIR :=
 LINUX_IMAGE :=
diff --git a/project/qemu/alloc_adb_ports.py b/project/qemu/alloc_adb_ports.py
new file mode 100755
index 0000000..094bd92
--- /dev/null
+++ b/project/qemu/alloc_adb_ports.py
@@ -0,0 +1,46 @@
+#!/bin/sh
+"exec" "`dirname $0`/py3-cmd" "$0" "$@"
+
+import argparse
+import socket
+
+# ADB expects its first console on 5554, and control on 5555
+ADB_BASE_PORT = 5554
+
+
+def alloc_adb_ports(min_port=ADB_BASE_PORT, num_ports=2):
+    """Allocates num_ports sequential ports above min_port for adb
+
+    adb normally uses ports in pairs. The exception is when a
+    port is needed for forwarding the adb connection, such as when
+    using a VM.
+    """
+
+    # We can't actually reserve ports atomically for QEMU, but we can at
+    # least scan and find two that are not currently in use.
+    while True:
+        alloced_ports = []
+        for port in range(min_port, min_port + num_ports):
+            # If the port is already in use, don't hand it out
+            try:
+                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
+                sock.connect(("localhost", port))
+                break
+            except IOError:
+                alloced_ports += [port]
+        if len(alloced_ports) == num_ports:
+            return alloced_ports
+
+        # We could increment by only 1, but if we are competing with other
+        # adb sessions for ports, this will be more polite
+        min_port += num_ports
+
+
+if __name__ == "__main__":
+    argument_parser = argparse.ArgumentParser()
+    argument_parser.add_argument("--min-port", required=True, type=int)
+    argument_parser.add_argument("--num-ports", required=True, type=int)
+    args = argument_parser.parse_args()
+
+    ports = alloc_adb_ports(args.min_port, args.num_ports)
+    print(*ports, sep=" ")
diff --git a/project/qemu/qemu.py b/project/qemu/qemu.py
index 13fdd0c..cf08d9d 100644
--- a/project/qemu/qemu.py
+++ b/project/qemu/qemu.py
@@ -9,6 +9,7 @@ import os
 from textwrap import dedent
 import re
 import select
+import shlex
 import socket
 import subprocess
 import shutil
@@ -17,8 +18,9 @@ import tempfile
 import time
 import threading
 
-from typing import Optional, List
+from typing import Optional, List, IO
 
+import alloc_adb_ports
 import qemu_options
 from qemu_error import AdbFailure, ConfigError, RunnerGenericError, Timeout
 
@@ -62,11 +64,14 @@ class Config(object):
         linux:            Path to a built Linux kernel tree or prebuilt
                           kernel image.
         linux_arch:       Architecture of Linux kernel.
+        initrd:           Path to a built ramdisk.img or other initrd,
+                          if different from the one in the Android images.
         atf:              Path to the ATF build to use.
         qemu:             Path to the emulator to use.
         arch:             Architecture definition.
         rpmbd:            Path to the rpmb daemon to use.
         adb:              Path to adb host tool.
+        extra_linux_args: Extra arguments to pass to Linux kernel.
         extra_qemu_flags: Extra flags to pass to QEMU.
     Setting android or linux to a false value will result in a QEMU which starts
     without those components. Only one of android and android_image_dir may be provided
@@ -110,10 +115,12 @@ class Config(object):
         self.boot_android = self.android_image_dir is not None
         self.linux = abspath("linux")
         self.linux_arch = config_dict.get("linux_arch")
+        self.initrd = abspath("initrd")
         self.atf = abspath("atf")
         self.qemu = abspath("qemu", "qemu-system-aarch64")
         self.rpmbd = abspath("rpmbd")
         self.arch = config_dict.get("arch")
+        self.extra_linux_args = config_dict.get("extra_linux_args", [])
         self.extra_qemu_flags = config_dict.get("extra_qemu_flags", [])
 
     def check_config(self, interactive: bool, boot_tests=(),
@@ -152,32 +159,6 @@ class Config(object):
                 raise ConfigError("Missing adb tool for Android")
 
 
-def alloc_ports():
-    """Allocates 2 sequential ports above 5554 for adb"""
-    # adb uses ports in pairs
-    port_width = 2
-
-    # We can't actually reserve ports atomically for QEMU, but we can at
-    # least scan and find two that are not currently in use.
-    min_port = ADB_BASE_PORT
-    while True:
-        alloced_ports = []
-        for port in range(min_port, min_port + port_width):
-            # If the port is already in use, don't hand it out
-            try:
-                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
-                sock.connect(("localhost", port))
-                break
-            except IOError:
-                alloced_ports += [port]
-        if len(alloced_ports) == port_width:
-            return alloced_ports
-
-        # We could increment by only 1, but if we are competing with other
-        # adb sessions for ports, this will be more polite
-        min_port += port_width
-
-
 def forward_ports(ports):
     """Generates arguments to forward ports in QEMU on a virtio network"""
     forwards = ""
@@ -204,8 +185,8 @@ class QEMUCommandPipe(object):
             f"pipe,id=command0,path={self.command_dir}/com", "-mon",
             "chardev=command0,mode=control"
         ]
-        self.com_pipe_in = None
-        self.com_pipe_out = None
+        self.com_pipe_in: Optional[IO] = None
+        self.com_pipe_out: Optional[IO] = None
 
     def open(self):
         # pylint: disable=consider-using-with
@@ -240,11 +221,12 @@ class QEMUCommandPipe(object):
                 raise RunnerGenericError("Failed to clean up command pipe.")
 
         # Clean up our command pipe
-        shutil.rmtree(self.command_dir, onerror=cb_handle_error)
+        shutil.rmtree(self.command_dir, onexc=cb_handle_error)
 
     def qmp_command(self, qmp_command):
         """Send a qmp command and return result."""
-
+        assert self.com_pipe_in
+        assert self.com_pipe_out
         try:
             json.dump(qmp_command, self.com_pipe_in)
             self.com_pipe_in.flush()
@@ -341,7 +323,7 @@ class RunnerSession:
         self.has_error = False
         self.command_pipe = None
         self.qemu_proc = None
-        self.ports = None
+        self.ports: Optional[List[int]] = None
         # stores the arguments used to start qemu iff performing a boot test
         self.args = []
         self.temp_files = []
@@ -357,6 +339,7 @@ class RunnerState(enum.Enum):
     OFF = 0
     BOOTLOADER = 1
     ANDROID = 2
+    ERROR = 3
 
 
 class Runner(object):
@@ -378,13 +361,13 @@ class Runner(object):
         self.interactive = interactive
         self.debug = debug
         self.verbose = verbose
-        self.adb_transport = None
+        self.adb_transport: Optional[int] = None
         self.use_rpmb = rpmb
-        self.rpmb_proc = None
-        self.rpmb_sock_dir = None
-        self.msg_sock = None
-        self.msg_sock_conn = None
-        self.msg_sock_dir = None
+        self.rpmb_proc: Optional[subprocess.Popen[bytes]] = None
+        self.rpmb_sock_dir: Optional[str] = None
+        self.msg_sock: Optional[socket.socket] = None
+        self.msg_sock_conn: Optional[socket.socket] = None
+        self.msg_sock_dir: Optional[str] = None
         self.debug_on_error = debug_on_error
         self.dump_stdout_on_error = False
         self.default_timeout = 60 * 10  # 10 Minutes
@@ -394,8 +377,8 @@ class Runner(object):
 
         # If we're not verbose or interactive, squelch command output
         if verbose or self.interactive:
-            self.stdout = None
-            self.stderr = None
+            self.stdout: Optional[IO] = None
+            self.stderr: Optional[int] = None
         else:
             self.stdout = tempfile.TemporaryFile()  # pylint: disable=consider-using-with
             self.stderr = subprocess.STDOUT
@@ -418,6 +401,8 @@ class Runner(object):
 
     def error_dump_output(self):
         if self.dump_stdout_on_error:
+            assert self.stdout
+            assert self.session
             sys.stdout.flush()
             sys.stderr.write("System log:\n")
             self.stdout.seek(0)
@@ -425,6 +410,7 @@ class Runner(object):
 
     def get_qemu_arg_temp_file(self):
         """Returns a temp file that will be deleted after qemu exits."""
+        assert self.session
         # pylint: disable=consider-using-with
         tmp = tempfile.NamedTemporaryFile(delete=False)
         self.session.temp_files.append(tmp.name)
@@ -499,7 +485,7 @@ class Runner(object):
 
     def msg_channel_wait_for_connection(self):
         """wait for testrunner to connect."""
-
+        assert self.msg_sock
         # Accept testrunner's connection request
         self.msg_sock_conn, _ = self.msg_sock.accept()
 
@@ -531,6 +517,7 @@ class Runner(object):
 
     def boottest_run(self, boot_tests, timeout=60 * 2):
         """Run boot test cases"""
+        assert self.session
         args = self.session.args
         has_error = False
         result = 2
@@ -637,8 +624,8 @@ class Runner(object):
 
     def androidtest_run(self, cmd, test_timeout=None):
         """Run android test cases"""
+        assert self.session, "No session; call launch before running any tests."
         session: RunnerSession = self.session
-        assert session, "No session; must call launch before running any tests."
 
         try:
             if not test_timeout:
@@ -654,11 +641,66 @@ class Runner(object):
             if test_result:
                 session.has_error = True
 
+            # If android reboots, adb starts failing before QEMU exits.
+            if self.adb(["get-state"]):
+                # Set self.state to RunnerState.ERROR if adb is no longer
+                # functional so the caller can reboot (if it needs to get back
+                # to a functional RunnerState.ANDROID state).
+                print("adb get-state failed after androidtest")
+                self.state = RunnerState.ERROR
+
+                # Give QEMU some time to exit.
+                self.session.qemu_proc.wait(10)
+
+            if self.session.qemu_proc.poll() is not None:
+                # Set self.state to RunnerState.ERROR if QEMU is no longer
+                # running so the caller can reboot (if it needs to get back to
+                # a functional RunnerState.ANDROID state).
+                print("QEMU is no longer running after androidtest")
+                self.state = RunnerState.ERROR
+
             return test_result
         except:
             session.has_error = True
             raise
 
+    def hostcommandtest_run(self, hostcmd: str, test_timeout=None):
+        """
+        Run host command which interacts with a running Android device over adb.
+
+        This differs from android tests which run entirely on-device and boot tests
+        which runs without a full Android environment.
+        """
+        assert self.session, "No session; call launch before running any tests."
+        assert self.session.ports, "No ports; did the QEMU session launch cleanly?"
+
+        env = os.environ.copy()
+        env["ADB_PORT"] = str(self.session.ports[1])
+        env["PROJECT_ROOT"] = self.config.script_dir
+        cmd_status = 1
+        match shlex.split(hostcmd):
+            case []:  # parse error
+                raise RunnerGenericError(f"Invalid host cmd: {hostcmd}")
+            case [exe, *args]:
+                exe_path = [f"{self.config.script_dir}/host_commands/{exe}"]
+                try:
+                    subproc = subprocess.run(
+                        exe_path + args,timeout=test_timeout, env=env
+                        )
+                    cmd_status = subproc.returncode
+                except subprocess.TimeoutExpired:
+                    print(
+                        f"Host command test timed out ({test_timeout} s): {hostcmd}"
+                    )
+                    qemu_handle_error(
+                        command_pipe=self.session.command_pipe,
+                        debug_on_error=self.debug_on_error
+                    )
+            case _:  # this shouldn't happen
+                raise RunnerGenericError(f"Unknown error")
+
+        return cmd_status
+
     def adb_bin(self):
         """Returns location of adb"""
         return self.config.adb
@@ -667,6 +709,7 @@ class Runner(object):
             args,
             timeout=60,
             on_timeout=lambda timeout: print(f"Timed out ({timeout} s)"),
+            need_qemu_running=False,
             force_output=False):
         """Runs an adb command
 
@@ -675,9 +718,27 @@ class Runner(object):
 
         Timeout specifies a timeout for the command in seconds.
 
+        If need_qemu_running is set to True the command will not be sent if
+        QEMU is not running. Set this to True when using "wait-for-device"
+        since "wait-for-device" can't tell the difference between adbd had not
+        started yet and adbd will never start since the emulator is no longer
+        running. Also, since this option currently only checks if QEMU is
+        running before sending the command, use this with short timeout values.
+
         If force_output is set true, will send results to stdout and
         stderr regardless of the runner's preferences.
         """
+
+        if need_qemu_running and self.session.qemu_proc.poll() is not None:
+            # Check if qemu is still running to avoid wasting time waiting for
+            # a command that can never succeed. Qemu should not normally exit
+            # before or while we are waiting for an adb command to complete.
+            # If it does the emulated system has crashed and adb
+            # wait-for-device will never succeed. Normal adb shell commands
+            # return 255 if QEMU exits while the command is running, so return
+            # the same status value here.
+            return 255
+
         if self.adb_transport:
             args = ["-t", str(self.adb_transport)] + args
 
@@ -698,7 +759,10 @@ class Runner(object):
         except subprocess.TimeoutExpired:
             if on_timeout:
                 on_timeout()
-
+        finally:
+            # Make sure we don't return with adp_proc still running.
+            # Since adb_proc.kill() is a NOP if adb_proc.wait() completed we
+            # can call this unconditionally.
             try:
                 adb_proc.kill()
             except OSError:
@@ -719,12 +783,12 @@ class Runner(object):
         num_tries = 0
 
         # Ensure device is up else adb root can fail
-        self.adb(["wait-for-device"])
+        self.adb(["wait-for-device"], need_qemu_running=True)
         self.check_adb(["root"])
 
         while True:
             # adbd might not be down by this point yet
-            self.adb(["wait-for-device"])
+            self.adb(["wait-for-device"], need_qemu_running=True)
 
             # Check that adbd is up and running with root permissions
             code = self.adb(["shell",
@@ -772,16 +836,18 @@ class Runner(object):
 
         # Sometimes adb can get stuck and will never connect. Using multiple
         # shorter timeouts works better than one longer timeout in such cases.
-        adb_exception = None
+        adb_exception: Optional[AdbFailure] = None
         for _ in range(10):
             try:
-                self.check_adb(["wait-for-device"], timeout=30, on_timeout=None)
+                self.check_adb(["wait-for-device"], timeout=30,
+                               on_timeout=None, need_qemu_running=True)
                 break
             except AdbFailure as e:
                 adb_exception = e
                 continue
         else:
             print("'adb wait-for-device' Timed out")
+            assert adb_exception
             raise adb_exception
 
         self.adb_root()
@@ -822,6 +888,8 @@ class Runner(object):
 
         if self.config.linux:
             args += self.qemu_arch_options.linux_options()
+            if len(self.config.extra_linux_args) > 0:
+                args[-1] += " " + " ".join(self.config.extra_linux_args)
 
         if self.config.boot_android:
             args += self.qemu_arch_options.android_drives_args()
@@ -857,6 +925,11 @@ class Runner(object):
         assert target_state in [RunnerState.BOOTLOADER,
                                 RunnerState.ANDROID], target_state
 
+        # Set self.state to RunnerState.ERROR in case we get an exception
+        # before self.state is set to target_state. This tells shutdown that
+        # cleanup might be needed.
+        self.state = RunnerState.ERROR
+
         self.session = RunnerSession()
         args = self.universal_args()
 
@@ -898,8 +971,9 @@ class Runner(object):
                 self.session.command_pipe = QEMUCommandPipe()
                 args += self.session.command_pipe.command_args
 
-            # Reserve ADB ports
-            self.session.ports = alloc_ports()
+            # Reserve ADB ports - adb uses ports in pairs
+            self.session.ports = alloc_adb_ports.alloc_adb_ports()
+            assert self.session.ports
 
             # Write expected serial number (as given in adb) to stdout.
             sys.stdout.write(
@@ -950,7 +1024,7 @@ class Runner(object):
         if self.state == RunnerState.OFF:
             return
 
-        assert self.session is not None
+        assert self.session
 
         # Clean up generated device tree
         for temp_file in self.session.temp_files:
@@ -976,6 +1050,7 @@ class Runner(object):
 
         if self.adb_transport:
             # Disconnect ADB and wait for our port to be released by qemu
+            assert self.session.ports
             self.adb_down(self.session.ports[1])
 
         # Ideally, we'd clear on launch instead, but it doesn't know whether a
@@ -1008,35 +1083,37 @@ class Runner(object):
 
     def run(self, boot_tests: Optional[List] = None,
             android_tests: Optional[List] = None,
+            hostcommand_tests: Optional[List] = None,
             timeout: Optional[int] = None) -> List[int]:
         """Run boot or android tests.
 
         Runs boot_tests through test_runner, android_tests through ADB,
-        returning aggregated test return codes in a list.
+        hostcommand_tests on host after starting ADB, returning
+        aggregated test return codes in a list.
 
         Returns:
           A list of return codes for the provided tests.
           A negative return code indicates an internal tool failure.
 
         Limitations:
-          Until test_runner is updated, only one of android_tests or boot_tests
-          may be provided.
+          Until test_runner is updated, only one of android_tests,
+          hostcommand_tests,  or boot_tests may be provided.
           Similarly, while boot_tests is a list, test_runner only knows how to
           correctly run a single test at a time.
           Again due to test_runner's current state, if boot_tests are
           specified, interactive will be ignored since the machine will
           terminate itself.
 
-          If android_tests is provided, a Linux and Android dir must be
-          provided in the config.
+          If android_tests or hostcommand_tests is provided, a Linux and
+          Android dir must be provided in the config.
         """
         assert self.state == RunnerState.OFF
         self.config.check_config(self.interactive, boot_tests, android_tests)
 
-        if boot_tests and android_tests:
+        if boot_tests and (android_tests or hostcommand_tests):
             raise RunnerGenericError(
-                "Cannot run boot tests and android tests in the same "
-                "QEMU instance")
+                "Cannot run boot tests and android or hostcommand tests"
+                " in the same QEMU instance")
 
         if boot_tests and len(boot_tests) > 1:
             raise RunnerGenericError(
@@ -1058,11 +1135,19 @@ class Runner(object):
                     if test_result:
                         break
 
+            if hostcommand_tests:
+                for hostcommand_test in hostcommand_tests:
+                    test_result = self.hostcommandtest_run(hostcommand_test, timeout)
+                    test_results.append(test_result)
+                    if test_result:
+                        break
+
             return test_results
         finally:
             # The wait on QEMU is done here to ensure that ADB failures do not
             # take away the user's serial console in interactive mode.
             if self.interactive and self.session:
                 # The user is responsible for quitting QEMU
+                assert self.session.qemu_proc
                 self.session.qemu_proc.wait()
             self.shutdown(factory_reset=True, full_wipe=False)
diff --git a/project/qemu/qemu_arm64_options.py b/project/qemu/qemu_arm64_options.py
index 5dc5023..83315b9 100644
--- a/project/qemu/qemu_arm64_options.py
+++ b/project/qemu/qemu_arm64_options.py
@@ -19,27 +19,38 @@ def _find_dtc():
     return None
 
 
-class QemuDrive():
-    def __init__(self, name: str, index: int, read_only: bool = True):
+class QemuDrive:
+    def __init__(
+        self,
+        name: str,
+        index: int,
+        dir_name: str,
+        read_only: bool = True,
+        ext: str = ".img",
+    ):
         self.name = name
         self.index = index
         self.read_only = read_only
+        self.ext = ext
+        self.img_path = self.path(pathlib.Path(dir_name))
+        if not os.path.exists(self.img_path):
+            raise RunnerGenericError(
+                f"image cannot be found at {self.img_path}"
+            )
 
     def index_letter(self):
         return chr(ord('a') + self.index)
 
     def path(self, directory: os.PathLike):
-        return f"{directory}/{self.name}.img"
+        return os.path.join(directory,f"{self.name}{self.ext}")
 
-    def ensure_image_exists(self, image_dir: os.PathLike,
-                            instance_dir: os.PathLike):
+    def ensure_image_exists(self, instance_dir: os.PathLike):
         if self.read_only:
             return
 
         path = self.path(instance_dir)
         if not os.path.exists(path):
-            snapshot_path = self.path(image_dir)
-            shutil.copy(snapshot_path, path)
+            shutil.copy(self.img_path, path)
 
     def delete_image_changes(self, instance_dir: os.PathLike):
         if self.read_only:
@@ -65,14 +76,24 @@ class QemuArm64Options(object):
 
     MACHINE = "virt,secure=on,virtualization=on"
 
+    # -no-reboot is to avoid the logs of trusty starting again when the system
+    # exists uncleanly, e.g., due to a boot or test failure.
     BASIC_ARGS = [
-        "-nographic", "-cpu", "max,sve=off,pauth=off", "-smp", "4", "-m", "1024", "-d",
-        "unimp", "-semihosting-config", "enable,target=native", "-no-acpi",
+        "-nographic", "-no-reboot",
+        "-cpu", "max,sve=off,pauth=off",
+        "-smp", "4",
+        "-m", "1024",
+        "-d", "unimp",
+        "-semihosting-config", "enable=on,target=native",
+        "-machine", "acpi=off",
     ]
 
     LINUX_ARGS = (
         "earlyprintk console=ttyAMA0,38400 keep_bootcon "
         "root=/dev/ram0 init=/init androidboot.hardware=qemu_trusty "
+        "androidboot.hypervisor.version=1.0.0 "
+        "androidboot.hypervisor.vm.supported=1 "
+        "androidboot.hypervisor.protected_vm.supported=1 "
         "trusty-log.log_ratelimit_interval=0 trusty-log.log_to_dmesg=always")
 
     def __init__(self, config, instance_dir):
@@ -106,6 +127,8 @@ class QemuArm64Options(object):
             "-chardev", f"socket,id=rpmb0,path={sock}"]
 
     def get_initrd_filename(self):
+        if self.config.initrd and pathlib.Path(self.config.initrd).is_file():
+            return self.config.initrd
         return self.config.android_image_dir + "/ramdisk.img"
 
     def initrd_dts(self):
@@ -165,16 +188,19 @@ class QemuArm64Options(object):
 
     def drives(self) -> list[QemuDrive]:
         return [
-            QemuDrive("userdata", 2, read_only=False),
-            QemuDrive("vendor", 1),
-            QemuDrive("system", 0)
+            QemuDrive("metadata", 3, self.config.atf, read_only=False),
+            QemuDrive(
+                "userdata", 2, self.config.android_image_dir, read_only=False
+            ),
+            QemuDrive("vendor", 1, self.config.android_image_dir),
+            QemuDrive("system", 0, self.config.android_image_dir),
         ]
 
     def create_drives_data(self):
         """If drives images don't exist, create some from their snapshots."""
         os.makedirs(self.instance_dir, exist_ok=True)
         for drive in self.drives():
-            drive.ensure_image_exists(self.config.android_image_dir, self.instance_dir)
+            drive.ensure_image_exists(self.instance_dir)
 
     def delete_drives_data(self):
         for drive in self.drives():
diff --git a/project/qemu/run.py b/project/qemu/run.py
index 9a44fb4..d6997b5 100755
--- a/project/qemu/run.py
+++ b/project/qemu/run.py
@@ -43,10 +43,12 @@ def _check_args(args):
     """Validate arguments passed to run_test."""
     assert args.headless, args
     assert not args.linux, args
+    assert not args.initrd, args
     assert not args.atf, args
     assert not args.qemu, args
     assert not args.arch, args
     assert not args.debug, args
+    assert not args.extra_linux_args, args
     assert not args.extra_qemu_flags, args
     assert not args.disable_rpmb, args
 
@@ -60,18 +62,19 @@ def _prepare_runner_for_test(runner, args):
     """
     if args.boot_test:
         target_state = qemu.RunnerState.BOOTLOADER
-    elif args.shell_command:
+    elif args.shell_command or args.host_command:
         target_state = qemu.RunnerState.ANDROID
     else:
         raise qemu_error.ConfigError(
-            "Command must request exactly one Android or boot test to run")
+            "Command must request exactly one Android, boot test, or"
+            " host command to run"
+        )
 
     # Due to limitations in the test runner, always reboot between boot tests
     if (runner.state != target_state or
             runner.state == qemu.RunnerState.BOOTLOADER):
         runner.reboot(target_state, factory_reset=True, full_wipe=False)
 
-
 def run_test(runner: qemu.Runner, cmd: List[str]) -> int:
     args = build_argparser().parse_args(cmd)
     _check_args(args)
@@ -82,6 +85,8 @@ def run_test(runner: qemu.Runner, cmd: List[str]) -> int:
         return runner.boottest_run(args.boot_test, timeout)
     if args.shell_command:
         return runner.androidtest_run(args.shell_command, timeout)
+    if args.host_command:
+        return runner.hostcommandtest_run(args.host_command[0], timeout)
 
     raise qemu.RunnerGenericError(
         "Command contained neither a boot test nor an Android test to run")
@@ -103,8 +108,10 @@ def build_argparser():
     argument_parser.add_argument("--debug-on-error", action="store_true")
     argument_parser.add_argument("--boot-test", action="append")
     argument_parser.add_argument("--shell-command", action="append")
+    argument_parser.add_argument("--host-command", action="append")
     argument_parser.add_argument("--android")
     argument_parser.add_argument("--linux")
+    argument_parser.add_argument("--initrd")
     argument_parser.add_argument("--instance-dir", type=str,
                                  default="/tmp/trusty-qemu-generic-arm64")
     argument_parser.add_argument("--atf")
@@ -112,6 +119,7 @@ def build_argparser():
     argument_parser.add_argument("--arch")
     argument_parser.add_argument("--disable-rpmb", action="store_true")
     argument_parser.add_argument("--timeout", type=int)
+    argument_parser.add_argument('-n', '--extra-linux-args', nargs='+', default=[])
     argument_parser.add_argument("extra_qemu_flags", nargs="*")
     return argument_parser
 
@@ -128,12 +136,16 @@ def main():
         config.boot_android = True
     if args.linux:
         config.linux = args.linux
+    if args.initrd:
+        config.initrd = args.initrd
     if args.atf:
         config.atf = args.atf
     if args.qemu:
         config.qemu = args.qemu
     if args.arch:
         config.arch = args.arch
+    if args.extra_linux_args:
+        config.extra_linux_args = args.extra_linux_args
     if args.extra_qemu_flags:
         config.extra_qemu_flags += args.extra_qemu_flags
 
@@ -146,7 +158,8 @@ def main():
                          debug_on_error=args.debug_on_error)
 
     try:
-        results = runner.run(args.boot_test, args.shell_command, args.timeout)
+        results = runner.run(args.boot_test, args.shell_command,
+                             args.host_command, args.timeout)
         print("Command results: " + repr(results))
 
         if any(results):
diff --git a/project/vm-arm-virt-inc.mk b/project/vm-arm-virt-inc.mk
new file mode 100644
index 0000000..d523994
--- /dev/null
+++ b/project/vm-arm-virt-inc.mk
@@ -0,0 +1,40 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+# release build
+DEBUG ?= 1
+UBSAN_ENABLED ?= false
+RELEASE_BUILD ?= true
+SYMTAB_ENABLED ?= false
+
+# no placeholder hals by default
+WITH_FAKE_HWRNG ?= false
+WITH_FAKE_HWKEY ?= false
+WITH_FAKE_KEYBOX ?= false
+
+USE_SYSTEM_BINDER := true
+
+# This keeps trusty is VMs in sync with the latest
+# Android Profile for DICE. This is required since
+# profile versions for each cert in a DICE chain must
+# be of greater than or equal version to their parent.
+# pvmfw uses the latest android profile for DICE and
+# launches trusty in protected VMs, so we match that
+# version.
+DICE_PROFILE_FOR_OPEN_DICE := android
+
+include project/generic-arm-virt-inc.mk
+include project/generic-arm-tz-inc.mk
+
diff --git a/project/vm-arm-virt-test-inc.mk b/project/vm-arm-virt-test-inc.mk
new file mode 100644
index 0000000..86892f0
--- /dev/null
+++ b/project/vm-arm-virt-test-inc.mk
@@ -0,0 +1,18 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+include project/generic-arm-virt-inc.mk
+include project/generic-arm-tz-test-inc.mk
+
diff --git a/project/vm-arm64-security-inc.mk b/project/vm-arm64-security-inc.mk
new file mode 100644
index 0000000..a7a16e7
--- /dev/null
+++ b/project/vm-arm64-security-inc.mk
@@ -0,0 +1,40 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+include project/vm-arm-virt-inc.mk
+
+#
+# overwrite list of TAs
+#
+TRUSTY_VM_INCLUDE_KEYMINT ?= true
+TRUSTY_VM_INCLUDE_GATEKEEPER ?= true
+
+# compiled from source
+TRUSTY_BUILTIN_USER_TASKS := \
+	trusty/user/app/gatekeeper \
+	trusty/user/app/keymint/app \
+	trusty/user/base/app/device_tree \
+
+ifeq (true,$(call TOBOOL,$(USER_COVERAGE_ENABLED)))
+TRUSTY_ALL_USER_TASKS += \
+	trusty/user/base/app/coverage \
+
+endif
+
+ifeq (true,$(call TOBOOL,$(UNITTEST_COVERAGE_ENABLED)))
+TRUSTY_ALL_USER_TASKS += \
+	trusty/user/base/app/line-coverage \
+
+endif
diff --git a/project/vm-arm64-security-placeholder-trusted-hal-inc.mk b/project/vm-arm64-security-placeholder-trusted-hal-inc.mk
new file mode 100644
index 0000000..a62c57a
--- /dev/null
+++ b/project/vm-arm64-security-placeholder-trusted-hal-inc.mk
@@ -0,0 +1,45 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+#
+# complement with the placeholder trusted hals
+#
+WITH_FAKE_HWRNG ?= true
+WITH_FAKE_HWKEY ?= true
+WITH_FAKE_KEYBOX ?= true
+
+# Derive RPMB key using HKDF
+WITH_HKDF_RPMB_KEY ?= true
+
+STORAGE_ENABLE_ERROR_REPORTING ?= true
+STORAGE_AIDL_ENABLED ?= true
+TRUSTY_VM_INCLUDE_SECURE_STORAGE_HAL ?= true
+
+KEYMINT_TRUSTY_VM ?= nonsecure
+
+include project/vm-arm64-security-inc.mk
+
+TRUSTY_BUILTIN_USER_TASKS += \
+	trusty/user/app/authmgr/authmgr-be/app \
+	trusty/user/app/sample/hwaes \
+	trusty/user/app/sample/hwbcc \
+	trusty/user/app/sample/hwcrypto \
+	trusty/user/app/sample/hwcryptohal/server/app \
+	trusty/user/app/sample/hwwsk \
+	trusty/user/app/sample/rust-hello-world-trusted-hal/app \
+	trusty/user/app/storage \
+	trusty/user/base/app/metrics \
+	trusty/user/base/app/system_state_server_static \
+
diff --git a/project/generic-arm64-gicv3-el3spmc-test-debug.mk b/project/vm-arm64-security-placeholder-trusted-hal-user.mk
similarity index 80%
rename from project/generic-arm64-gicv3-el3spmc-test-debug.mk
rename to project/vm-arm64-security-placeholder-trusted-hal-user.mk
index ec3be1d..8116ea4 100644
--- a/project/generic-arm64-gicv3-el3spmc-test-debug.mk
+++ b/project/vm-arm64-security-placeholder-trusted-hal-user.mk
@@ -1,4 +1,4 @@
-# Copyright (C) 2022 The Android Open Source Project
+# Copyright (C) 2025 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -13,7 +13,4 @@
 # limitations under the License.
 #
 
-GIC_VERSION := 3
-SPMC_EL := 3
-
-include project/generic-arm64-test-debug-inc.mk
+include project/vm-arm64-security-placeholder-trusted-hal-inc.mk
diff --git a/project/vm-arm64-security-placeholder-trusted-hal-userdebug.mk b/project/vm-arm64-security-placeholder-trusted-hal-userdebug.mk
new file mode 100644
index 0000000..7d55c5c
--- /dev/null
+++ b/project/vm-arm64-security-placeholder-trusted-hal-userdebug.mk
@@ -0,0 +1,25 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+# debug build
+DEBUG ?= 2
+UBSAN_ENABLED ?= true
+RELEASE_BUILD ?= false
+LOG_LEVEL_KERNEL_RUST := 2
+
+# If SYMTAB_ENABLED is true: do not strip symbols from the resulting app binary
+SYMTAB_ENABLED ?= true
+
+include project/vm-arm64-security-placeholder-trusted-hal-inc.mk
diff --git a/project/vm-arm64-security-user.mk b/project/vm-arm64-security-user.mk
new file mode 100644
index 0000000..07ddcf1
--- /dev/null
+++ b/project/vm-arm64-security-user.mk
@@ -0,0 +1,16 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+include project/vm-arm64-security-inc.mk
diff --git a/project/vm-arm64-security-userdebug.mk b/project/vm-arm64-security-userdebug.mk
new file mode 100644
index 0000000..39160f3
--- /dev/null
+++ b/project/vm-arm64-security-userdebug.mk
@@ -0,0 +1,25 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+# debug build
+DEBUG ?= 2
+UBSAN_ENABLED ?= true
+RELEASE_BUILD ?= false
+LOG_LEVEL_KERNEL_RUST := 2
+
+# If SYMTAB_ENABLED is true: do not strip symbols from the resulting app binary
+SYMTAB_ENABLED ?= true
+
+include project/vm-arm64-security-inc.mk
diff --git a/project/vm-arm64-test-inc.mk b/project/vm-arm64-test-inc.mk
new file mode 100644
index 0000000..46954b6
--- /dev/null
+++ b/project/vm-arm64-test-inc.mk
@@ -0,0 +1,59 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+include project/vm-arm-virt-inc.mk
+
+#
+# include list of test TAs for the Trusted HALs
+#
+TRUSTY_RUST_USER_TESTS := \
+	trusty/user/app/authmgr/authmgr-fe \
+	trusty/user/app/sample/hwcryptokey-test \
+	trusty/user/app/storage/test/storage-unittest-aidl \
+	trusty/user/app/storage/test/storage-unittest-aidl/ns \
+	trusty/user/app/authmgr/authmgr-be/lib \
+
+# the test-vm does not include any TAs by default
+# (except for the test TAs that are included by virt-test-inc.mk)
+#
+# tests in Trusty are mostly declared as TRUSTY_LOADABLE_USER_TESTS,
+# they also are included by default as builtin apps
+# (unless the top-level makefile initializes TRUSTY_BUILTIN_USER_TESTS,
+#  see documentation in trusty/kernel/app/trusty/user-tasks.mk)
+#
+# for virt payload, loadable TAs are generally not applicable
+# (apploader interface is not a stable ABI yet).
+# So apploader should generally be disabled.
+#
+# the Trusty build system however makes it complicated to disable
+# apploader service while still declaring tests as loadable.
+# as a short-term workaround, the test-vm will include apploader service
+# TODO(b/) evolve `trusty/kernel/app/trusty/user-tasks.mk` to support
+# disabling apploader service and rebalancing loadable test as builtin tests
+TRUSTY_BUILTIN_USER_TASKS := \
+	trusty/user/base/app/apploader \
+	trusty/user/app/authmgr/authmgr-fe/app \
+
+ifeq (true,$(call TOBOOL,$(USER_COVERAGE_ENABLED)))
+TRUSTY_ALL_USER_TASKS += \
+	trusty/user/base/app/coverage \
+
+endif
+
+ifeq (true,$(call TOBOOL,$(UNITTEST_COVERAGE_ENABLED)))
+TRUSTY_ALL_USER_TASKS += \
+	trusty/user/base/app/line-coverage \
+
+endif
diff --git a/project/vm-arm64-test-placeholder-trusted-hal-inc.mk b/project/vm-arm64-test-placeholder-trusted-hal-inc.mk
new file mode 100644
index 0000000..86a9807
--- /dev/null
+++ b/project/vm-arm64-test-placeholder-trusted-hal-inc.mk
@@ -0,0 +1,44 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+#
+# complement with the placeholder trusted hals
+#
+WITH_FAKE_HWRNG ?= true
+WITH_FAKE_HWKEY ?= true
+WITH_FAKE_KEYBOX ?= true
+
+# Derive RPMB key using HKDF
+WITH_HKDF_RPMB_KEY ?= true
+
+STORAGE_ENABLE_ERROR_REPORTING ?= true
+STORAGE_AIDL_ENABLED ?= true
+TRUSTY_VM_INCLUDE_SECURE_STORAGE_HAL ?= true
+AUTHMGRFE_MODE_INSECURE ?= true
+
+include project/vm-arm64-test-inc.mk
+
+TRUSTY_BUILTIN_USER_TASKS += \
+	trusty/user/app/authmgr/authmgr-be/app \
+	trusty/user/app/sample/hwaes \
+	trusty/user/app/sample/hwbcc \
+	trusty/user/app/sample/hwcrypto \
+	trusty/user/app/sample/hwcryptohal/server/app \
+	trusty/user/app/sample/hwwsk \
+	trusty/user/app/sample/rust-hello-world-trusted-hal/app \
+	trusty/user/app/storage \
+	trusty/user/base/app/metrics \
+	trusty/user/base/app/system_state_server_static \
+
diff --git a/project/vm-arm64-test-placeholder-trusted-hal-user.mk b/project/vm-arm64-test-placeholder-trusted-hal-user.mk
new file mode 100644
index 0000000..1bc2280
--- /dev/null
+++ b/project/vm-arm64-test-placeholder-trusted-hal-user.mk
@@ -0,0 +1,16 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+include project/vm-arm64-test-placeholder-trusted-hal-inc.mk
diff --git a/project/vm-arm64-test-placeholder-trusted-hal-userdebug.mk b/project/vm-arm64-test-placeholder-trusted-hal-userdebug.mk
new file mode 100644
index 0000000..7be99fc
--- /dev/null
+++ b/project/vm-arm64-test-placeholder-trusted-hal-userdebug.mk
@@ -0,0 +1,25 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+# debug build
+DEBUG ?= 2
+UBSAN_ENABLED ?= true
+RELEASE_BUILD ?= false
+LOG_LEVEL_KERNEL_RUST := 2
+
+# If SYMTAB_ENABLED is true: do not strip symbols from the resulting app binary
+SYMTAB_ENABLED ?= true
+
+include project/vm-arm64-test-placeholder-trusted-hal-inc.mk
diff --git a/project/vm-arm64-test-user.mk b/project/vm-arm64-test-user.mk
new file mode 100644
index 0000000..16fa5fe
--- /dev/null
+++ b/project/vm-arm64-test-user.mk
@@ -0,0 +1,16 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+include project/vm-arm64-test-inc.mk
diff --git a/project/vm-arm64-test-userdebug.mk b/project/vm-arm64-test-userdebug.mk
new file mode 100644
index 0000000..36a4ab9
--- /dev/null
+++ b/project/vm-arm64-test-userdebug.mk
@@ -0,0 +1,25 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+# debug build
+DEBUG ?= 2
+UBSAN_ENABLED ?= true
+RELEASE_BUILD ?= false
+LOG_LEVEL_KERNEL_RUST := 2
+
+# If SYMTAB_ENABLED is true: do not strip symbols from the resulting app binary
+SYMTAB_ENABLED ?= true
+
+include project/vm-arm64-test-inc.mk
diff --git a/project/vm-arm64-test_os-inc.mk b/project/vm-arm64-test_os-inc.mk
new file mode 100644
index 0000000..d48421f
--- /dev/null
+++ b/project/vm-arm64-test_os-inc.mk
@@ -0,0 +1,48 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+include project/vm-arm-virt-test-inc.mk
+
+# the test_os VM does not include any TAs by default
+# (except for the test TAs that are included by virt-test-inc.mk)
+#
+# tests in Trusty are mostly declared as TRUSTY_LOADABLE_USER_TESTS,
+# they also are included by default as builtin apps
+# (unless the top-level makefile initializes TRUSTY_BUILTIN_USER_TESTS,
+#  see documentation in trusty/kernel/app/trusty/user-tasks.mk)
+#
+# for virt payload, loadable TAs are generally not applicable
+# (apploader interface is not a stable ABI yet).
+# So apploader should generally be disabled.
+#
+# the Trusty build system however makes it complicated to disable
+# apploader service while still declaring tests as loadable.
+# as a short-term workaround, the test-vm will include apploader service
+# TODO(b/) evolve `trusty/kernel/app/trusty/user-tasks.mk` to support
+# disabling apploader service and rebalancing loadable test as builtin tests
+TRUSTY_BUILTIN_USER_TASKS := \
+	trusty/user/base/app/apploader \
+
+ifeq (true,$(call TOBOOL,$(USER_COVERAGE_ENABLED)))
+TRUSTY_ALL_USER_TASKS += \
+	trusty/user/base/app/coverage \
+
+endif
+
+ifeq (true,$(call TOBOOL,$(UNITTEST_COVERAGE_ENABLED)))
+TRUSTY_ALL_USER_TASKS += \
+	trusty/user/base/app/line-coverage \
+
+endif
diff --git a/project/vm-arm64-test_os-user.mk b/project/vm-arm64-test_os-user.mk
new file mode 100644
index 0000000..8a428e7
--- /dev/null
+++ b/project/vm-arm64-test_os-user.mk
@@ -0,0 +1,16 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+include project/vm-arm64-test_os-inc.mk
diff --git a/project/vm-arm64-test_os-userdebug.mk b/project/vm-arm64-test_os-userdebug.mk
new file mode 100644
index 0000000..1b77cdc
--- /dev/null
+++ b/project/vm-arm64-test_os-userdebug.mk
@@ -0,0 +1,25 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+# debug build
+DEBUG ?= 2
+UBSAN_ENABLED ?= true
+RELEASE_BUILD ?= false
+LOG_LEVEL_KERNEL_RUST := 2
+
+# If SYMTAB_ENABLED is true: do not strip symbols from the resulting app binary
+SYMTAB_ENABLED ?= true
+
+include project/vm-arm64-test_os-inc.mk
```

