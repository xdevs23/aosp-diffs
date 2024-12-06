```diff
diff --git a/agl_services_build/yocto-layer/meta-google/recipes-devtools/getprop/files/getprop b/agl_services_build/yocto-layer/meta-google/recipes-devtools/getprop/files/getprop
new file mode 100755
index 0000000..bf33def
--- /dev/null
+++ b/agl_services_build/yocto-layer/meta-google/recipes-devtools/getprop/files/getprop
@@ -0,0 +1,26 @@
+#!/usr/bin/env python3
+#
+# Copyright (C) 2022 The Android Open Source Project
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
+
+import sys
+
+PROPERTIES = {
+    'ro.build.flavor': 'trout_pvm-eng',
+}
+
+for arg in sys.argv[1:]:
+    val = PROPERTIES.get(arg)
+    if val:
+        print(val)
diff --git a/agl_services_build/yocto-layer/meta-google/recipes-devtools/getprop/getprop.bb b/agl_services_build/yocto-layer/meta-google/recipes-devtools/getprop/getprop.bb
new file mode 100644
index 0000000..c2c461c
--- /dev/null
+++ b/agl_services_build/yocto-layer/meta-google/recipes-devtools/getprop/getprop.bb
@@ -0,0 +1,16 @@
+SUMMARY = "A script that allows Google internal tools to recognize the host VM as a Trout device."
+
+LICENSE = "Apache-2.0"
+
+inherit allarch
+
+SRC_URI = " \
+    file://getprop \
+"
+
+do_install() {
+    install -d ${D}${prefix}/local/bin
+    install -m 0755 ${WORKDIR}/getprop ${D}${prefix}/local/bin
+}
+
+FILES_${PN} += "${prefix}/local/bin/getprop"
diff --git a/aosp_trout_arm64.mk b/aosp_trout_arm64.mk
index c37fb78..b4ce159 100644
--- a/aosp_trout_arm64.mk
+++ b/aosp_trout_arm64.mk
@@ -27,15 +27,6 @@ TARGET_RO_FILE_SYSTEM_TYPE := ext4
 TARGET_USES_CUTTLEFISH_AUDIO ?= false
 AUDIO_FEATURE_HFP_ENABLED ?= true
 
-# HWComposer choice. Setting this flag to true
-# will disable Ranchu and turn on the legacy
-# drmhwc. This is not a supported configuration and
-# should only be turned on for debugging and experimental
-# purposes. In general, omitting this line or leaving the
-# default configured (false) will do the right thing and pick
-# Ranchu from upstream Cuttlefish
-TARGET_ENABLE_DRMHWCOMPOSER ?= false
-
 # Audio Control HAL
 # TODO (chenhaosjtuacm, egranata): move them to kernel command line
 LOCAL_AUDIOCONTROL_PROPERTIES ?= \
diff --git a/aosp_trout_common.mk b/aosp_trout_common.mk
index 57ea994..ab99d05 100644
--- a/aosp_trout_common.mk
+++ b/aosp_trout_common.mk
@@ -54,6 +54,10 @@ endif
 # Audio Control HAL
 LOCAL_AUDIOCONTROL_HAL_PRODUCT_PACKAGE ?= android.hardware.automotive.audiocontrol-service.trout
 
+# VirtWiFi interface settings
+DEVICE_VIRTWIFI_PORT ?= eth0
+PRODUCT_VENDOR_PROPERTIES += ro.vendor.disable_rename_eth0=true
+
 # Dumpstate HAL
 # TODO(b/215200137): Re-enable once converted to AIDL
 #LOCAL_DUMPSTATE_PRODUCT_PACKAGE ?= android.hardware.dumpstate@1.1-service.trout
@@ -73,6 +77,7 @@ endif
 LOCAL_VHAL_PRODUCT_PACKAGE ?= ${TROUT_DEFAULT_VHAL_PACKAGES}
 
 # EVS HAL
+LOCAL_EVS_PROPERTIES ?= persist.automotive.evs.mode=1
 LOCAL_EVS_RRO_PACKAGE_OVERLAYS ?= TroutEvsOverlay
 ENABLE_EVS_SERVICE ?= true
 ENABLE_MOCK_EVSHAL ?= false
@@ -90,7 +95,7 @@ endif
 PRODUCT_COPY_FILES += $(LOCAL_EVS_PRODUCT_COPY_FILES)
 
 # A device inheriting trout can enable Vulkan support.
-TARGET_VULKAN_SUPPORT ?= false
+TARGET_VULKAN_SUPPORT ?= true
 
 PRODUCT_PROPERTY_OVERRIDES += \
     ro.hardware.type=automotive \
diff --git a/hal/vehicle/aidl/VirtualizedVehicleService.cpp b/hal/vehicle/aidl/VirtualizedVehicleService.cpp
index 4ed8422..94ee330 100644
--- a/hal/vehicle/aidl/VirtualizedVehicleService.cpp
+++ b/hal/vehicle/aidl/VirtualizedVehicleService.cpp
@@ -65,7 +65,7 @@ int main(int /* argc */, char* /* argv */[]) {
 
     constexpr auto maxConnectWaitTime = std::chrono::seconds(5);
     auto hardware = std::make_unique<GRPCVehicleHardware>(vsock->str());
-    if (const auto connected = hardware->waitForConnected(maxConnectWaitTime)) {
+    if (hardware->waitForConnected(maxConnectWaitTime)) {
         LOG(INFO) << "Connected to vsock server at " << vsock->str();
     } else {
         LOG(INFO) << "Failed to connect to vsock server at " << vsock->str()
diff --git a/rro_overlays/EvsOverlay/OWNERS b/rro_overlays/EvsOverlay/OWNERS
index af0b726..e51139a 100644
--- a/rro_overlays/EvsOverlay/OWNERS
+++ b/rro_overlays/EvsOverlay/OWNERS
@@ -1,3 +1,2 @@
 ankitarora@google.com
-chenhaosjtuacm@google.com
 egranata@google.com
diff --git a/sepolicy/vendor/google/genfs_contexts b/sepolicy/vendor/google/genfs_contexts
new file mode 100644
index 0000000..8afe34b
--- /dev/null
+++ b/sepolicy/vendor/google/genfs_contexts
@@ -0,0 +1,2 @@
+# TODO(tutankhamen): hardcoded virtio_mmio device just for testing
+genfscon sysfs /devices/platform/4a00b000.virtio_mmio/virtio11/uevent u:object_r:sysfs_gpu_trout:s0
diff --git a/sepolicy/vendor/google/hal_audiocontrol_impl.te b/sepolicy/vendor/google/hal_audiocontrol_impl.te
index e9d6870..6103cc5 100644
--- a/sepolicy/vendor/google/hal_audiocontrol_impl.te
+++ b/sepolicy/vendor/google/hal_audiocontrol_impl.te
@@ -15,7 +15,4 @@ allow system_server hal_audiocontrol_server:process sigkill;
 
 allow hal_audiocontrol_impl self:vsock_socket { create_socket_perms_no_ioctl listen accept };
 
-# TODO(b/130668487): Label the vsock sockets.
-allow hal_audiocontrol_impl unlabeled:vsock_socket { read shutdown write };
-
 allow hal_audiocontrol_impl proc_net:file { getattr open read };
diff --git a/tools/tracing/time_utility/ClockTime.cpp b/tools/tracing/time_utility/ClockTime.cpp
new file mode 100644
index 0000000..616628b
--- /dev/null
+++ b/tools/tracing/time_utility/ClockTime.cpp
@@ -0,0 +1,99 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <time.h>
+#include <cstring>
+#include <iostream>
+#include <optional>
+#include <sstream>
+#include <unordered_map>
+
+uint64_t s2ns(uint64_t s) {
+    return s * 1000000000ull;
+}
+
+void PrintHelpAndExit(const std::string& error_msg = "") {
+    int exit_error = 0;
+    if (!error_msg.empty()) {
+        std::cout << error_msg << "\n";
+        exit_error = 1;
+    }
+
+    std::cout << "Usage: ClockTime [CLOCK_ID]\n"
+              << "CLOCK_ID can be  CLOCK_REALTIME or CLOCK_MONOTONIC \n"
+              << "if omitted, it will obtain the processors's time-stamp counter \n"
+              << "on x86 it will use RDTSC, on arm64 it will use MRS CNTCVT. \n"
+              << "-h, --help      Print this help message\n";
+
+    exit(exit_error);
+}
+
+int GetTime(int type, uint64_t* ts_ns) {
+    struct timespec ts;
+    int res = clock_gettime(type, &ts);
+    if (!res) {
+        *ts_ns = s2ns(ts.tv_sec) + ts.tv_nsec;
+    }
+    return res;
+}
+
+uint64_t GetCPUTicks() {
+#if defined(__x86_64__) || defined(__amd64__)
+    uint32_t hi, lo;
+    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
+    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
+#elif defined(__aarch64__)
+    uint64_t vct;
+    asm volatile("mrs %0, cntvct_el0" : "=r"(vct));
+    return vct;
+#else
+    PrintHelpAndExit("GetCPUTicks() is not supported");
+    return 0;
+#endif
+}
+
+int main(int argc, char* argv[]) {
+    std::unordered_map<std::string, clockid_t> clock_map = {
+            std::make_pair("CLOCK_REALTIME", CLOCK_REALTIME),
+            std::make_pair("CLOCK_MONOTONIC", CLOCK_MONOTONIC)};
+
+    if (argc == 1) {
+        std::cout << GetCPUTicks() << "\n";
+    } else if (argc == 2) {
+        if (!(strcmp(argv[1], "-h") && strcmp(argv[1], "--help"))) {
+            PrintHelpAndExit();
+        }
+
+        uint64_t ts_ns;
+        auto it = clock_map.find(argv[1]);
+        if (it == clock_map.end()) {
+            PrintHelpAndExit("Wrong CLOCK_ID");
+        }
+
+        int res = GetTime(it->second, &ts_ns);
+        if (res) {
+            std::stringstream err_msg("GetTime() got error");
+            err_msg << res;
+            PrintHelpAndExit(err_msg.str());
+        }
+
+        std::cout << ts_ns << "\n";
+    } else {
+        PrintHelpAndExit("Wrong number of arguments");
+    }
+
+    return EXIT_SUCCESS;
+}
diff --git a/trout_arm64/BoardConfig.mk b/trout_arm64/BoardConfig.mk
index 578dab0..0e2b6a3 100644
--- a/trout_arm64/BoardConfig.mk
+++ b/trout_arm64/BoardConfig.mk
@@ -14,6 +14,26 @@
 # limitations under the License.
 #
 
+#
+# arm64 target for Trout
+#
+
+TARGET_BOARD_PLATFORM := vsoc_arm64
+TARGET_ARCH := arm64
+TARGET_ARCH_VARIANT := armv8-a
+TARGET_CPU_ABI := arm64-v8a
+TARGET_CPU_VARIANT := cortex-a53
+
+AUDIOSERVER_MULTILIB := first
+
+HOST_CROSS_OS := linux_musl
+HOST_CROSS_ARCH := arm64
+HOST_CROSS_2ND_ARCH :=
+
+# Android Bluetooth stack configuration
+LOCAL_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR ?= device/google/trout/product_files/bluetooth
+BOARD_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR := $(LOCAL_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR)
+
 # Enable sparse on all filesystem images
 TARGET_USERIMAGES_SPARSE_EROFS_DISABLED ?= false
 TARGET_USERIMAGES_SPARSE_EXT_DISABLED ?= false
@@ -82,14 +102,10 @@ RAMDISK_KERNEL_MODULES ?= \
 
 AUDIOSERVER_MULTILIB := first
 
-HOST_CROSS_OS := linux_bionic
+HOST_CROSS_OS := linux_musl
 HOST_CROSS_ARCH := arm64
 HOST_CROSS_2ND_ARCH :=
 
-# Android Bluetooth stack configuration
-LOCAL_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR ?= device/google/trout/product_files/bluetooth
-BOARD_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR := $(LOCAL_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR)
-
 # Turn off AVB so that trout can boot
 BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS += --flag 2
 BOARD_KERNEL_CMDLINE += androidboot.verifiedbootstate=orange
@@ -107,7 +123,7 @@ BOARD_KERNEL_CMDLINE += androidboot.cf_devcfg=1
 BOARD_KERNEL_CMDLINE += androidboot.cpuvulkan.version=0
 BOARD_KERNEL_CMDLINE += androidboot.hardware.gralloc=minigbm
 BOARD_KERNEL_CMDLINE += androidboot.hardware.hwcomposer=ranchu
-BOARD_KERNEL_CMDLINE += androidboot.hardware.egl=mesa
+BOARD_KERNEL_CMDLINE += androidboot.hardware.egl=emulation
 BOARD_KERNEL_CMDLINE += androidboot.hardware.hwcomposer.mode=client
 BOARD_KERNEL_CMDLINE += androidboot.hardware.hwcomposer.display_finder_mode=drm
 BOARD_KERNEL_CMDLINE += androidboot.lcd_density=160
diff --git a/vport_trigger/Android.bp b/vport_trigger/Android.bp
deleted file mode 100644
index e983817..0000000
--- a/vport_trigger/Android.bp
+++ /dev/null
@@ -1,34 +0,0 @@
-//
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_binary {
-    name: "vport_trigger",
-    init_rc: ["vport_trigger.rc"],
-    srcs: [
-        "main.cpp",
-    ],
-    shared_libs: [
-        "libcutils",
-	"liblog",
-	"libbase",
-    ],
-    vendor: true,
-    cflags: ["-Werror", "-Wall", "-D_FILE_OFFSET_BITS=64"]
-}
diff --git a/vport_trigger/vport_trigger.rc b/vport_trigger/vport_trigger.rc
index 958119d..29616a0 100644
--- a/vport_trigger/vport_trigger.rc
+++ b/vport_trigger/vport_trigger.rc
@@ -4,4 +4,5 @@ on fs
 
 
 service vport_trigger /vendor/bin/vport_trigger
+    user root
     oneshot
```

