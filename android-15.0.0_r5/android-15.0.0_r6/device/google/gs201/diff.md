```diff
diff --git a/BoardConfig-common.mk b/BoardConfig-common.mk
index 48d30a4..681bb14 100644
--- a/BoardConfig-common.mk
+++ b/BoardConfig-common.mk
@@ -16,9 +16,6 @@
 include build/make/target/board/BoardConfigMainlineCommon.mk
 include build/make/target/board/BoardConfigPixelCommon.mk
 
-# Should be uncommented after fixing vndk-sp violation is fixed.
-PRODUCT_FULL_TREBLE_OVERRIDE := true
-
 # HACK : To fix up after bring up multimedia devices.
 TARGET_SOC := gs201
 
@@ -30,7 +27,6 @@ TARGET_ARCH := arm64
 TARGET_ARCH_VARIANT := armv8-2a
 TARGET_CPU_ABI := arm64-v8a
 TARGET_CPU_VARIANT := cortex-a55
-TARGET_CPU_VARIANT_RUNTIME := cortex-a55
 
 # Enable 64-bit for non-zygote.
 ZYGOTE_FORCE_64 := true
@@ -50,7 +46,7 @@ BOARD_KERNEL_CMDLINE += dyndbg=\"func alloc_contig_dump_pages +p\"
 BOARD_KERNEL_CMDLINE += earlycon=exynos4210,0x10A00000 console=ttySAC0,115200 androidboot.console=ttySAC0 printk.devkmsg=on
 BOARD_KERNEL_CMDLINE += cma_sysfs.experimental=Y
 BOARD_KERNEL_CMDLINE += cgroup_disable=memory
-BOARD_KERNEL_CMDLINE += rcupdate.rcu_expedited=1 rcu_nocbs=all
+BOARD_KERNEL_CMDLINE += rcupdate.rcu_expedited=1 rcu_nocbs=all rcutree.enable_rcu_lazy
 BOARD_KERNEL_CMDLINE += stack_depot_disable=off page_pinner=on
 BOARD_KERNEL_CMDLINE += swiotlb=1024
 BOARD_KERNEL_CMDLINE += disable_dma32=on
diff --git a/OWNERS b/OWNERS
index e6ce5d0..d1ffbd2 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,2 @@
 # per-file for Pixel device makefiles, see go/pixel-device-mk-owner-checklist for details.
-per-file *.mk=file:device/google/gs-common:main:/MK_OWNERS
+per-file *.mk,{**/,}Android.bp=file:device/google/gs-common:main:/MK_OWNERS
diff --git a/conf/OWNERS b/conf/OWNERS
new file mode 100644
index 0000000..20af85b
--- /dev/null
+++ b/conf/OWNERS
@@ -0,0 +1,2 @@
+# per-file for Pixel fstab
+per-file fstab.*=file:device/google/gs-common:main:/FSTAB_OWNERS
diff --git a/conf/init.gs201.rc b/conf/init.gs201.rc
index f4bc6ea..9223edd 100644
--- a/conf/init.gs201.rc
+++ b/conf/init.gs201.rc
@@ -1,3 +1,4 @@
+import /vendor/etc/init/hw/init.gs201.storage.rc
 import /vendor/etc/init/hw/init.gs201.usb.rc
 import android.hardware.drm@1.2-service.widevine.rc
 import init.exynos.sensorhub.rc
@@ -51,6 +52,8 @@ on init
     chown system system /proc/vendor_sched/prefer_idle_clear
     chown system system /proc/vendor_sched/pmu_poll_enable
     chown system system /proc/vendor_sched/pmu_poll_time
+    chown system system /proc/vendor_sched/uclamp_fork_reset_clear
+    chown system system /proc/vendor_sched/uclamp_fork_reset_set
     chown system system /sys/devices/system/cpu/cpufreq/policy0/sched_pixel/lcpi_threshold
     chown system system /sys/devices/system/cpu/cpufreq/policy0/sched_pixel/spc_threshold
     chown system system /sys/devices/system/cpu/cpufreq/policy0/sched_pixel/limit_frequency
@@ -100,6 +103,8 @@ on init
     chmod 0220 /proc/vendor_sched/prefer_idle_clear
     chmod 0220 /proc/vendor_sched/pmu_poll_enable
     chmod 0220 /proc/vendor_sched/pmu_poll_time
+    chmod 0220 /proc/vendor_sched/uclamp_fork_reset_clear
+    chmod 0220 /proc/vendor_sched/uclamp_fork_reset_set
 
     start vendor.keymaster-4-0
 
@@ -141,16 +146,6 @@ on init
     write /sys/class/net/rmnet6/queues/rx-0/rps_cpus fe
     write /sys/class/net/rmnet7/queues/rx-0/rps_cpus fe
 
-    # Create UDS structure for base VR services.
-    mkdir /dev/socket/pdx 0775 system system
-    mkdir /dev/socket/pdx/system 0775 system system
-    mkdir /dev/socket/pdx/system/buffer_hub 0775 system system
-    mkdir /dev/socket/pdx/system/performance 0775 system system
-    mkdir /dev/socket/pdx/system/vr 0775 system system
-    mkdir /dev/socket/pdx/system/vr/display 0775 system system
-    mkdir /dev/socket/pdx/system/vr/pose 0775 system system
-    mkdir /dev/socket/pdx/system/vr/sensors 0775 system system
-
     # Boot time 183626384
     write /proc/vendor_sched/groups/ta/uclamp_min 159
     write /proc/vendor_sched/groups/ta/prefer_idle 1
@@ -261,6 +256,7 @@ on init
     chown system system /sys/class/power_supply/wireless/device/version
     chown system system /sys/class/power_supply/wireless/device/features
     chown system system /sys/class/power_supply/wireless/device/authtype
+    chown system system /sys/class/power_supply/wireless/device/authstart
 
     # Adaptive charge
     chown system system /sys/class/power_supply/battery/charge_deadline
@@ -688,6 +684,12 @@ on property:sys.boot_completed=1
     write /dev/cpuset/camera-daemon/cpus ${persist.device_config.vendor_system_native.camera-daemon_cpuset:-0-7}
     setprop vendor.powerhal.init 1
 
+    # Setup scheduler parameters
+    write /proc/vendor_sched/min_granularity_ns 1000000
+    write /proc/vendor_sched/latency_ns 8000000
+    write /proc/vendor_sched/max_load_balance_interval 1
+    write /proc/vendor_sched/enable_hrtick 1
+
     # Setup final cpu.uclamp
     write /proc/vendor_sched/groups/ta/uclamp_min 1
     write /proc/vendor_sched/groups/fg/uclamp_min 0
@@ -909,39 +911,11 @@ on property:vendor.brownout.mitigation.ready=1
     write /sys/devices/virtual/pmic/mitigation/triggered_lvl/uvlo2_lvl 3000
     write /sys/devices/virtual/pmic/mitigation/triggered_lvl/soft_ocp_cpu2_lvl 12000
     write /sys/devices/virtual/pmic/mitigation/clock_div/tpu_clk_div 0x1
-    write /sys/devices/virtual/pmic/mitigation/clock_div/gpu_clk_div 0x1
+    write /sys/devices/virtual/pmic/mitigation/clock_div/gpu_clk_div 0x81 #mask VDROOP1
     write /sys/devices/virtual/pmic/mitigation/clock_div/cpu1_clk_div 0x381
     write /sys/devices/virtual/pmic/mitigation/clock_div/cpu2_clk_div 0x1
 
 on property:vendor.thermal.link_ready=1
-    # BCL
-    chown system system /dev/thermal/tz-by-name/soc/mode
-    chown system system /dev/thermal/tz-by-name/vdroop2/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/vdroop2/trip_point_0_hyst
-    chown system system /dev/thermal/tz-by-name/vdroop1/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/vdroop1/trip_point_0_hyst
-    chown system system /dev/thermal/tz-by-name/smpl_gm/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/smpl_gm/trip_point_0_hyst
-    chown system system /dev/thermal/tz-by-name/ocp_cpu1/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/ocp_cpu1/trip_point_0_hyst
-    chown system system /dev/thermal/tz-by-name/ocp_cpu2/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/ocp_cpu2/trip_point_0_hyst
-    chown system system /dev/thermal/tz-by-name/ocp_tpu/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/ocp_tpu/trip_point_0_hyst
-    chown system system /dev/thermal/tz-by-name/ocp_gpu/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/ocp_gpu/trip_point_0_hyst
-    chown system system /dev/thermal/tz-by-name/soft_ocp_cpu1/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/soft_ocp_cpu1/trip_point_0_hyst
-    chown system system /dev/thermal/tz-by-name/soft_ocp_cpu2/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/soft_ocp_cpu2/trip_point_0_hyst
-    chown system system /dev/thermal/tz-by-name/soft_ocp_tpu/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/soft_ocp_tpu/trip_point_0_hyst
-    chown system system /dev/thermal/tz-by-name/soft_ocp_gpu/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/soft_ocp_gpu/trip_point_0_hyst
-    chown system system /dev/thermal/tz-by-name/soc/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/soc/trip_point_0_hyst
-    chown system system /dev/thermal/tz-by-name/batoilo/trip_point_0_temp
-    chown system system /dev/thermal/tz-by-name/batoilo/trip_point_0_hyst
     # Thermal
     chown system system /dev/thermal/tz-by-name/skin_therm/trip_point_0_temp
     chown system system /dev/thermal/tz-by-name/skin_therm/trip_point_0_hyst
diff --git a/conf/init.gs201.usb.rc b/conf/init.gs201.usb.rc
index 9ba9eb8..7d017d3 100644
--- a/conf/init.gs201.usb.rc
+++ b/conf/init.gs201.usb.rc
@@ -417,3 +417,7 @@ on property:ro.bootmode=usbuwb
 
 on property:vendor.usb.contaminantdisable=true
     exec /vendor/bin/hw/disable_contaminant_detection.sh
+
+# WAR for kernel 5.10 with CONFIG_USB_DUMMY_HCD enabled
+on property:sys.usb.controller=dummy_udc.0
+    setprop sys.usb.controller "11210000.dwc3"
diff --git a/conf/init.modem.rc b/conf/init.modem.rc
index 6c89e3b..861f0a1 100644
--- a/conf/init.modem.rc
+++ b/conf/init.modem.rc
@@ -11,7 +11,7 @@ on post-fs-data
     mkdir /data/vendor/slog 0771 system system
 
     # Modem extended log folder
-    mkdir /data/vendor/radio/extended_logs 0770 radio system
+    mkdir /data/vendor/radio/extended_logs 0771 radio system
 
     # Modem MDS log folder
     mkdir /data/vendor/radio/mds 0771 radio system
diff --git a/default-permissions.xml b/default-permissions.xml
index ecdbaf0..afe5bc4 100644
--- a/default-permissions.xml
+++ b/default-permissions.xml
@@ -178,5 +178,12 @@
         <!-- Notifications -->
         <permission name="android.permission.POST_NOTIFICATIONS" fixed="false"/>
     </exception>
+
+    <exception package="com.google.android.apps.pixel.relationships">
+        <!-- Contacts -->
+        <permission name="android.permission.READ_CALL_LOG" fixed="false"/>
+        <permission name="android.permission.READ_CONTACTS" fixed="false"/>
+        <permission name="android.permission.WRITE_CONTACTS" fixed="false"/>
+    </exception>
 </exceptions>
 
diff --git a/device.mk b/device.mk
index 38add23..95b4fc2 100644
--- a/device.mk
+++ b/device.mk
@@ -76,7 +76,6 @@ PRODUCT_SOONG_NAMESPACES += \
 	vendor/google_devices/common/chre/host/hal \
 	vendor/google/whitechapel/tools \
 	vendor/google/interfaces \
-	vendor/google_devices/common/proprietary/confirmatioui_hal \
 	vendor/google_nos/host/android \
 	vendor/google_nos/test/system-test-harness \
 	vendor/google/camera
@@ -212,6 +211,7 @@ USE_LASSEN_OEMHOOK := true
 # $(USE_LASSEN_OEMHOOK) is true and $(BOARD_WITHOUT_RADIO) is not true.
 ifneq ($(BOARD_WITHOUT_RADIO),true)
     PRODUCT_SOONG_NAMESPACES += vendor/google/tools/power-anomaly-sitril
+    $(call soong_config_set,sitril,use_lassen_oemhook_with_radio,true)
 endif
 
 # Use for GRIL
@@ -253,15 +253,23 @@ PRODUCT_PACKAGES += \
 	csffw_image_prebuilt__firmware_prebuilt_todx_mali_csffw.bin \
 	libGLES_mali \
 	vulkan.mali \
-	libOpenCL \
 	libgpudataproducer \
 
+# Install the OpenCL ICD Loader
+PRODUCT_SOONG_NAMESPACES += external/OpenCL-ICD-Loader
+PRODUCT_PACKAGES += \
+       libOpenCL \
+       mali_icd__customer_pixel_opencl-icd_ARM.icd
+ifeq ($(DEVICE_IS_64BIT_ONLY),false)
+PRODUCT_PACKAGES += \
+	mali_icd__customer_pixel_opencl-icd_ARM32.icd
+endif
+
 # Mali Configuration Properties
-# b/221255664 prevents setting PROTECTED_MAX_CORE_COUNT=2
 PRODUCT_VENDOR_PROPERTIES += \
 	vendor.mali.platform.config=/vendor/etc/mali/platform.config \
 	vendor.mali.debug.config=/vendor/etc/mali/debug.config \
-	vendor.mali.base_protected_max_core_count=1 \
+	vendor.mali.base_protected_max_core_count=4 \
 	vendor.mali.base_protected_tls_max=67108864 \
 	vendor.mali.platform_agt_frequency_khz=24576
 
@@ -308,6 +316,7 @@ PRODUCT_VENDOR_PROPERTIES += ro.surface_flinger.prime_shader_cache.ultrahdr=1
 DEVICE_MANIFEST_FILE := \
 	device/google/gs201/manifest.xml
 
+BOARD_USE_CODEC2_AIDL := V1
 ifneq (,$(filter aosp_%,$(TARGET_PRODUCT)))
 DEVICE_MANIFEST_FILE += \
 	device/google/gs201/manifest_media_aosp.xml
@@ -347,6 +356,14 @@ PRODUCT_COPY_FILES += \
 PRODUCT_COPY_FILES += \
 	device/google/gs201/conf/init.gs201.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.gs201.rc
 
+ifneq (,$(filter 5.%, $(TARGET_LINUX_KERNEL_VERSION)))
+PRODUCT_COPY_FILES += \
+	device/google/gs201/storage/5.10/init.gs201.storage.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.gs201.storage.rc
+else
+PRODUCT_COPY_FILES += \
+	device/google/gs201/storage/6.1/init.gs201.storage.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.gs201.storage.rc
+endif
+
 ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
 PRODUCT_COPY_FILES += \
 	device/google/gs201/conf/init.debug.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/init.debug.rc \
@@ -378,9 +395,6 @@ include device/google/gs-common/insmod/insmod.mk
 PRODUCT_HOST_PACKAGES += \
 	mkdtimg
 
-PRODUCT_PACKAGES += \
-	messaging
-
 # CHRE
 ## tools
 ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
@@ -763,12 +777,19 @@ PRODUCT_COPY_FILES += \
 	device/google/gs201/media_codecs_performance_c2.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_performance_c2.xml \
 
 PRODUCT_PROPERTY_OVERRIDES += \
-       debug.stagefright.c2-poolmask=458752 \
        debug.c2.use_dmabufheaps=1 \
        media.c2.dmabuf.padding=512 \
        debug.stagefright.ccodec_delayed_params=1 \
        ro.vendor.gpu.dataspace=1
 
+ifneq ($(BOARD_USE_CODEC2_AIDL), )
+PRODUCT_PROPERTY_OVERRIDES += \
+        debug.stagefright.c2-poolmask=1507328
+else
+PRODUCT_PROPERTY_OVERRIDES += \
+        debug.stagefright.c2-poolmask=458752
+endif
+
 # Create input surface on the framework side
 PRODUCT_PROPERTY_OVERRIDES += \
 	debug.stagefright.c2inputsurface=-1 \
@@ -817,8 +838,6 @@ PRODUCT_PACKAGES_DEBUG += \
    trusty_stats_test \
    trusty-coverage-controller \
 
-include device/google/gs101/confirmationui/confirmationui.mk
-
 # Trusty Secure DPU Daemon
 PRODUCT_PACKAGES += \
 	securedpud.slider
@@ -1138,7 +1157,7 @@ include hardware/google/pixel/wifi_ext/device.mk
 
 # Battery Stats Viewer
 PRODUCT_PACKAGES_DEBUG += BatteryStatsViewer
-PRODUCT_PACKAGES += dump_power_gs201.sh
+include device/google/gs201/dumpstate/item.mk
 
 # Install product specific framework compatibility matrix
 # (TODO: b/169535506) This includes the FCM for system_ext and product partition.
diff --git a/device_framework_matrix_product.xml b/device_framework_matrix_product.xml
index 772c5e5..02d92bc 100644
--- a/device_framework_matrix_product.xml
+++ b/device_framework_matrix_product.xml
@@ -78,7 +78,7 @@
     </hal>
     <hal format="aidl" optional="true">
       <name>com.google.hardware.pixel.display</name>
-        <version>12</version>
+        <version>13</version>
         <interface>
             <name>IDisplay</name>
             <instance>default</instance>
diff --git a/dumpstate/Android.bp b/dumpstate/Android.bp
index a325151..6f59dc6 100644
--- a/dumpstate/Android.bp
+++ b/dumpstate/Android.bp
@@ -2,9 +2,19 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-sh_binary {
-    name: "dump_power_gs201.sh",
-    src: "dump_power_gs201.sh",
+cc_binary {
+    name: "dump_power",
+    srcs: ["dump_power.cpp"],
+    cflags: [
+        "-Wall",
+	"-Wextra",
+	"-Werror",
+    ],
+    shared_libs: [
+        "libbase",
+        "libdump",
+        "libdumpstateutil",
+    ],
     vendor: true,
-    sub_dir: "dump",
-}
+    relative_install_path: "dump",
+}
\ No newline at end of file
diff --git a/dumpstate/dump_power.cpp b/dumpstate/dump_power.cpp
new file mode 100644
index 0000000..adb6c9b
--- /dev/null
+++ b/dumpstate/dump_power.cpp
@@ -0,0 +1,673 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+#include <cstring>
+#include <dirent.h>
+#include <dump/pixel_dump.h>
+#include <fstream>
+#include <stdio.h>
+#include <stdlib.h>
+#include <sys/sysinfo.h>
+#include <time.h>
+#include <vector>
+#include <android-base/file.h>
+#include <android-base/strings.h>
+#include "DumpstateUtil.h"
+void printTitle(const char *msg) {
+    printf("\n------ %s ------\n", msg);
+}
+int getCommandOutput(const char *cmd, std::string *output) {
+    char buffer[1024];
+    FILE *pipe = popen(cmd, "r");
+    if (!pipe) {
+        return -1;
+    }
+    while (fgets(buffer, sizeof buffer, pipe) != NULL) {
+        *output += buffer;
+    }
+    pclose(pipe);
+    if (output->back() == '\n')
+        output->pop_back();
+    return 0;
+}
+bool isValidFile(const char *file) {
+    if (!access(file, R_OK)) {
+        return false;
+    }
+    return true;
+}
+bool isUserBuild() {
+    return ::android::os::dumpstate::PropertiesHelper::IsUserBuild();
+}
+int getFilesInDir(const char *directory, std::vector<std::string> *files) {
+    std::string content;
+    struct dirent *entry;
+    DIR *dir = opendir(directory);
+    if (dir == NULL)
+        return -1;
+    files->clear();
+    while ((entry = readdir(dir)) != NULL)
+        files->push_back(entry->d_name);
+    closedir(dir);
+    sort(files->begin(), files->end());
+    return 0;
+}
+void dumpPowerStatsTimes() {
+    const char *title = "Power Stats Times";
+    char rBuff[128];
+    struct timespec rTs;
+    struct sysinfo info;
+    int ret;
+    printTitle(title);
+    sysinfo(&info);
+    const time_t boottime = time(NULL) - info.uptime;
+    ret = clock_gettime(CLOCK_REALTIME, &rTs);
+    if (ret)
+        return;
+    struct tm *nowTime = std::localtime(&rTs.tv_sec);
+    std::strftime(rBuff, sizeof(rBuff), "%m/%d/%Y %H:%M:%S", nowTime);
+    printf("Boot: %s", ctime(&boottime));
+    printf("Now: %s\n", rBuff);
+}
+int readContentsOfDir(const char* title, const char* directory, const char* strMatch,
+        bool useStrMatch = false, bool printDirectory = false) {
+    std::vector<std::string> files;
+    std::string content;
+    std::string fileLocation;
+    int ret;
+    ret = getFilesInDir(directory, &files);
+    if (ret < 0)
+        return ret;
+    printTitle(title);
+    for (auto &file : files) {
+        if (useStrMatch && std::string::npos == std::string(file).find(strMatch)) {
+            continue;
+        }
+        fileLocation = std::string(directory) + std::string(file);
+        if (!android::base::ReadFileToString(fileLocation, &content)) {
+            continue;
+        }
+        if (printDirectory) {
+            printf("\n\n%s\n", fileLocation.c_str());
+        }
+        if (content.back() == '\n')
+            content.pop_back();
+        printf("%s\n", content.c_str());
+    }
+    return 0;
+}
+void dumpAcpmStats() {
+    const char* acpmDir = "/sys/devices/platform/acpm_stats/";
+    const char* statsSubStr = "_stats";
+    const char* acpmTitle = "ACPM stats";
+    readContentsOfDir(acpmTitle, acpmDir, statsSubStr, true, true);
+}
+void dumpPowerSupplyStats() {
+    const char* dumpList[][2] = {
+            {"CPU PM stats", "/sys/devices/system/cpu/cpupm/cpupm/time_in_state"},
+            {"Power supply property battery", "/sys/class/power_supply/battery/uevent"},
+            {"Power supply property dc", "/sys/class/power_supply/dc/uevent"},
+            {"Power supply property gcpm", "/sys/class/power_supply/gcpm/uevent"},
+            {"Power supply property gcpm_pps", "/sys/class/power_supply/gcpm_pps/uevent"},
+            {"Power supply property main-charger", "/sys/class/power_supply/main-charger/uevent"},
+            {"Power supply property dc-mains", "/sys/class/power_supply/dc-mains/uevent"},
+            {"Power supply property tcpm", "/sys/class/power_supply/tcpm-source-psy-8-0025/uevent"},
+            {"Power supply property usb", "/sys/class/power_supply/usb/uevent"},
+            {"Power supply property wireless", "/sys/class/power_supply/wireless/uevent"},
+    };
+    for (const auto &row : dumpList) {
+        dumpFileContent(row[0], row[1]);
+    }
+}
+void dumpMaxFg() {
+    const char *maxfgLoc = "/sys/class/power_supply/maxfg";
+    const char *maxfg [][2] = {
+            {"Power supply property maxfg", "/sys/class/power_supply/maxfg/uevent"},
+            {"m5_state", "/sys/class/power_supply/maxfg/m5_model_state"},
+            {"maxfg", "/dev/logbuffer_maxfg"},
+            {"maxfg", "/dev/logbuffer_maxfg_monitor"},
+    };
+    const char *maxfgFlip [][2] = {
+            {"Power supply property maxfg_base", "/sys/class/power_supply/maxfg_base/uevent"},
+            {"Power supply property maxfg_flip", "/sys/class/power_supply/maxfg_flip/uevent"},
+            {"m5_state", "/sys/class/power_supply/maxfg_base/m5_model_state"},
+            {"maxfg_base", "/dev/logbuffer_maxfg_base"},
+            {"maxfg_flip", "/dev/logbuffer_maxfg_flip"},
+            {"maxfg_base", "/dev/logbuffer_maxfg_base_monitor"},
+            {"maxfg_flip", "/dev/logbuffer_maxfg_flip_monitor"},
+    };
+    const char *maxfgHistoryName = "Maxim FG History";
+    const char *maxfgHistoryDir = "/dev/maxfg_history";
+    std::string content;
+    if (isValidFile(maxfgLoc)) {
+        for (const auto &row : maxfg) {
+            dumpFileContent(row[0], row[1]);
+        }
+    } else {
+        for (const auto &row : maxfgFlip) {
+            dumpFileContent(row[0], row[1]);
+        }
+    }
+    if (isValidFile(maxfgHistoryDir)) {
+        dumpFileContent(maxfgHistoryName, maxfgHistoryDir);
+    }
+}
+void dumpPowerSupplyDock() {
+    const char* powerSupplyPropertyDockTitle = "Power supply property dock";
+    const char* powerSupplyPropertyDockFile = "/sys/class/power_supply/dock/uevent";
+    dumpFileContent(powerSupplyPropertyDockTitle, powerSupplyPropertyDockFile);
+}
+void dumpLogBufferTcpm() {
+    const char* logbufferTcpmTitle = "Logbuffer TCPM";
+    const char* logbufferTcpmFile = "/dev/logbuffer_tcpm";
+    const char* debugTcpmFile = "/sys/kernel/debug/tcpm";
+    const char* tcpmLogTitle = "TCPM logs";
+    const char* tcpmFile = "/sys/kernel/debug/tcpm";
+    const char* tcpmFileAlt = "/sys/kernel/debug/usb/tcpm";
+    int retCode;
+    dumpFileContent(logbufferTcpmTitle, logbufferTcpmFile);
+    retCode = readContentsOfDir(tcpmLogTitle, isValidFile(debugTcpmFile) ? tcpmFile : tcpmFileAlt,
+            NULL);
+    if (retCode < 0)
+        printTitle(tcpmLogTitle);
+}
+void dumpTcpc() {
+    int ret;
+    const char* max77759TcpcHead = "TCPC";
+    const char* i2cSubDirMatch = "i2c-";
+    const char* directory = "/sys/devices/platform/10d60000.hsi2c/";
+    const char* max77759Tcpc [][2] {
+            {"registers:", "/i2c-max77759tcpc/registers"},
+            {"frs:", "/i2c-max77759tcpc/frs"},
+            {"auto_discharge:", "/i2c-max77759tcpc/auto_discharge"},
+            {"bcl2_enabled:", "/i2c-max77759tcpc/bcl2_enabled"},
+            {"cc_toggle_enable:", "/i2c-max77759tcpc/cc_toggle_enable"},
+            {"containment_detection:", "/i2c-max77759tcpc/containment_detection"},
+            {"containment_detection_status:", "/i2c-max77759tcpc/containment_detection_status"},
+    };
+    std::vector<std::string> files;
+    std::string content;
+    printTitle(max77759TcpcHead);
+    ret = getFilesInDir(directory, &files);
+    if (ret < 0) {
+        for (auto &tcpcVal : max77759Tcpc)
+            printf("%s\n", tcpcVal[0]);
+        return;
+    }
+    for (auto &file : files) {
+        for (auto &tcpcVal : max77759Tcpc) {
+            printf("%s ", tcpcVal[0]);
+            if (std::string::npos == std::string(file).find(i2cSubDirMatch)) {
+                continue;
+            }
+            std::string fileName = directory + file + "/" + std::string(tcpcVal[1]);
+            if (!android::base::ReadFileToString(fileName, &content)) {
+                continue;
+            }
+            printf("%s\n", content.c_str());
+        }
+    }
+}
+void dumpPdEngine() {
+    const char* pdEngine [][2] {
+            {"PD Engine", "/dev/logbuffer_usbpd"},
+            {"PPS-google_cpm", "/dev/logbuffer_cpm"},
+            {"PPS-dc", "/dev/logbuffer_pca9468"},
+    };
+    for (const auto &row : pdEngine) {
+        dumpFileContent(row[0], row[1]);
+    }
+}
+void dumpWc68() {
+    const char* wc68Title = "WC68";
+    const char* wc68File = "/dev/logbuffer_wc68";
+    dumpFileContent(wc68Title, wc68File);
+}
+void dumpLn8411() {
+    const char* ln8411Title = "LN8411";
+    const char* ln8411File = "/dev/logbuffer_ln8411";
+    dumpFileContent(ln8411Title, ln8411File);
+}
+void dumpBatteryHealth() {
+    const char* batteryHealth [][2] {
+            {"Battery Health", "/sys/class/power_supply/battery/health_index_stats"},
+            {"BMS", "/dev/logbuffer_ssoc"},
+            {"TTF", "/dev/logbuffer_ttf"},
+            {"TTF details", "/sys/class/power_supply/battery/ttf_details"},
+            {"TTF stats", "/sys/class/power_supply/battery/ttf_stats"},
+            {"aacr_state", "/sys/class/power_supply/battery/aacr_state"},
+            {"maxq", "/dev/logbuffer_maxq"},
+            {"TEMP/DOCK-DEFEND", "/dev/logbuffer_bd"},
+    };
+    for (const auto &row : batteryHealth) {
+        dumpFileContent(row[0], row[1]);
+    }
+}
+void dumpBatteryDefend() {
+    const char* defendConfig [][3] {
+            {"TRICKLE-DEFEND Config",
+                    "/sys/devices/platform/google,battery/power_supply/battery/", "bd_"},
+            {"DWELL-DEFEND Config", "/sys/devices/platform/google,charger/", "charge_s"},
+            {"TEMP-DEFEND Config", "/sys/devices/platform/google,charger/", "bd_"},
+    };
+    std::vector<std::string> files;
+    struct dirent *entry;
+    std::string content;
+    std::string fileLocation;
+    for (auto &config : defendConfig) {
+        DIR *dir = opendir(config[1]);
+        if (dir == NULL)
+            continue;
+        printTitle(config[0]);
+        while ((entry = readdir(dir)) != NULL) {
+            if (std::string(entry->d_name).find(config[2]) != std::string::npos &&
+                    strncmp(config[2], entry->d_name, strlen(config[2])) == 0) {
+                files.push_back(entry->d_name);
+            }
+        }
+        closedir(dir);
+        sort(files.begin(), files.end());
+        for (auto &file : files) {
+            fileLocation = std::string(config[1]) + std::string(file);
+            if (!android::base::ReadFileToString(fileLocation, &content)) {
+                content = "\n";
+            }
+            printf("%s: %s", file.c_str(), content.c_str());
+            if (content.back() != '\n')
+                printf("\n");
+        }
+        files.clear();
+    }
+}
+void dumpBatteryEeprom() {
+    const char *title = "Battery EEPROM";
+    const char *files[] {
+            "/sys/devices/platform/10970000.hsi2c/i2c-4/4-0050/eeprom",
+            "/sys/devices/platform/10970000.hsi2c/i2c-5/5-0050/eeprom",
+            "/sys/devices/platform/10da0000.hsi2c/i2c-6/6-0050/eeprom",
+            "/sys/devices/platform/10da0000.hsi2c/i2c-7/7-0050/eeprom",
+            "/sys/devices/platform/10c90000.hsi2c/i2c-7/7-0050/eeprom",
+            "/sys/devices/platform/10c90000.hsi2c/i2c-6/6-0050/eeprom",
+    };
+    std::string result;
+    std::string xxdCmd;
+    printTitle(title);
+    for (auto &file : files) {
+        if (!isValidFile(file))
+            continue;
+        xxdCmd = "xxd " + std::string(file);
+        int ret = getCommandOutput(xxdCmd.c_str(), &result);
+        if (ret < 0)
+            return;
+        printf("%s\n", result.c_str());
+    }
+}
+void dumpChargerStats() {
+    const char *chgStatsTitle = "Charger Stats";
+    const char *chgStatsLocation = "/sys/class/power_supply/battery/charge_details";
+    const char *chargerStats [][3] {
+            {"Google Charger", "/sys/kernel/debug/google_charger/", "pps_"},
+            {"Google Battery", "/sys/kernel/debug/google_battery/", "ssoc_"},
+    };
+    std::vector<std::string> files;
+    std::string content;
+    struct dirent *entry;
+    dumpFileContent(chgStatsTitle, chgStatsLocation);
+    if (!isUserBuild())
+        return;
+    for (auto &stat : chargerStats) {
+        DIR *dir = opendir(stat[1]);
+        if (dir == NULL)
+            return;
+        printTitle(stat[0]);
+        while ((entry = readdir(dir)) != NULL)
+            if (std::string(entry->d_name).find(stat[2]) != std::string::npos)
+                files.push_back(entry->d_name);
+        closedir(dir);
+        sort(files.begin(), files.end());
+        for (auto &file : files) {
+            std::string fileLocation = std::string(stat[1]) + file;
+            if (!android::base::ReadFileToString(fileLocation, &content)) {
+                content = "\n";
+            }
+            printf("%s: %s", file.c_str(), content.c_str());
+            if (content.back() != '\n')
+                printf("\n");
+        }
+        files.clear();
+    }
+}
+void dumpWlcLogs() {
+    const char *dumpWlcList [][2] {
+            {"WLC Logs", "/dev/logbuffer_wireless"},
+            {"WLC VER", "/sys/class/power_supply/wireless/device/version"},
+            {"WLC STATUS", "/sys/class/power_supply/wireless/device/status"},
+            {"WLC FW Version", "/sys/class/power_supply/wireless/device/fw_rev"},
+            {"RTX", "/dev/logbuffer_rtx"},
+    };
+    for (auto &row : dumpWlcList) {
+        if (!isValidFile(row[1]))
+            printTitle(row[0]);
+        dumpFileContent(row[0], row[1]);
+    }
+}
+void dumpGvoteables() {
+    const char *directory = "/sys/kernel/debug/gvotables/";
+    const char *statusName = "/status";
+    const char *title = "gvotables";
+    std::string content;
+    std::vector<std::string> files;
+    int ret;
+    if (!isUserBuild())
+        return;
+    ret = getFilesInDir(directory, &files);
+    if (ret < 0)
+        return;
+    printTitle(title);
+    for (auto &file : files) {
+        std::string fileLocation = std::string(directory) + file + std::string(statusName);
+        if (!android::base::ReadFileToString(fileLocation, &content)) {
+            continue;
+        }
+        printf("%s: %s", file.c_str(), content.c_str());
+        if (content.back() != '\n')
+            printf("\n");
+    }
+    files.clear();
+}
+void dumpMitigation() {
+    const char *mitigationList [][2] {
+            {"Lastmeal" , "/data/vendor/mitigation/lastmeal.txt"},
+            {"Thismeal" , "/data/vendor/mitigation/thismeal.txt"},
+    };
+    for (auto &row : mitigationList) {
+        if (!isValidFile(row[1]))
+            printTitle(row[0]);
+        dumpFileContent(row[0], row[1]);
+    }
+}
+void dumpMitigationStats() {
+    int ret;
+    const char *directory = "/sys/devices/virtual/pmic/mitigation/last_triggered_count/";
+    const char *capacityDirectory = "/sys/devices/virtual/pmic/mitigation/last_triggered_capacity/";
+    const char *timestampDirectory =
+            "/sys/devices/virtual/pmic/mitigation/last_triggered_timestamp/";
+    const char *voltageDirectory = "/sys/devices/virtual/pmic/mitigation/last_triggered_voltage/";
+    const char *capacitySuffix = "_cap";
+    const char *timeSuffix = "_time";
+    const char *voltageSuffix = "_volt";
+    const char *countSuffix = "_count";
+    const char *title = "Mitigation Stats";
+    std::vector<std::string> files;
+    std::string content;
+    std::string fileLocation;
+    std::string source;
+    std::string subModuleName;
+    int count;
+    int soc;
+    int time;
+    int voltage;
+    ret = getFilesInDir(directory, &files);
+    if (ret < 0)
+        return;
+    printTitle(title);
+    printf("Source\t\tCount\tSOC\tTime\tVoltage\n");
+    for (auto &file : files) {
+        fileLocation = std::string(directory) + std::string(file);
+        if (!android::base::ReadFileToString(fileLocation, &content)) {
+            continue;
+        }
+        ret = atoi(android::base::Trim(content).c_str());
+        if (ret == -1)
+            continue;
+        count = ret;
+        subModuleName = std::string(file);
+        subModuleName.erase(subModuleName.find(countSuffix), strlen(countSuffix));
+        fileLocation = std::string(capacityDirectory) + std::string(subModuleName) +
+                std::string(capacitySuffix);
+        if (!android::base::ReadFileToString(fileLocation, &content)) {
+            continue;
+        }
+        ret = atoi(android::base::Trim(content).c_str());
+        if (ret == -1)
+            continue;
+        soc = ret;
+        fileLocation = std::string(timestampDirectory) + std::string(subModuleName) +
+                std::string(timeSuffix);
+        if (!android::base::ReadFileToString(fileLocation, &content)) {
+            continue;
+        }
+        ret = atoi(android::base::Trim(content).c_str());
+        if (ret == -1)
+            continue;
+        time = ret;
+        fileLocation = std::string(voltageDirectory) + std::string(subModuleName) +
+                std::string(voltageSuffix);
+        if (!android::base::ReadFileToString(fileLocation, &content)) {
+            continue;
+        }
+        ret = atoi(android::base::Trim(content).c_str());
+        if (ret == -1)
+            continue;
+        voltage = ret;
+        printf("%s \t%i\t%i\t%i\t%i\n", subModuleName.c_str(), count, soc, time, voltage);
+    }
+}
+void dumpMitigationDirs() {
+    const int paramCount = 4;
+    const char *titles[] = {
+            "Clock Divider Ratio",
+            "Clock Stats",
+            "Triggered Level",
+            "Instruction",
+    };
+    const char *directories[] = {
+            "/sys/devices/virtual/pmic/mitigation/clock_ratio/",
+            "/sys/devices/virtual/pmic/mitigation/clock_stats/",
+            "/sys/devices/virtual/pmic/mitigation/triggered_lvl/",
+            "/sys/devices/virtual/pmic/mitigation/instruction/",
+    };
+    const char *paramSuffix[] = {"_ratio", "_stats", "_lvl", ""};
+    const char *titleRowVal[] = {
+            "Source\t\tRatio",
+            "Source\t\tStats",
+            "Source\t\tLevel",
+            "",
+    };
+    const int eraseCnt[] = {6, 6, 4, 0};
+    const bool useTitleRow[] = {true, true, true, false};
+    std::vector<std::string> files;
+    std::string content;
+    std::string fileLocation;
+    std::string source;
+    std::string subModuleName;
+    std::string readout;
+    for (int i = 0; i < paramCount; i++) {
+        printTitle(titles[i]);
+        if (useTitleRow[i]) {
+            printf("%s\n", titleRowVal[i]);
+        }
+        getFilesInDir(directories[i], &files);
+        for (auto &file : files) {
+            fileLocation = std::string(directories[i]) + std::string(file);
+            if (!android::base::ReadFileToString(fileLocation, &content)) {
+                continue;
+            }
+            readout = android::base::Trim(content);
+            subModuleName = std::string(file);
+            subModuleName.erase(subModuleName.find(paramSuffix[i]), eraseCnt[i]);
+            if (useTitleRow[i]) {
+                printf("%s \t%s\n", subModuleName.c_str(), readout.c_str());
+            } else {
+                printf("%s=%s\n", subModuleName.c_str(), readout.c_str());
+            }
+        }
+    }
+}
+void dumpIrqDurationCounts() {
+    const char *title = "IRQ Duration Counts";
+    const char *colNames = "Source\t\t\t\tlt_5ms_cnt\tbt_5ms_to_10ms_cnt\tgt_10ms_cnt\tCode"
+            "\tCurrent Threshold (uA)\tCurrent Reading (uA)\n";
+    const int nonOdpmChannelCnt = 9;
+    const int odpmChCnt = 12;
+    enum Duration {
+        LT_5MS,
+        BT_5MS_10MS,
+        GT_10MS,
+        DUR_MAX,
+    };
+    const char *irqDurDirectories[] = {
+            "/sys/devices/virtual/pmic/mitigation/irq_dur_cnt/less_than_5ms_count",
+            "/sys/devices/virtual/pmic/mitigation/irq_dur_cnt/between_5ms_to_10ms_count",
+            "/sys/devices/virtual/pmic/mitigation/irq_dur_cnt/greater_than_10ms_count",
+    };
+    enum PowerWarn {
+        MAIN,
+        SUB,
+        PWRWARN_MAX,
+    };
+    const char *pwrwarnDirectories[] = {
+            "/sys/devices/virtual/pmic/mitigation/main_pwrwarn/",
+            "/sys/devices/virtual/pmic/mitigation/sub_pwrwarn/",
+    };
+    const char *lpfCurrentDirs[] = {
+            "/sys/devices/platform/acpm_mfd_bus@15500000/i2c-1/1-001f/s2mpg14-meter/"
+                    "s2mpg14-odpm/iio:device1/lpf_current",
+            "/sys/devices/platform/acpm_mfd_bus@15510000/i2c-0/0-002f/s2mpg15-meter/"
+                    "s2mpg15-odpm/iio:device0/lpf_current",
+    };
+    bool titlesInitialized = false;
+    std::vector<std::string> channelNames;
+    std::vector<std::string> channelData[DUR_MAX];
+    std::vector<std::string> pwrwarnThreshold[PWRWARN_MAX];
+    std::vector<std::string> pwrwarnCode[PWRWARN_MAX];
+    std::vector<std::string> lpfCurrentVals[PWRWARN_MAX];
+    std::vector<std::string> files;
+    std::string content;
+    std::string token;
+    std::string tokenCh;
+    std::string fileLocation;
+    for (int i = 0; i < DUR_MAX; i++) {
+        if (!android::base::ReadFileToString(irqDurDirectories[i], &content)) {
+            return;
+        }
+        std::istringstream tokenStream(content);
+        while (std::getline(tokenStream, token, '\n')) {
+            if (!titlesInitialized) {
+                tokenCh = token;
+                tokenCh.erase(tokenCh.find(':'), tokenCh.length());
+                channelNames.push_back(tokenCh);
+            }
+            // there is a space after the ':' which needs to be removed
+            token.erase(0, token.find(':') + 1);
+            channelData[i].push_back(token);
+        }
+        if (!titlesInitialized)
+            titlesInitialized = true;
+    }
+    for (int i = 0; i < PWRWARN_MAX; i++) {
+        getFilesInDir(pwrwarnDirectories[i], &files);
+        for (auto &file : files) {
+            fileLocation = std::string(pwrwarnDirectories[i]) + std::string(file);
+            if (!android::base::ReadFileToString(fileLocation, &content)) {
+                continue;
+            }
+            std::string readout;
+            readout = android::base::Trim(content);
+            std::string readoutThreshold = readout;
+            readoutThreshold.erase(0, readoutThreshold.find('=') + 1);
+            std::string readoutCode = readout;
+            readoutCode.erase(readoutCode.find('='), readoutCode.length());
+            pwrwarnThreshold[i].push_back(readoutThreshold);
+            pwrwarnCode[i].push_back(readoutCode);
+        }
+    }
+    for (int i = 0; i < PWRWARN_MAX; i++) {
+        if (!android::base::ReadFileToString(lpfCurrentDirs[i], &content)) {
+            continue;
+        }
+        std::istringstream tokenStream(content);
+        bool first = true;
+        while (std::getline(tokenStream, token, '\n')) {
+            token.erase(0, token.find(' '));
+            if (first) {
+                first = false;
+                continue;
+            }
+            lpfCurrentVals[i].push_back(token);
+        }
+    }
+    printTitle(title);
+    printf("%s", colNames);
+    for (uint i = 0; i < channelNames.size(); i++) {
+        std::string code = "";
+        std::string threshold = "";
+        std::string current = "";
+        std::string ltDataMsg = "";
+        std::string btDataMsg = "";
+        std::string gtDataMsg = "";
+        int pmicSel = 0;
+        int offset = 0;
+        std::string channelNameSuffix = "      \t";
+        if (i >= nonOdpmChannelCnt) {
+            offset = nonOdpmChannelCnt;
+            if (i >= (odpmChCnt + nonOdpmChannelCnt)) {
+                pmicSel = 1;
+                offset = odpmChCnt + nonOdpmChannelCnt;
+            }
+            channelNameSuffix = "";
+            code = pwrwarnCode[pmicSel][i - offset];
+            threshold = pwrwarnThreshold[pmicSel][i - offset];
+            current = lpfCurrentVals[pmicSel][i - offset];
+        }
+        if (i < channelData[0].size())
+            ltDataMsg = channelData[0][i];
+        if (i < channelData[1].size())
+            btDataMsg = channelData[1][i];
+        if (i < channelData[2].size())
+            gtDataMsg = channelData[2][i];
+        std::string adjustedChannelName = channelNames[i] + channelNameSuffix;
+        printf("%s     \t%s\t\t%s\t\t\t%s\t\t%s    \t%s       \t\t%s\n",
+                adjustedChannelName.c_str(),
+                ltDataMsg.c_str(),
+                btDataMsg.c_str(),
+                gtDataMsg.c_str(),
+                code.c_str(),
+                threshold.c_str(),
+                current.c_str());
+    }
+}
+int main() {
+    dumpPowerStatsTimes();
+    dumpAcpmStats();
+    dumpPowerSupplyStats();
+    dumpMaxFg();
+    dumpPowerSupplyDock();
+    dumpLogBufferTcpm();
+    dumpTcpc();
+    dumpPdEngine();
+    dumpWc68();
+    dumpLn8411();
+    dumpBatteryHealth();
+    dumpBatteryDefend();
+    dumpBatteryEeprom();
+    dumpChargerStats();
+    dumpWlcLogs();
+    dumpGvoteables();
+    dumpMitigation();
+    dumpMitigationStats();
+    dumpMitigationDirs();
+    dumpIrqDurationCounts();
+}
diff --git a/dumpstate/dump_power_gs201.sh b/dumpstate/dump_power_gs201.sh
deleted file mode 100644
index 64d7556..0000000
--- a/dumpstate/dump_power_gs201.sh
+++ /dev/null
@@ -1,315 +0,0 @@
-#!/vendor/bin/sh
-build_type="$(getprop ro.build.type)"
-
-echo "\n------ Power Stats Times ------"
-echo -n "Boot: " && /vendor/bin/uptime -s && echo -n "Now: " && date;
-
-echo "\n------ ACPM stats ------"
-for f in /sys/devices/platform/acpm_stats/*_stats ; do
-  echo "\n\n$f"
-  cat $f
-done
-
-echo "\n------ CPU PM stats ------"
-cat "/sys/devices/system/cpu/cpupm/cpupm/time_in_state"
-
-echo "\n------ GENPD summary ------"
-cat "/d/pm_genpd/pm_genpd_summary"
-
-echo "\n------ Power supply property battery ------"
-cat "/sys/class/power_supply/battery/uevent"
-echo "\n------ Power supply property dc ------"
-cat "/sys/class/power_supply/dc/uevent"
-echo "\n------ Power supply property gcpm ------"
-cat "/sys/class/power_supply/gcpm/uevent"
-echo "\n------ Power supply property gcpm_pps ------"
-cat "/sys/class/power_supply/gcpm_pps/uevent"
-echo "\n------ Power supply property main-charger ------"
-cat "/sys/class/power_supply/main-charger/uevent"
-
-if [ -d "/sys/class/power_supply/pca9468-mains/uevent" ]
-then
-  echo "\n------ Power supply property pca9468-mains ------"
-  cat "/sys/class/power_supply/pca9468-mains/uevent"
-else
-  echo "\n------ Power supply property pca94xx-mains ------"
-  cat "/sys/class/power_supply/pca94xx-mains/uevent"
-fi
-
-echo "\n------ Power supply property tcpm ------"
-cat /sys/class/power_supply/tcpm-source-psy-*/uevent
-echo "\n------ Power supply property usb ------"
-cat "/sys/class/power_supply/usb/uevent"
-echo "\n------ Power supply property wireless ------"
-cat "/sys/class/power_supply/wireless/uevent"
-
-if [ -d "/sys/class/power_supply/maxfg" ]
-then
-  echo "\n------ Power supply property maxfg ------"
-  cat "/sys/class/power_supply/maxfg/uevent"
-  echo "\n------ m5_state ------"
-  cat "/sys/class/power_supply/maxfg/m5_model_state"
-  echo "\n------ maxfg ------"
-  cat "/dev/logbuffer_maxfg"
-  echo "\n------ maxfg_monitor ------"
-  cat "/dev/logbuffer_maxfg_monitor"
-else
-  echo "\n------ Power supply property maxfg_base ------"
-  cat "/sys/class/power_supply/maxfg_base/uevent"
-  echo "\n------ Power supply property maxfg_secondary ------"
-  cat "/sys/class/power_supply/maxfg_secondary/uevent"
-  echo "\n------ m5_state ------"
-  cat "/sys/class/power_supply/maxfg_base/m5_model_state"
-  echo "\n------ maxfg_base ------"
-  cat "/dev/logbuffer_maxfg_base"
-  echo "\n------ maxfg_secondary ------"
-  cat "/dev/logbuffer_maxfg_secondary"
-  echo "\n------ maxfg_base_monitor ------"
-  cat "/dev/logbuffer_maxfg_base_monitor"
-  echo "\n------ maxfg_secondary_monitor ------"
-  cat "/dev/logbuffer_maxfg_secondary_monitor"
-  echo "\n------ google_dual_batt ------"
-  cat "/dev/logbuffer_dual_batt"
-fi
-
-if [ -e "/dev/maxfg_history" ]
-then
-  echo "\n------ Maxim FG History ------"
-  xxd "/dev/maxfg_history"
-fi
-
-if [ -d "/sys/class/power_supply/dock" ]
-then
-  echo "\n------ Power supply property dock ------"
-  cat "/sys/class/power_supply/dock/uevent"
-fi
-
-if [ -e "/dev/logbuffer_tcpm" ]
-then
-  echo "\n------ Logbuffer TCPM ------"
-  cat "/dev/logbuffer_tcpm"
-elif [ $build_type = "userdebug" ]
-then
-  echo "\n------ TCPM logs ------"
-  if [ -d "/sys/kernel/debug/tcpm" ]
-  then
-    cat /sys/kernel/debug/tcpm/*
-  else
-    cat /sys/kernel/debug/usb/tcpm*
-  fi
-fi
-
-echo "\n------ TCPC ------"
-max77759tcpc_path="/sys/devices/platform/10d60000.hsi2c/i2c-13/13-0025"
-echo "registers:"
-cat $max77759tcpc_path/registers
-echo "frs:"
-cat $max77759tcpc_path/frs
-echo "auto_discharge:"
-cat $max77759tcpc_path/auto_discharge
-echo "bc12_enabled:"
-cat $max77759tcpc_path/bc12_enabled
-echo "cc_toggle_enable:"
-cat $max77759tcpc_path/cc_toggle_enable
-echo "contaminant_detection:"
-cat $max77759tcpc_path/contaminant_detection
-echo "contaminant_detection_status:"
-cat $max77759tcpc_path/contaminant_detection_status
-
-echo "\n------ PD Engine ------"
-cat "/dev/logbuffer_usbpd"
-echo "\nPOGO Transport"
-cat "/dev/logbuffer_pogo_transport"
-echo "\n------ PPS-google_cpm ------"
-cat "/dev/logbuffer_cpm"
-echo "\n------ PPS-dc ------"
-cat "/dev/logbuffer_pca9468"
-
-echo "\n------ Battery Health ------"
-cat "/sys/class/power_supply/battery/health_index_stats"
-echo "\n------ Battery Health SoC Residency ------"
-cat "/sys/class/power_supply/battery/swelling_data"
-echo "\n------ BMS ------"
-cat "/dev/logbuffer_ssoc"
-echo "\n------ TTF ------"
-cat "/dev/logbuffer_ttf"
-echo "\n------ TTF details ------"
-cat "/sys/class/power_supply/battery/ttf_details"
-echo "\n------ TTF stats ------"
-cat "/sys/class/power_supply/battery/ttf_stats"
-echo "\n------ aacr_state ------"
-cat "/sys/class/power_supply/battery/aacr_state"
-echo "\n------ maxq ------"
-cat "/dev/logbuffer_maxq"
-echo "\n------ TEMP/DOCK-DEFEND ------"
-cat "/dev/logbuffer_bd"
-
-echo "\n------ TRICKLE-DEFEND Config ------"
-cd /sys/devices/platform/google,battery/power_supply/battery/
-for f in `ls bd_*`
-do
-  echo $f: `cat $f`
-done
-
-echo "\n------ DWELL-DEFEND Config ------"
-cd /sys/devices/platform/google,charger/
-for f in `ls charge_s*`
-do
-  echo "$f: `cat $f`"
-done
-
-echo "\n------ TEMP-DEFEND Config ------"
-cd /sys/devices/platform/google,charger/
-for f in `ls bd_*`
-do
-  echo "$f: `cat $f`"
-done
-
-echo "\n------ DC_registers dump ------"
-cat "/sys/class/power_supply/pca94xx-mains/device/registers_dump"
-echo "\n------ max77759_chg registers dump ------"
-cat "/sys/class/power_supply/main-charger/device/registers_dump"
-echo "\n------ max77729_pmic registers dump ------"
-cat /sys/devices/platform/*.hsi2c/i2c-*/*-0066/registers_dump
-
-if [ $build_type = "userdebug" ]
-then
-  echo "\n------ Charging table dump ------"
-  cat "/d/google_battery/chg_raw_profile"
-
-  echo "\n------ fg_model ------"
-  for f in /d/maxfg*
-  do
-    regs=`cat $f/fg_model`
-    echo $f:
-    echo "$regs"
-  done
-
-  echo "\n------ fg_alo_ver ------"
-  for f in /d/maxfg*
-  do
-    regs=`cat $f/algo_ver`
-    echo $f:
-    echo "$regs"
-  done
-
-  echo "\n------ fg_model_ok ------"
-  for f in /d/maxfg*
-  do
-    regs=`cat $f/model_ok`
-    echo $f:
-    echo "$regs"
-  done
-
-  echo "\n------ fg registers ------"
-  for f in /d/maxfg*
-  do
-    regs=`cat $f/registers`
-    echo $f:
-    echo "$regs"
-  done
-
-  echo "\n------ Maxim FG NV RAM ------"
-  for f in /d/maxfg*
-  do
-    regs=`cat $f/nv_registers`
-    echo $f:
-    echo "$regs"
-  done
-fi
-
-echo "\n------ Battery EEPROM ------"
-if [ -e "/sys/devices/platform/10da0000.hsi2c/i2c-15/15-0050/eeprom" ]
-then
-  xxd /sys/devices/platform/10da0000.hsi2c/i2c-15/15-0050/eeprom
-fi
-
-echo "\n------ Charger Stats ------"
-cat "/sys/class/power_supply/battery/charge_details"
-if [ $build_type = "userdebug" ]
-then
-  echo "\n------ Google Charger ------"
-  cd /sys/kernel/debug/google_charger/
-  for f in `ls pps_*`
-  do
-    echo "$f: `cat $f`"
-  done
-  echo "\n------ Google Battery ------"
-  cd /sys/kernel/debug/google_battery/
-  for f in `ls ssoc_*`
-  do
-    echo "$f: `cat $f`"
-  done
-fi
-
-echo "\n------ WLC logs ------"
-cat "/dev/logbuffer_wireless"
-echo "\n------ WLC VER ------"
-cat "/sys/class/power_supply/wireless/device/version"
-echo "\n------ WLC STATUS ------"
-cat "/sys/class/power_supply/wireless/device/status"
-echo "\n------ WLC FW Version ------"
-cat "/sys/class/power_supply/wireless/device/fw_rev"
-echo "\n------ RTX ------"
-cat "/dev/logbuffer_rtx"
-
-if [ $build_type = "userdebug" ]
-then
-  echo "\n------ gvotables ------"
-  cat /sys/kernel/debug/gvotables/*/status
-fi
-
-echo "\n------ Lastmeal ------"
-cat "/data/vendor/mitigation/lastmeal.txt"
-echo "\n------ Thismeal ------"
-cat "/data/vendor/mitigation/thismeal.txt"
-echo "\n------ Mitigation Stats ------"
-echo "Source\t\tCount\tSOC\tTime\tVoltage"
-for f in `ls /sys/devices/virtual/pmic/mitigation/last_triggered_count/*`
-do
-  count=`cat $f`
-  a=${f/\/sys\/devices\/virtual\/pmic\/mitigation\/last_triggered_count\//}
-  b=${f/last_triggered_count/last_triggered_capacity}
-  c=${f/last_triggered_count/last_triggered_timestamp/}
-  d=${f/last_triggered_count/last_triggered_voltage/}
-  cnt=`cat $f`
-  cap=`cat ${b/count/cap}`
-  ti=`cat ${c/count/time}`
-  volt=`cat ${d/count/volt}`
-  echo "${a/_count/} \t$cnt\t$cap\t$ti\t$volt"
-done
-
-echo "\n------ Clock Divider Ratio ------"
-echo \"Source\t\tRatio\"
-for f in `ls /sys/devices/virtual/pmic/mitigation/clock_ratio/*`
-do ratio=`cat $f`
-  a=${f/\/sys\/devices\/virtual\/pmic\/mitigation\/clock_ratio\//}
-  echo "${a/_ratio/} \t$ratio"
-done
-
-echo "\n------ Clock Stats ------"
-echo "Source\t\tStats"
-for f in `ls /sys/devices/virtual/pmic/mitigation/clock_stats/*`
-do
-  stats=`cat $f`
-  a=${f/\/sys\/devices\/virtual\/pmic\/mitigation\/clock_stats\//};
-  echo "${a/_stats/} \t$stats"
-done
-
-echo "\n------ Triggered Level ------"
-echo "Source\t\tLevel"
-for f in `ls /sys/devices/virtual/pmic/mitigation/triggered_lvl/*`
-do
-  lvl=`cat $f`
-  a=${f/\/sys\/devices\/virtual\/pmic\/mitigation\/triggered_lvl\//}
-  echo "${a/_lvl/} \t$lvl"
-done
-
-echo "\n------ Instruction ------"
-for f in `ls /sys/devices/virtual/pmic/mitigation/instruction/*`
-do
-  val=`cat $f`
-  a=${f/\/sys\/devices\/virtual\/pmic\/mitigation\/instruction\//}
-  echo "$a=$val"
-done
-
diff --git a/dumpstate/item.mk b/dumpstate/item.mk
new file mode 100644
index 0000000..692ff8b
--- /dev/null
+++ b/dumpstate/item.mk
@@ -0,0 +1 @@
+PRODUCT_PACKAGES += dump_power
diff --git a/manifest.xml b/manifest.xml
index 34b0326..8c6ed15 100644
--- a/manifest.xml
+++ b/manifest.xml
@@ -1,13 +1,4 @@
 <manifest version="1.0" type="device" target-level="7">
-    <hal format="hidl">
-        <name>android.hardware.graphics.mapper</name>
-        <transport arch="32+64">passthrough</transport>
-        <version>4.0</version>
-        <interface>
-            <name>IMapper</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
     <hal format="aidl">
         <name>android.hardware.boot</name>
         <fqname>IBootControl/default</fqname>
diff --git a/powerstats/Gs201CommonDataProviders.cpp b/powerstats/Gs201CommonDataProviders.cpp
index 2b1f561..5f96ea3 100644
--- a/powerstats/Gs201CommonDataProviders.cpp
+++ b/powerstats/Gs201CommonDataProviders.cpp
@@ -274,7 +274,7 @@ void addSoC(std::shared_ptr<PowerStats> p) {
 }
 
 void setEnergyMeter(std::shared_ptr<PowerStats> p) {
-    std::vector<const std::string> deviceNames { "s2mpg12-odpm", "s2mpg13-odpm" };
+    std::vector<std::string> deviceNames { "s2mpg12-odpm", "s2mpg13-odpm" };
     p->setEnergyMeterDataProvider(std::make_unique<IioEnergyMeterDataProvider>(deviceNames, true));
 }
 
diff --git a/storage/5.10/init.gs201.storage.rc b/storage/5.10/init.gs201.storage.rc
new file mode 100644
index 0000000..7df260d
--- /dev/null
+++ b/storage/5.10/init.gs201.storage.rc
@@ -0,0 +1,3 @@
+on init
+    write /sys/block/sda/queue/scheduler bfq
+    write /sys/block/sda/queue/iosched/slice_idle 0
\ No newline at end of file
diff --git a/storage/6.1/init.gs201.storage.rc b/storage/6.1/init.gs201.storage.rc
new file mode 100644
index 0000000..3d88bb6
--- /dev/null
+++ b/storage/6.1/init.gs201.storage.rc
@@ -0,0 +1,2 @@
+on init
+    write /sys/block/sda/queue/scheduler mq-deadline
\ No newline at end of file
diff --git a/task_profiles.json b/task_profiles.json
index fda6c3e..81e5e41 100644
--- a/task_profiles.json
+++ b/task_profiles.json
@@ -288,6 +288,10 @@
     {
       "Name": "OtaProfiles",
       "Profiles": [ "OtaPerformance", "ProcessCapacityNormal", "LowIoPriority", "TimerSlackHigh" ]
+    },
+    {
+      "Name": "InputPolicy",
+      "Profiles": [ "ResetUclampGrp" ]
     }
   ]
 }
diff --git a/usb/gadget/UsbGadget.h b/usb/gadget/UsbGadget.h
index d117b91..cdd1871 100644
--- a/usb/gadget/UsbGadget.h
+++ b/usb/gadget/UsbGadget.h
@@ -74,7 +74,7 @@ constexpr char kProcInterruptsPath[] = "/proc/interrupts";
 constexpr char kProcIrqPath[] = "/proc/irq/";
 constexpr char kSmpAffinityList[] = "/smp_affinity_list";
 #ifndef UDC_PATH
-#define UDC_PATH "/sys/class/udc/11210000.dwc3/"
+#define UDC_PATH "/sys/devices/platform/11210000.usb/11210000.dwc3/udc/11210000.dwc3/"
 #endif
 static MonitorFfs monitorFfs(kGadgetName);
 
diff --git a/usb/usb/Usb.cpp b/usb/usb/Usb.cpp
index 2c42b11..5b38729 100644
--- a/usb/usb/Usb.cpp
+++ b/usb/usb/Usb.cpp
@@ -51,6 +51,7 @@ namespace usb_flags = android::hardware::usb::flags;
 
 using aidl::android::frameworks::stats::IStats;
 using android::base::GetProperty;
+using android::base::ParseInt;
 using android::base::Tokenize;
 using android::base::Trim;
 using android::hardware::google::pixel::getStatsService;
@@ -91,6 +92,8 @@ constexpr char kThermalZoneForTempReadPrimary[] = "usb_pwr_therm2";
 constexpr char kThermalZoneForTempReadSecondary1[] = "usb_pwr_therm";
 constexpr char kThermalZoneForTempReadSecondary2[] = "qi_therm";
 constexpr char kPogoUsbActive[] = "/sys/devices/platform/google,pogo/pogo_usb_active";
+constexpr char kPogoEnableHub[] = "/sys/devices/platform/google,pogo/enable_hub";
+constexpr char kInternalHubDevnum[] = "/sys/bus/usb/devices/1-1/devnum";
 constexpr char KPogoMoveDataToUsb[] = "/sys/devices/platform/google,pogo/move_data_to_usb";
 constexpr char kPowerSupplyUsbType[] = "/sys/class/power_supply/usb/usb_type";
 constexpr char kUdcUeventRegex[] =
@@ -471,11 +474,16 @@ bool switchMode(const string &portName, const PortRole &in_role, struct Usb *usb
     return roleSwitch;
 }
 
-static int usbDeviceRemoved(const char *devname, void* client_data) {
-    return 0;
+static int getInternalHubUniqueId() {
+    string internalHubDevnum;
+    int devnum = 0, internalHubUniqueId = -1;
+    if (ReadFileToString(kInternalHubDevnum, &internalHubDevnum) &&
+        ParseInt(Trim(internalHubDevnum).c_str(), &devnum))
+        internalHubUniqueId = 1000 + devnum;
+    return internalHubUniqueId;
 }
 
-static int usbDeviceAdded(const char *devname, void* client_data) {
+static Status tuneInternalHub(const char *devname, void* client_data) {
     uint16_t vendorId, productId;
     struct usb_device *device;
     ::aidl::android::hardware::usb::Usb *usb;
@@ -484,7 +492,7 @@ static int usbDeviceAdded(const char *devname, void* client_data) {
     device = usb_device_open(devname);
     if (!device) {
         ALOGE("usb_device_open failed\n");
-        return 0;
+        return Status::ERROR;
     }
 
     usb = (::aidl::android::hardware::usb::Usb *)client_data;
@@ -506,6 +514,26 @@ static int usbDeviceAdded(const char *devname, void* client_data) {
 
     usb_device_close(device);
 
+    return Status::SUCCESS;
+}
+
+static int usbDeviceRemoved(const char *devname, void* client_data) {
+    return 0;
+}
+
+static int usbDeviceAdded(const char *devname, void* client_data) {
+    string pogoEnableHub;
+    int uniqueId = 0;
+
+    // Enable hub tuning when the pogo dock is connected.
+    if (ReadFileToString(kPogoEnableHub, &pogoEnableHub) && Trim(pogoEnableHub) == "1") {
+        // If enable_hub is set to 1, the internal hub is the first enumearted device on bus 1 and
+        // port 1.
+        uniqueId = usb_device_get_unique_id_from_name(devname);
+        if (uniqueId == getInternalHubUniqueId())
+            tuneInternalHub(devname, client_data);
+    }
+
     return 0;
 }
 
```

