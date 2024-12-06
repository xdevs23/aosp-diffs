```diff
diff --git a/FSTAB_OWNERS b/FSTAB_OWNERS
new file mode 100644
index 0000000..18093a0
--- /dev/null
+++ b/FSTAB_OWNERS
@@ -0,0 +1,11 @@
+# NOTE: CHANGE THIS FILE WITH CAUTIOUS
+# - this file is referenced by other OWNERS file, e.g. device/google/*/OWNERS
+# - changing this file might break the function, check go/gerrit-code-owners-syntax first
+
+jaegeuk@google.com
+huangrandall@google.com
+bvanassche@google.com
+daehojeong@google.com
+chullee@google.com
+vkon@google.com
+thomasyen@google.com
diff --git a/OWNERS b/OWNERS
index b715f13..57ca40f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,5 @@
 
 per-file *.te,*_contexts,te_macros,global_macros=set noparent
 per-file *.te,*_contexts,te_macros,global_macros=file:/sepolicy/OWNERS
-per-file *.mk=set noparent
-per-file *.mk=file:MK_OWNERS
+per-file *.mk,{**/,}Android.bp=set noparent
+per-file *.mk,{**/,}Android.bp=file:MK_OWNERS
diff --git a/audio/aidl/device_framework_matrix_product.xml b/audio/aidl/device_framework_matrix_product.xml
index 3079aab..0e7e998 100644
--- a/audio/aidl/device_framework_matrix_product.xml
+++ b/audio/aidl/device_framework_matrix_product.xml
@@ -9,7 +9,7 @@
     </hal>
     <hal format="aidl">
         <name>vendor.google.whitechapel.audio.extension</name>
-        <version>2</version>
+        <version>3</version>
         <interface>
             <name>IAudioExtension</name>
             <instance>default</instance>
diff --git a/audio/common.mk b/audio/common.mk
index edf7b6a..a691f0a 100644
--- a/audio/common.mk
+++ b/audio/common.mk
@@ -3,8 +3,15 @@ BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/audio/sepolicy/common
 #Audio Vendor libraries
 PRODUCT_PACKAGES += \
 	libfvsam_prm_parser \
-	libmahalcontroller \
+	libmahalcontroller
+
+ifeq ($(USE_MAM_V4_ABOVE),true)
+PRODUCT_PACKAGES += \
+	libMAM_Google_Pixel_Android
+else
+PRODUCT_PACKAGES += \
 	libAlgFx_HiFi3z
+endif
 
 ifneq ($(USE_AUDIO_HAL_AIDL),true)
 ## AudioHAL Configurations
diff --git a/audio/sepolicy/common/hal_audio_default.te b/audio/sepolicy/common/hal_audio_default.te
index fac4f1a..f6e0e5d 100644
--- a/audio/sepolicy/common/hal_audio_default.te
+++ b/audio/sepolicy/common/hal_audio_default.te
@@ -1,3 +1,4 @@
+# allow access to folders
 allow hal_audio_default audio_vendor_data_file:dir rw_dir_perms;
 allow hal_audio_default audio_vendor_data_file:file create_file_perms;
 
@@ -23,6 +24,7 @@ allow hal_audio_default sysfs_aoc_boottime:file r_file_perms;
 allow hal_audio_default dmabuf_heap_device:chr_file r_file_perms;
 
 set_prop(hal_audio_default, vendor_audio_prop);
+set_prop(hal_audio_default, vendor_audio_prop_restricted);
 
 hal_client_domain(hal_audio_default, hal_health);
 hal_client_domain(hal_audio_default, hal_thermal);
diff --git a/bcmbt/dump/dump_bcmbt.cpp b/bcmbt/dump/dump_bcmbt.cpp
index fde0ad0..22e2fcf 100644
--- a/bcmbt/dump/dump_bcmbt.cpp
+++ b/bcmbt/dump/dump_bcmbt.cpp
@@ -34,7 +34,8 @@ int main() {
         return 0;
     }
 
-    dumpLogs(BCMBT_SNOOP_LOG_DIRECTORY, outputDir.c_str(), 2, BCMBT_SNOOP_LOG_PREFIX);
+    dumpLogs(BCMBT_SNOOP_LOG_DIRECTORY, outputDir.c_str(), 4,
+             BCMBT_SNOOP_LOG_PREFIX);
     dumpLogs(BCMBT_SNOOP_LOG_DIRECTORY, outputDir.c_str(), 2, BCMBT_BACKUP_SNOOP_LOG_PREFIX);
     dumpLogs(BCMBT_FW_LOG_DIRECTORY, outputDir.c_str(), 10, BCMBT_FW_DUMP_LOG_PREFIX);
     dumpLogs(BCMBT_FW_LOG_DIRECTORY, outputDir.c_str(), 10, BCMBT_CHRE_DUMP_LOG_PREFIX);
diff --git a/betterbug/betterbug.mk b/betterbug/betterbug.mk
index 906933d..2930362 100644
--- a/betterbug/betterbug.mk
+++ b/betterbug/betterbug.mk
@@ -1,7 +1,7 @@
 # When neither AOSP nor factory targets
 ifeq (,$(filter aosp_% factory_%, $(TARGET_PRODUCT)))
   PRODUCT_PACKAGES += BetterBugStub
-  PRODUCT_PACKAGES_DEBUG += BetterBug
+  PRODUCT_PACKAGES_DEBUG += $(RELEASE_PACKAGE_BETTER_BUG)
 endif
 
 PRODUCT_PUBLIC_SEPOLICY_DIRS += device/google/gs-common/betterbug/sepolicy/product/public
diff --git a/bootctrl/1.2/BootControl.cpp b/bootctrl/1.2/BootControl.cpp
index ff02013..54764a0 100644
--- a/bootctrl/1.2/BootControl.cpp
+++ b/bootctrl/1.2/BootControl.cpp
@@ -19,6 +19,7 @@
 #include "BootControl.h"
 
 #include <android-base/file.h>
+#include <android-base/properties.h>
 #include <android-base/unique_fd.h>
 #include <bootloader_message/bootloader_message.h>
 #include <cutils/properties.h>
@@ -254,16 +255,15 @@ static bool blowAR_gs101() {
 }
 
 static bool blowAR() {
-    char platform[PROPERTY_VALUE_MAX];
-    property_get("ro.boot.hardware.platform", platform, "");
+    const auto& platform = ::android::base::GetProperty("ro.boot.hardware.platform", "");
 
-    if (std::string(platform) == "gs101") {
+    if (platform == "gs101") {
         return blowAR_gs101();
-    } else if (std::string(platform) == "gs201" || std::string(platform) == "zuma") {
+    } else if (platform == "gs201" || platform == "zuma" || platform == "zumapro") {
         return blowAR_zuma();
     }
 
-    return true;
+    return false;
 }
 
 }  // namespace
diff --git a/bootctrl/aidl/BootControl.cpp b/bootctrl/aidl/BootControl.cpp
index d894f8b..8655929 100644
--- a/bootctrl/aidl/BootControl.cpp
+++ b/bootctrl/aidl/BootControl.cpp
@@ -20,6 +20,7 @@
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
+#include <android-base/properties.h>
 #include <android-base/unique_fd.h>
 #include <bootloader_message/bootloader_message.h>
 #include <cutils/properties.h>
@@ -251,16 +252,15 @@ static bool blowAR_gs101() {
 }
 
 static bool blowAR() {
-    char platform[PROPERTY_VALUE_MAX];
-    property_get("ro.boot.hardware.platform", platform, "");
+    const auto& platform = ::android::base::GetProperty("ro.boot.hardware.platform", "");
 
-    if (std::string(platform) == "gs101") {
+    if (platform == "gs101") {
         return blowAR_gs101();
-    } else if (std::string(platform) == "gs201" || std::string(platform) == "zuma") {
+    } else if (platform == "gs201" || platform == "zuma" || platform == "zumapro") {
         return blowAR_zuma();
     }
 
-    return true;
+    return false;
 }
 
 static constexpr MergeStatus ToAIDLMergeStatus(HIDLMergeStatus status) {
diff --git a/camera/lyric.mk b/camera/lyric.mk
index 7762f4d..c886138 100644
--- a/camera/lyric.mk
+++ b/camera/lyric.mk
@@ -5,14 +5,22 @@ $(call soong_config_set,lyric,use_lyric_camera_hal,true)
 $(call soong_config_set,google3a_config,gcam_awb,true)
 $(call soong_config_set,google3a_config,ghawb_truetone,true)
 
+# Flag controls whether Lyric apex can be located in the dist-directory.
+$(call soong_config_set, lyric, dist_lyric_apex, $(RELEASE_PIXEL_DIST_LYRIC_APEX))
+
 # Select GCH backend.
 # TODO(b/192681010): This dependency inversion should be removed.
 ifneq ($(wildcard vendor/google/services/LyricCameraHAL/src),)
 $(call soong_config_set,gch,hwl_library,lyric)
 endif
 
-# Check if we're in the internal build
-ifneq ($(wildcard vendor/google/camera),)
+# Use build-time flag to select whether to build from source
+# or ingest prebuilt-apex.  We would want the development teams
+# using release configuration: (trunk-staging) to build from source.
+# All shipping releases will switch to prebuilts (trunk+)
+# if this condition is not true, then build from source.
+
+ifneq ($(RELEASE_PIXEL_CAMERA_ENABLE_PREBUILT),true)
 
 PRODUCT_SOONG_NAMESPACES += \
     vendor/google/camera \
@@ -33,8 +41,7 @@ PRODUCT_SOONG_NAMESPACES += \
 # Calibration tool for debug builds
 PRODUCT_PACKAGES_DEBUG += tarasque_test
 PRODUCT_PACKAGES_DEBUG += ProtoCalibGenerator
-
-endif  # vendor/google/camera check
+endif  # RELEASE_PIXEL_CAMERA_ENABLE_PREBUILT check
 
 # Init-time log settings for Google 3A
 PRODUCT_PACKAGES += libg3a_standalone_gabc_rc
diff --git a/camera/sepolicy/product/private/service_contexts b/camera/sepolicy/product/private/service_contexts
index fed03af..0cb84b4 100644
--- a/camera/sepolicy/product/private/service_contexts
+++ b/camera/sepolicy/product/private/service_contexts
@@ -1 +1,5 @@
-com.google.pixel.camera.services.binder.IServiceBinder/default u:object_r:camera_binder_service:s0
\ No newline at end of file
+com.google.pixel.camera.services.binder.IServiceBinder/default u:object_r:camera_binder_service:s0
+
+com.google.pixel.camera.services.cameraidremapper.ICameraIdRemapper/default u:object_r:camera_cameraidremapper_service:s0
+
+com.google.pixel.camera.services.lyricconfigprovider.ILyricConfigProvider/default u:object_r:camera_lyricconfigprovider_service:s0
diff --git a/camera/sepolicy/product/private/vendor_pbcs_app.te b/camera/sepolicy/product/private/vendor_pbcs_app.te
index 54bc0c0..b8a52d2 100644
--- a/camera/sepolicy/product/private/vendor_pbcs_app.te
+++ b/camera/sepolicy/product/private/vendor_pbcs_app.te
@@ -9,4 +9,10 @@ allow vendor_pbcs_app app_api_service:service_manager find;
 allow vendor_pbcs_app cameraserver_service:service_manager find;
 
 # Allow PBCS to add the ServiceBinder service to ServiceManager.
-add_service(vendor_pbcs_app, camera_binder_service);
\ No newline at end of file
+add_service(vendor_pbcs_app, camera_binder_service);
+
+# Allow PBCS to add the CameraIdRemapper service to ServiceManager.
+add_service(vendor_pbcs_app, camera_cameraidremapper_service);
+
+# Allow PBCS to add the LyricConfigProvider service to ServiceManager.
+add_service(vendor_pbcs_app, camera_lyricconfigprovider_service);
diff --git a/camera/sepolicy/product/private/vendor_pcs_app.te b/camera/sepolicy/product/private/vendor_pcs_app.te
index 55eeee7..d41adb4 100644
--- a/camera/sepolicy/product/private/vendor_pcs_app.te
+++ b/camera/sepolicy/product/private/vendor_pcs_app.te
@@ -8,6 +8,8 @@ allow vendor_pcs_app {
     app_api_service
     audioserver_service
     cameraserver_service
+    camera_cameraidremapper_service
+    camera_lyricconfigprovider_service
     drmserver_service
     mediametrics_service
     mediaserver_service
diff --git a/camera/sepolicy/product/public/service.te b/camera/sepolicy/product/public/service.te
index f94fd9f..2cdc125 100644
--- a/camera/sepolicy/product/public/service.te
+++ b/camera/sepolicy/product/public/service.te
@@ -1 +1,5 @@
-type camera_binder_service, hal_service_type, protected_service, service_manager_type;
\ No newline at end of file
+type camera_binder_service, hal_service_type, protected_service, service_manager_type;
+
+type camera_cameraidremapper_service, hal_service_type, protected_service, service_manager_type;
+
+type camera_lyricconfigprovider_service, hal_service_type, protected_service, service_manager_type;
diff --git a/camera/sepolicy/vendor/hal_camera_default.te b/camera/sepolicy/vendor/hal_camera_default.te
index 9e7b105..ebb58b8 100644
--- a/camera/sepolicy/vendor/hal_camera_default.te
+++ b/camera/sepolicy/vendor/hal_camera_default.te
@@ -1,6 +1,6 @@
 allow hal_camera_default camera_binder_service:service_manager find;
 # Allow Lyric Hal to find the LyricConfigProvider service through ServiceManager.
-allow hal_camera_default vendor_camera_lyricconfigprovider_service:service_manager find;
+allow hal_camera_default camera_lyricconfigprovider_service:service_manager find;
 
 allow hal_camera_default hal_pixel_remote_camera_service:service_manager find;
 
@@ -8,6 +8,5 @@ binder_call(hal_camera_default, vendor_pbcs_app);
 
 binder_call(hal_camera_default, vendor_pcs_app);
 
-# Allow Lyric HAL to start ISP Service and Image Processing HAL
-add_service(hal_camera_default, vendor_camera_isp_service)
+# Allow Lyric HAL to start Image Processing HAL
 add_service(hal_camera_default, vendor_image_processing_hal_service)
diff --git a/camera/sepolicy/vendor/service.te b/camera/sepolicy/vendor/service.te
index 35887ba..757bf6d 100644
--- a/camera/sepolicy/vendor/service.te
+++ b/camera/sepolicy/vendor/service.te
@@ -1,9 +1,3 @@
 type hal_pixel_remote_camera_service, hal_service_type, protected_service, service_manager_type;
 
-type vendor_camera_lyricconfigprovider_service, hal_service_type, protected_service, service_manager_type;
-
-type vendor_camera_isp_service, hal_service_type, protected_service, service_manager_type;
-
-type vendor_camera_cameraidremapper_service, hal_service_type, protected_service, service_manager_type;
-
 type vendor_image_processing_hal_service, hal_service_type, protected_service, service_manager_type;
diff --git a/camera/sepolicy/vendor/service_contexts b/camera/sepolicy/vendor/service_contexts
index 9f5e335..7a2d6ff 100644
--- a/camera/sepolicy/vendor/service_contexts
+++ b/camera/sepolicy/vendor/service_contexts
@@ -1,9 +1,3 @@
 com.google.pixel.camera.connectivity.hal.provider.ICameraProvider/default u:object_r:hal_pixel_remote_camera_service:s0
 
-com.google.pixel.camera.services.lyricconfigprovider.ILyricConfigProvider/default u:object_r:vendor_camera_lyricconfigprovider_service:s0
-
-com.google.pixel.camera.isp.IIspService/default u:object_r:vendor_camera_isp_service:s0
-
-com.google.pixel.camera.services.cameraidremapper.ICameraIdRemapper/default u:object_r:vendor_camera_cameraidremapper_service:s0
-
-com.google.android.imageprocessing.IImageProcessingHal u:object_r:vendor_image_processing_hal_service:s0
+com.google.android.imageprocessing.hal.IImageProcessingHal/default u:object_r:vendor_image_processing_hal_service:s0
diff --git a/camera/sepolicy/vendor/vendor_pbcs_app.te b/camera/sepolicy/vendor/vendor_pbcs_app.te
index b25c9a2..965ef54 100644
--- a/camera/sepolicy/vendor/vendor_pbcs_app.te
+++ b/camera/sepolicy/vendor/vendor_pbcs_app.te
@@ -1,9 +1,9 @@
 # Allow PBCS to add the ServiceBinder service to ServiceManager.
 add_service(vendor_pbcs_app, camera_binder_service);
 # Allow PBCS to add the LyricConfigProvider service to ServiceManager.
-add_service(vendor_pbcs_app, vendor_camera_lyricconfigprovider_service);
+add_service(vendor_pbcs_app, camera_lyricconfigprovider_service);
 # Allow PBCS to add the CameraIdRemapper service to ServiceManager.
-add_service(vendor_pbcs_app, vendor_camera_cameraidremapper_service);
+add_service(vendor_pbcs_app, camera_cameraidremapper_service);
 
 # Allow PBCS to read debug system properties of the form vendor.camera.pbcs.debug.*
 # and persist.vendor.camera.pbcs.debug.*
diff --git a/camera/sepolicy/vendor/vendor_pcs_app.te b/camera/sepolicy/vendor/vendor_pcs_app.te
index b4d71b5..068a0f7 100644
--- a/camera/sepolicy/vendor/vendor_pcs_app.te
+++ b/camera/sepolicy/vendor/vendor_pcs_app.te
@@ -1,6 +1,6 @@
 allow vendor_pcs_app {
-    vendor_camera_lyricconfigprovider_service
-    vendor_camera_cameraidremapper_service
+    camera_lyricconfigprovider_service
+    camera_cameraidremapper_service
     edgetpu_app_service
 }:service_manager find;
 
diff --git a/check_current_prebuilt/check_current_prebuilt.mk b/check_current_prebuilt/check_current_prebuilt.mk
new file mode 100644
index 0000000..72e359f
--- /dev/null
+++ b/check_current_prebuilt/check_current_prebuilt.mk
@@ -0,0 +1,27 @@
+# Create symlink for bootloader
+$(shell rm -f "pixel_current_bootloader")
+ifdef BOOTLOADER_FILE_PATH
+$(shell ln -sf ${BOOTLOADER_FILE_PATH} "pixel_current_bootloader")
+else ifdef BOOTLOADER_RADIO_FILE_PATH
+$(shell ln -sf ${BOOTLOADER_RADIO_FILE_PATH} "pixel_current_bootloader")
+endif
+
+# Create symlink for kernel
+$(shell rm -f "pixel_current_kernel")
+ifdef TARGET_KERNEL_DIR
+$(shell ln -sf ${TARGET_KERNEL_DIR} "pixel_current_kernel")
+endif
+
+# Create symlink for radio
+$(shell rm -f "pixel_current_radio")
+ifdef RADIO_FILE_PATH
+$(shell ln -sf ${RADIO_FILE_PATH} "pixel_current_radio")
+else ifdef BOOTLOADER_RADIO_FILE_PATH
+$(shell ln -sf ${BOOTLOADER_RADIO_FILE_PATH} "pixel_current_radio")
+endif
+
+# Create symlink for radiocfg
+$(shell rm -f "pixel_current_radiocfg")
+ifdef SRC_MDM_CFG_DIR
+$(shell ln -sf ${SRC_MDM_CFG_DIR} "pixel_current_radiocfg")
+endif
diff --git a/dauntless/gsc.mk b/dauntless/gsc.mk
index 188d9f9..b563cc4 100644
--- a/dauntless/gsc.mk
+++ b/dauntless/gsc.mk
@@ -1,6 +1,6 @@
 # Dauntless
 BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/dauntless/sepolicy
-ifneq ($(wildcard vendor),)
+ifneq ($(wildcard vendor/google_nos),)
 PRODUCT_SOONG_NAMESPACES += vendor/google_nos/init/dauntless
 
 PRODUCT_PACKAGES += \
@@ -20,4 +20,76 @@ PRODUCT_PACKAGES_DEBUG += citadel_integration_tests \
                           nugget_targeted_tests \
                           CitadelProvision \
                           nugget_aidl_test_weaver
+
+# Assign default value for RELEASE_GOOGLE_DAUNTLESS_DIR if no trunk flags support
+RELEASE_GOOGLE_DAUNTLESS_DIR ?= vendor/google_nos/prebuilts/dauntless
+
+# The production Dauntless firmware will be of flavors evt and d3m2.
+# There are also several flavors of pre-release chips. Each flavor
+# (production and pre-release) requires the firmware to be signed differently.
+DAUNTLESS_FIRMWARE_SIZE := 1048576
+
+# The nearly-production Dauntless chips are "proto1.1"
+ifneq (,$(wildcard $(RELEASE_GOOGLE_DAUNTLESS_DIR)/proto11.ec.bin))
+ifneq ($(DAUNTLESS_FIRMWARE_SIZE), $(shell stat -c "%s" $(RELEASE_GOOGLE_DAUNTLESS_DIR)/proto11.ec.bin))
+$(error GSC firmware size check fail)
+endif
+PRODUCT_COPY_FILES += \
+    $(RELEASE_GOOGLE_DAUNTLESS_DIR)/proto11.ec.bin:$(TARGET_COPY_OUT_VENDOR)/firmware/dauntless/proto11.ec.bin
+$(call dist-for-goals,droid,$(RELEASE_GOOGLE_DAUNTLESS_DIR)/proto11.ec.bin)
+else
+$(error GSC firmware not found in $(RELEASE_GOOGLE_DAUNTLESS_DIR))
+endif
+
+# The production Dauntless chips are "evt"
+ifneq (,$(wildcard $(RELEASE_GOOGLE_DAUNTLESS_DIR)/evt.ec.bin))
+ifneq ($(DAUNTLESS_FIRMWARE_SIZE), $(shell stat -c "%s" $(RELEASE_GOOGLE_DAUNTLESS_DIR)/evt.ec.bin))
+$(error GSC firmware size check fail)
+endif
+PRODUCT_COPY_FILES += \
+    $(RELEASE_GOOGLE_DAUNTLESS_DIR)/evt.ec.bin:$(TARGET_COPY_OUT_VENDOR)/firmware/dauntless/evt.ec.bin
+$(call dist-for-goals,droid,$(RELEASE_GOOGLE_DAUNTLESS_DIR)/evt.ec.bin)
+else
+$(error GSC firmware not found in $(RELEASE_GOOGLE_DAUNTLESS_DIR))
+endif
+
+# New 2023 production Dauntless chips are "d3m2"
+ifneq (,$(wildcard $(RELEASE_GOOGLE_DAUNTLESS_DIR)/d3m2.ec.bin))
+ifneq ($(DAUNTLESS_FIRMWARE_SIZE), $(shell stat -c "%s" $(RELEASE_GOOGLE_DAUNTLESS_DIR)/d3m2.ec.bin))
+$(error GSC firmware size check fail)
+endif
+PRODUCT_COPY_FILES += \
+    $(RELEASE_GOOGLE_DAUNTLESS_DIR)/d3m2.ec.bin:$(TARGET_COPY_OUT_VENDOR)/firmware/dauntless/d3m2.ec.bin
+$(call dist-for-goals,droid,$(RELEASE_GOOGLE_DAUNTLESS_DIR)/d3m2.ec.bin)
+else
+$(error GSC firmware not found in $(RELEASE_GOOGLE_DAUNTLESS_DIR))
 endif
+
+# Intermediate image artifacts are published, but aren't included in /vendor/firmware/dauntless
+# in PRODUCT_COPY_FILES
+# This is because intermediate images aren't needed on user devices, but the published artifact
+# is useful for flashstation purposes.
+
+# proto11 chips need an intermediate image prior to upgrading to newever versions of the firmware
+ifneq (,$(wildcard vendor/google_nos/prebuilts/dauntless/intermediate_images/proto11_intermediate.ec.bin))
+ifneq ($(DAUNTLESS_FIRMWARE_SIZE), $(shell stat -c "%s" vendor/google_nos/prebuilts/dauntless/intermediate_images/proto11_intermediate.ec.bin))
+$(error GSC firmware size check fail)
+endif
+$(call dist-for-goals,droid,vendor/google_nos/prebuilts/dauntless/intermediate_images/proto11_intermediate.ec.bin)
+endif
+# evt chips need an intermediate image prior to upgrading to newever versions of the firmware
+ifneq (,$(wildcard vendor/google_nos/prebuilts/dauntless/intermediate_images/evt_intermediate.ec.bin))
+ifneq ($(DAUNTLESS_FIRMWARE_SIZE), $(shell stat -c "%s" vendor/google_nos/prebuilts/dauntless/intermediate_images/evt_intermediate.ec.bin))
+$(error GSC firmware size check fail)
+endif
+$(call dist-for-goals,droid,vendor/google_nos/prebuilts/dauntless/intermediate_images/evt_intermediate.ec.bin)
+endif
+# d3m2 chips need an intermediate image prior to upgrading to newever versions of the firmware
+ifneq (,$(wildcard vendor/google_nos/prebuilts/dauntless/intermediate_images/d3m2_intermediate.ec.bin))
+ifneq ($(DAUNTLESS_FIRMWARE_SIZE), $(shell stat -c "%s" vendor/google_nos/prebuilts/dauntless/intermediate_images/d3m2_intermediate.ec.bin))
+$(error GSC firmware size check fail)
+endif
+$(call dist-for-goals,droid,vendor/google_nos/prebuilts/dauntless/intermediate_images/d3m2_intermediate.ec.bin)
+endif
+
+endif # $(wildcard vendor/google_nos)
diff --git a/display/dump_display.cpp b/display/dump_display.cpp
index b811889..2df6b4b 100644
--- a/display/dump_display.cpp
+++ b/display/dump_display.cpp
@@ -25,6 +25,6 @@ int main() {
     dumpFileContent("Primary panel name", "/sys/devices/platform/exynos-drm/primary-panel/panel_name");
     dumpFileContent("Primary panel extra info", "/sys/devices/platform/exynos-drm/primary-panel/panel_extinfo");
     dumpFileContent("Primary panel power Vreg", "/sys/devices/platform/exynos-drm/primary-panel/panel_pwr_vreg");
+    dumpFileContent("Primary panel power mode register", "/sys/devices/platform/exynos-drm/primary-panel/power_mode");
     return 0;
-}
-
+}
\ No newline at end of file
diff --git a/display/dump_second_display.cpp b/display/dump_second_display.cpp
index a6f2665..80ea909 100644
--- a/display/dump_second_display.cpp
+++ b/display/dump_second_display.cpp
@@ -20,6 +20,7 @@ int main() {
     dumpFileContent("CRTC-1 event log", "/sys/kernel/debug/dri/0/crtc-1/event");
     dumpFileContent("Secondary panel name", "/sys/devices/platform/exynos-drm/secondary-panel/panel_name");
     dumpFileContent("Secondary panel extra info", "/sys/devices/platform/exynos-drm/secondary-panel/panel_extinfo");
+    dumpFileContent("Secondary panel power mode register", "/sys/devices/platform/exynos-drm/secondary-panel/power_mode");
     return 0;
 }
 
diff --git a/edgetpu/sepolicy/edgetpu_tachyon_service.te b/edgetpu/sepolicy/edgetpu_tachyon_service.te
index da34353..80db366 100644
--- a/edgetpu/sepolicy/edgetpu_tachyon_service.te
+++ b/edgetpu/sepolicy/edgetpu_tachyon_service.te
@@ -27,6 +27,9 @@ allow edgetpu_tachyon_server gpu_device:chr_file rw_file_perms;
 allow edgetpu_tachyon_server gpu_device:dir r_dir_perms;
 allow edgetpu_tachyon_server ion_device:chr_file r_file_perms;
 
+# Allow Tachyon service to access camera hal via binder.
+binder_call(edgetpu_tachyon_server, hal_camera_default);
+
 # Allow Tachyon service to access dmabuf sysytem.
 allow edgetpu_tachyon_server dmabuf_system_heap_device:chr_file r_file_perms;
 
@@ -60,3 +63,8 @@ allow edgetpu_tachyon_server privapp_data_file:file { map read};
 userdebug_or_eng(`
     allow edgetpu_tachyon_server shell_data_file:file { map read};
 ')
+
+# For shell level testing
+userdebug_or_eng(`
+    binder_call(edgetpu_tachyon_server, shell);
+')
diff --git a/edgetpu/sepolicy/hal_camera_default.te b/edgetpu/sepolicy/hal_camera_default.te
index 624533a..e84f5dc 100644
--- a/edgetpu/sepolicy/hal_camera_default.te
+++ b/edgetpu/sepolicy/hal_camera_default.te
@@ -6,3 +6,10 @@ get_prop(hal_camera_default, vendor_edgetpu_runtime_prop)
 
 # Allow camera HAL to read hetero runtime properties
 get_prop(hal_camera_default, vendor_hetero_runtime_prop)
+
+# Allow camera HAL to access tachyon HAL
+allow hal_camera_default edgetpu_tachyon_service:service_manager find;
+
+# Allow camera HAL to communicate with tachyon hal using binder calls
+binder_call(hal_camera_default, edgetpu_tachyon_server);
+
diff --git a/edgetpu/sepolicy/hal_neuralnetworks_darwinn.te b/edgetpu/sepolicy/hal_neuralnetworks_darwinn.te
index 3b2cd4f..abdbcd7 100644
--- a/edgetpu/sepolicy/hal_neuralnetworks_darwinn.te
+++ b/edgetpu/sepolicy/hal_neuralnetworks_darwinn.te
@@ -1,3 +1,4 @@
+# Sepolicies for EdgeTPU
 type hal_neuralnetworks_darwinn, domain;
 hal_server_domain(hal_neuralnetworks_darwinn, hal_neuralnetworks)
 
@@ -62,3 +63,8 @@ get_prop(hal_neuralnetworks_darwinn, vendor_hetero_runtime_prop)
 # Allow DMA Buf access.
 allow hal_neuralnetworks_darwinn dmabuf_system_heap_device:chr_file r_file_perms;
 
+# Allows the NNAPI HAL to access the graphics_allocator_service.
+# This is required for shared memory buffer allocation.
+# Context:- b/361711471.
+hal_client_domain(hal_neuralnetworks_darwinn, hal_graphics_allocator);
+allow hal_neuralnetworks_darwinn hal_graphics_allocator_service:service_manager find;
diff --git a/esim/Android.bp b/esim/Android.bp
new file mode 100644
index 0000000..a2427f1
--- /dev/null
+++ b/esim/Android.bp
@@ -0,0 +1,10 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc {
+    name: "init.esim-gs.rc",
+    src: "init.esim-gs.rc",
+    vendor: true,
+    sub_dir: "init",
+}
diff --git a/esim/OWNERS b/esim/OWNERS
new file mode 100644
index 0000000..157ecd6
--- /dev/null
+++ b/esim/OWNERS
@@ -0,0 +1,2 @@
+kiwonp@google.com
+mewan@google.com
\ No newline at end of file
diff --git a/esim/esim.mk b/esim/esim.mk
new file mode 100644
index 0000000..47e21b7
--- /dev/null
+++ b/esim/esim.mk
@@ -0,0 +1,5 @@
+PRODUCT_PACKAGES += init.esim-gs.rc
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/esim/sepolicy/vendor
+# system_ext
+SYSTEM_EXT_PUBLIC_SEPOLICY_DIRS += device/google/gs-common/esim/sepolicy/system_ext/public
+SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += device/google/gs-common/esim/sepolicy/system_ext/private
diff --git a/esim/init.esim-gs.rc b/esim/init.esim-gs.rc
new file mode 100644
index 0000000..291f9ee
--- /dev/null
+++ b/esim/init.esim-gs.rc
@@ -0,0 +1,7 @@
+# Disable bootstrap when bootloader is unlocked in user build
+on property:ro.build.type=user && property:ro.boot.flash.locked=0
+    setprop setupwizard.feature.provisioning_profile_mode false
+
+# Disable bootstrap for DVT devices shipping to non-US carriers
+on property:ro.boot.warranty.sku=BOF
+    setprop setupwizard.feature.provisioning_profile_mode false
diff --git a/esim/sepolicy/system_ext/private/gmscore_app.te b/esim/sepolicy/system_ext/private/gmscore_app.te
new file mode 100644
index 0000000..90bc371
--- /dev/null
+++ b/esim/sepolicy/system_ext/private/gmscore_app.te
@@ -0,0 +1,2 @@
+# Allow to read setupwizard_feature_prop
+get_prop(priv_app, setupwizard_feature_prop)
diff --git a/esim/sepolicy/system_ext/private/priv_app.te b/esim/sepolicy/system_ext/private/priv_app.te
new file mode 100644
index 0000000..90bc371
--- /dev/null
+++ b/esim/sepolicy/system_ext/private/priv_app.te
@@ -0,0 +1,2 @@
+# Allow to read setupwizard_feature_prop
+get_prop(priv_app, setupwizard_feature_prop)
diff --git a/esim/sepolicy/system_ext/private/property_contexts b/esim/sepolicy/system_ext/private/property_contexts
new file mode 100644
index 0000000..464a289
--- /dev/null
+++ b/esim/sepolicy/system_ext/private/property_contexts
@@ -0,0 +1,2 @@
+# setupwizard
+setupwizard.feature.provisioning_profile_mode    u:object_r:setupwizard_feature_prop:s0
diff --git a/esim/sepolicy/system_ext/public/property.te b/esim/sepolicy/system_ext/public/property.te
new file mode 100644
index 0000000..96cb3b3
--- /dev/null
+++ b/esim/sepolicy/system_ext/public/property.te
@@ -0,0 +1,2 @@
+# setupwizard
+system_public_prop(setupwizard_feature_prop)
diff --git a/esim/sepolicy/vendor/vendor_init.te b/esim/sepolicy/vendor/vendor_init.te
new file mode 100644
index 0000000..c9cb14e
--- /dev/null
+++ b/esim/sepolicy/vendor/vendor_init.te
@@ -0,0 +1,2 @@
+# setupwizard
+set_prop(vendor_init, setupwizard_feature_prop)
diff --git a/euiccpixel_app/euiccpixel_app_st54.mk b/euiccpixel_app/euiccpixel_app_st54.mk
new file mode 100644
index 0000000..e96d06c
--- /dev/null
+++ b/euiccpixel_app/euiccpixel_app_st54.mk
@@ -0,0 +1,3 @@
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/euiccpixel_app/sepolicy/common
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/euiccpixel_app/sepolicy/st54
+PRODUCT_PACKAGES += EuiccSupportPixel-P23
diff --git a/euiccpixel_app/sepolicy/common/certs/EuiccSupportPixel.x509.pem b/euiccpixel_app/sepolicy/common/certs/EuiccSupportPixel.x509.pem
new file mode 100644
index 0000000..be303df
--- /dev/null
+++ b/euiccpixel_app/sepolicy/common/certs/EuiccSupportPixel.x509.pem
@@ -0,0 +1,29 @@
+-----BEGIN CERTIFICATE-----
+MIIF2zCCA8OgAwIBAgIVAIFP2e+Gh4wn4YFsSI7fRB6AXjIsMA0GCSqGSIb3DQEBCwUAMH4xCzAJ
+BgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRQw
+EgYDVQQKEwtHb29nbGUgSW5jLjEQMA4GA1UECxMHQW5kcm9pZDEaMBgGA1UEAxMRRXVpY2NTdXBw
+b3J0UGl4ZWwwHhcNMTkwMjI4MTkyMjE4WhcNNDkwMjI4MTkyMjE4WjB+MQswCQYDVQQGEwJVUzET
+MBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEUMBIGA1UEChMLR29v
+Z2xlIEluYy4xEDAOBgNVBAsTB0FuZHJvaWQxGjAYBgNVBAMTEUV1aWNjU3VwcG9ydFBpeGVsMIIC
+IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqklePqeltzqnyXVch9eJRXFBRQQIBIJWhcXb
+WIP/kZ28ISnQ2SrZisdxqtvRIeInxb7lU1rRQDfqCFSp/vMZ3l25Ryn6OVLFP4bxV1vO797t7Ef/
+amYA1mFKBsD4KLaIGj0/2RpGesneCOb0jWl2yRgIO2Ez7Y4YgWU/IoickZDLp1u6/7e7E/Qq9OXK
+aXvtBSzooGrYC7eyKn7O21FOfz5cQRo4BipjJqXG5Ez8Vi+m/dL1IFRZheYttEf3v390vBcb0oJ0
+oYPzLxmnb1LchjZC3yLAknRA0hNt8clvJ3tjXFjtzCGKsQsT4rnvvGFFABJTCf3EdEiwBNS5U4ho
++9+EtH7PpuoC+uVv2rLv/Gb7stlGQGx32KmK2CfKED3PdNqoT7WRx6nvVjCk3i7afdUcxQxcS9td
+5r80CB1bQEhS2sWLWB21PJrfMugWUJO5Bwz6u0es8dP+4FAHojIaF6iwB5ZYIuHGcEaOviHm4jOK
+rrGMlLqTwuEhq2aVIP55u7XRV98JLs2hlE5DJOWCIsPxybUDiddFvR+yzi/4FimsxJlEmaQAQcki
+uJ9DceVP03StPzFJSDRlqa4yF6xkZW5piNoANQ4MyI67V2Qf8g/L1UPYAi4hUMxQGo7Clw2hBRag
+ZTm65Xc7+ovBYxl5YaXAmNoJbss34Lw8tdrn4EECAwEAAaNQME4wDAYDVR0TBAUwAwEB/zAdBgNV
+HQ4EFgQU+hQdFrOGuCDI+bbebssw9TL5FcYwHwYDVR0jBBgwFoAU+hQdFrOGuCDI+bbebssw9TL5
+FcYwDQYJKoZIhvcNAQELBQADggIBAGmyZHXddei/zUUMowiyi/MTtqXf9hKDEN4zhAXkuiuHxqA9
+Ii0J1Sxz2dd5NkqMmtePKYFSGA884yVm1KAne/uoCWj57IK3jswiRYnKhXa293DxA/K9wY27IGbp
+ulSuuxbpjjV2tqGUuoNQGKX7Oy6s0GcibyZFc+LpD7ttGk5QoLC9qQdpXZgUv/yG2B99ERSXLCaL
+EWMNP/oVZQOCQGfsFM1fPLn3X0ZuCOQg9bljxFf3jTl+H6PIAhpCjKeeUQYLc41eQkCyR/f67aRB
+GvO4YDpXLn9eH23B+26rjPyFiVtMJ/jJZ7UEPeJ3XBj1COS/X7p9gGRS5rtfr9z7XxuMxvG0JU9U
+XA+bMfOOfCqflvw6IyUg+oxjBFIhgiP4fxna51+BqpctvB0OeRwUm6y4nN06AwqtD8SteQrEn0b0
+IDWOKlVeh0lJWrDDEHr55dXSF+CbOPUDmMxmGoulOEOy/qSWIQi8BfvdX+e88CmracNRYVffLuQj
+pRYN3TeiCJd+6/X9/x1Q8VLW7vOAb6uRyE2lOjX40DYBxK3xSq6J7Vp38f6z0vtQm2sAAQ4xqqon
+A9tB5p+nJlYHgSxXOZx3C13Rs/eMmiGCKkSpCTnGCgBC7PfJDdMK6SLw5Gn4oyGoZo4fXbADuHrU
+0JD1T1qdCm3aUSEmFgEA4rOL/0K3
+-----END CERTIFICATE-----
diff --git a/euiccpixel_app/sepolicy/common/euiccpixel_app.te b/euiccpixel_app/sepolicy/common/euiccpixel_app.te
new file mode 100644
index 0000000..8093b49
--- /dev/null
+++ b/euiccpixel_app/sepolicy/common/euiccpixel_app.te
@@ -0,0 +1,27 @@
+# Euiccpixel_app
+type euiccpixel_app, domain;
+app_domain(euiccpixel_app)
+
+allow euiccpixel_app activity_service:service_manager find;
+allow euiccpixel_app netstats_service:service_manager find;
+allow euiccpixel_app content_capture_service:service_manager find;
+allow euiccpixel_app activity_task_service:service_manager find;
+allow euiccpixel_app gpu_service:service_manager find;
+allow euiccpixel_app voiceinteraction_service:service_manager find;
+allow euiccpixel_app autofill_service:service_manager find;
+allow euiccpixel_app sensitive_content_protection_service:service_manager find;
+allow euiccpixel_app hint_service:service_manager find;
+allow euiccpixel_app audio_service:service_manager find;
+allow euiccpixel_app batterystats_service:service_manager find;
+allow euiccpixel_app batteryproperties_service:service_manager find;
+allow euiccpixel_app permission_checker_service:service_manager find;
+allow euiccpixel_app radio_service:service_manager find;
+allow euiccpixel_app nfc_service:service_manager find;
+
+set_prop(euiccpixel_app, vendor_secure_element_prop)
+set_prop(euiccpixel_app, vendor_modem_prop)
+get_prop(euiccpixel_app, dck_prop)
+
+# b/265286368 framework UI rendering properties and file access
+dontaudit euiccpixel_app default_prop:file { read };
+dontaudit euiccpixel_app sysfs_gpu_uevent:file { read open getattr };
diff --git a/euiccpixel_app/sepolicy/common/file.te b/euiccpixel_app/sepolicy/common/file.te
new file mode 100644
index 0000000..e76ee79
--- /dev/null
+++ b/euiccpixel_app/sepolicy/common/file.te
@@ -0,0 +1,2 @@
+# type for gpu uevent
+type sysfs_gpu_uevent, sysfs_type, fs_type;
diff --git a/euiccpixel_app/sepolicy/common/genfs_contexts b/euiccpixel_app/sepolicy/common/genfs_contexts
new file mode 100644
index 0000000..fc146df
--- /dev/null
+++ b/euiccpixel_app/sepolicy/common/genfs_contexts
@@ -0,0 +1 @@
+genfscon sysfs /devices/platform/34f00000.gpu0/uevent                 u:object_r:sysfs_gpu_uevent:s0
diff --git a/euiccpixel_app/sepolicy/common/keys.conf b/euiccpixel_app/sepolicy/common/keys.conf
new file mode 100644
index 0000000..7071a2a
--- /dev/null
+++ b/euiccpixel_app/sepolicy/common/keys.conf
@@ -0,0 +1,2 @@
+[@EUICCSUPPORTPIXEL]
+ALL : device/google/gs-common/euiccpixel_app/sepolicy/common/certs/EuiccSupportPixel.x509.pem
diff --git a/euiccpixel_app/sepolicy/common/mac_permissions.xml b/euiccpixel_app/sepolicy/common/mac_permissions.xml
new file mode 100644
index 0000000..0eab982
--- /dev/null
+++ b/euiccpixel_app/sepolicy/common/mac_permissions.xml
@@ -0,0 +1,27 @@
+<?xml version="1.0" encoding="utf-8"?>
+<policy>
+
+<!--
+
+    * A signature is a hex encoded X.509 certificate or a tag defined in
+      keys.conf and is required for each signer tag.
+    * A signer tag may contain a seinfo tag and multiple package stanzas.
+    * A default tag is allowed that can contain policy for all apps not signed with a
+      previously listed cert. It may not contain any inner package stanzas.
+    * Each signer/default/package tag is allowed to contain one seinfo tag. This tag
+      represents additional info that each app can use in setting a SELinux security
+      context on the eventual process.
+    * When a package is installed the following logic is used to determine what seinfo
+      value, if any, is assigned.
+      - All signatures used to sign the app are checked first.
+      - If a signer stanza has inner package stanzas, those stanza will be checked
+        to try and match the package name of the app. If the package name matches
+        then that seinfo tag is used. If no inner package matches then the outer
+        seinfo tag is assigned.
+      - The default tag is consulted last if needed.
+-->
+    <!-- google apps key -->
+    <signer signature="@EUICCSUPPORTPIXEL" >
+        <seinfo value="EuiccSupportPixel" />
+    </signer>
+</policy>
diff --git a/euiccpixel_app/sepolicy/common/seapp_contexts b/euiccpixel_app/sepolicy/common/seapp_contexts
new file mode 100644
index 0000000..9501a3a
--- /dev/null
+++ b/euiccpixel_app/sepolicy/common/seapp_contexts
@@ -0,0 +1,2 @@
+# Domain for EuiccSupportPixel
+user=_app isPrivApp=true seinfo=EuiccSupportPixel name=com.google.euiccpixel domain=euiccpixel_app type=app_data_file levelFrom=all
diff --git a/euiccpixel_app/sepolicy/st54/euiccpixel_app.te b/euiccpixel_app/sepolicy/st54/euiccpixel_app.te
new file mode 100644
index 0000000..3d81a57
--- /dev/null
+++ b/euiccpixel_app/sepolicy/st54/euiccpixel_app.te
@@ -0,0 +1,8 @@
+# euiccpixel requires st54spi for firmware upgrade
+userdebug_or_eng(`
+    net_domain(euiccpixel_app)
+
+    # Access to directly upgrade firmware on st54spi_device used for engineering devices
+    typeattribute st54spi_device mlstrustedobject;
+    allow euiccpixel_app st54spi_device:chr_file rw_file_perms;
+')
diff --git a/gcam_app/gcam.mk b/gcam_app/gcam.mk
new file mode 100644
index 0000000..38c7b69
--- /dev/null
+++ b/gcam_app/gcam.mk
@@ -0,0 +1,8 @@
+# vendor
+BOARD_SEPOLICY_DIRS += device/google/gs-common/gcam_app/sepolicy/vendor
+
+# product
+PRODUCT_PUBLIC_SEPOLICY_DIRS += device/google/gs-common/gcam_app/sepolicy/product/public
+PRODUCT_PRIVATE_SEPOLICY_DIRS += device/google/gs-common/gcam_app/sepolicy//product/private
+
+PRODUCT_PACKAGES += GoogleCamera
diff --git a/gcam_app/sepolicy/product/private/debug_camera_app.te b/gcam_app/sepolicy/product/private/debug_camera_app.te
new file mode 100644
index 0000000..4402e55
--- /dev/null
+++ b/gcam_app/sepolicy/product/private/debug_camera_app.te
@@ -0,0 +1,29 @@
+# GCANext and GCAEng.
+# b/363018500
+typeattribute debug_camera_app coredomain;
+
+userdebug_or_eng(`
+	app_domain(debug_camera_app)
+	net_domain(debug_camera_app)
+
+	allow debug_camera_app activity_service:service_manager find;
+	allow debug_camera_app activity_task_service:service_manager find;
+	allow debug_camera_app audioserver_service:service_manager find;
+	allow debug_camera_app batterystats_service:service_manager find;
+	allow debug_camera_app cameraserver_service:service_manager find;
+	allow debug_camera_app device_policy_service:service_manager find;
+	allow debug_camera_app device_state_service:service_manager find;
+	allow debug_camera_app gpu_service:service_manager find;
+	allow debug_camera_app mediaextractor_service:service_manager find;
+	allow debug_camera_app mediametrics_service:service_manager find;
+	allow debug_camera_app mediaserver_service:service_manager find;
+	allow debug_camera_app powerstats_service:service_manager find;
+	allow debug_camera_app sensorservice_service:service_manager find;
+	allow debug_camera_app thermal_service:service_manager find;
+	allow debug_camera_app trust_service:service_manager find;
+	allow debug_camera_app vibrator_manager_service:service_manager find;
+	allow debug_camera_app virtual_device_native_service:service_manager find;
+
+	# Allows GCA_Eng & GCA-Next to access the PowerHAL.
+	hal_client_domain(debug_camera_app, hal_power)
+')
diff --git a/gcam_app/sepolicy/product/private/google_camera_app.te b/gcam_app/sepolicy/product/private/google_camera_app.te
new file mode 100644
index 0000000..a4c7a79
--- /dev/null
+++ b/gcam_app/sepolicy/product/private/google_camera_app.te
@@ -0,0 +1,17 @@
+# GCARelease and GCADogfood.
+typeattribute google_camera_app coredomain;
+app_domain(google_camera_app)
+net_domain(google_camera_app)
+
+#allow google_camera_app app_api_service:service_manager find;
+#allow google_camera_app audioserver_service:service_manager find;
+#allow google_camera_app cameraserver_service:service_manager find;
+#allow google_camera_app mediaextractor_service:service_manager find;
+#allow google_camera_app mediametrics_service:service_manager find;
+#allow google_camera_app mediaserver_service:service_manager find;
+
+# Allows GCA to access the PowerHAL.
+hal_client_domain(google_camera_app, hal_power)
+
+# Library code may try to access vendor properties, but should be denied
+dontaudit google_camera_app vendor_default_prop:file { getattr map open };
diff --git a/gcam_app/sepolicy/product/private/seapp_contexts b/gcam_app/sepolicy/product/private/seapp_contexts
new file mode 100644
index 0000000..9ba54b7
--- /dev/null
+++ b/gcam_app/sepolicy/product/private/seapp_contexts
@@ -0,0 +1,12 @@
+# Google Camera
+user=_app isPrivApp=true seinfo=google name=com.google.android.GoogleCamera domain=google_camera_app type=app_data_file levelFrom=all
+
+# Google Camera Eng
+user=_app seinfo=CameraEng name=com.google.android.GoogleCameraEng domain=debug_camera_app type=app_data_file levelFrom=all
+
+# Also allow GoogleCameraNext, the fishfood version, the same access as GoogleCamera
+user=_app seinfo=CameraFishfood name=com.google.android.apps.googlecamera.fishfood domain=google_camera_app type=app_data_file levelFrom=all
+
+# Also label GoogleCameraNext, built with debug keys as debug_camera_app.
+user=_app seinfo=CameraEng name=com.google.android.apps.googlecamera.fishfood domain=debug_camera_app type=app_data_file levelFrom=all
+
diff --git a/gcam_app/sepolicy/product/public/debug_camera_app.te b/gcam_app/sepolicy/product/public/debug_camera_app.te
new file mode 100644
index 0000000..0572eee
--- /dev/null
+++ b/gcam_app/sepolicy/product/public/debug_camera_app.te
@@ -0,0 +1,2 @@
+# GCA-Eng and GCA-Next
+type debug_camera_app, domain;
diff --git a/gcam_app/sepolicy/product/public/google_camera_app.te b/gcam_app/sepolicy/product/public/google_camera_app.te
new file mode 100644
index 0000000..a8d6512
--- /dev/null
+++ b/gcam_app/sepolicy/product/public/google_camera_app.te
@@ -0,0 +1,2 @@
+# GCA-Release and GCA-Dogfood
+type google_camera_app, domain;
diff --git a/gcam_app/sepolicy/vendor/certs/app.x509.pem b/gcam_app/sepolicy/vendor/certs/app.x509.pem
new file mode 100644
index 0000000..8e3e627
--- /dev/null
+++ b/gcam_app/sepolicy/vendor/certs/app.x509.pem
@@ -0,0 +1,27 @@
+-----BEGIN CERTIFICATE-----
+MIIEqDCCA5CgAwIBAgIJANWFuGx90071MA0GCSqGSIb3DQEBBAUAMIGUMQswCQYD
+VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTW91bnRhaW4g
+VmlldzEQMA4GA1UEChMHQW5kcm9pZDEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UE
+AxMHQW5kcm9pZDEiMCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTAe
+Fw0wODA0MTUyMzM2NTZaFw0zNTA5MDEyMzM2NTZaMIGUMQswCQYDVQQGEwJVUzET
+MBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4G
+A1UEChMHQW5kcm9pZDEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UEAxMHQW5kcm9p
+ZDEiMCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTCCASAwDQYJKoZI
+hvcNAQEBBQADggENADCCAQgCggEBANbOLggKv+IxTdGNs8/TGFy0PTP6DHThvbbR
+24kT9ixcOd9W+EaBPWW+wPPKQmsHxajtWjmQwWfna8mZuSeJS48LIgAZlKkpFeVy
+xW0qMBujb8X8ETrWy550NaFtI6t9+u7hZeTfHwqNvacKhp1RbE6dBRGWynwMVX8X
+W8N1+UjFaq6GCJukT4qmpN2afb8sCjUigq0GuMwYXrFVee74bQgLHWGJwPmvmLHC
+69EH6kWr22ijx4OKXlSIx2xT1AsSHee70w5iDBiK4aph27yH3TxkXy9V89TDdexA
+cKk/cVHYNnDBapcavl7y0RiQ4biu8ymM8Ga/nmzhRKya6G0cGw8CAQOjgfwwgfkw
+HQYDVR0OBBYEFI0cxb6VTEM8YYY6FbBMvAPyT+CyMIHJBgNVHSMEgcEwgb6AFI0c
+xb6VTEM8YYY6FbBMvAPyT+CyoYGapIGXMIGUMQswCQYDVQQGEwJVUzETMBEGA1UE
+CBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4GA1UEChMH
+QW5kcm9pZDEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UEAxMHQW5kcm9pZDEiMCAG
+CSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbYIJANWFuGx90071MAwGA1Ud
+EwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADggEBABnTDPEF+3iSP0wNfdIjIz1AlnrP
+zgAIHVvXxunW7SBrDhEglQZBbKJEk5kT0mtKoOD1JMrSu1xuTKEBahWRbqHsXcla
+XjoBADb0kkjVEJu/Lh5hgYZnOjvlba8Ld7HCKePCVePoTJBdI4fvugnL8TsgK05a
+IskyY0hKI9L8KfqfGTl1lzOv2KoWD0KWwtAWPoGChZxmQ+nBli+gwYMzM1vAkP+a
+ayLe0a1EQimlOalO762r0GXO0ks+UeXde2Z4e+8S/pf7pITEI/tP+MxJTALw9QUW
+Ev9lKTk+jkbqxbsh8nfBUapfKqYn0eidpwq2AzVp3juYl7//fKnaPhJD9gs=
+-----END CERTIFICATE-----
diff --git a/gcam_app/sepolicy/vendor/certs/camera_eng.x509.pem b/gcam_app/sepolicy/vendor/certs/camera_eng.x509.pem
new file mode 100644
index 0000000..011a9ec
--- /dev/null
+++ b/gcam_app/sepolicy/vendor/certs/camera_eng.x509.pem
@@ -0,0 +1,17 @@
+-----BEGIN CERTIFICATE-----
+MIICpzCCAmWgAwIBAgIEUAV8QjALBgcqhkjOOAQDBQAwNzELMAkGA1UEBhMCVVMx
+EDAOBgNVBAoTB0FuZHJvaWQxFjAUBgNVBAMTDUFuZHJvaWQgRGVidWcwHhcNMTIw
+NzE3MTQ1MjUwWhcNMjIwNzE1MTQ1MjUwWjA3MQswCQYDVQQGEwJVUzEQMA4GA1UE
+ChMHQW5kcm9pZDEWMBQGA1UEAxMNQW5kcm9pZCBEZWJ1ZzCCAbcwggEsBgcqhkjO
+OAQBMIIBHwKBgQD9f1OBHXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR
++1k9jVj6v8X1ujD2y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb
++DtX58aophUPBPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdg
+UI8VIwvMspK5gqLrhAvwWBz1AoGBAPfhoIXWmz3ey7yrXDa4V7l5lK+7+jrqgvlX
+TAs9B4JnUVlXjrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozIpuE8FnqLVHyNKOCj
+rh4rs6Z1kW6jfwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4VrlnwaSi2ZegHtVJWQB
+TDv+z0kqA4GEAAKBgGrRG9fVZtJ69DnALkForP1FtL6FvJmMe5uOHHdUaT+MDUKK
+pPzhEISBOEJPpozRMFJO7/bxNzhjgi+mNymL/k1GoLhmZe7wQRc5AQNbHIBqoxgY
+DTA6qMyeWSPgam+r+nVoPEU7sgd3fPL958+xmxQwOBSqHfe0PVsiK1cGtIuUMAsG
+ByqGSM44BAMFAAMvADAsAhQJ0tGwRwIptb7SkCZh0RLycMXmHQIUZ1ACBqeAULp4
+rscXTxYEf4Tqovc=
+-----END CERTIFICATE-----
diff --git a/gcam_app/sepolicy/vendor/certs/camera_fishfood.x509.pem b/gcam_app/sepolicy/vendor/certs/camera_fishfood.x509.pem
new file mode 100644
index 0000000..fb11572
--- /dev/null
+++ b/gcam_app/sepolicy/vendor/certs/camera_fishfood.x509.pem
@@ -0,0 +1,15 @@
+-----BEGIN CERTIFICATE-----
+MIICUjCCAbsCBEk0mH4wDQYJKoZIhvcNAQEEBQAwcDELMAkGA1UEBhMCVVMxCzAJ
+BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRQwEgYDVQQKEwtHb29n
+bGUsIEluYzEUMBIGA1UECxMLR29vZ2xlLCBJbmMxEDAOBgNVBAMTB1Vua25vd24w
+HhcNMDgxMjAyMDIwNzU4WhcNMzYwNDE5MDIwNzU4WjBwMQswCQYDVQQGEwJVUzEL
+MAkGA1UECBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxFDASBgNVBAoTC0dv
+b2dsZSwgSW5jMRQwEgYDVQQLEwtHb29nbGUsIEluYzEQMA4GA1UEAxMHVW5rbm93
+bjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAn0gDGZD5sUcmOE4EU9GPjAu/
+jcd7JQSksSB8TGxEurwArcZhD6a2qy2oDjPy7vFrJqP2uFua+sqQn/u+s/TJT36B
+IqeY4OunXO090in6c2X0FRZBWqnBYX3Vg84Zuuigu9iF/BeptL0mQIBRIarbk3fe
+tAATOBQYiC7FIoL8WA0CAwEAATANBgkqhkiG9w0BAQQFAAOBgQBAhmae1jHaQ4Td
+0GHSJuBzuYzEuZ34teS+njy+l1Aeg98cb6lZwM5gXE/SrG0chM7eIEdsurGb6PIg
+Ov93F61lLY/MiQcI0SFtqERXWSZJ4OnTxLtM9Y2hnbHU/EG8uVhPZOZfQQ0FKf1b
+aIOMFB0Km9HbEZHLKg33kOoMsS2zpA==
+-----END CERTIFICATE-----
diff --git a/gcam_app/sepolicy/vendor/debug_camera_app.te b/gcam_app/sepolicy/vendor/debug_camera_app.te
new file mode 100644
index 0000000..8cac086
--- /dev/null
+++ b/gcam_app/sepolicy/vendor/debug_camera_app.te
@@ -0,0 +1,16 @@
+# GCANext and GCAEng.
+userdebug_or_eng(`
+    # Allows GCA-Eng & GCA-Next access the GXP device and properties.
+    allow debug_camera_app gxp_device:chr_file rw_file_perms;
+    get_prop(debug_camera_app, vendor_gxp_prop)
+
+    # Allows GCA-Eng & GCA-Next to find and access the EdgeTPU.
+    allow debug_camera_app edgetpu_app_service:service_manager find;
+    allow debug_camera_app edgetpu_device:chr_file { read write ioctl };
+    # Cannot find avc evidence for below.
+    # allow debug_camera_app edgetpu_device:chr_file { getattr map };
+
+    # Allows GCA_Eng & GCA-Next to access the hw_jpeg /dev/video12.
+    # allow debug_camera_app hw_jpg_device:chr_file rw_file_perms;
+')
+
diff --git a/gcam_app/sepolicy/vendor/google_camera_app.te b/gcam_app/sepolicy/vendor/google_camera_app.te
new file mode 100644
index 0000000..81f91ac
--- /dev/null
+++ b/gcam_app/sepolicy/vendor/google_camera_app.te
@@ -0,0 +1,13 @@
+# GCARelease and GCADogfood.
+
+# Allows GCA to acccess the GXP device & properties.
+#allow google_camera_app gxp_device:chr_file rw_file_perms;
+get_prop(google_camera_app, vendor_gxp_prop)
+
+# Allows GCA to find and access the EdgeTPU.
+#allow google_camera_app edgetpu_app_service:service_manager find;
+#allow google_camera_app edgetpu_device:chr_file { getattr read write ioctl map };
+
+# Allows GCA to access the hw_jpeg /dev/video12.
+#allow google_camera_app hw_jpg_device:chr_file rw_file_perms;
+
diff --git a/gcam_app/sepolicy/vendor/keys.conf b/gcam_app/sepolicy/vendor/keys.conf
new file mode 100644
index 0000000..92e5ae2
--- /dev/null
+++ b/gcam_app/sepolicy/vendor/keys.conf
@@ -0,0 +1,8 @@
+[@GOOGLE]
+ALL : device/google/gs-common/gcam_app/sepolicy/vendor/certs/app.x509.pem
+
+[@CAMERAENG]
+ALL : device/google/gs-common/gcam_app/sepolicy/vendor/certs/camera_eng.x509.pem
+
+[@CAMERAFISHFOOD]
+ALL : device/google/gs-common/gcam_app/sepolicy/vendor/certs/camera_fishfood.x509.pem
diff --git a/gcam_app/sepolicy/vendor/mac_permissions.xml b/gcam_app/sepolicy/vendor/mac_permissions.xml
new file mode 100644
index 0000000..12d9b1a
--- /dev/null
+++ b/gcam_app/sepolicy/vendor/mac_permissions.xml
@@ -0,0 +1,34 @@
+<?xml version="1.0" encoding="utf-8"?>
+<policy>
+
+<!--
+
+    * A signature is a hex encoded X.509 certificate or a tag defined in
+      keys.conf and is required for each signer tag.
+    * A signer tag may contain a seinfo tag and multiple package stanzas.
+    * A default tag is allowed that can contain policy for all apps not signed with a
+      previously listed cert. It may not contain any inner package stanzas.
+    * Each signer/default/package tag is allowed to contain one seinfo tag. This tag
+      represents additional info that each app can use in setting a SELinux security
+      context on the eventual process.
+    * When a package is installed the following logic is used to determine what seinfo
+      value, if any, is assigned.
+      - All signatures used to sign the app are checked first.
+      - If a signer stanza has inner package stanzas, those stanza will be checked
+        to try and match the package name of the app. If the package name matches
+        then that seinfo tag is used. If no inner package matches then the outer
+        seinfo tag is assigned.
+      - The default tag is consulted last if needed.
+-->
+    <!-- google apps key -->
+    <signer signature="@GOOGLE" >
+      <seinfo value="google" />
+    </signer>
+    <signer signature="@CAMERAENG" >
+      <seinfo value="CameraEng" />
+    </signer>
+    <signer signature="@CAMERAFISHFOOD" >
+      <seinfo value="CameraFishFood" />
+    </signer>
+
+</policy>
diff --git a/gps/brcm/sepolicy/genfs_contexts b/gps/brcm/sepolicy/genfs_contexts
index 446fc45..a551e96 100644
--- a/gps/brcm/sepolicy/genfs_contexts
+++ b/gps/brcm/sepolicy/genfs_contexts
@@ -1,3 +1,4 @@
 # GPS
 genfscon sysfs /devices/virtual/pps/pps0/assert_elapsed                         u:object_r:sysfs_gps_assert:s0
+genfscon sysfs /devices/platform/bbd_pps/pps_assert                             u:object_r:sysfs_gps_assert:s0
 
diff --git a/gps/lsi/sepolicy/gnssd.te b/gps/lsi/sepolicy/gnssd.te
index a293b95..29dfa2e 100644
--- a/gps/lsi/sepolicy/gnssd.te
+++ b/gps/lsi/sepolicy/gnssd.te
@@ -5,7 +5,9 @@ init_daemon_domain(gnssd);
 # Allow gnssd to access rild
 binder_call(gnssd, rild);
 binder_call(gnssd, hwservicemanager)
+binder_call(gnssd, servicemanager)
 allow gnssd hal_exynos_rild_hwservice:hwservice_manager find;
+allow gnssd hal_vendor_radio_external_service:service_manager find;
 allow gnssd radio_device:chr_file rw_file_perms;
 
 # Allow gnssd to acess gnss device
diff --git a/gps/pixel/sepolicy/hal_gnss_pixel.te b/gps/pixel/sepolicy/hal_gnss_pixel.te
index cc63702..e3e4d92 100644
--- a/gps/pixel/sepolicy/hal_gnss_pixel.te
+++ b/gps/pixel/sepolicy/hal_gnss_pixel.te
@@ -10,6 +10,9 @@ allow hal_gnss_pixel sysfs_gps:file rw_file_perms;
 # Allow access to CHRE multiclient HAL.
 get_prop(hal_gnss_pixel, vendor_chre_hal_prop)
 
+# Allow read vendor gps prop.
+get_prop(hal_gnss_pixel, vendor_gps_prop)
+
 # Allow binder to CHRE.
 binder_call(hal_gnss_pixel, hal_contexthub_default)
 allow hal_gnss_pixel hal_contexthub_service:service_manager find;
diff --git a/gpu/MK_OWNERS b/gpu/MK_OWNERS
new file mode 100644
index 0000000..1d0be18
--- /dev/null
+++ b/gpu/MK_OWNERS
@@ -0,0 +1,4 @@
+jessehall@google.com
+spyffe@google.com
+jorwag@google.com
+jeremykemp@google.com
diff --git a/gpu/OWNERS b/gpu/OWNERS
new file mode 100644
index 0000000..259dd93
--- /dev/null
+++ b/gpu/OWNERS
@@ -0,0 +1,2 @@
+per-file gpu.mk=set noparent
+per-file gpu.mk=file:MK_OWNERS
diff --git a/gpu/gpu.mk b/gpu/gpu.mk
index b87e7ad..4b11e13 100644
--- a/gpu/gpu.mk
+++ b/gpu/gpu.mk
@@ -2,15 +2,15 @@ BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/gpu/sepolicy
 
 PRODUCT_PACKAGES += gpu_probe
 
-USE_MAPPER5 := false
+USE_MAPPER5 := true
 
 PRODUCT_PACKAGES += pixel_gralloc_allocator
 PRODUCT_PACKAGES += pixel_gralloc_mapper
 
 ifeq ($(USE_MAPPER5), true)
-$(call soong_config_set,arm_gralloc,mapper_version,mapper5)
+$(call soong_config_set,pixel_gralloc,mapper_version,mapper5)
 $(call soong_config_set,aion_buffer,mapper_version,mapper5)
 else
-$(call soong_config_set,arm_gralloc,mapper_version,mapper4)
+$(call soong_config_set,pixel_gralloc,mapper_version,mapper4)
 $(call soong_config_set,aion_buffer,mapper_version,mapper4)
 endif
diff --git a/gril/aidl/2.0/compatibility_matrix.xml b/gril/aidl/2.0/compatibility_matrix.xml
new file mode 100644
index 0000000..8a4a776
--- /dev/null
+++ b/gril/aidl/2.0/compatibility_matrix.xml
@@ -0,0 +1,10 @@
+<compatibility-matrix version="1.0" type="framework">
+    <hal format="aidl" optional="true">
+        <name>vendor.google.radio_ext</name>
+        <version>2</version>
+        <interface>
+            <name>IRadioExt</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+</compatibility-matrix>
diff --git a/gril/aidl/2.0/gril_aidl.mk b/gril/aidl/2.0/gril_aidl.mk
new file mode 100644
index 0000000..d4fa9e9
--- /dev/null
+++ b/gril/aidl/2.0/gril_aidl.mk
@@ -0,0 +1,4 @@
+PRODUCT_PACKAGES += vendor.google.radioext@1.0-service
+DEVICE_PRODUCT_COMPATIBILITY_MATRIX_FILE += device/google/gs-common/gril/aidl/2.0/compatibility_matrix.xml
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/gril/aidl/2.0/sepolicy
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/gril/common/sepolicy
diff --git a/gril/aidl/2.0/sepolicy/file_contexts b/gril/aidl/2.0/sepolicy/file_contexts
new file mode 100644
index 0000000..9973b80
--- /dev/null
+++ b/gril/aidl/2.0/sepolicy/file_contexts
@@ -0,0 +1 @@
+/vendor/bin/hw/vendor\.google\.radioext@1\.0-service                        u:object_r:hal_aidl_radio_ext_exec:s0
diff --git a/gril/aidl/2.0/sepolicy/grilservice_app.te b/gril/aidl/2.0/sepolicy/grilservice_app.te
new file mode 100644
index 0000000..812c8a2
--- /dev/null
+++ b/gril/aidl/2.0/sepolicy/grilservice_app.te
@@ -0,0 +1,4 @@
+# allow grilservice_app to find hal_radio_ext_service
+allow grilservice_app hal_radio_ext_service:service_manager find;
+binder_call(grilservice_app, hal_aidl_radio_ext)
+binder_call(grilservice_app, twoshay)
diff --git a/gril/aidl/2.0/sepolicy/hal_aidl_radio_ext.te b/gril/aidl/2.0/sepolicy/hal_aidl_radio_ext.te
new file mode 100644
index 0000000..68dd397
--- /dev/null
+++ b/gril/aidl/2.0/sepolicy/hal_aidl_radio_ext.te
@@ -0,0 +1,33 @@
+# hal_aidl_radio_ext domain
+type hal_aidl_radio_ext, domain;
+type hal_aidl_radio_ext_exec, vendor_file_type, exec_type, file_type;
+
+init_daemon_domain(hal_aidl_radio_ext)
+
+get_prop(hal_aidl_radio_ext, hwservicemanager_prop)
+get_prop(hal_aidl_radio_ext, telephony_modemtype_prop)
+set_prop(hal_aidl_radio_ext, vendor_gril_prop)
+
+binder_call(hal_aidl_radio_ext, servicemanager)
+binder_call(hal_aidl_radio_ext, grilservice_app)
+binder_call(hal_aidl_radio_ext, hal_bluetooth_btlinux)
+
+add_service(hal_aidl_radio_ext, hal_radio_ext_service)
+
+# RW /dev/oem_ipc0
+allow hal_aidl_radio_ext radio_device:chr_file rw_file_perms;
+
+# RW MIPI Freq files
+allow hal_aidl_radio_ext radio_vendor_data_file:dir create_dir_perms;
+allow hal_aidl_radio_ext radio_vendor_data_file:file create_file_perms;
+
+# Bluetooth
+allow hal_aidl_radio_ext hal_bluetooth_coexistence_hwservice:hwservice_manager find;
+allow hal_aidl_radio_ext hal_bluetooth_coexistence_service:service_manager find;
+
+# Allow access to the backlight driver to set ssc_mode
+allow hal_aidl_radio_ext sysfs_leds:dir search;
+allow hal_aidl_radio_ext sysfs_leds:file rw_file_perms;
+
+# legacy/zuma/vendor
+allow hal_aidl_radio_ext sysfs_display:file rw_file_perms;
diff --git a/gril/aidl/2.0/sepolicy/hal_camera_default.te b/gril/aidl/2.0/sepolicy/hal_camera_default.te
new file mode 100644
index 0000000..61f8001
--- /dev/null
+++ b/gril/aidl/2.0/sepolicy/hal_camera_default.te
@@ -0,0 +1,2 @@
+# allow hal_camera_default to binder call hal_aidl_radio_ext
+binder_call(hal_camera_default, hal_aidl_radio_ext);
diff --git a/gril/aidl/2.0/sepolicy/twoshay.te b/gril/aidl/2.0/sepolicy/twoshay.te
new file mode 100644
index 0000000..f7d3fe1
--- /dev/null
+++ b/gril/aidl/2.0/sepolicy/twoshay.te
@@ -0,0 +1,2 @@
+# allow twoshay to binder call hal_aidl_radio_ext
+binder_call(twoshay, hal_aidl_radio_ext)
diff --git a/modem/radio_ext/sepolicy/service.te b/gril/common/sepolicy/service.te
similarity index 68%
rename from modem/radio_ext/sepolicy/service.te
rename to gril/common/sepolicy/service.te
index 7288ef1..ee6fb77 100644
--- a/modem/radio_ext/sepolicy/service.te
+++ b/gril/common/sepolicy/service.te
@@ -1,2 +1,3 @@
 # Radio Ext AIDL service
+# Shared definition so a single type is referenced
 type hal_radio_ext_service, hal_service_type, protected_service, service_manager_type;
diff --git a/gril/common/sepolicy/service_contexts b/gril/common/sepolicy/service_contexts
new file mode 100644
index 0000000..7e50c2e
--- /dev/null
+++ b/gril/common/sepolicy/service_contexts
@@ -0,0 +1 @@
+vendor.google.radio_ext.IRadioExt/default                 u:object_r:hal_radio_ext_service:s0
diff --git a/gril/hidl/1.7/compatibility_matrix.xml b/gril/hidl/1.7/compatibility_matrix.xml
new file mode 100644
index 0000000..6129633
--- /dev/null
+++ b/gril/hidl/1.7/compatibility_matrix.xml
@@ -0,0 +1,10 @@
+<compatibility-matrix version="1.0" type="framework">
+    <hal format="hidl" optional="true">
+        <name>vendor.google.radioext</name>
+        <version>1.7</version>
+        <interface>
+            <name>IRadioExt</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+</compatibility-matrix>
diff --git a/gril/hidl/1.7/gril_hidl.mk b/gril/hidl/1.7/gril_hidl.mk
new file mode 100644
index 0000000..0008a5d
--- /dev/null
+++ b/gril/hidl/1.7/gril_hidl.mk
@@ -0,0 +1,4 @@
+PRODUCT_PACKAGES += vendor.google.radioext@1.0-service
+DEVICE_PRODUCT_COMPATIBILITY_MATRIX_FILE += device/google/gs-common/gril/hidl/1.7/compatibility_matrix.xml
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/gril/hidl/1.7/sepolicy
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/gril/common/sepolicy
diff --git a/gril/hidl/1.7/sepolicy/file_contexts b/gril/hidl/1.7/sepolicy/file_contexts
new file mode 100644
index 0000000..dea8592
--- /dev/null
+++ b/gril/hidl/1.7/sepolicy/file_contexts
@@ -0,0 +1 @@
+/vendor/bin/hw/vendor\.google\.radioext@1\.0-service                        u:object_r:hal_radioext_default_exec:s0
diff --git a/gril/hidl/1.7/sepolicy/grilservice_app.te b/gril/hidl/1.7/sepolicy/grilservice_app.te
new file mode 100644
index 0000000..3a170b8
--- /dev/null
+++ b/gril/hidl/1.7/sepolicy/grilservice_app.te
@@ -0,0 +1,4 @@
+# allow grilservice_app to find hal_radio_ext_service
+allow grilservice_app hal_radio_ext_service:service_manager find;
+# allow grilservice_app to binder call hal_radioext_default
+binder_call(grilservice_app, hal_radioext_default)
diff --git a/gril/hidl/1.7/sepolicy/hal_camera_default.te b/gril/hidl/1.7/sepolicy/hal_camera_default.te
new file mode 100644
index 0000000..36bdd7e
--- /dev/null
+++ b/gril/hidl/1.7/sepolicy/hal_camera_default.te
@@ -0,0 +1,2 @@
+# allow hal_camera_default to binder call hal_radioext_default
+binder_call(hal_camera_default, hal_radioext_default);
diff --git a/gril/hidl/1.7/sepolicy/hal_radioext_default.te b/gril/hidl/1.7/sepolicy/hal_radioext_default.te
new file mode 100644
index 0000000..6931fb7
--- /dev/null
+++ b/gril/hidl/1.7/sepolicy/hal_radioext_default.te
@@ -0,0 +1,28 @@
+# hal_radioext_default domain
+type hal_radioext_default, domain;
+type hal_radioext_default_exec, vendor_file_type, exec_type, file_type;
+init_daemon_domain(hal_radioext_default)
+
+hwbinder_use(hal_radioext_default)
+get_prop(hal_radioext_default, hwservicemanager_prop)
+get_prop(hal_radioext_default, telephony_modemtype_prop)
+set_prop(hal_radioext_default, vendor_gril_prop)
+add_hwservice(hal_radioext_default, hal_radioext_hwservice)
+
+binder_call(hal_radioext_default, servicemanager)
+binder_call(hal_radioext_default, grilservice_app)
+binder_call(hal_radioext_default, hal_bluetooth_btlinux)
+
+# RW /dev/oem_ipc0
+allow hal_radioext_default radio_device:chr_file rw_file_perms;
+
+# RW MIPI Freq files
+allow hal_radioext_default radio_vendor_data_file:dir create_dir_perms;
+allow hal_radioext_default radio_vendor_data_file:file create_file_perms;
+
+# Bluetooth
+allow hal_radioext_default hal_bluetooth_coexistence_hwservice:hwservice_manager find;
+allow hal_radioext_default hal_bluetooth_coexistence_service:service_manager find;
+
+# legacy/zuma/vendor
+allow hal_radioext_default sysfs_display:file rw_file_perms;
diff --git a/gril/hidl/1.7/sepolicy/hwservice_contexts b/gril/hidl/1.7/sepolicy/hwservice_contexts
new file mode 100644
index 0000000..5589c31
--- /dev/null
+++ b/gril/hidl/1.7/sepolicy/hwservice_contexts
@@ -0,0 +1,2 @@
+# GRIL HAL
+vendor.google.radioext::IRadioExt                                                  u:object_r:hal_radioext_hwservice:s0
diff --git a/gril/hidl/1.7/sepolicy/twoshay.te b/gril/hidl/1.7/sepolicy/twoshay.te
new file mode 100644
index 0000000..75c3b27
--- /dev/null
+++ b/gril/hidl/1.7/sepolicy/twoshay.te
@@ -0,0 +1,2 @@
+# allow twoshay to binder call hal_radioext_default
+binder_call(twoshay, hal_radioext_default)
diff --git a/gs_watchdogd/gs_watchdogd.cpp b/gs_watchdogd/gs_watchdogd.cpp
index 82e01d0..333e023 100644
--- a/gs_watchdogd/gs_watchdogd.cpp
+++ b/gs_watchdogd/gs_watchdogd.cpp
@@ -19,37 +19,30 @@
 #include <android-base/logging.h>
 #include <android-base/stringprintf.h>
 #include <android-base/unique_fd.h>
+#include <log/log.h>
 
-#include <errno.h>
 #include <fcntl.h>
 #include <glob.h>
 #include <linux/watchdog.h>
 #include <stdlib.h>
 #include <string.h>
+#include <sys/cdefs.h>
 #include <unistd.h>
 
-#include <chrono>
+#include <cstdlib>
 #include <vector>
 
-#define DEV_GLOB "/sys/devices/platform/*.watchdog_cl*/watchdog/watchdog*"
+#define NSEC_PER_SEC (1000LL * 1000LL * 1000LL)
 
-#define DEFAULT_INTERVAL 10s
-#define DEFAULT_MARGIN 10s
+#define DEV_GLOB "/sys/devices/platform/*.watchdog_cl*/watchdog/watchdog*"
 
 using android::base::Basename;
 using android::base::StringPrintf;
-using std::literals::chrono_literals::operator""s;
-
-int main(int argc, char** argv) {
-    android::base::InitLogging(argv, &android::base::KernelLogger);
 
-    std::chrono::seconds interval = argc >= 2
-        ? std::chrono::seconds(atoi(argv[1])) : DEFAULT_INTERVAL;
-    std::chrono::seconds margin = argc >= 3
-        ? std::chrono::seconds(atoi(argv[2])) : DEFAULT_MARGIN;
+int main(int __unused argc, char** argv) {
+    auto min_timeout_nsecs = std::numeric_limits<typeof(NSEC_PER_SEC)>::max();
 
-    LOG(INFO) << "gs_watchdogd started (interval " << interval.count()
-              << ", margin " << margin.count() << ")!";
+    android::base::InitLogging(argv, &android::base::KernelLogger);
 
     glob_t globbuf;
     int ret = glob(DEV_GLOB, GLOB_MARK, nullptr, &globbuf);
@@ -61,8 +54,7 @@ int main(int argc, char** argv) {
     std::vector<android::base::unique_fd> wdt_dev_fds;
 
     for (size_t i = 0; i < globbuf.gl_pathc; i++) {
-        std::chrono::seconds timeout = interval + margin;
-        int timeout_secs = timeout.count();
+        int timeout_secs;
         std::string dev_path = StringPrintf("/dev/%s", Basename(globbuf.gl_pathv[i]).c_str());
 
         int fd = TEMP_FAILURE_RETRY(open(dev_path.c_str(), O_RDWR | O_CLOEXEC));
@@ -71,29 +63,39 @@ int main(int argc, char** argv) {
             return 1;
         }
 
-        wdt_dev_fds.emplace_back(fd);
-        ret = ioctl(fd, WDIOC_SETTIMEOUT, &timeout_secs);
+        ret = ioctl(fd, WDIOC_GETTIMEOUT, &timeout_secs);
         if (ret) {
-            PLOG(ERROR) << "Failed to set timeout to " << timeout_secs;
-            ret = ioctl(fd, WDIOC_GETTIMEOUT, &timeout_secs);
-            if (ret) {
-                PLOG(ERROR) << "Failed to get timeout";
-            } else {
-                interval = timeout > margin ? timeout - margin : 1s;
-                LOG(WARNING) << "Adjusted interval to timeout returned by driver: "
-                             << "timeout " << timeout_secs
-                             << ", interval " << interval.count()
-                             << ", margin " << margin.count();
-            }
+            PLOG(ERROR) << "Failed to get timeout on " << dev_path;
+            continue;
+        } else {
+            min_timeout_nsecs = std::min(min_timeout_nsecs, NSEC_PER_SEC * timeout_secs);
         }
+
+        wdt_dev_fds.emplace_back(fd);
     }
 
     globfree(&globbuf);
 
+    if (wdt_dev_fds.empty()) {
+        LOG(ERROR) << "no valid wdt dev found";
+        return 1;
+    }
+
+    timespec ts;
+    auto result = div(min_timeout_nsecs / 2, NSEC_PER_SEC);
+    ts.tv_sec = result.quot;
+    ts.tv_nsec = result.rem;
+
     while (true) {
+        timespec rem = ts;
+
         for (const auto& fd : wdt_dev_fds) {
             TEMP_FAILURE_RETRY(write(fd, "", 1));
         }
-        sleep(interval.count());
+
+        if (TEMP_FAILURE_RETRY(nanosleep(&rem, &rem))) {
+            PLOG(ERROR) << "nanosleep failed";
+            return 1;
+        }
     }
 }
diff --git a/gs_watchdogd/init.gs_watchdogd.rc b/gs_watchdogd/init.gs_watchdogd.rc
index f58ce50..ba3354f 100644
--- a/gs_watchdogd/init.gs_watchdogd.rc
+++ b/gs_watchdogd/init.gs_watchdogd.rc
@@ -1,5 +1,6 @@
-# Set watchdog timer to 30 seconds and pet it every 10 seconds to get a 20 second margin
-service gs_watchdogd /system_ext/bin/gs_watchdogd 10 20
+# Pet watchdog timer every half of its timeout period.
+service gs_watchdogd /system_ext/bin/gs_watchdogd
+    user root
     class core
     oneshot
     seclabel u:r:gs_watchdogd:s0
diff --git a/gsa/Android.bp b/gsa/Android.bp
new file mode 100644
index 0000000..59e0369
--- /dev/null
+++ b/gsa/Android.bp
@@ -0,0 +1,20 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_binary {
+    name: "dump_gsa",
+    srcs: ["dump_gsa.cpp"],
+    init_rc: ["init.gsa.rc"],
+    cflags: [
+        "-Wall",
+        "-Wextra",
+        "-Werror",
+        "-pedantic",
+    ],
+    shared_libs: [
+        "libdump",
+    ],
+    vendor: true,
+    relative_install_path: "dump",
+}
diff --git a/gsa/dump_gsa.cpp b/gsa/dump_gsa.cpp
new file mode 100644
index 0000000..6308036
--- /dev/null
+++ b/gsa/dump_gsa.cpp
@@ -0,0 +1,31 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include <dump/pixel_dump.h>
+#include <unistd.h>
+
+#define DIM(arr) (sizeof(arr) / sizeof(arr[0]))
+
+const char* paths[][2] = {{"GSA MAIN LOG", "/dev/gsa-log1"},
+                          {"GSA INTERMEDIATE LOG", "/dev/gsa-bl1-log2"}};
+
+int main() {
+  for (size_t i = 0; i < DIM(paths); i++) {
+    if (!access(paths[i][1], R_OK)) {
+      dumpFileContent(paths[i][0], paths[i][1]);
+    }
+  }
+  return 0;
+}
diff --git a/gsa/gsa.mk b/gsa/gsa.mk
new file mode 100644
index 0000000..1938c66
--- /dev/null
+++ b/gsa/gsa.mk
@@ -0,0 +1,3 @@
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/gsa/sepolicy/gsa
+
+PRODUCT_PACKAGES += dump_gsa
diff --git a/gsa/init.gsa.rc b/gsa/init.gsa.rc
new file mode 100644
index 0000000..357144e
--- /dev/null
+++ b/gsa/init.gsa.rc
@@ -0,0 +1,6 @@
+on init
+    # Change GSA log group for dumpstate
+    chmod 660         /dev/gsa-log1
+    chmod 660         /dev/gsa-bl1-log2
+    chown root system /dev/gsa-log1
+    chown root system /dev/gsa-bl1-log2
diff --git a/gsa/sepolicy/gsa/dump_gsa.te b/gsa/sepolicy/gsa/dump_gsa.te
new file mode 100644
index 0000000..dcc3ef6
--- /dev/null
+++ b/gsa/sepolicy/gsa/dump_gsa.te
@@ -0,0 +1,6 @@
+# GSA
+pixel_bugreport(dump_gsa)
+
+userdebug_or_eng(`
+  allow dump_gsa gsa_log_device:chr_file r_file_perms;
+')
diff --git a/gsa/sepolicy/gsa/file.te b/gsa/sepolicy/gsa/file.te
new file mode 100644
index 0000000..46a1732
--- /dev/null
+++ b/gsa/sepolicy/gsa/file.te
@@ -0,0 +1,2 @@
+# GSA
+type gsa_log_device, dev_type;
diff --git a/gsa/sepolicy/gsa/file_contexts b/gsa/sepolicy/gsa/file_contexts
new file mode 100644
index 0000000..ad3a72d
--- /dev/null
+++ b/gsa/sepolicy/gsa/file_contexts
@@ -0,0 +1,4 @@
+# GSA
+/dev/gsa-log1                                                               u:object_r:gsa_log_device:s0
+/dev/gsa-bl1-log2                                                           u:object_r:gsa_log_device:s0
+/vendor/bin/dump/dump_gsa                                                   u:object_r:dump_gsa_exec:s0
diff --git a/insmod/16k/Android.bp b/insmod/16k/Android.bp
deleted file mode 100644
index 975c5dc..0000000
--- a/insmod/16k/Android.bp
+++ /dev/null
@@ -1,14 +0,0 @@
-
-soong_namespace {
-}
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-sh_binary {
-    name: "insmod.sh",
-    src: "insmod.sh",
-    init_rc: ["init.module.rc"],
-    vendor: true,
-}
diff --git a/insmod/16k/insmod.sh b/insmod/16k/insmod.sh
deleted file mode 100644
index 8ec8199..0000000
--- a/insmod/16k/insmod.sh
+++ /dev/null
@@ -1,119 +0,0 @@
-#!/vendor/bin/sh
-
-#############################################################
-### init.insmod.cfg format:                               ###
-### ----------------------------------------------------- ###
-### [insmod|setprop|enable/moprobe|wait] [path|prop name] ###
-### ...                                                   ###
-#############################################################
-
-modules_dir=
-system_modules_dir=
-vendor_modules_dir=
-
-
-pagesize=$(getconf PAGESIZE)
-# bootoption=$(getprop ro.product.build.16k_page.enabled)
-# We do not need to check ro.product.build.16k_page.enabled , because this
-# version of insmod.sh will only be used if PRODUCT_16K_DEVELOPER_OPTION
-# is set to true
-
-if [ "$pagesize" != "4096" ] ; then
-    echo "Device has page size $pagesize , skip loading modules from vendor_dlkm/system_dlkm because all modules are stored on vendor_boot"
-    setprop vendor.common.modules.ready 1
-    setprop vendor.device.modules.ready 1
-    setprop vendor.all.modules.ready 1
-    setprop vendor.all.devices.ready 1
-    return 0
-fi
-
-
-for dir in system vendor; do
-  for f in /${dir}/lib/modules/*/modules.dep /${dir}/lib/modules/modules.dep; do
-    if [[ -f "$f" ]]; then
-      if [[ "${dir}" == "system" ]]; then
-        system_modules_dir="$(dirname "$f")"
-      else
-        vendor_modules_dir="$(dirname "$f")"
-        modules_dir=${vendor_modules_dir}
-      fi
-      break
-    fi
-  done
-done
-
-if [[ -z "${system_modules_dir}" ]]; then
-  echo "Unable to locate system kernel modules directory" 2>&1
-fi
-
-if [[ -z "${vendor_modules_dir}" ]]; then
-  echo "Unable to locate vendor kernel modules directory" 2>&1
-  exit 1
-fi
-
-# imitates wait_for_file() in init
-wait_for_file()
-{
-    filename="${1}"
-    timeout="${2:-5}"
-
-    expiry=$(($(date "+%s")+timeout))
-    while [[ ! -e "${filename}" ]] && [[ "$(date "+%s")" -le "${expiry}" ]]
-    do
-        sleep 0.01
-    done
-}
-
-if [ $# -eq 1 ]; then
-  cfg_file=$1
-else
-  # Set property even if there is no insmod config
-  # to unblock early-boot trigger
-  setprop vendor.common.modules.ready 1
-  setprop vendor.device.modules.ready 1
-  setprop vendor.all.modules.ready 1
-  setprop vendor.all.devices.ready 1
-  exit 1
-fi
-
-if [ -f $cfg_file ]; then
-  while IFS="|" read -r action arg
-  do
-    case $action in
-      "insmod") insmod $arg ;;
-      "setprop") setprop $arg 1 ;;
-      "enable") echo 1 > $arg ;;
-      "condinsmod")
-        prop=$(echo $arg | cut -d '|' -f 1)
-        module1=$(echo $arg | cut -d '|' -f 2)
-        module2=$(echo $arg | cut -d '|' -f 3)
-        value=$(getprop $prop)
-        if [[ ${value} == "true" ]]; then
-          insmod ${vendor_modules_dir}/${module1}
-        else
-          insmod ${vendor_modules_dir}/${module2}
-        fi
-        ;;
-      "modprobe")
-        case ${arg} in
-          "system -b *" | "system -b")
-            modules_dir=${system_modules_dir}
-            arg="-b --all=${system_modules_dir}/modules.load" ;;
-          "system *" | "system")
-            modules_dir=${system_modules_dir}
-            arg="--all=${system_modules_dir}/modules.load" ;;
-          "-b *" | "-b" | "vendor -b *" | "vendor -b")
-            modules_dir=${vendor_modules_dir}
-            arg="-b --all=${vendor_modules_dir}/modules.load" ;;
-          "*" | "" | "vendor *" | "vendor")
-            modules_dir=${vendor_modules_dir}
-            arg="--all=${vendor_modules_dir}/modules.load" ;;
-        esac
-        if [[ -d "${modules_dir}" ]]; then
-          modprobe -a -d "${modules_dir}" $arg
-        fi
-        ;;
-      "wait") wait_for_file $arg ;;
-    esac
-  done < $cfg_file
-fi
diff --git a/insmod/4k/Android.bp b/insmod/4k/Android.bp
deleted file mode 100644
index ddfec40..0000000
--- a/insmod/4k/Android.bp
+++ /dev/null
@@ -1,13 +0,0 @@
-
-soong_namespace {
-}
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-sh_binary {
-    name: "insmod.sh",
-    src: "insmod.sh",
-    init_rc: ["init.module.rc"],
-    vendor: true,
-}
diff --git a/insmod/4k/init.module.rc b/insmod/4k/init.module.rc
deleted file mode 100644
index de23b5b..0000000
--- a/insmod/4k/init.module.rc
+++ /dev/null
@@ -1,10 +0,0 @@
-on init
-    # Loading common kernel modules in background
-    start insmod_sh
-
-service insmod_sh /vendor/bin/insmod.sh /vendor/etc/init.common.cfg
-    class main
-    user root
-    group root system
-    disabled
-    oneshot
diff --git a/insmod/Android.bp b/insmod/Android.bp
index 143e777..eed35ec 100644
--- a/insmod/Android.bp
+++ b/insmod/Android.bp
@@ -2,6 +2,13 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+sh_binary {
+    name: "insmod.sh",
+    src: "insmod.sh",
+    init_rc: ["init.module.rc"],
+    vendor: true,
+}
+
 prebuilt_etc {
     name: "init.common.cfg",
     src: "init.common.cfg",
diff --git a/insmod/16k/init.module.rc b/insmod/init.module.rc
similarity index 100%
rename from insmod/16k/init.module.rc
rename to insmod/init.module.rc
diff --git a/insmod/insmod.mk b/insmod/insmod.mk
index 0d8da9e..aa2261a 100644
--- a/insmod/insmod.mk
+++ b/insmod/insmod.mk
@@ -1,9 +1,3 @@
-ifeq (true,$(PRODUCT_16K_DEVELOPER_OPTION))
-PRODUCT_SOONG_NAMESPACES += device/google/gs-common/insmod/16k
-else
-PRODUCT_SOONG_NAMESPACES += device/google/gs-common/insmod/4k
-endif
-
 BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/insmod/sepolicy
 PRODUCT_PACKAGES += \
         insmod.sh \
diff --git a/insmod/4k/insmod.sh b/insmod/insmod.sh
similarity index 100%
rename from insmod/4k/insmod.sh
rename to insmod/insmod.sh
diff --git a/mediacodec/vpu/mediacodec_google.mk b/mediacodec/vpu/mediacodec_google.mk
new file mode 100644
index 0000000..8c1e974
--- /dev/null
+++ b/mediacodec/vpu/mediacodec_google.mk
@@ -0,0 +1,21 @@
+PRODUCT_SOONG_NAMESPACES += hardware/google/video/cnm
+
+PRODUCT_PACKAGES += \
+	google.hardware.media.c2@3.0-service \
+	libgc2_store \
+	libgc2_base \
+	libgc2_vdi_vpu \
+	libgc2_log \
+	libgc2_utils \
+	libgc2_av1_dec \
+	libgc2_vp9_dec \
+	libgc2_hevc_dec \
+	libgc2_avc_dec \
+	libgc2_av1_enc \
+	libgc2_hevc_enc \
+	libgc2_avc_enc \
+	vpu_firmware
+
+$(call soong_config_set,cnm,soc,$(TARGET_BOARD_PLATFORM))
+
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/mediacodec/vpu/sepolicy
diff --git a/mediacodec/vpu/sepolicy/file_contexts b/mediacodec/vpu/sepolicy/file_contexts
new file mode 100644
index 0000000..138e20e
--- /dev/null
+++ b/mediacodec/vpu/sepolicy/file_contexts
@@ -0,0 +1,2 @@
+/vendor/bin/hw/google\.hardware\.media\.c2@3\.0-service                     u:object_r:mediacodec_google_exec:s0
+/dev/vpu                                                                    u:object_r:video_device:s0
diff --git a/mediacodec/vpu/sepolicy/mediacodec_google.te b/mediacodec/vpu/sepolicy/mediacodec_google.te
new file mode 100644
index 0000000..8022675
--- /dev/null
+++ b/mediacodec/vpu/sepolicy/mediacodec_google.te
@@ -0,0 +1,31 @@
+type mediacodec_google, domain;
+type mediacodec_google_exec, exec_type, vendor_file_type, file_type;
+
+init_daemon_domain(mediacodec_google)
+
+hal_server_domain(mediacodec_google, hal_codec2)
+
+hal_client_domain(mediacodec_google, hal_graphics_allocator)
+
+add_service(mediacodec_google, eco_service)
+
+allow mediacodec_google dmabuf_system_heap_device:chr_file r_file_perms;
+allow mediacodec_google video_device:chr_file { read write open ioctl map };
+
+# mediacodec_google should never execute any executable without a domain transition
+neverallow mediacodec_google { file_type fs_type }:file execute_no_trans;
+
+# Media processing code is inherently risky and thus should have limited
+# permissions and be isolated from the rest of the system and network.
+# Lengthier explanation here:
+# https://android-developers.googleblog.com/2016/05/hardening-media-stack.html
+neverallow mediacodec_google domain:{ udp_socket rawip_socket } *;
+neverallow mediacodec_google { domain userdebug_or_eng(`-su') }:tcp_socket *;
+
+# Allow HAL to send trace packets to Perfetto
+userdebug_or_eng(`perfetto_producer(mediacodec_google)')
+
+userdebug_or_eng(`
+ allow mediacodec_google vendor_media_data_file:dir rw_dir_perms;
+ allow mediacodec_google vendor_media_data_file:file create_file_perms;
+')
diff --git a/modem/dump_modemlog/Android.bp b/modem/dump_modemlog/Android.bp
index aca7b20..f509320 100644
--- a/modem/dump_modemlog/Android.bp
+++ b/modem/dump_modemlog/Android.bp
@@ -1,12 +1,12 @@
 package {
-    default_applicable_licenses: [ "Android-Apache-2.0" ],
+    default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-sh_binary {
-    name: "dump_modem.sh",
-    src: "dump_modem.sh",
+rust_binary {
+    name: "dump_modem",
+    srcs: ["dump_modem.rs"],
     vendor: true,
-    sub_dir: "dump",
+    relative_install_path: "dump",
 }
 
 // Modem Log Dumper
@@ -30,10 +30,10 @@ cc_defaults {
 
 cc_library {
     name: "modem_log_dumper",
-    srcs: [ "modem_log_dumper.cpp" ],
-    defaults: [ "modem_log_dumper_defaults" ],
+    srcs: ["modem_log_dumper.cpp"],
+    defaults: ["modem_log_dumper_defaults"],
     export_shared_lib_headers: modem_log_dumper_public_deps,
-    export_include_dirs: [ "include" ],
+    export_include_dirs: ["include"],
     vendor_available: true,
 }
 
@@ -41,7 +41,7 @@ cc_library {
 
 cc_binary {
     name: "dump_modemlog",
-    srcs: [ "dump_modemlog.cpp" ],
+    srcs: ["dump_modemlog.cpp"],
     cflags: [
         "-Wall",
         "-Wextra",
@@ -60,7 +60,7 @@ cc_binary {
 
 cc_test {
     name: "dump_modemlog_test",
-    srcs: [ "modem_log_dumper_test.cpp" ],
+    srcs: ["modem_log_dumper_test.cpp"],
     defaults: [
         "modem_log_dumper_defaults",
         "modem_android_property_manager_fake_defaults",
diff --git a/modem/dump_modemlog/dump_modem.rs b/modem/dump_modemlog/dump_modem.rs
new file mode 100644
index 0000000..d9af7eb
--- /dev/null
+++ b/modem/dump_modemlog/dump_modem.rs
@@ -0,0 +1,109 @@
+// Copyright 2024 Google LLC
+
+//! The dump_modem binary is used to capture kernel/userspace logs in bugreport
+
+use std::fs;
+
+const MODEM_STAT: &str = "/data/vendor/modem_stat/debug.txt";
+const SSRDUMP_DIR: &str = "/data/vendor/ssrdump";
+const RFSD_ERR_LOG_DIR: &str = "/data/vendor/log/rfsd";
+const WAKEUP_EVENTS: &str = "/sys/devices/platform/cpif/wakeup_events";
+const CPIF_LOGBUFFER: &str = "/dev/logbuffer_cpif";
+const PCIE_EVENT_STATS: &str = "/sys/devices/platform/cpif/modem/pcie_event_stats";
+
+fn handle_io_error(file: &str, err: std::io::Error) {
+    match err.kind() {
+        std::io::ErrorKind::NotFound => println!("{file} not found!"),
+        std::io::ErrorKind::PermissionDenied => println!("Permission denied to access {file}"),
+        _ => println!("I/O error accessing {file}: {err}"),
+    }
+}
+
+fn print_file(file: &str) -> Result<(), std::io::Error> {
+    fs::metadata(file)?;
+
+    let data = fs::read_to_string(file)?;
+
+    if data.is_empty() {
+        println!("{file} is empty");
+    } else {
+        print!("{data}");
+    }
+
+    Ok(())
+}
+
+fn print_file_and_handle_error(file: &str) {
+    if let Err(err) = print_file(file) {
+        handle_io_error(file, err);
+    }
+}
+
+fn print_matching_files_in_dir(dir: &str, filename: &str) {
+    let Ok(entries) = fs::read_dir(dir) else {
+        return println!("Cannot open directory {dir}");
+    };
+
+    for entry in entries {
+        let Ok(entry) = entry else {
+            continue;
+        };
+        if entry.path().is_file() && entry.file_name().to_string_lossy().starts_with(filename) {
+            if let Some(path_str) = entry.path().to_str() {
+                println!("{}", path_str);
+                print_file_and_handle_error(path_str);
+            }
+        }
+    }
+}
+
+// Capture modem stat log if it exists
+fn modem_stat() {
+    println!("------ Modem Stat ------");
+    print_file_and_handle_error(MODEM_STAT);
+    println!();
+}
+
+// Capture crash signatures from all modem crashes
+fn modem_ssr_history() {
+    println!("------ Modem SSR history ------");
+    print_matching_files_in_dir(SSRDUMP_DIR, "crashinfo_modem");
+    println!();
+}
+
+// Capture rfsd error logs from all existing log files
+fn rfsd_error_log() {
+    println!("------ RFSD error log ------");
+    print_matching_files_in_dir(RFSD_ERR_LOG_DIR, "rfslog");
+    println!();
+}
+
+// Capture modem wakeup events if the sysfs attribute exists
+fn wakeup_events() {
+    println!("------ Wakeup event counts ------");
+    print_file_and_handle_error(WAKEUP_EVENTS);
+    println!();
+}
+
+// Capture kernel driver logbuffer if it exists
+fn cpif_logbuffer() {
+    println!("------ CPIF Logbuffer ------");
+    print_file_and_handle_error(CPIF_LOGBUFFER);
+    println!();
+}
+
+// Capture modem pcie stats if the sysfs attribute exists
+fn pcie_event_stats() {
+    println!("------ PCIe event stats ------");
+    print_file_and_handle_error(PCIE_EVENT_STATS);
+    println!();
+}
+
+fn main() {
+    modem_stat();
+    modem_ssr_history();
+    rfsd_error_log();
+    wakeup_events();
+    cpif_logbuffer();
+    pcie_event_stats();
+}
diff --git a/modem/dump_modemlog/dump_modem.sh b/modem/dump_modemlog/dump_modem.sh
deleted file mode 100644
index d1a535d..0000000
--- a/modem/dump_modemlog/dump_modem.sh
+++ /dev/null
@@ -1,41 +0,0 @@
-#!/vendor/bin/sh
-
-WAKEUP_EVENTS_FILE=/sys/devices/platform/cpif/wakeup_events
-CPIF_LOGBUFFER=/dev/logbuffer_cpif
-PCIE_EVENT_STATS=/sys/devices/platform/cpif/modem/pcie_event_stats
-
-echo "------ Modem Stat ------"
-cat /data/vendor/modem_stat/debug.txt
-
-echo "\n------ Modem SSR history ------"
-for f in $(ls /data/vendor/ssrdump/crashinfo_modem*); do
-  echo $f
-  cat $f
-done
-
-echo "\n------ RFSD error log ------"
-for f in $(ls /data/vendor/log/rfsd/rfslog_*); do
-  echo $f
-  cat $f
-done
-
-if [ -e $WAKEUP_EVENTS_FILE ]
-then
-  echo "\n------ Wakeup event counts ------"
-  echo $WAKEUP_EVENTS_FILE
-  cat $WAKEUP_EVENTS_FILE
-fi
-
-if [ -e $CPIF_LOGBUFFER ]
-then
-  echo "\n------ CPIF Logbuffer ------"
-  echo $CPIF_LOGBUFFER
-  cat $CPIF_LOGBUFFER
-fi
-
-if [ -e $PCIE_EVENT_STATS ]
-then
-  echo "\n------ PCIe event stats ------"
-  echo $PCIE_EVENT_STATS
-  cat $PCIE_EVENT_STATS
-fi
diff --git a/modem/dump_modemlog/dump_modemlog.mk b/modem/dump_modemlog/dump_modemlog.mk
index 5e91ab7..c96e729 100644
--- a/modem/dump_modemlog/dump_modemlog.mk
+++ b/modem/dump_modemlog/dump_modemlog.mk
@@ -1,5 +1,5 @@
 BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/modem/dump_modemlog/sepolicy
 
-PRODUCT_PACKAGES += dump_modem.sh
+PRODUCT_PACKAGES += dump_modem
 PRODUCT_PACKAGES += dump_modemlog
 
diff --git a/modem/dump_modemlog/sepolicy/file_contexts b/modem/dump_modemlog/sepolicy/file_contexts
index 29315e9..6d5c082 100644
--- a/modem/dump_modemlog/sepolicy/file_contexts
+++ b/modem/dump_modemlog/sepolicy/file_contexts
@@ -1,3 +1,3 @@
-/vendor/bin/dump/dump_modem\.sh      u:object_r:dump_modem_exec:s0
+/vendor/bin/dump/dump_modem          u:object_r:dump_modem_exec:s0
 /vendor/bin/dump/dump_modemlog       u:object_r:dump_modemlog_exec:s0
 
diff --git a/modem/radio_ext/radio_ext.mk b/modem/radio_ext/radio_ext.mk
index 6750fdd..1df3bcc 100644
--- a/modem/radio_ext/radio_ext.mk
+++ b/modem/radio_ext/radio_ext.mk
@@ -3,3 +3,4 @@ PRODUCT_PACKAGES += vendor.google.radio_ext-service
 DEVICE_PRODUCT_COMPATIBILITY_MATRIX_FILE += device/google/gs-common/modem/radio_ext/compatibility_matrix.xml
 
 BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/modem/radio_ext/sepolicy
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/gril/common/sepolicy
diff --git a/modem/radio_ext/sepolicy/grilservice_app.te b/modem/radio_ext/sepolicy/grilservice_app.te
new file mode 100644
index 0000000..9bd8c8e
--- /dev/null
+++ b/modem/radio_ext/sepolicy/grilservice_app.te
@@ -0,0 +1,2 @@
+allow grilservice_app hal_radio_ext_service:service_manager find;
+binder_call(grilservice_app, hal_radio_ext)
diff --git a/modem/shared_modem_platform/compatibility_matrix.xml b/modem/shared_modem_platform/compatibility_matrix.xml
index 5019c3e..14d987a 100644
--- a/modem/shared_modem_platform/compatibility_matrix.xml
+++ b/modem/shared_modem_platform/compatibility_matrix.xml
@@ -2,7 +2,7 @@
     <!-- Optional since older devices will not register any services. -->
     <hal format="aidl" optional="true">
         <name>com.google.pixel.shared_modem_platform</name>
-        <version>1</version>
+        <version>3</version>
         <interface>
             <name>ISharedModemPlatform</name>
             <instance>default</instance>
diff --git a/nfc/sepolicy_st21nfc/file_contexts b/nfc/sepolicy_st21nfc/file_contexts
new file mode 100644
index 0000000..a06842a
--- /dev/null
+++ b/nfc/sepolicy_st21nfc/file_contexts
@@ -0,0 +1,2 @@
+/dev/st21nfc                                                                u:object_r:nfc_device:s0
+/vendor/bin/hw/android\.hardware\.nfc-service\.st                           u:object_r:hal_nfc_default_exec:s0
diff --git a/nfc/sepolicy_st54spi/file.te b/nfc/sepolicy_st54spi/file.te
new file mode 100644
index 0000000..5f9a80d
--- /dev/null
+++ b/nfc/sepolicy_st54spi/file.te
@@ -0,0 +1,3 @@
+# SecureElement SPI device
+type st54spi_device, dev_type;
+
diff --git a/nfc/sepolicy_st54spi/file_contexts b/nfc/sepolicy_st54spi/file_contexts
new file mode 100644
index 0000000..f2762f3
--- /dev/null
+++ b/nfc/sepolicy_st54spi/file_contexts
@@ -0,0 +1,3 @@
+/dev/st54spi                                                                u:object_r:st54spi_device:s0
+/vendor/bin/hw/android\.hardware\.secure_element-service\.thales            u:object_r:hal_secure_element_st54spi_aidl_exec:s0
+
diff --git a/nfc/sepolicy_st54spi/hal_secure_element_st54spi_aidl.te b/nfc/sepolicy_st54spi/hal_secure_element_st54spi_aidl.te
new file mode 100644
index 0000000..f2051e0
--- /dev/null
+++ b/nfc/sepolicy_st54spi/hal_secure_element_st54spi_aidl.te
@@ -0,0 +1,9 @@
+# sepolicy for ST54L secure element
+type hal_secure_element_st54spi_aidl, domain;
+type hal_secure_element_st54spi_aidl_exec, exec_type, vendor_file_type, file_type;
+init_daemon_domain(hal_secure_element_st54spi_aidl)
+hal_server_domain(hal_secure_element_st54spi_aidl, hal_secure_element)
+allow hal_secure_element_st54spi_aidl st54spi_device:chr_file rw_file_perms;
+allow hal_secure_element_st54spi_aidl nfc_device:chr_file rw_file_perms;
+set_prop(hal_secure_element_st54spi_aidl, vendor_secure_element_prop)
+
diff --git a/nfc/sepolicy_st54spi/property.te b/nfc/sepolicy_st54spi/property.te
new file mode 100644
index 0000000..1ac5526
--- /dev/null
+++ b/nfc/sepolicy_st54spi/property.te
@@ -0,0 +1,3 @@
+# SecureElement vendor property
+vendor_internal_prop(vendor_secure_element_prop)
+
diff --git a/nfc/sepolicy_st54spi/property_contexts b/nfc/sepolicy_st54spi/property_contexts
new file mode 100644
index 0000000..2067a86
--- /dev/null
+++ b/nfc/sepolicy_st54spi/property_contexts
@@ -0,0 +1,2 @@
+# SecureElement vendor property
+persist.vendor.se.                         u:object_r:vendor_secure_element_prop:s0
diff --git a/nfc/sepolicy_st54spi/vendor_init.te b/nfc/sepolicy_st54spi/vendor_init.te
new file mode 100644
index 0000000..91e5cdb
--- /dev/null
+++ b/nfc/sepolicy_st54spi/vendor_init.te
@@ -0,0 +1,2 @@
+# SecureElement vendor property
+set_prop(vendor_init, vendor_secure_element_prop)
diff --git a/nfc/st21nfc.mk b/nfc/st21nfc.mk
new file mode 100644
index 0000000..c30ecce
--- /dev/null
+++ b/nfc/st21nfc.mk
@@ -0,0 +1,2 @@
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/nfc/sepolicy_st21nfc
+PRODUCT_PACKAGES += android.hardware.nfc-service.st
diff --git a/nfc/st54spi.mk b/nfc/st54spi.mk
new file mode 100644
index 0000000..046de87
--- /dev/null
+++ b/nfc/st54spi.mk
@@ -0,0 +1,3 @@
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/nfc/sepolicy_st54spi
+PRODUCT_PACKAGES += android.hardware.secure_element-service.thales
+
diff --git a/performance/OWNERS b/performance/OWNERS
new file mode 100644
index 0000000..7ee3645
--- /dev/null
+++ b/performance/OWNERS
@@ -0,0 +1,4 @@
+wvw@google.com
+paillon@google.com
+jenhaochen@google.com
+liumartin@google.com
diff --git a/performance/perf.mk b/performance/perf.mk
index dfbdb5b..ad4011a 100644
--- a/performance/perf.mk
+++ b/performance/perf.mk
@@ -1,3 +1,7 @@
 BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/performance/sepolicy
 
 PRODUCT_PACKAGES += dump_perf
+
+# Ensure enough free space to create zram backing device
+PRODUCT_PRODUCT_PROPERTIES += \
+    ro.zram_backing_device_min_free_mb=1536
diff --git a/performance/sepolicy/file.te b/performance/sepolicy/file.te
index 8e16bbf..e79f9b2 100644
--- a/performance/sepolicy/file.te
+++ b/performance/sepolicy/file.te
@@ -1,2 +1,8 @@
+# proactive kill
 type sysfs_pakills, fs_type, sysfs_type;
+
+# bts dump
 type vendor_bts_debugfs, fs_type, debugfs_type;
+
+# proc_compaction_proactiveness type
+type proc_compaction_proactiveness, fs_type, proc_type;
diff --git a/performance/sepolicy/genfs_contexts b/performance/sepolicy/genfs_contexts
index 041021c..57e3634 100644
--- a/performance/sepolicy/genfs_contexts
+++ b/performance/sepolicy/genfs_contexts
@@ -1,3 +1,4 @@
 genfscon proc /sys/kernel/sched_pelt_multiplier u:object_r:proc_sched:s0
 genfscon sysfs /kernel/vendor_mm/pa_kill u:object_r:sysfs_pakills:s0
 genfscon debugfs /bts u:object_r:vendor_bts_debugfs:s0
+genfscon proc /sys/vm/compaction_proactiveness u:object_r:proc_compaction_proactiveness:s0
diff --git a/performance/sepolicy/hal_power_default.te b/performance/sepolicy/hal_power_default.te
index 763862d..309e8f7 100644
--- a/performance/sepolicy/hal_power_default.te
+++ b/performance/sepolicy/hal_power_default.te
@@ -1,2 +1,3 @@
 allow hal_power_default sysfs_pakills:file rw_file_perms;
 allow hal_power_default sysfs_pakills:dir r_dir_perms;
+r_dir_file(hal_power_default, sysfs_vendor_mm);
diff --git a/performance/sepolicy/vendor_init.te b/performance/sepolicy/vendor_init.te
index fefecb1..188984f 100644
--- a/performance/sepolicy/vendor_init.te
+++ b/performance/sepolicy/vendor_init.te
@@ -1,3 +1,3 @@
 # MM
 allow vendor_init proc_percpu_pagelist_high_fraction:file w_file_perms;
-
+allow vendor_init proc_compaction_proactiveness:file w_file_perms;
diff --git a/sensors/dump_sensors.cpp b/sensors/dump_sensors.cpp
index 58d63e9..4c406ce 100644
--- a/sensors/dump_sensors.cpp
+++ b/sensors/dump_sensors.cpp
@@ -26,7 +26,8 @@ int main() {
     if (!::android::os::dumpstate::PropertiesHelper::IsUserBuild()) {
         // Not a user build, if this is also not a production device dump the USF registry.
         std::string hwRev = ::android::base::GetProperty("ro.boot.hardware.revision", "");
-        if (hwRev.find("PROTO") != std::string::npos ||
+        if (hwRev.find("DEV") != std::string::npos ||
+            hwRev.find("PROTO") != std::string::npos ||
             hwRev.find("EVT") != std::string::npos ||
             hwRev.find("DVT") != std::string::npos ||
             hwRev.find("PVT") != std::string::npos) {
diff --git a/sepolicy/Android.bp b/sepolicy/Android.bp
new file mode 100644
index 0000000..160e494
--- /dev/null
+++ b/sepolicy/Android.bp
@@ -0,0 +1,5 @@
+se_flags {
+    name: "usb_udc_sysfs_selinux_flags",
+    flags: ["RELEASE_USB_UDC_SYSFS_SELINUX_POLICY_ENABLED"],
+    export_to: ["all_selinux_flags"],
+}
diff --git a/storage/init.storage.rc b/storage/init.storage.rc
index 9cad2ea..9e4acd4 100644
--- a/storage/init.storage.rc
+++ b/storage/init.storage.rc
@@ -1,3 +1,11 @@
+on init
+    # Make foreground and background I/O priority different. none-to-rt was
+    # introduced in kernel 5.14. promote-to-rt was introduced in kernel 6.5.
+    # Write none-to-rt first and promote-to-rt next to support both older and
+    # newer kernel versions.
+    write /dev/blkio/blkio.prio.class none-to-rt
+    write /dev/blkio/blkio.prio.class promote-to-rt
+
 on property:ro.build.type=userdebug
     write /dev/sys/block/bootdevice/pixel/enable_pixel_ufs_logging 1
     chown system /dev/sg3
diff --git a/storage/sepolicy/charger_vendor.te b/storage/sepolicy/charger_vendor.te
new file mode 100644
index 0000000..62a7661
--- /dev/null
+++ b/storage/sepolicy/charger_vendor.te
@@ -0,0 +1,3 @@
+# fork from dcb05d13
+allow charger_vendor sysfs_scsi_devices_0000:file r_file_perms;
+
diff --git a/storage/sepolicy/device.te b/storage/sepolicy/device.te
index e0968f9..1252ee0 100644
--- a/storage/sepolicy/device.te
+++ b/storage/sepolicy/device.te
@@ -1,2 +1,11 @@
 # Userdata Exp block device.
 type userdata_exp_block_device, dev_type;
+
+# Block Devices
+type persist_block_device, dev_type;
+type efs_block_device, dev_type;
+type modem_userdata_block_device, dev_type;
+
+# Storage firmware upgrade
+type ufs_internal_block_device, dev_type;
+
diff --git a/storage/sepolicy/dump_storage.te b/storage/sepolicy/dump_storage.te
index 5324c17..7a5f563 100644
--- a/storage/sepolicy/dump_storage.te
+++ b/storage/sepolicy/dump_storage.te
@@ -1,8 +1,11 @@
+# adb bugreport
 pixel_bugreport(dump_storage)
 
+# adb bugreport
 allow dump_storage sysfs_scsi_devices_0000:dir r_dir_perms;
 allow dump_storage sysfs_scsi_devices_0000:file r_file_perms;
 
+# adb bugreport
 userdebug_or_eng(`
   allow dump_storage debugfs_f2fs:dir r_dir_perms;
   allow dump_storage debugfs_f2fs:file r_file_perms;
@@ -17,7 +20,10 @@ userdebug_or_eng(`
   allow dump_storage dump_storage_data_file:file create_file_perms;
 ')
 
+# adb bugreport
 get_prop(dump_storage, boottime_public_prop)
 
+# adb bugreport
 dontaudit dump_storage debugfs_f2fs:dir r_dir_perms;
 dontaudit dump_storage debugfs_f2fs:file r_file_perms;
+
diff --git a/storage/sepolicy/dumpstate.te b/storage/sepolicy/dumpstate.te
index 2c01193..2220870 100644
--- a/storage/sepolicy/dumpstate.te
+++ b/storage/sepolicy/dumpstate.te
@@ -1 +1,7 @@
-allow dumpstate sysfs_scsi_devices_0000:file r_file_perms;
\ No newline at end of file
+# adb bugreport
+allow dumpstate sysfs_scsi_devices_0000:file r_file_perms;
+allow dumpstate persist_file:dir { getattr };
+allow dumpstate modem_efs_file:dir { getattr };
+allow dumpstate modem_userdata_file:dir { getattr };
+allow dumpstate vold:binder { call };
+
diff --git a/storage/sepolicy/e2fs.te b/storage/sepolicy/e2fs.te
index c280cb7..92ff839 100644
--- a/storage/sepolicy/e2fs.te
+++ b/storage/sepolicy/e2fs.te
@@ -1 +1,10 @@
+# fix mkfs
 allow e2fs userdata_exp_block_device:blk_file rw_file_perms;
+allow e2fs efs_block_device:blk_file rw_file_perms;
+allow e2fs modem_userdata_block_device:blk_file rw_file_perms;
+allowxperm e2fs { persist_block_device efs_block_device modem_userdata_block_device }:blk_file ioctl {
+  BLKSECDISCARD BLKDISCARD BLKPBSZGET BLKDISCARDZEROES BLKROGET
+};
+allow e2fs sysfs_scsi_devices_0000:dir r_dir_perms;
+allow e2fs sysfs_scsi_devices_0000:file r_file_perms;
+
diff --git a/storage/sepolicy/fastbootd.te b/storage/sepolicy/fastbootd.te
index 35bac15..e571d0b 100644
--- a/storage/sepolicy/fastbootd.te
+++ b/storage/sepolicy/fastbootd.te
@@ -1 +1,3 @@
+# fastbootd
 allow fastbootd devpts:chr_file rw_file_perms;
+
diff --git a/storage/sepolicy/file.te b/storage/sepolicy/file.te
index ed4f925..0fa9564 100644
--- a/storage/sepolicy/file.te
+++ b/storage/sepolicy/file.te
@@ -1,4 +1,6 @@
+# file.te
 type debugfs_f2fs, debugfs_type, fs_type;
 type dump_storage_data_file, file_type, data_file_type;
 type sg_device, dev_type;
 type sg_util_exec, exec_type, vendor_file_type, file_type;
+
diff --git a/storage/sepolicy/file_contexts b/storage/sepolicy/file_contexts
index ff863db..1ef5a67 100644
--- a/storage/sepolicy/file_contexts
+++ b/storage/sepolicy/file_contexts
@@ -1,6 +1,9 @@
+# storage
 /vendor/bin/dump/dump_storage      u:object_r:dump_storage_exec:s0
-/sys/devices/platform/[0-9]+\.ufs/pixel/enable_pixel_ufs_logging  u:object_r:sysfs_scsi_devices_0000:s0
+/sys/devices/platform/[0-9a-z]+\.ufs/pixel/enable_pixel_ufs_logging  u:object_r:sysfs_scsi_devices_0000:s0
 /dev/sg[0-9]                       u:object_r:sg_device:s0
 /data/vendor/storage(/.*)?         u:object_r:dump_storage_data_file:s0
 /vendor/bin/sg_read_buffer         u:object_r:sg_util_exec:s0
 /dev/block/by-name/userdata_exp.*  u:object_r:userdata_exp_block_device:s0
+/vendor/bin/ufs_firmware_update\.sh                                  u:object_r:ufs_firmware_update_exec:s0
+
diff --git a/storage/sepolicy/fsck.te b/storage/sepolicy/fsck.te
index 2043199..6502995 100644
--- a/storage/sepolicy/fsck.te
+++ b/storage/sepolicy/fsck.te
@@ -1 +1,8 @@
+# fix fsck
 allow fsck userdata_exp_block_device:blk_file rw_file_perms;
+allow fsck efs_block_device:blk_file rw_file_perms;
+allow fsck modem_userdata_block_device:blk_file rw_file_perms;
+allow fsck sysfs_scsi_devices_0000:dir r_dir_perms;
+allow fsck sysfs_scsi_devices_0000:file r_file_perms;
+allow fsck persist_block_device:blk_file rw_file_perms;
+
diff --git a/storage/sepolicy/genfs_contexts b/storage/sepolicy/genfs_contexts
index 1a27ec4..69baae6 100644
--- a/storage/sepolicy/genfs_contexts
+++ b/storage/sepolicy/genfs_contexts
@@ -1 +1,3 @@
+# f2fs
 genfscon debugfs /f2fs     u:object_r:debugfs_f2fs:s0
+
diff --git a/storage/sepolicy/hal_health_default.te b/storage/sepolicy/hal_health_default.te
new file mode 100644
index 0000000..49bf50c
--- /dev/null
+++ b/storage/sepolicy/hal_health_default.te
@@ -0,0 +1,3 @@
+# dumpsys android.hardware.power.stats.IPowerStats/default
+r_dir_file(hal_health_default, sysfs_scsi_devices_0000)
+
diff --git a/storage/sepolicy/hal_health_storage_default.te b/storage/sepolicy/hal_health_storage_default.te
index af6593a..20a3b7d 100644
--- a/storage/sepolicy/hal_health_storage_default.te
+++ b/storage/sepolicy/hal_health_storage_default.te
@@ -1,3 +1,4 @@
 # Access to /sys/devices/platform/*ufs/*
 allow hal_health_storage_default sysfs_scsi_devices_0000:dir r_dir_perms;
 allow hal_health_storage_default sysfs_scsi_devices_0000:file rw_file_perms;
+
diff --git a/storage/sepolicy/hal_power_stats_default.te b/storage/sepolicy/hal_power_stats_default.te
new file mode 100644
index 0000000..edd286c
--- /dev/null
+++ b/storage/sepolicy/hal_power_stats_default.te
@@ -0,0 +1,3 @@
+# dumpsys android.hardware.power.stats.IPowerStats/default
+r_dir_file(hal_power_stats_default, sysfs_scsi_devices_0000)
+
diff --git a/storage/sepolicy/init.te b/storage/sepolicy/init.te
index 7070318..dc24247 100644
--- a/storage/sepolicy/init.te
+++ b/storage/sepolicy/init.te
@@ -1 +1,3 @@
+# init
 allow init sysfs_scsi_devices_0000:file w_file_perms;
+
diff --git a/storage/sepolicy/recovery.te b/storage/sepolicy/recovery.te
new file mode 100644
index 0000000..8f5556c
--- /dev/null
+++ b/storage/sepolicy/recovery.te
@@ -0,0 +1,7 @@
+# factory data reset
+recovery_only(`
+  allow recovery sysfs_ota:file rw_file_perms;
+  allow recovery sysfs_scsi_devices_0000:file r_file_perms;
+  allow recovery sysfs_scsi_devices_0000:dir r_dir_perms;
+')
+
diff --git a/storage/sepolicy/ufs_firmware_update.te b/storage/sepolicy/ufs_firmware_update.te
new file mode 100644
index 0000000..2313121
--- /dev/null
+++ b/storage/sepolicy/ufs_firmware_update.te
@@ -0,0 +1,11 @@
+# support ufs ffu via ota
+init_daemon_domain(ufs_firmware_update)
+type ufs_firmware_update, domain;
+type ufs_firmware_update_exec, vendor_file_type, exec_type, file_type;
+
+# support ufs ffu via ota
+allow ufs_firmware_update vendor_toolbox_exec:file execute_no_trans;
+allow ufs_firmware_update block_device:dir { search };
+allow ufs_firmware_update ufs_internal_block_device:blk_file rw_file_perms;
+allow ufs_firmware_update sysfs_scsi_devices_0000:file r_file_perms;
+
diff --git a/storage/sepolicy/vendor_init.te b/storage/sepolicy/vendor_init.te
index da4fcba..73eb527 100644
--- a/storage/sepolicy/vendor_init.te
+++ b/storage/sepolicy/vendor_init.te
@@ -1 +1,6 @@
+# vendor_init
 allow vendor_init sg_device:chr_file r_file_perms;
+
+# dirty swappiness
+allow vendor_init proc_dirty:file w_file_perms;
+
diff --git a/storage/sepolicy/vold.te b/storage/sepolicy/vold.te
index 3d35589..b776c80 100644
--- a/storage/sepolicy/vold.te
+++ b/storage/sepolicy/vold.te
@@ -1,8 +1,17 @@
+# ufs hagc
 allow vold sysfs_scsi_devices_0000:file rw_file_perms;
 
 # Access userdata_exp block device.
 allow vold userdata_exp_block_device:blk_file rw_file_perms;
 allowxperm vold userdata_exp_block_device:blk_file ioctl BLKSECDISCARD;
 
+# adb bugreport
 dontaudit vold dumpstate:fifo_file rw_file_perms;
 dontaudit vold dumpstate:fd use ;
+
+# fix idle-maint
+allow vold efs_block_device:blk_file { getattr };
+allow vold modem_userdata_block_device:blk_file { getattr };
+allow vold modem_efs_file:dir { read open ioctl };
+allow vold modem_userdata_file:dir { read open ioctl };
+
diff --git a/touch/gti/dump_gti0.sh b/touch/gti/dump_gti0.sh
index a3af3d7..facb531 100644
--- a/touch/gti/dump_gti0.sh
+++ b/touch/gti/dump_gti0.sh
@@ -8,6 +8,11 @@ else
 heatmap_path=$path
 fi
 
+if [[ -f "${procfs_path}/dump" ]]; then
+  echo "------ Dump ------"
+  cat ${procfs_path}/dump
+fi
+
 echo "------ Force Touch Active ------"
 result=$( cat "$path/force_active" 2>&1 )
 if [ $? -eq 0 ]; then
@@ -60,10 +65,5 @@ cat $heatmap_path/ss_raw
 echo "------ Self Test ------"
 cat $path/self_test
 
-if [[ -f "${procfs_path}/dump" ]]; then
-  echo "------ Dump ------"
-  cat ${procfs_path}/dump
-fi
-
 echo "------ Disable Force Touch Active ------"
 echo 0 > $path/force_active
diff --git a/touch/gti/dump_gti1.sh b/touch/gti/dump_gti1.sh
index 297ad44..eabd6d6 100644
--- a/touch/gti/dump_gti1.sh
+++ b/touch/gti/dump_gti1.sh
@@ -8,6 +8,11 @@ else
 heatmap_path=$path
 fi
 
+if [[ -f "${procfs_path}/dump" ]]; then
+  echo "------ Dump ------"
+  cat ${procfs_path}/dump
+fi
+
 echo "------ Force Touch Active ------"
 result=$( cat "$path/force_active" 2>&1 )
 if [ $? -eq 0 ]; then
@@ -60,10 +65,5 @@ cat $heatmap_path/ss_raw
 echo "------ Self Test ------"
 cat $path/self_test
 
-if [[ -f "${procfs_path}/dump" ]]; then
-  echo "------ Dump ------"
-  cat ${procfs_path}/dump
-fi
-
 echo "------ Disable Force Touch Active ------"
 echo 0 > $path/force_active
diff --git a/touch/gti/ical/sepolicy/property.te b/touch/gti/ical/sepolicy/property.te
index 2a71d74..94fa3fc 100644
--- a/touch/gti/ical/sepolicy/property.te
+++ b/touch/gti/ical/sepolicy/property.te
@@ -1 +1,2 @@
 system_public_prop(vendor_gti_prop)
+typeattribute vendor_gti_prop         touch_property_type;
diff --git a/touch/gti/predump_sepolicy/genfs_contexts b/touch/gti/predump_sepolicy/genfs_contexts
index 45d3b53..1dd4bad 100644
--- a/touch/gti/predump_sepolicy/genfs_contexts
+++ b/touch/gti/predump_sepolicy/genfs_contexts
@@ -1,4 +1,6 @@
 # Touch
 genfscon sysfs /devices/virtual/goog_touch_interface                            u:object_r:sysfs_touch_gti:s0
+genfscon sysfs /devices/virtual/goog_touch_interface/gti.0/wakeup               u:object_r:sysfs_wakeup:s0
+genfscon sysfs /devices/virtual/goog_touch_interface/gti.1/wakeup               u:object_r:sysfs_wakeup:s0
 genfscon proc  /goog_touch_interface                                            u:object_r:proc_touch_gti:s0
 
diff --git a/touch/gti/sepolicy/genfs_contexts b/touch/gti/sepolicy/genfs_contexts
index 45d3b53..1dd4bad 100644
--- a/touch/gti/sepolicy/genfs_contexts
+++ b/touch/gti/sepolicy/genfs_contexts
@@ -1,4 +1,6 @@
 # Touch
 genfscon sysfs /devices/virtual/goog_touch_interface                            u:object_r:sysfs_touch_gti:s0
+genfscon sysfs /devices/virtual/goog_touch_interface/gti.0/wakeup               u:object_r:sysfs_wakeup:s0
+genfscon sysfs /devices/virtual/goog_touch_interface/gti.1/wakeup               u:object_r:sysfs_wakeup:s0
 genfscon proc  /goog_touch_interface                                            u:object_r:proc_touch_gti:s0
 
diff --git a/touch/nvt/nvt-spi20.mk b/touch/nvt/nvt-spi20.mk
new file mode 100644
index 0000000..ad46fcc
--- /dev/null
+++ b/touch/nvt/nvt-spi20.mk
@@ -0,0 +1,2 @@
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/touch/nvt/sepolicy
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/touch/nvt/sepolicy-spi20
diff --git a/touch/nvt/sepolicy-spi20/genfs_contexts b/touch/nvt/sepolicy-spi20/genfs_contexts
new file mode 100644
index 0000000..05467a3
--- /dev/null
+++ b/touch/nvt/sepolicy-spi20/genfs_contexts
@@ -0,0 +1,8 @@
+# Touch
+genfscon sysfs /devices/platform/111d0000.spi/spi_master/spi20/spi20.0   u:object_r:sysfs_touch:s0
+
+# System suspend wakeup files
+genfscon sysfs /devices/platform/111d0000.spi/spi_master/spi20/spi20.0/power_supply/nvt-pen-battery/wakeup                  u:object_r:sysfs_wakeup:s0
+genfscon sysfs /devices/platform/111d0000.spi/spi_master/spi20/spi20.0/power_supply/USI_Stylus_Battery/wakeup               u:object_r:sysfs_wakeup:s0
+genfscon sysfs /devices/platform/111d0000.spi/spi_master/spi20/spi20.0/input/input2/wakeup                                  u:object_r:sysfs_wakeup:s0
+genfscon sysfs /devices/platform/111d0000.spi/spi_master/spi20/spi20.0/wakeup                                               u:object_r:sysfs_wakeup:s0
diff --git a/touch/nvt/sepolicy/file.te b/touch/nvt/sepolicy/file.te
index e310df7..05a770b 100644
--- a/touch/nvt/sepolicy/file.te
+++ b/touch/nvt/sepolicy/file.te
@@ -1 +1,2 @@
 type sysfs_touch, sysfs_type, fs_type;
+type proc_touch, proc_type, fs_type;
diff --git a/touch/nvt/sepolicy/genfs_contexts b/touch/nvt/sepolicy/genfs_contexts
new file mode 100644
index 0000000..b120511
--- /dev/null
+++ b/touch/nvt/sepolicy/genfs_contexts
@@ -0,0 +1,12 @@
+genfscon proc  /nvt_baseline                u:object_r:proc_touch:s0
+genfscon proc  /nvt_cc_uniformity           u:object_r:proc_touch:s0
+genfscon proc  /nvt_diff                    u:object_r:proc_touch:s0
+genfscon proc  /nvt_fw_update               u:object_r:proc_touch:s0
+genfscon proc  /nvt_fw_version              u:object_r:proc_touch:s0
+genfscon proc  /nvt_heatmap                 u:object_r:proc_touch:s0
+genfscon proc  /nvt_pen_1d_diff             u:object_r:proc_touch:s0
+genfscon proc  /nvt_pen_2d_baseline         u:object_r:proc_touch:s0
+genfscon proc  /nvt_pen_2d_diff             u:object_r:proc_touch:s0
+genfscon proc  /nvt_pen_2d_raw              u:object_r:proc_touch:s0
+genfscon proc  /nvt_raw                     u:object_r:proc_touch:s0
+genfscon proc  /nvt_selftest                u:object_r:proc_touch:s0
diff --git a/touch/nvt/sepolicy/vendor_init.te b/touch/nvt/sepolicy/vendor_init.te
new file mode 100644
index 0000000..8b844dd
--- /dev/null
+++ b/touch/nvt/sepolicy/vendor_init.te
@@ -0,0 +1,5 @@
+allow vendor_init sysfs_touch:dir r_dir_perms;
+allow vendor_init sysfs_touch:file rw_file_perms;
+allow vendor_init proc_touch:dir r_dir_perms;
+allow vendor_init proc_touch:file rw_file_perms;
+set_prop(vendor_init, gesture_prop)
diff --git a/tts/de-de/de-de-x-multi-r51.zvoice b/tts/de-de/de-de-x-multi-r53.zvoice
similarity index 63%
rename from tts/de-de/de-de-x-multi-r51.zvoice
rename to tts/de-de/de-de-x-multi-r53.zvoice
index 8ca49a3..87a9b04 100644
Binary files a/tts/de-de/de-de-x-multi-r51.zvoice and b/tts/de-de/de-de-x-multi-r53.zvoice differ
diff --git a/tts/es-es/es-es-x-multi-r50.zvoice b/tts/es-es/es-es-x-multi-r52.zvoice
similarity index 54%
rename from tts/es-es/es-es-x-multi-r50.zvoice
rename to tts/es-es/es-es-x-multi-r52.zvoice
index b42cae9..5f8c243 100644
Binary files a/tts/es-es/es-es-x-multi-r50.zvoice and b/tts/es-es/es-es-x-multi-r52.zvoice differ
diff --git a/tts/fr-fr/fr-fr-x-multi-r51.zvoice b/tts/fr-fr/fr-fr-x-multi-r53.zvoice
similarity index 66%
rename from tts/fr-fr/fr-fr-x-multi-r51.zvoice
rename to tts/fr-fr/fr-fr-x-multi-r53.zvoice
index 2e3c160..71ad1ca 100644
Binary files a/tts/fr-fr/fr-fr-x-multi-r51.zvoice and b/tts/fr-fr/fr-fr-x-multi-r53.zvoice differ
diff --git a/tts/it-it/it-it-x-multi-r47.zvoice b/tts/it-it/it-it-x-multi-r49.zvoice
similarity index 55%
rename from tts/it-it/it-it-x-multi-r47.zvoice
rename to tts/it-it/it-it-x-multi-r49.zvoice
index 78dce63..c1ecf15 100644
Binary files a/tts/it-it/it-it-x-multi-r47.zvoice and b/tts/it-it/it-it-x-multi-r49.zvoice differ
diff --git a/tts/ja-jp/ja-jp-x-multi-r49.zvoice b/tts/ja-jp/ja-jp-x-multi-r51.zvoice
similarity index 68%
rename from tts/ja-jp/ja-jp-x-multi-r49.zvoice
rename to tts/ja-jp/ja-jp-x-multi-r51.zvoice
index c2f8c80..d507720 100644
Binary files a/tts/ja-jp/ja-jp-x-multi-r49.zvoice and b/tts/ja-jp/ja-jp-x-multi-r51.zvoice differ
diff --git a/tts/voice_packs.mk b/tts/voice_packs.mk
index 7b95af9..86e2590 100644
--- a/tts/voice_packs.mk
+++ b/tts/voice_packs.mk
@@ -15,8 +15,8 @@
 
 # Voice packs for Text-To-Speech
 PRODUCT_COPY_FILES += \
-	device/google/gs-common/tts/ja-jp/ja-jp-x-multi-r49.zvoice:product/tts/google/ja-jp/ja-jp-x-multi-r49.zvoice\
-	device/google/gs-common/tts/fr-fr/fr-fr-x-multi-r51.zvoice:product/tts/google/fr-fr/fr-fr-x-multi-r51.zvoice\
-	device/google/gs-common/tts/de-de/de-de-x-multi-r51.zvoice:product/tts/google/de-de/de-de-x-multi-r51.zvoice\
-	device/google/gs-common/tts/it-it/it-it-x-multi-r47.zvoice:product/tts/google/it-it/it-it-x-multi-r47.zvoice\
-	device/google/gs-common/tts/es-es/es-es-x-multi-r50.zvoice:product/tts/google/es-es/es-es-x-multi-r50.zvoice
+	device/google/gs-common/tts/ja-jp/ja-jp-x-multi-r51.zvoice:product/tts/google/ja-jp/ja-jp-x-multi-r51.zvoice\
+	device/google/gs-common/tts/fr-fr/fr-fr-x-multi-r53.zvoice:product/tts/google/fr-fr/fr-fr-x-multi-r53.zvoice\
+	device/google/gs-common/tts/de-de/de-de-x-multi-r53.zvoice:product/tts/google/de-de/de-de-x-multi-r53.zvoice\
+	device/google/gs-common/tts/it-it/it-it-x-multi-r49.zvoice:product/tts/google/it-it/it-it-x-multi-r49.zvoice\
+	device/google/gs-common/tts/es-es/es-es-x-multi-r52.zvoice:product/tts/google/es-es/es-es-x-multi-r52.zvoice
diff --git a/widevine/sepolicy/file.te b/widevine/sepolicy/file.te
new file mode 100644
index 0000000..a1e4e0e
--- /dev/null
+++ b/widevine/sepolicy/file.te
@@ -0,0 +1,3 @@
+# Widevine DRM
+type mediadrm_vendor_data_file, file_type, data_file_type;
+
diff --git a/widevine/sepolicy/file_contexts b/widevine/sepolicy/file_contexts
new file mode 100644
index 0000000..92aed3c
--- /dev/null
+++ b/widevine/sepolicy/file_contexts
@@ -0,0 +1,5 @@
+/vendor/bin/hw/android\.hardware\.drm-service\.widevine          u:object_r:hal_drm_widevine_exec:s0
+/vendor/bin/hw/android\.hardware\.drm-service\.clearkey          u:object_r:hal_drm_clearkey_exec:s0
+
+# Data
+/data/vendor/mediadrm(/.*)?                                      u:object_r:mediadrm_vendor_data_file:s0
diff --git a/widevine/sepolicy/hal_drm_clearkey.te b/widevine/sepolicy/hal_drm_clearkey.te
new file mode 100644
index 0000000..fff4f0d
--- /dev/null
+++ b/widevine/sepolicy/hal_drm_clearkey.te
@@ -0,0 +1,6 @@
+# sepolicy for DRM clearkey
+type hal_drm_clearkey, domain;
+type hal_drm_clearkey_exec, vendor_file_type, exec_type, file_type;
+init_daemon_domain(hal_drm_clearkey)
+
+hal_server_domain(hal_drm_clearkey, hal_drm)
diff --git a/widevine/sepolicy/hal_drm_widevine.te b/widevine/sepolicy/hal_drm_widevine.te
new file mode 100644
index 0000000..9b4792e
--- /dev/null
+++ b/widevine/sepolicy/hal_drm_widevine.te
@@ -0,0 +1,13 @@
+# sepolicy for DRM widevine
+type hal_drm_widevine, domain;
+type hal_drm_widevine_exec, vendor_file_type, exec_type, file_type;
+init_daemon_domain(hal_drm_widevine)
+
+hal_server_domain(hal_drm_widevine, hal_drm)
+
+# L3
+allow hal_drm_widevine mediadrm_vendor_data_file:file create_file_perms;
+allow hal_drm_widevine mediadrm_vendor_data_file:dir create_dir_perms;
+
+#L1
+#TODO(snehalreddy@) : Add L1 permissions
diff --git a/widevine/sepolicy/service_contexts b/widevine/sepolicy/service_contexts
new file mode 100644
index 0000000..6989dde
--- /dev/null
+++ b/widevine/sepolicy/service_contexts
@@ -0,0 +1 @@
+android.hardware.drm.IDrmFactory/widevine    u:object_r:hal_drm_service:s0
diff --git a/widevine/widevine_v2.mk b/widevine/widevine_v2.mk
new file mode 100644
index 0000000..5cd914b
--- /dev/null
+++ b/widevine/widevine_v2.mk
@@ -0,0 +1,2 @@
+include device/google/gs-common/widevine/widevine.mk
+BOARD_VENDOR_SEPOLICY_DIRS += device/google/gs-common/widevine/sepolicy/
\ No newline at end of file
diff --git a/wireless_charger/compatibility_matrix.xml b/wireless_charger/compatibility_matrix.xml
index b760b1d..5185344 100644
--- a/wireless_charger/compatibility_matrix.xml
+++ b/wireless_charger/compatibility_matrix.xml
@@ -9,7 +9,7 @@
     </hal>
     <hal format="aidl" optional="true">
         <name>vendor.google.wireless_charger.service</name>
-        <version>1</version>
+        <version>1-2</version>
         <interface>
             <name>IWlcService</name>
             <instance>default</instance>
diff --git a/wireless_charger/sepolicy/hal_wlcservice.te b/wireless_charger/sepolicy/hal_wlcservice.te
index eadb593..6eba2ef 100644
--- a/wireless_charger/sepolicy/hal_wlcservice.te
+++ b/wireless_charger/sepolicy/hal_wlcservice.te
@@ -8,6 +8,8 @@ allow hal_wlcservice vendor_wlc_file:file create_file_perms;
 allow hal_wlcservice hal_wireless_charger_service:service_manager find;
 allow hal_wlcservice kmsg_device:chr_file { getattr w_file_perms };
 
+get_prop(hal_wlcservice, vendor_wlcservice_test_prop)
+
 binder_call(hal_wlcservice, servicemanager)
 add_service(hal_wlcservice, hal_wlcservice_service)
 
diff --git a/wireless_charger/sepolicy/property.te b/wireless_charger/sepolicy/property.te
new file mode 100644
index 0000000..b8ddbdf
--- /dev/null
+++ b/wireless_charger/sepolicy/property.te
@@ -0,0 +1 @@
+vendor_internal_prop(vendor_wlcservice_test_prop)
diff --git a/wireless_charger/sepolicy/property_contexts b/wireless_charger/sepolicy/property_contexts
new file mode 100644
index 0000000..8cf8f70
--- /dev/null
+++ b/wireless_charger/sepolicy/property_contexts
@@ -0,0 +1 @@
+vendor.wlcservice.test.authentication       u:object_r:vendor_wlcservice_test_prop:s0 exact bool
```

