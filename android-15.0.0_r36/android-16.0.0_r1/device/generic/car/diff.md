```diff
diff --git a/AndroidProducts.mk b/AndroidProducts.mk
index d279dad..8c2cc18 100644
--- a/AndroidProducts.mk
+++ b/AndroidProducts.mk
@@ -22,6 +22,7 @@ PRODUCT_MAKEFILES := \
     $(LOCAL_DIR)/sdk_car_md_x86_64.mk \
     $(LOCAL_DIR)/sdk_car_cw_x86_64.mk \
     $(LOCAL_DIR)/sdk_car_x86_64.mk \
+    $(LOCAL_DIR)/sdk_car_dewd_x86_64.mk \
 
 COMMON_LUNCH_CHOICES := \
     gsi_car_arm64-trunk_staging-userdebug \
diff --git a/common/car.mk b/common/car.mk
index 073a3aa..fe80c16 100644
--- a/common/car.mk
+++ b/common/car.mk
@@ -22,6 +22,9 @@ PRODUCT_PACKAGES += \
     android.hardware.automotive.remoteaccess@V2-default-service \
     android.hardware.automotive.ivn@V1-default-service
 
+# Set car power policy daemon connect to VHAL timeout to 60s for emulator (default is 5s).
+PRODUCT_SYSTEM_PROPERTIES += cppd.connectvhal.Timeoutmillis=60000
+
 # Runtime Resource Overlay for Connectivity
 PRODUCT_PACKAGES += \
     CarConnectivityOverlay
diff --git a/emulator/car_emulator_vendor.mk b/emulator/car_emulator_vendor.mk
index 643237e..b4fa7b1 100644
--- a/emulator/car_emulator_vendor.mk
+++ b/emulator/car_emulator_vendor.mk
@@ -24,15 +24,15 @@ DEVICE_PACKAGE_OVERLAYS := device/generic/goldfish/overlay
 
 PRODUCT_CHARACTERISTICS := emulator
 
+# Provide our own manifest, device/generic/goldfish/manifest.xml is too new
+EMULATOR_VENDOR_NO_MANIFEST_FILE := true
+DEVICE_MANIFEST_FILE += device/generic/car/emulator/manifest.xml
+
 # Enable Google-specific location features,
 # like NetworkLocationProvider and LocationCollector
 PRODUCT_VENDOR_PROPERTIES += \
     ro.com.google.locationfeatures=1
 
-# Enable setupwizard
-PRODUCT_VENDOR_PROPERTIES += \
-    ro.setupwizard.mode?=OPTIONAL
-
 # More configurations
 PRODUCT_VENDOR_PROPERTIES += \
     ro.carwatchdog.client_healthcheck.interval=20 \
@@ -58,6 +58,9 @@ PRODUCT_PACKAGES += \
     android.hardware.automotive.remoteaccess@V2-default-service \
     android.hardware.automotive.ivn@V1-default-service
 
+# Set car power policy daemon connect to VHAL timeout to 60s for emulator (default is 5s).
+PRODUCT_SYSTEM_PROPERTIES += cppd.connectvhal.Timeoutmillis=60000
+
 # Copy car_core_hardware and overwrite handheld_core_hardware.xml with a disable config.
 # Overwrite goldfish related xml with a disable config.
 PRODUCT_COPY_FILES += \
@@ -65,12 +68,7 @@ PRODUCT_COPY_FILES += \
     device/generic/car/common/car_core_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/car_core_hardware.xml \
     device/generic/car/common/android.hardware.disable.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.ar.xml \
     device/generic/car/common/android.hardware.disable.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.autofocus.xml \
-    device/generic/car/common/android.hardware.disable.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.concurrent.xml \
-    device/generic/car/common/android.hardware.disable.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.full.xml \
-    device/generic/car/common/android.hardware.disable.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.front.xml \
     device/generic/car/common/android.hardware.disable.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.any.xml \
-    device/generic/car/common/android.hardware.disable.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.flash-autofocus.xml \
-    device/generic/car/common/android.hardware.disable.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.camera.raw.xml \
     device/generic/car/common/android.hardware.disable.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.fingerprint.xml \
     device/generic/car/common/android.hardware.disable.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.wifi.direct.xml \
 
@@ -156,6 +154,9 @@ endif
 # Disable biometrics for AAOS emulators
 EMULATOR_VENDOR_NO_BIOMETRICS := true
 
+# Disable camera for AAOS emulators
+EMULATOR_VENDOR_NO_CAMERA := true
+
 # Goldfish vendor partition configurations
 $(call inherit-product, device/generic/goldfish/product/generic.mk)
 
diff --git a/emulator/cluster/display_settings.xml b/emulator/cluster/display_settings.xml
index e06053e..2d826fb 100644
--- a/emulator/cluster/display_settings.xml
+++ b/emulator/cluster/display_settings.xml
@@ -3,6 +3,13 @@
     <!-- Use physical port number instead of local id -->
     <config identifier="1" />
 
+    <!-- Display settings for the driver display -->
+    <display name="port:0"
+      ignoreOrientationRequest="true"/>
+
     <!-- Display settings for cluster -->
-    <display name="port:1" forcedDensity="160" dontMoveToTop="true" />
+    <display name="port:1"
+      ignoreOrientationRequest="true"
+      forcedDensity="160"
+      dontMoveToTop="true" />
 </display-settings>
diff --git a/emulator/manifest.xml b/emulator/manifest.xml
new file mode 100644
index 0000000..b8b0d37
--- /dev/null
+++ b/emulator/manifest.xml
@@ -0,0 +1,2 @@
+<manifest version="1.0" type="device" target-level="7">
+</manifest>
diff --git a/emulator/multi-display-dynamic/display_settings.xml b/emulator/multi-display-dynamic/display_settings.xml
index 0576eb1..e1a99c1 100644
--- a/emulator/multi-display-dynamic/display_settings.xml
+++ b/emulator/multi-display-dynamic/display_settings.xml
@@ -21,32 +21,41 @@
     <!-- Use unique local ids added by Goldfish -->
     <config identifier="0" />
 
+    <!-- Display settings for the driver display -->
+    <display name="local:4619827259835644672"
+        ignoreOrientationRequest="true"/>
+
     <!-- Display settings for cluster -->
     <display name="virtual:com.android.emulator.multidisplay:1234562"
+        ignoreOrientationRequest="true"
         shouldShowSystemDecors="false"
         forcedDensity="160"
         dontMoveToTop="true"/>
 
     <!-- Display settings for 2nd Home -->
     <display name="virtual:com.android.emulator.multidisplay:1234563"
+        ignoreOrientationRequest="true"
         shouldShowSystemDecors="true"
         shouldShowIme="true"
         forcedDensity="160" />
 
     <!-- Display settings for 3rd Home -->
     <display name="virtual:com.android.emulator.multidisplay:1234564"
+        ignoreOrientationRequest="true"
         shouldShowSystemDecors="true"
         shouldShowIme="true"
         forcedDensity="160" />
 
     <!-- Display settings for 4th Home -->
     <display name="virtual:com.android.emulator.multidisplay:1234565"
+        ignoreOrientationRequest="true"
         shouldShowSystemDecors="true"
         shouldShowIme="true"
         forcedDensity="160" />
 
     <!-- Display settings for 5th Home -->
     <display name="virtual:com.android.emulator.multidisplay:1234565"
+        ignoreOrientationRequest="true"
         shouldShowSystemDecors="true"
         shouldShowIme="true"
         forcedDensity="160" />
diff --git a/emulator/multi-display/display_settings.xml b/emulator/multi-display/display_settings.xml
index 8f63b42..aa16dc3 100644
--- a/emulator/multi-display/display_settings.xml
+++ b/emulator/multi-display/display_settings.xml
@@ -3,19 +3,26 @@
 <!-- Use physical port number instead of local id -->
 <config identifier="1" />
 
+<!-- Display settings for the driver display -->
+<display name="port:0"
+    ignoreOrientationRequest="true"/>
+
 <!-- Display settings for cluster -->
 <display name="port:1"
+    ignoreOrientationRequest="true"
     forcedDensity="160"
     dontMoveToTop="true"/>
 
 <!-- Display settings for 2nd Home -->
 <display name="port:2"
+    ignoreOrientationRequest="true"
     shouldShowSystemDecors="true"
     shouldShowIme="true"
     forcedDensity="160" />
 
 <!-- Display settings for 3rd Home -->
 <display name="port:3"
+    ignoreOrientationRequest="true"
     shouldShowSystemDecors="true"
     shouldShowIme="true"
     forcedDensity="160" />
diff --git a/emulator/sepolicy/hal_vehicle_default.te b/emulator/sepolicy/hal_vehicle_default.te
index 194f0c9..426e320 100644
--- a/emulator/sepolicy/hal_vehicle_default.te
+++ b/emulator/sepolicy/hal_vehicle_default.te
@@ -1,3 +1,6 @@
+starting_at_board_api(202504, `
+typeattribute hal_vehicle_default unconstrained_vsock_violators;
+')
 allow hal_vehicle_default self:vsock_socket { connect create read write };
 
 # For communication between VHAL and the host
diff --git a/hals/health/Android.bp b/hals/health/Android.bp
index dba6a50..01d3ba2 100644
--- a/hals/health/Android.bp
+++ b/hals/health/Android.bp
@@ -26,6 +26,7 @@ cc_defaults {
     overrides: [
         "android.hardware.health-service.example",
         "com.google.cf.health",
+        "android.hardware.health-service.cuttlefish_recovery",
     ],
 
     vintf_fragments: ["android.hardware.health-service.automotive.xml"],
diff --git a/hals/health/OWNERS b/hals/health/OWNERS
index 5fac14e..529bbb9 100644
--- a/hals/health/OWNERS
+++ b/hals/health/OWNERS
@@ -2,4 +2,3 @@
 alanschen@google.com
 yabinh@google.com
 # TL
-igorr@google.com
\ No newline at end of file
diff --git a/sdk_car_arm64.mk b/sdk_car_arm64.mk
index 896fba0..3dbee86 100644
--- a/sdk_car_arm64.mk
+++ b/sdk_car_arm64.mk
@@ -53,3 +53,5 @@ PRODUCT_NAME := sdk_car_arm64
 PRODUCT_DEVICE := emulator_car64_arm64
 PRODUCT_BRAND := Android
 PRODUCT_MODEL := Car on arm64 emulator
+AB_OTA_UPDATER := true
+
diff --git a/sdk_car_dewd_x86_64.mk b/sdk_car_dewd_x86_64.mk
new file mode 100644
index 0000000..1d95e7c
--- /dev/null
+++ b/sdk_car_dewd_x86_64.mk
@@ -0,0 +1,43 @@
+#
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
+
+# Car UI Emulator Target with Declarative windowing definition
+
+# Exclude GAS Car Launcher
+DO_NOT_INCLUDE_GAS_CAR_LAUNCHER := true
+
+# # Exclude Car UI Reference Design
+DO_NOT_INCLUDE_CAR_UI_REFERENCE_DESIGN := true
+
+# Exclude Car Visual Overlay
+DISABLE_CAR_PRODUCT_VISUAL_OVERLAY := true
+
+# Copy additional files
+PRODUCT_COPY_FILES += \
+    packages/services/Car/car_product/dewd/car_dewd_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/car_dewd_hardware.xml \
+    packages/services/Car/car_product/dewd/config.ini:config.ini
+
+$(call inherit-product, packages/services/Car/car_product/dewd/car_dewd_common.mk)
+$(call inherit-product, device/generic/car/sdk_car_x86_64.mk)
+
+# TODO(b/303863968): Set it to true after cleaning up the system partition
+# changes from this makefile
+PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := false
+
+PRODUCT_NAME := sdk_car_dewd_x86_64
+PRODUCT_MODEL := Declarative windowing definition on x86_64 emulator
+PRODUCT_CHARACTERISTICS := automotive
+PRODUCT_SDK_ADDON_NAME := sdk_car_dewd_x86_64
+
diff --git a/sdk_car_x86_64.mk b/sdk_car_x86_64.mk
index 54fab5d..2069ed5 100644
--- a/sdk_car_x86_64.mk
+++ b/sdk_car_x86_64.mk
@@ -53,3 +53,5 @@ PRODUCT_NAME := sdk_car_x86_64
 PRODUCT_DEVICE := emulator_car64_x86_64
 PRODUCT_BRAND := Android
 PRODUCT_MODEL := Car on x86_64 emulator
+AB_OTA_UPDATER := true
+
```

