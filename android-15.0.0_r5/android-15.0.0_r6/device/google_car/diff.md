```diff
diff --git a/AndroidProducts.mk b/AndroidProducts.mk
index 58b4d06..b6e8475 100644
--- a/AndroidProducts.mk
+++ b/AndroidProducts.mk
@@ -22,6 +22,7 @@ PRODUCT_MAKEFILES := \
     $(LOCAL_DIR)/raven_car/aosp_raven_car.mk \
     $(LOCAL_DIR)/redfin_car/aosp_redfin_car.mk \
     $(LOCAL_DIR)/sunfish_car/aosp_sunfish_car.mk \
+    $(LOCAL_DIR)/husky_car/aosp_husky_car.mk \
     $(LOCAL_DIR)/tangorpro_car/aosp_tangorpro_car.mk
 
 
@@ -33,4 +34,5 @@ COMMON_LUNCH_CHOICES := \
     aosp_raven_car-trunk_staging-userdebug \
     aosp_redfin_car-trunk_staging-userdebug \
     aosp_sunfish_car-trunk_staging-userdebug \
+    aosp_husky_car-trunk_staging-userdebug \
     aosp_tangorpro_car-trunk_staging-userdebug
diff --git a/OWNERS b/OWNERS
index 3d821f6..252fd3c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,5 @@ sgaurav@google.com
 nirajdesai@google.com
 chengandrew@google.com
 calhuang@google.com
+wonil@google.com
+kwangun@google.com
diff --git a/common/overlay/frameworks/base/core/res/res/values/config.xml b/common/overlay/frameworks/base/core/res/res/values/config.xml
index e69f5e1..f978f10 100644
--- a/common/overlay/frameworks/base/core/res/res/values/config.xml
+++ b/common/overlay/frameworks/base/core/res/res/values/config.xml
@@ -8,7 +8,7 @@
     -->
   <integer name="config_longPressOnPowerBehavior">1</integer>
 
-  <bool name="config_single_volume">true</bool>
+  <bool name="config_single_volume">false</bool>
 
   <!-- Disable lockscreen sound effect -->
   <integer name="def_lockscreen_sounds_enabled">0</integer>
diff --git a/common/pre_google_car.mk b/common/pre_google_car.mk
index f33d93b..ff6d709 100644
--- a/common/pre_google_car.mk
+++ b/common/pre_google_car.mk
@@ -107,6 +107,14 @@ PRODUCT_COPY_FILES += \
         frameworks/native/data/etc/android.hardware.bluetooth.xml:system/etc/permissions/android.hardware.bluetooth.xml \
         frameworks/native/data/etc/android.hardware.bluetooth_le.xml:system/etc/permissions/android.hardware.bluetooth_le.xml
 
+PRODUCT_COPY_FILES += \
+        device/google_car/common/unavailable_features.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/unavailable_features.xml
+
+ifneq ($(PORTRAIT_UI), true)
+PRODUCT_COPY_FILES += \
+        device/google_car/common/unavailable_features_landscape.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/unavailable_features_landscape.xml
+endif
+
 # broadcast radio feature
  PRODUCT_COPY_FILES += \
         frameworks/native/data/etc/android.hardware.broadcastradio.xml:system/etc/permissions/android.hardware.broadcastradio.xml
diff --git a/common/unavailable_features.xml b/common/unavailable_features.xml
new file mode 100644
index 0000000..ebadbf7
--- /dev/null
+++ b/common/unavailable_features.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<permissions>
+    <!-- No Managed users feature -->
+    <unavailable-feature name="android.software.managed_users" />
+</permissions>
\ No newline at end of file
diff --git a/common/unavailable_features_landscape.xml b/common/unavailable_features_landscape.xml
new file mode 100644
index 0000000..37cdc35
--- /dev/null
+++ b/common/unavailable_features_landscape.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<permissions>
+    <unavailable-feature name="android.hardware.screen.portrait" />
+</permissions>
\ No newline at end of file
diff --git a/husky_car/BoardConfig.mk b/husky_car/BoardConfig.mk
new file mode 100644
index 0000000..62c8094
--- /dev/null
+++ b/husky_car/BoardConfig.mk
@@ -0,0 +1,19 @@
+#
+# Copyright (C) 2023 The Android Open-Source Project
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
+# * TARGET_SCREEN_DENSITY is scaled down by 1.9x
+
+TARGET_SCREEN_DENSITY := 252
diff --git a/husky_car/aosp_husky_car.mk b/husky_car/aosp_husky_car.mk
new file mode 100644
index 0000000..1d67bf1
--- /dev/null
+++ b/husky_car/aosp_husky_car.mk
@@ -0,0 +1,28 @@
+#
+# Copyright 2023 The Android Open-Source Project
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
+DEVICE_IS_64BIT_ONLY := true
+PIXEL_2023_GEN := true
+
+$(call inherit-product, device/google_car/common/pre_google_car.mk)
+$(call inherit-product, device/google_car/husky_car/device-husky-car.mk)
+$(call inherit-product, device/google_car/common/post_google_car.mk)
+
+PRODUCT_NAME := aosp_husky_car
+PRODUCT_DEVICE := husky
+PRODUCT_MODEL := AOSP on husky
+PRODUCT_BRAND := Android
+PRODUCT_MANUFACTURER := Google
diff --git a/husky_car/device-husky-car.mk b/husky_car/device-husky-car.mk
new file mode 100644
index 0000000..cafff23
--- /dev/null
+++ b/husky_car/device-husky-car.mk
@@ -0,0 +1,43 @@
+#
+# Copyright 2023 The Android Open Source Project
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
+PHONE_CAR_BOARD_PRODUCT := husky_car
+
+$(call inherit-product, packages/services/Car/car_product/build/car.mk)
+
+$(call inherit-product, device/google/shusky/husky_generic.mk)
+
+#include device/google/gs101/uwb/uwb.mk
+
+PRODUCT_PRODUCT_PROPERTIES+= \
+    ro.adb.secure=0
+
+
+PRODUCT_PRODUCT_PROPERTIES += \
+    ro.sys.multi_client_ime=com.example.android.multiclientinputmethod/.MultiClientInputMethod \
+    persist.debug.multi_client_ime=com.example.android.multiclientinputmethod/.MultiClientInputMethod \
+    boot.animation.displays=4630947239236256904,4630946674560563842 \
+
+PRODUCT_PACKAGES += \
+    MultiClientInputMethod \
+    MultiDisplaySecondaryHomeTestLauncher \
+    MultiDisplayTest \
+
+PRODUCT_PACKAGE_OVERLAYS += \
+    device/google_car/husky_car/overlay
+
+PRODUCT_PACKAGES += \
+    librs_jni
diff --git a/husky_car/overlay/frameworks/base/core/res/res/values/config.xml b/husky_car/overlay/frameworks/base/core/res/res/values/config.xml
new file mode 100644
index 0000000..68630c0
--- /dev/null
+++ b/husky_car/overlay/frameworks/base/core/res/res/values/config.xml
@@ -0,0 +1,54 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+/*
+** Copyright 2022, The Android Open Source Project
+**
+** Licensed under the Apache License, Version 2.0 (the "License");
+** you may not use this file except in compliance with the License.
+** You may obtain a copy of the License at
+**
+**     http://www.apache.org/licenses/LICENSE-2.0
+**
+** Unless required by applicable law or agreed to in writing, software
+** distributed under the License is distributed on an "AS IS" BASIS,
+** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+** See the License for the specific language governing permissions and
+** limitations under the License.
+*/
+-->
+
+<resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <!-- This is the default launcher package with an activity to use on secondary displays that
+         support system decorations.
+         This launcher package must have an activity that supports multiple instances and has
+         corresponding launch mode set in AndroidManifest.
+         {@see android.view.Display#FLAG_SHOULD_SHOW_SYSTEM_DECORATIONS} -->
+    <string name="config_secondaryHomePackage" translatable="false">com.android.car.multidisplay</string>
+
+    <!-- Whether the system enables per-display focus. If the system has the input method for each
+         display, this value should be true. -->
+    <bool name="config_perDisplayFocusEnabled">true</bool>
+    <!-- True if the device supports system decorations on secondary displays. -->
+    <bool name="config_supportsSystemDecorsOnSecondaryDisplays">true</bool>
+
+    <!-- Whether to only install system packages on a user if they're allow-listed for that user
+         type. These are flags and can be freely combined.
+         0  - disable allow-list (install all system packages; no logging)
+         1  - enforce (only install system packages if they are allow-listed)
+         2  - log (log non-allow-listed packages)
+         4  - any package not mentioned in the allow-list file is implicitly allow-listed on all users
+         8  - same as 4, but just for the SYSTEM user
+         16 - ignore OTAs (don't install system packages during OTAs)
+         Common scenarios:
+          - to enable feature (fully enforced) for a complete allow-list: 1
+          - to enable feature for an incomplete allow-list (so use implicit allow-list mode): 5
+          - to enable feature but implicitly allow-list for SYSTEM user to ease local development: 9
+          - to disable feature completely if it had never been enabled: 16
+          - to henceforth disable feature and try to undo its previous effects: 0
+        Note: This list must be kept current with PACKAGE_WHITELIST_MODE_PROP in
+        frameworks/base/services/core/java/com/android/server/pm/UserSystemPackageInstaller.java
+        Package allow-list disabled for testing profile user as default allow-list does not
+        support PROFILE user. -->
+    <integer name="config_userTypePackageWhitelistMode">2</integer>
+
+</resources>
diff --git a/tangorpro_car/BoardConfig.mk b/tangorpro_car/BoardConfig.mk
index ff875e5..7d7a452 100644
--- a/tangorpro_car/BoardConfig.mk
+++ b/tangorpro_car/BoardConfig.mk
@@ -15,7 +15,7 @@
 #
 
 # Adjust the TARGET_SCREEN_DENSITY based on the target name
-ifeq (,$(filter tangorpro_ui_portrait_car, $(TARGET_PRODUCT)))
+ifeq (,$(findstring tangorpro_ui_portrait_car, $(TARGET_PRODUCT)))
     TARGET_SCREEN_DENSITY := 280
 else
     TARGET_SCREEN_DENSITY := 150
diff --git a/tangorpro_car/aosp_tangorpro_car.mk b/tangorpro_car/aosp_tangorpro_car.mk
index 96b000c..329fd36 100644
--- a/tangorpro_car/aosp_tangorpro_car.mk
+++ b/tangorpro_car/aosp_tangorpro_car.mk
@@ -17,6 +17,9 @@
 DEVICE_IS_64BIT_ONLY := true
 
 
+PRODUCT_COPY_FILES += \
+        device/google_car/tangorpro_car/unavailable_features.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/unavailable_features_tangorpro_car.xml
+
 PRODUCT_PACKAGE_OVERLAYS += device/google_car/tangorpro_car/overlay
 
 $(call inherit-product, device/google_car/common/pre_google_car.mk)
@@ -28,3 +31,7 @@ PRODUCT_DEVICE := tangorpro
 PRODUCT_MODEL := AOSP on Tangorpro
 PRODUCT_BRAND := Android
 PRODUCT_MANUFACTURER := Google
+
+PRODUCT_BRAND_FOR_ATTESTATION := google
+PRODUCT_NAME_FOR_ATTESTATION := tangorpro
+PRODUCT_MODEL_FOR_ATTESTATION := Pixel Tablet
diff --git a/tangorpro_car/unavailable_features.xml b/tangorpro_car/unavailable_features.xml
new file mode 100644
index 0000000..8700657
--- /dev/null
+++ b/tangorpro_car/unavailable_features.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<permissions>
+    <unavailable-feature name="android.hardware.location.gps" />
+</permissions>
\ No newline at end of file
```

