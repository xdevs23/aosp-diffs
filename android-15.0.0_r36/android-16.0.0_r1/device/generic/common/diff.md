```diff
diff --git a/AndroidProducts.mk b/AndroidProducts.mk
index f21288f..b002607 100644
--- a/AndroidProducts.mk
+++ b/AndroidProducts.mk
@@ -17,10 +17,8 @@
 PRODUCT_MAKEFILES := \
     $(LOCAL_DIR)/gsi_arm.mk \
     $(LOCAL_DIR)/gsi_arm64.mk \
-    $(LOCAL_DIR)/gsi_arm64_soong_system.mk \
     $(LOCAL_DIR)/gsi_x86.mk \
     $(LOCAL_DIR)/gsi_x86_64.mk \
-    $(LOCAL_DIR)/gsi_x86_64_soong_system.mk \
     $(LOCAL_DIR)/mgsi/csi_arm.mk \
     $(LOCAL_DIR)/mgsi/csi_arm64.mk \
     $(LOCAL_DIR)/mgsi/csi_x86.mk \
diff --git a/OWNERS b/OWNERS
index 0d84092..946694c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1 @@
 szuweilin@google.com
-ycchen@google.com
diff --git a/gsi_arm.mk b/gsi_arm.mk
index 6272fb5..2170bd8 100644
--- a/gsi_arm.mk
+++ b/gsi_arm.mk
@@ -52,3 +52,7 @@ PRODUCT_NAME := gsi_arm
 PRODUCT_DEVICE := generic
 PRODUCT_BRAND := Android
 PRODUCT_MODEL := GSI on ARM
+
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := android_gsi
+PRODUCT_USE_SOONG_NOTICE_XML := true
+USE_SOONG_DEFINED_SYSTEM_IMAGE := true
diff --git a/gsi_arm64.mk b/gsi_arm64.mk
index ceb2e94..f81942f 100644
--- a/gsi_arm64.mk
+++ b/gsi_arm64.mk
@@ -56,3 +56,7 @@ PRODUCT_NAME := gsi_arm64
 PRODUCT_DEVICE := generic_arm64
 PRODUCT_BRAND := Android
 PRODUCT_MODEL := GSI on ARM64
+
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := android_gsi
+PRODUCT_USE_SOONG_NOTICE_XML := true
+USE_SOONG_DEFINED_SYSTEM_IMAGE := true
diff --git a/gsi_arm64_soong_system.mk b/gsi_arm64_soong_system.mk
deleted file mode 100644
index 40f7751..0000000
--- a/gsi_arm64_soong_system.mk
+++ /dev/null
@@ -1,21 +0,0 @@
-#
-# Copyright (C) 2024 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-
-$(call inherit-product, device/generic/common/gsi_arm64.mk)
-
-PRODUCT_NAME := gsi_arm64_soong_system
-PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := android_gsi
-USE_SOONG_DEFINED_SYSTEM_IMAGE := true
diff --git a/gsi_product.mk b/gsi_product.mk
index a394c92..47f5c54 100644
--- a/gsi_product.mk
+++ b/gsi_product.mk
@@ -23,6 +23,7 @@ PRODUCT_PACKAGES += \
     Camera2 \
     Dialer \
     LatinIME \
+    frameworks-base-overlays \
 
 # Default AOSP sounds
 $(call inherit-product-if-exists, frameworks/base/data/sounds/AllAudio.mk)
diff --git a/gsi_x86.mk b/gsi_x86.mk
index 030d9b4..7cef98e 100644
--- a/gsi_x86.mk
+++ b/gsi_x86.mk
@@ -48,3 +48,7 @@ PRODUCT_NAME := gsi_x86
 PRODUCT_DEVICE := generic_x86
 PRODUCT_BRAND := Android
 PRODUCT_MODEL := GSI on x86
+
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := android_gsi
+PRODUCT_USE_SOONG_NOTICE_XML := true
+USE_SOONG_DEFINED_SYSTEM_IMAGE := true
diff --git a/gsi_x86_64.mk b/gsi_x86_64.mk
index d21d0b9..3f7f419 100644
--- a/gsi_x86_64.mk
+++ b/gsi_x86_64.mk
@@ -52,3 +52,7 @@ PRODUCT_NAME := gsi_x86_64
 PRODUCT_DEVICE := generic_x86_64
 PRODUCT_BRAND := Android
 PRODUCT_MODEL := GSI on x86_64
+
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := android_gsi
+PRODUCT_USE_SOONG_NOTICE_XML := true
+USE_SOONG_DEFINED_SYSTEM_IMAGE := true
diff --git a/gsi_x86_64_soong_system.mk b/gsi_x86_64_soong_system.mk
deleted file mode 100644
index 6e90d3f..0000000
--- a/gsi_x86_64_soong_system.mk
+++ /dev/null
@@ -1,21 +0,0 @@
-#
-# Copyright (C) 2024 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-
-$(call inherit-product, device/generic/common/gsi_x86_64.mk)
-
-PRODUCT_NAME := gsi_x86_64_soong_system
-PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := android_gsi
-USE_SOONG_DEFINED_SYSTEM_IMAGE := true
```

