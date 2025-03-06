```diff
diff --git a/AndroidProducts.mk b/AndroidProducts.mk
index b002607..f21288f 100644
--- a/AndroidProducts.mk
+++ b/AndroidProducts.mk
@@ -17,8 +17,10 @@
 PRODUCT_MAKEFILES := \
     $(LOCAL_DIR)/gsi_arm.mk \
     $(LOCAL_DIR)/gsi_arm64.mk \
+    $(LOCAL_DIR)/gsi_arm64_soong_system.mk \
     $(LOCAL_DIR)/gsi_x86.mk \
     $(LOCAL_DIR)/gsi_x86_64.mk \
+    $(LOCAL_DIR)/gsi_x86_64_soong_system.mk \
     $(LOCAL_DIR)/mgsi/csi_arm.mk \
     $(LOCAL_DIR)/mgsi/csi_arm64.mk \
     $(LOCAL_DIR)/mgsi/csi_x86.mk \
diff --git a/gsi_arm64_soong_system.mk b/gsi_arm64_soong_system.mk
new file mode 100644
index 0000000..40f7751
--- /dev/null
+++ b/gsi_arm64_soong_system.mk
@@ -0,0 +1,21 @@
+#
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
+$(call inherit-product, device/generic/common/gsi_arm64.mk)
+
+PRODUCT_NAME := gsi_arm64_soong_system
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := android_gsi
+USE_SOONG_DEFINED_SYSTEM_IMAGE := true
diff --git a/gsi_x86_64_soong_system.mk b/gsi_x86_64_soong_system.mk
new file mode 100644
index 0000000..6e90d3f
--- /dev/null
+++ b/gsi_x86_64_soong_system.mk
@@ -0,0 +1,21 @@
+#
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
+$(call inherit-product, device/generic/common/gsi_x86_64.mk)
+
+PRODUCT_NAME := gsi_x86_64_soong_system
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := android_gsi
+USE_SOONG_DEFINED_SYSTEM_IMAGE := true
```

