```diff
diff --git a/gsi_product.mk b/gsi_product.mk
index aad06d2..a394c92 100644
--- a/gsi_product.mk
+++ b/gsi_product.mk
@@ -23,7 +23,6 @@ PRODUCT_PACKAGES += \
     Camera2 \
     Dialer \
     LatinIME \
-    messaging \
 
 # Default AOSP sounds
 $(call inherit-product-if-exists, frameworks/base/data/sounds/AllAudio.mk)
diff --git a/overlays/framework/Android.bp b/overlays/framework/Android.bp
new file mode 100644
index 0000000..5a5686e
--- /dev/null
+++ b/overlays/framework/Android.bp
@@ -0,0 +1,29 @@
+//
+// Copyright 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+
+package {
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "device_generic_common_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["device_generic_common_license"],
+}
+
+runtime_resource_overlay {
+    name: "gsi_overlay_framework",
+    system_ext_specific: true,
+}
diff --git a/overlays/framework/AndroidManifest.xml b/overlays/framework/AndroidManifest.xml
new file mode 100644
index 0000000..17b1b71
--- /dev/null
+++ b/overlays/framework/AndroidManifest.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+ * Copyright (C) 2024 The Android Open Source Project
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
+ -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="android.gsi.overlay">
+
+    <application android:hasCode="false" />
+
+    <overlay
+      android:targetPackage="android"
+      />
+</manifest>
diff --git a/overlays/framework/res/values/config.xml b/overlays/framework/res/values/config.xml
new file mode 100644
index 0000000..10926c6
--- /dev/null
+++ b/overlays/framework/res/values/config.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+ * Copyright (C) 2024 The Android Open Source Project
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
+-->
+
+<resources>
+    <integer name="config_multiuserMaximumUsers">4</integer>
+</resources>
diff --git a/overlays/overlay-config.xml b/overlays/overlay-config.xml
index 8ef8a81..380f651 100644
--- a/overlays/overlay-config.xml
+++ b/overlays/overlay-config.xml
@@ -16,6 +16,7 @@
 
 <config>
     <!-- Immutable overlays must precede mutable ones -->
+    <overlay package="android.gsi.overlay" mutable="false" enabled="true" />
     <overlay package="com.android.systemui.gsi.overlay" mutable="false" enabled="true" />
 
     <!-- Mutable overlays -->
```

