```diff
diff --git a/flags/Android.bp b/flags/Android.bp
index d38820e..58aa2fd 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -18,12 +18,13 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+// ----
 aconfig_declarations {
     name: "media_mainline_aconfig_flags",
     package: "com.android.media.mainline.flags",
     container: "com.android.media",
     srcs: [
-        "**/*.aconfig",
+        "flags.aconfig",
     ],
 }
 
@@ -39,3 +40,48 @@ java_aconfig_library {
     defaults: ["framework-minus-apex-aconfig-java-defaults"],
     min_sdk_version: "29",
 }
+
+// ----
+// NB: mediametrics in the module is >= SDK 35
+aconfig_declarations {
+    name: "media_metrics_aconfig_flags",
+    package: "com.android.media.metrics.flags",
+    container: "com.android.media",
+    exportable: true,
+    srcs: [
+        "mediametrics.aconfig",
+    ],
+}
+
+java_aconfig_library {
+    name: "com.android.media.metrics.flags-container-aconfig-java",
+    defaults: ["framework-minus-apex-aconfig-java-defaults"],
+    aconfig_declarations: "media_metrics_aconfig_flags",
+    visibility: [
+        "//packages/modules/Media:__subpackages__",
+        "//frameworks/base",
+        "//frameworks/base:__subpackages__",
+    ],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.media",
+    ],
+    min_sdk_version: "35",
+}
+
+java_aconfig_library {
+    name: "com.android.media.metrics.flags-client-aconfig-java",
+    defaults: ["framework-minus-apex-aconfig-java-defaults"],
+    aconfig_declarations: "media_metrics_aconfig_flags",
+    mode: "exported",
+    visibility: [
+        "//packages/modules/Media:__subpackages__",
+        "//frameworks/base",
+        "//frameworks/base:__subpackages__",
+    ],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.media",
+    ],
+    min_sdk_version: "35",
+}
diff --git a/flags/mediametrics.aconfig b/flags/mediametrics.aconfig
new file mode 100644
index 0000000..bd700ea
--- /dev/null
+++ b/flags/mediametrics.aconfig
@@ -0,0 +1,10 @@
+package: "com.android.media.metrics.flags"
+container: "com.android.media"
+
+flag {
+  name: "mediametrics_to_module"
+  namespace: "media_reliability"
+  description: "Move android.media.metrics.* to androd.media.metrics.module in module"
+  bug: "189976186"
+  is_exported: true
+}
```

