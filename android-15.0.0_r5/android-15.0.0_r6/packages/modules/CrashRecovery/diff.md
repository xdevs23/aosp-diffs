```diff
diff --git a/OWNERS b/OWNERS
new file mode 100644
index 0000000..3619d3e
--- /dev/null
+++ b/OWNERS
@@ -0,0 +1 @@
+include platform/frameworks/base:/services/core/java/com/android/server/crashrecovery/OWNERS
diff --git a/apex/Android.bp b/apex/Android.bp
index 1e3a03b..ec52e2d 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -16,33 +16,19 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-soong_config_module_type {
-    name: "custom_bootclasspath_fragment",
-    module_type: "bootclasspath_fragment",
-    config_namespace: "ANDROID",
-    bool_variables: [
-        "release_crashrecovery_module",
-    ],
-    properties: [
-        "enabled"
-    ],
-}
-
 // Encapsulate the contributions made by the com.android.crashrecovery to the bootclasspath.
-custom_bootclasspath_fragment {
+bootclasspath_fragment {
     // This fragment will be enabled using release_crashrecovery_module flag
-    enabled: false,
-    soong_config_variables: {
-      release_crashrecovery_module: {
-        enabled: true,
-      },
-    },
+    enabled: select(release_flag("RELEASE_CRASHRECOVERY_MODULE"), {
+        true: true,
+        false: false,
+    }),
 
     name: "com.android.crashrecovery-bootclasspath-fragment",
     contents: ["framework-crashrecovery"],
     apex_available: ["com.android.crashrecovery"],
     hidden_api: {
-        split_packages: ["*"] // TODO(b/289203818) be more specific
+        split_packages: ["*"], // TODO(b/289203818) be more specific
     },
     // The bootclasspath_fragments that provide APIs on which this depends.
     fragments: [
@@ -62,27 +48,13 @@ custom_bootclasspath_fragment {
     ],
 }
 
-soong_config_module_type {
-    name: "custom_systemserverclasspath_fragment",
-    module_type: "systemserverclasspath_fragment",
-    config_namespace: "ANDROID",
-    bool_variables: [
-        "release_crashrecovery_module",
-    ],
-    properties: [
-        "enabled"
-    ],
-}
-
 // Encapsulate the contributions made by the com.android.crashrecovery to the systemserverclasspath.
-custom_systemserverclasspath_fragment {
+systemserverclasspath_fragment {
     // This fragment will be enabled using release_crashrecovery_module flag
-    enabled: false,
-    soong_config_variables: {
-      release_crashrecovery_module: {
-        enabled: true,
-      },
-    },
+    enabled: select(release_flag("RELEASE_CRASHRECOVERY_MODULE"), {
+        true: true,
+        false: false,
+    }),
 
     name: "com.android.crashrecovery-systemserverclasspath-fragment",
     contents: ["service-crashrecovery"],
@@ -100,36 +72,22 @@ android_app_certificate {
     certificate: "com.android.crashrecovery",
 }
 
-soong_config_module_type {
-    name: "custom_apex",
-    module_type: "apex",
-    config_namespace: "ANDROID",
-    bool_variables: [
-        "release_crashrecovery_module",
-    ],
-    properties: [
-        "enabled"
-    ],
-}
-
-custom_apex {
+apex {
     // This apex will be enabled using release_crashrecovery_module flag
-    enabled: false,
-    soong_config_variables: {
-        release_crashrecovery_module: {
-          enabled: true,
-        },
-    },
+    enabled: select(release_flag("RELEASE_CRASHRECOVERY_MODULE"), {
+        true: true,
+        false: false,
+    }),
 
     name: "com.android.crashrecovery",
     defaults: ["v-launched-apex-module"],
     bootclasspath_fragments: ["com.android.crashrecovery-bootclasspath-fragment"],
     systemserverclasspath_fragments: [
-    "com.android.crashrecovery-systemserverclasspath-fragment",
+        "com.android.crashrecovery-systemserverclasspath-fragment",
     ],
     file_contexts: ":com.android.crashrecovery-file_contexts",
     prebuilts: [
-      "current_sdkinfo",
+        "current_sdkinfo",
     ],
     key: "com.android.crashrecovery.key",
     certificate: ":com.android.crashrecovery.certificate",
@@ -137,26 +95,12 @@ custom_apex {
     min_sdk_version: "34",
 }
 
-soong_config_module_type {
-    name: "custom_sdk",
-    module_type: "sdk",
-    config_namespace: "ANDROID",
-    bool_variables: [
-        "release_crashrecovery_module",
-    ],
-    properties: [
-        "enabled"
-    ],
-}
-
-custom_sdk {
+sdk {
     // This sdk will be enabled using release_crashrecovery_module flag
-    enabled: false,
-    soong_config_variables: {
-        release_crashrecovery_module: {
-          enabled: true,
-        },
-    },
+    enabled: select(release_flag("RELEASE_CRASHRECOVERY_MODULE"), {
+        true: true,
+        false: false,
+    }),
 
     name: "crashrecovery-sdk",
     apexes: ["com.android.crashrecovery"],
```

