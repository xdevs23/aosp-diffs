```diff
diff --git a/Android.bp b/Android.bp
index e5bfbe3..dbf15cd 100644
--- a/Android.bp
+++ b/Android.bp
@@ -16,11 +16,20 @@ package {
     ],
 }
 
+java_defaults {
+    name: "kotlin_stdlib_defaults",
+    host_supported: true,
+    sdk_version: "core_current",
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+}
+
 java_import {
     name: "kotlin-annotations",
-    host_supported: true,
+    defaults: ["kotlin_stdlib_defaults"],
     jars: ["lib/annotations-13.0.jar"],
-    sdk_version: "core_current",
 }
 
 // exclude_dirs is used to remove META-INF resources for java multi-release
@@ -28,55 +37,42 @@ java_import {
 
 java_import {
     name: "kotlin-reflect",
-    host_supported: true,
+    defaults: ["kotlin_stdlib_defaults"],
     jars: ["lib/kotlin-reflect.jar"],
-    sdk_version: "core_current",
     exclude_dirs: ["META-INF/versions"],
 }
 
 java_import {
     name: "kotlin-stdlib",
-    host_supported: true,
+    defaults: ["kotlin_stdlib_defaults"],
     jars: ["lib/kotlin-stdlib.jar"],
-    sdk_version: "core_current",
     exclude_dirs: ["META-INF/versions"],
-    apex_available: [
-        "//apex_available:platform",
-        "//apex_available:anyapex",
-    ],
 }
 
 java_import {
     name: "kotlin-stdlib-jdk7",
-    host_supported: true,
+    defaults: ["kotlin_stdlib_defaults"],
     jars: ["lib/kotlin-stdlib-jdk7.jar"],
-    sdk_version: "core_current",
     exclude_dirs: ["META-INF/versions"],
 }
 
 java_import {
     name: "kotlin-stdlib-jdk8",
-    host_supported: true,
+    defaults: ["kotlin_stdlib_defaults"],
     jars: [
         "lib/kotlin-stdlib-jdk8.jar",
         "lib/kotlin-stdlib-jdk7.jar",
     ],
-    sdk_version: "core_current",
     exclude_dirs: ["META-INF/versions"],
-    apex_available: [
-        "//apex_available:platform",
-        "//apex_available:anyapex",
-    ],
 }
 
 java_import {
     name: "kotlin-test",
-    host_supported: true,
+    defaults: ["kotlin_stdlib_defaults"],
     jars: [
         "lib/kotlin-test.jar",
         "lib/kotlin-test-junit.jar",
     ],
-    sdk_version: "core_current",
     exclude_dirs: ["META-INF/versions"],
 }
 
@@ -86,6 +82,13 @@ java_import {
     jars: ["lib/parcelize-runtime.jar"],
     sdk_version: "core_current",
     exclude_dirs: ["META-INF/versions"],
+    apex_available: [
+        "//apex_available:platform",
+        // AdServices is using androidx.datastore_datastore-core which requires the dependency
+        "com.android.adservices",
+        "com.android.extservices",
+        "com.android.ondevicepersonalization",
+    ],
 }
 
 // See: http://go/android-license-faq
```

