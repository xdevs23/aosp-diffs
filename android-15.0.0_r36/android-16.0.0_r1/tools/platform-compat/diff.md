```diff
diff --git a/build/Android.bp b/build/Android.bp
index 16c3be2..abbc8a8 100644
--- a/build/Android.bp
+++ b/build/Android.bp
@@ -23,11 +23,6 @@ python_binary_host {
     name: "process-compat-config",
     main: "process_compat_config.py",
     srcs: ["process_compat_config.py"],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_test_host {
@@ -37,11 +32,6 @@ python_test_host {
         "process_compat_config.py",
         "process-compat-config-test.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     test_options: {
         unit_test: true,
     },
diff --git a/java/android/compat/annotation/Android.bp b/java/android/compat/annotation/Android.bp
index 6172c83..27695bd 100644
--- a/java/android/compat/annotation/Android.bp
+++ b/java/android/compat/annotation/Android.bp
@@ -29,6 +29,10 @@ java_library {
         "LoggingOnly.java",
         "Overridable.java",
     ],
+    apex_available: [
+        "com.android.nfcservices",
+        "//apex_available:platform",
+    ],
     sdk_version: "core_current",
     exported_plugins: ["compat-changeid-annotation-processor"],
 }
diff --git a/java/com/android/class2nonsdklist/Class2NonSdkList.java b/java/com/android/class2nonsdklist/Class2NonSdkList.java
index 42a4605..aa9085f 100644
--- a/java/com/android/class2nonsdklist/Class2NonSdkList.java
+++ b/java/com/android/class2nonsdklist/Class2NonSdkList.java
@@ -78,6 +78,7 @@ public class Class2NonSdkList {
         map.put(33, FLAG_UNSUPPORTED);
         map.put(34, FLAG_UNSUPPORTED);
         map.put(35, FLAG_UNSUPPORTED);
+        map.put(36, FLAG_UNSUPPORTED);
         map.put(10000, FLAG_UNSUPPORTED); // VMRuntime.SDK_VERSION_CUR_DEVELOPMENT
         TARGET_SDK_TO_LIST_MAP = Collections.unmodifiableMap(map);
     }
```

