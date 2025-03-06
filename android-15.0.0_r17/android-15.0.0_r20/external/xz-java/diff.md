```diff
diff --git a/Android.bp b/Android.bp
index f4d0a1d..c3c678f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,5 +42,8 @@ java_library_static {
     min_sdk_version: "29",
     // b/267831518: Pin tradefed and dependencies to Java 11.
     java_version: "11",
-
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.virt",
+    ],
 }
```

