```diff
diff --git a/Android.bp b/Android.bp
index da07d37f..5aa121f8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -51,4 +51,8 @@ java_library {
     sdk_version: "current",
     // TODO(b/237039251) use "apex_inherit" when Java modules support it
     min_sdk_version: "29",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.virt",
+    ],
 }
diff --git a/OWNERS b/OWNERS
deleted file mode 100644
index 76c0501e..00000000
--- a/OWNERS
+++ /dev/null
@@ -1,3 +0,0 @@
-# Default code reviewers picked from top 3 or more developers.
-# Please update this list if you find better candidates.
-jsharkey@android.com
```

