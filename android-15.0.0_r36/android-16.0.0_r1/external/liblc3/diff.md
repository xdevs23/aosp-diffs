```diff
diff --git a/Android.bp b/Android.bp
index 4047753..88c2766 100644
--- a/Android.bp
+++ b/Android.bp
@@ -2,10 +2,12 @@ cc_library_static {
     name: "liblc3",
     host_supported: true,
     visibility: [
+        "//hardware/interfaces/bluetooth:__subpackages__",
         "//packages/modules/Bluetooth:__subpackages__",
     ],
     apex_available: [
-        "com.android.btservices",
+        "//apex_available:platform",
+        "com.android.bt",
     ],
     srcs: [
         "src/*.c",
diff --git a/OWNERS b/OWNERS
index 1f825f8..1660f4d 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 asoulier@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

