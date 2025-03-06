```diff
diff --git a/Android.bp b/Android.bp
index ecf4cab8..73197435 100644
--- a/Android.bp
+++ b/Android.bp
@@ -55,6 +55,7 @@ cc_defaults {
         "-Wno-overloaded-virtual",
         "-Wno-implicit-fallthrough",
         "-Wno-macro-redefined",
+        "-Wno-enum-constexpr-conversion",
     ],
 
     target: {
@@ -109,6 +110,7 @@ cc_library_shared {
 
     cflags: [
         "-DWITHOUT_SYSTEMD",
+        "-Wno-enum-constexpr-conversion",
     ],
 
     rtti: true,
diff --git a/third_party/boost/Android.bp b/third_party/boost/Android.bp
index 09d3a57b..8c19e01b 100644
--- a/third_party/boost/Android.bp
+++ b/third_party/boost/Android.bp
@@ -33,6 +33,7 @@ cc_defaults {
     "-Wall",
     "-Werror",
     "-fexceptions",
+    "-Wno-enum-constexpr-conversion",
   ],
   host_supported: true,
   rtti: true,
diff --git a/third_party/boost/boost-1_76_0.json b/third_party/boost/boost-1_76_0.json
index ecf3c380..079bf151 100644
--- a/third_party/boost/boost-1_76_0.json
+++ b/third_party/boost/boost-1_76_0.json
@@ -15,7 +15,8 @@
       "cflags": [
         "-Wall",
         "-Werror",
-        "-fexceptions"
+        "-fexceptions",
+        "-Wno-enum-constexpr-conversion"
       ],
       "visibility": ["//external/sdv/vsomeip"]
     },
```

