```diff
diff --git a/Android.bp b/Android.bp
index 63ef59a..cb7b52e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -44,7 +44,10 @@ rust_library {
         "libprotobuf",
     ],
     aliases: ["protobuf:protobufv3"],
-    apex_available: ["//apex_available:platform"],
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
     product_available: true,
     vendor_available: true,
     min_sdk_version: "29",
diff --git a/cargo_embargo.json b/cargo_embargo.json
index 962df6f..2477278 100644
--- a/cargo_embargo.json
+++ b/cargo_embargo.json
@@ -1,7 +1,4 @@
 {
-  "apex_available": [
-    "//apex_available:platform"
-  ],
   "features": [
     "_secure",
     "boringssl",
```

