```diff
diff --git a/Android.bp b/Android.bp
index 71bfe58..5a71bb0 100644
--- a/Android.bp
+++ b/Android.bp
@@ -33,11 +33,7 @@ rust_library {
     ],
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
-        "com.android.compos",
-        "com.android.uwb",
-        "com.android.virt",
-        "com.android.configinfrastructure",
+        "//apex_available:anyapex",
     ],
     product_available: true,
     vendor_available: true,
@@ -58,7 +54,7 @@ rust_test {
     flags: [
         "-C panic=abort",
         "-Z panic_abort_tests",
-    ]
+    ],
 }
 
 // Build a separate rust_library rather than depending directly on libsystem_properties_bindgen,
@@ -79,11 +75,7 @@ rust_library {
     vendor_available: true,
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
-        "com.android.compos",
-        "com.android.uwb",
-        "com.android.virt",
-        "com.android.configinfrastructure",
+        "//apex_available:anyapex",
     ],
     min_sdk_version: "29",
     lints: "none",
@@ -113,11 +105,7 @@ rust_bindgen {
     vendor_available: true,
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
-        "com.android.compos",
-        "com.android.uwb",
-        "com.android.virt",
-        "com.android.configinfrastructure",
+        "//apex_available:anyapex",
     ],
     min_sdk_version: "29",
 }
@@ -146,11 +134,7 @@ rust_bindgen {
     vendor_available: true,
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
-        "com.android.compos",
-        "com.android.uwb",
-        "com.android.virt",
-        "com.android.configinfrastructure",
+        "//apex_available:anyapex",
     ],
     min_sdk_version: "29",
 }
```

