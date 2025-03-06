```diff
diff --git a/Android.bp b/Android.bp
index f69b1d1..71bfe58 100644
--- a/Android.bp
+++ b/Android.bp
@@ -37,6 +37,7 @@ rust_library {
         "com.android.compos",
         "com.android.uwb",
         "com.android.virt",
+        "com.android.configinfrastructure",
     ],
     product_available: true,
     vendor_available: true,
@@ -82,6 +83,7 @@ rust_library {
         "com.android.compos",
         "com.android.uwb",
         "com.android.virt",
+        "com.android.configinfrastructure",
     ],
     min_sdk_version: "29",
     lints: "none",
@@ -115,6 +117,7 @@ rust_bindgen {
         "com.android.compos",
         "com.android.uwb",
         "com.android.virt",
+        "com.android.configinfrastructure",
     ],
     min_sdk_version: "29",
 }
@@ -147,6 +150,7 @@ rust_bindgen {
         "com.android.compos",
         "com.android.uwb",
         "com.android.virt",
+        "com.android.configinfrastructure",
     ],
     min_sdk_version: "29",
 }
```

