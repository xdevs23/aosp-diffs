```diff
diff --git a/Android.bp b/Android.bp
index 9c386fe..56f85a6 100644
--- a/Android.bp
+++ b/Android.bp
@@ -7,8 +7,6 @@ package {
     default_applicable_licenses: ["external_rust_crates_clang-sys_license"],
 }
 
-// Added automatically by a large-scale-change
-// See: http://go/android-license-faq
 license {
     name: "external_rust_crates_clang-sys_license",
     visibility: [":__subpackages__"],
@@ -16,7 +14,7 @@ license {
         "SPDX-license-identifier-Apache-2.0",
     ],
     license_text: [
-        "LICENSE.txt",
+        "LICENSE",
     ],
 }
 
```

