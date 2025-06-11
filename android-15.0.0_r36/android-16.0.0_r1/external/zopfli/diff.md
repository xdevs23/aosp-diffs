```diff
diff --git a/METADATA b/METADATA
index e8ea873..a7b2efe 100644
--- a/METADATA
+++ b/METADATA
@@ -1,15 +1,19 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/zopfli
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
 name: "zopfli"
 description: "Zopfli Compression Algorithm is a compression library programmed in C to perform very good, but slow, deflate or zlib compression."
 third_party {
-  url {
-    type: GIT
-    value: "https://github.com/google/zopfli.git"
-  }
-  version: "831773bc28e318b91a3255fa12c9fcde1606058b"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2021
-    month: 6
-    day: 14
+    year: 2025
+    month: 1
+    day: 16
+  }
+  identifier {
+    type: "Git"
+    value: "https://github.com/google/zopfli.git"
+    version: "ccf9f0588d4a4509cb1040310ec122243e670ee6"
   }
 }
diff --git a/src/zopflipng/lodepng/lodepng_util.cpp b/src/zopflipng/lodepng/lodepng_util.cpp
index 574138a..11a6c0f 100644
--- a/src/zopflipng/lodepng/lodepng_util.cpp
+++ b/src/zopflipng/lodepng/lodepng_util.cpp
@@ -1151,7 +1151,7 @@ unsigned convertToXYZ(float* out, float whitepoint[3], const unsigned char* in,
     use_icc = validateICC(&icc);
   }
 
-  data = (unsigned char*)lodepng_malloc(w * h * (bit16 ? 8 : 4));
+  data = (unsigned char*)lodepng_malloc((size_t)w * (size_t)h * (bit16 ? 8 : 4));
   error = lodepng_convert(data, in, &tempmode, mode_in, w, h);
   if(error) goto cleanup;
 
```

