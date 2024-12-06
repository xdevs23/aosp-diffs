```diff
diff --git a/BUILD.gn b/BUILD.gn
index b39d278..a17f9e0 100644
--- a/BUILD.gn
+++ b/BUILD.gn
@@ -35,11 +35,27 @@ if (current_cpu == "x86" || current_cpu == "x64") {
 
     inputs = [
       "simd/nasm/jdct.inc",
+      "simd/nasm/jsimdcfg.inc",
       "simd/nasm/jsimdext.inc",
+      "simd/nasm/jcolsamp.inc",
     ]
 
     if (current_cpu == "x86") {
       include_dirs += [ "simd/i386/" ]
+      inputs += [
+        "simd/i386/jccolext-avx2.asm",
+        "simd/i386/jccolext-mmx.asm",
+        "simd/i386/jccolext-sse2.asm",
+        "simd/i386/jcgryext-avx2.asm",
+        "simd/i386/jcgryext-mmx.asm",
+        "simd/i386/jcgryext-sse2.asm",
+        "simd/i386/jdcolext-avx2.asm",
+        "simd/i386/jdcolext-mmx.asm",
+        "simd/i386/jdcolext-sse2.asm",
+        "simd/i386/jdmrgext-avx2.asm",
+        "simd/i386/jdmrgext-mmx.asm",
+        "simd/i386/jdmrgext-sse2.asm",
+      ]
       sources = [
         "simd/i386/jccolor-avx2.asm",
         "simd/i386/jccolor-mmx.asm",
@@ -92,6 +108,16 @@ if (current_cpu == "x86" || current_cpu == "x64") {
       ]
     } else if (current_cpu == "x64") {
       include_dirs += [ "simd/x86_64/" ]
+      inputs += [
+        "simd/x86_64/jccolext-avx2.asm",
+        "simd/x86_64/jccolext-sse2.asm",
+        "simd/x86_64/jcgryext-avx2.asm",
+        "simd/x86_64/jcgryext-sse2.asm",
+        "simd/x86_64/jdcolext-avx2.asm",
+        "simd/x86_64/jdcolext-sse2.asm",
+        "simd/x86_64/jdmrgext-avx2.asm",
+        "simd/x86_64/jdmrgext-sse2.asm",
+      ]
       sources = [
         "simd/x86_64/jccolor-avx2.asm",
         "simd/x86_64/jccolor-sse2.asm",
diff --git a/METADATA b/METADATA
index c37f6c5..60843b0 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update libjpeg-turbo
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/libjpeg-turbo
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "libjpeg-turbo"
 description: "libjpeg-turbo is a JPEG image codec."
@@ -11,12 +11,12 @@ third_party {
   }
   last_upgrade_date {
     year: 2024
-    month: 1
-    day: 8
+    month: 9
+    day: 16
   }
   identifier {
     type: "Git"
     value: "https://chromium.googlesource.com/chromium/deps/libjpeg_turbo"
-    version: "9b894306ec3b28cea46e84c32b56773a98c483da"
+    version: "927aabfcd26897abb9776ecf2a6c38ea5bb52ab6"
   }
 }
diff --git a/README.chromium b/README.chromium
index 78e33e2..2fc5ab1 100644
--- a/README.chromium
+++ b/README.chromium
@@ -50,6 +50,10 @@ following changes which are not merged to upstream:
   lld) arising from attempts to reference the table from assembler on
   32-bit x86. This only affects shared libraries, but that's important
   for downstream Android builds.
+* Merged upstream patch https://github.com/libjpeg-turbo/libjpeg-turbo/commit/0fc7313e545a3ff499c19ee6591bb87f0ad8b2a4
+  This patch resolves an O(n^2) slowdown issue when JPEG files contain an
+  enormous number of markers; this would only occur in a maliciouly-crafted
+  image, or through fuzzing.
 * Patches to enable running the upstream unit tests through GTest.
   The upstream unit tests are defined here under the section 'TESTS':
   https://github.com/libjpeg-turbo/libjpeg-turbo/blob/master/CMakeLists.txt
diff --git a/jcomapi.c b/jcomapi.c
index efbb835..84f37e1 100644
--- a/jcomapi.c
+++ b/jcomapi.c
@@ -3,8 +3,8 @@
  *
  * This file was part of the Independent JPEG Group's software:
  * Copyright (C) 1994-1997, Thomas G. Lane.
- * It was modified by The libjpeg-turbo Project to include only code relevant
- * to libjpeg-turbo.
+ * libjpeg-turbo Modifications:
+ * Copyright (C) 2024, D. R. Commander.
  * For conditions of distribution and use, see the accompanying README.ijg
  * file.
  *
@@ -51,6 +51,7 @@ jpeg_abort(j_common_ptr cinfo)
      * A bit kludgy to do it here, but this is the most central place.
      */
     ((j_decompress_ptr)cinfo)->marker_list = NULL;
+    ((j_decompress_ptr)cinfo)->master->marker_list_end = NULL;
   } else {
     cinfo->global_state = CSTATE_START;
   }
diff --git a/jconfig.h b/jconfig.h
index d347c33..944a478 100644
--- a/jconfig.h
+++ b/jconfig.h
@@ -21,6 +21,14 @@
 /* Use accelerated SIMD routines. */
 #define WITH_SIMD 1
 
+#ifdef _WIN32
+/* Define "boolean" as unsigned char, not int, per Windows custom */
+#ifndef __RPCNDR_H__ /* don't conflict if rpcndr.h already read */
+typedef unsigned char boolean;
+#endif
+#define HAVE_BOOLEAN /* prevent jmorecfg.h from redefining it */
+#endif
+
 /*
  * Define BITS_IN_JSAMPLE as either
  *   8   for 8-bit sample values (the usual setting)
diff --git a/jconfig.h.in b/jconfig.h.in
index e018012..766c3f2 100644
--- a/jconfig.h.in
+++ b/jconfig.h.in
@@ -21,6 +21,14 @@
 /* Use accelerated SIMD routines. */
 #cmakedefine WITH_SIMD 1
 
+#ifdef _WIN32
+/* Define "boolean" as unsigned char, not int, per Windows custom */
+#ifndef __RPCNDR_H__            /* don't conflict if rpcndr.h already read */
+typedef unsigned char boolean;
+#endif
+#define HAVE_BOOLEAN            /* prevent jmorecfg.h from redefining it */
+#endif
+
 /*
  * Define BITS_IN_JSAMPLE as either
  *   8   for 8-bit sample values (the usual setting)
diff --git a/jdmarker.c b/jdmarker.c
index f7eba61..e12c955 100644
--- a/jdmarker.c
+++ b/jdmarker.c
@@ -3,8 +3,10 @@
  *
  * This file was part of the Independent JPEG Group's software:
  * Copyright (C) 1991-1998, Thomas G. Lane.
+ * Lossless JPEG Modifications:
+ * Copyright (C) 1999, Ken Murchison.
  * libjpeg-turbo Modifications:
- * Copyright (C) 2012, 2015, 2022, D. R. Commander.
+ * Copyright (C) 2012, 2015, 2022, 2024, D. R. Commander.
  * For conditions of distribution and use, see the accompanying README.ijg
  * file.
  *
@@ -815,13 +817,11 @@ save_marker(j_decompress_ptr cinfo)
   /* Done reading what we want to read */
   if (cur_marker != NULL) {     /* will be NULL if bogus length word */
     /* Add new marker to end of list */
-    if (cinfo->marker_list == NULL) {
-      cinfo->marker_list = cur_marker;
+    if (cinfo->marker_list == NULL || cinfo->master->marker_list_end == NULL) {
+      cinfo->marker_list = cinfo->master->marker_list_end = cur_marker;
     } else {
-      jpeg_saved_marker_ptr prev = cinfo->marker_list;
-      while (prev->next != NULL)
-        prev = prev->next;
-      prev->next = cur_marker;
+      cinfo->master->marker_list_end->next = cur_marker;
+      cinfo->master->marker_list_end = cur_marker;
     }
     /* Reset pointer & calc remaining data length */
     data = cur_marker->data;
diff --git a/jpegint.h b/jpegint.h
index 6af9e2a..d4adc98 100644
--- a/jpegint.h
+++ b/jpegint.h
@@ -4,8 +4,10 @@
  * This file was part of the Independent JPEG Group's software:
  * Copyright (C) 1991-1997, Thomas G. Lane.
  * Modified 1997-2009 by Guido Vollbeding.
+ * Lossless JPEG Modifications:
+ * Copyright (C) 1999, Ken Murchison.
  * libjpeg-turbo Modifications:
- * Copyright (C) 2015-2016, 2019, 2021, D. R. Commander.
+ * Copyright (C) 2015-2017, 2019, 2021-2022, 2024, D. R. Commander.
  * Copyright (C) 2015, Google, Inc.
  * Copyright (C) 2021, Alex Richardson.
  * For conditions of distribution and use, see the accompanying README.ijg
@@ -174,6 +176,9 @@ struct jpeg_decomp_master {
 
   /* Last iMCU row that was successfully decoded */
   JDIMENSION last_good_iMCU_row;
+
+  /* Tail of list of saved markers */
+  jpeg_saved_marker_ptr marker_list_end;
 };
 
 /* Input control module */
```

