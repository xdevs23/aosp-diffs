```diff
diff --git a/OWNERS b/OWNERS
index ffd753e..5f90cef 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1 @@
 jmtrivi@google.com
-gkasten@android.com
diff --git a/libSBRdec/src/lpp_tran.cpp b/libSBRdec/src/lpp_tran.cpp
index 68a25bf..01951c8 100644
--- a/libSBRdec/src/lpp_tran.cpp
+++ b/libSBRdec/src/lpp_tran.cpp
@@ -118,7 +118,11 @@ amm-info@iis.fraunhofer.de
   \sa lppTransposer(), main_audio.cpp, sbr_scale.h, \ref documentationOverview
 */
 
-#ifdef __ANDROID__
+#if __has_include(<android/ndk-version.h>)
+#include <android/ndk-version.h>
+#endif
+
+#if defined __ANDROID__ && !defined __ANDROID_NDK__
 #include "log/log.h"
 #endif
 
@@ -334,7 +338,7 @@ void lppTransposer(
       }
     }
   }
-#ifdef __ANDROID__
+#if defined __ANDROID__ && !defined __ANDROID_NDK__
   else {
     // Safetynet logging
     android_errorWriteLog(0x534e4554, "112160868");
@@ -930,7 +934,7 @@ void lppTransposerHBE(
       FDKmemclear(&qmfBufferImag[i][targetStopBand], memSize);
     }
   }
-#ifdef __ANDROID__
+#if defined __ANDROID__ && !defined __ANDROID_NDK__
   else {
     // Safetynet logging
     android_errorWriteLog(0x534e4554, "112160868");
```

