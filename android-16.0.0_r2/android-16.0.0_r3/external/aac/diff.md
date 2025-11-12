```diff
diff --git a/Android.bp b/Android.bp
index 1c7192d..8853e3f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -31,7 +31,7 @@ license {
     ],
 }
 
-cc_library_static {
+cc_library {
     name: "libFraunhoferAAC",
     vendor_available: true,
     host_supported: true,
diff --git a/libMpegTPDec/src/tpdec_asc.cpp b/libMpegTPDec/src/tpdec_asc.cpp
index 8f77017..27bb4dc 100644
--- a/libMpegTPDec/src/tpdec_asc.cpp
+++ b/libMpegTPDec/src/tpdec_asc.cpp
@@ -479,12 +479,6 @@ void CProgramConfig_Read(CProgramConfig *pPce, HANDLE_FDK_BITSTREAM bs,
     pPce->isValid = 0;
   }
 
-  /* Check order of elements according to ISO / IEC 13818 - 7:2003(E),
-   * chapter 8.5.1 */
-  if (CProgramConfig_Check(pPce)) {
-    pPce->isValid = 0;
-  }
-
   for (i = 0; i < commentBytes; i++) {
     UCHAR text;
 
```

