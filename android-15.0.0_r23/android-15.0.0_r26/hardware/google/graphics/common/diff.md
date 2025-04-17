```diff
diff --git a/libhwc2.1/libresource/ExynosMPP.cpp b/libhwc2.1/libresource/ExynosMPP.cpp
index 3d22575..3a529a8 100644
--- a/libhwc2.1/libresource/ExynosMPP.cpp
+++ b/libhwc2.1/libresource/ExynosMPP.cpp
@@ -2164,6 +2164,16 @@ int64_t ExynosMPP::isSupported(ExynosDisplay &display, struct exynos_image &src,
     if (!isSupportLayerColorTransform(src,dst))
         return -eMPPUnsupportedColorTransform;
 
+    if (mMPPType == MPP_TYPE_M2M) {
+        // G2D currently always sets the canvas size as the aligned full-screen size
+        if (dst.x + dst.w > pixel_align(display.mXres, getDstStrideAlignment(dst.format))) {
+            return -eMPPExceedCanvasWidth;
+        }
+        if (dst.y + dst.h > pixel_align(display.mYres, G2D_JUSTIFIED_DST_ALIGN)) {
+            return -eMPPExceedCanvasHeight;
+        }
+    }
+
     return NO_ERROR;
 }
 
diff --git a/libhwc2.1/libresource/ExynosMPP.h b/libhwc2.1/libresource/ExynosMPP.h
index 6beca8a..63828bf 100644
--- a/libhwc2.1/libresource/ExynosMPP.h
+++ b/libhwc2.1/libresource/ExynosMPP.h
@@ -173,6 +173,8 @@ enum {
     eMPPUnsupportedDynamicMeta    =     1ULL << 32,
     eMPPSatisfiedRestriction      =     1ULL << 33,
     eMPPExeedHWResource           =     1ULL << 34,
+    eMPPExceedCanvasWidth         =     1ULL << 35,
+    eMPPExceedCanvasHeight        =     1ULL << 36,
 };
 
 enum {
```

