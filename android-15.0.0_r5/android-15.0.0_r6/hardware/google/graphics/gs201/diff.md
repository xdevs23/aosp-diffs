```diff
diff --git a/libhwc2.1/libresource/ExynosMPPModule.cpp b/libhwc2.1/libresource/ExynosMPPModule.cpp
index c532117..1457122 100644
--- a/libhwc2.1/libresource/ExynosMPPModule.cpp
+++ b/libhwc2.1/libresource/ExynosMPPModule.cpp
@@ -52,6 +52,9 @@ bool ExynosMPPModule::checkSpecificRestriction(const uint32_t refreshRate,
         } else if (src.w >= 1680 && src.h > dst.h && (dst.h * 100 / src.h) < 60) {
             // vertical downscale RGB layer
             return true;
+        } else if (src.w >= 2480 && src.h > dst.h && (dst.h * 100 / src.h) < 75) {
+            // vertical downscale RGB layer
+            return true;
         }
     }
 
```

