```diff
diff --git a/mini_common.mk b/mini_common.mk
index 2ee5b56..892bcef 100644
--- a/mini_common.mk
+++ b/mini_common.mk
@@ -17,7 +17,6 @@ PRODUCT_DEVICE := mini
 PRODUCT_NAME := mini
 
 PRODUCT_SOONG_NAMESPACES += device/generic/goldfish
-PRODUCT_SOONG_NAMESPACES += device/generic/goldfish-opengl
 
 # add all configurations
 PRODUCT_AAPT_CONFIG := normal ldpi mdpi hdpi xhdpi xxhdpi
```

