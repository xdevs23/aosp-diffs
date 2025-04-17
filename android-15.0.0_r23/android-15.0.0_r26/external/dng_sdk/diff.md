```diff
diff --git a/source/dng_ifd.cpp b/source/dng_ifd.cpp
index 7f22065..bf3fb2c 100644
--- a/source/dng_ifd.cpp
+++ b/source/dng_ifd.cpp
@@ -351,7 +351,8 @@ bool dng_ifd::ParseTag (dng_stream &stream,
 			
 			CheckTagType (parentCode, tagCode, tagType, ttShort);
 			
-			CheckTagCount (parentCode, tagCode, tagCount, 1, 0x0FFFF);
+			if (!CheckTagCount (parentCode, tagCode, tagCount, 1, 0x0FFFF))
+				return false;
 			
 			#if qDNGValidate
 			
@@ -973,7 +974,8 @@ bool dng_ifd::ParseTag (dng_stream &stream,
 			
 			CheckTagType (parentCode, tagCode, tagType, ttShort);
 			
-			CheckTagCount (parentCode, tagCode, tagCount, 1, fSamplesPerPixel);
+			if (!CheckTagCount (parentCode, tagCode, tagCount, 1, fSamplesPerPixel))
+				return false;
 			
 			#if qDNGValidate
 			
@@ -1025,7 +1027,8 @@ bool dng_ifd::ParseTag (dng_stream &stream,
 			
 			CheckTagType (parentCode, tagCode, tagType, ttShort);
 			
-			CheckTagCount (parentCode, tagCode, tagCount, fSamplesPerPixel);
+			if (!CheckTagCount (parentCode, tagCode, tagCount, fSamplesPerPixel))
+				return false;
 			
 			#if qDNGValidate
 			
```

