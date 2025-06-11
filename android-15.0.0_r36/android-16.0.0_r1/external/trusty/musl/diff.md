```diff
diff --git a/include/endian.h b/include/endian.h
index f201a0bb..4ded32f7 100644
--- a/include/endian.h
+++ b/include/endian.h
@@ -26,7 +26,7 @@
 
 static __inline uint16_t __bswap16(uint16_t __x)
 {
-	return __x<<8 | __x>>8;
+	return ((uint16_t)(__x<<8)) | ((uint16_t)(__x>>8));
 }
 
 static __inline uint32_t __bswap32(uint32_t __x)
```

