```diff
diff --git a/include/features.h b/include/features.h
index f4d651ef..57b4590d 100644
--- a/include/features.h
+++ b/include/features.h
@@ -35,4 +35,10 @@
 #define _Noreturn
 #endif
 
+#if (__GNUC__ > 3) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4) || defined(__clang__)
+#define __warn_unused_result __attribute__((__warn_unused_result__))
+#else
+#define __warn_unused_result
+#endif
+
 #endif
diff --git a/include/sys/mman.h b/include/sys/mman.h
index d0761b18..63783180 100644
--- a/include/sys/mman.h
+++ b/include/sys/mman.h
@@ -109,8 +109,8 @@ extern "C" {
 
 #include <bits/mman.h>
 
-void *mmap (void *, size_t, int, int, int, off_t);
-int munmap (void *, size_t);
+__warn_unused_result void *mmap (void *, size_t, int, int, int, off_t);
+__warn_unused_result int munmap (void *, size_t);
 
 int mprotect (void *, size_t, int);
 int msync (void *, size_t, int);
```

