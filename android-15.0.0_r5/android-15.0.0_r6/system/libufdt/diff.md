```diff
diff --git a/OWNERS b/OWNERS
index f512bb3..5aba112 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 bowgotsai@google.com
 szuweilin@google.com
+dimorinny@google.com
diff --git a/include/ufdt_overlay.h b/include/ufdt_overlay.h
index fe8bd54..af3e0c9 100644
--- a/include/ufdt_overlay.h
+++ b/include/ufdt_overlay.h
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2016 The Android Open Source Project
+ * Copyright (C) 2016-2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -39,4 +39,22 @@ struct fdt_header *ufdt_apply_overlay(struct fdt_header *main_fdt_header,
                                       void *overlay_fdtp,
                                       size_t overlay_size);
 
+/*
+ * Apply device tree `overlays` to `main_fdt_header` fdt buffer. (API is unstable)
+ *
+ * `main_fdt_header` is getting overrided by result tree, so it must
+ * have enough space (provided by `main_fdt_buffer_size`) to store it.
+ * `main_fdt_header` and all `overlays` must be 8 bytes aligned.
+ *
+ * `dto_malloc` is used for:
+ * - ufdt structures around main fdt and overlays.
+ * - result tree temporary buffer at most `main_fdt_buffer_size` size.
+ *
+ * TODO(b/362830550): expose a more comprehensive error type.
+ * Returns 0 or -1 in case of error.
+ */
+int ufdt_apply_multioverlay(struct fdt_header *main_fdt_header,
+                            size_t main_fdt_buffer_size, void *const *overlays,
+                            size_t overlays_count);
+
 #endif /* UFDT_OVERLAY_H */
diff --git a/sysdeps/libufdt_sysdeps_posix.c b/sysdeps/libufdt_sysdeps_posix.c
index 91b4e47..c1c9f41 100644
--- a/sysdeps/libufdt_sysdeps_posix.c
+++ b/sysdeps/libufdt_sysdeps_posix.c
@@ -37,9 +37,11 @@ void dto_qsort(void *base, size_t nmemb, size_t size,
   qsort(base, nmemb, size, compar);
 }
 
+#ifndef DTO_DISABLE_DEFAULT_POSIX_LIBC_ALLOCATION
 void *dto_malloc(size_t size) { return malloc(size); }
 
 void dto_free(void *ptr) { free(ptr); }
+#endif
 
 char *dto_strchr(const char *s, int c) { return strchr(s, c); }
 
diff --git a/sysdeps/libufdt_sysdeps_vendor.c b/sysdeps/libufdt_sysdeps_vendor.c
index 235d995..fc5b186 100644
--- a/sysdeps/libufdt_sysdeps_vendor.c
+++ b/sysdeps/libufdt_sysdeps_vendor.c
@@ -5,6 +5,7 @@
 #include <stdlib.h>
 #include <sys/types.h>
 
+#ifndef DTO_DISABLE_DEFAULT_VENDOR_LIBC_PRINT
 int dto_print(const char *fmt, ...) {
   int err;
 
@@ -15,6 +16,7 @@ int dto_print(const char *fmt, ...) {
 
   return err;
 }
+#endif
 
 /* Codes from
  * https://android.googlesource.com/platform/bionic.git/+/eclair-release/libc/stdlib/qsort.c
@@ -180,9 +182,11 @@ void dto_qsort(void *base, size_t nmemb, size_t size,
  * bootloader source with the names conforming to POSIX.
  */
 
+#ifndef DTO_DISABLE_DEFAULT_VENDOR_LIBC_ALLOCATION
 void *dto_malloc(size_t size) { return malloc(size); }
 
 void dto_free(void *ptr) { free(ptr); }
+#endif
 
 char *dto_strchr(const char *s, int c) { return strchr(s, c); }
 
diff --git a/ufdt_overlay.c b/ufdt_overlay.c
index 69467a6..4a32291 100644
--- a/ufdt_overlay.c
+++ b/ufdt_overlay.c
@@ -690,3 +690,100 @@ fail:
 
   return NULL;
 }
+
+/*
+ * Apply device tree `overlays` to `main_fdt_header` fdt buffer. (API is unstable)
+ *
+ * `main_fdt_header` is getting overrided by result tree, so it must
+ * have enough space (provided by `main_fdt_buffer_size`) to store it.
+ * `main_fdt_header` and all `overlays` must be 8 bytes aligned.
+ *
+ * `dto_malloc` is used for:
+ * - ufdt structures around main fdt and overlays.
+ * - result tree temporary buffer at most `main_fdt_buffer_size` size.
+ *
+ * TODO(b/362830550): expose a more comprehensive error type.
+ * Returns 0 or -1 in case of error.
+ */
+int ufdt_apply_multioverlay(struct fdt_header *main_fdt_header,
+                            size_t main_fdt_buffer_size, void *const *overlays,
+                            size_t overlays_count) {
+  void *temporary_buffer = NULL;
+
+  if (main_fdt_header == NULL || fdt_check_header(main_fdt_header) != 0 ||
+      overlays == NULL) {
+    return -1;
+  }
+  if (overlays_count == 0) {
+    return 0;
+  }
+
+  size_t result_size = fdt_totalsize(main_fdt_header);
+  struct ufdt_node_pool pool;
+  ufdt_node_pool_construct(&pool);
+  struct ufdt *main_tree = ufdt_from_fdt(main_fdt_header, result_size, &pool);
+
+  for (int i = 0; i < overlays_count; i++) {
+    struct fdt_header *current_overlay = overlays[i];
+    if (fdt_check_header(current_overlay) != 0) {
+      dto_error("Failed to parse %dth overlay header\n", i);
+      goto error;
+    }
+
+    size_t overlay_size = fdt_totalsize(current_overlay);
+    result_size += overlay_size;
+
+    // prepare main tree by rebuilding phandle table. don't need to do so
+    // for the first iteration since main_tree hasn't been updated yet
+    if (i != 0) {
+      main_tree->phandle_table = build_phandle_table(main_tree);
+    }
+
+    struct ufdt *overlay_tree =
+        ufdt_from_fdt(current_overlay, overlay_size, &pool);
+    int err = ufdt_overlay_apply(main_tree, overlay_tree, overlay_size, &pool);
+    ufdt_destruct(overlay_tree, &pool);
+    if (err < 0) {
+      dto_error("Failed to apply overlay number: %d\n", i);
+      goto error;
+    }
+  }
+
+  if (result_size > main_fdt_buffer_size) {
+    dto_error(
+        "Not enough space in main_fdt to apply the overlays. Required %d, "
+        "available: %d\n",
+        result_size, main_fdt_buffer_size);
+    goto error;
+  }
+
+  // ufdt tree has references to fdt buffer, so we cannot dump ufdt to
+  // underlying fdt buffer directly. allocate intermediate buffer for that.
+  temporary_buffer = dto_malloc(result_size);
+  if (temporary_buffer == NULL) {
+    dto_error("Failed to allocate memory for temporary buffer: %d\n",
+              result_size);
+    goto error;
+  }
+
+  int err = ufdt_to_fdt(main_tree, temporary_buffer, result_size);
+  if (err < 0) {
+    dto_error(
+        "Failed to dump the result device tree to the temporary buffer\n");
+    goto error;
+  }
+  ufdt_destruct(main_tree, &pool);
+
+  dto_memcpy(main_fdt_header, temporary_buffer, result_size);
+  dto_free(temporary_buffer);
+  ufdt_node_pool_destruct(&pool);
+
+  return 0;
+
+error:
+  dto_free(temporary_buffer);
+  ufdt_destruct(main_tree, &pool);
+  ufdt_node_pool_destruct(&pool);
+
+  return -1;
+}
```

