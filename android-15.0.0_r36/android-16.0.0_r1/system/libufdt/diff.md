```diff
diff --git a/sysdeps/libufdt_sysdeps_posix.c b/sysdeps/libufdt_sysdeps_posix.c
index c1c9f41..e4b1ed1 100644
--- a/sysdeps/libufdt_sysdeps_posix.c
+++ b/sysdeps/libufdt_sysdeps_posix.c
@@ -21,6 +21,7 @@
 #include <stdlib.h>
 #include <string.h>
 
+#ifndef DTO_DISABLE_DEFAULT_POSIX_LIBC_PRINT
 int dto_print(const char *fmt, ...) {
   int err;
 
@@ -31,6 +32,7 @@ int dto_print(const char *fmt, ...) {
 
   return err;
 }
+#endif
 
 void dto_qsort(void *base, size_t nmemb, size_t size,
                int (*compar)(const void *, const void *)) {
diff --git a/ufdt_convert.c b/ufdt_convert.c
index 8147f5b..37be5a4 100644
--- a/ufdt_convert.c
+++ b/ufdt_convert.c
@@ -291,6 +291,11 @@ int phandle_table_entry_cmp(const void *pa, const void *pb) {
 struct ufdt_static_phandle_table build_phandle_table(struct ufdt *tree) {
   struct ufdt_static_phandle_table res;
   res.len = count_phandle_node(tree->root);
+  if (!res.len) {
+    dto_debug("phandle table is empty\n");
+    res.data = NULL;
+    return res;
+  }
   res.data = dto_malloc(sizeof(struct ufdt_phandle_table_entry) * res.len);
   int cur = 0;
   set_phandle_table_entry(tree->root, res.data, &cur);
@@ -366,7 +371,7 @@ static int _ufdt_output_property_to_fdt(
       (struct fdt_property *)((char *)fdtp + fdt_off_dt_struct(fdtp) +
                               new_propoff);
   char *fdt_end = (char *)fdtp + fdt_totalsize(fdtp);
-  if ((char *)new_prop + new_prop_size > fdt_end) {
+  if (fdt_end - (char *)new_prop < (ptrdiff_t)new_prop_size) {
     dto_error("Not enough space for adding property.\n");
     return -1;
   }
@@ -426,6 +431,11 @@ static int _ufdt_output_strtab_to_fdt(const struct ufdt *tree, void *fdt) {
     const char *src_strtab = (const char *)src_fdt + fdt_off_dt_strings(src_fdt);
     int strtab_size = fdt_size_dt_strings(src_fdt);
 
+    if (strtab_size == 0) {
+      dto_debug("String table is empty in fdtp\n");
+      continue;
+    }
+
     dest -= strtab_size;
     if (dest < struct_top) {
       dto_error("Not enough space for string table.\n");
diff --git a/ufdt_overlay.c b/ufdt_overlay.c
index 6fa8c31..9f23c57 100644
--- a/ufdt_overlay.c
+++ b/ufdt_overlay.c
@@ -290,6 +290,12 @@ int ufdt_overlay_do_fixups(struct ufdt *main_tree, struct ufdt *overlay_tree) {
 
     const char *fixups_paths = ufdt_node_get_fdt_prop_data(fixups, &len);
 
+    if (len == 0 || !fixups_paths || fixups_paths[len - 1] != 0) {
+      dto_error("Format error for %s: fixups are not null terminated\n",
+                ufdt_node_name(fixups));
+      return -1;
+    }
+
     if (ufdt_do_one_fixup(overlay_tree, fixups_paths, len, phandle) < 0) {
       dto_error("Failed one fixup in ufdt_do_one_fixup\n");
       return -1;
diff --git a/utils/src/Android.bp b/utils/src/Android.bp
index bd79167..41d6ca8 100644
--- a/utils/src/Android.bp
+++ b/utils/src/Android.bp
@@ -58,9 +58,4 @@ python_binary_host {
     name: "mkdtboimg",
     main: "mkdtboimg.py",
     srcs: ["mkdtboimg.py"],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
```

