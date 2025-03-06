```diff
diff --git a/ufdt_overlay.c b/ufdt_overlay.c
index 4a32291..6fa8c31 100644
--- a/ufdt_overlay.c
+++ b/ufdt_overlay.c
@@ -723,10 +723,10 @@ int ufdt_apply_multioverlay(struct fdt_header *main_fdt_header,
   ufdt_node_pool_construct(&pool);
   struct ufdt *main_tree = ufdt_from_fdt(main_fdt_header, result_size, &pool);
 
-  for (int i = 0; i < overlays_count; i++) {
+  for (size_t i = 0; i < overlays_count; i++) {
     struct fdt_header *current_overlay = overlays[i];
     if (fdt_check_header(current_overlay) != 0) {
-      dto_error("Failed to parse %dth overlay header\n", i);
+      dto_error("Failed to parse %zuth overlay header\n", i);
       goto error;
     }
 
```

