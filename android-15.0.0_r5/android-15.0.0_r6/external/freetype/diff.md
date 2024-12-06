```diff
diff --git a/src/sfnt/ttcolr.c b/src/sfnt/ttcolr.c
index 281e7135e..d3af201cc 100644
--- a/src/sfnt/ttcolr.c
+++ b/src/sfnt/ttcolr.c
@@ -208,18 +208,19 @@
     colr->num_base_glyphs = FT_NEXT_USHORT( p );
     base_glyph_offset     = FT_NEXT_ULONG( p );
 
-    if ( base_glyph_offset >= table_size )
+    if ( table_size <= base_glyph_offset )
       goto InvalidTable;
-    if ( colr->num_base_glyphs * BASE_GLYPH_SIZE >
-           table_size - base_glyph_offset )
+    if ( ( table_size - base_glyph_offset ) / BASE_GLYPH_SIZE
+             < colr->num_base_glyphs )
       goto InvalidTable;
 
     layer_offset     = FT_NEXT_ULONG( p );
     colr->num_layers = FT_NEXT_USHORT( p );
 
-    if ( layer_offset >= table_size )
+    if ( table_size <= layer_offset )
       goto InvalidTable;
-    if ( colr->num_layers * LAYER_SIZE > table_size - layer_offset )
+    if ( ( table_size - layer_offset ) / LAYER_SIZE
+             < colr->num_layers )
       goto InvalidTable;
 
     if ( colr->version == 1 )
@@ -229,14 +230,14 @@
 
       base_glyphs_offset_v1 = FT_NEXT_ULONG( p );
 
-      if ( base_glyphs_offset_v1 >= table_size - 4 )
+      if ( table_size - 4 <= base_glyphs_offset_v1 )
         goto InvalidTable;
 
       p1                 = (FT_Byte*)( table + base_glyphs_offset_v1 );
       num_base_glyphs_v1 = FT_PEEK_ULONG( p1 );
 
-      if ( num_base_glyphs_v1 * BASE_GLYPH_PAINT_RECORD_SIZE >
-             table_size - base_glyphs_offset_v1 )
+      if ( ( table_size - base_glyphs_offset_v1 ) / BASE_GLYPH_PAINT_RECORD_SIZE
+               < num_base_glyphs_v1 )
         goto InvalidTable;
 
       colr->num_base_glyphs_v1 = num_base_glyphs_v1;
@@ -244,19 +245,19 @@
 
       layer_offset_v1 = FT_NEXT_ULONG( p );
 
-      if ( layer_offset_v1 >= table_size )
+      if ( table_size <= layer_offset_v1 )
         goto InvalidTable;
 
       if ( layer_offset_v1 )
       {
-        if ( layer_offset_v1 >= table_size - 4 )
+        if ( table_size - 4 <= layer_offset_v1 )
           goto InvalidTable;
 
         p1            = (FT_Byte*)( table + layer_offset_v1 );
         num_layers_v1 = FT_PEEK_ULONG( p1 );
 
-        if ( num_layers_v1 * LAYER_V1_LIST_PAINT_OFFSET_SIZE >
-               table_size - layer_offset_v1 )
+        if ( ( table_size - layer_offset_v1 ) / LAYER_V1_LIST_PAINT_OFFSET_SIZE
+                < num_layers_v1 )
           goto InvalidTable;
 
         colr->num_layers_v1 = num_layers_v1;
@@ -279,7 +280,7 @@
 
       clip_list_offset = FT_NEXT_ULONG( p );
 
-      if ( clip_list_offset >= table_size )
+      if ( table_size <= clip_list_offset )
         goto InvalidTable;
 
       if ( clip_list_offset )
@@ -311,7 +312,7 @@
           goto InvalidTable;
 
         var_store_offset = FT_NEXT_ULONG( p );
-        if ( var_store_offset >= table_size )
+        if ( table_size <= var_store_offset )
           goto InvalidTable;
 
         if ( var_store_offset )
```

