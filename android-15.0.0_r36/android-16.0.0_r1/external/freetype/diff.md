```diff
diff --git a/OWNERS b/OWNERS
index 862b5c7d6..f4e7f8aac 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 set noparent
 
 file:platform/frameworks/base:/core/java/android/text/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/devel-teeui/OWNERS b/devel-teeui/OWNERS
index 205025ed9..b79a4c421 100644
--- a/devel-teeui/OWNERS
+++ b/devel-teeui/OWNERS
@@ -1,4 +1,3 @@
 jdanis@google.com
 mmaurer@google.com
-trong@google.com
 ncbray@google.com
diff --git a/src/sfnt/ttcolr.c b/src/sfnt/ttcolr.c
index d3af201cc..281e7135e 100644
--- a/src/sfnt/ttcolr.c
+++ b/src/sfnt/ttcolr.c
@@ -208,19 +208,18 @@
     colr->num_base_glyphs = FT_NEXT_USHORT( p );
     base_glyph_offset     = FT_NEXT_ULONG( p );
 
-    if ( table_size <= base_glyph_offset )
+    if ( base_glyph_offset >= table_size )
       goto InvalidTable;
-    if ( ( table_size - base_glyph_offset ) / BASE_GLYPH_SIZE
-             < colr->num_base_glyphs )
+    if ( colr->num_base_glyphs * BASE_GLYPH_SIZE >
+           table_size - base_glyph_offset )
       goto InvalidTable;
 
     layer_offset     = FT_NEXT_ULONG( p );
     colr->num_layers = FT_NEXT_USHORT( p );
 
-    if ( table_size <= layer_offset )
+    if ( layer_offset >= table_size )
       goto InvalidTable;
-    if ( ( table_size - layer_offset ) / LAYER_SIZE
-             < colr->num_layers )
+    if ( colr->num_layers * LAYER_SIZE > table_size - layer_offset )
       goto InvalidTable;
 
     if ( colr->version == 1 )
@@ -230,14 +229,14 @@
 
       base_glyphs_offset_v1 = FT_NEXT_ULONG( p );
 
-      if ( table_size - 4 <= base_glyphs_offset_v1 )
+      if ( base_glyphs_offset_v1 >= table_size - 4 )
         goto InvalidTable;
 
       p1                 = (FT_Byte*)( table + base_glyphs_offset_v1 );
       num_base_glyphs_v1 = FT_PEEK_ULONG( p1 );
 
-      if ( ( table_size - base_glyphs_offset_v1 ) / BASE_GLYPH_PAINT_RECORD_SIZE
-               < num_base_glyphs_v1 )
+      if ( num_base_glyphs_v1 * BASE_GLYPH_PAINT_RECORD_SIZE >
+             table_size - base_glyphs_offset_v1 )
         goto InvalidTable;
 
       colr->num_base_glyphs_v1 = num_base_glyphs_v1;
@@ -245,19 +244,19 @@
 
       layer_offset_v1 = FT_NEXT_ULONG( p );
 
-      if ( table_size <= layer_offset_v1 )
+      if ( layer_offset_v1 >= table_size )
         goto InvalidTable;
 
       if ( layer_offset_v1 )
       {
-        if ( table_size - 4 <= layer_offset_v1 )
+        if ( layer_offset_v1 >= table_size - 4 )
           goto InvalidTable;
 
         p1            = (FT_Byte*)( table + layer_offset_v1 );
         num_layers_v1 = FT_PEEK_ULONG( p1 );
 
-        if ( ( table_size - layer_offset_v1 ) / LAYER_V1_LIST_PAINT_OFFSET_SIZE
-                < num_layers_v1 )
+        if ( num_layers_v1 * LAYER_V1_LIST_PAINT_OFFSET_SIZE >
+               table_size - layer_offset_v1 )
           goto InvalidTable;
 
         colr->num_layers_v1 = num_layers_v1;
@@ -280,7 +279,7 @@
 
       clip_list_offset = FT_NEXT_ULONG( p );
 
-      if ( table_size <= clip_list_offset )
+      if ( clip_list_offset >= table_size )
         goto InvalidTable;
 
       if ( clip_list_offset )
@@ -312,7 +311,7 @@
           goto InvalidTable;
 
         var_store_offset = FT_NEXT_ULONG( p );
-        if ( table_size <= var_store_offset )
+        if ( var_store_offset >= table_size )
           goto InvalidTable;
 
         if ( var_store_offset )
```

