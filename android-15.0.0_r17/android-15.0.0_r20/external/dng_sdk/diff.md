```diff
diff --git a/OWNERS b/OWNERS
index 9a9ef38..8442daf 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
-adaubert@google.com
+adaubert@google.com # legacy, only for compliance reasons still in place.
+nchusid@google.com
\ No newline at end of file
diff --git a/source/dng_lossless_jpeg.cpp b/source/dng_lossless_jpeg.cpp
index 9d0d01a..8802f32 100644
--- a/source/dng_lossless_jpeg.cpp
+++ b/source/dng_lossless_jpeg.cpp
@@ -1616,6 +1616,10 @@ inline int32 dng_lossless_decoder::get_bit ()
 inline int32 dng_lossless_decoder::HuffDecode (HuffmanTable *htbl)
 	{
 	
+	if (htbl == nullptr) {
+		ThrowBadFormat ();
+	}
+
     // If the huffman code is less than 8 bits, we can use the fast
     // table lookup to get its value.  It's more than 8 bits about
     // 3-4% of the time.
```

