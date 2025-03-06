```diff
diff --git a/README b/README
new file mode 100644
index 000000000..1372f2874
--- /dev/null
+++ b/README
@@ -0,0 +1,4 @@
+This app is not actively supported and the source is only available as a
+reference. This project will be removed from the source manifest sometime in the
+future.
+
diff --git a/gallerycommon/src/com/android/gallery3d/exif/ExifParser.java b/gallerycommon/src/com/android/gallery3d/exif/ExifParser.java
index 5467d423d..29bb1bfb4 100644
--- a/gallerycommon/src/com/android/gallery3d/exif/ExifParser.java
+++ b/gallerycommon/src/com/android/gallery3d/exif/ExifParser.java
@@ -617,11 +617,7 @@ class ExifParser {
             if (isThumbnailRequested()) {
                 if (tag.hasValue()) {
                     for (int i = 0; i < tag.getComponentCount(); i++) {
-                        if (tag.getDataType() == ExifTag.TYPE_UNSIGNED_SHORT) {
-                            registerUncompressedStrip(i, tag.getValueAt(i));
-                        } else {
-                            registerUncompressedStrip(i, tag.getValueAt(i));
-                        }
+                        registerUncompressedStrip(i, tag.getValueAt(i));
                     }
                 } else {
                     mCorrespondingEvent.put(tag.getOffset(), new ExifTagEvent(tag, false));
```

