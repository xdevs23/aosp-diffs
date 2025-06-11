```diff
diff --git a/Android.bp b/Android.bp
index a864ec33f..ebec43cf0 100644
--- a/Android.bp
+++ b/Android.bp
@@ -41,6 +41,7 @@ android_app {
     ],
 
     optimize: {
+        keep_runtime_invisible_annotations: true,
         proguard_flags_files: ["proguard.flags"],
     },
 
diff --git a/proguard.flags b/proguard.flags
index 4054922b0..1a3b43dfb 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -50,13 +50,19 @@
 -keep interface android.support.v4.app.** { *; }
 -keep class com.actionbarsherlock.** { *; }
 -keep interface com.actionbarsherlock.** { *; }
--keepattributes *Annotation*
+-keepattributes RuntimeVisibleAnnotations,
+                RuntimeVisibleParameterAnnotations,
+                RuntimeVisibleTypeAnnotations,
+                AnnotationDefault
 
 # Required for JobIntentService
 -keep class androidx.core.app.CoreComponentFactory { *; }
 
 # Required for mp4parser
--keep public class * implements com.coremedia.iso.boxes.Box
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep public class * implements com.coremedia.iso.boxes.Box {
+  void <init>();
+}
 
 #-assumenosideeffects junit.framework.Assert {
 #*;
@@ -90,5 +96,3 @@
 -keep class com.android.gallery3d.jpegstream.JPEGOutputStream { *; }
 -keep class com.android.gallery3d.jpegstream.JPEGInputStream { *; }
 -keep class com.android.gallery3d.jpegstream.StreamUtils { *; }
-
-
```

