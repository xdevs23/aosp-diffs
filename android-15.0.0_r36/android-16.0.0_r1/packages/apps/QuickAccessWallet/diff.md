```diff
diff --git a/Android.bp b/Android.bp
index af9d42a..d89b528 100644
--- a/Android.bp
+++ b/Android.bp
@@ -31,6 +31,7 @@ android_app {
         "androidx.recyclerview_recyclerview",
     ],
     optimize: {
+        keep_runtime_invisible_annotations: true,
         proguard_flags_files: [
             "proguard.flags",
         ],
diff --git a/proguard.flags b/proguard.flags
index 9a5b943..d35e37e 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -1,4 +1,7 @@
--keepattributes *Annotation*
+-keepattributes RuntimeVisibleAnnotations,
+                RuntimeVisibleParameterAnnotations,
+                RuntimeVisibleTypeAnnotations,
+                AnnotationDefault
 -keep class com.android.systemui.plugins.annotations.* { *; }
 -keep class com.android.systemui.plugins.GlobalActionsPanelPlugin { *; }
 -keep class com.android.systemui.plugins.GlobalActionsPanelPlugin.* { *; }
diff --git a/tests/robolectric/Android.bp b/tests/robolectric/Android.bp
index 6b57e4e..0b29e4e 100644
--- a/tests/robolectric/Android.bp
+++ b/tests/robolectric/Android.bp
@@ -31,6 +31,5 @@ android_robolectric_test {
         "androidx.test.runner",
         "androidx.test.ext.junit",
     ],
-    upstream: true,
     strict_mode: false,
 }
```

