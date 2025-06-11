```diff
diff --git a/files/proguard-android-optimize.txt b/files/proguard-android-optimize.txt
index 3e671f7a6..e0e841969 100644
--- a/files/proguard-android-optimize.txt
+++ b/files/proguard-android-optimize.txt
@@ -23,7 +23,10 @@
 -dontskipnonpubliclibraryclasses
 -verbose
 
--keepattributes *Annotation*
+-keepattributes AnnotationDefault,
+                RuntimeVisibleAnnotations,
+                RuntimeVisibleParameterAnnotations,
+                RuntimeVisibleTypeAnnotations
 -keep public class com.google.vending.licensing.ILicensingService
 -keep public class com.android.vending.licensing.ILicensingService
 
diff --git a/files/proguard-android.txt b/files/proguard-android.txt
index 5f254934d..698ccb587 100644
--- a/files/proguard-android.txt
+++ b/files/proguard-android.txt
@@ -16,7 +16,10 @@
 # "proguard-android-optimize.txt" file instead of this one from your
 # project.properties file.
 
--keepattributes *Annotation*
+-keepattributes AnnotationDefault,
+                RuntimeVisibleAnnotations,
+                RuntimeVisibleParameterAnnotations,
+                RuntimeVisibleTypeAnnotations
 -keep public class com.google.vending.licensing.ILicensingService
 -keep public class com.android.vending.licensing.ILicensingService
 
```

