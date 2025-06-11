```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 8e263ae9c..7a56af5be 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -120,6 +120,7 @@
     android:name="com.android.dialer.binary.aosp.AospDialerApplication"
     android:supportsRtl="true"
     android:usesCleartextTraffic="false"
+    android:enableOnBackInvokedCallback="false"
     android:extractNativeLibs="true">
   </application>
 
diff --git a/OWNERS b/OWNERS
index 42a8443b0..0c59ca895 100644
--- a/OWNERS
+++ b/OWNERS
@@ -4,6 +4,4 @@ twyen@google.com
 zachh@google.com
 linyuh@google.com
 tgunn@google.com
-hallliu@google.com
 breadley@google.com
-paulye@google.com
diff --git a/java/com/android/dialer/proguard/proguard.flags b/java/com/android/dialer/proguard/proguard.flags
index 514531353..36ff1df4b 100644
--- a/java/com/android/dialer/proguard/proguard.flags
+++ b/java/com/android/dialer/proguard/proguard.flags
@@ -1,6 +1,12 @@
 # Keep the annotation, classes, methods, and fields marked as UsedByReflection
--keep class com.android.dialer.proguard.UsedByReflection
--keep @com.android.dialer.proguard.UsedByReflection class *
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep class com.android.dialer.proguard.UsedByReflection {
+    void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @com.android.dialer.proguard.UsedByReflection class * {
+    void <init>();
+}
 -keepclassmembers class * {
     @com.android.dialer.proguard.UsedByReflection *;
 }
```

