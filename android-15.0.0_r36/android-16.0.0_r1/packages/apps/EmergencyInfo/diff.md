```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 5780a17..d1826a2 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -50,6 +50,7 @@
          android:label="@string/app_label"
          android:supportsRtl="true"
          android:appComponentFactory="androidx.core.app.CoreComponentFactory"
+         android:enableOnBackInvokedCallback="false"
          tools:replace="android:appComponentFactory">
         <activity android:name=".view.ViewInfoActivity"
              android:theme="@style/AppThemeEmergency"
diff --git a/OWNERS b/OWNERS
index 1da401c..d2ced88 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,9 +1,7 @@
-# Default code reviewers picked from top 3 or more developers.
-# Please update this list if you find better candidates.
+# Listed in order of preference, but all are equally responsible.
+jpdsmith@google.com
 peet@google.com
-lindatseng@google.com
-mfritze@google.com
-zhfan@google.com
+aadambek@google.com
 
 #GestureLauncherService
 joselima@google.com
diff --git a/tests/robolectric/Android.bp b/tests/robolectric/Android.bp
index 2f084fc..3239e7f 100644
--- a/tests/robolectric/Android.bp
+++ b/tests/robolectric/Android.bp
@@ -23,6 +23,5 @@ android_robolectric_test {
     java_resource_dirs: ["config"],
     static_libs: ["emergencyinfo-test-common"],
     instrumentation_for: "EmergencyInfo",
-    upstream: true,
     strict_mode: false,
 }
```

