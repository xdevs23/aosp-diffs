```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 4d7c870..16ad71b 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -37,4 +37,7 @@
   <!-- Required to trigger action 'bug report capture' in ActivityManagerService -->
   <uses-permission android:name="android.permission.READ_LOGS" />
   <uses-permission android:name="android.permission.DUMP" />
+
+   <!--    Required for skipping the bugreport consent popup displayed by the OS  -->
+  <uses-permission android:name="android.permission.CAPTURE_CONSENTLESS_BUGREPORT_DELEGATED_CONSENT" />
 </manifest>
diff --git a/privapp-permissions-com.android.tv.feedbackconsent.xml b/privapp-permissions-com.android.tv.feedbackconsent.xml
index 968c0e2..060aab6 100644
--- a/privapp-permissions-com.android.tv.feedbackconsent.xml
+++ b/privapp-permissions-com.android.tv.feedbackconsent.xml
@@ -18,5 +18,8 @@
   <privapp-permissions package="com.android.tv.feedbackconsent">
     <permission name="android.permission.DUMP" />
     <permission name="android.permission.READ_LOGS" />
+
+    <!--    Required for skipping the bugreport consent popup displayed by the OS  -->
+    <permission name="android.permission.CAPTURE_CONSENTLESS_BUGREPORT_DELEGATED_CONSENT" />
   </privapp-permissions>
 </permissions>
\ No newline at end of file
```

