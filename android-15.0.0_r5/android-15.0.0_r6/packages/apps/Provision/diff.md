```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 11f85c0..a589b5a 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -33,6 +33,7 @@
     <application>
         <activity android:name="DefaultActivity"
              android:excludeFromRecents="true"
+             android:directBootAware="true"
              android:exported="true">
             <intent-filter android:priority="1">
                 <action android:name="android.intent.action.MAIN"/>
```

