```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 1fa49f3..18f3848 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -86,7 +86,7 @@
         <activity android:name="StkInputActivity"
             android:label="@string/app_name"
             android:icon="@drawable/ic_launcher_sim_toolkit"
-            android:theme="@style/StkInputTheme"
+            android:theme="@style/Theme.AppCompat.DayNight.NoActionBar"
             android:configChanges="orientation|locale|screenSize|keyboardHidden"
             android:exported="false"
             android:autoRemoveFromRecents="true"
diff --git a/res/layout/stk_input.xml b/res/layout/stk_input.xml
index 427ad42..6461ca8 100644
--- a/res/layout/stk_input.xml
+++ b/res/layout/stk_input.xml
@@ -16,6 +16,7 @@
 
 <LinearLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
+    android:fitsSystemWindows="true"
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical">
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 50ad532..1f48325 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -19,7 +19,7 @@
     <string name="app_name" msgid="3369897473091780760">"‏ابزار کار SIM"</string>
     <string name="menu_end_session" msgid="9087134977926181033">"پایان جلسه"</string>
     <string name="help" msgid="1290449694178547017">"راهنمایی"</string>
-    <string name="menu_back" msgid="7136697148453089659">"برگشت"</string>
+    <string name="menu_back" msgid="7136697148453089659">"برگشتن"</string>
     <string name="service_name" msgid="6767598098497885828">"نام سرویس"</string>
     <string name="stk_no_service" msgid="1905632157498220090">"سرویسی موجود نیست"</string>
     <string name="button_ok" msgid="7914432227722142434">"تأیید"</string>
diff --git a/res/values/styles.xml b/res/values/styles.xml
index 8f373c3..1b07a74 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -27,9 +27,4 @@
     <style name="StkTheme" parent="@android:style/Theme.DeviceDefault.DayNight">
         <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
     </style>
-
-    <style name="StkInputTheme" parent="@style/Theme.AppCompat.DayNight.NoActionBar">
-        <item name="android:statusBarColor">@android:color/transparent</item>
-        <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
-    </style>
 </resources>
```

