```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 18f3848..1fa49f3 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -86,7 +86,7 @@
         <activity android:name="StkInputActivity"
             android:label="@string/app_name"
             android:icon="@drawable/ic_launcher_sim_toolkit"
-            android:theme="@style/Theme.AppCompat.DayNight.NoActionBar"
+            android:theme="@style/StkInputTheme"
             android:configChanges="orientation|locale|screenSize|keyboardHidden"
             android:exported="false"
             android:autoRemoveFromRecents="true"
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 1239170..dc4f3c3 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -29,12 +29,12 @@
     <string name="alphabet" msgid="9068318253752197929">"Alphabets"</string>
     <string name="digits" msgid="7391551783961486324">"Digits (0-9, *, #, +)"</string>
     <string name="default_call_setup_msg" msgid="6490156065165946828">"Call in progress…"</string>
-    <string name="default_setup_call_msg" msgid="5819132588246209714">"Call being set up"</string>
-    <string name="stk_app_state" msgid="6274976677198791616">"Application status"</string>
+    <string name="default_setup_call_msg" msgid="5819132588246209714">"Call being setup"</string>
+    <string name="stk_app_state" msgid="6274976677198791616">"Application state"</string>
     <string name="enable_app" msgid="1980493713217690903">"Enabled"</string>
     <string name="disable_app" msgid="2298201833946002357">"Disabled"</string>
-    <string name="stk_dialog_title" msgid="1047336800509270520">"SIM Tool Kit"</string>
-    <string name="default_tone_dialog_msg" msgid="8354658178971283852">"Playing tone"</string>
+    <string name="stk_dialog_title" msgid="1047336800509270520">"SIM ToolKit"</string>
+    <string name="default_tone_dialog_msg" msgid="8354658178971283852">"Playing Tone"</string>
     <string name="default_open_channel_msg" msgid="2043011408855389673">"Open Channel?"</string>
     <string name="default_send_data_msg" msgid="6602200147341683792">"Sending Data"</string>
     <string name="default_receive_data_msg" msgid="5545535916402887726">"Receiving Data"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index d0eefab..62128f3 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -42,5 +42,5 @@
     <string name="stk_dialog_accept" msgid="2899431442032305374">"હા"</string>
     <string name="stk_dialog_reject" msgid="1455086565615694879">"નહીં"</string>
     <string name="no_sim_card_inserted" msgid="3177955793136053581">"કૃપા કરીને સિમ ટૂલકિટ લોન્ચ કરવા માટે સિમ શામેલ કરો."</string>
-    <string name="stk_channel_name" msgid="3945765236566954372">"મોબાઇલ સેવાના સંદેશા"</string>
+    <string name="stk_channel_name" msgid="3945765236566954372">"મોબાઇલ સેવાના મેસેજ"</string>
 </resources>
diff --git a/res/values/styles.xml b/res/values/styles.xml
index 1b07a74..8f373c3 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -27,4 +27,9 @@
     <style name="StkTheme" parent="@android:style/Theme.DeviceDefault.DayNight">
         <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
     </style>
+
+    <style name="StkInputTheme" parent="@style/Theme.AppCompat.DayNight.NoActionBar">
+        <item name="android:statusBarColor">@android:color/transparent</item>
+        <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
+    </style>
 </resources>
```

