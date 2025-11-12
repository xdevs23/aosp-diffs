```diff
diff --git a/EmergencyGestureAction/AndroidManifest.xml b/EmergencyGestureAction/AndroidManifest.xml
index 33219e9..d689167 100644
--- a/EmergencyGestureAction/AndroidManifest.xml
+++ b/EmergencyGestureAction/AndroidManifest.xml
@@ -33,9 +33,9 @@
         android:appComponentFactory="androidx.core.app.CoreComponentFactory"
         tools:replace="android:appComponentFactory">
 
-        <activity-alias android:name=".action.EmergencyAction"
+        <activity-alias android:name="com.android.emergency.action.EmergencyAction"
                         android:label="@string/emergency_action_title"
-                        android:targetActivity=".action.EmergencyActionActivity"
+                        android:targetActivity="com.android.emergency.action.EmergencyActionActivity"
                         android:permission="android.permission.MANAGE_SENSOR_PRIVACY"
                         android:directBootAware="true"
                         android:enabled="true"
@@ -48,7 +48,7 @@
         </activity-alias>
 
         <activity
-            android:name=".action.EmergencyActionActivity"
+            android:name="com.android.emergency.action.EmergencyActionActivity"
             android:label="@string/emergency_action_title"
             android:theme="@style/AppThemeEmergencyAction"
             android:directBootAware="true"
@@ -59,7 +59,7 @@
             android:exported="false"/>
 
         <service
-            android:name=".action.service.EmergencyActionForegroundService"
+            android:name="com.android.emergency.action.service.EmergencyActionForegroundService"
             android:directBootAware="true"
             android:foregroundServiceType="specialUse"
             android:exported="false">
@@ -67,7 +67,7 @@
         </service>
 
         <receiver
-            android:name=".action.broadcast.EmergencyActionBroadcastReceiver"
+            android:name="com.android.emergency.action.broadcast.EmergencyActionBroadcastReceiver"
             android:exported="false">
             <intent-filter>
                 <action android:name="com.android.emergency.broadcast.MAKE_EMERGENCY_CALL" />
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 4020a62..3bf5907 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -100,7 +100,7 @@
     <string name="phone_type_and_phone_number" msgid="5034188169563878371">"<xliff:g id="PHONE_TYPE">%1$s</xliff:g> • <xliff:g id="PHONE_NUMBER">%2$s</xliff:g>"</string>
     <string name="no_info_provided" msgid="716200382010821001">"ఫోన్ యజమాని గురించి సమాచారం ఏదీ లేదు"</string>
     <string name="tap_pencil" msgid="3429817710241457947">"మీ ఫోన్ అన్‌లాక్ చేయబడినప్పుడు, ఎమర్జెన్సీ పరిస్థితుల్లో ఇక్కడ ప్రదర్శించబడే సమాచారాన్ని జోడించడానికి పెన్సిల్ చిహ్నాన్ని ట్యాప్ చేయండి"</string>
-    <string name="clear_all" msgid="8899013032870561633">"అన్నీ తీసివేయండి"</string>
+    <string name="clear_all" msgid="8899013032870561633">"అన్నీ క్లియర్ చేయండి"</string>
     <string name="clear" msgid="3648880442502887163">"తీసివేయండి"</string>
     <string name="clear_all_message" msgid="1548432000373861295">"మొత్తం సమాచారం మరియు కాంటాక్ట్‌లను తీసివేయాలా?"</string>
     <string name="emergency_info_footer" msgid="8751758742506410146">"వైద్య సమాచారం మరియు అత్యవసర కాంటాక్ట్‌లను జోడిస్తే, అత్యవసర పరిస్థితిలో ముందుగా ప్రతిస్పందించే వారికి సహాయకరంగా ఉంటాయి.\n\nఎవరైనా సరే, మీ ఫోన్‌ని అన్‌లాక్ చేయకుండానే మీ లాక్ స్క్రీన్ నుండి ఈ సమాచారాన్ని చదవగలరు మరియు మీ కాంటాక్ట్‌ల పేర్లు ట్యాప్ చేయడం ద్వారా వారికి కాల్ చేయగలరు."</string>
```

