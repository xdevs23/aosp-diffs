```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 662091733..965db102f 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -54,6 +54,7 @@
     <uses-permission android:name="android.permission.READ_SMS" />
     <uses-permission android:name="android.permission.HIDE_NON_SYSTEM_OVERLAY_WINDOWS"/>
     <uses-permission android:name="com.android.cellbroadcastservice.FULL_ACCESS_CELL_BROADCAST_HISTORY" />
+    <uses-permission android:name="com.android.cellbroadcastservice.CELL_BROADCAST_PRIVILEGE_ACCESS" />
     <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
     <uses-permission android:name="android.permission.BLUETOOTH" />
     <uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
@@ -163,6 +164,7 @@
                 <action android:name="android.intent.action.LOCALE_CHANGED" />
                 <action android:name="android.intent.action.SERVICE_STATE" />
                 <action android:name="android.intent.action.BOOT_COMPLETED" />
+                <action android:name="com.android.cellbroadcastservice.action.USER_SWITCHED" />
             </intent-filter>
             <intent-filter>
                 <action android:name="android.telephony.action.SECRET_CODE" />
diff --git a/AndroidManifest_Platform.xml b/AndroidManifest_Platform.xml
index 9cb7bd6c9..cd90f1059 100644
--- a/AndroidManifest_Platform.xml
+++ b/AndroidManifest_Platform.xml
@@ -38,6 +38,7 @@
   <uses-permission android:name="android.permission.READ_SMS" />
   <uses-permission android:name="android.permission.HIDE_NON_SYSTEM_OVERLAY_WINDOWS"/>
   <uses-permission android:name="com.android.cellbroadcastservice.FULL_ACCESS_CELL_BROADCAST_HISTORY" />
+  <uses-permission android:name="com.android.cellbroadcastservice.CELL_BROADCAST_PRIVILEGE_ACCESS" />
   <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
   <uses-permission android:name="android.permission.BLUETOOTH" />
   <uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
@@ -139,6 +140,7 @@
         <action android:name="android.telephony.action.CARRIER_CONFIG_CHANGED" />
         <action android:name="android.intent.action.SERVICE_STATE" />
         <action android:name="android.intent.action.BOOT_COMPLETED" />
+        <action android:name="com.android.cellbroadcastservice.action.USER_SWITCHED" />
       </intent-filter>
       <intent-filter>
         <action android:name="android.telephony.action.SECRET_CODE" />
diff --git a/apex/Android.bp b/apex/Android.bp
index 614c10672..52d335d7f 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -34,4 +34,8 @@ apex {
     name: "com.android.cellbroadcast",
     defaults:["com.android.cellbroadcast-defaults"],
     apps: ["CellBroadcastApp", "CellBroadcastServiceModule"],
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
diff --git a/apex/permissions/com.android.cellbroadcastservice.xml b/apex/permissions/com.android.cellbroadcastservice.xml
index 3bd9dc882..3735b1d8e 100644
--- a/apex/permissions/com.android.cellbroadcastservice.xml
+++ b/apex/permissions/com.android.cellbroadcastservice.xml
@@ -19,5 +19,6 @@
         <permission name="android.permission.MODIFY_PHONE_STATE"/>
         <permission name="android.permission.READ_PRIVILEGED_PHONE_STATE"/>
         <permission name="android.permission.RECEIVE_EMERGENCY_BROADCAST"/>
+        <permission name="android.permission.MANAGE_USERS"/>
     </privapp-permissions>
 </permissions>
\ No newline at end of file
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 238c60967..c315dc12f 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -64,9 +64,9 @@
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"‏تتغير إعدادات نظام WEA التلقائي بناءً على شريحة SIM."</string>
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"السماح بالتنبيهات"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"تلقّي الإشعارات بإنذارات الطوارئ اللاسلكية"</string>
-    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"التذكير بالإنذارات"</string>
-    <string name="enable_alert_speech_title" msgid="8052104771053526941">"نطق رسالة التنبيه"</string>
-    <string name="enable_alert_speech_summary" msgid="2855629032890937297">"استخدام ميزة \"تحويل النص إلى كلام\" للاستماع إلى رسائل إنذارات الطوارئ اللاسلكية"</string>
+    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"التذكير بالتنبيهات"</string>
+    <string name="enable_alert_speech_title" msgid="8052104771053526941">"الاستماع إلى رسالة التنبيه"</string>
+    <string name="enable_alert_speech_summary" msgid="2855629032890937297">"استخدام ميزة \"تحويل النص إلى كلام\" للاستماع إلى تنبيهات الطوارئ اللاسلكية"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"سيتم تشغيل صوت تذكير بمستوى صوت منتظم"</string>
     <string name="emergency_alert_history_title" msgid="8310173569237268431">"سجلّ تنبيهات الطوارئ"</string>
     <string name="alert_preferences_title" msgid="6001469026393248468">"الإعدادات المفضّلة للتنبيهات"</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 0eac39fdc..3fd70fd1b 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -56,7 +56,7 @@
     <string name="public_safety_message" msgid="9119928798786998252">"ৰাজহুৱা নিৰাপত্তা বিষয়ক বাৰ্তা"</string>
     <string name="state_local_test_alert" msgid="8003145745857480200">"ৰাজ্যিক/স্থানীয় পৰীক্ষামূলক সতৰ্কবাণী"</string>
     <string name="emergency_alert" msgid="624783871477634263">"জৰুৰীকালীন সতৰ্কবাণী"</string>
-    <string name="emergency_alerts_title" msgid="6605036374197485429">"সতৰ্কবাণীসমূহ"</string>
+    <string name="emergency_alerts_title" msgid="6605036374197485429">"সতৰ্কবার্তা"</string>
     <string name="notification_channel_broadcast_messages" msgid="880704362482824524">"সম্প্ৰচাৰ কৰা বাৰ্তাবোৰ"</string>
     <string name="notification_channel_emergency_alerts" msgid="5008287980979183617">"জৰুৰীকালীন সতৰ্কবাণীসমূহ"</string>
     <string name="notification_channel_emergency_alerts_high_priority" msgid="3937475297436439073">"অস্বীকৃত জৰুৰীকালীন সতৰ্কবাণী"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index a0e150124..76e8e3b97 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -170,7 +170,7 @@
     <string name="message_coordinates" msgid="356333576818059052">"ನಿರ್ದೇಶಾಂಕಗಳು:"</string>
     <string name="maximum_waiting_time" msgid="3504809124079381356">"ಗರಿಷ್ಠ ಕಾಯುವ ಸಮಯ:"</string>
     <string name="seconds" msgid="141450721520515025">"ಸೆಕೆಂಡುಗಳು"</string>
-    <string name="message_copied" msgid="6922953753733166675">"ಸಂದೇಶವನ್ನು ನಕಲಿಸಲಾಗಿದೆ"</string>
+    <string name="message_copied" msgid="6922953753733166675">"ಸಂದೇಶವನ್ನು ಕಾಪಿ ಮಾಡಲಾಗಿದೆ"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
     <string name="top_intro_roaming_text" msgid="5250650823028195358">"ನೀವು ರೋಮಿಂಗ್‌ನಲ್ಲಿರುವಾಗ ಅಥವಾ ಸಕ್ರಿಯ SIM ಕಾರ್ಡ್ ಅನ್ನು ಹೊಂದಿಲ್ಲದಿದ್ದರೆ, ಈ ಸೆಟ್ಟಿಂಗ್‌ನಲ್ಲಿ ಸೇರಿಸದ ಕೆಲವು ಅಲರ್ಟ್‌ಗಳನ್ನು ನೀವು ಸ್ವೀಕರಿಸಬಹುದು"</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"ನಿಮ್ಮ ಸೆಟ್ಟಿಂಗ್‌ಗಳು ಬದಲಾಗಿವೆ"</string>
diff --git a/res/values-mcc208/config.xml b/res/values-mcc208/config.xml
index 7f97464de..361e6532d 100644
--- a/res/values-mcc208/config.xml
+++ b/res/values-mcc208/config.xml
@@ -72,4 +72,8 @@
 
     <!-- Whether to restore the sub-toggle setting to carrier default -->
     <bool name="restore_sub_toggle_to_carrier_default">true</bool>
+    <!-- Allow user to enable/disable audio speech alert (text-to-speech for received messages)-->
+    <bool name="show_alert_speech_setting">true</bool>
+    <!-- Default value which determines whether spoken alerts enabled -->
+    <bool name="enable_alert_speech_default">false</bool>
 </resources>
diff --git a/res/values-mcc226-af/strings.xml b/res/values-mcc226-af/strings.xml
index 53d1d4527..c5bcc7a2d 100644
--- a/res/values-mcc226-af/strings.xml
+++ b/res/values-mcc226-af/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Waarskuwing oor naderende risiko"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Naderende bedreigings vir lewe en eiendom"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Waarskuwing oor vermiste kind"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-waarskuwing: waarskuwing oor vermiste kind"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-waarskuwing: Presidensiële waarskuwing"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-waarskuwing: Uiterste waarskuwing"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-waarskuwing: Uiterste waarskuwing"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-waarskuwing: Uiterste waarskuwing"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-waarskuwing: Ernstige waarskuwing"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-waarskuwing: Oefeningboodskap"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Aanbevole handelinge wat lewens of eiendom kan red"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Waarskuwing oor publieke veiligheid"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Stil waarskuwing"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Waarskuwings oor oefeninge"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Ontvang noodwaarskuwing: oefening-/drilboodskap"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-WAARSKUWING : Waarskuwing oor naderende risiko"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-WAARSKUWING : Uiterste waarskuwing"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-WAARSKUWING : Uiterste waarskuwing"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-WAARSKUWING : Uiterste waarskuwing"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-WAARSKUWING : Ernstige waarskuwing"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-WAARSKUWING: Waarskuwing oor vermiste kind"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-WAARSKUWING : Waarskuwing oor publieke veiligheid"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-WAARSKUWING : Waarskuwings oor oefeninge"</string>
 </resources>
diff --git a/res/values-mcc226-am/strings.xml b/res/values-mcc226-am/strings.xml
index 14b1787ae..623e283df 100644
--- a/res/values-mcc226-am/strings.xml
+++ b/res/values-mcc226-am/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"የአፋታኝ ስጋት ማንቂያ"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"በሕይወት እና ንብረት ላይ አፋጣኝ ስጋቶች"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"የጠፋ ልጅ ማንቂያ"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-ማንቂያ፦ የጠፋ ልጅ ማንቂያ"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-ማንቂያ፦ ፕሬዝዳንታዊ ማንቂያ"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-ማንቂያ፦ እጅግ ከፍተኛ ማስጠንቀቂያ"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-ማንቂያ፦ እጅግ ከፍተኛ ማስጠንቀቂያ"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-ማንቂያ፦ እጅግ ከፍተኛ ማስጠንቀቂያ"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-ማንቂያ፦ እጅግ ከባድ ማንቂያ"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-ማንቂያ፦ የልምምድ ማንቂያ"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"ሕይወቶች ወይም ንብረትን ሊያድኑ የሚችሉ የሚመከሩ እርምጃዎች"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"የሕዝብ ደህንነት ማንቂያ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"የፀጥታ ማንቂያ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"የአካል ብቃት እንቅስቃሴ ማንቂያዎች"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"የአደጋ ጊዜ ማንቂያ ይቀበሉ ፦ የልምምድ/ድሪል መልዕክት"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ማንቂያ ፦ አፋጣኝ ማንቂያ"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ማንቂያ ፦ እጅግ ከፍተኛ ማንቂያ"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ማንቂያ ፦ እጅግ ከፍተኛ ማንቂያ"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ማንቂያ ፦ እጅግ ከፍተኛ ማንቂያ"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ማንቂያ ፦ እጅግ ከባድ ማንቂያ"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ማንቂያ ፦ የጠፋ ልጅ ማንቂያ"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ማንቂያ ፦ የሕዝብ ደህንነት ማንቂያ"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ማንቂያ ፦ የልምምድ ማንቂያዎች"</string>
 </resources>
diff --git a/res/values-mcc226-ar/strings.xml b/res/values-mcc226-ar/strings.xml
index c4a83557c..935554d24 100644
--- a/res/values-mcc226-ar/strings.xml
+++ b/res/values-mcc226-ar/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"تنبيه الخطر الوشيك"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"تهديدات وشيكة للحياة والممتلكات"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"تنبيه بشأن فقدان طفل"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"‏RO-Alert: تنبيه بشأن فقدان طفل"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"‏RO-Alert: تنبيه رئاسي"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"‏Ro-Alert: تنبيه حالة التأهب القصوى"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"‏Ro-Alert: تنبيه حالة التأهب القصوى"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"‏Ro-Alert: تنبيه حالة التأهب القصوى"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"‏RO-Alert: تنبيه حالة خطر شديد"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"‏Ro-Alert: تنبيه تدريبي"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"الإجراءات المقترَحة التي يمكن أن تنقذ الأرواح أو الممتلكات"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"تنبيه بشأن السلامة العامة"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"تنبيه صامت"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"تنبيهات تجريبية"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"تلقّي تنبيه طوارئ: رسالة تجريبية أو تدريبية"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"‏‫RO-ALERT: تنبيه بشأن خطر وشيك"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"‏‫RO-ALERT: تنبيه حالة التأهب القصوى"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"‏‫RO-ALERT: تنبيه حالة التأهب القصوى"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"‏‫RO-ALERT: تنبيه حالة التأهب القصوى"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"‏‫RO-Alert: تنبيه حالة طوارئ خطيرة"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"‏‫RO-ALERT: تنبيه بشأن فقدان طفل"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"‏‫RO-ALERT: تنبيه بشأن السلامة العامة"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"‏‫RO-ALERT: تنبيهات تجريبية"</string>
 </resources>
diff --git a/res/values-mcc226-as/strings.xml b/res/values-mcc226-as/strings.xml
index c01285b9a..a7048ff77 100644
--- a/res/values-mcc226-as/strings.xml
+++ b/res/values-mcc226-as/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"গুৰুতৰ বিপদাশংকাৰ সতৰ্কবাৰ্তা"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"জীৱন আৰু সম্পত্তিৰ প্ৰতি চৰম ভাবুকি"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"শিশু হেৰুওৱাৰ সতৰ্কবাৰ্তা"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-সতৰ্কবাৰ্তা: শিশু হেৰুওৱাৰ সতৰ্কবাৰ্তা"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-সতর্কবার্তা: ৰাষ্ট্ৰপতিয়ে জাৰি কৰা সতৰ্কবার্তা"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-সতর্কবার্তা: অতি বেছি জৰুৰীকালীন সতর্কবার্তা"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-সতর্কবার্তা: অতি বেছি জৰুৰীকালীন সতর্কবার্তা"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-সতর্কবার্তা: অতি বেছি জৰুৰীকালীন সতর্কবার্তা"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-সতর্কবার্তা: গুৰুতৰ সতর্কবার্তা"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-সতর্কবার্তা: অনুশীলন সতর্কবার্তা"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"জীৱন অথবা সম্পত্তি ৰক্ষা কৰিব পৰা চুপাৰিছ কৰা কাৰ্যসমূহ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"ৰাজহুৱা সুৰক্ষা বিষয়ক সতৰ্কবাৰ্তা"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"নীৰৱ সতৰ্কবাৰ্তা"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"অনুশীলনৰ সতৰ্কবাৰ্তা"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"জৰুৰীকালীন সতৰ্কবাৰ্তা পাওক: অনুশীলন/ড্ৰিলৰ বাৰ্তা"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-সতৰ্কবাৰ্তা : গুৰুতৰ বিপদাশংকাৰ সতৰ্কবাৰ্তা"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-সতৰ্কবাৰ্তা : অতি বেছি জৰুৰীকালীন সতৰ্কবাৰ্তা"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-সতৰ্কবাৰ্তা : অতি বেছি জৰুৰীকালীন সতৰ্কবাৰ্তা"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-সতৰ্কবাৰ্তা : অতি বেছি জৰুৰীকালীন সতৰ্কবাৰ্তা"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-সতৰ্কবাৰ্তা: গুৰুতৰ সতৰ্কবাৰ্তা"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-সতৰ্কবাৰ্তা: শিশু হেৰুওৱাৰ সতৰ্কবাৰ্তা"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-সতৰ্কবাৰ্তা : ৰাজহুৱা সুৰক্ষা বিষয়ক সতৰ্কবাৰ্তা"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-সতৰ্কবাৰ্তা : অনুশীলনৰ সতৰ্কবাৰ্তা"</string>
 </resources>
diff --git a/res/values-mcc226-az/strings.xml b/res/values-mcc226-az/strings.xml
index 0d120623c..1b0362b30 100644
--- a/res/values-mcc226-az/strings.xml
+++ b/res/values-mcc226-az/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Yaxın təhlükə siqnalı"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Həyat və mülkiyyət üçün yaxın təhlükə"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"İtmiş Uşaq Siqnalı"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO Siqnalı: İtmiş Uşaq Siqnalı"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO siqnalı: Prezident siqnalı"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO siqnalı: Ekstremal siqnal"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO siqnalı: Ekstremal siqnal"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO siqnalı: Ekstremal siqnal"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO siqnalı: Ağır Hal siqnalı"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO siqnalı: Tapşırıq siqnalı"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Həyat və ya mülkiyyətin qorunması ilə bağlı tövsiyə olunan əməliyyatlar"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"İctimai təhlükəsizlik siqnalı"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Səssiz siqnal"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Məşq siqnalları"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Fövqəladə hal siqnalı alın: məşq/təlim mesajı"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO siqnalı: Yaxın təhlükə siqnalı"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO siqnalı: Ekstremal siqnal"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO siqnalı: Ekstremal siqnal"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO siqnalı: Ekstremal siqnal"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO siqnalı: Ağır hal siqnalı"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO siqnalı: İtmiş uşaq siqnalı"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO siqnalı: İctimai təhlükəsizlik siqnalı"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO siqnalı: Məşq siqnalı"</string>
 </resources>
diff --git a/res/values-mcc226-b+sr+Latn/strings.xml b/res/values-mcc226-b+sr+Latn/strings.xml
index bc614d176..518aec23f 100644
--- a/res/values-mcc226-b+sr+Latn/strings.xml
+++ b/res/values-mcc226-b+sr+Latn/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Upozorenje o neposrednoj opasnosti"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Neposredne pretnje po život i imovinu"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Upozorenje o nestalom detetu"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: upozorenje o nestalom detetu"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: predsedničko upozorenje"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: upozorenje o ekstremnoj opasnosti"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: upozorenje o ekstremnoj opasnosti"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: upozorenje o ekstremnoj opasnosti"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: upozorenje o ozbiljnoj opasnosti"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: vežba za slučaj upozorenja"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Preporučene radnje koje mogu da sačuvaju živote ili imovinu"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Upozorenje o javnoj bezbednosti"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Nečujno upozorenje"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Upozorenja o vežbama"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Primajte upozorenja o hitnom slučaju: poruka o vežbi"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: upozorenje o neposrednoj opasnosti"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: upozorenje o ekstremnoj opasnosti"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: upozorenje o ekstremnoj opasnosti"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: upozorenje o ekstremnoj opasnosti"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: upozorenje o ozbiljnoj opasnosti"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: upozorenje o nestalom detetu"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: upozorenje o javnoj bezbednosti"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: upozorenja o vežbama"</string>
 </resources>
diff --git a/res/values-mcc226-be/strings.xml b/res/values-mcc226-be/strings.xml
index 701b6d7aa..4d0e47f97 100644
--- a/res/values-mcc226-be/strings.xml
+++ b/res/values-mcc226-be/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Абвестка аб непазбежнай рызыцы"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Непазбежная пагроза для жыцця і маёмасці"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Абвестка аб прапаўшым дзіцяці"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: абвестка аб прапаўшым дзіцяці"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Абвестка RO: прэзідэнцкая абвестка"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Абвестка RO: экстранная абвестка"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Абвестка RO: экстранная абвестка"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Абвестка RO: экстранная абвестка"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Абвестка RO: абвестка аб сур’ёзнай пагрозе"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Абвестка RO: вучэбная абвестка"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Рэкамендаваныя дзеянні, якія могуць выратаваць жыцці ці зберагчы маёмасць"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Абвестка пра пагрозу грамадскай бяспецы"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Бязгучная абвестка"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Трэніровачныя абвесткі"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Атрымліваць экстранныя абвесткі: вучэбныя/трэніровачныя паведамленні"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: абвестка аб непазбежнай рызыцы"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: экстранная абвестка"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: экстранная абвестка"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: экстранная абвестка"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: абвестка аб сур’ёзнай пагрозе"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: абвестка аб прапаўшым дзіцяці"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: абвестка пра пагрозу грамадскай бяспецы"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: трэніровачныя абвесткі"</string>
 </resources>
diff --git a/res/values-mcc226-bg/strings.xml b/res/values-mcc226-bg/strings.xml
index 83525eda6..7bda11841 100644
--- a/res/values-mcc226-bg/strings.xml
+++ b/res/values-mcc226-bg/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Сигнал за непосредствен риск"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Непосредствени заплахи за живота и имуществото"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Сигнал за изчезнало дете"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Сигнал за изчезнало дете"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Сигнал от президента"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Сигнал за извънредна заплаха"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Сигнал за извънредна заплаха"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Сигнал за извънредна заплаха"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Сигнал за сериозна заплаха"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Сигнал за провеждане на учение"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Препоръчителни действия, които могат да спасят животи или имущество"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Сигнал за обществена безопасност"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Сигнал в тих режим"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Сигнали за провеждане на учения"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Получаване на сигнал при спешен случай: Съобщение за провеждане на учение/тренировка"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: Сигнал за непосредствен риск"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: Сигнал за извънредна заплаха"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: Сигнал за извънредна заплаха"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: Сигнал за извънредна заплаха"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: Сигнал за сериозна заплаха"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: Сигнал за изчезнало дете"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: Сигнал за обществена безопасност"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: Сигнали за провеждане на учения"</string>
 </resources>
diff --git a/res/values-mcc226-bn/strings.xml b/res/values-mcc226-bn/strings.xml
index b9e729b86..2955e3f04 100644
--- a/res/values-mcc226-bn/strings.xml
+++ b/res/values-mcc226-bn/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"গুরুতর ঝুঁকির সম্ভাবনার ব্যাপারে সতর্কতা"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"জীবন ও সম্পত্তির ব্যাপারে গুরুতর ঝুঁকি"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"নিখোঁজ বাচ্চা সম্পর্কে সতর্কতা"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-সতর্কতা: নিখোঁজ বাচ্চা সম্পর্কে সতর্কতা"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: প্রেসিডেনশিয়াল লেভেলের সতর্কতা"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: চরম সতর্কতা"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: চরম সতর্কতা"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: চরম সতর্কতা"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: গুরুতর সতর্কতা"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Exercise সতর্কতা"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"জীবন বা সম্পত্তি রক্ষা করতে পারে এমন কাজের সাজেশন"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"পাবলিক নিরাপত্তা সতর্কতা"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"নিঃশব্দ সতর্কতা"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"মহড়ার জন্য সতর্কতা"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"জরুরি সতর্কতা পান: ড্রিল/মহড়ার জন্য মেসেজ"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-সতর্কতা : গুরুতর ঝুঁকির সম্ভাবনার ব্যাপারে সতর্কতা"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-সতর্কতা : চরম সতর্কতা"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-সতর্কতা : চরম সতর্কতা"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-সতর্কতা : চরম সতর্কতা"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-সতর্কতা : গুরুতর সতর্কতা"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-সতর্কতা : নিখোঁজ বাচ্চা সম্পর্কে সতর্কতা"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-সতর্কতা : পাবলিক নিরাপত্তা সতর্কতা"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-সতর্কতা : মহড়ার জন্য সতর্কতা"</string>
 </resources>
diff --git a/res/values-mcc226-bs/strings.xml b/res/values-mcc226-bs/strings.xml
index 610640367..a64d69035 100644
--- a/res/values-mcc226-bs/strings.xml
+++ b/res/values-mcc226-bs/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Upozorenje na neposrednu opasnost"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Neposredna opasnost po život i imovinu"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Upozorenje o nestalom djetetu"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Upozorenje rumunske vlade: nestalo dijete"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Upozorenje rumunske vlade: predsjedničko upozorenje"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Upozorenje rumunske vlade: ekstremno upozorenje"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Upozorenje rumunske vlade: ekstremno upozorenje"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Upozorenje rumunske vlade: ekstremno upozorenje"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Upozorenje rumunske vlade: ozbiljno upozorenje"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Upozorenje rumunske vlade: upozorenje za vježbu"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Preporučene radnje kojim se mogu spasiti životi ili imovina"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Upozorenje o javnoj sigurnosti"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Tiho upozorenje"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Upozorenja za vježbu"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Primite upozorenje na hitan slučaj: poruka za vježbu"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"UPOZORENJE ZA RUMUNIJU: upozorenje na neposrednu opasnost"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"UPOZORENJE ZA RUMUNIJU: ekstremno upozorenje"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"UPOZORENJE ZA RUMUNIJU: ekstremno upozorenje"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"UPOZORENJE ZA RUMUNIJU: ekstremno upozorenje"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"UPOZORENJE ZA RUMUNIJU: ozbiljno upozorenje"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"UPOZORENJE ZA RUMUNIJU: nestalo dijete"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"UPOZORENJE ZA RUMUNIJU: upozorenje o javnoj sigurnosti"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"UPOZORENJE ZA RUMUNIJU: upozorenja za vježbu"</string>
 </resources>
diff --git a/res/values-mcc226-ca/strings.xml b/res/values-mcc226-ca/strings.xml
index fe6913ffa..accd3249c 100644
--- a/res/values-mcc226-ca/strings.xml
+++ b/res/values-mcc226-ca/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Alerta de risc imminent"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Amenaces imminents per a la vida i la propietat"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Alerta de nens perduts"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: alerta de nens perduts"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: alerta presidencial"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: alerta extrema"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: alerta extrema"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: alerta extrema"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: alerta important"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: alerta de pràctica"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Accions recomanades que poden salvar vides o propietats"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Alerta de seguretat pública"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Alerta silenciosa"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Alertes de simulacre"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Rep una alerta d\'emergència: missatge de simulacre o pràctica"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: alerta de risc imminent"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: alerta extrema"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: alerta extrema"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: alerta extrema"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: alerta important"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: alerta de nens perduts"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: alerta de seguretat pública"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: alertes de simulacre"</string>
 </resources>
diff --git a/res/values-mcc226-cs/strings.xml b/res/values-mcc226-cs/strings.xml
index 295ef150a..99290ad5e 100644
--- a/res/values-mcc226-cs/strings.xml
+++ b/res/values-mcc226-cs/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Upozornění na bezprostřední riziko"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Bezprostřední ohrožení života a majetku"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Upozornění na pohřešované dítě"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Upozornění na pohřešované dítě"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Upozornění RO: prezidentské upozornění"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Upozornění RO: extrémní upozornění"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Upozornění RO: extrémní upozornění"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Upozornění RO: extrémní upozornění"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Upozornění RO: závažné upozornění"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Upozornění RO: cvičení"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Doporučené akce, které mohou zachránit životy či majetek"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Upozornění ohledně veřejné bezpečnosti"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Tiché upozornění"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Cvičné výstrahy"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Přijmout výstražnou zprávu: testovací zpráva / cvičení"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: Upozornění na bezprostřední riziko"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: Upozornění na extrémní situaci"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: Upozornění na extrémní situaci"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: Upozornění na extrémní situaci"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: Upozornění na závažnou situaci"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: Upozornění na pohřešované dítě"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: Upozornění ohledně veřejné bezpečnosti"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: Cvičná upozornění"</string>
 </resources>
diff --git a/res/values-mcc226-da/strings.xml b/res/values-mcc226-da/strings.xml
index 090021750..d00577084 100644
--- a/res/values-mcc226-da/strings.xml
+++ b/res/values-mcc226-da/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Advarsel om overhængende fare"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Overhængende trusler mod liv og ejendom"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Underretning om efterlyst barn"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Underretning om efterlyst barn"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Advarsel fra præsidenten"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Advarsel om ekstrem fare"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Advarsel om ekstrem fare"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Advarsel om ekstrem fare"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Advarsel om alvorlig fare"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Øvelsesadvarsel"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Anbefalede handlinger, der kan redde liv eller ejendom"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Offentlig sikkerhedsadvarsel"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Lydløs underretning"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Øvelsesunderretninger"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Modtag varsling: testbesked"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: Advarsel om overhængende fare"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: Advarsel om ekstrem fare"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: Advarsel om ekstrem fare"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: Advarsel om ekstrem fare"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: Advarsel om alvorlig fare"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: Underretning om efterlyst barn"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: Offentlig sikkerhedsadvarsel"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: Øvelsesunderretninger"</string>
 </resources>
diff --git a/res/values-mcc226-de/strings.xml b/res/values-mcc226-de/strings.xml
index f393e0248..b60a28d7b 100644
--- a/res/values-mcc226-de/strings.xml
+++ b/res/values-mcc226-de/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Warnung zu unmittelbarem Risiko"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Unmittelbare Gefahren für Leben und Eigentum"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Alarmierung wegen eines vermissten Kindes"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Alarmierung wegen eines vermissten Kindes"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Warnung der Kategorie \"Höchste Dringlichkeit\""</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Warnung der Kategorie \"Extrem\""</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Warnung der Kategorie \"Extrem\""</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Warnung der Kategorie \"Extrem\""</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Warnung der Kategorie \"Ernst\""</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Warnung der Kategorie \"Übung\""</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Empfohlene Maßnahmen, die Leben oder Eigentum retten können"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Warnung zur öffentlichen Sicherheit"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Lautlose Warnung"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Warnungen der Kategorie „Übung“"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Notfallbenachrichtigung erhalten: Übungsnachricht"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: Warnung der Kategorie „Unmittelbares Risiko“"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: Warnung der Kategorie „Extrem“"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: Warnung der Kategorie „Extrem“"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: Warnung der Kategorie „Extrem“"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: Warnung der Kategorie „Ernst“"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: Warnung wegen eines vermissten Kindes"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: Warnung zur öffentlichen Sicherheit"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: Warnungen der Kategorie „Übung“"</string>
 </resources>
diff --git a/res/values-mcc226-el/strings.xml b/res/values-mcc226-el/strings.xml
index 5a21a656f..2050d0907 100644
--- a/res/values-mcc226-el/strings.xml
+++ b/res/values-mcc226-el/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Ειδοποίηση επικείμενου κινδύνου"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Επικείμενες απειλές για τη ζωή και την ιδιοκτησία"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Ειδοποίηση για εξαφάνιση παιδιού"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Ειδοποίηση για εξαφάνιση παιδιού"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Προεδρική ειδοποίηση"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Πολύ σοβαρή ειδοποίηση"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Πολύ σοβαρή ειδοποίηση"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Πολύ σοβαρή ειδοποίηση"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Σοβαρή ειδοποίηση"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Ειδοποίηση άσκησης"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Προτεινόμενες ενέργειες που μπορεί να προστατεύσουν τη ζωή ή την ιδιοκτησία σας"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Ειδοποίηση δημόσιας ασφάλειας"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Αθόρυβη ειδοποίηση"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Ειδοποιήσεις άσκησης"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Λήψη ειδοποίησης έκτακτης ανάγκης: Μήνυμα άσκησης/ετοιμότητας"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : Ειδοποίηση για επικείμενο κίνδυνο"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : Πολύ σοβαρή ειδοποίηση"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : Πολύ σοβαρή ειδοποίηση"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : Πολύ σοβαρή ειδοποίηση"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : Σοβαρή ειδοποίηση"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : Ειδοποίηση για εξαφάνιση παιδιού"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : Ειδοποίηση δημόσιας ασφάλειας"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : Ειδοποιήσεις άσκησης"</string>
 </resources>
diff --git a/res/values-mcc226-en-rAU/strings.xml b/res/values-mcc226-en-rAU/strings.xml
index 960d8c9a6..4d220d433 100644
--- a/res/values-mcc226-en-rAU/strings.xml
+++ b/res/values-mcc226-en-rAU/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Imminent risk alert"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Imminent threats to life and property"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Missing child alert"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: missing child alert"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Presidential alert"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Extreme alert"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Extreme alert"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Extreme alert"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Severe alert"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Exercise alert"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Recommended actions that can save lives or property"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Public safety alert"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Silent alert"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Exercise alerts"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Receive emergency alert: Exercise/drill message"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: Imminent risk alert"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: Extreme alert"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: Extreme alert"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: Extreme alert"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: Severe alert"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: Missing child alert"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: Public safety alert"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: Exercise alerts"</string>
 </resources>
diff --git a/res/values-mcc226-en-rCA/strings.xml b/res/values-mcc226-en-rCA/strings.xml
index 2ee829fde..bb73eebaa 100644
--- a/res/values-mcc226-en-rCA/strings.xml
+++ b/res/values-mcc226-en-rCA/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Imminent Risk Alert"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Imminent threats to life and property"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Missing Child Alert"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Missing Child Alert"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Presidential Alert"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Extreme Alert"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Extreme Alert"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Extreme Alert"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Severe Alert"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Exercise Alert"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Recommended actions that can save lives or property"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Public Safety Alert"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Silent Alert"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Exercise Alerts"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Receive emergency alert: exercise/drill message"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : Imminent Risk Alert"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : Extreme Alert"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : Extreme Alert"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : Extreme Alert"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : Severe Alert"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : Missing Child Alert"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : Public Safety Alert"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : Exercise Alerts"</string>
 </resources>
diff --git a/res/values-mcc226-en-rGB/strings.xml b/res/values-mcc226-en-rGB/strings.xml
index 960d8c9a6..4d220d433 100644
--- a/res/values-mcc226-en-rGB/strings.xml
+++ b/res/values-mcc226-en-rGB/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Imminent risk alert"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Imminent threats to life and property"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Missing child alert"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: missing child alert"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Presidential alert"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Extreme alert"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Extreme alert"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Extreme alert"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Severe alert"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Exercise alert"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Recommended actions that can save lives or property"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Public safety alert"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Silent alert"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Exercise alerts"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Receive emergency alert: Exercise/drill message"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: Imminent risk alert"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: Extreme alert"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: Extreme alert"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: Extreme alert"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: Severe alert"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: Missing child alert"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: Public safety alert"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: Exercise alerts"</string>
 </resources>
diff --git a/res/values-mcc226-en-rIN/strings.xml b/res/values-mcc226-en-rIN/strings.xml
index 960d8c9a6..4d220d433 100644
--- a/res/values-mcc226-en-rIN/strings.xml
+++ b/res/values-mcc226-en-rIN/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Imminent risk alert"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Imminent threats to life and property"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Missing child alert"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: missing child alert"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Presidential alert"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Extreme alert"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Extreme alert"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Extreme alert"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Severe alert"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Exercise alert"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Recommended actions that can save lives or property"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Public safety alert"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Silent alert"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Exercise alerts"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Receive emergency alert: Exercise/drill message"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: Imminent risk alert"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: Extreme alert"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: Extreme alert"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: Extreme alert"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: Severe alert"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: Missing child alert"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: Public safety alert"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: Exercise alerts"</string>
 </resources>
diff --git a/res/values-mcc226-es-rUS/strings.xml b/res/values-mcc226-es-rUS/strings.xml
index 69c77de4b..c7aca55f9 100644
--- a/res/values-mcc226-es-rUS/strings.xml
+++ b/res/values-mcc226-es-rUS/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Alerta de riesgo inminente"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Amenazas inminentes para la vida y la propiedad"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Alerta de menor desaparecido"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Alerta para Rumania: Menor desaparecido"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Alerta RO: Alerta presidencial"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Alerta RO: Alerta extrema"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Alerta RO: Alerta extrema"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Alerta RO: Alerta extrema"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Alerta RO: Alerta grave"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Alerta RO: Simulación de alerta"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Acciones recomendadas que pueden salvar vidas o propiedades"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Alerta de seguridad pública"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Alerta silenciosa"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Alertas de ejercicio"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Recibe alertas de emergencia: mensaje de simulacro/ejercicio"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"ALERTA RO: Alerta de riesgo inminente"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"ALERTA RO: Alerta extrema"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"ALERTA RO: Alerta extrema"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"ALERTA RO: Alerta extrema"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"ALERTA RO: Alerta grave"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"ALERTA RO: Alerta de menor desaparecido"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"ALERTA RO: Alerta de seguridad pública"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"ALERTA RO: Alertas de prueba"</string>
 </resources>
diff --git a/res/values-mcc226-es/strings.xml b/res/values-mcc226-es/strings.xml
index 99a607db8..a014617c5 100644
--- a/res/values-mcc226-es/strings.xml
+++ b/res/values-mcc226-es/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Alerta de riesgo inminente"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Amenazas inminentes contra la vida y la propiedad"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Alerta de menor desaparecido"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Alerta de menor desaparecido"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: alerta presidencial"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: alerta extrema"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: alerta extrema"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: alerta extrema"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: alerta grave"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: alerta de práctica"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Acciones recomendadas que pueden salvar vidas o propiedades"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Alerta de seguridad pública"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Alerta silenciosa"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Alertas de simulacro"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Recibir alerta de emergencia: mensaje de prueba/simulacro"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: alerta de riesgo inminente"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: alerta extrema"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: alerta extrema"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: alerta extrema"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: alerta grave"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: alerta de menor desaparecido"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: alerta de seguridad pública"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: alertas de simulacro"</string>
 </resources>
diff --git a/res/values-mcc226-et/strings.xml b/res/values-mcc226-et/strings.xml
index 88a9b634c..3bf2cdacb 100644
--- a/res/values-mcc226-et/strings.xml
+++ b/res/values-mcc226-et/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Vahetu ohu hoiatus"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Vahetu oht elule ja varale"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Kadunud lapse märguanne"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Rumeenia märguanne: kadunud lapse märguanne"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Rumeenia märguanne: presidendi edastatud hoiatus"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Rumeenia märguanne: äärmusliku olukorra hoiatus"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Rumeenia märguanne: äärmusliku olukorra hoiatus"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Rumeenia märguanne: äärmusliku olukorra hoiatus"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Rumeenia märguanne: tõsise ohu hoiatus"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Rumeenia märguanne: treeninghoiatus"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Soovitatud toimingud, mis võivad päästa elusid või vara"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Avalik ohutusmärguanne"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Hääletu hoiatus"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Harjutuse hoiatused"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Hädaolukorra hoiatuse saamine: treeningsõnum"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : vahetu ohu hoiatus"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : äärmusliku olukorra hoiatus"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : äärmusliku olukorra hoiatus"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : äärmusliku olukorra hoiatus"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : tõsise ohu hoiatus"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : kadunud lapse märguanne"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : avalik ohutusmärguanne"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : harjutuse hoiatused"</string>
 </resources>
diff --git a/res/values-mcc226-eu/strings.xml b/res/values-mcc226-eu/strings.xml
index d74e02a53..b61595cbe 100644
--- a/res/values-mcc226-eu/strings.xml
+++ b/res/values-mcc226-eu/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Berehalako arriskuari buruzko alerta"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Bizitzaren eta jabetzen aurkako berehalako mehatxuak"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Desagertutako haur baten inguruko alerta"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Errumania: desagertutako haur baten inguruko alerta"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO alerta: gobernuaren alerta"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO alerta: muturreko alerta"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO alerta: muturreko alerta"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO alerta: muturreko alerta"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO alerta: alerta larria"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO alerta: ariketa motako alerta"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Bizia edo ondasunak salbatzeko gomendioak"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Segurtasun publikoari buruzko alerta"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Alerta isila"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Simulazio-alertak"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Jaso larrialdi-alerta: simulazio-mezua"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : berehalako arriskuari buruzko alerta"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : muturreko alerta"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : muturreko alerta"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : muturreko alerta"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : alerta larria"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : desagertutako haur bati buruzko alerta"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : segurtasun publikoari buruzko alerta"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : simulazio-alertak"</string>
 </resources>
diff --git a/res/values-mcc226-fa/strings.xml b/res/values-mcc226-fa/strings.xml
index 6b696c451..7a0145875 100644
--- a/res/values-mcc226-fa/strings.xml
+++ b/res/values-mcc226-fa/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"هشدار خطر قریب‌الوقوع"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"تهدیدهای قریب‌الوقوع جانی و مالی"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"هشدار کودک گم‌شده"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"‏هشدار-RO: هشدار کودک گم‌شده"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"هشدار رومانی: هشدار ریاست جمهوری"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"هشدار رومانی: هشدار شدید"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"هشدار رومانی: هشدار شدید"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"هشدار رومانی: هشدار شدید"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"هشدار رومانی: هشدار جدی"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"هشدار رومانی: هشدار آزمایشی"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"اقدام‌های توصیه‌شده که می‌تواند جان افراد یا اموال آن‌ها را حفظ کند"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"هشدار ایمنی عمومی"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"هشدار بی‌صدا"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"هشدارهای تمرینی"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"دریافت هشدار شرایط اضطراری: پیام تمرینی/آموزشی"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"هشدار رومانی : هشدار خطر قریب‌الوقوع"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"هشدار رومانی : هشدار شدید"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"هشدار رومانی : هشدار شدید"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"هشدار رومانی : هشدار شدید"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"هشدار رومانی : هشدار جدی"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"هشدار رومانی : هشدار کودک گم‌شده"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"هشدار رومانی : هشدار ایمنی عمومی"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"هشدار رومانی : هشدارهای تمرینی"</string>
 </resources>
diff --git a/res/values-mcc226-fi/strings.xml b/res/values-mcc226-fi/strings.xml
index 3a2705d76..a1c127bcf 100644
--- a/res/values-mcc226-fi/strings.xml
+++ b/res/values-mcc226-fi/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Välitön riski -hälytykset"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Välittömät ihmishenkiä ja omaisuutta koskevat uhat"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Kadonnutta lasta koskeva hälytys"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-hälytys: Kadonnutta lasta koskeva hälytys"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-hälytys: presidenttitason hälytys"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-hälytys: äärimmäinen hälytys"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-hälytys: äärimmäinen hälytys"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-hälytys: äärimmäinen hälytys"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-hälytys: vakava hälytys"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-hälytys: harjoitushälytys"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Toimintasuositukset, joilla voidaan suojata ihmishenkiä tai omaisuutta"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Yleistä turvallisuutta koskeva hälytys"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Äänetön hälytys"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Harjoitushälytykset"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Vastaanota hätävaroitus: harjoitusviesti"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-HÄLYTYS: Välitön vaara -hälytys"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-HÄLYTYS: Äärimmäinen hälytys"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-HÄLYTYS: Äärimmäinen hälytys"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-HÄLYTYS: Äärimmäinen hälytys"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-HÄLYTYS: Vakava hälytys"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-HÄLYTYS: Kadonnutta lasta koskeva hälytys"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-HÄLYTYS: Yleistä turvallisuutta koskeva hälytys"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-HÄLYTYS: Harjoitushälytykset"</string>
 </resources>
diff --git a/res/values-mcc226-fr-rCA/strings.xml b/res/values-mcc226-fr-rCA/strings.xml
index 69d30f3e6..9df09cc1b 100644
--- a/res/values-mcc226-fr-rCA/strings.xml
+++ b/res/values-mcc226-fr-rCA/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Alerte de risque imminent"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Menaces imminentes pour la vie et les biens"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Alerte d\'enfant perdu"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Alerte pour la Roumanie : Alerte d\'enfant perdu"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Alerte pour la Roumanie : alerte présidentielle"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Alerte pour la Roumanie : alerte extrême"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Alerte pour la Roumanie : alerte extrême"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Alerte pour la Roumanie : alerte extrême"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Alerte pour la Roumanie : alerte sévère"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Alerte pour la Roumanie : alerte d\'exercice"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Actions recommandées pouvant sauver des vies ou des biens"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Alerte relative à la sécurité publique"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Alerte silencieuse"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Alertes d\'exercice"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Recevoir une alerte d\'urgence : message en cas d\'exercice ou de simulation"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"ALERTE POUR LA ROUMANIE : alerte de risque imminent"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"ALERTE POUR LA ROUMANIE : alerte extrême"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"ALERTE POUR LA ROUMANIE : alerte extrême"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"ALERTE POUR LA ROUMANIE : alerte extrême"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"ALERTE POUR LA ROUMANIE : alerte grave"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"ALERTE POUR LA ROUMANIE : alerte d\'enfant perdu"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"ALERTE – ROUMANIE : alerte de sécurité publique"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"ALERTE POUR LA ROUMANIE : alertes d\'exercice"</string>
 </resources>
diff --git a/res/values-mcc226-fr/strings.xml b/res/values-mcc226-fr/strings.xml
index 46473c1c0..5bfc85da7 100644
--- a/res/values-mcc226-fr/strings.xml
+++ b/res/values-mcc226-fr/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Alerte de risque imminent"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Menaces imminentes pour les biens et personnes"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Alerte d\'enfant disparu"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Alerte pour la Roumanie : alerte d\'enfant disparu"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Alerte pour la Roumanie : alerte présidentielle"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Alerte pour la Roumanie : alerte extrême"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Alerte pour la Roumanie : alerte extrême"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Alerte pour la Roumanie : alerte extrême"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Alerte pour la Roumanie : alerte importante"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Alerte pour la Roumanie : alerte d\'exercice"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Actions recommandées susceptibles de sauver des vies ou des biens"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Alerte de sécurité publique"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Alerte silencieuse"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Alertes d\'exercice"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Recevoir une alerte d\'urgence : message en cas d\'exercice/de simulation"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"Alerte pour la Roumanie : alerte risque imminent"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"Alerte pour la Roumanie : alerte extrême"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"Alerte pour la Roumanie : alerte extrême"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"Alerte pour la Roumanie : alerte extrême"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"Alerte pour la Roumanie : alerte importante"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"Alerte pour la Roumanie : alerte d\'enfant disparu"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"Alerte pour la Roumanie : alerte sécurité publique"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"Alerte pour la Roumanie : alertes d\'exercice"</string>
 </resources>
diff --git a/res/values-mcc226-gl/strings.xml b/res/values-mcc226-gl/strings.xml
index fd868c015..0cbbdd406 100644
--- a/res/values-mcc226-gl/strings.xml
+++ b/res/values-mcc226-gl/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Alerta de perigo inminente"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Ameazas inminentes á vida e á propiedade"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Alerta de desaparición infantil"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Alerta para Romanía: desaparición infantil"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Alerta para Romanía: alerta presidencial"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Alerta para Romanía: alerta extrema"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Alerta para Romanía: alerta extrema"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Alerta para Romanía: alerta extrema"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Alerta para Romanía: alerta grave"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Alerta para Romanía: alerta de simulacro"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Accións recomendadas que poden salvar vidas ou propiedades"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Alerta de seguranza pública"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Alerta silenciosa"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Alertas de simulacro"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Recibe alertas de emerxencia: mensaxe de simulacro ou práctica"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"Alerta para Romanía: Alerta de perigo inminente"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"Alerta para Romanía: Alerta extrema"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"Alerta para Romanía: Alerta extrema"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"Alerta para Romanía: Alerta extrema"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"Alerta para Romanía: Alerta grave"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"Alerta para Romanía: Desaparición infantil"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"Alerta para Romanía: Alerta de seguranza pública"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"Alerta para Romanía: Alertas de simulacro"</string>
 </resources>
diff --git a/res/values-mcc226-gu/strings.xml b/res/values-mcc226-gu/strings.xml
index da8839654..5f8ff5d48 100644
--- a/res/values-mcc226-gu/strings.xml
+++ b/res/values-mcc226-gu/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"તાત્કાલિક જોખમનું અલર્ટ"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"જીવન અને પ્રોપર્ટીને તાત્કાલિક જોખમ"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"લાપતા બાળક વિશે અલર્ટ"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-અલર્ટ: લાપતા બાળક વિશે અલર્ટ"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-અલર્ટ: અધ્યક્ષ સંબંધિત અલર્ટ"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-અલર્ટ: અત્યંત ગંભીર અલર્ટ"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-અલર્ટ: અત્યંત ગંભીર અલર્ટ"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-અલર્ટ: અત્યંત ગંભીર અલર્ટ"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-અલર્ટ: ગંભીર અલર્ટ"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-અલર્ટ: કસરત સંબંધિત અલર્ટ"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"સુઝાવ આપેલી ઍક્શન જે જીવન અથવા પ્રોપર્ટીને બચાવી શકે છે"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"સાર્વજનિક સલામતી માટે અલર્ટ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"સાઇલન્ટ અલર્ટ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"અભ્યાસ માટે ડ્રિલના અલર્ટ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"ઇમર્જન્સી માટે અલર્ટ મેળવો: અભ્યાસ/તાલીમ સંબંધિત મેસેજ"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-અલર્ટ: તાત્કાલિક જોખમનું અલર્ટ"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-અલર્ટ: અત્યંત ગંભીર અલર્ટ"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-અલર્ટ: અત્યંત ગંભીર અલર્ટ"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-અલર્ટ: અત્યંત ગંભીર અલર્ટ"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-અલર્ટ: ગંભીર અલર્ટ"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-અલર્ટ: ગુમ થયેલા બાળક વિશે અલર્ટ"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-અલર્ટ: સાર્વજનિક સલામતી માટે અલર્ટ"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-અલર્ટ: અભ્યાસ માટે ડ્રિલના અલર્ટ"</string>
 </resources>
diff --git a/res/values-mcc226-hi/strings.xml b/res/values-mcc226-hi/strings.xml
index 185cbbd8d..c8a78f356 100644
--- a/res/values-mcc226-hi/strings.xml
+++ b/res/values-mcc226-hi/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"आने वाले खतरे की चेतावनी"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"जान-माल के खतरे की चेतावनी"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"बच्चे के लापता होने की चेतावनी"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"रोमानिया-अलर्ट: बच्चे के लापता होने की चेतावनी"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: प्रेसिडेंशियल अलर्ट"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: गंभीर अलर्ट"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: गंभीर अलर्ट"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: गंभीर अलर्ट"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: गंभीर अलर्ट"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: एक्सरसाइज़ अलर्ट"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"सुझाई गई ऐसी कार्रवाइयां जो जान-माल का नुकसान होने से रोक सकती हैं"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"लोगों की सुरक्षा से जुड़ी चेतावनी"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"बिना आवाज़ वाली चेतावनी"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"मॉक ड्रिल की चेतावनियां"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"खतरे की चेतावनी पाएं: एक्सरसाइज़/मॉक ड्रिल के बारे में मैसेज"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"रोमानिया-अलर्ट : आने वाले खतरे की चेतावनी"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"रोमानिया-अलर्ट : बेहद गंभीर स्थिति से जुड़ी चेतावनी"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"रोमानिया-अलर्ट : बेहद गंभीर स्थिति से जुड़ी चेतावनी"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"रोमानिया-अलर्ट : बेहद गंभीर स्थिति से जुड़ी चेतावनी"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"रोमानिया-अलर्ट : गंभीर स्थिति से जुड़ी चेतावनी"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"रोमानिया-अलर्ट: बच्चे के लापता होने की चेतावनी"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"रोमानिया-अलर्ट : लोगों की सुरक्षा से जुड़ी चेतावनी"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"रोमानिया-अलर्ट : मॉक ड्रिल की चेतावनी"</string>
 </resources>
diff --git a/res/values-mcc226-hr/strings.xml b/res/values-mcc226-hr/strings.xml
index fe2062f05..c536d53cb 100644
--- a/res/values-mcc226-hr/strings.xml
+++ b/res/values-mcc226-hr/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Upozorenje o neposrednoj opasnosti"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Neposredne prijetnje po život i imovinu"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Upozorenje o nestalom djetetu"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: upozorenje o nestalom djetetu"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: predsjedničko upozorenje"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: ekstremno upozorenje"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: ekstremno upozorenje"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: ekstremno upozorenje"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: ozbiljno upozorenje"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: poruka za vježbu"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Preporučene radnje koje mogu spasiti živote ili imovinu"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Upozorenje o javnoj sigurnosti"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Bešumno upozorenje"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Probna upozorenja"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Primanje hitnih upozorenja: probna poruka"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: upozorenje o neposrednoj opasnosti"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: upozorenje o ekstremnom događaju"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: upozorenje o ekstremnom događaju"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: upozorenje o ekstremnom događaju"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: upozorenje o ozbiljnom događaju"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: upozorenje o nestalom djetetu"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: upozorenje o javnoj sigurnosti"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: probna upozorenja"</string>
 </resources>
diff --git a/res/values-mcc226-hu/strings.xml b/res/values-mcc226-hu/strings.xml
index cd3cc7e29..ffbe9dce9 100644
--- a/res/values-mcc226-hu/strings.xml
+++ b/res/values-mcc226-hu/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Fenyegető kockázatra vonatkozó riasztás"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Az életet és a vagyontárgyakat fenyegető közvetlen veszélyek"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Eltűnt gyermek miatti riasztás"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Eltűnt gyermek miatti riasztás"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Elnöki vészjelzés"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Extrém riasztás"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Extrém riasztás"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Extrém riasztás"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Súlyos riasztás"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Gyakorlati riasztás"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Élet és anyagi eszközök mentésére szolgáló javasolt intézkedések"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Közbiztonsággal kapcsolatos riasztás"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Csendes riasztás"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Riasztási gyakorlatok"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Vészjelzés fogadása: gyakorlati/próbaüzenet"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : Fenyegető kockázatra vonatkozó riasztás"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-Alert : Extrém riasztás"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-Alert : Extrém riasztás"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-Alert : Extrém riasztás"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : Súlyos riasztás"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : Eltűnt gyermek miatti riasztás"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : Közbiztonsággal kapcsolatos riasztás"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : Riasztási gyakorlatok"</string>
 </resources>
diff --git a/res/values-mcc226-hy/strings.xml b/res/values-mcc226-hy/strings.xml
index f858b8afb..9d5264483 100644
--- a/res/values-mcc226-hy/strings.xml
+++ b/res/values-mcc226-hy/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Անխուսափելի ռիսկի մասին զգուշացում"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Կյանքին և գույքին սպառնացող վտանգներ"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Կորած երեխայի մասին ծանուցում"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Ռումինիայի համար․ կորած երեխայի մասին ծանուցում"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert՝ նախագահական ծանուցում"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert՝ արտակարգ իրավիճակի ահազանգ"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert՝ արտակարգ իրավիճակի ահազանգ"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert՝ արտակարգ իրավիճակի ահազանգ"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert՝ հրատապ ահազանգ"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert՝ ուսումնավարժական ահազանգ"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Առաջարկվող գործողություններ, որոնք կօգնեն փրկել կյանքը և գույքը"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Հանրային անվտանգության սպառնալիքի մասին զգուշացում"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Անձայն ծանուցում"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Ուսումնական տագնապների մասին ծանուցումներ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Ստանալ արտակարգ իրավիճակի մասին ծանուցում․ ուսումնական տագնապի մասին հաղորդագրություն"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"Ռումինիա․ մոտալուտ սպառնալիքի մասին զգուշացում"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"Ռումինիա․ արտակարգ իրավիճակի մասին ահազանգ"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"Ռումինիա․ արտակարգ իրավիճակի մասին ահազանգ"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"Ռումինիա․ արտակարգ իրավիճակի մասին ահազանգ"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"Ռումինիա․ վտանգավոր իրավիճակի մասին ծանուցում"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"Ռումինիա․ կորած երեխայի մասին ծանուցում"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"Ռումինիա․ հանրային անվտանգության մասին զգուշացում"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"Ռումինիա․ ուսումնական տագնապներ"</string>
 </resources>
diff --git a/res/values-mcc226-in/strings.xml b/res/values-mcc226-in/strings.xml
index 4e5a8a895..f8aeac6ca 100644
--- a/res/values-mcc226-in/strings.xml
+++ b/res/values-mcc226-in/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Peringatan Risiko yang Segera Terjadi"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Ancaman segera terhadap nyawa dan harta"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Peringatan Anak Hilang"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Peringatan Anak Hilang"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Peringatan Presidensial"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Peringatan Ekstrem"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Peringatan Ekstrem"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Peringatan Ekstrem"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Peringatan Parah"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Peringatan Latihan"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Tindakan yang disarankan untuk menyelamatkan nyawa atau harta benda"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Peringatan Keselamatan Publik"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Peringatan Senyap"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Peringatan Latihan"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Terima peringatan darurat: Pesan Simulasi"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: Peringatan Risiko yang Segera Terjadi"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: Peringatan Ekstrem"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: Peringatan Ekstrem"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: Peringatan Ekstrem"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: Peringatan Parah"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: Peringatan Anak Hilang"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: Peringatan Keselamatan Publik"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: Peringatan Latihan"</string>
 </resources>
diff --git a/res/values-mcc226-is/strings.xml b/res/values-mcc226-is/strings.xml
index 61c61d58c..0ce45c153 100644
--- a/res/values-mcc226-is/strings.xml
+++ b/res/values-mcc226-is/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Bráðaviðvörun"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Líf eða eignir eru í bráðri hættu"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Viðvörun um týnd börn"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: viðvörun um týnd börn"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: viðvörun frá forseta"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: viðvörun á háu stigi"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: viðvörun á háu stigi"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: viðvörun á háu stigi"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: alvarleg viðvörun"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: æfingaviðvörun"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Ráðlögð viðbrögð sem geta bjargað mannslífum og verndað eignir"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Almannavarnatilkynning"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Hljóðlaus viðvörun"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Æfingaviðvaranir"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Fá neyðartilkynningu: æfinga-/prufuskilaboð"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : Bráðaviðvörun"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : Viðvörun á háu stigi"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : Viðvörun á háu stigi"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : Viðvörun á háu stigi"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : Alvarleg viðvörun"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : Viðvörun um týnd börn"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : Almannavarnatilkynning"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : Æfingaviðvaranir"</string>
 </resources>
diff --git a/res/values-mcc226-it/strings.xml b/res/values-mcc226-it/strings.xml
index d37511ad0..c0a0bd776 100644
--- a/res/values-mcc226-it/strings.xml
+++ b/res/values-mcc226-it/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Allerta di rischio imminente"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Minacce imminenti alla vita e alle proprietà"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Allerta bambino scomparso"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: allerta bambino scomparso"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: allerta presidenziale"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: allerta per condizioni estreme"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: allerta per condizioni estreme"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: allerta per condizioni estreme"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: allerta per condizioni gravi"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: allerta di esercitazione"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Comportamenti consigliati che possono salvare vite umane o proprietà"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Allerta sicurezza pubblica"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Avviso silenzioso"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Avvisi di simulazione"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Ricevi avviso di emergenza: messaggio di simulazione"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: allerta per rischio imminente"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: allerta per condizioni estreme"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: allerta per condizioni estreme"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: allerta per condizioni estreme"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: allerta per condizioni gravi"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: allerta bambino scomparso"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: allerta sicurezza pubblica"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: avvisi di simulazione"</string>
 </resources>
diff --git a/res/values-mcc226-iw/strings.xml b/res/values-mcc226-iw/strings.xml
index ed9bb7a50..2b9ceae80 100644
--- a/res/values-mcc226-iw/strings.xml
+++ b/res/values-mcc226-iw/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"התרעה על סיכון מיידי"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"איומים מיידיים לנפש ולרכוש"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"התראה על ילד נעדר"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"התראה ברומניה: התראה על ילד נעדר"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"התרעה ברומניה: התרעה נשיאותית"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"התרעה ברומניה: התרעה קיצונית"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"התראה ברומניה: התראה קיצונית"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"התרעה ברומניה: התרעה קיצונית"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"התרעה ברומניה: התרעה חמורה"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"התרעה ברומניה: התרעת תרגול"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"פעולות מומלצות שיכולות לעזור בהצלת חיים או רכוש"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"התרעה בנוגע לביטחון הציבור"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"התראה שקטה"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"התרעות לגבי תרגול"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"קבלת התרעה על מקרה חירום: הודעה לגבי תרגול"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"התרעה ברומניה : התרעה על סיכון מיידי"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"התרעה ברומניה: התרעה קיצונית"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"התרעה ברומניה: התרעה קיצונית"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"התרעה ברומניה: התרעה קיצונית"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"התרעה ברומניה: התרעה חמורה"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"התרעה ברומניה: התרעה על ילד או ילדה נעדרים"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"התרעה ברומניה : התרעה בנוגע לביטחון הציבור"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"התרעה ברומניה : התרעות לגבי תרגול"</string>
 </resources>
diff --git a/res/values-mcc226-ja/strings.xml b/res/values-mcc226-ja/strings.xml
index c107b1b38..6e65cc06c 100644
--- a/res/values-mcc226-ja/strings.xml
+++ b/res/values-mcc226-ja/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"差し迫った危険に関するアラート"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"命や財産に関わる差し迫った脅威"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"児童行方不明警報"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: 児童行方不明警報"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: 国家レベルの警報"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: 最重要警報"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: 最重要警報"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: 最重要警報"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: 重要警報"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: 訓練用警報"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"人命や財産を守るための推奨される対応"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"災害情報アラート"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"サイレント アラート"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"訓練用速報メール"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"緊急速報メール: 訓練用メッセージを受け取る"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : 差し迫った危険に関するアラート"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : 最重要速報メール"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : 最重要速報メール"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : 最重要速報メール"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : 重要警報"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : 児童行方不明警報"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : 災害情報アラート"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : 訓練用速報メール"</string>
 </resources>
diff --git a/res/values-mcc226-ka/strings.xml b/res/values-mcc226-ka/strings.xml
index f78792ef0..a0b3a595d 100644
--- a/res/values-mcc226-ka/strings.xml
+++ b/res/values-mcc226-ka/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"გარდაუვალი რისკის გაფრთხილება"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"სიცოცხლისა და საკუთრების გარდაუვალი საფრთხეები"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"გაფრთხილება დაკარგული ბავშვის შესახებ"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: გაფრთხილება დაკარგული ბავშვის შესახებ"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-გაფრთხილება: საპრეზიდენტო გაფრთხილება"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-გაფრთხილება: უკიდურესი საფრთხის გაფრთხილება"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-გაფრთხილება: უკიდურესი საფრთხის გაფრთხილება"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-გაფრთხილება: უკიდურესი საფრთხის გაფრთხილება"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-გაფრთხილება: სერიოზული საფრთხის გაფრთხილება"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-გაფრთხილება: სავარჯიშო გაფრთხილება"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"რეკომენდებული ქმედებები სიცოცხლის ან საკუთრების გადასარჩენად"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"საჯარო უსაფრთხოების გაფრთხილება"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"ჩუმი გაფრთხილება"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"სავარჯიშო გაფრთხილებები"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"საგანგებო ვითარების გაფრთხილების მიღება: სავარჯიშო/საწვრთნელი შეტყობინება"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : გაფრთხილება გარდაუვალი რისკის შესახებ"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: უკიდურესი საფრთხის გაფრთხილება"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: უკიდურესი საფრთხის გაფრთხილება"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: უკიდურესი საფრთხის გაფრთხილება"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: სერიოზული საფრთხის გაფრთხილება"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-Alert: გაფრთხილება დაკარგული ბავშვის შესახებ"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : საჯარო უსაფრთხოების გაფრთხილება"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : სავარჯიშო გაფრთხილებები"</string>
 </resources>
diff --git a/res/values-mcc226-kk/strings.xml b/res/values-mcc226-kk/strings.xml
index 436507194..89cc96d07 100644
--- a/res/values-mcc226-kk/strings.xml
+++ b/res/values-mcc226-kk/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Төніп тұрған қауіп туралы хабарландыру"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Өмірге және мүлікке төніп тұрған қауіптер"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Жоғалған бала туралы хабарландыру"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: жоғалған бала туралы хабарландыру"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Румыния: президент хабарландыруы"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Румыния: төтенше жағдай хабарландыруы"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Румыния: төтенше жағдай хабарландыруы"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Румыния: төтенше жағдай хабарландыруы"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Румыния: маңызды хабарландыру"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Румыния: оқу хабарландыруы"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Өмір мен мүлікті сақтауға ұсынылған әрекеттер"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Қоғамдық қауіпсіздік туралы хабарландыру"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Дыбыссыз хабарландыру"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Жаттығу хабарландырулары"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Шұғыл хабарландыру алу: оқу/жаттығу хабары"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: төніп тұрған қауіп туралы хабарландыру"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: төтенше жағдай туралы хабарландыру"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: төтенше жағдай туралы хабарландыру"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: төтенше жағдай туралы хабарландыру"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: маңызды хабарландыру"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: жоғалған бала туралы хабарландыру"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: қоғамдық қауіпсіздік туралы хабарландыру"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: жаттығу хабарландырулары"</string>
 </resources>
diff --git a/res/values-mcc226-km/strings.xml b/res/values-mcc226-km/strings.xml
index dc8b89853..1854fcbb5 100644
--- a/res/values-mcc226-km/strings.xml
+++ b/res/values-mcc226-km/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"ការជូនដំណឹងអំពីហានិភ័យដែលទំនងនឹងកើតមាន"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"ការគំរាមកំហែងដល់អាយុជីវិត និងទ្រព្យសម្បត្តិ​ដែលទំនងនឹងកើតមាន"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"ការជូនដំណឹងអំពីការបាត់កុមារ"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"ការជូនដំណឹងរបស់រូម៉ានី៖ ការជូនដំណឹងអំពីការបាត់កុមារ"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"ការជូនដំណឹង​របស់រូម៉ានី៖ ការជូនដំណឹង​ផ្លូវការ"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"ការជូនដំណឹងរបស់រូម៉ានី៖ ការជូនដំណឹងអំពីគ្រោះថ្នាក់ធ្ងន់ធ្ងរបំផុត"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"ការជូនដំណឹងរបស់រូម៉ានី៖ ការជូនដំណឹងអំពីគ្រោះថ្នាក់ធ្ងន់ធ្ងរបំផុត"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"ការជូនដំណឹងរបស់រូម៉ានី៖ ការជូនដំណឹងអំពីគ្រោះថ្នាក់ធ្ងន់ធ្ងរបំផុត"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"ការជូនដំណឹងរបស់រូម៉ានី៖ ការជូនដំណឹងអំពីគ្រោះថ្នាក់ធ្ងន់ធ្ងរ"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"ការជូនដំណឹងរបស់រូម៉ានី៖ ការជូនដំណឹងអំពីការហ្វឹកហាត់"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"សកម្មភាព​ដែលណែនាំ​ឱ្យធ្វើ​ដែលអាច​ជួយសង្គ្រោះអាយុជីវិត ឬទ្រព្យ​សម្បត្តិ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"ការជូនដំណឹង​អំពីសុវត្ថិភាព​សាធារណៈ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"ការជូនដំណឹងស្ងាត់"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"ការជូនដំណឹង​អំពី​ការអនុវត្តសាកល្បង"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"ទទួលការប្រកាសអាសន្ន៖ សារនៃ​ការអនុវត្ត/ការហ្វឹកហាត់"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"ការជូនដំណឹងរូម៉ានី៖ ការជូនដំណឹងអំពីហានិភ័យដែលទំនងនឹងកើតមាន"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"ការជូនដំណឹងរូម៉ានី៖ ការជូនដំណឹងអំពីអាសន្នធ្ងន់ធ្ងរ"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"ការជូនដំណឹងរូម៉ានី៖ ការជូនដំណឹងអំពីអាសន្នធ្ងន់ធ្ងរ"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"ការជូនដំណឹងរូម៉ានី៖ ការជូនដំណឹងអំពីអាសន្នធ្ងន់ធ្ងរ"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"ការជូនដំណឹងរូម៉ានី៖ ការជូនដំណឹងអំពីអាសន្នធ្ងន់ធ្ងរ"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"ការជូនដំណឹងរូម៉ានី៖ ការជូនដំណឹងអំពីការបាត់កុមារ"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"ការជូនដំណឹងរូម៉ានី៖ ការជូនដំណឹងសុវត្ថិភាពសាធារណៈ"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"ការជូនដំណឹងរូម៉ានី៖ ការជូនដំណឹងការអនុវត្តសាកល្បង"</string>
 </resources>
diff --git a/res/values-mcc226-kn/strings.xml b/res/values-mcc226-kn/strings.xml
index 413aa35a3..a21a2f8e1 100644
--- a/res/values-mcc226-kn/strings.xml
+++ b/res/values-mcc226-kn/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"ಸನ್ನಿಹಿತ ಅಪಾಯದ ಅಲರ್ಟ್"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"ಜೀವ ಮತ್ತು ಆಸ್ತಿಗೆ ಸನ್ನಿಹಿತ ಬೆದರಿಕೆಗಳು"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"ಕಾಣೆಯಾದ ಮಕ್ಕಳ ಕುರಿತ ಅಲರ್ಟ್"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-ಅಲರ್ಟ್: ಕಾಣೆಯಾದ ಮಕ್ಕಳ ಕುರಿತ ಅಲರ್ಟ್"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-ಅಲರ್ಟ್: ಪ್ರೆಸಿಡೆನ್ಶಿಯಲ್ ಅಲರ್ಟ್"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-ಅಲರ್ಟ್: ತಕ್ಷಣದ ಅಲರ್ಟ್"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-ಅಲರ್ಟ್: ತಕ್ಷಣದ ಅಲರ್ಟ್"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-ಅಲರ್ಟ್: ತಕ್ಷಣದ ಅಲರ್ಟ್"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-ಅಲರ್ಟ್: ಗಂಭೀರ ಅಲರ್ಟ್"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-ಅಲರ್ಟ್: ಪ್ರಾಯೋಗಿಕ ಅಲರ್ಟ್"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"ಜೀವನ ಅಥವಾ ಆಸ್ತಿಯನ್ನು ಉಳಿಸಬಹುದಾದ ಶಿಫಾರಸು ಮಾಡಲಾದ ಕ್ರಮಗಳು"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"ಸಾರ್ವಜನಿಕ ಸುರಕ್ಷತೆಯ ಎಚ್ಚರಿಕೆ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"ಸೈಲೆಂಟ್ ಅಲರ್ಟ್"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"ಅಭ್ಯಾಸದ ಅಲರ್ಟ್‌ಗಳು"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"ತುರ್ತು ಅಲರ್ಟ್ ಅನ್ನು ಸ್ವೀಕರಿಸಿ: ಅಭ್ಯಾಸ/ಡ್ರಿಲ್ ಕುರಿತ ಸಂದೇಶ"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ಅಲರ್ಟ್: ಸನ್ನಿಹಿತ ಅಪಾಯದ ಅಲರ್ಟ್"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ಅಲರ್ಟ್: ತಕ್ಷಣದ ಅಲರ್ಟ್"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ಅಲರ್ಟ್: ತಕ್ಷಣದ ಅಲರ್ಟ್"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ಅಲರ್ಟ್: ತಕ್ಷಣದ ಅಲರ್ಟ್"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ಅಲರ್ಟ್: ಗಂಭೀರ ಅಲರ್ಟ್"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ಅಲರ್ಟ್: ಕಾಣೆಯಾದ ಮಕ್ಕಳ ಕುರಿತ ಅಲರ್ಟ್"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ಅಲರ್ಟ್: ಸಾರ್ವಜನಿಕ ಸುರಕ್ಷತೆಯ ಎಚ್ಚರಿಕೆ"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ಅಲರ್ಟ್: ಅಭ್ಯಾಸದ ಅಲರ್ಟ್‌ಗಳು"</string>
 </resources>
diff --git a/res/values-mcc226-ko/strings.xml b/res/values-mcc226-ko/strings.xml
index 4cbcc4956..cf04cf163 100644
--- a/res/values-mcc226-ko/strings.xml
+++ b/res/values-mcc226-ko/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"급박한 위험 알림"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"생명 및 재산에 대한 급박한 위험"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"아동 실종 경보"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: 아동 실종 경보"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: 위급재난 경보"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: 긴급 경보"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: 긴급 경보"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: 긴급 경보"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: 위험 경보"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: 훈련 경보"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"생명이나 재산을 보호할 수 있는 행동 요령"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"공공 안전 알림"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"무음 알림"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"안전 훈련 알림"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"긴급 재난 문자 받기: 훈련 메시지"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : 급박한 위험 알림"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : 긴급 알림"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : 긴급 알림"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : 긴급 알림"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : 심각한 위험 알림"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : 아동 실종 알림"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : 공공 안전 알림"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : 안전 훈련 알림"</string>
 </resources>
diff --git a/res/values-mcc226-ky/strings.xml b/res/values-mcc226-ky/strings.xml
index 332717aa5..07b437121 100644
--- a/res/values-mcc226-ky/strings.xml
+++ b/res/values-mcc226-ky/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Кооптуу жагдай тууралуу эскертүү"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Өмүргө жана мүлккө келтирилген коркунучтар"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Баланын жоголгону тууралуу эскертүү"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-эскертүүсү: Баланын жоголгону тууралуу эскертүү"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-билдирүүсү: Президенттин шашылыш билдирүүсү"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-билдирүүсү: Өтө коркунучтуу кырдаал жөнүндө шашылыш билдирүү"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-билдирүүсү: Өтө коркунучтуу кырдаал жөнүндө шашылыш билдирүү"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-билдирүүсү: Өтө коркунучтуу кырдаал жөнүндө шашылыш билдирүү"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-билдирүүсү: Олуттуу кырдаал жөнүндө шашылыш билдирүү"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-билдирүүсү: Көнүгүү билдирүүсү"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Бирөөнүн өмүрүн же мүлкүн сактап калууга сунушталган аракеттер"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Коомдук коопсуздукка жаралган коркунуч билдирүүсү"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Үнсүз эскертүү"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Көнүгүү билдирүүлөрү"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Шашылыш билдирүүнү алуу: Көнүгүү/Көнүгүү билдирүүсү"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ЭСКЕРТҮҮСҮ : Кооптуу жагдай эскертүүсү"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ЭСКЕРТҮҮСҮ: Өзгөчө кырдаалдагы шашылыш билдирүү"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ЭСКЕРТҮҮСҮ: Өзгөчө кырдаалдагы шашылыш билдирүү"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ЭСКЕРТҮҮСҮ: Өзгөчө кырдаалдагы шашылыш билдирүү"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ЭСКЕРТҮҮСҮ: Олуттуу кырдаал жөнүндө билдирүү"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ЭСКЕРТҮҮСҮ: Баланын жоголгону тууралуу эскертүү"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ЭСКЕРТҮҮСҮ : Коом үчүн коркунуч билдирүүсү"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ЭСКЕРТҮҮСҮ : Көнүгүү билдирүүлөрү"</string>
 </resources>
diff --git a/res/values-mcc226-lo/strings.xml b/res/values-mcc226-lo/strings.xml
index 3b02fa2ac..14f5280ee 100644
--- a/res/values-mcc226-lo/strings.xml
+++ b/res/values-mcc226-lo/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"ແຈ້ງເຕືອນຄວາມສ່ຽງທີ່ຈະເກີດຂຶ້ນ"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"ໄພຄຸກຄາມຕໍ່ຊີວິດ ແລະ ຊັບສິນທີ່ຈະເກີດຂຶ້ນ"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"ແຈ້ງເຕືອນເດັກສູນຫາຍ"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"ການເຕືອນ RO: ແຈ້ງເຕືອນເດັກສູນຫາຍ"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"ການເຕືອນ RO: ການເຕືອນລະດັບປະທານາທິບໍດີ"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"ການເຕືອນ RO : ການເຕືອນລະດັບສູງສຸດ"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"ການເຕືອນ RO : ການເຕືອນລະດັບສູງສຸດ"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"ການເຕືອນ RO : ການເຕືອນລະດັບສູງສຸດ"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"ການເຕືອນ RO: ການເຕືອນລະດັບຮ້າຍແຮງ"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"ການເຕືອນ RO: ການເຕືອນເຝິກຊ້ອມ"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"ຄຳສັ່ງທີ່ແນະນຳທີ່ສາມາດຊ່ວຍຊີວິດ ຫຼື ຊັບສິນໄດ້"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"ການແຈ້ງເຕືອນດ້ານຄວາມປອດໄພສາທາລະນະ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"ແຈ້ງເຕືອນງຽບ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"ແຈ້ງເຕືອນເຝິກແອບ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"ຮັບແຈ້ງເຕືອນເຫດສຸກເສີນ: ຂໍ້ຄວາມເຝິກແອບ"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : ແຈ້ງເຕືອນຄວາມສ່ຽງທີ່ໃກ້ຈະເກີດຂຶ້ນ"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : ການເຕືອນສຸດຂີດ"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : ການເຕືອນສຸດຂີດ"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : ການເຕືອນສຸດຂີດ"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : ແຈ້ງເຕືອນຮຸນແຮງ"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : ແຈ້ງເຕືອນເດັກສູນຫາຍ"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : ແຈ້ງເຕືອນຄວາມປອດໄພສາທາລະນະ"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : ແຈ້ງເຕືອນເຝິກແອບ"</string>
 </resources>
diff --git a/res/values-mcc226-lt/strings.xml b/res/values-mcc226-lt/strings.xml
index a9181e9f2..e933fa502 100644
--- a/res/values-mcc226-lt/strings.xml
+++ b/res/values-mcc226-lt/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Įspėjimas apie neišvengiamą riziką"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Neišvengiama grėsmė gyvybei ir nuosavybei"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Įspėjimas apie dingusį vaiką"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Rumunijos įspėjimas: įspėjimas apie dingusį vaiką"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Rumunijos įspėjimas: prezidento paskelbtas įspėj."</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Rumunijos įspėjimas: ekstremalus įspėjimas"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Rumunijos įspėjimas: ekstremalus įspėjimas"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Rumunijos įspėjimas: ekstremalus įspėjimas"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Rumunijos įspėjimas: rimtas įspėjimas"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Rumunijos įspėjimas: mokomasis įspėjimas"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Rekomenduojami veiksmai, kuriais galima apsaugoti gyvybę ar nuosavybę"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Visuomenės saugumo įspėjimas"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Tylus įspėjimas"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Įspėjimai apie pratybas"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Gaukite įspėjimą apie kritinę padėtį: pratybų / mokomasis pranešimas"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: įspėjimas apie neišvengiamą pavojų"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: ekstremalus įspėjimas"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: ekstremalus įspėjimas"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: ekstremalus įspėjimas"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: rimtas įspėjimas"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: įspėjimas apie dingusį vaiką"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: visuomenės saugumo įspėjimas"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: mokomieji įspėjimai"</string>
 </resources>
diff --git a/res/values-mcc226-lv/strings.xml b/res/values-mcc226-lv/strings.xml
index 91b2f7412..6ef0f9ca1 100644
--- a/res/values-mcc226-lv/strings.xml
+++ b/res/values-mcc226-lv/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Brīdinājums par nenovēršamu risku"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Nenovēršams apdraudējums dzīvībai un īpašumam"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Brīdinājums par pazudušu bērnu"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: brīdinājums par pazudušu bērnu"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: valsts līmeņa brīdinājums"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: ārkārtas situācijas brīdinājums"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: ārkārtas situācijas brīdinājums"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: ārkārtas situācijas brīdinājums"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: nopietnas situācijas brīdinājums"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: vingrinājuma brīdinājums"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Ieteicamās darbības, kas var izglābt dzīvību vai īpašumu"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Brīdinājums par sabiedrisko drošību"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Kluss brīdinājums"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Mācību trauksmes brīdinājumi"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Saņemt ārkārtas brīdinājumu: mācību trauksmes/simulācijas ziņojumu"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: brīdinājums par nenovēršamu risku"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: ārkārtas situācijas brīdinājums"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: ārkārtas situācijas brīdinājums"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: ārkārtas situācijas brīdinājums"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: nopietnas situācijas brīdinājums"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: brīdinājums par pazudušu bērnu"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: brīdinājums par sabiedrisko drošību"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: mācību trauksmes brīdinājumi"</string>
 </resources>
diff --git a/res/values-mcc226-mk/strings.xml b/res/values-mcc226-mk/strings.xml
index cc07bd64b..1e5452b17 100644
--- a/res/values-mcc226-mk/strings.xml
+++ b/res/values-mcc226-mk/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Предупредување за непосреден ризик"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Непосредни закани по животот и имотот"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Предупредување за изгубено дете"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Романија: предупредување за изгубено дете"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: претседателско предупредување"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: предупредување од највисок степен"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: предупредување од највисок степен"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: предупредување од највисок степен"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: сериозно предупредување"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: предупредување за вежба"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Препорачани дејства што може да спасат животи или имот"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Предупредување за јавна безбедност"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Безгласно предупредување"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Предупредувања за вежба"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Добивајте предупредувања за итни случаи: порака за вежба/обука"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ПРЕДУПРЕДУВАЊЕ : Непосреден ризик"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ПРЕДУПРЕДУВАЊЕ : Екстремна ситуација"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ПРЕДУПРЕДУВАЊЕ : Екстремна ситуација"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ПРЕДУПРЕДУВАЊЕ : Екстремна ситуација"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ПРЕДУПРЕДУВАЊЕ : Сериозна ситуација"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ПРЕДУПРЕДУВАЊЕ : Изгубено дете"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ПРЕДУПРЕДУВАЊЕ : Јавна безбедност"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ПРЕДУПРЕДУВАЊЕ : Вежба"</string>
 </resources>
diff --git a/res/values-mcc226-ml/strings.xml b/res/values-mcc226-ml/strings.xml
index 1b44037aa..2527f4ab1 100644
--- a/res/values-mcc226-ml/strings.xml
+++ b/res/values-mcc226-ml/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"ആസന്നമായ അപകടം സംബന്ധിച്ച മുന്നറിയിപ്പ്"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"ജീവനും സ്വത്തിനും സംഭവിക്കാനിരിക്കുന്ന ഭീഷണികൾ"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"കുട്ടിയെ കാണാനില്ലെന്ന മുന്നറിയിപ്പ്"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-അലേർട്ട്: കുട്ടിയെ കാണാനില്ലെന്ന മുന്നറിയിപ്പ്"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"റൊമാനിയ-മുന്നറിയിപ്പ്: പ്രസിഡൻഷ്യൽ മുന്നറിയിപ്പ്"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"റൊമാനിയ-മുന്നറിയിപ്പ്: അതീവ ഗുരുതര മുന്നറിയിപ്പ്"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"റൊമാനിയ-മുന്നറിയിപ്പ്: അതീവ ഗുരുതര മുന്നറിയിപ്പ്"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"റൊമാനിയ-മുന്നറിയിപ്പ്: അതീവ ഗുരുതര മുന്നറിയിപ്പ്"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"റൊമാനിയ-മുന്നറിയിപ്പ്: ഗുരുതര മുന്നറിയിപ്പ്"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"റൊമാനിയ-മുന്നറിയിപ്പ്: പരിശീലന മുന്നറിയിപ്പ്"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"ജീവനോ സ്വത്തോ സംരക്ഷിക്കുന്ന, ശുപാർശ ചെയ്യുന്ന നടപടികൾ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"പൊതു സുരക്ഷാ മുന്നറിയിപ്പ്"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"നിശബ്‌ദ മുന്നറിയിപ്പ്"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"പരിശീലന അറിയിപ്പുകൾ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"അടിയന്തര മുന്നറിയിപ്പുകൾ നേടൂ: പരിശീലന/ഡ്രിൽ സന്ദേശം"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"റൊമാനിയ-മുന്നറിയിപ്പ് : ആസന്നമായ അപകടം സംബന്ധിച്ച അലേർട്ട്"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"റൊമാനിയ-മുന്നറിയിപ്പ് : അതീവ ഗുരുതര മുന്നറിയിപ്പ്"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"റൊമാനിയ-മുന്നറിയിപ്പ് : അതീവ ഗുരുതര മുന്നറിയിപ്പ്"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"റൊമാനിയ-മുന്നറിയിപ്പ് : അതീവ ഗുരുതര മുന്നറിയിപ്പ്"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"റൊമാനിയ-മുന്നറിയിപ്പ് : ഗുരുതര മുന്നറിയിപ്പ്"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-അലേർട്ട്: കുട്ടിയെ കാണാനില്ലെന്ന മുന്നറിയിപ്പ്"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"റൊമാനിയ-മുന്നറിയിപ്പ് : പൊതുസുരക്ഷാ അലേർട്ട്"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"റൊമാനിയ-മുന്നറിയിപ്പ് : പരിശീലന മുന്നറിയിപ്പ്"</string>
 </resources>
diff --git a/res/values-mcc226-mn/strings.xml b/res/values-mcc226-mn/strings.xml
index 88784fcf0..cb2908dc9 100644
--- a/res/values-mcc226-mn/strings.xml
+++ b/res/values-mcc226-mn/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Ноцтой эрсдэлийн сэрэмжлүүлэг"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Амь нас, өмч хөрөнгөд учрах ноцтой эрсдэл"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Алга болсон хүүхдийн сэрэмжлүүлэг"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"РУ-Сэрэмжлүүлэг: Алга болсон хүүхдийн сэрэмжлүүлэг"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-сэрэмжлүүлэг: Ерөнхийлөгчийн сэрэмжлүүлэг"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-сэрэмжлүүлэг: Ноцтой сэрэмжлүүлэг"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-сэрэмжлүүлэг: Ноцтой сэрэмжлүүлэг"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-сэрэмжлүүлэг: Ноцтой сэрэмжлүүлэг"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-сэрэмжлүүлэг: Маш ноцтой сэрэмжлүүлэг"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-сэрэмжлүүлэг: Сургуулилалтын сэрэмжлүүлэг"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Амь нас, өмч хөрөнгийг аварч болох санал болгосон үйлдэл"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Олон нийтийн аюулгүй байдлын сэрэмжлүүлэг"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Чимээгүй сэрэмжлүүлэг"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Сургуулилалтын сэрэмжлүүлэг"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Утасгүй яаралтай тусламжийн сэрэмжлүүлэг хүлээн авах: дасгал/сургуулилалтын мессеж"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : Ноцтой эрсдэлийн сэрэмжлүүлэг"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : Ноцтой байдлын сэрэмжлүүлэг"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : Ноцтой байдлын сэрэмжлүүлэг"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : Ноцтой байдлын сэрэмжлүүлэг"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-сэрэмжлүүлэг: Маш ноцтой байдлын сэрэмжлүүлэг"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : Алга болсон хүүхдийн тухай сэрэмжлүүлэг"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : Нийтийн аюулгүй байдлын сэрэмжлүүлэг"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : Сургуулилалтын сэрэмжлүүлэг"</string>
 </resources>
diff --git a/res/values-mcc226-mr/strings.xml b/res/values-mcc226-mr/strings.xml
index 84857992d..9ddc5c4b1 100644
--- a/res/values-mcc226-mr/strings.xml
+++ b/res/values-mcc226-mr/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"धोक्याचा स्पष्ट इशारा"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"जीवन आणि मालमत्तेला असलेला स्पष्ट धोका"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"हरवलेल्या लहान मुलाशी संबंधित सूचना"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO इशारा: हरवलेल्या लहान मुलाशी संबंधित सूचना"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO सूचना: राष्ट्रपतींनी दिलेला इशारा"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO सूचना: अतिदक्षतेचा इशारा"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO सूचना: अतिदक्षतेचा इशारा"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO सूचना: अतिदक्षतेचा इशारा"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO सूचना: दक्षतेचा इशारा"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO सूचना: चाचणी सूचना"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"जीवन आणि मालमत्ता वाचवू शकतात अशा शिफारस केलेल्या उपाययोजना"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"सार्वजनिक सुरक्षितता इशारा"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"सायलंट अलर्ट"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"व्यायामासंबंधित सूचना"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"आणीबाणी इशारा मिळवा: व्यायाम/ड्रिल मेसेज"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO इशारा : धोक्याचा स्पष्ट इशारा"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO इशारा : अतिदक्षतेचा इशारा"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO इशारा : अतिदक्षतेचा इशारा"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO इशारा : अतिदक्षतेचा इशारा"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO इशारा : दक्षतेचा इशारा"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO इशारा: हरवलेल्या लहान मुलाशी संबंधित सूचना"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO इशारा : सार्वजनिक सुरक्षितता इशारा"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO इशारा : व्यायामासंबंधित इशारा"</string>
 </resources>
diff --git a/res/values-mcc226-ms/strings.xml b/res/values-mcc226-ms/strings.xml
index f35ded014..7b5d586d6 100644
--- a/res/values-mcc226-ms/strings.xml
+++ b/res/values-mcc226-ms/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Makluman Risiko Berkemungkinan Tinggi"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Ancaman yang berkemungkinan besar berlaku kepada nyawa dan harta benda"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Makluman Kanak-Kanak Hilang"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Makluman-RO: Makluman Kanak-Kanak Hilang"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Makluman-RO: Makluman Presiden"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Makluman-RO: Makluman Ekstrem"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Makluman-RO: Makluman Ekstrem"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Makluman-RO: Makluman Ekstrem"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Makluman-RO: Makluman Teruk"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Makluman-RO: Makluman Latihan"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Tindakan yang disyorkan untuk menyelamatkan nyawa atau harta"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Makluman Keselamatan Awam"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Makluman Senyap"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Makluman Latihan"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Terima amaran kecemasan: mesej latihan/latih tubi"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"MAKLUMAN-RO : Makluman Risiko Berkemungkinan Besar Berlaku"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"MAKLUMAN-RO : Makluman Ekstrem"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"MAKLUMAN-RO : Makluman Ekstrem"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"MAKLUMAN-RO : Makluman Ekstrem"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"MAKLUMAN-RO : Makluman Teruk"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"MAKLUMAN-RO: Makluman Kanak-Kanak Hilang"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"MAKLUMAN-RO : Makluman Keselamatan Awam"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"MAKLUMAN-RO : Makluman Latihan"</string>
 </resources>
diff --git a/res/values-mcc226-my/strings.xml b/res/values-mcc226-my/strings.xml
index b35253286..43c25cb64 100644
--- a/res/values-mcc226-my/strings.xml
+++ b/res/values-mcc226-my/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"ချက်ချင်းဖြစ်နိုင်သော အန္တရာယ်သတိပေးချက်"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"အသက်အိုးအိမ်အတွက် ချက်ချင်းကျရောက်နိုင်သော အန္တရာယ်များ"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"ကလေးပျောက်ကြောင်း သတိပေးချက်"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-သတိပေးချက်- ကလေးပျောက်ကြောင်း သတိပေးချက်"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-သတိပေးချက်− သမ္မတအဆင့် သတိပေးချက်"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-သတိပေးချက်− ပြင်းထန်သည့် သတိပေးချက်"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-သတိပေးချက်− ပြင်းထန်သည့် သတိပေးချက်"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-သတိပေးချက်− ပြင်းထန်သည့် သတိပေးချက်"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-သတိပေးချက်− လွန်ကဲပြင်းထန်သည့် သတိပေးချက်"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-သတိပေးချက်− လေ့ကျင့်ရေး သတိပေးချက်"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"အသက်အိုးအိမ်တို့ကို ကယ်တင်နိုင်သော အကြံပြုထားသည့် လုပ်ဆောင်ချက်များ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"လူထုလုံခြုံရေး သတိပေးချက်"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"အသံတိတ် သတိပေးချက်"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"လေ့ကျင့်သည့် သတိပေးချက်များ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"အရေးပေါ် သတိပေးချက်ကို လက်ခံရန်- လေ့ကျင့်ရေး/သရုပ်ပြ မက်ဆေ့ဂျ်"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT - ချက်ချင်းဖြစ်ပေါ်နိုင်သော အန္တရာယ်ကို သတိပေးချက်"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT − အလွန်ပြင်းထန်ကြောင်း သတိပေးချက်"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT − အလွန်ပြင်းထန်ကြောင်း သတိပေးချက်"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT − အလွန်ပြင်းထန်ကြောင်း သတိပေးချက်"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT - အလွန်ပြင်းထန်ကြောင်း သတိပေးချက်"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT - ကလေးပျောက်ကြောင်း သတိပေးချက်"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT - လူထုလုံခြုံရေး သတိပေးချက်"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT - လေ့ကျင့်သည့် သတိပေးချက်များ"</string>
 </resources>
diff --git a/res/values-mcc226-nb/strings.xml b/res/values-mcc226-nb/strings.xml
index 59ecc4a13..2fd6683db 100644
--- a/res/values-mcc226-nb/strings.xml
+++ b/res/values-mcc226-nb/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Varsel om umiddelbar fare"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Umiddelbare trusler mot liv og eiendom"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Varsel om savnet barn"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-varsel: Varsel om savnet barn"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-varsel: presidentvarsel"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-varsel: ekstremvarsel"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-varsel: ekstremvarsel"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-varsel: ekstremvarsel"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-varsel: alvorlig varsel"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-varsel: øvelsesvarsel"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Anbefalte handlinger som kan redde liv eller eiendom"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Offentlig sikkerhetsvarsel"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Stille varsel"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Øvelsesvarsler"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Motta nødvarsel: øvelsesmelding"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-VARSEL: varsel om umiddelbar fare"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-VARSEL: ekstremvarsel"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-VARSEL: ekstremvarsel"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-VARSEL: ekstremvarsel"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-VARSEL: alvorlig varsel"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-VARSEL: varsel om savnet barn"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-VARSEL: offentlig sikkerhetsvarsel"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-VARSEL: øvelsesvarsler"</string>
 </resources>
diff --git a/res/values-mcc226-ne/strings.xml b/res/values-mcc226-ne/strings.xml
index 93d74840e..2c553e526 100644
--- a/res/values-mcc226-ne/strings.xml
+++ b/res/values-mcc226-ne/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"सम्भाव्य जोखिमसम्बन्धी अलर्ट"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"जनधनसँग सम्बन्धित सम्भाव्य खतराहरू"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"बच्चा हराएको सूचना"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: बच्चा हराएको सूचना"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: राष्ट्राध्यक्षीय सतर्कता"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: चरम गम्भीरता भएको सतर्कता"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: चरम गम्भीरता भएको सतर्कता"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: चरम गम्भीरता भएको सतर्कता"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: गम्भीर सतर्कता"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: व्यायामसम्बन्धी सतर्कता"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"जीवन वा सम्पत्तिको सुरक्षा गर्न सक्ने सिफारिस गरिएका कार्यहरू"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"सार्वजनिक सुरक्षासम्बन्धी अलर्ट"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"साइलेन्ट अलर्ट"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"अभ्याससम्बन्धी अलर्टहरू"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"आपत्‌कालीन अलर्ट प्राप्त गर्नुहोस्: अभ्यास/तालीमसम्बन्धी म्यासेज"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : सम्भाव्य जोखिमसम्बन्धी अलर्ट"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-Alert: चरम गम्भीर स्थितिसम्बन्धी अलर्ट"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-Alert: चरम गम्भीर स्थितिसम्बन्धी अलर्ट"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-Alert: चरम गम्भीर स्थितिसम्बन्धी अलर्ट"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-Alert: गम्भीर स्थितिसम्बन्धी अलर्ट"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-Alert: बच्चा हराएको सूचना"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : सार्वजनिक सुरक्षासम्बन्धी अलर्ट"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : अभ्याससम्बन्धी अलर्ट"</string>
 </resources>
diff --git a/res/values-mcc226-nl/strings.xml b/res/values-mcc226-nl/strings.xml
index ef989db53..e60ecced4 100644
--- a/res/values-mcc226-nl/strings.xml
+++ b/res/values-mcc226-nl/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Melding voor dreigend risico"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Directe bedreigingen voor levens en eigendommen"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Waarschuwing voor vermist kind"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: waarschuwing voor vermist kind"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: presidentiële waarschuwing"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: extreme waarschuwing"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: extreme waarschuwing"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: extreme waarschuwing"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: ernstige waarschuwing"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: oefeningswaarschuwing"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Aanbevolen acties die levens of eigendommen kunnen redden"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Openbare veiligheidsmelding"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Stille melding"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Oefeningsmeldingen"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Noodmelding ontvangen: bericht voor oefening/test"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: waarschuwing voor dreigend risico"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: extreme waarschuwing"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: extreme waarschuwing"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: extreme waarschuwing"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: ernstige waarschuwing"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: waarschuwing voor vermist kind"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : openbare veiligheidsmelding"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : meldingen voor oefeningen"</string>
 </resources>
diff --git a/res/values-mcc226-or/strings.xml b/res/values-mcc226-or/strings.xml
index 7730be77b..eca1b7fef 100644
--- a/res/values-mcc226-or/strings.xml
+++ b/res/values-mcc226-or/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"ଆସନ୍ନ ବିପଦର ଆଲର୍ଟ"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"ଜୀବନ ଏବଂ ସମ୍ପତ୍ତି ପ୍ରତି ଆସନ୍ନ ବିପଦ"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"ହଜି ଯାଇଥିବା ପିଲା ବିଷୟରେ ଆଲର୍ଟ"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-ଆଲର୍ଟ: ହଜି ଯାଇଥିବା ପିଲା ବିଷୟରେ ଆଲର୍ଟ"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-ଆଲର୍ଟ: ପ୍ରେସିଡେନ୍ସିଆଲ୍ ଆଲର୍ଟ"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-ଆଲର୍ଟ: ଏକ୍ସଟ୍ରିମ୍ ଆଲର୍ଟ"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-ଆଲର୍ଟ: ଏକ୍ସଟ୍ରିମ୍ ଆଲର୍ଟ"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-ଆଲର୍ଟ: ଏକ୍ସଟ୍ରିମ୍ ଆଲର୍ଟ"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-ଆଲର୍ଟ: ଗମ୍ଭୀର ଆଲର୍ଟ"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-ଆଲର୍ଟ: ବ୍ୟାୟାମ ଆଲର୍ଟ"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"ଜୀବନ କିମ୍ବା ସମ୍ପତ୍ତିକୁ ସେଭ କରିପାରୁଥିବା ସୁପାରିଶ କରାଯାଇଥିବା କାର୍ଯ୍ୟ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"ପବ୍ଲିକ ସୁରକ୍ଷା ଆଲର୍ଟ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"ସାଇଲେଣ୍ଟ ଆଲର୍ଟ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"ବ୍ୟାୟାମ ଆଲର୍ଟ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"ଜରୁରୀକାଳୀନ ଆଲର୍ଟ ପାଆନ୍ତୁ: ବ୍ୟାୟାମ/ଡ୍ରିଲ ମେସେଜ"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ଆଲର୍ଟ : ଆସନ୍ନ ବିପଦର ଆଲର୍ଟ"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ଆଲର୍ଟ: ଏକ୍ସଟ୍ରିମ ଆଲର୍ଟ"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ଆଲର୍ଟ: ଏକ୍ସଟ୍ରିମ ଆଲର୍ଟ"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ଆଲର୍ଟ: ଏକ୍ସଟ୍ରିମ ଆଲର୍ଟ"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ଆଲର୍ଟ: ଗୁରତର ଆଲର୍ଟ"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ଆଲର୍ଟ: ନିଖୋଜ ପିଲାଙ୍କ ବିଷୟରେ ଆଲର୍ଟ"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ଆଲର୍ଟ : ପବ୍ଲିକ ସୁରକ୍ଷା ଆଲର୍ଟ"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ଆଲର୍ଟ : ବ୍ୟାୟାମ ଆଲର୍ଟ"</string>
 </resources>
diff --git a/res/values-mcc226-pa/strings.xml b/res/values-mcc226-pa/strings.xml
index 9053316d9..2b212a0cb 100644
--- a/res/values-mcc226-pa/strings.xml
+++ b/res/values-mcc226-pa/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"ਪ੍ਰਤੱਖ ਜੋਖਮ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"ਜਾਨ ਅਤੇ ਮਾਲ \'ਤੇ ਪ੍ਰਤੱਖ ਖਤਰੇ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"ਲਾਪਤਾ ਬੱਚੇ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-ਅਲਰਟ: ਲਾਪਤਾ ਬੱਚੇ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-ਅਲਰਟ: ਰਾਸ਼ਟਰਪਤੀ ਵੱਲੋਂ ਅਲਰਟ"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-ਅਲਰਟ: ਗੰਭੀਰ ਅਲਰਟ"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-ਅਲਰਟ: ਗੰਭੀਰ ਅਲਰਟ"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-ਅਲਰਟ: ਗੰਭੀਰ ਅਲਰਟ"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-ਅਲਰਟ: ਬਹੁਤ ਗੰਭੀਰ ਅਲਰਟ"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-ਅਲਰਟ: ਅਭਿਆਸੀ ਅਲਰਟ"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"ਜਾਨ ਜਾਂ ਮਾਲ ਦੀ ਸੁਰੱਖਿਆ ਕਰ ਸਕਣ ਵਾਲੀਆਂ ਸਿਫ਼ਾਰਸ਼ੀ ਕਾਰਵਾਈਆਂ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"ਜਨਤਕ ਸੁਰੱਖਿਆ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"ਬਿਨਾਂ ਅਵਾਜ਼ ਵਾਲਾ ਅਲਰਟ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"ਅਭਿਆਸ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"ਐਮਰਜੈਂਸੀ ਅਲਰਟ ਪ੍ਰਾਪਤ ਕਰੋ: ਅਭਿਆਸੀ/ਡ੍ਰਿਲ ਸੁਨੇਹਾ"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ਅਲਰਟ : ਪ੍ਰਤੱਖ ਜੋਖਮ ਦਾ ਅਲਰਟ"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ਅਲਰਟ : ਗੰਭੀਰ ਸਥਿਤੀ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ਅਲਰਟ : ਗੰਭੀਰ ਸਥਿਤੀ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ਅਲਰਟ : ਗੰਭੀਰ ਸਥਿਤੀ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ਅਲਰਟ: ਬਹੁਤ ਗੰਭੀਰ ਸਥਿਤੀ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ਅਲਰਟ : ਲਾਪਤਾ ਬੱਚੇ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ਅਲਰਟ : ਜਨਤਕ ਸੁਰੱਖਿਆ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ਅਲਰਟ : ਅਭਿਆਸ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
 </resources>
diff --git a/res/values-mcc226-pl/strings.xml b/res/values-mcc226-pl/strings.xml
index f6eb4dbcc..a3d2fe92d 100644
--- a/res/values-mcc226-pl/strings.xml
+++ b/res/values-mcc226-pl/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Alert o bezpośrednim zagrożeniu"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Bezpośrednie zagrożenia życia i mienia"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Alert o zaginięciu dziecka"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Alert dla Rumunii: alert o zaginięciu dziecka"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Alert dla Rumunii: alert prezydencki"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Alert dla Rumunii: ekstremalny alert"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Alert dla Rumunii: ekstremalny alert"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Alert dla Rumunii: ekstremalny alert"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Alert dla Rumunii: poważny alert"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Alert dla Rumunii: alert ćwiczeniowy"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Zalecane działania, które mogą ocalić życie lub mienie"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Alert dotyczący bezpieczeństwa publicznego"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Cichy alert"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Alerty ćwiczeniowe"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Otrzymuj alerty o zagrożeniach: komunikat o ćwiczeniach/symulacji"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: alert o bezpośrednim zagrożeniu"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: alert o ekstremalnym zagrożeniu"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: alert o ekstremalnym zagrożeniu"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: alert o ekstremalnym zagrożeniu"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: alert o poważnym zagrożeniu"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: alert o zaginięciu dziecka"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: alert dotyczący bezpieczeństwa publicznego"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: alerty ćwiczeniowe"</string>
 </resources>
diff --git a/res/values-mcc226-pt-rPT/strings.xml b/res/values-mcc226-pt-rPT/strings.xml
index fb11795b3..4bd96a1b5 100644
--- a/res/values-mcc226-pt-rPT/strings.xml
+++ b/res/values-mcc226-pt-rPT/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Alerta de risco iminente"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Ameaças iminentes à vida e à propriedade"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Alerta de criança desaparecida"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: alerta de criança desaparecida"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: alerta presidencial"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: alerta extremo"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: alerta extremo"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: alerta extremo"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: alerta grave"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: mensagem de exercício"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Ações recomendadas que podem salvar vidas ou propriedades."</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Alerta de segurança pública"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Alerta silencioso"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Alertas de exercício"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Receber um alerta de emergência: mensagem de simulação/exercício"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: alerta de risco iminente"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: alerta extremo"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: alerta extremo"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: alerta extremo"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: alerta grave"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: alerta de criança desaparecida"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: alerta de segurança pública"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: alertas de exercício"</string>
 </resources>
diff --git a/res/values-mcc226-pt/strings.xml b/res/values-mcc226-pt/strings.xml
index 64de34ad9..a23f5997e 100644
--- a/res/values-mcc226-pt/strings.xml
+++ b/res/values-mcc226-pt/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Alerta de risco iminente"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Ameaças iminentes à vida ou à propriedade"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Alerta de criança desaparecida"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: alerta de criança desaparecida"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alerta: alerta presidencial"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alerta: alerta extremo"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alerta: alerta extremo"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alerta: alerta extremo"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alerta: alerta grave"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alerta: alerta de treinamento"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Ações recomendadas que podem salvar vidas ou propriedades"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Alerta de segurança pública"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Alerta silencioso"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Alertas de simulação"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Receber alerta de emergência: mensagem de simulação/treinamento"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: alerta de risco iminente"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: alerta extremo"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: alerta extremo"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: alerta extremo"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: alerta grave"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: alerta de criança desaparecida"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: alerta de segurança pública"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: alertas de simulação"</string>
 </resources>
diff --git a/res/values-mcc226-ro/strings.xml b/res/values-mcc226-ro/strings.xml
index 8fa60db3a..0d70b82b7 100644
--- a/res/values-mcc226-ro/strings.xml
+++ b/res/values-mcc226-ro/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Alertă de Risc Iminent"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Pericole cu risc iminent privind viața și bunurile"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Alertă pentru un copil dispărut"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Alertă pentru un copil dispărut"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: alertă prezidențială"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: alertă extremă"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: alertă extremă"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: alertă extremă"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: alertă gravă"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: mesaj de exercițiu"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Acțiuni recomandate care pot salva vieți sau bunuri"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Alertă pentru siguranță publică"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Alertă silențioasă"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Alerte de exercițiu"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Primește alerte de urgență: mesaj de exercițiu/simulare"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : Alertă de Risc Iminent"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : Alertă Extremă"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : Alertă Extremă"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : Alertă Extremă"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : Alertă Severă"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : Alertă dispariție copil"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : Alertă pentru siguranță publică"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : Alertă de exercițiu"</string>
 </resources>
diff --git a/res/values-mcc226-ru/strings.xml b/res/values-mcc226-ru/strings.xml
index 1c9df4999..cde58f2fd 100644
--- a/res/values-mcc226-ru/strings.xml
+++ b/res/values-mcc226-ru/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Оповещение о надвигающейся угрозе"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Надвигающиеся угрозы жизни и имуществу"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Оповещение о пропавшем ребенке"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Румыния: оповещение о пропавшем ребенке"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Румыния: президентское оповещение"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Румыния: чрезвычайная ситуация"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Румыния: чрезвычайная ситуация"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Румыния: чрезвычайная ситуация"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Румыния: серьезная угроза"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Румыния: учебная тревога"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Рекомендуемые действия, которые помогут сохранить жизни или имущество"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Оповещение об угрозе общественной безопасности"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Оповещения без звука"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Оповещения об учебных тревогах"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Получать экстренные оповещения об учебных тревогах"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"Румыния: оповещение о надвигающейся угрозе"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"Румыния: оповещение о чрезвычайной ситуации"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"Румыния: оповещение о чрезвычайной ситуации"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"Румыния: оповещение о чрезвычайной ситуации"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"Румыния: оповещение о серьезной угрозе"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"Румыния: оповещение о пропавшем ребенке"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"Румыния: угроза общественной безопасности"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"Румыния: оповещения об учебных тревогах"</string>
 </resources>
diff --git a/res/values-mcc226-si/strings.xml b/res/values-mcc226-si/strings.xml
index cc1d908c2..2ee93385b 100644
--- a/res/values-mcc226-si/strings.xml
+++ b/res/values-mcc226-si/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"ආසන්න අවදානම් ඇඟවීම"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"ජීවිත හා දේපළවලට ඇති විය හැකි ආසන්න තර්ජන"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"ළමයෙකු අතුරුදහන් වීමේ ඇඟවීම"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-ඇඟවීම: ළමයෙකු අතුරුදහන් වීමේ ඇඟවීම"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-ඇඟවීම: ජනාධිපති ඇඟවීම"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-ඇඟවීම: අතිශය ඇඟවීම"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-ඇඟවීම: අතිශය ඇඟවීම"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-ඇඟවීම: අතිශය ඇඟවීම"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-ඇඟවීම: ප්‍රචණ්ඩ ඇඟවීම"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-ඇඟවීම: ව්‍යායාම ඇඟවීම"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"ජීවිත හෝ දේපළ බේරා ගත හැකි නිර්දේශිත ක්‍රියා"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"පොදු ආරක්ෂාව පිළිබඳ ඇඟවීම"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"නිහඬ ඇඟවීම"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"ව්‍යායාම ඇඟවීම්"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"හදිසි අවස්ථා ඇඟවීම ලබා ගන්න: ව්‍යායාම/සරඹ පණිවිඩය"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ඇඟවීම: ආසන්න අවදානම් ඇඟවීම"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ඇඟවීම: අතිශය ඇඟවීම"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ඇඟවීම: අතිශය ඇඟවීම"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ඇඟවීම: අතිශය ඇඟවීම"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ඇඟවීම: ප්‍රචණ්ඩ ඇඟවීම"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ඇඟවීම: ළමයෙකු අතුරුදහන් වීමේ ඇඟවීම"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ඇඟවීම: මහජන ආරක්ෂක අනතුරු ඇඟවීම"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ඇඟවීම: අභ්‍යාස ඇඟවීම්"</string>
 </resources>
diff --git a/res/values-mcc226-sk/strings.xml b/res/values-mcc226-sk/strings.xml
index 186f17ca8..21285ee5f 100644
--- a/res/values-mcc226-sk/strings.xml
+++ b/res/values-mcc226-sk/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Upozornenie na bezprostredné nebezpečenstvo"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Bezprostredné ohrozenie života a majetku"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Upozornenie na nezvestné dieťa"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Upozornenie RO: upozornenie na nezvestné dieťa"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Upozornenie RO: prezidentské upozornenie"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Upozornenie RO: extrémne upozornenie"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Upozornenie RO: extrémne upozornenie"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Upozornenie RO: extrémne upozornenie"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Upozornenie RO: závažné upozornenie"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Upozornenie RO: cvičné upozornenie"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Odporúčané akcie, ktoré môžu zachrániť životy alebo majetok"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Upozornenie týkajúce sa verejnej bezpečnosti"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Tiché upozornenie"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Cvičné upozornenia"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Prijatá tiesňová výstraha: správa o cvičení"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : Upozornenie na bezprostredné nebezpečenstvo"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : Upozornenie na extrémnu situáciu"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : Upozornenie na extrémnu situáciu"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : Upozornenie na extrémnu situáciu"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : Závažné upozornenie"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : Upozornenie na nezvestné dieťa"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : Upozornenie týkajúce sa verejnej bezpečnosti"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : Upozornenie na cvičenie"</string>
 </resources>
diff --git a/res/values-mcc226-sl/strings.xml b/res/values-mcc226-sl/strings.xml
index 1eb4dec37..2ce0d1c78 100644
--- a/res/values-mcc226-sl/strings.xml
+++ b/res/values-mcc226-sl/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Opozorilo o neposredni nevarnosti"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Neposredne nevarnosti za življenje in premoženje"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Opozorilo o pogrešanem otroku"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Opozorilo za RO: Opozorilo o pogrešanem otroku"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Opozorilo za RO: Predsedniško opozorilo"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Opozorilo za RO: Izredno resno opozorilo"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Opozorilo za RO: Izredno resno opozorilo"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Opozorilo za RO: Izredno resno opozorilo"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Opozorilo za RO: Resno opozorilo"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Opozorilo za RO: Sporočilo za vajo"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Priporočena dejanja, ki lahko rešijo življenja ali premoženje"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Opozorilo za javno varnost"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Tihi alarm"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Opozorila za vajo"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Prejemanje nujnega opozorila: sporočilo za vajo/simulacijo"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"OPOZORILO ZA RO: Opozorilo o neposredni nevarnosti"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"OPOZORILO ZA RO: Izredno resno opozorilo"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"OPOZORILO ZA RO: Izredno resno opozorilo"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"OPOZORILO ZA RO: Izredno resno opozorilo"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"OPOZORILO ZA RO: Resno opozorilo"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"OPOZORILO ZA RO: Opozorilo o pogrešanem otroku"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"OPOZORILO ZA RO: Opozorilo za javno varnost"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"OPOZORILO ZA RO: Opozorila za vajo"</string>
 </resources>
diff --git a/res/values-mcc226-sq/strings.xml b/res/values-mcc226-sq/strings.xml
index 5b3489c52..a8d9fcc90 100644
--- a/res/values-mcc226-sq/strings.xml
+++ b/res/values-mcc226-sq/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Sinjalizim për rrezik të pashmangshëm"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Kërcënime të pashmangshme për jetën dhe pronën"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Sinjalizim për fëmijë të humbur"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Sinjalizim për fëmijë të humbur"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Alarm presidencial"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Alarm ekstrem"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Alarm ekstrem"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Alarm ekstrem"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Alarm i rëndë"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Alarm ushtrimi"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Veprime të rekomanduara që mund të shpëtojnë jetën ose pronën"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Sinjalizim i sigurisë publike"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Sinjalizim i heshtur"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Sinjalizime për ushtrime"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Merr alarmin e urgjencës: mesazhi i ushtrimit/stërvitjes"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: Sinjalizim për rrezik të pashmangshëm"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: Sinjalizim ekstrem"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: Sinjalizim ekstrem"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: Sinjalizim ekstrem"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: Sinjalizim serioz"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: Sinjalizim për fëmijë të humbur"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: Sinjalizim i sigurisë publike"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: Sinjalizime për ushtrime"</string>
 </resources>
diff --git a/res/values-mcc226-sr/strings.xml b/res/values-mcc226-sr/strings.xml
index ce03b4090..0c7ba92d7 100644
--- a/res/values-mcc226-sr/strings.xml
+++ b/res/values-mcc226-sr/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Упозорење о непосредној опасности"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Непосредне претње по живот и имовину"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Упозорење о несталом детету"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: упозорење о несталом детету"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: председничко упозорење"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: упозорење о екстремној опасности"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: упозорење о екстремној опасности"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: упозорење о екстремној опасности"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: упозорење о озбиљној опасности"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: вежба за случај упозорења"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Препоручене радње које могу да сачувају животе или имовину"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Упозорење о јавној безбедности"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Нечујно упозорење"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Упозорења о вежбама"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Примајте упозорења о хитном случају: порука о вежби"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: упозорење о непосредној опасности"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: упозорење о екстремној опасности"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: упозорење о екстремној опасности"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: упозорење о екстремној опасности"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: упозорење о озбиљној опасности"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: упозорење о несталом детету"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: упозорење о јавној безбедности"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: упозорења о вежбама"</string>
 </resources>
diff --git a/res/values-mcc226-sv/strings.xml b/res/values-mcc226-sv/strings.xml
index b4ef2f465..aa8787acd 100644
--- a/res/values-mcc226-sv/strings.xml
+++ b/res/values-mcc226-sv/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Varning om överhängande risk"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Omedelbara hot mot liv och egendom"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Varning om barn som saknas"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Varning om barn som saknas"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: varning utfärdad av presidenten"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: extrem fara"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: extrem fara"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: extrem fara"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: allvarlig fara"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: övningsmeddelande"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Rekommenderade åtgärder som kan rädda liv eller egendom"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Säkerhetsvarning till allmänheten"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Ljudlös varning"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Varningar om övningar"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Ta emot varningar om nödsituation: övnings-/testmeddelande"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT: varning om överhängande risk"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT: varning om extrem fara"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT: varning om extrem fara"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT: varning om extrem fara"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: varning om allvarlig fara"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: varning om barn som saknas"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT: säkerhetsvarning till allmänheten"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT: varningar om övningar"</string>
 </resources>
diff --git a/res/values-mcc226-sw/strings.xml b/res/values-mcc226-sw/strings.xml
index 20375d9ca..9fffc9b4f 100644
--- a/res/values-mcc226-sw/strings.xml
+++ b/res/values-mcc226-sw/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Arifa kuhusu Hatari Inayoweza Kutokea Hivi Karibuni"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Matishio ya uharibifu wa mali na upotevu wa maisha yanayoweza kutokea hivi karibuni"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Arifa kuhusu Mtoto Aliyepotea"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Arifa kuhusu Mtoto Aliyepotea"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Arifa ya RO: Arifa ya Rais"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Arifa ya RO: Arifa ya Hatari Kubwa"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Arifa ya RO: Arifa ya Hatari Kubwa"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Arifa ya RO: Arifa ya Hatari Kubwa"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Arifa ya RO: Arifa ya Hatari Kubwa"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Arifa ya RO: Arifa ya Mazoezi"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Hatua zinazopendekezwa ambazo zinaweza kuokoa maisha au mali"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Tahadhari kuhusu Usalama wa Umma"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Arifa Isiyo na Mlio"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Arifa kuhusu Mazoezi"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Pokea tahadhari ya dharura: ujumbe wa mazoezi au taratibu za wakati wa dharura"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : Tahadhari kuhusu Hatari Inayoweza Kutokea Hivi Karibuni"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : Tahadhari kuhusu Hatari Kubwa"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : Tahadhari kuhusu Hatari Kubwa"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : Tahadhari kuhusu Hatari Kubwa"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : Tahadhari kuhusu Hatari Kubwa"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-Alert: Arifa kuhusu Mtoto Aliyepotea"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : Tahadhari kuhusu Usalama wa Umma"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : Arifa kuhusu Mazoezi"</string>
 </resources>
diff --git a/res/values-mcc226-ta/strings.xml b/res/values-mcc226-ta/strings.xml
index 55cfeb24d..2e7e6682d 100644
--- a/res/values-mcc226-ta/strings.xml
+++ b/res/values-mcc226-ta/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"உடனடி அபாயத்திற்கான எச்சரிக்கை"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"உயிருக்கும் உடைமைக்கும் உடனடி அச்சுறுத்தல்கள்"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"பிள்ளை காணவில்லை என்பதற்கான எச்சரிக்கை"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-எச்சரிக்கை: பிள்ளை காணவில்லை எனும் எச்சரிக்கை"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-எச்சரிக்கை: பிரசிடெண்ட்ஷியல் எச்சரிக்கை"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-எச்சரிக்கை: தீவிரமான எச்சரிக்கை"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-எச்சரிக்கை: தீவிரமான எச்சரிக்கை"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-எச்சரிக்கை: தீவிரமான எச்சரிக்கை"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-எச்சரிக்கை: அதிதீவிர எச்சரிக்கை"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-எச்சரிக்கை: பயிற்சி எச்சரிக்கை"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"உயிர் அல்லது உடைமையைப் பாதுகாப்பதற்குப் பரிந்துரைக்கப்படும் நடவடிக்கைகள்"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"பொதுப் பாதுகாப்பு எச்சரிக்கை"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"சைலன்ட் எச்சரிக்கை"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"பயிற்சி விழிப்பூட்டல்கள்"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"அவசரகால எச்சரிக்கையைப் பெறுங்கள்: உடற்பயிற்சி/டிரில் மெசேஜ்"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-எச்சரிக்கை: உடனடி அபாயத்திற்கான எச்சரிக்கை"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-எச்சரிக்கை: தீவிரமான எச்சரிக்கை"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-எச்சரிக்கை: தீவிரமான எச்சரிக்கை"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-எச்சரிக்கை: தீவிரமான எச்சரிக்கை"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-எச்சரிக்கை: அதிதீவிர எச்சரிக்கை"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-எச்சரிக்கை: பிள்ளை காணவில்லை எனும் எச்சரிக்கை"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-எச்சரிக்கை: பொதுப் பாதுகாப்பு எச்சரிக்கை"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-எச்சரிக்கை: பயிற்சி எச்சரிக்கைகள்"</string>
 </resources>
diff --git a/res/values-mcc226-te/strings.xml b/res/values-mcc226-te/strings.xml
index 5022b6a31..f8187b6b1 100644
--- a/res/values-mcc226-te/strings.xml
+++ b/res/values-mcc226-te/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"తీవ్రమైన ప్రమాద హెచ్చరిక"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"ప్రాణాలకు, అలాగే ప్రాపర్టీకి తీవ్రమైన బెదిరింపులు"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"తప్పిపోయిన పిల్లల గురించి అలర్ట్"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-అలర్ట్: తప్పిపోయిన పిల్లల గురించి అలర్ట్"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-అలర్ట్: అధ్యక్ష అలర్ట్"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-అలర్ట్: విపరీత అలర్ట్"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-అలర్ట్: విపరీత అలర్ట్"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-అలర్ట్: విపరీత అలర్ట్"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-అలర్ట్: తీవ్ర అలర్ట్"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-అలర్ట్: అభ్యాస అలర్ట్"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"ప్రాణాలు లేదా ప్రాపర్టీలను కాపాడేందుకు సిఫార్సు చేసిన చర్యలు"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"పబ్లిక్ భద్రత అలర్ట్"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"నిశ్శబ్ద అలర్ట్"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"వ్యాయామ అలర్ట్‌లు"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"ఎమర్జెన్సీ అలర్ట్‌ను అందుకోండి: వ్యాయామ/డ్రిల్ మెసేజ్"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : తీవ్రమైన ప్రమాద అలర్ట్"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-అలర్ట్: తీవ్రమైన అలర్ట్"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-అలర్ట్: తీవ్రమైన అలర్ట్"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-అలర్ట్: తీవ్రమైన అలర్ట్"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT: తీవ్రమైన అలర్ట్"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT: తప్పిపోయిన పిల్లల గురించి అలర్ట్"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : పబ్లిక్ భత్రతా అలర్ట్"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : వ్యాయామం అలర్ట్‌లు"</string>
 </resources>
diff --git a/res/values-mcc226-th/strings.xml b/res/values-mcc226-th/strings.xml
index 462b30387..1573f463f 100644
--- a/res/values-mcc226-th/strings.xml
+++ b/res/values-mcc226-th/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"การแจ้งเตือนความเสี่ยงเกิดอันตรายร้ายแรง"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"ภัยคุกคามต่อชีวิตและทรัพย์สินที่ร้ายแรง"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"การแจ้งเตือนเด็กหาย"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"การแจ้งเตือน RO: การแจ้งเตือนเด็กหาย"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"การแจ้งเตือน RO: การแจ้งเตือนระดับสูง"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"การแจ้งเตือน RO: การแจ้งเตือนระดับสูงสุด"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"การแจ้งเตือน RO: การแจ้งเตือนระดับสูงสุด"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"การแจ้งเตือน RO: การแจ้งเตือนระดับสูงสุด"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"การแจ้งเตือน RO: การแจ้งเตือนระดับร้ายแรง"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"การแจ้งเตือน RO: การแจ้งเตือนทดสอบ"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"การดำเนินการที่แนะนำซึ่งจะช่วยรักษาชีวิตหรือทรัพย์สินได้"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"การแจ้งเตือนด้านความปลอดภัยสาธารณะ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"การแจ้งเตือนแบบเงียบ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"การแจ้งเตือนของการฝึกซ้อม"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"รับการแจ้งเตือนเหตุฉุกเฉิน: ข้อความทดสอบ/ฝึกซ้อม"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"การแจ้งเตือน RO : การแจ้งเตือนความเสี่ยงเกิดอันตรายร้ายแรง"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"การแจ้งเตือน RO: การแจ้งเตือนระดับสูงสุด"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"การแจ้งเตือน RO: การแจ้งเตือนระดับสูงสุด"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"การแจ้งเตือน RO: การแจ้งเตือนระดับสูงสุด"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"การแจ้งเตือน RO: การแจ้งเตือนระดับร้ายแรง"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"การแจ้งเตือน RO: การแจ้งเตือนเด็กหาย"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"การแจ้งเตือน RO : การแจ้งเตือนความปลอดภัยสาธารณะ"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"การแจ้งเตือน RO : การแจ้งเตือนทดสอบ"</string>
 </resources>
diff --git a/res/values-mcc226-tl/strings.xml b/res/values-mcc226-tl/strings.xml
index e363ea4bd..71c828572 100644
--- a/res/values-mcc226-tl/strings.xml
+++ b/res/values-mcc226-tl/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Alerto sa Napipintong Panganib"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Mga napipintong banta sa buhay at ari-arian"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Alerto sa Nawawalang Bata"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Alerto sa Nawawalang Bata"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Presidential na Alerto"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Extreme na Alerto"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Extreme na Alerto"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Extreme na Alerto"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Malalang Alerto"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Pagsasanay na Alerto"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Mga inirerekomendang pagkilos na makakaligtas ng mga buhay o pag-aari"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Alerto para sa Pampublikong Kaligtasan"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Silent na Alerto"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Mga Alerto para sa Pagsasanay"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Makatanggap ng alertong pang-emergency: mensahe sa pagsasanay/drill"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : Alerto sa Napipintong Panganib"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : Extreme na Alerto"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : Extreme na Alerto"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : Extreme na Alerto"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : Malalang Alerto"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : Alerto sa Nawawalang Bata"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : Alerto para sa Pampublikong Kaligtasan"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : Mga Alerto para sa Pagsasanay"</string>
 </resources>
diff --git a/res/values-mcc226-tr/strings.xml b/res/values-mcc226-tr/strings.xml
index 2569be37d..9e7e193fe 100644
--- a/res/values-mcc226-tr/strings.xml
+++ b/res/values-mcc226-tr/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Yaklaşan Risk Uyarısı"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Cana ve mala karşı yaklaşan tehditler"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Kayıp Çocuk Uyarısı"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO Uyarısı: Kayıp Çocuk Uyarısı"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO Uyarısı: Başkanlık Uyarısı"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO Uyarısı: Olağanüstü Durum Uyarısı"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO Uyarısı: Olağanüstü Durum Uyarısı"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO Uyarısı: Olağanüstü Durum Uyarısı"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO Uyarısı: Yüksek Düzey Uyarı"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO Uyarısı: Alıştırma Uyarısı"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Can ve mal kaybını önleyebilecek işlem önerileri"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Kamu Güvenliği Uyarısı"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Sessiz Uyarı"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Tatbikat Uyarıları"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Acil durum uyarısı alın: Alıştırma/tatbikat mesajı"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO UYARISI : Yaklaşan Risk Uyarısı"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO UYARISI: Olağanüstü Durum Uyarısı"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO UYARISI: Olağanüstü Durum Uyarısı"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO UYARISI: Olağanüstü Durum Uyarısı"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO UYARISI: Yüksek Düzey Uyarı"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO UYARISI: Kayıp Çocuk Uyarısı"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO UYARISI: Kamu Güvenliği Uyarısı"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO UYARISI: Tatbikat Uyarıları"</string>
 </resources>
diff --git a/res/values-mcc226-uk/strings.xml b/res/values-mcc226-uk/strings.xml
index c8fad8abc..370c1e8e1 100644
--- a/res/values-mcc226-uk/strings.xml
+++ b/res/values-mcc226-uk/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Сповіщення про пряму небезпеку"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Пряма загроза життю й майну"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Сповіщення про зниклу дитину"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: сповіщення про зниклу дитину"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: президентське сповіщення"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: сповіщення про надзвичайну ситуацію"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: сповіщення про надзвичайну ситуацію"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: сповіщення про надзвичайну ситуацію"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: сповіщення про сильну загрозу"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: тренувальне сповіщення"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Рекомендовані дії, щоб урятувати життя чи власність"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Сповіщення щодо громадської безпеки"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Беззвучне сповіщення"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Навчальні сповіщення"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Отримати екстрене сповіщення: тренувальне/симуляційне повідомлення"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : сповіщення про неминучу загрозу"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : сповіщення про надзвичайну ситуацію"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : сповіщення про надзвичайну ситуацію"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : сповіщення про надзвичайну ситуацію"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : сповіщення про сильну загрозу"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : сповіщення про зниклу дитину"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : сповіщення щодо громадської безпеки"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : навчальні сповіщення"</string>
 </resources>
diff --git a/res/values-mcc226-ur/strings.xml b/res/values-mcc226-ur/strings.xml
index 06a7e1c48..9b0a97147 100644
--- a/res/values-mcc226-ur/strings.xml
+++ b/res/values-mcc226-ur/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"ناگزیر خطرہ سے متعلق الرٹ"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"زندگی اور املاک کو ناگزیر خطرات سے متعلق الرٹ"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"گمشدہ بچے سے متعلق الرٹ"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"‏RO-الرٹ: گمشدہ بچے سے متعلق الرٹ"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"‏RO-الرٹ: صدارتی الرٹ"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"‏RO-الرٹ: انتہائی الرٹ"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"‏RO-الرٹ: انتہائی الرٹ"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"‏RO-الرٹ: انتہائی الرٹ"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"‏RO-الرٹ: شدید الرٹ"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"‏RO-الرٹ: ورزش الرٹ"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"ایسی تجویز کردہ کارروائیاں جو زندگیاں یا ملکیت بچا سکتی ہیں"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"عوامی حفاظت سے متعلق الرٹ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"خاموش الرٹ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"ورزش سے متعلق الرٹس"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"ایمرجنسی الرٹ موصول کریں: ورزش/ڈرِل پیغام"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"‏‫RO-ALERT : ناگزیر خطرہ سے متعلق الرٹ"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"‏‫RO-ALERT : انتہائی الرٹ"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"‏‫RO-ALERT : انتہائی الرٹ"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"‏‫RO-ALERT : انتہائی الرٹ"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"‏‫RO-ALERT : شدید الرٹ"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"‏‫RO-ALERT : گمشدہ بچے سے متعلق الرٹ"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"‏‫RO-ALERT : عوامی حفاظت سے متعلق الرٹ"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"‏‫RO-ALERT : ورزش سے متعلق الرٹس"</string>
 </resources>
diff --git a/res/values-mcc226-uz/strings.xml b/res/values-mcc226-uz/strings.xml
index c168d47bf..5de9da026 100644
--- a/res/values-mcc226-uz/strings.xml
+++ b/res/values-mcc226-uz/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Muqarrar xatar ogohlantiruvi"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Inson hayoti va mulkiga nisbatan muqarrar xatarlar"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Yoʻqolgan bola signali"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"RO-Alert: Yoʻqolgan bola signali"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: prezident ogohlantiruvi"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: favqulodda ogohlantiruv"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: favqulodda ogohlantiruv"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: favqulodda ogohlantiruv"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: jiddiy ogohlantiruv"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: oʻquv-mashgʻulot ogohlantiruvi"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Inson hayoti yoki mulkini asrashga oid tavsiya etiladigan amallar"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Ommaviy xavfsizlik haqida ogohlantirish"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Ovozsiz ogohlantiruv"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Oʻquv mashqi ogohlantirishlari"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Favqulodda ogohlantirish olish: oʻquv-mashgʻulot xabari"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : Muqarrar xatar ogohlantiruvi"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT : Favqulodda ogohlantiruv"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT : Favqulodda ogohlantiruv"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT : Favqulodda ogohlantiruv"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT : Jiddiy ogohlantiruv"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT : Yoʻqolgan bola haqida ogohlantirish"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : Ommaviy xavfsizlik haqida ogohlantirish"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : Oʻquv-mashgʻulot ogohlantiruvi"</string>
 </resources>
diff --git a/res/values-mcc226-vi/strings.xml b/res/values-mcc226-vi/strings.xml
index 465a1ca56..7c475223d 100644
--- a/res/values-mcc226-vi/strings.xml
+++ b/res/values-mcc226-vi/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Cảnh báo rủi ro sắp xảy ra"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Mối đe doạ sắp xảy ra đối với tính mạng và tài sản"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Cảnh báo về trẻ mất tích"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"Cảnh báo cho Romania: Cảnh báo về trẻ mất tích"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"Cảnh báo cho Romania: Cảnh báo của tổng thống"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"Cảnh báo cho Romania: Cảnh báo cực kỳ nghiêm trọng"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Cảnh báo cho Romania: Cảnh báo cực kỳ nghiêm trọng"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Cảnh báo cho Romania: Cảnh báo cực kỳ nghiêm trọng"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Cảnh báo cho Romania: Cảnh báo nghiêm trọng"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"Cảnh báo cho Romania: Cảnh báo diễn tập"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Hành động được đề xuất có thể bảo vệ tính mạng hoặc tài sản"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Cảnh báo chung về an toàn"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Cảnh báo im lặng"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Cảnh báo diễn tập"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Nhận cảnh báo khẩn cấp: thông báo tập huấn/diễn tập"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"CẢNH BÁO CHO ROMANIA: Cảnh báo rủi ro sắp xảy ra"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"CẢNH BÁO CHO ROMANIA: Cảnh báo cực kỳ nghiêm trọng"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"CẢNH BÁO CHO ROMANIA: Cảnh báo cực kỳ nghiêm trọng"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"CẢNH BÁO CHO ROMANIA: Cảnh báo cực kỳ nghiêm trọng"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"CẢNH BÁO CHO ROMANIA: Cảnh báo nghiêm trọng"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"CẢNH BÁO CHO ROMANIA: Cảnh báo trẻ mất tích"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"CẢNH BÁO CHO ROMANIA: Cảnh báo chung về an toàn"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"CẢNH BÁO CHO ROMANIA: Cảnh báo diễn tập"</string>
 </resources>
diff --git a/res/values-mcc226-zh-rCN/strings.xml b/res/values-mcc226-zh-rCN/strings.xml
index f8121d509..209a494d0 100644
--- a/res/values-mcc226-zh-rCN/strings.xml
+++ b/res/values-mcc226-zh-rCN/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"风险迫近警报"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"生命和财产即将受到威胁"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"儿童失踪警报"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"罗马尼亚警报：儿童失踪警报"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"罗马尼亚警报：国家级警报"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"罗马尼亚警报：极严重警报"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"罗马尼亚警报：极严重警报"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"罗马尼亚警报：极严重警报"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"罗马尼亚警报：严重警报"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"罗马尼亚警报：演习警报"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"可挽救生命或财产的推荐措施"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"公共安全警报"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"静音警报"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"演习警报"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"接收紧急警报：演习/模拟消息"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"罗马尼亚警报：风险迫近警报"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"罗马尼亚警报：极严重警报"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"罗马尼亚警报：极严重警报"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"罗马尼亚警报：极严重警报"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"罗马尼亚警报：严重警报"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"罗马尼亚警报：儿童失踪警报"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"罗马尼亚警报：公共安全警报"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"罗马尼亚警报：演习警报"</string>
 </resources>
diff --git a/res/values-mcc226-zh-rHK/strings.xml b/res/values-mcc226-zh-rHK/strings.xml
index 47e84fe51..00c416a60 100644
--- a/res/values-mcc226-zh-rHK/strings.xml
+++ b/res/values-mcc226-zh-rHK/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"即時危機警示"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"即時生命財產威脅"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"兒童失蹤警示"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"羅馬尼亞警示：兒童失蹤警示"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"羅馬尼亞警示：國家級警示"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"羅馬尼亞警示：極嚴重警示"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"羅馬尼亞警示：極嚴重警示"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"羅馬尼亞警示：極嚴重警示"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"羅馬尼亞警示：嚴重警示"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"羅馬尼亞警示：練習警示"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"有助挽救生命或財產的應變措施建議"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"公共安全警示"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"將警示設為靜音"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"演習警示"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"接收緊急警示：演習/訓練訊息"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"羅馬尼亞警示：即時危機警示"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"羅馬尼亞警示：極嚴重警示"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"羅馬尼亞警示：極嚴重警示"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"羅馬尼亞警示：極嚴重警示"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"羅馬尼亞警示：嚴重警示"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"羅馬尼亞警示：兒童失蹤警示"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"羅馬尼亞警示：公共安全警示"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"羅馬尼亞警示：演習警示"</string>
 </resources>
diff --git a/res/values-mcc226-zh-rTW/strings.xml b/res/values-mcc226-zh-rTW/strings.xml
index 1cb6e7107..871cc93fe 100644
--- a/res/values-mcc226-zh-rTW/strings.xml
+++ b/res/values-mcc226-zh-rTW/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"緊急危機警報"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"生命財產將立即受威脅"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"失蹤兒童警報"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"羅馬尼亞警報：失蹤兒童警報"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"羅馬尼亞警報：國家級警報"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"羅馬尼亞警報：極嚴重警報"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"羅馬尼亞警報：極嚴重警報"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"羅馬尼亞警報：極嚴重警報"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"羅馬尼亞警報：嚴重警報"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"羅馬尼亞警報：演習警報"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"可挽救生命財產的應變措施建議"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"公共安全警報"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"無聲警報"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"演習警報"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"接收緊急警報：演習/模擬訊息"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT：緊急危機警報"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-ALERT：極度緊急警報"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-ALERT：極度緊急警報"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-ALERT：極度緊急警報"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-ALERT：嚴重警報"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"RO-ALERT：失蹤兒童警報"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT：公共安全警報"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT：演習警報"</string>
 </resources>
diff --git a/res/values-mcc226-zu/strings.xml b/res/values-mcc226-zu/strings.xml
index 27714900d..6220db001 100644
--- a/res/values-mcc226-zu/strings.xml
+++ b/res/values-mcc226-zu/strings.xml
@@ -16,12 +16,20 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="enable_cmas_presidential_alerts_title" msgid="3661150741509605283">"Isexwayiso Ngengozi Eseduze"</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="8347705366713694241">"Izinsongo eziseduze zokuphila kanye nempahla"</string>
     <string name="enable_public_safety_messages_title" msgid="2475018227538267649">"Isexwayiso Sengane Elahlekile"</string>
-    <string name="public_safety_message" msgid="5242662040426167782">"I-RO-Alert: Isexwayiso Sengane Elahlekile"</string>
-    <string name="cmas_presidential_level_alert" msgid="8476571012670281437">"RO-Alert: Isexwayiso Sikamongameli"</string>
-    <string name="cmas_extreme_alert" msgid="1713701020039340032">"RO-Alert: Isexwayiso esinkulu"</string>
-    <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"RO-Alert: Isexwayiso esinkulu"</string>
-    <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"RO-Alert: Isexwayiso esinkulu"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"RO-Alert: Isexwayiso Esinamandla"</string>
-    <string name="cmas_exercise_alert" msgid="5696553249081579138">"RO-Alert: Isexwayiso se-Exercise"</string>
+    <string name="enable_public_safety_messages_summary" msgid="4419379368753674332">"Izenzo ezinconyelwe ezingasindisa izimpilo noma impahla"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="5354726577579867638">"Isexwayiso Sokuphepha Esidlangalaleni"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="8834699940573410921">"Isexwayiso Esithulile"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="2484615513998712565">"Izexwayiso Zokuzilungiselela"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="645953203648316566">"Thola isexwayiso esiphuthumayo: Umyalezo wokuzilungiselela/wokuqeqeshwa"</string>
+    <string name="cmas_presidential_level_alert" msgid="4433533803942786891">"RO-ALERT : Isexwayiso Ngengozi Eseduze"</string>
+    <string name="cmas_extreme_alert" msgid="8873984143193938989">"RO-Alert: Isexwayiso Esidlulele"</string>
+    <string name="cmas_extreme_immediate_observed_alert" msgid="6945883922054156265">"RO-Alert: Isexwayiso Esidlulele"</string>
+    <string name="cmas_extreme_immediate_likely_alert" msgid="2472409745602501961">"RO-Alert: Isexwayiso Esidlulele"</string>
+    <string name="cmas_severe_alert" msgid="2807762412380961321">"RO-Alert: Isexwayiso Esinamandla"</string>
+    <string name="public_safety_message" msgid="2382301497387374529">"I-RO-Alert: Isexwayiso Sengane Elahlekile"</string>
+    <string name="cmas_amber_alert" msgid="7019618668011011043">"RO-ALERT : Isexwayiso Sokuphepha Komphakathi"</string>
+    <string name="cmas_exercise_alert" msgid="1318544042828018186">"RO-ALERT : Izaziso Zokuzilungiselela"</string>
 </resources>
diff --git a/res/values-mcc226/config.xml b/res/values-mcc226/config.xml
index 48539c0c5..163300e40 100644
--- a/res/values-mcc226/config.xml
+++ b/res/values-mcc226/config.xml
@@ -17,29 +17,43 @@
 <resources>
     <!-- Whether to display presidential alert in the settings -->
     <bool name="show_presidential_alerts_settings">true</bool>
-    <!-- 4370 -->
+    <!-- 4370, 4383 -->
     <string-array name="cmas_presidential_alerts_channels_range_strings" translatable="false">
         <item>0x1112:rat=gsm, emergency=true, always_on=true</item>
+        <!-- additional language -->
+        <item>0x111F:rat=gsm, emergency=true, filter_language=true, always_on=true</item>
     </string-array>
-    <!-- 4371 -->
+    <!-- 4371, 4384 -->
     <string-array name="cmas_alert_extreme_channels_range_strings" translatable="false">
         <item>0x1113:rat=gsm, emergency=true</item>
+        <!-- additional language -->
+        <item>0x1120:rat=gsm, emergency=true, filter_language=true</item>
     </string-array>
-    <!-- 4375 -->
+    <!-- 4375, 4388 -->
     <string-array name="cmas_alerts_severe_range_strings" translatable="false">
-        <item>0x1117:rat=gsm, emergency=true</item>
+        <item>0x1117:rat=gsm, type=info, emergency=true</item>
+        <!-- additional language -->
+        <item>0x1124:rat=gsm, type=info, emergency=true, filter_language=true</item>
     </string-array>
-    <!-- 4379 Orange Alert for RO -->
+    <!-- 4379, 4392 Orange Alert for RO -->
     <string-array name="public_safety_messages_channels_range_strings" translatable="false">
-        <item>0x111B:rat=gsm, emergency=true</item>
+        <item>0x111B:rat=gsm, type=info, emergency=true</item>
+        <!-- additional language -->
+        <item>0x1128:rat=gsm, type=info, emergency=true, filter_language=true</item>
     </string-array>
+    <!-- 4396, 4397 public safety alert for Romania -->
     <string-array name="cmas_amber_alerts_channels_range_strings" translatable="false">
+        <item>0x112C:rat=gsm, type=mute, emergency=true</item>
+        <!-- additional language -->
+        <item>0x112D:rat=gsm, type=mute, emergency=true, filter_language=true</item>
     </string-array>
     <string-array name="required_monthly_test_range_strings" translatable="false">
     </string-array>
-    <!-- 4381 -->
+    <!-- 4381, 4394 -->
     <string-array name="exercise_alert_range_strings" translatable="false">
         <item>0x111D:rat=gsm, emergency=true</item>
+        <!-- additional language -->
+        <item>0x112A:rat=gsm, emergency=true, filter_language=true</item>
     </string-array>
     <string-array name="operator_defined_alert_range_strings" translatable="false">
     </string-array>
diff --git a/res/values-mcc226/strings.xml b/res/values-mcc226/strings.xml
index b537cb06a..0bde3ba1b 100644
--- a/res/values-mcc226/strings.xml
+++ b/res/values-mcc226/strings.xml
@@ -16,20 +16,53 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <!-- Preference title for enable presidential threat alerts checkbox. [CHAR LIMIT=40] -->
+    <!-- Required Romanian(ro) translation for this message: Alertă de Risc Iminent -->
+    <string name="enable_cmas_presidential_alerts_title">Imminent Risk Alert</string>
+    <!-- Preference summary for enable presidential threat alerts checkbox. [CHAR LIMIT=100] -->
+    <!-- Required Romanian(ro) translation for this message: Pericole cu risc iminent privind viața și bunurile -->
+    <string name="enable_cmas_presidential_alerts_summary">Imminent threats to life and property</string>
     <!-- Preference title for enable Romania orange alert messages checkbox. [CHAR LIMIT=100] -->
+    <!-- Required Romanian(ro) translation for this message: Alertă pentru un copil dispărut -->
     <string name="enable_public_safety_messages_title">Missing Child Alert</string>
-    <!-- Dialog title for all orange alert for Romania [CHAR LIMIT=50] -->
-    <string name="public_safety_message">RO-Alert: Missing Child Alert</string>
+    <!-- Preference summary for enable Romania orange alert messages checkbox. [CHAR LIMIT=100] -->
+    <!-- Required Romanian(ro) translation for this message: Acțiuni recomandate care pot salva vieți sau bunuri -->
+    <string name="enable_public_safety_messages_summary">Recommended actions that can save lives or property</string>
+    <!-- Preference title for enable Romania public safety messages checkbox. [CHAR LIMIT=50] -->
+    <!-- Required Romanian(ro) translation for this message: Alertă pentru siguranță publică -->
+    <string name="enable_cmas_amber_alerts_title">Public Safety Alert</string>
+    <!-- Preference summary for enable Romania public safety messages checkbox. [CHAR LIMIT=100] -->
+    <!-- Required Romanian(ro) translation for this message: Alertă silențioasă -->
+    <string name="enable_cmas_amber_alerts_summary">Silent Alert</string>
+    <!-- Preference title for exercise test alerts checkbox. [CHAR LIMIT=50] -->
+    <!-- Required Romanian(ro) translation for this message: Alerte de exercițiu -->
+    <string name="enable_exercise_test_alerts_title">Exercise Alerts</string>
+    <!-- Preference summary for exercise test alerts checkbox. [CHAR LIMIT=125] -->
+    <!-- Required Romanian(ro) translation for this message: Primește alerte de urgență: mesaj de exercițiu/simulare -->
+    <string name="enable_exercise_test_alerts_summary">Receive emergency alert: exercise/drill message</string>
+
     <!-- CMAS dialog title for Romania presidential level alert. [CHAR LIMIT=60] -->
-    <string name="cmas_presidential_level_alert">RO-Alert: Presidential Alert</string>
+    <!-- Required Romanian(ro) translation for this message: RO-ALERT : Alertă de Risc Iminent -->
+    <string name="cmas_presidential_level_alert">RO-ALERT : Imminent Risk Alert</string>
     <!-- CMAS dialog title for Romania extreme alert. [CHAR LIMIT=50] -->
-    <string name="cmas_extreme_alert">RO-Alert: Extreme Alert</string>
+    <!-- Required Romanian(ro) translation for this message: RO-ALERT : Alertă Extremă -->
+    <string name="cmas_extreme_alert">RO-ALERT : Extreme Alert</string>
     <!-- CMAS dialog title for Romania extreme alert with extreme severity, immediate urgency, and observed certainty. [CHAR LIMIT=50] -->
-    <string name="cmas_extreme_immediate_observed_alert">RO-Alert: Extreme Alert</string>
+    <!-- Required Romanian(ro) translation for this message: RO-ALERT : Alertă Extremă -->
+    <string name="cmas_extreme_immediate_observed_alert">RO-ALERT : Extreme Alert</string>
     <!-- CMAS dialog title for Romania extreme alert with extreme severity, immediate urgency,  and likely certainty. [CHAR LIMIT=50] -->
-    <string name="cmas_extreme_immediate_likely_alert">RO-Alert: Extreme Alert</string>
+    <!-- Required Romanian(ro) translation for this message: RO-ALERT : Alertă Extremă -->
+    <string name="cmas_extreme_immediate_likely_alert">RO-ALERT : Extreme Alert</string>
     <!-- CMAS dialog title for Romania severe alert. [CHAR LIMIT=50] -->
-    <string name="cmas_severe_alert">RO-Alert: Severe Alert</string>
+    <!-- Required Romanian(ro) translation for this message: RO-ALERT : Alertă Severă -->
+    <string name="cmas_severe_alert">RO-ALERT : Severe Alert</string>
+    <!-- Dialog title for all orange alert for Romania [CHAR LIMIT=50] -->
+    <!-- Required Romanian(ro) translation for this message: RO-ALERT : Alertă dispariție copil -->
+    <string name="public_safety_message">RO-ALERT : Missing Child Alert</string>
+    <!-- CMAS dialog title for Romania public safety messages. [CHAR LIMIT=50] -->
+    <!-- Required Romanian(ro) translation for this message: RO-ALERT : Alertă pentru siguranță publică -->
+    <string name="cmas_amber_alert">RO-ALERT : Public Safety Alert</string>
     <!-- CMAS dialog title for Romania Exercise Alert (drill/simulation alert) [CHAR LIMIT=50] -->
-    <string name="cmas_exercise_alert">RO-Alert: Exercise Alert</string>
+    <!-- Required Romanian(ro) translation for this message: RO-ALERT : Alertă de exercițiu -->
+    <string name="cmas_exercise_alert">RO-ALERT : Exercise Alerts</string>
 </resources>
\ No newline at end of file
diff --git a/res/values-mcc234-bs/strings.xml b/res/values-mcc234-bs/strings.xml
index 1aaece5f1..04c247192 100644
--- a/res/values-mcc234-bs/strings.xml
+++ b/res/values-mcc234-bs/strings.xml
@@ -30,7 +30,7 @@
     <string name="cmas_required_monthly_test" msgid="1226904101913162471">"Probno upozorenje"</string>
     <string name="cmas_exercise_alert" msgid="4540370572086918020">"Upozorenje za vježbu"</string>
     <string name="app_label" msgid="3863159788297913185">"Hitna upozorenja"</string>
-    <string name="sms_cb_settings" msgid="4187131985831792308">"Hitna upozorenja"</string>
+    <string name="sms_cb_settings" msgid="4187131985831792308">"Upozorenja na hitan slučaj"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="805446672915814777">"Primajte obavještenja o hitnim upozorenjima"</string>
     <string name="enable_alert_speech_summary" msgid="5021926525240750702">"Koristite pretvaranje teksta u govor za izgovaranje hitnih upozorenja"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="2931455154355509465">"Primajte testove sa sistema upozorenja na hitan slučaj"</string>
diff --git a/res/values-mcc234-iw/strings.xml b/res/values-mcc234-iw/strings.xml
index ef183d57e..f1bd25d29 100644
--- a/res/values-mcc234-iw/strings.xml
+++ b/res/values-mcc234-iw/strings.xml
@@ -30,7 +30,7 @@
     <string name="cmas_required_monthly_test" msgid="1226904101913162471">"התרעת בדיקה"</string>
     <string name="cmas_exercise_alert" msgid="4540370572086918020">"התרעת תרגול"</string>
     <string name="app_label" msgid="3863159788297913185">"התרעות על מצב חירום"</string>
-    <string name="sms_cb_settings" msgid="4187131985831792308">"התרעות על מצב חירום"</string>
+    <string name="sms_cb_settings" msgid="4187131985831792308">"התרעות על מקרה חירום"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="805446672915814777">"קבלת התרעות על מקרי חירום"</string>
     <string name="enable_alert_speech_summary" msgid="5021926525240750702">"‏שימוש בהמרת טקסט לדיבור (TTS) להקראה של התרעות על מקרי חירום"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="2931455154355509465">"קבלת התראות בדיקה ממערכת ההתראה על מקרה חירום"</string>
diff --git a/res/values-mcc262/config.xml b/res/values-mcc262/config.xml
index b7a01c4d5..f8737b5b4 100644
--- a/res/values-mcc262/config.xml
+++ b/res/values-mcc262/config.xml
@@ -34,9 +34,9 @@
     </string-array>
     <!-- 4396, 4397 DE/EU level 4 alert -->
     <string-array name="public_safety_messages_channels_range_strings" translatable="false">
-        <item>0x112C:rat=gsm, emergency=true, vibration=0|500|500|500|500|500|500|1000|500|1000|500|1000|500|500|500|500|500|500|500, pulsation=0xffffffff|10000</item>
+        <item>0x112C:rat=gsm, emergency=true, type=info, pulsation=0xffffffff|10000</item>
         <!-- additional language -->
-        <item>0x112D:rat=gsm, emergency=true, filter_language=true, vibration=0|500|500|500|500|500|500|1000|500|1000|500|1000|500|500|500|500|500|500|500, pulsation=0xffffffff|10000</item>
+        <item>0x112D:rat=gsm, emergency=true, type=info, filter_language=true, pulsation=0xffffffff|10000</item>
     </string-array>
 
     <!-- 4398, 4399 DE/EU test alert -->
diff --git a/res/values-mcc310-af/strings.xml b/res/values-mcc310-af/strings.xml
index f1c45a8c0..6cc6135ee 100644
--- a/res/values-mcc310-af/strings.xml
+++ b/res/values-mcc310-af/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Wys onttrekkingdialoog nadat eerste waarskuwing gewys is (behalwe presidensiële waarskuwing)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Nasionale waarskuwings"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Nasionale waarskuwingsboodskappe. Kan nie afgeskakel word nie."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignoreer Moenie Steur Nie en ander volume-instellings. Indien afgeskakel kan kritiekste waarskuwings op hardste volume lui."</string>
 </resources>
diff --git a/res/values-mcc310-am/strings.xml b/res/values-mcc310-am/strings.xml
index de60df30a..1e92bade0 100644
--- a/res/values-mcc310-am/strings.xml
+++ b/res/values-mcc310-am/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"የመጀመሪያው ማንቂያ (ከብሔራዊ ማንቂያ ሌላ) ከታየ በኋላ የመርጦ መውጫ መገናኛን አሳይ።"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"ብሔራዊ ማንቂያዎች"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"የብሔራዊ ማስጠንቀቂያ መልዕክቶች። ሊጠፋ አይችልም።"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"አትረብሽን እና ሌሎች የድምፅ ቅንብሮችን ችላ ይበሉ። ሲጠፋ በጣም ወሳኝ ማንቂያዎች በሙሉ የድምፅ መጠን ድምፅ ሊያሰሙ ይችላሉ።"</string>
 </resources>
diff --git a/res/values-mcc310-ar/strings.xml b/res/values-mcc310-ar/strings.xml
index b4140d257..e3790617e 100644
--- a/res/values-mcc310-ar/strings.xml
+++ b/res/values-mcc310-ar/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"عرض خيار الإيقاف بعد عرض أوّل تنبيه (غير التنبيه الوطني)"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"التنبيهات الوطنية"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"رسائل التحذير الوطنية، لا يمكن إيقافها"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"هذا الخيار لتجاهل ميزة \"عدم الإزعاج\" والإعدادات الأخرى لمستوى الصوت. وفي حال إيقافه، قد يستمر سماع تنبيهات الأمان بصوت عالٍ."</string>
 </resources>
diff --git a/res/values-mcc310-as/strings.xml b/res/values-mcc310-as/strings.xml
index 261cb1472..b201021e4 100644
--- a/res/values-mcc310-as/strings.xml
+++ b/res/values-mcc310-as/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"প্ৰথমটো সতৰ্কবাৰ্তা দেখুওৱাৰ পাছত এটা পৰিহাৰ কৰাৰ ডায়লগ দেখুৱাওক (ৰাষ্ট্ৰীয় স্তৰৰ সতৰ্কবাৰ্তাৰ বাহিৰে)।"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"ৰাষ্ট্ৰীয় সতৰ্কবাৰ্তা"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"ৰাষ্ট্ৰীয় সকীয়নিমূলক বাৰ্তা। অফ কৰিব নোৱাৰি।"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"অসুবিধা নিদিব আৰু অন্য ধ্বনিৰ ছেটিং উপেক্ষা কৰক অফ কৰিলে, আটাইতকৈ গুৰুত্বপূৰ্ণ সতৰ্কবাৰ্তাসমূহ তথাপিও সম্পূৰ্ণ ভলিউমত বাজিব।"</string>
 </resources>
diff --git a/res/values-mcc310-az/strings.xml b/res/values-mcc310-az/strings.xml
index c44bfac40..fba607280 100644
--- a/res/values-mcc310-az/strings.xml
+++ b/res/values-mcc310-az/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"İlk siqnaldan (Dövlət siqnalından başqa) sonra imtina dialoqunu göstərin."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Dövlət xəbərdarlıqları"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Dövlət xəbərdarlıq mesajları. Deaktiv edilə bilməz."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"\"Narahat Etməyin\" və digər səs ayarlarını nəzərə almayın. Söndürüləndə əksər kritik siqnallar ən yüksək həddə səslənə bilər."</string>
 </resources>
diff --git a/res/values-mcc310-b+sr+Latn/strings.xml b/res/values-mcc310-b+sr+Latn/strings.xml
index 7db9f765a..e91a6dbd4 100644
--- a/res/values-mcc310-b+sr+Latn/strings.xml
+++ b/res/values-mcc310-b+sr+Latn/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Prikaži dijalog za onemogućavanje posle prikaza prvog upozorenja (osim upozorenja na nivou zemlje)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Upozorenja na nivou zemlje"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Upozorenja na nivou zemlje. Ne mogu da se isključe."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignoriše Ne uznemiravaj i druga podešavanja zvuka. Kada je isključeno, važna obaveštenja mogu da se oglašavaju najvećom jačinom."</string>
 </resources>
diff --git a/res/values-mcc310-be/strings.xml b/res/values-mcc310-be/strings.xml
index 154ead8cc..8efdbde16 100644
--- a/res/values-mcc310-be/strings.xml
+++ b/res/values-mcc310-be/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Прапаноўваць выключыць абвесткі (акрамя дзяржаўных) пасля першага паказу."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Дзяржаўныя абвесткі"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Дзяржаўныя папераджальныя паведамленні. Нельга выключыць."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ігнараваць рэжым \"Не турбаваць\" і іншыя налады гучнасці. Калі функцыя выключана, самыя важныя абвесткі ўсё роўна могуць мець поўную гучнасць."</string>
 </resources>
diff --git a/res/values-mcc310-bg/strings.xml b/res/values-mcc310-bg/strings.xml
index c6aaaeebe..13b1a51cf 100644
--- a/res/values-mcc310-bg/strings.xml
+++ b/res/values-mcc310-bg/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Извеждане на диал. прозорец за отказ след показване на първия сигнал (разл. от националния сигнал)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Национални сигнали"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Съобщения за национални предупреждения. Не могат да бъдат изключени."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Игнориране на „Не безпокойте“ и указаната сила на звука. Когато е изключено, критичните сигнали пак може да са с пълна сила."</string>
 </resources>
diff --git a/res/values-mcc310-bn/strings.xml b/res/values-mcc310-bn/strings.xml
index e507032c4..f6c2d9323 100644
--- a/res/values-mcc310-bn/strings.xml
+++ b/res/values-mcc310-bn/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"প্রথম সতর্কতার পরে একটি অপ্ট-আউট ডায়ালগ দেখুন (জাতীয় স্তরে সতর্কতা ছাড়া)।"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"জাতীয় স্তরে কোনও বিপদের সতর্কবার্তা"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"জাতীয় স্তরে কোনও বিপদের সতর্কবার্তা দেখানো মেসেজ। তাই এটি বন্ধ করা যাবে না।"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"বিরক্ত করবে না &amp; অন্য ভলিউম সেটিংস এড়িয়ে যান। বন্ধ করলে অত্যন্ত গুরুত্বপূর্ণ সতর্কতা এখনও সম্পূর্ণ ভলিউমে হয়ত শুনতে পারা যাবে।"</string>
 </resources>
diff --git a/res/values-mcc310-bs/strings.xml b/res/values-mcc310-bs/strings.xml
index 62918b02c..c134339fe 100644
--- a/res/values-mcc310-bs/strings.xml
+++ b/res/values-mcc310-bs/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Prikaz dijaloškog okvira za isključivanje nakon primanja prvog upozorenja (osim nacionalnog)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Javna upozorenja"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Javne poruke upozorenja. Nije moguće isključiti."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Zanemarite funkciju Ne ometaj i druge postavke jačine zvuka. Kada je isključeno, većina kritičnih upozorenja je i dalje glasna."</string>
 </resources>
diff --git a/res/values-mcc310-ca/strings.xml b/res/values-mcc310-ca/strings.xml
index 1f8eb06d2..0c8102a9c 100644
--- a/res/values-mcc310-ca/strings.xml
+++ b/res/values-mcc310-ca/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Mostra un quadre de diàleg de desactivació després de la primera alerta (tret d\'alerta nacional)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Alertes nacionals"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Missatges d\'advertiment nacionals. No es poden desactivar."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignora No molestis i altres opcions del volum. Si està desactivat, pot ser que les alertes més crítiques sonin a tot volum."</string>
 </resources>
diff --git a/res/values-mcc310-cs/strings.xml b/res/values-mcc310-cs/strings.xml
index 2a5583c83..e33485195 100644
--- a/res/values-mcc310-cs/strings.xml
+++ b/res/values-mcc310-cs/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Po zobrazení první výstrahy (jiné než celostátní výstrahy) zobrazit dialog k odhlášení."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Celostátní upozornění"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Celostátní varování. Tuto funkci nelze vypnout."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignorovat nastavení režimu Nerušit a další nastavení hlasitosti. Nejkritičtější upozornění mohou znít naplno, i když je tato možnost vypnutá."</string>
 </resources>
diff --git a/res/values-mcc310-da/strings.xml b/res/values-mcc310-da/strings.xml
index db74ddd08..2d2cc0589 100644
--- a/res/values-mcc310-da/strings.xml
+++ b/res/values-mcc310-da/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Vis en dialogboks om fravalg efter visningen af den første advarsel (nationalt varsel er undtaget)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Nationale varsler"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Nationale advarselsmeddelelser. Kan ikke deaktiveres."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignorer Forstyr ikke og andre lydstyrkeindstillinger. Når funktionen er deaktiveret, afspilles de mest kritiske underretninger muligvis stadig ved fuld lydstyrke."</string>
 </resources>
diff --git a/res/values-mcc310-de/strings.xml b/res/values-mcc310-de/strings.xml
index b8ddd6521..63f46fd74 100644
--- a/res/values-mcc310-de/strings.xml
+++ b/res/values-mcc310-de/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Nach erster Warnung Deaktivierungsoption anzeigen (außer bei nationalen Warnungen)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Nationale Warnungen"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Nationale Warnungen. Diese Mitteilungen können nicht deaktiviert werden."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"„Bitte nicht stören“ und andere Lautstärkeeinstellungen ignorieren. Wenn deaktiviert, werden die wichtigsten Benachrichtigungen evtl. weiterhin laut wiedergegeben."</string>
 </resources>
diff --git a/res/values-mcc310-el/strings.xml b/res/values-mcc310-el/strings.xml
index 523fc7ed7..90b883f7c 100644
--- a/res/values-mcc310-el/strings.xml
+++ b/res/values-mcc310-el/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Εμφάνιση παραθύρου εξαίρεσης μετά την πρώτη ειδοποίηση (εκτός από Ειδοποίηση σε εθνικό επίπεδο)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Ειδοποιήσεις σε εθνικό επίπεδο"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Μηνύματα προειδοποίησης σε εθνικό επίπεδο. Δεν είναι δυνατή η απενεργοποίησή τους."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Παράβλεψη Μην ενοχλείτε και ρυθμίσεων έντασης ήχου. Εάν απενεργοποιηθεί, οι κρίσιμες ειδοποιήσεις ίσως είναι σε πλήρη ένταση."</string>
 </resources>
diff --git a/res/values-mcc310-en-rAU/strings.xml b/res/values-mcc310-en-rAU/strings.xml
index 10269eba3..d002ce4d4 100644
--- a/res/values-mcc310-en-rAU/strings.xml
+++ b/res/values-mcc310-en-rAU/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Show an opt-out dialogue after displaying the first alert (other than national alert)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"National alerts"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"National warning messages. Can\'t be turned off."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignore Do Not Disturb and other volume settings. When turned off, the most critical alerts may still sound at full volume."</string>
 </resources>
diff --git a/res/values-mcc310-en-rCA/strings.xml b/res/values-mcc310-en-rCA/strings.xml
index 6bf27d451..8a613b830 100644
--- a/res/values-mcc310-en-rCA/strings.xml
+++ b/res/values-mcc310-en-rCA/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Show an opt-out dialog after displaying the first alert (other than National alert)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"National alerts"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"National warning messages. Can\'t be turned off."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignore Do Not Disturb &amp; other volume settings. When turned off, the most critical alerts may still sound at full volume."</string>
 </resources>
diff --git a/res/values-mcc310-en-rGB/strings.xml b/res/values-mcc310-en-rGB/strings.xml
index 10269eba3..d002ce4d4 100644
--- a/res/values-mcc310-en-rGB/strings.xml
+++ b/res/values-mcc310-en-rGB/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Show an opt-out dialogue after displaying the first alert (other than national alert)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"National alerts"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"National warning messages. Can\'t be turned off."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignore Do Not Disturb and other volume settings. When turned off, the most critical alerts may still sound at full volume."</string>
 </resources>
diff --git a/res/values-mcc310-en-rIN/strings.xml b/res/values-mcc310-en-rIN/strings.xml
index 10269eba3..d002ce4d4 100644
--- a/res/values-mcc310-en-rIN/strings.xml
+++ b/res/values-mcc310-en-rIN/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Show an opt-out dialogue after displaying the first alert (other than national alert)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"National alerts"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"National warning messages. Can\'t be turned off."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignore Do Not Disturb and other volume settings. When turned off, the most critical alerts may still sound at full volume."</string>
 </resources>
diff --git a/res/values-mcc310-es-rUS/strings.xml b/res/values-mcc310-es-rUS/strings.xml
index 11cf51a76..d16d15a3e 100644
--- a/res/values-mcc310-es-rUS/strings.xml
+++ b/res/values-mcc310-es-rUS/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Mostrar diálogo para inhabilitar después de la primera alerta (alertas que no sean nacionales)"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Alertas nacionales"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Mensajes de advertencia nacionales. No pueden desactivarse."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignorar No interrumpir y otros parámetros de volumen. Cuando se desactiva, las alertas importantes podrían seguir sonando."</string>
 </resources>
diff --git a/res/values-mcc310-es/strings.xml b/res/values-mcc310-es/strings.xml
index c9e1ea8f1..828ae4549 100644
--- a/res/values-mcc310-es/strings.xml
+++ b/res/values-mcc310-es/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Muestra un cuadro para darse de baja tras la primera alerta (excepto si es una alerta nacional)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Alertas nacionales"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Mensajes de alerta nacional. No se pueden desactivar."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignorar No molestar y otros ajustes de volumen. Si está desactivado, las alertas importantes seguirán sonando a todo volumen."</string>
 </resources>
diff --git a/res/values-mcc310-et/strings.xml b/res/values-mcc310-et/strings.xml
index b67fdbc77..568c2545e 100644
--- a/res/values-mcc310-et/strings.xml
+++ b/res/values-mcc310-et/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Loobumise dialoogi näitamine pärast esimese hoiatuse kuvamist (v.a riiklik hoiatus)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Riiklikud hoiatused"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Riiklikud hoiatussõnumid. Ei saa välja lülitada."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Funktsiooni Mitte segada ja teisi helitugevuse seadeid eiratakse. Kui see on välja lülitatud, võivad kõige kriitilisemad hoiatused endiselt kosta täieliku helitugevusega."</string>
 </resources>
diff --git a/res/values-mcc310-eu/strings.xml b/res/values-mcc310-eu/strings.xml
index c222c268b..3d09adb99 100644
--- a/res/values-mcc310-eu/strings.xml
+++ b/res/values-mcc310-eu/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Erakutsi alertak ez jasotzea aukeratzeko leihoa lehena jaso ondoren (alerta nazionaletan izan ezik)"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Alerta nazionalak"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Abisu-mezu nazionalak. Ezin dira desaktibatu."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Egin ez ikusi ez molestatzeko moduaren eta bolumenaren bestelako ezarpenei. Desaktibatuz gero, alerta larrienak bolumen osoan entzungo dira."</string>
 </resources>
diff --git a/res/values-mcc310-fa/strings.xml b/res/values-mcc310-fa/strings.xml
index e41c33e20..92eb72dd1 100644
--- a/res/values-mcc310-fa/strings.xml
+++ b/res/values-mcc310-fa/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"نمایش کادر گفتگوی امکان انصراف پس‌از نمایش اولین هشدار (غیر از «هشدار ملی»)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"هشدارهای ملی"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"پیام‌های اخطار ملی. این هشدارها را نمی‌توانید خاموش کنید."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"نادیده گرفتن «مزاحم نشوید» و دیگر تنظیمات میزان صدا. وقتی خاموش است، شاید بحرانی‌ترین هشدارها همچنان با صدای کامل پخش شوند."</string>
 </resources>
diff --git a/res/values-mcc310-fi/strings.xml b/res/values-mcc310-fi/strings.xml
index c9a15fdae..320bc0c15 100644
--- a/res/values-mcc310-fi/strings.xml
+++ b/res/values-mcc310-fi/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Näytä kieltäytymisikkuna ensimmäisen hälytyksen (muun kuin kansallisen hälytyksen) jälkeen."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Kansalliset hälytykset"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Kansalliset varoitusviestit. Ei voi poistaa käytöstä."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ohita Älä häiritse ja vastaavat asetukset. Kun asetus on pois päältä, tärkeimmät voivat silti kuulua täydellä voimakkuudella."</string>
 </resources>
diff --git a/res/values-mcc310-fr-rCA/strings.xml b/res/values-mcc310-fr-rCA/strings.xml
index 4562b032c..d01f62661 100644
--- a/res/values-mcc310-fr-rCA/strings.xml
+++ b/res/values-mcc310-fr-rCA/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Afficher la boîte de dialogue de désactivation après la première alerte (sauf alerte nationale)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Alertes nationales"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Messages nationaux de mise en garde. Ils ne peuvent pas être désactivés."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignorez Ne pas déranger et d\'autres paramètres de volume. Après la désactivation, les alertes critiques sont toujours émises."</string>
 </resources>
diff --git a/res/values-mcc310-fr/strings.xml b/res/values-mcc310-fr/strings.xml
index c4e261983..646053382 100644
--- a/res/values-mcc310-fr/strings.xml
+++ b/res/values-mcc310-fr/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Afficher une boîte de dialogue de désactivation après la première alerte (sauf alerte nationale)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Alertes nationales"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Messages d\'avertissement nationaux. Il est impossible de les désactiver."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignorer Ne pas déranger et les autres réglages de volume. Une fois le mode désactivé, les alertes les plus importantes peuvent toujours retentir à plein volume."</string>
 </resources>
diff --git a/res/values-mcc310-gl/strings.xml b/res/values-mcc310-gl/strings.xml
index 7736751ae..d2ea8a9ae 100644
--- a/res/values-mcc310-gl/strings.xml
+++ b/res/values-mcc310-gl/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Mostra un cadro de diálogo de desactivación despois da primeira alerta (agás alerta nacional)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Alertas nacionais"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Mensaxes de advertencia nacional. Esta función non se pode desactivar."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignora o modo Non molestar e outras opcións do volume. Se o desactivas, as alertas máis críticas poden soar ao máximo volume."</string>
 </resources>
diff --git a/res/values-mcc310-gu/strings.xml b/res/values-mcc310-gu/strings.xml
index d71d3572a..e0d6a246a 100644
--- a/res/values-mcc310-gu/strings.xml
+++ b/res/values-mcc310-gu/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"પ્રથમ અલર્ટ બતાવ્યા પછી નાપસંદ કરવા માટેનો સંવાદ બતાવો (રાષ્ટ્રીય અલર્ટ સિવાય અન્ય)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"રાષ્ટ્ર સંબંધિત જોખમની અલર્ટ"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"રાષ્ટ્ર સંબંધિત જોખમની ચેતવણીના મેસેજ. બંધ કરી શકાતા નથી."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"ખલેલ પાડશો નહીં મોડ અને વૉલ્યૂમના અન્ય સેટિંગ અવગણો. બંધ કરવામાં આવે, ત્યારે સૌથી અગત્યની ગંભીર અલર્ટ હજુ પણ સંપૂર્ણ વૉલ્યૂમમાં વાગી શકે છે."</string>
 </resources>
diff --git a/res/values-mcc310-hi/strings.xml b/res/values-mcc310-hi/strings.xml
index c12a371ee..3811d8c86 100644
--- a/res/values-mcc310-hi/strings.xml
+++ b/res/values-mcc310-hi/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"पहली चेतावनी (राष्ट्रीय स्तर की चेतावनी को छोड़कर) दिखाने के बाद, ऑप्ट-आउट करने का डायलॉग दिखाएं."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"देश पर खतरा होने की चेतावनियां पाएं"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"देश पर खतरा होने की चेतावनी देने वाले मैसेज. इसे बंद नहीं किया जा सकता."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"\'परेशान न करें\' मोड और आवाज़ की अन्य सेटिंग अनदेखी करें. इनके बंद होने पर, गंभीर सूचनाएं पूरी आवाज़ में सुनाई दे सकती हैं."</string>
 </resources>
diff --git a/res/values-mcc310-hr/strings.xml b/res/values-mcc310-hr/strings.xml
index a252ea450..aa342dfe5 100644
--- a/res/values-mcc310-hr/strings.xml
+++ b/res/values-mcc310-hr/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Prikaži dijaloški okvir za isključivanje nakon prikazivanja prvog upozorenja (osim nacionalnog)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Nacionalno upozorenje"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Poruke upozorenja na nacionalnoj razini. Ne mogu se isključiti."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Zanemarivanje načina Ne uznemiravaj i drugih postavki glasnoće. Kad se isključi, najkritičnija upozorenja i dalje se mogu oglašavati punom jačinom."</string>
 </resources>
diff --git a/res/values-mcc310-hu/strings.xml b/res/values-mcc310-hu/strings.xml
index 0bd68eaf8..2e52b4abd 100644
--- a/res/values-mcc310-hu/strings.xml
+++ b/res/values-mcc310-hu/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Leiratkozási párbeszédpanel megjelenítése az első értesítés után (kivéve országos riasztás esetén)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Országos értesítések"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Országos figyelmeztető üzenetek. Nem lehet kikapcsolni."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"A „Ne zavarjanak” funkció és más hangerő-beállítások figyelmen kívül hagyása. Kikapcsolt állapotban a legfontosabb figyelmeztetések továbbra is teljes hangerővel szólhatnak."</string>
 </resources>
diff --git a/res/values-mcc310-hy/strings.xml b/res/values-mcc310-hy/strings.xml
index 5b3d0c256..23546f96c 100644
--- a/res/values-mcc310-hy/strings.xml
+++ b/res/values-mcc310-hy/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Ցուցադրել ազդարարումն անջատելու պատուհան առաջին ազդարարումից հետո (եթե այն համապետական չէ)"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Համապետական զգուշացումներ"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Համապետական նախազգուշացնող ծանուցումներ։ Հնարավոր չէ անջատել։"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Անտեսել «Չանհանգստացնել» ռեժիմի և ձայնի ուժգնության պարամետրերը։ Եթե անջատված է, գերկարևոր ծանուցումները կարող են հնչեցվել։"</string>
 </resources>
diff --git a/res/values-mcc310-in/strings.xml b/res/values-mcc310-in/strings.xml
index 9e6fcc9ac..e8d705e76 100644
--- a/res/values-mcc310-in/strings.xml
+++ b/res/values-mcc310-in/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Tampilkan dialog pilihan tidak ikut setelah peringatan pertama (selain Peringatan nasional)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Peringatan nasional"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Pesan peringatan nasional. Tidak dapat dinonaktifkan."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Abaikan fitur Jangan Ganggu &amp; setelan volume lainnya. Saat dinonaktifkan, peringatan yang paling penting mungkin masih berbunyi dengan volume penuh."</string>
 </resources>
diff --git a/res/values-mcc310-is/strings.xml b/res/values-mcc310-is/strings.xml
index a07753142..668907a65 100644
--- a/res/values-mcc310-is/strings.xml
+++ b/res/values-mcc310-is/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Sýna glugga til að afþakka viðvaranir eftir að sú fyrsta birtist (nema neyðarviðvaranir)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Almannavarnatilkynningar"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Skilaboð frá almannavörnum. Ekki er hægt að slökkva."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Hunsa „Ónáðið ekki“ og aðrar hljóðstyrksstillingar Hljóðmerki sem fylgja mikilvægum viðvörunum munu þó hugsanlega enn spilast á hæsta hljóðstyrk þrátt fyrir að slökkt sé á þessu."</string>
 </resources>
diff --git a/res/values-mcc310-it/strings.xml b/res/values-mcc310-it/strings.xml
index e91cfb759..cda1d4a84 100644
--- a/res/values-mcc310-it/strings.xml
+++ b/res/values-mcc310-it/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Mostra finestra di disattivazione dopo la prima allerta (diversa da un\'allerta nazionale)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Allerte nazionali"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Messaggi di allerta nazionale. Non possono essere disattivati."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignora Non disturbare e altre impostazioni volume. Se off, gli avvisi più critici potrebbero suonare comunque a volume pieno."</string>
 </resources>
diff --git a/res/values-mcc310-iw/strings.xml b/res/values-mcc310-iw/strings.xml
index a17d689b9..6e9503778 100644
--- a/res/values-mcc310-iw/strings.xml
+++ b/res/values-mcc310-iw/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"הצגת תיבת דו-שיח לביטול ההסכמה לאחר הצגת ההתרעה הראשונה (מלבד התרעה ברמה הלאומית)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"התרעות לאומיות"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"הודעות אזהרה לאומיות. לא ניתן להשבית אותן."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"התעלמות מהתכונה \"נא לא להפריע\" ומהגדרות אחרות של עוצמת השמע. כשההגדרה מושבתת, ההתראות הכי קריטיות עדיין מושמעות בעוצמה מלאה."</string>
 </resources>
diff --git a/res/values-mcc310-ja/strings.xml b/res/values-mcc310-ja/strings.xml
index 8cb168acf..dbcf2cc4d 100644
--- a/res/values-mcc310-ja/strings.xml
+++ b/res/values-mcc310-ja/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"警報（全国的な警報以外）を初めて表示した後に、受信停止選択ダイアログを表示します。"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"全国的な警報"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"全国的な警報メッセージです。OFF にすることはできません。"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"サイレント モードと他の音量設定を無視します。最も重要なアラートの場合は、設定にかかわらず最大音量で通知されます。"</string>
 </resources>
diff --git a/res/values-mcc310-ka/strings.xml b/res/values-mcc310-ka/strings.xml
index 90b24f15f..855bd8011 100644
--- a/res/values-mcc310-ka/strings.xml
+++ b/res/values-mcc310-ka/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"პირველი გაფრთხილების შემდეგ უარის თქმის დიალოგის ჩვენება (ეროვნული დონის გაფრთხილებათა გარდა)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"ეროვნული დონის გაფრთხილებები"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"ეროვნული დონის გამაფრთხილებელი შეტყობინებები. არ შეიძლება იყოს გამორთული."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"„არ შემაწუხოთ“ და ხმის სხვა პარამეტრების იგნორირება. გამორთვისას, შესაძლოა, სრული სიმძლავრით ჩაირთოს კრიტიკული გაფრთხილებები."</string>
 </resources>
diff --git a/res/values-mcc310-kk/strings.xml b/res/values-mcc310-kk/strings.xml
index 9d05fe144..9a085145a 100644
--- a/res/values-mcc310-kk/strings.xml
+++ b/res/values-mcc310-kk/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Алғашқы ескерту (ел бойынша ескертуден бөлек) берілген соң, бас тарту диалогтік терезесі шығады."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Мемлекеттік деңгейдегі ескертулер"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Мемлекеттік деңгейдегі ескерту хабарлары. Оларды өшіруге болмайды."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Мазаламау режимін/басқа дыбыс параметрлерін елемеу Өшірулі болса, аса маңызды хабарландырулар бәрібір де қатты шығуы мүмкін."</string>
 </resources>
diff --git a/res/values-mcc310-km/strings.xml b/res/values-mcc310-km/strings.xml
index 52de798f7..4b8c390fa 100644
--- a/res/values-mcc310-km/strings.xml
+++ b/res/values-mcc310-km/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"បង្ហាញ​ប្រអប់​សម្រាប់ការផ្តាច់ចេញ បន្ទាប់ពី​បង្ហាញ​ការជូនដំណឹង​ដំបូង (ក្រៅពីការជូនដំណឹង​ថ្នាក់ជាតិ)។"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"ការជូនដំណឹង​ថ្នាក់ជាតិ"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"សារអំពី​ការព្រមាន​ថ្នាក់ជាតិ។ មិនអាច​បិទ​បានទេ​។"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"មិនអើពើចំពោះមុខងារកុំរំខាន និងការកំណត់កម្រិតសំឡេងផ្សេងទៀត។ នៅពេលបិទ ការជូនដំណឹងសំខាន់ខ្លាំងនៅតែអាចបញ្ចេញសំឡេងនៅកម្រិតសំឡេងពេញ។"</string>
 </resources>
diff --git a/res/values-mcc310-kn/strings.xml b/res/values-mcc310-kn/strings.xml
index c37d28943..0c758aae8 100644
--- a/res/values-mcc310-kn/strings.xml
+++ b/res/values-mcc310-kn/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"ಮೊದಲ ಎಚ್ಚರಿಕೆಯನ್ನು (ರಾಷ್ಟ್ರೀಯ ಎಚ್ಚರಿಕೆ ಹೊರತುಪಡಿಸಿ) ಪ್ರದರ್ಶಿಸಿದ ಬಳಿಕ ಆಯ್ಕೆಯಿಂದ ಹೊರಗುಳಿದ ಸಂವಾದ ತೋರಿಸಿ."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"ರಾಷ್ಟ್ರೀಯ ಎಚ್ಚರಿಕೆಗಳು"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"ರಾಷ್ಟ್ರೀಯ ಎಚ್ಚರಿಕೆ ಸಂದೇಶಗಳು. ಆಫ್ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"ಅಡಚಣೆ ಮಾಡಬೇಡಿ, ಇತರೆ ವಾಲ್ಯೂಮ್ ಸೆಟ್ಟಿಂಗ್‌ಗಳನ್ನು ನಿರ್ಲಕ್ಷಿಸಿ. ಆಫ್ ಮಾಡಿದಾಗಲೂ, ಅತ್ಯಂತ ಗಂಭೀರವಾದ ಅಲರ್ಟ್‌ಗಳು ಪೂರ್ಣ ವಾಲ್ಯೂಮ್‌ನಲ್ಲಿ ಧ್ವನಿಸಬಹುದು."</string>
 </resources>
diff --git a/res/values-mcc310-ko/strings.xml b/res/values-mcc310-ko/strings.xml
index 5640f7fee..1eb671624 100644
--- a/res/values-mcc310-ko/strings.xml
+++ b/res/values-mcc310-ko/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"전국 경보가 아닌 첫 번째 경보를 표시한 후 선택 해제 대화상자를 표시합니다."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"정부 알림 문자"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"긴급 재난 문자입니다. 이 메시지는 끌 수 없습니다."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"방해 금지 모드 및 기타 볼륨 설정을 무시합니다. 사용 중지되어 있어도 가장 중요한 알림은 최대 볼륨으로 울릴 수 있습니다."</string>
 </resources>
diff --git a/res/values-mcc310-ky/strings.xml b/res/values-mcc310-ky/strings.xml
index 4c42b8a26..393fa8d0a 100644
--- a/res/values-mcc310-ky/strings.xml
+++ b/res/values-mcc310-ky/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Биринчи шашылыш билдирүү келгенден кийин дароо өчүрүп салуу сунушталат (Жалпы улуттуктан башка)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Улуттук деңгээлдеги шашылыш билдирүүлөр"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Улуттук деңгээлдеги билдирүүлөр Өчүрүүгө болбойт."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"\"Тынчымды алба\" жана үн көлөмүнүн башка параметрлери колдонулбасын. Өчүрүлсө да, маанилүү эскертүүлөр дагы деле катуу угулат."</string>
 </resources>
diff --git a/res/values-mcc310-lo/strings.xml b/res/values-mcc310-lo/strings.xml
index 5ff6c2267..08663cadc 100644
--- a/res/values-mcc310-lo/strings.xml
+++ b/res/values-mcc310-lo/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"ສະແດງໜ້າຈໍປິດຮັບຂໍ້ມູນຫຼັງຈາກການສະແດງແຈ້ງເຕືອນທຳອິດ (ນອກເໜືອໄປຈາກການເຕືອນລະດັບປະເທດ)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"ການເຕືອນລະດັບປະເທດ"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"ຂໍ້ຄວາມຄຳເຕືອນລະດັບປະເທດ. ບໍ່ສາມາດປິດໄດ້."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"ບໍ່ສົນໃຈໂໝດຫ້າມລົບກວນ ແລະ ການຕັ້ງຄ່າສຽງອື່ນໆ. ເມື່ອປິດແລ້ວ, ແຈ້ງເຕືອນວິກິດສ່ວນໃຫຍ່ອາດຍັງມີສຽງລະດັບສູງສຸດ."</string>
 </resources>
diff --git a/res/values-mcc310-lt/strings.xml b/res/values-mcc310-lt/strings.xml
index bddc3e50c..e29b3a187 100644
--- a/res/values-mcc310-lt/strings.xml
+++ b/res/values-mcc310-lt/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Rodyti atsisakymo dialogo langą pateikus pirmą įspėjimą (ne nacionalinį įspėjimą)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Nacionaliniai įspėjimai"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Nacionalinių įspėjimų pranešimai. Negalima išjungti."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignoruoti netrukd. režimą ir kitus garsumo nust. Kai išjungta, kritiniai įspėjimai vis tiek gali skambėti maksimaliu garsumu."</string>
 </resources>
diff --git a/res/values-mcc310-lv/strings.xml b/res/values-mcc310-lv/strings.xml
index 9b72add86..2db28be12 100644
--- a/res/values-mcc310-lv/strings.xml
+++ b/res/values-mcc310-lv/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Rādīt atteikšanās dialoglodziņu pēc pirmā brīdinājuma (kurš nav valsts līmeņa brīdinājums)"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Valsts līmeņa brīdinājumi"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Valsts līmeņa brīdinājuma ziņojumi. Tos nevar izslēgt."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignorēt režīmu “Netraucēt” un citus skaļuma iestatījumus. Ja tas ir izslēgts, kritiskākie brīdinājumi var tikt atskaņoti pilnā skaļumā."</string>
 </resources>
diff --git a/res/values-mcc310-mk/strings.xml b/res/values-mcc310-mk/strings.xml
index 1afa1d8d2..ceee22657 100644
--- a/res/values-mcc310-mk/strings.xml
+++ b/res/values-mcc310-mk/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Прикажи дијалог за откажување по првото предупредување (освен за „Национално предупредување“)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Национални предупредувања"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Национални пораки за опомена. Не може да се исклучат."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Игнорирајте „Не вознемирувај“ и други поставки. Кога се исклуч., најкрит. предуп. сè уште може да се пуштат со макс. јачина."</string>
 </resources>
diff --git a/res/values-mcc310-ml/strings.xml b/res/values-mcc310-ml/strings.xml
index 2ab418bb2..ba7ce94c2 100644
--- a/res/values-mcc310-ml/strings.xml
+++ b/res/values-mcc310-ml/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"ആദ്യത്തെ മുന്നറിയിപ്പിന് ശേഷം ഒരു ഒഴിവാക്കൽ ഡയലോഗ് കാണിക്കുക (ദേശീയ മുന്നറിയിപ്പ് കൂടാതെ)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"ദേശീയ മുന്നറിയിപ്പുകൾ"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"ദേശീയ മുന്നറിയിപ്പ് സന്ദേശങ്ങൾ. ഓഫാക്കാനാകില്ല."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"ശല്യപ്പെടുത്തരുത് മോഡും മറ്റ് ശബ്ദ ക്രമീകരണവും അവഗണിക്കുക. ഓഫാക്കിയാലും അതീവ ഗുരുതര മുന്നറിയിപ്പുകൾ ഫുൾ വോളിയത്തിൽ ലഭിക്കും."</string>
 </resources>
diff --git a/res/values-mcc310-mn/strings.xml b/res/values-mcc310-mn/strings.xml
index 4ef33efa6..dab7e5c95 100644
--- a/res/values-mcc310-mn/strings.xml
+++ b/res/values-mcc310-mn/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Эхний сэрэмжлүүлгийг (Үндэсний сэрэмжлүүлгээс бусад) харуулсны дараa татгалзах харилцах цонх харуул."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Үндэсний сэрэмжлүүлэг"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Үндэсний сануулгын мессеж. Унтраах боломжгүй."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Бүү саад бол онцлог, дууны түвшний бусад тохиргоог үл хэрэгс. Унтраасан үед хамгийн ноцтой сэрэмжлүүлгийг чанга дуугаргана."</string>
 </resources>
diff --git a/res/values-mcc310-mr/strings.xml b/res/values-mcc310-mr/strings.xml
index 6031c9865..36d758613 100644
--- a/res/values-mcc310-mr/strings.xml
+++ b/res/values-mcc310-mr/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"पहिली सूचना (राष्ट्रीय सूचनेव्यतिरिक्त) डिस्प्ले केल्यानंतर निवड रद्द करा डायलॉग दाखवा."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"राष्ट्रीय इशारे"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"चेतावणी देणारे राष्ट्रीय मेसेज. बंद केले जाऊ शकत नाहीत."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"व्यत्यय आणू नका व इतर व्हॉल्यूम सेटिंग्जकडे दुर्लक्ष करा. बंद केले, तरीही सर्वात गंभीर इशारे पूर्ण व्हॉल्यूममध्ये वाजू शकतात."</string>
 </resources>
diff --git a/res/values-mcc310-ms/strings.xml b/res/values-mcc310-ms/strings.xml
index cccefd786..f6ff8b159 100644
--- a/res/values-mcc310-ms/strings.xml
+++ b/res/values-mcc310-ms/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Tunjukkan dialog tarik diri selepas memaparkan makluman yang pertama (selain makluman Kebangsaan)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Makluman kebangsaan"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Mesej amaran kebangsaan. Tidak boleh dimatikan."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Abaikan Jangan Ganggu &amp; tetapan kelantangan lain. Apabila dimatikan, bunyi kebanyakan makluman genting masih pada kelantangan penuh."</string>
 </resources>
diff --git a/res/values-mcc310-my/strings.xml b/res/values-mcc310-my/strings.xml
index ecafe39a0..5ac8f57bb 100644
--- a/res/values-mcc310-my/strings.xml
+++ b/res/values-mcc310-my/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"ပထမ သတိပေးချက် (နိုင်ငံတော်အဆင့် သတိပေးချက်မှလွဲ၍) ပြပြီးနောက် ထွက်ရန်ဒိုင်ယာလော့ခ်ကို ပြပါ။"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"တစ်နိုင်ငံလုံးဆိုင်ရာ သတိပေးချက်များ"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"တစ်နိုင်ငံလုံးဆိုင်ရာ သတိပေး မက်ဆေ့ဂျ်များ။ ပိတ်၍မရပါ။"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"‘မနှောင့်ယှက်ရ’ နှင့် အခြားအသံဆက်တင်များ ပယ်ပါ။ ပိတ်ထားပါကလည်း အရေးပေါ်အဖြစ်ဆုံး သတိပေးချက်ကို အကျယ်ဆုံးအသံဖြင့် ဖွင့်မည်။"</string>
 </resources>
diff --git a/res/values-mcc310-nb/strings.xml b/res/values-mcc310-nb/strings.xml
index 79abd25ee..1edea4ccb 100644
--- a/res/values-mcc310-nb/strings.xml
+++ b/res/values-mcc310-nb/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Vis en bortvelgingsdialog etter det første varselet (gjelder ikke for nasjonale varsler)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Nasjonale varsler"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Nasjonale varselmeldinger. Kan ikke slås av."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignorer «Ikke forstyrr» og andre voluminnstillinger. Når dette er av, kan svært kritiske varsler spilles av med fullt volum."</string>
 </resources>
diff --git a/res/values-mcc310-ne/strings.xml b/res/values-mcc310-ne/strings.xml
index 15b2bc2b5..b37f5ad1f 100644
--- a/res/values-mcc310-ne/strings.xml
+++ b/res/values-mcc310-ne/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"पहिलो अलर्ट देखाएपछि बाहिरिने डायलग देखाउनुहोस् (राष्ट्रव्यापी अलर्टबाहेक)।"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"राष्ट्रव्यापी अलर्टहरू"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"राष्ट्रव्यापी चेतावनीमूलक म्यासेजहरू। अफ गर्न मिल्दैन।"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Do Not Disturb र भोल्युमसम्बन्धी अन्य सेटिङको बेवास्ता गर्नुहोस्। यो सुविधा अफ गरिएको भए पनि सबैभन्दा महत्त्वपूर्ण अलर्ट प्राप्त हुँदा पूरा भोल्युममा घण्टी बज्न सक्छ।"</string>
 </resources>
diff --git a/res/values-mcc310-nl/strings.xml b/res/values-mcc310-nl/strings.xml
index 534d0e443..a6b216b7e 100644
--- a/res/values-mcc310-nl/strings.xml
+++ b/res/values-mcc310-nl/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Een toestemmingsvenster tonen na de eerste melding (geen nationale melding)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Nationale meldingen"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Nationale waarschuwingsberichten. Kunnen niet worden uitgezet."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Negeer Niet storen en andere volume-instellingen. De meest kritieke meldingen kun je nog steeds op volledig volume krijgen."</string>
 </resources>
diff --git a/res/values-mcc310-or/strings.xml b/res/values-mcc310-or/strings.xml
index 1f6850323..39f15d438 100644
--- a/res/values-mcc310-or/strings.xml
+++ b/res/values-mcc310-or/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"ପ୍ରଥମ ଆଲର୍ଟ (ଜାତୀୟ ଆଲର୍ଟ ବ୍ୟତୀତ ଅନ୍ୟ କିଛି) ଡିସପ୍ଲେ କରିବା ପରେ ଏକ ଅପ୍ଟ-ଆଉଟ୍ ଡାଏଲଗ୍ ଦେଖାନ୍ତୁ।"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"ଜାତୀୟ ଆଲର୍ଟଗୁଡ଼ିକ"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"ଜାତୀୟ ଚେତାବନୀ ସମ୍ବନ୍ଧୀୟ ମେସେଜଗୁଡ଼ିକ। ବନ୍ଦ କରାଯାଇପାରିବ ନାହିଁ।"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"ବିରକ୍ତ କରନ୍ତୁ ନାହିଁ ଓ ଅନ୍ୟ ଭଲ୍ୟୁମ ସେଟିଂସକୁ ଅଣଦେଖା କର। ବନ୍ଦ ହେଲେ, ସବୁଠୁ ଗୁରୁତ୍ୱପୂର୍ଣ୍ଣ ଆଲର୍ଟ ପୂର୍ଣ୍ଣ ଭଲ୍ୟୁମରେ ସାଉଣ୍ଡ କରିପାରେ।"</string>
 </resources>
diff --git a/res/values-mcc310-pa/strings.xml b/res/values-mcc310-pa/strings.xml
index 9326ed209..4610219f8 100644
--- a/res/values-mcc310-pa/strings.xml
+++ b/res/values-mcc310-pa/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"ਪਹਿਲਾ ਅਲਰਟ ਦਿਖਾਉਣ ਤੋਂ ਬਾਅਦ ਹਟਣ ਦੀ ਚੋਣ ਸੰਬੰਧੀ ਇੱਕ ਵਿੰਡੋ ਦਿਖਾਓ (ਰਾਸ਼ਟਰੀ ਅਲਰਟ ਤੋਂ ਇਲਾਵਾ)।"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"ਰਾਸ਼ਟਰੀ ਅਲਰਟ"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"ਰਾਸ਼ਟਰੀ ਚਿਤਾਵਨੀ ਸੰਬੰਧੀ ਸੁਨੇਹੇ। ਇਨ੍ਹਾਂ ਨੂੰ ਬੰਦ ਨਹੀਂ ਕੀਤਾ ਜਾ ਸਕਦਾ।"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"\'ਪਰੇਸ਼ਾਨ ਨਾ ਕਰੋ\' ਅਤੇ ਹੋਰ ਅਵਾਜ਼ ਸੈਟਿੰਗਾਂ ਨੂੰ ਅਣਡਿੱਠ ਕਰੋ। ਬੰਦ ਕੀਤੇ ਜਾਣ ਤੋਂ ਬਾਅਦ ਵੀ ਸਭ ਤੋਂ ਗੰਭੀਰ ਅਲਰਟ ਪੂਰੀ ਅਵਾਜ਼ ਵਿੱਚ ਵੱਜ ਸਕਦੇ ਹਨ।"</string>
 </resources>
diff --git a/res/values-mcc310-pl/strings.xml b/res/values-mcc310-pl/strings.xml
index bbccc08a2..02a1c7970 100644
--- a/res/values-mcc310-pl/strings.xml
+++ b/res/values-mcc310-pl/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Pokaż okno rezygnacji po wyświetleniu pierwszego alertu (innego niż alert krajowy)"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Alerty krajowe"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Wiadomości z ostrzeżeniami krajowymi. Nie można ich wyłączyć."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignoruj tryb Nie przeszkadzać i ustawienia głośności. Po wyłączeniu najważniejsze alerty dalej będą miały pełną głośność."</string>
 </resources>
diff --git a/res/values-mcc310-pt-rPT/strings.xml b/res/values-mcc310-pt-rPT/strings.xml
index f93f9ab42..510d5872a 100644
--- a/res/values-mcc310-pt-rPT/strings.xml
+++ b/res/values-mcc310-pt-rPT/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Mostrar uma caixa de diálogo de recusa após apresentar o 1.º alerta (para além do Alerta nacional)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Alertas nacionais"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Mensagens de aviso nacionais. Não é possível desativá-las."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignorar Não incomodar e outras definições de volume. Quando desativado, os alertas mais críticos ainda podem soar no máximo."</string>
 </resources>
diff --git a/res/values-mcc310-pt/strings.xml b/res/values-mcc310-pt/strings.xml
index 0c3bfaf8b..49306e781 100644
--- a/res/values-mcc310-pt/strings.xml
+++ b/res/values-mcc310-pt/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Mostrar caixa de diálogo de desativação depois do primeiro alerta. Exceção: alerta nacional."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Alertas nacionais"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Mensagens de aviso nacionais. Não é possível desativá-las."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignorar Não Perturbe e outras config. de volume. Se desativado, os alertas importantes ainda poderão tocar no volume máximo."</string>
 </resources>
diff --git a/res/values-mcc310-ro/strings.xml b/res/values-mcc310-ro/strings.xml
index 2a1fc804a..ee9d073bf 100644
--- a/res/values-mcc310-ro/strings.xml
+++ b/res/values-mcc310-ro/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Afișează un dialog de renunțare după afișarea primei alerte (alta decât alerta națională)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Alerte naționale"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Mesaje de avertizare naționale. Nu pot fi dezactivate."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignoră Nu deranja și alte setări de volum. Când sunt dezactivate, alertele importante se pot declanșa totuși la volum maxim."</string>
 </resources>
diff --git a/res/values-mcc310-ru/strings.xml b/res/values-mcc310-ru/strings.xml
index 4a9cc1493..1641bc9c1 100644
--- a/res/values-mcc310-ru/strings.xml
+++ b/res/values-mcc310-ru/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Предлагать отключить после первого оповещения (кроме общенационального)"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Федеральные оповещения"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Федеральные экстренные сообщения. Эти уведомления нельзя отключить."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Игнорировать режим \"Не беспокоить\" и др. настройки. Даже если параметр отключен, критические оповещения могут звучать громко."</string>
 </resources>
diff --git a/res/values-mcc310-si/strings.xml b/res/values-mcc310-si/strings.xml
index 9ba6f9e4d..0309c6597 100644
--- a/res/values-mcc310-si/strings.xml
+++ b/res/values-mcc310-si/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"පළමු අනතුරු ඇඟවීම සංදර්ශනය කිරීමෙන් පසුව ඉවත් වීමේ සංවාදයක් (ජාතික ඇඟවීම හැර) පෙන්වන්න."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"ජාතික ඇඟවීම්"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"ජාතික අනතුරු ඇඟවීමේ පණිවිඩ. ක්‍රියාවිරහිත කිරීමට නොහැකිය."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"බාධා නොකරන්න සහ වෙනත් හඬ සැකසීම් නොසලකන්න. ක්‍රියා විරහිත කළ විට, වඩාත්ම වැදගත් ඇඟවීම් තවමත් සම්පූර්ණ පරිමාවෙන් ශබ්ද කළ හැක."</string>
 </resources>
diff --git a/res/values-mcc310-sk/strings.xml b/res/values-mcc310-sk/strings.xml
index af1f78f12..44a9e5161 100644
--- a/res/values-mcc310-sk/strings.xml
+++ b/res/values-mcc310-sk/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Zobraziť dialógové okno na odhlásenie po prvom varovaní (okrem celoštátneho varovania)"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Národné upozornenia"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Národné upozornenia. Nedajú sa vypnúť."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignorovať režim bez vyrušení a ďalšie nast. hlasitosti Keď je toto vypnuté, hlasitosť najzávažnejších upozor. môže byť max."</string>
 </resources>
diff --git a/res/values-mcc310-sl/strings.xml b/res/values-mcc310-sl/strings.xml
index 5d97023ab..d7712110f 100644
--- a/res/values-mcc310-sl/strings.xml
+++ b/res/values-mcc310-sl/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Po prikazu prvega opozorila (ki ni državno opozorilo) pokaži pogovorno okno za onemogočenje."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Nacionalna opozorila"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Nacionalna opozorilna sporočila. Teh ni mogoče izklopiti."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Prezrtje načina »Ne moti« in drugih nastavitev glasnosti. Če je to izklopljeno, se zvok najbolj kritičnih opozoril lahko še vedno predvaja s polno glasnostjo."</string>
 </resources>
diff --git a/res/values-mcc310-sq/strings.xml b/res/values-mcc310-sq/strings.xml
index 50bc122df..ad73c1a73 100644
--- a/res/values-mcc310-sq/strings.xml
+++ b/res/values-mcc310-sq/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Shfaq dialogun e tërheqjes pas shfaqjes së sinjalizimit të parë (përveç \"Sinjalizimit kombëtar\")."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Sinjalizimet kombëtare"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Mesazhet paralajmëruese kombëtare. Nuk mund të çaktivizohen."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Shpërfill \"Mos shqetëso\" dhe cilësimet e tjera të volumit. Kur është joaktiv, sinjalizimet më kritike mund të dëgjohen përsëri me volum të plotë."</string>
 </resources>
diff --git a/res/values-mcc310-sr/strings.xml b/res/values-mcc310-sr/strings.xml
index f35deb4eb..129a0e598 100644
--- a/res/values-mcc310-sr/strings.xml
+++ b/res/values-mcc310-sr/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Прикажи дијалог за онемогућавање после приказа првог упозорења (осим упозорења на нивоу земље)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Упозорења на нивоу земље"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Упозорења на нивоу земље. Не могу да се искључе."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Игнорише Не узнемиравај и друга подешавања звука. Када је искључено, важна обавештења могу да се оглашавају највећом јачином."</string>
 </resources>
diff --git a/res/values-mcc310-sv/strings.xml b/res/values-mcc310-sv/strings.xml
index b0714adb1..20596b6e2 100644
--- a/res/values-mcc310-sv/strings.xml
+++ b/res/values-mcc310-sv/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Visa en dialogruta för att välja bort detta när första varningen visas (ej nationella varningar)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Nationella varningsmeddelanden"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Nationella varningsmeddelanden. Detta kan inte stängas av."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ignorera Stör ej och andra volyminställningar. Även när detta är inaktiverat kan viktiga varningar spelas upp med full volym."</string>
 </resources>
diff --git a/res/values-mcc310-sw/strings.xml b/res/values-mcc310-sw/strings.xml
index 8a0478f8a..f7d2ffab2 100644
--- a/res/values-mcc310-sw/strings.xml
+++ b/res/values-mcc310-sw/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Onyesha kidirisha cha kujiondoa baada ya kuonyesha arifa ya kwanza (kando na Arifa ya kitaifa)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Arifa za kitaifa"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Ujumbe wa maonyo ya kitaifa. Huwezi kuuzima."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Puuza Usinisumbue na mipangilio mingine ya sauti. Ukiizima, huenda bado tahadhari kuu zaidi zikasikika kwa sauti ya juu."</string>
 </resources>
diff --git a/res/values-mcc310-ta/strings.xml b/res/values-mcc310-ta/strings.xml
index 6af4ca283..9c627d82a 100644
--- a/res/values-mcc310-ta/strings.xml
+++ b/res/values-mcc310-ta/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"முதல் விழிப்பூட்டலை (தேசிய அளவிலான எச்சரிக்கையைத் தவிர்த்து) காட்டிய பிறகு விலகல் செய்தியைக் காட்டு."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"தேசிய அளவிலான எச்சரிக்கைகள்"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"தேசிய அளவிலான எச்சரிக்கை மெசேஜ்கள். இவற்றை முடக்க முடியாது."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"தொந்தரவு செய்ய வேண்டாம் &amp; பிற ஒலியளவு அமைப்புகளைப் புறக்கணிக்கும். ஆஃப் செய்திருக்கும்போது, அதிமுக்கிய எச்சரிக்கை முழு ஒலியளவில் ஒலிக்கக்கூடும்."</string>
 </resources>
diff --git a/res/values-mcc310-te/strings.xml b/res/values-mcc310-te/strings.xml
index ab3b18f4f..93b8b1d05 100644
--- a/res/values-mcc310-te/strings.xml
+++ b/res/values-mcc310-te/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"మొదటి అలర్ట్‌ను (జాతీయ అలర్ట్ మినహా) ప్రదర్శించిన తర్వాత నిలిపివేత డైలాగ్‌ను చూపించండి."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"జాతీయ అలర్ట్‌లు"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"జాతీయ హెచ్చరిక మెసేజ్‌లు. ఆఫ్ చేయలేరు."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"డిస్టర్బ్ చేయవద్దు, ఇతర వాల్యూమ్ సెట్టింగ్‌లు తిరస్కరించండి. ఆఫ్‌లో ఉన్నా, అతి ముఖ్యమైన అలర్ట్స్ పూర్తి వాల్యూమ్‌లో రింగ్ అవ్వవచ్చు."</string>
 </resources>
diff --git a/res/values-mcc310-th/strings.xml b/res/values-mcc310-th/strings.xml
index b62fe3c9c..656e95254 100644
--- a/res/values-mcc310-th/strings.xml
+++ b/res/values-mcc310-th/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"แสดงกล่องโต้ตอบเพื่อเลือกไม่รับหลังจากแสดงการแจ้งเตือนแรก (นอกเหนือจากการแจ้งเตือนระดับประเทศ)"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"การแจ้งเตือนระดับประเทศ"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"ข้อความเตือนระดับประเทศ ปิดข้อความไม่ได้"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"ไม่สนใจโหมดห้ามรบกวนและการตั้งค่าระดับเสียงอื่นๆ เมื่อปิดอยู่ การแจ้งเตือนที่สำคัญที่สุดอาจยังคงส่งเสียงระดับดังสุดอยู่"</string>
 </resources>
diff --git a/res/values-mcc310-tl/strings.xml b/res/values-mcc310-tl/strings.xml
index 96cd8f696..f4bf1a747 100644
--- a/res/values-mcc310-tl/strings.xml
+++ b/res/values-mcc310-tl/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Magpakita ng dialog sa pag-opt out pagkatapos ipakita ang unang alerto (bukod sa Pambansang Alerto)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Mga pambansang alerto"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Mga pambansang mensahe ng babala. Hindi puwedeng i-off."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Balewalain ang Huwag Istorbohin at ibang volume settings. Kapag off, baka tumunog pa rin nang malakas ang mga critical alert."</string>
 </resources>
diff --git a/res/values-mcc310-tr/strings.xml b/res/values-mcc310-tr/strings.xml
index 28a995ad9..977bf3fb7 100644
--- a/res/values-mcc310-tr/strings.xml
+++ b/res/values-mcc310-tr/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"İlk uyarı (ulusal düzey hariç) gösterildikten sonra devre dışı bırakmayı sor."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Ulusal uyarılar"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Ulusal uyarı mesajları. Kapatılamaz."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Rahatsız Etmeyin ve diğer ses ayarları yok sayılır. Bu ayar kapalıyken de en önemli uyarılar en yüksek ses seviyesinde çalabilir."</string>
 </resources>
diff --git a/res/values-mcc310-uk/strings.xml b/res/values-mcc310-uk/strings.xml
index 5c51db597..22f6efb0c 100644
--- a/res/values-mcc310-uk/strings.xml
+++ b/res/values-mcc310-uk/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Пропонувати вимкнути після першого сповіщення (крім тих, які стосуються всієї країни)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Сповіщення на державному рівні"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Попередження на державному рівні. Їх не можна вимкнути."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ігнорувати режим \"Не турбувати\" й інші налаштування гучності. Якщо вимкнути опцію, гучність важливих сповіщень не зміниться."</string>
 </resources>
diff --git a/res/values-mcc310-ur/strings.xml b/res/values-mcc310-ur/strings.xml
index 65506b5ed..ac50ade26 100644
--- a/res/values-mcc310-ur/strings.xml
+++ b/res/values-mcc310-ur/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"پہلا الرٹ (قومی الرٹ کے علاوہ) ڈسپلے کرنے کے بعد ایک آپٹ آؤٹ ڈائیلاگ دکھائیں۔"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"قومی الرٹس"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"قومی وارننگ کے پیغامات۔ آف نہیں کیا جا سکتا۔"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"ڈسٹرب نہ کریں اور دیگر والیوم کی ترتیبات کو نظر انداز کریں۔ آف ہونے پر، انتہائی اہم الرٹس پھر بھی مکمل والیوم پر بج سکتے ہیں۔"</string>
 </resources>
diff --git a/res/values-mcc310-uz/strings.xml b/res/values-mcc310-uz/strings.xml
index 8064971b1..c8118e9ec 100644
--- a/res/values-mcc310-uz/strings.xml
+++ b/res/values-mcc310-uz/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Birinchi ogohlantirishdan keyin umummilliy ogohlantirishlarni faolsizlantirishni taklif qilish"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Federal bildirishnomalar"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Favqulodda fideral bildirishnomalar Uni faolsizlantirish imkonsiz."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Bezovta qilinmasin va boshqa tovush sozlamalarini rad etish. Faolsizlantirilganda aksariyat jiddiy signallar baribir maksimal balandlikda chalinishi mumkin."</string>
 </resources>
diff --git a/res/values-mcc310-vi/strings.xml b/res/values-mcc310-vi/strings.xml
index 87e34cf41..9eff103d4 100644
--- a/res/values-mcc310-vi/strings.xml
+++ b/res/values-mcc310-vi/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Hiển thị hộp thoại chọn không nhận sau khi hiện cảnh báo đầu tiên (trừ Cảnh báo cấp quốc gia)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Cảnh báo cấp quốc gia"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Thông báo cảnh báo cấp quốc gia. Không thể tắt."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Bỏ qua Không làm phiền và tuỳ chọn âm lượng khác. Khi tắt, cảnh báo nghiêm trọng nhất vẫn có thể phát ở mức âm lượng tối đa."</string>
 </resources>
diff --git a/res/values-mcc310-zh-rCN/strings.xml b/res/values-mcc310-zh-rCN/strings.xml
index 34cf7789f..bb674cc7e 100644
--- a/res/values-mcc310-zh-rCN/strings.xml
+++ b/res/values-mcc310-zh-rCN/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"在显示第一条警报（国家/地区级警报除外）后，显示可供用户停用 CMAS 的对话框。"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"国家级警报"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"国家级警告消息。无法关闭。"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"忽略“勿扰”模式及其他音量设置。关闭后，设备收到最严重警报时仍可能以最大音量响起。"</string>
 </resources>
diff --git a/res/values-mcc310-zh-rHK/strings.xml b/res/values-mcc310-zh-rHK/strings.xml
index e9ccb335f..9116ec444 100644
--- a/res/values-mcc310-zh-rHK/strings.xml
+++ b/res/values-mcc310-zh-rHK/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"第一次警報出現後顯示停用對話框 (國家級警報除外)。"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"國家級警示"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"國家級警示訊息。這類訊息無法關閉。"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"忽略「請勿騷擾」模式及其他音量設定。即使關閉此功能，最重要的警示可能仍會以最高音量發出。"</string>
 </resources>
diff --git a/res/values-mcc310-zh-rTW/strings.xml b/res/values-mcc310-zh-rTW/strings.xml
index 157cecd9b..7a192fca9 100644
--- a/res/values-mcc310-zh-rTW/strings.xml
+++ b/res/values-mcc310-zh-rTW/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"第一次警報出現後顯示停用對話方塊 (國家級警報除外)。"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"國家級警報"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"國家級警報訊息。這類訊息無法關閉。"</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"忽略零打擾和其他音量設定。關閉之後，裝置仍會在收到重大警示時以最大音量播放音效。"</string>
 </resources>
diff --git a/res/values-mcc310-zu/strings.xml b/res/values-mcc310-zu/strings.xml
index 2ee0cef58..b7fc9a5f6 100644
--- a/res/values-mcc310-zu/strings.xml
+++ b/res/values-mcc310-zu/strings.xml
@@ -32,4 +32,5 @@
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Bonisa ingxoxo yokukhetha ukuphuma ngemuva kokubonisa isexwayiso sokuqala (Ngaphandle Kwesexwayiso Sikazwelonke)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Izexwayiso zikazwelonke"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Imiyalezo yesexwayiso kazwe lonke. Ayikwazi ukuvalwa."</string>
+    <string name="override_dnd_summary" msgid="3839647560760294340">"Ziba okuthi Ungaphazamisi namanye amasethingi evolumu. Lapho zivaliwe, izaziso ezisemqoka kakhulu zingase ziqhubeke zikhala ngevolumu egcwele."</string>
 </resources>
diff --git a/res/values-mcc310/config.xml b/res/values-mcc310/config.xml
index c89f986fc..d6e73adaf 100644
--- a/res/values-mcc310/config.xml
+++ b/res/values-mcc310/config.xml
@@ -19,17 +19,17 @@
     <string name="emergency_alert_second_language_code" translatable="false">es</string>
     <!-- 4370, 4383 -->
     <string-array name="cmas_presidential_alerts_channels_range_strings" translatable="false">
-        <item>0x1112:rat=gsm, emergency=true, always_on=true</item>
-        <item>0x1000:rat=cdma, emergency=true, always_on=true</item>
+        <item>0x1112:rat=gsm, emergency=true, always_on=true, override_dnd=true</item>
+        <item>0x1000:rat=cdma, emergency=true, always_on=true, override_dnd=true</item>
         <!-- additional language -->
-        <item>0x111F:rat=gsm, emergency=true, filter_language=true, always_on=true</item>
+        <item>0x111F:rat=gsm, emergency=true, filter_language=true, always_on=true, override_dnd=true</item>
     </string-array>
     <!-- 4371~4372, 4384~4385 -->
     <string-array name="cmas_alert_extreme_channels_range_strings" translatable="false">
-        <item>0x1113-0x1114:rat=gsm, emergency=true</item>
-        <item>0x1001:rat=cdma, emergency=true</item>
+        <item>0x1113-0x1114:rat=gsm, emergency=true, override_dnd=true</item>
+        <item>0x1001:rat=cdma, emergency=true, override_dnd=true</item>
         <!-- additional language -->
-        <item>0x1120-0x1121:rat=gsm, emergency=true, filter_language=true</item>
+        <item>0x1120-0x1121:rat=gsm, emergency=true, filter_language=true, override_dnd=true</item>
     </string-array>
     <!-- 4373~4378, 4386~4391 -->
     <string-array name="cmas_alerts_severe_range_strings" translatable="false">
@@ -96,4 +96,6 @@
     <bool name="show_separate_operator_defined_settings">true</bool>
     <!-- whether to display a separate exercise test settings. today, most of time, exercise channels was controlled by the main test toggle. -->
     <bool name="show_separate_exercise_settings">true</bool>
+    <!-- Whether to show override dnd settings -->
+    <bool name="show_override_dnd_settings">true</bool>
 </resources>
diff --git a/res/values-mcc310/strings.xml b/res/values-mcc310/strings.xml
index 069654466..167479340 100644
--- a/res/values-mcc310/strings.xml
+++ b/res/values-mcc310/strings.xml
@@ -51,4 +51,6 @@
     <string name="enable_cmas_presidential_alerts_title">National alerts</string>
     <!-- Preference summary for enable national threat alerts checkbox. [CHAR LIMIT=100] -->
     <string name="enable_cmas_presidential_alerts_summary">National warning messages. Can\'t be turned off.</string>
+    <!-- Preference summary for overriding Do Not Disturb mode. [CHAR LIMIT=125] -->
+    <string name="override_dnd_summary">Ignore Do Not Disturb &amp; other volume settings. When turned off, the most critical alerts may still sound at full volume.</string>
 </resources>
diff --git a/res/values-mcc420-as/strings.xml b/res/values-mcc420-as/strings.xml
index c233cc47e..2566d249e 100644
--- a/res/values-mcc420-as/strings.xml
+++ b/res/values-mcc420-as/strings.xml
@@ -21,7 +21,7 @@
     <skip />
     <string name="cmas_severe_alert" msgid="1611418922477376647">"জৰুৰীকালীন সকীয়নিমূলক সতৰ্কবাৰ্তাসমূহ"</string>
     <string name="pws_other_message_identifiers" msgid="7907712751421890873">"সতৰ্কবার্তাসমূহ"</string>
-    <string name="enable_emergency_alerts_message_title" msgid="5267857032926801433">"সতৰ্কবার্তাসমূহ"</string>
+    <string name="enable_emergency_alerts_message_title" msgid="5267857032926801433">"সতৰ্কবার্তা"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="8961532453478455676">"জীৱন অথবা সম্পত্তি ৰক্ষা কৰিব পৰা চুপাৰিছ কৰা কাৰ্যসমূহ"</string>
     <string name="cmas_required_monthly_test" msgid="5733131786754331921">"পৰীক্ষণৰ বাবে ব্যৱহৃত সতৰ্কবাৰ্তা"</string>
     <string name="cmas_exercise_alert" msgid="7249058541625071454">"অনুশীলনসমূহ"</string>
diff --git a/res/values-mcc440-mnc50/config.xml b/res/values-mcc440-mnc50/config.xml
index ba237e220..48fad0b4e 100644
--- a/res/values-mcc440-mnc50/config.xml
+++ b/res/values-mcc440-mnc50/config.xml
@@ -21,6 +21,6 @@
         <!-- 0x1101 for tsunami -->
         <item>0x1101:rat=gsm, type=etws_tsunami, emergency=true</item>
         <!-- 0x1104 for other purposes -->
-        <item>0x1104:rat=gsm, type=other, emergency=true, scope=carrier</item>
+        <item>0x1104:rat=gsm, type=other, emergency=true</item>
     </string-array>
 </resources>
diff --git a/res/values-mcc450-mnc05/config.xml b/res/values-mcc450-mnc05/config.xml
deleted file mode 100644
index ed3333fb0..000000000
--- a/res/values-mcc450-mnc05/config.xml
+++ /dev/null
@@ -1,43 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2020 The Android Open Source Project
-
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-
-          http://www.apache.org/licenses/LICENSE-2.0
-
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-
-<resources>
-  <!-- 4370, 4383, 40960(0xA000 test-mode) -->
-  <!-- Emergency alert tone duration set to 1 minute for Korean users -->
-  <string-array name="cmas_presidential_alerts_channels_range_strings" translatable="false">
-    <item>0x1112:rat=gsm, emergency=true, override_dnd=true, always_on=true</item>
-    <item>0x111F:rat=gsm, emergency=true, override_dnd=true, always_on=true, filter_language=true</item>
-    <item>0xA000:rat=gsm, emergency=true, override_dnd=true, testing_mode=true</item>
-  </string-array>
-  <!-- 4371, 4384, 40961(0xA001 test mode) -->
-  <string-array name="emergency_alerts_channels_range_strings" translatable="false">
-    <item>0x1113:rat=gsm, emergency=true, override_dnd=true</item>
-    <item>0x1120:rat=gsm, emergency=true, override_dnd=true, filter_language=true</item>
-    <item>0xA001:rat=gsm, emergency=true, override_dnd=true, testing_mode=true</item>
-  </string-array>
-  <!-- 4372, 4385, 4373~4378 Class 1 reserved channels for Korea, 0xA002 ~0xA009 for test mode -->
-  <string-array name="public_safety_messages_channels_range_strings" translatable="false">
-    <item>0x1114:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true</item>
-    <item>0x1115-0x111A:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true</item>
-    <item>0x1121:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true, filter_language=true</item>
-    <item>0xA002-0xA009:rat=gsm, emergency=true, type=info, testing_mode=true, screen_on_duration=0, dismiss_on_outside_touch=true</item>
-  </string-array>
-
-  <!-- 40970~45055 biz purpose channels -->
-  <string-array name="additional_cbs_channels_strings" translatable="false">
-    <item>0xA00A-0xAFFF:rat=gsm, emergency=false, scope=carrier, exclude_from_sms_inbox=true, display=false</item>
-  </string-array>
-</resources>
diff --git a/res/values-mcc450-mnc06/config.xml b/res/values-mcc450-mnc06/config.xml
deleted file mode 100644
index ca0328c8f..000000000
--- a/res/values-mcc450-mnc06/config.xml
+++ /dev/null
@@ -1,43 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2020 The Android Open Source Project
-
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-
-          http://www.apache.org/licenses/LICENSE-2.0
-
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-
-<resources>
-  <!-- 4370, 4383, (0xA16A test-mode) -->
-  <!-- Emergency alert tone duration set to 1 minute for Korean users -->
-  <string-array name="cmas_presidential_alerts_channels_range_strings" translatable="false">
-    <item>0x1112:rat=gsm, emergency=true, override_dnd=true, always_on=true</item>
-    <item>0x111F:rat=gsm, emergency=true, override_dnd=true, always_on=true, filter_language=true</item>
-    <item>0xA16A:rat=gsm, emergency=true, override_dnd=true, testing_mode=true</item>
-  </string-array>
-  <!-- 4371, 4384, (0xA16B test mode) -->
-  <string-array name="emergency_alerts_channels_range_strings" translatable="false">
-    <item>0x1113:rat=gsm, emergency=true, override_dnd=true</item>
-    <item>0x1120:rat=gsm, emergency=true, override_dnd=true, filter_language=true</item>
-    <item>0xA16B:rat=gsm, emergency=true, override_dnd=true, testing_mode=true</item>
-  </string-array>
-  <!-- 4372, 4385, 4373~4378 Class 1 reserved channels for Korea, 0xA16A for test mode -->
-  <string-array name="public_safety_messages_channels_range_strings" translatable="false">
-    <item>0x1114:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true</item>
-    <item>0x1115-0x111A:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true</item>
-    <item>0x1121:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true, filter_language=true</item>
-    <item>0xA16C:rat=gsm, emergency=true, type=info, testing_mode=true, screen_on_duration=0, dismiss_on_outside_touch=true</item>
-  </string-array>
-  <!-- 40990~45055 biz purpose channels -->
-  <string-array name="additional_cbs_channels_strings" translatable="false">
-    <item>0xA000-0xA169:rat=gsm, emergency=false, scope=carrier, exclude_from_sms_inbox=true, display=false</item>
-    <item>0xA16D-0xAFFF:rat=gsm, emergency=false, scope=carrier, exclude_from_sms_inbox=true, display=false</item>
-  </string-array>
-</resources>
diff --git a/res/values-mcc450/config.xml b/res/values-mcc450/config.xml
index bf20b91f0..100f1a1c4 100644
--- a/res/values-mcc450/config.xml
+++ b/res/values-mcc450/config.xml
@@ -23,32 +23,41 @@
     <!-- KR want to hide pop-up dialog(full-screen message) but shown from history menu, sms inbox and foreground notification-->
     <bool name="show_public_safety_full_screen_settings">true</bool>
 
-    <!-- 4370, 4383 -->
+    <!-- 4370, 4383, 40960, 40970 -->
     <!-- Emergecny alert tone duration set to 1 minute for Korean users -->
     <string-array name="cmas_presidential_alerts_channels_range_strings" translatable="false">
         <item>0x1112:rat=gsm, emergency=true, always_on=true, override_dnd=true</item>
         <item>0x111F:rat=gsm, emergency=true, always_on=true, override_dnd=true, filter_language=true</item>
+        <item>0xA000:rat=gsm, emergency=true, override_dnd=true, testing_mode=true</item>
+        <item>0xA00A:rat=gsm, emergency=true, override_dnd=true, testing_mode=true, filter_language=true</item>
     </string-array>
-    <!-- 4371, 4384 -->
+    <!-- 4371, 4384, 40961, 40971 -->
     <string-array name="emergency_alerts_channels_range_strings" translatable="false">
         <item>0x1113:rat=gsm, emergency=true, override_dnd=true</item>
         <item>0x1120:rat=gsm, emergency=true, override_dnd=true, filter_language=true</item>
+        <item>0xA001:rat=gsm, emergency=true, override_dnd=true, testing_mode=true</item>
+        <item>0xA00B:rat=gsm, emergency=true, override_dnd=true, testing_mode=true, filter_language=true</item>
     </string-array>
-    <!-- 4372, 4373~4378, 4385 Class 1 reserved channels for Korea -->
+    <!-- 4372, 4373~4378, 4385, 40962, 40972 Class 1 reserved channels for Korea -->
     <string-array name="public_safety_messages_channels_range_strings" translatable="false">
         <item>0x1114:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true</item>
         <item>0x1115-0x111A:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true</item>
         <item>0x1121:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true, filter_language=true</item>
+        <item>0xA002:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true, testing_mode=true</item>
+        <item>0xA00C:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true, testing_mode=true, filter_language=true</item>
     </string-array>
-    <!-- 4379, 4392 -->
+    <!-- 4379, 4392, 40969, 40979 -->
     <string-array name="cmas_amber_alerts_channels_range_strings" translatable="false">
         <item>0x111B:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true</item>
-        <!-- additional language -->
         <item>0x1128:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true, filter_language=true</item>
+        <item>0xA009:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true, testing_mode=true</item>
+        <item>0xA013:rat=gsm, emergency=true, type=info, screen_on_duration=0, dismiss_on_outside_touch=true, testing_mode=true, filter_language=true</item>
     </string-array>
-    <!-- 40960~45055 biz purpose channels -->
+    <!-- 40963~40968, 40973~40978, 40980~45055 biz purpose channels -->
     <string-array name="additional_cbs_channels_strings" translatable="false">
-        <item>0xA000-0xAFFF:rat=gsm, emergency=false, scope=carrier, exclude_from_sms_inbox=true, display=false</item>
+        <item>0xA003-0xA008:rat=gsm, emergency=false, scope=carrier, exclude_from_sms_inbox=true, display=false</item>
+        <item>0xA00D-0xA012:rat=gsm, emergency=false, scope=carrier, exclude_from_sms_inbox=true, display=false</item>
+        <item>0xA014-0xAFFF:rat=gsm, emergency=false, scope=carrier, exclude_from_sms_inbox=true, display=false</item>
     </string-array>
     <!-- Channels to receive geo-fencing trigger messages -->
     <string-array name="geo_fencing_trigger_messages_range_strings" translatable="false">
diff --git a/res/values-mcc520-af/strings.xml b/res/values-mcc520-af/strings.xml
new file mode 100644
index 000000000..67fb2dafb
--- /dev/null
+++ b/res/values-mcc520-af/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Nasionale waarskuwing"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Uiterste waarskuwing"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Inligtingwaarskuwing"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER-veiligheidsberig"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Toetswaarskuwing"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Uiterste waarskuwing"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Inligtingwaarskuwing"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER-veiligheidsberig"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Toetswaarskuwing"</string>
+</resources>
diff --git a/res/values-mcc520-am/strings.xml b/res/values-mcc520-am/strings.xml
new file mode 100644
index 000000000..a3f3306dd
--- /dev/null
+++ b/res/values-mcc520-am/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"ብሔራዊ ማንቂያ"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"እጅግ ከባድ ማንቂያ"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"የመረጃ ማንቂያ"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"የልጅ ስርቆት ማንቂያ"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"ማንቂያን ፈትሽ"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"እጅግ ከባድ ማንቂያ"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"የመረጃ ማንቂያ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"የልጅ ስርቆት ማንቂያ"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"ማንቂያን ፈትሽ"</string>
+</resources>
diff --git a/res/values-mcc520-ar/strings.xml b/res/values-mcc520-ar/strings.xml
new file mode 100644
index 000000000..7bcf8ea2e
--- /dev/null
+++ b/res/values-mcc520-ar/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"تنبيه وطني"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"تنبيه حالة طوارئ قصوى"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"تنبيه للمعلومات"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"إنذار آمبر"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"تنبيه تجريبي"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"تنبيه حالة طوارئ قصوى"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"تنبيه للمعلومات"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"إنذار آمبر"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"تنبيه تجريبي"</string>
+</resources>
diff --git a/res/values-mcc520-as/strings.xml b/res/values-mcc520-as/strings.xml
new file mode 100644
index 000000000..c2f2ccdc0
--- /dev/null
+++ b/res/values-mcc520-as/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"ৰাষ্ট্ৰীয় স্তৰৰ সতৰ্কবাৰ্তা"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"চৰম সতৰ্কবাৰ্তা"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"তথ্যৰ সতৰ্কবাৰ্তা"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"এম্বাৰ সতৰ্কবাৰ্তা"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"পৰীক্ষামূলক সতৰ্কবাৰ্তা"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"চৰম সতৰ্কবাৰ্তা"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"তথ্যৰ সতৰ্কবাৰ্তা"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"এম্বাৰ সতৰ্কবাৰ্তা"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"পৰীক্ষামূলক সতৰ্কবাৰ্তা"</string>
+</resources>
diff --git a/res/values-mcc520-az/strings.xml b/res/values-mcc520-az/strings.xml
new file mode 100644
index 000000000..2a92ed37c
--- /dev/null
+++ b/res/values-mcc520-az/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Dövlət siqnalı"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Ekstremal hal siqnalı"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Məlumatlandırıcı siqnal"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Uşaq oğurluğu siqnalı"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Test siqnalı"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Ekstremal hal siqnalı"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Məlumatlandırıcı siqnal"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Uşaq oğurluğu siqnalı"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Test siqnalı"</string>
+</resources>
diff --git a/res/values-mcc520-b+sr+Latn/strings.xml b/res/values-mcc520-b+sr+Latn/strings.xml
new file mode 100644
index 000000000..07f2b67d4
--- /dev/null
+++ b/res/values-mcc520-b+sr+Latn/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Upozorenje na nivou zemlje"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Obaveštenje o ekstremnoj opasnosti"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informativno upozorenje"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Amber upozorenje"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Probno upozorenje"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Obaveštenje o ekstremnoj opasnosti"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informativno upozorenje"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Amber upozorenje"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Probno upozorenje"</string>
+</resources>
diff --git a/res/values-mcc520-be/strings.xml b/res/values-mcc520-be/strings.xml
new file mode 100644
index 000000000..57ea3897e
--- /dev/null
+++ b/res/values-mcc520-be/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Дзяржаўная абвестка"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Экстранная абвестка"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Інфармацыйная абвестка"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Абвестка AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Тэставая абвестка"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Экстранная абвестка"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Інфармацыйная абвестка"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Абвестка AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Тэставая абвестка"</string>
+</resources>
diff --git a/res/values-mcc520-bg/strings.xml b/res/values-mcc520-bg/strings.xml
new file mode 100644
index 000000000..ba9468057
--- /dev/null
+++ b/res/values-mcc520-bg/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Национален сигнал"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Сигнал за извънредна заплаха"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Информационен сигнал"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Сигнал за изчезнало дете"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Тестови сигнал"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Сигнал за извънредна заплаха"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Информационен сигнал"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Сигнал за изчезнало дете"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Тестови сигнал"</string>
+</resources>
diff --git a/res/values-mcc520-bn/strings.xml b/res/values-mcc520-bn/strings.xml
new file mode 100644
index 000000000..a3a9f8ddc
--- /dev/null
+++ b/res/values-mcc520-bn/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"জাতীয় স্তরে সতর্কতা"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"চরম সতর্কতা"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"তথ্যমূলক সতর্কতা"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER সতর্কতা"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"পরীক্ষামূলকভাবে জারি সতর্কতা"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"চরম সতর্কতা"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"তথ্যমূলক সতর্কতা"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER সতর্কতা"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"পরীক্ষামূলকভাবে জারি সতর্কতা"</string>
+</resources>
diff --git a/res/values-mcc520-bs/strings.xml b/res/values-mcc520-bs/strings.xml
new file mode 100644
index 000000000..d16f4d5ae
--- /dev/null
+++ b/res/values-mcc520-bs/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Nacionalno upozorenje"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Izuzetno hitno upozorenje"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informativno upozorenje"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER upozorenje"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Testno upozorenje"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Izuzetno hitno upozorenje"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informativno upozorenje"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER upozorenje"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Testno upozorenje"</string>
+</resources>
diff --git a/res/values-mcc520-ca/strings.xml b/res/values-mcc520-ca/strings.xml
new file mode 100644
index 000000000..8f40cf0d9
--- /dev/null
+++ b/res/values-mcc520-ca/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Alerta nacional"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Alerta extrema"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Alerta informativa"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Alerta AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Alerta de prova"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Alerta extrema"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Alerta informativa"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Alerta AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Alerta de prova"</string>
+</resources>
diff --git a/res/values-mcc520-cs/strings.xml b/res/values-mcc520-cs/strings.xml
new file mode 100644
index 000000000..5da884318
--- /dev/null
+++ b/res/values-mcc520-cs/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Celostátní upozornění"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Extrémní výstraha"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informační upozornění"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Varování AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Testovací výstraha"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Extrémní výstraha"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informační upozornění"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Varování AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Testovací výstraha"</string>
+</resources>
diff --git a/res/values-mcc520-da/strings.xml b/res/values-mcc520-da/strings.xml
new file mode 100644
index 000000000..92f3b1b0d
--- /dev/null
+++ b/res/values-mcc520-da/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Nationalt varsel"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Alarm ved ekstrem fare"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informationsunderretning"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Underretning om barnebortførelse"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Testalarm"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Alarm ved ekstrem fare"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informationsunderretning"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Underretning om barnebortførelse"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Testalarm"</string>
+</resources>
diff --git a/res/values-mcc520-de/strings.xml b/res/values-mcc520-de/strings.xml
new file mode 100644
index 000000000..efb678e29
--- /dev/null
+++ b/res/values-mcc520-de/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Nationale Warnung"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Warnung der Kategorie „Extrem“"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informative Benachrichtigung"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER Alert"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Testwarnung"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Warnung der Kategorie „Extrem“"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informative Benachrichtigung"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER Alert"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Testwarnung"</string>
+</resources>
diff --git a/res/values-mcc520-el/strings.xml b/res/values-mcc520-el/strings.xml
new file mode 100644
index 000000000..992366db4
--- /dev/null
+++ b/res/values-mcc520-el/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Ειδοποίηση σε εθνικό επίπεδο"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Ειδοποίηση ακραίας κατάστασης"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Ενημερωτική ειδοποίηση"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Ειδοποίηση AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Δοκιμαστική ειδοποίηση"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Ειδοποίηση ακραίας κατάστασης"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Ενημερωτική ειδοποίηση"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Ειδοποίηση AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Δοκιμαστική ειδοποίηση"</string>
+</resources>
diff --git a/res/values-mcc520-en-rAU/strings.xml b/res/values-mcc520-en-rAU/strings.xml
new file mode 100644
index 000000000..21a61bb4c
--- /dev/null
+++ b/res/values-mcc520-en-rAU/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"National alert"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Extreme alert"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informational alert"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Amber alert"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Test alert"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Extreme alert"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informational alert"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Amber alert"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Test alert"</string>
+</resources>
diff --git a/res/values-mcc520-en-rCA/strings.xml b/res/values-mcc520-en-rCA/strings.xml
new file mode 100644
index 000000000..74b6f0190
--- /dev/null
+++ b/res/values-mcc520-en-rCA/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"National Alert"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Extreme Alert"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informational Alert"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Amber Alert"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Test Alert"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Extreme Alert"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informational Alert"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Amber Alert"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Test Alert"</string>
+</resources>
diff --git a/res/values-mcc520-en-rGB/strings.xml b/res/values-mcc520-en-rGB/strings.xml
new file mode 100644
index 000000000..21a61bb4c
--- /dev/null
+++ b/res/values-mcc520-en-rGB/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"National alert"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Extreme alert"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informational alert"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Amber alert"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Test alert"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Extreme alert"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informational alert"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Amber alert"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Test alert"</string>
+</resources>
diff --git a/res/values-mcc520-en-rIN/strings.xml b/res/values-mcc520-en-rIN/strings.xml
new file mode 100644
index 000000000..21a61bb4c
--- /dev/null
+++ b/res/values-mcc520-en-rIN/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"National alert"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Extreme alert"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informational alert"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Amber alert"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Test alert"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Extreme alert"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informational alert"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Amber alert"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Test alert"</string>
+</resources>
diff --git a/res/values-mcc520-es-rUS/strings.xml b/res/values-mcc520-es-rUS/strings.xml
new file mode 100644
index 000000000..801d95058
--- /dev/null
+++ b/res/values-mcc520-es-rUS/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Alerta nacional"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Alerta extrema"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Alerta informativa"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Alerta AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Alerta de prueba"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Alerta extrema"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Alerta informativa"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Alerta AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Alerta de prueba"</string>
+</resources>
diff --git a/res/values-mcc520-es/strings.xml b/res/values-mcc520-es/strings.xml
new file mode 100644
index 000000000..801d95058
--- /dev/null
+++ b/res/values-mcc520-es/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Alerta nacional"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Alerta extrema"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Alerta informativa"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Alerta AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Alerta de prueba"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Alerta extrema"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Alerta informativa"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Alerta AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Alerta de prueba"</string>
+</resources>
diff --git a/res/values-mcc520-et/strings.xml b/res/values-mcc520-et/strings.xml
new file mode 100644
index 000000000..99c8c8457
--- /dev/null
+++ b/res/values-mcc520-et/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Riiklik hoiatus"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Äärmusliku olukorra hoiatus"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Teavitus"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER-märguanne"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Testhoiatus"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Äärmusliku olukorra hoiatus"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Teavitus"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER-märguanne"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Testhoiatus"</string>
+</resources>
diff --git a/res/values-mcc520-eu/strings.xml b/res/values-mcc520-eu/strings.xml
new file mode 100644
index 000000000..e8d417780
--- /dev/null
+++ b/res/values-mcc520-eu/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Alerta nazionala"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Muturreko alerta"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informatzeko alerta"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Alerta anbara"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Probako alerta"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Muturreko alerta"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informatzeko alerta"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Alerta anbara"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Probako alerta"</string>
+</resources>
diff --git a/res/values-mcc520-fa/strings.xml b/res/values-mcc520-fa/strings.xml
new file mode 100644
index 000000000..a8c470d00
--- /dev/null
+++ b/res/values-mcc520-fa/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"هشدار ملی"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"هشدار شدید"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"هشدار اطلاعاتی"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"هشدار امبر"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"هشدار آزمایشی"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"هشدار شدید"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"هشدار اطلاعاتی"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"هشدار امبر"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"هشدار آزمایشی"</string>
+</resources>
diff --git a/res/values-mcc520-fi/strings.xml b/res/values-mcc520-fi/strings.xml
new file mode 100644
index 000000000..1c1b52363
--- /dev/null
+++ b/res/values-mcc520-fi/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Kansallinen hälytys"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Erittäin vakava hälytys"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Yleistä turvallisuutta koskeva ilmoitus"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER-hälytys"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Testihälytys"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Erittäin vakava hälytys"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Yleistä turvallisuutta koskeva ilmoitus"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER-hälytys"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Testihälytys"</string>
+</resources>
diff --git a/res/values-mcc520-fr-rCA/strings.xml b/res/values-mcc520-fr-rCA/strings.xml
new file mode 100644
index 000000000..96b5c48d0
--- /dev/null
+++ b/res/values-mcc520-fr-rCA/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Alerte nationale"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Alerte extrême"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Alerte informative"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Alerte AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Alerte test"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Alerte extrême"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Alerte informative"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Alerte AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Alerte test"</string>
+</resources>
diff --git a/res/values-mcc520-fr/strings.xml b/res/values-mcc520-fr/strings.xml
new file mode 100644
index 000000000..e93cda068
--- /dev/null
+++ b/res/values-mcc520-fr/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Alerte nationale"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Alerte critique"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Alerte d\'information"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Alerte enlèvement"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Alerte de test"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Alerte critique"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Alerte d\'information"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Alerte enlèvement"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Alerte de test"</string>
+</resources>
diff --git a/res/values-mcc520-gl/strings.xml b/res/values-mcc520-gl/strings.xml
new file mode 100644
index 000000000..1839fd659
--- /dev/null
+++ b/res/values-mcc520-gl/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Alerta nacional"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Alerta extrema"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Alerta informativa"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Alerta AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Alerta de proba"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Alerta extrema"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Alerta informativa"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Alerta AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Alerta de proba"</string>
+</resources>
diff --git a/res/values-mcc520-gu/strings.xml b/res/values-mcc520-gu/strings.xml
new file mode 100644
index 000000000..60bbc8cd4
--- /dev/null
+++ b/res/values-mcc520-gu/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"રાષ્ટ્રીય અલર્ટ"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"અત્યંત ગંભીર અલર્ટ"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"માહિતી માટેનું અલર્ટ"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER અલર્ટ"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"પરીક્ષણ માટેનું અલર્ટ"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"અત્યંત ગંભીર અલર્ટ"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"માહિતી માટેનું અલર્ટ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER અલર્ટ"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"પરીક્ષણ માટેનું અલર્ટ"</string>
+</resources>
diff --git a/res/values-mcc520-hi/strings.xml b/res/values-mcc520-hi/strings.xml
new file mode 100644
index 000000000..81c0e9022
--- /dev/null
+++ b/res/values-mcc520-hi/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"राष्ट्रीय स्तर पर मिली चेतावनी"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"बेहद गंभीर स्थिति से जुड़ी चेतावनी"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"जानकारी देने वाली चेतावनी"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"ऐंबर अलर्ट (अगवा बच्चों से जुड़ी जानकारी)"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"हर महीने होने वाली जांच से जुड़ी चेतावनी"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"बेहद गंभीर स्थिति से जुड़ी चेतावनी"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"जानकारी देने वाली चेतावनी"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"ऐंबर अलर्ट (अगवा बच्चों से जुड़ी जानकारी)"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"हर महीने होने वाली जांच से जुड़ी चेतावनी"</string>
+</resources>
diff --git a/res/values-mcc520-hr/strings.xml b/res/values-mcc520-hr/strings.xml
new file mode 100644
index 000000000..9831bb41c
--- /dev/null
+++ b/res/values-mcc520-hr/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Nacionalno upozorenje"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Upozorenje o ekstremnoj situaciji"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informativno upozorenje"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER upozorenje"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Testno upozorenje"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Upozorenje o ekstremnoj situaciji"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informativno upozorenje"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER upozorenje"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Testno upozorenje"</string>
+</resources>
diff --git a/res/values-mcc520-hu/strings.xml b/res/values-mcc520-hu/strings.xml
new file mode 100644
index 000000000..adbc0d96f
--- /dev/null
+++ b/res/values-mcc520-hu/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Országos riasztás"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Rendkívüli riasztás"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Tájékoztató riasztás"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER riasztás"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Próbariasztás"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Rendkívüli riasztás"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Tájékoztató riasztás"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER riasztás"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Próbariasztás"</string>
+</resources>
diff --git a/res/values-mcc520-hy/strings.xml b/res/values-mcc520-hy/strings.xml
new file mode 100644
index 000000000..6a1557bde
--- /dev/null
+++ b/res/values-mcc520-hy/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Համապետական ծանուցում"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Ծանուցում ծայրահեղ վտանգավոր իրավիճակի մասին"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Տեղեկատվական ծանուցում"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER ծանուցում"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Փորձնական ծանուցում"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Ծանուցում ծայրահեղ վտանգավոր իրավիճակի մասին"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Տեղեկատվական ծանուցում"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER ծանուցում"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Փորձնական ծանուցում"</string>
+</resources>
diff --git a/res/values-mcc520-in/strings.xml b/res/values-mcc520-in/strings.xml
new file mode 100644
index 000000000..31a6c6690
--- /dev/null
+++ b/res/values-mcc520-in/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Peringatan Nasional"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Peringatan Ekstrem"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Peringatan Informasi"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER Alert"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Peringatan Pengujian"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Peringatan Ekstrem"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Peringatan Informasi"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER Alert"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Peringatan Pengujian"</string>
+</resources>
diff --git a/res/values-mcc520-is/strings.xml b/res/values-mcc520-is/strings.xml
new file mode 100644
index 000000000..52602f15a
--- /dev/null
+++ b/res/values-mcc520-is/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Viðvörun á landsvísu"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Viðvörun á háu stigi"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Viðvörun til upplýsingar"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Tilkynning um týnt barn"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Prufuviðvörun"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Viðvörun á háu stigi"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Viðvörun til upplýsingar"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Tilkynning um týnt barn"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Prufuviðvörun"</string>
+</resources>
diff --git a/res/values-mcc520-it/strings.xml b/res/values-mcc520-it/strings.xml
new file mode 100644
index 000000000..86382a9e5
--- /dev/null
+++ b/res/values-mcc520-it/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Allerta nazionale"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Allerta per condizioni estreme"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Allerta informativa"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Allerta AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Allerta di prova"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Allerta per condizioni estreme"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Allerta informativa"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Allerta AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Allerta di prova"</string>
+</resources>
diff --git a/res/values-mcc520-iw/strings.xml b/res/values-mcc520-iw/strings.xml
new file mode 100644
index 000000000..f6d196da7
--- /dev/null
+++ b/res/values-mcc520-iw/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"התראה לאומית"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"התראה קיצונית"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"התראה עם מידע"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"‏התרעת AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"התראה בנושא בדיקה"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"התראה קיצונית"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"התראה עם מידע"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"‏התרעת AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"התראה בנושא בדיקה"</string>
+</resources>
diff --git a/res/values-mcc520-ja/strings.xml b/res/values-mcc520-ja/strings.xml
new file mode 100644
index 000000000..02b936d16
--- /dev/null
+++ b/res/values-mcc520-ja/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"全国的な警報"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"最重要速報メール"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"情報アラート"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"アンバー アラート"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"テストアラート"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"最重要速報メール"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"情報アラート"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"アンバー アラート"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"テストアラート"</string>
+</resources>
diff --git a/res/values-mcc520-ka/strings.xml b/res/values-mcc520-ka/strings.xml
new file mode 100644
index 000000000..1145fbe83
--- /dev/null
+++ b/res/values-mcc520-ka/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"ეროვნული დონის გაფრთხილება"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"ექსტრემალური ვითარების გაფრთხილება"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"ინფორმაციული გაფრთხილება"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER-ის გაფრთხილება"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"სატესტო გაფრთხილება"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"ექსტრემალური ვითარების გაფრთხილება"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"ინფორმაციული გაფრთხილება"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER-ის გაფრთხილება"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"სატესტო გაფრთხილება"</string>
+</resources>
diff --git a/res/values-mcc520-kk/strings.xml b/res/values-mcc520-kk/strings.xml
new file mode 100644
index 000000000..316ddc5cf
--- /dev/null
+++ b/res/values-mcc520-kk/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Жалпыұлттық дабыл"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Өте маңызды дабыл"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Ақпараттық дабыл"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER дабылы"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Сынақ дабыл"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Өте маңызды дабыл"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Ақпараттық дабыл"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER дабылы"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Сынақ дабыл"</string>
+</resources>
diff --git a/res/values-mcc520-km/strings.xml b/res/values-mcc520-km/strings.xml
new file mode 100644
index 000000000..eb8a61219
--- /dev/null
+++ b/res/values-mcc520-km/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"ការជូនដំណឹង​ថ្នាក់ជាតិ"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"ការជូនដំណឹង​ពេលអាសន្នធ្ងន់ធ្ងរ"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"ការជូនដំណឹងជាព័ត៌មាន"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"ការជូនដំណឹងអំពីការចាប់ជំរិតក្មេង"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"ការ​ជូន​ដំណឹងសាកល្បង"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"ការជូនដំណឹង​ពេលអាសន្នធ្ងន់ធ្ងរ"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"ការជូនដំណឹងជាព័ត៌មាន"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"ការជូនដំណឹងអំពីការចាប់ជំរិតក្មេង"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"ការ​ជូន​ដំណឹងសាកល្បង"</string>
+</resources>
diff --git a/res/values-mcc520-kn/strings.xml b/res/values-mcc520-kn/strings.xml
new file mode 100644
index 000000000..be757877d
--- /dev/null
+++ b/res/values-mcc520-kn/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"ರಾಷ್ಟ್ರೀಯ ಎಚ್ಚರಿಕೆ"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"ತೀವ್ರ ಎಚ್ಚರಿಕೆ"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"ಮಾಹಿತಿ ಎಚ್ಚರಿಕೆ"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER ಎಚ್ಚರಿಕೆ"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"ಪರೀಕ್ಷೆ ಎಚ್ಚರಿಕೆ"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"ತೀವ್ರ ಎಚ್ಚರಿಕೆ"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"ಮಾಹಿತಿ ಎಚ್ಚರಿಕೆ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER ಎಚ್ಚರಿಕೆ"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"ಪರೀಕ್ಷೆ ಎಚ್ಚರಿಕೆ"</string>
+</resources>
diff --git a/res/values-mcc520-ko/strings.xml b/res/values-mcc520-ko/strings.xml
new file mode 100644
index 000000000..3ba7e0845
--- /dev/null
+++ b/res/values-mcc520-ko/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"전국 경보"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"안전 안내 문자"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"정보 알림"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"앰버 경보"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"테스트 알림"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"안전 안내 문자"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"정보 알림"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"앰버 경보"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"테스트 알림"</string>
+</resources>
diff --git a/res/values-mcc520-ky/strings.xml b/res/values-mcc520-ky/strings.xml
new file mode 100644
index 000000000..b5a4e87d5
--- /dev/null
+++ b/res/values-mcc520-ky/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Жалпы улуттук шашылыш билдирүү"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Өтө коркунучтуу кырдаал жөнүндө шашылыш билдирүү"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Маалыматтык эскертүү"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Amber билдирүүсү"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Сынамык шашылыш билдирүү"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Өтө коркунучтуу кырдаал жөнүндө шашылыш билдирүү"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Маалыматтык эскертүү"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Amber билдирүүсү"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Сынамык шашылыш билдирүү"</string>
+</resources>
diff --git a/res/values-mcc520-lo/strings.xml b/res/values-mcc520-lo/strings.xml
new file mode 100644
index 000000000..adecaa41c
--- /dev/null
+++ b/res/values-mcc520-lo/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"ການແຈ້ງເຕືອນລະດັບຊາດ"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"ການແຈ້ງເຕືອນໄພຂັ້ນຮຸນແຮງ"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"ການແຈ້ງເຕືອນເພື່ອໃຫ້ຂໍ້ມູນ"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"ການແຈ້ງເຕືອນ AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"ການແຈ້ງເຕືອນເພື່ອທົດສອບລະບົບ"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"ການແຈ້ງເຕືອນໄພຂັ້ນຮຸນແຮງ"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"ການແຈ້ງເຕືອນເພື່ອໃຫ້ຂໍ້ມູນ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"ການແຈ້ງເຕືອນ AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"ການແຈ້ງເຕືອນເພື່ອທົດສອບລະບົບ"</string>
+</resources>
diff --git a/res/values-mcc520-lt/strings.xml b/res/values-mcc520-lt/strings.xml
new file mode 100644
index 000000000..8997df522
--- /dev/null
+++ b/res/values-mcc520-lt/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Nacionalinis įspėjimas"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Skubus įspėjimas"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informacinis įspėjimas"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER įspėjimas"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Bandomasis įspėjimas"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Skubus įspėjimas"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informacinis įspėjimas"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER įspėjimas"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Bandomasis įspėjimas"</string>
+</resources>
diff --git a/res/values-mcc520-lv/strings.xml b/res/values-mcc520-lv/strings.xml
new file mode 100644
index 000000000..ca4e1317a
--- /dev/null
+++ b/res/values-mcc520-lv/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Valsts līmeņa brīdinājums"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Brīdinājums par ārkārtas situāciju"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informatīvs brīdinājums"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER brīdinājums"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Testa brīdinājums"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Brīdinājums par ārkārtas situāciju"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informatīvs brīdinājums"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER brīdinājums"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Testa brīdinājums"</string>
+</resources>
diff --git a/res/values-mcc520-mk/strings.xml b/res/values-mcc520-mk/strings.xml
new file mode 100644
index 000000000..183db2e80
--- /dev/null
+++ b/res/values-mcc520-mk/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Национално предупредување"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Предупредување за екстремни ситуации"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Информативно предупредување"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Предупредување AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Пробно предупредување"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Предупредување за екстремни ситуации"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Информативно предупредување"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Предупредување AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Пробно предупредување"</string>
+</resources>
diff --git a/res/values-mcc520-ml/strings.xml b/res/values-mcc520-ml/strings.xml
new file mode 100644
index 000000000..a10ce441a
--- /dev/null
+++ b/res/values-mcc520-ml/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"ദേശീയ മുന്നറിയിപ്പ്"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"അതീവ ഗുരുതരമായ മുന്നറിയിപ്പ്"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"വിവരദായക മുന്നറിയിപ്പ്"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"ആംബർ അലേർട്ട്"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"പരീക്ഷണ മുന്നറിയിപ്പ്"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"അതീവ ഗുരുതരമായ മുന്നറിയിപ്പ്"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"വിവരദായക മുന്നറിയിപ്പ്"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"ആംബർ അലേർട്ട്"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"പരീക്ഷണ മുന്നറിയിപ്പ്"</string>
+</resources>
diff --git a/res/values-mcc520-mn/strings.xml b/res/values-mcc520-mn/strings.xml
new file mode 100644
index 000000000..3e5c56f70
--- /dev/null
+++ b/res/values-mcc520-mn/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Үндэсний сэрэмжлүүлэг"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Маш ноцтой сэрэмжлүүлэг"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Мэдээллийн зориулалттай сэрэмжлүүлэг"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER сэрэмжлүүлэг"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Туршилтын сэрэмжлүүлэг"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Маш ноцтой сэрэмжлүүлэг"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Мэдээллийн зориулалттай сэрэмжлүүлэг"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER сэрэмжлүүлэг"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Туршилтын сэрэмжлүүлэг"</string>
+</resources>
diff --git a/res/values-mcc520-mr/strings.xml b/res/values-mcc520-mr/strings.xml
new file mode 100644
index 000000000..cc31c15d8
--- /dev/null
+++ b/res/values-mcc520-mr/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"राष्ट्रीय इशारा"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"अत्यधिक गंभीर परिस्थितीशी संबंधित इशारा"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"माहितीपर इशारा"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"अँबर अलर्ट"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"चाचणीची इशारा"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"अत्यधिक गंभीर परिस्थितीशी संबंधित इशारा"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"माहितीपर इशारा"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"अँबर अलर्ट"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"चाचणीची इशारा"</string>
+</resources>
diff --git a/res/values-mcc520-ms/strings.xml b/res/values-mcc520-ms/strings.xml
new file mode 100644
index 000000000..0bf7f9149
--- /dev/null
+++ b/res/values-mcc520-ms/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Makluman Kebangsaan"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Makluman Ekstrem"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Makluman Bermaklumat"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Makluman Amber"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Makluman Ujian"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Makluman Ekstrem"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Makluman Bermaklumat"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Makluman Amber"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Makluman Ujian"</string>
+</resources>
diff --git a/res/values-mcc520-my/strings.xml b/res/values-mcc520-my/strings.xml
new file mode 100644
index 000000000..0de74792b
--- /dev/null
+++ b/res/values-mcc520-my/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"နိုင်ငံတော်အဆင့် သတိပေးချက်"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"လွန်ကဲမှု သတိပေးချက်"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"ပညာပေး သတိပေးချက်"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Amber သတိပေးချက်"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"စစ်ဆေးမှု သတိပေးချက်"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"လွန်ကဲမှု သတိပေးချက်"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"ပညာပေး သတိပေးချက်"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Amber သတိပေးချက်"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"စစ်ဆေးမှု သတိပေးချက်"</string>
+</resources>
diff --git a/res/values-mcc520-nb/strings.xml b/res/values-mcc520-nb/strings.xml
new file mode 100644
index 000000000..413e92ca2
--- /dev/null
+++ b/res/values-mcc520-nb/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Nasjonalt varsel"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Ekstremvarsel"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informasjonsvarsel"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER-varsel"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Testvarsel"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Ekstremvarsel"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informasjonsvarsel"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER-varsel"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Testvarsel"</string>
+</resources>
diff --git a/res/values-mcc520-ne/strings.xml b/res/values-mcc520-ne/strings.xml
new file mode 100644
index 000000000..cb04eb6c4
--- /dev/null
+++ b/res/values-mcc520-ne/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"राष्ट्रव्यापी अलर्ट"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"अत्यन्तै गम्भीर खतरासम्बन्धी अलर्ट"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"जानकारीमूलक अलर्ट"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER अलर्ट"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"टेस्ट अलर्ट"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"अत्यन्तै गम्भीर खतरासम्बन्धी अलर्ट"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"जानकारीमूलक अलर्ट"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER अलर्ट"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"टेस्ट अलर्ट"</string>
+</resources>
diff --git a/res/values-mcc520-nl/strings.xml b/res/values-mcc520-nl/strings.xml
new file mode 100644
index 000000000..040df3876
--- /dev/null
+++ b/res/values-mcc520-nl/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Nationale melding"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Melding voor extreme noodsituatie"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informatieve melding"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER Alert"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Testmelding"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Melding voor extreme noodsituatie"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informatieve melding"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER Alert"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Testmelding"</string>
+</resources>
diff --git a/res/values-mcc520-or/strings.xml b/res/values-mcc520-or/strings.xml
new file mode 100644
index 000000000..af9a4f1d2
--- /dev/null
+++ b/res/values-mcc520-or/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"ଜାତୀୟ ଆଲର୍ଟ"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"ଏକ୍ସଟ୍ରିମ ଆଲର୍ଟ"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"ସୂଚନା ଆଲର୍ଟ"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"ଅମ୍ବର ଆଲର୍ଟ"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"ଟେଷ୍ଟ ଆଲର୍ଟ"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"ଏକ୍ସଟ୍ରିମ ଆଲର୍ଟ"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"ସୂଚନା ଆଲର୍ଟ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"ଅମ୍ବର ଆଲର୍ଟ"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"ଟେଷ୍ଟ ଆଲର୍ଟ"</string>
+</resources>
diff --git a/res/values-mcc520-pa/strings.xml b/res/values-mcc520-pa/strings.xml
new file mode 100644
index 000000000..3397b9d4d
--- /dev/null
+++ b/res/values-mcc520-pa/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"ਰਾਸ਼ਟਰੀ ਅਲਰਟ"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"ਬਹੁਤ ਜ਼ਿਆਦਾ ਖਰਾਬ ਹਾਲਾਤ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"ਜਾਣਕਾਰੀ ਭਰਪੂਰ ਅਲਰਟ"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER ਅਲਰਟ"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"ਜਾਂਚ ਅਲਰਟ"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"ਬਹੁਤ ਜ਼ਿਆਦਾ ਖਰਾਬ ਹਾਲਾਤ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"ਜਾਣਕਾਰੀ ਭਰਪੂਰ ਅਲਰਟ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER ਅਲਰਟ"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"ਜਾਂਚ ਅਲਰਟ"</string>
+</resources>
diff --git a/res/values-mcc520-pl/strings.xml b/res/values-mcc520-pl/strings.xml
new file mode 100644
index 000000000..d0216fcf7
--- /dev/null
+++ b/res/values-mcc520-pl/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Alert krajowy"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Alert o ekstremalnym zagrożeniu"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Alert informacyjny"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Alert AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Alert testowy"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Alert o ekstremalnym zagrożeniu"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Alert informacyjny"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Alert AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Alert testowy"</string>
+</resources>
diff --git a/res/values-mcc520-pt-rPT/strings.xml b/res/values-mcc520-pt-rPT/strings.xml
new file mode 100644
index 000000000..b466aa330
--- /dev/null
+++ b/res/values-mcc520-pt-rPT/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Alerta nacional"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Alerta extremo"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Alerta informativo"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Alerta AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Alerta de teste"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Alerta extremo"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Alerta informativo"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Alerta AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Alerta de teste"</string>
+</resources>
diff --git a/res/values-mcc520-pt/strings.xml b/res/values-mcc520-pt/strings.xml
new file mode 100644
index 000000000..56e93754e
--- /dev/null
+++ b/res/values-mcc520-pt/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Alerta nacional"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Alerta extremo"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Alerta informativo"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Alerta AMBER (rapto de criança)"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Alerta de teste"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Alerta extremo"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Alerta informativo"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Alerta AMBER (rapto de criança)"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Alerta de teste"</string>
+</resources>
diff --git a/res/values-mcc520-ro/strings.xml b/res/values-mcc520-ro/strings.xml
new file mode 100644
index 000000000..83dd63d39
--- /dev/null
+++ b/res/values-mcc520-ro/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Alertă națională"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Alertă extremă"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Alertă informativă"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Alertă AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Alertă de testare"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Alertă extremă"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Alertă informativă"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Alertă AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Alertă de testare"</string>
+</resources>
diff --git a/res/values-mcc520-ru/strings.xml b/res/values-mcc520-ru/strings.xml
new file mode 100644
index 000000000..cd3d2b0ef
--- /dev/null
+++ b/res/values-mcc520-ru/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Общенациональное оповещение"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Оповещение о критической угрозе"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Информационное оповещение"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Оповещение AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Тестовое оповещение"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Оповещение о критической угрозе"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Информационное оповещение"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Оповещение AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Тестовое оповещение"</string>
+</resources>
diff --git a/res/values-mcc520-si/strings.xml b/res/values-mcc520-si/strings.xml
new file mode 100644
index 000000000..e443ac386
--- /dev/null
+++ b/res/values-mcc520-si/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"ජාතික ඇඟවීම"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"බරපතළ ඇඟවීම"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"තොරතුරු ඇඟවීම"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"ඇම්බර් ඇඟවීම"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"පරීක්ෂණ ඇඟවීම"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"බරපතළ ඇඟවීම"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"තොරතුරු ඇඟවීම"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"ඇම්බර් ඇඟවීම"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"පරීක්ෂණ ඇඟවීම"</string>
+</resources>
diff --git a/res/values-mcc520-sk/strings.xml b/res/values-mcc520-sk/strings.xml
new file mode 100644
index 000000000..27af54935
--- /dev/null
+++ b/res/values-mcc520-sk/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Celoštátne upozornenie"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Upozornenie na extrémnu situáciu"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informačné upozornenie"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Upozornenie Amber"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Testovacie upozornenie"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Upozornenie na extrémnu situáciu"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informačné upozornenie"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Upozornenie Amber"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Testovacie upozornenie"</string>
+</resources>
diff --git a/res/values-mcc520-sl/strings.xml b/res/values-mcc520-sl/strings.xml
new file mode 100644
index 000000000..6da490f9a
--- /dev/null
+++ b/res/values-mcc520-sl/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Državno opozorilo"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Izredno resno opozorilo"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informativno opozorilo"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Opozorilo AMBER"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Preizkusno opozorilo"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Izredno resno opozorilo"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informativno opozorilo"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Opozorilo AMBER"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Preizkusno opozorilo"</string>
+</resources>
diff --git a/res/values-mcc520-sq/strings.xml b/res/values-mcc520-sq/strings.xml
new file mode 100644
index 000000000..b4a183e6a
--- /dev/null
+++ b/res/values-mcc520-sq/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Sinjalizim kombëtar"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Sinjalizim ekstrem"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Sinjalizim ndërkombëtar"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Sinjalizimi Amber"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Sinjalizim testimi"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Sinjalizim ekstrem"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Sinjalizim ndërkombëtar"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Sinjalizimi Amber"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Sinjalizim testimi"</string>
+</resources>
diff --git a/res/values-mcc520-sr/strings.xml b/res/values-mcc520-sr/strings.xml
new file mode 100644
index 000000000..6e73d7b50
--- /dev/null
+++ b/res/values-mcc520-sr/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Упозорење на нивоу земље"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Обавештење о екстремној опасности"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Информативно упозорење"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Amber упозорење"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Пробно упозорење"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Обавештење о екстремној опасности"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Информативно упозорење"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Amber упозорење"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Пробно упозорење"</string>
+</resources>
diff --git a/res/values-mcc520-sv/strings.xml b/res/values-mcc520-sv/strings.xml
new file mode 100644
index 000000000..8e2d2846b
--- /dev/null
+++ b/res/values-mcc520-sv/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Nationell varning"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Varning om allvarlig nödsituation"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Informationsvarning"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER-varning"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Testvarning"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Varning om allvarlig nödsituation"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Informationsvarning"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER-varning"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Testvarning"</string>
+</resources>
diff --git a/res/values-mcc520-sw/strings.xml b/res/values-mcc520-sw/strings.xml
new file mode 100644
index 000000000..f8c1d581c
--- /dev/null
+++ b/res/values-mcc520-sw/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Tahadhari ya Kitaifa"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Tahadhari ya Hali Hatari"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Tahadhari ya Maelezo"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Tahadhari ya Watoto Waliotekwa Nyara"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Tahadhari ya Jaribio"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Tahadhari ya Hali Hatari"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Tahadhari ya Maelezo"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Tahadhari ya Watoto Waliotekwa Nyara"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Tahadhari ya Jaribio"</string>
+</resources>
diff --git a/res/values-mcc520-ta/strings.xml b/res/values-mcc520-ta/strings.xml
new file mode 100644
index 000000000..960f17ac4
--- /dev/null
+++ b/res/values-mcc520-ta/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"தேசிய அளவிலான எச்சரிக்கை"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"தீவிர எச்சரிக்கை"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"தகவல் தொடர்பான எச்சரிக்கை"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER எச்சரிக்கை"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"பரிசோதனை எச்சரிக்கை"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"தீவிர எச்சரிக்கை"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"தகவல் தொடர்பான எச்சரிக்கை"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER எச்சரிக்கை"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"பரிசோதனை எச்சரிக்கை"</string>
+</resources>
diff --git a/res/values-mcc520-te/strings.xml b/res/values-mcc520-te/strings.xml
new file mode 100644
index 000000000..58eab1cf0
--- /dev/null
+++ b/res/values-mcc520-te/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"జాతీయ అలర్ట్"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"అత్యంత తీవ్రమైన అలర్ట్"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"సమాచార అలర్ట్"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"యాంబర్ అలర్ట్"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"టెస్ట్ అలర్ట్"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"అత్యంత తీవ్రమైన అలర్ట్"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"సమాచార అలర్ట్"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"యాంబర్ అలర్ట్"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"టెస్ట్ అలర్ట్"</string>
+</resources>
diff --git a/res/values-mcc520-th/strings.xml b/res/values-mcc520-th/strings.xml
new file mode 100644
index 000000000..a1f24aae3
--- /dev/null
+++ b/res/values-mcc520-th/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"การแจ้งเตือนระดับชาติ"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"การแจ้งเตือนภัยขั้นรุนแรง"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"การแจ้งเตือนเพื่อให้ข้อมูล"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"การแจ้งเตือนการลักพาตัว"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"การแจ้งเตือนเพื่อทดสอบระบบ"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"การแจ้งเตือนภัยขั้นรุนแรง"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"การแจ้งเตือนเพื่อให้ข้อมูล"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"การแจ้งเตือนการลักพาตัว"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"การแจ้งเตือนเพื่อทดสอบระบบ"</string>
+</resources>
diff --git a/res/values-mcc520-tl/strings.xml b/res/values-mcc520-tl/strings.xml
new file mode 100644
index 000000000..36ab29c44
--- /dev/null
+++ b/res/values-mcc520-tl/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Pambansang Alerto"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Napakatinding Alerto"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Nagbibigay-impormasyong Alerto"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"AMBER Alert"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Pansubok na Alerto"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Napakatinding Alerto"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Nagbibigay-impormasyong Alerto"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"AMBER Alert"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Pansubok na Alerto"</string>
+</resources>
diff --git a/res/values-mcc520-tr/strings.xml b/res/values-mcc520-tr/strings.xml
new file mode 100644
index 000000000..4f88a41cd
--- /dev/null
+++ b/res/values-mcc520-tr/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Ulusal Düzeyde Uyarı"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Olağanüstü Uyarı"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Bilgilendirme Amaçlı Uyarı"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Amber Kayıp Çocuk Alarmı"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Test Amaçlı Uyarı"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Olağanüstü Uyarı"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Bilgilendirme Amaçlı Uyarı"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Amber Kayıp Çocuk Alarmı"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Test Amaçlı Uyarı"</string>
+</resources>
diff --git a/res/values-mcc520-uk/strings.xml b/res/values-mcc520-uk/strings.xml
new file mode 100644
index 000000000..247cabadc
--- /dev/null
+++ b/res/values-mcc520-uk/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Національне сповіщення"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Сповіщення про надзвичайну ситуацію"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Інформаційне сповіщення"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Сповіщення Amber"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Тестове сповіщення"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Сповіщення про надзвичайну ситуацію"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Інформаційне сповіщення"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Сповіщення Amber"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Тестове сповіщення"</string>
+</resources>
diff --git a/res/values-mcc520-ur/strings.xml b/res/values-mcc520-ur/strings.xml
new file mode 100644
index 000000000..c22320c5a
--- /dev/null
+++ b/res/values-mcc520-ur/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"قومی الرٹ"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"انتہائی الرٹ"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"معلوماتی الرٹ"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"زرد الرٹ"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"ٹیسٹ الرٹ"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"انتہائی الرٹ"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"معلوماتی الرٹ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"زرد الرٹ"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"ٹیسٹ الرٹ"</string>
+</resources>
diff --git a/res/values-mcc520-uz/strings.xml b/res/values-mcc520-uz/strings.xml
new file mode 100644
index 000000000..2fe3f0272
--- /dev/null
+++ b/res/values-mcc520-uz/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Umummilliy ogohlantirish"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Juda muhim ogohlantirish"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Axborotnoma ogohlantirish"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Amber ogohlantirishi"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Sinov ogohlantirishi"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Juda muhim ogohlantirish"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Axborotnoma ogohlantirish"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Amber ogohlantirishi"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Sinov ogohlantirishi"</string>
+</resources>
diff --git a/res/values-mcc520-vi/strings.xml b/res/values-mcc520-vi/strings.xml
new file mode 100644
index 000000000..77c181de1
--- /dev/null
+++ b/res/values-mcc520-vi/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Cảnh báo cấp quốc gia"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Cảnh báo cực kỳ nghiêm trọng"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Cảnh báo cung cấp thông tin"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Cảnh báo Amber"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Cảnh báo thử nghiệm"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Cảnh báo cực kỳ nghiêm trọng"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Cảnh báo cung cấp thông tin"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Cảnh báo Amber"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Cảnh báo thử nghiệm"</string>
+</resources>
diff --git a/res/values-mcc520-zh-rCN/strings.xml b/res/values-mcc520-zh-rCN/strings.xml
new file mode 100644
index 000000000..bfcb01c35
--- /dev/null
+++ b/res/values-mcc520-zh-rCN/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"国家级警报"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"极严重警报"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"信息警报"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"安珀警报"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"测试警报"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"极严重警报"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"信息警报"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"安珀警报"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"测试警报"</string>
+</resources>
diff --git a/res/values-mcc520-zh-rHK/strings.xml b/res/values-mcc520-zh-rHK/strings.xml
new file mode 100644
index 000000000..fabe1db2a
--- /dev/null
+++ b/res/values-mcc520-zh-rHK/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"全國警報"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"極嚴重警報"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"資訊性警報"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"安珀警報"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"測試警報"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"極嚴重警報"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"資訊性警報"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"安珀警報"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"測試警報"</string>
+</resources>
diff --git a/res/values-mcc520-zh-rTW/strings.xml b/res/values-mcc520-zh-rTW/strings.xml
new file mode 100644
index 000000000..4da22c574
--- /dev/null
+++ b/res/values-mcc520-zh-rTW/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"國家級警報"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"極度緊急警報"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"資訊型快訊"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"安珀警報"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"測試警報"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"極度緊急警報"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"資訊型快訊"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"安珀警報"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"測試警報"</string>
+</resources>
diff --git a/res/values-mcc520-zu/strings.xml b/res/values-mcc520-zu/strings.xml
new file mode 100644
index 000000000..6c0ec1022
--- /dev/null
+++ b/res/values-mcc520-zu/strings.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--   Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+  -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="cmas_presidential_level_alert" msgid="8652246909903979543">"Isexwayiso Sikazwelonke"</string>
+    <string name="cmas_extreme_alert" msgid="1539624055186085113">"Isexwayiso Esedlulele"</string>
+    <string name="public_safety_message" msgid="7803260172096958825">"Isexwayiso Esiyisaziso"</string>
+    <string name="cmas_amber_alert" msgid="1681714155769596431">"Isexwayiso se-Amber"</string>
+    <string name="cmas_required_monthly_test" msgid="5859775148883208089">"Isexwayiso Sokuhlola"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5439928947393191297">"Isexwayiso Esedlulele"</string>
+    <string name="enable_public_safety_messages_title" msgid="6569566741315399257">"Isexwayiso Esiyisaziso"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6521849845212532074">"Isexwayiso se-Amber"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="1889517460681507007">"Isexwayiso Sokuhlola"</string>
+</resources>
diff --git a/res/values-mcc520/config.xml b/res/values-mcc520/config.xml
new file mode 100644
index 000000000..574049e6c
--- /dev/null
+++ b/res/values-mcc520/config.xml
@@ -0,0 +1,76 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources>
+    <!-- 4370, 4383 -->
+    <string-array name="cmas_presidential_alerts_channels_range_strings" translatable="false">
+        <item>0x1112:rat=gsm, emergency=true, always_on=true, override_dnd=true</item>
+        <item>0x111F:rat=gsm, emergency=true, always_on=true, override_dnd=true</item>
+    </string-array>
+
+    <!-- 4371, 4384, 4372, 4385 -->
+    <string-array name="cmas_alert_extreme_channels_range_strings" translatable="false">
+        <item>0x1113:rat=gsm, emergency=true, override_dnd=true</item>
+        <item>0x1120:rat=gsm, emergency=true, override_dnd=true</item>
+        <item>0x1114:rat=gsm, emergency=true, type=mute</item>
+        <item>0x1121:rat=gsm, emergency=true, type=mute</item>
+    </string-array>
+
+    <!-- 4379, 4392 -->
+    <string-array name="cmas_amber_alerts_channels_range_strings" translatable="false">
+    <item>0x111B:rat=gsm, type=info, emergency=true</item>
+    <item>0x1128:rat=gsm, type=info, emergency=true</item>
+    </string-array>
+
+    <!-- 4396, 4397 : Channels to receive public safety messages-->
+    <string-array name="public_safety_messages_channels_range_strings" translatable="false">
+        <item>0x112C:rat=gsm, type=info, emergency=true</item>
+        <item>0x112D:rat=gsm, type=info, emergency=true</item>
+    </string-array>
+
+    <!-- 4380, 4393 -->
+    <string-array name="required_monthly_test_range_strings" translatable="false">
+        <item>0x111C:rat=gsm, emergency=true, testing_mode=true</item>
+        <item>0x1129:rat=gsm, emergency=true, testing_mode=true</item>
+    </string-array>
+
+    <!-- 4400: Channels to receive geo-fencing trigger messages -->
+    <string-array name="geo_fencing_trigger_messages_range_strings" translatable="false">
+        <!-- geo-fencing trigger messages -->
+        <item>0x1130:rat=gsm, emergency=true</item>
+    </string-array>
+
+    <!-- 4373~4378, 4386~4391 : Channel to receive severe alert message -->
+    <string-array name="cmas_alerts_severe_range_strings" translatable="false"></string-array>
+    <!-- 4352~4354, 4356 -->
+    <string-array name="etws_alerts_range_strings" translatable="false"></string-array>
+    <!-- 4355 -->
+    <string-array name="etws_test_alerts_range_strings" translatable="false"></string-array>
+    <!-- Operator Defined Alert -->
+    <string-array name="operator_defined_alert_range_strings" translatable="false"></string-array>
+    <!-- Exercise Alert -->
+    <string-array name="exercise_alert_range_strings" translatable="false"></string-array>
+
+    <!-- Other test alerts toggle default value -->
+    <bool name="test_alerts_enabled_default">true</bool>
+
+    <!-- Whether to show severe alert settings -->
+    <bool name="show_severe_alert_settings">false</bool>
+    <!-- Whether to display state/local test settings, some countries/carriers want to enable it by default and not allow users to disable -->
+    <bool name="show_state_local_test_settings">false</bool>
+    <!-- Whether to show test settings -->
+    <bool name="show_test_settings">false</bool>
+</resources>
diff --git a/res/values-mcc520/strings.xml b/res/values-mcc520/strings.xml
new file mode 100644
index 000000000..80c5cd85d
--- /dev/null
+++ b/res/values-mcc520/strings.xml
@@ -0,0 +1,47 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+           xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <!-- CMAS dialog title for presidential level alert. [CHAR LIMIT=50] -->
+    <!-- Required Thai(th) translation for this message:  การแจ้งเตือนระดับชาติ -->
+    <string name="cmas_presidential_level_alert">National Alert</string>
+    <!-- CMAS dialog title for extreme alert. [CHAR LIMIT=50] -->
+    <!-- Required Thai(th) translation for this message:  การแจ้งเตือนภัยขั้นรุนแรง -->
+    <string name="cmas_extreme_alert">Extreme Alert</string>
+    <!-- Dialog title for all public safety message broadcasts. [CHAR LIMIT=50] -->
+    <!-- Required Thai(th) translation for this message:  การแจ้งเตือนเพื่อให้ข้อมูล -->
+    <string name="public_safety_message">Informational Alert</string>
+    <!-- CMAS dialog title for child abduction emergency (Amber Alert). [CHAR LIMIT=50] -->
+    <!-- Required Thai(th) translation for this message:  การแจ้งเตือนการลักพาตัว -->
+    <string name="cmas_amber_alert">Amber Alert</string>
+    <!-- CMAS dialog title for required monthly test. [CHAR LIMIT=50] -->
+    <!-- Required Thai(th) translation for this message: การแจ้งเตือนเพื่อทดสอบระบบ -->
+    <string name="cmas_required_monthly_test">Test Alert</string>
+
+    <!-- Preference title for enable CMAS extreme threat alerts checkbox. [CHAR LIMIT=50] -->
+    <!-- Required Thai(th) translation for this message: การแจ้งเตือนภัยขั้นรุนแรง -->
+    <string name="enable_cmas_extreme_threat_alerts_title">Extreme Alert</string>
+    <!-- Preference title for enable public safety messages checkbox. [CHAR LIMIT=100] -->
+    <!-- Required Thai(th) translation for this message: การแจ้งเตือนเพื่อให้ข้อมูล -->
+    <string name="enable_public_safety_messages_title">Informational Alert</string>
+    <!-- Preference title for enable CMAS amber alerts checkbox. [CHAR LIMIT=50] -->
+    <!-- Required Thai(th) translation for this message: การแจ้งเตือนการลักพาตัว -->
+    <string name="enable_cmas_amber_alerts_title">Amber Alert</string>
+    <!-- Preference title for required monthly alerts checkbox. [CHAR LIMIT=50] -->
+    <!-- Required Thai(th) translation for this message: การแจ้งเตือนเพื่อทดสอบระบบ -->
+    <string name="enable_cmas_test_alerts_title">Test Alert</string>
+</resources>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index ec4619d7f..b261ea2e6 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -99,7 +99,7 @@
     <string name="enable_alert_vibrate_title" msgid="5421032189422312508">"Vibração"</string>
     <string name="enable_alert_vibrate_summary" msgid="4733669825477146614"></string>
     <string name="override_dnd_title" msgid="5120805993144214421">"Sempre tocar no volume máximo"</string>
-    <string name="override_dnd_summary" msgid="9026675822792800258">"Ignorar \"Não perturbe\" e outras configurações de volume"</string>
+    <string name="override_dnd_summary" msgid="9026675822792800258">"Ignorar o não perturbe e outras configurações de volume"</string>
     <string name="enable_area_update_info_alerts_title" msgid="3442042268424617226">"Transmissões de atualização de área"</string>
     <string name="enable_area_update_info_alerts_summary" msgid="6437816607144264910">"Mostrar informações de atualização no status do chip"</string>
     <string name="cmas_category_heading" msgid="3923503130776640717">"Categoria de alerta:"</string>
diff --git a/res/values/themes.xml b/res/values/themes.xml
index 4a1418368..1a2654b8d 100644
--- a/res/values/themes.xml
+++ b/res/values/themes.xml
@@ -44,4 +44,9 @@
         <item name="android:actionModeBackground">?android:attr/colorBackground</item>
     </style>
 
+    <style name="CellBroadcastListActivityActionModeTheme">
+        <item name="android:windowActionModeOverlay">true</item>
+        <item name="android:actionModeBackground">?android:attr/colorBackground</item>
+    </style>
+
 </resources>
diff --git a/res/xml-v31/preferences.xml b/res/xml-v31/preferences.xml
new file mode 100644
index 000000000..c99f55e74
--- /dev/null
+++ b/res/xml-v31/preferences.xml
@@ -0,0 +1,153 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+/*
+ * Copyright (C) 2011 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+-->
+<PreferenceScreen
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto">
+
+    <Preference android:key="alerts_header"
+                android:summary="@string/alerts_header_summary"
+                android:icon="@drawable/ic_info_outline_24dp"
+                android:selectable="false" />
+
+    <com.android.settingslib.widget.TopIntroPreference
+                      android:key="alert_prefs_top_intro"/>
+
+    <com.android.settingslib.widget.MainSwitchPreference android:defaultValue="@bool/master_toggle_enabled_default"
+                      android:key="enable_alerts_master_toggle"
+                      android:summary="@string/enable_alerts_master_toggle_summary"
+                      android:title="@string/enable_alerts_master_toggle_title" />
+
+    <!-- Settings to enable / disable emergency alerts -->
+    <PreferenceCategory android:title="@string/emergency_alerts_title"
+                        android:key="category_emergency_alerts">
+
+        <!-- Enable emergency alerts -->
+        <SwitchPreferenceCompat android:defaultValue="@bool/emergency_alerts_enabled_default"
+                          android:key="enable_emergency_alerts"
+                          android:summary="@string/enable_emergency_alerts_message_summary"
+                          android:title="@string/enable_emergency_alerts_message_title" />
+
+        <!-- Show checkbox for Presidential alerts in settings -->
+        <SwitchPreferenceCompat android:defaultValue="true"
+                          android:enabled="false"
+                          android:key="enable_cmas_presidential_alerts"
+                          android:summary="@string/enable_cmas_presidential_alerts_summary"
+                          android:title="@string/enable_cmas_presidential_alerts_title"/>
+
+        <!-- Enable CMAS Extreme Threat alerts -->
+        <SwitchPreferenceCompat android:defaultValue="@bool/extreme_threat_alerts_enabled_default"
+                          android:key="enable_cmas_extreme_threat_alerts"
+                          android:summary="@string/enable_cmas_extreme_threat_alerts_summary"
+                          android:title="@string/enable_cmas_extreme_threat_alerts_title" />
+
+        <!-- Enable CMAS Severe Threat alerts -->
+        <SwitchPreferenceCompat android:defaultValue="@bool/severe_threat_alerts_enabled_default"
+                          android:key="enable_cmas_severe_threat_alerts"
+                          android:summary="@string/enable_cmas_severe_threat_alerts_summary"
+                          android:title="@string/enable_cmas_severe_threat_alerts_title" />
+
+        <!-- Enable CMAS AMBER alerts -->
+        <SwitchPreferenceCompat android:defaultValue="@bool/amber_alerts_enabled_default"
+                          android:key="enable_cmas_amber_alerts"
+                          android:summary="@string/enable_cmas_amber_alerts_summary"
+                          android:title="@string/enable_cmas_amber_alerts_title" />
+
+        <!-- Enable public safety messages -->
+        <SwitchPreferenceCompat android:defaultValue="@bool/public_safety_messages_enabled_default"
+                          android:key="enable_public_safety_messages"
+                          android:summary="@string/enable_public_safety_messages_summary"
+                          android:title="@string/enable_public_safety_messages_title" />
+
+        <!-- Enable public safety full screen messages -->
+        <SwitchPreferenceCompat android:defaultValue="@bool/public_safety_messages_full_screen_enabled_default"
+            android:key="enable_public_safety_messages_full_screen"
+            android:summary="@string/enable_full_screen_public_safety_messages_summary"
+            android:title="@string/enable_full_screen_public_safety_messages_title" />
+
+        <!-- Enable state/local test alerts -->
+        <SwitchPreferenceCompat android:defaultValue="@bool/state_local_test_alerts_enabled_default"
+                          android:key="enable_state_local_test_alerts"
+                          android:summary="@string/enable_state_local_test_alerts_summary"
+                          android:title="@string/enable_state_local_test_alerts_title" />
+
+        <!-- Enable other test alerts -->
+        <SwitchPreferenceCompat android:defaultValue="@bool/test_alerts_enabled_default"
+                          android:key="enable_test_alerts"
+                          android:summary="@string/enable_cmas_test_alerts_summary"
+                          android:title="@string/enable_cmas_test_alerts_title" />
+
+        <!-- Enable exercise test alerts -->
+        <SwitchPreferenceCompat android:defaultValue="@bool/test_exercise_alerts_enabled_default"
+                          android:key="enable_exercise_alerts"
+                          android:summary="@string/enable_exercise_test_alerts_summary"
+                          android:title="@string/enable_exercise_test_alerts_title" />
+
+        <!-- Enable operator defined test alerts -->
+        <SwitchPreferenceCompat android:defaultValue="@bool/test_operator_defined_alerts_enabled_default"
+                          android:key="enable_operator_defined_alerts"
+                          android:summary="@string/enable_operator_defined_test_alerts_summary"
+                          android:title="@string/enable_operator_defined_test_alerts_title" />
+
+        <!-- Default value is true for Brazil and India. This preference is ignored and hidden
+        unless the boolean "config_showAreaUpdateInfoSettings" is set to true in the global resource. -->
+        <SwitchPreferenceCompat android:defaultValue="@bool/area_update_info_alerts_enabled_default"
+                          android:key="enable_area_update_info_alerts"
+                          android:summary="@string/enable_area_update_info_alerts_summary"
+                          android:title="@string/enable_area_update_info_alerts_title" />
+
+        <Preference android:key="emergency_alert_history"
+                    android:title="@string/emergency_alert_history_title" />
+
+    </PreferenceCategory>
+
+
+    <!-- Settings of how alerts are shown to user. -->
+    <PreferenceCategory android:title="@string/alert_preferences_title"
+                        android:key="category_alert_preferences">
+
+        <SwitchPreferenceCompat android:defaultValue="true"
+                          android:key="enable_alert_vibrate"
+                          android:summary="@string/enable_alert_vibrate_summary"
+                          android:title="@string/enable_alert_vibrate_title" />
+
+        <ListPreference android:key="alert_reminder_interval"
+                        android:title="@string/alert_reminder_interval_title"
+                        android:entries="@array/alert_reminder_interval_entries"
+                        android:entryValues="@array/alert_reminder_interval_values"
+                        android:defaultValue="@string/alert_reminder_interval_in_min_default"
+                        android:dialogTitle="@string/alert_reminder_dialog_title" />
+
+        <!-- Show additional language on/off switch in settings -->
+        <SwitchPreferenceCompat android:defaultValue="false"
+                          android:key="receive_cmas_in_second_language"
+                          android:summary="@string/receive_cmas_in_second_language_summary"
+                          android:title="@string/receive_cmas_in_second_language_title" />
+
+        <SwitchPreferenceCompat android:defaultValue="@bool/override_dnd_default"
+                          android:key="override_dnd"
+                          android:summary="@string/override_dnd_summary"
+                          android:title="@string/override_dnd_title" />
+
+        <SwitchPreferenceCompat android:defaultValue="@bool/enable_alert_speech_default"
+                          android:key="enable_alert_speech"
+                          android:summary="@string/enable_alert_speech_summary"
+                          android:title="@string/enable_alert_speech_title" />
+    </PreferenceCategory>
+
+</PreferenceScreen>
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertReminder.java b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertReminder.java
index 7bdbe19d1..9837faef2 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertReminder.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertReminder.java
@@ -122,7 +122,10 @@ public class CellBroadcastAlertReminder extends Service {
             loge("can't get Ringtone for alert reminder sound");
         }
 
-        if (enableVibration) {
+        AudioManager audioManager = getSystemService(AudioManager.class);
+        int audioMode = audioManager.getRingerMode();
+        log("audio mode : " + audioMode);
+        if (enableVibration && audioMode != AudioManager.RINGER_MODE_SILENT) {
             // Vibrate for 500ms.
             Vibrator vibrator = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
             if (vibrator != null) {
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastBackupAgent.java b/src/com/android/cellbroadcastreceiver/CellBroadcastBackupAgent.java
index 059a98434..7bd00b553 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastBackupAgent.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastBackupAgent.java
@@ -24,6 +24,7 @@ import android.preference.PreferenceManager;
 import android.util.Log;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.modules.utils.build.SdkLevel;
 
 /**
  * The CellBroadcast backup agent backs up the shared
@@ -51,7 +52,14 @@ public class CellBroadcastBackupAgent extends BackupAgentHelper {
 
         // Cell broadcast was configured during boot up before the shared preference is restored,
         // we need to re-configure it.
-        sendBroadcastAsUser(intent, UserHandle.SYSTEM);
+        if (SdkLevel.isAtLeastT()) {
+            // ACTION_USER_SWITCHED is supported on T and above.
+            // on T and above, channels are registered in current user for multiuser scenario
+            sendBroadcastAsUser(intent, UserHandle.CURRENT);
+        } else {
+            // before T, channels are registered in system user for multiuser scenario
+            sendBroadcastAsUser(intent, UserHandle.SYSTEM);
+        }
     }
 }
 
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastContentProvider.java b/src/com/android/cellbroadcastreceiver/CellBroadcastContentProvider.java
index 6b1dadced..9c260e2f4 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastContentProvider.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastContentProvider.java
@@ -27,6 +27,7 @@ import android.content.ContentValues;
 import android.content.Context;
 import android.content.UriMatcher;
 import android.database.Cursor;
+import android.database.SQLException;
 import android.database.sqlite.SQLiteDatabase;
 import android.database.sqlite.SQLiteQueryBuilder;
 import android.net.Uri;
@@ -42,6 +43,7 @@ import android.text.TextUtils;
 import android.util.Log;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.modules.utils.build.SdkLevel;
 
 import java.util.concurrent.CountDownLatch;
 
@@ -367,20 +369,28 @@ public class CellBroadcastContentProvider extends ContentProvider {
      * @param columnValue the ID or delivery time of the broadcast to mark read
      * @return true if the database was updated, false otherwise
      */
-    boolean markBroadcastRead(String columnName, long columnValue) {
-        SQLiteDatabase db = awaitInitAndGetWritableDatabase();
+    @VisibleForTesting
+    public boolean markBroadcastRead(String columnName, long columnValue) {
+        try {
+            SQLiteDatabase db = awaitInitAndGetWritableDatabase();
 
-        ContentValues cv = new ContentValues(1);
-        cv.put(Telephony.CellBroadcasts.MESSAGE_READ, 1);
+            ContentValues cv = new ContentValues(1);
+            cv.put(Telephony.CellBroadcasts.MESSAGE_READ, 1);
 
-        String whereClause = columnName + "=?";
-        String[] whereArgs = new String[]{Long.toString(columnValue)};
+            String whereClause = columnName + "=?";
+            String[] whereArgs = new String[]{Long.toString(columnValue)};
 
-        int rowCount = db.update(CellBroadcastDatabaseHelper.TABLE_NAME, cv, whereClause, whereArgs);
-        if (rowCount != 0) {
-            return true;
-        } else {
-            Log.e(TAG, "failed to mark broadcast read: " + columnName + " = " + columnValue);
+            int rowCount = db.update(CellBroadcastDatabaseHelper.TABLE_NAME, cv, whereClause,
+                    whereArgs);
+
+            if (rowCount != 0) {
+                return true;
+            } else {
+                Log.e(TAG, "failed to mark broadcast read: " + columnName + " = " + columnValue);
+                return false;
+            }
+        } catch (SQLException e) {
+            Log.e(TAG, "markBroadcastRead", e);
             return false;
         }
     }
@@ -397,21 +407,27 @@ public class CellBroadcastContentProvider extends ContentProvider {
     @VisibleForTesting
     public boolean markBroadcastSmsSyncPending(String columnName, long columnValue,
             boolean isSmsSyncPending) {
-        SQLiteDatabase db = awaitInitAndGetWritableDatabase();
+        try {
+            SQLiteDatabase db = awaitInitAndGetWritableDatabase();
 
-        ContentValues cv = new ContentValues(1);
-        cv.put(CellBroadcastDatabaseHelper.SMS_SYNC_PENDING, isSmsSyncPending ? 1 : 0);
+            ContentValues cv = new ContentValues(1);
+            cv.put(CellBroadcastDatabaseHelper.SMS_SYNC_PENDING, isSmsSyncPending ? 1 : 0);
 
-        String whereClause = columnName + "=?";
-        String[] whereArgs = new String[]{Long.toString(columnValue)};
+            String whereClause = columnName + "=?";
+            String[] whereArgs = new String[]{Long.toString(columnValue)};
 
-        int rowCount = db.update(CellBroadcastDatabaseHelper.TABLE_NAME, cv, whereClause,
-                whereArgs);
-        if (rowCount != 0) {
-            return true;
-        } else {
-            Log.e(TAG, "failed to mark broadcast pending for sms inbox sync:  " + isSmsSyncPending
-                    + " where: " + columnName + " = " + columnValue);
+            int rowCount = db.update(CellBroadcastDatabaseHelper.TABLE_NAME, cv, whereClause,
+                    whereArgs);
+            if (rowCount != 0) {
+                return true;
+            } else {
+                Log.e(TAG,
+                        "failed to mark broadcast pending for sms inbox sync:  " + isSmsSyncPending
+                                + " where: " + columnName + " = " + columnValue);
+                return false;
+            }
+        } catch (SQLException e) {
+            Log.e(TAG, "markBroadcastSmsSyncPending", e);
             return false;
         }
     }
@@ -456,9 +472,9 @@ public class CellBroadcastContentProvider extends ContentProvider {
     @VisibleForTesting
     public void writeMessageToSmsInbox(@NonNull SmsCbMessage message, @NonNull Context context) {
         UserManager userManager = (UserManager) context.getSystemService(Context.USER_SERVICE);
-        if (!userManager.isSystemUser()) {
-            // SMS database is single-user mode, discard non-system users to avoid inserting twice.
-            Log.d(TAG, "ignoring writeMessageToSmsInbox due to non-system user");
+        if (!isPrimaryUser(context)) {
+            // SMS database is single-user mode, discard non-main users to avoid inserting twice.
+            Log.d(TAG, "ignoring writeMessageToSmsInbox due to non-main user");
             return;
         }
         // Note SMS database is not direct boot aware for privacy reasons, we should only interact
@@ -552,4 +568,13 @@ public class CellBroadcastContentProvider extends ContentProvider {
             return null;
         }
     }
+
+    private boolean isPrimaryUser(Context context) {
+        UserManager userManager = context.getSystemService(UserManager.class);
+        if (SdkLevel.isAtLeastU()) {
+            return userManager.isMainUser();
+        } else {
+            return userManager.isSystemUser();
+        }
+    }
 }
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastListActivity.java b/src/com/android/cellbroadcastreceiver/CellBroadcastListActivity.java
index 21db3437c..d2e3e3da4 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastListActivity.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastListActivity.java
@@ -20,7 +20,6 @@ import static android.view.WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTE
 
 import android.annotation.Nullable;
 import android.app.ActionBar;
-import android.app.AlertDialog;
 import android.app.Dialog;
 import android.app.DialogFragment;
 import android.app.FragmentManager;
@@ -33,6 +32,7 @@ import android.content.DialogInterface.OnClickListener;
 import android.content.Intent;
 import android.content.Loader;
 import android.content.pm.PackageManager;
+import android.content.res.Resources;
 import android.database.Cursor;
 import android.net.Uri;
 import android.os.Bundle;
@@ -52,10 +52,12 @@ import android.view.WindowManager;
 import android.widget.AbsListView.MultiChoiceModeListener;
 import android.widget.ListView;
 import android.widget.TextView;
+import androidx.appcompat.app.AlertDialog;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.modules.utils.build.SdkLevel;
 import com.android.settingslib.collapsingtoolbar.CollapsingToolbarBaseActivity;
+import com.android.settingslib.widget.SettingsThemeHelper;
 
 import java.util.ArrayList;
 
@@ -67,17 +69,18 @@ public class CellBroadcastListActivity extends CollapsingToolbarBaseActivity {
 
     @VisibleForTesting
     public CursorLoaderListFragment mListFragment;
+    private boolean mHideToolbar = false;
 
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         boolean isWatch = getPackageManager().hasSystemFeature(PackageManager.FEATURE_WATCH);
         // for backward compatibility on R devices or wearable devices due to small screen device.
-        boolean hideToolbar = !SdkLevel.isAtLeastS() || isWatch;
-        if (hideToolbar) {
+        mHideToolbar = !SdkLevel.isAtLeastS() || isWatch;
+        if (mHideToolbar) {
             setCustomizeContentView(R.layout.cell_broadcast_list_collapsing_no_toobar);
         }
         super.onCreate(savedInstanceState);
-        if (hideToolbar) {
+        if (mHideToolbar) {
             ActionBar actionBar = getActionBar();
             if (actionBar != null) {
                 // android.R.id.home will be triggered in onOptionsItemSelected()
@@ -121,6 +124,22 @@ public class CellBroadcastListActivity extends CollapsingToolbarBaseActivity {
         return super.onOptionsItemSelected(item);
     }
 
+    /**
+     *  Overrides the default {@link android.content.ContextWrapper#getTheme()} method
+     *  to apply a custom style(CellBroadcastListActivityActionModeTheme)
+     *  when an expressive theme is enabled.
+     */
+    @Override
+    public Resources.Theme getTheme() {
+        Resources.Theme theme = super.getTheme();
+        if (SettingsThemeHelper.isExpressiveTheme(this)) {
+            theme.applyStyle(
+                    R.style.CellBroadcastListActivityActionModeTheme,
+                    true);
+        }
+        return theme;
+    }
+
     /**
      * List fragment queries SQLite database on worker thread.
      */
@@ -204,6 +223,8 @@ public class CellBroadcastListActivity extends CollapsingToolbarBaseActivity {
 
         private boolean mIsWatch;
 
+        @VisibleForTesting
+        public android.app.AlertDialog.Builder mInjectAlertDialogBuilderOld;
         @VisibleForTesting
         public AlertDialog.Builder mInjectAlertDialogBuilder;
 
@@ -369,13 +390,24 @@ public class CellBroadcastListActivity extends CollapsingToolbarBaseActivity {
                     messageDisplayed, geometry);
             int titleId = (mCurrentLoaderId == LOADER_NORMAL_HISTORY)
                     ? R.string.view_details_title : R.string.view_details_debugging_title;
-            AlertDialog.Builder dialogBuilder = mInjectAlertDialogBuilder != null
-                    ? mInjectAlertDialogBuilder : new AlertDialog.Builder(getActivity());
-            dialogBuilder
-                    .setTitle(titleId)
-                    .setMessage(details)
-                    .setCancelable(true)
-                    .show();
+            if (mActivity != null && !mActivity.mHideToolbar) {
+                AlertDialog.Builder dialogBuilder = mInjectAlertDialogBuilder != null
+                        ? mInjectAlertDialogBuilder : new AlertDialog.Builder(getActivity());
+                dialogBuilder
+                        .setTitle(titleId)
+                        .setMessage(details)
+                        .setCancelable(true)
+                        .show();
+            } else {
+                android.app.AlertDialog.Builder dialogBuilder = mInjectAlertDialogBuilderOld != null
+                        ? mInjectAlertDialogBuilderOld : new android.app.AlertDialog.Builder(
+                        getActivity());
+                dialogBuilder
+                        .setTitle(titleId)
+                        .setMessage(details)
+                        .setCancelable(true)
+                        .show();
+            }
         }
 
         private void updateActionIconsVisibility() {
@@ -632,15 +664,29 @@ public class CellBroadcastListActivity extends CollapsingToolbarBaseActivity {
                 long[] rowId = getArguments().getLongArray(ROW_ID);
                 boolean deleteAll = rowId[0] == -1;
                 DeleteThreadListener listener = new DeleteThreadListener(getActivity(), rowId);
-                AlertDialog.Builder builder = new AlertDialog.Builder(
-                        DeleteDialogFragment.this.getActivity());
-                builder.setIconAttribute(android.R.attr.alertDialogIcon)
-                        .setCancelable(true)
-                        .setPositiveButton(R.string.button_delete, listener)
-                        .setNegativeButton(R.string.button_cancel, null)
-                        .setMessage(deleteAll ? R.string.confirm_delete_all_broadcasts
-                                : R.string.confirm_delete_broadcast);
-                return builder.create();
+                CellBroadcastListActivity activity =
+                        (CellBroadcastListActivity) DeleteDialogFragment.this.getActivity();
+                if (!activity.mHideToolbar) {
+                    AlertDialog.Builder builder = new AlertDialog.Builder(
+                            DeleteDialogFragment.this.getActivity());
+                    builder.setIconAttribute(android.R.attr.alertDialogIcon)
+                            .setCancelable(true)
+                            .setPositiveButton(R.string.button_delete, listener)
+                            .setNegativeButton(R.string.button_cancel, null)
+                            .setMessage(deleteAll ? R.string.confirm_delete_all_broadcasts
+                                    : R.string.confirm_delete_broadcast);
+                    return builder.create();
+                } else {
+                    android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(
+                            DeleteDialogFragment.this.getActivity());
+                    builder.setIconAttribute(android.R.attr.alertDialogIcon)
+                            .setCancelable(true)
+                            .setPositiveButton(R.string.button_delete, listener)
+                            .setNegativeButton(R.string.button_cancel, null)
+                            .setMessage(deleteAll ? R.string.confirm_delete_all_broadcasts
+                                    : R.string.confirm_delete_broadcast);
+                    return builder.create();
+                }
             }
 
             @Override
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java b/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java
index 9f840b00d..b8448e674 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java
@@ -38,6 +38,7 @@ import android.os.Build;
 import android.os.Bundle;
 import android.os.RemoteException;
 import android.os.SystemProperties;
+import android.os.UserHandle;
 import android.os.UserManager;
 import android.provider.Telephony;
 import android.provider.Telephony.CellBroadcasts;
@@ -56,6 +57,7 @@ import androidx.localbroadcastmanager.content.LocalBroadcastManager;
 import androidx.preference.PreferenceManager;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.modules.utils.build.SdkLevel;
 
 import java.util.ArrayList;
 import java.util.Arrays;
@@ -100,6 +102,9 @@ public class CellBroadcastReceiver extends BroadcastReceiver {
             "com.android.cellbroadcastreceiver.intent.START_CONFIG";
     public static final String ACTION_MARK_AS_READ =
             "com.android.cellbroadcastreceiver.intent.action.MARK_AS_READ";
+
+    public static final String ACTION_CELLBROADCAST_USER_SWITCHED =
+            "com.android.cellbroadcastservice.action.USER_SWITCHED";
     public static final String EXTRA_DELIVERY_TIME =
             "com.android.cellbroadcastreceiver.intent.extra.ID";
     public static final String EXTRA_NOTIF_ID =
@@ -228,6 +233,15 @@ public class CellBroadcastReceiver extends BroadcastReceiver {
                         provider.resyncToSmsInbox(mContext);
                         return true;
                     });
+        } else if (ACTION_CELLBROADCAST_USER_SWITCHED.equals(intent.getAction())) {
+            Log.d(TAG, "CELLBROADCAST_USER_SWITCHED is received");
+            if (!isRepresentativeUser(context)) {
+                Log.d(TAG, "it is not current user");
+                return;
+            }
+            resetCellBroadcastChannelRanges();
+            initializeSharedPreference(context, SubscriptionManager.getDefaultSubscriptionId());
+            startConfigServiceToEnableChannels();
         } else {
             Log.w(TAG, "onReceive() unexpected action " + action);
         }
@@ -561,7 +575,7 @@ public class CellBroadcastReceiver extends BroadcastReceiver {
      */
     @VisibleForTesting
     public void initializeSharedPreference(Context context, int subId) {
-        if (isSystemUser()) {
+        if (isRepresentativeUser(context)) {
             Log.d(TAG, "initializeSharedPreference");
 
             resetSettingsAsNeeded(context, subId);
@@ -591,7 +605,7 @@ public class CellBroadcastReceiver extends BroadcastReceiver {
 
             adjustReminderInterval();
         } else {
-            Log.e(TAG, "initializeSharedPreference: Not system user.");
+            Log.e(TAG, "initializeSharedPreference: Not current user.");
         }
     }
 
@@ -734,21 +748,51 @@ public class CellBroadcastReceiver extends BroadcastReceiver {
 
     /**
      * This method's purpose if to enable unit testing
-     *
-     * @return if the mContext user is a system user
      */
-    private boolean isSystemUser() {
-        return isSystemUser(mContext);
+    @VisibleForTesting
+    public void startConfigServiceToEnableChannels() {
+        startConfigService(mContext, CellBroadcastConfigService.ACTION_ENABLE_CHANNELS);
     }
 
     /**
-     * This method's purpose if to enable unit testing
+     * Check if user from context is representative user
+     * @param context Context
+     * @return whether the user is current user
+     */
+    private static boolean isRepresentativeUser(Context context) {
+        if (SdkLevel.isAtLeastT()) {
+            // ACTION_USER_SWITCHED is supported on T and above.
+            // on T and above, channels are registered in current user for multiuser scenario
+            boolean isCurrentUser = UserHandle.myUserId() == sActivityManagerProxy.getCurrentUser();
+            Log.d(TAG, "isCurrentUser: " + isCurrentUser);
+            return isCurrentUser;
+        } else {
+            // before T, channels are registered in system user for multiuser scenario
+            boolean isSystemUser = isSystemUser(context);
+            Log.d(TAG, "isSystemUser: " + isSystemUser);
+            return isSystemUser;
+        }
+    }
+
+    /**
+     * Testing interface used to mock ActivityManager in testing
      */
     @VisibleForTesting
-    public void startConfigServiceToEnableChannels() {
-        startConfigService(mContext, CellBroadcastConfigService.ACTION_ENABLE_CHANNELS);
+    public interface ActivityManagerProxy {
+        /**
+         * @return The current user
+         */
+        int getCurrentUser();
     }
 
+    @VisibleForTesting
+    public static ActivityManagerProxy sActivityManagerProxy = new ActivityManagerProxy() {
+        @Override
+        public int getCurrentUser() {
+            return ActivityManager.getCurrentUser();
+        }
+    };
+
     /**
      * Check if user from context is system user
      * @param context
@@ -765,12 +809,12 @@ public class CellBroadcastReceiver extends BroadcastReceiver {
      * @param context the broadcast receiver context
      */
     static void startConfigService(Context context, String action) {
-        if (isSystemUser(context)) {
+        if (isRepresentativeUser(context)) {
             Log.d(TAG, "Start Cell Broadcast configuration for intent=" + action);
             context.startService(new Intent(action, null, context,
                     CellBroadcastConfigService.class));
         } else {
-            Log.e(TAG, "startConfigService: Not system user.");
+            Log.e(TAG, "startConfigService: Not representative user.");
         }
     }
 
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java b/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java
index ef4f55018..a36b0619d 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java
@@ -30,6 +30,7 @@ import android.content.pm.PackageManager;
 import android.content.res.Configuration;
 import android.content.res.Resources;
 import android.os.Bundle;
+import android.os.UserHandle;
 import android.os.UserManager;
 import android.os.Vibrator;
 import android.telephony.SubscriptionManager;
@@ -54,6 +55,7 @@ import com.android.internal.annotations.VisibleForTesting;
 import com.android.modules.utils.build.SdkLevel;
 import com.android.settingslib.collapsingtoolbar.CollapsingToolbarBaseActivity;
 import com.android.settingslib.widget.MainSwitchPreference;
+import com.android.settingslib.widget.SettingsBasePreferenceFragment;
 
 import java.util.HashMap;
 import java.util.Map;
@@ -69,6 +71,8 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
 
     @VisibleForTesting
     public CellBroadcastSettings.CellBroadcastSettingsFragment mCellBroadcastSettingsFragment;
+    @VisibleForTesting
+    public CellBroadcastSettings.CellBroadcastSettingsOldFragment mCellBroadcastSettingsOldFragment;
 
     /**
      * Keys for user preferences.
@@ -211,15 +215,28 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
         }
 
         // We only add new CellBroadcastSettingsFragment if no fragment is restored.
-        Fragment fragment = getFragmentManager().findFragmentById(
-                com.android.settingslib.collapsingtoolbar.R.id.content_frame);
-        if (fragment == null) {
-            mCellBroadcastSettingsFragment = new CellBroadcastSettingsFragment();
-            getFragmentManager()
-                    .beginTransaction()
-                    .add(com.android.settingslib.collapsingtoolbar.R.id.content_frame,
-                            mCellBroadcastSettingsFragment)
-                    .commit();
+        if (hideToolbar) {
+            Fragment fragmentOld = getFragmentManager().findFragmentById(
+                    com.android.settingslib.collapsingtoolbar.R.id.content_frame);
+            if (fragmentOld == null) {
+                mCellBroadcastSettingsOldFragment = new CellBroadcastSettingsOldFragment();
+                getFragmentManager()
+                        .beginTransaction()
+                        .add(com.android.settingslib.collapsingtoolbar.R.id.content_frame,
+                                mCellBroadcastSettingsOldFragment)
+                        .commit();
+            }
+        } else {
+            androidx.fragment.app.Fragment fragment = getSupportFragmentManager().findFragmentById(
+                    com.android.settingslib.collapsingtoolbar.R.id.content_frame);
+            if (fragment == null) {
+                mCellBroadcastSettingsFragment = new CellBroadcastSettingsFragment();
+                getSupportFragmentManager()
+                        .beginTransaction()
+                        .add(com.android.settingslib.collapsingtoolbar.R.id.content_frame,
+                                mCellBroadcastSettingsFragment)
+                        .commit();
+            }
         }
     }
 
@@ -301,7 +318,7 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
     /**
      * New fragment-style implementation of preferences.
      */
-    public static class CellBroadcastSettingsFragment extends PreferenceFragment {
+    public static class CellBroadcastSettingsFragment extends SettingsBasePreferenceFragment {
 
         private TwoStatePreference mExtremeCheckBox;
         private TwoStatePreference mSevereCheckBox;
@@ -894,7 +911,639 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
             areaInfoIntent.putExtra(AREA_INFO_UPDATE_ENABLED_EXTRA, enabled);
             // sending broadcast protected by the permission which is only
             // granted for CBR mainline module.
-            getContext().sendBroadcast(areaInfoIntent, CBR_MODULE_PERMISSION);
+            getContext().sendBroadcastAsUser(areaInfoIntent, UserHandle.SYSTEM,
+                    CBR_MODULE_PERMISSION);
+        }
+
+
+        @Override
+        public void onResume() {
+            super.onResume();
+            updatePreferenceVisibility();
+        }
+
+        @Override
+        public void onDestroy() {
+            super.onDestroy();
+            LocalBroadcastManager.getInstance(getContext())
+                    .unregisterReceiver(mTestingModeChangedReceiver);
+        }
+
+        /**
+         * Callback to be called when preference or master toggle is changed by user
+         *
+         * @param context Context to use
+         */
+        public void onPreferenceChangedByUser(Context context, boolean enableChannels) {
+            if (enableChannels) {
+                Log.d(TAG, "onPreferenceChangedByUser: enable channels");
+                CellBroadcastReceiver.startConfigService(context,
+                        CellBroadcastConfigService.ACTION_ENABLE_CHANNELS);
+            }
+            setPreferenceChanged(context, true);
+            // Notify backup manager a backup pass is needed.
+            new BackupManager(context).dataChanged();
+        }
+    }
+
+    /**
+     * SettingFragment for R
+     */
+    public static class CellBroadcastSettingsOldFragment extends PreferenceFragment {
+
+        private TwoStatePreference mExtremeCheckBox;
+        private TwoStatePreference mSevereCheckBox;
+        private TwoStatePreference mAmberCheckBox;
+        private TwoStatePreference mMasterToggle;
+        private TwoStatePreference mPublicSafetyMessagesChannelCheckBox;
+        private TwoStatePreference mPublicSafetyMessagesChannelFullScreenCheckBox;
+        private TwoStatePreference mEmergencyAlertsCheckBox;
+        private ListPreference mReminderInterval;
+        private TwoStatePreference mSpeechCheckBox;
+        private TwoStatePreference mOverrideDndCheckBox;
+        private TwoStatePreference mAreaUpdateInfoCheckBox;
+        private TwoStatePreference mTestCheckBox;
+        private TwoStatePreference mExerciseTestCheckBox;
+        private TwoStatePreference mOperatorDefinedCheckBox;
+        private TwoStatePreference mStateLocalTestCheckBox;
+        private TwoStatePreference mEnableVibrateCheckBox;
+        private Preference mAlertHistory;
+        private Preference mAlertsHeader;
+        private PreferenceCategory mAlertCategory;
+        private PreferenceCategory mAlertPreferencesCategory;
+        private boolean mDisableSevereWhenExtremeDisabled = true;
+
+        // Show checkbox for Presidential alerts in settings
+        private TwoStatePreference mPresidentialCheckBox;
+
+        // on/off switch in settings for receiving alert in second language code
+        private TwoStatePreference mReceiveCmasInSecondLanguageCheckBox;
+
+        // Show the top introduction
+        private Preference mTopIntroPreference;
+
+        private final BroadcastReceiver mTestingModeChangedReceiver = new BroadcastReceiver() {
+            @Override
+            public void onReceive(Context context, Intent intent) {
+                switch (intent.getAction()) {
+                    case CellBroadcastReceiver.ACTION_TESTING_MODE_CHANGED:
+                        updatePreferenceVisibility();
+                        break;
+                }
+            }
+        };
+
+        private void initPreferences() {
+            mExtremeCheckBox = (TwoStatePreference)
+                    findPreference(KEY_ENABLE_CMAS_EXTREME_THREAT_ALERTS);
+            mSevereCheckBox = (TwoStatePreference)
+                    findPreference(KEY_ENABLE_CMAS_SEVERE_THREAT_ALERTS);
+            mAmberCheckBox = (TwoStatePreference)
+                    findPreference(KEY_ENABLE_CMAS_AMBER_ALERTS);
+            mMasterToggle = (TwoStatePreference)
+                    findPreference(KEY_ENABLE_ALERTS_MASTER_TOGGLE);
+            mPublicSafetyMessagesChannelCheckBox = (TwoStatePreference)
+                    findPreference(KEY_ENABLE_PUBLIC_SAFETY_MESSAGES);
+            mPublicSafetyMessagesChannelFullScreenCheckBox = (TwoStatePreference)
+                    findPreference(KEY_ENABLE_PUBLIC_SAFETY_MESSAGES_FULL_SCREEN);
+            mEmergencyAlertsCheckBox = (TwoStatePreference)
+                    findPreference(KEY_ENABLE_EMERGENCY_ALERTS);
+            mReminderInterval = (ListPreference)
+                    findPreference(KEY_ALERT_REMINDER_INTERVAL);
+            mSpeechCheckBox = (TwoStatePreference)
+                    findPreference(KEY_ENABLE_ALERT_SPEECH);
+            mOverrideDndCheckBox = (TwoStatePreference)
+                    findPreference(KEY_OVERRIDE_DND);
+            mAreaUpdateInfoCheckBox = (TwoStatePreference)
+                    findPreference(KEY_ENABLE_AREA_UPDATE_INFO_ALERTS);
+            mTestCheckBox = (TwoStatePreference)
+                    findPreference(KEY_ENABLE_TEST_ALERTS);
+            mExerciseTestCheckBox = (TwoStatePreference) findPreference(KEY_ENABLE_EXERCISE_ALERTS);
+            mOperatorDefinedCheckBox = (TwoStatePreference)
+                    findPreference(KEY_OPERATOR_DEFINED_ALERTS);
+            mStateLocalTestCheckBox = (TwoStatePreference)
+                    findPreference(KEY_ENABLE_STATE_LOCAL_TEST_ALERTS);
+            mAlertHistory = findPreference(KEY_EMERGENCY_ALERT_HISTORY);
+            mAlertsHeader = findPreference(KEY_ALERTS_HEADER);
+            mReceiveCmasInSecondLanguageCheckBox = (TwoStatePreference) findPreference(
+                    KEY_RECEIVE_CMAS_IN_SECOND_LANGUAGE);
+            mEnableVibrateCheckBox = findPreference(KEY_ENABLE_ALERT_VIBRATE);
+
+            // Show checkbox for Presidential alerts in settings
+            mPresidentialCheckBox = (TwoStatePreference)
+                    findPreference(KEY_ENABLE_CMAS_PRESIDENTIAL_ALERTS);
+
+            PackageManager pm = getActivity().getPackageManager();
+            if (!pm.hasSystemFeature(PackageManager.FEATURE_WATCH)) {
+                mAlertPreferencesCategory = (PreferenceCategory)
+                        findPreference(KEY_CATEGORY_ALERT_PREFERENCES);
+                mAlertCategory = (PreferenceCategory)
+                        findPreference(KEY_CATEGORY_EMERGENCY_ALERTS);
+            }
+            mTopIntroPreference = findPreference(KEY_PREFS_TOP_INTRO);
+        }
+
+        @Override
+        public View onCreateView(LayoutInflater inflater, ViewGroup container,
+                Bundle savedInstanceState) {
+            View root = super.onCreateView(inflater, container, savedInstanceState);
+            PackageManager pm = getActivity().getPackageManager();
+            if (pm != null
+                    && pm.hasSystemFeature(
+                    PackageManager.FEATURE_WATCH)) {
+                ViewGroup.LayoutParams layoutParams = getListView().getLayoutParams();
+                if (layoutParams instanceof ViewGroup.MarginLayoutParams) {
+                    int watchMarginInPixel = (int) getResources().getDimension(
+                            R.dimen.pref_top_margin);
+                    ((ViewGroup.MarginLayoutParams) layoutParams).topMargin = watchMarginInPixel;
+                    ((ViewGroup.MarginLayoutParams) layoutParams).bottomMargin = watchMarginInPixel;
+                    getListView().setLayoutParams(layoutParams);
+                }
+            }
+            return root;
+        }
+
+        @Override
+        public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
+
+            LocalBroadcastManager.getInstance(getContext())
+                    .registerReceiver(mTestingModeChangedReceiver, new IntentFilter(
+                            CellBroadcastReceiver.ACTION_TESTING_MODE_CHANGED));
+
+            // Load the preferences from an XML resource
+            PackageManager pm = getActivity().getPackageManager();
+            if (pm.hasSystemFeature(PackageManager.FEATURE_WATCH)) {
+                addPreferencesFromResource(R.xml.watch_preferences);
+            } else {
+                addPreferencesFromResource(R.xml.preferences);
+            }
+
+            initPreferences();
+
+            Resources res = CellBroadcastSettings.getResourcesForDefaultSubId(getContext());
+
+            mDisableSevereWhenExtremeDisabled = res.getBoolean(
+                    R.bool.disable_severe_when_extreme_disabled);
+
+            // Handler for settings that require us to reconfigure enabled channels in radio
+            Preference.OnPreferenceChangeListener startConfigServiceListener =
+                    new Preference.OnPreferenceChangeListener() {
+                        @Override
+                        public boolean onPreferenceChange(Preference pref, Object newValue) {
+                            if (mDisableSevereWhenExtremeDisabled) {
+                                if (pref.getKey().equals(KEY_ENABLE_CMAS_EXTREME_THREAT_ALERTS)) {
+                                    boolean isExtremeAlertChecked = (Boolean) newValue;
+                                    if (mSevereCheckBox != null) {
+                                        mSevereCheckBox.setEnabled(isExtremeAlertChecked);
+                                        mSevereCheckBox.setChecked(false);
+                                    }
+                                }
+                            }
+
+                            // check if area update was disabled
+                            if (pref.getKey().equals(KEY_ENABLE_AREA_UPDATE_INFO_ALERTS)) {
+                                boolean isEnabledAlert = (Boolean) newValue;
+                                notifyAreaInfoUpdate(isEnabledAlert);
+                            }
+
+                            onPreferenceChangedByUser(getContext(), true);
+                            return true;
+                        }
+                    };
+
+            Preference.OnPreferenceChangeListener alertPreferenceToggleListener =
+                    new Preference.OnPreferenceChangeListener() {
+                        @Override
+                        public boolean onPreferenceChange(Preference pref, Object newValue) {
+                            onPreferenceChangedByUser(getContext(), false);
+                            return true;
+                        }
+                    };
+
+            initReminderIntervalList();
+
+            if (mMasterToggle != null) {
+
+                initAlertsToggleDisabledAsNeeded();
+
+                if (mMasterToggle instanceof MainSwitchPreference) {
+                    MainSwitchPreference mainSwitchPreference =
+                            (MainSwitchPreference) mMasterToggle;
+                    final OnCheckedChangeListener mainSwitchListener =
+                            new OnCheckedChangeListener() {
+                                @Override
+                                public void onCheckedChanged(CompoundButton buttonView,
+                                        boolean isChecked) {
+                                    setAlertsEnabled(isChecked);
+                                    onPreferenceChangedByUser(getContext(), true);
+                                }
+                            };
+                    mainSwitchPreference.addOnSwitchChangeListener(mainSwitchListener);
+                } else {
+                    Preference.OnPreferenceChangeListener mainSwitchListener =
+                            new Preference.OnPreferenceChangeListener() {
+                                @Override
+                                public boolean onPreferenceChange(
+                                        Preference pref, Object newValue) {
+                                    setAlertsEnabled((Boolean) newValue);
+                                    onPreferenceChangedByUser(getContext(), true);
+                                    return true;
+                                }
+                            };
+                    mMasterToggle.setOnPreferenceChangeListener(mainSwitchListener);
+                }
+                // If allow alerts are disabled, we turn all sub-alerts off. If it's enabled, we
+                // leave them as they are.
+                if (!mMasterToggle.isChecked()) {
+                    setAlertsEnabled(false);
+                }
+            }
+            // note that mPresidentialCheckBox does not use the startConfigServiceListener because
+            // the user is never allowed to change the preference
+            if (mAreaUpdateInfoCheckBox != null) {
+                mAreaUpdateInfoCheckBox.setOnPreferenceChangeListener(startConfigServiceListener);
+            }
+            if (mExtremeCheckBox != null) {
+                mExtremeCheckBox.setOnPreferenceChangeListener(startConfigServiceListener);
+            }
+            if (mPublicSafetyMessagesChannelCheckBox != null) {
+                mPublicSafetyMessagesChannelCheckBox.setOnPreferenceChangeListener(
+                        startConfigServiceListener);
+            }
+            if (mPublicSafetyMessagesChannelFullScreenCheckBox != null) {
+                mPublicSafetyMessagesChannelFullScreenCheckBox.setOnPreferenceChangeListener(
+                        startConfigServiceListener);
+            }
+            if (mEmergencyAlertsCheckBox != null) {
+                mEmergencyAlertsCheckBox.setOnPreferenceChangeListener(startConfigServiceListener);
+            }
+            if (mSevereCheckBox != null) {
+                mSevereCheckBox.setOnPreferenceChangeListener(startConfigServiceListener);
+                if (mDisableSevereWhenExtremeDisabled) {
+                    if (mExtremeCheckBox != null) {
+                        mSevereCheckBox.setEnabled(mExtremeCheckBox.isChecked());
+                    }
+                }
+            }
+            if (mAmberCheckBox != null) {
+                mAmberCheckBox.setOnPreferenceChangeListener(startConfigServiceListener);
+            }
+            if (mTestCheckBox != null) {
+                mTestCheckBox.setOnPreferenceChangeListener(startConfigServiceListener);
+            }
+            if (mExerciseTestCheckBox != null) {
+                mExerciseTestCheckBox.setOnPreferenceChangeListener(startConfigServiceListener);
+            }
+            if (mOperatorDefinedCheckBox != null) {
+                mOperatorDefinedCheckBox.setOnPreferenceChangeListener(startConfigServiceListener);
+            }
+            if (mStateLocalTestCheckBox != null) {
+                mStateLocalTestCheckBox.setOnPreferenceChangeListener(
+                        startConfigServiceListener);
+            }
+
+            SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(getContext());
+
+            if (mOverrideDndCheckBox != null) {
+                if (!sp.getBoolean(KEY_OVERRIDE_DND_SETTINGS_CHANGED, false)) {
+                    // If the user hasn't changed this settings yet, use the default settings
+                    // from resource overlay.
+                    mOverrideDndCheckBox.setChecked(res.getBoolean(R.bool.override_dnd_default));
+                }
+                mOverrideDndCheckBox.setOnPreferenceChangeListener(
+                        (pref, newValue) -> {
+                            sp.edit().putBoolean(KEY_OVERRIDE_DND_SETTINGS_CHANGED,
+                                    true).apply();
+                            updateVibrationPreference((boolean) newValue);
+                            return true;
+                        });
+            }
+
+            if (mAlertHistory != null) {
+                mAlertHistory.setOnPreferenceClickListener(
+                        preference -> {
+                            final Intent intent = new Intent(getContext(),
+                                    CellBroadcastListActivity.class);
+                            startActivity(intent);
+                            return true;
+                        });
+            }
+
+            if (mSpeechCheckBox != null) {
+                mSpeechCheckBox.setOnPreferenceChangeListener(alertPreferenceToggleListener);
+            }
+
+            updateVibrationPreference(sp.getBoolean(CellBroadcastSettings.KEY_OVERRIDE_DND,
+                    false));
+            updatePreferenceVisibility();
+        }
+
+        /**
+         * Update the vibration preference based on override DND. If DND is overridden, then do
+         * not allow users to turn off vibration.
+         *
+         * @param overrideDnd {@code true} if the alert will be played at full volume, regardless
+         * DND settings.
+         */
+        private void updateVibrationPreference(boolean overrideDnd) {
+            if (mEnableVibrateCheckBox != null) {
+                if (overrideDnd) {
+                    // If DND is enabled, always enable vibration.
+                    mEnableVibrateCheckBox.setChecked(true);
+                }
+                // Grey out the preference if DND is overridden.
+                mEnableVibrateCheckBox.setEnabled(!overrideDnd);
+            }
+        }
+
+        /**
+         * Dynamically update each preference's visibility based on configuration.
+         */
+        private void updatePreferenceVisibility() {
+            Resources res = CellBroadcastSettings.getResourcesForDefaultSubId(getContext());
+
+            // The settings should be based on the config by the subscription
+            CellBroadcastChannelManager channelManager = new CellBroadcastChannelManager(
+                    getContext(), SubscriptionManager.getDefaultSubscriptionId(), null);
+
+            PreferenceScreen preferenceScreen = getPreferenceScreen();
+            boolean isWatch = getActivity().getPackageManager().hasSystemFeature(
+                    PackageManager.FEATURE_WATCH);
+
+            if (mMasterToggle != null) {
+                mMasterToggle.setVisible(res.getBoolean(R.bool.show_main_switch_settings));
+            }
+
+            if (mPresidentialCheckBox != null) {
+                mPresidentialCheckBox.setVisible(
+                        res.getBoolean(R.bool.show_presidential_alerts_settings));
+                if (isWatch && !mPresidentialCheckBox.isVisible()) {
+                    preferenceScreen.removePreference(mPresidentialCheckBox);
+                }
+            }
+
+            if (mExtremeCheckBox != null) {
+                mExtremeCheckBox.setVisible(res.getBoolean(R.bool.show_extreme_alert_settings)
+                        && !channelManager.getCellBroadcastChannelRanges(
+                        R.array.cmas_alert_extreme_channels_range_strings).isEmpty());
+                if (isWatch && !mExtremeCheckBox.isVisible()) {
+                    preferenceScreen.removePreference(mExtremeCheckBox);
+                }
+            }
+
+            if (mSevereCheckBox != null) {
+                mSevereCheckBox.setVisible(res.getBoolean(R.bool.show_severe_alert_settings)
+                        && !channelManager.getCellBroadcastChannelRanges(
+                        R.array.cmas_alerts_severe_range_strings).isEmpty());
+                if (isWatch && !mSevereCheckBox.isVisible()) {
+                    preferenceScreen.removePreference(mSevereCheckBox);
+                }
+            }
+
+            if (mAmberCheckBox != null) {
+                mAmberCheckBox.setVisible(res.getBoolean(R.bool.show_amber_alert_settings)
+                        && !channelManager.getCellBroadcastChannelRanges(
+                        R.array.cmas_amber_alerts_channels_range_strings).isEmpty());
+                if (isWatch && !mAmberCheckBox.isVisible()) {
+                    preferenceScreen.removePreference(mAmberCheckBox);
+                }
+            }
+
+            if (mPublicSafetyMessagesChannelCheckBox != null) {
+                mPublicSafetyMessagesChannelCheckBox.setVisible(
+                        res.getBoolean(R.bool.show_public_safety_settings)
+                                && !channelManager.getCellBroadcastChannelRanges(
+                                        R.array.public_safety_messages_channels_range_strings)
+                                .isEmpty());
+                if (isWatch && !mPublicSafetyMessagesChannelCheckBox.isVisible()) {
+                    preferenceScreen.removePreference(mPublicSafetyMessagesChannelCheckBox);
+                }
+            }
+            // this is the matching full screen settings for public safety toggle. shown only if
+            // public safety toggle is displayed.
+            if (mPublicSafetyMessagesChannelFullScreenCheckBox != null) {
+                mPublicSafetyMessagesChannelFullScreenCheckBox.setVisible(
+                        isShowFullScreenMessageVisible(getContext(), res));
+            }
+
+            if (mTestCheckBox != null) {
+                mTestCheckBox.setVisible(isTestAlertsToggleVisible(getContext()));
+            }
+
+            if (mExerciseTestCheckBox != null) {
+                mExerciseTestCheckBox.setVisible(
+                        isExerciseTestAlertsToggleVisible(res, getContext(), channelManager));
+            }
+
+            if (mOperatorDefinedCheckBox != null) {
+                mOperatorDefinedCheckBox.setVisible(
+                        isOperatorTestAlertsToggleVisible(res, getContext(), channelManager));
+            }
+
+            if (mEmergencyAlertsCheckBox != null) {
+                mEmergencyAlertsCheckBox.setVisible(!channelManager.getCellBroadcastChannelRanges(
+                        R.array.emergency_alerts_channels_range_strings).isEmpty());
+                if (isWatch && !mEmergencyAlertsCheckBox.isVisible()) {
+                    preferenceScreen.removePreference(mEmergencyAlertsCheckBox);
+                }
+            }
+
+            if (mStateLocalTestCheckBox != null) {
+                mStateLocalTestCheckBox.setVisible(
+                        res.getBoolean(R.bool.show_state_local_test_settings)
+                                && !channelManager.getCellBroadcastChannelRanges(
+                                R.array.state_local_test_alert_range_strings).isEmpty());
+                if (isWatch && !mStateLocalTestCheckBox.isVisible()) {
+                    preferenceScreen.removePreference(mStateLocalTestCheckBox);
+                }
+            }
+
+            if (mReceiveCmasInSecondLanguageCheckBox != null) {
+                mReceiveCmasInSecondLanguageCheckBox.setVisible(!res.getString(
+                        R.string.emergency_alert_second_language_code).isEmpty());
+                if (isWatch && !mReceiveCmasInSecondLanguageCheckBox.isVisible()) {
+                    preferenceScreen.removePreference(mReceiveCmasInSecondLanguageCheckBox);
+                }
+            }
+
+            if (mAreaUpdateInfoCheckBox != null) {
+                mAreaUpdateInfoCheckBox.setVisible(
+                        res.getBoolean(R.bool.config_showAreaUpdateInfoSettings));
+                if (isWatch && !mAreaUpdateInfoCheckBox.isVisible()) {
+                    preferenceScreen.removePreference(mAreaUpdateInfoCheckBox);
+                }
+            }
+
+            if (mOverrideDndCheckBox != null) {
+                mOverrideDndCheckBox.setVisible(res.getBoolean(R.bool.show_override_dnd_settings));
+                if (isWatch && !mOverrideDndCheckBox.isVisible()) {
+                    preferenceScreen.removePreference(mOverrideDndCheckBox);
+                }
+            }
+
+            if (mEnableVibrateCheckBox != null) {
+                // Only show vibrate toggle when override DND toggle is available to users, or when
+                // override DND default is turned off.
+                // In some countries, override DND is always on, which means vibration is always on.
+                // In that case, no need to show vibration toggle for users.
+                mEnableVibrateCheckBox.setVisible(isVibrationToggleVisible(getContext(), res));
+                if (isWatch && !mEnableVibrateCheckBox.isVisible()) {
+                    preferenceScreen.removePreference(mEnableVibrateCheckBox);
+                }
+            }
+            if (mAlertsHeader != null) {
+                mAlertsHeader.setVisible(
+                        !getContext().getString(R.string.alerts_header_summary).isEmpty());
+                if (isWatch && !mAlertsHeader.isVisible()) {
+                    preferenceScreen.removePreference(mAlertsHeader);
+                }
+            }
+
+            if (mSpeechCheckBox != null) {
+                mSpeechCheckBox.setVisible(res.getBoolean(R.bool.show_alert_speech_setting)
+                        || getActivity().getPackageManager()
+                        .hasSystemFeature(PackageManager.FEATURE_WATCH));
+            }
+
+            if (mTopIntroPreference != null) {
+                mTopIntroPreference.setTitle(getTopIntroduction());
+            }
+        }
+
+        private int getTopIntroduction() {
+            // Only set specific top introduction for roaming support now
+            if (!CellBroadcastReceiver.getRoamingOperatorSupported(getContext()).isEmpty()) {
+                return R.string.top_intro_roaming_text;
+            }
+            return R.string.top_intro_default_text;
+        }
+
+        private void initReminderIntervalList() {
+            Resources res = CellBroadcastSettings.getResourcesForDefaultSubId(getContext());
+
+            String[] activeValues =
+                    res.getStringArray(R.array.alert_reminder_interval_active_values);
+            String[] allEntries = res.getStringArray(R.array.alert_reminder_interval_entries);
+            String[] newEntries = new String[activeValues.length];
+
+            // Only add active interval to the list
+            for (int i = 0; i < activeValues.length; i++) {
+                int index = mReminderInterval.findIndexOfValue(activeValues[i]);
+                if (index != -1) {
+                    newEntries[i] = allEntries[index];
+                    if (DBG) Log.d(TAG, "Added " + allEntries[index]);
+                } else {
+                    Log.e(TAG, "Can't find " + activeValues[i]);
+                }
+            }
+
+            mReminderInterval.setEntries(newEntries);
+            mReminderInterval.setEntryValues(activeValues);
+            mReminderInterval.setSummary(mReminderInterval.getEntry());
+            mReminderInterval.setOnPreferenceChangeListener(
+                    new Preference.OnPreferenceChangeListener() {
+                        @Override
+                        public boolean onPreferenceChange(Preference pref, Object newValue) {
+                            final ListPreference listPref = (ListPreference) pref;
+                            final int idx = listPref.findIndexOfValue((String) newValue);
+                            listPref.setSummary(listPref.getEntries()[idx]);
+                            return true;
+                        }
+                    });
+        }
+
+        /**
+         * Set the extreme toggle disabled as needed.
+         */
+        @VisibleForTesting
+        public void initAlertsToggleDisabledAsNeeded() {
+            Resources res = CellBroadcastSettings.getResourcesForDefaultSubId(getContext());
+            if (res.getBoolean(R.bool.disable_extreme_alert_settings)) {
+                mExtremeCheckBox.setEnabled(false);
+                mExtremeCheckBox.setChecked(
+                        res.getBoolean(R.bool.extreme_threat_alerts_enabled_default));
+            }
+        }
+
+        /**
+         * Enable the toggles to set it on/off or carrier default.
+         */
+        @VisibleForTesting
+        public void setAlertsEnabled(boolean alertsEnabled) {
+            Resources res = CellBroadcastSettings.getResourcesForDefaultSubId(getContext());
+
+            boolean resetCarrierDefault = res.getBoolean(
+                    R.bool.restore_sub_toggle_to_carrier_default);
+
+            if (mSevereCheckBox != null) {
+                mSevereCheckBox.setEnabled(alertsEnabled);
+                mSevereCheckBox.setChecked(resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                        R.bool.severe_threat_alerts_enabled_default) : alertsEnabled);
+            }
+            if (!res.getBoolean(R.bool.disable_extreme_alert_settings)
+                    && mExtremeCheckBox != null) {
+                mExtremeCheckBox.setEnabled(alertsEnabled);
+                mExtremeCheckBox.setChecked(resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                        R.bool.extreme_threat_alerts_enabled_default) : alertsEnabled);
+            }
+            if (mAmberCheckBox != null) {
+                mAmberCheckBox.setEnabled(alertsEnabled);
+                mAmberCheckBox.setChecked(resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                        R.bool.amber_alerts_enabled_default) : alertsEnabled);
+            }
+            if (mAreaUpdateInfoCheckBox != null) {
+                mAreaUpdateInfoCheckBox.setEnabled(alertsEnabled);
+                mAreaUpdateInfoCheckBox.setChecked(
+                        resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                                R.bool.area_update_info_alerts_enabled_default) : alertsEnabled);
+                notifyAreaInfoUpdate(resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                        R.bool.area_update_info_alerts_enabled_default) : alertsEnabled);
+            }
+            if (mEmergencyAlertsCheckBox != null) {
+                mEmergencyAlertsCheckBox.setEnabled(alertsEnabled);
+                mEmergencyAlertsCheckBox.setChecked(
+                        resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                                R.bool.emergency_alerts_enabled_default) : alertsEnabled);
+            }
+            if (mPublicSafetyMessagesChannelCheckBox != null) {
+                mPublicSafetyMessagesChannelCheckBox.setEnabled(alertsEnabled);
+                mPublicSafetyMessagesChannelCheckBox.setChecked(
+                        resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                                R.bool.public_safety_messages_enabled_default) : alertsEnabled);
+            }
+            if (mStateLocalTestCheckBox != null) {
+                mStateLocalTestCheckBox.setEnabled(alertsEnabled);
+                mStateLocalTestCheckBox.setChecked(
+                        resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                                R.bool.state_local_test_alerts_enabled_default) : alertsEnabled);
+            }
+            if (mTestCheckBox != null) {
+                mTestCheckBox.setEnabled(alertsEnabled);
+                mTestCheckBox.setChecked(resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                        R.bool.test_alerts_enabled_default) : alertsEnabled);
+            }
+            if (mExerciseTestCheckBox != null) {
+                mExerciseTestCheckBox.setEnabled(alertsEnabled);
+                mExerciseTestCheckBox.setChecked(
+                        resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                                R.bool.test_exercise_alerts_enabled_default) : alertsEnabled);
+            }
+            if (mOperatorDefinedCheckBox != null) {
+                mOperatorDefinedCheckBox.setEnabled(alertsEnabled);
+                mOperatorDefinedCheckBox.setChecked(
+                        resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                                R.bool.test_operator_defined_alerts_enabled_default)
+                                : alertsEnabled);
+            }
+        }
+
+        private void notifyAreaInfoUpdate(boolean enabled) {
+            Intent areaInfoIntent = new Intent(AREA_INFO_UPDATE_ACTION);
+            areaInfoIntent.putExtra(AREA_INFO_UPDATE_ENABLED_EXTRA, enabled);
+            // sending broadcast protected by the permission which is only
+            // granted for CBR mainline module.
+            getContext().sendBroadcastAsUser(areaInfoIntent, UserHandle.SYSTEM,
+                    CBR_MODULE_PERMISSION);
         }
 
 
diff --git a/tests/compliancetests/Android.bp b/tests/compliancetests/Android.bp
index 77fcf7250..22dd98576 100644
--- a/tests/compliancetests/Android.bp
+++ b/tests/compliancetests/Android.bp
@@ -31,7 +31,7 @@ java_defaults {
         "mockito-target-minus-junit4",
         "truth",
         "ub-uiautomator",
-        "cellbroadcast.mockmodem",
+        "android.telephony.mockmodem",
         "modules-utils-build_system",
         "junit-params",
     ],
@@ -40,22 +40,6 @@ java_defaults {
     platform_apis: true,
 }
 
-java_import {
-    name: "prebuilt_cellbroadcast_mockmodem",
-    jars: ["mockmodem/classes.jar"],
-}
-
-android_library {
-    name: "cellbroadcast.mockmodem",
-    asset_dirs: ["mockmodem/assets"],
-    manifest: "mockmodem/AndroidManifest.xml",
-    static_libs: [
-        "prebuilt_cellbroadcast_mockmodem",
-    ],
-    min_sdk_version: "30",
-    platform_apis: true,
-}
-
 android_test {
     name: "CellBroadcastReceiverComplianceTests",
     defaults: ["CellBroadcastTestCommonComplianceTest"],
diff --git a/tests/compliancetests/assets/emergency_alert_channels.json b/tests/compliancetests/assets/emergency_alert_channels.json
index 7dabd7065..a9a9cada9 100644
--- a/tests/compliancetests/assets/emergency_alert_channels.json
+++ b/tests/compliancetests/assets/emergency_alert_channels.json
@@ -995,157 +995,73 @@
       "filter_language": "language_setting"
     },
     "40960": {
-      "title": "안전 안내문자", //"Public Safety Alert",
-      "default_value": "true",
-      "toggle_avail": "true",
-      "end_channel": "45055",
-      "display": "false"
-    },
-    "4400": {
-      "title": "",
-      "default_value": "true",
-      "toggle_avail": "false"
-    }
-  },
-  "korea_skt": {
-    "4352": {
-      "title": "",
-      "default_value": "true",
-      "toggle_avail": "false",
-      "end_channel": "4354"
-    },
-    "4356": {
-      "title": "",
-      "default_value": "true",
-      "toggle_avail": "false"
-    },
-    "4370": {
       "title": "위급 재난문자", //"Extreme Emergency Alert",
       "default_value": "true",
-      "toggle_avail": "false"
+      "toggle_avail": "false",
+      "display": "false"
     },
-    "4383": {
+    "40970": {
       "title": "위급 재난문자", //"Extreme Emergency Alert",
       "default_value": "true",
       "toggle_avail": "false",
-      "filter_language": "language_setting"
+      "filter_language": "language_setting",
+      "display": "false"
     },
-    "4371": {
+    "40961": {
       "title": "긴급 재난문자", //"Emergency Alert",
       "default_value": "true",
-      "toggle_avail": "true"
+      "toggle_avail": "true",
+      "display": "false"
     },
-    "4384": {
+    "40971": {
       "title": "긴급 재난문자", //"Emergency Alert",
       "default_value": "true",
       "toggle_avail": "true",
-      "filter_language": "language_setting"
-    },
-    "4372": {
-      "title": "안전 안내문자", //"Public Safety Alert",
-      "default_value": "true",
-      "toggle_avail": "true"
+      "filter_language": "language_setting",
+      "display": "false"
     },
-    "4373": {
+    "40962": {
       "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true",
-      "end_channel": "4378"
-    },
-    "4379": {
-      "title": "실종 경보문자", //"Amber Alert",
-      "default_value": "true",
-      "toggle_avail": "true"
-    },
-    "4392": {
-      "title": "실종 경보문자", //"Amber Alert",
-      "default_value": "true",
-      "toggle_avail": "true",
-      "filter_language": "language_setting"
+      "display": "false"
     },
-    "4385": {
+    "40972": {
       "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true",
-      "filter_language": "language_setting"
-    },
-    "40960": {
-      "title": "안전 안내문자", //"Public Safety Message",
-      "default_value": "true",
-      "toggle_avail": "true",
-      "end_channel": "45055",
+      "filter_language": "language_setting",
       "display": "false"
     },
-    "4400": {
-      "title": "",
-      "default_value": "true",
-      "toggle_avail": "false"
-    }
-  },
-  "korea_lgu": {
-    "4352": {
-      "title": "",
-      "default_value": "true",
-      "toggle_avail": "false",
-      "end_channel": "4354"
-    },
-    "4356": {
-      "title": "",
-      "default_value": "true",
-      "toggle_avail": "false"
-    },
-    "4370": {
-      "title": "위급 재난문자", //"Extreme Emergency Alert",
-      "default_value": "true",
-      "toggle_avail": "false"
-    },
-    "4383": {
-      "title": "위급 재난문자", //"Extreme Emergency Alert",
-      "default_value": "true",
-      "toggle_avail": "false",
-      "filter_language": "language_setting"
-    },
-    "4371": {
-      "title": "긴급 재난문자", //"Emergency Alert",
-      "default_value": "true",
-      "toggle_avail": "true"
-    },
-    "4384": {
-      "title": "긴급 재난문자", //"Emergency Alert",
-      "default_value": "true",
-      "toggle_avail": "true",
-      "filter_language": "language_setting"
-    },
-    "4372": {
-      "title": "안전 안내문자", //"Public Safety Alert",
-      "default_value": "true",
-      "toggle_avail": "true"
-    },
-    "4373": {
-      "title": "안전 안내문자", //"Public Safety Alert",
+    "40969": {
+      "title": "실종 경보문자", //"Amber Alert",
       "default_value": "true",
       "toggle_avail": "true",
-      "end_channel": "4378"
+      "display": "false"
     },
-    "4379": {
+    "40979": {
       "title": "실종 경보문자", //"Amber Alert",
       "default_value": "true",
-      "toggle_avail": "true"
+      "toggle_avail": "true",
+      "filter_language": "language_setting",
+      "display": "false"
     },
-    "4392": {
-      "title": "실종 경보문자", //"Amber Alert",
+    "40963": {
+      "title": "브로드캐스트 메시지", //"Broadcast messages",
       "default_value": "true",
       "toggle_avail": "true",
-      "filter_language": "language_setting"
+      "end_channel": "40968",
+      "display": "false"
     },
-    "4385": {
-      "title": "안전 안내문자", //"Public Safety Alert",
+    "40973": {
+      "title": "브로드캐스트 메시지", //"Broadcast messages",
       "default_value": "true",
       "toggle_avail": "true",
-      "filter_language": "language_setting"
+      "end_channel": "40978",
+      "display": "false"
     },
-    "40960": {
-      "title": "안전 안내문자", //"Public Safety Alert",
+    "40980": {
+      "title": "브로드캐스트 메시지", //"Broadcast messages",
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "45055",
@@ -1263,27 +1179,62 @@
       "toggle_avail": "false"
     },
     "4370": {
-      "title": "RO-Alert: Presidential Alert",
+      "title": "RO-ALERT : Imminent Risk Alert",
+      "default_value": "true",
+      "toggle_avail": "false"
+    },
+    "4383": {
+      "title": "RO-ALERT : Imminent Risk Alert",
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4371": {
-      "title": "RO-Alert: Extreme Alert",
+      "title": "RO-ALERT : Extreme Alert",
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4384": {
+      "title": "RO-ALERT : Extreme Alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4375": {
-      "title": "RO-Alert: Severe Alert",
+      "title": "RO-ALERT : Severe Alert",
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4388": {
+      "title": "RO-ALERT : Severe Alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4379": {
-      "title": "RO-Alert: Missing Child Alert",
+      "title": "RO-ALERT : Missing Child Alert",
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4392": {
+      "title": "RO-ALERT : Missing Child Alert",
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4396": {
+      "title": "RO-ALERT : Public Safety Alert",
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4397": {
+      "title": "RO-ALERT : Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4381": {
-      "title": "RO-Alert: Exercise alert",
+      "title": "RO-ALERT : Exercise Alerts",
+      "default_value": "false",
+      "toggle_avail": "true"
+    },
+    "4394": {
+      "title": "RO-ALERT : Exercise Alerts",
       "default_value": "false",
       "toggle_avail": "true"
     }
@@ -4878,5 +4829,74 @@
       "default_value": "false",
       "toggle_avail": "true"
     }
+  },
+  "Thailand": {
+    "4370": {
+      "title": "การแจ้งเตือนระดับชาติ", // National Alert
+      "default_value": "true",
+      "toggle_avail": "false"
+    },
+    "4383": {
+      "title": "การแจ้งเตือนระดับชาติ", // National Alert
+      "default_value": "true",
+      "toggle_avail": "false"
+    },
+    "4371": {
+      "title": "การแจ้งเตือนภัยขั้นรุนแรง", // Extreme Alert
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4384": {
+      "title": "การแจ้งเตือนภัยขั้นรุนแรง",  // Extreme Alert
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4372": {
+      "title": "การแจ้งเตือนภัยขั้นรุนแรง", // Extreme Alert
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4385": {
+      "title": "การแจ้งเตือนภัยขั้นรุนแรง", // Extreme Alert
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4396": {
+      "title": "การแจ้งเตือนเพื่อให้ข้อมูล", // Informational Alert
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4397": {
+      "title": "การแจ้งเตือนเพื่อให้ข้อมูล", // Informational Alert
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4379": {
+      "title": "การแจ้งเตือนการลักพาตัว", // Amber Alert
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4392": {
+      "title": "การแจ้งเตือนการลักพาตัว", // Amber Alert
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "4380": {
+      "title": "การแจ้งเตือนเพื่อทดสอบระบบ", // Test Alert
+      "default_value": "false",
+      "toggle_avail": "false",
+      "test_mode": "true"
+    },
+    "4393": {
+      "title": "การแจ้งเตือนเพื่อทดสอบระบบ", // Test Alert
+      "default_value": "false",
+      "toggle_avail": "false",
+      "test_mode": "true"
+    },
+    "4400": {
+      "title": "",
+      "default_value": "true",
+      "toggle_avail": "false"
+    }
   }
 }
diff --git a/tests/compliancetests/assets/emergency_alert_settings.json b/tests/compliancetests/assets/emergency_alert_settings.json
index a9e92374d..b8a597bfd 100644
--- a/tests/compliancetests/assets/emergency_alert_settings.json
+++ b/tests/compliancetests/assets/emergency_alert_settings.json
@@ -433,50 +433,6 @@
       "toggle_avail": "true"
     }
   },
-  "korea_skt": {
-    "긴급 재난문자": { //"Emergency Alert"
-      "default_value": "true",
-      "toggle_avail": "true"
-    },
-    "안전 안내문자": { // "Public Safety Alert"
-      "default_value": "true",
-      "toggle_avail": "true"
-    },
-    "실종 경보문자": { // "Amber Alert"
-      "default_value": "true",
-      "toggle_avail": "true"
-    },
-    "진동": { //"Vibration"
-      "default_value": "true",
-      "toggle_avail": "true"
-    },
-    "경보 메시지를 음성으로 알림": { //"Speak alert message"
-      "default_value": "false",
-      "toggle_avail": "true"
-    }
-  },
-  "korea_lgu": {
-    "긴급 재난문자": { //"Emergency Alert"
-      "default_value": "true",
-      "toggle_avail": "true"
-    },
-    "안전 안내문자": { // "Public Safety Alert"
-      "default_value": "true",
-      "toggle_avail": "true"
-    },
-    "실종 경보문자": { // "Amber Alert"
-      "default_value": "true",
-      "toggle_avail": "true"
-    },
-    "진동": { //"Vibration"
-      "default_value": "true",
-      "toggle_avail": "true"
-    },
-    "경보 메시지를 음성으로 알림": { //"Speak alert message"
-      "default_value": "false",
-      "toggle_avail": "true"
-    }
-  },
   "latvia": {
     "Extreme threats": {
       "default_value": "true",
@@ -672,6 +628,10 @@
       "default_value": "true",
       "toggle_avail": "true"
     },
+    "Public Safety Alert": {
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
     "Test alerts": {
       "default_value": "false",
       "toggle_avail": "true"
@@ -748,6 +708,10 @@
     "Vibreur": { //"Vibration": {
       "default_value": "true",
       "toggle_avail": "true"
+    },
+    "Énoncer un message d'alerte": {
+      "default_value": "false",
+      "toggle_avail": "true"
     }
   },
   "us_vzw": {
@@ -778,6 +742,10 @@
     "Spanish": {
       "default_value": "false",
       "toggle_avail": "true"
+    },
+    "Always alert at full volume": {
+      "default_value": "false",
+      "toggle_avail": "true"
     }
   },
   "us_att": {
@@ -812,6 +780,10 @@
     "Spanish": {
       "default_value": "false",
       "toggle_avail": "true"
+    },
+    "Always alert at full volume": {
+      "default_value": "false",
+      "toggle_avail": "true"
     }
   },
   "us_tmo": {
@@ -838,6 +810,10 @@
     "Vibration": {
       "default_value": "true",
       "toggle_avail": "true"
+    },
+    "Always alert at full volume": {
+      "default_value": "false",
+      "toggle_avail": "true"
     }
   },
   "us_dish": {
@@ -872,6 +848,10 @@
     "Spanish": {
       "default_value": "false",
       "toggle_avail": "true"
+    },
+    "Always alert at full volume": {
+      "default_value": "false",
+      "toggle_avail": "true"
     }
   },
   "qatar_vodafone": {
@@ -1012,6 +992,10 @@
     "Spanish": {
       "default_value": "false",
       "toggle_avail": "true"
+    },
+    "Always alert at full volume": {
+      "default_value": "false",
+      "toggle_avail": "true"
     }
   },
   "us_sprint": {
@@ -1042,6 +1026,10 @@
     "Spanish": {
       "default_value": "false",
       "toggle_avail": "true"
+    },
+    "Always alert at full volume": {
+      "default_value": "false",
+      "toggle_avail": "true"
     }
   },
   "us_usc": {
@@ -1076,6 +1064,10 @@
     "Spanish": {
       "default_value": "false",
       "toggle_avail": "true"
+    },
+    "Always alert at full volume": {
+      "default_value": "false",
+      "toggle_avail": "true"
     }
   },
   "azerbaijan": {
@@ -1367,5 +1359,23 @@
       "default_value": "true",
       "toggle_avail": "true"
     }
+  },
+  "Thailand": {
+    "การแจ้งเตือนภัยขั้นรุนแรง": { // Extreme Alert
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "การแจ้งเตือนเพื่อให้ข้อมูล": { // Informational Alert
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "การแจ้งเตือนการลักพาตัว": { // Amber Alert
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "การสั่น": { // Vibration
+      "default_value": "true",
+      "toggle_avail": "true"
+    }
   }
 }
diff --git a/tests/compliancetests/assets/region_plmn_list.json b/tests/compliancetests/assets/region_plmn_list.json
index f57b85450..1b0d50aaa 100644
--- a/tests/compliancetests/assets/region_plmn_list.json
+++ b/tests/compliancetests/assets/region_plmn_list.json
@@ -104,20 +104,10 @@
     "language": "es"
   },
   "korea": {
-    "mccmnc": ["45002"],
+    "mccmnc": ["45002", "45005", "45006"],
     "imsi": "450020123456789",
     "language": "ko"
   },
-  "korea_skt": {
-    "mccmnc": ["45005"],
-    "imsi": "450050123456789",
-    "language": "ko"
-  },
-  "korea_lgu": {
-    "mccmnc": ["45006"],
-    "imsi": "450060123456789",
-    "language": "ko"
-  },
   "canada": {
     "mccmnc": ["302720"],
     "imsi": "302720012345678"
@@ -343,5 +333,10 @@
   "Luxembourg": {
     "mccmnc": ["27001"],
     "imsi": "270010123456789"
+  },
+  "Thailand": {
+    "mccmnc": ["52001"],
+    "imsi": "520010123456789",
+    "language": "th"
   }
 }
diff --git a/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java b/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java
index 0ad5437ca..b8d6dfd61 100644
--- a/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java
+++ b/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java
@@ -154,7 +154,7 @@ public class CellBroadcastBaseTest {
     @BeforeClass
     public static void beforeAllTests() throws Exception {
         logd("CellBroadcastBaseTest#beforeAllTests()");
-        if (!SdkLevel.isAtLeastT()) {
+        if (!SdkLevel.isAtLeastB()) {
             Log.i(TAG, "sdk level is below the latest platform");
             sPreconditionError = ERROR_SDK_VERSION;
             return;
@@ -168,6 +168,14 @@ public class CellBroadcastBaseTest {
             return;
         }
 
+        boolean hasTelephonyCallingFeature =
+                pm.hasSystemFeature("android.hardware.telephony.calling");
+        if (!hasTelephonyCallingFeature) {
+            Log.i(TAG, "Voice Capable Off device");
+            sPreconditionError = ERROR_NO_TELEPHONY;
+            return;
+        }
+
         TelephonyManager tm =
                 (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
         boolean isMultiSim = tm != null && tm.getPhoneCount() > 1;
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastActivityTestCase.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastActivityTestCase.java
index 7a69b8710..354965e8f 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastActivityTestCase.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastActivityTestCase.java
@@ -29,6 +29,7 @@ import android.content.pm.PackageManager;
 import android.content.res.Configuration;
 import android.content.res.Resources;
 import android.os.Handler;
+import android.os.UserHandle;
 import android.test.ActivityUnitTestCase;
 import android.util.Log;
 import android.view.Display;
@@ -130,6 +131,10 @@ public class CellBroadcastActivityTestCase<T extends Activity> extends ActivityU
 
         private SharedPreferences mSharedPreferences;
 
+        Intent mSendBroadcastIntent;
+        UserHandle mUserHandle;
+        String mReceiverPermission;
+
         public TestContext(Context base) {
             super(base);
             mResources = spy(super.getResources());
@@ -205,6 +210,15 @@ public class CellBroadcastActivityTestCase<T extends Activity> extends ActivityU
             return newTestContext;
         }
 
+        @Override
+        public void sendBroadcastAsUser(Intent intent, UserHandle user,
+                String receiverPermission) {
+            mSendBroadcastIntent = intent;
+            mUserHandle = user;
+            mReceiverPermission = receiverPermission;
+            super.sendBroadcastAsUser(intent, user, receiverPermission);
+        }
+
         public void enableOverrideConfiguration(boolean enabled) {
             mIsOverrideConfigurationEnabled = enabled;
         }
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertReminderTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertReminderTest.java
index 2f74bfbd7..0d0441c87 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertReminderTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertReminderTest.java
@@ -99,6 +99,7 @@ public class CellBroadcastAlertReminderTest extends
     public void setUp() throws Exception {
         super.setUp();
         MockitoAnnotations.initMocks(this);
+        doReturn(AudioManager.RINGER_MODE_NORMAL).when(mMockedAudioManager).getRingerMode();
     }
 
     @After
@@ -170,6 +171,49 @@ public class CellBroadcastAlertReminderTest extends
         listenerHandler.quit();
     }
 
+    /**
+     * When the reminder is set to vibrate and DND turn on, vibrate method should not be called.
+     */
+    public void testStartServiceNotVibrateIfDNDModeOn() throws Throwable {
+        doReturn(AudioManager.RINGER_MODE_SILENT).when(mMockedAudioManager).getRingerMode();
+        PhoneStateListenerHandler phoneStateListenerHandler = new PhoneStateListenerHandler(
+                "testStartServiceVibrate",
+                () -> {
+                    Intent intent = new Intent(mContext, CellBroadcastAlertReminder.class);
+                    intent.setAction(CellBroadcastAlertReminder.ACTION_PLAY_ALERT_REMINDER);
+                    intent.putExtra(CellBroadcastAlertReminder.ALERT_REMINDER_VIBRATE_EXTRA,
+                            true);
+                    startService(intent);
+                });
+        phoneStateListenerHandler.start();
+        waitUntilReady();
+
+        verify(mMockedVibrator, never()).vibrate(any(), (AudioAttributes) any());
+        phoneStateListenerHandler.quit();
+    }
+
+    /**
+     * When the reminder is set to vibrate and Ringer mode set to vibrate, vibrate method should be
+     * called once.
+     */
+    public void testStartServiceVibrateIfRingerModeVibrate() throws Throwable {
+        doReturn(AudioManager.RINGER_MODE_VIBRATE).when(mMockedAudioManager).getRingerMode();
+        PhoneStateListenerHandler phoneStateListenerHandler = new PhoneStateListenerHandler(
+                "testStartServiceVibrate",
+                () -> {
+                    Intent intent = new Intent(mContext, CellBroadcastAlertReminder.class);
+                    intent.setAction(CellBroadcastAlertReminder.ACTION_PLAY_ALERT_REMINDER);
+                    intent.putExtra(CellBroadcastAlertReminder.ALERT_REMINDER_VIBRATE_EXTRA,
+                            true);
+                    startService(intent);
+                });
+        phoneStateListenerHandler.start();
+        waitUntilReady();
+
+        verify(mMockedVibrator).vibrate(any(), (AudioAttributes) any());
+        phoneStateListenerHandler.quit();
+    }
+
     public void testQueueAlertReminderReturnFalseIfIntervalNull() {
         doReturn(mSharedPreferences).when(mMockContext).getSharedPreferences(anyString(), anyInt());
         doReturn(null).when(mSharedPreferences).getString(
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastBackupAgentTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastBackupAgentTest.java
index 2d40d38f9..e9357c694 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastBackupAgentTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastBackupAgentTest.java
@@ -30,6 +30,7 @@ import android.os.UserHandle;
 
 import com.android.cellbroadcastreceiver.CellBroadcastBackupAgent;
 import com.android.cellbroadcastreceiver.CellBroadcastInternalReceiver;
+import com.android.modules.utils.build.SdkLevel;
 
 import org.junit.Before;
 import org.junit.Test;
@@ -88,7 +89,11 @@ public class CellBroadcastBackupAgentTest {
 
         ArgumentCaptor<Intent> intentArg = ArgumentCaptor.forClass(Intent.class);
         mBackupAgentUT.onRestoreFinished();
-        verify(mMockContext).sendBroadcastAsUser(intentArg.capture(), eq(UserHandle.SYSTEM));
+        if (SdkLevel.isAtLeastT()) {
+            verify(mMockContext).sendBroadcastAsUser(intentArg.capture(), eq(UserHandle.CURRENT));
+        } else {
+            verify(mMockContext).sendBroadcastAsUser(intentArg.capture(), eq(UserHandle.SYSTEM));
+        }
         assertEquals(packageName, intentArg.getValue().getComponent().getPackageName());
         assertEquals(className, intentArg.getValue().getComponent().getClassName());
     }
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastContentProviderTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastContentProviderTest.java
index 07264e71f..8634d6b71 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastContentProviderTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastContentProviderTest.java
@@ -15,9 +15,10 @@
  */
 package com.android.cellbroadcastreceiver.unit;
 
+import static com.google.common.truth.Truth.assertThat;
+
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.doReturn;
-import static com.google.common.truth.Truth.assertThat;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
@@ -28,6 +29,8 @@ import android.content.pm.PackageManager;
 import android.content.res.Configuration;
 import android.content.res.Resources;
 import android.database.Cursor;
+import android.database.SQLException;
+import android.database.sqlite.SQLiteDatabase;
 import android.net.Uri;
 import android.os.UserManager;
 import android.provider.Telephony.CellBroadcasts;
@@ -39,8 +42,12 @@ import android.telephony.SubscriptionManager;
 import android.test.mock.MockContentResolver;
 import android.test.mock.MockContext;
 import android.util.Log;
+
 import com.android.cellbroadcastreceiver.CellBroadcastDatabaseHelper;
+import com.android.modules.utils.build.SdkLevel;
+
 import junit.framework.TestCase;
+
 import org.junit.Test;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
@@ -200,7 +207,11 @@ public class CellBroadcastContentProviderTest extends TestCase {
     @InstrumentationTest
     public void testWriteSmsInboxBeforeUserUnlock() {
         doReturn(false).when(mUserManager).isUserUnlocked();
-        doReturn(true).when(mUserManager).isSystemUser();
+        if (SdkLevel.isAtLeastU()) {
+            doReturn(true).when(mUserManager).isMainUser();
+        } else {
+            doReturn(true).when(mUserManager).isSystemUser();
+        }
         SmsCbMessage msg = fakeSmsCbMessage();
         mCellBroadcastProviderTestable.insertNewBroadcast(msg);
         // verify does not write message to SMS db
@@ -269,6 +280,31 @@ public class CellBroadcastContentProviderTest extends TestCase {
                 .isEqualTo(CMAS_CERTAINTY);
     }
 
+    @Test
+    @InstrumentationTest
+    public void testDbUpdateOperationsWhenStorageFull() {
+        ExceptionThrowingDatabaseHelper exceptionHelper =
+                new ExceptionThrowingDatabaseHelper(mContext, new SQLException());
+        mCellBroadcastProviderTestable.mOpenHelper = exceptionHelper;
+
+        SmsCbMessage msg = fakeSmsCbMessage();
+        long deliveryTime = msg.getReceivedTime();
+
+        try {
+            mCellBroadcastProviderTestable.markBroadcastRead(CellBroadcasts.DELIVERY_TIME,
+                    deliveryTime);
+        } catch (SQLException e) {
+            fail("must handle the SQLException that occurs when the database is full.");
+        }
+
+        try {
+            mCellBroadcastProviderTestable.markBroadcastSmsSyncPending(CellBroadcasts.DELIVERY_TIME,
+                    deliveryTime, true);
+        } catch (SQLException e) {
+            fail("must handle the SQLException that occurs when the database is full.");
+        }
+    }
+
     /**
      * This is used to give the CellBroadcastContentProviderTest a mocked context which takes a
      * CellBroadcastProvider and attaches it to the ContentResolver.
@@ -314,6 +350,15 @@ public class CellBroadcastContentProviderTest extends TestCase {
             }
         }
 
+        @Override
+        public String getSystemServiceName(Class<?> serviceClass) {
+            if (UserManager.class.equals(serviceClass)) {
+                return Context.USER_SERVICE;
+            }
+            return super.getSystemServiceName(serviceClass);
+        }
+
+
         @Override
         public int checkCallingOrSelfPermission(String permission) {
             return PackageManager.PERMISSION_GRANTED;
@@ -329,4 +374,29 @@ public class CellBroadcastContentProviderTest extends TestCase {
                         CMAS_SEVERITY, CMAS_URGENCY, CMAS_CERTAINTY), 0, null,
                 System.currentTimeMillis(), 1, SubscriptionManager.INVALID_SUBSCRIPTION_ID);
     }
+
+    static class ExceptionThrowingDatabaseHelper extends CellBroadcastDatabaseHelper {
+        private final SQLException mExceptionToThrow;
+
+        ExceptionThrowingDatabaseHelper(Context context, SQLException exception) {
+            super(context, false /* isTestMode */);
+            this.mExceptionToThrow = exception;
+        }
+
+        @Override
+        public SQLiteDatabase getWritableDatabase() {
+            if (mExceptionToThrow != null) {
+                throw mExceptionToThrow;
+            }
+            return super.getWritableDatabase();
+        }
+
+        @Override
+        public SQLiteDatabase getReadableDatabase() {
+            if (mExceptionToThrow != null) {
+                throw mExceptionToThrow;
+            }
+            return super.getReadableDatabase();
+        }
+    }
  }
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastListActivityTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastListActivityTest.java
index 2567562f3..198a5016b 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastListActivityTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastListActivityTest.java
@@ -52,15 +52,16 @@ import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
-import android.app.AlertDialog;
 import android.app.Fragment;
 import android.app.LoaderManager;
 import android.app.NotificationManager;
 import android.content.Context;
 import android.content.pm.PackageManager;
 import android.content.res.Resources;
+import android.content.res.TypedArray;
 import android.database.Cursor;
 import android.database.MatrixCursor;
+import android.graphics.drawable.Drawable;
 import android.os.Build;
 import android.os.Bundle;
 import android.os.Handler;
@@ -80,6 +81,7 @@ import android.view.WindowManager;
 import android.widget.CheckedTextView;
 import android.widget.ListView;
 
+import androidx.appcompat.app.AlertDialog;
 import androidx.test.filters.SdkSuppress;
 import androidx.test.platform.app.InstrumentationRegistry;
 
@@ -88,7 +90,9 @@ import com.android.cellbroadcastreceiver.CellBroadcastListActivity;
 import com.android.cellbroadcastreceiver.CellBroadcastListItem;
 import com.android.cellbroadcastreceiver.R;
 import com.android.internal.view.menu.ContextMenuBuilder;
+import com.android.modules.utils.build.SdkLevel;
 import com.android.settingslib.collapsingtoolbar.CollapsingToolbarBaseActivity;
+import com.android.settingslib.widget.SettingsThemeHelper;
 
 import org.junit.After;
 import org.junit.Before;
@@ -540,7 +544,14 @@ public class CellBroadcastListActivityTest extends
         assertNotNull(activity.mListFragment);
 
         // mock out the AlertDialog.Builder
-        AlertDialog.Builder mockAlertDialogBuilder = getMockAlertDialogBuilder(activity);
+        boolean isHideToolbal = isHideToolbar();
+        AlertDialog.Builder mockAlertDialogBuilder = null;
+        android.app.AlertDialog.Builder mockAlertDialogBuilderOld = null;
+        if (isHideToolbal) {
+            mockAlertDialogBuilderOld = getMockAlertDialogBuilderOld(activity);
+        } else {
+            mockAlertDialogBuilder = getMockAlertDialogBuilder(activity);
+        }
 
         // create mock delete menu item
         MenuItem mockMenuItem = mock(MenuItem.class);
@@ -556,7 +567,12 @@ public class CellBroadcastListActivityTest extends
         activity.mListFragment.getMultiChoiceModeListener().onActionItemClicked(mode, mockMenuItem);
 
         verify(mode, times(1)).finish();
-        verify(mockAlertDialogBuilder, never()).show();
+        if (isHideToolbal) {
+            verify(mockAlertDialogBuilderOld, never()).show();
+
+        } else {
+            verify(mockAlertDialogBuilder, never()).show();
+        }
 
         // mock out the adapter cursor
         Cursor mockCursor = getMockCursor(activity, 1, 0L);
@@ -565,7 +581,12 @@ public class CellBroadcastListActivityTest extends
         activity.mListFragment.getMultiChoiceModeListener().onActionItemClicked(mode, mockMenuItem);
 
         verify(mode, times(2)).finish();
-        verify(mockAlertDialogBuilder).show();
+        if (isHideToolbal) {
+            verify(mockAlertDialogBuilderOld).show();
+
+        } else {
+            verify(mockAlertDialogBuilder).show();
+        }
 
         // getColumnIndex is called 13 times within CellBroadcastCursorAdapter.createFromCursor
         verify(mockCursor, times(13)).getColumnIndex(mColumnCaptor.capture());
@@ -591,8 +612,14 @@ public class CellBroadcastListActivityTest extends
 
         // mock out the adapter cursor and the AlertDialog.Builder
         Cursor mockCursor = getMockCursor(activity, 1, 0L);
-        AlertDialog.Builder mockAlertDialogBuilder = getMockAlertDialogBuilder(activity);
-
+        boolean hideToolbar = isHideToolbar();
+        AlertDialog.Builder mockAlertDialogBuilder = null;
+        android.app.AlertDialog.Builder mockAlertDialogBuilderOld = null;
+        if (hideToolbar) {
+            mockAlertDialogBuilderOld = getMockAlertDialogBuilderOld(activity);
+        } else {
+            mockAlertDialogBuilder = getMockAlertDialogBuilder(activity);
+        }
         // create mock delete menu item
         MenuItem mockMenuItem = mock(MenuItem.class);
         doReturn(MENU_VIEW_DETAILS).when(mockMenuItem).getItemId();
@@ -603,7 +630,11 @@ public class CellBroadcastListActivityTest extends
         // verify the showing the alert dialog
         activity.mListFragment.onContextItemSelected(mockMenuItem);
 
-        verify(mockAlertDialogBuilder).show();
+        if (hideToolbar) {
+            verify(mockAlertDialogBuilderOld).show();
+        } else {
+            verify(mockAlertDialogBuilder).show();
+        }
 
         // getColumnIndex is called 13 times within CellBroadcastCursorAdapter.createFromCursor
         verify(mockCursor, times(13)).getColumnIndex(mColumnCaptor.capture());
@@ -766,7 +797,14 @@ public class CellBroadcastListActivityTest extends
 
         Cursor mockCursor = getMockCursor(activity, 0, 0L);
         doReturn("test").when(mockCursor).getString(anyInt());
-        AlertDialog.Builder mockAlertDialogBuilder = getMockAlertDialogBuilder(activity);
+        boolean hideToolbar = isHideToolbar();
+        AlertDialog.Builder mockAlertDialogBuilder = null;
+        android.app.AlertDialog.Builder mockAlertDialogBuilderOld = null;
+        if (hideToolbar) {
+            mockAlertDialogBuilderOld = getMockAlertDialogBuilderOld(activity);
+        } else {
+            mockAlertDialogBuilder = getMockAlertDialogBuilder(activity);
+        }
 
         // set the LocationCheckTime
         Field fieldCurrentLoaderId =
@@ -789,10 +827,15 @@ public class CellBroadcastListActivityTest extends
 
         // verify the locationCheckTime in dialog's message
         ArgumentCaptor<CharSequence> detailCaptor = ArgumentCaptor.forClass(CharSequence.class);
-        verify(mockAlertDialogBuilder).setMessage(detailCaptor.capture());
+        if (hideToolbar) {
+            verify(mockAlertDialogBuilderOld).setMessage(detailCaptor.capture());
+            verify(mockAlertDialogBuilderOld).show();
+        } else {
+            verify(mockAlertDialogBuilder).setMessage(detailCaptor.capture());
+            verify(mockAlertDialogBuilder).show();
+        }
         assertTrue(detailCaptor.getValue().toString().contains(
                 DateFormat.getDateTimeInstance().format(locationCheckTime)));
-        verify(mockAlertDialogBuilder).show();
     }
 
     public void testOnResume() throws Throwable {
@@ -864,4 +907,43 @@ public class CellBroadcastListActivityTest extends
         activity.mListFragment.mInjectAlertDialogBuilder = mockAlertDialogBuilder;
         return mockAlertDialogBuilder;
     }
+
+    public void testGetThemeCustomStyle() throws Throwable {
+        CellBroadcastListActivity activity = startActivity();
+        Resources.Theme returnedTheme = activity.getTheme();
+        int windowActionModeOverlay = mContext.getResources().getIdentifier(
+                "windowActionModeOverlay", "attr", "android");
+        int actionModeBackground = mContext.getResources().getIdentifier("actionModeBackground",
+                "attr", "android");
+        int[] attrsToObtain = new int[]{
+                windowActionModeOverlay,
+                actionModeBackground
+        };
+        TypedArray typedArray = returnedTheme.obtainStyledAttributes(attrsToObtain);
+        boolean windowActionModeOverlayValue = typedArray.getBoolean(0, false);
+        Drawable actionModeBackgroundDrawableValue = typedArray.getDrawable(1);
+        if (SettingsThemeHelper.isExpressiveTheme(mContext)) {
+            assertTrue(windowActionModeOverlayValue);
+            assertNotNull(actionModeBackgroundDrawableValue);
+        }
+    }
+
+    private android.app.AlertDialog.Builder getMockAlertDialogBuilderOld(
+            CellBroadcastListActivity activity) {
+        android.app.AlertDialog.Builder mockAlertDialogBuilder = mock(
+                android.app.AlertDialog.Builder.class);
+        doReturn(mockAlertDialogBuilder).when(mockAlertDialogBuilder).setTitle(anyInt());
+        doReturn(mockAlertDialogBuilder).when(mockAlertDialogBuilder).setMessage(any());
+        doReturn(mockAlertDialogBuilder).when(mockAlertDialogBuilder).setCancelable(anyBoolean());
+        activity.mListFragment.mInjectAlertDialogBuilderOld = mockAlertDialogBuilder;
+        return mockAlertDialogBuilder;
+    }
+
+    private boolean isHideToolbar() {
+        boolean isWatch = mContext.getPackageManager().hasSystemFeature(
+                PackageManager.FEATURE_WATCH);
+        // for backward compatibility on R devices or wearable devices due to small screen device.
+        boolean hideToolbar = !SdkLevel.isAtLeastS() || isWatch;
+        return hideToolbar;
+    }
 }
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastReceiverTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastReceiverTest.java
index 5c46b282e..e9c439a10 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastReceiverTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastReceiverTest.java
@@ -46,6 +46,7 @@ import android.content.res.Configuration;
 import android.content.res.Resources;
 import android.media.AudioDeviceInfo;
 import android.os.RemoteException;
+import android.os.UserHandle;
 import android.os.UserManager;
 import android.provider.Telephony;
 import android.telephony.CarrierConfigManager;
@@ -60,6 +61,7 @@ import com.android.cellbroadcastreceiver.CellBroadcastListActivity;
 import com.android.cellbroadcastreceiver.CellBroadcastReceiver;
 import com.android.cellbroadcastreceiver.CellBroadcastSettings;
 import com.android.cellbroadcastreceiver.R;
+import com.android.modules.utils.build.SdkLevel;
 
 import org.junit.After;
 import org.junit.Assert;
@@ -83,6 +85,7 @@ public class CellBroadcastReceiverTest extends CellBroadcastTest {
 
     @Mock
     UserManager mUserManager;
+
     @Mock
     Intent mIntent;
     @Mock
@@ -99,6 +102,10 @@ public class CellBroadcastReceiverTest extends CellBroadcastTest {
     SubscriptionManager mSubscriptionManager;
     FakeSharedPreferences mFakeSharedPreferences = new FakeSharedPreferences();
 
+    CellBroadcastReceiver.ActivityManagerProxy mTestActivityManagerProxy;
+
+    CellBroadcastReceiver.ActivityManagerProxy mBackupActivityManagerProxy;
+
     private Configuration mConfiguration = new Configuration();
     private AudioDeviceInfo[] mDevices = new AudioDeviceInfo[0];
     private Object mLock = new Object();
@@ -138,10 +145,22 @@ public class CellBroadcastReceiverTest extends CellBroadcastTest {
         doReturn(mPackageName).when(mContext).getPackageName();
         doReturn(mFakeSharedPreferences).when(mContext).getSharedPreferences(anyString(), anyInt());
         doReturn(mUserManager).when(mContext).getSystemService(Context.USER_SERVICE);
-        doReturn(false).when(mUserManager).isSystemUser();
+        mBackupActivityManagerProxy = CellBroadcastReceiver.sActivityManagerProxy;
+        mTestActivityManagerProxy = mock(CellBroadcastReceiver.ActivityManagerProxy.class);
+        CellBroadcastReceiver.sActivityManagerProxy = mTestActivityManagerProxy;
+        setCurrentUser(false);
         setContext();
     }
 
+    private void setCurrentUser(boolean currentUser) {
+        if (SdkLevel.isAtLeastT()) {
+            int userId = currentUser ? UserHandle.myUserId() : UserHandle.myUserId() + 1;
+            doReturn(userId).when(mTestActivityManagerProxy).getCurrentUser();
+        } else {
+            doReturn(currentUser).when(mUserManager).isSystemUser();
+        }
+    }
+
     @Test
     public void testOnReceive_actionCarrierConfigChanged() {
         doReturn(CarrierConfigManager.ACTION_CARRIER_CONFIG_CHANGED).when(mIntent).getAction();
@@ -235,7 +254,7 @@ public class CellBroadcastReceiverTest extends CellBroadcastTest {
     @Test
     public void testInitializeSharedPreference_ifSystemUser_invalidSub() throws RemoteException {
         doReturn("An invalid action").when(mIntent).getAction();
-        doReturn(true).when(mUserManager).isSystemUser();
+        setCurrentUser(true);
         doReturn(true).when(mCellBroadcastReceiver).sharedPrefsHaveDefaultValues();
         doNothing().when(mCellBroadcastReceiver).adjustReminderInterval();
         mockTelephonyManager();
@@ -267,7 +286,7 @@ public class CellBroadcastReceiverTest extends CellBroadcastTest {
     @Test
     public void testInitializeSharedPreference_ifSystemUser_firstSub() throws Exception {
         doReturn("An invalid action").when(mIntent).getAction();
-        doReturn(true).when(mUserManager).isSystemUser();
+        setCurrentUser(true);
         doReturn(true).when(mCellBroadcastReceiver).sharedPrefsHaveDefaultValues();
         doNothing().when(mCellBroadcastReceiver).adjustReminderInterval();
         mockTelephonyManager();
@@ -300,7 +319,7 @@ public class CellBroadcastReceiverTest extends CellBroadcastTest {
     @Test
     public void testInitializeSharedPreference_ifSystemUser_carrierChange() throws Exception {
         doReturn("An invalid action").when(mIntent).getAction();
-        doReturn(true).when(mUserManager).isSystemUser();
+        setCurrentUser(true);
         doReturn(true).when(mCellBroadcastReceiver).sharedPrefsHaveDefaultValues();
         doNothing().when(mCellBroadcastReceiver).adjustReminderInterval();
         mockTelephonyManager();
@@ -328,11 +347,11 @@ public class CellBroadcastReceiverTest extends CellBroadcastTest {
     }
 
     @Test
-    public void testInitializeSharedPreference_ifNotSystemUser() {
+    public void testInitializeSharedPreference_ifNotSystemUser() throws RemoteException {
         doReturn("An invalid action").when(mIntent).getAction();
-        doReturn(false).when(mUserManager).isSystemUser();
+        setCurrentUser(false);
 
-        mCellBroadcastReceiver.initializeSharedPreference(any(), anyInt());
+        mCellBroadcastReceiver.initializeSharedPreference(mContext, 1);
         assertThat(mFakeSharedPreferences.getValueCount()).isEqualTo(0);
     }
 
@@ -788,8 +807,29 @@ public class CellBroadcastReceiverTest extends CellBroadcastTest {
         }
     }
 
+    @Test
+    public void testOnReceive_userSwitchedAction() {
+        doReturn(CellBroadcastReceiver.ACTION_CELLBROADCAST_USER_SWITCHED)
+                .when(mIntent).getAction();
+
+        setCurrentUser(false);
+        mCellBroadcastReceiver.onReceive(mContext, mIntent);
+        verify(mCellBroadcastReceiver, never()).initializeSharedPreference(any(), anyInt());
+        verify(mCellBroadcastReceiver, never()).startConfigServiceToEnableChannels();
+        verify(mCellBroadcastReceiver, never()).resetCellBroadcastChannelRanges();
+
+        setCurrentUser(true);
+        doReturn(true).when(mCellBroadcastReceiver).sharedPrefsHaveDefaultValues();
+        doNothing().when(mCellBroadcastReceiver).adjustReminderInterval();
+        mCellBroadcastReceiver.onReceive(mContext, mIntent);
+        verify(mCellBroadcastReceiver).initializeSharedPreference(any(), anyInt());
+        verify(mCellBroadcastReceiver).startConfigServiceToEnableChannels();
+        verify(mCellBroadcastReceiver).resetCellBroadcastChannelRanges();
+    }
+
     @After
     public void tearDown() throws Exception {
+        CellBroadcastReceiver.sActivityManagerProxy = mBackupActivityManagerProxy;
         super.tearDown();
     }
 }
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java
index 7478fe16b..2b72b3608 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java
@@ -31,13 +31,17 @@ import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
+import android.app.Instrumentation;
+import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.SharedPreferences;
+import android.content.pm.PackageManager;
 import android.content.res.Configuration;
 import android.content.res.Resources;
 import android.os.Looper;
 import android.os.RemoteException;
+import android.os.UserHandle;
 import android.os.UserManager;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
@@ -51,6 +55,7 @@ import androidx.test.uiautomator.UiDevice;
 
 import com.android.cellbroadcastreceiver.CellBroadcastChannelManager;
 import com.android.cellbroadcastreceiver.CellBroadcastConfigService;
+import com.android.cellbroadcastreceiver.CellBroadcastReceiver;
 import com.android.cellbroadcastreceiver.CellBroadcastSettings;
 import com.android.cellbroadcastreceiver.R;
 import com.android.internal.telephony.CellBroadcastUtils;
@@ -96,6 +101,10 @@ public class CellBroadcastSettingsTest extends
 
     FakeSharedPreferences mFakeSharedPreferences = new FakeSharedPreferences();
 
+    CellBroadcastReceiver.ActivityManagerProxy mTestActivityManagerProxy;
+
+    CellBroadcastReceiver.ActivityManagerProxy mBackupActivityManagerProxy;
+
     public CellBroadcastSettingsTest() {
         super(CellBroadcastSettings.class);
     }
@@ -110,12 +119,16 @@ public class CellBroadcastSettingsTest extends
         injectSystemService(SubscriptionManager.class, mockSubManager);
         SubscriptionInfo mockSubInfo = mock(SubscriptionInfo.class);
         doReturn(mockSubInfo).when(mockSubManager).getActiveSubscriptionInfo(anyInt());
+        mBackupActivityManagerProxy = CellBroadcastReceiver.sActivityManagerProxy;
+        mTestActivityManagerProxy = mock(CellBroadcastReceiver.ActivityManagerProxy.class);
+        CellBroadcastReceiver.sActivityManagerProxy = mTestActivityManagerProxy;
     }
 
     @After
     public void tearDown() throws Exception {
         CellBroadcastSettings.resetResourcesCache();
         CellBroadcastChannelManager.clearAllCellBroadcastChannelRanges();
+        CellBroadcastReceiver.sActivityManagerProxy = mBackupActivityManagerProxy;
         super.tearDown();
     }
 
@@ -202,8 +215,11 @@ public class CellBroadcastSettingsTest extends
         assertFalse(CellBroadcastSettings.hasAnyPreferenceChanged(mContext));
 
         CellBroadcastSettings cellBroadcastSettingActivity = startActivity();
+        waitForMs(100);
 
-        TwoStatePreference speechCheckBox =
+        TwoStatePreference speechCheckBox = !SdkLevel.isAtLeastS()
+                ? cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_ALERT_SPEECH) :
                 cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_ENABLE_ALERT_SPEECH);
         assertNotNull(speechCheckBox);
@@ -219,7 +235,7 @@ public class CellBroadcastSettingsTest extends
         CellBroadcastSettings.CellBroadcastSettingsFragment fragment =
                 new CellBroadcastSettings.CellBroadcastSettingsFragment();
         doReturn(mUserManager).when(mockContext).getSystemService(Context.USER_SERVICE);
-        doReturn(true).when(mUserManager).isSystemUser();
+        setCurrentUser(true);
         doReturn(mMockedSharedPreference).when(mockContext).getSharedPreferences(anyString(),
                 anyInt());
         doReturn(mEditor).when(mMockedSharedPreference).edit();
@@ -377,8 +393,11 @@ public class CellBroadcastSettingsTest extends
                 R.bool.disable_extreme_alert_settings);
 
         CellBroadcastSettings cellBroadcastSettingActivity = startActivity();
+        waitForMs(100);
 
-        TwoStatePreference extremeCheckBox =
+        TwoStatePreference extremeCheckBox = !SdkLevel.isAtLeastS()
+                ? cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_CMAS_EXTREME_THREAT_ALERTS) :
                 cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_ENABLE_CMAS_EXTREME_THREAT_ALERTS);
 
@@ -390,9 +409,15 @@ public class CellBroadcastSettingsTest extends
         doReturn(true).when(mContext.getResources()).getBoolean(
                 R.bool.disable_extreme_alert_settings);
 
-        cellBroadcastSettingActivity.mCellBroadcastSettingsFragment
-                .initAlertsToggleDisabledAsNeeded();
-        cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.onResume();
+        if (!SdkLevel.isAtLeastS()) {
+            cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment
+                    .initAlertsToggleDisabledAsNeeded();
+            cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.onResume();
+        } else {
+            cellBroadcastSettingActivity.mCellBroadcastSettingsFragment
+                    .initAlertsToggleDisabledAsNeeded();
+            cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.onResume();
+        }
 
         assertFalse(extremeCheckBox.isEnabled());
     }
@@ -405,9 +430,13 @@ public class CellBroadcastSettingsTest extends
         setPreference(PREFERENCE_PUT_TYPE_STRING, ROAMING_OPERATOR_SUPPORTED, "XXX");
 
         CellBroadcastSettings settings = startActivity();
+        waitForMs(100);
 
-        Preference topIntroPreference = settings.mCellBroadcastSettingsFragment.findPreference(
-                CellBroadcastSettings.KEY_PREFS_TOP_INTRO);
+        Preference topIntroPreference = !SdkLevel.isAtLeastS()
+                ? settings.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_PREFS_TOP_INTRO) :
+                settings.mCellBroadcastSettingsFragment.findPreference(
+                        CellBroadcastSettings.KEY_PREFS_TOP_INTRO);
         assertEquals(topIntroRoamingText, topIntroPreference.getTitle().toString());
     }
 
@@ -425,10 +454,14 @@ public class CellBroadcastSettingsTest extends
         CellBroadcastSettings settings = startActivity();
         waitForMs(100);
 
-        TwoStatePreference exerciseTestCheckBox =
+        TwoStatePreference exerciseTestCheckBox = !SdkLevel.isAtLeastS()
+                ? settings.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS) :
                 settings.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
-        TwoStatePreference operatorDefinedCheckBox =
+        TwoStatePreference operatorDefinedCheckBox = !SdkLevel.isAtLeastS()
+                ? settings.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS) :
                 settings.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
 
@@ -450,10 +483,14 @@ public class CellBroadcastSettingsTest extends
         CellBroadcastSettings settings = startActivity();
         waitForMs(100);
 
-        TwoStatePreference exerciseTestCheckBox =
+        TwoStatePreference exerciseTestCheckBox = !SdkLevel.isAtLeastS()
+                ? settings.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS) :
                 settings.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
-        TwoStatePreference operatorDefinedCheckBox =
+        TwoStatePreference operatorDefinedCheckBox = !SdkLevel.isAtLeastS()
+                ? settings.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS) :
                 settings.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
 
@@ -479,10 +516,14 @@ public class CellBroadcastSettingsTest extends
         CellBroadcastSettings settings = startActivity();
         waitForMs(100);
 
-        TwoStatePreference exerciseTestCheckBox =
+        TwoStatePreference exerciseTestCheckBox = !SdkLevel.isAtLeastS()
+                ? settings.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS) :
                 settings.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
-        TwoStatePreference operatorDefinedCheckBox =
+        TwoStatePreference operatorDefinedCheckBox = !SdkLevel.isAtLeastS()
+                ? settings.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS) :
                 settings.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
 
@@ -516,30 +557,67 @@ public class CellBroadcastSettingsTest extends
                 R.bool.test_alerts_enabled_default);
 
         CellBroadcastSettings cellBroadcastSettingActivity = startActivity();
+        waitForMs(100);
 
-        TwoStatePreference severeCheckBox =
+        TwoStatePreference severeCheckBox = !SdkLevel.isAtLeastS()
+                ? cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_CMAS_SEVERE_THREAT_ALERTS) :
                 cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_ENABLE_CMAS_SEVERE_THREAT_ALERTS);
-        TwoStatePreference amberCheckBox =
+        TwoStatePreference amberCheckBox = !SdkLevel.isAtLeastS()
+                ? cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_CMAS_AMBER_ALERTS) :
                 cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_ENABLE_CMAS_AMBER_ALERTS);
-        TwoStatePreference testCheckBox =
+        TwoStatePreference testCheckBox = !SdkLevel.isAtLeastS()
+                ? cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_TEST_ALERTS) :
                 cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_ENABLE_TEST_ALERTS);
 
-        cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.setAlertsEnabled(false);
+        if (!SdkLevel.isAtLeastS()) {
+            cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.setAlertsEnabled(false);
+        } else {
+            cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.setAlertsEnabled(false);
+        }
 
         assertFalse(severeCheckBox.isChecked());
         assertFalse(amberCheckBox.isChecked());
         assertFalse(testCheckBox.isChecked());
 
-        cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.setAlertsEnabled(true);
+        if (!SdkLevel.isAtLeastS()) {
+            cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.setAlertsEnabled(true);
+        } else {
+            cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.setAlertsEnabled(true);
+        }
 
         assertTrue(severeCheckBox.isChecked());
         assertTrue(amberCheckBox.isChecked());
         assertTrue(testCheckBox.isChecked());
     }
 
+    @Test
+    public void testNotifyAreaInfoUpdate() throws Throwable {
+        doReturn(false).when(mContext.getResources()).getBoolean(
+                R.bool.test_alerts_enabled_default);
+
+        CellBroadcastSettings cellBroadcastSettingActivity = startActivity();
+        waitForMs(100);
+        if (!SdkLevel.isAtLeastS()) {
+            cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment
+                .setAlertsEnabled(false);
+        } else {
+            cellBroadcastSettingActivity.mCellBroadcastSettingsFragment
+                .setAlertsEnabled(false);
+        }
+
+        assertEquals("com.android.cellbroadcastreceiver.action.AREA_UPDATE_INFO_ENABLED",
+                mContext.mSendBroadcastIntent.getAction());
+        assertEquals(UserHandle.SYSTEM, mContext.mUserHandle);
+        assertEquals("com.android.cellbroadcastservice.FULL_ACCESS_CELL_BROADCAST_HISTORY",
+                mContext.mReceiverPermission);
+    }
+
     @Test
     public void testRestoreToggleToCarrierDefault() throws Throwable {
         doReturn(true).when(mContext.getResources()).getBoolean(
@@ -552,27 +630,102 @@ public class CellBroadcastSettingsTest extends
                 R.bool.test_alerts_enabled_default);
 
         CellBroadcastSettings cellBroadcastSettingActivity = startActivity();
+        waitForMs(100);
 
-        TwoStatePreference severeCheckBox =
+        TwoStatePreference severeCheckBox = !SdkLevel.isAtLeastS()
+                ? cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_CMAS_SEVERE_THREAT_ALERTS) :
                 cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_ENABLE_CMAS_SEVERE_THREAT_ALERTS);
-        TwoStatePreference amberCheckBox =
+        TwoStatePreference amberCheckBox = !SdkLevel.isAtLeastS()
+                ? cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_CMAS_AMBER_ALERTS) :
                 cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_ENABLE_CMAS_AMBER_ALERTS);
-        TwoStatePreference testCheckBox =
+        TwoStatePreference testCheckBox = !SdkLevel.isAtLeastS()
+                ? cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_TEST_ALERTS) :
                 cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_ENABLE_TEST_ALERTS);
 
-        cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.setAlertsEnabled(false);
+        if (!SdkLevel.isAtLeastS()) {
+            cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.setAlertsEnabled(false);
+        } else {
+            cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.setAlertsEnabled(false);
+        }
 
         assertFalse(severeCheckBox.isChecked());
         assertFalse(amberCheckBox.isChecked());
         assertFalse(testCheckBox.isChecked());
 
-        cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.setAlertsEnabled(true);
+        if (!SdkLevel.isAtLeastS()) {
+            cellBroadcastSettingActivity.mCellBroadcastSettingsOldFragment.setAlertsEnabled(true);
+        } else {
+            cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.setAlertsEnabled(true);
+        }
 
         assertTrue(severeCheckBox.isChecked());
         assertTrue(amberCheckBox.isChecked());
         assertFalse(testCheckBox.isChecked());
     }
+
+    @InstrumentationTest
+    @Test
+    public void testFragmentCreationInOnCreateIfNoExistingFragmentToRestore() throws Throwable {
+        try {
+            mDevice.wakeUp();
+            mDevice.pressMenu();
+        } catch (RemoteException exception) {
+            Assert.fail("Exception " + exception);
+        }
+        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
+
+        CellBroadcastSettings activity =
+                (CellBroadcastSettings) instrumentation.startActivitySync(
+                        createActivityIntent());
+        ComponentName activityComponentName = activity.getComponentName();
+        Instrumentation.ActivityMonitor monitor = instrumentation.addMonitor(
+                activityComponentName.getClassName(), null, false);
+        waitForMs(100);
+        if (isHideToolbar()) {
+            assertNotNull(activity.mCellBroadcastSettingsOldFragment);
+        } else {
+            assertNotNull(activity.mCellBroadcastSettingsFragment);
+        }
+
+        try {
+            mDevice.setOrientationLeft();
+
+            CellBroadcastSettings newActivity =
+                    (CellBroadcastSettings) instrumentation.waitForMonitorWithTimeout(
+                            monitor, DEVICE_WAIT_TIME * 5);
+
+            if (isHideToolbar()) {
+                assertNull(newActivity.mCellBroadcastSettingsOldFragment);
+            } else {
+                assertNull(newActivity.mCellBroadcastSettingsFragment);
+            }
+            mDevice.setOrientationNatural();
+            instrumentation.removeMonitor(monitor);
+        } catch (Exception e) {
+            Assert.fail("Exception " + e);
+        }
+    }
+
+    private boolean isHideToolbar() {
+        boolean isWatch = mContext.getPackageManager().hasSystemFeature(
+                PackageManager.FEATURE_WATCH);
+        // for backward compatibility on R devices or wearable devices due to small screen device.
+        boolean hideToolbar = !SdkLevel.isAtLeastS() || isWatch;
+        return hideToolbar;
+    }
+
+    private void setCurrentUser(boolean currentUser) {
+        if (SdkLevel.isAtLeastT()) {
+            int userId = currentUser ? UserHandle.myUserId() : UserHandle.myUserId() + 1;
+            doReturn(userId).when(mTestActivityManagerProxy).getCurrentUser();
+        } else {
+            doReturn(currentUser).when(mUserManager).isSystemUser();
+        }
+    }
 }
```

