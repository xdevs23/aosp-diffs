```diff
diff --git a/Android.bp b/Android.bp
index 4954e3b88..a0c036dea 100644
--- a/Android.bp
+++ b/Android.bp
@@ -19,9 +19,9 @@ android_library {
     name: "CellBroadcastCommon",
     defaults: ["CellBroadcastDefaults"],
     srcs: [
-      "src/**/*.java",
-      ":cellbroadcast-constants-shared-srcs",
-      ":statslog-cellbroadcast-module-java-gen",
+        "src/**/*.java",
+        ":cellbroadcast-constants-shared-srcs",
+        ":statslog-cellbroadcast-module-java-gen",
     ],
     libs: [
         "framework-annotations-lib",
@@ -45,7 +45,7 @@ android_library {
     ],
     resource_dirs: ["res"],
     manifest: "AndroidManifest_Lib.xml",
-    apex_available : [
+    apex_available: [
         "com.android.cellbroadcast",
         "//apex_available:platform",
     ],
@@ -61,6 +61,7 @@ android_app {
     apex_available: ["com.android.cellbroadcast"],
     privapp_allowlist: ":privapp_allowlist_com.android.cellbroadcastreceiver.module.xml",
     resource_dirs: [],
+    updatable: true,
 }
 
 android_app {
@@ -71,7 +72,10 @@ android_app {
     certificate: "platform",
     // CellBroadcastAppPlatform is a replacement for com.android.cellbroadcast apex which consists
     // of CellBroadcastApp
-    overrides: ["com.android.cellbroadcast", "CellBroadcastLegacyApp"],
+    overrides: [
+        "com.android.cellbroadcast",
+        "CellBroadcastLegacyApp",
+    ],
     manifest: "AndroidManifest_Platform.xml",
     system_ext_specific: true,
     privileged: true,
@@ -96,7 +100,8 @@ java_library {
     },
     srcs: ["proto/*.proto"],
     sdk_version: "core_current",
-    apex_available : ["com.android.cellbroadcast",
-                      "//apex_available:platform",
+    apex_available: [
+        "com.android.cellbroadcast",
+        "//apex_available:platform",
     ],
 }
diff --git a/TEST_MAPPING b/TEST_MAPPING
index ad814c866..d1cf88618 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,7 +1,7 @@
 {
   "cellbroadcast-mainline-presubmit": [
     {
-      "name": "GoogleCellBroadcastReceiverUnitTests",
+      "name": "CellBroadcastReceiverMTS",
       "options": [
         {
           "exclude-annotation": "androidx.test.filters.FlakyTest"
@@ -11,7 +11,7 @@
   ],
   "mainline-presubmit": [
     {
-      "name": "GoogleCellBroadcastReceiverUnitTests[com.google.android.cellbroadcast.apex]",
+      "name": "CellBroadcastReceiverMTS[com.google.android.cellbroadcast.apex]",
       "options": [
         {
           "exclude-annotation": "androidx.test.filters.FlakyTest"
@@ -30,7 +30,7 @@
       "keywords": ["internal"]
     },
     {
-      "name": "GoogleCellBroadcastReceiverUnitTests",
+      "name": "CellBroadcastReceiverMTS",
       "options": [
         {
           "exclude-annotation": "androidx.test.filters.FlakyTest"
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index e7cc20519..4b5884d39 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -64,11 +64,11 @@
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"‏تتغير إعدادات نظام WEA التلقائي بناءً على شريحة SIM."</string>
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"السماح بالتنبيهات"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"تلقّي الإشعارات بإنذارات الطوارئ اللاسلكية"</string>
-    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"تذكير التنبيه"</string>
+    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"التذكير بالإنذارات"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"الاستماع إلى رسالة التنبيه"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"استخدام ميزة \"تحويل النص إلى كلام\" للاستماع إلى رسائل إنذارات الطوارئ اللاسلكية"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"سيتم تشغيل صوت تذكير بمستوى صوت منتظم"</string>
-    <string name="emergency_alert_history_title" msgid="8310173569237268431">"سجلّ إنذارات الطوارئ"</string>
+    <string name="emergency_alert_history_title" msgid="8310173569237268431">"سجلّ تنبيهات الطوارئ"</string>
     <string name="alert_preferences_title" msgid="6001469026393248468">"الإعدادات المفضّلة للتنبيهات"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"‏مجموعات البث التجريبية في ETWS"</string>
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"مجموعات البث التجريبية لنظام التحذير المبكر من موجات تسونامي عقب الزلازل"</string>
@@ -76,7 +76,7 @@
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"التهديدات القصوى للحياة والممتلكات"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"التهديدات الخطيرة"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"التهديدات الخطيرة للحياة والممتلكات"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"‏تنبيهات AMBER"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"إنذارات آمبر"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"نشرات طارئة عن اختطاف الأطفال"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"رسائل التنبيه"</string>
     <string name="enable_alert_message_summary" msgid="6525664541696985610">"إرسال تحذير بشأن التهديدات الوشيكة للسلامة"</string>
@@ -89,7 +89,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"إنذارات الطوارئ"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"إرسال تحذير بشأن الأحداث التي تهدد الحياة"</string>
     <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"رسائل تجريبية"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"تلقّي اختبارات مشغّل شبكة الجوّال والاختبارات الشهرية من نظام تنبيهات السلامة"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"تلقّي تنبيهات اختبارية من مشغّل شبكة الجوّال واختبارات شهرية من نظام تنبيهات السلامة"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
     <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"تلقّي تنبيه بحالة طوارئ: رسالة تجريبية"</string>
@@ -141,7 +141,7 @@
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"أنت حاليًا تتلقى إنذارات الطوارئ اللاسلكية. هل تريد مواصلة تلقي إنذارات الطوارئ اللاسلكية؟"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"نعم"</string>
     <string name="cmas_opt_out_button_no" msgid="3110484064328538553">"لا"</string>
-    <string name="cb_list_activity_title" msgid="1433502151877791724">"سجلّ إنذارات الطوارئ"</string>
+    <string name="cb_list_activity_title" msgid="1433502151877791724">"سجلّ تنبيهات الطوارئ"</string>
     <string name="action_delete" msgid="7435661404543945861">"حذف"</string>
     <string name="action_detail_info" msgid="8486524382178381810">"عرض التفاصيل"</string>
   <string-array name="alert_reminder_interval_entries">
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 27e5323e4..1cee2b4be 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -63,7 +63,7 @@
     <string name="notification_channel_broadcast_messages_in_voicecall" msgid="3291001780110813190">"Obaveštenja u hitnim slučajevima tokom glasovnog poziva"</string>
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"Automatske promene podešavanja bežičnih upozorenja o hitnim slučajevima na osnovu SIM-a"</string>
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Dozvoli obaveštenja"</string>
-    <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Šalji mi bežična obaveštenja o hitnim slučajevima"</string>
+    <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Šalji mi obaveštenja o hitnim slučajevima preko mreže"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Podsetnik za obaveštenja"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"Izgovori poruku obaveštenja"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Koristi pretvaranje teksta u govor za izgovaranje poruka bežičnih obaveštenja o hitnim slučajevima"</string>
@@ -100,8 +100,8 @@
     <string name="enable_alert_vibrate_summary" msgid="4733669825477146614"></string>
     <string name="override_dnd_title" msgid="5120805993144214421">"Uvek obaveštavaj punom jačinom zvuka"</string>
     <string name="override_dnd_summary" msgid="9026675822792800258">"Ignoriše Ne uznemiravaj i druga podešavanja jačine zvuka"</string>
-    <string name="enable_area_update_info_alerts_title" msgid="3442042268424617226">"Obaveštenja o ažuriranju područja"</string>
-    <string name="enable_area_update_info_alerts_summary" msgid="6437816607144264910">"Prikazuj informacije o ažuriranju u statusu SIM kartice"</string>
+    <string name="enable_area_update_info_alerts_title" msgid="3442042268424617226">"Emitovanja novosti za područje"</string>
+    <string name="enable_area_update_info_alerts_summary" msgid="6437816607144264910">"Prikaz najnovijih informacija u statusu SIM kartice"</string>
     <string name="cmas_category_heading" msgid="3923503130776640717">"Kategorija upozorenja:"</string>
     <string name="cmas_category_geo" msgid="4979494217069688527">"Geofizička"</string>
     <string name="cmas_category_met" msgid="7563732573851773537">"Meteorološka"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 1ba87eebb..105af9791 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -17,7 +17,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_label" msgid="2008319089248760277">"Абвесткі пра надзвычайныя сітуацыі"</string>
-    <string name="sms_cb_settings" msgid="9021266457863671070">"Абвесткі па бесправадных сетках пра надзвычайныя сітуацыі"</string>
+    <string name="sms_cb_settings" msgid="9021266457863671070">"Экстранныя абвесткі па бесправадных сетках"</string>
     <string name="sms_cb_sender_name_default" msgid="972946539768958828">"Аварыйныя абвесткі па бесправадных сетках"</string>
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Аварыйныя абвесткі па бесправадных сетках"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Аварыйныя абвесткі па бесправадных сетках"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index d983afa30..a38f18131 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -63,7 +63,7 @@
     <string name="notification_channel_broadcast_messages_in_voicecall" msgid="3291001780110813190">"Сигнали при спешни случаи по време на гласово обаждане"</string>
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"Автоматични промени в настройките за WEA въз основа на SIM картата"</string>
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Разрешаване на сигналите"</string>
-    <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Получ. на известия за безж. сигнали при спешност"</string>
+    <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Получаване на известия за безжични сигнали при спешен случай"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Напомняне за сигнал"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"Изговаряне на съобщението"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Използване на синтезиран говор за съобщенията за безжични сигнали при спешни случаи"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 7dfcc03d7..b4dcaa613 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -64,7 +64,7 @@
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"সিমের উপর ভিত্তি করে অটোমেটিক WEA সেটিংস পরিবর্তন হয়"</string>
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"সতর্কতার অনুমতি দিন"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"ওয়্যারলেস জরুরি সতর্কতার বিজ্ঞপ্তি রিসিভ করুন"</string>
-    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"সতর্কতা অনুস্মারক"</string>
+    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"সতর্কতার রিমাইন্ডার"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"সতর্কতা মেসেজ বলুন"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"জরুরি সতর্কতা মেসেজ বলতে টেক্সট-টু-স্পিচ ব্যবহার করুন"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"নির্দিষ্ট সময় অন্তর রিমাইন্ডার শোনা যাবে"</string>
@@ -96,7 +96,7 @@
     <!-- no translation found for enable_operator_defined_test_alerts_title (7459219458579095832) -->
     <skip />
     <string name="enable_operator_defined_test_alerts_summary" msgid="7856514354348843433">"জরুরি সতর্কতা পান: অপারেটর সংক্রান্ত সতর্কতা"</string>
-    <string name="enable_alert_vibrate_title" msgid="5421032189422312508">"কম্পন"</string>
+    <string name="enable_alert_vibrate_title" msgid="5421032189422312508">"ভাইব্রেশন"</string>
     <string name="enable_alert_vibrate_summary" msgid="4733669825477146614"></string>
     <string name="override_dnd_title" msgid="5120805993144214421">"যেকোনও সময়ে বিজ্ঞপ্তি পেতে সম্পূর্ণ ভলিউম দিন"</string>
     <string name="override_dnd_summary" msgid="9026675822792800258">"বিরক্ত করবে না &amp; অন্য ভলিউম সেটিংস এড়িয়ে যান"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 358d0479f..b2638d641 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -68,7 +68,7 @@
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"Læs advarselsmeddelelser op"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Få oplæst beskeder fra mobilbaseret varsling"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"Der afspilles en påmindelseslyd i normal lydstyrke"</string>
-    <string name="emergency_alert_history_title" msgid="8310173569237268431">"Historik for varslinger"</string>
+    <string name="emergency_alert_history_title" msgid="8310173569237268431">"Historik for advarsler"</string>
     <string name="alert_preferences_title" msgid="6001469026393248468">"Præferencer for alarmer"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"Testmeddelelser fra ETWS"</string>
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"Testmeddelelser for ETWS (varslingssystem ved jordskælv og tsunami)"</string>
@@ -141,7 +141,7 @@
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"Du er i øjeblikket tilmeldt mobilbaseret varsling. Vil du fortsætte med at modtage disse?"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"Ja"</string>
     <string name="cmas_opt_out_button_no" msgid="3110484064328538553">"Nej"</string>
-    <string name="cb_list_activity_title" msgid="1433502151877791724">"Historik for varslinger"</string>
+    <string name="cb_list_activity_title" msgid="1433502151877791724">"Historik for advarsler"</string>
     <string name="action_delete" msgid="7435661404543945861">"Slet"</string>
     <string name="action_detail_info" msgid="8486524382178381810">"Vis oplysninger"</string>
   <string-array name="alert_reminder_interval_entries">
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index fe1d1f5fd..569bed0a4 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -105,7 +105,7 @@
     <string name="cmas_category_heading" msgid="3923503130776640717">"Categoría de la alerta:"</string>
     <string name="cmas_category_geo" msgid="4979494217069688527">"Geofísicas"</string>
     <string name="cmas_category_met" msgid="7563732573851773537">"Meteorológicas"</string>
-    <string name="cmas_category_safety" msgid="2986472639641883453">"Seguridad"</string>
+    <string name="cmas_category_safety" msgid="2986472639641883453">"Emergencias"</string>
     <string name="cmas_category_security" msgid="2549520159044403704">"Seguridad"</string>
     <string name="cmas_category_rescue" msgid="4907571719983321086">"Rescates"</string>
     <string name="cmas_category_fire" msgid="3331981591918341119">"Incendios"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 1d760f552..abad776c3 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -172,7 +172,7 @@
     <string name="seconds" msgid="141450721520515025">"sekundit"</string>
     <string name="message_copied" msgid="6922953753733166675">"Sõnum on kopeeritud"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
-    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Kui kasutate rändlust või teil ei ole aktiivset SIM-kaarti, võite näha märguandeid, mida nendes seadetes pole"</string>
+    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Kui kasutate rändlust või teil ei ole aktiivset SIM-kaarti, võite näha märguandeid, mida nendes seadetes pole."</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"Teie seaded muutusid"</string>
     <string name="notification_cb_settings_changed_text" msgid="8722470940705858715">"Eriolukorra raadiosideteatiste seaded lähtestati, sest vahetasite SIM-i"</string>
 </resources>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index a13796166..6d1be85fa 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -64,10 +64,10 @@
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"Hari gabeko larrialdi-alerten ezarpenak automatikoki aldatu dira SIMean oinarrituta"</string>
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Eman alertak erabiltzeko baimena"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Jaso hari gabeko larrialdi-alerten jakinarazpenak"</string>
-    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Alerta-egoeraren abisua"</string>
+    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Alerta-gogorarazpena"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"Irakurri alerta-mezua ozen"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Erabili testua ahots bihurtzeko eginbidea hari gabeko larrialdi-alertak ozen irakurtzeko"</string>
-    <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"Abisu-soinu batek joko du ohiko bolumenean"</string>
+    <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"Gogorarazpen-soinu batek joko du ohiko bolumenean"</string>
     <string name="emergency_alert_history_title" msgid="8310173569237268431">"Larrialdi-alerten historia"</string>
     <string name="alert_preferences_title" msgid="6001469026393248468">"Alerten hobespenak"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"ETWS probako igorpenak"</string>
@@ -136,8 +136,8 @@
     <string name="delivery_time_heading" msgid="5980836543433619329">"Jasota:"</string>
     <string name="notification_multiple" msgid="5121978148152124860">"<xliff:g id="COUNT">%s</xliff:g> alerta dituzu irakurri gabe."</string>
     <string name="notification_multiple_title" msgid="1523638925739947855">"Alerta berriak"</string>
-    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"Erakutsi zerbitzua ez erabiltzeko leihoa lehen alerta jaso ondoren (gobernuaren alerta izan ezik)"</string>
-    <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"Erakutsi ez erabiltzeko leihoa"</string>
+    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"Erakutsi alertak ez jasotzea aukeratzeko leihoa lehena jaso ondoren (gobernuaren alerta izan ezik)"</string>
+    <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"Erakutsi ez jasotzea aukeratzeko leihoa"</string>
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"Aktibatuta daukazu hari gabeko larrialdi-alertak jasotzeko aukera. Halakoak jasotzen jarraitu nahi duzu?"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"Bai"</string>
     <string name="cmas_opt_out_button_no" msgid="3110484064328538553">"Ez"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 5c50d8923..8df4f2012 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -65,7 +65,7 @@
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"اجازه دادن به هشدارها"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"اعلان‌های مربوط به هشدار اضطراری بی‌سیم دریافت شود"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"یادآور هشدار"</string>
-    <string name="enable_alert_speech_title" msgid="8052104771053526941">"گفتن پیام هشدار"</string>
+    <string name="enable_alert_speech_title" msgid="8052104771053526941">"بلند خواندن پیام هشدار"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"برای گفتن پیام‌های هشدار اضطراری بی‌سیم از «نوشتار به گفتار» استفاده کنید"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"صدای یادآوری با میزان صدای معمول پخش می‌شود"</string>
     <string name="emergency_alert_history_title" msgid="8310173569237268431">"سابقه هشدار اضطراری"</string>
@@ -100,7 +100,7 @@
     <string name="enable_alert_vibrate_summary" msgid="4733669825477146614"></string>
     <string name="override_dnd_title" msgid="5120805993144214421">"همیشه با بیشترین میزان صدا هشدار داده شود"</string>
     <string name="override_dnd_summary" msgid="9026675822792800258">"نادیده گرفتن «مزاحم نشوید» و دیگر تنظیمات میزان صدا"</string>
-    <string name="enable_area_update_info_alerts_title" msgid="3442042268424617226">"پخش‌های به‌روزرسانی منطقه"</string>
+    <string name="enable_area_update_info_alerts_title" msgid="3442042268424617226">"پخش به‌روزرسانی‌های خاص منطقه"</string>
     <string name="enable_area_update_info_alerts_summary" msgid="6437816607144264910">"نمایش اطلاعات به‌روزرسانی در وضعیت سیم‌کارت"</string>
     <string name="cmas_category_heading" msgid="3923503130776640717">"دسته هشدار:"</string>
     <string name="cmas_category_geo" msgid="4979494217069688527">"ژئوفیزیکی"</string>
@@ -137,7 +137,7 @@
     <string name="notification_multiple" msgid="5121978148152124860">"<xliff:g id="COUNT">%s</xliff:g> هشدار خوانده نشده."</string>
     <string name="notification_multiple_title" msgid="1523638925739947855">"هشدارهای جدید"</string>
     <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"نمایش کادر گفتگوی امکان انصراف، پس از نمایش اولین هشدار (غیر از هشدار رياست جمهوری)."</string>
-    <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"نمایش گفتگوی انصراف"</string>
+    <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"نمایش کادر گفتگوی انصراف"</string>
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"درحال‌حاضر، هشدارهای اضطراری بی‌سیم را دریافت می‌کنید. مایلید همچنان هشدارهای اضطراری بی‌سیم را دریافت کنید؟"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"بله"</string>
     <string name="cmas_opt_out_button_no" msgid="3110484064328538553">"نه"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 5a738fbca..9c8527377 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -68,7 +68,7 @@
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"Puhu varoitusilmoitus"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Käytä tekstistä puheeksi -toimintoa langattomissa vaaratiedotteissa"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"Muistutusääni soi tavallisella äänenvoimakkuudella"</string>
-    <string name="emergency_alert_history_title" msgid="8310173569237268431">"Hätävaroitushistoria"</string>
+    <string name="emergency_alert_history_title" msgid="8310173569237268431">"Hätähälytyshistoria"</string>
     <string name="alert_preferences_title" msgid="6001469026393248468">"Hälytysasetukset"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"ETWS-testilähetykset"</string>
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"Maanjäristys- ja tsunamivaroitusjärjestelmän koelähetykset"</string>
@@ -141,7 +141,7 @@
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"Vastaanotat tällä hetkellä langattomia hätähälytyksiä. Haluatko jatkaa langattomien hätähälytysten vastaanottamista?"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"Kyllä"</string>
     <string name="cmas_opt_out_button_no" msgid="3110484064328538553">"Ei"</string>
-    <string name="cb_list_activity_title" msgid="1433502151877791724">"Hätävaroitushistoria"</string>
+    <string name="cb_list_activity_title" msgid="1433502151877791724">"Hätähälytyshistoria"</string>
     <string name="action_delete" msgid="7435661404543945861">"Poista"</string>
     <string name="action_detail_info" msgid="8486524382178381810">"Näytä tiedot"</string>
   <string-array name="alert_reminder_interval_entries">
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 789662f05..d73bf7006 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -77,7 +77,7 @@
     <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"ગંભીર જોખમો"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"જીવન અને સંપત્તિના ગંભીર જોખમો"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"AMBER અલર્ટ"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"બાળ અપહરણની કટોકટીના બુલેટિન"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"બાળ અપહરણની ઇમર્જન્સી બુલેટિન"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"અલર્ટ મેસેજ"</string>
     <string name="enable_alert_message_summary" msgid="6525664541696985610">"નિકટવર્તી સલામતી જોખમો વિશે ચેતવો"</string>
     <string name="enable_public_safety_messages_title" msgid="5576770949182656524">"સાર્વજનિક સુરક્ષા મેસેજ"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 449d46997..3a020a1ba 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -62,13 +62,13 @@
     <string name="notification_channel_emergency_alerts_high_priority" msgid="3937475297436439073">"अस्वीकार की गई आपातकालीन चेतावनियां"</string>
     <string name="notification_channel_broadcast_messages_in_voicecall" msgid="3291001780110813190">"वॉयस कॉल के दौरान आपातकालीन चेतावनियां"</string>
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"अपने-आप काम करने वाली WEA की सूचनाओं की सेटिंग, सिम के हिसाब से बदल जाती है"</string>
-    <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"खतरे की चेतावनी दिखाए जाने की अनुमति दें"</string>
-    <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"वायरलेस इमरजेंसी अलर्ट की सूचनाएं पाएं"</string>
-    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"खतरे से जु़ड़ी चेतावनी का रिमाइंडर"</string>
-    <string name="enable_alert_speech_title" msgid="8052104771053526941">"अलर्ट मैसेज बोलें"</string>
+    <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"चेतावनी दिखाने की अनुमति दें"</string>
+    <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"खतरे की चेतावनी से जुड़ी सूचनाएं पाएं"</string>
+    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"चेतावनी का रिमाइंडर"</string>
+    <string name="enable_alert_speech_title" msgid="8052104771053526941">"चेतावनी वाले मैसेज की जानकारी बोलकर दें"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"वायरलेस इमरजेंसी अलर्ट वाला मैसेज बोलने के लिए लिखाई को बोली में बदलने की सुविधा इस्तेमाल करें"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"रिमाइंडर की आवाज़ सामान्य रहेगी"</string>
-    <string name="emergency_alert_history_title" msgid="8310173569237268431">"आपातकालीन चेतावनियों का इतिहास"</string>
+    <string name="emergency_alert_history_title" msgid="8310173569237268431">"खतरे की चेतावनियों का इतिहास"</string>
     <string name="alert_preferences_title" msgid="6001469026393248468">"खतरे की चेतावनियों की सेटिंग"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"ETWS परीक्षण प्रसारण"</string>
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"भूकंप सुनामी चेतावनी सिस्‍टम के लिए परीक्षण प्रसारण"</string>
@@ -101,7 +101,7 @@
     <string name="override_dnd_title" msgid="5120805993144214421">"हमेशा सबसे तेज़ आवाज़ (फ़ुल वॉल्यूम) में सूचना दें"</string>
     <string name="override_dnd_summary" msgid="9026675822792800258">"\'परेशान न करें\' मोड और आवाज़ की अन्य सेटिंग को अनदेखा करें"</string>
     <string name="enable_area_update_info_alerts_title" msgid="3442042268424617226">"मौजूदा इलाके की जानकारी से जुड़े ब्रॉडकास्ट"</string>
-    <string name="enable_area_update_info_alerts_summary" msgid="6437816607144264910">"सिम के स्टेटस में अपडेट की गई जानकारी दिखाएं"</string>
+    <string name="enable_area_update_info_alerts_summary" msgid="6437816607144264910">"इलाके की जानकारी, सिम के स्टेटस में दिखाएं"</string>
     <string name="cmas_category_heading" msgid="3923503130776640717">"अलर्ट श्रेणी:"</string>
     <string name="cmas_category_geo" msgid="4979494217069688527">"भूभौतिकीय"</string>
     <string name="cmas_category_met" msgid="7563732573851773537">"मौसम संबंधी"</string>
@@ -136,8 +136,8 @@
     <string name="delivery_time_heading" msgid="5980836543433619329">"पाया:"</string>
     <string name="notification_multiple" msgid="5121978148152124860">"<xliff:g id="COUNT">%s</xliff:g> बिना पढ़े अलर्ट."</string>
     <string name="notification_multiple_title" msgid="1523638925739947855">"नए अलर्ट"</string>
-    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"पहला अलर्ट (प्रेसिडेंशियल अलर्ट के अलावा) दिखाने के बाद, ऑप्ट-आउट डायलॉग दिखाएं."</string>
-    <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"ऑप्ट-आउट डॉयलॉग दिखाएं"</string>
+    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"पहला अलर्ट (प्रेसिडेंशियल अलर्ट के अलावा) दिखाने के बाद, ऑप्ट-आउट करने से जुड़ा डायलॉग दिखाएं."</string>
+    <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"ऑप्ट-आउट करने से जुड़ा डायलॉग दिखाएं"</string>
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"फ़िलहाल, आपको वायरलेस इमरजेंसी अलर्ट की सूचनाएं भेजी जा रही हैं. क्या आप वायरलेस इमरजेंसी अलर्ट की सूचनाएं आगे भी पाना चाहेंगे?"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"हां"</string>
     <string name="cmas_opt_out_button_no" msgid="3110484064328538553">"नहीं"</string>
@@ -172,7 +172,7 @@
     <string name="seconds" msgid="141450721520515025">"सेकंड"</string>
     <string name="message_copied" msgid="6922953753733166675">"मैसेज कॉपी किया गया"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
-    <string name="top_intro_roaming_text" msgid="5250650823028195358">"रोमिंग में होने के दौरान या कोई चालू सिम न होने पर, आपको ऐसी सूचनाएं मिल सकती हैं जो इन सेटिंग में शामिल नहीं हैं"</string>
+    <string name="top_intro_roaming_text" msgid="5250650823028195358">"रोमिंग में होने के दौरान या कोई चालू सिम न होने पर, आपको कुछ ऐसी चेतावनियां भी मिल सकती हैं जो इन सेटिंग में शामिल नहीं हैं"</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"सेटिंग में बदलाव किया गया"</string>
     <string name="notification_cb_settings_changed_text" msgid="8722470940705858715">"सिम बदलने की वजह से, खतरे की चेतावनी देने वाली सेटिंग को रीसेट किया गया"</string>
 </resources>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index ae771e870..c8efc4c61 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -65,7 +65,7 @@
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Dopusti upozorenja"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Primajte obavijesti o hitnim upozorenjima putem bežične mreže"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Podsjetnik upozorenja"</string>
-    <string name="enable_alert_speech_title" msgid="8052104771053526941">"Izgovaranje poruka upozorenja"</string>
+    <string name="enable_alert_speech_title" msgid="8052104771053526941">"Izgovori poruku upozorenja"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Koristi pretvaranje teksta u govor za izgovaranje poruka hitnih upozorenja putem bežične mreže"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"Zvuk podsjetnika bit će uobičajene glasnoće"</string>
     <string name="emergency_alert_history_title" msgid="8310173569237268431">"Povijest hitnih upozorenja"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 5db5d681c..a2b8dcbf0 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -88,7 +88,7 @@
     <string name="enable_state_local_test_alerts_summary" msgid="780298327377950187">"Terima pesan percobaan dari otoritas negara bagian atau lokal"</string>
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"Peringatan darurat"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"Peringatkan tentang peristiwa yang mengancam jiwa"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"Uji peringatan"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"Peringatan uji coba"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Terima pengujian operator dan pengujian bulanan dari sistem peringatan keselamatan"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
@@ -101,7 +101,7 @@
     <string name="override_dnd_title" msgid="5120805993144214421">"Selalu ingatkan dengan volume penuh"</string>
     <string name="override_dnd_summary" msgid="9026675822792800258">"Abaikan fitur Jangan Ganggu &amp; setelan volume lainnya"</string>
     <string name="enable_area_update_info_alerts_title" msgid="3442042268424617226">"Siaran update area"</string>
-    <string name="enable_area_update_info_alerts_summary" msgid="6437816607144264910">"Tampilan informasi update di status SIM"</string>
+    <string name="enable_area_update_info_alerts_summary" msgid="6437816607144264910">"Tampilkan informasi update di status SIM"</string>
     <string name="cmas_category_heading" msgid="3923503130776640717">"Kategori Notifikasi:"</string>
     <string name="cmas_category_geo" msgid="4979494217069688527">"Geofisika"</string>
     <string name="cmas_category_met" msgid="7563732573851773537">"Meteorologi"</string>
@@ -136,8 +136,8 @@
     <string name="delivery_time_heading" msgid="5980836543433619329">"Diterima:"</string>
     <string name="notification_multiple" msgid="5121978148152124860">"<xliff:g id="COUNT">%s</xliff:g> peringatan belum dibaca."</string>
     <string name="notification_multiple_title" msgid="1523638925739947855">"Peringatan baru"</string>
-    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"Tunjukkan dialog menolak ikut serta setelah notifikasi pertama tampil (selain Notifikasi Presidensial)."</string>
-    <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"Tunjukkan dialog pilihan tidak ikut"</string>
+    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"Tampilkan dialog pilihan tidak ikut setelah peringatan pertama (selain Peringatan Kepresidenan)."</string>
+    <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"Tampilkan dialog pilihan tidak ikut"</string>
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"Saat ini Anda menerima peringatan darurat nirkabel. Ingin terus menerima peringatan darurat nirkabel?"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"Ya"</string>
     <string name="cmas_opt_out_button_no" msgid="3110484064328538553">"Tidak"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 04aeb31fb..bac0b45b7 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -64,7 +64,7 @@
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"Le impostazioni WEA automatiche cambiano in base alla SIM"</string>
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Consenti avvisi"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Ricevi notifiche per avvisi di emergenza wireless"</string>
-    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Promemoria allerte"</string>
+    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Promemoria avvisi"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"Leggimi messaggio di allerta"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Usa la sintesi vocale per leggermi i messaggi degli avvisi di emergenza wireless"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"Verrà riprodotto un suono di promemoria a volume normale"</string>
@@ -88,8 +88,8 @@
     <string name="enable_state_local_test_alerts_summary" msgid="780298327377950187">"Ricevi messaggi di prova da autorità statali e locali"</string>
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"Avvisi di emergenza"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"Avvisi relativi a eventi potenzialmente letali"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"Allerte di prova"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Ricevi test dell\'operatore e test mensili dal sistema di allerte relative alla sicurezza"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"Avvisi di prova"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Ricevi test dell\'operatore e test mensili dal sistema di avvisi relativi alla sicurezza"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
     <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"Ricevi avviso di emergenza: messaggio di esercitazione"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 8aaa6b5bf..1ac4a58e5 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -65,7 +65,7 @@
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"הצגת התרעות"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"קבלת התרעות אלחוטיות על מקרי חירום"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"תזכורת להתרעות"</string>
-    <string name="enable_alert_speech_title" msgid="8052104771053526941">"הודעת התראה תושמע בקול"</string>
+    <string name="enable_alert_speech_title" msgid="8052104771053526941">"הודעות התרעה יושמעו בקול"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"‏שימוש בהמרת טקסט לדיבור (TTS) להקראה של התרעות אלחוטיות על מקרי חירום"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"צליל תזכורת יושמע בעוצמת קול רגילה"</string>
     <string name="emergency_alert_history_title" msgid="8310173569237268431">"היסטוריה של התרעות חירום"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 81be82427..18e8a146b 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -76,7 +76,7 @@
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"命や財産に関わる極めて重大な脅威"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"重大な脅威"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"命や財産に関わる重大な脅威"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"誘拐事件速報"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"アンバー アラート"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"児童誘拐警報の速報"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"警告メッセージ"</string>
     <string name="enable_alert_message_summary" msgid="6525664541696985610">"差し迫った安全上の脅威に関する警告"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index e981e0263..c61bb45e0 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -72,10 +72,10 @@
     <string name="alert_preferences_title" msgid="6001469026393248468">"Хабарландыру параметрлері"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"ETWS сынақ таратылымдары"</string>
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"Earthquake Tsunami Warning System жүйесі үшін сынақ таратылымдарын көрсету"</string>
-    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5416260219062637770">"Үлкен қауіптер"</string>
-    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"Өмірге және мүлікке төнген үлкен қауіптер"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"Ауыр қауіптер"</string>
-    <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"Өмірге және мүлікке төнген ауыр қауіптер"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5416260219062637770">"Аса үлкен қауіптер"</string>
+    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"Өмірге және мүлікке төнген аса үлкен қауіптер"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"Үлкен қауіптер"</string>
+    <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"Өмірге және мүлікке төнген үлкен қауіптер"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"AMBER хабарландырулары"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"Жоғалған балалар туралы хабарлар"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"Ескерту хабарлары"</string>
diff --git a/res/values-mcc208-kk/strings.xml b/res/values-mcc208-kk/strings.xml
index 1faa379ff..8df551fa7 100644
--- a/res/values-mcc208-kk/strings.xml
+++ b/res/values-mcc208-kk/strings.xml
@@ -24,9 +24,9 @@
     <string name="cmas_required_monthly_test" msgid="3216225136685938963">"FR-ALERT сынақ"</string>
     <string name="cmas_exercise_alert" msgid="6540820517122545556">"Fr-ALERT Жаттығу"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="1268433786689479357">"Үлкен қатер туралы хабарландырулар (2-деңгей)"</string>
-    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6125474083043183037">"Үлкен қатер туралы хабарландыруларды көрсету"</string>
+    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6125474083043183037">"Аса үлкен қауіп туралы хабарландыруларды көрсету"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="6185770513604614548">"Айтарлықтай қатер туралы хабарландырулар (3-деңгей)"</string>
-    <string name="enable_cmas_severe_threat_alerts_summary" msgid="3073259381449390054">"Айтарлықтай қатерлер туралы хабарландыруларды көрсету"</string>
+    <string name="enable_cmas_severe_threat_alerts_summary" msgid="3073259381449390054">"Үлкен қауіптер туралы хабарландыруларды көрсету"</string>
     <string name="enable_public_safety_messages_title" msgid="4231398452970069457">"Ескерту (4-деңгей)"</string>
     <string name="enable_public_safety_messages_summary" msgid="1691623841627340948">"Ескерту хабарларын көрсету"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="4087727029650572978">"Ұрлап кету туралы хабарландыру"</string>
diff --git a/res/values-mcc208-my/strings.xml b/res/values-mcc208-my/strings.xml
index 258e3b699..f10cd1ff2 100644
--- a/res/values-mcc208-my/strings.xml
+++ b/res/values-mcc208-my/strings.xml
@@ -24,7 +24,7 @@
     <string name="cmas_required_monthly_test" msgid="3216225136685938963">"FR-ALERT စမ်းသပ်ချက်"</string>
     <string name="cmas_exercise_alert" msgid="6540820517122545556">"Fr-ALERT လေ့ကျင့်ခန်း"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="1268433786689479357">"အရေးပေါ် သတိပေးချက်များ (အဆင့် ၂)"</string>
-    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6125474083043183037">"ဆိုးရွားသည့် ခြိမ်းခြောက်မှုများအတွက် သတိပေးမက်ဆေ့ဂျ်များ ပြရန်"</string>
+    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6125474083043183037">"လွန်ကဲ အန္တရာယ်များအတွက် သတိပေးမက်ဆေ့ဂျ်များ ပြရန်"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="6185770513604614548">"အထူးအရေးပေါ် သတိပေးချက်များ (အဆင့် ၃)"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="3073259381449390054">"ဆိုးရွားလွန်းသည့် ခြိမ်းခြောက်မှုများအတွက် သတိပေးမက်ဆေ့ဂျ်များ ပြရန်"</string>
     <string name="enable_public_safety_messages_title" msgid="4231398452970069457">"သတိပေးချက် (အဆင့် ၄)"</string>
diff --git a/res/values-mcc208-pt/strings.xml b/res/values-mcc208-pt/strings.xml
index 86209ebfe..29d55cf45 100644
--- a/res/values-mcc208-pt/strings.xml
+++ b/res/values-mcc208-pt/strings.xml
@@ -26,7 +26,7 @@
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="1268433786689479357">"Alertas extremos (nível 2)"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6125474083043183037">"Mostrar mensagens de alerta para ameaças extremas"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="6185770513604614548">"Ameaças graves (nível 3)"</string>
-    <string name="enable_cmas_severe_threat_alerts_summary" msgid="3073259381449390054">"Mostrar mensagens de alerta para ameaças graves"</string>
+    <string name="enable_cmas_severe_threat_alerts_summary" msgid="3073259381449390054">"Mostrar mensagens de alerta severo"</string>
     <string name="enable_public_safety_messages_title" msgid="4231398452970069457">"Alerta (nível 4)"</string>
     <string name="enable_public_safety_messages_summary" msgid="1691623841627340948">"Mostrar mensagens de alerta"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="4087727029650572978">"Alerta de sequestro"</string>
diff --git a/res/values-mcc232-pt/strings.xml b/res/values-mcc232-pt/strings.xml
index 419d2dd9e..ee335de6d 100644
--- a/res/values-mcc232-pt/strings.xml
+++ b/res/values-mcc232-pt/strings.xml
@@ -17,15 +17,15 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Alerta de emergência"</string>
-    <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ameaça extrema"</string>
-    <string name="cmas_severe_alert" msgid="628940584325136759">"Ameaça grave"</string>
+    <string name="cmas_extreme_alert" msgid="9122792746957924456">"Alerta extremo"</string>
+    <string name="cmas_severe_alert" msgid="628940584325136759">"Alerta severo"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informações sobre a ameaça"</string>
     <string name="cmas_amber_alert" msgid="404589837946037736">"Busca de pessoas desaparecidas"</string>
     <string name="state_local_test_alert" msgid="3774161961273584245">"Alerta de teste"</string>
     <string name="cmas_exercise_alert" msgid="4845005677469935113">"Alarme de teste"</string>
     <string name="cmas_required_monthly_test" msgid="8386390153236774475">"Teste de transmissão celular"</string>
-    <string name="enable_cmas_extreme_threat_alerts_title" msgid="2361635321508611596">"Ameaça extrema"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="1718166777595485623">"Ameaça grave"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="2361635321508611596">"Alerta extremo"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="1718166777595485623">"Alerta severo"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="3125202178531035580">"Pessoas desaparecidas"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5252326889751639729">"Busca de pessoas desaparecidas"</string>
     <string name="enable_public_safety_messages_title" msgid="3974955568145658404">"Informações sobre a ameaça"</string>
diff --git a/res/values-mcc234-in/strings.xml b/res/values-mcc234-in/strings.xml
index 5b285a562..084e2ebda 100644
--- a/res/values-mcc234-in/strings.xml
+++ b/res/values-mcc234-in/strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="8511466399220042295">"Peringatan ekstrem"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="2271741871998936543">"Peringatan serius"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="6022925848643811044">"Peringatan pengujian"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="6022925848643811044">"Peringatan uji coba"</string>
     <string name="enable_exercise_test_alerts_title" msgid="411880452689537935">"Peringatan latihan"</string>
     <string name="cmas_presidential_level_alert" msgid="3429191761649839884">"Peringatan Pemerintah"</string>
     <string name="cmas_extreme_alert" msgid="3474352706075109113">"Peringatan Ekstrem"</string>
diff --git a/res/values-mcc234-it/strings.xml b/res/values-mcc234-it/strings.xml
index 6771a1374..2e2488292 100644
--- a/res/values-mcc234-it/strings.xml
+++ b/res/values-mcc234-it/strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="8511466399220042295">"Allerte per condizioni estreme"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="2271741871998936543">"Allerte per condizioni gravi"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="6022925848643811044">"Allerte di prova"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="6022925848643811044">"Avvisi di prova"</string>
     <string name="enable_exercise_test_alerts_title" msgid="411880452689537935">"Simulazioni di avvisi"</string>
     <string name="cmas_presidential_level_alert" msgid="3429191761649839884">"Allerta governativa"</string>
     <string name="cmas_extreme_alert" msgid="3474352706075109113">"Allerta per condizioni estreme"</string>
diff --git a/res/values-mcc234-iw/strings.xml b/res/values-mcc234-iw/strings.xml
index 9406d8e94..ef183d57e 100644
--- a/res/values-mcc234-iw/strings.xml
+++ b/res/values-mcc234-iw/strings.xml
@@ -36,5 +36,5 @@
     <string name="enable_cmas_test_alerts_summary" msgid="2931455154355509465">"קבלת התראות בדיקה ממערכת ההתראה על מקרה חירום"</string>
     <string name="cmas_opt_out_dialog_text" msgid="1972978578760513449">"ההגדרה שלך עכשיו היא לקבל התרעות על מקרי חירום. האם ברצונך להמשיך לקבל התרעות על מקרי חירום?"</string>
     <string name="emergency_alert_settings_title_watches" msgid="5299419351642118203">"התרעות על מצב חירום"</string>
-    <string name="notification_cb_settings_changed_text" msgid="6861845802821634203">"יש להקיש כדי לראות את ההגדרות של ההתרעות על מקרי חירום"</string>
+    <string name="notification_cb_settings_changed_text" msgid="6861845802821634203">"יש ללחוץ כדי לראות את ההגדרות של ההתרעות על מקרי חירום"</string>
 </resources>
diff --git a/res/values-mcc234-sk/strings.xml b/res/values-mcc234-sk/strings.xml
index 79558ab39..ccce1da1f 100644
--- a/res/values-mcc234-sk/strings.xml
+++ b/res/values-mcc234-sk/strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="8511466399220042295">"Upozornenia na extrémne situácie"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="2271741871998936543">"Závažné upozornenia"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="6022925848643811044">"Testovacie upozornenia"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="6022925848643811044">"Testovacie výstrahy"</string>
     <string name="enable_exercise_test_alerts_title" msgid="411880452689537935">"Cvičné upozornenia"</string>
     <string name="cmas_presidential_level_alert" msgid="3429191761649839884">"Upozornenie verejnej správy"</string>
     <string name="cmas_extreme_alert" msgid="3474352706075109113">"Upozornenie na extrémnu situáciu"</string>
diff --git a/res/values-mcc262-pt/strings.xml b/res/values-mcc262-pt/strings.xml
index d023f339b..4ce97c8b9 100644
--- a/res/values-mcc262-pt/strings.xml
+++ b/res/values-mcc262-pt/strings.xml
@@ -17,15 +17,15 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_presidential_level_alert" msgid="2107659575955828996">"Alarme de emergência"</string>
-    <string name="cmas_extreme_alert" msgid="3655071721612807998">"Ameaça extrema"</string>
-    <string name="cmas_severe_alert" msgid="8204679766209106041">"Ameaça grave"</string>
+    <string name="cmas_extreme_alert" msgid="3655071721612807998">"Alerta extremo"</string>
+    <string name="cmas_severe_alert" msgid="8204679766209106041">"Alerta severo"</string>
     <string name="public_safety_message" msgid="8870933058203924990">"Informações sobre a ameaça"</string>
     <string name="state_local_test_alert" msgid="4208083984152605275">"Alerta de teste"</string>
     <string name="cmas_operator_defined_alert" msgid="7554916428554204737">"Reservado à UE"</string>
     <string name="cmas_exercise_alert" msgid="9166953612111508567">"Alarme de teste"</string>
     <string name="cmas_required_monthly_test" msgid="5030077310729851915">"Teste de transmissão celular"</string>
-    <string name="enable_cmas_extreme_threat_alerts_title" msgid="140477407513377226">"Ameaça extrema"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="2244702687286589592">"Ameaça grave"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="140477407513377226">"Alerta extremo"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="2244702687286589592">"Alerta severo"</string>
     <string name="enable_public_safety_messages_title" msgid="9081684819449444846">"Informações sobre a ameaça"</string>
     <string name="enable_state_local_test_alerts_title" msgid="2160210558920782153">"Alerta de teste"</string>
     <string name="enable_operator_defined_test_alerts_title" msgid="6867927342721101561">"Reservado à UE"</string>
diff --git a/res/values-mcc270-en-rAU/strings.xml b/res/values-mcc270-en-rAU/strings.xml
index bc799db82..cc8e5ab96 100644
--- a/res/values-mcc270-en-rAU/strings.xml
+++ b/res/values-mcc270-en-rAU/strings.xml
@@ -16,17 +16,17 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="6712775293264329163">"LU-alert"</string>
-    <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-alert"</string>
-    <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-alert"</string>
-    <string name="public_safety_message" msgid="7178887441252495779">"LU-alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-alert: Kidnapping alert"</string>
-    <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-alert test"</string>
-    <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-alert exercise"</string>
+    <string name="cmas_presidential_level_alert" msgid="6712775293264329163">"LU-Alert"</string>
+    <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
+    <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
+    <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
+    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Kidnapping alert"</string>
+    <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
+    <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Exercise"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnapping alert"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Show alert messages for child abductions"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-alert test"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Show test messages"</string>
-    <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-alert exercise"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Exercise"</string>
     <string name="enable_exercise_test_alerts_summary" msgid="7365706865492962183">"Show exercise messages"</string>
 </resources>
diff --git a/res/values-mcc270-en-rGB/strings.xml b/res/values-mcc270-en-rGB/strings.xml
index bc799db82..cc8e5ab96 100644
--- a/res/values-mcc270-en-rGB/strings.xml
+++ b/res/values-mcc270-en-rGB/strings.xml
@@ -16,17 +16,17 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="6712775293264329163">"LU-alert"</string>
-    <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-alert"</string>
-    <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-alert"</string>
-    <string name="public_safety_message" msgid="7178887441252495779">"LU-alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-alert: Kidnapping alert"</string>
-    <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-alert test"</string>
-    <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-alert exercise"</string>
+    <string name="cmas_presidential_level_alert" msgid="6712775293264329163">"LU-Alert"</string>
+    <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
+    <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
+    <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
+    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Kidnapping alert"</string>
+    <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
+    <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Exercise"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnapping alert"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Show alert messages for child abductions"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-alert test"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Show test messages"</string>
-    <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-alert exercise"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Exercise"</string>
     <string name="enable_exercise_test_alerts_summary" msgid="7365706865492962183">"Show exercise messages"</string>
 </resources>
diff --git a/res/values-mcc270-en-rIN/strings.xml b/res/values-mcc270-en-rIN/strings.xml
index bc799db82..cc8e5ab96 100644
--- a/res/values-mcc270-en-rIN/strings.xml
+++ b/res/values-mcc270-en-rIN/strings.xml
@@ -16,17 +16,17 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="6712775293264329163">"LU-alert"</string>
-    <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-alert"</string>
-    <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-alert"</string>
-    <string name="public_safety_message" msgid="7178887441252495779">"LU-alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-alert: Kidnapping alert"</string>
-    <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-alert test"</string>
-    <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-alert exercise"</string>
+    <string name="cmas_presidential_level_alert" msgid="6712775293264329163">"LU-Alert"</string>
+    <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
+    <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
+    <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
+    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Kidnapping alert"</string>
+    <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
+    <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Exercise"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnapping alert"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Show alert messages for child abductions"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-alert test"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Show test messages"</string>
-    <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-alert exercise"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Exercise"</string>
     <string name="enable_exercise_test_alerts_summary" msgid="7365706865492962183">"Show exercise messages"</string>
 </resources>
diff --git a/res/values-mcc284-in/strings.xml b/res/values-mcc284-in/strings.xml
index a4f92d2fc..76847f126 100644
--- a/res/values-mcc284-in/strings.xml
+++ b/res/values-mcc284-in/strings.xml
@@ -30,7 +30,7 @@
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="4573406416500374588">"Pesan Informasi"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="7180345818103607889">"Peringatan Orang Hilang"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Pesan untuk Orang Hilang"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Peringatan Pengujian"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Peringatan Uji Coba"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Terima Pesan Pengujian"</string>
     <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Peringatan Latihan"</string>
     <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Terima Pesan Latihan"</string>
diff --git a/res/values-mcc284-it/strings.xml b/res/values-mcc284-it/strings.xml
index 6a834a713..a7a316265 100644
--- a/res/values-mcc284-it/strings.xml
+++ b/res/values-mcc284-it/strings.xml
@@ -30,7 +30,7 @@
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="4573406416500374588">"Messaggi informativi"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="7180345818103607889">"Allerte persone scomparse"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Messaggi relativi a persone scomparse"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Allerte di prova"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Avvisi di prova"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Ricevi messaggi di prova"</string>
     <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Avvisi di simulazioni"</string>
     <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Ricevi messaggi per le simulazioni"</string>
diff --git a/res/values-mcc284-kk/strings.xml b/res/values-mcc284-kk/strings.xml
index 71557ebe6..12f98e1f4 100644
--- a/res/values-mcc284-kk/strings.xml
+++ b/res/values-mcc284-kk/strings.xml
@@ -24,8 +24,8 @@
     <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Жаттығу"</string>
     <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Резервтелді"</string>
     <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Техникалық сынақ"</string>
-    <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Үлкен қауіптер"</string>
-    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Өмірге және мүлікке төнген үлкен қауіптер"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Үлкен және аса үлкен қауіптер"</string>
+    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Өмірге және мүлікке төнген үлкен және аса үлкен қауіптер"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Ақпарат"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="4573406416500374588">"Ақпараттық хабарландырулар"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="7180345818103607889">"Жоғалған адам туралы хабарландырулар"</string>
diff --git a/res/values-mcc284-pt/strings.xml b/res/values-mcc284-pt/strings.xml
index 0438d474d..b4f05f088 100644
--- a/res/values-mcc284-pt/strings.xml
+++ b/res/values-mcc284-pt/strings.xml
@@ -24,7 +24,7 @@
     <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: exercício"</string>
     <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: reservado"</string>
     <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: teste técnico"</string>
-    <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ameaças graves e extremas"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Alerta severo e extremo"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ameaças graves e extremas à vida e propriedade"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informações"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="4573406416500374588">"Mensagens informativas"</string>
diff --git a/res/values-mcc284-sk/strings.xml b/res/values-mcc284-sk/strings.xml
index 1d526614b..e2c1e5c84 100644
--- a/res/values-mcc284-sk/strings.xml
+++ b/res/values-mcc284-sk/strings.xml
@@ -30,7 +30,7 @@
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="4573406416500374588">"Informačné správy"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="7180345818103607889">"Upozornenia na nezvestné osoby"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Správy o nezvestných osobách"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testovacie varovania"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testovacie výstrahy"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Dostávať testovacie správy"</string>
     <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Cvičné výstrahy"</string>
     <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Prijímať cvičné správy"</string>
diff --git a/res/values-mcc310-hi/strings.xml b/res/values-mcc310-hi/strings.xml
index f23862191..c12a371ee 100644
--- a/res/values-mcc310-hi/strings.xml
+++ b/res/values-mcc310-hi/strings.xml
@@ -29,7 +29,7 @@
     <skip />
     <string name="enable_cmas_test_alerts_summary" msgid="6138676147687910935">"सुरक्षा से जुड़ी चेतावनी देने वाले सिस्टम से हर महीने ज़रूरी टेस्ट अलर्ट पाएं"</string>
     <string name="cmas_presidential_level_alert" msgid="5810314558991898384">"राष्ट्रीय स्तर पर चेतावनी"</string>
-    <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"पहली चेतावनी (राष्ट्रीय स्तर पर चेतावनी के अलावा) दिखाने के बाद, ऑप्ट-आउट डायलॉग दिखाएं."</string>
+    <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"पहली चेतावनी (राष्ट्रीय स्तर की चेतावनी को छोड़कर) दिखाने के बाद, ऑप्ट-आउट करने का डायलॉग दिखाएं."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"देश पर खतरा होने की चेतावनियां पाएं"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"देश पर खतरा होने की चेतावनी देने वाले मैसेज. इसे बंद नहीं किया जा सकता."</string>
 </resources>
diff --git a/res/values-mcc310-kn/strings.xml b/res/values-mcc310-kn/strings.xml
index 31006ef8e..c37d28943 100644
--- a/res/values-mcc310-kn/strings.xml
+++ b/res/values-mcc310-kn/strings.xml
@@ -21,8 +21,8 @@
     <string name="emergency_alert_settings_title_watches" msgid="5702555089013313773">"ವೈರ್‌ಲೆಸ್ ತುರ್ತು ಅಲರ್ಟ್‌ಗಳು"</string>
     <string name="receive_cmas_in_second_language_title" msgid="7539080017840218665">"ಸ್ಪ್ಯಾನಿಶ್"</string>
     <string name="receive_cmas_in_second_language_summary" msgid="4482209573334686904">"ಸಾಧ್ಯವಾದಾಗ ಸ್ಪ್ಯಾನಿಶ್ ಭಾಷೆಯಲ್ಲಿ ತುರ್ತು ಎಚ್ಚರಿಕೆಗಳನ್ನು ಸ್ವೀಕರಿಸಿ"</string>
-    <string name="confirm_delete_broadcast" msgid="6808374217554967811">"ಈ ಅಲರ್ಟ್ ಅನ್ನು ಅಳಿಸುವುದೇ?"</string>
-    <string name="confirm_delete_all_broadcasts" msgid="4748571670736214158">"ಸ್ವೀಕರಿಸಿದ ಎಲ್ಲಾ ಅಲರ್ಟ್‌ಗಳನ್ನು ಅಳಿಸುವುದೇ?"</string>
+    <string name="confirm_delete_broadcast" msgid="6808374217554967811">"ಈ ಅಲರ್ಟ್ ಅನ್ನು ಅಳಿಸಬೇಕೆ?"</string>
+    <string name="confirm_delete_all_broadcasts" msgid="4748571670736214158">"ಸ್ವೀಕರಿಸಿದ ಎಲ್ಲಾ ಅಲರ್ಟ್‌ಗಳನ್ನು ಅಳಿಸಬೇಕೆ?"</string>
     <string name="menu_delete" msgid="2691868773984777519">"ಅಲರ್ಟ್ ಅನ್ನು ಅಳಿಸಿ"</string>
     <string name="menu_delete_all" msgid="8991615021908376216">"ಅಲರ್ಟ್‌ಗಳನ್ನು ಅಳಿಸಿ"</string>
     <!-- no translation found for enable_cmas_test_alerts_title (3722503121618497385) -->
diff --git a/res/values-mcc310-pt/strings.xml b/res/values-mcc310-pt/strings.xml
index 0f6906226..0c3bfaf8b 100644
--- a/res/values-mcc310-pt/strings.xml
+++ b/res/values-mcc310-pt/strings.xml
@@ -29,7 +29,7 @@
     <skip />
     <string name="enable_cmas_test_alerts_summary" msgid="6138676147687910935">"Receber os testes mensais obrigatórios pelo sistema de aviso de segurança"</string>
     <string name="cmas_presidential_level_alert" msgid="5810314558991898384">"Alerta nacional"</string>
-    <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Mostrar caixa de diálogo de desativação após exibir o primeiro alerta. Exceção: alerta nacional."</string>
+    <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Mostrar caixa de diálogo de desativação depois do primeiro alerta. Exceção: alerta nacional."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Alertas nacionais"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Mensagens de aviso nacionais. Não é possível desativá-las."</string>
 </resources>
diff --git a/res/values-mcc310-sk/strings.xml b/res/values-mcc310-sk/strings.xml
index 3c73cf4a1..3ee4716fb 100644
--- a/res/values-mcc310-sk/strings.xml
+++ b/res/values-mcc310-sk/strings.xml
@@ -16,9 +16,9 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_label" msgid="6018514276739876277">"Bezdrôtové núdzové upozornenia"</string>
-    <string name="sms_cb_settings" msgid="1556918270840502446">"Bezdrôtové núdzové upozornenia"</string>
-    <string name="emergency_alert_settings_title_watches" msgid="5702555089013313773">"Bezdrôtové núdzové upozornenia"</string>
+    <string name="app_label" msgid="6018514276739876277">"Bezdrôtové tiesňové výstrahy"</string>
+    <string name="sms_cb_settings" msgid="1556918270840502446">"Bezdrôtové tiesňové výstrahy"</string>
+    <string name="emergency_alert_settings_title_watches" msgid="5702555089013313773">"Bezdrôtové tiesňové výstrahy"</string>
     <string name="receive_cmas_in_second_language_title" msgid="7539080017840218665">"Španielčina"</string>
     <string name="receive_cmas_in_second_language_summary" msgid="4482209573334686904">"Dostávať tiesňové upozornenia v španielčine (keď je to možné)"</string>
     <string name="confirm_delete_broadcast" msgid="6808374217554967811">"Chcete odstrániť toto upozornenie?"</string>
diff --git a/res/values-mcc310-tr/strings.xml b/res/values-mcc310-tr/strings.xml
index 9d219b4cc..28a995ad9 100644
--- a/res/values-mcc310-tr/strings.xml
+++ b/res/values-mcc310-tr/strings.xml
@@ -29,7 +29,7 @@
     <skip />
     <string name="enable_cmas_test_alerts_summary" msgid="6138676147687910935">"Gereken aylık testleri güvenlik uyarı sisteminden al"</string>
     <string name="cmas_presidential_level_alert" msgid="5810314558991898384">"Ulusal düzeyde uyarı"</string>
-    <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"İlk uyarı (Ulusal düzeyde uyarı hariç) görüntülendikten sonra devre dışı bırakma iletişimini göster."</string>
+    <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"İlk uyarı (ulusal düzey hariç) gösterildikten sonra devre dışı bırakmayı sor."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Ulusal uyarılar"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"Ulusal uyarı mesajları. Kapatılamaz."</string>
 </resources>
diff --git a/res/values-mcc334/config.xml b/res/values-mcc334/config.xml
index 8782f1139..4b23f0284 100644
--- a/res/values-mcc334/config.xml
+++ b/res/values-mcc334/config.xml
@@ -17,50 +17,50 @@
 <resources>
     <!-- Channel 4370, 4383, 919 -->
     <string-array name="cmas_presidential_alerts_channels_range_strings" translatable="false">
-        <item>0x1112:rat=gsm, emergency=true, alert_duration=8000, always_on=true</item>
-        <item>0x111F:rat=gsm, emergency=true, alert_duration=8000, always_on=true</item>
+        <item>0x1112:rat=gsm, emergency=true, always_on=true</item>
+        <item>0x111F:rat=gsm, emergency=true, always_on=true</item>
         <!-- Channel 919 is the secondary channel for level 1-3, following the highest level config -->
-        <item>0x397:rat=gsm, emergency=true, alert_duration=8000, always_on=true</item>
+        <item>0x397:rat=gsm, emergency=true, always_on=true</item>
     </string-array>
 
     <!-- 4371~4372, 4384~4385 -->
     <string-array name="cmas_alert_extreme_channels_range_strings" translatable="false">
-        <item>0x1113-0x1114:rat=gsm, alert_duration=8000, emergency=true</item>
-        <item>0x1120-0x1121:rat=gsm, alert_duration=8000, emergency=true</item>
+        <item>0x1113-0x1114:rat=gsm, emergency=true</item>
+        <item>0x1120-0x1121:rat=gsm, emergency=true</item>
     </string-array>
 
     <!-- 4373~4378, 4386~4391 -->
     <string-array name="cmas_alerts_severe_range_strings" translatable="false">
-        <item>0x1115-0x111A:rat=gsm, alert_duration=8000, emergency=true</item>
-        <item>0x1122-0x1127:rat=gsm, alert_duration=8000, emergency=true</item>
+        <item>0x1115-0x111A:rat=gsm, emergency=true</item>
+        <item>0x1122-0x1127:rat=gsm, emergency=true</item>
     </string-array>
 
     <!-- 4379 -->
     <string-array name="cmas_amber_alerts_channels_range_strings" translatable="false">
-        <item>0x111B:rat=gsm, alert_duration=8000, emergency=true</item>
+        <item>0x111B:rat=gsm, emergency=true</item>
     </string-array>
 
     <!-- 4380, 519 -->
     <string-array name="required_monthly_test_range_strings" translatable="false">
-        <item>0x111C:rat=gsm, alert_duration=8000, emergency=true</item>
+        <item>0x111C:rat=gsm, emergency=true</item>
         <!-- Channel 519 is the secondary channel for test and exercise alert -->
-        <item>0x207:rat=gsm, alert_duration=8000, emergency=true</item>
+        <item>0x207:rat=gsm, emergency=true</item>
     </string-array>
 
     <!-- 4381 -->
     <string-array name="exercise_alert_range_strings" translatable="false">
-        <item>0x111D:rat=gsm, alert_duration=8000, emergency=true</item>
+        <item>0x111D:rat=gsm, emergency=true</item>
     </string-array>
 
     <!-- Channel 6400 -->
     <string-array name="public_safety_messages_channels_range_strings" translatable="false">
-        <item>0x1900:rat=gsm, alert_duration=8000, emergency=true</item>
+        <item>0x1900:rat=gsm, emergency=true</item>
     </string-array>
 
     <!-- Channel 4396-4399 -->
     <string-array name="emergency_alerts_channels_range_strings" translatable="false">
         <!-- Channel 4396-4399 reserved for future -->
-        <item>0x112C-0x112F:rat=gsm, alert_duration=8000, emergency=true</item>
+        <item>0x112C-0x112F:rat=gsm, emergency=true</item>
     </string-array>
 
     <string-array name="operator_defined_alert_range_strings" translatable="false" />
diff --git a/res/values-mcc420-in/strings.xml b/res/values-mcc420-in/strings.xml
index 4f4f2c157..a67b155bd 100644
--- a/res/values-mcc420-in/strings.xml
+++ b/res/values-mcc420-in/strings.xml
@@ -14,7 +14,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_presidential_level_alert" msgid="5922755396541728069">"Notifikasi Peringatan Nasional"</string>
-    <string name="cmas_extreme_alert" msgid="2666370743728576543">"Notifikasi Peringatan Darurat Ekstrim"</string>
+    <string name="cmas_extreme_alert" msgid="2666370743728576543">"Notifikasi Peringatan Darurat Ekstrem"</string>
     <!-- no translation found for cmas_extreme_immediate_observed_alert (9214912512697774351) -->
     <skip />
     <!-- no translation found for cmas_extreme_immediate_likely_alert (5872678423468023949) -->
diff --git a/res/values-mcc420-sk/strings.xml b/res/values-mcc420-sk/strings.xml
index edce27b54..7a443c670 100644
--- a/res/values-mcc420-sk/strings.xml
+++ b/res/values-mcc420-sk/strings.xml
@@ -20,8 +20,8 @@
     <!-- no translation found for cmas_extreme_immediate_likely_alert (5872678423468023949) -->
     <skip />
     <string name="cmas_severe_alert" msgid="1611418922477376647">"Tiesňové upozornenia"</string>
-    <string name="pws_other_message_identifiers" msgid="7907712751421890873">"Upozornenia"</string>
-    <string name="enable_emergency_alerts_message_title" msgid="5267857032926801433">"Upozornenia"</string>
+    <string name="pws_other_message_identifiers" msgid="7907712751421890873">"Výstrahy"</string>
+    <string name="enable_emergency_alerts_message_title" msgid="5267857032926801433">"Výstrahy"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="8961532453478455676">"Odporúčané akcie, ktoré môžu zachrániť životy alebo majetok"</string>
     <string name="cmas_required_monthly_test" msgid="5733131786754331921">"Testovacie upozornenia"</string>
     <string name="cmas_exercise_alert" msgid="7249058541625071454">"Cvičenia"</string>
diff --git a/res/values-mcc424-in/strings.xml b/res/values-mcc424-in/strings.xml
index 75dbeba79..cb644448f 100644
--- a/res/values-mcc424-in/strings.xml
+++ b/res/values-mcc424-in/strings.xml
@@ -28,5 +28,5 @@
     <string name="state_local_test_alert" msgid="5347253401221487116">"Uji Peringatan"</string>
     <string name="enable_emergency_alerts_message_title" msgid="5365080705719184919">"Notifikasi Peringatan"</string>
     <string name="enable_public_safety_messages_title" msgid="4702006823902961758">"Peringatan Keamanan Publik"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="3586102183699625309">"Uji Peringatan"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="3586102183699625309">"Peringatan Uji Coba"</string>
 </resources>
diff --git a/res/values-mcc424-sk/strings.xml b/res/values-mcc424-sk/strings.xml
index ba9f82332..6e7de906b 100644
--- a/res/values-mcc424-sk/strings.xml
+++ b/res/values-mcc424-sk/strings.xml
@@ -28,5 +28,5 @@
     <string name="state_local_test_alert" msgid="5347253401221487116">"Testovacie varovanie"</string>
     <string name="enable_emergency_alerts_message_title" msgid="5365080705719184919">"Upozornenia"</string>
     <string name="enable_public_safety_messages_title" msgid="4702006823902961758">"Varovania verejnej bezpečnosti"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="3586102183699625309">"Testovacie varovania"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="3586102183699625309">"Testovacie výstrahy"</string>
 </resources>
diff --git a/res/values-mcc427-hi/strings.xml b/res/values-mcc427-hi/strings.xml
index 96ea080ac..c81d8a509 100644
--- a/res/values-mcc427-hi/strings.xml
+++ b/res/values-mcc427-hi/strings.xml
@@ -17,7 +17,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_presidential_level_alert" msgid="5786487196661686996">"राष्ट्रीय आपातकाल की चेतावनी"</string>
-    <string name="show_cmas_opt_out_summary" msgid="1317444474007208209">"पहली चेतावनी (राष्ट्रीय स्तर पर चेतावनी के अलावा) दिखाने के बाद, ऑप्ट-आउट डायलॉग दिखाएं."</string>
+    <string name="show_cmas_opt_out_summary" msgid="1317444474007208209">"पहली चेतावनी (राष्ट्रीय स्तर की चेतावनी को छोड़कर) दिखाने के बाद, ऑप्ट-आउट करने का डायलॉग दिखाएं."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="789927829034029104">"राष्ट्रीय आपातकाल की चेतावनियां"</string>
     <string name="cmas_extreme_alert" msgid="3470880837863412562">"आपातकालीन स्थिति की चेतावनी"</string>
     <string name="cmas_extreme_immediate_observed_alert" msgid="2411683921516746239">"आपातकालीन स्थिति की चेतावनी"</string>
diff --git a/res/values-mcc427-in/strings.xml b/res/values-mcc427-in/strings.xml
index c15f0811f..a3aaa976b 100644
--- a/res/values-mcc427-in/strings.xml
+++ b/res/values-mcc427-in/strings.xml
@@ -30,5 +30,5 @@
     <string name="state_local_test_alert" msgid="7009393486453350790">"Peringatan Pengujian"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="3253477871276901425">"Peringatan"</string>
     <string name="enable_public_safety_messages_title" msgid="6164589595328113173">"Peringatan keamanan publik"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="5347896880762045640">"Peringatan pengujian"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="5347896880762045640">"Peringatan uji coba"</string>
 </resources>
diff --git a/res/values-mcc427-it/strings.xml b/res/values-mcc427-it/strings.xml
index 7218b2b21..eebc991d5 100644
--- a/res/values-mcc427-it/strings.xml
+++ b/res/values-mcc427-it/strings.xml
@@ -30,5 +30,5 @@
     <string name="state_local_test_alert" msgid="7009393486453350790">"Allerta di prova"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="3253477871276901425">"Avvisi"</string>
     <string name="enable_public_safety_messages_title" msgid="6164589595328113173">"Allerte sicurezza pubblica"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="5347896880762045640">"Allerte di prova"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="5347896880762045640">"Avvisi di prova"</string>
 </resources>
diff --git a/res/values-mcc427-pt/strings.xml b/res/values-mcc427-pt/strings.xml
index ef07e198a..442f58321 100644
--- a/res/values-mcc427-pt/strings.xml
+++ b/res/values-mcc427-pt/strings.xml
@@ -17,7 +17,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_presidential_level_alert" msgid="5786487196661686996">"Alerta de emergência nacional"</string>
-    <string name="show_cmas_opt_out_summary" msgid="1317444474007208209">"Mostrar caixa de diálogo de desativação após exibir o primeiro alerta. Exceção: alerta nacional."</string>
+    <string name="show_cmas_opt_out_summary" msgid="1317444474007208209">"Mostrar caixa de diálogo de desativação depois do primeiro alerta. Exceção: alerta nacional."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="789927829034029104">"Alertas de emergência nacional"</string>
     <string name="cmas_extreme_alert" msgid="3470880837863412562">"Alerta de emergência"</string>
     <string name="cmas_extreme_immediate_observed_alert" msgid="2411683921516746239">"Alerta de emergência"</string>
diff --git a/res/values-mcc427-sk/strings.xml b/res/values-mcc427-sk/strings.xml
index a4af9d79d..168609b4e 100644
--- a/res/values-mcc427-sk/strings.xml
+++ b/res/values-mcc427-sk/strings.xml
@@ -30,5 +30,5 @@
     <string name="state_local_test_alert" msgid="7009393486453350790">"Testovacie varovanie"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="3253477871276901425">"Varovania"</string>
     <string name="enable_public_safety_messages_title" msgid="6164589595328113173">"Varovania verejnej bezpečnosti"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="5347896880762045640">"Testovacie varovania"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="5347896880762045640">"Testovacie výstrahy"</string>
 </resources>
diff --git a/res/values-mcc427-zh-rCN/strings.xml b/res/values-mcc427-zh-rCN/strings.xml
index ad0bad023..5f63a131d 100644
--- a/res/values-mcc427-zh-rCN/strings.xml
+++ b/res/values-mcc427-zh-rCN/strings.xml
@@ -17,7 +17,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_presidential_level_alert" msgid="5786487196661686996">"国家级紧急警报"</string>
-    <string name="show_cmas_opt_out_summary" msgid="1317444474007208209">"在显示第一条警报（国家/地区级警报除外）后，显示可供用户停用 CMAS 的对话框。"</string>
+    <string name="show_cmas_opt_out_summary" msgid="1317444474007208209">"在显示第一条警报（国家/地区级警报除外）后，显示可供用户停用警报的对话框。"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="789927829034029104">"国家紧急警报"</string>
     <string name="cmas_extreme_alert" msgid="3470880837863412562">"紧急警报"</string>
     <string name="cmas_extreme_immediate_observed_alert" msgid="2411683921516746239">"紧急警报"</string>
diff --git a/res/values-mcc440-mnc20/config.xml b/res/values-mcc440-mnc20/config.xml
index ee877aa10..fc8c1e060 100644
--- a/res/values-mcc440-mnc20/config.xml
+++ b/res/values-mcc440-mnc20/config.xml
@@ -19,13 +19,7 @@
     <string-array name="etws_test_alerts_range_strings" translatable="false">
         <item>0x1103:rat=gsm, emergency=true, debug_build=true</item>
     </string-array>
-    <string-array name="additional_cbs_channels_strings" translatable="false">
-        <item>0xA800:type=etws_earthquake, emergency=true, scope=carrier</item>
-        <item>0xAFEE:type=etws_tsunami, emergency=true, scope=carrier</item>
-        <item>0xAC00-0xAFED:type=other, emergency=true, scope=carrier</item>
-        <item>0xA802:type=test, emergency=true, scope=carrier</item>
-        <item>0xA804:type=test, emergency=true, scope=carrier</item>
-    </string-array>
+
     <!-- Whether to show test settings -->
     <bool name="show_test_settings">false</bool>
     <bool name="allow_testing_mode_on_user_build">false</bool>
diff --git a/res/values-mcc450-sk/strings.xml b/res/values-mcc450-sk/strings.xml
index a279ff7bc..e01a37c49 100644
--- a/res/values-mcc450-sk/strings.xml
+++ b/res/values-mcc450-sk/strings.xml
@@ -19,10 +19,10 @@
     <string name="cmas_presidential_level_alert" msgid="5649815444496135942">"Upozornenie v krajnej núdzi"</string>
     <string name="emergency_alert" msgid="3311447424971987519">"Tiesňové varovanie"</string>
     <string name="public_safety_message" msgid="909566512650220068">"Varovanie verejnej bezpečnosti"</string>
-    <string name="cmas_amber_alert" msgid="3379756389634116131">"Upozornenie Amber"</string>
+    <string name="cmas_amber_alert" msgid="3379756389634116131">"Upozornenie na únos dieťaťa"</string>
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Tiesňové varovanie"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Varovanie verejnej bezpečnosti"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Upozornenie Amber"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Upozornenie na únos dieťaťa"</string>
     <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
     <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"V telefóne môžete v prípade katastrof dostávať varovania, napríklad pokyny na evakuáciu. Táto služba je výsledkom spolupráce kórejskej vlády, poskytovateľov sietí a výrobcov zariadení.\n\nVarovania nemusíte dostať, ak sa vyskytne problém so zariadením alebo kvalitou siete."</string>
diff --git a/res/values-mcc466-in/strings.xml b/res/values-mcc466-in/strings.xml
index ce7b3d0d6..557532eb1 100644
--- a/res/values-mcc466-in/strings.xml
+++ b/res/values-mcc466-in/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="2072968896927919629">"Notifikasi Kepresidenan"</string>
+    <string name="cmas_presidential_level_alert" msgid="2072968896927919629">"Peringatan Kepresidenan"</string>
     <string name="emergency_alert" msgid="5431770009291479378">"Peringatan Darurat"</string>
     <string name="public_safety_message" msgid="3043854916586710461">"Pesan Peringatan"</string>
     <string name="enable_cmas_test_alerts_title" msgid="4165080207837566277">"Pengujian bulanan wajib"</string>
diff --git a/res/values-mcc724-de/strings.xml b/res/values-mcc724-de/strings.xml
index 3f8afef0d..8d4404ae4 100644
--- a/res/values-mcc724-de/strings.xml
+++ b/res/values-mcc724-de/strings.xml
@@ -20,7 +20,7 @@
     <string name="cmas_severe_alert" msgid="4773544726385840011">"Warnung der Kategorie „Ernst“"</string>
     <string name="cmas_required_monthly_test" msgid="5274965928258227096">"Warnung der Kategorie „Übung“"</string>
     <string name="cmas_exercise_alert" msgid="4971838389621550184">"Warnung für technischen Test"</string>
-    <string name="enable_cmas_extreme_threat_alerts_title" msgid="3095141156358640879">"Erhebliche Gefahren"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="3095141156358640879">"Extreme Gefahren"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6931853411327178941">"Erhebliche Gefahren für Leben und Eigentum"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="2603680055509729555">"Erhebliche Gefahren"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="405751015446465202">"Erhebliche Gefahren für Leben und Eigentum"</string>
diff --git a/res/values-mcc724-kk/strings.xml b/res/values-mcc724-kk/strings.xml
index b9b76787c..cebec85fc 100644
--- a/res/values-mcc724-kk/strings.xml
+++ b/res/values-mcc724-kk/strings.xml
@@ -20,10 +20,10 @@
     <string name="cmas_severe_alert" msgid="4773544726385840011">"Маңыздылығы жоғары хабарландыру"</string>
     <string name="cmas_required_monthly_test" msgid="5274965928258227096">"Жаттығу хабарландыруы"</string>
     <string name="cmas_exercise_alert" msgid="4971838389621550184">"Техникалық сынақ хабарландырулары"</string>
-    <string name="enable_cmas_extreme_threat_alerts_title" msgid="3095141156358640879">"Аса үлкен қауіп"</string>
-    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6931853411327178941">"Өмірге және мүлікке төнетін аса үлкен қауіп"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="2603680055509729555">"Елеулі қауіптер"</string>
-    <string name="enable_cmas_severe_threat_alerts_summary" msgid="405751015446465202">"Өмірге және мүлікке төнген елеулі қауіптер"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="3095141156358640879">"Аса үлкен қауіптер"</string>
+    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6931853411327178941">"Өмірге және мүлікке төнген аса үлкен қауіптер"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="2603680055509729555">"Үлкен қауіптер"</string>
+    <string name="enable_cmas_severe_threat_alerts_summary" msgid="405751015446465202">"Өмірге және мүлікке төнген үлкен қауіптер"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5550182663333808054">"Мемлекеттік және жергілікті сынақтар"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5713628754819156297">"Мемлекеттік және жергілікті органдардан сынақ хабарларын алу"</string>
     <string name="enable_exercise_test_alerts_title" msgid="1926178722994782168">"Техникалық сынақ хабарландырулары"</string>
diff --git a/res/values-mcc724-my/strings.xml b/res/values-mcc724-my/strings.xml
index 478756628..fe31722cd 100644
--- a/res/values-mcc724-my/strings.xml
+++ b/res/values-mcc724-my/strings.xml
@@ -22,7 +22,7 @@
     <string name="cmas_exercise_alert" msgid="4971838389621550184">"နည်းပညာဆိုင်ရာ စမ်းသပ် သတိပေးချက်များ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="3095141156358640879">"လွန်ကဲ အန္တရာယ်များ"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6931853411327178941">"အသက်အိုးအိမ်အတွက် အလွန်အန္တရာယ်ရှိသည်"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="2603680055509729555">"အလွန်ကြီးမားသော အန္တရာယ်များ"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="2603680055509729555">"ကြီးမားသော အန္တရာယ်များ"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="405751015446465202">"အသက်အိုးအိမ်အတွက် အလွန်ကြီးမားသော အန္တရာယ်ရှိသည်"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5550182663333808054">"ပြည်နယ်နှင့် ဒေသတွင်း စမ်းသပ်မှုများ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5713628754819156297">"ပြည်နယ်နှင့် ဒေသခံ အာဏာပိုင်များထံမှ စမ်းသပ်မက်ဆေ့ဂျ်များ လက်ခံသည်"</string>
diff --git a/res/values-mcc724-pt/strings.xml b/res/values-mcc724-pt/strings.xml
index e44428385..8411be683 100644
--- a/res/values-mcc724-pt/strings.xml
+++ b/res/values-mcc724-pt/strings.xml
@@ -23,7 +23,7 @@
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="3095141156358640879">"Alerta Extremo"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6931853411327178941">"Ameaças extremas à vida ou à propriedade"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="2603680055509729555">"Alerta Severo"</string>
-    <string name="enable_cmas_severe_threat_alerts_summary" msgid="405751015446465202">"Medidas de proteção necessárias"</string>
+    <string name="enable_cmas_severe_threat_alerts_summary" msgid="405751015446465202">"Ameaças graves à vida e propriedade"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5550182663333808054">"Alerta de teste"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5713628754819156297">"Recebimento de alertas de testes das autoridades competentes"</string>
     <string name="enable_exercise_test_alerts_title" msgid="1926178722994782168">"Alerta de teste técnico"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 8f29a130c..dd891cc4f 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -63,7 +63,7 @@
     <string name="notification_channel_broadcast_messages_in_voicecall" msgid="3291001780110813190">"व्हॉइस कॉलमधील आणीबाणी सूचना"</string>
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"SIM वर आधारित ऑटोमॅटिक WEA सेटिंग्जमधील बदल"</string>
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"अलर्टना अनुमती द्या"</string>
-    <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"वायरलेस आणीबाणी अलर्ट सूचना मिळवा"</string>
+    <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"वायरलेस आणीबाणी अलर्ट नोटिफिकेशन मिळवा"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"अलर्ट रिमाइंडर"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"सूचना मेसेज बोला"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"आणीबाणीमधील वायरलेस इशारा मेसेज बोलण्यासाठी टेक्स्ट-टू-स्पीच वापरा"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 18baa9d95..96c088515 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -65,7 +65,7 @@
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Benarkan makluman"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Terima pemberitahuan makluman kecemasan wayarles"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Peringatan makluman"</string>
-    <string name="enable_alert_speech_title" msgid="8052104771053526941">"Tuturkan mesej isyarat"</string>
+    <string name="enable_alert_speech_title" msgid="8052104771053526941">"Tuturkan mesej makluman"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Gunakan teks ke pertuturan untuk menuturkan mesej makluman kecemasan wayarles"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"Bunyi peringatan akan dimainkan pada kelantangan biasa"</string>
     <string name="emergency_alert_history_title" msgid="8310173569237268431">"Sejarah makluman kecemasan"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 35a2a6609..5a261789b 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -72,10 +72,10 @@
     <string name="alert_preferences_title" msgid="6001469026393248468">"သတိပေးချက် ရွေးချယ်မှုများ"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"ETWS စမ်းသပ်ထုတ်လွှင့်ချက်များ"</string>
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"မြေငလျင်ဆူနာမီ သတိပေးရေးစနစ်အတွက် စမ်းသပ်ထုတ်လွှင့်ချက်များ"</string>
-    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5416260219062637770">"အလွန်အန္တရာယ်ရှိနေသည်"</string>
-    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"အသက်အိုးအိမ်အတွက် အလွန်အန္တရာယ်ရှိနေသည်"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"ကြီးမားသည့် အန္တရာယ်ရှိနေပါသည်"</string>
-    <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"အသက်အိုးအိမ်အတွက် ကြီးမားသည့် အန္တရာယ်ရှိနေသည်"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5416260219062637770">"လွန်ကဲ အန္တရာယ်များ"</string>
+    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"အသက်အိုးအိမ်အတွက် အလွန်အန္တရာယ်ရှိသည်"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"ကြီးမားသော အန္တရာယ်များ"</string>
+    <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"အသက်အိုးအိမ်အတွက် ကြီးမားသော အန္တရာယ်ရှိသည်"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"AMBER သတိပေးချက်များ"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"ကလေးခိုးမှု အရေးပေါ်ကြေညာချက်"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"သတိပေး မက်ဆေ့ဂျ်များ"</string>
@@ -101,7 +101,7 @@
     <string name="override_dnd_title" msgid="5120805993144214421">"သတိပေးချက်ကို အမြဲ အသံအကျယ်ဆုံး"</string>
     <string name="override_dnd_summary" msgid="9026675822792800258">"\'မနှောင့်ယှက်ရ\'နှင့် အခြားအသံဆက်တင်များကို ပယ်ပါ"</string>
     <string name="enable_area_update_info_alerts_title" msgid="3442042268424617226">"နယ်မြေအပ်ဒိတ် ထုတ်လွှင့်ခြင်းများ"</string>
-    <string name="enable_area_update_info_alerts_summary" msgid="6437816607144264910">"ဆင်းမ်ကဒ်အခြေအနေတွင် အပ်ဒိတ်အချက်အလက်များကို ပြသရန်"</string>
+    <string name="enable_area_update_info_alerts_summary" msgid="6437816607144264910">"ဆင်းမ်ကတ်အခြေအနေတွင် အပ်ဒိတ်အချက်အလက် ပြရန်"</string>
     <string name="cmas_category_heading" msgid="3923503130776640717">"သတိပေးချက် အမျိုးအစား:"</string>
     <string name="cmas_category_geo" msgid="4979494217069688527">"ဘူမိရုပ်ပိုင်းဆိုင်ရာ"</string>
     <string name="cmas_category_met" msgid="7563732573851773537">"မိုးလေဝသဆိုင်ရာ"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 22ee1c235..931aa622c 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -88,7 +88,7 @@
     <string name="enable_state_local_test_alerts_summary" msgid="780298327377950187">"राज्यस्तरीय र स्थानीय अधिकारीहरूबाट परीक्षणसम्बन्धी म्यासेजहरू प्राप्त गर्नुहोस्"</string>
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"आपत्‌कालीन सतर्कताहरू"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"जीवन जोखिममा पर्न सक्ने घटनाहरूबारे सचेत गराउनुहोस्"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"परीक्षणसम्बन्धी सतर्कताहरू"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"परीक्षणको अलर्ट"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"सुरक्षा सतर्कता प्रणालीबाट क्यारियर परीक्षण र मासिक परीक्षणहरू प्राप्त होस्"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
@@ -149,7 +149,7 @@
     <item msgid="9097229303902157183">"हरेक २ मिनेट"</item>
     <item msgid="5718214950343391480">"हरेक ५ मिनेट"</item>
     <item msgid="3863339891188103437">"हरेक १५ मिनेट"</item>
-    <item msgid="7388573183644474611">"कदापि होइन"</item>
+    <item msgid="7388573183644474611">"कहिले पनि नगर्नु"</item>
   </string-array>
     <string name="emergency_alert_settings_title_watches" msgid="4477073412799894883">"वायरलेस आपत्‌कालीन अलर्टहरू"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="7293800023375154256">"राष्ट्राध्यक्षीय सतर्कताहरू"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 43f60b28a..72c2c2ebd 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -96,7 +96,7 @@
     <!-- no translation found for enable_operator_defined_test_alerts_title (7459219458579095832) -->
     <skip />
     <string name="enable_operator_defined_test_alerts_summary" msgid="7856514354348843433">"ଜରୁରୀକାଳୀନ ଆଲର୍ଟ ପାଆନ୍ତୁ: ଅପରେଟରଙ୍କ ଦ୍ୱାରା ନିର୍ଦ୍ଦିଷ୍ଟ କରାଯାଇଛି"</string>
-    <string name="enable_alert_vibrate_title" msgid="5421032189422312508">"ଭାଇବ୍ରେସନ୍"</string>
+    <string name="enable_alert_vibrate_title" msgid="5421032189422312508">"ଭାଇବ୍ରେସନ"</string>
     <string name="enable_alert_vibrate_summary" msgid="4733669825477146614"></string>
     <string name="override_dnd_title" msgid="5120805993144214421">"ସର୍ବଦା ଉଚ୍ଚ ଭଲ୍ୟୁମରେ ଆଲର୍ଟ କରନ୍ତୁ"</string>
     <string name="override_dnd_summary" msgid="9026675822792800258">"\"ବିରକ୍ତ କରନ୍ତୁ ନାହିଁ\" ଓ ଅନ୍ୟ ଭଲ୍ୟୁମ୍ ସେଟିଂସକୁ ଅଣଦେଖା କରନ୍ତୁ"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index cbfefb01b..8333d5526 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -76,7 +76,7 @@
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"ਜਾਨ ਅਤੇ ਮਾਲ ਦੇ ਹੱਦੋਂ ਵੱਧ ਖਤਰਿਆਂ ਸੰਬੰਧੀ ਸੁਚੇਤਨਾਵਾਂ"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"ਗੰਭੀਰ ਖਤਰੇ"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"ਜਾਨ ਅਤੇ ਮਾਲ ਦੇ ਗੰਭੀਰ ਖਤਰਿਆਂ ਸੰਬੰਧੀ ਸੁਚੇਤਨਾਵਾਂ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"AMBER ਸੁਚੇਤਨਾਵਾਂ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"AMBER ਅਲਰਟ"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"ਅਗਵਾ ਹੋਏ ਬੱਚੇ ਸੰਬੰਧੀ ਐਮਰਜੈਂਸੀ ਬੁਲੇਟਿਨ"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"ਅਲਰਟ ਸੰਬੰਧੀ ਸੁਨੇਹੇ"</string>
     <string name="enable_alert_message_summary" msgid="6525664541696985610">"ਸੰਭਾਵੀ ਸੁਰੱਖਿਆ ਖਤਰਿਆਂ ਬਾਰੇ ਚਿਤਾਵਨੀ ਦਿਓ"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 572dccc4d..e6d102360 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -89,7 +89,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"Alertas de emergência"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"Avisar acerca de eventos potencialmente fatais"</string>
     <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"Alertas de teste"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Receba testes do operador e testes mensais do sistema de alerta de segurança"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Receba testes da operadora e testes mensais do sistema de alerta de segurança"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
     <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"Receber um alerta de emergência: mensagem de simulação/exercício"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index 61ea7d1a6..ec4619d7f 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -72,9 +72,9 @@
     <string name="alert_preferences_title" msgid="6001469026393248468">"Preferências de alertas"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"Transmissões de teste do ETWS"</string>
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"Transmissões de teste do Sistema de aviso de tsunamis e terremotos"</string>
-    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5416260219062637770">"Ameaças extremas"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5416260219062637770">"Alerta extremo"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"Ameaças extremas, materiais ou à vida"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"Ameaças graves"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"Alerta severo"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"Ameaças graves, materiais ou à vida"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"Alertas AMBER"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"Boletins de emergência envolvendo sequestro de crianças"</string>
@@ -136,7 +136,7 @@
     <string name="delivery_time_heading" msgid="5980836543433619329">"Recebida:"</string>
     <string name="notification_multiple" msgid="5121978148152124860">"<xliff:g id="COUNT">%s</xliff:g> alertas não lidos."</string>
     <string name="notification_multiple_title" msgid="1523638925739947855">"Novos alertas"</string>
-    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"Mostrar caixa de diálogo de desativação após exibir o primeiro alerta (exceção: alerta presidencial)."</string>
+    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"Mostrar caixa de diálogo de desativação depois do primeiro alerta (exceção: alerta presidencial)."</string>
     <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"Mostrar diálogo de desativação"</string>
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"Você está recebendo alertas de emergência sem fio. Quer continuar a recebê-los?"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"Sim"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 69de14c49..a1fc015b8 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -63,8 +63,8 @@
     <string name="notification_channel_broadcast_messages_in_voicecall" msgid="3291001780110813190">"Оповещения о чрезвычайных ситуациях, поступающие во время голосовых вызовов"</string>
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"Автоматические настройки экстренных оповещений по беспроводным сетям изменены согласно SIM-карте"</string>
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Разрешить оповещения"</string>
-    <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Получать экстренные оповещения по беспроводным сетям"</string>
-    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Периодичность напоминаний"</string>
+    <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Уведомления об экстренных оповещениях по беспроводному каналу"</string>
+    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Напоминания"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"Произносить оповещения"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Использовать озвучивание текста для чтения экстренных оповещений по беспроводным сетям"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"Проигрывать звук напоминания на обычной громкости"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index eeb68cb38..edcf69291 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -16,11 +16,11 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_label" msgid="2008319089248760277">"Bezdrôtové tiesňové upozornenia"</string>
+    <string name="app_label" msgid="2008319089248760277">"Bezdrôtové tiesňové výstrahy"</string>
     <string name="sms_cb_settings" msgid="9021266457863671070">"Bezdrôtové tiesňové upozornenia"</string>
-    <string name="sms_cb_sender_name_default" msgid="972946539768958828">"Bezdrôtové núdzové upozornenia"</string>
-    <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Bezdrôtové tiesňové varovania"</string>
-    <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Bezdrôtové núdzové upozornenia"</string>
+    <string name="sms_cb_sender_name_default" msgid="972946539768958828">"Bezdrôtové tiesňové výstrahy"</string>
+    <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Bezdrôtové tiesňové výstrahy"</string>
+    <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Bezdrôtové tiesňové výstrahy"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informačné upozornenie"</string>
     <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
     <skip />
@@ -48,7 +48,7 @@
     <string name="cmas_extreme_immediate_observed_alert" msgid="2328845915287460780">"Mimoriadne tiesňové upozornenie"</string>
     <string name="cmas_extreme_immediate_likely_alert" msgid="1859702950323471778">"Mimoriadne tiesňové upozornenie"</string>
     <string name="cmas_severe_alert" msgid="4135809475315826913">"Závažné tiesňové upozornenie"</string>
-    <string name="cmas_amber_alert" msgid="6154867710264778887">"Únos dieťaťa (upozornenie Amber)"</string>
+    <string name="cmas_amber_alert" msgid="6154867710264778887">"Upozornenie na únos dieťaťa"</string>
     <string name="cmas_required_monthly_test" msgid="1890205712251132193">"Povinný mesačný test"</string>
     <string name="cmas_exercise_alert" msgid="2892255514938370321">"Tiesňové upozornenie (cvičenie)"</string>
     <string name="cmas_operator_defined_alert" msgid="8755372450810011476">"Tiesňové upozornenie (operátor)"</string>
@@ -56,20 +56,20 @@
     <string name="public_safety_message" msgid="9119928798786998252">"Správa verejnej bezpečnosti"</string>
     <string name="state_local_test_alert" msgid="8003145745857480200">"Štátny/miestny test"</string>
     <string name="emergency_alert" msgid="624783871477634263">"Tiesňové upozornenie"</string>
-    <string name="emergency_alerts_title" msgid="6605036374197485429">"Upozornenia"</string>
+    <string name="emergency_alerts_title" msgid="6605036374197485429">"Výstrahy"</string>
     <string name="notification_channel_broadcast_messages" msgid="880704362482824524">"Správy vysielania"</string>
     <string name="notification_channel_emergency_alerts" msgid="5008287980979183617">"Tiesňové upozornenia"</string>
     <string name="notification_channel_emergency_alerts_high_priority" msgid="3937475297436439073">"Nepotvrdené tiesňové upozornenia"</string>
     <string name="notification_channel_broadcast_messages_in_voicecall" msgid="3291001780110813190">"Tiesňové upozornenia v hlasovom hovore"</string>
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"Automatické zmeny nastavení bezdrôtových tiesňových upozornení na základe SIM karty"</string>
-    <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Povoliť upozornenia"</string>
+    <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Povoliť výstrahy"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Prijímať bezdrôtové tiesňové upozornenia"</string>
-    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Pripomínať upozornenia"</string>
+    <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Pripomenutie výstrah"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"Čítať upozornenia"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Čítať bezdrôtové tiesňové upozornenia prevodom textu na reč"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"Zvuk pripomenutí sa prehrá bežnou hlasitosťou"</string>
-    <string name="emergency_alert_history_title" msgid="8310173569237268431">"História tiesňových varovaní"</string>
-    <string name="alert_preferences_title" msgid="6001469026393248468">"Nastavenia upozornení"</string>
+    <string name="emergency_alert_history_title" msgid="8310173569237268431">"História tiesňových výstrah"</string>
+    <string name="alert_preferences_title" msgid="6001469026393248468">"Nastavenia výstrah"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"Testovacie vysielania ETWS"</string>
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"Testovacie vysielania systému varovania pred zemetrasením a cunami"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="5416260219062637770">"Extrémne hrozby"</string>
@@ -88,7 +88,7 @@
     <string name="enable_state_local_test_alerts_summary" msgid="780298327377950187">"Dostávať testovacie správy zo systému bezpečnostných upozornení"</string>
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"Tiesňové upozornenia"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"Upozorňovať na udalosti ohrozujúce život"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"Testovacie upozornenia"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"Testovacie výstrahy"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Dostávať testy od operátora a mesačné testy zo systému bezpečnostných upozornení"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
@@ -141,7 +141,7 @@
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"Aktuálne prijímate bezdrôtové tiesňové upozornenia. Chcete ich prijímať aj naďalej?"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"Áno"</string>
     <string name="cmas_opt_out_button_no" msgid="3110484064328538553">"Nie"</string>
-    <string name="cb_list_activity_title" msgid="1433502151877791724">"História tiesňových varovaní"</string>
+    <string name="cb_list_activity_title" msgid="1433502151877791724">"História tiesňových výstrah"</string>
     <string name="action_delete" msgid="7435661404543945861">"Odstrániť"</string>
     <string name="action_detail_info" msgid="8486524382178381810">"Zobraziť podrobnosti"</string>
   <string-array name="alert_reminder_interval_entries">
@@ -151,7 +151,7 @@
     <item msgid="3863339891188103437">"Každých 15 minút"</item>
     <item msgid="7388573183644474611">"Nikdy"</item>
   </string-array>
-    <string name="emergency_alert_settings_title_watches" msgid="4477073412799894883">"Bezdrôtové núdzové upozornenia"</string>
+    <string name="emergency_alert_settings_title_watches" msgid="4477073412799894883">"Bezdrôtové tiesňové výstrahy"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="7293800023375154256">"Prezidentské upozornenia"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="7900094335808247024">"Národné upozornenia vydané prezidentom. Nie je ich možné vypnúť."</string>
     <string name="receive_cmas_in_second_language_title" msgid="1223260365527361964"></string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index f979cb449..8403bf5dd 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -63,7 +63,7 @@
     <string name="notification_channel_broadcast_messages_in_voicecall" msgid="3291001780110813190">"Обавештења у хитним случајевима током гласовног позива"</string>
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"Аутоматске промене подешавања бежичних упозорења о хитним случајевима на основу SIM-а"</string>
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Дозволи обавештења"</string>
-    <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Шаљи ми бежична обавештења о хитним случајевима"</string>
+    <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Шаљи ми обавештења о хитним случајевима преко мреже"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Подсетник за обавештења"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"Изговори поруку обавештења"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Користи претварање текста у говор за изговарање порука бежичних обавештења о хитним случајевима"</string>
@@ -100,8 +100,8 @@
     <string name="enable_alert_vibrate_summary" msgid="4733669825477146614"></string>
     <string name="override_dnd_title" msgid="5120805993144214421">"Увек обавештавај пуном јачином звука"</string>
     <string name="override_dnd_summary" msgid="9026675822792800258">"Игнорише Не узнемиравај и друга подешавања јачине звука"</string>
-    <string name="enable_area_update_info_alerts_title" msgid="3442042268424617226">"Обавештења о ажурирању подручја"</string>
-    <string name="enable_area_update_info_alerts_summary" msgid="6437816607144264910">"Приказуј информације о ажурирању у статусу SIM картице"</string>
+    <string name="enable_area_update_info_alerts_title" msgid="3442042268424617226">"Емитовања новости за подручје"</string>
+    <string name="enable_area_update_info_alerts_summary" msgid="6437816607144264910">"Приказ најновијих информација у статусу SIM картице"</string>
     <string name="cmas_category_heading" msgid="3923503130776640717">"Категорија упозорења:"</string>
     <string name="cmas_category_geo" msgid="4979494217069688527">"Геофизичка"</string>
     <string name="cmas_category_met" msgid="7563732573851773537">"Метеоролошка"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 3cd8ddc34..7dbca630b 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -172,7 +172,7 @@
     <string name="seconds" msgid="141450721520515025">"sekunde"</string>
     <string name="message_copied" msgid="6922953753733166675">"Ujumbe umenakiliwa"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
-    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Wakati unatumia mitandao ya ng\'ambo au huna SIM inayotumika, huenda ukapata arifa fulani ambazo hazijajumuisha katika mipangilio hii"</string>
+    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Wakati unatumia mitandao ya ng\'ambo au huna SIM inayotumika, huenda ukapata arifa fulani ambazo hazijajumuishwa katika mipangilio hii"</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"Mipangilio yako imebadilika"</string>
     <string name="notification_cb_settings_changed_text" msgid="8722470940705858715">"Mipangilio ya tahadhari za dharura kupitia vifaa vya mkononi imewekwa upya kwa sababu umebadilisha SIM yako"</string>
 </resources>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index de6e0912f..588496e26 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -56,7 +56,7 @@
     <string name="public_safety_message" msgid="9119928798786998252">"பொதுமக்களுக்கான பாதுகாப்புச் செய்தி"</string>
     <string name="state_local_test_alert" msgid="8003145745857480200">"மாநில/உள்ளூர் சோதனை மெசேஜ்கள்"</string>
     <string name="emergency_alert" msgid="624783871477634263">"அவசரகால எச்சரிக்கை"</string>
-    <string name="emergency_alerts_title" msgid="6605036374197485429">"எச்சரிக்கைகள்"</string>
+    <string name="emergency_alerts_title" msgid="6605036374197485429">"விழிப்பூட்டல்கள்"</string>
     <string name="notification_channel_broadcast_messages" msgid="880704362482824524">"வலைபரப்புச் செய்திகள்"</string>
     <string name="notification_channel_emergency_alerts" msgid="5008287980979183617">"அவசரகால எச்சரிக்கைகள்"</string>
     <string name="notification_channel_emergency_alerts_high_priority" msgid="3937475297436439073">"உறுதிசெய்யப்படாத அவசரகால எச்சரிக்கைகள்"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 25108d1af..8fbdc777e 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -77,7 +77,7 @@
     <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"ภัยคุกคามที่ร้ายแรง"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"ภัยคุกคามต่อชีวิตและทรัพย์สินระดับรุนแรง"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"การแจ้งเตือนเด็กหาย Amber Alert"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"กระดานข่าวสารเหตุฉุกเฉินการลักพาตัวเด็ก"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"ประกาศข่าวสารเหตุฉุกเฉินการลักพาตัวเด็ก"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"ข้อความแจ้งเตือน"</string>
     <string name="enable_alert_message_summary" msgid="6525664541696985610">"เตือนเกี่ยวกับภัยคุกคามความปลอดภัยที่จะเกิดขึ้น"</string>
     <string name="enable_public_safety_messages_title" msgid="5576770949182656524">"ข้อความด้านความปลอดภัยสาธารณะ"</string>
@@ -136,8 +136,8 @@
     <string name="delivery_time_heading" msgid="5980836543433619329">"ได้รับ:"</string>
     <string name="notification_multiple" msgid="5121978148152124860">"<xliff:g id="COUNT">%s</xliff:g> การแจ้งเตือนที่ยังไม่ได้อ่าน"</string>
     <string name="notification_multiple_title" msgid="1523638925739947855">"การแจ้งเตือนใหม่"</string>
-    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"แสดงกล่องโต้ตอบเพื่อเลือกไม่ใช้งานหลังจากแสดงการแจ้งเตือนแรก (นอกเหนือจากการแจ้งเตือนระดับสูง)"</string>
-    <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"แสดงกล่องโต้ตอบเพื่อเลือกไม่ใช้งาน"</string>
+    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"แสดงกล่องโต้ตอบเพื่อเลือกไม่รับหลังจากแสดงการแจ้งเตือนแรก (นอกเหนือจากการแจ้งเตือนระดับสูง)"</string>
+    <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"แสดงกล่องโต้ตอบเพื่อเลือกไม่รับ"</string>
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"ขณะนี้คุณรับการแจ้งเหตุฉุกเฉินแบบไร้สาย คุณต้องการรับการแจ้งเหตุฉุกเฉินแบบไร้สายต่อหรือไม่"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"ใช่"</string>
     <string name="cmas_opt_out_button_no" msgid="3110484064328538553">"ไม่ใช่"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 210208cec..628a2414a 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -136,7 +136,7 @@
     <string name="delivery_time_heading" msgid="5980836543433619329">"接收时间："</string>
     <string name="notification_multiple" msgid="5121978148152124860">"<xliff:g id="COUNT">%s</xliff:g> 条未读警报。"</string>
     <string name="notification_multiple_title" msgid="1523638925739947855">"新警报"</string>
-    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"在显示第一条警报（国家级警报除外）后，显示是否停收警报的对话框。"</string>
+    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"在显示第一条警报后，显示是否停收警报的对话框（国家级警报除外）。"</string>
     <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"显示警报停收对话框"</string>
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"您目前已设置接收无线紧急警报。要继续接收无线紧急警报吗？"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"是"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 99290efbe..d5005720b 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -76,7 +76,7 @@
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"極嚴重的生命財產威脅"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"嚴重威脅"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"嚴重的生命財產威脅"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"安珀警示"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"安珀警報"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"誘拐兒童緊急事件公告"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"警示訊息"</string>
     <string name="enable_alert_message_summary" msgid="6525664541696985610">"對即將發生的安全威脅發出警告"</string>
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java
index 4d896ae87..fa754b569 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java
@@ -490,7 +490,9 @@ public class CellBroadcastAlertService extends Service {
         if (channelManager.isEmergencyMessage(cbm) && !sRemindAfterCallFinish) {
             // start alert sound / vibration / TTS and display full-screen alert
             openEmergencyAlertNotification(cbm);
-            Resources res = CellBroadcastSettings.getResources(mContext, cbm.getSubscriptionId());
+            Resources res = CellBroadcastSettings.getResourcesByOperator(mContext,
+                    cbm.getSubscriptionId(),
+                    CellBroadcastReceiver.getRoamingOperatorSupported(mContext));
 
             CellBroadcastChannelRange range = channelManager
                     .getCellBroadcastChannelRangeFromMessage(cbm);
@@ -618,14 +620,20 @@ public class CellBroadcastAlertService extends Service {
 
         if (resourcesKey == R.array.exercise_alert_range_strings
                 && res.getBoolean(R.bool.show_separate_exercise_settings)) {
-            return emergencyAlertEnabled && checkAlertConfigEnabled(
+            return emergencyAlertEnabled
+                    && CellBroadcastSettings.isExerciseTestAlertsToggleVisible(
+                    res, getApplicationContext(), channelManager)
+                    && checkAlertConfigEnabled(
                     subId, CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS,
                     res.getBoolean(R.bool.test_exercise_alerts_enabled_default));
         }
 
         if (resourcesKey == R.array.operator_defined_alert_range_strings
                 && res.getBoolean(R.bool.show_separate_operator_defined_settings)) {
-            return emergencyAlertEnabled && checkAlertConfigEnabled(
+            return emergencyAlertEnabled
+                    && CellBroadcastSettings.isOperatorTestAlertsToggleVisible(
+                    res, getApplicationContext(), channelManager)
+                    && checkAlertConfigEnabled(
                     subId, CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS,
                     res.getBoolean(R.bool.test_operator_defined_alerts_enabled_default));
         }
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastConfigService.java b/src/com/android/cellbroadcastreceiver/CellBroadcastConfigService.java
index 78e31b68b..b64ff88f1 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastConfigService.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastConfigService.java
@@ -301,17 +301,28 @@ public class CellBroadcastConfigService extends IntentService {
                         && prefs.getBoolean(CellBroadcastSettings.KEY_ENABLE_TEST_ALERTS,
                         false)));
 
+        CellBroadcastChannelManager channelManager = new CellBroadcastChannelManager(
+                getApplicationContext(), SubscriptionManager.getDefaultSubscriptionId(),
+                roamingOperator);
         boolean enableExerciseAlerts = enableAlertsMasterToggle && (isRoaming
                 ? (res.getBoolean(R.bool.show_separate_exercise_settings)
+                && CellBroadcastSettings.isExerciseTestAlertsToggleVisible(
+                        res, getApplicationContext(), channelManager)
                 && res.getBoolean(R.bool.test_exercise_alerts_enabled_default))
                 : (res.getBoolean(R.bool.show_separate_exercise_settings)
+                        && CellBroadcastSettings.isExerciseTestAlertsToggleVisible(
+                                res, getApplicationContext(), channelManager)
                         && prefs.getBoolean(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS,
                         false)));
 
         boolean enableOperatorDefined = enableAlertsMasterToggle && (isRoaming
                 ? (res.getBoolean(R.bool.show_separate_operator_defined_settings)
+                && CellBroadcastSettings.isOperatorTestAlertsToggleVisible(
+                        res, getApplicationContext(), channelManager)
                 && res.getBoolean(R.bool.test_operator_defined_alerts_enabled_default))
                 : (res.getBoolean(R.bool.show_separate_operator_defined_settings)
+                        && CellBroadcastSettings.isOperatorTestAlertsToggleVisible(
+                                res, getApplicationContext(), channelManager)
                         && prefs.getBoolean(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS,
                         false)));
 
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastSearchIndexableProvider.java b/src/com/android/cellbroadcastreceiver/CellBroadcastSearchIndexableProvider.java
index e6c5ec553..3d2da1fb3 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastSearchIndexableProvider.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastSearchIndexableProvider.java
@@ -42,6 +42,7 @@ import android.content.pm.PackageManager;
 import android.content.res.Resources;
 import android.database.Cursor;
 import android.database.MatrixCursor;
+import android.os.UserManager;
 import android.provider.SearchIndexableResource;
 import android.provider.SearchIndexablesProvider;
 import android.telephony.SubscriptionManager;
@@ -104,6 +105,32 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
         return CellBroadcastSettings.isTestAlertsToggleVisible(getContextMethod());
     }
 
+    /**
+     * this method is to make this class unit-testable, because
+     * CellBroadcastSettings.isExerciseTestAlertsToggleVisible is a static method and
+     * therefore not mockable
+     *
+     * @return true if test alerts toggle is Visible
+     */
+    @VisibleForTesting
+    public boolean isExerciseTestAlertsToggleVisible(CellBroadcastChannelManager channelManager) {
+        return CellBroadcastSettings.isExerciseTestAlertsToggleVisible(
+                getResourcesMethod(), getContext(), channelManager);
+    }
+
+    /**
+     * this method is to make this class unit-testable, because
+     * CellBroadcastSettings.isOperatorTestAlertsToggleVisible is a static method and
+     * therefore not mockable
+     *
+     * @return true if test alerts toggle is Visible
+     */
+    @VisibleForTesting
+    public boolean isOperatorTestAlertsToggleVisible(CellBroadcastChannelManager channelManager) {
+        return CellBroadcastSettings.isOperatorTestAlertsToggleVisible(
+                getResourcesMethod(), getContext(), channelManager);
+    }
+
     /**
      * this method is to make this class unit-testable, because
      * CellBroadcastSettings.isShowFullScreenMessageVisible is a static method and therefore not
@@ -199,15 +226,52 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
 
         Resources res = getResourcesMethod();
         Object[] ref;
+        final UserManager userManager = getContextMethod().getSystemService(UserManager.class);
+        boolean isAdminUser = userManager.isAdminUser();
+
+        if (!isAdminUser) {
+            ref = new Object[1];
+            ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
+                    CellBroadcastSettings.class.getSimpleName();
+            cursor.addRow(ref);
+        }
+
+        if (!isAdminUser || !res.getBoolean(R.bool.show_main_switch_settings)) {
+            ref = new Object[1];
+            ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
+                    CellBroadcastSettings.KEY_ENABLE_ALERTS_MASTER_TOGGLE;
+            cursor.addRow(ref);
+        }
 
-        if (!res.getBoolean(R.bool.show_presidential_alerts_settings)) {
+        if (!isAdminUser) {
+            ref = new Object[1];
+            ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
+                    CellBroadcastSettings.KEY_EMERGENCY_ALERT_HISTORY;
+            cursor.addRow(ref);
+        }
+
+        if (!isAdminUser) {
+            ref = new Object[1];
+            ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
+                    CellBroadcastSettings.KEY_ALERT_REMINDER_INTERVAL;
+            cursor.addRow(ref);
+        }
+
+        if (!isAdminUser || !res.getBoolean(R.bool.show_override_dnd_settings)) {
+            ref = new Object[1];
+            ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
+                    CellBroadcastSettings.KEY_OVERRIDE_DND;
+            cursor.addRow(ref);
+        }
+
+        if (!isAdminUser || !res.getBoolean(R.bool.show_presidential_alerts_settings)) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
                     CellBroadcastSettings.KEY_ENABLE_CMAS_PRESIDENTIAL_ALERTS;
             cursor.addRow(ref);
         }
 
-        if (!CellBroadcastSettings.getResources(getContextMethod(),
+        if (!isAdminUser || !CellBroadcastSettings.getResources(getContextMethod(),
                         SubscriptionManager.DEFAULT_SUBSCRIPTION_ID)
                 .getBoolean(R.bool.show_alert_speech_setting)) {
             ref = new Object[1];
@@ -216,7 +280,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
             cursor.addRow(ref);
         }
 
-        if (!res.getBoolean(R.bool.show_extreme_alert_settings)) {
+        if (!isAdminUser || !res.getBoolean(R.bool.show_extreme_alert_settings)) {
             // Remove CMAS preference items in emergency alert category.
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
@@ -224,7 +288,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
             cursor.addRow(ref);
         }
 
-        if (!res.getBoolean(R.bool.show_severe_alert_settings)) {
+        if (!isAdminUser || !res.getBoolean(R.bool.show_severe_alert_settings)) {
 
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
@@ -232,14 +296,14 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
             cursor.addRow(ref);
         }
 
-        if (!res.getBoolean(R.bool.show_amber_alert_settings)) {
+        if (!isAdminUser || !res.getBoolean(R.bool.show_amber_alert_settings)) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
                     CellBroadcastSettings.KEY_ENABLE_CMAS_AMBER_ALERTS;
             cursor.addRow(ref);
         }
 
-        if (!res.getBoolean(R.bool.config_showAreaUpdateInfoSettings)) {
+        if (!isAdminUser || !res.getBoolean(R.bool.config_showAreaUpdateInfoSettings)) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
                     CellBroadcastSettings.KEY_ENABLE_AREA_UPDATE_INFO_ALERTS;
@@ -248,7 +312,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
 
         CellBroadcastChannelManager channelManager = new CellBroadcastChannelManager(
                 getContextMethod(), SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
-        if (channelManager.getCellBroadcastChannelRanges(
+        if (!isAdminUser || channelManager.getCellBroadcastChannelRanges(
                 R.array.cmas_amber_alerts_channels_range_strings).isEmpty()) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
@@ -256,7 +320,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
             cursor.addRow(ref);
         }
 
-        if (channelManager.getCellBroadcastChannelRanges(
+        if (!isAdminUser || channelManager.getCellBroadcastChannelRanges(
                 R.array.emergency_alerts_channels_range_strings).isEmpty()) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
@@ -264,7 +328,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
             cursor.addRow(ref);
         }
 
-        if (channelManager.getCellBroadcastChannelRanges(
+        if (!isAdminUser || channelManager.getCellBroadcastChannelRanges(
                 R.array.public_safety_messages_channels_range_strings).isEmpty()) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
@@ -272,7 +336,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
             cursor.addRow(ref);
         }
 
-        if (channelManager.getCellBroadcastChannelRanges(
+        if (!isAdminUser || channelManager.getCellBroadcastChannelRanges(
                 R.array.state_local_test_alert_range_strings).isEmpty()) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
@@ -280,14 +344,29 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
             cursor.addRow(ref);
         }
 
-        if (!isTestAlertsToggleVisible()) {
+        if (!isAdminUser || !isTestAlertsToggleVisible()) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
                     CellBroadcastSettings.KEY_ENABLE_TEST_ALERTS;
             cursor.addRow(ref);
         }
 
-        if (res.getString(R.string.emergency_alert_second_language_code).isEmpty()) {
+        if (!isAdminUser || !isExerciseTestAlertsToggleVisible(channelManager)) {
+            ref = new Object[1];
+            ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
+                    CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS;
+            cursor.addRow(ref);
+        }
+
+        if (!isAdminUser || !isOperatorTestAlertsToggleVisible(channelManager)) {
+            ref = new Object[1];
+            ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
+                    CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS;
+            cursor.addRow(ref);
+        }
+
+        if (!isAdminUser
+                || res.getString(R.string.emergency_alert_second_language_code).isEmpty()) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
                     CellBroadcastSettings.KEY_RECEIVE_CMAS_IN_SECOND_LANGUAGE;
@@ -296,14 +375,14 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
 
         boolean isVisibleVibrationSetting = CellBroadcastSettings
                 .isVibrationToggleVisible(getContextMethod(), res);
-        if (!isVisibleVibrationSetting) {
+        if (!isAdminUser || !isVisibleVibrationSetting) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
                     CellBroadcastSettings.KEY_ENABLE_ALERT_VIBRATE;
             cursor.addRow(ref);
         }
 
-        if (!isShowFullScreenMessageVisible(res)) {
+        if (!isAdminUser || !isShowFullScreenMessageVisible(res)) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
                     CellBroadcastSettings.KEY_ENABLE_PUBLIC_SAFETY_MESSAGES_FULL_SCREEN;
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java b/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java
index 106a28406..116f9a8f1 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java
@@ -669,31 +669,13 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
             }
 
             if (mExerciseTestCheckBox != null) {
-                boolean visible = false;
-                if (res.getBoolean(R.bool.show_separate_exercise_settings)) {
-                    if (res.getBoolean(R.bool.show_exercise_settings)
-                            || CellBroadcastReceiver.isTestingMode(getContext())) {
-                        if (!channelManager.getCellBroadcastChannelRanges(
-                                R.array.exercise_alert_range_strings).isEmpty()) {
-                            visible = true;
-                        }
-                    }
-                }
-                mExerciseTestCheckBox.setVisible(visible);
+                mExerciseTestCheckBox.setVisible(
+                        isExerciseTestAlertsToggleVisible(res, getContext(), channelManager));
             }
 
             if (mOperatorDefinedCheckBox != null) {
-                boolean visible = false;
-                if (res.getBoolean(R.bool.show_separate_operator_defined_settings)) {
-                    if (res.getBoolean(R.bool.show_operator_defined_settings)
-                            || CellBroadcastReceiver.isTestingMode(getContext())) {
-                        if (!channelManager.getCellBroadcastChannelRanges(
-                                R.array.operator_defined_alert_range_strings).isEmpty()) {
-                            visible = true;
-                        }
-                    }
-                }
-                mOperatorDefinedCheckBox.setVisible(visible);
+                mOperatorDefinedCheckBox.setVisible(
+                        isOperatorTestAlertsToggleVisible(res, getContext(), channelManager));
             }
 
             if (mEmergencyAlertsCheckBox != null) {
@@ -967,6 +949,36 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
         return false;
     }
 
+    /**
+     * Check whether exercise test alert toggle is visible
+     * @param res Resources
+     * @param context Context
+     * @param channelManager ChannelManager
+     */
+    public static boolean isExerciseTestAlertsToggleVisible(Resources res, Context context,
+            CellBroadcastChannelManager channelManager) {
+        return res.getBoolean(R.bool.show_separate_exercise_settings)
+                && (res.getBoolean(R.bool.show_exercise_settings)
+                || CellBroadcastReceiver.isTestingMode(context))
+                && !channelManager.getCellBroadcastChannelRanges(
+                R.array.exercise_alert_range_strings).isEmpty();
+    }
+
+    /**
+     * Check whether operator test alert toggle is visible
+     * @param res Resources
+     * @param context Context
+     * @param channelManager ChannelManager
+     */
+    public static boolean isOperatorTestAlertsToggleVisible(Resources res, Context context,
+            CellBroadcastChannelManager channelManager) {
+        return res.getBoolean(R.bool.show_separate_operator_defined_settings)
+                && (res.getBoolean(R.bool.show_operator_defined_settings)
+                || CellBroadcastReceiver.isTestingMode(context))
+                && !channelManager.getCellBroadcastChannelRanges(
+                R.array.operator_defined_alert_range_strings).isEmpty();
+    }
+
     public static boolean isTestAlertsToggleVisible(Context context) {
         return isTestAlertsToggleVisible(context, null);
     }
diff --git a/tests/compliancetests/Android.bp b/tests/compliancetests/Android.bp
index 22dd98576..77fcf7250 100644
--- a/tests/compliancetests/Android.bp
+++ b/tests/compliancetests/Android.bp
@@ -31,7 +31,7 @@ java_defaults {
         "mockito-target-minus-junit4",
         "truth",
         "ub-uiautomator",
-        "android.telephony.mockmodem",
+        "cellbroadcast.mockmodem",
         "modules-utils-build_system",
         "junit-params",
     ],
@@ -40,6 +40,22 @@ java_defaults {
     platform_apis: true,
 }
 
+java_import {
+    name: "prebuilt_cellbroadcast_mockmodem",
+    jars: ["mockmodem/classes.jar"],
+}
+
+android_library {
+    name: "cellbroadcast.mockmodem",
+    asset_dirs: ["mockmodem/assets"],
+    manifest: "mockmodem/AndroidManifest.xml",
+    static_libs: [
+        "prebuilt_cellbroadcast_mockmodem",
+    ],
+    min_sdk_version: "30",
+    platform_apis: true,
+}
+
 android_test {
     name: "CellBroadcastReceiverComplianceTests",
     defaults: ["CellBroadcastTestCommonComplianceTest"],
diff --git a/tests/compliancetests/assets/emergency_alert_channels.json b/tests/compliancetests/assets/emergency_alert_channels.json
index fe2915b91..ed2de49e4 100644
--- a/tests/compliancetests/assets/emergency_alert_channels.json
+++ b/tests/compliancetests/assets/emergency_alert_channels.json
@@ -693,43 +693,6 @@
       "title": "子供の誘拐（誘拐事件速報）", //"Child abduction (Amber alert)",
       "default_value": "true",
       "toggle_avail": "true"
-    },
-    "43008": {
-      "title": "緊急地震速報", //"Earthquake warning",
-      "default_value": "true",
-      "toggle_avail": "false"
-    },
-    "45038": {
-      "title": "津波警報", //"Tsunami warning",
-      "default_value": "true",
-      "toggle_avail": "false",
-      "warning_type": "02"
-    },
-    "44032": {
-      "title": "緊急速報メール", //"Emergency warning",
-      "default_value": "true",
-      "toggle_avail": "false",
-      "end_channel": "45037"
-    },
-    "45000": {
-      "title": "緊急速報メール", //"Emergency warning",
-      "default_value": "true",
-      "toggle_avail": "false"
-    },
-    "45037": {
-      "title": "緊急速報メール", //"Emergency warning",
-      "default_value": "true",
-      "toggle_avail": "false"
-    },
-    "43010": {
-      "title": "ETWS 試験メッセージ", //"ETWS test message",
-      "default_value": "false",
-      "toggle_avail": "false"
-    },
-    "43012": {
-      "title": "ETWS 試験メッセージ", //"ETWS test message",
-      "default_value": "false",
-      "toggle_avail": "false"
     }
   },
   "hongkong": {
diff --git a/tests/compliancetests/mockmodem/AndroidManifest.xml b/tests/compliancetests/mockmodem/AndroidManifest.xml
new file mode 100644
index 000000000..71fdccdc2
--- /dev/null
+++ b/tests/compliancetests/mockmodem/AndroidManifest.xml
@@ -0,0 +1,38 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2022 The Android Open Source Project
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
+-->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+     package="android.telephony.mockmodem">
+
+    <!-- Must be debuggable for compat shell commands to work on user builds -->
+    <application android:debuggable="true">
+        <service android:name="android.telephony.mockmodem.MockModemService"
+             android:directBootAware="true"
+             android:persistent="true"
+             android:exported="true">
+            <intent-filter>
+                <action android:name="android.telephony.mockmodem.iradioconfig"/>
+                <action android:name="android.telephony.mockmodem.iradiomodem"/>
+                <action android:name="android.telephony.mockmodem.iradiosim"/>
+                <action android:name="android.telephony.mockmodem.iradionetwork"/>
+                <action android:name="android.telephony.mockmodem.iradiodata"/>
+                <action android:name="android.telephony.mockmodem.iradiomessaging"/>
+                <action android:name="android.telephony.mockmodem.iradiovoice"/>
+                <action android:name="android.telephony.mockmodem.iradioims"/>
+            </intent-filter>
+        </service>
+    </application>
+</manifest>
diff --git a/tests/compliancetests/mockmodem/assets/mock_network_tw_cht.xml b/tests/compliancetests/mockmodem/assets/mock_network_tw_cht.xml
new file mode 100644
index 000000000..1a0e8c626
--- /dev/null
+++ b/tests/compliancetests/mockmodem/assets/mock_network_tw_cht.xml
@@ -0,0 +1,56 @@
+<?xml version="1.0" encoding="utf-8"?>
+<MockNetwork carrierid="1">
+    <MockCellProperty>
+        <EHPLMNLIST>46692</EHPLMNLIST>
+        <AllowRoamingList>310026</AllowRoamingList>
+    </MockCellProperty>
+
+    <MockNetworkProfile id="0" rat="LTE" connection="primary">
+        <MockCellIdentity>
+            <MCC>466</MCC>
+            <MNC>92</MNC>
+            <CI>101</CI>
+            <PCI>273</PCI>
+            <TAC>13100</TAC>
+            <EARFCN>9260</EARFCN>
+            <OperatorInfo>
+                <AlphaLong>Chung Hwa Telecom</AlphaLong>
+                <AlphaShort>CHT</AlphaShort>
+                <OperatorNumeric>46692</OperatorNumeric>
+            </OperatorInfo>
+        </MockCellIdentity>
+
+        <MockCellSignalStrength>
+            <SignalStrength>20</SignalStrength>
+            <RSRP>71</RSRP>
+            <RSRQ>6</RSRQ>
+            <RSSNR>100</RSSNR>
+            <CQI>13</CQI>
+            <TimingAdvance>0</TimingAdvance>
+            <CqiTableIndex>1</CqiTableIndex>
+        </MockCellSignalStrength>
+    </MockNetworkProfile>
+
+    <MockNetworkProfile id="1" rat="WCDMA">
+        <MockCellIdentity>
+            <MCC>466</MCC>
+            <MNC>92</MNC>
+            <LAC>9222</LAC>
+            <CID>14549</CID>
+            <PSC>413</PSC>
+            <UARFCN>10613</UARFCN>
+            <OperatorInfo>
+                <AlphaLong>Chung Hwa Telecom</AlphaLong>
+                <AlphaShort>CHT</AlphaShort>
+                <OperatorNumeric>46692</OperatorNumeric>
+            </OperatorInfo>
+        </MockCellIdentity>
+
+        <MockCellSignalStrength>
+            <SignalStrength>20</SignalStrength>
+            <BitErrorRate>3</BitErrorRate>
+            <RSCP>45</RSCP>
+            <ECNO>25</ECNO>
+        </MockCellSignalStrength>
+    </MockNetworkProfile>
+</MockNetwork>
diff --git a/tests/compliancetests/mockmodem/assets/mock_network_tw_fet.xml b/tests/compliancetests/mockmodem/assets/mock_network_tw_fet.xml
new file mode 100644
index 000000000..140768ebc
--- /dev/null
+++ b/tests/compliancetests/mockmodem/assets/mock_network_tw_fet.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="utf-8"?>
+<MockNetwork carrierid="2">
+    <MockCellProperty>
+        <EHPLMNLIST>46601,46605</EHPLMNLIST>
+        <AllowRoamingList>310026</AllowRoamingList>
+    </MockCellProperty>
+
+    <MockNetworkProfile id="0" rat="WCDMA" connection="primary">
+        <MockCellIdentity>
+            <MCC>466</MCC>
+            <MNC>01</MNC>
+            <LAC>8122</LAC>
+            <CID>16249</CID>
+            <PSC>413</PSC>
+            <UARFCN>10613</UARFCN>
+            <OperatorInfo>
+                <AlphaLong>Far EasTone</AlphaLong>
+                <AlphaShort>FET</AlphaShort>
+                <OperatorNumeric>46601</OperatorNumeric>
+            </OperatorInfo>
+        </MockCellIdentity>
+
+        <MockCellSignalStrength>
+            <SignalStrength>10</SignalStrength>
+            <BitErrorRate>6</BitErrorRate>
+            <RSCP>55</RSCP>
+            <ECNO>15</ECNO>
+        </MockCellSignalStrength>
+    </MockNetworkProfile>
+</MockNetwork>
diff --git a/tests/compliancetests/mockmodem/assets/mock_network_us_fi.xml b/tests/compliancetests/mockmodem/assets/mock_network_us_fi.xml
new file mode 100644
index 000000000..bf194c47b
--- /dev/null
+++ b/tests/compliancetests/mockmodem/assets/mock_network_us_fi.xml
@@ -0,0 +1,56 @@
+<?xml version="1.0" encoding="utf-8"?>
+<MockNetwork carrierid="3">
+    <MockCellProperty>
+        <EHPLMNLIST>312580</EHPLMNLIST>
+        <AllowRoamingList>310026</AllowRoamingList>
+    </MockCellProperty>
+
+    <MockNetworkProfile id="0" rat="LTE" connection="primary">
+        <MockCellIdentity>
+            <MCC>312</MCC>
+            <MNC>580</MNC>
+            <CI>101</CI>
+            <PCI>273</PCI>
+            <TAC>13100</TAC>
+            <EARFCN>9260</EARFCN>
+            <OperatorInfo>
+                <AlphaLong>Google Fi</AlphaLong>
+                <AlphaShort>Fi</AlphaShort>
+                <OperatorNumeric>312580</OperatorNumeric>
+            </OperatorInfo>
+        </MockCellIdentity>
+
+        <MockCellSignalStrength>
+            <SignalStrength>20</SignalStrength>
+            <RSRP>71</RSRP>
+            <RSRQ>6</RSRQ>
+            <RSSNR>100</RSSNR>
+            <CQI>13</CQI>
+            <TimingAdvance>0</TimingAdvance>
+            <CqiTableIndex>1</CqiTableIndex>
+        </MockCellSignalStrength>
+    </MockNetworkProfile>
+
+    <MockNetworkProfile id="1" rat="WCDMA">
+        <MockCellIdentity>
+            <MCC>312</MCC>
+            <MNC>580</MNC>
+            <LAC>9222</LAC>
+            <CID>14549</CID>
+            <PSC>413</PSC>
+            <UARFCN>10613</UARFCN>
+            <OperatorInfo>
+                <AlphaLong>Google Fi</AlphaLong>
+                <AlphaShort>Fi</AlphaShort>
+                <OperatorNumeric>312580</OperatorNumeric>
+            </OperatorInfo>
+        </MockCellIdentity>
+
+        <MockCellSignalStrength>
+            <SignalStrength>20</SignalStrength>
+            <BitErrorRate>3</BitErrorRate>
+            <RSCP>45</RSCP>
+            <ECNO>25</ECNO>
+        </MockCellSignalStrength>
+    </MockNetworkProfile>
+</MockNetwork>
diff --git a/tests/compliancetests/mockmodem/assets/mock_sim_tw_cht.xml b/tests/compliancetests/mockmodem/assets/mock_sim_tw_cht.xml
new file mode 100644
index 000000000..6125c2d19
--- /dev/null
+++ b/tests/compliancetests/mockmodem/assets/mock_sim_tw_cht.xml
@@ -0,0 +1,32 @@
+<MockSim numofapp="2" atr="3B9F96801FC78031E073FE2111634082918307900099">
+<MockSimProfile id="0" type="APPTYPE_USIM">
+    <PinProfile appstate="APPSTATE_READY">
+        <Pin1State>PINSTATE_DISABLED</Pin1State>
+        <Pin2State>PINSTATE_ENABLED_NOT_VERIFIED</Pin2State>
+    </PinProfile>
+
+    <FacilityLock>
+        <FD>LOCK_DISABLED</FD>
+        <SC>LOCK_DISABLED</SC>
+    </FacilityLock>
+
+    <MF name="MF" path="3F00">
+        <EFDIR name="ADF1" curr_active="true">A0000000871002F886FF9289050B00FE</EFDIR>
+    </MF>
+
+    <ADF aid="A0000000871002F886FF9289050B00FE">
+        <EF name="EF_IMSI" id="6F07" command="" mnc-digit="2">466920123456789</EF>
+        <EF name="EF_ICCID" id="2FE2" command="0xb0">89886920042507847155</EF>
+        <EF name="EF_ICCID" id="2FE2" command="0xc0">0000000A2FE2040000FFFF01020002</EF>
+        <EF name="EF_GID1" id="6F3E" command="0xb0">BA01270000000000</EF>
+        <EF name="EF_GID1" id="6F3E" command="0xc0">000000086F3E040000FFFF01020002</EF>
+    </ADF>
+</MockSimProfile>
+
+<MockSimProfile id="1" type="APPTYPE_ISIM">
+    <PinProfile appstate="APPSTATE_DETECTED">
+        <Pin1State>PINSTATE_DISABLED</Pin1State>
+        <Pin2State>PINSTATE_ENABLED_NOT_VERIFIED</Pin2State>
+    </PinProfile>
+</MockSimProfile>
+</MockSim>
diff --git a/tests/compliancetests/mockmodem/assets/mock_sim_tw_fet.xml b/tests/compliancetests/mockmodem/assets/mock_sim_tw_fet.xml
new file mode 100644
index 000000000..4463d8816
--- /dev/null
+++ b/tests/compliancetests/mockmodem/assets/mock_sim_tw_fet.xml
@@ -0,0 +1,23 @@
+<MockSim numofapp="1" atr="3B9E95801FC78031E073FE211B66D001A0E50F0048">
+<MockSimProfile id="0" type="APPTYPE_USIM">
+    <PinProfile appstate="APPSTATE_READY">
+        <Pin1State>PINSTATE_DISABLED</Pin1State>
+        <Pin2State>PINSTATE_ENABLED_NOT_VERIFIED</Pin2State>
+    </PinProfile>
+
+    <FacilityLock>
+        <FD>LOCK_DISABLED</FD>
+        <SC>LOCK_DISABLED</SC>
+    </FacilityLock>
+
+    <MF name="MF" path="3F00">
+        <EFDIR name="ADF1" curr_active="true">A0000000871002FF33FFFF8901010100</EFDIR>
+    </MF>
+
+    <ADF aid="A0000000871002FF33FFFF8901010100">
+        <EF name="EF_IMSI" id="6F07" command="" mnc-digit="2">466011122334455</EF>
+        <EF name="EF_ICCID" id="2FE2" command="0xb0">89886021157300856597</EF>
+        <EF name="EF_ICCID" id="2FE2" command="0xc0">0000000A2FE2040000FFFF01020002</EF>
+    </ADF>
+</MockSimProfile>
+</MockSim>
\ No newline at end of file
diff --git a/tests/compliancetests/mockmodem/assets/mock_sim_us_fi.xml b/tests/compliancetests/mockmodem/assets/mock_sim_us_fi.xml
new file mode 100644
index 000000000..0e4ccc342
--- /dev/null
+++ b/tests/compliancetests/mockmodem/assets/mock_sim_us_fi.xml
@@ -0,0 +1,32 @@
+<MockSim numofapp="2" atr="3B9F97C00A3FC6828031E073FE211F65D002341512810F51">
+<MockSimProfile id="0" type="APPTYPE_USIM">
+    <PinProfile appstate="APPSTATE_READY">
+        <Pin1State>PINSTATE_DISABLED</Pin1State>
+        <Pin2State>PINSTATE_ENABLED_NOT_VERIFIED</Pin2State>
+    </PinProfile>
+
+    <FacilityLock>
+        <FD>LOCK_DISABLED</FD>
+        <SC>LOCK_DISABLED</SC>
+    </FacilityLock>
+
+    <MF name="MF" path="3F00">
+        <EFDIR name="ADF1" curr_active="true">A0000000871002F310FFFF89190417FF</EFDIR>
+    </MF>
+
+    <ADF aid="A0000000871002F310FFFF89190417FF">
+        <EF name="EF_IMSI" id="6F07" command="" mnc-digit="3">312580123456789</EF>
+        <EF name="EF_ICCID" id="2FE2" command="0xb0">89015801000037773143</EF>
+        <EF name="EF_ICCID" id="2FE2" command="0xc0">0000000A2FE2040000FFFF01020002</EF>
+        <EF name="EF_GID1" id="6F3E" command="0xb0">0001</EF>
+        <EF name="EF_GID1" id="6F3E" command="0xc0">000000026F3E040000FFFF01020002</EF>
+    </ADF>
+</MockSimProfile>
+
+<MockSimProfile id="1" type="APPTYPE_ISIM">
+    <PinProfile appstate="APPSTATE_DETECTED">
+        <Pin1State>PINSTATE_DISABLED</Pin1State>
+        <Pin2State>PINSTATE_ENABLED_NOT_VERIFIED</Pin2State>
+    </PinProfile>
+</MockSimProfile>
+</MockSim>
diff --git a/tests/compliancetests/mockmodem/classes.jar b/tests/compliancetests/mockmodem/classes.jar
new file mode 100644
index 000000000..961422a1c
Binary files /dev/null and b/tests/compliancetests/mockmodem/classes.jar differ
diff --git a/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java b/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java
index d805fc2e0..a364dec54 100644
--- a/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java
+++ b/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java
@@ -144,9 +144,7 @@ public class CellBroadcastBaseTest {
     @BeforeClass
     public static void beforeAllTests() throws Exception {
         logd("CellBroadcastBaseTest#beforeAllTests()");
-        // TODO: Make cellbroadcastcompliancetest use old mockmodem lib so that test can be
-        // run on the previous platform as well.
-        if (!SdkLevel.isAtLeastV()) {
+        if (!SdkLevel.isAtLeastT()) {
             Log.i(TAG, "sdk level is below the latest platform");
             sPreconditionError = ERROR_SDK_VERSION;
             return;
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index d09d94b03..046bc1221 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -82,7 +82,6 @@ android_test {
     instrumentation_for: "CellBroadcastApp",
     test_suites: [
         "device-tests",
-        "mts-cellbroadcast",
     ],
     manifest: "AndroidManifest.xml",
     test_config: "AndroidTest.xml",
@@ -96,9 +95,9 @@ android_test {
     instrumentation_for: "CellBroadcastApp",
     test_suites: [
         "general-tests",
-        "mts-cellbroadcast",
     ],
     manifest: "AndroidManifest.xml",
+    target_sdk_version: "10000",
     test_config: "AndroidTest_PixelExperience.xml",
 }
 
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertDialogTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertDialogTest.java
index cfb896222..02043dc64 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertDialogTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertDialogTest.java
@@ -20,7 +20,9 @@ import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.ArgumentMatchers.nullable;
 import static org.mockito.Mockito.atLeastOnce;
+import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.times;
@@ -41,11 +43,13 @@ import android.content.pm.ProviderInfo;
 import android.content.res.Configuration;
 import android.content.res.Resources;
 import android.os.Bundle;
+import android.os.IBinder;
 import android.os.IPowerManager;
 import android.os.IThermalService;
 import android.os.Looper;
 import android.os.Message;
 import android.os.PowerManager;
+import android.os.RemoteException;
 import android.telephony.SmsCbMessage;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
@@ -76,6 +80,8 @@ import org.mockito.ArgumentCaptor;
 import org.mockito.Captor;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
+import org.mockito.invocation.InvocationOnMock;
+import org.mockito.stubbing.Answer;
 
 import java.lang.reflect.Field;
 import java.lang.reflect.Method;
@@ -147,6 +153,10 @@ public class CellBroadcastAlertDialogTest extends
         // PowerManager is a final class so we can't use Mockito to mock it, but we can mock
         // its underlying service.
         doReturn(true).when(mMockedPowerManagerService).isInteractive();
+        if (SdkLevel.isAtLeastU()) {
+            doReturn(true).when(
+                    mMockedPowerManagerService).isDisplayInteractive(anyInt());
+        }
         mPowerManager = new PowerManager(mContext, mMockedPowerManagerService,
                 mMockedThermalService, null);
         injectSystemService(PowerManager.class, mPowerManager);
@@ -286,6 +296,23 @@ public class CellBroadcastAlertDialogTest extends
         };
         mMockedActivityManagerHelper = new MockedServiceManager();
         mMockedActivityManagerHelper.replaceService("window", mWindowManagerService);
+        Field fieldHandler = ActivityManager.class.getDeclaredField("IActivityManagerSingleton");
+        fieldHandler.setAccessible(true);
+        Singleton<IActivityManager> activityManager =
+                (Singleton<IActivityManager>) fieldHandler.get(null);
+        IActivityManager realInstance = activityManager.get();
+        doAnswer(new Answer() {
+            public Void answer(InvocationOnMock invocation) throws RemoteException {
+                if (realInstance != null) {
+                    realInstance.finishReceiver(invocation.getArgument(0),
+                            invocation.getArgument(1), invocation.getArgument(2),
+                            invocation.getArgument(3), invocation.getArgument(4),
+                            invocation.getArgument(5));
+                }
+                return null;
+            }
+        }).when(mMockedActivityManager).finishReceiver(nullable(IBinder.class), anyInt(),
+                nullable(String.class), nullable(Bundle.class), anyBoolean(), anyInt());
         mMockedActivityManagerHelper.replaceInstance(ActivityManager.class,
                 "IActivityManagerSingleton", null, activityManagerSingleton);
     }
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertServiceTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertServiceTest.java
index a7f5df8e1..54dfe35bd 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertServiceTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertServiceTest.java
@@ -67,6 +67,8 @@ import android.view.Display;
 
 import com.android.cellbroadcastreceiver.CellBroadcastAlertAudio;
 import com.android.cellbroadcastreceiver.CellBroadcastAlertService;
+import com.android.cellbroadcastreceiver.CellBroadcastChannelManager;
+import com.android.cellbroadcastreceiver.CellBroadcastReceiver;
 import com.android.cellbroadcastreceiver.CellBroadcastSettings;
 import com.android.internal.telephony.gsm.SmsCbConstants;
 import com.android.modules.utils.build.SdkLevel;
@@ -141,6 +143,8 @@ public class CellBroadcastAlertServiceTest extends
 
     @After
     public void tearDown() throws Exception {
+        CellBroadcastSettings.resetResourcesCache();
+        CellBroadcastChannelManager.clearAllCellBroadcastChannelRanges();
         super.tearDown();
     }
 
@@ -365,6 +369,86 @@ public class CellBroadcastAlertServiceTest extends
         compareCellBroadCastMessage(message, newMessageList.get(0));
     }
 
+    public void testShowNewAlertWithNotification() {
+        if (!SdkLevel.isAtLeastS()) {
+            return;
+        }
+        doReturn("").when(mMockedSharedPreferences).getString(
+                eq("roaming_operator_supported"), any());
+        doReturn(false).when(mResources).getBoolean(
+                com.android.cellbroadcastreceiver.R.bool.show_alert_dialog_with_notification);
+
+        Intent intent = new Intent(mContext, CellBroadcastAlertService.class);
+        intent.setAction(SHOW_NEW_ALERT_ACTION);
+        SmsCbMessage message = createMessage(34788612);
+        intent.putExtra("message", message);
+        startService(intent);
+        waitForServiceIntent();
+
+        verify(mMockedNotificationManager, times(0))
+                .notify(anyInt(), any());
+
+        doReturn(true).when(mResources).getBoolean(
+                com.android.cellbroadcastreceiver.R.bool.show_alert_dialog_with_notification);
+
+        intent = new Intent(mContext, CellBroadcastAlertService.class);
+        intent.setAction(SHOW_NEW_ALERT_ACTION);
+        message = createMessage(34788612);
+        intent.putExtra("message", message);
+        startService(intent);
+        waitForServiceIntent();
+
+        ArgumentCaptor<Notification> notificationCaptor =
+                ArgumentCaptor.forClass(Notification.class);
+        ArgumentCaptor<Integer> mInt = ArgumentCaptor.forClass(Integer.class);
+        verify(mMockedNotificationManager, times(1))
+                .notify(mInt.capture(), notificationCaptor.capture());
+        assertEquals(1, (int) mInt.getValue());
+    }
+
+    public void testShowNewAlertWithNotificationInRoaming() {
+        if (!SdkLevel.isAtLeastS()) {
+            return;
+        }
+        doReturn(false).when(mResources).getBoolean(
+                com.android.cellbroadcastreceiver.R.bool.show_alert_dialog_with_notification);
+        doReturn("123456").when(mMockedSharedPreferences).getString(
+                eq("roaming_operator_supported"), any());
+        Resources mockResources2 = mock(Resources.class);
+        CellBroadcastSettings.sResourcesCacheByOperator.put("123456", mockResources2);
+        doReturn("").when(mockResources2).getText(anyInt());
+
+        doReturn(false).when(mockResources2).getBoolean(
+                com.android.cellbroadcastreceiver.R.bool.show_alert_dialog_with_notification);
+
+        Intent intent = new Intent(mContext, CellBroadcastAlertService.class);
+        intent.setAction(SHOW_NEW_ALERT_ACTION);
+        SmsCbMessage message = createMessage(34788612);
+        intent.putExtra("message", message);
+        startService(intent);
+        waitForServiceIntent();
+
+        verify(mMockedNotificationManager, times(0))
+                .notify(anyInt(), any());
+
+        doReturn(true).when(mockResources2).getBoolean(
+                com.android.cellbroadcastreceiver.R.bool.show_alert_dialog_with_notification);
+
+        intent = new Intent(mContext, CellBroadcastAlertService.class);
+        intent.setAction(SHOW_NEW_ALERT_ACTION);
+        message = createMessage(34788612);
+        intent.putExtra("message", message);
+        startService(intent);
+        waitForServiceIntent();
+
+        ArgumentCaptor<Notification> notificationCaptor =
+                ArgumentCaptor.forClass(Notification.class);
+        ArgumentCaptor<Integer> intCaptor = ArgumentCaptor.forClass(Integer.class);
+        verify(mMockedNotificationManager, times(1))
+                .notify(intCaptor.capture(), notificationCaptor.capture());
+        assertEquals(1, (int) intCaptor.getValue());
+    }
+
     // Test showNewAlert method with a CMAS child abduction alert, using the default language code
     @InstrumentationTest
     // This test has a module dependency, so it is disabled for OEM testing because it is not a true
@@ -430,6 +514,7 @@ public class CellBroadcastAlertServiceTest extends
 
         putResources(com.android.cellbroadcastreceiver.R.bool.show_separate_exercise_settings,
                 true);
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings, true);
         putResources(com.android.cellbroadcastreceiver.R.array.exercise_alert_range_strings,
                 new String[]{
                     "0x111D:rat=gsm, emergency=true",
@@ -602,6 +687,285 @@ public class CellBroadcastAlertServiceTest extends
         ((TestContextWrapper) mContext).injectCreateConfigurationContext(null);
     }
 
+    public void testShouldDisplayMessageForExerciseAlerts() {
+        putResources(com.android.cellbroadcastreceiver.R.array
+                .exercise_alert_range_strings, new String[]{
+                    "0x111D:rat=gsm, emergency=true",
+                });
+        sendMessage(1);
+
+        CellBroadcastAlertService cellBroadcastAlertService =
+                (CellBroadcastAlertService) getService();
+        SmsCbMessage message = new SmsCbMessage(1, 2, 3, new SmsCbLocation(),
+                SmsCbConstants.MESSAGE_ID_CMAS_ALERT_EXERCISE,
+                "language", "body",
+                SmsCbMessage.MESSAGE_PRIORITY_NORMAL, null,
+                null, 0, 1);
+
+        enablePreference(CellBroadcastSettings.KEY_ENABLE_ALERTS_MASTER_TOGGLE);
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .show_separate_exercise_settings, true);
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .test_exercise_alerts_enabled_default, false);
+        // disable testing mode
+        disablePreference(CellBroadcastReceiver.TESTING_MODE);
+
+        enablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings, true);
+        assertTrue("Should enable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings, false);
+        assertFalse("Should disable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        disablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings, true);
+        assertFalse("Should disable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings, false);
+        assertFalse("Should disable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        // enable testing mode
+        enablePreference(CellBroadcastReceiver.TESTING_MODE);
+
+        enablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings, true);
+        assertTrue("Should enable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings, false);
+        assertTrue("Should enable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        disablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings, true);
+        assertFalse("Should disable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings, false);
+        assertFalse("Should disable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        // roaming case
+        Context mockContext = mock(Context.class);
+        Resources mockResources = mock(Resources.class);
+        doReturn(mockResources).when(mockContext).getResources();
+        ((TestContextWrapper) mContext).injectCreateConfigurationContext(mockContext);
+        // inject roaming operator
+        doReturn("123").when(mMockedSharedPreferences)
+                .getString(anyString(), anyString());
+        doReturn(true).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool.show_separate_exercise_settings));
+
+        // disable testing mode
+        disablePreference(CellBroadcastReceiver.TESTING_MODE);
+
+        doReturn(true).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings));
+        doReturn(false).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool.test_exercise_alerts_enabled_default));
+        disablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        assertFalse("Should disable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+        enablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        assertTrue("Should enable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        doReturn(true).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool.test_exercise_alerts_enabled_default));
+        disablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        assertTrue("Should enable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+        enablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        assertTrue("Should enable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        doReturn(false).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings));
+        disablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        assertFalse("Should disable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+        enablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        assertFalse("Should disable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        doReturn(false).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool.test_exercise_alerts_enabled_default));
+        disablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        assertFalse("Should disable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+        enablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        assertFalse("Should disable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        // enable testing mode
+        enablePreference(CellBroadcastReceiver.TESTING_MODE);
+        disablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        assertFalse("Should disable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+        enablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        assertTrue("Should enable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        doReturn(true).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool.test_exercise_alerts_enabled_default));
+        disablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        assertTrue("Should enable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+        enablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        assertTrue("Should enable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        ((TestContextWrapper) mContext).injectCreateConfigurationContext(null);
+    }
+
+    public void testShouldDisplayMessageForOperatorAlerts() {
+        putResources(com.android.cellbroadcastreceiver.R.array
+                .operator_defined_alert_range_strings, new String[]{
+                    "0x111E:rat=gsm, emergency=true",
+                });
+        sendMessage(1);
+
+        CellBroadcastAlertService cellBroadcastAlertService =
+                (CellBroadcastAlertService) getService();
+        SmsCbMessage message = new SmsCbMessage(1, 2, 3, new SmsCbLocation(),
+                SmsCbConstants.MESSAGE_ID_CMAS_ALERT_OPERATOR_DEFINED_USE,
+                "language", "body",
+                SmsCbMessage.MESSAGE_PRIORITY_NORMAL, null,
+                null, 0, 1);
+
+        enablePreference(CellBroadcastSettings.KEY_ENABLE_ALERTS_MASTER_TOGGLE);
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .show_separate_operator_defined_settings, true);
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .test_operator_defined_alerts_enabled_default, false);
+        // disable testing mode
+        disablePreference(CellBroadcastReceiver.TESTING_MODE);
+
+        enablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_operator_defined_settings, true);
+        assertTrue("Should enable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .show_operator_defined_settings, false);
+        assertFalse("Should disable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        disablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_operator_defined_settings, true);
+        assertFalse("Should disable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .show_operator_defined_settings, false);
+        assertFalse("Should disable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        // enable testing mode
+        enablePreference(CellBroadcastReceiver.TESTING_MODE);
+
+        enablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_operator_defined_settings, true);
+        assertTrue("Should enable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .show_operator_defined_settings, false);
+        assertTrue("Should enable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        disablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_operator_defined_settings, true);
+        assertFalse("Should disable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .show_operator_defined_settings, false);
+        assertFalse("Should disable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        // roaming case
+        Context mockContext = mock(Context.class);
+        Resources mockResources = mock(Resources.class);
+        doReturn(mockResources).when(mockContext).getResources();
+        ((TestContextWrapper) mContext).injectCreateConfigurationContext(mockContext);
+        // inject roaming operator
+        doReturn("123").when(mMockedSharedPreferences)
+                .getString(anyString(), anyString());
+        doReturn(true).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool
+                        .show_separate_operator_defined_settings));
+
+        // disable testing mode
+        disablePreference(CellBroadcastReceiver.TESTING_MODE);
+
+        doReturn(true).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool.show_operator_defined_settings));
+        doReturn(false).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool
+                        .test_operator_defined_alerts_enabled_default));
+        disablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        assertFalse("Should disable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+        enablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        assertTrue("Should enable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        doReturn(true).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool
+                        .test_operator_defined_alerts_enabled_default));
+        disablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        assertTrue("Should enable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+        enablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        assertTrue("Should enable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        doReturn(false).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool.show_operator_defined_settings));
+        disablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        assertFalse("Should disable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+        enablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        assertFalse("Should disable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        doReturn(false).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool
+                        .test_operator_defined_alerts_enabled_default));
+        disablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        assertFalse("Should disable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+        enablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        assertFalse("Should disable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        // enable testing mode
+        enablePreference(CellBroadcastReceiver.TESTING_MODE);
+        disablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        assertFalse("Should disable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+        enablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        assertTrue("Should enable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        doReturn(true).when(mockResources).getBoolean(
+                eq(com.android.cellbroadcastreceiver.R.bool
+                        .test_operator_defined_alerts_enabled_default));
+        disablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        assertTrue("Should enable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+        enablePreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+        assertTrue("Should enable operator test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        ((TestContextWrapper) mContext).injectCreateConfigurationContext(null);
+    }
+
     public void testShouldDisplayMessageWithMasterToggleState() {
         Context mockContext = mock(Context.class);
         doReturn(mResources).when(mockContext).getResources();
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastConfigServiceTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastConfigServiceTest.java
index 86898cc77..2808abecb 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastConfigServiceTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastConfigServiceTest.java
@@ -21,10 +21,13 @@ import static com.android.cellbroadcastreceiver.CellBroadcastConfigService.CbCon
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
+import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.nullable;
 import static org.mockito.Matchers.any;
 import static org.mockito.Matchers.anyInt;
 import static org.mockito.Matchers.anyString;
 import static org.mockito.Mockito.atLeastOnce;
+import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.eq;
@@ -46,6 +49,7 @@ import android.content.SharedPreferences;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
 import android.os.Bundle;
+import android.os.IBinder;
 import android.os.RemoteException;
 import android.telephony.CellBroadcastIdRange;
 import android.telephony.SmsCbMessage;
@@ -60,6 +64,7 @@ import androidx.test.filters.SmallTest;
 
 import com.android.cellbroadcastreceiver.CellBroadcastAlertService;
 import com.android.cellbroadcastreceiver.CellBroadcastConfigService;
+import com.android.cellbroadcastreceiver.CellBroadcastReceiver;
 import com.android.cellbroadcastreceiver.CellBroadcastSettings;
 import com.android.internal.telephony.ISms;
 import com.android.internal.telephony.cdma.sms.SmsEnvelope;
@@ -72,7 +77,10 @@ import org.junit.Test;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Captor;
 import org.mockito.Mock;
+import org.mockito.invocation.InvocationOnMock;
+import org.mockito.stubbing.Answer;
 
+import java.lang.reflect.Field;
 import java.lang.reflect.Method;
 import java.util.ArrayList;
 import java.util.List;
@@ -760,6 +768,157 @@ public class CellBroadcastConfigServiceTest extends CellBroadcastTest {
         verifySetRanges(configs, 4, 2);
     }
 
+    /**
+     * Test enabling channels for exercise test channels
+     */
+    @Test
+    @SmallTest
+    public void testEnablingExerciseTestChannels() throws Exception {
+        setPreference(CellBroadcastSettings.KEY_ENABLE_ALERTS_MASTER_TOGGLE, true);
+
+        // check enable when setting is shown and preference is true
+        setPreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS, true);
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .show_separate_exercise_settings, true);
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .show_exercise_settings, true);
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .test_exercise_alerts_enabled_default, true);
+
+        CbConfig[] enableConfigs = new CbConfig[]{
+                new CbConfig(SmsCbConstants.MESSAGE_ID_CMAS_ALERT_EXERCISE,
+                        SmsCbConstants.MESSAGE_ID_CMAS_ALERT_EXERCISE,
+                        SmsCbMessage.MESSAGE_FORMAT_3GPP, true),
+        };
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(enableConfigs, 1, 1);
+
+        // check disable when preference is false
+        setPreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS, false);
+
+        CbConfig[] disableConfigs = new CbConfig[]{
+                new CbConfig(SmsCbConstants.MESSAGE_ID_CMAS_ALERT_EXERCISE,
+                        SmsCbConstants.MESSAGE_ID_CMAS_ALERT_EXERCISE,
+                        SmsCbMessage.MESSAGE_FORMAT_3GPP, false),
+        };
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(disableConfigs, 2, 1);
+
+        // check disable when setting is not shown
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings, false);
+
+        setPreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS, true);
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(disableConfigs, 3, 2);
+
+        // check disable when setting is not shown and preference is off
+        setPreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS, false);
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(disableConfigs, 4, 3);
+
+        // testingmode is on
+        // check disable when setting is shown and preference is off
+        setPreference(CellBroadcastReceiver.TESTING_MODE, true);
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(disableConfigs, 5, 4);
+
+        // check enable when setting is shown and preference is on
+        setPreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS, true);
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(enableConfigs, 6, 2);
+
+        // roaming case
+        Context mockContext = mock(Context.class);
+        doReturn(mResources).when(mockContext).getResources();
+        doReturn(mockContext).when(mContext).createConfigurationContext(any());
+        doReturn("123").when(mMockedSharedPreferences).getString(anyString(), anyString());
+        doReturn(mResources).when(mConfigService).getResources(anyInt(), anyString());
+
+        setPreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS, false);
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(enableConfigs, 7, 3);
+
+        setPreference(CellBroadcastReceiver.TESTING_MODE, false);
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(disableConfigs, 8, 5);
+    }
+
+    /**
+     * Test enabling channels for operator test channels
+     */
+    @Test
+    @SmallTest
+    public void testEnablingOperatorTestChannels() throws Exception {
+        setPreference(CellBroadcastSettings.KEY_ENABLE_ALERTS_MASTER_TOGGLE, true);
+
+        // check enable when setting is shown and preference is true
+        setPreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS, true);
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .show_separate_operator_defined_settings, true);
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .show_operator_defined_settings, true);
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .test_operator_defined_alerts_enabled_default, true);
+
+        CbConfig[] enableConfigs = new CbConfig[]{
+                new CbConfig(SmsCbConstants.MESSAGE_ID_CMAS_ALERT_OPERATOR_DEFINED_USE,
+                        SmsCbConstants.MESSAGE_ID_CMAS_ALERT_OPERATOR_DEFINED_USE,
+                        SmsCbMessage.MESSAGE_FORMAT_3GPP, true),
+        };
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(enableConfigs, 1, 1);
+
+        // check disable when preference is false
+        setPreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS, false);
+
+        CbConfig[] disableConfigs = new CbConfig[]{
+                new CbConfig(SmsCbConstants.MESSAGE_ID_CMAS_ALERT_OPERATOR_DEFINED_USE,
+                        SmsCbConstants.MESSAGE_ID_CMAS_ALERT_OPERATOR_DEFINED_USE,
+                        SmsCbMessage.MESSAGE_FORMAT_3GPP, false),
+        };
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(disableConfigs, 2, 1);
+
+        // check disable when setting is not shown
+        putResources(com.android.cellbroadcastreceiver.R.bool
+                .show_operator_defined_settings, false);
+
+        setPreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS, true);
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(disableConfigs, 3, 2);
+
+        // check disable when setting is not shown and preference is off
+        setPreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS, false);
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(disableConfigs, 4, 3);
+
+        // testingmode is on
+        // check disable when setting is shown and preference is off
+        setPreference(CellBroadcastReceiver.TESTING_MODE, true);
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(disableConfigs, 5, 4);
+
+        // check enable when setting is shown and preference is on
+        setPreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS, true);
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(enableConfigs, 6, 2);
+
+        // roaming case
+        Context mockContext = mock(Context.class);
+        doReturn(mResources).when(mockContext).getResources();
+        doReturn(mockContext).when(mContext).createConfigurationContext(any());
+        doReturn("123").when(mMockedSharedPreferences).getString(anyString(), anyString());
+        doReturn(mResources).when(mConfigService).getResources(anyInt(), anyString());
+
+        setPreference(CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS, false);
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(enableConfigs, 7, 3);
+
+        setPreference(CellBroadcastReceiver.TESTING_MODE, false);
+        mConfigService.enableCellBroadcastChannels(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID);
+        verifySetRanges(disableConfigs, 8, 5);
+    }
+
     /**
      * Test handling the intent to enable channels
      */
@@ -1546,6 +1705,23 @@ public class CellBroadcastConfigServiceTest extends CellBroadcastTest {
             }
         };
         mMockedServiceManager.replaceService("window", mWindowManagerService);
+        Field fieldHandler = ActivityManager.class.getDeclaredField("IActivityManagerSingleton");
+        fieldHandler.setAccessible(true);
+        Singleton<IActivityManager> activityManager =
+                (Singleton<IActivityManager>) fieldHandler.get(null);
+        IActivityManager realInstance = activityManager.get();
+        doAnswer(new Answer() {
+            public Void answer(InvocationOnMock invocation) throws RemoteException {
+                if (realInstance != null) {
+                    realInstance.finishReceiver(invocation.getArgument(0),
+                            invocation.getArgument(1), invocation.getArgument(2),
+                            invocation.getArgument(3), invocation.getArgument(4),
+                            invocation.getArgument(5));
+                }
+                return null;
+            }
+        }).when(mMockedActivityManager).finishReceiver(nullable(IBinder.class), anyInt(),
+                nullable(String.class), nullable(Bundle.class), anyBoolean(), anyInt());
         mMockedServiceManager.replaceInstance(ActivityManager.class,
                 "IActivityManagerSingleton", null, activityManagerSingleton);
         doNothing().when(mConfigService).resetAllPreferences();
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSearchIndexableProviderTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSearchIndexableProviderTest.java
index b34d4f00d..458c18f8c 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSearchIndexableProviderTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSearchIndexableProviderTest.java
@@ -18,13 +18,16 @@ package com.android.cellbroadcastreceiver.unit;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
+import android.content.Context;
 import android.database.Cursor;
+import android.os.UserManager;
 import android.os.Vibrator;
 
 import com.android.cellbroadcastreceiver.CellBroadcastSearchIndexableProvider;
@@ -37,6 +40,9 @@ import org.mockito.Mock;
 public class CellBroadcastSearchIndexableProviderTest extends CellBroadcastTest {
     CellBroadcastSearchIndexableProvider mSearchIndexableProvider;
 
+    @Mock
+    UserManager mUserManager;
+
     @Before
     public void setUp() throws Exception {
         super.setUp(getClass().getSimpleName());
@@ -48,6 +54,9 @@ public class CellBroadcastSearchIndexableProviderTest extends CellBroadcastTest
         doReturn(mResources).when(mSearchIndexableProvider).getResourcesMethod();
         doReturn("testString").when(mResources).getString(anyInt());
         doReturn(null).when(mSearchIndexableProvider).queryRawData(null);
+        doReturn(Context.USER_SERVICE).when(mContext).getSystemServiceName(UserManager.class);
+        doReturn(mUserManager).when(mContext).getSystemService(Context.USER_SERVICE);
+        doReturn(true).when(mUserManager).isAdminUser();
     }
 
     @Test
@@ -79,6 +88,10 @@ public class CellBroadcastSearchIndexableProviderTest extends CellBroadcastTest
         doReturn(mVibrator).when(mContext).getSystemService("test");
         doReturn(true).when(mVibrator).hasVibrator();
         doReturn(false).when(mSearchIndexableProvider).isShowFullScreenMessageVisible(mResources);
+        doReturn(false).when(mSearchIndexableProvider)
+                .isExerciseTestAlertsToggleVisible(any());
+        doReturn(false).when(mSearchIndexableProvider)
+                .isOperatorTestAlertsToggleVisible(any());
         Cursor cursor = mSearchIndexableProvider.queryNonIndexableKeys(new String[]{""});
 
         //KEY_RECEIVE_CMAS_IN_SECOND_LANGUAGE
@@ -87,27 +100,76 @@ public class CellBroadcastSearchIndexableProviderTest extends CellBroadcastTest
         //KEY_ENABLE_PUBLIC_SAFETY_MESSAGES
         //KEY_ENABLE_EMERGENCY_ALERTS
         //KEY_ENABLE_CMAS_AMBER_ALERTS
-        //KEY_ENABLE_AREA_UPDATE_INFO_ALERTS
+        //KEY_ENABLE_AREA_UPDATE_INFO_ALERTSf
         //KEY_ENABLE_CMAS_AMBER_ALERTS
         //KEY_ENABLE_CMAS_SEVERE_THREAT_ALERTS
         //KEY_ENABLE_CMAS_EXTREME_THREAT_ALERTS
         //KEY_ENABLE_ALERT_SPEECH
         //KEY_ENABLE_CMAS_PRESIDENTIAL_ALERTS
-        assertThat(cursor.getCount()).isEqualTo(13);
+        //KEY_ENABLE_ALERTS_MASTER_TOGGLE
+        //KEY_OVERRIDE_DND
+        //KEY_ENABLE_EXERCISE_ALERTS
+        //KEY_OPERATOR_DEFINED_ALERTS
+        assertThat(cursor.getCount()).isEqualTo(17);
 
         doReturn(false).when(mVibrator).hasVibrator();
         //KEY_ENABLE_ALERT_VIBRATE
         cursor = mSearchIndexableProvider.queryNonIndexableKeys(new String[]{""});
-        assertThat(cursor.getCount()).isEqualTo(14);
+        assertThat(cursor.getCount()).isEqualTo(18);
 
         doReturn(true).when(mSearchIndexableProvider).isTestAlertsToggleVisible();
         //KEY_ENABLE_TEST_ALERTS
         cursor = mSearchIndexableProvider.queryNonIndexableKeys(new String[]{""});
-        assertThat(cursor.getCount()).isEqualTo(13);
+        assertThat(cursor.getCount()).isEqualTo(17);
 
         doReturn(true).when(mSearchIndexableProvider).isShowFullScreenMessageVisible(mResources);
         //KEY_ENABLE_TEST_ALERTS
         cursor = mSearchIndexableProvider.queryNonIndexableKeys(new String[]{""});
-        assertThat(cursor.getCount()).isEqualTo(12);
+        assertThat(cursor.getCount()).isEqualTo(16);
+
+        doReturn(true).when(mSearchIndexableProvider)
+                .isExerciseTestAlertsToggleVisible(any());
+        doReturn(true).when(mSearchIndexableProvider)
+                .isOperatorTestAlertsToggleVisible(any());
+        cursor = mSearchIndexableProvider.queryNonIndexableKeys(new String[]{""});
+        assertThat(cursor.getCount()).isEqualTo(14);
+    }
+
+    @Test
+    public void testQueryNonIndexableKeysWithNonAdminMode() {
+        doReturn(false).when(mSearchIndexableProvider).isTestAlertsToggleVisible();
+        doReturn(false).when(mResources).getBoolean(anyInt());
+        doReturn("").when(mResources).getString(anyInt());
+        doReturn("test").when(mContext).getSystemServiceName(Vibrator.class);
+        doReturn(mVibrator).when(mContext).getSystemService("test");
+        doReturn(true).when(mVibrator).hasVibrator();
+        doReturn(false).when(mSearchIndexableProvider).isShowFullScreenMessageVisible(mResources);
+        doReturn(false).when(mSearchIndexableProvider)
+                .isExerciseTestAlertsToggleVisible(any());
+        doReturn(false).when(mSearchIndexableProvider)
+                .isOperatorTestAlertsToggleVisible(any());
+        doReturn(false).when(mUserManager).isAdminUser();
+        Cursor cursor = mSearchIndexableProvider.queryNonIndexableKeys(new String[]{""});
+
+        //KEY_RECEIVE_CMAS_IN_SECOND_LANGUAGE
+        //KEY_ENABLE_TEST_ALERTS
+        //KEY_ENABLE_STATE_LOCAL_TEST_ALERTS
+        //KEY_ENABLE_PUBLIC_SAFETY_MESSAGES
+        //KEY_ENABLE_EMERGENCY_ALERTS
+        //KEY_ENABLE_CMAS_AMBER_ALERTS
+        //KEY_ENABLE_AREA_UPDATE_INFO_ALERTS
+        //KEY_ENABLE_CMAS_AMBER_ALERTS
+        //KEY_ENABLE_CMAS_SEVERE_THREAT_ALERTS
+        //KEY_ENABLE_CMAS_EXTREME_THREAT_ALERTS
+        //KEY_ENABLE_ALERT_SPEECH
+        //KEY_ENABLE_CMAS_PRESIDENTIAL_ALERTS
+        //KEY_ENABLE_ALERTS_MASTER_TOGGLE
+        //KEY_OVERRIDE_DND
+        //KEY_ENABLE_EXERCISE_ALERTS
+        //KEY_OPERATOR_DEFINED_ALERTS
+        //KEY_EMERGENCY_ALERT_HISTORY
+        //KEY_ALERT_REMINDER_INTERVAL
+        //TITLE
+        assertThat(cursor.getCount()).isEqualTo(21);
     }
 }
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java
index 7402059c9..57821b872 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java
@@ -30,7 +30,6 @@ import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
-import android.content.BroadcastReceiver;
 import android.content.Context;
 import android.content.Intent;
 import android.content.SharedPreferences;
@@ -65,7 +64,6 @@ import org.mockito.Captor;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
-import java.lang.reflect.Field;
 import java.util.Locale;
 
 
@@ -104,6 +102,10 @@ public class CellBroadcastSettingsTest extends
         mDevice = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
         MockitoAnnotations.initMocks(this);
         CellBroadcastSettings.resetResourcesCache();
+        SubscriptionManager mockSubManager = mock(SubscriptionManager.class);
+        injectSystemService(SubscriptionManager.class, mockSubManager);
+        SubscriptionInfo mockSubInfo = mock(SubscriptionInfo.class);
+        doReturn(mockSubInfo).when(mockSubManager).getActiveSubscriptionInfo(anyInt());
     }
 
     @After
@@ -371,7 +373,6 @@ public class CellBroadcastSettingsTest extends
         String topIntroRoamingText = "test";
         doReturn(topIntroRoamingText).when(mContext.getResources()).getString(
                 eq(R.string.top_intro_roaming_text));
-        setSubscriptionManager();
         setPreference(PREFERENCE_PUT_TYPE_STRING, ROAMING_OPERATOR_SUPPORTED, "XXX");
 
         CellBroadcastSettings settings = startActivity();
@@ -383,7 +384,6 @@ public class CellBroadcastSettingsTest extends
 
     @Test
     public void testDoNotShowTestCheckBox() throws Throwable {
-        setSubscriptionManager();
         setPreference(PREFERENCE_PUT_TYPE_BOOL, TESTING_MODE, "false");
         doReturn(false).when(mContext.getResources()).getBoolean(
                 eq(R.bool.show_separate_exercise_settings));
@@ -394,6 +394,7 @@ public class CellBroadcastSettingsTest extends
         doReturn(new String[]{"0x111E:rat=gsm, emergency=true"}).when(mContext.getResources())
                 .getStringArray(eq(R.array.operator_defined_alert_range_strings));
         CellBroadcastSettings settings = startActivity();
+        waitForMs(100);
 
         TwoStatePreference exerciseTestCheckBox =
                 settings.mCellBroadcastSettingsFragment.findPreference(
@@ -402,24 +403,12 @@ public class CellBroadcastSettingsTest extends
                 settings.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
 
-        // received the ACTION_TESTING_MODE_CHANGED, do not show exerciseTestCheckBox &
-        // operatorDefinedCheckBox
-        Field fieldTestingModeChangedReceiver =
-                CellBroadcastSettings.CellBroadcastSettingsFragment.class.getDeclaredField(
-                        "mTestingModeChangedReceiver");
-        fieldTestingModeChangedReceiver.setAccessible(true);
-        BroadcastReceiver broadcastReceiver =
-                (BroadcastReceiver) fieldTestingModeChangedReceiver.get(
-                        settings.mCellBroadcastSettingsFragment);
-        broadcastReceiver.onReceive(mContext, new Intent().setAction(ACTION_TESTING_MODE_CHANGED));
-
         assertFalse(exerciseTestCheckBox.isVisible());
         assertFalse(operatorDefinedCheckBox.isVisible());
     }
 
     @Test
-    public void testShowTestCheckBox() throws Throwable {
-        setSubscriptionManager();
+    public void testShowTestCheckBoxWithTestingMode() throws Throwable {
         setPreference(PREFERENCE_PUT_TYPE_BOOL, TESTING_MODE, "true");
         doReturn(true).when(mContext.getResources()).getBoolean(
                 eq(R.bool.show_separate_exercise_settings));
@@ -430,6 +419,7 @@ public class CellBroadcastSettingsTest extends
         doReturn(new String[]{"0x111E:rat=gsm, emergency=true"}).when(mContext.getResources())
                 .getStringArray(eq(R.array.operator_defined_alert_range_strings));
         CellBroadcastSettings settings = startActivity();
+        waitForMs(100);
 
         TwoStatePreference exerciseTestCheckBox =
                 settings.mCellBroadcastSettingsFragment.findPreference(
@@ -438,28 +428,37 @@ public class CellBroadcastSettingsTest extends
                 settings.mCellBroadcastSettingsFragment.findPreference(
                         CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
 
-        // received the ACTION_TESTING_MODE_CHANGED, show exerciseTestCheckBox &
-        // operatorDefinedCheckBox
-        Field fieldTestingModeChangedReceiver =
-                CellBroadcastSettings.CellBroadcastSettingsFragment.class.getDeclaredField(
-                        "mTestingModeChangedReceiver");
-        fieldTestingModeChangedReceiver.setAccessible(true);
-        BroadcastReceiver broadcastReceiver =
-                (BroadcastReceiver) fieldTestingModeChangedReceiver.get(
-                        settings.mCellBroadcastSettingsFragment);
-        broadcastReceiver.onReceive(mContext, new Intent().setAction(ACTION_TESTING_MODE_CHANGED));
-
-        waitForChange(() -> exerciseTestCheckBox.isVisible(), TEST_TIMEOUT_MILLIS);
         assertTrue(exerciseTestCheckBox.isVisible());
-        waitForChange(() -> operatorDefinedCheckBox.isVisible(), TEST_TIMEOUT_MILLIS);
         assertTrue(operatorDefinedCheckBox.isVisible());
     }
 
-    private void setSubscriptionManager() {
-        SubscriptionManager mockSubManager = mock(SubscriptionManager.class);
-        injectSystemService(SubscriptionManager.class, mockSubManager);
-        SubscriptionInfo mockSubInfo = mock(SubscriptionInfo.class);
-        doReturn(mockSubInfo).when(mockSubManager).getActiveSubscriptionInfo(anyInt());
+    @Test
+    public void testShowTestCheckBox() throws Throwable {
+        setPreference(PREFERENCE_PUT_TYPE_BOOL, TESTING_MODE, "false");
+        doReturn(true).when(mContext.getResources()).getBoolean(
+                eq(R.bool.show_separate_exercise_settings));
+        doReturn(true).when(mContext.getResources()).getBoolean(
+                eq(R.bool.show_separate_operator_defined_settings));
+        doReturn(true).when(mContext.getResources()).getBoolean(
+                eq(R.bool.show_exercise_settings));
+        doReturn(true).when(mContext.getResources()).getBoolean(
+                eq(R.bool.show_operator_defined_settings));
+        doReturn(new String[]{"0x111D:rat=gsm, emergency=true"}).when(mContext.getResources())
+                .getStringArray(eq(R.array.exercise_alert_range_strings));
+        doReturn(new String[]{"0x111E:rat=gsm, emergency=true"}).when(mContext.getResources())
+                .getStringArray(eq(R.array.operator_defined_alert_range_strings));
+        CellBroadcastSettings settings = startActivity();
+        waitForMs(100);
+
+        TwoStatePreference exerciseTestCheckBox =
+                settings.mCellBroadcastSettingsFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        TwoStatePreference operatorDefinedCheckBox =
+                settings.mCellBroadcastSettingsFragment.findPreference(
+                        CellBroadcastSettings.KEY_OPERATOR_DEFINED_ALERTS);
+
+        assertTrue(exerciseTestCheckBox.isVisible());
+        assertTrue(operatorDefinedCheckBox.isVisible());
     }
 
     private void setPreference(int putType, String key, String value) {
```

