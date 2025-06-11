```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index b883e9712..662091733 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -138,6 +138,7 @@
                   android:launchMode="singleInstance"
                   android:exported="false"
                   android:excludeFromRecents="true"
+                  android:enableOnBackInvokedCallback="false"
                   android:configChanges="orientation|keyboardHidden|screenSize|keyboard|navigation">
             <intent-filter>
                 <action android:name="android.provider.Telephony.SMS_CB_RECEIVED" />
diff --git a/AndroidManifest_Platform.xml b/AndroidManifest_Platform.xml
index 0f2e48170..9cb7bd6c9 100644
--- a/AndroidManifest_Platform.xml
+++ b/AndroidManifest_Platform.xml
@@ -116,6 +116,7 @@
         android:launchMode="singleTask"
         android:exported="false"
         android:excludeFromRecents="true"
+        android:enableOnBackInvokedCallback="false"
         android:configChanges="orientation|keyboardHidden|screenSize|keyboard|navigation">
       <intent-filter>
         <action android:name="android.provider.Telephony.SMS_CB_RECEIVED" />
diff --git a/proguard.flags b/proguard.flags
index 9edd4ec23..8467f720a 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -2,7 +2,10 @@
 # http://proguard.sourceforge.net/index.html#manual/usage.html
 
 # Keep classes and methods that have the @VisibleForTesting annotation
--keep @com.android.internal.annotations.VisibleForTesting class *
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @com.android.internal.annotations.VisibleForTesting class * {
+    void <init>();
+}
 -keepclassmembers class * {
     @com.android.internal.annotations.VisibleForTesting *;
 }
@@ -32,7 +35,10 @@
 }
 
 # Keep annotated classes or class members.
--keep @androidx.annotation.Keep class *
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @androidx.annotation.Keep class * {
+    void <init>();
+}
 -keepclassmembers class * {
     @androidx.annotation.Keep *;
 }
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 4b5884d39..238c60967 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -65,7 +65,7 @@
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"السماح بالتنبيهات"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"تلقّي الإشعارات بإنذارات الطوارئ اللاسلكية"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"التذكير بالإنذارات"</string>
-    <string name="enable_alert_speech_title" msgid="8052104771053526941">"الاستماع إلى رسالة التنبيه"</string>
+    <string name="enable_alert_speech_title" msgid="8052104771053526941">"نطق رسالة التنبيه"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"استخدام ميزة \"تحويل النص إلى كلام\" للاستماع إلى رسائل إنذارات الطوارئ اللاسلكية"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"سيتم تشغيل صوت تذكير بمستوى صوت منتظم"</string>
     <string name="emergency_alert_history_title" msgid="8310173569237268431">"سجلّ تنبيهات الطوارئ"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 1cee2b4be..dfd6cf5d6 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -16,11 +16,11 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_label" msgid="2008319089248760277">"Bežična obaveštenja o hitnim slučajevima"</string>
-    <string name="sms_cb_settings" msgid="9021266457863671070">"Bežična obaveštenja o hitnim slučajevima"</string>
-    <string name="sms_cb_sender_name_default" msgid="972946539768958828">"Bežična upozorenja o hitnim slučajevima"</string>
-    <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Bežična upozorenja o hitnim slučajevima"</string>
-    <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Bežična upozorenja o hitnim slučajevima"</string>
+    <string name="app_label" msgid="2008319089248760277">"Upozorenja o hitnim slučajevima"</string>
+    <string name="sms_cb_settings" msgid="9021266457863671070">"Upozorenja o hitnim slučajevima"</string>
+    <string name="sms_cb_sender_name_default" msgid="972946539768958828">"Upozorenja o hitnim slučajevima"</string>
+    <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Upozorenja o hitnim slučajevima"</string>
+    <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Upozorenja o hitnim slučajevima"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informativno obaveštenje"</string>
     <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
     <skip />
@@ -138,7 +138,7 @@
     <string name="notification_multiple_title" msgid="1523638925739947855">"Nova upozorenja"</string>
     <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"Prikaži dijalog za onemogućavanje posle prikaza prvog upozorenja (osim predsedničkog upozorenja)."</string>
     <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"Prikaži dijalog za onemogućavanje"</string>
-    <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"Trenutno primate bežična obaveštenjenja o hitnim slučajevima. Želite li da nastavite da ih primate?"</string>
+    <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"Trenutno primate obaveštenjenja o hitnim slučajevima preko mobilne mreže. Želite li da nastavite da ih primate?"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"Da"</string>
     <string name="cmas_opt_out_button_no" msgid="3110484064328538553">"He"</string>
     <string name="cb_list_activity_title" msgid="1433502151877791724">"Istorija obaveštenja o hitnim slučajevima"</string>
@@ -151,7 +151,7 @@
     <item msgid="3863339891188103437">"Svakih 15 minuta"</item>
     <item msgid="7388573183644474611">"Nikad"</item>
   </string-array>
-    <string name="emergency_alert_settings_title_watches" msgid="4477073412799894883">"Bežična obaveštenja o hitnim slučajevima"</string>
+    <string name="emergency_alert_settings_title_watches" msgid="4477073412799894883">"Upozorenja o hitnim slučajevima"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="7293800023375154256">"Obaveštenja predsednika"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="7900094335808247024">"Upozorenja koja izdaje predsednik na nivou zemlje. Ne mogu da se isključe."</string>
     <string name="receive_cmas_in_second_language_title" msgid="1223260365527361964"></string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 70ccf6604..ab181d4d2 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -172,7 +172,7 @@
     <string name="seconds" msgid="141450721520515025">"sekundy"</string>
     <string name="message_copied" msgid="6922953753733166675">"Zpráva byla zkopírována"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
-    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Když používáte roaming nebo nemáte aktivní SIM kartu, můžete dostávat upozornění, která v těchto nastaveních nejsou zahrnuta"</string>
+    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Když používáte roaming nebo nemáte aktivní SIM kartu, můžete dostávat i upozornění, která v těchto nastaveních nejsou zahrnuta"</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"Vaše nastavení se změnilo"</string>
     <string name="notification_cb_settings_changed_text" msgid="8722470940705858715">"Nastavení bezdrátových výstražných zpráv byla resetována, protože se změnila vaše SIM karta"</string>
 </resources>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index 3b51de7bf..b8606cc27 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -33,7 +33,7 @@
     <string name="menu_view_details" msgid="1040989019045280975">"Προβολή λεπτομερειών"</string>
     <string name="menu_delete" msgid="128380070910799366">"Διαγραφή εκπομπής"</string>
     <string name="view_details_title" msgid="1780427629491781473">"Λεπτομέρειες ειδοποίησης"</string>
-    <string name="view_details_debugging_title" msgid="5699927030805114173">"Λεπτομέρειες ειδοποίησης για εντοπισμό και διόρθωση σφαλμάτων"</string>
+    <string name="view_details_debugging_title" msgid="5699927030805114173">"Λεπτομέρειες ειδοποίησης για αποσφαλμάτωση"</string>
     <string name="confirm_delete_broadcast" msgid="2540199303730232322">"Διαγραφή αυτής της μετάδοσης;"</string>
     <string name="confirm_delete_all_broadcasts" msgid="2924444089047280871">"Να διαγραφούν όλα τα ληφθέντα μηνύματα μετάδοσης;"</string>
     <string name="button_delete" msgid="4672451757925194350">"Διαγραφή"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index abad776c3..1f75ec13c 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -62,7 +62,7 @@
     <string name="notification_channel_emergency_alerts_high_priority" msgid="3937475297436439073">"Tähelepanuta jäänud hädaolukorra hoiatused"</string>
     <string name="notification_channel_broadcast_messages_in_voicecall" msgid="3291001780110813190">"Hädaolukorra teatised häälkõnes"</string>
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"WEA seadete automaatsed muudatused SIM-kaardi põhjal"</string>
-    <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Teatiste lubamine"</string>
+    <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Luba teatised"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Saate juhtmevabalt hädaolukorra teatisi"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Teatiste meeldetuletus"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"Märguandesõnumi esitamine kõnena"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 6d1be85fa..a1f55cf90 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -172,7 +172,7 @@
     <string name="seconds" msgid="141450721520515025">"segundo"</string>
     <string name="message_copied" msgid="6922953753733166675">"Kopiatu da mezua"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
-    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Ibiltaritza darabilzunean edo SIM aktiborik ez duzunean, baliteke ezarpen hauetan sartzen ez diren alerta batzuk jasotzea"</string>
+    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Ibiltaritzan zaudenean edo SIM aktiborik ez duzunean, baliteke ezarpen hauetan sartzen ez diren alerta batzuk jasotzea"</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"Ezarpenak aldatu dira"</string>
     <string name="notification_cb_settings_changed_text" msgid="8722470940705858715">"Gailuetarako larrialdi-alerten ezarpenak berrezarri dira, SIMa aldatu delako"</string>
 </resources>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 8df4f2012..e6c2584a0 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -76,7 +76,7 @@
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"تهدیدهای بسیار جدی جانی و مالی"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"تهدیدهای جدی"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"تهدیدهای جدی جانی و مالی"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"‏هشدارهای AMBER"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"هشدارهای امبر"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"بولتن‌های اضطراری کودک‌ربایی"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"پیام‌های هشدار"</string>
     <string name="enable_alert_message_summary" msgid="6525664541696985610">"هشدار درباره تهدیدهای ایمنی قریب‌الوقوع"</string>
@@ -172,7 +172,7 @@
     <string name="seconds" msgid="141450721520515025">"ثانیه"</string>
     <string name="message_copied" msgid="6922953753733166675">"پیام کپی شد"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
-    <string name="top_intro_roaming_text" msgid="5250650823028195358">"وقتی درحال فراگردی هستید یا سیم‌کارت فعال ندارید، ممکن است هشدارهایی دریافت کنید که در این تنظیمات لحاظ نشده‌اند"</string>
+    <string name="top_intro_roaming_text" msgid="5250650823028195358">"وقتی درحال فراگردی هستید یا سیم‌کارت فعال ندارید، ممکن است هشدارهایی دریافت کنید که در این تنظیمات گنجانده نشده‌اند"</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"تنظیماتتان تغییر کرد"</string>
     <string name="notification_cb_settings_changed_text" msgid="8722470940705858715">"تنظیمات هشدارهای اضطراری بی‌سیم به‌دلیل تغییر سیم‌کارتتان بازنشانی شد"</string>
 </resources>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 9c8527377..67cb658a5 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -65,7 +65,7 @@
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Salli hälytykset"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Vastaanota langattomia hätätiedotteita"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Hälytysmuistutus"</string>
-    <string name="enable_alert_speech_title" msgid="8052104771053526941">"Puhu varoitusilmoitus"</string>
+    <string name="enable_alert_speech_title" msgid="8052104771053526941">"Puhutut varoitusilmoitukset"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Käytä tekstistä puheeksi -toimintoa langattomissa vaaratiedotteissa"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"Muistutusääni soi tavallisella äänenvoimakkuudella"</string>
     <string name="emergency_alert_history_title" msgid="8310173569237268431">"Hätähälytyshistoria"</string>
@@ -136,7 +136,7 @@
     <string name="delivery_time_heading" msgid="5980836543433619329">"Vastaanotettu:"</string>
     <string name="notification_multiple" msgid="5121978148152124860">"<xliff:g id="COUNT">%s</xliff:g> lukematonta hälytystä"</string>
     <string name="notification_multiple_title" msgid="1523638925739947855">"Uusia hälytyksiä"</string>
-    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"Näytä kieltäytymisikkuna ensimmäisen hälytyksen jälkeen (muun kuin presidentin hälytyksen)."</string>
+    <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"Näytä kieltäytymisikkuna ensimmäisen hälytyksen jälkeen (muun kuin presidenttitason hälytyksen)."</string>
     <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"Näytä kieltäytymisikkuna"</string>
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"Vastaanotat tällä hetkellä langattomia hätähälytyksiä. Haluatko jatkaa langattomien hätähälytysten vastaanottamista?"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"Kyllä"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 5c6e787e3..5f2397351 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -89,14 +89,14 @@
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"Alertes d\'urgence"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"Avertir des événements potentiellement mortels"</string>
     <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"Alertes tests"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Recevoir des tests du fournisseur de services et des tests mensuels du système d\'alertes de sécurité"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Recevez des tests de l\'opérateur et des tests mensuels du système d\'alertes de sécurité"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
     <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"Recevoir une alerte d\'urgence : message en cas d\'exercice ou de simulation"</string>
     <!-- no translation found for enable_operator_defined_test_alerts_title (7459219458579095832) -->
     <skip />
     <string name="enable_operator_defined_test_alerts_summary" msgid="7856514354348843433">"Recevoir les alertes d\'urgence : défini par le fournisseur de services"</string>
-    <string name="enable_alert_vibrate_title" msgid="5421032189422312508">"Vibrations"</string>
+    <string name="enable_alert_vibrate_title" msgid="5421032189422312508">"Vibration"</string>
     <string name="enable_alert_vibrate_summary" msgid="4733669825477146614"></string>
     <string name="override_dnd_title" msgid="5120805993144214421">"Toujours émettre les alertes au plein volume"</string>
     <string name="override_dnd_summary" msgid="9026675822792800258">"Ignorer le mode Ne pas déranger et d\'autres paramètres de volume"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index d73bf7006..a832e6d0b 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -72,8 +72,8 @@
     <string name="alert_preferences_title" msgid="6001469026393248468">"અલર્ટની પસંદગીઓ"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"ETWSના પરીક્ષણ બ્રોડકાસ્ટ"</string>
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"ભૂકંપ ત્સુનામીની ચેતવણી આપતી સિસ્ટમ માટેનાં પરીક્ષણ બ્રોડકાસ્ટ"</string>
-    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5416260219062637770">"આત્યંતિક જોખમો"</string>
-    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"જીવન અને સંપત્તિના આત્યંતિક જોખમો"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="5416260219062637770">"ભારે જોખમો"</string>
+    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"જીવન અને સંપત્તિને ભારે જોખમો"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"ગંભીર જોખમો"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"જીવન અને સંપત્તિના ગંભીર જોખમો"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"AMBER અલર્ટ"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 3a020a1ba..19ed1cb82 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -62,7 +62,7 @@
     <string name="notification_channel_emergency_alerts_high_priority" msgid="3937475297436439073">"अस्वीकार की गई आपातकालीन चेतावनियां"</string>
     <string name="notification_channel_broadcast_messages_in_voicecall" msgid="3291001780110813190">"वॉयस कॉल के दौरान आपातकालीन चेतावनियां"</string>
     <string name="notification_channel_settings_updates" msgid="6779759372516475085">"अपने-आप काम करने वाली WEA की सूचनाओं की सेटिंग, सिम के हिसाब से बदल जाती है"</string>
-    <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"चेतावनी दिखाने की अनुमति दें"</string>
+    <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"चेतावनियां पाने की सुविधा चालू करें"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"खतरे की चेतावनी से जुड़ी सूचनाएं पाएं"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"चेतावनी का रिमाइंडर"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"चेतावनी वाले मैसेज की जानकारी बोलकर दें"</string>
@@ -88,7 +88,7 @@
     <string name="enable_state_local_test_alerts_summary" msgid="780298327377950187">"राज्य और स्थानीय अधिकारियों से टेस्ट मैसेज पाएं"</string>
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"इमरजेंसी के समय सूचनाएं"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"ऐसे मामलों के बारे में चेतावनी देना, जिनकी वजह से जान का खतरा हो सकता है"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"जांच करने के लिए भेजी जाने वाली चेतावनियां"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"टेस्ट अलर्ट"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"सुरक्षा से जुड़ी चेतावनी वाले सिस्टम से हर महीने टेस्ट अलर्ट पाएं. साथ ही, मोबाइल और इंटरनेट कंपनी से टेस्ट अलर्ट पाएं"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index c8efc4c61..df1f25ca6 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -77,7 +77,7 @@
     <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"Ozbiljne prijetnje"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"Ozbiljne prijetnje po život i imovinu"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"AMBER upozorenja"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"Hitni bilteni o otmicama djece"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"Hitne obavijesti o otmicama djece"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"Poruke upozorenja"</string>
     <string name="enable_alert_message_summary" msgid="6525664541696985610">"Upozorenja o neposrednim sigurnosnim prijetnjama"</string>
     <string name="enable_public_safety_messages_title" msgid="5576770949182656524">"Poruke o javnoj sigurnosti"</string>
@@ -89,7 +89,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"Hitna upozorenja"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"Upozorenja o događajima opasnima po život"</string>
     <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"Testna upozorenja"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Primajte testove mobilnog operatera i mjesečne testove sustava sigurnosnih upozorenja"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Primajte testove mobilnog operatera i mjesečne testove iz sustava sigurnosnih upozorenja"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
     <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"Primanje hitnih upozorenja: poruka o vježbi"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index bac0b45b7..38db333b0 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -65,7 +65,7 @@
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"Consenti avvisi"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"Ricevi notifiche per avvisi di emergenza wireless"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"Promemoria avvisi"</string>
-    <string name="enable_alert_speech_title" msgid="8052104771053526941">"Leggimi messaggio di allerta"</string>
+    <string name="enable_alert_speech_title" msgid="8052104771053526941">"Messaggio di allerta vocale"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"Usa la sintesi vocale per leggermi i messaggi degli avvisi di emergenza wireless"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"Verrà riprodotto un suono di promemoria a volume normale"</string>
     <string name="emergency_alert_history_title" msgid="8310173569237268431">"Cronologia avvisi di emergenza"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 18e8a146b..1616d32e7 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -89,7 +89,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"緊急速報メール"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"生死にかかわる出来事に関する警告"</string>
     <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"テストアラート"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"携帯通信会社のテストや、安全警告システムの毎月のテストを受信する"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"携帯通信会社のテストや、安全警告システムの毎月のテスト"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
     <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"緊急速報メール: 訓練用メッセージを受け取る"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index a1842dabd..a0e150124 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -34,8 +34,8 @@
     <string name="menu_delete" msgid="128380070910799366">"ಪ್ರಸಾರ ಅಳಿಸಿ"</string>
     <string name="view_details_title" msgid="1780427629491781473">"ಎಚ್ಚರಿಕೆ ವಿವರಗಳು"</string>
     <string name="view_details_debugging_title" msgid="5699927030805114173">"ಡೀಬಗ್ ಮಾಡುವಿಕೆಯ ಕುರಿತು ಎಚ್ಚರಿಕೆಯ ವಿವರಗಳು"</string>
-    <string name="confirm_delete_broadcast" msgid="2540199303730232322">"ಈ ಪ್ರಸಾರವನ್ನು ಅಳಿಸುವುದೇ?"</string>
-    <string name="confirm_delete_all_broadcasts" msgid="2924444089047280871">"ಸ್ವೀಕರಿಸಿದ ಎಲ್ಲಾ ಪ್ರಸಾರ ಸಂದೇಶಗಳನ್ನು ಅಳಿಸುವುದೇ?"</string>
+    <string name="confirm_delete_broadcast" msgid="2540199303730232322">"ಈ ಪ್ರಸಾರವನ್ನು ಅಳಿಸಬೇಕೆ?"</string>
+    <string name="confirm_delete_all_broadcasts" msgid="2924444089047280871">"ಸ್ವೀಕರಿಸಿದ ಎಲ್ಲಾ ಪ್ರಸಾರ ಸಂದೇಶಗಳನ್ನು ಅಳಿಸಬೇಕೆ?"</string>
     <string name="button_delete" msgid="4672451757925194350">"ಅಳಿಸಿ"</string>
     <string name="button_cancel" msgid="7479958360523246140">"ರದ್ದುಮಾಡಿ"</string>
     <string name="etws_earthquake_warning" msgid="6428741104423152511">"ಭೂಕಂಪ ಮುನ್ನೆಚ್ಚರಿಕೆ"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index 18981e5ab..549e45a43 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -17,7 +17,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_label" msgid="2008319089248760277">"긴급 재난 문자"</string>
-    <string name="sms_cb_settings" msgid="9021266457863671070">"긴급 재난 문자"</string>
+    <string name="sms_cb_settings" msgid="9021266457863671070">"무선 긴급 재난 문자"</string>
     <string name="sms_cb_sender_name_default" msgid="972946539768958828">"긴급 재난 문자"</string>
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"위급 재난 문자"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"긴급 재난 문자"</string>
@@ -68,7 +68,7 @@
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"경보 메시지를 음성으로 알림"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"재난문자를 TTS(텍스트 음성 변환) 기능을 사용하여 음성으로 알림"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"경보 알림음이 보통 볼륨으로 재생됨"</string>
-    <string name="emergency_alert_history_title" msgid="8310173569237268431">"긴급 경보 기록"</string>
+    <string name="emergency_alert_history_title" msgid="8310173569237268431">"긴급 재난 문자 기록"</string>
     <string name="alert_preferences_title" msgid="6001469026393248468">"재난문자 환경설정"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"ETWS 테스트 브로드캐스트"</string>
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"지진 해일 경보 시스템용 테스트 브로드캐스트"</string>
diff --git a/res/values-mcc232-mr/strings.xml b/res/values-mcc232-mr/strings.xml
index 0f680c557..fc0f1661c 100644
--- a/res/values-mcc232-mr/strings.xml
+++ b/res/values-mcc232-mr/strings.xml
@@ -35,5 +35,5 @@
     <string name="enable_exercise_test_alerts_title" msgid="569839026995925829">"चाचणी अलार्म"</string>
     <string name="enable_exercise_test_alerts_summary" msgid="9221851253406484290">"व्यायामाच्या संदर्भातील चाचणी अलार्म"</string>
     <string name="enable_cmas_test_alerts_title" msgid="3897522692038895778">"सेल प्रसारण चाचणी"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="3008029598281530835">"सेल प्रसारण संबंधित सिस्टम चाचण्या"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="3008029598281530835">"सेल प्रसारण संबंधित सिस्टीम चाचण्या"</string>
 </resources>
diff --git a/res/values-mcc270-af/strings.xml b/res/values-mcc270-af/strings.xml
index 28a9f84bb..de2c56eb1 100644
--- a/res/values-mcc270-af/strings.xml
+++ b/res/values-mcc270-af/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-waarskuwing"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-waarskuwing"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-waarskuwing"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-waarskuwing : Ontvoeringwaarskuwing"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-waarskuwing: Waarskuwing oor vermiste/ontvoerde persoon"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-waarskuwingtoets"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-waarskuwingoefening"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Ontvoering-veiligheidsberig"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Wys waarskuwingboodskappe oor kinderontvoerings"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Waarskuwing oor vermiste/ontvoerde persoon"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Wys waarskuwingboodskappe oor vermiste persoon of ontvoeringsituasies"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-waarskuwingtoets"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Wys toetsboodskappe"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-waarskuwingoefening"</string>
diff --git a/res/values-mcc270-am/strings.xml b/res/values-mcc270-am/strings.xml
index 206acaf9d..d4ae481c1 100644
--- a/res/values-mcc270-am/strings.xml
+++ b/res/values-mcc270-am/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"የልጅ ጠለፋ-ማንቂያ"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"የልጅ ጠለፋ-ማንቂያ"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"የልጅ ጠለፋ-ማንቂያ"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"የልጅ ጠለፋ-ማንቂያ ፦ የጠለፋ ማንቂያ"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-ማንቂያ፦ የጠፋ ሰው / የጠለፋ ማንቂያ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"የልጅ ጠለፋ-ማንቂያ ሙከራ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"የልጅ ጠለፋ-ማንቂያ ልምምድ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"የጠለፋ ማንቂያ"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"የልጅ ጠለፋዎች የማንቂያ መልዕክቶችን አሳይ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"የጠፋ ሰው/ የጠለፋ ማንቂያ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"ለጠፋ ሰው / ለጠለፋ ሁኔታዎች የማንቂያ መልዕክቶችን አሳይ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"የልጅ ጠለፋ-ማንቂያ ሙከራ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"የሙከራ መልዕክቶችን አሳይ"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"የልጅ ጠለፋ-ማንቂያ ልምምድ"</string>
diff --git a/res/values-mcc270-ar/strings.xml b/res/values-mcc270-ar/strings.xml
index b2984bc2f..557df8902 100644
--- a/res/values-mcc270-ar/strings.xml
+++ b/res/values-mcc270-ar/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"‏‫LU-Alert : تنبيه الاختطاف"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"‏‫LU-Alert: تنبيه بشأن اختفاء شخص أو اختطافه"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"‏اختبار تنبيه LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"‏تجربة تنبيه LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"تنبيه بشأن الاختطاف"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"إظهار رسائل تنبيه حول اختطاف الأطفال"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"تنبيه بشأن اختفاء شخص أو اختطافه"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"عرض رسائل تنبيه في حالات اختفاء الأشخاص أو اختطافهم"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"‏اختبار تنبيه LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"عرض رسائل الاختبار"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"‏تجربة تنبيه LU-Alert"</string>
diff --git a/res/values-mcc270-as/strings.xml b/res/values-mcc270-as/strings.xml
index 4456156f7..13e2425b2 100644
--- a/res/values-mcc270-as/strings.xml
+++ b/res/values-mcc270-as/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-সতৰ্কবাৰ্তা"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-সতৰ্কবাৰ্তা"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-সতৰ্কবাৰ্তা"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-সতৰ্কবাৰ্তা : অপহৰণৰ সতৰ্কবাৰ্তা"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-সতৰ্কবাৰ্তা : ব্যক্তি সন্ধানহীন হোৱাৰ / অপহৰণৰ সতৰ্কবাৰ্তা"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-সতৰ্কবাৰ্তা পৰীক্ষণ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-সতৰ্কবাৰ্তা অনুশীলন"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"অপহৰণৰ সতৰ্কবাৰ্তা"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"শিশু অপহৰণৰ সতৰ্কবাৰ্তা দেখুৱাওক"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"ব্যক্তি সন্ধানহীন হোৱাৰ / অপহৰণৰ সতৰ্কবাৰ্তা"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"ব্যক্তি সন্ধানহীন হোৱা / অপহৰণৰ পৰিস্থিতিৰ বাবে সতৰ্কবাৰ্তা দেখুৱাওক"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-সতৰ্কবাৰ্তা পৰীক্ষণ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"পৰীক্ষণ বাৰ্তা দেখুৱাওক"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-সতৰ্কবাৰ্তা অনুশীলন"</string>
diff --git a/res/values-mcc270-az/strings.xml b/res/values-mcc270-az/strings.xml
index 21d463c6e..8660fb4ca 100644
--- a/res/values-mcc270-az/strings.xml
+++ b/res/values-mcc270-az/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Adam oğurluğu xəbərdarlığı"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: İtkin düşmə / adam oğurluğu xəbərdarlığı"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert testi"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert məşqi"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Adam oğurluğu xəbərdarlığı"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Uşaq oğurluğu ilə bağlı xəbərdarlıq mesajlarını göstərin"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"İtkin düşmə / adam oğurluğu xəbərdarlığı"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"İtkin düşmə / adam oğurluğu halları üçün xəbərdarlıq mesajları göstərilsin"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert testi"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Test mesajlarını göstərin"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert məşqi"</string>
diff --git a/res/values-mcc270-b+sr+Latn/strings.xml b/res/values-mcc270-b+sr+Latn/strings.xml
index a42bc1f19..b884b2b09 100644
--- a/res/values-mcc270-b+sr+Latn/strings.xml
+++ b/res/values-mcc270-b+sr+Latn/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Upozorenje o otmici"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Upozorenje o nestaloj osobi ili otmici"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert vežbanje"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Upozorenje o otmici"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Prikazuj poruke upozorenja za otmice dece"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Upozorenje o nestaloj osobi ili otmici"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Prikazuje poruke upozorenja u vezi sa nestalom osobom ili otmicom"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Prikazuj probne poruke"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert vežbanje"</string>
diff --git a/res/values-mcc270-be/strings.xml b/res/values-mcc270-be/strings.xml
index bfa8156fe..12f152586 100644
--- a/res/values-mcc270-be/strings.xml
+++ b/res/values-mcc270-be/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Абвестка пра выкраданне чалавека"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : прапажа без вестак/выкраданне чалавека"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert : Тэсціраванне"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert : Вучэбная трывога"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Абвестка пра выкраданне чалавека"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Паказваць абвесткі пра выкраданні дзяцей"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Прапажа без вестак ці выкраданне чалавека"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Паказваць абвесткі пра прапажу без вестак ці выкраданне чалавека"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert : Тэсціраванне"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Паказваць тэставыя абвесткі"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert : Вучэбная трывога"</string>
diff --git a/res/values-mcc270-bg/strings.xml b/res/values-mcc270-bg/strings.xml
index 50348021f..87aea875a 100644
--- a/res/values-mcc270-bg/strings.xml
+++ b/res/values-mcc270-bg/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Сигнал за отвличане на човек"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Сигнал за човек в неизвестност/отвличане"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: Тестване"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: Обучение"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Сигнал за отвличане"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Показване на съобщения за сигнали за отвличания на деца"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Сигнал за човек в неизвестност/отвличане"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Показване на съобщения за сигнали за ситуации с човек в неизвестност/отвличане"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: Тестване"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Показване на тестови съобщения"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert: Обучение"</string>
diff --git a/res/values-mcc270-bn/strings.xml b/res/values-mcc270-bn/strings.xml
index deff3f39b..383790cc1 100644
--- a/res/values-mcc270-bn/strings.xml
+++ b/res/values-mcc270-bn/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : অপহরণ সংক্রান্ত সতর্কতা"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: নিখোঁজ ব্যক্তি / অপহরণ সম্পর্কে সতর্কতা"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert টেস্ট"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert এক্সারসাইজ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"অপহরণ সংক্রান্ত সতর্কতা"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"শিশু অপহরণ সংক্রান্ত সতর্কতা মেসেজ দেখুন"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"নিখোঁজ ব্যক্তি / অপহরণ সম্পর্কে সতর্কতা"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"নিখোঁজ ব্যক্তি / অপহরণের পরিস্থিতি সম্পর্কে সতর্কতা মেসেজ দেখুন"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert টেস্ট"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"টেস্ট মেসেজ দেখুন"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert এক্সারসাইজ"</string>
diff --git a/res/values-mcc270-bs/strings.xml b/res/values-mcc270-bs/strings.xml
index 34702ebfe..7a644ca90 100644
--- a/res/values-mcc270-bs/strings.xml
+++ b/res/values-mcc270-bs/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: upozorenje o otmici"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: upozorenje o nestanku osobe / otmici"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: vježba"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Upozorenje o otmici"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Prikaz poruka upozorenja za otmice djece"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Upozorenje o nestanku osobe / otmici"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Prikazivanje poruka upozorenja u situacijama nestanka osobe / otmice"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Prikaz testnih poruka"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert: vježba"</string>
diff --git a/res/values-mcc270-ca/strings.xml b/res/values-mcc270-ca/strings.xml
index 722dd7e66..430f46f26 100644
--- a/res/values-mcc270-ca/strings.xml
+++ b/res/values-mcc270-ca/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: alerta de segrest"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: alerta de desaparició o segrest"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Prova de LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Simulacre de LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerta de segrest"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Mostra els missatges d\'alerta de segrestos de menors"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Alerta de desaparició o segrest"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Mostra els missatges d\'alerta de desaparicions o segrestos"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Prova de LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Mostra els missatges de prova"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Simulacre de LU-Alert"</string>
diff --git a/res/values-mcc270-cs/strings.xml b/res/values-mcc270-cs/strings.xml
index 20a372dcc..a2aa3b199 100644
--- a/res/values-mcc270-cs/strings.xml
+++ b/res/values-mcc270-cs/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Upozornění na únos"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Pohřešovaná osoba / únos"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: Cvičení"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Upozornění na únos"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Zobrazovat upozornění na únosy dětí"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Pohřešovaná osoba / únos"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Zobrazovat upozornění na pohřešování/únosy"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Zobrazit testovací zprávy"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert: Cvičení"</string>
diff --git a/res/values-mcc270-da/strings.xml b/res/values-mcc270-da/strings.xml
index 7591fbfc3..57bd6db22 100644
--- a/res/values-mcc270-da/strings.xml
+++ b/res/values-mcc270-da/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Underretning om kidnapning"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Underretning om forsvundet/bortført person"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert (test)"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert (øvelse)"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Underretning om bortførelse"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Vis underretninger om bortførelse af børn"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Underretning om forsvundet/bortført person"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Vis underretninger om forsvundne/bortførte personer"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert (test)"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Vis underretninger om tests"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert (øvelse)"</string>
diff --git a/res/values-mcc270-de/strings.xml b/res/values-mcc270-de/strings.xml
index e5645cbf2..400bf7395 100644
--- a/res/values-mcc270-de/strings.xml
+++ b/res/values-mcc270-de/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Entführungswarnung"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Vermissten- / Entführungsmeldung"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Übung"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Entführungswarnung"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Warnmeldungen bei Kindesentführungen anzeigen"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Vermissten- / Entführungsmeldung"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Warnmeldungen bei Vermissten- / Entführungssituationen anzeigen"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Testmeldungen anzeigen"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Übung"</string>
diff --git a/res/values-mcc270-el/strings.xml b/res/values-mcc270-el/strings.xml
index b2d95ce5a..0848fa9f4 100644
--- a/res/values-mcc270-el/strings.xml
+++ b/res/values-mcc270-el/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Συναγερμός απαγωγής"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : Ειδοποίηση για εξαφάνιση/απαγωγή"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Δοκιμή LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Άσκηση LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Ειδοποίηση απαγωγής"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Εμφάνιση μηνυμάτων συναγερμού για απαγωγές παιδιών"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Ειδοποίηση για εξαφάνιση/απαγωγή"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Εμφάνιση μηνυμάτων ειδοποίησης για περιπτώσεις εξαφάνισης/απαγωγής"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Δοκιμή LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Εμφάνιση δοκιμαστικών μηνυμάτων"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Άσκηση LU-Alert"</string>
diff --git a/res/values-mcc270-en-rAU/strings.xml b/res/values-mcc270-en-rAU/strings.xml
index cc8e5ab96..3aac20f18 100644
--- a/res/values-mcc270-en-rAU/strings.xml
+++ b/res/values-mcc270-en-rAU/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Kidnapping alert"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Missing person / kidnapping alert"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Exercise"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnapping alert"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Show alert messages for child abductions"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Missing person / kidnapping alert"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Show alert messages for missing person / kidnapping situations"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Show test messages"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Exercise"</string>
diff --git a/res/values-mcc270-en-rCA/strings.xml b/res/values-mcc270-en-rCA/strings.xml
index 084fbc719..9a63238e1 100644
--- a/res/values-mcc270-en-rCA/strings.xml
+++ b/res/values-mcc270-en-rCA/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Kidnapping alert"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : Missing person / kidnapping alert"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Exercise"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnapping alert"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Show alert messages for child abductions"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Missing person / kidnapping alert"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Show alert messages for missing person / kidnapping situations"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Show test messages"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Exercise"</string>
diff --git a/res/values-mcc270-en-rGB/strings.xml b/res/values-mcc270-en-rGB/strings.xml
index cc8e5ab96..3aac20f18 100644
--- a/res/values-mcc270-en-rGB/strings.xml
+++ b/res/values-mcc270-en-rGB/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Kidnapping alert"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Missing person / kidnapping alert"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Exercise"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnapping alert"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Show alert messages for child abductions"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Missing person / kidnapping alert"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Show alert messages for missing person / kidnapping situations"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Show test messages"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Exercise"</string>
diff --git a/res/values-mcc270-en-rIN/strings.xml b/res/values-mcc270-en-rIN/strings.xml
index cc8e5ab96..3aac20f18 100644
--- a/res/values-mcc270-en-rIN/strings.xml
+++ b/res/values-mcc270-en-rIN/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Kidnapping alert"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Missing person / kidnapping alert"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Exercise"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnapping alert"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Show alert messages for child abductions"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Missing person / kidnapping alert"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Show alert messages for missing person / kidnapping situations"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Show test messages"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Exercise"</string>
diff --git a/res/values-mcc270-es-rUS/strings.xml b/res/values-mcc270-es-rUS/strings.xml
index 388346455..63afa9e01 100644
--- a/res/values-mcc270-es-rUS/strings.xml
+++ b/res/values-mcc270-es-rUS/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Alerta de secuestro"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Persona desaparecida o secuestro"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Prueba de LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Ejercicio de LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerta de secuestro"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Mostrar mensajes de alerta sobre secuestros de menores"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Alerta de persona desaparecida o secuestro"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Muestra mensajes de alerta para situaciones de personas desaparecidas o secuestros"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Prueba de LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Mostrar mensajes de prueba"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Ejercicio de LU-Alert"</string>
diff --git a/res/values-mcc270-es/strings.xml b/res/values-mcc270-es/strings.xml
index 85ee27bc4..ff2374124 100644
--- a/res/values-mcc270-es/strings.xml
+++ b/res/values-mcc270-es/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Alerta de secuestro"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Alerta de desaparición o secuestro"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Prueba"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Simulacro"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerta de secuestro"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Muestra mensajes de alerta sobre secuestros de niños"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Alerta de desaparición o secuestro de personas"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Muestra mensajes de alerta sobre situaciones de desaparición o secuestro de personas"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Prueba"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Muestra mensajes de prueba"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Simulacro"</string>
diff --git a/res/values-mcc270-et/strings.xml b/res/values-mcc270-et/strings.xml
index fa515257f..8644f21a5 100644
--- a/res/values-mcc270-et/strings.xml
+++ b/res/values-mcc270-et/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: lapseröövi hoiatus"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-märguanne: kadunud lapse / lapseröövi hoiatus"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alerti test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alerti harjutus"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Lapseröövi hoiatus"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Lapseröövi hoiatussõnumite kuvamine"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Kadunud lapse / lapseröövi hoiatus"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Hoiatussõnumite kuvamine lapse kadumisega / lapserööviga seotud olukordades"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alerti test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Testsõnumite kuvamine"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alerti harjutus"</string>
diff --git a/res/values-mcc270-eu/strings.xml b/res/values-mcc270-eu/strings.xml
index b1d23ee99..21611fa26 100644
--- a/res/values-mcc270-eu/strings.xml
+++ b/res/values-mcc270-eu/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: bahiketa-alerta"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: desagertutako pertsona / bahiketa-alerta"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: proba"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: simulazioa"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Bahiketa-alerta"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Erakutsi bahitutako haurrei buruzko alertak"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Desagertutako pertsona / Bahiketa-alerta"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Erakutsi alerta-mezuak norbait desagertu bada edo bahitu badute"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: proba"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Erakutsi probako mezuak"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert: simulazioa"</string>
diff --git a/res/values-mcc270-fa/strings.xml b/res/values-mcc270-fa/strings.xml
index 5b544710c..7ff365e61 100644
--- a/res/values-mcc270-fa/strings.xml
+++ b/res/values-mcc270-fa/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"‏هشدار LU"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"‏هشدار LU"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"‏هشدار LU"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"‏هشدار LU : هشدار آدم‌ربایی"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"‏هشدار LU : هشدار شخص گم‌شده / آدم‌ربایی"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"‏آزمایش هشدار LU"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"‏تمرین هشدار LU"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"هشدار آدم‌ربایی"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"نمایش پیام‌های هشدار برای کودک‌ربایی"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"هشدار شخص گم‌شده / آدم‌ربایی"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"نمایش پیام‌های هشدار برای وضعیت‌های شخص گم‌شده / آدم‌ربایی"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"‏آزمایش هشدار LU"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"نمایش پیام‌های آزمایشی"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"‏تمرین هشدار LU"</string>
diff --git a/res/values-mcc270-fi/strings.xml b/res/values-mcc270-fi/strings.xml
index 4721172c8..48cd755d5 100644
--- a/res/values-mcc270-fi/strings.xml
+++ b/res/values-mcc270-fi/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : hälytys sieppauksesta"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: kadonnut henkilö- tai sieppausvaroitus"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert-testi"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert-harjoitus"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Hälytys sieppauksesta"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Näytä hälytysviestit lapsikaappauksista"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Kadonnut henkilö- tai sieppausvaroitus"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Näytä hälytysviestit katoamistapauksesta tai sieppauksesta"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert-testi"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Näytä testiviestit"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert-harjoitus"</string>
diff --git a/res/values-mcc270-fr-rCA/strings.xml b/res/values-mcc270-fr-rCA/strings.xml
index 7c077ce27..90b98e117 100644
--- a/res/values-mcc270-fr-rCA/strings.xml
+++ b/res/values-mcc270-fr-rCA/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Alerte enlèvement"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : Alerte disparition / enlèvement"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Exercice"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerte enlèvement"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Afficher les messages d\'alerte pour les enlèvements d\'enfant"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Alerte disparition / enlèvement"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Afficher les messages d’alerte pour des disparitions / enlèvements"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Afficher les messages de test"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Exercice"</string>
diff --git a/res/values-mcc270-fr/strings.xml b/res/values-mcc270-fr/strings.xml
index 88d054419..480d0a55f 100644
--- a/res/values-mcc270-fr/strings.xml
+++ b/res/values-mcc270-fr/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Alerte enlèvement"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : Alerte disparition / enlèvement"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Exercice"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerte enlèvement"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Afficher les messages d\'alerte pour les enlèvements d\'enfants"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Alerte disparition / enlèvement"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Afficher les messages d\'alerte pour des disparitions / enlèvements"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Afficher les messages de test"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Exercice"</string>
diff --git a/res/values-mcc270-gl/strings.xml b/res/values-mcc270-gl/strings.xml
index 5c5ae0074..f93037f60 100644
--- a/res/values-mcc270-gl/strings.xml
+++ b/res/values-mcc270-gl/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Alerta de secuestro"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Alerta de desaparición ou secuestro"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Proba de LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Simulacro de LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerta de secuestro"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Mostra mensaxes de alerta relacionadas con secuestros infantís"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Alerta de desaparición ou secuestro"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Mostra mensaxes de alerta relacionadas con desaparicións ou secuestros"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Proba de LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Mostra mensaxes de proba"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Simulacro de LU-Alert"</string>
diff --git a/res/values-mcc270-gu/strings.xml b/res/values-mcc270-gu/strings.xml
index aafd4e29c..614916b35 100644
--- a/res/values-mcc270-gu/strings.xml
+++ b/res/values-mcc270-gu/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : અપહરણ માટેનું અલર્ટ"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : ગુમ થયેલી વ્યક્તિ / અપહરણ માટેનું અલર્ટ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alertનું પરીક્ષણ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alertનો અભ્યાસ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"અપહરણ માટેનું અલર્ટ"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"બાળકના અપહરણ માટેના અલર્ટ મેસેજ બતાવો"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"ગુમ થયેલી વ્યક્તિ / અપહરણ માટેનું અલર્ટ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"ગુમ થયેલી વ્યક્તિ / અપહરણ સંબંધિત પરિસ્થિતિઓ માટે અલર્ટ મેસેજ બતાવો"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alertનું પરીક્ષણ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"પરીક્ષણ માટેના મેસેજ બતાવો"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alertનો અભ્યાસ"</string>
diff --git a/res/values-mcc270-hi/strings.xml b/res/values-mcc270-hi/strings.xml
index dfbc5c142..039331e85 100644
--- a/res/values-mcc270-hi/strings.xml
+++ b/res/values-mcc270-hi/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"एलयू-चेतावनी"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"एलयू-चेतावनी"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"एलयू-चेतावनी"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"एलयू-चेतावनी : अपहरण की चेतावनी"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"एलयू-सूचना : व्यक्ति के गुम होने / अपहरण की सूचना"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"एलयू-चेतावनी की जांच"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"एलयू-चेतावनी की ड्रिल"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"अपहरण की चेतावनी"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"बच्चों के अपहरण से जुड़ी चेतावनी वाले मैसेज दिखाएं"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"व्यक्ति के गुम होने / अपहरण की चेतावनी"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"व्यक्ति के गुम होने / अपहरण की चेतावनी वाले मैसेज दिखाएं"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"एलयू-चेतावनी की जांच"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"टेस्ट मैसेज दिखाएं"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"एलयू-चेतावनी की ड्रिल"</string>
diff --git a/res/values-mcc270-hr/strings.xml b/res/values-mcc270-hr/strings.xml
index ed25fc4bc..a9921fec9 100644
--- a/res/values-mcc270-hr/strings.xml
+++ b/res/values-mcc270-hr/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : upozorenje o otmici"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: upozorenje o nestaloj osobi/otmici"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert – testiranje"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert – vježba"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Upozorenje o otmici"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Prikazivanje poruka upozorenja za otmice djece"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Upozorenje o nestaloj osobi/otmici"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Prikaži poruke upozorenja za nestale osobe/otmice"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert – testiranje"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Prikazivanje testnih poruka"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert – vježba"</string>
diff --git a/res/values-mcc270-hu/strings.xml b/res/values-mcc270-hu/strings.xml
index 83ae12f7e..a7ea470f6 100644
--- a/res/values-mcc270-hu/strings.xml
+++ b/res/values-mcc270-hu/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-riasztás"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-riasztás"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-riasztás"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-riasztás: Emberrablási riasztás"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-riasztás: Eltűnés/emberrablás miatti riasztás"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-riasztási teszt"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-riasztási gyakorlat"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Emberrablásról szóló riasztás"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Gyermekrablás esetén kiadott riasztási üzenetek megjelenítése"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Eltűnés vagy emberrablás miatti riasztás"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Eltűnés vagy emberrablás esetén kiadott riasztási üzenetek megjelenítése"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-riasztási teszt"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Tesztüzenetek megjelenítése"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-riasztási gyakorlat"</string>
diff --git a/res/values-mcc270-hy/strings.xml b/res/values-mcc270-hy/strings.xml
index ceea6f819..1adb20758 100644
--- a/res/values-mcc270-hy/strings.xml
+++ b/res/values-mcc270-hy/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert․ առևանգման մասին զգուշացում"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : Կորած անձի / առևանգման մասին զգուշացում"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert․ փորձարկում"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert․ վարժանք"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Առևանգման մասին զգուշացում"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Ցուցադրել զգուշացումներ երեխաների առևանգման մասին"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Կորած անձի / առևանգման մասին զգուշացում"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Ցուցադրել զգուշացման հաղորդագրություններ մարդկանց անհետ կորելու կամ առևանգման իրավիճակների դեպքում"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert․ փորձարկում"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Ցուցադրել փորձնական հաղորդագրություններ"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert․ վարժանք"</string>
diff --git a/res/values-mcc270-in/strings.xml b/res/values-mcc270-in/strings.xml
index c5bd20200..0a15a845b 100644
--- a/res/values-mcc270-in/strings.xml
+++ b/res/values-mcc270-in/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Peringatan penculikan"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Peringatan orang hilang/penculikan"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Pengujian LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Latihan LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Peringatan penculikan"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Tampilkan pesan peringatan untuk penculikan anak"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Peringatan orang hilang/penculikan"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Tampilkan pesan peringatan untuk situasi orang hilang/penculikan"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Pengujian LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Tampilkan pesan pengujian"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Latihan LU-Alert"</string>
diff --git a/res/values-mcc270-is/strings.xml b/res/values-mcc270-is/strings.xml
index 5e0ef39ef..d1bfa68bf 100644
--- a/res/values-mcc270-is/strings.xml
+++ b/res/values-mcc270-is/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-viðvörun"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-viðvörun"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-viðvörun"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-viðvörun : Viðvörun um mannrán"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-viðvörun: Viðvörun um týndan einstakling / mannrán"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-viðvörunarprófun"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-viðvörunaræfing"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Viðvörun um mannrán"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Sýna viðvaranir varðandi mannrán á börnum"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Viðvörun um týndan einstakling / mannrán"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Sýna viðvaranir um tilvik þar sem fólks er saknað / mannrán"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-viðvörunarprófun"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Sýna prófskilaboð"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-viðvörunaræfing"</string>
diff --git a/res/values-mcc270-it/strings.xml b/res/values-mcc270-it/strings.xml
index d1d2543ca..428788730 100644
--- a/res/values-mcc270-it/strings.xml
+++ b/res/values-mcc270-it/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Allerta per rapimento"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Allerta per persona scomparsa/rapimento"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Test LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Esercitazione LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Allerta rapimento"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Mostra messaggi di allerta relativi a rapimenti di bambini"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Allerta per persona scomparsa/rapimento"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Mostra messaggi di allerta relativi a persone scomparse/rapimenti"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Test LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Mostra messaggi relativi a test"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Esercitazione LU-Alert"</string>
diff --git a/res/values-mcc270-iw/strings.xml b/res/values-mcc270-iw/strings.xml
index 50014c014..0cc95fc69 100644
--- a/res/values-mcc270-iw/strings.xml
+++ b/res/values-mcc270-iw/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"התרעה בלוקסמבורג"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"התרעה בלוקסמבורג"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"התרעה בלוקסמבורג"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"התרעה בלוקסמבורג: התרעה על חטיפה"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"התרעה בלוקסמבורג: התרעה על חטיפה או אדם נעדר"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"בדיקה של התרעה בלוקסמבורג"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"תרגיל התרעה בלוקסמבורג"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"התרעה על חטיפה"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"הצגת הודעות התרעה על חטיפות של ילדים"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"התרעה על חטיפה או אדם נעדר"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"הצגת התרעות על מצבים של חטיפה או אנשים נעדרים"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"בדיקה של התרעה בלוקסמבורג"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"הצגת הודעות בדיקה"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"תרגיל התרעה בלוקסמבורג"</string>
diff --git a/res/values-mcc270-ja/strings.xml b/res/values-mcc270-ja/strings.xml
index 56798a926..8b2304e6a 100644
--- a/res/values-mcc270-ja/strings.xml
+++ b/res/values-mcc270-ja/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: 誘拐に関するアラート"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: 行方不明者 / 誘拐に関するアラート"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert テスト"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert 訓練"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"誘拐に関するアラート"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"児童誘拐についてのアラート メッセージを表示する"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"行方不明者 / 誘拐に関するアラート"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"行方不明者 / 誘拐の状況についてのアラート メッセージを表示する"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert テスト"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"テスト メッセージを表示する"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert 訓練"</string>
diff --git a/res/values-mcc270-ka/strings.xml b/res/values-mcc270-ka/strings.xml
index 932995496..348cbb311 100644
--- a/res/values-mcc270-ka/strings.xml
+++ b/res/values-mcc270-ka/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-გაფრთხილება"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-გაფრთხილება"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-გაფრთხილება"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-გაფრთხილება : გატაცების გაფრთხილება"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-გაფრთხილება : დაკარგული ადამიანის / გატაცების გაფრთხილება"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"სატესტო LU-გაფრთხილება"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"საცდელი LU-გაფრთხილება"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"გატაცების გაფრთხილება"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ბავშვის გატაცების შესახებ გაფრთხილებების ჩვენება"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"დაკარგული ადამიანის / გატაცების გაფრთხილება"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"გაფრთხილების შეტყობინებების ჩვენება დაკარგვის / გატაცების სიტუაციებისთვის"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"სატესტო LU-გაფრთხილება"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"სატესტო შეტყობინებების ჩვენება"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"საცდელი LU-გაფრთხილება"</string>
diff --git a/res/values-mcc270-kk/strings.xml b/res/values-mcc270-kk/strings.xml
index cfa95af48..596942dc9 100644
--- a/res/values-mcc270-kk/strings.xml
+++ b/res/values-mcc270-kk/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : адам ұрлау туралы хабарландыру"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: жоғалған адам/ұрланған бала туралы дабыл"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert сынағы"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert жаттығуы"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Адам ұрлау туралы хабарландыру"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Жоғалған балалар туралы хабарландыруларды көрсету"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Жоғалған адам/ұрланған бала туралы дабыл"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Жоғалып кеткен адамдар/ұрлап әкеткен балалар туралы дабыл хабарларын көрсету"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert сынағы"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Сынақ хабарларын көрсету"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert жаттығуы"</string>
diff --git a/res/values-mcc270-km/strings.xml b/res/values-mcc270-km/strings.xml
index e2f360eda..04389de55 100644
--- a/res/values-mcc270-km/strings.xml
+++ b/res/values-mcc270-km/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert៖ ការ​ជូនដំណឹង​អំពី​ការ​ចាប់​ជំរិត"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert៖ ការជូនដំណឹងអំពីការបាត់ខ្លួន / ការចាប់ជំរិត"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"ការធ្វើតេស្ដ LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"ការសាកល្បង LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"ការជូនដំណឹង​អំពី​ការចាប់​ជំរិត"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"បង្ហាញ​សារ​ជូនដំណឹង​សម្រាប់ការ​ចាប់​ជំរិត​កុមារ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"ការជូនដំណឹងអំពីការបាត់ខ្លួន / ការចាប់ជំរិត"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"បង្ហាញសារជូន​ដំណឹងសម្រាប់ស្ថានភាពបាត់ខ្លួន / ចាប់ជំរិត"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"ការធ្វើតេស្ដ LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"បង្ហាញ​សារ​សាកល្បង"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"ការសាកល្បង LU-Alert"</string>
diff --git a/res/values-mcc270-kn/strings.xml b/res/values-mcc270-kn/strings.xml
index 790e19417..84cb3becc 100644
--- a/res/values-mcc270-kn/strings.xml
+++ b/res/values-mcc270-kn/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-ಅಲರ್ಟ್"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-ಅಲರ್ಟ್"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-ಅಲರ್ಟ್"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-ಅಲರ್ಟ್ : ಅಪಹರಣದ ಎಚ್ಚರಿಕೆ"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-ಅಲರ್ಟ್ : ವ್ಯಕ್ತಿ ಕಾಣೆ / ಅಪಹರಣವಾಗಿರುವ ಎಚ್ಚರಿಕೆ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-ಅಲರ್ಟ್ ಪರೀಕ್ಷೆ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-ಅಲರ್ಟ್ ಅಭ್ಯಾಸ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"ಅಪಹರಣದ ಅಲರ್ಟ್"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ಮಕ್ಕಳ ಅಪಹರಣದ ಎಚ್ಚರಿಕೆ ಸಂದೇಶವನ್ನು ತೋರಿಸಿ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"ವ್ಯಕ್ತಿ ಕಾಣೆ / ಅಪಹರಣವಾಗಿರುವ ಕುರಿತು ಎಚ್ಚರಿಕೆ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"ವ್ಯಕ್ತಿಯೊಬ್ಬರು ಕಾಣೆಯಾಗಿರುವುದು / ಅಪಹರಣವಾಗಿರುವ ಸಂದರ್ಭಗಳಿಗೆ ಸೂಕ್ತವಾದ ಎಚ್ಚರಿಕೆ ಸಂದೇಶಗಳನ್ನು ತೋರಿಸಿ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-ಅಲರ್ಟ್ ಪರೀಕ್ಷೆ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"ಪರೀಕ್ಷಾ ಸಂದೇಶಗಳನ್ನು ತೋರಿಸಿ"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-ಅಲರ್ಟ್ ಅಭ್ಯಾಸ"</string>
diff --git a/res/values-mcc270-ko/strings.xml b/res/values-mcc270-ko/strings.xml
index 2723f6dd2..21dd310e9 100644
--- a/res/values-mcc270-ko/strings.xml
+++ b/res/values-mcc270-ko/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: 유괴 경보"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: 실종자/유괴 경보"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert 테스트"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert 안전 훈련"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"유괴 경보"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"아동 유괴 관련 경보 메시지 표시"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"실종자/유괴 경보"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"실종자/유괴 상황 관련 경보 메시지 표시"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert 테스트"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"테스트 메시지 표시"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert 안전 훈련"</string>
diff --git a/res/values-mcc270-ky/strings.xml b/res/values-mcc270-ky/strings.xml
index e175f4f3f..8b87cbd03 100644
--- a/res/values-mcc270-ky/strings.xml
+++ b/res/values-mcc270-ky/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Уурдалгандыгы тууралуу шашылыш билдирүү"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Жоголуу/уурдоо жөнүндө шашылыш кабар"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: Сыноо"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: Көнүгүү"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Уурдалгандыгы тууралуу шашылыш билдирүү"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Балдардын уурдалгандыгы жөнүндө шашылыш билдирүүлөрдү көрсөтүү"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Адамдын жоголгону/уурдалганы жөнүндө шашылыш кабар"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Адамдын жоголгону/уурдалганы жөнүндө шашылыш билдирүүлөрдү көрсөтүү"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: Сыноо"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Сынамык билдирүүлөрдү көрсөтүү"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert: Көнүгүү"</string>
diff --git a/res/values-mcc270-lo/strings.xml b/res/values-mcc270-lo/strings.xml
index cba7d107e..9aeb12116 100644
--- a/res/values-mcc270-lo/strings.xml
+++ b/res/values-mcc270-lo/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : ການແຈ້ງເຕືອນການລັກພາຕົວ"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : ການແຈ້ງເຕືອນບຸກຄົນສູນຫາຍ / ການລັກພາຕົວ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"ການທົດສອບ LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"ການຝຶກຊ້ອມ LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"ການແຈ້ງເຕືອນການລັກພາຕົວ"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ສະແດງຂໍ້ຄວາມແຈ້ງເຕືອນເລື່ອງການລັກພາຕົວເດັກນ້ອຍ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"ການແຈ້ງເຕືອນບຸກຄົນສູນຫາຍ / ການລັກພາຕົວ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"ສະແດງຂໍ້ຄວາມແຈ້ງເຕືອນສຳລັບສະຖານະການບຸກຄົນສູນຫາຍ / ການລັກພາຕົວ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"ການທົດສອບ LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"ສະແດງຂໍ້ຄວາມທົດສອບ"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"ການຝຶກຊ້ອມ LU-Alert"</string>
diff --git a/res/values-mcc270-lt/strings.xml b/res/values-mcc270-lt/strings.xml
index eec58beae..2a5867140 100644
--- a/res/values-mcc270-lt/strings.xml
+++ b/res/values-mcc270-lt/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"„LU-Alert“: įspėjimas apie pagrobimą"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"„LU-Alert“: įspėj. apie dingusį asmenį / pagrobimą"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"„LU-Alert“ bandymas"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"„LU-Alert“ pratybos"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Įspėjimas apie pagrobimą"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Rodyti įspėjimų pranešimus apie vaikų pagrobimą"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Įspėjimas apie dingusį asmenį / pagrobimą"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Rodyti įspėjimų pranešimus apie dingusį asmenį / pagrobimą"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"„LU-Alert“ bandymas"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Rodyti bandomuosius pranešimus"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"„LU-Alert“ pratybos"</string>
diff --git a/res/values-mcc270-lv/strings.xml b/res/values-mcc270-lv/strings.xml
index 252d2dd4c..57a9d42fc 100644
--- a/res/values-mcc270-lv/strings.xml
+++ b/res/values-mcc270-lv/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: trauksme nolaupīšanas dēļ"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: brīdinājums par pazudušu personu/nolaupīšanu"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert pārbaude"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert mācību ziņojums"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Trauksme nolaupīšanas dēļ"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Rādīt trauksmes ziņojumus par bērnu nolaupīšanu"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Brīdinājums par pazudušu personu/nolaupīšanu"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Rādīt brīdinājumus par pazudušu personu/nolaupīšanu"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert pārbaude"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Rādīt pārbaudes ziņojumus"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert mācību ziņojums"</string>
diff --git a/res/values-mcc270-mk/strings.xml b/res/values-mcc270-mk/strings.xml
index dc8a9c2d9..29d32579a 100644
--- a/res/values-mcc270-mk/strings.xml
+++ b/res/values-mcc270-mk/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: предупредување за киднапирање"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: предупред. за исчезнато лице/киднапирање"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: пробно"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: вежби"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Предупредување за киднапирање"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Прикажувај пораки за предупредување за киднапирање деца"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Предупредувањe за исчезнато лице/киднапирање"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Прикажувај пораки за предупредување за ситуации на исчезнато лице/киднапирање"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: пробно"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Прикажувај пробни пораки"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert: вежби"</string>
diff --git a/res/values-mcc270-ml/strings.xml b/res/values-mcc270-ml/strings.xml
index c545b90dd..18ab55512 100644
--- a/res/values-mcc270-ml/strings.xml
+++ b/res/values-mcc270-ml/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : തട്ടിക്കൊണ്ടുപോകൽ മുന്നറിയിപ്പ്"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-അലേർട്ട്: കാണാതാകൽ / തട്ടിക്കൊണ്ടുപോകൽ അലേർട്ട്"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert പരിശീലനം"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"തട്ടിക്കൊണ്ടുപോകൽ മുന്നറിയിപ്പ്"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"കുട്ടികളെ തട്ടിക്കൊണ്ടുപോകൽ സംബന്ധിച്ച മുന്നറിയിപ്പ് സന്ദേശങ്ങൾ കാണിക്കുക"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"വ്യക്തിയെ കാണാതാകൽ / തട്ടിക്കൊണ്ടുപോകൽ അലേർട്ട്"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"വ്യക്തിയെ കാണാതാകൽ / തട്ടിക്കൊണ്ടുപോകൽ സാഹചര്യങ്ങൾ സംബന്ധിച്ച മുന്നറിയിപ്പ് സന്ദേശങ്ങൾ കാണിക്കുക"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"ടെസ്റ്റ് സന്ദേശങ്ങൾ കാണിക്കുക"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert പരിശീലനം"</string>
diff --git a/res/values-mcc270-mn/strings.xml b/res/values-mcc270-mn/strings.xml
index 7d4af9a3c..e8ea09b25 100644
--- a/res/values-mcc270-mn/strings.xml
+++ b/res/values-mcc270-mn/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-сэрэмжлүүлэг"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-сэрэмжлүүлэг"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-сэрэмжлүүлэг"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-сэрэмжлүүлэг : Хүн хулгайлсан тухай сэрэмжлүүлэг"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-сэрэмжлүүлэг : Алга болсон / хулгайлагдсан хүний сэрэмжлүүлэг"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-сэрэмжлүүлгийн туршилт"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-сэрэмжлүүлгийн сургуулилалт"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Хүн хулгайлсан тухай сэрэмжлүүлэг"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Хүүхэд хулгайлсан тухай сэрэмжлүүлгийн мессежийг харуулах"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Алга болсон / хулгайлагдсан хүний сэрэмжлүүлэг"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Алга болсон / хулгайлагдсан хүний нөхцөл байдалд зориулж сэрэмжлүүлгийн мессеж харуулах"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-сэрэмжлүүлгийн туршилт"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Туршилтын мессежийг харуулах"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-сэрэмжлүүлгийн сургуулилалт"</string>
diff --git a/res/values-mcc270-mr/strings.xml b/res/values-mcc270-mr/strings.xml
index ef5b07c2c..3928dfcee 100644
--- a/res/values-mcc270-mr/strings.xml
+++ b/res/values-mcc270-mr/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU सूचना"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU सूचना"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU सूचना"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU सूचना : अपहरणासंबंधित सूचना"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU सूचना : हरवलेली व्यक्ती / अपहरणासंबंधित सूचना"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU सूचना चाचणी"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU सूचना व्यायाम"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"अपहरणासंबंधित इशारा"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"लहान मुलांच्या अपहरणांसंबंधित सूचना मेसेज दाखवा"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"हरवलेली व्यक्ती / अपहरणासंबंधित सूचना"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"हरवलेली व्यक्ती / अपहरण झालेल्या परिस्थितींसाठी सूचना मेसेज दाखवा"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU सूचना चाचणी"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"चाचणी मेसेज दाखवा"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU सूचना व्यायाम"</string>
diff --git a/res/values-mcc270-ms/strings.xml b/res/values-mcc270-ms/strings.xml
index 66e52fc34..9ca44501d 100644
--- a/res/values-mcc270-ms/strings.xml
+++ b/res/values-mcc270-ms/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"Makluman-LU"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"Makluman-LU"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"Makluman-LU"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"Makluman-LU : Makluman penculikan"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"Makluman-LU : Makluman orang hilang / penculikan"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Ujian Makluman-LU"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Latihan Makluman-LU"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Makluman penculikan"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Tunjukkan mesej makluman untuk penculikan kanak-kanak"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Makluman orang hilang / penculikan"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Tunjukkan mesej makluman untuk situasi orang hilang / penculikan"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Ujian Makluman-LU"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Tunjukkan mesej ujian"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Latihan Makluman-LU"</string>
diff --git a/res/values-mcc270-my/strings.xml b/res/values-mcc270-my/strings.xml
index 45ba5166d..7b833bcd1 100644
--- a/res/values-mcc270-my/strings.xml
+++ b/res/values-mcc270-my/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-သတိပေးချက်"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-သတိပေးချက်"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-သတိပေးချက်"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-သတိပေးချက်- ပြန်ပေးဆွဲမှု သတိပေးချက်"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-သတိပေးချက်- လူပျောက်/ပြန်ပေးဆွဲခံရသူ သတိပေးချက်"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-သတိပေးချက် စမ်းသပ်မှု"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-သတိပေးချက် လုပ်ထုံးလုပ်နည်း"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"ပြန်ပေးဆွဲမှု သတိပေးချက်"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ကလေးခိုးယူခံရမှုများအတွက် သတိပေးမက်ဆေ့ဂျ်များ ပြပါ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"လူပျောက် / ပြန်ပေးဆွဲခံရသူ သတိပေးချက်"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"လူပျောက်ခြင်း / ပြန်ပေးဆွဲခံရခြင်း အခြေအနေများအတွက် သတိပေးမက်ဆေ့ဂျ်များ ပြပါ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-သတိပေးချက် စမ်းသပ်မှု"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"စမ်းသပ်မက်ဆေ့ဂျ်များ ပြပါ"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-သတိပေးချက် လုပ်ထုံးလုပ်နည်း"</string>
diff --git a/res/values-mcc270-nb/strings.xml b/res/values-mcc270-nb/strings.xml
index 8949c34f9..7735c907a 100644
--- a/res/values-mcc270-nb/strings.xml
+++ b/res/values-mcc270-nb/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: varsel om kidnapping"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-varsel: varsel om savnet person / kidnapping"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: øvelse"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnappingsvarsel"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Vis varselsmeldinger om bortføring av barn"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Varsel om savnet person / kidnapping"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Vis varselsmeldinger for savnet person / kidnappingssituasjoner"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Vis testmeldinger"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert: øvelse"</string>
diff --git a/res/values-mcc270-ne/strings.xml b/res/values-mcc270-ne/strings.xml
index 87e167748..63176b19a 100644
--- a/res/values-mcc270-ne/strings.xml
+++ b/res/values-mcc270-ne/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-सतर्कता"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-सतर्कता"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-सतर्कता"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-सतर्कता : अपहरणसम्बन्धी सूचना"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-अलर्ट: मानिस हराएको वा अपहरणमा परेको जानकारी दिने अलर्ट"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-सतर्कतासम्बन्धी परीक्षण"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-सतर्कतासम्बन्धी अभ्यास"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"अपहरणसम्बन्धी सूचना"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"बालबालिकाको अपहरणसँग सम्बन्धित सतर्कताका म्यासेजहरू देखाउनुहोस्"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"मानिस हराएको वा अपहरणमा परेको जानकारी दिने अलर्ट"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"मानिस हराएको वा अपहरणमा परेको अवस्थामा सो कुराको जानकारी दिने अलर्ट म्यासेजहरू देखाउनुहोस्"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-सतर्कतासम्बन्धी परीक्षण"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"परीक्षणसम्बन्धी म्यासेजहरू देखाउनुहोस्"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-सतर्कतासम्बन्धी अभ्यास"</string>
diff --git a/res/values-mcc270-nl/strings.xml b/res/values-mcc270-nl/strings.xml
index 298e71753..8a0da74ad 100644
--- a/res/values-mcc270-nl/strings.xml
+++ b/res/values-mcc270-nl/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: kidnappingswaarschuwing"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: waarschuwing voor vermissing/kidnapping"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: oefening"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Vermist Kind Alert"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Waarschuwingen voor gekidnapte kinderen tonen"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Waarschuwing voor vermissing/kidnapping"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Waarschuwingen voor vermissing/kidnapping tonen"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Testberichten tonen"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert: oefening"</string>
diff --git a/res/values-mcc270-or/strings.xml b/res/values-mcc270-or/strings.xml
index ccf553060..d0b74c91c 100644
--- a/res/values-mcc270-or/strings.xml
+++ b/res/values-mcc270-or/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-ଆଲର୍ଟ"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-ଆଲର୍ଟ"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-ଆଲର୍ଟ"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-ଆଲର୍ଟ : ଅପହରଣର ଆଲର୍ଟ"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-ଆଲର୍ଟ : ନିଖୋଜ ବ୍ୟକ୍ତି / ଅପହରଣ ପାଇଁ ଆଲର୍ଟ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-ଆଲର୍ଟ ଟେଷ୍ଟ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-ଆଲର୍ଟ ବ୍ୟାୟାମ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"ଅପହରଣର ଆଲର୍ଟ"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ଶିଶୁ ଅପହରଣ ପାଇଁ ଆଲର୍ଟ ମେସେଜଗୁଡ଼ିକ ଦେଖାନ୍ତୁ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"ନିଖୋଜ ବ୍ୟକ୍ତି / ଅପହରଣ ପାଇଁ ଆଲର୍ଟ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"ନିଖୋଜ ବ୍ୟକ୍ତି / ଅପହରଣ ପରିସ୍ଥିତି ପାଇଁ ଆଲର୍ଟ ମେସେଜଗୁଡ଼ିକୁ ଦେଖାନ୍ତୁ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-ଆଲର୍ଟ ଟେଷ୍ଟ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"ପରୀକ୍ଷା ବିଷୟରେ ମେସେଜଗୁଡ଼ିକ ଦେଖାନ୍ତୁ"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-ଆଲର୍ଟ ବ୍ୟାୟାମ"</string>
diff --git a/res/values-mcc270-pa/strings.xml b/res/values-mcc270-pa/strings.xml
index eb066e43b..e73d269b0 100644
--- a/res/values-mcc270-pa/strings.xml
+++ b/res/values-mcc270-pa/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-ਅਲਰਟ"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-ਅਲਰਟ"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-ਅਲਰਟ"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-ਅਲਰਟ : ਅਪਹਰਨ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-ਅਲਰਟ : ਗੁੰਮਸ਼ੁਦਾ ਵਿਅਕਤੀ / ਅਪਹਰਨ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-ਅਲਰਟ ਸੰਬੰਧੀ ਜਾਂਚ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-ਅਲਰਟ ਸੰਬੰਧੀ ਅਭਿਆਸ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"ਅਪਹਰਨ ਹੋ ਜਾਣ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ਅਪਹਰਨ ਹੋਏ ਬੱਚੇ ਲਈ ਅਲਰਟ ਸੁਨੇਹੇ ਦਿਖਾਓ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"ਗੁੰਮਸ਼ੁਦਾ ਵਿਅਕਤੀ / ਅਪਹਰਨ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"ਗੁੰਮਸ਼ੁਦਾ ਵਿਅਕਤੀ / ਅਪਹਰਨ ਸੰਬੰਧੀ ਅਲਰਟ ਦਿਖਾਓ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-ਅਲਰਟ ਸੰਬੰਧੀ ਜਾਂਚ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"ਜਾਂਚ ਸੁਨੇਹੇ ਦਿਖਾਓ"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-ਅਲਰਟ ਸੰਬੰਧੀ ਅਭਿਆਸ"</string>
diff --git a/res/values-mcc270-pl/strings.xml b/res/values-mcc270-pl/strings.xml
index fbd6ef4dd..ca52f560c 100644
--- a/res/values-mcc270-pl/strings.xml
+++ b/res/values-mcc270-pl/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Alert dotyczący porwania"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: alert o zaginięciu lub porwaniu"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: Ćwiczenie"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alert o porwaniu"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Pokazuj alerty o uprowadzeniu dziecka"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Alert o zaginięciu lub porwaniu"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Pokazuj alerty o zaginięciu lub porwaniu"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Pokazuj komunikaty testowe"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert: Ćwiczenie"</string>
diff --git a/res/values-mcc270-pt-rPT/strings.xml b/res/values-mcc270-pt-rPT/strings.xml
index 08f2a97b7..358c35634 100644
--- a/res/values-mcc270-pt-rPT/strings.xml
+++ b/res/values-mcc270-pt-rPT/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: alerta de rapto"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: alerta de pessoa desaparecida/rapto"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Teste de LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Exercício de LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerta de rapto"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Mostrar mensagens de alerta para raptos de crianças"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Alerta de pessoa desaparecida/rapto"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Veja mensagens de alerta para situações de pessoa desaparecida/rapto"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Teste de LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Mostrar mensagens de teste"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Exercício de LU-Alert"</string>
diff --git a/res/values-mcc270-pt/strings.xml b/res/values-mcc270-pt/strings.xml
index 1b5e24158..adbfe6eb6 100644
--- a/res/values-mcc270-pt/strings.xml
+++ b/res/values-mcc270-pt/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: alerta de sequestro"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: alerta de desaparecimento / sequestro"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Teste de LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Simulação de LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerta de sequestro"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Mostrar mensagens de alerta para sequestro de crianças"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Alerta de desaparecimento / sequestro"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Mostrar mensagens de alerta para situações de desaparecimento / sequestro"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Teste de LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Mostrar mensagens de teste"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Simulação de LU-Alert"</string>
diff --git a/res/values-mcc270-ro/strings.xml b/res/values-mcc270-ro/strings.xml
index 4a701f27b..8f4046be3 100644
--- a/res/values-mcc270-ro/strings.xml
+++ b/res/values-mcc270-ro/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: alertă de răpire"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: alertă dispariție/răpire a unei persoane"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Test LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Simulare LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alertă de răpire"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Afișează mesaje de alertă pentru răpirile de copii"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Alertă de dispariție / răpire a unei persoane"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Afișează mesaje de alertă pentru situații de dispariție / răpire a unei persoane"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Test LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Afișează mesaje de test"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Simulare LU-Alert"</string>
diff --git a/res/values-mcc270-ru/strings.xml b/res/values-mcc270-ru/strings.xml
index 64917b441..87fc2ea3d 100644
--- a/res/values-mcc270-ru/strings.xml
+++ b/res/values-mcc270-ru/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: оповещение о похищении"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: оповещение о пропаже или похищении"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: тестовые оповещения"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: учебная тревога"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Оповещения о похищениях"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Показывать сообщения о пропавших детях"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Оповещения о пропаже или похищении людей"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Показывать сообщения о пропаже или похищении людей"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: тестовые оповещения"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Показывать тестовые сообщения"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert: учебная тревога"</string>
diff --git a/res/values-mcc270-si/strings.xml b/res/values-mcc270-si/strings.xml
index 0e3025856..8aac5140a 100644
--- a/res/values-mcc270-si/strings.xml
+++ b/res/values-mcc270-si/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-ඇඟවීම"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-ඇඟවීම"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-ඇඟවීම"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-ඇඟවීම: පැහැරගැනීම් ඇඟවීම"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-ඇඟවීම: අතුරුදහන් වූ පුද්ගලයා / පැහැරගැනීමේ ඇඟවීම"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-ඇඟවීම පරීක්ෂණය"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-ඇඟවීම අභ්‍යාසය"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"පහර ගැනීමේ ඇඟවීම"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ළමයින් පැහැර ගැනීම් සඳහා ඇඟවීම් පණිවිඩ පෙන්වන්න"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"අතුරුදහන් වූ පුද්ගලයා / පැහැරගැනීමේ ඇඟවීම"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"අතුරුදහන් වූ පුද්ගලයා / පැහැර ගැනීමේ අවස්ථා සඳහා ඇඟවීම් පණිවිඩ පෙන්වන්න"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-ඇඟවීම පරීක්ෂණය"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"පරීක්ෂණ පණිවිඩ පෙන්වන්න"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-ඇඟවීම අභ්‍යාසය"</string>
diff --git a/res/values-mcc270-sk/strings.xml b/res/values-mcc270-sk/strings.xml
index c045a42ad..394168310 100644
--- a/res/values-mcc270-sk/strings.xml
+++ b/res/values-mcc270-sk/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: upozornenie na únos"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : nezvestná osoba alebo únos"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Cvičenie"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Upozornenie na únos"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Zobrazovať upozornenia na únosy detí"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Upozornenie na nezvestnú osobu alebo únos"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Zobrazovať upozornenia na nezvestné osoby alebo únosy"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Zobrazovať testovacie správy"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Cvičenie"</string>
diff --git a/res/values-mcc270-sl/strings.xml b/res/values-mcc270-sl/strings.xml
index 5882c8d43..5b0bae167 100644
--- a/res/values-mcc270-sl/strings.xml
+++ b/res/values-mcc270-sl/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"Opozorilo za LU"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"Opozorilo za LU"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"Opozorilo za LU"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"Opozorilo za LU: Opozorilo o ugrabitvi"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"Opozorilo za LU: O pogrešani osebi/ugrabitvi"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Preizkus opozorila za LU"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Vaja za opozorilo za LU"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Opozorilo o ugrabitvi"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Prikaz opozorilnih sporočil o ugrabitvah otrok"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Opozorilo o pogrešani osebi/ugrabitvi"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Prikaz opozorilnih sporočil o pogrešanih osebah/ugrabitvah"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Preizkus opozorila za LU"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Prikaz preizkusnih sporočil"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Vaja za opozorilo za LU"</string>
diff --git a/res/values-mcc270-sq/strings.xml b/res/values-mcc270-sq/strings.xml
index 05885b396..bc1b9c326 100644
--- a/res/values-mcc270-sq/strings.xml
+++ b/res/values-mcc270-sq/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Sinjalizim për rrëmbim"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Sinjalizim personi të humbur / rrëmbimi"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: Testim"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: Ushtrim"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Sinjalizim rrëmbimi"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Shfaq mesazhe sinjalizuese për rrëmbimet e fëmijëve"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Sinjalizim personi të humbur / rrëmbimi"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Shfaq mesazhe sinjalizuese për situatat e personave të humbur / rrëmbimeve"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: Testim"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Shfaq mesazhet e testimit"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert: Ushtrim"</string>
diff --git a/res/values-mcc270-sr/strings.xml b/res/values-mcc270-sr/strings.xml
index 265808851..6b4f15c7f 100644
--- a/res/values-mcc270-sr/strings.xml
+++ b/res/values-mcc270-sr/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Упозорење о отмици"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Упозорење о несталој особи или отмици"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert тест"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert вежбање"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Упозорење о отмици"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Приказуј поруке упозорења за отмице деце"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Упозорење о несталој особи или отмици"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Приказује поруке упозорења у вези са несталом особом или отмицом"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert тест"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Приказуј пробне поруке"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert вежбање"</string>
diff --git a/res/values-mcc270-sv/strings.xml b/res/values-mcc270-sv/strings.xml
index 2d1bdd331..81f4d12de 100644
--- a/res/values-mcc270-sv/strings.xml
+++ b/res/values-mcc270-sv/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-varning"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-varning"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-varning"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-varning : Varning om kidnappning"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Varning om försvinnande/kidnappning"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-varningstest"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-varningsövning"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Varning om kidnappning"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Visa varningsmeddelanden om kidnappade barn"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Varning om försvinnande/kidnappning"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Visa varningsmeddelanden om försvinnanden/kidnappningar"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-varningstest"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Visa testmeddelanden"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-varningsövning"</string>
diff --git a/res/values-mcc270-sw/strings.xml b/res/values-mcc270-sw/strings.xml
index fc016f8f4..eab467fd5 100644
--- a/res/values-mcc270-sw/strings.xml
+++ b/res/values-mcc270-sw/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Arifa kuhusu utekaji nyara"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : Arifa ya mtu kupotea / kutekwa nyara"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Jaribio la LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Majaribio ya LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Arifa kuhusu utekaji nyara"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Onyesha ujumbe wa arifa kuhusu matukio ya watoto kutekwa nyara"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Arifa ya mtu kupotea / kutekwa nyara"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Onyesha ujumbe wa arifa za matukio ya mtu kupotea / kutekwa nyara"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Jaribio la LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Onyesha ujumbe wa jaribio"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Majaribio ya LU-Alert"</string>
diff --git a/res/values-mcc270-ta/strings.xml b/res/values-mcc270-ta/strings.xml
index 02eae5d17..622196fcd 100644
--- a/res/values-mcc270-ta/strings.xml
+++ b/res/values-mcc270-ta/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : கடத்தல் குறித்த எச்சரிக்கை"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : காணாமல் போனவர் / கடத்தல் எச்சரிக்கை"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert பரிசோதனை"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert பயிற்சி"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"கடத்தல் குறித்த எச்சரிக்கை"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"குழந்தை கடத்தல்கள் குறித்த எச்சரிக்கை மெசேஜ்களைக் காட்டும்"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"காணாமல் போனவர் / கடத்தல் எச்சரிக்கை"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"காணாமல் போனவர் / கடத்தல் குறித்த எச்சரிக்கை மெசேஜ்களைக் காட்டும்"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert பரிசோதனை"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"பரிசோதனை மெசேஜ்களைக் காட்டும்"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert பயிற்சி"</string>
diff --git a/res/values-mcc270-te/strings.xml b/res/values-mcc270-te/strings.xml
index 539251f46..3bf0a424e 100644
--- a/res/values-mcc270-te/strings.xml
+++ b/res/values-mcc270-te/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-అలర్ట్"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-అలర్ట్"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-అలర్ట్"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-అలర్ట్ : కిడ్నాపింగ్ అలర్ట్"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-అలర్ట్ : వ్యక్తి అదృశ్యం / కిడ్నాప్ అలర్ట్"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-అలర్ట్ టెస్ట్"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-అలర్ట్ డ్రిల్"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"కిడ్నాపింగ్ అలర్ట్"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"పిల్లల కిడ్నాప్‌లకు సంబంధించిన అలర్ట్ మెసేజ్‌లను చూడండి"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"వ్యక్తి అదృశ్యం / కిడ్నాప్‌కు సంబంధించిన అలర్ట్"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"వ్యక్తి అదృశ్యమైనప్పుడు / కిడ్నాప్ అయినప్పుడు అలర్ట్ మెసేజ్‌లు చూపండి"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-అలర్ట్ టెస్ట్"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"టెస్ట్ మెసేజ్‌లను చూడండి"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-అలర్ట్ డ్రిల్"</string>
diff --git a/res/values-mcc270-th/strings.xml b/res/values-mcc270-th/strings.xml
index 7b62aebc2..311fc4cef 100644
--- a/res/values-mcc270-th/strings.xml
+++ b/res/values-mcc270-th/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : การแจ้งเตือนการลักพาตัวเด็ก"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: การแจ้งเตือนการหายตัวไป/การลักพาตัว"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"การทดสอบ LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"การฝึกซ้อม LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"การแจ้งเตือนการลักพาตัวเด็ก"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"แสดงข้อความแจ้งเตือนเรื่องการลักพาตัวเด็ก"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"การแจ้งเตือนการหายตัวไป/การลักพาตัว"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"แสดงข้อความแจ้งเตือนสถานการณ์การหายตัวไป/การลักพาตัว"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"การทดสอบ LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"แสดงข้อความทดสอบ"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"การฝึกซ้อม LU-Alert"</string>
diff --git a/res/values-mcc270-tl/strings.xml b/res/values-mcc270-tl/strings.xml
index 33410c69e..6dd366423 100644
--- a/res/values-mcc270-tl/strings.xml
+++ b/res/values-mcc270-tl/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Alerto sa pag-kidnap"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : Alerto sa nawawalang tao / pag-kidnap"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Pagsubok sa LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Pagsasanay sa LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerto sa pag-kidnap"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Magpakita ng mga mensahe ng alerto para sa mga pagdukot ng bata"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Alerto sa nawawalang tao / pag-kidnap"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Magpakita ng mga alertong mensahe para sa mga sitwasyon ng nawawalang tao / pag-kidnap"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Pagsubok sa LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Magpakita ng mga mensahe ng pagsubok"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Pagsasanay sa LU-Alert"</string>
diff --git a/res/values-mcc270-tr/strings.xml b/res/values-mcc270-tr/strings.xml
index 0db79c931..525659cf9 100644
--- a/res/values-mcc270-tr/strings.xml
+++ b/res/values-mcc270-tr/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Kaçırılma uyarısı"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Kayıp kişi / kaçırılma uyarısı"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Testi"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Tatbikatı"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kaçırılma uyarısı"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Çocuk kaçırma olaylarıyla ilgili uyarı mesajlarını göster"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Kayıp kişi / kaçırılma uyarısı"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Kayıp kişi / kaçırılma durumlarıyla ilgili uyarı mesajlarını göster"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Testi"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Test mesajlarını göster"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Tatbikatı"</string>
diff --git a/res/values-mcc270-uk/strings.xml b/res/values-mcc270-uk/strings.xml
index 412f74c3f..7f1b5baae 100644
--- a/res/values-mcc270-uk/strings.xml
+++ b/res/values-mcc270-uk/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: сповіщення про викрадення"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: сповіщення про зниклих/викрадених людей"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: тестове сповіщення"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: тренувальне сповіщення"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Сповіщення про викрадення дитини"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Показувати сповіщення про викрадених дітей"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Сповіщення про зниклих/викрадених людей"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Показувати сповіщення про зниклих/викрадених людей"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: тестові сповіщення"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Показувати тестові повідомлення"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert: тренувальні сповіщення"</string>
diff --git a/res/values-mcc270-ur/strings.xml b/res/values-mcc270-ur/strings.xml
index ddd15ef46..e40336821 100644
--- a/res/values-mcc270-ur/strings.xml
+++ b/res/values-mcc270-ur/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"‫LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"‫LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"‫LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"‏‫Alert-LU: اغوا سے متعلق الرٹ"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"‏‫LU-Alert: لاپتہ فرد / اغوا سے متعلق الرٹ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"‏‫LU-Alert ٹيسٹ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"‏‫LU-Alert ورزش"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"اغوا سے متعلق الرٹ"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"بچوں کے اغوا کے لیے الرٹ پیغامات دکھائیں"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"لا پتہ فرد / اغوا سے متعلق الرٹ"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"لاپتہ فرد / اغوا کی صورتحال کے لیے الرٹ پیغامات دکھائیں"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"‏‫LU-Alert ٹيسٹ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"ٹیسٹ پیغامات دکھائیں"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"‏‫LU-Alert ورزش"</string>
diff --git a/res/values-mcc270-uz/strings.xml b/res/values-mcc270-uz/strings.xml
index 5ddab3f6b..7a0101aa1 100644
--- a/res/values-mcc270-uz/strings.xml
+++ b/res/values-mcc270-uz/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Bola oʻgʻirlanishi haqida ogohlantirish"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert : Yoʻqolish / oʻgʻirlanish ogohlantiruvi"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert sinovi"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert simulyatsiyasi"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Bola oʻgʻirlanishi haqida ogohlantirish"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Bola oʻgʻrilanishi haqida ogohlantirishlarini koʻrsatish"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Yoʻqolish / oʻgʻirlanish haqida ogohlantirish"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Shaxslarning yoʻqolishi / oʻgʻirlanishi holatlari uchun ogohlantirish xabarlarini koʻrsatish"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert sinovi"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Sinov xabarlarini koʻrsatish"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert simulyatsiyasi"</string>
diff --git a/res/values-mcc270-vi/strings.xml b/res/values-mcc270-vi/strings.xml
index 17df1fc72..9d933c0e0 100644
--- a/res/values-mcc270-vi/strings.xml
+++ b/res/values-mcc270-vi/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Cảnh báo bắt cóc"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert: Cảnh báo mất tích/bắt cóc"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Kiểm thử"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Diễn tập"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Cảnh báo bắt cóc trẻ em"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Hiện cảnh báo bắt cóc trẻ em"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Cảnh báo mất tích/bắt cóc"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Hiện cảnh báo về tình huống mất tích/bắt cóc"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Kiểm thử"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Hiện thông báo kiểm thử"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert Diễn tập"</string>
diff --git a/res/values-mcc270-zh-rCN/strings.xml b/res/values-mcc270-zh-rCN/strings.xml
index 09152261b..362c27dec 100644
--- a/res/values-mcc270-zh-rCN/strings.xml
+++ b/res/values-mcc270-zh-rCN/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert：绑架警报"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert：人员失踪/绑架警报"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert 测试"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert 演习"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"绑架警报"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"显示有关儿童被诱拐的警报消息"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"人员失踪/绑架警报"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"显示关于人员失踪/绑架事件的警报消息"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert 测试"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"显示测试消息"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert 演习"</string>
diff --git a/res/values-mcc270-zh-rHK/strings.xml b/res/values-mcc270-zh-rHK/strings.xml
index 5066b70a7..fb8a672fd 100644
--- a/res/values-mcc270-zh-rHK/strings.xml
+++ b/res/values-mcc270-zh-rHK/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert：綁架警示"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert：失蹤/綁架警示"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert 測試"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert 演習"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"綁架警示"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"顯示兒童誘帶案件的警示訊息"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"失蹤/綁架警示"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"顯示失蹤/綁架情況的警示訊息"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert 測試"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"顯示測試訊息"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert 演習"</string>
diff --git a/res/values-mcc270-zh-rTW/strings.xml b/res/values-mcc270-zh-rTW/strings.xml
index eda696b6c..57a17830e 100644
--- a/res/values-mcc270-zh-rTW/strings.xml
+++ b/res/values-mcc270-zh-rTW/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert：綁架警報"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"LU-Alert：失蹤/綁架警報"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert 測試"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert 演習"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"綁架警報"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"顯示兒童誘拐案件的警報訊息"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"失蹤/綁架警報"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"顯示失蹤/綁架事件的警報訊息"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert 測試"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"顯示測試訊息"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"LU-Alert 演習"</string>
diff --git a/res/values-mcc270-zu/strings.xml b/res/values-mcc270-zu/strings.xml
index ff52ae253..b41e032e8 100644
--- a/res/values-mcc270-zu/strings.xml
+++ b/res/values-mcc270-zu/strings.xml
@@ -20,11 +20,11 @@
     <string name="cmas_extreme_alert" msgid="5707699462404036561">"I-LU-Alert"</string>
     <string name="cmas_severe_alert" msgid="3403847334974558596">"I-LU-Alert"</string>
     <string name="public_safety_message" msgid="7178887441252495779">"I-LU-Alert"</string>
-    <string name="cmas_amber_alert" msgid="1934668428381380827">"I-LU-Alert : Isexwayiso sokuthumba"</string>
+    <string name="cmas_amber_alert" msgid="258609494655720157">"I-LU-Alert : Isexwayiso solahlekile / sothunjiwe"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Ukuhlolwa kwe-LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Isivivinyo Se-LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Isexwayiso sokuthunjwa"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Bonisa imiyalezo yesixwayiso yokuthunjwa kwezingane"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="709666858644713262">"Isexwayiso somuntu olahlekile / othunyiwe"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="3678172264874835315">"Bonisa imiyalezo yezexwayiso zezimo zomuntu olahlekile / othunjiwe"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Ukuhlolwa kwe-LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Bonisa imiyalezo yokuhlola"</string>
     <string name="enable_exercise_test_alerts_title" msgid="8642537980920870855">"Isivivinyo Se-LU-Alert"</string>
diff --git a/res/values-mcc270/strings.xml b/res/values-mcc270/strings.xml
index 208c60149..7fc76024c 100644
--- a/res/values-mcc270/strings.xml
+++ b/res/values-mcc270/strings.xml
@@ -38,9 +38,9 @@
     <string name="public_safety_message">LU-Alert</string>
 
     <!-- CMAS dialog title for 'EU-Amber / Child Abdunction Alert' alert notification (amber alert). [CHAR LIMIT=50] -->
-    <!-- Required German (de) translation for this message: "LU-Alert : Entführungswarnung" -->
-    <!-- Required French (fr) translation for this message: "LU-Alert : Alerte enlèvement" -->
-    <string name="cmas_amber_alert">LU-Alert : Kidnapping alert</string>
+    <!-- Required German (de) translation for this message: "LU-Alert : Vermissten- / Entführungsmeldung" -->
+    <!-- Required French (fr) translation for this message: "LU-Alert : Alerte disparition / enlèvement" -->
+    <string name="cmas_amber_alert">LU-Alert : Missing person / kidnapping alert</string>
 
     <!-- CMAS dialog title for 'EU-Monthly Test' alert notification. [CHAR LIMIT=50] -->
     <!-- Required German (de) translation for this message: "LU-Alert Test" -->
@@ -53,13 +53,13 @@
     <string name="cmas_exercise_alert">LU-Alert Exercise</string>
 
     <!-- Preference title for enable 'EU-Amber / Child Abdunction Alert' checkbox. [CHAR LIMIT=50] -->
-    <!-- Required German (de) translation for this message: "Entführungswarnung" -->
-    <!-- Required French (fr) translation for this message: "Alerte enlèvement" -->
-    <string name="enable_cmas_amber_alerts_title">Kidnapping alert</string>
+    <!-- Required German (de) translation for this message: "Vermissten- / Entführungsmeldung" -->
+    <!-- Required French (fr) translation for this message: "Alerte disparition / enlèvement" -->
+    <string name="enable_cmas_amber_alerts_title">Missing person / kidnapping alert</string>
     <!-- Preference summary for enable 'EU-Amber / Child Abdunction Alert' checkbox. [CHAR LIMIT=100] -->
-    <!-- Required German (de) translation for this message: "Warnmeldungen bei Kindesentführungen anzeigen" -->
-    <!-- Required French (fr) translation for this message: "Afficher les messages d’alerte pour les enlèvements d'enfant" -->
-    <string name="enable_cmas_amber_alerts_summary">Show alert messages for child abductions</string>
+    <!-- Required German (de) translation for this message: "Warnmeldungen bei Vermissten- / Entführungssituationen anzeigen" -->
+    <!-- Required French (fr) translation for this message: "Afficher les messages d’alerte pour des disparitions / enlèvements" -->
+    <string name="enable_cmas_amber_alerts_summary">Show alert messages for missing person / kidnapping situations</string>
 
     <!-- Preference title for 'EU-Monthly Test' checkbox. [CHAR LIMIT=50] -->
     <!-- Required German (de) translation for this message: "LU-Alert Test" -->
diff --git a/res/values-mcc310-b+sr+Latn/strings.xml b/res/values-mcc310-b+sr+Latn/strings.xml
index ba5544b3a..7db9f765a 100644
--- a/res/values-mcc310-b+sr+Latn/strings.xml
+++ b/res/values-mcc310-b+sr+Latn/strings.xml
@@ -16,9 +16,9 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_label" msgid="6018514276739876277">"Mobilna upozorenja o hitnim slučajevima"</string>
-    <string name="sms_cb_settings" msgid="1556918270840502446">"Mobilna upozorenja o hitnim slučajevima"</string>
-    <string name="emergency_alert_settings_title_watches" msgid="5702555089013313773">"Mobilna upozorenja o hitnim slučajevima"</string>
+    <string name="app_label" msgid="6018514276739876277">"Upozorenja o hitnim slučajevima"</string>
+    <string name="sms_cb_settings" msgid="1556918270840502446">"Upozorenja o hitnim slučajevima"</string>
+    <string name="emergency_alert_settings_title_watches" msgid="5702555089013313773">"Upozorenja o hitnim slučajevima"</string>
     <string name="receive_cmas_in_second_language_title" msgid="7539080017840218665">"španski"</string>
     <string name="receive_cmas_in_second_language_summary" msgid="4482209573334686904">"Primajte obaveštenja o hitnim slučajevima na španskom kada je to moguće"</string>
     <string name="confirm_delete_broadcast" msgid="6808374217554967811">"Želite da izbrišete ovo upozorenje?"</string>
diff --git a/res/values-mcc310-mk/strings.xml b/res/values-mcc310-mk/strings.xml
index 2ff23cabf..1afa1d8d2 100644
--- a/res/values-mcc310-mk/strings.xml
+++ b/res/values-mcc310-mk/strings.xml
@@ -27,7 +27,7 @@
     <string name="menu_delete_all" msgid="8991615021908376216">"Избриши ги предупредувањата"</string>
     <!-- no translation found for enable_cmas_test_alerts_title (3722503121618497385) -->
     <skip />
-    <string name="enable_cmas_test_alerts_summary" msgid="6138676147687910935">"Примај задолжителни месечни тест-пораки од безбедносниот систем за предупредување"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="6138676147687910935">"Примајте задолжителни месечни пробни предупредувања од системот за безбедносни предупредувања"</string>
     <string name="cmas_presidential_level_alert" msgid="5810314558991898384">"Национално предупредување"</string>
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Прикажи дијалог за откажување по првото предупредување (освен за „Национално предупредување“)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Национални предупредувања"</string>
diff --git a/res/values-mcc310-sk/strings.xml b/res/values-mcc310-sk/strings.xml
index 3ee4716fb..af1f78f12 100644
--- a/res/values-mcc310-sk/strings.xml
+++ b/res/values-mcc310-sk/strings.xml
@@ -27,7 +27,7 @@
     <string name="menu_delete_all" msgid="8991615021908376216">"Odstrániť upozornenia"</string>
     <!-- no translation found for enable_cmas_test_alerts_title (3722503121618497385) -->
     <skip />
-    <string name="enable_cmas_test_alerts_summary" msgid="6138676147687910935">"Dostávať požadované mesačné testy zo systému bezpečnostných upozornení"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="6138676147687910935">"Dostávať požadované mesačné testy zo systému bezpečnostných výstrah"</string>
     <string name="cmas_presidential_level_alert" msgid="5810314558991898384">"Celoštátne varovanie"</string>
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"Zobraziť dialógové okno na odhlásenie po prvom varovaní (okrem celoštátneho varovania)"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"Národné upozornenia"</string>
diff --git a/res/values-mcc310-sr/strings.xml b/res/values-mcc310-sr/strings.xml
index 80ac3c093..f35deb4eb 100644
--- a/res/values-mcc310-sr/strings.xml
+++ b/res/values-mcc310-sr/strings.xml
@@ -16,9 +16,9 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_label" msgid="6018514276739876277">"Мобилна упозорења о хитним случајевима"</string>
-    <string name="sms_cb_settings" msgid="1556918270840502446">"Мобилна упозорења о хитним случајевима"</string>
-    <string name="emergency_alert_settings_title_watches" msgid="5702555089013313773">"Мобилна упозорења о хитним случајевима"</string>
+    <string name="app_label" msgid="6018514276739876277">"Упозорења о хитним случајевима"</string>
+    <string name="sms_cb_settings" msgid="1556918270840502446">"Упозорења о хитним случајевима"</string>
+    <string name="emergency_alert_settings_title_watches" msgid="5702555089013313773">"Упозорења о хитним случајевима"</string>
     <string name="receive_cmas_in_second_language_title" msgid="7539080017840218665">"шпански"</string>
     <string name="receive_cmas_in_second_language_summary" msgid="4482209573334686904">"Примајте обавештења о хитним случајевима на шпанском када је то могуће"</string>
     <string name="confirm_delete_broadcast" msgid="6808374217554967811">"Желите да избришете ово упозорење?"</string>
diff --git a/res/values-mcc404/config.xml b/res/values-mcc404/config.xml
index 309d30c8c..da988ea55 100644
--- a/res/values-mcc404/config.xml
+++ b/res/values-mcc404/config.xml
@@ -22,58 +22,58 @@
 
     <!-- 4370, 4383 -->
     <string-array name="cmas_presidential_alerts_channels_range_strings" translatable="false">
-        <item>0x1112:rat=gsm, emergency=true, always_on=true, alert_duration=31500</item>
-        <item>0x1000:rat=cdma, emergency=true, always_on=true, alert_duration=31500</item>
+        <item>0x1112:rat=gsm, emergency=true, always_on=true, alert_duration=15000</item>
+        <item>0x1000:rat=cdma, emergency=true, always_on=true, alert_duration=15000</item>
         <!-- additional language -->
-        <item>0x111F:rat=gsm, emergency=true, always_on=true, alert_duration=31500</item>
+        <item>0x111F:rat=gsm, emergency=true, always_on=true, alert_duration=15000</item>
     </string-array>
     <!-- 4371~4372, 4384~4385 -->
     <string-array name="cmas_alert_extreme_channels_range_strings" translatable="false">
-        <item>0x1113-0x1114:rat=gsm, emergency=true, alert_duration=31500, always_on=true</item>
-        <item>0x1001:rat=cdma, emergency=true, alert_duration=31500, always_on=true</item>
+        <item>0x1113-0x1114:rat=gsm, emergency=true, alert_duration=15000, always_on=true</item>
+        <item>0x1001:rat=cdma, emergency=true, alert_duration=15000, always_on=true</item>
         <!-- additional language -->
-        <item>0x1120-0x1121:rat=gsm, emergency=true, alert_duration=31500, always_on=true</item>
+        <item>0x1120-0x1121:rat=gsm, emergency=true, alert_duration=15000, always_on=true</item>
     </string-array>
     <!-- 4373~4378, 4386~4391 -->
     <string-array name="cmas_alerts_severe_range_strings" translatable="false">
-        <item>0x1115-0x111A:rat=gsm, emergency=true, alert_duration=31500, always_on=true</item>
-        <item>0x1002:rat=cdma, emergency=true, alert_duration=31500, always_on=true</item>
+        <item>0x1115-0x111A:rat=gsm, emergency=true, alert_duration=15000, always_on=true</item>
+        <item>0x1002:rat=cdma, emergency=true, alert_duration=15000, always_on=true</item>
         <!-- additional language -->
-        <item>0x1122-0x1127:rat=gsm, emergency=true, alert_duration=31500, always_on=true</item>
+        <item>0x1122-0x1127:rat=gsm, emergency=true, alert_duration=15000, always_on=true</item>
     </string-array>
     <!-- 4379, 4392 -->
     <string-array name="cmas_amber_alerts_channels_range_strings" translatable="false">
-        <item>0x111B:rat=gsm, emergency=true, alert_duration=31500</item>
-        <item>0x1003:rat=cdma, emergency=true, alert_duration=31500</item>
+        <item>0x111B:rat=gsm, emergency=true, alert_duration=15000</item>
+        <item>0x1003:rat=cdma, emergency=true, alert_duration=15000</item>
         <!-- additional language -->
-        <item>0x1128:rat=gsm, emergency=true, alert_duration=31500</item>
+        <item>0x1128:rat=gsm, emergency=true, alert_duration=15000</item>
     </string-array>
     <!-- 4380~4382, 4393~4395 -->
     <string-array name="required_monthly_test_range_strings" translatable="false">
-        <item>0x111C:rat=gsm, emergency=true, alert_duration=31500</item>
-        <item>0x1004:rat=cdma, emergency=true, alert_duration=31500</item>
+        <item>0x111C:rat=gsm, emergency=true, alert_duration=15000</item>
+        <item>0x1004:rat=cdma, emergency=true, alert_duration=15000</item>
         <!-- additional language -->
-        <item>0x1129:rat=gsm, emergency=true, alert_duration=31500</item>
+        <item>0x1129:rat=gsm, emergency=true, alert_duration=15000</item>
     </string-array>
     <string-array name="exercise_alert_range_strings" translatable="false">
-        <item>0x111D:rat=gsm, emergency=true, alert_duration=31500</item>
+        <item>0x111D:rat=gsm, emergency=true, alert_duration=15000</item>
         <!-- additional language -->
-        <item>0x112A:rat=gsm, emergency=true, alert_duration=31500</item>
+        <item>0x112A:rat=gsm, emergency=true, alert_duration=15000</item>
     </string-array>
     <string-array name="operator_defined_alert_range_strings" translatable="false">
-        <item>0x111E:rat=gsm, emergency=true, alert_duration=31500</item>
+        <item>0x111E:rat=gsm, emergency=true, alert_duration=15000</item>
         <!-- additional language -->
-        <item>0x112B:rat=gsm, emergency=true, alert_duration=31500</item>
+        <item>0x112B:rat=gsm, emergency=true, alert_duration=15000</item>
     </string-array>
 
     <!-- 4352~4354, 4356 -->
     <string-array name="etws_alerts_range_strings" translatable="false">
-        <item>0x1100-0x1102:rat=gsm, emergency=true, alert_duration=31500</item>
-        <item>0x1104:rat=gsm, emergency=true, alert_duration=31500</item>
+        <item>0x1100-0x1102:rat=gsm, emergency=true, alert_duration=15000</item>
+        <item>0x1104:rat=gsm, emergency=true, alert_duration=15000</item>
     </string-array>
     <!-- 4355-->
     <string-array name="etws_test_alerts_range_strings" translatable="false">
-        <item>0x1103:rat=gsm, emergency=true, alert_duration=31500</item>
+        <item>0x1103:rat=gsm, emergency=true, alert_duration=15000</item>
     </string-array>
 
     <!-- Whether to disable the status bar while alert is showing, not allow
diff --git a/res/values-mcc420-mk/strings.xml b/res/values-mcc420-mk/strings.xml
index 54d5a3507..9e49a4a71 100644
--- a/res/values-mcc420-mk/strings.xml
+++ b/res/values-mcc420-mk/strings.xml
@@ -23,6 +23,6 @@
     <string name="pws_other_message_identifiers" msgid="7907712751421890873">"Предупредувања"</string>
     <string name="enable_emergency_alerts_message_title" msgid="5267857032926801433">"Предупредувања"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="8961532453478455676">"Препорачани дејства што може да спасат живот или имот"</string>
-    <string name="cmas_required_monthly_test" msgid="5733131786754331921">"Тест-предупредувања"</string>
+    <string name="cmas_required_monthly_test" msgid="5733131786754331921">"Пробни предупредувања"</string>
     <string name="cmas_exercise_alert" msgid="7249058541625071454">"Вежби"</string>
 </resources>
diff --git a/res/values-mcc420/config.xml b/res/values-mcc420/config.xml
index f0aa8beef..cb1655f55 100644
--- a/res/values-mcc420/config.xml
+++ b/res/values-mcc420/config.xml
@@ -39,9 +39,13 @@
     </string-array>
     <!-- 4373~4378, 4386~4391 -->
     <string-array name="cmas_alerts_severe_range_strings" translatable="false">
-        <item>0x1115-0x111A:rat=gsm, emergency=true, always_on=true, language=ar</item>
+        <item>0x1115-0x1118:rat=gsm, emergency=true, always_on=true, language=ar</item>
+        <item>0x1119:rat=gsm, emergency=true, type=info, always_on=true, language=ar</item>
+        <item>0x111A:rat=gsm, emergency=true, always_on=true, language=ar</item>
         <!-- additional language -->
-        <item>0x1122-0x1127:rat=gsm, emergency=true, always_on=true, language=en</item>
+        <item>0x1122-0x1125:rat=gsm, emergency=true, always_on=true, language=en</item>
+        <item>0x1126:rat=gsm, emergency=true, type=info, always_on=true, language=en</item>
+        <item>0x1127:rat=gsm, emergency=true, always_on=true, language=en</item>
     </string-array>
     <!-- 4379, 4392 -->
     <string-array name="emergency_alerts_channels_range_strings" translatable="false">
diff --git a/res/values-mcc466-mk/strings.xml b/res/values-mcc466-mk/strings.xml
index e191dec06..beb7994bf 100644
--- a/res/values-mcc466-mk/strings.xml
+++ b/res/values-mcc466-mk/strings.xml
@@ -20,5 +20,5 @@
     <string name="emergency_alert" msgid="5431770009291479378">"Предупредување за итни случаи"</string>
     <string name="public_safety_message" msgid="3043854916586710461">"Порака за предупредување"</string>
     <string name="enable_cmas_test_alerts_title" msgid="4165080207837566277">"Задолжително месечно тест-предупредување"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="1339769389077152402">"Примај тест-пораки од безбедносниот систем за предупредување"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="1339769389077152402">"Примајте пробни предупредувања од системот за безбедносни предупредувања"</string>
 </resources>
diff --git a/res/values-mcc724-gu/strings.xml b/res/values-mcc724-gu/strings.xml
index ed8e5ca33..fe5e84b7f 100644
--- a/res/values-mcc724-gu/strings.xml
+++ b/res/values-mcc724-gu/strings.xml
@@ -21,7 +21,7 @@
     <string name="cmas_required_monthly_test" msgid="5274965928258227096">"કસરત માટેનું અલર્ટ"</string>
     <string name="cmas_exercise_alert" msgid="4971838389621550184">"ટેક્નિકલ પરીક્ષણ માટેનું અલર્ટ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="3095141156358640879">"આત્યંતિક જોખમો"</string>
-    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6931853411327178941">"જીવન અને સંપત્તિના આત્યંતિક જોખમો"</string>
+    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6931853411327178941">"જીવન અને સંપત્તિને ભારે જોખમો"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="2603680055509729555">"ગંભીર જોખમો"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="405751015446465202">"જીવન અને સંપત્તિના ગંભીર જોખમો"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5550182663333808054">"રાજ્ય અને સ્થાનિક પરીક્ષણો"</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 6fb3c5a18..6d681f32c 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -88,8 +88,8 @@
     <string name="enable_state_local_test_alerts_summary" msgid="780298327377950187">"Добивајте тест-пораки од државните и локалните власти"</string>
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"Предупредувања за итни случаи"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"Предупреди за настани опасни по живот"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"Тест-предупредувања"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Примај тест-предупредувања од операторот и месечни тест-предупредувања од безбедносниот систем"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"Пробни предупредувања"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Примајте пробни предупредувања од операторот и месечни пробни предупредувања од системот за безбедносни предупредувања"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
     <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"Добивајте предупредувања за итни случаи: порака за вежба/обука"</string>
@@ -172,7 +172,7 @@
     <string name="seconds" msgid="141450721520515025">"секунди"</string>
     <string name="message_copied" msgid="6922953753733166675">"Пораката е копирана"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
-    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Кога сте во роаминг или немате активна SIM-картичка, може да добивате некои известувања што не се опфатени во поставкиве"</string>
+    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Кога сте во роаминг или немате активна SIM-картичка, може да добивате некои предупредувања што не се опфатени во поставкиве"</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"Вашите поставки се променети"</string>
     <string name="notification_cb_settings_changed_text" msgid="8722470940705858715">"Поставките за безжични предупредувања за итни случаи се ресетираа бидејќи ја променивте SIM-картичката"</string>
 </resources>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index dd891cc4f..9310a88e3 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -17,7 +17,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_label" msgid="2008319089248760277">"वायरलेस आणीबाणी अलर्ट"</string>
-    <string name="sms_cb_settings" msgid="9021266457863671070">"वायरलेस आणीबाणी अलर्ट"</string>
+    <string name="sms_cb_settings" msgid="9021266457863671070">"वायरलेस आणीबाणी इशारे"</string>
     <string name="sms_cb_sender_name_default" msgid="972946539768958828">"वायरलेस आणीबाणी सूचना"</string>
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"आणीबाणीच्या वायरलेस सूचना"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"आणीबाणीच्या वायरलेस सूचना"</string>
@@ -68,7 +68,7 @@
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"सूचना मेसेज बोला"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"आणीबाणीमधील वायरलेस इशारा मेसेज बोलण्यासाठी टेक्स्ट-टू-स्पीच वापरा"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"नियमित व्हॉल्यूमवर एक रिमाइंडर आवाज प्ले होईल"</string>
-    <string name="emergency_alert_history_title" msgid="8310173569237268431">"आणीबाणी अलर्ट इतिहास"</string>
+    <string name="emergency_alert_history_title" msgid="8310173569237268431">"आणीबाणी इशारा इतिहास"</string>
     <string name="alert_preferences_title" msgid="6001469026393248468">"अलर्ट प्राधान्ये"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"ETWS चाचणी प्रसारणे"</string>
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"भूकंप त्सुनामी चेतावणी सिस्टमसाठी चाचणी प्रसारणे"</string>
@@ -141,7 +141,7 @@
     <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"तुम्हाला सध्या आणीबाणीमधील वायरलेस इशारा सूचना मिळत आहेत. तुम्हाला आणीबाणीमधील वायरलेस इशारा सूचना पुढे सुरू ठेवायच्या आहेत का?"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"होय"</string>
     <string name="cmas_opt_out_button_no" msgid="3110484064328538553">"नाही"</string>
-    <string name="cb_list_activity_title" msgid="1433502151877791724">"आणीबाणी अलर्ट इतिहास"</string>
+    <string name="cb_list_activity_title" msgid="1433502151877791724">"आणीबाणी इशारा इतिहास"</string>
     <string name="action_delete" msgid="7435661404543945861">"हटवा"</string>
     <string name="action_detail_info" msgid="8486524382178381810">"तपशील दाखवा"</string>
   <string-array name="alert_reminder_interval_entries">
@@ -172,7 +172,7 @@
     <string name="seconds" msgid="141450721520515025">"सेकंद"</string>
     <string name="message_copied" msgid="6922953753733166675">"मेसेज कॉपी केला"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
-    <string name="top_intro_roaming_text" msgid="5250650823028195358">"तुम्ही रोमिंगमध्ये असताना किंवा तुमच्याकडे अ‍ॅक्टिव्ह सिम नसताना, तुम्हाला या सेटिंग्जमध्ये समावेश नसलेल्या काही सूचना मिळू शकतात"</string>
+    <string name="top_intro_roaming_text" msgid="5250650823028195358">"तुम्ही रोमिंगमध्ये असताना किंवा तुमच्याकडे अ‍ॅक्टिव्ह सिम नसताना, तुम्हाला या सेटिंग्जमध्ये समाविष्ट नसलेले काही अलर्ट मिळू शकतात"</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"तुमची सेटिंग्ज बदलली आहेत"</string>
     <string name="notification_cb_settings_changed_text" msgid="8722470940705858715">"तुमचे सिम बदलल्यामुळे वायरलेस आणीबाणी इशाऱ्यांची सेटिंग्ज रीसेट करण्यात आली आहेत"</string>
 </resources>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 72c2c2ebd..07b7cb9fc 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -77,7 +77,7 @@
     <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"ଗମ୍ଭୀର ବିପଦ ଆଶଙ୍କା"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"ଜୀବନ ଓ ସମ୍ପତ୍ତି ପ୍ରତି ଗମ୍ଭୀର ବିପଦ ଆଶଙ୍କା"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"AMBER ଆଲର୍ଟ"</string>
-    <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"ଶିଶୁ ଅପହରଣର ଜରୁରୀକାଳୀନ ବୁଲେଟିନ୍"</string>
+    <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"ଶିଶୁ ଅପହରଣର ଜରୁରୀକାଳୀନ ବୁଲେଟିନ"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"ଆଲର୍ଟ ମେସେଜ୍"</string>
     <string name="enable_alert_message_summary" msgid="6525664541696985610">"ଏପରି ବିଷୟରେ ସୂଚନା ଦେବା, ଯେଉଁ କାରଣରୁ ସୁରକ୍ଷା ଉପରେ ବିପଦ ଆସିପାରେ"</string>
     <string name="enable_public_safety_messages_title" msgid="5576770949182656524">"ପବ୍ଲିକଙ୍କ ସୁରକ୍ଷା ପାଇଁ ମେସେଜ"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 8333d5526..f9a3536da 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -56,7 +56,7 @@
     <string name="public_safety_message" msgid="9119928798786998252">"ਜਨਤਕ ਸੁਰੱਖਿਆ ਸੰਬੰਧੀ ਸੁਨੇਹਾ"</string>
     <string name="state_local_test_alert" msgid="8003145745857480200">"ਰਾਜ ਜਾਂ ਸਥਾਨਕ ਟੈਸਟ"</string>
     <string name="emergency_alert" msgid="624783871477634263">"ਐਮਰਜੈਂਸੀ ਅਲਰਟ"</string>
-    <string name="emergency_alerts_title" msgid="6605036374197485429">"ਸੁਚੇਤਨਾਵਾਂ"</string>
+    <string name="emergency_alerts_title" msgid="6605036374197485429">"ਅਲਰਟ"</string>
     <string name="notification_channel_broadcast_messages" msgid="880704362482824524">"ਪ੍ਰਸਾਰਿਤ ਸੁਨੇਹੇ"</string>
     <string name="notification_channel_emergency_alerts" msgid="5008287980979183617">"ਸੰਕਟਕਾਲੀਨ ਚਿਤਾਵਨੀਆਂ"</string>
     <string name="notification_channel_emergency_alerts_high_priority" msgid="3937475297436439073">"ਅਸਵੀਕਾਰ ਕੀਤੇ ਐਮਰਜੈਂਸੀ ਅਲਰਟ"</string>
@@ -73,9 +73,9 @@
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"ETWS ਟੈਸਟ ਪ੍ਰਸਾਰਣ"</string>
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"ਭੂਚਾਲ ਸੁਨਾਮੀ ਚਿਤਾਵਨੀ ਸਿਸਟਮ ਲਈ ਟੈਸਟ ਪ੍ਰਸਾਰਣ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="5416260219062637770">"ਹੱਦੋਂ ਵੱਧ ਖਤਰੇ"</string>
-    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"ਜਾਨ ਅਤੇ ਮਾਲ ਦੇ ਹੱਦੋਂ ਵੱਧ ਖਤਰਿਆਂ ਸੰਬੰਧੀ ਸੁਚੇਤਨਾਵਾਂ"</string>
+    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"ਜਾਨ ਅਤੇ ਮਾਲ ਦੇ ਹੱਦੋਂ ਵੱਧ ਖਤਰਿਆਂ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"ਗੰਭੀਰ ਖਤਰੇ"</string>
-    <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"ਜਾਨ ਅਤੇ ਮਾਲ ਦੇ ਗੰਭੀਰ ਖਤਰਿਆਂ ਸੰਬੰਧੀ ਸੁਚੇਤਨਾਵਾਂ"</string>
+    <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"ਜਾਨ ਅਤੇ ਮਾਲ ਦੇ ਗੰਭੀਰ ਖਤਰਿਆਂ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"AMBER ਅਲਰਟ"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"ਅਗਵਾ ਹੋਏ ਬੱਚੇ ਸੰਬੰਧੀ ਐਮਰਜੈਂਸੀ ਬੁਲੇਟਿਨ"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"ਅਲਰਟ ਸੰਬੰਧੀ ਸੁਨੇਹੇ"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 3397bf016..e185d0cbd 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -89,7 +89,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"Alerte de urgență"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"Avertizează cu privire la evenimentele care pun în pericol viața"</string>
     <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"Alerte de testare"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Trimite teste de la operator și teste lunare de la sistemul de alertă privind siguranța"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"Primește teste de la operator și teste lunare de la sistemul de alertă privind siguranța"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
     <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"Primește alerta de urgență: mesaj de exercițiu/simulare"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index a1fc015b8..858f778e3 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -172,7 +172,7 @@
     <string name="seconds" msgid="141450721520515025">"сек."</string>
     <string name="message_copied" msgid="6922953753733166675">"Сообщение скопировано"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
-    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Если вы находитесь в роуминге или у вас нет активной SIM-карты, вам могут приходить оповещения, не указанные в этих настройках"</string>
+    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Если вы находитесь в роуминге или у вас нет активной SIM-карты, вам могут приходить оповещения, не указанные в этих настройках."</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"Настройки были изменены"</string>
     <string name="notification_cb_settings_changed_text" msgid="8722470940705858715">"Настройки экстренных оповещений по беспроводному каналу были сброшены, так как установлена другая SIM-карта"</string>
 </resources>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index edcf69291..5d199d88d 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -17,7 +17,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_label" msgid="2008319089248760277">"Bezdrôtové tiesňové výstrahy"</string>
-    <string name="sms_cb_settings" msgid="9021266457863671070">"Bezdrôtové tiesňové upozornenia"</string>
+    <string name="sms_cb_settings" msgid="9021266457863671070">"Bezdrôtové tiesňové výstrahy"</string>
     <string name="sms_cb_sender_name_default" msgid="972946539768958828">"Bezdrôtové tiesňové výstrahy"</string>
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Bezdrôtové tiesňové výstrahy"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Bezdrôtové tiesňové výstrahy"</string>
@@ -172,7 +172,7 @@
     <string name="seconds" msgid="141450721520515025">"s"</string>
     <string name="message_copied" msgid="6922953753733166675">"Správa bola skopírovaná"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
-    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Keď používate roaming alebo nemáte aktívnu SIM kartu, môžete dostávať upozornenia, ktoré v týchto nastaveniach nie sú zahrnuté"</string>
+    <string name="top_intro_roaming_text" msgid="5250650823028195358">"Keď používate roaming alebo nemáte aktívnu SIM kartu, môžete dostávať výstrahy, ktoré v týchto nastaveniach nie sú zahrnuté"</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"Nastavenia boli zmenené"</string>
     <string name="notification_cb_settings_changed_text" msgid="8722470940705858715">"Nastavenia bezdrôtových núdzových upozornení boli resetované, pretože bola vymenená SIM karta"</string>
 </resources>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 8403bf5dd..5a2ba129c 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -16,11 +16,11 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_label" msgid="2008319089248760277">"Бежична обавештења о хитним случајевима"</string>
-    <string name="sms_cb_settings" msgid="9021266457863671070">"Бежична обавештења о хитним случајевима"</string>
-    <string name="sms_cb_sender_name_default" msgid="972946539768958828">"Бежична упозорења о хитним случајевима"</string>
-    <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Бежична упозорења о хитним случајевима"</string>
-    <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Бежична упозорења о хитним случајевима"</string>
+    <string name="app_label" msgid="2008319089248760277">"Упозорења о хитним случајевима"</string>
+    <string name="sms_cb_settings" msgid="9021266457863671070">"Упозорења о хитним случајевима"</string>
+    <string name="sms_cb_sender_name_default" msgid="972946539768958828">"Упозорења о хитним случајевима"</string>
+    <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Упозорења о хитним случајевима"</string>
+    <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Упозорења о хитним случајевима"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Информативно обавештење"</string>
     <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
     <skip />
@@ -138,7 +138,7 @@
     <string name="notification_multiple_title" msgid="1523638925739947855">"Нова упозорења"</string>
     <string name="show_cmas_opt_out_summary" msgid="6926059266585295440">"Прикажи дијалог за онемогућавање после приказа првог упозорења (осим председничког упозорења)."</string>
     <string name="show_cmas_opt_out_title" msgid="9182104842820171132">"Прикажи дијалог за онемогућавање"</string>
-    <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"Тренутно примате бежична обавештењења о хитним случајевима. Желите ли да наставите да их примате?"</string>
+    <string name="cmas_opt_out_dialog_text" msgid="4820577535626084938">"Тренутно примате обавештењења о хитним случајевима преко мобилне мреже. Желите ли да наставите да их примате?"</string>
     <string name="cmas_opt_out_button_yes" msgid="7248930667195432936">"Да"</string>
     <string name="cmas_opt_out_button_no" msgid="3110484064328538553">"He"</string>
     <string name="cb_list_activity_title" msgid="1433502151877791724">"Историја обавештења о хитним случајевима"</string>
@@ -151,7 +151,7 @@
     <item msgid="3863339891188103437">"Сваких 15 минута"</item>
     <item msgid="7388573183644474611">"Никад"</item>
   </string-array>
-    <string name="emergency_alert_settings_title_watches" msgid="4477073412799894883">"Бежична обавештења о хитним случајевима"</string>
+    <string name="emergency_alert_settings_title_watches" msgid="4477073412799894883">"Упозорења о хитним случајевима"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="7293800023375154256">"Обавештења председника"</string>
     <string name="enable_cmas_presidential_alerts_summary" msgid="7900094335808247024">"Упозорења која издаје председник на нивоу земље. Не могу да се искључе."</string>
     <string name="receive_cmas_in_second_language_title" msgid="1223260365527361964"></string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 588496e26..e2f411d33 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -89,7 +89,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"அவசரகால விழிப்பூட்டல்கள்"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"உயிருக்கு ஆபத்தை விளைவிக்கும் நிகழ்வுகள் பற்றி எச்சரிக்கவும்"</string>
     <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"பரிசோதனை எச்சரிக்கைகள்"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"பாதுகாப்பு விழிப்பூட்டல் அமைப்பிலிருந்து மொபைல் நிறுவன சோதனைகளையும் மாதாந்திர சோதனைகளையும் பெறுவீர்கள்"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"மொபைல் நிறுவன சோதனைகளையும் பாதுகாப்பு விழிப்பூட்டல் அமைப்பிலிருந்து மாதாந்திர சோதனைகளையும் பெறுவீர்கள்"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
     <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"அவசரகால எச்சரிக்கையைப் பெறுக: பயிற்சி/டிரில் மெசேஜ்"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 628a2414a..0aa317192 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -172,7 +172,7 @@
     <string name="seconds" msgid="141450721520515025">"秒"</string>
     <string name="message_copied" msgid="6922953753733166675">"已复制消息"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
-    <string name="top_intro_roaming_text" msgid="5250650823028195358">"如果您正在漫游或没有使用中的 SIM 卡，可能会收到这些设置中不包含的一些提醒"</string>
+    <string name="top_intro_roaming_text" msgid="5250650823028195358">"漫游或 SIM 卡处于未启用状态时，您可能会收到不属于以下设置的提醒"</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"您的设置更改了"</string>
     <string name="notification_cb_settings_changed_text" msgid="8722470940705858715">"无线紧急警报设置已重置，因为您的 SIM 卡更换了"</string>
 </resources>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 89eb76caf..e02a49c6a 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -89,7 +89,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"緊急警報"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"針對威脅生命安全的事件發出警告"</string>
     <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"測試警報"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"接收電信業者測試用訊息和安全性警示系統發出的每月測試訊息"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"接收電信業者測試用訊息，和安全性警示系統的每月測試訊息"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
     <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"接收緊急警報：演習/模擬訊息"</string>
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertDialog.java b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertDialog.java
index e2076d161..d3aeb2fa8 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertDialog.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertDialog.java
@@ -663,7 +663,7 @@ public class CellBroadcastAlertDialog extends Activity {
         if (!(isChangingConfigurations() || latestMessage == null) && pm.isScreenOn()) {
             Log.d(TAG, "call addToNotificationBar when activity goes in background");
             CellBroadcastAlertService.addToNotificationBar(latestMessage, messageList,
-                    getApplicationContext(), true, true, false);
+                    getApplicationContext(), true, true, false, null);
         }
         super.onUserLeaveHint();
     }
@@ -1283,7 +1283,8 @@ public class CellBroadcastAlertDialog extends Activity {
             // do not alert if remove unread messages from the notification bar.
            CellBroadcastAlertService.addToNotificationBar(
                    CellBroadcastReceiverApp.getLatestMessage(),
-                   unreadMessageList, context,false, false, false);
+                   unreadMessageList, context, false, false, false,
+                   null);
         }
     }
 
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java
index fa754b569..c5217b981 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java
@@ -150,6 +150,9 @@ public class CellBroadcastAlertService extends Service {
     /** Intent extra for passing a SmsCbMessage */
     private static final String EXTRA_MESSAGE = "message";
 
+    /** Intent extra for passing a PendingIntentElement for testing */
+    private static final String EXTRA_PENDING_INTENT_ELEMENT = "pending_intent_element";
+
     /**
      * Key for accessing message filter from SystemProperties. For testing use.
      */
@@ -190,7 +193,6 @@ public class CellBroadcastAlertService extends Service {
      */
     private static boolean sRemindAfterCallFinish = false;
 
-
     @Override
     public int onStartCommand(Intent intent, int flags, int startId) {
         mContext = getApplicationContext();
@@ -255,7 +257,13 @@ public class CellBroadcastAlertService extends Service {
         TelephonyManager tm = ((TelephonyManager) mContext.getSystemService(
                 Context.TELEPHONY_SERVICE)).createForSubscriptionId(message.getSubscriptionId());
 
-        if (tm.getEmergencyCallbackMode() && CellBroadcastSettings.getResourcesByOperator(
+        boolean isEmergencyCallbackMode = false;
+        try {
+            isEmergencyCallbackMode = tm.getEmergencyCallbackMode();
+        } catch (UnsupportedOperationException e) {
+            Log.d(TAG, "telephony calling feature is not available");
+        }
+        if (isEmergencyCallbackMode && CellBroadcastSettings.getResourcesByOperator(
                 mContext, message.getSubscriptionId(),
                         CellBroadcastReceiver.getRoamingOperatorSupported(mContext))
                 .getBoolean(R.bool.ignore_messages_in_ecbm)) {
@@ -468,6 +476,7 @@ public class CellBroadcastAlertService extends Service {
         }
 
         SmsCbMessage cbm = intent.getParcelableExtra(EXTRA_MESSAGE);
+        Bundle injectedPendingIntent = intent.getBundleExtra(EXTRA_PENDING_INTENT_ELEMENT);
 
         if (cbm == null) {
             Log.e(TAG, "received SHOW_NEW_ALERT_ACTION with no message extra");
@@ -505,18 +514,24 @@ public class CellBroadcastAlertService extends Service {
                             && isConnectedToCompanionDevices())
                     // show dialog and notification for specific channel
                     || (range != null && range.mDisplayDialogWithNotification)) {
+
                 // add notification to the bar by passing the list of unread non-emergency
                 // cell broadcast messages. The notification should be of LOW_IMPORTANCE if the
                 // notification is shown together with full-screen dialog.
-                addToNotificationBar(cbm, CellBroadcastReceiverApp.addNewMessageToList(cbm),
-                        this, false, true, shouldDisplayFullScreenMessage(cbm));
+                // The notification is already handled for watch
+                if (!getPackageManager().hasSystemFeature(PackageManager.FEATURE_WATCH)) {
+                    addToNotificationBar(cbm, CellBroadcastReceiverApp.addNewMessageToList(cbm),
+                            this, false, true,
+                            shouldDisplayFullScreenMessage(cbm), injectedPendingIntent);
+                }
             }
         } else {
             // add notification to the bar by passing the list of unread non-emergency
             // cell broadcast messages
             ArrayList<SmsCbMessage> messageList = CellBroadcastReceiverApp
                     .addNewMessageToList(cbm);
-            addToNotificationBar(cbm, messageList, this, false, true, false);
+            addToNotificationBar(cbm, messageList, this, false, true,
+                    false, injectedPendingIntent);
         }
         CellBroadcastReceiverMetrics.getInstance().logFeatureChangedAsNeeded(mContext);
     }
@@ -783,7 +798,7 @@ public class CellBroadcastAlertService extends Service {
         // For FEATURE_WATCH, the dialog doesn't make sense from a UI/UX perspective.
         // But the audio & vibration still breakthrough DND.
         if (isWatch) {
-            addToNotificationBar(message, messageList, this, false, true, false);
+            addToNotificationBar(message, messageList, this, false, true, false, null);
         } else {
             Intent alertDialogIntent = createDisplayMessageIntent(this,
                     CellBroadcastAlertDialog.class, messageList);
@@ -821,7 +836,8 @@ public class CellBroadcastAlertService extends Service {
      */
     static void addToNotificationBar(SmsCbMessage message,
             ArrayList<SmsCbMessage> messageList, Context context,
-            boolean fromSaveState, boolean shouldAlert, boolean fromDialog) {
+            boolean fromSaveState, boolean shouldAlert, boolean fromDialog,
+            Bundle injectedPendingIntent) {
 
         Resources res = CellBroadcastSettings.getResourcesByOperator(context,
                 message.getSubscriptionId(),
@@ -865,9 +881,13 @@ public class CellBroadcastAlertService extends Service {
                 options.setPendingIntentCreatorBackgroundActivityStartMode(
                         ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED);
             }
+            int flags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;
+            if (injectedPendingIntent != null) {
+                injectedPendingIntent.putInt("flag", flags);
+                injectedPendingIntent.putBundle("option", options.toBundle());
+            }
             pi = PendingIntent.getActivity(context, REQUEST_CODE_CONTENT_INTENT, intent,
-                            PendingIntent.FLAG_UPDATE_CURRENT
-                            | PendingIntent.FLAG_IMMUTABLE, options.toBundle());
+                    flags, options.toBundle());
         }
         CellBroadcastChannelManager channelManager = new CellBroadcastChannelManager(
                 context, message.getSubscriptionId());
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastConfigService.java b/src/com/android/cellbroadcastreceiver/CellBroadcastConfigService.java
index b64ff88f1..ea8a9644a 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastConfigService.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastConfigService.java
@@ -31,6 +31,7 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.SharedPreferences;
 import android.content.res.Resources;
+import android.os.Bundle;
 import android.telephony.CellBroadcastIdRange;
 import android.telephony.SmsManager;
 import android.telephony.SubscriptionInfo;
@@ -74,6 +75,7 @@ public class CellBroadcastConfigService extends IntentService {
     public static final String ACTION_RESET_SETTINGS_AS_NEEDED = "RESET_SETTINGS_AS_NEEDED";
 
     public static final String EXTRA_SUB = "SUB";
+    private static final String EXTRA_PENDING_INTENT_ELEMENT = "pending_intent_element";
 
     private static final String ACTION_SET_CHANNELS_DONE =
             "android.cellbroadcast.compliancetest.SET_CHANNELS_DONE";
@@ -151,6 +153,10 @@ public class CellBroadcastConfigService extends IntentService {
                     options.setPendingIntentCreatorBackgroundActivityStartMode(
                             ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED);
                 }
+                Bundle injectedPendingIntent = intent.getBundleExtra(EXTRA_PENDING_INTENT_ELEMENT);
+                if (injectedPendingIntent != null) {
+                    injectedPendingIntent.putBundle("option", options.toBundle());
+                }
                 PendingIntent pi = PendingIntent.getActivity(c,
                         CellBroadcastAlertService.SETTINGS_CHANGED_NOTIFICATION_ID, settingsIntent,
                         PendingIntent.FLAG_ONE_SHOT
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java b/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java
index 7169117c1..9f840b00d 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java
@@ -256,7 +256,12 @@ public class CellBroadcastReceiver extends BroadcastReceiver {
 
             // check the mcc on emergency only mode
             if (TextUtils.isEmpty(networkOperator)) {
-                String countryCode = tm.getNetworkCountryIso();
+                String countryCode = null;
+                try {
+                    countryCode = tm.getNetworkCountryIso();
+                } catch (IllegalArgumentException e) {
+                    loge("IllegalArgumentException while getting network country iso" + e);
+                }
                 if (mMccMap != null && !TextUtils.isEmpty(countryCode)) {
                     networkOperator = mMccMap.get(countryCode.toLowerCase(Locale.ROOT).trim());
                     logd("networkOperator on emergency mode: " + networkOperator
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java b/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java
index 116f9a8f1..ef4f55018 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java
@@ -458,7 +458,16 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
                                 notifyAreaInfoUpdate(isEnabledAlert);
                             }
 
-                            onPreferenceChangedByUser(getContext());
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
                             return true;
                         }
                     };
@@ -474,12 +483,13 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
                             (MainSwitchPreference) mMasterToggle;
                     final OnCheckedChangeListener mainSwitchListener =
                             new OnCheckedChangeListener() {
-                        @Override
-                        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
-                            setAlertsEnabled(isChecked);
-                            onPreferenceChangedByUser(getContext());
-                        }
-                    };
+                                @Override
+                                public void onCheckedChanged(CompoundButton buttonView,
+                                        boolean isChecked) {
+                                    setAlertsEnabled(isChecked);
+                                    onPreferenceChangedByUser(getContext(), true);
+                                }
+                            };
                     mainSwitchPreference.addOnSwitchChangeListener(mainSwitchListener);
                 } else {
                     Preference.OnPreferenceChangeListener mainSwitchListener =
@@ -488,7 +498,7 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
                                 public boolean onPreferenceChange(
                                         Preference pref, Object newValue) {
                                     setAlertsEnabled((Boolean) newValue);
-                                    onPreferenceChangedByUser(getContext());
+                                    onPreferenceChangedByUser(getContext(), true);
                                     return true;
                                 }
                             };
@@ -571,6 +581,10 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
                         });
             }
 
+            if (mSpeechCheckBox != null) {
+                mSpeechCheckBox.setOnPreferenceChangeListener(alertPreferenceToggleListener);
+            }
+
             updateVibrationPreference(sp.getBoolean(CellBroadcastSettings.KEY_OVERRIDE_DND,
                     false));
             updatePreferenceVisibility();
@@ -902,11 +916,13 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
          *
          * @param context Context to use
          */
-        public void onPreferenceChangedByUser(Context context) {
-            CellBroadcastReceiver.startConfigService(context,
-                    CellBroadcastConfigService.ACTION_ENABLE_CHANNELS);
+        public void onPreferenceChangedByUser(Context context, boolean enableChannels) {
+            if (enableChannels) {
+                Log.d(TAG, "onPreferenceChangedByUser: enable channels");
+                CellBroadcastReceiver.startConfigService(context,
+                        CellBroadcastConfigService.ACTION_ENABLE_CHANNELS);
+            }
             setPreferenceChanged(context, true);
-
             // Notify backup manager a backup pass is needed.
             new BackupManager(context).dataChanged();
         }
diff --git a/tests/compliancetests/assets/emergency_alert_channels.json b/tests/compliancetests/assets/emergency_alert_channels.json
index ed2de49e4..7dabd7065 100644
--- a/tests/compliancetests/assets/emergency_alert_channels.json
+++ b/tests/compliancetests/assets/emergency_alert_channels.json
@@ -1655,44 +1655,44 @@
       "toggle_avail": "false"
     },
     "4370": {
-      "title": "Presidential Alert",
+      "title": "國家級警報",  //Presidential Alert
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4383": {
-      "title": "Presidential Alert",
+      "title": "國家級警報",  //Presidential Alert
       "default_value": "true",
       "toggle_avail": "false"
     },
     "911": {
-      "title": "Alert Message",
+      "title": "警訊通知",  //Alert Message
       "default_value": "true",
       "toggle_avail": "true"
     },
     "919": {
-      "title": "Alert Message",
+      "title": "警訊通知",  //Alert Message
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4371": {
-      "title": "Emergency Alert",
+      "title": "緊急警報",  //Emergency Alert
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "4379"
     },
     "4384": {
-      "title": "Emergency Alert",
+      "title": "緊急警報",  //Emergency Alert
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "4392"
     },
     "4380": {
-      "title": "Required Monthly Test",
+      "title": "每月測試用訊息",  //Required Monthly Test
       "default_value": "false",
       "toggle_avail": "true"
     },
     "4393": {
-      "title": "Required Monthly Test",
+      "title": "每月測試用訊息",  //Required Monthly Test
       "default_value": "false",
       "toggle_avail": "true"
     }
@@ -4422,59 +4422,64 @@
   },
   "austria_tmobile": {
     "4370": {
-      "title": "Emergency alert", //Notfallalarm
+      "title": "Notfallalarm", //Emergency alert
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4383": {
-      "title": "Emergency alert", //Notfallalarm
+      "title": "Notfallalarm", //Emergency alert
       "default_value": "true",
-      "toggle_avail": "false"
+      "toggle_avail": "false",
+      "filter_language": "language_setting"
     },
     "919": {
-      "title": "Emergency alert", //Notfallalarm
+      "title": "Notfallalarm", //Emergency alert
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4372": {
-      "title": "Extreme threat", //Extreme Gefahr
+      "title": "Extreme Gefahr", //Extreme threat
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4385": {
-      "title": "Extreme threat", //Extreme Gefahr
+      "title": "Extreme Gefahr", //Extreme threat
       "default_value": "true",
-      "toggle_avail": "true"
+      "toggle_avail": "true",
+      "filter_language": "language_setting"
     },
     "4378": {
-      "title": "Severe threat", //Erhebliche Gefahr
+      "title": "Erhebliche Gefahr", //Severe threat
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4391": {
-      "title": "Severe threat", //Erhebliche Gefahr
+      "title": "Erhebliche Gefahr", //Severe threat
       "default_value": "true",
-      "toggle_avail": "true"
+      "toggle_avail": "true",
+      "filter_language": "language_setting"
     },
     "4396": {
-      "title": "Threat information", // Gefahreninformation
+      "title": "Gefahreninformation", //Threat information
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4397": {
-      "title": "Threat information", //Gefahreninformation
+      "title": "Gefahreninformation", //Threat information
       "default_value": "true",
-      "toggle_avail": "true"
+      "toggle_avail": "true",
+      "filter_language": "language_setting"
     },
     "4379": {
-      "title": "Search for missing person", //Suche nach abgängiger Person
+      "title": "Suche nach abgängiger Person", //Search for missing person
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4392": {
-      "title": "Search for missing person", //Suche nach abgängiger Person
+      "title": "Suche nach abgängiger Person", //Search for missing person
       "default_value": "true",
-      "toggle_avail": "true"
+      "toggle_avail": "true",
+      "filter_language": "language_setting"
     },
     "4380": {
       "title": "Cell Broadcast Test", //Cell Broadcast Test
@@ -4484,17 +4489,19 @@
     "4393": {
       "title": "Cell Broadcast Test", //Cell Broadcast Test
       "default_value": "false",
-      "toggle_avail": "false"
+      "toggle_avail": "false",
+      "filter_language": "language_setting"
     },
     "4381": {
-      "title": "Test alarm", //Übungsalarm
+      "title": "Übungsalarm", //Test alarm
       "default_value": "false",
       "toggle_avail": "false"
     },
     "4394": {
-      "title": "Test alarm", //Übungsalarm
+      "title": "Übungsalarm", //Test alarm
       "default_value": "false",
-      "toggle_avail": "false"
+      "toggle_avail": "false",
+      "filter_language": "language_setting"
     }
   },
   "macedonia_telekom": {
@@ -4842,12 +4849,12 @@
       "toggle_avail": "false"
     },
     "4379": {
-      "title": "LU-Alert : Kidnapping alert", // LU-Alert : Entführungswarnung
+      "title": "LU-Alert : Missing person / kidnapping alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4392": {
-      "title": "LU-Alert : Kidnapping alert", // LU-Alert : Entführungswarnung
+      "title": "LU-Alert : Missing person / kidnapping alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
diff --git a/tests/compliancetests/assets/emergency_alert_settings.json b/tests/compliancetests/assets/emergency_alert_settings.json
index 6c85f06a9..a9e92374d 100644
--- a/tests/compliancetests/assets/emergency_alert_settings.json
+++ b/tests/compliancetests/assets/emergency_alert_settings.json
@@ -703,19 +703,19 @@
     }
   },
   "taiwan": {
-    "Emergency alerts": {
+    "緊急警報": {  //Emergency alerts
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Alert messages": {
+    "警訊通知": {  //Alert messages
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Required monthly test": {
+    "每月測試用訊息": {  //Required monthly test
       "default_value": "false",
       "toggle_avail": "true"
     },
-    "Vibration": {
+    "震動": {  //Vibration
       "default_value": "true",
       "toggle_avail": "true"
     }
@@ -1235,23 +1235,23 @@
     }
   },
   "austria_tmobile": {
-    "Extreme threat": {  // Extreme Gefahr
+    "Extreme Gefahr": {  // Extreme threat
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Severe threat": {  // Erhebliche Gefahr
+    "Erhebliche Gefahr": {  //Severe threat
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Missing persons": {  // Abgängige Personen
+    "Abgängige Personen": {  //Missing persons
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Threat information": { // Gefahreninformation
+    "Gefahreninformation": { //Threat information
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Test alert": {  // Testwarnung
+    "Testwarnung": {  //Test alert
       "default_value": "false",
       "toggle_avail": "true"
     },
@@ -1351,7 +1351,7 @@
     }
   },
   "Luxembourg": {
-    "Kidnapping alert": {  // Entführungswarnung
+    "Missing person / kidnapping alert": {  // Vermissten- / Entführungsmeldung
       "default_value": "true",
       "toggle_avail": "true"
     },
diff --git a/tests/compliancetests/assets/region_plmn_list.json b/tests/compliancetests/assets/region_plmn_list.json
index 79c500439..f57b85450 100644
--- a/tests/compliancetests/assets/region_plmn_list.json
+++ b/tests/compliancetests/assets/region_plmn_list.json
@@ -124,7 +124,8 @@
   },
   "taiwan": {
     "mccmnc": ["46601"],
-    "imsi": "466010123456789"
+    "imsi": "466010123456789",
+    "language": "zh-rTW"
   },
   "brazil": {
     "mccmnc": ["72406"],
@@ -315,7 +316,8 @@
   },
   "austria_tmobile": {
     "mccmnc": ["23207"],
-    "imsi": "232070123456789"
+    "imsi": "232070123456789",
+    "language": "de"
   },
   "macedonia_telekom": {
     "mccmnc": ["29401"],
diff --git a/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java b/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java
index a364dec54..0ad5437ca 100644
--- a/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java
+++ b/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java
@@ -26,6 +26,7 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
 import android.content.pm.PackageManager;
+import android.hardware.radio.network.Domain;
 import android.os.Build;
 import android.os.Handler;
 import android.os.HandlerThread;
@@ -74,7 +75,8 @@ public class CellBroadcastBaseTest {
     protected static int sPreconditionError = 0;
     protected static final int ERROR_SDK_VERSION = 1;
     protected static final int ERROR_NO_TELEPHONY = 2;
-    protected static final int ERROR_MOCK_MODEM_DISABLE = 3;
+    protected static final int ERROR_MULTI_SIM = 3;
+    protected static final int ERROR_MOCK_MODEM_DISABLE = 4;
 
     protected static final String ALLOW_MOCK_MODEM_PROPERTY = "persist.radio.allow_mock_modem";
     protected static final boolean DEBUG = !"user".equals(Build.TYPE);
@@ -99,21 +101,29 @@ public class CellBroadcastBaseTest {
     protected static IRadioMessagingImpl.CallBackWithExecutor sCallBackWithExecutor = null;
     private static ServiceStateListener sServiceStateCallback;
     private static int sServiceState = ServiceState.STATE_OUT_OF_SERVICE;
+    private static int sDataServiceState = ServiceState.STATE_OUT_OF_SERVICE;
     private static final Object OBJECT = new Object();
     private static final int SERVICE_STATE_MAX_WAIT = 20 * 1000;
-    protected static CountDownLatch sServiceStateLatch =  new CountDownLatch(1);
+    protected static CountDownLatch sServiceStateLatch = new CountDownLatch(1);
+    protected static CountDownLatch sDataServiceStateLatch = new CountDownLatch(1);
 
     private static class ServiceStateListener extends TelephonyCallback
             implements TelephonyCallback.ServiceStateListener {
         @Override
         public void onServiceStateChanged(ServiceState serviceState) {
             Log.d(TAG, "Callback: service state = " + serviceState.getVoiceRegState());
+            Log.d(TAG, "Callback: service data state = " + serviceState.getDataRegState());
             synchronized (OBJECT) {
                 sServiceState = serviceState.getVoiceRegState();
+                sDataServiceState = serviceState.getDataRegState();
                 if (sServiceState == ServiceState.STATE_IN_SERVICE) {
                     sServiceStateLatch.countDown();
                     logd("countdown sServiceStateLatch");
                 }
+                if (sDataServiceState == ServiceState.STATE_OUT_OF_SERVICE) {
+                    sDataServiceStateLatch.countDown();
+                    logd("countdown sDataServiceStateLatch");
+                }
             }
         }
     }
@@ -158,6 +168,15 @@ public class CellBroadcastBaseTest {
             return;
         }
 
+        TelephonyManager tm =
+                (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
+        boolean isMultiSim = tm != null && tm.getPhoneCount() > 1;
+        if (!SdkLevel.isAtLeastU() && isMultiSim) {
+            Log.i(TAG, "Not support Multi-Sim");
+            sPreconditionError = ERROR_MULTI_SIM;
+            return;
+        }
+
         if (!isMockModemAllowed()) {
             Log.i(TAG, "Mock Modem is not allowed");
             sPreconditionError = ERROR_MOCK_MODEM_DISABLE;
@@ -356,6 +375,9 @@ public class CellBroadcastBaseTest {
             case ERROR_NO_TELEPHONY:
                 errorMessage = "Not have Telephony Feature";
                 break;
+            case ERROR_MULTI_SIM:
+                errorMessage = "Multi-sim is not supported in Mock Modem";
+                break;
             case ERROR_MOCK_MODEM_DISABLE:
                 errorMessage = "Please enable mock modem to run the test! The option can be "
                         + "updated in Settings -> System -> Developer options -> Allow Mock Modem";
@@ -377,10 +399,12 @@ public class CellBroadcastBaseTest {
                 new Handler(serviceStateChangeCallbackHandlerThread.getLooper());
         TelephonyManager telephonyManager =
                 (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
-        sSetChannelIsDone = new CountDownLatch(1);
+        sServiceStateLatch = new CountDownLatch(1);
+        sDataServiceStateLatch = new CountDownLatch(1);
         // Register service state change callback
         synchronized (OBJECT) {
             sServiceState = ServiceState.STATE_OUT_OF_SERVICE;
+            sDataServiceState = ServiceState.STATE_OUT_OF_SERVICE;
         }
 
         serviceStateChangeCallbackHandler.post(
@@ -392,10 +416,17 @@ public class CellBroadcastBaseTest {
                                     Runnable::run, sServiceStateCallback));
                 });
 
+        logd("Disable Data Service");
+        sMockModemManager.changeNetworkService(sSlotId, MockSimService.MOCK_SIM_PROFILE_ID_TWN_CHT,
+                false, Domain.PS);
+
+        logd("Wait for data service state change to out of service");
+        waitForNotifyForDataServiceState();
+
         // Enter Service
-        logd("Enter Service");
+        logd("Enter Voice Service");
         sMockModemManager.changeNetworkService(sSlotId, MockSimService.MOCK_SIM_PROFILE_ID_TWN_CHT,
-                true);
+                true, Domain.CS);
 
         // Expect: Home State
         logd("Wait for service state change to in service");
@@ -414,6 +445,14 @@ public class CellBroadcastBaseTest {
         }
     }
 
+    private static void waitForNotifyForDataServiceState() {
+        try {
+            sDataServiceStateLatch.await(SERVICE_STATE_MAX_WAIT, TimeUnit.MILLISECONDS);
+        } catch (InterruptedException e) {
+            // do nothing
+        }
+    }
+
     private static int sSubIdForDummySub;
     private static String sIccIdForDummySub;
     private static int sSubTypeForDummySub;
diff --git a/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastUiTest.java b/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastUiTest.java
index b76fd792b..86377ae4f 100644
--- a/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastUiTest.java
+++ b/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastUiTest.java
@@ -33,6 +33,7 @@ import android.provider.Settings;
 import android.provider.Telephony;
 import android.support.test.uiautomator.By;
 import android.support.test.uiautomator.BySelector;
+import android.support.test.uiautomator.StaleObjectException;
 import android.support.test.uiautomator.UiObject;
 import android.support.test.uiautomator.UiObject2;
 import android.support.test.uiautomator.UiObjectNotFoundException;
@@ -54,6 +55,9 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 
 import java.util.Iterator;
+import java.util.Locale;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
 
 @RunWith(JUnitParamsRunner.class)
 public class CellBroadcastUiTest extends CellBroadcastBaseTest {
@@ -67,6 +71,7 @@ public class CellBroadcastUiTest extends CellBroadcastBaseTest {
     private static final int MESSAGE_ID_ETWS_TYPE_MASK = 0xFFF8;
     /** Value for messages of ETWS type after applying {@link #MESSAGE_ID_ETWS_TYPE_MASK}. */
     private static final int MESSAGE_ID_ETWS_TYPE = 0x1100; // 4352
+    private static final int TWO_BYTE_LANGUAGE_CODE = 2;
     private static final String CELL_BROADCAST_LIST_ACTIVITY =
             "com.android.cellbroadcastreceiver.CellBroadcastSettings";
     private static final BySelector SYSUI_FULL_SCREEN_DIALOG =
@@ -106,18 +111,26 @@ public class CellBroadcastUiTest extends CellBroadcastBaseTest {
         }
         if ("testEmergencyAlertSettingsUi".equals(mTestNameRule.getMethodName())
                 || "testAlertUiOnReceivedAlert".equals(mTestNameRule.getMethodName())) {
-            // close disturbing dialog if exist
-            UiObject2 yesButton = sDevice.wait(Until.findObject(YES_BUTTON), 100);
-            if (yesButton != null) {
-                logd("dismiss disturbing dialog");
-                yesButton.click();
+            try {
+                // close disturbing dialog if exist
+                UiObject2 yesButton = sDevice.wait(Until.findObject(YES_BUTTON), 100);
+                if (yesButton != null) {
+                    logd("dismiss disturbing dialog");
+                    yesButton.click();
+                }
+            } catch (StaleObjectException ex) {
+                logd("caught StaleObjectException");
             }
-            // if left alertdialog exist, close it
-            UiObject2 okItem = sDevice.wait(Until.findObject(
-                    By.res(sPackageName, "dismissButton")), 100);
-            if (okItem != null) {
-                logd("dismiss left alertdialog");
-                okItem.click();
+            try {
+                // if left alertdialog exist, close it
+                UiObject2 okItem = sDevice.wait(Until.findObject(
+                        By.res(sPackageName, "dismissButton")), 100);
+                if (okItem != null) {
+                    logd("dismiss left alertdialog");
+                    okItem.click();
+                }
+            } catch (StaleObjectException ex) {
+                logd("caught StaleObjectException");
             }
             sDevice.pressHome();
         }
@@ -417,13 +430,42 @@ public class CellBroadcastUiTest extends CellBroadcastBaseTest {
         return isConfirmed;
     }
 
+    private String[] extractLanguageAndRegionCodes(String languageTag) {
+        if (languageTag == null || languageTag.isEmpty()) {
+            logd("languageTag is null or empty");
+            return null;
+        }
+
+        // Regular expression to match language tags like "zh-rTW", "en-rGB", etc.
+        // Assumes "-r" always exists.
+        Pattern pattern = Pattern.compile("^([a-z]{2})-r([A-Z]{2})$");
+        Matcher matcher = pattern.matcher(languageTag);
+
+        if (matcher.matches()) {
+            String languageCode = matcher.group(1);
+            String regionCode = matcher.group(2);
+            logd("changeLocale: languageCode: " + languageCode + " regionCode: " + regionCode);
+            return new String[]{languageCode, regionCode};
+        } else {
+            logd("Invalid languageTag format");
+            return null; // Invalid language tag format
+        }
+    }
+
     private void changeLocale(CellBroadcastCarrierTestConfig info,
             String packageName, boolean checkAlertUi) {
         LocaleManager localeManager = getContext().getSystemService(LocaleManager.class);
         if (info.mLanguageTag != null && (checkAlertUi || info.mCheckSettingWithMainLanguage)) {
             logd("setApplicationLocales " + info.mLanguageTag);
-            localeManager.setApplicationLocales(packageName,
-                    LocaleList.forLanguageTags(info.mLanguageTag));
+            if (info.mLanguageTag.length() > TWO_BYTE_LANGUAGE_CODE) {
+                String[] languageRegion = extractLanguageAndRegionCodes(info.mLanguageTag);
+                Locale locale = new Locale(languageRegion[0], languageRegion[1]);
+                localeManager.setApplicationLocales(packageName, new LocaleList(locale));
+            } else {
+                logd("setApplicationLocales " + info.mLanguageTag);
+                localeManager.setApplicationLocales(packageName,
+                        LocaleList.forLanguageTags(info.mLanguageTag));
+            }
         } else {
             logd("setApplicationLocales to default");
             localeManager.setApplicationLocales(packageName,
diff --git a/tests/testapp/Android.bp b/tests/testapp/Android.bp
index a5b48c028..d59fe1eb3 100644
--- a/tests/testapp/Android.bp
+++ b/tests/testapp/Android.bp
@@ -29,6 +29,7 @@ android_test {
     static_libs: [
     "junit",
     "modules-utils-build_system",
+    "androidx.core_core",
     ],
     // Include all test java files.
     srcs: [
diff --git a/tests/testapp/src/com/android/cellbroadcastreceiver/tests/SendTestBroadcastActivity.java b/tests/testapp/src/com/android/cellbroadcastreceiver/tests/SendTestBroadcastActivity.java
index ea4697878..436c9de3c 100644
--- a/tests/testapp/src/com/android/cellbroadcastreceiver/tests/SendTestBroadcastActivity.java
+++ b/tests/testapp/src/com/android/cellbroadcastreceiver/tests/SendTestBroadcastActivity.java
@@ -27,6 +27,10 @@ import android.widget.Button;
 import android.widget.CheckBox;
 import android.widget.EditText;
 
+import androidx.core.graphics.Insets;
+import androidx.core.view.ViewCompat;
+import androidx.core.view.WindowInsetsCompat;
+
 import java.util.Random;
 
 /**
@@ -112,6 +116,8 @@ public class SendTestBroadcastActivity extends Activity {
 
         setContentView(R.layout.test_buttons);
 
+        setupEdgeToEdge(this);
+
         /* Set message ID to a random value from 1-65535. */
         EditText messageIdField = (EditText) findViewById(R.id.message_id);
         messageIdField.setText(String.valueOf(new Random().nextInt(65535) + 1));
@@ -699,4 +705,23 @@ public class SendTestBroadcastActivity extends Activity {
                     }
                 });
     }
+
+    /**
+     * Given an activity, configure the activity to adjust for edge to edge restrictions.
+     * @param activity the activity.
+     */
+    public static void setupEdgeToEdge(Activity activity) {
+        ViewCompat.setOnApplyWindowInsetsListener(activity.findViewById(android.R.id.content),
+                (v, windowInsets) -> {
+                    Insets insets = windowInsets.getInsets(
+                            WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.ime());
+
+                    // Apply the insets paddings to the view.
+                    v.setPadding(insets.left, insets.top, insets.right, insets.bottom);
+
+                    // Return CONSUMED if you don't want the window insets to keep being
+                    // passed down to descendant views.
+                    return WindowInsetsCompat.CONSUMED;
+                });
+    }
 }
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertDialogTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertDialogTest.java
index 02043dc64..68627fb99 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertDialogTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertDialogTest.java
@@ -17,50 +17,34 @@
 package com.android.cellbroadcastreceiver.unit;
 
 import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
-import static org.mockito.ArgumentMatchers.nullable;
 import static org.mockito.Mockito.atLeastOnce;
-import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
-import android.app.ActivityManager;
-import android.app.ActivityOptions;
-import android.app.ContentProviderHolder;
-import android.app.IActivityManager;
 import android.app.Notification;
 import android.app.NotificationManager;
-import android.app.PendingIntent;
-import android.content.IContentProvider;
 import android.content.Intent;
 import android.content.SharedPreferences;
-import android.content.pm.ApplicationInfo;
-import android.content.pm.ProviderInfo;
 import android.content.res.Configuration;
 import android.content.res.Resources;
 import android.os.Bundle;
-import android.os.IBinder;
 import android.os.IPowerManager;
 import android.os.IThermalService;
 import android.os.Looper;
 import android.os.Message;
 import android.os.PowerManager;
-import android.os.RemoteException;
 import android.telephony.SmsCbMessage;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
 import android.text.TextUtils;
-import android.util.Singleton;
-import android.view.IWindowManager;
 import android.view.KeyEvent;
 import android.view.View;
 import android.view.ViewGroup;
 import android.view.WindowManager;
-import android.view.WindowManagerGlobal;
 import android.widget.ImageView;
 import android.widget.LinearLayout;
 import android.widget.TextView;
@@ -80,10 +64,7 @@ import org.mockito.ArgumentCaptor;
 import org.mockito.Captor;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
-import org.mockito.invocation.InvocationOnMock;
-import org.mockito.stubbing.Answer;
 
-import java.lang.reflect.Field;
 import java.lang.reflect.Method;
 import java.util.ArrayList;
 
@@ -99,18 +80,9 @@ public class CellBroadcastAlertDialogTest extends
     @Mock
     private IThermalService.Stub mMockedThermalService;
 
-    @Mock
-    private IActivityManager.Stub mMockedActivityManager;
-
-    @Mock
-    IWindowManager.Stub mWindowManagerService;
-
     @Mock
     LinearLayout mMockLinearLayout;
 
-    @Captor
-    private ArgumentCaptor<Integer> mFlags;
-
     @Captor
     private ArgumentCaptor<Integer> mInt;
 
@@ -129,8 +101,6 @@ public class CellBroadcastAlertDialogTest extends
 
     private ArrayList<SmsCbMessage> mMessageList;
 
-    MockedServiceManager mMockedActivityManagerHelper;
-
     @Override
     protected Intent createActivityIntent() {
         mMessageList = new ArrayList<>(1);
@@ -229,8 +199,6 @@ public class CellBroadcastAlertDialogTest extends
     }
 
     public void testAddToNotification() throws Throwable {
-        setUpMockActivityManager();
-
         doReturn(true).when(mContext.getResources()).getBoolean(R.bool.show_alert_title);
         doReturn(false).when(mContext.getResources()).getBoolean(
                 R.bool.disable_capture_alert_dialog);
@@ -251,70 +219,6 @@ public class CellBroadcastAlertDialogTest extends
                 b.getCharSequence(Notification.EXTRA_TITLE).toString()));
         assertEquals(CellBroadcastAlertServiceTest.createMessage(98235).getMessageBody(),
                 b.getCharSequence(Notification.EXTRA_TEXT));
-
-        ArgumentCaptor<Bundle> bundleArgs = ArgumentCaptor.forClass(Bundle.class);
-        verify(mMockedActivityManager, times(2))
-                .getIntentSenderWithFeature(anyInt(), any(), any(), any(), any(), anyInt(),
-                        any(), any(), mFlags.capture(), bundleArgs.capture(), anyInt());
-
-        assertTrue((PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE)
-                ==  mFlags.getAllValues().get(0));
-        assertTrue((PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE)
-                ==  mFlags.getAllValues().get(1));
-
-        if (SdkLevel.isAtLeastU()) {
-            ActivityOptions activityOptions = new ActivityOptions(bundleArgs.getAllValues().get(0));
-            int startMode = activityOptions.getPendingIntentCreatorBackgroundActivityStartMode();
-            assertEquals(ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED, startMode);
-            activityOptions = new ActivityOptions(bundleArgs.getAllValues().get(1));
-            startMode = activityOptions.getPendingIntentCreatorBackgroundActivityStartMode();
-            assertEquals(ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED, startMode);
-        }
-
-        Field field = ((Class) WindowManagerGlobal.class).getDeclaredField("sWindowManagerService");
-        field.setAccessible(true);
-        field.set(null, null);
-
-        mMockedActivityManagerHelper.restoreAllServices();
-    }
-
-    private void setUpMockActivityManager() throws Exception {
-        ProviderInfo providerInfo = new ProviderInfo();
-        providerInfo.authority = "test";
-        providerInfo.applicationInfo = new ApplicationInfo();
-        providerInfo.applicationInfo.uid = 999;
-        ContentProviderHolder holder = new ContentProviderHolder(providerInfo);
-        doReturn(holder).when(mMockedActivityManager)
-                .getContentProvider(any(), any(), any(), anyInt(), anyBoolean());
-        holder.provider = mock(IContentProvider.class);
-
-        Singleton<IActivityManager> activityManagerSingleton = new Singleton<IActivityManager>() {
-            @Override
-            protected IActivityManager create() {
-                return mMockedActivityManager;
-            }
-        };
-        mMockedActivityManagerHelper = new MockedServiceManager();
-        mMockedActivityManagerHelper.replaceService("window", mWindowManagerService);
-        Field fieldHandler = ActivityManager.class.getDeclaredField("IActivityManagerSingleton");
-        fieldHandler.setAccessible(true);
-        Singleton<IActivityManager> activityManager =
-                (Singleton<IActivityManager>) fieldHandler.get(null);
-        IActivityManager realInstance = activityManager.get();
-        doAnswer(new Answer() {
-            public Void answer(InvocationOnMock invocation) throws RemoteException {
-                if (realInstance != null) {
-                    realInstance.finishReceiver(invocation.getArgument(0),
-                            invocation.getArgument(1), invocation.getArgument(2),
-                            invocation.getArgument(3), invocation.getArgument(4),
-                            invocation.getArgument(5));
-                }
-                return null;
-            }
-        }).when(mMockedActivityManager).finishReceiver(nullable(IBinder.class), anyInt(),
-                nullable(String.class), nullable(Bundle.class), anyBoolean(), anyInt());
-        mMockedActivityManagerHelper.replaceInstance(ActivityManager.class,
-                "IActivityManagerSingleton", null, activityManagerSingleton);
     }
 
     public void testAddToNotificationWithDifferentConfiguration() throws Throwable {
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertServiceTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertServiceTest.java
index 54dfe35bd..58e3f3690 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertServiceTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertServiceTest.java
@@ -29,16 +29,19 @@ import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.doThrow;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
+import android.app.ActivityOptions;
 import android.app.IActivityManager;
 import android.app.Notification;
 import android.app.NotificationChannel;
 import android.app.NotificationManager;
+import android.app.PendingIntent;
 import android.app.Service;
 import android.content.Context;
 import android.content.Intent;
@@ -46,6 +49,7 @@ import android.content.SharedPreferences;
 import android.content.pm.PackageManager;
 import android.content.pm.ServiceInfo;
 import android.content.res.Resources;
+import android.os.Bundle;
 import android.os.Handler;
 import android.os.IPowerManager;
 import android.os.Looper;
@@ -687,6 +691,48 @@ public class CellBroadcastAlertServiceTest extends
         ((TestContextWrapper) mContext).injectCreateConfigurationContext(null);
     }
 
+    public void testShouldDisplayMessageInEcbmMode() {
+        putResources(com.android.cellbroadcastreceiver.R.bool.ignore_messages_in_ecbm, true);
+        doReturn(false).when(mMockedTelephonyManager).getEmergencyCallbackMode();
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
+                .test_exercise_alerts_enabled_default, true);
+        enablePreference(CellBroadcastSettings.KEY_ENABLE_EXERCISE_ALERTS);
+        putResources(com.android.cellbroadcastreceiver.R.bool.show_exercise_settings, true);
+        assertTrue("Should enable exercise test channel",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        doReturn(true).when(mMockedTelephonyManager).getEmergencyCallbackMode();
+        assertFalse("Should ignore exercise test channel in ecbm mode",
+                cellBroadcastAlertService.shouldDisplayMessage(message));
+
+        doThrow(new UnsupportedOperationException("test")).when(mMockedTelephonyManager)
+                .getEmergencyCallbackMode();
+        try {
+            assertTrue("Should enable exercise test channel",
+                    cellBroadcastAlertService.shouldDisplayMessage(message));
+        } catch (Exception UnsupportedOperationException) {
+            throw new AssertionError("not expected exception",
+                    UnsupportedOperationException);
+        }
+    }
+
     public void testShouldDisplayMessageForExerciseAlerts() {
         putResources(com.android.cellbroadcastreceiver.R.array
                 .exercise_alert_range_strings, new String[]{
@@ -1162,6 +1208,38 @@ public class CellBroadcastAlertServiceTest extends
                 mServiceIntentToVerify.getSerializableExtra(ALERT_AUDIO_TONE_TYPE));
     }
 
+    public void testNotificationPendingIntentFlag() {
+        if (!SdkLevel.isAtLeastS()) {
+            return;
+        }
+        doReturn(new String[]{"0x1113:rat=gsm, emergency=false"}).when(mResources).getStringArray(
+                eq(com.android.cellbroadcastreceiver.R.array
+                        .cmas_alert_extreme_channels_range_strings));
+
+        Intent intent = new Intent(mContext, CellBroadcastAlertService.class);
+        intent.setAction(SHOW_NEW_ALERT_ACTION);
+
+        SmsCbMessage message = createMessageForCmasMessageClass(13788634,
+                0x1113, 0x1113);
+        intent.putExtra("message", message);
+        Bundle testBundle = new Bundle();
+        intent.putExtra("pending_intent_element", testBundle);
+        startService(intent);
+        waitForServiceIntent();
+
+        verify(mMockedNotificationManager, times(1))
+                .notify(anyInt(), any());
+
+        assertEquals(PendingIntent.FLAG_UPDATE_CURRENT
+                | PendingIntent.FLAG_IMMUTABLE, testBundle.getInt("flag"));
+        if (SdkLevel.isAtLeastU()) {
+            ActivityOptions activityOptions =
+                    new ActivityOptions(testBundle.getBundle("option"));
+            int startMode = activityOptions.getPendingIntentCreatorBackgroundActivityStartMode();
+            assertEquals(ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED, startMode);
+        }
+    }
+
     private static Map<String, NotificationChannel> mapNotificationChannelCaptor(
             ArgumentCaptor<NotificationChannel> captor) {
         Map<String, NotificationChannel> m = new HashMap<>();
@@ -1182,6 +1260,8 @@ public class CellBroadcastAlertServiceTest extends
         IPowerManager mockedPowerService = mock(IPowerManager.class);
         mMockedPowerManager = new PowerManager(mContext, mockedPowerService, null, handler);
         doReturn("alert dialog title").when(mResources).getText(anyInt());
+        doReturn(true).when(mResources).getBoolean(
+                com.android.cellbroadcastreceiver.R.bool.show_alert_dialog_with_notification);
 
         Intent intent = new Intent(mContext, CellBroadcastAlertService.class);
         intent.setAction(SHOW_NEW_ALERT_ACTION);
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastBootupConfigTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastBootupConfigTest.java
index 77701787d..ec0dd2519 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastBootupConfigTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastBootupConfigTest.java
@@ -38,8 +38,8 @@ import static com.android.internal.telephony.gsm.SmsCbConstants.MESSAGE_ID_ETWS_
 
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.eq;
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.anyString;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.timeout;
 import static org.mockito.Mockito.verify;
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastConfigServiceTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastConfigServiceTest.java
index 2808abecb..2dc77a16d 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastConfigServiceTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastConfigServiceTest.java
@@ -16,18 +16,17 @@
 
 package com.android.cellbroadcastreceiver.unit;
 
+import static androidx.test.core.app.ApplicationProvider.getApplicationContext;
+
 import static com.android.cellbroadcastreceiver.CellBroadcastConfigService.CbConfig;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
-import static org.mockito.ArgumentMatchers.anyBoolean;
-import static org.mockito.ArgumentMatchers.nullable;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.anyString;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.atLeastOnce;
-import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.eq;
@@ -37,9 +36,7 @@ import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
-import android.app.ActivityManager;
 import android.app.ActivityOptions;
-import android.app.IActivityManager;
 import android.app.Notification;
 import android.app.NotificationManager;
 import android.content.Context;
@@ -49,7 +46,6 @@ import android.content.SharedPreferences;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
 import android.os.Bundle;
-import android.os.IBinder;
 import android.os.RemoteException;
 import android.telephony.CellBroadcastIdRange;
 import android.telephony.SmsCbMessage;
@@ -57,8 +53,6 @@ import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
 import android.util.DisplayMetrics;
-import android.util.Singleton;
-import android.view.IWindowManager;
 
 import androidx.test.filters.SmallTest;
 
@@ -77,10 +71,7 @@ import org.junit.Test;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Captor;
 import org.mockito.Mock;
-import org.mockito.invocation.InvocationOnMock;
-import org.mockito.stubbing.Answer;
 
-import java.lang.reflect.Field;
 import java.lang.reflect.Method;
 import java.util.ArrayList;
 import java.util.List;
@@ -107,12 +98,6 @@ public class CellBroadcastConfigServiceTest extends CellBroadcastTest {
 
     private CellBroadcastConfigService mConfigService;
 
-    @Mock
-    IWindowManager.Stub mWindowManagerService;
-
-    @Mock
-    private IActivityManager.Stub mMockedActivityManager;
-
     @Mock
     private NotificationManager mMockedNotificationManager;
 
@@ -1694,36 +1679,11 @@ public class CellBroadcastConfigServiceTest extends CellBroadcastTest {
                 .getSystemServiceName(NotificationManager.class);
         doReturn(mMockedNotificationManager).when(mContext)
                 .getSystemService(Context.NOTIFICATION_SERVICE);
-        doReturn("testPackageName").when(mContext).getPackageName();
+        String packageName = getApplicationContext().getPackageName();
+        doReturn(packageName).when(mContext).getPackageName();
         doReturn(new ApplicationInfo()).when(mContext).getApplicationInfo();
         doReturn(mResources).when(mConfigService).getResources();
         doReturn(new DisplayMetrics()).when(mResources).getDisplayMetrics();
-        Singleton<IActivityManager> activityManagerSingleton = new Singleton<IActivityManager>() {
-            @Override
-            protected IActivityManager create() {
-                return mMockedActivityManager;
-            }
-        };
-        mMockedServiceManager.replaceService("window", mWindowManagerService);
-        Field fieldHandler = ActivityManager.class.getDeclaredField("IActivityManagerSingleton");
-        fieldHandler.setAccessible(true);
-        Singleton<IActivityManager> activityManager =
-                (Singleton<IActivityManager>) fieldHandler.get(null);
-        IActivityManager realInstance = activityManager.get();
-        doAnswer(new Answer() {
-            public Void answer(InvocationOnMock invocation) throws RemoteException {
-                if (realInstance != null) {
-                    realInstance.finishReceiver(invocation.getArgument(0),
-                            invocation.getArgument(1), invocation.getArgument(2),
-                            invocation.getArgument(3), invocation.getArgument(4),
-                            invocation.getArgument(5));
-                }
-                return null;
-            }
-        }).when(mMockedActivityManager).finishReceiver(nullable(IBinder.class), anyInt(),
-                nullable(String.class), nullable(Bundle.class), anyBoolean(), anyInt());
-        mMockedServiceManager.replaceInstance(ActivityManager.class,
-                "IActivityManagerSingleton", null, activityManagerSingleton);
         doNothing().when(mConfigService).resetAllPreferences();
         doReturn(CellBroadcastConfigService.ACTION_UPDATE_SETTINGS_FOR_CARRIER)
                 .when(mIntent).getAction();
@@ -1742,6 +1702,8 @@ public class CellBroadcastConfigServiceTest extends CellBroadcastTest {
         // set ANY_PREFERENCE_CHANGED_BY_USER to true
         setPreference(CellBroadcastSettings.ANY_PREFERENCE_CHANGED_BY_USER, true);
         method.setAccessible(true);
+        Bundle testBundle = new Bundle();
+        doReturn(testBundle).when(mIntent).getBundleExtra("pending_intent_element");
         method.invoke(mConfigService, mIntent);
         verify(mConfigService, times(2)).resetAllPreferences();
         verify(mMockedNotificationManager, times(1)).notify(mInt.capture(),
@@ -1749,11 +1711,8 @@ public class CellBroadcastConfigServiceTest extends CellBroadcastTest {
         assertEquals(CellBroadcastAlertService.SETTINGS_CHANGED_NOTIFICATION_ID,
                 (int) mInt.getValue());
         if (SdkLevel.isAtLeastU()) {
-            ArgumentCaptor<Bundle> bundleArgs = ArgumentCaptor.forClass(Bundle.class);
-            verify(mMockedActivityManager, times(1))
-                    .getIntentSenderWithFeature(anyInt(), any(), any(), any(), any(), anyInt(),
-                            any(), any(), anyInt(), bundleArgs.capture(), anyInt());
-            ActivityOptions activityOptions = new ActivityOptions(bundleArgs.getAllValues().get(0));
+            ActivityOptions activityOptions =
+                    new ActivityOptions(testBundle.getBundle("option"));
             int startMode = activityOptions.getPendingIntentCreatorBackgroundActivityStartMode();
             assertEquals(ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED, startMode);
         }
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastReceiverTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastReceiverTest.java
index d5da192c0..5c46b282e 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastReceiverTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastReceiverTest.java
@@ -28,6 +28,7 @@ import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.doThrow;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.spy;
@@ -694,6 +695,14 @@ public class CellBroadcastReceiverTest extends CellBroadcastTest {
         assertThat(mFakeSharedPreferences.getString(
                 "roaming_operator_supported", "")).isEqualTo("310");
 
+        doThrow(new IllegalArgumentException("test"))
+                .when(mMockTelephonyManager).getNetworkCountryIso();
+        try {
+            mCellBroadcastReceiver.onReceive(mContext, mIntent);
+        } catch (Exception IllegalArgumentException) {
+            throw new AssertionError("not expected exception", IllegalArgumentException);
+        }
+
         doReturn(ServiceState.STATE_OUT_OF_SERVICE).when(mIntent)
                 .getIntExtra(anyString(), anyInt());
         doReturn("123456").when(mMockTelephonyManager).getSimOperator();
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastServiceTestCase.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastServiceTestCase.java
index ee5ecbb2a..53d6e6331 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastServiceTestCase.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastServiceTestCase.java
@@ -18,7 +18,7 @@ package com.android.cellbroadcastreceiver.unit;
 
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.eq;
-import static org.mockito.Matchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java
index 57821b872..7478fe16b 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java
@@ -13,6 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+
 package com.android.cellbroadcastreceiver.unit;
 
 import static androidx.test.espresso.Espresso.onView;
@@ -20,9 +21,9 @@ import static androidx.test.espresso.action.ViewActions.click;
 import static androidx.test.espresso.matcher.ViewMatchers.withText;
 
 import static org.mockito.ArgumentMatchers.anyBoolean;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.anyString;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.mock;
@@ -52,6 +53,7 @@ import com.android.cellbroadcastreceiver.CellBroadcastChannelManager;
 import com.android.cellbroadcastreceiver.CellBroadcastConfigService;
 import com.android.cellbroadcastreceiver.CellBroadcastSettings;
 import com.android.cellbroadcastreceiver.R;
+import com.android.internal.telephony.CellBroadcastUtils;
 import com.android.modules.utils.build.SdkLevel;
 
 import junit.framework.Assert;
@@ -70,6 +72,8 @@ import java.util.Locale;
 public class CellBroadcastSettingsTest extends
         CellBroadcastActivityTestCase<CellBroadcastSettings> {
 
+    private static final String TAG = "CellBroadcastSettingsTest";
+
     private UiDevice mDevice;
     private static final long DEVICE_WAIT_TIME = 1000L;
     private static final String ROAMING_OPERATOR_SUPPORTED = "roaming_operator_supported";
@@ -132,7 +136,7 @@ public class CellBroadcastSettingsTest extends
         int w = mDevice.getDisplayWidth();
         int h = mDevice.getDisplayHeight();
 
-        waitUntilDialogOpens(()-> {
+        waitUntilDialogOpens(() -> {
             mDevice.swipe(w / 2 /* start X */,
                     h / 2 /* start Y */,
                     w / 2 /* end X */,
@@ -174,19 +178,38 @@ public class CellBroadcastSettingsTest extends
 
         assertFalse("receive_cmas_in_second_language was not reset to the default (false)",
                 PreferenceManager.getDefaultSharedPreferences(mContext)
-                .getBoolean(CellBroadcastSettings.KEY_RECEIVE_CMAS_IN_SECOND_LANGUAGE, true));
+                        .getBoolean(CellBroadcastSettings.KEY_RECEIVE_CMAS_IN_SECOND_LANGUAGE,
+                                true));
         assertTrue("enable_alert_vibrate was not reset to the default (true)",
                 PreferenceManager.getDefaultSharedPreferences(mContext)
-                .getBoolean(CellBroadcastSettings.KEY_ENABLE_ALERT_VIBRATE, false));
+                        .getBoolean(CellBroadcastSettings.KEY_ENABLE_ALERT_VIBRATE, false));
     }
 
     @Test
-    public void testHasAnyPreferenceChanged() {
+    public void testHasAnyPreferenceChanged() throws Throwable {
         mContext.injectSharedPreferences(mFakeSharedPreferences);
         assertFalse(CellBroadcastSettings.hasAnyPreferenceChanged(mContext));
         PreferenceManager.getDefaultSharedPreferences(mContext).edit()
                 .putBoolean("any_preference_changed_by_user", true).apply();
         assertTrue(CellBroadcastSettings.hasAnyPreferenceChanged(mContext));
+
+        doReturn(true).when(mContext.getResources()).getBoolean(
+                R.bool.show_alert_speech_setting);
+        doReturn(false).when(mContext.getResources()).getBoolean(
+                R.bool.enable_alert_speech_default);
+
+        CellBroadcastSettings.resetAllPreferences(mContext);
+        assertFalse(CellBroadcastSettings.hasAnyPreferenceChanged(mContext));
+
+        CellBroadcastSettings cellBroadcastSettingActivity = startActivity();
+
+        TwoStatePreference speechCheckBox =
+                cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_ALERT_SPEECH);
+        assertNotNull(speechCheckBox);
+
+        speechCheckBox.performClick();
+        assertTrue(CellBroadcastSettings.hasAnyPreferenceChanged(mContext));
     }
 
     @Test
@@ -202,7 +225,10 @@ public class CellBroadcastSettingsTest extends
         doReturn(mEditor).when(mMockedSharedPreference).edit();
         doReturn(mEditor).when(mEditor).putBoolean(anyString(), anyBoolean());
 
-        fragment.onPreferenceChangedByUser(mockContext);
+        fragment.onPreferenceChangedByUser(mockContext, false);
+        verify(mockContext, times(0)).startService(mIntent.capture());
+
+        fragment.onPreferenceChangedByUser(mockContext, true);
 
         verify(mockContext, times(1)).startService(mIntent.capture());
         assertEquals(CellBroadcastConfigService.ACTION_ENABLE_CHANNELS,
@@ -330,8 +356,11 @@ public class CellBroadcastSettingsTest extends
     }
 
     private void openAlertReminderDialog() {
-        onView(withText(mContext.getString(com.android.cellbroadcastreceiver.R
-                .string.alert_reminder_interval_title))).perform(click());
+        String packageName = CellBroadcastUtils
+                .getDefaultCellBroadcastReceiverPackageName(mContext);
+        int resId = mContext.getResources().getIdentifier("alert_reminder_interval_title",
+                "string", packageName);
+        onView(withText(resId)).perform(click());
     }
 
     @Test
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastTest.java
index c91a67734..cf84ff0cb 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastTest.java
@@ -16,8 +16,8 @@
 
 package com.android.cellbroadcastreceiver.unit;
 
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.anyString;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.eq;
 
```

