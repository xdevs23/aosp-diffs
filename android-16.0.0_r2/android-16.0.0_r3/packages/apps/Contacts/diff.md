```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index e0d9ece0a..889abdfaa 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -20,8 +20,8 @@
           android:versionName="1.7.34">
 
     <uses-sdk
-        android:minSdkVersion="34"
-        android:targetSdkVersion="34"/>
+        android:minSdkVersion="36"
+        android:targetSdkVersion="36"/>
 
     <original-package android:name="com.android.contacts"/>
 
@@ -392,13 +392,6 @@
 
         </activity-alias>
 
-        <!-- Accounts changed prompt that can appear when creating a new contact. -->
-        <activity
-            android:name=".activities.ContactEditorAccountsChangedActivity"
-            android:exported="false"
-            android:theme="@style/ContactEditorAccountsChangedActivityTheme"
-            android:windowSoftInputMode="adjustResize"/>
-
         <!-- Edit or create a contact with only the most important fields displayed initially. -->
         <activity
             android:name=".activities.ContactEditorActivity"
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 7f7e30452..b4dc881bc 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -123,7 +123,7 @@
     <string name="quickcontact_transparent_view_description" msgid="7783027850792852265">"Klik om na die vorige skerm terug te keer"</string>
     <string name="quickcontact_add_phone_number" msgid="1683577288080727862">"Voeg foonnommer by"</string>
     <string name="quickcontact_add_email" msgid="1442894568471116797">"Voeg e-pos by"</string>
-    <string name="missing_app" msgid="5674389915738964148">"Geen program is gevind om hierdie handeling te behartig nie."</string>
+    <string name="missing_app" msgid="5674389915738964148">"Geen app is gevind om hierdie handeling te behartig nie."</string>
     <string name="menu_share" msgid="6343022811796001773">"Deel"</string>
     <string name="menu_add_contact" msgid="5822356185421997656">"Voeg by kontakte"</string>
     <string name="menu_add_contacts" msgid="7114262784903366463">"Voeg by"</string>
@@ -276,7 +276,7 @@
     <string name="sms_by_shortcut" msgid="4682340916268521006">"<xliff:g id="CONTACT_NAME">%s</xliff:g> (Boodskap)"</string>
     <string name="description_video_call" msgid="4956825008907720371">"Maak video-oproep"</string>
     <string name="clearFrequentsConfirmation_title" msgid="9194415661170740437">"Vee dikwels-gebruikte kontakte uit?"</string>
-    <string name="clearFrequentsConfirmation" msgid="2120741757522063938">"Jy gaan die lys van dikwels gebruikte kontakte in die Kontakte- en Foon-program uitvee en e-posprogramme dwing om jou adresvoorkeure van nuuts af te leer."</string>
+    <string name="clearFrequentsConfirmation" msgid="2120741757522063938">"Jy gaan die lys van dikwels gebruikte kontakte in die Kontakte- en Foon-app uitvee en e-posapps dwing om jou adresvoorkeure van nuuts af te leer."</string>
     <string name="clearFrequentsProgress_title" msgid="8271935295080659743">"Vee tans dikwels-gebruikte kontakte uit..."</string>
     <string name="status_available" msgid="8081626460682959098">"Beskikbaar"</string>
     <string name="status_away" msgid="2677693194455091315">"Weg"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 9ac0f8ec8..826f7ecbb 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -133,8 +133,8 @@
     <string name="group_name_dialog_update_title" msgid="3955919589366745101">"Preimenujte oznaku"</string>
     <string name="group_name_dialog_hint" msgid="6023999218213062973">"Ime oznake"</string>
     <string name="label_name_dialog_hint" msgid="7027635439255596191">"Ime oznake"</string>
-    <string name="audio_chat" msgid="5921525823973697372">"Audio ćaskanje"</string>
-    <string name="video_chat" msgid="2477295971622477433">"Video ćaskanje"</string>
+    <string name="audio_chat" msgid="5921525823973697372">"Audio čet"</string>
+    <string name="video_chat" msgid="2477295971622477433">"Video čet"</string>
     <string name="account_type_format" msgid="4926968760755013450">"<xliff:g id="SOURCE">%1$s</xliff:g>"</string>
     <string name="google_account_type_format" msgid="4046692740262396811">"<xliff:g id="SOURCE">%1$s</xliff:g> nalog"</string>
     <string name="take_photo" msgid="820071555236547516">"Slikaj"</string>
@@ -336,15 +336,15 @@
     <string name="map_work" msgid="8296916987749726461">"Prikaži poslovnu adresu"</string>
     <string name="map_other" msgid="4009931029322619674">"Prikaži adresu"</string>
     <string name="map_custom" msgid="7797812861927817335">"Prikaži adresu <xliff:g id="CUSTOM_LABEL">%s</xliff:g>"</string>
-    <string name="chat_aim" msgid="2044861410748519265">"Započni ćaskanje preko AIM-a"</string>
-    <string name="chat_msn" msgid="4733206223124506247">"Započni ćaskanje preko Windows Live-a"</string>
-    <string name="chat_yahoo" msgid="3807571878191282528">"Započni ćaskanje preko Yahoo-a"</string>
-    <string name="chat_skype" msgid="5130564346825936093">"Započni ćaskanje preko Skype-a"</string>
-    <string name="chat_qq" msgid="2971335421266098608">"Započni ćaskanje preko QQ-a"</string>
-    <string name="chat_gtalk" msgid="2927882858741904064">"Ćaskaj preko Google Talk-a"</string>
-    <string name="chat_icq" msgid="4289041376069626281">"Započni ćaskanje preko ICQ-a"</string>
-    <string name="chat_jabber" msgid="1097960594943864847">"Započni ćaskanje preko Jabber-a"</string>
-    <string name="chat" msgid="8390862712584830532">"Ćaskanje"</string>
+    <string name="chat_aim" msgid="2044861410748519265">"Započni čet preko AIM-a"</string>
+    <string name="chat_msn" msgid="4733206223124506247">"Započni čet preko Windows Live-a"</string>
+    <string name="chat_yahoo" msgid="3807571878191282528">"Započni čet preko Yahoo-a"</string>
+    <string name="chat_skype" msgid="5130564346825936093">"Započni čet preko Skype-a"</string>
+    <string name="chat_qq" msgid="2971335421266098608">"Započni čet preko QQ-a"</string>
+    <string name="chat_gtalk" msgid="2927882858741904064">"Četuj preko Google Talk-a"</string>
+    <string name="chat_icq" msgid="4289041376069626281">"Započni čet preko ICQ-a"</string>
+    <string name="chat_jabber" msgid="1097960594943864847">"Započni čet preko Jabber-a"</string>
+    <string name="chat" msgid="8390862712584830532">"Čet"</string>
     <string name="description_minus_button" msgid="1305985971158054217">"izbriši"</string>
     <string name="expand_name_fields_description" msgid="6059558159338959487">"Prikažite još polja za ime"</string>
     <string name="collapse_name_fields_description" msgid="7950435675716414477">"Skupite polja za ime"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 192320cc5..625aef561 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -21,7 +21,7 @@
     <string name="shortcut_add_contact" msgid="7949342235528657981">"পরিচিতি যোগ করুন"</string>
     <string name="shortcutContact" msgid="8009736387364461511">"পরিচিতি"</string>
     <string name="shortcutDialContact" msgid="155367248069127153">"সরাসরি ডায়াল"</string>
-    <string name="shortcutMessageContact" msgid="9123517151981679277">"সরাসরি বার্তা"</string>
+    <string name="shortcutMessageContact" msgid="9123517151981679277">"সরাসরি মেসেজ"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"পরিচিতি বেছে নিন"</string>
     <string name="contactInsertOrEditActivityTitle" msgid="1788154962629911262">"পরিচিতিতে যোগ করুন"</string>
     <string name="contactPickerActivityTitle" msgid="1842634991247618890">"একটি পরিচিতি বেছে নিন"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index b61a1009b..e0861cd81 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -20,8 +20,8 @@
     <string name="contactsList" msgid="4456188358262700898">"Kontaktuak"</string>
     <string name="shortcut_add_contact" msgid="7949342235528657981">"Gehitu kontaktua"</string>
     <string name="shortcutContact" msgid="8009736387364461511">"Kontaktua"</string>
-    <string name="shortcutDialContact" msgid="155367248069127153">"Markatze zuzena"</string>
-    <string name="shortcutMessageContact" msgid="9123517151981679277">"Mezu zuzena"</string>
+    <string name="shortcutDialContact" msgid="155367248069127153">"Zuzeneko markatzea"</string>
+    <string name="shortcutMessageContact" msgid="9123517151981679277">"Zuzeneko mezua"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"Aukeratu kontaktua"</string>
     <string name="contactInsertOrEditActivityTitle" msgid="1788154962629911262">"Gehitu kontaktu batean"</string>
     <string name="contactPickerActivityTitle" msgid="1842634991247618890">"Aukeratu kontaktu bat"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 0d06d893c..ad324587e 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -231,7 +231,7 @@
     <string name="hamburger_feature_highlight_body" msgid="782935036630531528">"Gardez vos contacts organisés et utiles"</string>
     <string name="undo" msgid="2446931036220975026">"Annuler"</string>
     <string name="call_custom" msgid="2844900154492073207">"Appeller <xliff:g id="CUSTOM_LABEL">%s</xliff:g>"</string>
-    <string name="call_home" msgid="2443904771140750492">"Appeler le numéro de téléphone du domicile"</string>
+    <string name="call_home" msgid="2443904771140750492">"Appeler le domicile"</string>
     <string name="call_mobile" msgid="6504312789160309832">"Appeler le numéro de téléphone mobile"</string>
     <string name="call_work" msgid="2414313348547560346">"Appeler le numéro de téléphone professionnel"</string>
     <string name="call_fax_work" msgid="5026843006300760797">"Appeler le numéro de télécopie professionnel"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index f846babc1..43858570f 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -180,7 +180,7 @@
     <string name="contact_editor_prompt_one_account" msgid="765343809177951169">"אנשי קשר חדשים יישמרו ב-<xliff:g id="ACCOUNT_NAME">%1$s</xliff:g>."</string>
     <string name="contact_editor_prompt_multiple_accounts" msgid="1543322760761168351">"בחר חשבון ברירת מחדל לאנשי קשר חדשים:"</string>
     <string name="contact_editor_title_new_contact" msgid="7534775011591770343">"איש קשר חדש"</string>
-    <string name="contact_editor_title_existing_contact" msgid="3647774955741654029">"עריכת איש קשר"</string>
+    <string name="contact_editor_title_existing_contact" msgid="3647774955741654029">"עריכת איש/אשת קשר"</string>
     <string name="contact_editor_title_read_only_contact" msgid="5494810291515292596">"תצוגה בלבד"</string>
     <string name="contact_editor_pick_raw_contact_to_edit_dialog_title" msgid="4478782370280424187">"בחר איש קשר לעריכה"</string>
     <string name="contact_editor_pick_linked_contact_dialog_title" msgid="3332134735168016293">"אנשי קשר מקושרים"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 29bdd1d90..a5ddc562b 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -164,10 +164,10 @@
     <string name="create_group_item_label" msgid="921929508079162463">"ಹೊಸದನ್ನು ರಚಿಸಿ…"</string>
     <string name="delete_group_dialog_message" msgid="754082019928025404">"\"<xliff:g id="GROUP_LABEL">%1$s</xliff:g>\" ಲೇಬಲ್ ಅಳಿಸಬೇಕೆ? (ಸಂಪರ್ಕಗಳು ತಾವಾಗಿ ಅಳಿಸಿ ಹೋಗುವುದಿಲ್ಲ.)"</string>
     <string name="toast_join_with_empty_contact" msgid="3886468280665325350">"ಮತ್ತೊಬ್ಬರೊಂದಿಗೆ ಲಿಂಕ್ ಮಾಡುವ ಮೊದಲು ಸಂಪರ್ಕದ ಹೆಸರನ್ನು ಟೈಪ್‌ ಮಾಡಿ."</string>
-    <string name="copy_text" msgid="6835250673373028909">"ಕ್ಲಿಪ್‌ಬೋರ್ಡ್‌ಗೆ ನಕಲಿಸಿ"</string>
+    <string name="copy_text" msgid="6835250673373028909">"ಕ್ಲಿಪ್‌ಬೋರ್ಡ್‌ಗೆ ಕಾಪಿ ಮಾಡಿ"</string>
     <string name="set_default" msgid="3704074175618702225">"ಡೀಫಾಲ್ಟ್ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="clear_default" msgid="2055883863621491533">"ಡಿಫಾಲ್ಟ್‌ ತೆರವುಗೊಳಿಸಿ"</string>
-    <string name="toast_text_copied" msgid="845906090076228771">"ಪಠ್ಯವನ್ನು ನಕಲಿಸಲಾಗಿದೆ"</string>
+    <string name="toast_text_copied" msgid="845906090076228771">"ಪಠ್ಯವನ್ನು ಕಾಪಿ ಮಾಡಲಾಗಿದೆ"</string>
     <string name="cancel_confirmation_dialog_message" msgid="7486892574762212762">"ಬದಲಾವಣೆಗಳನ್ನು ತ್ಯಜಿಸುವುದೇ?"</string>
     <string name="cancel_confirmation_dialog_cancel_editing_button" msgid="8280294641821133477">"ತ್ಯಜಿಸು"</string>
     <string name="cancel_confirmation_dialog_keep_editing_button" msgid="7117943783437253341">"ರದ್ದುಮಾಡಿ"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 063e8d2c7..371a9f39f 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -21,7 +21,7 @@
     <string name="shortcut_add_contact" msgid="7949342235528657981">"കോൺടാക്റ്റ് ചേർക്കുക"</string>
     <string name="shortcutContact" msgid="8009736387364461511">"കോൺടാക്റ്റ്"</string>
     <string name="shortcutDialContact" msgid="155367248069127153">"നേരിട്ടുള്ള ഡയൽ"</string>
-    <string name="shortcutMessageContact" msgid="9123517151981679277">"സന്ദേശങ്ങൾ നേരിട്ട്"</string>
+    <string name="shortcutMessageContact" msgid="9123517151981679277">"നേരിട്ടുള്ള സന്ദേശം"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"കോൺടാക്‌റ്റ് തിരഞ്ഞെടുക്കുക"</string>
     <string name="contactInsertOrEditActivityTitle" msgid="1788154962629911262">"കോണ്‍‌ടാക്റ്റിലേക്ക് ചേര്‍ക്കുക"</string>
     <string name="contactPickerActivityTitle" msgid="1842634991247618890">"കോൺടാക്റ്റ് തിരഞ്ഞെടുക്കൂ"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 8640f30af..9d25e8caf 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -20,7 +20,7 @@
     <string name="contactsList" msgid="4456188358262700898">"कन्ट्याक्टहरू"</string>
     <string name="shortcut_add_contact" msgid="7949342235528657981">"सम्पर्क थप्नुहोस्"</string>
     <string name="shortcutContact" msgid="8009736387364461511">"कन्ट्याक्ट"</string>
-    <string name="shortcutDialContact" msgid="155367248069127153">"सीधा डायल गर्नुहोस्"</string>
+    <string name="shortcutDialContact" msgid="155367248069127153">"डाइरेक्ट डायल"</string>
     <string name="shortcutMessageContact" msgid="9123517151981679277">"डाइरेक्ट म्यासेज"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"सम्पर्क छनौट गर्नुहोस्"</string>
     <string name="contactInsertOrEditActivityTitle" msgid="1788154962629911262">"सम्पर्कमा थप्नुहोस्"</string>
@@ -316,7 +316,7 @@
     <string name="ghostData_company" msgid="3873500610390675876">"कम्पनी"</string>
     <string name="ghostData_department" msgid="8610642449404163799">"विभाग"</string>
     <string name="ghostData_title" msgid="8584897460662904533">"शीर्षक"</string>
-    <string name="label_notes" msgid="7134226125644463585">"टिप्पणीहरू"</string>
+    <string name="label_notes" msgid="7134226125644463585">"नोटहरू"</string>
     <string name="label_custom_field" msgid="4160584225306364924">" कस्टम"</string>
     <string name="label_sip_address" msgid="8876347942587537552">"SIP"</string>
     <string name="websiteLabelsGroup" msgid="114754928100220315">"वेबसाइट"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 4171a10d0..ca4b3ef90 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -20,8 +20,8 @@
     <string name="contactsList" msgid="4456188358262700898">"Kontakty"</string>
     <string name="shortcut_add_contact" msgid="7949342235528657981">"Dodaj kontakt"</string>
     <string name="shortcutContact" msgid="8009736387364461511">"Kontakt"</string>
-    <string name="shortcutDialContact" msgid="155367248069127153">"Telefon do osoby"</string>
-    <string name="shortcutMessageContact" msgid="9123517151981679277">"SMS do osoby"</string>
+    <string name="shortcutDialContact" msgid="155367248069127153">"Telefon bezpośredni"</string>
+    <string name="shortcutMessageContact" msgid="9123517151981679277">"SMS bezpośredni"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"Wybierz kontakt"</string>
     <string name="contactInsertOrEditActivityTitle" msgid="1788154962629911262">"Dodaj do kontaktu"</string>
     <string name="contactPickerActivityTitle" msgid="1842634991247618890">"Wybierz kontakt"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 96df34e13..a6e1bd8a9 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -133,8 +133,8 @@
     <string name="group_name_dialog_update_title" msgid="3955919589366745101">"Преименујте ознаку"</string>
     <string name="group_name_dialog_hint" msgid="6023999218213062973">"Име ознаке"</string>
     <string name="label_name_dialog_hint" msgid="7027635439255596191">"Име ознаке"</string>
-    <string name="audio_chat" msgid="5921525823973697372">"Аудио ћаскање"</string>
-    <string name="video_chat" msgid="2477295971622477433">"Видео ћаскање"</string>
+    <string name="audio_chat" msgid="5921525823973697372">"Аудио чет"</string>
+    <string name="video_chat" msgid="2477295971622477433">"Видео чет"</string>
     <string name="account_type_format" msgid="4926968760755013450">"<xliff:g id="SOURCE">%1$s</xliff:g>"</string>
     <string name="google_account_type_format" msgid="4046692740262396811">"<xliff:g id="SOURCE">%1$s</xliff:g> налог"</string>
     <string name="take_photo" msgid="820071555236547516">"Сликај"</string>
@@ -336,15 +336,15 @@
     <string name="map_work" msgid="8296916987749726461">"Прикажи пословну адресу"</string>
     <string name="map_other" msgid="4009931029322619674">"Прикажи адресу"</string>
     <string name="map_custom" msgid="7797812861927817335">"Прикажи адресу <xliff:g id="CUSTOM_LABEL">%s</xliff:g>"</string>
-    <string name="chat_aim" msgid="2044861410748519265">"Започни ћаскање преко AIM-а"</string>
-    <string name="chat_msn" msgid="4733206223124506247">"Започни ћаскање преко Windows Live-а"</string>
-    <string name="chat_yahoo" msgid="3807571878191282528">"Започни ћаскање преко Yahoo-а"</string>
-    <string name="chat_skype" msgid="5130564346825936093">"Започни ћаскање преко Skype-а"</string>
-    <string name="chat_qq" msgid="2971335421266098608">"Започни ћаскање преко QQ-а"</string>
-    <string name="chat_gtalk" msgid="2927882858741904064">"Ћаскај преко Google Talk-а"</string>
-    <string name="chat_icq" msgid="4289041376069626281">"Започни ћаскање преко ICQ-а"</string>
-    <string name="chat_jabber" msgid="1097960594943864847">"Започни ћаскање преко Jabber-а"</string>
-    <string name="chat" msgid="8390862712584830532">"Ћаскање"</string>
+    <string name="chat_aim" msgid="2044861410748519265">"Започни чет преко AIM-а"</string>
+    <string name="chat_msn" msgid="4733206223124506247">"Започни чет преко Windows Live-а"</string>
+    <string name="chat_yahoo" msgid="3807571878191282528">"Започни чет преко Yahoo-а"</string>
+    <string name="chat_skype" msgid="5130564346825936093">"Започни чет преко Skype-а"</string>
+    <string name="chat_qq" msgid="2971335421266098608">"Започни чет преко QQ-а"</string>
+    <string name="chat_gtalk" msgid="2927882858741904064">"Четуј преко Google Talk-а"</string>
+    <string name="chat_icq" msgid="4289041376069626281">"Започни чет преко ICQ-а"</string>
+    <string name="chat_jabber" msgid="1097960594943864847">"Започни чет преко Jabber-а"</string>
+    <string name="chat" msgid="8390862712584830532">"Чет"</string>
     <string name="description_minus_button" msgid="1305985971158054217">"избриши"</string>
     <string name="expand_name_fields_description" msgid="6059558159338959487">"Прикажите још поља за име"</string>
     <string name="collapse_name_fields_description" msgid="7950435675716414477">"Скупите поља за име"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 321a022f0..18d0d51ab 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -20,8 +20,8 @@
     <string name="contactsList" msgid="4456188358262700898">"కాంటాక్ట్‌లు"</string>
     <string name="shortcut_add_contact" msgid="7949342235528657981">"కాంటాక్ట్‌ను జోడించండి"</string>
     <string name="shortcutContact" msgid="8009736387364461511">"కాంటాక్ట్"</string>
-    <string name="shortcutDialContact" msgid="155367248069127153">"నేరుగా డయల్"</string>
-    <string name="shortcutMessageContact" msgid="9123517151981679277">"నేరుగా మెసేజ్‌"</string>
+    <string name="shortcutDialContact" msgid="155367248069127153">"డైరెక్ట్ కాల్"</string>
+    <string name="shortcutMessageContact" msgid="9123517151981679277">"డైరెక్ట్ మెసేజ్"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"కాంటాక్ట్‌ను ఎంచుకోండి"</string>
     <string name="contactInsertOrEditActivityTitle" msgid="1788154962629911262">"కాంటాక్ట్‌కు జోడించండి"</string>
     <string name="contactPickerActivityTitle" msgid="1842634991247618890">"కాంటాక్ట్‌ను ఎంచుకోండి"</string>
@@ -291,7 +291,7 @@
     <string name="list_filter_phones" msgid="6839133198968393843">"ఫోన్ నంబర్‌లు గల అన్ని కాంటాక్ట్‌లు"</string>
     <string name="list_filter_phones_work" msgid="5583425697781385616">"వర్క్ ప్రొఫైల్ కాంటాక్ట్‌లు"</string>
     <string name="view_updates_from_group" msgid="6233444629074835594">"తాజా విషయాలను చూడండి"</string>
-    <string name="account_phone" msgid="8044426231251817556">"పరికరం"</string>
+    <string name="account_phone" msgid="8044426231251817556">"డివైజ్"</string>
     <string name="account_sim" msgid="3200457113308694663">"SIM"</string>
     <string name="nameLabelsGroup" msgid="513809148312046843">"పేరు"</string>
     <string name="nicknameLabelsGroup" msgid="794390116782033956">"మారుపేరు"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 4e67f7001..826c0242f 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -20,7 +20,7 @@
     <string name="contactsList" msgid="4456188358262700898">"Kişiler"</string>
     <string name="shortcut_add_contact" msgid="7949342235528657981">"Kişi ekle"</string>
     <string name="shortcutContact" msgid="8009736387364461511">"Kişi"</string>
-    <string name="shortcutDialContact" msgid="155367248069127153">"Doğrudan çevirme"</string>
+    <string name="shortcutDialContact" msgid="155367248069127153">"Doğrudan arama"</string>
     <string name="shortcutMessageContact" msgid="9123517151981679277">"Doğrudan mesaj"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"Kişi seçin"</string>
     <string name="contactInsertOrEditActivityTitle" msgid="1788154962629911262">"Kişiye ekle"</string>
diff --git a/res/values/styles.xml b/res/values/styles.xml
index ffd800fc1..08381da94 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -289,14 +289,6 @@
         <item name="android:windowCloseOnTouchOutside">true</item>
     </style>
 
-    <style name="ContactEditorAccountsChangedActivityTheme" parent="@android:style/Theme.Material.Light.Dialog.NoActionBar.MinWidth">
-        <item name="android:windowCloseOnTouchOutside">true</item>
-        <item name="android:textColorPrimary">@color/primary_text_color</item>
-        <item name="android:textColorSecondary">@color/secondary_text_color</item>
-        <item name="android:listViewStyle">@style/ListViewStyle</item>
-        <item name="android:colorAccent">@color/primary_color</item>
-    </style>
-
     <style name="SelectableItem" parent="@android:style/Theme.Material.Light">
         <item name="android:background">?android:attr/selectableItemBackground</item>
     </style>
diff --git a/res/xml/preference_display_options.xml b/res/xml/preference_display_options.xml
index c969cd24f..3be0fdcd8 100644
--- a/res/xml/preference_display_options.xml
+++ b/res/xml/preference_display_options.xml
@@ -26,11 +26,10 @@
         android:title="@string/settings_accounts">
     </Preference>
 
-    <com.android.contacts.preference.DefaultAccountPreference
+    <Preference
         android:icon="@null"
         android:key="defaultAccount"
-        android:title="@string/default_editor_account"
-        android:dialogTitle="@string/default_editor_account" />
+        android:title="@string/default_editor_account" />
 
     <Preference
         android:icon="@null"
diff --git a/src/com/android/contacts/MoreContactUtils.java b/src/com/android/contacts/MoreContactUtils.java
index 7f000ec63..59e3c0377 100644
--- a/src/com/android/contacts/MoreContactUtils.java
+++ b/src/com/android/contacts/MoreContactUtils.java
@@ -16,6 +16,7 @@
 
 package com.android.contacts;
 
+import android.app.Activity;
 import android.content.Context;
 import android.content.Intent;
 import android.graphics.Rect;
@@ -24,28 +25,34 @@ import android.provider.ContactsContract;
 import android.telephony.PhoneNumberUtils;
 import android.text.TextUtils;
 import android.view.View;
+import android.view.ViewGroup;
 import android.widget.TextView;
 
+import androidx.annotation.NonNull;
+import androidx.core.graphics.Insets;
+import androidx.core.view.ViewCompat;
+import androidx.core.view.WindowInsetsCompat;
+
 import com.android.contacts.model.account.AccountType;
 
 import com.google.i18n.phonenumbers.NumberParseException;
 import com.google.i18n.phonenumbers.PhoneNumberUtil;
 
-/**
- * Shared static contact utility methods.
- */
+/** Shared static contact utility methods. */
 public class MoreContactUtils {
 
     private static final String WAIT_SYMBOL_AS_STRING = String.valueOf(PhoneNumberUtils.WAIT);
 
     /**
      * Returns true if two data with mimetypes which represent values in contact entries are
-     * considered equal for collapsing in the GUI. For caller-id, use
-     * {@link android.telephony.PhoneNumberUtils#compare(android.content.Context, String, String)}
-     * instead
+     * considered equal for collapsing in the GUI. For caller-id, use {@link
+     * android.telephony.PhoneNumberUtils#compare(android.content.Context, String, String)} instead
      */
-    public static boolean shouldCollapse(CharSequence mimetype1, CharSequence data1,
-              CharSequence mimetype2, CharSequence data2) {
+    public static boolean shouldCollapse(
+            CharSequence mimetype1,
+            CharSequence data1,
+            CharSequence mimetype2,
+            CharSequence data2) {
         // different mimetypes? don't collapse
         if (!TextUtils.equals(mimetype1, mimetype2)) return false;
 
@@ -57,8 +64,8 @@ public class MoreContactUtils {
 
         // if this is not about phone numbers, we know this is not a match (of course, some
         // mimetypes could have more sophisticated matching is the future, e.g. addresses)
-        if (!TextUtils.equals(ContactsContract.CommonDataKinds.Phone.CONTENT_ITEM_TYPE,
-                mimetype1)) {
+        if (!TextUtils.equals(
+                ContactsContract.CommonDataKinds.Phone.CONTENT_ITEM_TYPE, mimetype1)) {
             return false;
         }
 
@@ -165,18 +172,18 @@ public class MoreContactUtils {
                 case SHORT_NSN_MATCH:
                     return false;
                 default:
-                    throw new IllegalStateException("Unknown result value from phone number " +
-                            "library");
+                    throw new IllegalStateException(
+                            "Unknown result value from phone number " + "library");
             }
         }
         return true;
     }
 
     /**
-     * Returns the {@link android.graphics.Rect} with left, top, right, and bottom coordinates
-     * that are equivalent to the given {@link android.view.View}'s bounds. This is equivalent to
-     * how the target {@link android.graphics.Rect} is calculated in
-     * {@link android.provider.ContactsContract.QuickContact#showQuickContact}.
+     * Returns the {@link android.graphics.Rect} with left, top, right, and bottom coordinates that
+     * are equivalent to the given {@link android.view.View}'s bounds. This is equivalent to how the
+     * target {@link android.graphics.Rect} is calculated in {@link
+     * android.provider.ContactsContract.QuickContact#showQuickContact}.
      */
     public static Rect getTargetRectFromView(View view) {
         final int[] pos = new int[2];
@@ -191,8 +198,8 @@ public class MoreContactUtils {
     }
 
     /**
-     * Returns a header view based on the R.layout.list_separator, where the
-     * containing {@link android.widget.TextView} is set using the given textResourceId.
+     * Returns a header view based on the R.layout.list_separator, where the containing {@link
+     * android.widget.TextView} is set using the given textResourceId.
      */
     public static TextView createHeaderView(Context context, int textResourceId) {
         final TextView textView = (TextView) View.inflate(context, R.layout.list_separator, null);
@@ -201,29 +208,37 @@ public class MoreContactUtils {
     }
 
     /**
-     * Set the top padding on the header view dynamically, based on whether the header is in
-     * the first row or not.
+     * Set the top padding on the header view dynamically, based on whether the header is in the
+     * first row or not.
      */
-    public static void setHeaderViewBottomPadding(Context context, TextView textView,
-            boolean isFirstRow) {
+    public static void setHeaderViewBottomPadding(
+            Context context, TextView textView, boolean isFirstRow) {
         final int topPadding;
         if (isFirstRow) {
-            topPadding = (int) context.getResources().getDimension(
-                    R.dimen.frequently_contacted_title_top_margin_when_first_row);
+            topPadding =
+                    (int)
+                            context.getResources()
+                                    .getDimension(
+                                            R.dimen
+                                                    .frequently_contacted_title_top_margin_when_first_row);
         } else {
-            topPadding = (int) context.getResources().getDimension(
-                    R.dimen.frequently_contacted_title_top_margin);
+            topPadding =
+                    (int)
+                            context.getResources()
+                                    .getDimension(R.dimen.frequently_contacted_title_top_margin);
         }
-        textView.setPaddingRelative(textView.getPaddingStart(), topPadding,
-                textView.getPaddingEnd(), textView.getPaddingBottom());
+        textView.setPaddingRelative(
+                textView.getPaddingStart(),
+                topPadding,
+                textView.getPaddingEnd(),
+                textView.getPaddingBottom());
     }
 
-
     /**
      * Returns the intent to launch for the given invitable account type and contact lookup URI.
-     * This will return null if the account type is not invitable (i.e. there is no
-     * {@link AccountType#getInviteContactActivityClassName()} or
-     * {@link AccountType#syncAdapterPackageName}).
+     * This will return null if the account type is not invitable (i.e. there is no {@link
+     * AccountType#getInviteContactActivityClassName()} or {@link
+     * AccountType#syncAdapterPackageName}).
      */
     public static Intent getInvitableIntent(AccountType accountType, Uri lookupUri) {
         String syncAdapterPackageName = accountType.syncAdapterPackageName;
@@ -240,4 +255,66 @@ public class MoreContactUtils {
         intent.setData(lookupUri);
         return intent;
     }
+
+    /**
+     * Enable new edge to edge feature.
+     *
+     * @param activity the Activity need to setup the edge to edge feature.
+     */
+    public static void setupEdgeToEdge(@NonNull Activity activity, EdgeToEdgeInsetHandler handler) {
+        ViewCompat.setOnApplyWindowInsetsListener(
+                activity.findViewById(android.R.id.content),
+                (v, windowInsets) -> {
+                    final Insets insets =
+                            windowInsets.getInsets(
+                                    WindowInsetsCompat.Type.systemBars()
+                                            | WindowInsetsCompat.Type.ime()
+                                            | WindowInsetsCompat.Type.displayCutout());
+
+                    // Apply the insets paddings to the view.
+                    v.setPadding(
+                            insets.left,
+                            handler == null ? insets.top : v.getPaddingTop(),
+                            insets.right,
+                            insets.bottom);
+
+                    if (handler != null) {
+                        handler.applyTopInset(insets.top);
+                    }
+
+                    // Return CONSUMED if you don't want the window insets to keep being
+                    // passed down to descendant views.
+                    return WindowInsetsCompat.CONSUMED;
+                });
+    }
+
+    /** Handles setting the insets on a {@link View}. */
+    public static class EdgeToEdgeInsetHandler {
+
+        private final View mView;
+
+        private int mOriginalHeight = -1;
+        private int mOriginalPaddingTop = -1;
+
+        public EdgeToEdgeInsetHandler(View view) {
+            mView = view;
+        }
+
+        public void applyTopInset(int top) {
+            ViewGroup.LayoutParams layoutParams = mView.getLayoutParams();
+            if (mOriginalHeight == -1) {
+                mOriginalHeight = layoutParams.height;
+            }
+            if (mOriginalPaddingTop == -1) {
+                mOriginalPaddingTop = mView.getPaddingTop();
+            }
+            layoutParams.height = mOriginalHeight + top;
+            mView.setLayoutParams(layoutParams);
+            mView.setPadding(
+                    mView.getPaddingLeft(),
+                    mOriginalPaddingTop + top,
+                    mView.getPaddingRight(),
+                    mView.getPaddingBottom());
+        }
+    }
 }
diff --git a/src/com/android/contacts/SimImportFragment.java b/src/com/android/contacts/SimImportFragment.java
index 1d16df0b3..599bccd4a 100644
--- a/src/com/android/contacts/SimImportFragment.java
+++ b/src/com/android/contacts/SimImportFragment.java
@@ -22,14 +22,6 @@ import android.content.Context;
 import android.content.IntentFilter;
 import android.content.Loader;
 import android.os.Bundle;
-import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
-import com.google.android.material.snackbar.Snackbar;
-
-import androidx.collection.ArrayMap;
-import androidx.core.view.ViewCompat;
-import androidx.core.widget.ContentLoadingProgressBar;
-import androidx.appcompat.widget.Toolbar;
 import android.util.SparseBooleanArray;
 import android.view.LayoutInflater;
 import android.view.View;
@@ -40,6 +32,15 @@ import android.widget.ArrayAdapter;
 import android.widget.ListView;
 import android.widget.TextView;
 
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+import androidx.appcompat.widget.Toolbar;
+import androidx.collection.ArrayMap;
+import androidx.core.view.ViewCompat;
+import androidx.core.widget.ContentLoadingProgressBar;
+
+import com.android.contacts.MoreContactUtils;
+import com.android.contacts.MoreContactUtils.EdgeToEdgeInsetHandler;
 import com.android.contacts.compat.CompatUtils;
 import com.android.contacts.database.SimContactDao;
 import com.android.contacts.editor.AccountHeaderPresenter;
@@ -51,6 +52,8 @@ import com.android.contacts.model.account.AccountWithDataSet;
 import com.android.contacts.preference.ContactsPreferences;
 import com.android.contacts.util.concurrent.ContactsExecutors;
 import com.android.contacts.util.concurrent.ListenableFutureLoader;
+
+import com.google.android.material.snackbar.Snackbar;
 import com.google.common.base.Function;
 import com.google.common.util.concurrent.Futures;
 import com.google.common.util.concurrent.ListenableFuture;
@@ -70,7 +73,8 @@ import java.util.concurrent.Callable;
  */
 public class SimImportFragment extends Fragment
         implements LoaderManager.LoaderCallbacks<SimImportFragment.LoaderResult>,
-        AdapterView.OnItemClickListener, AbsListView.OnScrollListener {
+                AdapterView.OnItemClickListener,
+                AbsListView.OnScrollListener {
 
     private static final String KEY_SUFFIX_SELECTED_IDS = "_selectedIds";
     private static final String ARG_SUBSCRIPTION_ID = "subscriptionId";
@@ -102,8 +106,10 @@ public class SimImportFragment extends Fragment
         mAdapter = new SimContactAdapter(getActivity());
 
         final Bundle args = getArguments();
-        mSubscriptionId = args == null ? SimCard.NO_SUBSCRIPTION_ID :
-                args.getInt(ARG_SUBSCRIPTION_ID, SimCard.NO_SUBSCRIPTION_ID);
+        mSubscriptionId =
+                args == null
+                        ? SimCard.NO_SUBSCRIPTION_ID
+                        : args.getInt(ARG_SUBSCRIPTION_ID, SimCard.NO_SUBSCRIPTION_ID);
     }
 
     @Override
@@ -114,15 +120,14 @@ public class SimImportFragment extends Fragment
 
     @Nullable
     @Override
-    public View onCreateView(LayoutInflater inflater, ViewGroup container,
-            Bundle savedInstanceState) {
+    public View onCreateView(
+            LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
         final View view = inflater.inflate(R.layout.fragment_sim_import, container, false);
 
         mAccountHeaderContainer = view.findViewById(R.id.account_header_container);
-        mAccountScrolledElevationPixels = getResources()
-                .getDimension(R.dimen.contact_list_header_elevation);
-        mAccountHeaderPresenter = new AccountHeaderPresenter(
-                mAccountHeaderContainer);
+        mAccountScrolledElevationPixels =
+                getResources().getDimension(R.dimen.contact_list_header_elevation);
+        mAccountHeaderPresenter = new AccountHeaderPresenter(mAccountHeaderContainer);
         if (savedInstanceState != null) {
             mAccountHeaderPresenter.onRestoreInstanceState(savedInstanceState);
         } else {
@@ -130,15 +135,16 @@ public class SimImportFragment extends Fragment
             // after they are loaded.
             mAccountHeaderPresenter.setCurrentAccount(mPreferences.getDefaultAccount());
         }
-        mAccountHeaderPresenter.setObserver(new AccountHeaderPresenter.Observer() {
-            @Override
-            public void onChange(AccountHeaderPresenter sender) {
-                rememberSelectionsForCurrentAccount();
-                mAdapter.setAccount(sender.getCurrentAccount());
-                showSelectionsForCurrentAccount();
-                updateToolbarWithCurrentSelections();
-            }
-        });
+        mAccountHeaderPresenter.setObserver(
+                new AccountHeaderPresenter.Observer() {
+                    @Override
+                    public void onChange(AccountHeaderPresenter sender) {
+                        rememberSelectionsForCurrentAccount();
+                        mAdapter.setAccount(sender.getCurrentAccount());
+                        showSelectionsForCurrentAccount();
+                        updateToolbarWithCurrentSelections();
+                    }
+                });
         mAdapter.setAccount(mAccountHeaderPresenter.getCurrentAccount());
 
         mListView = (ListView) view.findViewById(R.id.list);
@@ -147,24 +153,27 @@ public class SimImportFragment extends Fragment
         mListView.setChoiceMode(AbsListView.CHOICE_MODE_MULTIPLE);
         mListView.setOnItemClickListener(this);
         mImportButton = view.findViewById(R.id.import_button);
-        mImportButton.setOnClickListener(new View.OnClickListener() {
-            @Override
-            public void onClick(View v) {
-                importCurrentSelections();
-                // Do we wait for import to finish?
-                getActivity().setResult(Activity.RESULT_OK);
-                getActivity().finish();
-            }
-        });
+        mImportButton.setOnClickListener(
+                new View.OnClickListener() {
+                    @Override
+                    public void onClick(View v) {
+                        importCurrentSelections();
+                        // Do we wait for import to finish?
+                        getActivity().setResult(Activity.RESULT_OK);
+                        getActivity().finish();
+                    }
+                });
 
         mToolbar = (Toolbar) view.findViewById(R.id.toolbar);
-        mToolbar.setNavigationOnClickListener(new View.OnClickListener() {
-            @Override
-            public void onClick(View v) {
-                getActivity().setResult(Activity.RESULT_CANCELED);
-                getActivity().finish();
-            }
-        });
+        MoreContactUtils.setupEdgeToEdge(getActivity(), new EdgeToEdgeInsetHandler(mToolbar));
+        mToolbar.setNavigationOnClickListener(
+                new View.OnClickListener() {
+                    @Override
+                    public void onClick(View v) {
+                        getActivity().setResult(Activity.RESULT_CANCELED);
+                        getActivity().finish();
+                    }
+                });
 
         mLoadingIndicator = (ContentLoadingProgressBar) view.findViewById(R.id.loading_progress);
 
@@ -188,8 +197,8 @@ public class SimImportFragment extends Fragment
             return;
         }
         for (int i = 0, len = mListView.getCount(); i < len; i++) {
-            mListView.setItemChecked(i,
-                    Arrays.binarySearch(ids, mListView.getItemIdAtPosition(i)) >= 0);
+            mListView.setItemChecked(
+                    i, Arrays.binarySearch(ids, mListView.getItemIdAtPosition(i)) >= 0);
         }
     }
 
@@ -243,8 +252,7 @@ public class SimImportFragment extends Fragment
     }
 
     @Override
-    public void onLoadFinished(Loader<LoaderResult> loader,
-            LoaderResult data) {
+    public void onLoadFinished(Loader<LoaderResult> loader, LoaderResult data) {
         mLoadingIndicator.hide();
         if (data == null) {
             return;
@@ -259,8 +267,7 @@ public class SimImportFragment extends Fragment
     }
 
     @Override
-    public void onLoaderReset(Loader<LoaderResult> loader) {
-    }
+    public void onLoaderReset(Loader<LoaderResult> loader) {}
 
     private void restoreAdapterSelectedStates(List<AccountInfo> accounts) {
         if (mSavedInstanceState == null) {
@@ -268,8 +275,9 @@ public class SimImportFragment extends Fragment
         }
 
         for (AccountInfo account : accounts) {
-            final long[] selections = mSavedInstanceState.getLongArray(
-                    account.getAccount().stringify() + KEY_SUFFIX_SELECTED_IDS);
+            final long[] selections =
+                    mSavedInstanceState.getLongArray(
+                            account.getAccount().stringify() + KEY_SUFFIX_SELECTED_IDS);
             mPerAccountCheckedIds.put(account.getAccount(), selections);
         }
         mSavedInstanceState = null;
@@ -282,8 +290,8 @@ public class SimImportFragment extends Fragment
 
         // Make sure the selections are up-to-date
         for (Map.Entry<AccountWithDataSet, long[]> entry : mPerAccountCheckedIds.entrySet()) {
-            outState.putLongArray(entry.getKey().stringify() + KEY_SUFFIX_SELECTED_IDS,
-                    entry.getValue());
+            outState.putLongArray(
+                    entry.getKey().stringify() + KEY_SUFFIX_SELECTED_IDS, entry.getValue());
         }
     }
 
@@ -297,14 +305,17 @@ public class SimImportFragment extends Fragment
                 importableContacts.add(mAdapter.getItem(checked.keyAt(i)));
             }
         }
-        SimImportService.startImport(getContext(), mSubscriptionId, importableContacts,
+        SimImportService.startImport(
+                getContext(),
+                mSubscriptionId,
+                importableContacts,
                 mAccountHeaderPresenter.getCurrentAccount());
     }
 
     public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
         if (mAdapter.existsInCurrentAccount(position)) {
-            Snackbar.make(getView(), R.string.sim_import_contact_exists_toast,
-                    Snackbar.LENGTH_LONG).show();
+            Snackbar.make(getView(), R.string.sim_import_contact_exists_toast, Snackbar.LENGTH_LONG)
+                    .show();
         } else {
             updateToolbarWithCurrentSelections();
         }
@@ -318,11 +329,11 @@ public class SimImportFragment extends Fragment
     }
 
     @Override
-    public void onScrollStateChanged(AbsListView view, int scrollState) { }
+    public void onScrollStateChanged(AbsListView view, int scrollState) {}
 
     @Override
-    public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount,
-            int totalItemCount) {
+    public void onScroll(
+            AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
         int firstCompletelyVisibleItem = firstVisibleItem;
         if (view != null && view.getChildAt(0) != null && view.getChildAt(0).getTop() < 0) {
             firstCompletelyVisibleItem++;
@@ -335,9 +346,7 @@ public class SimImportFragment extends Fragment
         }
     }
 
-    /**
-     * Creates a fragment that will display contacts stored on the default SIM card
-     */
+    /** Creates a fragment that will display contacts stored on the default SIM card */
     public static SimImportFragment newInstance() {
         return new SimImportFragment();
     }
@@ -394,9 +403,10 @@ public class SimImportFragment extends Fragment
         public View getView(int position, View convertView, ViewGroup parent) {
             TextView text = (TextView) convertView;
             if (text == null) {
-                final int layoutRes = existsInCurrentAccount(position) ?
-                        R.layout.sim_import_list_item_disabled :
-                        R.layout.sim_import_list_item;
+                final int layoutRes =
+                        existsInCurrentAccount(position)
+                                ? R.layout.sim_import_list_item_disabled
+                                : R.layout.sim_import_list_item;
                 text = (TextView) mInflater.inflate(layoutRes, parent, false);
             }
             text.setText(getItemLabel(getItem(position)));
@@ -444,7 +454,6 @@ public class SimImportFragment extends Fragment
         }
     }
 
-
     private static class SimContactLoader extends ListenableFutureLoader<LoaderResult> {
         private SimContactDao mDao;
         private AccountTypeManager mAccountTypeManager;
@@ -459,25 +468,30 @@ public class SimImportFragment extends Fragment
 
         @Override
         protected ListenableFuture<LoaderResult> loadData() {
-            final ListenableFuture<List<Object>> future = Futures.<Object>allAsList(
-                    mAccountTypeManager
-                            .filterAccountsAsync(AccountTypeManager.writableFilter()),
-                    ContactsExecutors.getSimReadExecutor().<Object>submit(
-                            new Callable<Object>() {
+            final ListenableFuture<List<Object>> future =
+                    Futures.<Object>allAsList(
+                            mAccountTypeManager.filterAccountsAsync(
+                                    AccountTypeManager.insertableFilter(getContext())),
+                            ContactsExecutors.getSimReadExecutor()
+                                    .<Object>submit(
+                                            new Callable<Object>() {
+                                                @Override
+                                                public LoaderResult call() throws Exception {
+                                                    return loadFromSim();
+                                                }
+                                            }));
+            return Futures.transform(
+                    future,
+                    new Function<List<Object>, LoaderResult>() {
                         @Override
-                        public LoaderResult call() throws Exception {
-                            return loadFromSim();
+                        public LoaderResult apply(List<Object> input) {
+                            final List<AccountInfo> accounts = (List<AccountInfo>) input.get(0);
+                            final LoaderResult simLoadResult = (LoaderResult) input.get(1);
+                            simLoadResult.accounts = accounts;
+                            return simLoadResult;
                         }
-                    }));
-            return Futures.transform(future, new Function<List<Object>, LoaderResult>() {
-                @Override
-                public LoaderResult apply(List<Object> input) {
-                    final List<AccountInfo> accounts = (List<AccountInfo>) input.get(0);
-                    final LoaderResult simLoadResult = (LoaderResult) input.get(1);
-                    simLoadResult.accounts = accounts;
-                    return simLoadResult;
-                }
-            }, MoreExecutors.directExecutor());
+                    },
+                    MoreExecutors.directExecutor());
         }
 
         private LoaderResult loadFromSim() {
diff --git a/src/com/android/contacts/activities/AttachPhotoActivity.java b/src/com/android/contacts/activities/AttachPhotoActivity.java
index bfa25e6ba..cb62bce22 100644
--- a/src/com/android/contacts/activities/AttachPhotoActivity.java
+++ b/src/com/android/contacts/activities/AttachPhotoActivity.java
@@ -16,7 +16,6 @@
 
 package com.android.contacts.activities;
 
-import android.app.Activity;
 import android.content.ActivityNotFoundException;
 import android.content.ContentResolver;
 import android.content.ContentValues;
@@ -32,8 +31,8 @@ import android.os.Bundle;
 import android.provider.ContactsContract.CommonDataKinds.Photo;
 import android.provider.ContactsContract.Contacts;
 import android.provider.ContactsContract.DisplayPhoto;
-import android.provider.ContactsContract.Intents;
 import android.provider.ContactsContract.RawContacts;
+import android.provider.ContactsContract.Settings;
 import android.util.Log;
 import android.widget.Toast;
 
@@ -52,7 +51,9 @@ import com.android.contacts.model.ValuesDelta;
 import com.android.contacts.model.account.AccountInfo;
 import com.android.contacts.model.account.AccountType;
 import com.android.contacts.model.account.AccountWithDataSet;
+import com.android.contacts.preference.ContactsPreferences;
 import com.android.contacts.util.ContactPhotoUtils;
+
 import com.google.common.base.Preconditions;
 import com.google.common.util.concurrent.Futures;
 import com.google.common.util.concurrent.ListenableFuture;
@@ -61,10 +62,9 @@ import java.io.FileNotFoundException;
 import java.util.List;
 
 /**
- * Provides an external interface for other applications to attach images
- * to contacts. It will first present a contact picker and then run the
- * image that is handed to it through the cropper to make the image the proper
- * size and give the user a chance to use the face detector.
+ * Provides an external interface for other applications to attach images to contacts. It will first
+ * present a contact picker and then run the image that is handed to it through the cropper to make
+ * the image the proper size and give the user a chance to use the face detector.
  */
 public class AttachPhotoActivity extends ContactsActivity {
     private static final String TAG = AttachPhotoActivity.class.getSimpleName();
@@ -119,8 +119,13 @@ public class AttachPhotoActivity extends ContactsActivity {
         // member varible so only need to load this if this is the first time
         // through.
         if (mPhotoDim == 0) {
-            Cursor c = mContentResolver.query(DisplayPhoto.CONTENT_MAX_DIMENSIONS_URI,
-                    new String[]{DisplayPhoto.DISPLAY_MAX_DIM}, null, null, null);
+            Cursor c =
+                    mContentResolver.query(
+                            DisplayPhoto.CONTENT_MAX_DIMENSIONS_URI,
+                            new String[] {DisplayPhoto.DISPLAY_MAX_DIM},
+                            null,
+                            null,
+                            null);
             if (c != null) {
                 try {
                     if (c.moveToFirst()) {
@@ -133,8 +138,9 @@ public class AttachPhotoActivity extends ContactsActivity {
         }
 
         // Start loading accounts in case they are needed.
-        mAccountsFuture = AccountTypeManager.getInstance(this).filterAccountsAsync(
-                AccountTypeManager.writableFilter());
+        mAccountsFuture =
+                AccountTypeManager.getInstance(this)
+                        .filterAccountsAsync(AccountTypeManager.insertableFilter(this));
     }
 
     @Override
@@ -154,23 +160,14 @@ public class AttachPhotoActivity extends ContactsActivity {
     @Override
     protected void onActivityResult(int requestCode, int resultCode, Intent result) {
         if (requestCode == REQUEST_PICK_DEFAULT_ACCOUNT_FOR_NEW_CONTACT) {
+            AccountWithDataSet defaultAccount = new ContactsPreferences(this).getDefaultAccount();
             // Bail if the account selector was not successful.
-            if (resultCode != Activity.RESULT_OK) {
+            if (defaultAccount == null) {
                 Log.w(TAG, "account selector was not successful");
                 finish();
                 return;
             }
-            // If there's an account specified, use it.
-            if (result != null) {
-                AccountWithDataSet account = result.getParcelableExtra(
-                        Intents.Insert.EXTRA_ACCOUNT);
-                if (account != null) {
-                    createNewRawContact(account);
-                    return;
-                }
-            }
-            // If there isn't an account specified, then the user opted to keep the contact local.
-            createNewRawContact(null);
+            createNewRawContact(defaultAccount);
         } else if (requestCode == REQUEST_PICK_CONTACT) {
             if (resultCode != RESULT_OK) {
                 finish();
@@ -181,7 +178,6 @@ public class AttachPhotoActivity extends ContactsActivity {
             final Intent myIntent = getIntent();
             final Uri inputUri = myIntent.getData();
 
-
             // Save the URI into a temporary file provider URI so that
             // we can add the FLAG_GRANT_WRITE_URI_PERMISSION flag to the eventual
             // crop intent for read-only URI's.
@@ -203,12 +199,14 @@ public class AttachPhotoActivity extends ContactsActivity {
                 // without performing any cropping.
                 mCroppedPhotoUri = mTempPhotoUri;
                 mContactUri = result.getData();
-                loadContact(mContactUri, new Listener() {
-                    @Override
-                    public void onContactLoaded(Contact contact) {
-                        saveContact(contact);
-                    }
-                });
+                loadContact(
+                        mContactUri,
+                        new Listener() {
+                            @Override
+                            public void onContactLoaded(Contact contact) {
+                                saveContact(contact);
+                            }
+                        });
                 return;
             }
 
@@ -230,19 +228,24 @@ public class AttachPhotoActivity extends ContactsActivity {
                 finish();
                 return;
             }
-            loadContact(mContactUri, new Listener() {
-                @Override
-                public void onContactLoaded(Contact contact) {
-                    saveContact(contact);
-                }
-            });
+            loadContact(
+                    mContactUri,
+                    new Listener() {
+                        @Override
+                        public void onContactLoaded(Contact contact) {
+                            saveContact(contact);
+                        }
+                    });
         }
     }
 
     private ResolveInfo getIntentHandler(Intent intent) {
-        final List<ResolveInfo> resolveInfos = getPackageManager()
-                .queryIntentActivities(intent,
-                        PackageManager.MATCH_DEFAULT_ONLY | PackageManager.MATCH_SYSTEM_ONLY);
+        final List<ResolveInfo> resolveInfos =
+                getPackageManager()
+                        .queryIntentActivities(
+                                intent,
+                                PackageManager.MATCH_DEFAULT_ONLY
+                                        | PackageManager.MATCH_SYSTEM_ONLY);
         return (resolveInfos != null && resolveInfos.size() > 0) ? resolveInfos.get(0) : null;
     }
 
@@ -252,19 +255,19 @@ public class AttachPhotoActivity extends ContactsActivity {
     // instance, the loader doesn't persist across Activity restarts.
     private void loadContact(Uri contactUri, final Listener listener) {
         final ContactLoader loader = new ContactLoader(this, contactUri, true);
-        loader.registerListener(0, new OnLoadCompleteListener<Contact>() {
-            @Override
-            public void onLoadComplete(
-                    Loader<Contact> loader, Contact contact) {
-                try {
-                    loader.reset();
-                }
-                catch (RuntimeException e) {
-                    Log.e(TAG, "Error resetting loader", e);
-                }
-                listener.onContactLoaded(contact);
-            }
-        });
+        loader.registerListener(
+                0,
+                new OnLoadCompleteListener<Contact>() {
+                    @Override
+                    public void onLoadComplete(Loader<Contact> loader, Contact contact) {
+                        try {
+                            loader.reset();
+                        } catch (RuntimeException e) {
+                            Log.e(TAG, "Error resetting loader", e);
+                        }
+                        listener.onContactLoaded(contact);
+                    }
+                });
         loader.startLoading();
     }
 
@@ -273,10 +276,8 @@ public class AttachPhotoActivity extends ContactsActivity {
     }
 
     /**
-     * If prerequisites have been met, attach the photo to a raw-contact and save.
-     * The prerequisites are:
-     * - photo has been cropped
-     * - contact has been loaded
+     * If prerequisites have been met, attach the photo to a raw-contact and save. The prerequisites
+     * are: - photo has been cropped - contact has been loaded
      */
     private void saveContact(Contact contact) {
 
@@ -298,8 +299,8 @@ public class AttachPhotoActivity extends ContactsActivity {
         saveToContact(contact, deltaList, raw);
     }
 
-    private void saveToContact(Contact contact, RawContactDeltaList deltaList,
-            RawContactDelta raw) {
+    private void saveToContact(
+            Contact contact, RawContactDeltaList deltaList, RawContactDelta raw) {
 
         // Create a scaled, compressed bitmap to add to the entity-delta list.
         final int size = ContactsUtils.getThumbnailSize(this);
@@ -343,15 +344,17 @@ public class AttachPhotoActivity extends ContactsActivity {
         if (Log.isLoggable(TAG, Log.VERBOSE)) {
             Log.v(TAG, "all prerequisites met, about to save photo to contact");
         }
-        Intent intent = ContactSaveService.createSaveContactIntent(
-                this,
-                deltaList,
-                "", 0,
-                contact.isUserProfile(),
-                null, null,
-                raw.getRawContactId() != null ? raw.getRawContactId() : -1,
-                mCroppedPhotoUri
-        );
+        Intent intent =
+                ContactSaveService.createSaveContactIntent(
+                        this,
+                        deltaList,
+                        "",
+                        0,
+                        contact.isUserProfile(),
+                        null,
+                        null,
+                        raw.getRawContactId() != null ? raw.getRawContactId() : -1,
+                        mCroppedPhotoUri);
         ContactSaveService.startService(this, intent);
         finish();
     }
@@ -365,14 +368,16 @@ public class AttachPhotoActivity extends ContactsActivity {
         // Technically this could block but in reality this method won't be called until the user
         // presses the save button which should allow plenty of time for the accounts to
         // finish loading. Note also that this could be stale if the accounts have changed since
-        // we requested them but that's OK since ContactEditorAccountsChangedActivity will reload
-        // the accounts
+        // we requested them but that's OK since account picker will reload the accounts
         final List<AccountInfo> accountInfos = Futures.getUnchecked(mAccountsFuture);
 
         final List<AccountWithDataSet> accounts = AccountInfo.extractAccounts(accountInfos);
         if (editorUtils.shouldShowAccountChangedNotification(accounts)) {
-            Intent intent = new Intent(this, ContactEditorAccountsChangedActivity.class)
-                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
+            Intent intent =
+                    new Intent(Settings.ACTION_SET_DEFAULT_ACCOUNT)
+                            .addFlags(
+                                    Intent.FLAG_ACTIVITY_CLEAR_TOP
+                                            | Intent.FLAG_ACTIVITY_SINGLE_TOP);
             startActivityForResult(intent, REQUEST_PICK_DEFAULT_ACCOUNT_FOR_NEW_CONTACT);
         } else {
             // Otherwise, there should be a default account. Then either create a null contact
@@ -382,26 +387,27 @@ public class AttachPhotoActivity extends ContactsActivity {
         }
     }
 
-    /**
-     * Create a new writeable raw contact to store mCroppedPhotoUri.
-     */
+    /** Create a new writeable raw contact to store mCroppedPhotoUri. */
     private void createNewRawContact(final AccountWithDataSet account) {
         // Reload the contact from URI instead of trying to pull the contact from a member variable,
         // since this function can be called after the activity stops and resumes.
-        loadContact(mContactUri, new Listener() {
-            @Override
-            public void onContactLoaded(Contact contactToSave) {
-                final RawContactDeltaList deltaList = contactToSave.createRawContactDeltaList();
-                final ContentValues after = new ContentValues();
-                after.put(RawContacts.ACCOUNT_TYPE, account != null ? account.type : null);
-                after.put(RawContacts.ACCOUNT_NAME, account != null ? account.name : null);
-                after.put(RawContacts.DATA_SET, account != null ? account.dataSet : null);
-
-                final RawContactDelta newRawContactDelta
-                        = new RawContactDelta(ValuesDelta.fromAfter(after));
-                deltaList.add(newRawContactDelta);
-                saveToContact(contactToSave, deltaList, newRawContactDelta);
-            }
-        });
+        loadContact(
+                mContactUri,
+                new Listener() {
+                    @Override
+                    public void onContactLoaded(Contact contactToSave) {
+                        final RawContactDeltaList deltaList =
+                                contactToSave.createRawContactDeltaList();
+                        final ContentValues after = new ContentValues();
+                        after.put(RawContacts.ACCOUNT_TYPE, account != null ? account.type : null);
+                        after.put(RawContacts.ACCOUNT_NAME, account != null ? account.name : null);
+                        after.put(RawContacts.DATA_SET, account != null ? account.dataSet : null);
+
+                        final RawContactDelta newRawContactDelta =
+                                new RawContactDelta(ValuesDelta.fromAfter(after));
+                        deltaList.add(newRawContactDelta);
+                        saveToContact(contactToSave, deltaList, newRawContactDelta);
+                    }
+                });
     }
 }
diff --git a/src/com/android/contacts/activities/ContactEditorAccountsChangedActivity.java b/src/com/android/contacts/activities/ContactEditorAccountsChangedActivity.java
deleted file mode 100644
index 8f0509bab..000000000
--- a/src/com/android/contacts/activities/ContactEditorAccountsChangedActivity.java
+++ /dev/null
@@ -1,234 +0,0 @@
-/*
- * Copyright (C) 2011 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License
- */
-
-package com.android.contacts.activities;
-
-import android.app.Activity;
-import android.app.AlertDialog;
-import android.content.DialogInterface;
-import android.content.Intent;
-import android.os.Bundle;
-import android.provider.ContactsContract.Intents;
-import android.view.View;
-import android.view.View.OnClickListener;
-import android.widget.AdapterView;
-import android.widget.AdapterView.OnItemClickListener;
-import android.widget.Button;
-import android.widget.ListView;
-import android.widget.TextView;
-
-import com.android.contacts.R;
-import com.android.contacts.editor.ContactEditorUtils;
-import com.android.contacts.model.AccountTypeManager;
-import com.android.contacts.model.account.AccountInfo;
-import com.android.contacts.model.account.AccountWithDataSet;
-import com.android.contacts.model.account.AccountsLoader;
-import com.android.contacts.util.AccountsListAdapter;
-import com.android.contacts.util.ImplicitIntentsUtil;
-
-import java.util.List;
-
-/**
- * This activity can be shown to the user when creating a new contact to inform the user about
- * which account the contact will be saved in. There is also an option to add an account at
- * this time. The {@link Intent} in the activity result will contain an extra
- * {@link #Intents.Insert.ACCOUNT} that contains the {@link AccountWithDataSet} to create
- * the new contact in. If the activity result doesn't contain intent data, then there is no
- * account for this contact.
- */
-public class ContactEditorAccountsChangedActivity extends Activity
-        implements AccountsLoader.AccountsListener {
-    private static final int SUBACTIVITY_ADD_NEW_ACCOUNT = 1;
-
-    private AccountsListAdapter mAccountListAdapter;
-    private ContactEditorUtils mEditorUtils;
-    private AlertDialog mDialog;
-
-    private final OnItemClickListener mAccountListItemClickListener = new OnItemClickListener() {
-        @Override
-        public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
-            if (mAccountListAdapter == null) {
-                return;
-            }
-            saveAccountAndReturnResult(mAccountListAdapter.getItem(position));
-        }
-    };
-
-    private final OnClickListener mAddAccountClickListener = new OnClickListener() {
-        @Override
-        public void onClick(View v) {
-            final Intent intent = ImplicitIntentsUtil.getIntentForAddingGoogleAccount();
-            startActivityForResult(intent, SUBACTIVITY_ADD_NEW_ACCOUNT);
-        }
-    };
-
-    @Override
-    protected void onResume() {
-        super.onResume();
-        if (mDialog != null && !mDialog.isShowing()) {
-            mDialog.show();
-        }
-    }
-
-    @Override
-    protected void onPause() {
-        super.onPause();
-        if (mDialog != null) {
-            mDialog.dismiss();
-        }
-    }
-
-    @Override
-    protected void onCreate(Bundle savedInstanceState) {
-        super.onCreate(savedInstanceState);
-        mEditorUtils = ContactEditorUtils.create(this);
-        AccountsLoader.loadAccounts(this, 0, AccountTypeManager.writableFilter());
-    }
-
-    @Override
-    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
-        if (requestCode == SUBACTIVITY_ADD_NEW_ACCOUNT) {
-            // If the user canceled the account setup process, then keep this activity visible to
-            // the user.
-            if (resultCode != RESULT_OK) {
-                return;
-            }
-            // Subactivity was successful, so pass the result back and finish the activity.
-            AccountWithDataSet account = mEditorUtils.getCreatedAccount(resultCode, data);
-            if (account == null) {
-                setResult(resultCode);
-                finish();
-                return;
-            }
-            saveAccountAndReturnResult(account);
-        }
-    }
-
-    private void updateDisplayedAccounts(List<AccountInfo> accounts) {
-        final int numAccounts = accounts.size();
-        if (numAccounts < 0) {
-            throw new IllegalStateException("Cannot have a negative number of accounts");
-        }
-
-        final View view;
-        if (numAccounts >= 2) {
-            // When the user has 2+ writable accounts, show a list of accounts so the user can pick
-            // which account to create a contact in.
-            view = View.inflate(this,
-                    R.layout.contact_editor_accounts_changed_activity_with_picker, null);
-
-            final TextView textView = (TextView) view.findViewById(R.id.text);
-            textView.setText(getString(R.string.contact_editor_prompt_multiple_accounts));
-
-            final Button button = (Button) view.findViewById(R.id.add_account_button);
-            button.setText(getString(R.string.add_new_account));
-            button.setOnClickListener(mAddAccountClickListener);
-
-            final ListView accountListView = (ListView) view.findViewById(R.id.account_list);
-            mAccountListAdapter = new AccountsListAdapter(this, accounts);
-            accountListView.setAdapter(mAccountListAdapter);
-            accountListView.setOnItemClickListener(mAccountListItemClickListener);
-        } else if (numAccounts == 1
-                && !accounts.get(0).getAccount().equals(AccountWithDataSet.getLocalAccount(this))) {
-            // If the user has 1 writable account we will just show the user a message with 2
-            // possible action buttons.
-            view = View.inflate(this,
-                    R.layout.contact_editor_accounts_changed_activity_with_text, null);
-
-            final TextView textView = (TextView) view.findViewById(R.id.text);
-            final Button leftButton = (Button) view.findViewById(R.id.left_button);
-            final Button rightButton = (Button) view.findViewById(R.id.right_button);
-
-            final AccountInfo accountInfo = accounts.get(0);
-            textView.setText(getString(R.string.contact_editor_prompt_one_account,
-                    accountInfo.getNameLabel()));
-
-            // This button allows the user to add a new account to the device and return to
-            // this app afterwards.
-            leftButton.setText(getString(R.string.add_new_account));
-            leftButton.setOnClickListener(mAddAccountClickListener);
-
-            // This button allows the user to continue creating the contact in the specified
-            // account.
-            rightButton.setText(getString(android.R.string.ok));
-            rightButton.setOnClickListener(new OnClickListener() {
-                @Override
-                public void onClick(View v) {
-                    saveAccountAndReturnResult(accountInfo.getAccount());
-                }
-            });
-        } else {
-            // If the user has 0 writable accounts, we will just show the user a message with 2
-            // possible action buttons.
-            view = View.inflate(this,
-                    R.layout.contact_editor_accounts_changed_activity_with_text, null);
-
-            final TextView textView = (TextView) view.findViewById(R.id.text);
-            final Button leftButton = (Button) view.findViewById(R.id.left_button);
-            final Button rightButton = (Button) view.findViewById(R.id.right_button);
-
-            textView.setText(getString(R.string.contact_editor_prompt_zero_accounts));
-
-            // This button allows the user to continue editing the contact as a phone-only
-            // local contact.
-            leftButton.setText(getString(android.R.string.cancel));
-            leftButton.setOnClickListener(new OnClickListener() {
-                @Override
-                public void onClick(View v) {
-                    // Remember that the user wants to create local contacts, so the user is not
-                    // prompted again with this activity.
-                    saveAccountAndReturnResult(AccountWithDataSet.getNullAccount());
-                    finish();
-                }
-            });
-
-            // This button allows the user to add a new account to the device and return to
-            // this app afterwards.
-            rightButton.setText(getString(R.string.add_account));
-            rightButton.setOnClickListener(mAddAccountClickListener);
-        }
-
-        if (mDialog != null && mDialog.isShowing()) {
-            mDialog.dismiss();
-        }
-        mDialog = new AlertDialog.Builder(this)
-                .setView(view)
-                .setOnCancelListener(new DialogInterface.OnCancelListener() {
-                    @Override
-                    public void onCancel(DialogInterface dialog) {
-                        finish();
-                    }
-                })
-                .create();
-        mDialog.show();
-    }
-
-    private void saveAccountAndReturnResult(AccountWithDataSet account) {
-        // Save this as the default account
-        mEditorUtils.saveDefaultAccount(account);
-
-        // Pass account info in activity result intent
-        Intent intent = new Intent();
-        intent.putExtra(Intents.Insert.EXTRA_ACCOUNT, account);
-        setResult(RESULT_OK, intent);
-        finish();
-    }
-
-    @Override
-    public void onAccountsLoaded(List<AccountInfo> accounts) {
-        updateDisplayedAccounts(accounts);
-    }
-}
diff --git a/src/com/android/contacts/activities/ContactEditorActivity.java b/src/com/android/contacts/activities/ContactEditorActivity.java
index 2af25f847..a27e7e76e 100644
--- a/src/com/android/contacts/activities/ContactEditorActivity.java
+++ b/src/com/android/contacts/activities/ContactEditorActivity.java
@@ -17,21 +17,20 @@
 package com.android.contacts.activities;
 
 import android.app.Dialog;
-import android.app.FragmentTransaction;
 import android.content.ComponentName;
 import android.content.ContentValues;
 import android.content.Intent;
 import android.net.Uri;
 import android.os.Bundle;
-import android.provider.ContactsContract.QuickContact;
-import androidx.appcompat.widget.Toolbar;
 import android.util.Log;
-import android.view.View;
-import android.view.inputmethod.InputMethodManager;
+
+import androidx.appcompat.widget.Toolbar;
 
 import com.android.contacts.AppCompatContactsActivity;
 import com.android.contacts.ContactSaveService;
 import com.android.contacts.DynamicShortcuts;
+import com.android.contacts.MoreContactUtils;
+import com.android.contacts.MoreContactUtils.EdgeToEdgeInsetHandler;
 import com.android.contacts.R;
 import com.android.contacts.detail.PhotoSelectionHandler;
 import com.android.contacts.editor.ContactEditorFragment;
@@ -45,12 +44,9 @@ import com.android.contacts.util.ImplicitIntentsUtil;
 import java.io.FileNotFoundException;
 import java.util.ArrayList;
 
-/**
- * Contact editor with only the most important fields displayed initially.
- */
-public class ContactEditorActivity extends AppCompatContactsActivity implements
-        PhotoSourceDialogFragment.Listener,
-        DialogManager.DialogShowingViewActivity {
+/** Contact editor with only the most important fields displayed initially. */
+public class ContactEditorActivity extends AppCompatContactsActivity
+        implements PhotoSourceDialogFragment.Listener, DialogManager.DialogShowingViewActivity {
     private static final String TAG = "ContactEditorActivity";
 
     public static final String ACTION_JOIN_COMPLETED = "joinCompleted";
@@ -61,10 +57,10 @@ public class ContactEditorActivity extends AppCompatContactsActivity implements
     public static final int RESULT_CODE_EDITED = 4;
 
     /**
-     * The contact will be saved to this account when this is set for an insert. This
-     * is necessary because {@link android.accounts.Account} cannot be created with null values
-     * for the name and type and an Account is needed for
-     * {@link android.provider.ContactsContract.Intents.Insert#EXTRA_ACCOUNT}
+     * The contact will be saved to this account when this is set for an insert. This is necessary
+     * because {@link android.accounts.Account} cannot be created with null values for the name and
+     * type and an Account is needed for {@link
+     * android.provider.ContactsContract.Intents.Insert#EXTRA_ACCOUNT}
      */
     public static final String EXTRA_ACCOUNT_WITH_DATA_SET =
             "com.android.contacts.ACCOUNT_WITH_DATA_SET";
@@ -76,101 +72,69 @@ public class ContactEditorActivity extends AppCompatContactsActivity implements
     private static final String STATE_PHOTO_URI = "photo_uri";
 
     /**
-     * Boolean intent key that specifies that this activity should finish itself
-     * (instead of launching a new view intent) after the editor changes have been
-     * saved.
+     * Boolean intent key that specifies that this activity should finish itself (instead of
+     * launching a new view intent) after the editor changes have been saved.
      */
     public static final String INTENT_KEY_FINISH_ACTIVITY_ON_SAVE_COMPLETED =
             "finishActivityOnSaveCompleted";
 
-    /**
-     * Contract for contact editors Fragments that are managed by this Activity.
-     */
+    /** Contract for contact editors Fragments that are managed by this Activity. */
     public interface ContactEditor {
 
-        /**
-         * Modes that specify what the AsyncTask has to perform after saving
-         */
+        /** Modes that specify what the AsyncTask has to perform after saving */
         interface SaveMode {
-            /**
-             * Close the editor after saving
-             */
+            /** Close the editor after saving */
             int CLOSE = 0;
 
-            /**
-             * Reload the data so that the user can continue editing
-             */
+            /** Reload the data so that the user can continue editing */
             int RELOAD = 1;
 
-            /**
-             * Split the contact after saving
-             */
+            /** Split the contact after saving */
             int SPLIT = 2;
 
-            /**
-             * Join another contact after saving
-             */
+            /** Join another contact after saving */
             int JOIN = 3;
 
-            /**
-             * Navigate to the editor view after saving.
-             */
+            /** Navigate to the editor view after saving. */
             int EDITOR = 4;
         }
 
-        /**
-         * The status of the contact editor.
-         */
+        /** The status of the contact editor. */
         interface Status {
-            /**
-             * The loader is fetching data
-             */
+            /** The loader is fetching data */
             int LOADING = 0;
 
-            /**
-             * Not currently busy. We are waiting for the user to enter data
-             */
+            /** Not currently busy. We are waiting for the user to enter data */
             int EDITING = 1;
 
             /**
-             * The data is currently being saved. This is used to prevent more
-             * auto-saves (they shouldn't overlap)
+             * The data is currently being saved. This is used to prevent more auto-saves (they
+             * shouldn't overlap)
              */
             int SAVING = 2;
 
             /**
-             * Prevents any more saves. This is used if in the following cases:
-             * - After Save/Close
-             * - After Revert
-             * - After the user has accepted an edit suggestion
-             * - After the user chooses to expand the editor
+             * Prevents any more saves. This is used if in the following cases: - After Save/Close -
+             * After Revert - After the user has accepted an edit suggestion - After the user
+             * chooses to expand the editor
              */
             int CLOSING = 3;
 
-            /**
-             * Prevents saving while running a child activity.
-             */
+            /** Prevents saving while running a child activity. */
             int SUB_ACTIVITY = 4;
         }
 
-        /**
-         * Sets the hosting Activity that will receive callbacks from the contact editor.
-         */
+        /** Sets the hosting Activity that will receive callbacks from the contact editor. */
         void setListener(ContactEditorFragment.Listener listener);
 
-        /**
-         * Initialize the contact editor.
-         */
+        /** Initialize the contact editor. */
         void load(String action, Uri lookupUri, Bundle intentExtras);
 
-        /**
-         * Applies extras from the hosting Activity to the writable raw contact.
-         */
+        /** Applies extras from the hosting Activity to the writable raw contact. */
         void setIntentExtras(Bundle extras);
 
         /**
-         * Saves or creates the contact based on the mode, and if successful
-         * finishes the activity.
+         * Saves or creates the contact based on the mode, and if successful finishes the activity.
          */
         boolean save(int saveMode);
 
@@ -180,26 +144,22 @@ public class ContactEditorActivity extends AppCompatContactsActivity implements
          */
         boolean revert();
 
-        /**
-         * Invoked after the contact is saved.
-         */
-        void onSaveCompleted(boolean hadChanges, int saveMode, boolean saveSucceeded,
-                Uri contactLookupUri, Long joinContactId);
+        /** Invoked after the contact is saved. */
+        void onSaveCompleted(
+                boolean hadChanges,
+                int saveMode,
+                boolean saveSucceeded,
+                Uri contactLookupUri,
+                Long joinContactId);
 
-        /**
-         * Invoked after the contact is joined.
-         */
+        /** Invoked after the contact is joined. */
         void onJoinCompleted(Uri uri);
     }
 
-    /**
-     * Displays a PopupWindow with photo edit options.
-     */
+    /** Displays a PopupWindow with photo edit options. */
     private final class EditorPhotoSelectionHandler extends PhotoSelectionHandler {
 
-        /**
-         * Receiver of photo edit option callbacks.
-         */
+        /** Receiver of photo edit option callbacks. */
         private final class EditorPhotoActionListener extends PhotoActionListener {
 
             @Override
@@ -224,8 +184,7 @@ public class ContactEditorActivity extends AppCompatContactsActivity implements
             }
 
             @Override
-            public void onPhotoSelectionDismissed() {
-            }
+            public void onPhotoSelectionDismissed() {}
         }
 
         private final EditorPhotoActionListener mPhotoActionListener;
@@ -236,8 +195,12 @@ public class ContactEditorActivity extends AppCompatContactsActivity implements
             // be anchored at changeAnchorView).
 
             // TODO: empty raw contact delta list
-            super(ContactEditorActivity.this, /* changeAnchorView =*/ null, photoMode,
-                    /* isDirectoryContact =*/ false, new RawContactDeltaList());
+            super(
+                    ContactEditorActivity.this,
+                    /* changeAnchorView= */ null,
+                    photoMode,
+                    /* isDirectoryContact= */ false,
+                    new RawContactDeltaList());
             mPhotoActionListener = new EditorPhotoActionListener();
         }
 
@@ -263,13 +226,12 @@ public class ContactEditorActivity extends AppCompatContactsActivity implements
     private Uri mPhotoUri;
     private int mPhotoMode;
 
-    private final ContactEditorFragment.Listener  mFragmentListener =
+    private final ContactEditorFragment.Listener mFragmentListener =
             new ContactEditorFragment.Listener() {
 
                 @Override
                 public void onDeleteRequested(Uri contactUri) {
-                    ContactDeletionInteraction.start(
-                            ContactEditorActivity.this, contactUri, true);
+                    ContactDeletionInteraction.start(ContactEditorActivity.this, contactUri, true);
                 }
 
                 @Override
@@ -302,10 +264,13 @@ public class ContactEditorActivity extends AppCompatContactsActivity implements
                 @Override
                 public void onEditOtherRawContactRequested(
                         Uri contactLookupUri, long rawContactId, ArrayList<ContentValues> values) {
-                    final Intent intent = EditorIntents.createEditOtherRawContactIntent(
-                            ContactEditorActivity.this, contactLookupUri, rawContactId, values);
-                    ImplicitIntentsUtil.startActivityInApp(
-                            ContactEditorActivity.this, intent);
+                    final Intent intent =
+                            EditorIntents.createEditOtherRawContactIntent(
+                                    ContactEditorActivity.this,
+                                    contactLookupUri,
+                                    rawContactId,
+                                    values);
+                    ImplicitIntentsUtil.startActivityInApp(ContactEditorActivity.this, intent);
                     finish();
                 }
             };
@@ -329,8 +294,8 @@ public class ContactEditorActivity extends AppCompatContactsActivity implements
         // Determine whether or not this activity should be finished after the user is done
         // editing the contact or if this activity should launch another activity to view the
         // contact's details.
-        mFinishActivityOnSaveCompleted = intent.getBooleanExtra(
-                INTENT_KEY_FINISH_ACTIVITY_ON_SAVE_COMPLETED, false);
+        mFinishActivityOnSaveCompleted =
+                intent.getBooleanExtra(INTENT_KEY_FINISH_ACTIVITY_ON_SAVE_COMPLETED, false);
 
         // The only situation where action could be ACTION_JOIN_COMPLETED is if the
         // user joined the contact with another and closed the activity before
@@ -347,6 +312,7 @@ public class ContactEditorActivity extends AppCompatContactsActivity implements
 
         setContentView(R.layout.contact_editor_activity);
         mToolbar = (Toolbar) findViewById(R.id.toolbar);
+        MoreContactUtils.setupEdgeToEdge(this, new EdgeToEdgeInsetHandler(mToolbar));
         setSupportActionBar(mToolbar);
         if (Intent.ACTION_EDIT.equals(action)) {
             mActionBarTitleResId = R.string.contact_editor_title_existing_contact;
@@ -358,7 +324,7 @@ public class ContactEditorActivity extends AppCompatContactsActivity implements
         setTitle(mActionBarTitleResId);
 
         mFragment =
-            (ContactEditor) getFragmentManager().findFragmentById(R.id.contact_editor_fragment);
+                (ContactEditor) getFragmentManager().findFragmentById(R.id.contact_editor_fragment);
 
         if (savedState != null) {
             // Restore state
@@ -393,8 +359,10 @@ public class ContactEditorActivity extends AppCompatContactsActivity implements
         if (Intent.ACTION_EDIT.equals(action)) {
             mFragment.setIntentExtras(intent.getExtras());
         } else if (ACTION_SAVE_COMPLETED.equals(action)) {
-            mFragment.onSaveCompleted(true,
-                    intent.getIntExtra(ContactEditorFragment.SAVE_MODE_EXTRA_KEY,
+            mFragment.onSaveCompleted(
+                    true,
+                    intent.getIntExtra(
+                            ContactEditorFragment.SAVE_MODE_EXTRA_KEY,
                             ContactEditor.SaveMode.CLOSE),
                     intent.getBooleanExtra(ContactSaveService.EXTRA_SAVE_SUCCEEDED, false),
                     intent.getData(),
@@ -423,8 +391,8 @@ public class ContactEditorActivity extends AppCompatContactsActivity implements
         super.onSaveInstanceState(outState);
         outState.putInt(STATE_PHOTO_MODE, mPhotoMode);
         outState.putInt(STATE_ACTION_BAR_TITLE, mActionBarTitleResId);
-        outState.putString(STATE_PHOTO_URI,
-                mPhotoUri != null ? mPhotoUri.toString() : Uri.EMPTY.toString());
+        outState.putString(
+                STATE_PHOTO_URI, mPhotoUri != null ? mPhotoUri.toString() : Uri.EMPTY.toString());
     }
 
     @Override
diff --git a/src/com/android/contacts/activities/ContactSelectionActivity.java b/src/com/android/contacts/activities/ContactSelectionActivity.java
index 9273c612f..80351e4c5 100644
--- a/src/com/android/contacts/activities/ContactSelectionActivity.java
+++ b/src/com/android/contacts/activities/ContactSelectionActivity.java
@@ -24,8 +24,6 @@ import android.graphics.drawable.Drawable;
 import android.net.Uri;
 import android.os.Bundle;
 import android.provider.ContactsContract.Contacts;
-import androidx.core.content.ContextCompat;
-import androidx.appcompat.widget.Toolbar;
 import android.text.TextUtils;
 import android.util.Log;
 import android.view.Menu;
@@ -37,7 +35,12 @@ import android.view.View.OnFocusChangeListener;
 import android.widget.TextView;
 import android.widget.Toast;
 
+import androidx.appcompat.widget.Toolbar;
+import androidx.core.content.ContextCompat;
+
 import com.android.contacts.AppCompatContactsActivity;
+import com.android.contacts.MoreContactUtils;
+import com.android.contacts.MoreContactUtils.EdgeToEdgeInsetHandler;
 import com.android.contacts.R;
 import com.android.contacts.editor.EditorIntents;
 import com.android.contacts.list.ContactEntryListFragment;
@@ -67,12 +70,15 @@ import com.android.contacts.util.ViewUtil;
 import java.util.ArrayList;
 
 /**
- * Displays a list of contacts (or phone numbers or postal addresses) for the
- * purposes of selecting one.
+ * Displays a list of contacts (or phone numbers or postal addresses) for the purposes of selecting
+ * one.
  */
-public class ContactSelectionActivity extends AppCompatContactsActivity implements
-        View.OnCreateContextMenuListener, ActionBarAdapter.Listener, OnClickListener,
-        OnFocusChangeListener, OnCheckBoxListActionListener {
+public class ContactSelectionActivity extends AppCompatContactsActivity
+        implements View.OnCreateContextMenuListener,
+                ActionBarAdapter.Listener,
+                OnClickListener,
+                OnFocusChangeListener,
+                OnCheckBoxListActionListener {
     private static final String TAG = "ContactSelection";
 
     private static final String KEY_ACTION_CODE = "actionCode";
@@ -145,23 +151,27 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
 
     private void prepareSearchViewAndActionBar(Bundle savedState) {
         mToolbar = getView(R.id.toolbar);
+        MoreContactUtils.setupEdgeToEdge(
+                this, new EdgeToEdgeInsetHandler(findViewById(R.id.toolbar_frame)));
         setSupportActionBar(mToolbar);
 
         // Add a shadow under the toolbar.
         ViewUtil.addRectangularOutlineProvider(findViewById(R.id.toolbar_parent), getResources());
 
-        mActionBarAdapter = new ActionBarAdapter(this, this, getSupportActionBar(), mToolbar,
-                R.string.enter_contact_name);
+        mActionBarAdapter =
+                new ActionBarAdapter(
+                        this, this, getSupportActionBar(), mToolbar, R.string.enter_contact_name);
         mActionBarAdapter.setShowHomeIcon(true);
         mActionBarAdapter.setShowHomeAsUp(true);
         mActionBarAdapter.initialize(savedState, mRequest);
 
         // Postal address pickers (and legacy pickers) don't support search, so just show
         // "HomeAsUp" button and title.
-        mIsSearchSupported = mRequest.getActionCode() != ContactsRequest.ACTION_PICK_POSTAL
-                && mRequest.getActionCode() != ContactsRequest.ACTION_PICK_EMAILS
-                && mRequest.getActionCode() != ContactsRequest.ACTION_PICK_PHONES
-                && !mRequest.isLegacyCompatibilityMode();
+        mIsSearchSupported =
+                mRequest.getActionCode() != ContactsRequest.ACTION_PICK_POSTAL
+                        && mRequest.getActionCode() != ContactsRequest.ACTION_PICK_EMAILS
+                        && mRequest.getActionCode() != ContactsRequest.ACTION_PICK_PHONES
+                        && !mRequest.isLegacyCompatibilityMode();
         configureSearchMode();
     }
 
@@ -173,7 +183,7 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
     @Override
     public boolean onOptionsItemSelected(MenuItem item) {
         final int id = item.getItemId();
-        if (id == android.R.id.home) {// Go back to previous screen, intending "cancel"
+        if (id == android.R.id.home) { // Go back to previous screen, intending "cancel"
             setResult(RESULT_CANCELED);
             onBackPressed();
         } else if (id == R.id.menu_search) {
@@ -203,173 +213,198 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
         int titleResId = -1;
         int actionCode = mRequest.getActionCode();
         switch (actionCode) {
-            case ContactsRequest.ACTION_INSERT_OR_EDIT_CONTACT: {
-                titleResId = R.string.contactInsertOrEditActivityTitle;
-                break;
-            }
-            case ContactsRequest.ACTION_PICK_CONTACT: {
-                titleResId = R.string.contactPickerActivityTitle;
-                break;
-            }
-            case ContactsRequest.ACTION_PICK_OR_CREATE_CONTACT: {
-                titleResId = R.string.contactPickerActivityTitle;
-                break;
-            }
-            case ContactsRequest.ACTION_CREATE_SHORTCUT_CONTACT: {
-                titleResId = R.string.shortcutActivityTitle;
-                break;
-            }
-            case ContactsRequest.ACTION_PICK_PHONE: {
-                titleResId = R.string.contactPickerActivityTitle;
-                break;
-            }
-            case ContactsRequest.ACTION_PICK_EMAIL: {
-                titleResId = R.string.contactPickerActivityTitle;
-                break;
-            }
-            case ContactsRequest.ACTION_PICK_PHONES: {
-                titleResId = R.string.pickerSelectContactsActivityTitle;
-                break;
-            }
-            case ContactsRequest.ACTION_PICK_EMAILS: {
-                titleResId = R.string.pickerSelectContactsActivityTitle;
-                break;
-            }
-            case ContactsRequest.ACTION_CREATE_SHORTCUT_CALL: {
-                titleResId = R.string.shortcutActivityTitle;
-                break;
-            }
-            case ContactsRequest.ACTION_CREATE_SHORTCUT_SMS: {
-                titleResId = R.string.shortcutActivityTitle;
-                break;
-            }
-            case ContactsRequest.ACTION_PICK_POSTAL: {
-                titleResId = R.string.contactPickerActivityTitle;
-                break;
-            }
-            case ContactsRequest.ACTION_PICK_JOIN: {
-                titleResId = R.string.titleJoinContactDataWith;
-                break;
-            }
-            case ContactsRequest.ACTION_PICK_GROUP_MEMBERS: {
-                titleResId = R.string.groupMemberPickerActivityTitle;
-                break;
-            }
+            case ContactsRequest.ACTION_INSERT_OR_EDIT_CONTACT:
+                {
+                    titleResId = R.string.contactInsertOrEditActivityTitle;
+                    break;
+                }
+            case ContactsRequest.ACTION_PICK_CONTACT:
+                {
+                    titleResId = R.string.contactPickerActivityTitle;
+                    break;
+                }
+            case ContactsRequest.ACTION_PICK_OR_CREATE_CONTACT:
+                {
+                    titleResId = R.string.contactPickerActivityTitle;
+                    break;
+                }
+            case ContactsRequest.ACTION_CREATE_SHORTCUT_CONTACT:
+                {
+                    titleResId = R.string.shortcutActivityTitle;
+                    break;
+                }
+            case ContactsRequest.ACTION_PICK_PHONE:
+                {
+                    titleResId = R.string.contactPickerActivityTitle;
+                    break;
+                }
+            case ContactsRequest.ACTION_PICK_EMAIL:
+                {
+                    titleResId = R.string.contactPickerActivityTitle;
+                    break;
+                }
+            case ContactsRequest.ACTION_PICK_PHONES:
+                {
+                    titleResId = R.string.pickerSelectContactsActivityTitle;
+                    break;
+                }
+            case ContactsRequest.ACTION_PICK_EMAILS:
+                {
+                    titleResId = R.string.pickerSelectContactsActivityTitle;
+                    break;
+                }
+            case ContactsRequest.ACTION_CREATE_SHORTCUT_CALL:
+                {
+                    titleResId = R.string.shortcutActivityTitle;
+                    break;
+                }
+            case ContactsRequest.ACTION_CREATE_SHORTCUT_SMS:
+                {
+                    titleResId = R.string.shortcutActivityTitle;
+                    break;
+                }
+            case ContactsRequest.ACTION_PICK_POSTAL:
+                {
+                    titleResId = R.string.contactPickerActivityTitle;
+                    break;
+                }
+            case ContactsRequest.ACTION_PICK_JOIN:
+                {
+                    titleResId = R.string.titleJoinContactDataWith;
+                    break;
+                }
+            case ContactsRequest.ACTION_PICK_GROUP_MEMBERS:
+                {
+                    titleResId = R.string.groupMemberPickerActivityTitle;
+                    break;
+                }
         }
         if (titleResId > 0) {
             getSupportActionBar().setTitle(titleResId);
         }
     }
 
-    /**
-     * Creates the fragment based on the current request.
-     */
+    /** Creates the fragment based on the current request. */
     public void configureListFragment() {
         switch (mActionCode) {
-            case ContactsRequest.ACTION_INSERT_OR_EDIT_CONTACT: {
-                ContactPickerFragment fragment = new ContactPickerFragment();
-                fragment.setEditMode(true);
-                fragment.setDirectorySearchMode(DirectoryListLoader.SEARCH_MODE_NONE);
-                fragment.setCreateContactEnabled(!mRequest.isSearchMode());
-                fragment.setListType(ListEvent.ListType.PICK_CONTACT);
-                mListFragment = fragment;
-                break;
-            }
+            case ContactsRequest.ACTION_INSERT_OR_EDIT_CONTACT:
+                {
+                    ContactPickerFragment fragment = new ContactPickerFragment();
+                    fragment.setEditMode(true);
+                    fragment.setDirectorySearchMode(DirectoryListLoader.SEARCH_MODE_NONE);
+                    fragment.setCreateContactEnabled(!mRequest.isSearchMode());
+                    fragment.setListType(ListEvent.ListType.PICK_CONTACT);
+                    mListFragment = fragment;
+                    break;
+                }
 
             case ContactsRequest.ACTION_DEFAULT:
-            case ContactsRequest.ACTION_PICK_CONTACT: {
-                ContactPickerFragment fragment = new ContactPickerFragment();
-                fragment.setIncludeFavorites(mRequest.shouldIncludeFavorites());
-                fragment.setListType(ListEvent.ListType.PICK_CONTACT);
-                mListFragment = fragment;
-                break;
-            }
+            case ContactsRequest.ACTION_PICK_CONTACT:
+                {
+                    ContactPickerFragment fragment = new ContactPickerFragment();
+                    fragment.setIncludeFavorites(mRequest.shouldIncludeFavorites());
+                    fragment.setListType(ListEvent.ListType.PICK_CONTACT);
+                    mListFragment = fragment;
+                    break;
+                }
 
-            case ContactsRequest.ACTION_PICK_OR_CREATE_CONTACT: {
-                ContactPickerFragment fragment = new ContactPickerFragment();
-                fragment.setCreateContactEnabled(!mRequest.isSearchMode());
-                fragment.setListType(ListEvent.ListType.PICK_CONTACT);
-                mListFragment = fragment;
-                break;
-            }
+            case ContactsRequest.ACTION_PICK_OR_CREATE_CONTACT:
+                {
+                    ContactPickerFragment fragment = new ContactPickerFragment();
+                    fragment.setCreateContactEnabled(!mRequest.isSearchMode());
+                    fragment.setListType(ListEvent.ListType.PICK_CONTACT);
+                    mListFragment = fragment;
+                    break;
+                }
 
-            case ContactsRequest.ACTION_CREATE_SHORTCUT_CONTACT: {
-                ContactPickerFragment fragment = new ContactPickerFragment();
-                fragment.setShortcutRequested(true);
-                fragment.setListType(ListEvent.ListType.PICK_CONTACT_FOR_SHORTCUT);
-                mListFragment = fragment;
-                break;
-            }
+            case ContactsRequest.ACTION_CREATE_SHORTCUT_CONTACT:
+                {
+                    ContactPickerFragment fragment = new ContactPickerFragment();
+                    fragment.setShortcutRequested(true);
+                    fragment.setListType(ListEvent.ListType.PICK_CONTACT_FOR_SHORTCUT);
+                    mListFragment = fragment;
+                    break;
+                }
 
-            case ContactsRequest.ACTION_PICK_PHONE: {
-                PhoneNumberPickerFragment fragment = getPhoneNumberPickerFragment(mRequest);
-                fragment.setListType(ListEvent.ListType.PICK_PHONE);
-                mListFragment = fragment;
-                break;
-            }
+            case ContactsRequest.ACTION_PICK_PHONE:
+                {
+                    PhoneNumberPickerFragment fragment = getPhoneNumberPickerFragment(mRequest);
+                    fragment.setListType(ListEvent.ListType.PICK_PHONE);
+                    mListFragment = fragment;
+                    break;
+                }
 
-            case ContactsRequest.ACTION_PICK_EMAIL: {
-                mListFragment = new EmailAddressPickerFragment();
-                mListFragment.setListType(ListEvent.ListType.PICK_EMAIL);
-                break;
-            }
+            case ContactsRequest.ACTION_PICK_EMAIL:
+                {
+                    mListFragment = new EmailAddressPickerFragment();
+                    mListFragment.setListType(ListEvent.ListType.PICK_EMAIL);
+                    break;
+                }
 
-            case ContactsRequest.ACTION_PICK_PHONES: {
-                mListFragment = new MultiSelectPhoneNumbersListFragment();
-                mListFragment.setArguments(getIntent().getExtras());
-                break;
-            }
+            case ContactsRequest.ACTION_PICK_PHONES:
+                {
+                    mListFragment = new MultiSelectPhoneNumbersListFragment();
+                    mListFragment.setArguments(getIntent().getExtras());
+                    break;
+                }
 
-            case ContactsRequest.ACTION_PICK_EMAILS: {
-                mListFragment = new MultiSelectEmailAddressesListFragment();
-                mListFragment.setArguments(getIntent().getExtras());
-                break;
-            }
-            case ContactsRequest.ACTION_CREATE_SHORTCUT_CALL: {
-                PhoneNumberPickerFragment fragment = getPhoneNumberPickerFragment(mRequest);
-                fragment.setShortcutAction(Intent.ACTION_CALL);
-                fragment.setListType(ListEvent.ListType.PICK_CONTACT_FOR_SHORTCUT);
-                mListFragment = fragment;
-                break;
-            }
+            case ContactsRequest.ACTION_PICK_EMAILS:
+                {
+                    mListFragment = new MultiSelectEmailAddressesListFragment();
+                    mListFragment.setArguments(getIntent().getExtras());
+                    break;
+                }
+            case ContactsRequest.ACTION_CREATE_SHORTCUT_CALL:
+                {
+                    PhoneNumberPickerFragment fragment = getPhoneNumberPickerFragment(mRequest);
+                    fragment.setShortcutAction(Intent.ACTION_CALL);
+                    fragment.setListType(ListEvent.ListType.PICK_CONTACT_FOR_SHORTCUT);
+                    mListFragment = fragment;
+                    break;
+                }
 
-            case ContactsRequest.ACTION_CREATE_SHORTCUT_SMS: {
-                PhoneNumberPickerFragment fragment = getPhoneNumberPickerFragment(mRequest);
-                fragment.setShortcutAction(Intent.ACTION_SENDTO);
-                fragment.setListType(ListEvent.ListType.PICK_CONTACT_FOR_SHORTCUT);
-                mListFragment = fragment;
-                break;
-            }
+            case ContactsRequest.ACTION_CREATE_SHORTCUT_SMS:
+                {
+                    PhoneNumberPickerFragment fragment = getPhoneNumberPickerFragment(mRequest);
+                    fragment.setShortcutAction(Intent.ACTION_SENDTO);
+                    fragment.setListType(ListEvent.ListType.PICK_CONTACT_FOR_SHORTCUT);
+                    mListFragment = fragment;
+                    break;
+                }
 
-            case ContactsRequest.ACTION_PICK_POSTAL: {
-                PostalAddressPickerFragment fragment = new PostalAddressPickerFragment();
-                fragment.setListType(ListEvent.ListType.PICK_POSTAL);
-                mListFragment = fragment;
-                break;
-            }
+            case ContactsRequest.ACTION_PICK_POSTAL:
+                {
+                    PostalAddressPickerFragment fragment = new PostalAddressPickerFragment();
+                    fragment.setListType(ListEvent.ListType.PICK_POSTAL);
+                    mListFragment = fragment;
+                    break;
+                }
 
-            case ContactsRequest.ACTION_PICK_JOIN: {
-                JoinContactListFragment joinFragment = new JoinContactListFragment();
-                joinFragment.setTargetContactId(getTargetContactId());
-                joinFragment.setListType(ListEvent.ListType.PICK_JOIN);
-                mListFragment = joinFragment;
-                break;
-            }
+            case ContactsRequest.ACTION_PICK_JOIN:
+                {
+                    JoinContactListFragment joinFragment = new JoinContactListFragment();
+                    joinFragment.setTargetContactId(getTargetContactId());
+                    joinFragment.setListType(ListEvent.ListType.PICK_JOIN);
+                    mListFragment = joinFragment;
+                    break;
+                }
 
-            case ContactsRequest.ACTION_PICK_GROUP_MEMBERS: {
-                final String accountName = getIntent().getStringExtra(
-                        UiIntentActions.GROUP_ACCOUNT_NAME);
-                final String accountType = getIntent().getStringExtra(
-                        UiIntentActions.GROUP_ACCOUNT_TYPE);
-                final String accountDataSet = getIntent().getStringExtra(
-                        UiIntentActions.GROUP_ACCOUNT_DATA_SET);
-                final ArrayList<String> contactIds = getIntent().getStringArrayListExtra(
-                        UiIntentActions.GROUP_CONTACT_IDS);
-                mListFragment = GroupMemberPickerFragment.newInstance(
-                        accountName, accountType, accountDataSet, contactIds);
-                mListFragment.setListType(ListEvent.ListType.PICK_GROUP_MEMBERS);
-                break;
-            }
+            case ContactsRequest.ACTION_PICK_GROUP_MEMBERS:
+                {
+                    final String accountName =
+                            getIntent().getStringExtra(UiIntentActions.GROUP_ACCOUNT_NAME);
+                    final String accountType =
+                            getIntent().getStringExtra(UiIntentActions.GROUP_ACCOUNT_TYPE);
+                    final String accountDataSet =
+                            getIntent().getStringExtra(UiIntentActions.GROUP_ACCOUNT_DATA_SET);
+                    final ArrayList<String> contactIds =
+                            getIntent().getStringArrayListExtra(UiIntentActions.GROUP_CONTACT_IDS);
+                    mListFragment =
+                            GroupMemberPickerFragment.newInstance(
+                                    accountName, accountType, accountDataSet, contactIds);
+                    mListFragment.setListType(ListEvent.ListType.PICK_GROUP_MEMBERS);
+                    break;
+                }
 
             default:
                 throw new IllegalStateException("Invalid action code: " + mActionCode);
@@ -381,7 +416,8 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
         mListFragment.setLegacyCompatibilityMode(mRequest.isLegacyCompatibilityMode());
         mListFragment.setDirectoryResultLimit(DEFAULT_DIRECTORY_RESULT_LIMIT);
 
-        getFragmentManager().beginTransaction()
+        getFragmentManager()
+                .beginTransaction()
                 .replace(R.id.list_container, mListFragment)
                 .commitAllowingStateLoss();
     }
@@ -396,27 +432,28 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
 
     public void setupActionListener() {
         if (mListFragment instanceof ContactPickerFragment) {
-            ((ContactPickerFragment) mListFragment).setOnContactPickerActionListener(
-                    new ContactPickerActionListener());
+            ((ContactPickerFragment) mListFragment)
+                    .setOnContactPickerActionListener(new ContactPickerActionListener());
         } else if (mListFragment instanceof PhoneNumberPickerFragment) {
-            ((PhoneNumberPickerFragment) mListFragment).setOnPhoneNumberPickerActionListener(
-                    new PhoneNumberPickerActionListener());
+            ((PhoneNumberPickerFragment) mListFragment)
+                    .setOnPhoneNumberPickerActionListener(new PhoneNumberPickerActionListener());
         } else if (mListFragment instanceof PostalAddressPickerFragment) {
-            ((PostalAddressPickerFragment) mListFragment).setOnPostalAddressPickerActionListener(
-                    new PostalAddressPickerActionListener());
+            ((PostalAddressPickerFragment) mListFragment)
+                    .setOnPostalAddressPickerActionListener(
+                            new PostalAddressPickerActionListener());
         } else if (mListFragment instanceof EmailAddressPickerFragment) {
-            ((EmailAddressPickerFragment) mListFragment).setOnEmailAddressPickerActionListener(
-                    new EmailAddressPickerActionListener());
+            ((EmailAddressPickerFragment) mListFragment)
+                    .setOnEmailAddressPickerActionListener(new EmailAddressPickerActionListener());
         } else if (mListFragment instanceof MultiSelectEmailAddressesListFragment) {
             ((MultiSelectEmailAddressesListFragment) mListFragment).setCheckBoxListListener(this);
         } else if (mListFragment instanceof MultiSelectPhoneNumbersListFragment) {
             ((MultiSelectPhoneNumbersListFragment) mListFragment).setCheckBoxListListener(this);
         } else if (mListFragment instanceof JoinContactListFragment) {
-            ((JoinContactListFragment) mListFragment).setOnContactPickerActionListener(
-                    new JoinContactActionListener());
+            ((JoinContactListFragment) mListFragment)
+                    .setOnContactPickerActionListener(new JoinContactActionListener());
         } else if (mListFragment instanceof GroupMemberPickerFragment) {
-            ((GroupMemberPickerFragment) mListFragment).setListener(
-                    new GroupMemberPickerListener());
+            ((GroupMemberPickerFragment) mListFragment)
+                    .setListener(new GroupMemberPickerListener());
             getMultiSelectListFragment().setCheckBoxListListener(this);
         } else {
             throw new IllegalStateException("Unsupported list fragment type: " + mListFragment);
@@ -481,19 +518,21 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
     }
 
     private void updateAddContactsButton(int count) {
-        final TextView textView = (TextView) mActionBarAdapter.getSelectionContainer()
-                .findViewById(R.id.add_contacts);
+        final TextView textView =
+                (TextView)
+                        mActionBarAdapter.getSelectionContainer().findViewById(R.id.add_contacts);
         if (count > 0) {
             textView.setVisibility(View.VISIBLE);
             textView.setAllCaps(true);
-            textView.setOnClickListener(new OnClickListener() {
-                @Override
-                public void onClick(View v) {
-                    final long[] contactIds =
-                            getMultiSelectListFragment().getSelectedContactIdsArray();
-                    returnSelectedContacts(contactIds);
-                }
-            });
+            textView.setOnClickListener(
+                    new OnClickListener() {
+                        @Override
+                        public void onClick(View v) {
+                            final long[] contactIds =
+                                    getMultiSelectListFragment().getSelectedContactIdsArray();
+                            returnSelectedContacts(contactIds);
+                        }
+                    });
         } else {
             textView.setVisibility(View.GONE);
         }
@@ -512,9 +551,12 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
 
         @Override
         public void onEditContactAction(Uri contactLookupUri) {
-            startActivityAndForwardResult(EditorIntents.createEditContactIntent(
-                    ContactSelectionActivity.this, contactLookupUri, /* materialPalette =*/ null,
-                    /* photoId =*/ -1));
+            startActivityAndForwardResult(
+                    EditorIntents.createEditContactIntent(
+                            ContactSelectionActivity.this,
+                            contactLookupUri,
+                            /* materialPalette= */ null,
+                            /* photoId= */ -1));
         }
 
         @Override
@@ -528,16 +570,16 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
         }
     }
 
-    private final class PhoneNumberPickerActionListener implements
-            OnPhoneNumberPickerActionListener {
+    private final class PhoneNumberPickerActionListener
+            implements OnPhoneNumberPickerActionListener {
         @Override
         public void onPickDataUri(Uri dataUri, boolean isVideoCall, int callInitiationType) {
             returnPickerResult(dataUri);
         }
 
         @Override
-        public void onPickPhoneNumber(String phoneNumber, boolean isVideoCall,
-                                      int callInitiationType) {
+        public void onPickPhoneNumber(
+                String phoneNumber, boolean isVideoCall, int callInitiationType) {
             Log.w(TAG, "Unsupported call.");
         }
 
@@ -561,16 +603,13 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
         }
 
         @Override
-        public void onShortcutIntentCreated(Intent intent) {
-        }
+        public void onShortcutIntentCreated(Intent intent) {}
 
         @Override
-        public void onCreateNewContactAction() {
-        }
+        public void onCreateNewContactAction() {}
 
         @Override
-        public void onEditContactAction(Uri contactLookupUri) {
-        }
+        public void onEditContactAction(Uri contactLookupUri) {}
     }
 
     private final class GroupMemberPickerListener implements GroupMemberPickerFragment.Listener {
@@ -594,16 +633,16 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
         returnPickerResult(intent);
     }
 
-    private final class PostalAddressPickerActionListener implements
-            OnPostalAddressPickerActionListener {
+    private final class PostalAddressPickerActionListener
+            implements OnPostalAddressPickerActionListener {
         @Override
         public void onPickPostalAddressAction(Uri dataUri) {
             returnPickerResult(dataUri);
         }
     }
 
-    private final class EmailAddressPickerActionListener implements
-            OnEmailAddressPickerActionListener {
+    private final class EmailAddressPickerActionListener
+            implements OnEmailAddressPickerActionListener {
         @Override
         public void onPickEmailAddressAction(Uri dataUri) {
             returnPickerResult(dataUri);
@@ -622,8 +661,8 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
             ImplicitIntentsUtil.startActivityInApp(ContactSelectionActivity.this, intent);
         } catch (ActivityNotFoundException e) {
             Log.e(TAG, "startActivity() failed: " + e);
-            Toast.makeText(ContactSelectionActivity.this, R.string.missing_app,
-                    Toast.LENGTH_SHORT).show();
+            Toast.makeText(ContactSelectionActivity.this, R.string.missing_app, Toast.LENGTH_SHORT)
+                    .show();
         }
         finish();
     }
@@ -658,11 +697,15 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
 
     private long getTargetContactId() {
         Intent intent = getIntent();
-        final long targetContactId = intent.getLongExtra(
-                UiIntentActions.TARGET_CONTACT_ID_EXTRA_KEY, -1);
+        final long targetContactId =
+                intent.getLongExtra(UiIntentActions.TARGET_CONTACT_ID_EXTRA_KEY, -1);
         if (targetContactId == -1) {
-            Log.e(TAG, "Intent " + intent.getAction() + " is missing required extra: "
-                    + UiIntentActions.TARGET_CONTACT_ID_EXTRA_KEY);
+            Log.e(
+                    TAG,
+                    "Intent "
+                            + intent.getAction()
+                            + " is missing required extra: "
+                            + UiIntentActions.TARGET_CONTACT_ID_EXTRA_KEY);
             setResult(RESULT_CANCELED);
             finish();
             return -1;
@@ -672,8 +715,7 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
 
     private void startCreateNewContactActivity() {
         Intent intent = new Intent(Intent.ACTION_INSERT, Contacts.CONTENT_URI);
-        intent.putExtra(ContactEditorActivity.
-                INTENT_KEY_FINISH_ACTIVITY_ON_SAVE_COMPLETED, true);
+        intent.putExtra(ContactEditorActivity.INTENT_KEY_FINISH_ACTIVITY_ON_SAVE_COMPLETED, true);
         startActivityAndForwardResult(intent);
     }
 
@@ -689,8 +731,11 @@ public class ContactSelectionActivity extends AppCompatContactsActivity implemen
 
         final Drawable searchIcon = searchItem.getIcon();
         if (searchIcon != null) {
-            searchIcon.mutate().setColorFilter(ContextCompat.getColor(this,
-                    R.color.actionbar_icon_color), PorterDuff.Mode.SRC_ATOP);
+            searchIcon
+                    .mutate()
+                    .setColorFilter(
+                            ContextCompat.getColor(this, R.color.actionbar_icon_color),
+                            PorterDuff.Mode.SRC_ATOP);
         }
         return true;
     }
diff --git a/src/com/android/contacts/activities/SimImportActivity.java b/src/com/android/contacts/activities/SimImportActivity.java
index 2dff45b43..c778b1ad7 100644
--- a/src/com/android/contacts/activities/SimImportActivity.java
+++ b/src/com/android/contacts/activities/SimImportActivity.java
@@ -27,8 +27,8 @@ import com.android.contacts.model.SimCard;
 /**
  * Host activity for SimImportFragment
  *
- * Initially SimImportFragment was a DialogFragment but there were accessibility issues with
- * that so it was changed to an activity
+ * <p>Initially SimImportFragment was a DialogFragment but there were accessibility issues with that
+ * so it was changed to an activity
  */
 public class SimImportActivity extends AppCompatContactsActivity {
 
@@ -41,8 +41,11 @@ public class SimImportActivity extends AppCompatContactsActivity {
         final FragmentManager fragmentManager = getFragmentManager();
         Fragment fragment = fragmentManager.findFragmentByTag("SimImport");
         if (fragment == null) {
-            fragment = SimImportFragment.newInstance(getIntent().getIntExtra(EXTRA_SUBSCRIPTION_ID,
-                    SimCard.NO_SUBSCRIPTION_ID));
+            fragment =
+                    SimImportFragment.newInstance(
+                            getIntent()
+                                    .getIntExtra(
+                                            EXTRA_SUBSCRIPTION_ID, SimCard.NO_SUBSCRIPTION_ID));
             fragmentManager.beginTransaction().add(R.id.root, fragment, "SimImport").commit();
         }
     }
diff --git a/src/com/android/contacts/editor/ContactEditorFragment.java b/src/com/android/contacts/editor/ContactEditorFragment.java
index 52c20e69a..d7d164f0a 100755
--- a/src/com/android/contacts/editor/ContactEditorFragment.java
+++ b/src/com/android/contacts/editor/ContactEditorFragment.java
@@ -42,7 +42,7 @@ import android.provider.ContactsContract.CommonDataKinds.StructuredName;
 import android.provider.ContactsContract.CommonDataKinds.StructuredPostal;
 import android.provider.ContactsContract.Intents;
 import android.provider.ContactsContract.RawContacts;
-import androidx.appcompat.widget.Toolbar;
+import android.provider.ContactsContract.Settings;
 import android.text.TextUtils;
 import android.util.Log;
 import android.view.LayoutInflater;
@@ -54,15 +54,15 @@ import android.view.ViewGroup;
 import android.view.inputmethod.InputMethodManager;
 import android.widget.AdapterView;
 import android.widget.BaseAdapter;
-import android.widget.EditText;
 import android.widget.LinearLayout;
 import android.widget.ListPopupWindow;
 import android.widget.Toast;
 
+import androidx.appcompat.widget.Toolbar;
+
 import com.android.contacts.ContactSaveService;
 import com.android.contacts.GroupMetaDataLoader;
 import com.android.contacts.R;
-import com.android.contacts.activities.ContactEditorAccountsChangedActivity;
 import com.android.contacts.activities.ContactEditorActivity;
 import com.android.contacts.activities.ContactEditorActivity.ContactEditor;
 import com.android.contacts.activities.ContactSelectionActivity;
@@ -98,26 +98,28 @@ import com.google.common.collect.ImmutableList;
 import com.google.common.collect.Lists;
 
 import java.io.FileNotFoundException;
-import java.util.Arrays;
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.Collections;
 import java.util.HashSet;
 import java.util.Iterator;
 import java.util.List;
 import java.util.Locale;
 import java.util.Set;
+
 import javax.annotation.Nullable;
 
-/**
- * Contact editor with only the most important fields displayed initially.
- */
-public class ContactEditorFragment extends Fragment implements
-        ContactEditor, SplitContactConfirmationDialogFragment.Listener,
-        JoinContactConfirmationDialogFragment.Listener,
-        AggregationSuggestionEngine.Listener, AggregationSuggestionView.Listener,
-        CancelEditDialogFragment.Listener,
-        RawContactEditorView.Listener, PhotoEditorView.Listener,
-        AccountsLoader.AccountsListener {
+/** Contact editor with only the most important fields displayed initially. */
+public class ContactEditorFragment extends Fragment
+        implements ContactEditor,
+                SplitContactConfirmationDialogFragment.Listener,
+                JoinContactConfirmationDialogFragment.Listener,
+                AggregationSuggestionEngine.Listener,
+                AggregationSuggestionView.Listener,
+                CancelEditDialogFragment.Listener,
+                RawContactEditorView.Listener,
+                PhotoEditorView.Listener,
+                AccountsLoader.AccountsListener {
 
     static final String TAG = "ContactEditor";
 
@@ -133,10 +135,11 @@ public class ContactEditorFragment extends Fragment implements
     private static final String KEY_PHOTO_RAW_CONTACT_ID = "photo_raw_contact_id";
     private static final String KEY_UPDATED_PHOTOS = "updated_photos";
 
-    private static final List<String> VALID_INTENT_ACTIONS = Arrays.asList(
-            Intent.ACTION_EDIT,
-            Intent.ACTION_INSERT,
-            ContactEditorActivity.ACTION_SAVE_COMPLETED);
+    private static final List<String> VALID_INTENT_ACTIONS =
+            Arrays.asList(
+                    Intent.ACTION_EDIT,
+                    Intent.ACTION_INSERT,
+                    ContactEditorActivity.ACTION_SAVE_COMPLETED);
 
     private static final String KEY_ACTION = "action";
     private static final String KEY_URI = "uri";
@@ -180,33 +183,30 @@ public class ContactEditorFragment extends Fragment implements
     protected static final int REQUEST_CODE_ACCOUNTS_CHANGED = 1;
 
     /**
-     * An intent extra that forces the editor to add the edited contact
-     * to the default group (e.g. "My Contacts").
+     * An intent extra that forces the editor to add the edited contact to the default group (e.g.
+     * "My Contacts").
      */
     public static final String INTENT_EXTRA_ADD_TO_DEFAULT_DIRECTORY = "addToDefaultDirectory";
 
     public static final String INTENT_EXTRA_NEW_LOCAL_PROFILE = "newLocalProfile";
 
-    public static final String INTENT_EXTRA_DISABLE_DELETE_MENU_OPTION =
-            "disableDeleteMenuOption";
+    public static final String INTENT_EXTRA_DISABLE_DELETE_MENU_OPTION = "disableDeleteMenuOption";
 
     /**
-     * Intent key to pass the photo palette primary color calculated by
-     * {@link com.android.contacts.quickcontact.QuickContactActivity} to the editor.
+     * Intent key to pass the photo palette primary color calculated by {@link
+     * com.android.contacts.quickcontact.QuickContactActivity} to the editor.
      */
     public static final String INTENT_EXTRA_MATERIAL_PALETTE_PRIMARY_COLOR =
             "material_palette_primary_color";
 
     /**
-     * Intent key to pass the photo palette secondary color calculated by
-     * {@link com.android.contacts.quickcontact.QuickContactActivity} to the editor.
+     * Intent key to pass the photo palette secondary color calculated by {@link
+     * com.android.contacts.quickcontact.QuickContactActivity} to the editor.
      */
     public static final String INTENT_EXTRA_MATERIAL_PALETTE_SECONDARY_COLOR =
             "material_palette_secondary_color";
 
-    /**
-     * Intent key to pass the ID of the photo to display on the editor.
-     */
+    /** Intent key to pass the ID of the photo to display on the editor. */
     // TODO: This can be cleaned up if we decide to not pass the photo id through
     // QuickContactActivity.
     public static final String INTENT_EXTRA_PHOTO_ID = "photo_id";
@@ -218,24 +218,18 @@ public class ContactEditorFragment extends Fragment implements
     public static final String INTENT_EXTRA_RAW_CONTACT_ID_TO_DISPLAY_ALONE =
             "raw_contact_id_to_display_alone";
 
-    /**
-     * Intent extra to specify a {@link ContactEditor.SaveMode}.
-     */
+    /** Intent extra to specify a {@link ContactEditor.SaveMode}. */
     public static final String SAVE_MODE_EXTRA_KEY = "saveMode";
 
-    /**
-     * Intent extra key for the contact ID to join the current contact to after saving.
-     */
+    /** Intent extra key for the contact ID to join the current contact to after saving. */
     public static final String JOIN_CONTACT_ID_EXTRA_KEY = "joinContactId";
 
-    /**
-     * Callbacks for Activities that host contact editors Fragments.
-     */
+    /** Callbacks for Activities that host contact editors Fragments. */
     public interface Listener {
 
         /**
-         * Contact was not found, so somehow close this fragment. This is raised after a contact
-         * is removed via Menu/Delete
+         * Contact was not found, so somehow close this fragment. This is raised after a contact is
+         * removed via Menu/Delete
          */
         void onContactNotFound();
 
@@ -243,44 +237,37 @@ public class ContactEditorFragment extends Fragment implements
          * Contact was split, so we can close now.
          *
          * @param newLookupUri The lookup uri of the new contact that should be shown to the user.
-         *                     The editor tries best to chose the most natural contact here.
+         *     The editor tries best to chose the most natural contact here.
          */
         void onContactSplit(Uri newLookupUri);
 
-        /**
-         * User has tapped Revert, close the fragment now.
-         */
+        /** User has tapped Revert, close the fragment now. */
         void onReverted();
 
-        /**
-         * Contact was saved and the Fragment can now be closed safely.
-         */
+        /** Contact was saved and the Fragment can now be closed safely. */
         void onSaveFinished(Intent resultIntent);
 
         /**
-         * User switched to editing a different raw contact (a suggestion from the
-         * aggregation engine).
+         * User switched to editing a different raw contact (a suggestion from the aggregation
+         * engine).
          */
-        void onEditOtherRawContactRequested(Uri contactLookupUri, long rawContactId,
-                ArrayList<ContentValues> contentValues);
+        void onEditOtherRawContactRequested(
+                Uri contactLookupUri, long rawContactId, ArrayList<ContentValues> contentValues);
 
-        /**
-         * User has requested that contact be deleted.
-         */
+        /** User has requested that contact be deleted. */
         void onDeleteRequested(Uri contactUri);
     }
 
-    /**
-     * Adapter for aggregation suggestions displayed in a PopupWindow when
-     * editor fields change.
-     */
+    /** Adapter for aggregation suggestions displayed in a PopupWindow when editor fields change. */
     private static final class AggregationSuggestionAdapter extends BaseAdapter {
         private final LayoutInflater mLayoutInflater;
         private final AggregationSuggestionView.Listener mListener;
         private final List<AggregationSuggestionEngine.Suggestion> mSuggestions;
 
-        public AggregationSuggestionAdapter(Activity activity,
-                AggregationSuggestionView.Listener listener, List<Suggestion> suggestions) {
+        public AggregationSuggestionAdapter(
+                Activity activity,
+                AggregationSuggestionView.Listener listener,
+                List<Suggestion> suggestions) {
             mLayoutInflater = activity.getLayoutInflater();
             mListener = listener;
             mSuggestions = suggestions;
@@ -290,8 +277,8 @@ public class ContactEditorFragment extends Fragment implements
         public View getView(int position, View convertView, ViewGroup parent) {
             final Suggestion suggestion = (Suggestion) getItem(position);
             final AggregationSuggestionView suggestionView =
-                    (AggregationSuggestionView) mLayoutInflater.inflate(
-                            R.layout.aggregation_suggestions_item, null);
+                    (AggregationSuggestionView)
+                            mLayoutInflater.inflate(R.layout.aggregation_suggestions_item, null);
             suggestionView.setListener(mListener);
             suggestionView.bindSuggestion(suggestion);
             return suggestionView;
@@ -384,9 +371,7 @@ public class ContactEditorFragment extends Fragment implements
     protected long mReadOnlyDisplayNameId;
     protected boolean mCopyReadOnlyName;
 
-    /**
-     * The contact data loader listener.
-     */
+    /** The contact data loader listener. */
     protected final LoaderManager.LoaderCallbacks<Contact> mContactLoaderListener =
             new LoaderManager.LoaderCallbacks<Contact>() {
 
@@ -395,7 +380,9 @@ public class ContactEditorFragment extends Fragment implements
                 @Override
                 public Loader<Contact> onCreateLoader(int id, Bundle args) {
                     mLoaderStartTime = SystemClock.elapsedRealtime();
-                    return new ContactLoader(mContext, mLookupUri,
+                    return new ContactLoader(
+                            mContext,
+                            mLookupUri,
                             /* postViewNotification */ true,
                             /* loadGroupMetaData */ true);
                 }
@@ -404,8 +391,10 @@ public class ContactEditorFragment extends Fragment implements
                 public void onLoadFinished(Loader<Contact> loader, Contact contact) {
                     final long loaderCurrentTime = SystemClock.elapsedRealtime();
                     if (Log.isLoggable(TAG, Log.VERBOSE)) {
-                        Log.v(TAG,
-                                "Time needed for loading: " + (loaderCurrentTime-mLoaderStartTime));
+                        Log.v(
+                                TAG,
+                                "Time needed for loading: "
+                                        + (loaderCurrentTime - mLoaderStartTime));
                     }
                     if (!contact.isLoaded()) {
                         // Item has been deleted. Close activity without saving again.
@@ -421,25 +410,26 @@ public class ContactEditorFragment extends Fragment implements
                     setState(contact);
                     final long setDataEndTime = SystemClock.elapsedRealtime();
                     if (Log.isLoggable(TAG, Log.VERBOSE)) {
-                        Log.v(TAG, "Time needed for setting UI: "
-                                + (setDataEndTime - setDataStartTime));
+                        Log.v(
+                                TAG,
+                                "Time needed for setting UI: "
+                                        + (setDataEndTime - setDataStartTime));
                     }
                 }
 
                 @Override
-                public void onLoaderReset(Loader<Contact> loader) {
-                }
+                public void onLoaderReset(Loader<Contact> loader) {}
             };
 
-    /**
-     * The groups meta data loader listener.
-     */
+    /** The groups meta data loader listener. */
     protected final LoaderManager.LoaderCallbacks<Cursor> mGroupsLoaderListener =
             new LoaderManager.LoaderCallbacks<Cursor>() {
 
                 @Override
                 public CursorLoader onCreateLoader(int id, Bundle args) {
-                    return new GroupMetaDataLoader(mContext, ContactsContract.Groups.CONTENT_URI,
+                    return new GroupMetaDataLoader(
+                            mContext,
+                            ContactsContract.Groups.CONTENT_URI,
                             GroupUtil.ALL_GROUPS_SELECTION);
                 }
 
@@ -450,8 +440,7 @@ public class ContactEditorFragment extends Fragment implements
                 }
 
                 @Override
-                public void onLoaderReset(Loader<Cursor> loader) {
-                }
+                public void onLoaderReset(Loader<Cursor> loader) {}
             };
 
     private long mPhotoRawContactId;
@@ -484,7 +473,7 @@ public class ContactEditorFragment extends Fragment implements
         super.onCreate(savedState);
 
         inputMethodManager =
-            (InputMethodManager) getActivity().getSystemService(Context.INPUT_METHOD_SERVICE);
+                (InputMethodManager) getActivity().getSystemService(Context.INPUT_METHOD_SERVICE);
 
         if (savedState == null) {
             mViewIdGenerator = new ViewIdGenerator();
@@ -500,12 +489,13 @@ public class ContactEditorFragment extends Fragment implements
             mNewLocalProfile = savedState.getBoolean(KEY_NEW_LOCAL_PROFILE);
             mMaterialPalette = savedState.getParcelable(KEY_MATERIAL_PALETTE);
             mAccountWithDataSet = savedState.getParcelable(KEY_ACCOUNT);
-            mRawContacts = ImmutableList.copyOf(savedState.<RawContact>getParcelableArrayList(
-                    KEY_RAW_CONTACTS));
+            mRawContacts =
+                    ImmutableList.copyOf(
+                            savedState.<RawContact>getParcelableArrayList(KEY_RAW_CONTACTS));
             // NOTE: mGroupMetaData is not saved/restored
 
             // Read state from savedState. No loading involved here
-            mState = savedState.<RawContactDeltaList> getParcelable(KEY_EDIT_STATE);
+            mState = savedState.<RawContactDeltaList>getParcelable(KEY_EDIT_STATE);
             mStatus = savedState.getInt(KEY_STATUS);
 
             mHasNewContact = savedState.getBoolean(KEY_HAS_NEW_CONTACT);
@@ -519,8 +509,8 @@ public class ContactEditorFragment extends Fragment implements
             mEnabled = savedState.getBoolean(KEY_ENABLED);
 
             // Aggregation PopupWindow
-            mAggregationSuggestionsRawContactId = savedState.getLong(
-                    KEY_AGGREGATION_SUGGESTIONS_RAW_CONTACT_ID);
+            mAggregationSuggestionsRawContactId =
+                    savedState.getLong(KEY_AGGREGATION_SUGGESTIONS_RAW_CONTACT_ID);
 
             // Join Activity
             mContactIdForJoin = savedState.getLong(KEY_CONTACT_ID_FOR_JOIN);
@@ -537,8 +527,7 @@ public class ContactEditorFragment extends Fragment implements
     public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedState) {
         setHasOptionsMenu(true);
 
-        final View view = inflater.inflate(
-                R.layout.contact_editor_fragment, container, false);
+        final View view = inflater.inflate(R.layout.contact_editor_fragment, container, false);
         mContent = (LinearLayout) view.findViewById(R.id.raw_contacts_editor_view);
         return view;
     }
@@ -568,14 +557,20 @@ public class ContactEditorFragment extends Fragment implements
         // Handle initial actions only when existing state missing
         if (savedInstanceState == null) {
             if (mIntentExtras != null) {
-                final Account account = mIntentExtras == null ? null :
-                        (Account) mIntentExtras.getParcelable(Intents.Insert.EXTRA_ACCOUNT);
-                final String dataSet = mIntentExtras == null ? null :
-                        mIntentExtras.getString(Intents.Insert.EXTRA_DATA_SET);
-                mAccountWithDataSet = account != null
-                        ? new AccountWithDataSet(account.name, account.type, dataSet)
-                        : mIntentExtras.<AccountWithDataSet>getParcelable(
-                                ContactEditorActivity.EXTRA_ACCOUNT_WITH_DATA_SET);
+                final Account account =
+                        mIntentExtras == null
+                                ? null
+                                : (Account)
+                                        mIntentExtras.getParcelable(Intents.Insert.EXTRA_ACCOUNT);
+                final String dataSet =
+                        mIntentExtras == null
+                                ? null
+                                : mIntentExtras.getString(Intents.Insert.EXTRA_DATA_SET);
+                mAccountWithDataSet =
+                        account != null
+                                ? new AccountWithDataSet(account.name, account.type, dataSet)
+                                : mIntentExtras.<AccountWithDataSet>getParcelable(
+                                        ContactEditorActivity.EXTRA_ACCOUNT_WITH_DATA_SET);
             }
 
             if (Intent.ACTION_EDIT.equals(mAction)) {
@@ -589,7 +584,8 @@ public class ContactEditorFragment extends Fragment implements
         }
 
         if (mHasNewContact) {
-            AccountsLoader.loadAccounts(this, LOADER_ACCOUNTS, AccountTypeManager.writableFilter());
+            AccountsLoader.loadAccounts(
+                    this, LOADER_ACCOUNTS, AccountTypeManager.insertableFilter(getContext()));
         }
     }
 
@@ -628,8 +624,11 @@ public class ContactEditorFragment extends Fragment implements
         }
         outState.putParcelable(KEY_VIEW_ID_GENERATOR, mViewIdGenerator);
 
-        outState.putParcelableArrayList(KEY_RAW_CONTACTS, mRawContacts == null ?
-                Lists.<RawContact>newArrayList() : Lists.newArrayList(mRawContacts));
+        outState.putParcelableArrayList(
+                KEY_RAW_CONTACTS,
+                mRawContacts == null
+                        ? Lists.<RawContact>newArrayList()
+                        : Lists.newArrayList(mRawContacts));
         // NOTE: mGroupMetaData is not saved
 
         outState.putParcelable(KEY_EDIT_STATE, mState);
@@ -644,8 +643,8 @@ public class ContactEditorFragment extends Fragment implements
         outState.putBoolean(KEY_ENABLED, mEnabled);
 
         // Aggregation PopupWindow
-        outState.putLong(KEY_AGGREGATION_SUGGESTIONS_RAW_CONTACT_ID,
-                mAggregationSuggestionsRawContactId);
+        outState.putLong(
+                KEY_AGGREGATION_SUGGESTIONS_RAW_CONTACT_ID, mAggregationSuggestionsRawContactId);
 
         // Join Activity
         outState.putLong(KEY_CONTACT_ID_FOR_JOIN, mContactIdForJoin);
@@ -683,35 +682,36 @@ public class ContactEditorFragment extends Fragment implements
     @Override
     public void onActivityResult(int requestCode, int resultCode, Intent data) {
         switch (requestCode) {
-            case REQUEST_CODE_JOIN: {
-                // Ignore failed requests
-                if (resultCode != Activity.RESULT_OK) return;
-                if (data != null) {
-                    final long contactId = ContentUris.parseId(data.getData());
-                    if (hasPendingChanges()) {
-                        // Ask the user if they want to save changes before doing the join
-                        JoinContactConfirmationDialogFragment.show(this, contactId);
-                    } else {
-                        // Do the join immediately
-                        joinAggregate(contactId);
+            case REQUEST_CODE_JOIN:
+                {
+                    // Ignore failed requests
+                    if (resultCode != Activity.RESULT_OK) return;
+                    if (data != null) {
+                        final long contactId = ContentUris.parseId(data.getData());
+                        if (hasPendingChanges()) {
+                            // Ask the user if they want to save changes before doing the join
+                            JoinContactConfirmationDialogFragment.show(this, contactId);
+                        } else {
+                            // Do the join immediately
+                            joinAggregate(contactId);
+                        }
                     }
+                    break;
                 }
-                break;
-            }
-            case REQUEST_CODE_ACCOUNTS_CHANGED: {
-                // Bail if the account selector was not successful.
-                if (resultCode != Activity.RESULT_OK || data == null ||
-                        !data.hasExtra(Intents.Insert.EXTRA_ACCOUNT)) {
-                    if (mListener != null) {
-                        mListener.onReverted();
+            case REQUEST_CODE_ACCOUNTS_CHANGED:
+                {
+                    AccountWithDataSet defaultAccount =
+                            new ContactsPreferences(mContext).getDefaultAccount();
+                    // Bail if the account selector was not successful.
+                    if (defaultAccount == null) {
+                        if (mListener != null) {
+                            mListener.onReverted();
+                        }
+                        return;
                     }
-                    return;
+                    createContact(defaultAccount);
+                    break;
                 }
-                AccountWithDataSet account = data.getParcelableExtra(
-                        Intents.Insert.EXTRA_ACCOUNT);
-                createContact(account);
-                break;
-            }
         }
     }
 
@@ -732,15 +732,18 @@ public class ContactEditorFragment extends Fragment implements
             return;
         }
 
-        final AccountWithDataSet account = mAccountWithDataSet != null
-                ? mAccountWithDataSet
-                : view.getCurrentRawContactDelta().getAccountWithDataSet();
+        final AccountWithDataSet account =
+                mAccountWithDataSet != null
+                        ? mAccountWithDataSet
+                        : view.getCurrentRawContactDelta().getAccountWithDataSet();
 
         // The current account was removed
         if (!AccountInfo.contains(data, account) && !data.isEmpty()) {
             if (isReadyToBindEditors()) {
-                onRebindEditorsForNewContact(getContent().getCurrentRawContactDelta(),
-                        account, data.get(0).getAccount());
+                onRebindEditorsForNewContact(
+                        getContent().getCurrentRawContactDelta(),
+                        account,
+                        data.get(0).getAccount());
             } else {
                 mAccountWithDataSet = data.get(0).getAccount();
             }
@@ -775,12 +778,14 @@ public class ContactEditorFragment extends Fragment implements
         saveMenu.setVisible(!isEditingReadOnlyRawContact());
         if (saveMenu.isVisible()) {
             // Since we're using a custom action layout we have to manually hook up the handler.
-            saveMenu.getActionView().setOnClickListener(new View.OnClickListener() {
-                @Override
-                public void onClick(View v) {
-                    onOptionsItemSelected(saveMenu);
-                }
-            });
+            saveMenu.getActionView()
+                    .setOnClickListener(
+                            new View.OnClickListener() {
+                                @Override
+                                public void onClick(View v) {
+                                    onOptionsItemSelected(saveMenu);
+                                }
+                            });
         }
 
         final MenuItem helpMenu = menu.findItem(R.id.menu_help);
@@ -848,8 +853,10 @@ public class ContactEditorFragment extends Fragment implements
             // This may happen when this Fragment is recreated by the system during users
             // confirming the split action (and thus this method is called just before onCreate()),
             // for example.
-            Log.e(TAG, "mState became null during the user's confirming split action. " +
-                    "Cannot perform the save action.");
+            Log.e(
+                    TAG,
+                    "mState became null during the user's confirming split action. "
+                            + "Cannot perform the save action.");
             return;
         }
 
@@ -885,10 +892,9 @@ public class ContactEditorFragment extends Fragment implements
 
         // If we just started creating a new contact and haven't added any data, it's too
         // early to do a join
-        if (mState.size() == 1 && mState.get(0).isContactInsert()
-                && !hasPendingChanges()) {
-            Toast.makeText(mContext, R.string.toast_join_with_empty_contact,
-                    Toast.LENGTH_LONG).show();
+        if (mState.size() == 1 && mState.get(0).isContactInsert() && !hasPendingChanges()) {
+            Toast.makeText(mContext, R.string.toast_join_with_empty_contact, Toast.LENGTH_LONG)
+                    .show();
             return true;
         }
 
@@ -908,7 +914,8 @@ public class ContactEditorFragment extends Fragment implements
         }
 
         // If we are about to close the editor - there is no need to refresh the data
-        if (saveMode == SaveMode.CLOSE || saveMode == SaveMode.EDITOR
+        if (saveMode == SaveMode.CLOSE
+                || saveMode == SaveMode.EDITOR
                 || saveMode == SaveMode.SPLIT) {
             getLoaderManager().destroyLoader(LOADER_CONTACT);
         }
@@ -922,8 +929,12 @@ public class ContactEditorFragment extends Fragment implements
                 mStatus = Status.EDITING;
                 return true;
             }
-            onSaveCompleted(/* hadChanges =*/ false, saveMode,
-                    /* saveSucceeded =*/ mLookupUri != null, mLookupUri, /* joinContactId =*/ null);
+            onSaveCompleted(
+                    /* hadChanges= */ false,
+                    saveMode,
+                    /* saveSucceeded= */ mLookupUri != null,
+                    mLookupUri,
+                    /* joinContactId= */ null);
             return true;
         }
 
@@ -937,8 +948,8 @@ public class ContactEditorFragment extends Fragment implements
     //
 
     /**
-     * Check if our internal {@link #mState} is valid, usually checked before
-     * performing user actions.
+     * Check if our internal {@link #mState} is valid, usually checked before performing user
+     * actions.
      */
     private boolean hasValidState() {
         return mState.size() > 0;
@@ -949,8 +960,8 @@ public class ContactEditorFragment extends Fragment implements
     }
 
     /**
-     * Whether the contact being edited is composed of read-only raw contacts
-     * aggregated with a newly created writable raw contact.
+     * Whether the contact being edited is composed of read-only raw contacts aggregated with a
+     * newly created writable raw contact.
      */
     private boolean isEditingReadOnlyRawContactWithNewContact() {
         return mHasNewContact && mState.size() > 1;
@@ -960,16 +971,14 @@ public class ContactEditorFragment extends Fragment implements
      * @return true if the single raw contact we're looking at is read-only.
      */
     private boolean isEditingReadOnlyRawContact() {
-        return hasValidState() && mRawContactIdToDisplayAlone > 0
+        return hasValidState()
+                && mRawContactIdToDisplayAlone > 0
                 && !mState.getByRawContactId(mRawContactIdToDisplayAlone)
                         .getAccountType(AccountTypeManager.getInstance(mContext))
-                                .areContactsWritable();
+                        .areContactsWritable();
     }
 
-    /**
-     * Return true if there are any edits to the current contact which need to
-     * be saved.
-     */
+    /** Return true if there are any edits to the current contact which need to be saved. */
     private boolean hasPendingRawContactChanges(Set<String> excludedMimeTypes) {
         final AccountTypeManager accountTypes = AccountTypeManager.getInstance(mContext);
         return RawContactModifier.hasChanges(mState, accountTypes, excludedMimeTypes);
@@ -977,19 +986,22 @@ public class ContactEditorFragment extends Fragment implements
 
     /**
      * Determines if changes were made in the editor that need to be saved, while taking into
-     * account that name changes are not real for read-only contacts.
-     * See go/editing-read-only-contacts
+     * account that name changes are not real for read-only contacts. See
+     * go/editing-read-only-contacts
      */
     private boolean hasPendingChanges() {
         if (isEditingReadOnlyRawContactWithNewContact()) {
             // We created a new raw contact delta with a default display name.
             // We must test for pending changes while ignoring the default display name.
-            final RawContactDelta beforeRawContactDelta = mState
-                    .getByRawContactId(mReadOnlyDisplayNameId);
-            final ValuesDelta beforeDelta = beforeRawContactDelta == null ? null :
-                  beforeRawContactDelta.getSuperPrimaryEntry(StructuredName.CONTENT_ITEM_TYPE);
-            final ValuesDelta pendingDelta = mState
-                    .getSuperPrimaryEntry(StructuredName.CONTENT_ITEM_TYPE);
+            final RawContactDelta beforeRawContactDelta =
+                    mState.getByRawContactId(mReadOnlyDisplayNameId);
+            final ValuesDelta beforeDelta =
+                    beforeRawContactDelta == null
+                            ? null
+                            : beforeRawContactDelta.getSuperPrimaryEntry(
+                                    StructuredName.CONTENT_ITEM_TYPE);
+            final ValuesDelta pendingDelta =
+                    mState.getSuperPrimaryEntry(StructuredName.CONTENT_ITEM_TYPE);
             if (structuredNamesAreEqual(beforeDelta, pendingDelta)) {
                 final Set<String> excludedMimeTypes = new HashSet<>();
                 excludedMimeTypes.add(StructuredName.CONTENT_ITEM_TYPE);
@@ -997,7 +1009,7 @@ public class ContactEditorFragment extends Fragment implements
             }
             return true;
         }
-        return hasPendingRawContactChanges(/* excludedMimeTypes =*/ null);
+        return hasPendingRawContactChanges(/* excludedMimeTypes= */ null);
     }
 
     /**
@@ -1006,8 +1018,8 @@ public class ContactEditorFragment extends Fragment implements
      *
      * @param before original {@link ValuesDelta}
      * @param after copied {@link ValuesDelta}
-     * @return true if the copied {@link ValuesDelta} has all the same values in the structured
-     * name fields as the original.
+     * @return true if the copied {@link ValuesDelta} has all the same values in the structured name
+     *     fields as the original.
      */
     private boolean structuredNamesAreEqual(ValuesDelta before, ValuesDelta after) {
         if (before == after) return true;
@@ -1059,15 +1071,12 @@ public class ContactEditorFragment extends Fragment implements
         // If there is no default account or the accounts have changed such that we need to
         // prompt the user again, then launch the account prompt.
         if (mEditorUtils.shouldShowAccountChangedNotification(accounts)) {
-            Intent intent = new Intent(mContext, ContactEditorAccountsChangedActivity.class);
+            Intent intent = new Intent(Settings.ACTION_SET_DEFAULT_ACCOUNT);
             // Prevent a second instance from being started on rotates
             intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
             mStatus = Status.SUB_ACTIVITY;
             startActivityForResult(intent, REQUEST_CODE_ACCOUNTS_CHANGED);
         } else {
-            // Make sure the default account is automatically set if there is only one non-device
-            // account.
-            mEditorUtils.maybeUpdateDefaultAccount(accounts);
             // Otherwise, there should be a default account. Then either create a local contact
             // (if default account is null) or create a contact with the specified account.
             AccountWithDataSet defaultAccount = mEditorUtils.getOnlyOrDefaultAccount(accounts);
@@ -1121,21 +1130,27 @@ public class ContactEditorFragment extends Fragment implements
         }
     }
 
-    /**
-     * Prepare {@link #mState} for a newly created phone-local contact.
-     */
-    private void setStateForNewContact(AccountWithDataSet account, AccountType accountType,
-            boolean isUserProfile) {
-        setStateForNewContact(account, accountType, /* oldState =*/ null,
-                /* oldAccountType =*/ null, isUserProfile);
+    /** Prepare {@link #mState} for a newly created phone-local contact. */
+    private void setStateForNewContact(
+            AccountWithDataSet account, AccountType accountType, boolean isUserProfile) {
+        setStateForNewContact(
+                account,
+                accountType,
+                /* oldState= */ null,
+                /* oldAccountType= */ null,
+                isUserProfile);
     }
 
     /**
      * Prepare {@link #mState} for a newly created phone-local contact, migrating the state
      * specified by oldState and oldAccountType.
      */
-    private void setStateForNewContact(AccountWithDataSet account, AccountType accountType,
-            RawContactDelta oldState, AccountType oldAccountType, boolean isUserProfile) {
+    private void setStateForNewContact(
+            AccountWithDataSet account,
+            AccountType accountType,
+            RawContactDelta oldState,
+            AccountType oldAccountType,
+            boolean isUserProfile) {
         mStatus = Status.EDITING;
         mAccountWithDataSet = account;
         mState.add(createNewRawContactDelta(account, accountType, oldState, oldAccountType));
@@ -1145,14 +1160,17 @@ public class ContactEditorFragment extends Fragment implements
     }
 
     /**
-     * Returns a {@link RawContactDelta} for a new contact suitable for addition into
-     * {@link #mState}.
+     * Returns a {@link RawContactDelta} for a new contact suitable for addition into {@link
+     * #mState}.
      *
-     * If oldState and oldAccountType are specified, the state specified by those parameters
-     * is migrated to the result {@link RawContactDelta}.
+     * <p>If oldState and oldAccountType are specified, the state specified by those parameters is
+     * migrated to the result {@link RawContactDelta}.
      */
-    private RawContactDelta createNewRawContactDelta(AccountWithDataSet account,
-            AccountType accountType, RawContactDelta oldState, AccountType oldAccountType) {
+    private RawContactDelta createNewRawContactDelta(
+            AccountWithDataSet account,
+            AccountType accountType,
+            RawContactDelta oldState,
+            AccountType oldAccountType) {
         final RawContact rawContact = new RawContact();
         if (account != null) {
             rawContact.setAccount(account);
@@ -1160,8 +1178,8 @@ public class ContactEditorFragment extends Fragment implements
             rawContact.setAccountToLocal();
         }
 
-        final RawContactDelta result = new RawContactDelta(
-                ValuesDelta.fromAfter(rawContact.getValues()));
+        final RawContactDelta result =
+                new RawContactDelta(ValuesDelta.fromAfter(rawContact.getValues()));
         if (oldState == null) {
             // Parse any values from incoming intent
             RawContactModifier.parseExtras(mContext, accountType, result, mIntentExtras);
@@ -1177,8 +1195,8 @@ public class ContactEditorFragment extends Fragment implements
         RawContactModifier.ensureKindExists(result, accountType, Email.CONTENT_ITEM_TYPE);
         RawContactModifier.ensureKindExists(result, accountType, Organization.CONTENT_ITEM_TYPE);
         RawContactModifier.ensureKindExists(result, accountType, Event.CONTENT_ITEM_TYPE);
-        RawContactModifier.ensureKindExists(result, accountType,
-                StructuredPostal.CONTENT_ITEM_TYPE);
+        RawContactModifier.ensureKindExists(
+                result, accountType, StructuredPostal.CONTENT_ITEM_TYPE);
 
         // Set the correct URI for saving the contact as a profile
         if (mNewLocalProfile) {
@@ -1188,11 +1206,9 @@ public class ContactEditorFragment extends Fragment implements
         return result;
     }
 
-    /**
-     * Prepare {@link #mState} for an existing contact.
-     */
-    private void setStateForExistingContact(boolean isUserProfile,
-            ImmutableList<RawContact> rawContacts) {
+    /** Prepare {@link #mState} for an existing contact. */
+    private void setStateForExistingContact(
+            boolean isUserProfile, ImmutableList<RawContact> rawContacts) {
         setEnabled(true);
 
         mState.addAll(rawContacts.iterator());
@@ -1223,9 +1239,7 @@ public class ContactEditorFragment extends Fragment implements
         bindEditors();
     }
 
-    /**
-     * Set the enabled state of editors.
-     */
+    /** Set the enabled state of editors. */
     private void setEnabled(boolean enabled) {
         if (mEnabled != enabled) {
             mEnabled = enabled;
@@ -1245,15 +1259,15 @@ public class ContactEditorFragment extends Fragment implements
     }
 
     /**
-     * Returns a {@link RawContactDelta} for a local contact suitable for addition into
-     * {@link #mState}.
+     * Returns a {@link RawContactDelta} for a local contact suitable for addition into {@link
+     * #mState}.
      */
     private static RawContactDelta createLocalRawContactDelta() {
         final RawContact rawContact = new RawContact();
         rawContact.setAccountToLocal();
 
-        final RawContactDelta result = new RawContactDelta(
-                ValuesDelta.fromAfter(rawContact.getValues()));
+        final RawContactDelta result =
+                new RawContactDelta(ValuesDelta.fromAfter(rawContact.getValues()));
         result.setProfileQueryUri();
 
         return result;
@@ -1268,10 +1282,10 @@ public class ContactEditorFragment extends Fragment implements
         final int writableIndex = mState.indexOfFirstWritableRawContact(getContext());
         final RawContactDelta writable = mState.get(writableIndex);
         final RawContactDelta readOnly = mState.getByRawContactId(mContact.getNameRawContactId());
-        final ValuesDelta writeNameDelta = writable
-                .getSuperPrimaryEntry(StructuredName.CONTENT_ITEM_TYPE);
-        final ValuesDelta readNameDelta = readOnly
-                .getSuperPrimaryEntry(StructuredName.CONTENT_ITEM_TYPE);
+        final ValuesDelta writeNameDelta =
+                writable.getSuperPrimaryEntry(StructuredName.CONTENT_ITEM_TYPE);
+        final ValuesDelta readNameDelta =
+                readOnly.getSuperPrimaryEntry(StructuredName.CONTENT_ITEM_TYPE);
         mCopyReadOnlyName = false;
         if (writeNameDelta == null || readNameDelta == null) {
             return;
@@ -1294,8 +1308,13 @@ public class ContactEditorFragment extends Fragment implements
         if (mCopyReadOnlyName) {
             copyReadOnlyName();
         }
-        editorView.setState(mState, mMaterialPalette, mViewIdGenerator,
-                mHasNewContact, mIsUserProfile, mAccountWithDataSet,
+        editorView.setState(
+                mState,
+                mMaterialPalette,
+                mViewIdGenerator,
+                mHasNewContact,
+                mIsUserProfile,
+                mAccountWithDataSet,
                 mRawContactIdToDisplayAlone);
         if (isEditingReadOnlyRawContact()) {
             final Toolbar toolbar = getEditorActivity().getToolbar();
@@ -1320,8 +1339,8 @@ public class ContactEditorFragment extends Fragment implements
         }
         final StructuredNameEditorView nameEditor = editorView.getNameEditorView();
         final TextFieldsEditorView phoneticNameEditor = editorView.getPhoneticEditorView();
-        final boolean useJapaneseOrder = 
-                       Locale.JAPANESE.getLanguage().equals(Locale.getDefault().getLanguage());
+        final boolean useJapaneseOrder =
+                Locale.JAPANESE.getLanguage().equals(Locale.getDefault().getLanguage());
         if (useJapaneseOrder && nameEditor != null && phoneticNameEditor != null) {
             nameEditor.setPhoneticView(phoneticNameEditor);
         }
@@ -1335,9 +1354,7 @@ public class ContactEditorFragment extends Fragment implements
         invalidateOptionsMenu();
     }
 
-    /**
-     * Invalidates the options menu if we are still associated with an Activity.
-     */
+    /** Invalidates the options menu if we are still associated with an Activity. */
     private void invalidateOptionsMenu() {
         final Activity activity = getActivity();
         if (activity != null) {
@@ -1369,15 +1386,16 @@ public class ContactEditorFragment extends Fragment implements
     }
 
     /**
-     * Removes a current editor ({@link #mState}) and rebinds new editor for a new account.
-     * Some of old data are reused with new restriction enforced by the new account.
+     * Removes a current editor ({@link #mState}) and rebinds new editor for a new account. Some of
+     * old data are reused with new restriction enforced by the new account.
      *
      * @param oldState Old data being edited.
      * @param oldAccount Old account associated with oldState.
      * @param newAccount New account to be used.
      */
     private void rebindEditorsForNewContact(
-            RawContactDelta oldState, AccountWithDataSet oldAccount,
+            RawContactDelta oldState,
+            AccountWithDataSet oldAccount,
             AccountWithDataSet newAccount) {
         AccountTypeManager accountTypes = AccountTypeManager.getInstance(mContext);
         AccountType oldAccountType = accountTypes.getAccountTypeForAccount(oldAccount);
@@ -1386,8 +1404,8 @@ public class ContactEditorFragment extends Fragment implements
         mExistingContactDataReady = false;
         mNewContactDataReady = false;
         mState = new RawContactDeltaList();
-        setStateForNewContact(newAccount, newAccountType, oldState, oldAccountType,
-                isEditingUserProfile());
+        setStateForNewContact(
+                newAccount, newAccountType, oldState, oldAccountType, isEditingUserProfile());
         if (mIsEdit) {
             setStateForExistingContact(isEditingUserProfile(), mRawContacts);
         }
@@ -1411,18 +1429,19 @@ public class ContactEditorFragment extends Fragment implements
         if (mIntentExtras != null) {
             mAutoAddToDefaultGroup =
                     mIntentExtras.containsKey(INTENT_EXTRA_ADD_TO_DEFAULT_DIRECTORY);
-            mNewLocalProfile =
-                    mIntentExtras.getBoolean(INTENT_EXTRA_NEW_LOCAL_PROFILE);
+            mNewLocalProfile = mIntentExtras.getBoolean(INTENT_EXTRA_NEW_LOCAL_PROFILE);
             mDisableDeleteMenuOption =
                     mIntentExtras.getBoolean(INTENT_EXTRA_DISABLE_DELETE_MENU_OPTION);
             if (mIntentExtras.containsKey(INTENT_EXTRA_MATERIAL_PALETTE_PRIMARY_COLOR)
                     && mIntentExtras.containsKey(INTENT_EXTRA_MATERIAL_PALETTE_SECONDARY_COLOR)) {
-                mMaterialPalette = new MaterialColorMapUtils.MaterialPalette(
-                        mIntentExtras.getInt(INTENT_EXTRA_MATERIAL_PALETTE_PRIMARY_COLOR),
-                        mIntentExtras.getInt(INTENT_EXTRA_MATERIAL_PALETTE_SECONDARY_COLOR));
+                mMaterialPalette =
+                        new MaterialColorMapUtils.MaterialPalette(
+                                mIntentExtras.getInt(INTENT_EXTRA_MATERIAL_PALETTE_PRIMARY_COLOR),
+                                mIntentExtras.getInt(
+                                        INTENT_EXTRA_MATERIAL_PALETTE_SECONDARY_COLOR));
             }
-            mRawContactIdToDisplayAlone = mIntentExtras
-                    .getLong(INTENT_EXTRA_RAW_CONTACT_ID_TO_DISPLAY_ALONE);
+            mRawContactIdToDisplayAlone =
+                    mIntentExtras.getLong(INTENT_EXTRA_RAW_CONTACT_ID_TO_DISPLAY_ALONE);
         }
     }
 
@@ -1436,16 +1455,22 @@ public class ContactEditorFragment extends Fragment implements
         onSaveCompleted(false, SaveMode.RELOAD, uri != null, uri, /* joinContactId */ null);
     }
 
-
     private String getNameToDisplay(Uri contactUri) {
         // The contact has been deleted or the uri is otherwise no longer right.
         if (contactUri == null) {
             return null;
         }
         final ContentResolver resolver = mContext.getContentResolver();
-        final Cursor cursor = resolver.query(contactUri, new String[]{
-                ContactsContract.Contacts.DISPLAY_NAME,
-                ContactsContract.Contacts.DISPLAY_NAME_ALTERNATIVE}, null, null, null);
+        final Cursor cursor =
+                resolver.query(
+                        contactUri,
+                        new String[] {
+                            ContactsContract.Contacts.DISPLAY_NAME,
+                            ContactsContract.Contacts.DISPLAY_NAME_ALTERNATIVE
+                        },
+                        null,
+                        null,
+                        null);
 
         if (cursor != null) {
             try {
@@ -1453,8 +1478,8 @@ public class ContactEditorFragment extends Fragment implements
                     final String displayName = cursor.getString(0);
                     final String displayNameAlt = cursor.getString(1);
                     cursor.close();
-                    return ContactDisplayUtils.getPreferredDisplayName(displayName, displayNameAlt,
-                            new ContactsPreferences(mContext));
+                    return ContactDisplayUtils.getPreferredDisplayName(
+                            displayName, displayNameAlt, new ContactsPreferences(mContext));
                 }
             } finally {
                 cursor.close();
@@ -1463,10 +1488,13 @@ public class ContactEditorFragment extends Fragment implements
         return null;
     }
 
-
     @Override
-    public void onSaveCompleted(boolean hadChanges, int saveMode, boolean saveSucceeded,
-            Uri contactLookupUri, Long joinContactId) {
+    public void onSaveCompleted(
+            boolean hadChanges,
+            int saveMode,
+            boolean saveSucceeded,
+            Uri contactLookupUri,
+            Long joinContactId) {
         if (hadChanges) {
             if (saveSucceeded) {
                 switch (saveMode) {
@@ -1480,8 +1508,10 @@ public class ContactEditorFragment extends Fragment implements
                         final String displayName = getNameToDisplay(contactLookupUri);
                         final String toastMessage;
                         if (!TextUtils.isEmpty(displayName)) {
-                            toastMessage = getResources().getString(
-                                    R.string.contactSavedNamedToast, displayName);
+                            toastMessage =
+                                    getResources()
+                                            .getString(
+                                                    R.string.contactSavedNamedToast, displayName);
                         } else {
                             toastMessage = getResources().getString(R.string.contactSavedToast);
                         }
@@ -1493,28 +1523,32 @@ public class ContactEditorFragment extends Fragment implements
             }
         }
         switch (saveMode) {
-            case SaveMode.CLOSE: {
-                final Intent resultIntent;
-                if (saveSucceeded && contactLookupUri != null) {
-                    final Uri lookupUri = ContactEditorUtils.maybeConvertToLegacyLookupUri(
-                            mContext, contactLookupUri, mLookupUri);
-                    resultIntent = ImplicitIntentsUtil.composeQuickContactIntent(
-                            mContext, lookupUri, ScreenType.EDITOR);
-                    resultIntent.putExtra(QuickContactActivity.EXTRA_CONTACT_EDITED, true);
-                } else {
-                    resultIntent = null;
+            case SaveMode.CLOSE:
+                {
+                    final Intent resultIntent;
+                    if (saveSucceeded && contactLookupUri != null) {
+                        final Uri lookupUri =
+                                ContactEditorUtils.maybeConvertToLegacyLookupUri(
+                                        mContext, contactLookupUri, mLookupUri);
+                        resultIntent =
+                                ImplicitIntentsUtil.composeQuickContactIntent(
+                                        mContext, lookupUri, ScreenType.EDITOR);
+                        resultIntent.putExtra(QuickContactActivity.EXTRA_CONTACT_EDITED, true);
+                    } else {
+                        resultIntent = null;
+                    }
+                    // It is already saved, so prevent it from being saved again
+                    mStatus = Status.CLOSING;
+                    if (mListener != null) mListener.onSaveFinished(resultIntent);
+                    break;
+                }
+            case SaveMode.EDITOR:
+                {
+                    // It is already saved, so prevent it from being saved again
+                    mStatus = Status.CLOSING;
+                    if (mListener != null) mListener.onSaveFinished(/* resultIntent= */ null);
+                    break;
                 }
-                // It is already saved, so prevent it from being saved again
-                mStatus = Status.CLOSING;
-                if (mListener != null) mListener.onSaveFinished(resultIntent);
-                break;
-            }
-            case SaveMode.EDITOR: {
-                // It is already saved, so prevent it from being saved again
-                mStatus = Status.CLOSING;
-                if (mListener != null) mListener.onSaveFinished(/* resultIntent= */ null);
-                break;
-            }
             case SaveMode.JOIN:
                 if (saveSucceeded && contactLookupUri != null && joinContactId != null) {
                     joinAggregate(joinContactId);
@@ -1563,11 +1597,9 @@ public class ContactEditorFragment extends Fragment implements
     // Aggregation PopupWindow
     //
 
-    /**
-     * Triggers an asynchronous search for aggregation suggestions.
-     */
-    protected void acquireAggregationSuggestions(Context context,
-            long rawContactId, ValuesDelta valuesDelta) {
+    /** Triggers an asynchronous search for aggregation suggestions. */
+    protected void acquireAggregationSuggestions(
+            Context context, long rawContactId, ValuesDelta valuesDelta) {
         mAggregationSuggestionsRawContactId = rawContactId;
 
         if (mAggregationSuggestionEngine == null) {
@@ -1583,9 +1615,7 @@ public class ContactEditorFragment extends Fragment implements
         mAggregationSuggestionEngine.onNameChange(valuesDelta);
     }
 
-    /**
-     * Returns the contact ID for the currently edited contact or 0 if the contact is new.
-     */
+    /** Returns the contact ID for the currently edited contact or 0 if the contact is new. */
     private long getContactId() {
         for (RawContactDelta rawContact : mState) {
             Long contactId = rawContact.getValues().getAsLong(RawContacts.CONTACT_ID);
@@ -1600,7 +1630,9 @@ public class ContactEditorFragment extends Fragment implements
     public void onAggregationSuggestionChange() {
         final Activity activity = getActivity();
         if ((activity != null && activity.isFinishing())
-                || !isVisible() ||  mState.isEmpty() || mStatus != Status.EDITING) {
+                || !isVisible()
+                || mState.isEmpty()
+                || mStatus != Status.EDITING) {
             return;
         }
 
@@ -1621,30 +1653,31 @@ public class ContactEditorFragment extends Fragment implements
         mAggregationSuggestionPopup.setAdapter(
                 new AggregationSuggestionAdapter(
                         getActivity(),
-                        /* listener =*/ this,
+                        /* listener= */ this,
                         mAggregationSuggestionEngine.getSuggestions()));
-        mAggregationSuggestionPopup.setOnItemClickListener(new AdapterView.OnItemClickListener() {
-            @Override
-            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
-                final AggregationSuggestionView suggestionView = (AggregationSuggestionView) view;
-                suggestionView.handleItemClickEvent();
-                UiClosables.closeQuietly(mAggregationSuggestionPopup);
-                mAggregationSuggestionPopup = null;
-            }
-        });
+        mAggregationSuggestionPopup.setOnItemClickListener(
+                new AdapterView.OnItemClickListener() {
+                    @Override
+                    public void onItemClick(
+                            AdapterView<?> parent, View view, int position, long id) {
+                        final AggregationSuggestionView suggestionView =
+                                (AggregationSuggestionView) view;
+                        suggestionView.handleItemClickEvent();
+                        UiClosables.closeQuietly(mAggregationSuggestionPopup);
+                        mAggregationSuggestionPopup = null;
+                    }
+                });
         mAggregationSuggestionPopup.show();
     }
 
-    /**
-     * Returns the editor view that should be used as the anchor for aggregation suggestions.
-     */
+    /** Returns the editor view that should be used as the anchor for aggregation suggestions. */
     protected View getAggregationAnchorView() {
         return getContent().getAggregationAnchorView();
     }
 
     /**
-     * Joins the suggested contact (specified by the id's of constituent raw
-     * contacts), save all changes, and stay in the editor.
+     * Joins the suggested contact (specified by the id's of constituent raw contacts), save all
+     * changes, and stay in the editor.
      */
     public void doJoinSuggestedContact(long[] rawContactIds) {
         if (!hasValidState() || mStatus != Status.EDITING) {
@@ -1668,14 +1701,14 @@ public class ContactEditorFragment extends Fragment implements
         if (mListener != null) {
             // make sure we don't save this contact when closing down
             mStatus = Status.CLOSING;
-            mListener.onEditOtherRawContactRequested(contactUri, rawContactId,
+            mListener.onEditOtherRawContactRequested(
+                    contactUri,
+                    rawContactId,
                     getContent().getCurrentRawContactDelta().getContentValues());
         }
     }
 
-    /**
-     * Sets group metadata on all bound editors.
-     */
+    /** Sets group metadata on all bound editors. */
     protected void setGroupMetaData() {
         if (mGroupMetaData != null) {
             getContent().setGroupMetaData(mGroupMetaData);
@@ -1686,20 +1719,26 @@ public class ContactEditorFragment extends Fragment implements
      * Persist the accumulated editor deltas.
      *
      * @param joinContactId the raw contact ID to join the contact being saved to after the save,
-     *         may be null.
+     *     may be null.
      */
     protected boolean doSaveAction(int saveMode, Long joinContactId) {
-        final Intent intent = ContactSaveService.createSaveContactIntent(mContext, mState,
-                SAVE_MODE_EXTRA_KEY, saveMode, isEditingUserProfile(),
-                ((Activity) mContext).getClass(),
-                ContactEditorActivity.ACTION_SAVE_COMPLETED, mUpdatedPhotos,
-                JOIN_CONTACT_ID_EXTRA_KEY, joinContactId);
+        final Intent intent =
+                ContactSaveService.createSaveContactIntent(
+                        mContext,
+                        mState,
+                        SAVE_MODE_EXTRA_KEY,
+                        saveMode,
+                        isEditingUserProfile(),
+                        ((Activity) mContext).getClass(),
+                        ContactEditorActivity.ACTION_SAVE_COMPLETED,
+                        mUpdatedPhotos,
+                        JOIN_CONTACT_ID_EXTRA_KEY,
+                        joinContactId);
         return startSaveService(mContext, intent, saveMode);
     }
 
     private boolean startSaveService(Context context, Intent intent, int saveMode) {
-        final boolean result = ContactSaveService.startService(
-                context, intent, saveMode);
+        final boolean result = ContactSaveService.startService(context, intent, saveMode);
         if (!result) {
             onCancelEditConfirmed();
         }
@@ -1710,13 +1749,15 @@ public class ContactEditorFragment extends Fragment implements
     // Join Activity
     //
 
-    /**
-     * Performs aggregation with the contact selected by the user from suggestions or A-Z list.
-     */
+    /** Performs aggregation with the contact selected by the user from suggestions or A-Z list. */
     protected void joinAggregate(final long contactId) {
-        final Intent intent = ContactSaveService.createJoinContactsIntent(
-                mContext, mContactIdForJoin, contactId, ContactEditorActivity.class,
-                ContactEditorActivity.ACTION_JOIN_COMPLETED);
+        final Intent intent =
+                ContactSaveService.createJoinContactsIntent(
+                        mContext,
+                        mContactIdForJoin,
+                        contactId,
+                        ContactEditorActivity.class,
+                        ContactEditorActivity.ACTION_JOIN_COMPLETED);
         mContext.startService(intent);
     }
 
@@ -1728,8 +1769,8 @@ public class ContactEditorFragment extends Fragment implements
     public void updatePhoto(Uri uri) throws FileNotFoundException {
         final Bitmap bitmap = ContactPhotoUtils.getBitmapFromUri(getActivity(), uri);
         if (bitmap == null || bitmap.getHeight() <= 0 || bitmap.getWidth() <= 0) {
-            Toast.makeText(mContext, R.string.contactPhotoSavedErrorToast,
-                    Toast.LENGTH_SHORT).show();
+            Toast.makeText(mContext, R.string.contactPhotoSavedErrorToast, Toast.LENGTH_SHORT)
+                    .show();
             return;
         }
         mUpdatedPhotos.putParcelable(String.valueOf(mPhotoRawContactId), uri);
@@ -1750,8 +1791,10 @@ public class ContactEditorFragment extends Fragment implements
     }
 
     @Override
-    public void onRebindEditorsForNewContact(RawContactDelta oldState,
-            AccountWithDataSet oldAccount, AccountWithDataSet newAccount) {
+    public void onRebindEditorsForNewContact(
+            RawContactDelta oldState,
+            AccountWithDataSet oldAccount,
+            AccountWithDataSet newAccount) {
         mNewContactAccountChanged = true;
         rebindEditorsForNewContact(oldState, oldAccount, newAccount);
     }
@@ -1760,8 +1803,7 @@ public class ContactEditorFragment extends Fragment implements
     public void onBindEditorsFailed() {
         final Activity activity = getActivity();
         if (activity != null && !activity.isFinishing()) {
-            Toast.makeText(activity, R.string.editor_failed_to_load,
-                    Toast.LENGTH_SHORT).show();
+            Toast.makeText(activity, R.string.editor_failed_to_load, Toast.LENGTH_SHORT).show();
             activity.setResult(Activity.RESULT_CANCELED);
             activity.finish();
         }
@@ -1784,7 +1826,8 @@ public class ContactEditorFragment extends Fragment implements
     }
 
     private int getPhotoMode() {
-        return getContent().isWritablePhotoSet() ? PhotoActionPopup.Modes.WRITE_ABLE_PHOTO
+        return getContent().isWritablePhotoSet()
+                ? PhotoActionPopup.Modes.WRITE_ABLE_PHOTO
                 : PhotoActionPopup.Modes.NO_PHOTO;
     }
 
@@ -1804,45 +1847,46 @@ public class ContactEditorFragment extends Fragment implements
         }
         boolean shouldRestoreSoftInput = savedInstanceState.getBoolean(KEY_RESTORE_SOFT_INPUT);
         new Handler()
-            .postDelayed(
-                    () -> {
-                        if (!isResumed()) {
-                            return;
-                        }
-                        View root = getView();
-                        if (root == null) {
-                            return;
-                        }
-                        View focusedView = root.findFocus();
-                        if (focusedView != null) {
-                            return;
-                        }
-                        focusedView = getView().findViewById(focusedViewId);
-                        if (focusedView == null) {
-                            return;
-                        }
-                        boolean didFocus = focusedView.requestFocus();
-                        if (!didFocus) {
-                            Log.i(TAG, "requestFocus failed");
-                            return;
-                        }
-                        if (shouldRestoreSoftInput) {
-                            boolean didShow = inputMethodManager
-                                .showSoftInput(focusedView, InputMethodManager.SHOW_IMPLICIT);
-                            if (Log.isLoggable(TAG, Log.DEBUG)) {
-                                Log.d(TAG, "showSoftInput -> " + didShow);
+                .postDelayed(
+                        () -> {
+                            if (!isResumed()) {
+                                return;
                             }
-                        }
-                    },
-            RESTORE_FOCUS_DELAY_MILLIS);
+                            View root = getView();
+                            if (root == null) {
+                                return;
+                            }
+                            View focusedView = root.findFocus();
+                            if (focusedView != null) {
+                                return;
+                            }
+                            focusedView = getView().findViewById(focusedViewId);
+                            if (focusedView == null) {
+                                return;
+                            }
+                            boolean didFocus = focusedView.requestFocus();
+                            if (!didFocus) {
+                                Log.i(TAG, "requestFocus failed");
+                                return;
+                            }
+                            if (shouldRestoreSoftInput) {
+                                boolean didShow =
+                                        inputMethodManager.showSoftInput(
+                                                focusedView, InputMethodManager.SHOW_IMPLICIT);
+                                if (Log.isLoggable(TAG, Log.DEBUG)) {
+                                    Log.d(TAG, "showSoftInput -> " + didShow);
+                                }
+                            }
+                        },
+                        RESTORE_FOCUS_DELAY_MILLIS);
     }
 
     private void hideSoftKeyboard() {
-        InputMethodManager imm = (InputMethodManager) mContext.getSystemService(
-            Context.INPUT_METHOD_SERVICE);
+        InputMethodManager imm =
+                (InputMethodManager) mContext.getSystemService(Context.INPUT_METHOD_SERVICE);
         if (imm != null && mContent != null) {
             imm.hideSoftInputFromWindow(
-                mContent.getWindowToken(), InputMethodManager.HIDE_NOT_ALWAYS);
+                    mContent.getWindowToken(), InputMethodManager.HIDE_NOT_ALWAYS);
         }
     }
 }
diff --git a/src/com/android/contacts/editor/ContactEditorUtils.java b/src/com/android/contacts/editor/ContactEditorUtils.java
index 0e9b5c90b..232c1e40b 100644
--- a/src/com/android/contacts/editor/ContactEditorUtils.java
+++ b/src/com/android/contacts/editor/ContactEditorUtils.java
@@ -30,11 +30,11 @@ import android.text.TextUtils;
 import com.android.contacts.model.account.AccountWithDataSet;
 import com.android.contacts.preference.ContactsPreferences;
 
+import com.google.common.annotations.VisibleForTesting;
+
 import java.util.List;
 
-/**
- * Utility methods for the "account changed" notification in the new contact creation flow.
- */
+/** Utility methods for the "account changed" notification in the new contact creation flow. */
 public class ContactEditorUtils {
     private static final String TAG = "ContactEditorUtils";
 
@@ -51,22 +51,24 @@ public class ContactEditorUtils {
     }
 
     /**
-     * Returns a legacy version of the given contactLookupUri if a legacy Uri was originally
-     * passed to the contact editor.
+     * Returns a legacy version of the given contactLookupUri if a legacy Uri was originally passed
+     * to the contact editor.
      *
      * @param contactLookupUri The Uri to possibly convert to legacy format.
-     * @param requestLookupUri The lookup Uri originally passed to the contact editor
-     *                         (via Intent data), may be null.
+     * @param requestLookupUri The lookup Uri originally passed to the contact editor (via Intent
+     *     data), may be null.
      */
-    static Uri maybeConvertToLegacyLookupUri(Context context, Uri contactLookupUri,
-            Uri requestLookupUri) {
+    static Uri maybeConvertToLegacyLookupUri(
+            Context context, Uri contactLookupUri, Uri requestLookupUri) {
         final String legacyAuthority = "contacts";
-        final String requestAuthority = requestLookupUri == null
-                ? null : requestLookupUri.getAuthority();
+        final String requestAuthority =
+                requestLookupUri == null ? null : requestLookupUri.getAuthority();
         if (legacyAuthority.equals(requestAuthority)) {
             // Build a legacy Uri if that is what was requested by caller
-            final long contactId = ContentUris.parseId(ContactsContract.Contacts.lookupContact(
-                    context.getContentResolver(), contactLookupUri));
+            final long contactId =
+                    ContentUris.parseId(
+                            ContactsContract.Contacts.lookupContact(
+                                    context.getContentResolver(), contactLookupUri));
             final Uri legacyContentUri = Uri.parse("content://contacts/people");
             return ContentUris.withAppendedId(legacyContentUri, contactId);
         }
@@ -74,36 +76,26 @@ public class ContactEditorUtils {
         return contactLookupUri;
     }
 
+    @VisibleForTesting
     void cleanupForTest() {
         mContactsPrefs.clearDefaultAccount();
     }
 
+    @VisibleForTesting
     void removeDefaultAccountForTest() {
         mContactsPrefs.clearDefaultAccount();
     }
 
-    /**
-     * Saves the default account, which can later be obtained with {@link #getOnlyOrDefaultAccount}.
-     *
-     * This should be called when saving a newly created contact.
-     *
-     * @param defaultAccount the account used to save a newly created contact.
-     */
-    public void saveDefaultAccount(AccountWithDataSet defaultAccount) {
-        if (defaultAccount == null) {
-            mContactsPrefs.clearDefaultAccount();
-        } else {
-            mContactsPrefs.setDefaultAccount(defaultAccount);
-        }
+    @VisibleForTesting
+    void setDefaultAccountForTest(AccountWithDataSet account) {
+        mContactsPrefs.setDefaultAccountForTest(account);
     }
 
     /**
-     * @return the first account if there is only a single account or the default account saved
-     * with {@link #saveDefaultAccount}.
-     *
-     * A null return value indicates that there is multiple accounts and a default hasn't been set
-     *
-     * Also note that the returned account may have been removed already.
+     * @return the first account if there is only a single account or the default account.
+     *     <p>A null return value indicates that there is multiple accounts and a default hasn't
+     *     been set
+     *     <p>Also note that the returned account may have been removed already.
      */
     public AccountWithDataSet getOnlyOrDefaultAccount(
             List<AccountWithDataSet> currentWritableAccounts) {
@@ -118,33 +110,17 @@ public class ContactEditorUtils {
         return mContactsPrefs.shouldShowAccountChangedNotification(writableAccounts);
     }
 
-    /**
-     * Sets the only non-device account to be default if it is not already.
-     */
-    public void maybeUpdateDefaultAccount(List<AccountWithDataSet> currentWritableAccounts) {
-        if (currentWritableAccounts.size() == 1) {
-            final AccountWithDataSet onlyAccount = currentWritableAccounts.get(0);
-            if (!onlyAccount.equals(AccountWithDataSet.getLocalAccount(mContext))
-                    && !onlyAccount.equals(mContactsPrefs.getDefaultAccount())) {
-                mContactsPrefs.setDefaultAccount(onlyAccount);
-            }
-        }
-    }
-
     /**
      * Parses a result from {@link AccountManager#newChooseAccountIntent(Account, List, String[],
-     *     String, String, String[], Bundle)} and returns the created {@link Account}, or null if
-     * the user has canceled the wizard.
+     * String, String, String[], Bundle)} and returns the created {@link Account}, or null if the
+     * user has canceled the wizard.
      *
-     * <p>Pass the {@code resultCode} and {@code data} parameters passed to
-     * {@link Activity#onActivityResult} or {@link android.app.Fragment#onActivityResult}.
-     * </p>
+     * <p>Pass the {@code resultCode} and {@code data} parameters passed to {@link
+     * Activity#onActivityResult} or {@link android.app.Fragment#onActivityResult}.
      *
-     * <p>
-     * Note although the return type is {@link AccountWithDataSet}, return values from this method
-     * will never have {@link AccountWithDataSet#dataSet} set, as there's no way to create an
+     * <p>Note although the return type is {@link AccountWithDataSet}, return values from this
+     * method will never have {@link AccountWithDataSet#dataSet} set, as there's no way to create an
      * extension package account from setup wizard.
-     * </p>
      */
     public AccountWithDataSet getCreatedAccount(int resultCode, Intent resultData) {
         // Javadoc doesn't say anything about resultCode but that the data intent will be non null
diff --git a/src/com/android/contacts/editor/SelectAccountDialogFragment.java b/src/com/android/contacts/editor/SelectAccountDialogFragment.java
index 3b41c86ad..9b3959b70 100644
--- a/src/com/android/contacts/editor/SelectAccountDialogFragment.java
+++ b/src/com/android/contacts/editor/SelectAccountDialogFragment.java
@@ -33,6 +33,7 @@ import com.android.contacts.model.account.AccountWithDataSet;
 import com.android.contacts.model.account.AccountsLoader;
 import com.android.contacts.util.AccountsListAdapter;
 import com.google.common.base.Preconditions;
+import com.google.common.base.Predicate;
 
 import java.util.List;
 
@@ -50,7 +51,7 @@ public final class SelectAccountDialogFragment extends DialogFragment
     private static final String KEY_EXTRA_ARGS = "extra_args";
 
     private AccountsListAdapter mAccountsAdapter;
-    private AccountTypeManager.AccountFilter mFilter;
+    private Predicate<AccountInfo> mFilter;
 
     /**
      * Show the dialog.
@@ -82,9 +83,14 @@ public final class SelectAccountDialogFragment extends DialogFragment
     public void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
         final Bundle args = getArguments();
-        mFilter = (AccountTypeManager.AccountFilter) args.getSerializable(KEY_LIST_FILTER);
-        if (mFilter == null) {
+        AccountTypeManager.AccountFilter filter =
+            (AccountTypeManager.AccountFilter) args.getSerializable(KEY_LIST_FILTER);
+        if (filter == null) {
             mFilter = AccountTypeManager.AccountFilter.ALL;
+        } else if (filter == AccountTypeManager.AccountFilter.CONTACTS_INSERTABLE) {
+            mFilter = AccountTypeManager.insertableFilter(getActivity());
+        } else {
+            mFilter = filter;
         }
     }
 
diff --git a/src/com/android/contacts/interactions/ImportDialogFragment.java b/src/com/android/contacts/interactions/ImportDialogFragment.java
index 693536a9b..6a4634b44 100644
--- a/src/com/android/contacts/interactions/ImportDialogFragment.java
+++ b/src/com/android/contacts/interactions/ImportDialogFragment.java
@@ -117,7 +117,7 @@ public class ImportDialogFragment extends DialogFragment {
 
         // Start loading the accounts. This is done in onResume in case they were refreshed.
         mAccountsFuture = AccountTypeManager.getInstance(getActivity()).filterAccountsAsync(
-                AccountTypeManager.writableFilter());
+                AccountTypeManager.insertableFilter(getActivity()));
     }
 
     @Override
@@ -286,7 +286,7 @@ public class ImportDialogFragment extends DialogFragment {
             args.putInt(KEY_SUBSCRIPTION_ID, subscriptionId);
             SelectAccountDialogFragment.show(
                     getFragmentManager(), R.string.dialog_new_contact_account,
-                    AccountTypeManager.AccountFilter.CONTACTS_WRITABLE, args);
+                    AccountTypeManager.AccountFilter.CONTACTS_INSERTABLE, args);
         } else {
             AccountSelectionUtil.doImport(getActivity(), resId,
                     (size == 1 ? accountList.get(0) : null),
diff --git a/src/com/android/contacts/list/AccountFilterActivity.java b/src/com/android/contacts/list/AccountFilterActivity.java
index 6559489fd..a37cd173b 100644
--- a/src/com/android/contacts/list/AccountFilterActivity.java
+++ b/src/com/android/contacts/list/AccountFilterActivity.java
@@ -29,6 +29,7 @@ import android.widget.AdapterView;
 import android.widget.BaseAdapter;
 import android.widget.ListView;
 
+import com.android.contacts.MoreContactUtils;
 import com.android.contacts.R;
 import com.android.contacts.model.AccountTypeManager;
 
@@ -59,6 +60,7 @@ public class AccountFilterActivity extends Activity implements AdapterView.OnIte
     protected void onCreate(Bundle icicle) {
         super.onCreate(icicle);
         setContentView(R.layout.contact_list_filter);
+        MoreContactUtils.setupEdgeToEdge(this, null);
 
         mListView = (ListView) findViewById(android.R.id.list);
         mListView.setOnItemClickListener(this);
@@ -68,17 +70,17 @@ public class AccountFilterActivity extends Activity implements AdapterView.OnIte
             actionBar.setDisplayHomeAsUpEnabled(true);
         }
 
-        mCurrentFilterType = ContactListFilterController.getInstance(this).isCustomFilterPersisted()
-                ? ContactListFilter.FILTER_TYPE_CUSTOM
-                : ContactListFilter.FILTER_TYPE_ALL_ACCOUNTS;
+        mCurrentFilterType =
+                ContactListFilterController.getInstance(this).isCustomFilterPersisted()
+                        ? ContactListFilter.FILTER_TYPE_CUSTOM
+                        : ContactListFilter.FILTER_TYPE_ALL_ACCOUNTS;
 
         // We don't need to use AccountFilterUtil.FilterLoader since we only want to show
         // the "All contacts" and "Customize" options.
         final List<ContactListFilter> filters = new ArrayList<>();
-        filters.add(ContactListFilter.createFilterWithType(
-                ContactListFilter.FILTER_TYPE_ALL_ACCOUNTS));
-        filters.add(ContactListFilter.createFilterWithType(
-                ContactListFilter.FILTER_TYPE_CUSTOM));
+        filters.add(
+                ContactListFilter.createFilterWithType(ContactListFilter.FILTER_TYPE_ALL_ACCOUNTS));
+        filters.add(ContactListFilter.createFilterWithType(ContactListFilter.FILTER_TYPE_CUSTOM));
         mListView.setAdapter(new FilterListAdapter(this, filters, mCurrentFilterType));
     }
 
@@ -90,9 +92,11 @@ public class AccountFilterActivity extends Activity implements AdapterView.OnIte
         if (filter.filterType == ContactListFilter.FILTER_TYPE_CUSTOM) {
             mCustomFilterView = listFilterView;
             mIsCustomFilterViewSelected = listFilterView.isChecked();
-            final Intent intent = new Intent(this, CustomContactListFilterActivity.class)
-                    .putExtra(CustomContactListFilterActivity.EXTRA_CURRENT_LIST_FILTER_TYPE,
-                            mCurrentFilterType);
+            final Intent intent =
+                    new Intent(this, CustomContactListFilterActivity.class)
+                            .putExtra(
+                                    CustomContactListFilterActivity.EXTRA_CURRENT_LIST_FILTER_TYPE,
+                                    mCurrentFilterType);
             listFilterView.setActivated(true);
             // Switching activity has the highest priority. So when we open another activity, the
             // announcement that indicates an account is checked will be interrupted. This is the
@@ -111,8 +115,9 @@ public class AccountFilterActivity extends Activity implements AdapterView.OnIte
 
     @Override
     protected void onActivityResult(int requestCode, int resultCode, Intent data) {
-        if (resultCode == Activity.RESULT_CANCELED && mCustomFilterView != null &&
-                !mIsCustomFilterViewSelected) {
+        if (resultCode == Activity.RESULT_CANCELED
+                && mCustomFilterView != null
+                && !mIsCustomFilterViewSelected) {
             mCustomFilterView.setActivated(false);
             return;
         }
@@ -122,15 +127,17 @@ public class AccountFilterActivity extends Activity implements AdapterView.OnIte
         }
 
         switch (requestCode) {
-            case SUBACTIVITY_CUSTOMIZE_FILTER: {
-                final Intent intent = new Intent();
-                ContactListFilter filter = ContactListFilter.createFilterWithType(
-                        ContactListFilter.FILTER_TYPE_CUSTOM);
-                intent.putExtra(EXTRA_CONTACT_LIST_FILTER, filter);
-                setResult(Activity.RESULT_OK, intent);
-                finish();
-                break;
-            }
+            case SUBACTIVITY_CUSTOMIZE_FILTER:
+                {
+                    final Intent intent = new Intent();
+                    ContactListFilter filter =
+                            ContactListFilter.createFilterWithType(
+                                    ContactListFilter.FILTER_TYPE_CUSTOM);
+                    intent.putExtra(EXTRA_CONTACT_LIST_FILTER, filter);
+                    setResult(Activity.RESULT_OK, intent);
+                    finish();
+                    break;
+                }
         }
     }
 
@@ -140,10 +147,9 @@ public class AccountFilterActivity extends Activity implements AdapterView.OnIte
         private final AccountTypeManager mAccountTypes;
         private final int mCurrentFilter;
 
-        public FilterListAdapter(
-                Context context, List<ContactListFilter> filters, int current) {
-            mLayoutInflater = (LayoutInflater) context.getSystemService
-                    (Context.LAYOUT_INFLATER_SERVICE);
+        public FilterListAdapter(Context context, List<ContactListFilter> filters, int current) {
+            mLayoutInflater =
+                    (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
             mFilters = filters;
             mCurrentFilter = current;
             mAccountTypes = AccountTypeManager.getInstance(context);
@@ -169,8 +175,10 @@ public class AccountFilterActivity extends Activity implements AdapterView.OnIte
             if (convertView != null) {
                 view = (ContactListFilterView) convertView;
             } else {
-                view = (ContactListFilterView) mLayoutInflater.inflate(
-                        R.layout.contact_list_filter_item, parent, false);
+                view =
+                        (ContactListFilterView)
+                                mLayoutInflater.inflate(
+                                        R.layout.contact_list_filter_item, parent, false);
             }
             view.setSingleAccount(mFilters.size() == 1);
             final ContactListFilter filter = mFilters.get(position);
diff --git a/src/com/android/contacts/list/ContactListFilter.java b/src/com/android/contacts/list/ContactListFilter.java
index 091a0c2b8..7446970dc 100644
--- a/src/com/android/contacts/list/ContactListFilter.java
+++ b/src/com/android/contacts/list/ContactListFilter.java
@@ -32,9 +32,7 @@ import com.android.contacts.model.account.GoogleAccountType;
 import java.util.ArrayList;
 import java.util.List;
 
-/**
- * Contact list filter parameters.
- */
+/** Contact list filter parameters. */
 public final class ContactListFilter implements Comparable<ContactListFilter>, Parcelable {
 
     public static final int FILTER_TYPE_DEFAULT = -1;
@@ -50,10 +48,10 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
     public static final int FILTER_TYPE_ACCOUNT = 0;
 
     /**
-     * Obsolete filter which had been used in Honeycomb. This may be stored in
-     * {@link SharedPreferences}, but should be replaced with ALL filter when it is found.
+     * Obsolete filter which had been used in Honeycomb. This may be stored in {@link
+     * SharedPreferences}, but should be replaced with ALL filter when it is found.
      *
-     * TODO: "group" filter and relevant variables are all obsolete. Remove them.
+     * <p>TODO: "group" filter and relevant variables are all obsolete. Remove them.
      */
     private static final int FILTER_TYPE_GROUP = 1;
 
@@ -69,8 +67,8 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
     public final Drawable icon;
     private String mId;
 
-    public ContactListFilter(int filterType, String accountType, String accountName, String dataSet,
-            Drawable icon) {
+    public ContactListFilter(
+            int filterType, String accountType, String accountName, String dataSet, Drawable icon) {
         this.filterType = filterType;
         this.accountType = accountType;
         this.accountName = accountName;
@@ -82,38 +80,54 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
         return new ContactListFilter(filterType, null, null, null, null);
     }
 
-    public static ContactListFilter createAccountFilter(String accountType, String accountName,
-            String dataSet, Drawable icon) {
-        return new ContactListFilter(ContactListFilter.FILTER_TYPE_ACCOUNT, accountType,
-                accountName, dataSet, icon);
+    public static ContactListFilter createAccountFilter(
+            String accountType, String accountName, String dataSet, Drawable icon) {
+        return new ContactListFilter(
+                ContactListFilter.FILTER_TYPE_ACCOUNT, accountType, accountName, dataSet, icon);
     }
 
-    public static ContactListFilter createGroupMembersFilter(String accountType, String accountName,
-            String dataSet) {
-        return new ContactListFilter(ContactListFilter.FILTER_TYPE_GROUP_MEMBERS, accountType,
-                accountName, dataSet, /* icon */ null);
+    public static ContactListFilter createGroupMembersFilter(
+            String accountType, String accountName, String dataSet) {
+        return new ContactListFilter(
+                ContactListFilter.FILTER_TYPE_GROUP_MEMBERS,
+                accountType,
+                accountName,
+                dataSet, /* icon */
+                null);
     }
 
     public static ContactListFilter createDeviceContactsFilter(Drawable icon) {
-        return new ContactListFilter(ContactListFilter.FILTER_TYPE_DEVICE_CONTACTS,
-                /* accountType= */ null, /* accountName= */ null, /* dataSet= */ null, icon);
+        return new ContactListFilter(
+                ContactListFilter.FILTER_TYPE_DEVICE_CONTACTS,
+                /* accountType= */ null,
+                /* accountName= */ null,
+                /* dataSet= */ null,
+                icon);
     }
 
-    public static ContactListFilter createDeviceContactsFilter(Drawable icon,
-            AccountWithDataSet account) {
-        return new ContactListFilter(ContactListFilter.FILTER_TYPE_DEVICE_CONTACTS,
-                account.type, account.name, account.dataSet, icon);
+    public static ContactListFilter createDeviceContactsFilter(
+            Drawable icon, AccountWithDataSet account) {
+        return new ContactListFilter(
+                ContactListFilter.FILTER_TYPE_DEVICE_CONTACTS,
+                account.type,
+                account.name,
+                account.dataSet,
+                icon);
     }
 
-    public static ContactListFilter createSimContactsFilter(Drawable icon,
-            AccountWithDataSet account) {
-        return new ContactListFilter(ContactListFilter.FILTER_TYPE_SIM_CONTACTS,
-                account.type, account.name, account.dataSet, icon);
+    public static ContactListFilter createSimContactsFilter(
+            Drawable icon, AccountWithDataSet account) {
+        return new ContactListFilter(
+                ContactListFilter.FILTER_TYPE_SIM_CONTACTS,
+                account.type,
+                account.name,
+                account.dataSet,
+                icon);
     }
 
     /**
-     * Whether the given {@link ContactListFilter} has a filter type that should be displayed as
-     * the default contacts list view.
+     * Whether the given {@link ContactListFilter} has a filter type that should be displayed as the
+     * default contacts list view.
      */
     public boolean isContactsFilterType() {
         return filterType == ContactListFilter.FILTER_TYPE_DEFAULT
@@ -121,11 +135,20 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
                 || filterType == ContactListFilter.FILTER_TYPE_CUSTOM;
     }
 
+    /**
+     * Whether the given {@link ContactListFilter} has a filter type for contacts that are stored
+     * only locally, such as on the SIM card or device only account.
+     */
+    public boolean isLocalAccountTypeFilter() {
+        return filterType == ContactListFilter.FILTER_TYPE_DEVICE_CONTACTS
+                || filterType == ContactListFilter.FILTER_TYPE_SIM_CONTACTS;
+    }
+
     /** Returns the {@link ListEvent.ListType} for the type of this filter. */
     public int toListType() {
         switch (filterType) {
             case FILTER_TYPE_DEFAULT:
-                // Fall through
+            // Fall through
             case FILTER_TYPE_ALL_ACCOUNTS:
                 return ListEvent.ListType.ALL_CONTACTS;
             case FILTER_TYPE_CUSTOM:
@@ -146,10 +169,7 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
         return ListEvent.ListType.UNKNOWN_LIST;
     }
 
-
-    /**
-     * Returns true if this filter is based on data and may become invalid over time.
-     */
+    /** Returns true if this filter is based on data and may become invalid over time. */
     public boolean isValidationRequired() {
         return filterType == FILTER_TYPE_ACCOUNT;
     }
@@ -170,8 +190,11 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
             case FILTER_TYPE_SINGLE_CONTACT:
                 return "single";
             case FILTER_TYPE_ACCOUNT:
-                return "account: " + accountType + (dataSet != null ? "/" + dataSet : "")
-                        + " " + accountName;
+                return "account: "
+                        + accountType
+                        + (dataSet != null ? "/" + dataSet : "")
+                        + " "
+                        + accountName;
             case FILTER_TYPE_GROUP_MEMBERS:
                 return "group_members";
             case FILTER_TYPE_DEVICE_CONTACTS:
@@ -232,25 +255,25 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
     }
 
     /**
-     * Store the given {@link ContactListFilter} to preferences. If the requested filter is
-     * of type {@link #FILTER_TYPE_SINGLE_CONTACT} then do not save it to preferences because
-     * it is a temporary state.
+     * Store the given {@link ContactListFilter} to preferences. If the requested filter is of type
+     * {@link #FILTER_TYPE_SINGLE_CONTACT} then do not save it to preferences because it is a
+     * temporary state.
      */
     public static void storeToPreferences(SharedPreferences prefs, ContactListFilter filter) {
         if (filter != null && filter.filterType == FILTER_TYPE_SINGLE_CONTACT) {
             return;
         }
         prefs.edit()
-            .putInt(KEY_FILTER_TYPE, filter == null ? FILTER_TYPE_DEFAULT : filter.filterType)
-            .putString(KEY_ACCOUNT_NAME, filter == null ? null : filter.accountName)
-            .putString(KEY_ACCOUNT_TYPE, filter == null ? null : filter.accountType)
-            .putString(KEY_DATA_SET, filter == null ? null : filter.dataSet)
-            .apply();
+                .putInt(KEY_FILTER_TYPE, filter == null ? FILTER_TYPE_DEFAULT : filter.filterType)
+                .putString(KEY_ACCOUNT_NAME, filter == null ? null : filter.accountName)
+                .putString(KEY_ACCOUNT_TYPE, filter == null ? null : filter.accountType)
+                .putString(KEY_DATA_SET, filter == null ? null : filter.dataSet)
+                .apply();
     }
 
     /**
-     * Try to obtain ContactListFilter object saved in SharedPreference.
-     * If there's no info there, return ALL filter instead.
+     * Try to obtain ContactListFilter object saved in SharedPreference. If there's no info there,
+     * return ALL filter instead.
      */
     public static ContactListFilter restoreDefaultPreferences(SharedPreferences prefs) {
         ContactListFilter filter = restoreFromPreferences(prefs);
@@ -259,8 +282,8 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
         }
         // "Group" filter is obsolete and thus is not exposed anymore. The "single contact mode"
         // should also not be stored in preferences anymore since it is a temporary state.
-        if (filter.filterType == FILTER_TYPE_GROUP ||
-                filter.filterType == FILTER_TYPE_SINGLE_CONTACT) {
+        if (filter.filterType == FILTER_TYPE_GROUP
+                || filter.filterType == FILTER_TYPE_SINGLE_CONTACT) {
             filter = ContactListFilter.createFilterWithType(FILTER_TYPE_ALL_ACCOUNTS);
         }
         return filter;
@@ -278,7 +301,6 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
         return new ContactListFilter(filterType, accountType, accountName, dataSet, null);
     }
 
-
     @Override
     public void writeToParcel(Parcel dest, int flags) {
         dest.writeInt(filterType);
@@ -289,29 +311,28 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
 
     public static final Parcelable.Creator<ContactListFilter> CREATOR =
             new Parcelable.Creator<ContactListFilter>() {
-        @Override
-        public ContactListFilter createFromParcel(Parcel source) {
-            int filterType = source.readInt();
-            String accountName = source.readString();
-            String accountType = source.readString();
-            String dataSet = source.readString();
-            return new ContactListFilter(filterType, accountType, accountName, dataSet, null);
-        }
+                @Override
+                public ContactListFilter createFromParcel(Parcel source) {
+                    int filterType = source.readInt();
+                    String accountName = source.readString();
+                    String accountType = source.readString();
+                    String dataSet = source.readString();
+                    return new ContactListFilter(
+                            filterType, accountType, accountName, dataSet, null);
+                }
 
-        @Override
-        public ContactListFilter[] newArray(int size) {
-            return new ContactListFilter[size];
-        }
-    };
+                @Override
+                public ContactListFilter[] newArray(int size) {
+                    return new ContactListFilter[size];
+                }
+            };
 
     @Override
     public int describeContents() {
         return 0;
     }
 
-    /**
-     * Returns a string that can be used as a stable persistent identifier for this filter.
-     */
+    /** Returns a string that can be used as a stable persistent identifier for this filter. */
     public String getId() {
         if (mId == null) {
             StringBuilder sb = new StringBuilder();
@@ -334,11 +355,10 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
      * Adds the account query parameters to the given {@code uriBuilder}.
      *
      * @throws IllegalStateException if the filter type is not {@link #FILTER_TYPE_ACCOUNT} or
-     * {@link #FILTER_TYPE_GROUP_MEMBERS}.
+     *     {@link #FILTER_TYPE_GROUP_MEMBERS}.
      */
     public Uri.Builder addAccountQueryParameterToUrl(Uri.Builder uriBuilder) {
-        if (filterType != FILTER_TYPE_ACCOUNT
-                && filterType != FILTER_TYPE_GROUP_MEMBERS) {
+        if (filterType != FILTER_TYPE_ACCOUNT && filterType != FILTER_TYPE_GROUP_MEMBERS) {
             throw new IllegalStateException(
                     "filterType must be FILTER_TYPE_ACCOUNT or FILER_TYPE_GROUP_MEMBERS");
         }
@@ -354,12 +374,13 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
     }
 
     public AccountWithDataSet toAccountWithDataSet() {
-        if (filterType == FILTER_TYPE_ACCOUNT || filterType == FILTER_TYPE_DEVICE_CONTACTS
+        if (filterType == FILTER_TYPE_ACCOUNT
+                || filterType == FILTER_TYPE_DEVICE_CONTACTS
                 || filterType == FILTER_TYPE_SIM_CONTACTS) {
             return new AccountWithDataSet(accountName, accountType, dataSet);
         } else {
-            throw new IllegalStateException("Cannot create Account from filter type " +
-                    filterTypeToString(filterType));
+            throw new IllegalStateException(
+                    "Cannot create Account from filter type " + filterTypeToString(filterType));
         }
     }
 
@@ -463,8 +484,8 @@ public final class ContactListFilter implements Comparable<ContactListFilter>, P
     }
 
     /**
-     * Returns true if this ContactListFilter is Google account type. (i.e. where
-     * accountType = "com.google" and dataSet = null)
+     * Returns true if this ContactListFilter is Google account type. (i.e. where accountType =
+     * "com.google" and dataSet = null)
      */
     public boolean isGoogleAccountType() {
         return GoogleAccountType.ACCOUNT_TYPE.equals(accountType) && dataSet == null;
diff --git a/src/com/android/contacts/list/DefaultContactBrowseListFragment.java b/src/com/android/contacts/list/DefaultContactBrowseListFragment.java
index 2aacabe20..6c13cacba 100644
--- a/src/com/android/contacts/list/DefaultContactBrowseListFragment.java
+++ b/src/com/android/contacts/list/DefaultContactBrowseListFragment.java
@@ -37,8 +37,6 @@ import android.os.Bundle;
 import android.os.Handler;
 import android.provider.ContactsContract;
 import android.provider.ContactsContract.Directory;
-import androidx.core.content.ContextCompat;
-import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
 import android.text.TextUtils;
 import android.util.Log;
 import android.view.Gravity;
@@ -57,6 +55,9 @@ import android.widget.LinearLayout.LayoutParams;
 import android.widget.TextView;
 import android.widget.Toast;
 
+import androidx.core.content.ContextCompat;
+import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
+
 import com.android.contacts.ContactSaveService;
 import com.android.contacts.Experiments;
 import com.android.contacts.R;
@@ -66,12 +67,14 @@ import com.android.contacts.compat.CompatUtils;
 import com.android.contacts.interactions.ContactDeletionInteraction;
 import com.android.contacts.interactions.ContactMultiDeletionInteraction;
 import com.android.contacts.interactions.ContactMultiDeletionInteraction.MultiContactDeleteListener;
+import com.android.contacts.list.ContactListFilterController.ContactListFilterListener;
 import com.android.contacts.logging.ListEvent;
 import com.android.contacts.logging.Logger;
 import com.android.contacts.logging.ScreenEvent;
 import com.android.contacts.model.AccountTypeManager;
 import com.android.contacts.model.account.AccountInfo;
 import com.android.contacts.model.account.AccountWithDataSet;
+import com.android.contacts.preference.ContactsPreferences;
 import com.android.contacts.quickcontact.QuickContactActivity;
 import com.android.contacts.util.AccountFilterUtil;
 import com.android.contacts.util.ImplicitIntentsUtil;
@@ -79,6 +82,7 @@ import com.android.contacts.util.SharedPreferenceUtil;
 import com.android.contacts.util.SyncUtil;
 import com.android.contactsbind.FeatureHighlightHelper;
 import com.android.contactsbind.experiments.Flags;
+
 import com.google.common.util.concurrent.Futures;
 
 import java.util.HashMap;
@@ -88,11 +92,11 @@ import java.util.Map;
 import java.util.concurrent.Future;
 
 /**
- * Fragment containing a contact list used for browsing (as compared to
- * picking a contact with one of the PICK intents).
+ * Fragment containing a contact list used for browsing (as compared to picking a contact with one
+ * of the PICK intents).
  */
 public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
-        implements EnableGlobalSyncDialogFragment.Listener {
+        implements EnableGlobalSyncDialogFragment.Listener, ContactListFilterListener {
 
     private static final String TAG = "DefaultListFragment";
     private static final String ENABLE_DEBUG_OPTIONS_HIDDEN_CODE = "debug debug!";
@@ -110,14 +114,15 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
 
     private SwipeRefreshLayout mSwipeRefreshLayout;
     private final Handler mHandler = new Handler();
-    private final Runnable mCancelRefresh = new Runnable() {
-        @Override
-        public void run() {
-            if (mSwipeRefreshLayout.isRefreshing()) {
-                mSwipeRefreshLayout.setRefreshing(false);
-            }
-        }
-    };
+    private final Runnable mCancelRefresh =
+            new Runnable() {
+                @Override
+                public void run() {
+                    if (mSwipeRefreshLayout.isRefreshing()) {
+                        mSwipeRefreshLayout.setRefreshing(false);
+                    }
+                }
+            };
 
     private View mAlertContainer;
     private TextView mAlertText;
@@ -132,10 +137,9 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
     private boolean mCanSetActionBar = false;
 
     /**
-     * If {@link #configureFragment()} is already called. Used to avoid calling it twice
-     * in {@link #onResume()}.
-     * (This initialization only needs to be done once in onResume() when the Activity was just
-     * created from scratch -- i.e. onCreate() was just called)
+     * If {@link #configureFragment()} is already called. Used to avoid calling it twice in {@link
+     * #onResume()}. (This initialization only needs to be done once in onResume() when the Activity
+     * was just created from scratch -- i.e. onCreate() was just called)
      */
     private boolean mFragmentInitialized;
 
@@ -162,88 +166,99 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
 
     private Future<List<AccountInfo>> mWritableAccountsFuture;
 
-    private final ActionBarAdapter.Listener mActionBarListener = new ActionBarAdapter.Listener() {
-        @Override
-        public void onAction(int action) {
-            switch (action) {
-                case ActionBarAdapter.Listener.Action.START_SELECTION_MODE:
-                    displayCheckBoxes(true);
-                    startSearchOrSelectionMode();
-                    break;
-                case ActionBarAdapter.Listener.Action.START_SEARCH_MODE:
-                    if (!mIsRecreatedInstance) {
-                        Logger.logScreenView(mActivity, ScreenEvent.ScreenType.SEARCH);
+    private boolean mCanInsertIntoLocalAccounts;
+
+    private final ActionBarAdapter.Listener mActionBarListener =
+            new ActionBarAdapter.Listener() {
+                @Override
+                public void onAction(int action) {
+                    switch (action) {
+                        case ActionBarAdapter.Listener.Action.START_SELECTION_MODE:
+                            displayCheckBoxes(true);
+                            startSearchOrSelectionMode();
+                            break;
+                        case ActionBarAdapter.Listener.Action.START_SEARCH_MODE:
+                            if (!mIsRecreatedInstance) {
+                                Logger.logScreenView(mActivity, ScreenEvent.ScreenType.SEARCH);
+                            }
+                            startSearchOrSelectionMode();
+                            break;
+                        case ActionBarAdapter.Listener.Action
+                                .BEGIN_STOPPING_SEARCH_AND_SELECTION_MODE:
+                            mActivity.showFabWithAnimation(
+                                    /* showFab */ canInsertIntoCurrentFilter());
+                            break;
+                        case ActionBarAdapter.Listener.Action.STOP_SEARCH_AND_SELECTION_MODE:
+                            // If queryString is empty, fragment data will not be reloaded,
+                            // so hamburger promo should be checked now.
+                            // Otherwise, promo should be checked and displayed after reloading,
+                            // b/30706521.
+                            if (TextUtils.isEmpty(getQueryString())) {
+                                maybeShowHamburgerFeatureHighlight();
+                            }
+                            setQueryTextToFragment("");
+                            maybeHideCheckBoxes();
+                            mActivity.invalidateOptionsMenu();
+                            mActivity.showFabWithAnimation(
+                                    /* showFab */ canInsertIntoCurrentFilter());
+
+                            // Alert user if sync is off and not dismissed before
+                            setSyncOffAlert();
+
+                            // Determine whether the account has pullToRefresh feature
+                            setSwipeRefreshLayoutEnabledOrNot(getFilter());
+                            break;
+                        case ActionBarAdapter.Listener.Action.CHANGE_SEARCH_QUERY:
+                            final String queryString = mActionBarAdapter.getQueryString();
+                            setQueryTextToFragment(queryString);
+                            updateDebugOptionsVisibility(
+                                    ENABLE_DEBUG_OPTIONS_HIDDEN_CODE.equals(queryString));
+                            break;
+                        default:
+                            throw new IllegalStateException(
+                                    "Unknown ActionBarAdapter action: " + action);
                     }
-                    startSearchOrSelectionMode();
-                    break;
-                case ActionBarAdapter.Listener.Action.BEGIN_STOPPING_SEARCH_AND_SELECTION_MODE:
-                    mActivity.showFabWithAnimation(/* showFab */ true);
-                    break;
-                case ActionBarAdapter.Listener.Action.STOP_SEARCH_AND_SELECTION_MODE:
-                    // If queryString is empty, fragment data will not be reloaded,
-                    // so hamburger promo should be checked now.
-                    // Otherwise, promo should be checked and displayed after reloading, b/30706521.
-                    if (TextUtils.isEmpty(getQueryString())) {
-                        maybeShowHamburgerFeatureHighlight();
-                    }
-                    setQueryTextToFragment("");
+                }
+
+                private void startSearchOrSelectionMode() {
+                    configureContactListFragment();
                     maybeHideCheckBoxes();
                     mActivity.invalidateOptionsMenu();
-                    mActivity.showFabWithAnimation(/* showFab */ true);
-
-                    // Alert user if sync is off and not dismissed before
-                    setSyncOffAlert();
-
-                    // Determine whether the account has pullToRefresh feature
-                    setSwipeRefreshLayoutEnabledOrNot(getFilter());
-                    break;
-                case ActionBarAdapter.Listener.Action.CHANGE_SEARCH_QUERY:
-                    final String queryString = mActionBarAdapter.getQueryString();
-                    setQueryTextToFragment(queryString);
-                    updateDebugOptionsVisibility(
-                            ENABLE_DEBUG_OPTIONS_HIDDEN_CODE.equals(queryString));
-                    break;
-                default:
-                    throw new IllegalStateException("Unknown ActionBarAdapter action: " + action);
-            }
-        }
+                    mActivity.showFabWithAnimation(/* showFab */ false);
 
-        private void startSearchOrSelectionMode() {
-            configureContactListFragment();
-            maybeHideCheckBoxes();
-            mActivity.invalidateOptionsMenu();
-            mActivity.showFabWithAnimation(/* showFab */ false);
-
-            final Context context = getContext();
-            if (!SharedPreferenceUtil.getHamburgerPromoTriggerActionHappenedBefore(context)) {
-                SharedPreferenceUtil.setHamburgerPromoTriggerActionHappenedBefore(context);
-            }
-        }
-
-        private void updateDebugOptionsVisibility(boolean visible) {
-            if (mEnableDebugMenuOptions != visible) {
-                mEnableDebugMenuOptions = visible;
-                mActivity.invalidateOptionsMenu();
-            }
-        }
+                    final Context context = getContext();
+                    if (!SharedPreferenceUtil.getHamburgerPromoTriggerActionHappenedBefore(
+                            context)) {
+                        SharedPreferenceUtil.setHamburgerPromoTriggerActionHappenedBefore(context);
+                    }
+                }
 
-        private void setQueryTextToFragment(String query) {
-            setQueryString(query, true);
-            setVisibleScrollbarEnabled(!isSearchMode());
-        }
+                private void updateDebugOptionsVisibility(boolean visible) {
+                    if (mEnableDebugMenuOptions != visible) {
+                        mEnableDebugMenuOptions = visible;
+                        mActivity.invalidateOptionsMenu();
+                    }
+                }
 
-        @Override
-        public void onUpButtonPressed() {
-            mActivity.onBackPressed();
-        }
-    };
+                private void setQueryTextToFragment(String query) {
+                    setQueryString(query, true);
+                    setVisibleScrollbarEnabled(!isSearchMode());
+                }
 
-    private final View.OnClickListener mAddContactListener = new View.OnClickListener() {
-        @Override
-        public void onClick(View v) {
-            AccountFilterUtil.startEditorIntent(getContext(), mActivity.getIntent(), getFilter());
-        }
-    };
+                @Override
+                public void onUpButtonPressed() {
+                    mActivity.onBackPressed();
+                }
+            };
+
+    private final View.OnClickListener mAddContactListener =
+            new View.OnClickListener() {
+                @Override
+                public void onClick(View v) {
+                    AccountFilterUtil.startEditorIntent(
+                            getContext(), mActivity.getIntent(), getFilter());
+                }
+            };
 
     public DefaultContactBrowseListFragment() {
         setPhotoLoaderEnabled(true);
@@ -257,17 +272,15 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
     }
 
     /**
-     * Whether a search result was clicked by the user. Tracked so that we can distinguish
-     * between exiting the search mode after a result was clicked from exiting w/o clicking
-     * any search result.
+     * Whether a search result was clicked by the user. Tracked so that we can distinguish between
+     * exiting the search mode after a result was clicked from exiting w/o clicking any search
+     * result.
      */
     public boolean wasSearchResultClicked() {
         return mSearchResultClicked;
     }
 
-    /**
-     * Resets whether a search result was clicked by the user to false.
-     */
+    /** Resets whether a search result was clicked by the user to false. */
     public void resetSearchResultClicked() {
         mSearchResultClicked = false;
     }
@@ -292,7 +305,8 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
     }
 
     private void maybeShowHamburgerFeatureHighlight() {
-        if (mActionBarAdapter!= null && !mActionBarAdapter.isSearchMode()
+        if (mActionBarAdapter != null
+                && !mActionBarAdapter.isSearchMode()
                 && !mActionBarAdapter.isSelectionMode()
                 && !isTalkbackOnAndOnPreLollipopMr1()
                 && SharedPreferenceUtil.getShouldShowHamburgerPromo(getContext())) {
@@ -304,10 +318,10 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
 
     // There's a crash if we show feature highlight when Talkback is on, on API 21 and below.
     // See b/31180524.
-    private boolean isTalkbackOnAndOnPreLollipopMr1(){
+    private boolean isTalkbackOnAndOnPreLollipopMr1() {
         return ((AccessibilityManager) getContext().getSystemService(Context.ACCESSIBILITY_SERVICE))
-                .isTouchExplorationEnabled()
-                    && !CompatUtils.isLollipopMr1Compatible();
+                        .isTouchExplorationEnabled()
+                && !CompatUtils.isLollipopMr1Compatible();
     }
 
     private void bindListHeader(int numberOfContacts) {
@@ -328,10 +342,14 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         } else if (filter.filterType == ContactListFilter.FILTER_TYPE_CUSTOM) {
             bindListHeaderCustom(getListView(), mAccountFilterContainer);
         } else if (filter.filterType != ContactListFilter.FILTER_TYPE_ALL_ACCOUNTS) {
-            final AccountWithDataSet accountWithDataSet = new AccountWithDataSet(
-                    filter.accountName, filter.accountType, filter.dataSet);
-            bindListHeader(getContext(), getListView(), mAccountFilterContainer,
-                    accountWithDataSet, numberOfContacts);
+            final AccountWithDataSet accountWithDataSet =
+                    new AccountWithDataSet(filter.accountName, filter.accountType, filter.dataSet);
+            bindListHeader(
+                    getContext(),
+                    getListView(),
+                    mAccountFilterContainer,
+                    accountWithDataSet,
+                    numberOfContacts);
         } else {
             hideHeaderAndAddPadding(getContext(), getListView(), mAccountFilterContainer);
         }
@@ -408,7 +426,7 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         adapter.setSectionHeaderDisplayEnabled(isSectionHeaderDisplayEnabled());
         adapter.setDisplayPhotos(true);
         adapter.setPhotoPosition(
-                ContactListItemView.getDefaultPhotoPosition(/* opposite = */ false));
+                ContactListItemView.getDefaultPhotoPosition(/* opposite= */ false));
         return adapter;
     }
 
@@ -439,8 +457,10 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         final ImageView image = (ImageView) emptyHomeView.findViewById(R.id.empty_home_image);
         final LayoutParams params = (LayoutParams) image.getLayoutParams();
         final int screenHeight = getResources().getDisplayMetrics().heightPixels;
-        final int marginTop = screenHeight / 2 -
-                getResources().getDimensionPixelSize(R.dimen.empty_home_view_image_offset) ;
+        final int marginTop =
+                screenHeight / 2
+                        - getResources()
+                                .getDimensionPixelSize(R.dimen.empty_home_view_image_offset);
         params.setMargins(0, marginTop, 0, 0);
         params.gravity = Gravity.CENTER_HORIZONTAL;
         image.setLayoutParams(params);
@@ -478,13 +498,15 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         super.onCreate(savedState);
         mIsRecreatedInstance = (savedState != null);
         mContactListFilterController = ContactListFilterController.getInstance(getContext());
+        mContactListFilterController.addListener(this);
         mContactListFilterController.checkFilterValidity(false);
         // Use FILTER_TYPE_ALL_ACCOUNTS filter if the instance is not a re-created one.
         // This is useful when user upgrades app while an account filter was
         // stored in sharedPreference in a previous version of Contacts app.
-        final ContactListFilter filter = mIsRecreatedInstance
-                ? getFilter()
-                : AccountFilterUtil.createContactsFilter(getContext());
+        final ContactListFilter filter =
+                mIsRecreatedInstance
+                        ? getFilter()
+                        : AccountFilterUtil.createContactsFilter(getContext());
         setContactListFilter(filter);
     }
 
@@ -508,18 +530,20 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         mAlertContainer = getView().findViewById(R.id.alert_container);
         mAlertText = (TextView) mAlertContainer.findViewById(R.id.alert_text);
         mAlertDismissIcon = (ImageView) mAlertContainer.findViewById(R.id.alert_dismiss_icon);
-        mAlertText.setOnClickListener(new View.OnClickListener() {
-            @Override
-            public void onClick(View v) {
-                turnSyncOn();
-            }
-        });
-        mAlertDismissIcon.setOnClickListener(new View.OnClickListener() {
-            @Override
-            public void onClick(View v) {
-                dismiss();
-            }
-        });
+        mAlertText.setOnClickListener(
+                new View.OnClickListener() {
+                    @Override
+                    public void onClick(View v) {
+                        turnSyncOn();
+                    }
+                });
+        mAlertDismissIcon.setOnClickListener(
+                new View.OnClickListener() {
+                    @Override
+                    public void onClick(View v) {
+                        dismiss();
+                    }
+                });
 
         mAlertContainer.setVisibility(View.GONE);
     }
@@ -530,11 +554,11 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
                 && mReasonSyncOff == SyncUtil.SYNC_SETTING_ACCOUNT_SYNC_OFF) {
             ContentResolver.setSyncAutomatically(
                     new Account(filter.accountName, filter.accountType),
-                    ContactsContract.AUTHORITY, true);
+                    ContactsContract.AUTHORITY,
+                    true);
             mAlertContainer.setVisibility(View.GONE);
         } else {
-            final EnableGlobalSyncDialogFragment dialog = new
-                    EnableGlobalSyncDialogFragment();
+            final EnableGlobalSyncDialogFragment dialog = new EnableGlobalSyncDialogFragment();
             dialog.show(this, filter);
         }
     }
@@ -551,8 +575,8 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         final List<Account> syncableAccounts = filter.getSyncableAccounts(accounts);
         if (syncableAccounts != null && syncableAccounts.size() > 0) {
             for (Account account : syncableAccounts) {
-                ContentResolver.setSyncAutomatically(new Account(account.name, account.type),
-                        ContactsContract.AUTHORITY, true);
+                ContentResolver.setSyncAutomatically(
+                        new Account(account.name, account.type), ContactsContract.AUTHORITY, true);
             }
         }
         mAlertContainer.setVisibility(View.GONE);
@@ -576,23 +600,28 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
 
         mSwipeRefreshLayout.setEnabled(true);
         // Request sync contacts
-        mSwipeRefreshLayout.setOnRefreshListener(new SwipeRefreshLayout.OnRefreshListener() {
-            @Override
-            public void onRefresh() {
-                mHandler.removeCallbacks(mCancelRefresh);
-
-                final boolean isNetworkConnected = SyncUtil.isNetworkConnected(getContext());
-                if (!isNetworkConnected) {
-                    mSwipeRefreshLayout.setRefreshing(false);
-                    ((PeopleActivity)getActivity()).showConnectionErrorMsg();
-                    return;
-                }
+        mSwipeRefreshLayout.setOnRefreshListener(
+                new SwipeRefreshLayout.OnRefreshListener() {
+                    @Override
+                    public void onRefresh() {
+                        mHandler.removeCallbacks(mCancelRefresh);
+
+                        final boolean isNetworkConnected =
+                                SyncUtil.isNetworkConnected(getContext());
+                        if (!isNetworkConnected) {
+                            mSwipeRefreshLayout.setRefreshing(false);
+                            ((PeopleActivity) getActivity()).showConnectionErrorMsg();
+                            return;
+                        }
 
-                syncContacts(getFilter());
-                mHandler.postDelayed(mCancelRefresh, Flags.getInstance()
-                        .getInteger(Experiments.PULL_TO_REFRESH_CANCEL_REFRESH_MILLIS));
-            }
-        });
+                        syncContacts(getFilter());
+                        mHandler.postDelayed(
+                                mCancelRefresh,
+                                Flags.getInstance()
+                                        .getInteger(
+                                                Experiments.PULL_TO_REFRESH_CANCEL_REFRESH_MILLIS));
+                    }
+                });
         mSwipeRefreshLayout.setColorSchemeResources(
                 R.color.swipe_refresh_color1,
                 R.color.swipe_refresh_color2,
@@ -615,8 +644,8 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         bundle.putBoolean(ContentResolver.SYNC_EXTRAS_EXPEDITED, true);
         bundle.putBoolean(ContentResolver.SYNC_EXTRAS_MANUAL, true);
 
-        final List<AccountWithDataSet> accounts = AccountInfo.extractAccounts(
-                Futures.getUnchecked(mWritableAccountsFuture));
+        final List<AccountWithDataSet> accounts =
+                AccountInfo.extractAccounts(Futures.getUnchecked(mWritableAccountsFuture));
         final List<Account> syncableAccounts = filter.getSyncableAccounts(accounts);
         if (syncableAccounts != null && syncableAccounts.size() > 0) {
             for (Account account : syncableAccounts) {
@@ -631,9 +660,11 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
 
     private void setSyncOffAlert() {
         final ContactListFilter filter = getFilter();
-        final Account account =  filter.filterType == ContactListFilter.FILTER_TYPE_ACCOUNT
-                && filter.isGoogleAccountType()
-                ? new Account(filter.accountName, filter.accountType) : null;
+        final Account account =
+                filter.filterType == ContactListFilter.FILTER_TYPE_ACCOUNT
+                                && filter.isGoogleAccountType()
+                        ? new Account(filter.accountName, filter.accountType)
+                        : null;
 
         if (account == null && !filter.isContactsFilterType()) {
             mAlertContainer.setVisibility(View.GONE);
@@ -664,9 +695,13 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         super.onActivityCreated(savedInstanceState);
 
         mActivity = (PeopleActivity) getActivity();
-        mActionBarAdapter = new ActionBarAdapter(mActivity, mActionBarListener,
-                mActivity.getSupportActionBar(), mActivity.getToolbar(),
-                R.string.enter_contact_name);
+        mActionBarAdapter =
+                new ActionBarAdapter(
+                        mActivity,
+                        mActionBarListener,
+                        mActivity.getSupportActionBar(),
+                        mActivity.getToolbar(),
+                        R.string.enter_contact_name);
         mActionBarAdapter.setShowHomeIcon(true);
         initializeActionBarAdapter(savedInstanceState);
         if (isSearchMode()) {
@@ -716,8 +751,9 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
                 filter = AccountFilterUtil.createContactsFilter(getContext());
                 break;
             case ContactsRequest.ACTION_CONTACTS_WITH_PHONES:
-                filter = ContactListFilter.createFilterWithType(
-                        ContactListFilter.FILTER_TYPE_WITH_PHONE_NUMBERS_ONLY);
+                filter =
+                        ContactListFilter.createFilterWithType(
+                                ContactListFilter.FILTER_TYPE_WITH_PHONE_NUMBERS_ONLY);
                 break;
 
             case ContactsRequest.ACTION_FREQUENT:
@@ -770,8 +806,31 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         mDisableOptionItemSelected = false;
         maybeHideCheckBoxes();
 
-        mWritableAccountsFuture = AccountTypeManager.getInstance(getContext()).filterAccountsAsync(
-                AccountTypeManager.writableFilter());
+        mWritableAccountsFuture =
+                AccountTypeManager.getInstance(getContext())
+                        .filterAccountsAsync(AccountTypeManager.writableFilter());
+
+        mCanInsertIntoLocalAccounts =
+                new ContactsPreferences(getActivity()).canInsertIntoLocalAccounts();
+        onFabDependencyChanged();
+    }
+
+    @Override
+    public void onContactListFilterChanged() {
+        onFabDependencyChanged();
+    }
+
+    private void onFabDependencyChanged() {
+        if (mActivity != null
+                && mActionBarAdapter != null
+                && !mActionBarAdapter.isSelectionMode()
+                && !isSearchMode()) {
+            mActivity.showFabWithAnimation(canInsertIntoCurrentFilter());
+        }
+    }
+
+    private boolean canInsertIntoCurrentFilter() {
+        return mCanInsertIntoLocalAccounts || !getFilter().isLocalAccountTypeFilter();
     }
 
     private void maybeHideCheckBoxes() {
@@ -780,7 +839,7 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         }
     }
 
-    public ActionBarAdapter getActionBarAdapter(){
+    public ActionBarAdapter getActionBarAdapter() {
         return mActionBarAdapter;
     }
 
@@ -826,8 +885,7 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
                 showSearchProgress(true);
             } else {
                 mSearchProgressText.setText(R.string.listFoundAllContactsZero);
-                mSearchProgressText.sendAccessibilityEvent(
-                        AccessibilityEvent.TYPE_VIEW_SELECTED);
+                mSearchProgressText.sendAccessibilityEvent(AccessibilityEvent.TYPE_VIEW_SELECTED);
                 showSearchProgress(false);
             }
         }
@@ -885,11 +943,13 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         swipeRefreshLayout.setRefreshing(false);
         swipeRefreshLayout.setEnabled(false);
 
-        if (filter != null && !mActionBarAdapter.isSearchMode()
+        if (filter != null
+                && !mActionBarAdapter.isSearchMode()
                 && !mActionBarAdapter.isSelectionMode()) {
             if (filter.isSyncable()
                     || (filter.shouldShowSyncState()
-                    && SyncUtil.hasSyncableAccount(AccountTypeManager.getInstance(getContext())))) {
+                            && SyncUtil.hasSyncableAccount(
+                                    AccountTypeManager.getInstance(getContext())))) {
                 swipeRefreshLayout.setEnabled(true);
             }
         }
@@ -914,16 +974,19 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         ContactBrowserActionListener() {}
 
         @Override
-        public void onSelectionChange() {
-        }
+        public void onSelectionChange() {}
 
         @Override
-        public void onViewContactAction(int position, Uri contactLookupUri,
-                boolean isEnterpriseContact) {
+        public void onViewContactAction(
+                int position, Uri contactLookupUri, boolean isEnterpriseContact) {
             if (isEnterpriseContact) {
                 // No implicit intent as user may have a different contacts app in work profile.
-                ContactsContract.QuickContact.showQuickContact(getContext(), new Rect(),
-                        contactLookupUri, QuickContactActivity.MODE_FULLY_EXPANDED, null);
+                ContactsContract.QuickContact.showQuickContact(
+                        getContext(),
+                        new Rect(),
+                        contactLookupUri,
+                        QuickContactActivity.MODE_FULLY_EXPANDED,
+                        null);
             } else {
                 final int previousScreen;
                 if (isSearchMode()) {
@@ -940,10 +1003,12 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
                     }
                 }
 
-                Logger.logListEvent(ListEvent.ActionType.CLICK,
+                Logger.logListEvent(
+                        ListEvent.ActionType.CLICK,
                         /* listType */ getListTypeIncludingSearch(),
                         /* count */ getAdapter().getCount(),
-                        /* clickedIndex */ position, /* numSelected */ 0);
+                        /* clickedIndex */ position, /* numSelected */
+                        0);
 
                 ImplicitIntentsUtil.startQuickContact(
                         getActivity(), contactLookupUri, previousScreen);
@@ -969,8 +1034,9 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
                 filter = AccountFilterUtil.createContactsFilter(getContext());
                 setFilterAndUpdateTitle(filter);
             } else {
-                filter = ContactListFilter.createFilterWithType(
-                        ContactListFilter.FILTER_TYPE_SINGLE_CONTACT);
+                filter =
+                        ContactListFilter.createFilterWithType(
+                                ContactListFilter.FILTER_TYPE_SINGLE_CONTACT);
                 setFilterAndUpdateTitle(filter, /* restoreSelectedUri */ false);
             }
             setContactListFilter(filter);
@@ -985,12 +1051,10 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         mContactsAvailable = contactsAvailable;
     }
 
-    /**
-     * Set filter via ContactListFilterController
-     */
+    /** Set filter via ContactListFilterController */
     private void setContactListFilter(ContactListFilter filter) {
-        mContactListFilterController.setContactListFilter(filter,
-                /* persistent */ isAllContactsFilter(filter));
+        mContactListFilterController.setContactListFilter(
+                filter, /* persistent */ isAllContactsFilter(filter));
     }
 
     @Override
@@ -1010,28 +1074,30 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
             return;
         }
 
-        final boolean isSearchOrSelectionMode = mActionBarAdapter.isSearchMode()
-                || mActionBarAdapter.isSelectionMode();
+        final boolean isSearchOrSelectionMode =
+                mActionBarAdapter.isSearchMode() || mActionBarAdapter.isSelectionMode();
         makeMenuItemVisible(menu, R.id.menu_search, !isSearchOrSelectionMode);
 
-        final boolean showSelectedContactOptions = mActionBarAdapter.isSelectionMode()
-                && getSelectedContactIds().size() != 0;
+        final boolean showSelectedContactOptions =
+                mActionBarAdapter.isSelectionMode() && getSelectedContactIds().size() != 0;
         makeMenuItemVisible(menu, R.id.menu_share, showSelectedContactOptions);
         makeMenuItemVisible(menu, R.id.menu_delete, showSelectedContactOptions);
-        final boolean showLinkContactsOptions = mActionBarAdapter.isSelectionMode()
-                && getSelectedContactIds().size() > 1;
+        final boolean showLinkContactsOptions =
+                mActionBarAdapter.isSelectionMode() && getSelectedContactIds().size() > 1;
         makeMenuItemVisible(menu, R.id.menu_join, showLinkContactsOptions);
 
         // Debug options need to be visible even in search mode.
-        makeMenuItemVisible(menu, R.id.export_database, mEnableDebugMenuOptions &&
-                hasExportIntentHandler());
+        makeMenuItemVisible(
+                menu, R.id.export_database, mEnableDebugMenuOptions && hasExportIntentHandler());
 
         // Light tint the icons for normal mode, dark tint for search or selection mode.
         for (int i = 0; i < menu.size(); ++i) {
             final Drawable icon = menu.getItem(i).getIcon();
             if (icon != null && !isSearchOrSelectionMode) {
-                icon.mutate().setColorFilter(ContextCompat.getColor(getContext(),
-                        R.color.actionbar_icon_color), PorterDuff.Mode.SRC_ATOP);
+                icon.mutate()
+                        .setColorFilter(
+                                ContextCompat.getColor(getContext(), R.color.actionbar_icon_color),
+                                PorterDuff.Mode.SRC_ATOP);
             }
         }
     }
@@ -1047,8 +1113,9 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         final Intent intent = new Intent();
         intent.setAction("com.android.providers.contacts.DUMP_DATABASE");
         final List<ResolveInfo> receivers =
-                getContext().getPackageManager().queryIntentActivities(intent,
-                PackageManager.MATCH_DEFAULT_ONLY);
+                getContext()
+                        .getPackageManager()
+                        .queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY);
         return receivers != null && receivers.size() > 0;
     }
 
@@ -1074,10 +1141,12 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
             shareSelectedContacts();
             return true;
         } else if (id == R.id.menu_join) {
-            Logger.logListEvent(ListEvent.ActionType.LINK,
-                        /* listType */ getListTypeIncludingSearch(),
-                        /* count */ getAdapter().getCount(), /* clickedIndex */ -1,
-                        /* numSelected */ getAdapter().getSelectedContactIds().size());
+            Logger.logListEvent(
+                    ListEvent.ActionType.LINK,
+                    /* listType */ getListTypeIncludingSearch(),
+                    /* count */ getAdapter().getCount(), /* clickedIndex */
+                    -1,
+                    /* numSelected */ getAdapter().getSelectedContactIds().size());
             joinSelectedContacts();
             return true;
         } else if (id == R.id.menu_delete) {
@@ -1099,10 +1168,11 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
     private void shareSelectedContacts() {
         final StringBuilder uriListBuilder = new StringBuilder();
         for (Long contactId : getSelectedContactIds()) {
-            final Uri contactUri = ContentUris.withAppendedId(
-                    ContactsContract.Contacts.CONTENT_URI, contactId);
-            final Uri lookupUri = ContactsContract.Contacts.getLookupUri(
-                    getContext().getContentResolver(), contactUri);
+            final Uri contactUri =
+                    ContentUris.withAppendedId(ContactsContract.Contacts.CONTENT_URI, contactId);
+            final Uri lookupUri =
+                    ContactsContract.Contacts.getLookupUri(
+                            getContext().getContentResolver(), contactUri);
             if (lookupUri == null) {
                 continue;
             }
@@ -1119,20 +1189,23 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         if (uriListBuilder.length() == 0) {
             return;
         }
-        final Uri uri = Uri.withAppendedPath(
-                ContactsContract.Contacts.CONTENT_MULTI_VCARD_URI,
-                Uri.encode(uriListBuilder.toString()));
+        final Uri uri =
+                Uri.withAppendedPath(
+                        ContactsContract.Contacts.CONTENT_MULTI_VCARD_URI,
+                        Uri.encode(uriListBuilder.toString()));
         final Intent intent = new Intent(Intent.ACTION_SEND);
         intent.setType(ContactsContract.Contacts.CONTENT_VCARD_TYPE);
         intent.putExtra(Intent.EXTRA_STREAM, uri);
         try {
-            MessageFormat msgFormat = new MessageFormat(
-                getResources().getString(R.string.title_share_via),
-                Locale.getDefault());
+            MessageFormat msgFormat =
+                    new MessageFormat(
+                            getResources().getString(R.string.title_share_via),
+                            Locale.getDefault());
             Map<String, Object> arguments = new HashMap<>();
             arguments.put("count", getSelectedContactIds().size());
-            startActivityForResult(Intent.createChooser(intent, msgFormat.format(arguments))
-                    , ACTIVITY_REQUEST_CODE_SHARE);
+            startActivityForResult(
+                    Intent.createChooser(intent, msgFormat.format(arguments)),
+                    ACTIVITY_REQUEST_CODE_SHARE);
         } catch (final ActivityNotFoundException ex) {
             Toast.makeText(getContext(), R.string.share_error, Toast.LENGTH_SHORT).show();
         }
@@ -1140,8 +1213,9 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
 
     private void joinSelectedContacts() {
         final Context context = getContext();
-        final Intent intent = ContactSaveService.createJoinSeveralContactsIntent(
-                context, getSelectedContactIdsArray());
+        final Intent intent =
+                ContactSaveService.createJoinSeveralContactsIntent(
+                        context, getSelectedContactIdsArray());
         context.startService(intent);
 
         mActionBarAdapter.setSelectionMode(false);
@@ -1158,10 +1232,12 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         @Override
         public void onDeletionFinished() {
             // The parameters count and numSelected are both the number of contacts before deletion.
-            Logger.logListEvent(ListEvent.ActionType.DELETE,
-                /* listType */ getListTypeIncludingSearch(),
-                /* count */ getAdapter().getCount(), /* clickedIndex */ -1,
-                /* numSelected */ getSelectedContactIds().size());
+            Logger.logListEvent(
+                    ListEvent.ActionType.DELETE,
+                    /* listType */ getListTypeIncludingSearch(),
+                    /* count */ getAdapter().getCount(), /* clickedIndex */
+                    -1,
+                    /* numSelected */ getSelectedContactIds().size());
             mActionBarAdapter.setSelectionMode(false);
             mIsDeletionInProgress = false;
         }
@@ -1186,18 +1262,22 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
                     onPickerResult(data);
                 }
             case ACTIVITY_REQUEST_CODE_SHARE:
-                Logger.logListEvent(ListEvent.ActionType.SHARE,
-                    /* listType */ getListTypeIncludingSearch(),
-                    /* count */ getAdapter().getCount(), /* clickedIndex */ -1,
-                    /* numSelected */ getAdapter().getSelectedContactIds().size());
+                Logger.logListEvent(
+                        ListEvent.ActionType.SHARE,
+                        /* listType */ getListTypeIncludingSearch(),
+                        /* count */ getAdapter().getCount(), /* clickedIndex */
+                        -1,
+                        /* numSelected */ getAdapter().getSelectedContactIds().size());
 
-// TODO fix or remove multipicker code: ag/54762
-//                else if (resultCode == RESULT_CANCELED && mMode == MODE_PICK_MULTIPLE_PHONES) {
-//                    // Finish the activity if the sub activity was canceled as back key is used
-//                    // to confirm user selection in MODE_PICK_MULTIPLE_PHONES.
-//                    finish();
-//                }
-//                break;
+                // TODO fix or remove multipicker code: ag/54762
+                //                else if (resultCode == RESULT_CANCELED && mMode ==
+                // MODE_PICK_MULTIPLE_PHONES) {
+                //                    // Finish the activity if the sub activity was canceled as
+                // back key is used
+                //                    // to confirm user selection in MODE_PICK_MULTIPLE_PHONES.
+                //                    finish();
+                //                }
+                //                break;
         }
     }
 
@@ -1231,6 +1311,8 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         if (mActionBarAdapter != null) {
             mActionBarAdapter.setListener(null);
         }
+
+        mContactListFilterController.removeListener(this);
         super.onDestroy();
     }
 
@@ -1241,7 +1323,7 @@ public class DefaultContactBrowseListFragment extends ContactBrowseListFragment
         }
 
         if (mActionBarAdapter != null && !mActionBarAdapter.isSearchMode()) {
-            final String query = new String(new int[]{unicodeChar}, 0, 1);
+            final String query = new String(new int[] {unicodeChar}, 0, 1);
             mActionBarAdapter.setSearchMode(true);
             mActionBarAdapter.setQueryString(query);
             return true;
diff --git a/src/com/android/contacts/model/AccountTypeManager.java b/src/com/android/contacts/model/AccountTypeManager.java
index 75beb1cbc..8882d815a 100644
--- a/src/com/android/contacts/model/AccountTypeManager.java
+++ b/src/com/android/contacts/model/AccountTypeManager.java
@@ -43,10 +43,12 @@ import com.android.contacts.model.account.AccountType;
 import com.android.contacts.model.account.AccountTypeProvider;
 import com.android.contacts.model.account.AccountTypeWithDataSet;
 import com.android.contacts.model.account.AccountWithDataSet;
+import com.android.contacts.model.account.DeviceLocalAccountType;
 import com.android.contacts.model.account.FallbackAccountType;
 import com.android.contacts.model.account.GoogleAccountType;
 import com.android.contacts.model.account.SimAccountType;
 import com.android.contacts.model.dataitem.DataKind;
+import com.android.contacts.preference.ContactsPreferences;
 import com.android.contacts.util.concurrent.ContactsExecutors;
 
 import com.google.common.base.Function;
@@ -69,8 +71,8 @@ import java.util.concurrent.Executor;
 import javax.annotation.Nullable;
 
 /**
- * Singleton holder for all parsed {@link AccountType} available on the
- * system, typically filled through {@link PackageManager} queries.
+ * Singleton holder for all parsed {@link AccountType} available on the system, typically filled
+ * through {@link PackageManager} queries.
  */
 public abstract class AccountTypeManager {
     static final String TAG = "AccountTypeManager";
@@ -78,8 +80,8 @@ public abstract class AccountTypeManager {
     private static final Object mInitializationLock = new Object();
     private static AccountTypeManager mAccountTypeManager;
 
-    public static final String BROADCAST_ACCOUNTS_CHANGED = AccountTypeManager.class.getName() +
-            ".AccountsChanged";
+    public static final String BROADCAST_ACCOUNTS_CHANGED =
+            AccountTypeManager.class.getName() + ".AccountsChanged";
 
     public enum AccountFilter implements Predicate<AccountInfo> {
         ALL {
@@ -94,11 +96,22 @@ public abstract class AccountTypeManager {
                 return input != null && input.getType().areContactsWritable();
             }
         },
+        // This should never be used directly because the insertable filter is not
+        // implementable by this enum. Rather it is just a dummy to pass around.
+        // Anything that is passed this should grab the actual implementation from the
+        // insertableFilter function.
+        CONTACTS_INSERTABLE {
+            @Override
+            public boolean apply(@Nullable AccountInfo input) {
+                return false;
+            }
+        },
         DRAWER_DISPLAYABLE {
             @Override
             public boolean apply(@Nullable AccountInfo input) {
-                return input != null && ((input.getType() instanceof SimAccountType)
-                        || input.getType().areContactsWritable());
+                return input != null
+                        && ((input.getType() instanceof SimAccountType)
+                                || input.getType().areContactsWritable());
             }
         },
         GROUPS_WRITABLE {
@@ -110,8 +123,8 @@ public abstract class AccountTypeManager {
     }
 
     /**
-     * Requests the singleton instance of {@link AccountTypeManager} with data bound from
-     * the available authenticators. This method can safely be called from the UI thread.
+     * Requests the singleton instance of {@link AccountTypeManager} with data bound from the
+     * available authenticators. This method can safely be called from the UI thread.
      */
     public static AccountTypeManager getInstance(Context context) {
         if (!hasRequiredPermissions(context)) {
@@ -129,9 +142,9 @@ public abstract class AccountTypeManager {
     }
 
     /**
-     * Set the instance of account type manager.  This is only for and should only be used by unit
-     * tests.  While having this method is not ideal, it's simpler than the alternative of
-     * holding this as a service in the ContactsApplication context class.
+     * Set the instance of account type manager. This is only for and should only be used by unit
+     * tests. While having this method is not ideal, it's simpler than the alternative of holding
+     * this as a service in the ContactsApplication context class.
      *
      * @param mockManager The mock AccountTypeManager.
      */
@@ -141,42 +154,43 @@ public abstract class AccountTypeManager {
         }
     }
 
-    private static final AccountTypeManager EMPTY = new AccountTypeManager() {
+    private static final AccountTypeManager EMPTY =
+            new AccountTypeManager() {
 
-        @Override
-        public ListenableFuture<List<AccountInfo>> getAccountsAsync() {
-            return Futures.immediateFuture(Collections.<AccountInfo>emptyList());
-        }
+                @Override
+                public ListenableFuture<List<AccountInfo>> getAccountsAsync() {
+                    return Futures.immediateFuture(Collections.<AccountInfo>emptyList());
+                }
 
-        @Override
-        public ListenableFuture<List<AccountInfo>> filterAccountsAsync(
-                Predicate<AccountInfo> filter) {
-            return Futures.immediateFuture(Collections.<AccountInfo>emptyList());
-        }
+                @Override
+                public ListenableFuture<List<AccountInfo>> filterAccountsAsync(
+                        Predicate<AccountInfo> filter) {
+                    return Futures.immediateFuture(Collections.<AccountInfo>emptyList());
+                }
 
-        @Override
-        public AccountInfo getAccountInfoForAccount(AccountWithDataSet account) {
-            return null;
-        }
+                @Override
+                public AccountInfo getAccountInfoForAccount(AccountWithDataSet account) {
+                    return null;
+                }
 
-        @Override
-        public Account getDefaultGoogleAccount() {
-            return null;
-        }
+                @Override
+                public Account getDefaultGoogleAccount() {
+                    return null;
+                }
 
-        @Override
-        public AccountType getAccountType(AccountTypeWithDataSet accountTypeWithDataSet) {
-            return null;
-        }
-    };
+                @Override
+                public AccountType getAccountType(AccountTypeWithDataSet accountTypeWithDataSet) {
+                    return null;
+                }
+            };
 
     /**
      * Returns the list of all accounts (if contactWritableOnly is false) or just the list of
      * contact writable accounts (if contactWritableOnly is true).
      *
      * <p>TODO(mhagerott) delete this method. It's left in place to prevent build breakages when
-     * this change is automerged. Usages of this method in downstream branches should be
-     * replaced with an asynchronous account loading pattern</p>
+     * this change is automerged. Usages of this method in downstream branches should be replaced
+     * with an asynchronous account loading pattern
      */
     public List<AccountWithDataSet> getAccounts(boolean contactWritableOnly) {
         return contactWritableOnly
@@ -188,9 +202,9 @@ public abstract class AccountTypeManager {
      * Returns all contact writable accounts
      *
      * <p>In general this method should be avoided. It exists to support some legacy usages of
-     * accounts in infrequently used features where refactoring to asynchronous loading is
-     * not justified. The chance that this will actually block is pretty low if the app has been
-     * launched previously</p>
+     * accounts in infrequently used features where refactoring to asynchronous loading is not
+     * justified. The chance that this will actually block is pretty low if the app has been
+     * launched previously
      */
     public List<AccountWithDataSet> blockForWritableAccounts() {
         return AccountInfo.extractAccounts(
@@ -202,40 +216,36 @@ public abstract class AccountTypeManager {
      */
     public abstract ListenableFuture<List<AccountInfo>> getAccountsAsync();
 
-    /**
-     * Loads accounts and applies the fitler returning only for which the predicate is true
-     */
+    /** Loads accounts and applies the filter returning only for which the predicate is true */
     public abstract ListenableFuture<List<AccountInfo>> filterAccountsAsync(
             Predicate<AccountInfo> filter);
 
     public abstract AccountInfo getAccountInfoForAccount(AccountWithDataSet account);
 
-    /**
-     * Returns the default google account.
-     */
+    /** Returns the default google account. */
     public abstract Account getDefaultGoogleAccount();
 
     /**
      * Returns the Google Accounts.
      *
-     * <p>This method exists in addition to filterAccountsByTypeAsync because it should be safe
-     * to call synchronously.
-     * </p>
+     * <p>This method exists in addition to filterAccountsByTypeAsync because it should be safe to
+     * call synchronously.
      */
     public List<AccountInfo> getWritableGoogleAccounts() {
         // This implementation may block and should be overridden by the Impl class
-        return Futures.getUnchecked(filterAccountsAsync(new Predicate<AccountInfo>() {
-            @Override
-            public boolean apply(@Nullable AccountInfo input) {
-                return  input.getType().areContactsWritable() &&
-                        GoogleAccountType.ACCOUNT_TYPE.equals(input.getType().accountType);
-            }
-        }));
-    }
-
-    /**
-     * Returns true if there are real accounts (not "local" account) in the list of accounts.
-     */
+        return Futures.getUnchecked(
+                filterAccountsAsync(
+                        new Predicate<AccountInfo>() {
+                            @Override
+                            public boolean apply(@Nullable AccountInfo input) {
+                                return input.getType().areContactsWritable()
+                                        && GoogleAccountType.ACCOUNT_TYPE.equals(
+                                                input.getType().accountType);
+                            }
+                        }));
+    }
+
+    /** Returns true if there are real accounts (not "local" account) in the list of accounts. */
     public boolean hasNonLocalAccount() {
         final List<AccountWithDataSet> allAccounts =
                 AccountInfo.extractAccounts(Futures.getUnchecked(getAccountsAsync()));
@@ -248,19 +258,18 @@ public abstract class AccountTypeManager {
         return !allAccounts.get(0).isNullAccount();
     }
 
-    static Account getDefaultGoogleAccount(AccountManager accountManager,
-            SharedPreferences prefs, String defaultAccountKey) {
+    static Account getDefaultGoogleAccount(
+            AccountManager accountManager, SharedPreferences prefs, String defaultAccountKey) {
         // Get all the google accounts on the device
-        final Account[] accounts = accountManager.getAccountsByType(
-                GoogleAccountType.ACCOUNT_TYPE);
+        final Account[] accounts = accountManager.getAccountsByType(GoogleAccountType.ACCOUNT_TYPE);
         if (accounts == null || accounts.length == 0) {
             return null;
         }
 
         // Get the default account from preferences
         final String defaultAccount = prefs.getString(defaultAccountKey, null);
-        final AccountWithDataSet accountWithDataSet = defaultAccount == null ? null :
-                AccountWithDataSet.unstringify(defaultAccount);
+        final AccountWithDataSet accountWithDataSet =
+                defaultAccount == null ? null : AccountWithDataSet.unstringify(defaultAccount);
 
         // Look for an account matching the one from preferences
         if (accountWithDataSet != null) {
@@ -290,17 +299,15 @@ public abstract class AccountTypeManager {
     }
 
     /**
-     * Find the best {@link DataKind} matching the requested
-     * {@link AccountType#accountType}, {@link AccountType#dataSet}, and {@link DataKind#mimeType}.
-     * If no direct match found, we try searching {@link FallbackAccountType}.
+     * Find the best {@link DataKind} matching the requested {@link AccountType#accountType}, {@link
+     * AccountType#dataSet}, and {@link DataKind#mimeType}. If no direct match found, we try
+     * searching {@link FallbackAccountType}.
      */
     public DataKind getKindOrFallback(AccountType type, String mimeType) {
         return type == null ? null : type.getKindForMimetype(mimeType);
     }
 
-    /**
-     * Returns whether the specified account still exists
-     */
+    /** Returns whether the specified account still exists */
     public boolean exists(AccountWithDataSet account) {
         final List<AccountWithDataSet> accounts =
                 AccountInfo.extractAccounts(Futures.getUnchecked(getAccountsAsync()));
@@ -310,8 +317,8 @@ public abstract class AccountTypeManager {
     /**
      * Returns whether the specified account is writable
      *
-     * <p>This checks that the account still exists and that
-     * {@link AccountType#areContactsWritable()} is true</p>
+     * <p>This checks that the account still exists and that {@link
+     * AccountType#areContactsWritable()} is true
      */
     public boolean isWritable(AccountWithDataSet account) {
         return exists(account) && getAccountInfoForAccount(account).getType().areContactsWritable();
@@ -322,10 +329,13 @@ public abstract class AccountTypeManager {
     }
 
     private static boolean hasRequiredPermissions(Context context) {
-        final boolean canGetAccounts = ContextCompat.checkSelfPermission(context,
-                android.Manifest.permission.GET_ACCOUNTS) == PackageManager.PERMISSION_GRANTED;
-        final boolean canReadContacts = ContextCompat.checkSelfPermission(context,
-                android.Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED;
+        final boolean canGetAccounts =
+                ContextCompat.checkSelfPermission(context, android.Manifest.permission.GET_ACCOUNTS)
+                        == PackageManager.PERMISSION_GRANTED;
+        final boolean canReadContacts =
+                ContextCompat.checkSelfPermission(
+                                context, android.Manifest.permission.READ_CONTACTS)
+                        == PackageManager.PERMISSION_GRANTED;
         return canGetAccounts && canReadContacts;
     }
 
@@ -333,6 +343,28 @@ public abstract class AccountTypeManager {
         return AccountFilter.CONTACTS_WRITABLE;
     }
 
+    public static Predicate<AccountInfo> insertableFilter(Context context) {
+        boolean canInsertIntoLocalAccounts =
+                new ContactsPreferences(context).canInsertIntoLocalAccounts();
+        return new Predicate<AccountInfo>() {
+            @Override
+            public boolean apply(@Nullable AccountInfo input) {
+                return input != null
+                        && input.getType().areContactsWritable()
+                        && isContactInsertable(input);
+            }
+
+            private boolean isContactInsertable(AccountInfo input) {
+                return !isLocalAccountType(input) || canInsertIntoLocalAccounts;
+            }
+
+            private boolean isLocalAccountType(AccountInfo input) {
+                return input.getType() instanceof DeviceLocalAccountType
+                        || input.getType() instanceof SimAccountType;
+            }
+        };
+    }
+
     public static Predicate<AccountInfo> drawerDisplayableFilter() {
         return AccountFilter.DRAWER_DISPLAYABLE;
     }
@@ -373,29 +405,29 @@ class AccountTypeManagerImpl extends AccountTypeManager
                 }
             };
 
+    private final BroadcastReceiver mBroadcastReceiver =
+            new BroadcastReceiver() {
+                @Override
+                public void onReceive(Context context, Intent intent) {
+                    // Don't use reloadAccountTypesIfNeeded when packages change in case a
+                    // contacts.xml
+                    // was updated.
+                    reloadAccountTypes();
+                }
+            };
 
-    private final BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
-        @Override
-        public void onReceive(Context context, Intent intent) {
-            // Don't use reloadAccountTypesIfNeeded when packages change in case a contacts.xml
-            // was updated.
-            reloadAccountTypes();
-        }
-    };
-
-    private final BroadcastReceiver mSimBroadcastReceiver = new BroadcastReceiver() {
-        @Override
-        public void onReceive(Context context, Intent intent) {
-            if (ContactsContract.SimContacts.ACTION_SIM_ACCOUNTS_CHANGED.equals(
-                    intent.getAction())) {
-                reloadSimAccounts();
-            }
-        }
-    };
+    private final BroadcastReceiver mSimBroadcastReceiver =
+            new BroadcastReceiver() {
+                @Override
+                public void onReceive(Context context, Intent intent) {
+                    if (ContactsContract.SimContacts.ACTION_SIM_ACCOUNTS_CHANGED.equals(
+                            intent.getAction())) {
+                        reloadSimAccounts();
+                    }
+                }
+            };
 
-    /**
-     * Internal constructor that only performs initial parsing.
-     */
+    /** Internal constructor that only performs initial parsing. */
     public AccountTypeManagerImpl(Context context) {
         mContext = context;
         mLocalAccountLocator = new DeviceLocalAccountLocator(context, AccountManager.get(context));
@@ -423,8 +455,8 @@ class AccountTypeManagerImpl extends AccountTypeManager
         filter = new IntentFilter(Intent.ACTION_LOCALE_CHANGED);
         mContext.registerReceiver(mBroadcastReceiver, filter);
 
-        IntentFilter simFilter = new IntentFilter(
-                ContactsContract.SimContacts.ACTION_SIM_ACCOUNTS_CHANGED);
+        IntentFilter simFilter =
+                new IntentFilter(ContactsContract.SimContacts.ACTION_SIM_ACCOUNTS_CHANGED);
         mContext.registerReceiver(mSimBroadcastReceiver, simFilter, Context.RECEIVER_EXPORTED);
 
         mAccountManager.addOnAccountsUpdatedListener(this, mMainThreadHandler, false);
@@ -442,12 +474,12 @@ class AccountTypeManagerImpl extends AccountTypeManager
     /* This notification will arrive on the UI thread */
     public void onAccountsUpdated(Account[] accounts) {
         reloadLocalAccounts();
-        maybeNotifyAccountsUpdated(mAccountManagerAccounts,
-                getAccountsWithDataSets(accounts, mTypeProvider));
+        maybeNotifyAccountsUpdated(
+                mAccountManagerAccounts, getAccountsWithDataSets(accounts, mTypeProvider));
     }
 
-    private void maybeNotifyAccountsUpdated(List<AccountWithDataSet> current,
-            List<AccountWithDataSet> update) {
+    private void maybeNotifyAccountsUpdated(
+            List<AccountWithDataSet> current, List<AccountWithDataSet> update) {
         if (Objects.equal(current, update)) {
             return;
         }
@@ -458,8 +490,8 @@ class AccountTypeManagerImpl extends AccountTypeManager
 
     private void notifyAccountsChanged() {
         ContactListFilterController.getInstance(mContext).checkFilterValidity(true);
-        LocalBroadcastManager.getInstance(mContext).sendBroadcast(
-                new Intent(BROADCAST_ACCOUNTS_CHANGED));
+        LocalBroadcastManager.getInstance(mContext)
+                .sendBroadcast(new Intent(BROADCAST_ACCOUNTS_CHANGED));
     }
 
     private synchronized void startLoadingIfNeeded() {
@@ -477,14 +509,18 @@ class AccountTypeManagerImpl extends AccountTypeManager
     private synchronized void loadAccountTypes() {
         mTypeProvider = new AccountTypeProvider(mContext);
 
-        mAccountTypesFuture = mExecutor.submit(new Callable<AccountTypeProvider>() {
-            @Override
-            public AccountTypeProvider call() throws Exception {
-                // This will request the AccountType for each Account forcing them to be loaded
-                getAccountsWithDataSets(mAccountManager.getAccounts(), mTypeProvider);
-                return mTypeProvider;
-            }
-        });
+        mAccountTypesFuture =
+                mExecutor.submit(
+                        new Callable<AccountTypeProvider>() {
+                            @Override
+                            public AccountTypeProvider call() throws Exception {
+                                // This will request the AccountType for each Account forcing them
+                                // to be loaded
+                                getAccountsWithDataSets(
+                                        mAccountManager.getAccounts(), mTypeProvider);
+                                return mTypeProvider;
+                            }
+                        });
     }
 
     private FutureCallback<List<AccountWithDataSet>> newAccountsUpdatedCallback(
@@ -496,14 +532,15 @@ class AccountTypeManagerImpl extends AccountTypeManager
             }
 
             @Override
-            public void onFailure(Throwable t) {
-            }
+            public void onFailure(Throwable t) {}
         };
     }
 
     private synchronized void reloadAccountTypesIfNeeded() {
-        if (mTypeProvider == null || mTypeProvider.shouldUpdate(
-                mAccountManager.getAuthenticatorTypes(), ContentResolver.getSyncAdapterTypes())) {
+        if (mTypeProvider == null
+                || mTypeProvider.shouldUpdate(
+                        mAccountManager.getAuthenticatorTypes(),
+                        ContentResolver.getSyncAdapterTypes())) {
             reloadAccountTypes();
         }
     }
@@ -511,47 +548,57 @@ class AccountTypeManagerImpl extends AccountTypeManager
     private synchronized void reloadAccountTypes() {
         loadAccountTypes();
         Futures.addCallback(
-                Futures.transform(mAccountTypesFuture, mAccountsExtractor,
-                        MoreExecutors.directExecutor()),
+                Futures.transform(
+                        mAccountTypesFuture, mAccountsExtractor, MoreExecutors.directExecutor()),
                 newAccountsUpdatedCallback(mAccountManagerAccounts),
                 mMainThreadExecutor);
     }
 
     private synchronized void loadLocalAccounts() {
-        mLocalAccountsFuture = mExecutor.submit(new Callable<List<AccountWithDataSet>>() {
-            @Override
-            public List<AccountWithDataSet> call() throws Exception {
-                return mLocalAccountLocator.getDeviceLocalAccounts();
-            }
-        });
+        mLocalAccountsFuture =
+                mExecutor.submit(
+                        new Callable<List<AccountWithDataSet>>() {
+                            @Override
+                            public List<AccountWithDataSet> call() throws Exception {
+                                return mLocalAccountLocator.getDeviceLocalAccounts();
+                            }
+                        });
     }
 
     private synchronized void reloadLocalAccounts() {
         loadLocalAccounts();
-        Futures.addCallback(mLocalAccountsFuture, newAccountsUpdatedCallback(mLocalAccounts),
+        Futures.addCallback(
+                mLocalAccountsFuture,
+                newAccountsUpdatedCallback(mLocalAccounts),
                 mMainThreadExecutor);
     }
 
     private synchronized void loadSimAccounts() {
-        mSimAccountsFuture = mExecutor.submit(new Callable<List<AccountWithDataSet>>() {
-            @Override
-            public List<AccountWithDataSet> call() throws Exception {
-                List<AccountWithDataSet> simAccountWithDataSets = new ArrayList<>();
-                List<ContactsContract.SimAccount> simAccounts =
-                        ContactsContract.SimContacts.getSimAccounts(mContext.getContentResolver());
-                for (ContactsContract.SimAccount simAccount : simAccounts) {
-                    simAccountWithDataSets.add(new AccountWithDataSet(simAccount.getAccountName(),
-                            simAccount.getAccountType(), null));
-                }
-                return simAccountWithDataSets;
-            }
-        });
+        mSimAccountsFuture =
+                mExecutor.submit(
+                        new Callable<List<AccountWithDataSet>>() {
+                            @Override
+                            public List<AccountWithDataSet> call() throws Exception {
+                                List<AccountWithDataSet> simAccountWithDataSets = new ArrayList<>();
+                                List<ContactsContract.SimAccount> simAccounts =
+                                        ContactsContract.SimContacts.getSimAccounts(
+                                                mContext.getContentResolver());
+                                for (ContactsContract.SimAccount simAccount : simAccounts) {
+                                    simAccountWithDataSets.add(
+                                            new AccountWithDataSet(
+                                                    simAccount.getAccountName(),
+                                                    simAccount.getAccountType(),
+                                                    null));
+                                }
+                                return simAccountWithDataSets;
+                            }
+                        });
     }
 
     private synchronized void reloadSimAccounts() {
         loadSimAccounts();
-        Futures.addCallback(mSimAccountsFuture, newAccountsUpdatedCallback(mSimAccounts),
-                mMainThreadExecutor);
+        Futures.addCallback(
+                mSimAccountsFuture, newAccountsUpdatedCallback(mSimAccounts), mMainThreadExecutor);
     }
 
     @Override
@@ -565,53 +612,65 @@ class AccountTypeManagerImpl extends AccountTypeManager
         final ListenableFuture<List<List<AccountWithDataSet>>> all =
                 Futures.nonCancellationPropagating(
                         Futures.successfulAsList(
-                                Futures.transform(mAccountTypesFuture, mAccountsExtractor,
+                                Futures.transform(
+                                        mAccountTypesFuture,
+                                        mAccountsExtractor,
                                         MoreExecutors.directExecutor()),
                                 mLocalAccountsFuture,
                                 mSimAccountsFuture));
 
-        return Futures.transform(all, new Function<List<List<AccountWithDataSet>>,
-                List<AccountInfo>>() {
-            @Nullable
-            @Override
-            public List<AccountInfo> apply(@Nullable List<List<AccountWithDataSet>> input) {
-                // input.get(0) contains accounts from AccountManager
-                // input.get(1) contains device local accounts
-                // input.get(2) contains SIM accounts
-                Preconditions.checkArgument(input.size() == 3,
-                        "List should have exactly 3 elements");
-
-                final List<AccountInfo> result = new ArrayList<>();
-                for (AccountWithDataSet account : input.get(0)) {
-                    result.add(
-                            typeProvider.getTypeForAccount(account).wrapAccount(mContext, account));
-                }
-
-                for (AccountWithDataSet account : input.get(1)) {
-                    result.add(
-                            typeProvider.getTypeForAccount(account).wrapAccount(mContext, account));
-                }
-
-                for (AccountWithDataSet account : input.get(2)) {
-                    result.add(
-                            typeProvider.getTypeForAccount(account).wrapAccount(mContext, account));
-                }
-                AccountInfo.sortAccounts(null, result);
-                return result;
-            }
-        }, MoreExecutors.directExecutor());
+        return Futures.transform(
+                all,
+                new Function<List<List<AccountWithDataSet>>, List<AccountInfo>>() {
+                    @Nullable
+                    @Override
+                    public List<AccountInfo> apply(@Nullable List<List<AccountWithDataSet>> input) {
+                        // input.get(0) contains accounts from AccountManager
+                        // input.get(1) contains device local accounts
+                        // input.get(2) contains SIM accounts
+                        Preconditions.checkArgument(
+                                input.size() == 3, "List should have exactly 3 elements");
+
+                        final List<AccountInfo> result = new ArrayList<>();
+                        for (AccountWithDataSet account : input.get(0)) {
+                            result.add(
+                                    typeProvider
+                                            .getTypeForAccount(account)
+                                            .wrapAccount(mContext, account));
+                        }
+
+                        for (AccountWithDataSet account : input.get(1)) {
+                            result.add(
+                                    typeProvider
+                                            .getTypeForAccount(account)
+                                            .wrapAccount(mContext, account));
+                        }
+
+                        for (AccountWithDataSet account : input.get(2)) {
+                            result.add(
+                                    typeProvider
+                                            .getTypeForAccount(account)
+                                            .wrapAccount(mContext, account));
+                        }
+                        AccountInfo.sortAccounts(null, result);
+                        return result;
+                    }
+                },
+                MoreExecutors.directExecutor());
     }
 
     @Override
     public ListenableFuture<List<AccountInfo>> filterAccountsAsync(
             final Predicate<AccountInfo> filter) {
-        return Futures.transform(getAllAccountsAsyncInternal(), new Function<List<AccountInfo>,
-                List<AccountInfo>>() {
-            @Override
-            public List<AccountInfo> apply(List<AccountInfo> input) {
-                return new ArrayList<>(Collections2.filter(input, filter));
-            }
-        }, mExecutor);
+        return Futures.transform(
+                getAllAccountsAsyncInternal(),
+                new Function<List<AccountInfo>, List<AccountInfo>>() {
+                    @Override
+                    public List<AccountInfo> apply(List<AccountInfo> input) {
+                        return new ArrayList<>(Collections2.filter(input, filter));
+                    }
+                },
+                mExecutor);
     }
 
     @Override
@@ -626,22 +685,21 @@ class AccountTypeManagerImpl extends AccountTypeManager
         return type.wrapAccount(mContext, account);
     }
 
-    private List<AccountWithDataSet> getAccountsWithDataSets(Account[] accounts,
-            AccountTypeProvider typeProvider) {
+    private List<AccountWithDataSet> getAccountsWithDataSets(
+            Account[] accounts, AccountTypeProvider typeProvider) {
         List<AccountWithDataSet> result = new ArrayList<>();
         for (Account account : accounts) {
             final List<AccountType> types = typeProvider.getAccountTypes(account.type);
             for (AccountType type : types) {
-                result.add(new AccountWithDataSet(
-                        account.name, account.type, type.dataSet));
+                result.add(new AccountWithDataSet(account.name, account.type, type.dataSet));
             }
         }
         return result;
     }
 
     /**
-     * Returns the default google account specified in preferences, the first google account
-     * if it is not specified in preferences or is no longer on the device, and null otherwise.
+     * Returns the default google account specified in preferences, the first google account if it
+     * is not specified in preferences or is no longer on the device, and null otherwise.
      */
     @Override
     public Account getDefaultGoogleAccount() {
@@ -658,8 +716,8 @@ class AccountTypeManagerImpl extends AccountTypeManager
                 mAccountManager.getAccountsByType(GoogleAccountType.ACCOUNT_TYPE);
         final List<AccountInfo> result = new ArrayList<>();
         for (Account account : googleAccounts) {
-            final AccountWithDataSet accountWithDataSet = new AccountWithDataSet(
-                    account.name, account.type, null);
+            final AccountWithDataSet accountWithDataSet =
+                    new AccountWithDataSet(account.name, account.type, null);
             final AccountType type = mTypeProvider.getTypeForAccount(accountWithDataSet);
             if (type != null) {
                 // Accounts with a dataSet (e.g. Google plus accounts) are not writable.
@@ -674,7 +732,6 @@ class AccountTypeManagerImpl extends AccountTypeManager
      *
      * <p>This is overriden for performance since the default implementation blocks until all
      * accounts are loaded
-     * </p>
      */
     @Override
     public boolean hasNonLocalAccount() {
@@ -691,9 +748,9 @@ class AccountTypeManagerImpl extends AccountTypeManager
     }
 
     /**
-     * Find the best {@link DataKind} matching the requested
-     * {@link AccountType#accountType}, {@link AccountType#dataSet}, and {@link DataKind#mimeType}.
-     * If no direct match found, we try searching {@link FallbackAccountType}.
+     * Find the best {@link DataKind} matching the requested {@link AccountType#accountType}, {@link
+     * AccountType#dataSet}, and {@link DataKind#mimeType}. If no direct match found, we try
+     * searching {@link FallbackAccountType}.
      */
     @Override
     public DataKind getKindOrFallback(AccountType type, String mimeType) {
@@ -723,9 +780,8 @@ class AccountTypeManagerImpl extends AccountTypeManager
      *
      * <p>This is overridden for performance. The default implementation loads all accounts then
      * searches through them for specified. This implementation will only load the types for the
-     * specified AccountType (it may still require blocking on IO in some cases but it shouldn't
-     * be as bad as blocking for all accounts).
-     * </p>
+     * specified AccountType (it may still require blocking on IO in some cases but it shouldn't be
+     * as bad as blocking for all accounts).
      */
     @Override
     public boolean exists(AccountWithDataSet account) {
@@ -738,13 +794,12 @@ class AccountTypeManagerImpl extends AccountTypeManager
         return false;
     }
 
-    /**
-     * Return {@link AccountType} for the given account type and data set.
-     */
+    /** Return {@link AccountType} for the given account type and data set. */
     @Override
     public AccountType getAccountType(AccountTypeWithDataSet accountTypeWithDataSet) {
-        final AccountType type = mTypeProvider.getType(
-                accountTypeWithDataSet.accountType, accountTypeWithDataSet.dataSet);
+        final AccountType type =
+                mTypeProvider.getType(
+                        accountTypeWithDataSet.accountType, accountTypeWithDataSet.dataSet);
         return type != null ? type : mFallbackAccountType;
     }
 }
diff --git a/src/com/android/contacts/model/DeviceLocalAccountLocator.java b/src/com/android/contacts/model/DeviceLocalAccountLocator.java
index e8a2ba0ff..fbbed1910 100644
--- a/src/com/android/contacts/model/DeviceLocalAccountLocator.java
+++ b/src/com/android/contacts/model/DeviceLocalAccountLocator.java
@@ -18,17 +18,15 @@ package com.android.contacts.model;
 import android.accounts.Account;
 import android.accounts.AccountManager;
 import android.content.Context;
-import android.provider.ContactsContract;
 
 import com.android.contacts.model.account.AccountWithDataSet;
 import com.android.contacts.model.account.GoogleAccountType;
+import com.android.contacts.preference.ContactsPreferences;
 
 import java.util.Collections;
 import java.util.List;
 
-/**
- * Attempts to detect accounts for device contacts
- */
+/** Attempts to detect accounts for device contacts */
 public final class DeviceLocalAccountLocator {
 
     private final Context mContext;
@@ -41,17 +39,22 @@ public final class DeviceLocalAccountLocator {
         mLocalAccount = Collections.singletonList(AccountWithDataSet.getLocalAccount(context));
     }
 
-    /**
-     * Returns a list of device local accounts
-     */
+    /** Returns a list of device local accounts */
     public List<AccountWithDataSet> getDeviceLocalAccounts() {
-        @SuppressWarnings("MissingPermission") final Account[] accounts = mAccountManager
-                .getAccountsByType(GoogleAccountType.ACCOUNT_TYPE);
+        @SuppressWarnings("MissingPermission")
+        final Account[] accounts =
+                mAccountManager.getAccountsByType(GoogleAccountType.ACCOUNT_TYPE);
 
-        if (accounts.length > 0 && !mLocalAccount.get(0).hasData(mContext)) {
+        if (accounts.length > 0
+                && !mLocalAccount.get(0).hasData(mContext)
+                && !isDeviceLocalDefaultAccount()) {
             return Collections.emptyList();
         } else {
             return mLocalAccount;
         }
     }
+
+    private boolean isDeviceLocalDefaultAccount() {
+        return new ContactsPreferences(mContext).isDeviceLocalDefault();
+    }
 }
diff --git a/src/com/android/contacts/preference/ContactsPreferenceActivity.java b/src/com/android/contacts/preference/ContactsPreferenceActivity.java
index 1658f3d43..038458752 100644
--- a/src/com/android/contacts/preference/ContactsPreferenceActivity.java
+++ b/src/com/android/contacts/preference/ContactsPreferenceActivity.java
@@ -22,18 +22,20 @@ import android.os.Bundle;
 import android.preference.PreferenceActivity;
 import android.provider.ContactsContract.DisplayNameSources;
 import android.provider.ContactsContract.ProviderStatus;
+import android.text.TextUtils;
+import android.view.MenuInflater;
+import android.view.MenuItem;
+import android.view.View;
+import android.view.ViewGroup;
+
 import androidx.annotation.LayoutRes;
 import androidx.annotation.NonNull;
 import androidx.annotation.StringRes;
 import androidx.appcompat.app.ActionBar;
 import androidx.appcompat.app.AppCompatDelegate;
 import androidx.appcompat.widget.Toolbar;
-import android.text.TextUtils;
-import android.view.MenuInflater;
-import android.view.MenuItem;
-import android.view.View;
-import android.view.ViewGroup;
 
+import com.android.contacts.MoreContactUtils;
 import com.android.contacts.R;
 import com.android.contacts.editor.SelectAccountDialogFragment;
 import com.android.contacts.interactions.ImportDialogFragment;
@@ -43,9 +45,7 @@ import com.android.contacts.preference.DisplayOptionsPreferenceFragment.ProfileL
 import com.android.contacts.preference.DisplayOptionsPreferenceFragment.ProfileQuery;
 import com.android.contacts.util.AccountSelectionUtil;
 
-/**
- * Contacts settings.
- */
+/** Contacts settings. */
 public final class ContactsPreferenceActivity extends PreferenceActivity
         implements ProfileListener, SelectAccountDialogFragment.Listener {
 
@@ -68,6 +68,7 @@ public final class ContactsPreferenceActivity extends PreferenceActivity
         super.onCreate(savedInstanceState);
         mCompatDelegate.onCreate(savedInstanceState);
 
+        MoreContactUtils.setupEdgeToEdge(this, null);
 
         final ActionBar actionBar = mCompatDelegate.getSupportActionBar();
         if (actionBar != null) {
@@ -81,15 +82,17 @@ public final class ContactsPreferenceActivity extends PreferenceActivity
         mAreContactsAvailable = providerStatus == ProviderStatus.STATUS_NORMAL;
 
         if (savedInstanceState == null) {
-            final DisplayOptionsPreferenceFragment fragment = DisplayOptionsPreferenceFragment
-                    .newInstance(mNewLocalProfileExtra, mAreContactsAvailable);
-            getFragmentManager().beginTransaction()
+            final DisplayOptionsPreferenceFragment fragment =
+                    DisplayOptionsPreferenceFragment.newInstance(
+                            mNewLocalProfileExtra, mAreContactsAvailable);
+            getFragmentManager()
+                    .beginTransaction()
                     .replace(android.R.id.content, fragment, TAG_DISPLAY_OPTIONS)
                     .commit();
             setActivityTitle(R.string.activity_title_settings);
         } else {
-            final AboutPreferenceFragment aboutFragment = (AboutPreferenceFragment)
-                    getFragmentManager().findFragmentByTag(TAG_ABOUT);
+            final AboutPreferenceFragment aboutFragment =
+                    (AboutPreferenceFragment) getFragmentManager().findFragmentByTag(TAG_ABOUT);
 
             if (aboutFragment != null) {
                 setActivityTitle(R.string.setting_about);
@@ -165,7 +168,8 @@ public final class ContactsPreferenceActivity extends PreferenceActivity
     }
 
     protected void showAboutFragment() {
-        getFragmentManager().beginTransaction()
+        getFragmentManager()
+                .beginTransaction()
                 .replace(android.R.id.content, AboutPreferenceFragment.newInstance(), TAG_ABOUT)
                 .addToBackStack(null)
                 .commit();
@@ -213,18 +217,21 @@ public final class ContactsPreferenceActivity extends PreferenceActivity
         if (hasProfile && TextUtils.isEmpty(displayName)) {
             displayName = getString(R.string.missing_name);
         }
-        final DisplayOptionsPreferenceFragment fragment = (DisplayOptionsPreferenceFragment)
-                getFragmentManager().findFragmentByTag(TAG_DISPLAY_OPTIONS);
+        final DisplayOptionsPreferenceFragment fragment =
+                (DisplayOptionsPreferenceFragment)
+                        getFragmentManager().findFragmentByTag(TAG_DISPLAY_OPTIONS);
         fragment.updateMyInfoPreference(hasProfile, displayName, contactId, displayNameSource);
     }
 
     @Override
     public void onAccountChosen(AccountWithDataSet account, Bundle extraArgs) {
-        AccountSelectionUtil.doImport(this, extraArgs.getInt(ImportDialogFragment
-                .KEY_RES_ID), account, extraArgs.getInt(ImportDialogFragment.KEY_SUBSCRIPTION_ID));
+        AccountSelectionUtil.doImport(
+                this,
+                extraArgs.getInt(ImportDialogFragment.KEY_RES_ID),
+                account,
+                extraArgs.getInt(ImportDialogFragment.KEY_SUBSCRIPTION_ID));
     }
 
     @Override
-    public void onAccountSelectorCancelled() {
-    }
+    public void onAccountSelectorCancelled() {}
 }
diff --git a/src/com/android/contacts/preference/ContactsPreferences.java b/src/com/android/contacts/preference/ContactsPreferences.java
index e1a58d37b..bd535e45b 100644
--- a/src/com/android/contacts/preference/ContactsPreferences.java
+++ b/src/com/android/contacts/preference/ContactsPreferences.java
@@ -16,19 +16,23 @@
 
 package com.android.contacts.preference;
 
+import static android.Manifest.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS;
+
+import android.accounts.Account;
 import android.app.backup.BackupManager;
 import android.content.Context;
 import android.content.SharedPreferences;
 import android.content.SharedPreferences.Editor;
 import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
+import android.content.pm.PackageManager;
 import android.os.Handler;
 import android.os.Looper;
-import android.preference.PreferenceManager;
+import android.os.StrictMode;
+import android.provider.ContactsContract.RawContacts.DefaultAccount;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
 import android.provider.Settings;
 import android.provider.Settings.SettingNotFoundException;
-import android.text.TextUtils;
 
-import androidx.annotation.NonNull;
 import androidx.annotation.VisibleForTesting;
 
 import com.android.contacts.R;
@@ -36,33 +40,23 @@ import com.android.contacts.model.account.AccountWithDataSet;
 
 import java.util.List;
 
-/**
- * Manages user preferences for contacts.
- */
+/** Manages user preferences for contacts. */
 public class ContactsPreferences implements OnSharedPreferenceChangeListener {
 
-    /**
-     * The value for the DISPLAY_ORDER key to show the given name first.
-     */
+    /** The value for the DISPLAY_ORDER key to show the given name first. */
     public static final int DISPLAY_ORDER_PRIMARY = 1;
 
-    /**
-     * The value for the DISPLAY_ORDER key to show the family name first.
-     */
+    /** The value for the DISPLAY_ORDER key to show the family name first. */
     public static final int DISPLAY_ORDER_ALTERNATIVE = 2;
 
     public static final String DISPLAY_ORDER_KEY = "android.contacts.DISPLAY_ORDER";
 
-    /**
-     * The value for the SORT_ORDER key corresponding to sort by given name first.
-     */
+    /** The value for the SORT_ORDER key corresponding to sort by given name first. */
     public static final int SORT_ORDER_PRIMARY = 1;
 
     public static final String SORT_ORDER_KEY = "android.contacts.SORT_ORDER";
 
-    /**
-     * The value for the SORT_ORDER key corresponding to sort by family name first.
-     */
+    /** The value for the SORT_ORDER key corresponding to sort by family name first. */
     public static final int SORT_ORDER_ALTERNATIVE = 2;
 
     public static final String PREF_DISPLAY_ONLY_PHONES = "only_phones";
@@ -89,23 +83,29 @@ public class ContactsPreferences implements OnSharedPreferenceChangeListener {
     private final boolean mIsDefaultAccountUserChangeable;
     private String mDefaultAccountKey;
 
+    private final DefaultAccountReader mDefaultAccountReader;
+
     public ContactsPreferences(Context context) {
-        this(context,
-                context.getResources().getBoolean(R.bool.config_default_account_user_changeable));
+        this(
+                context,
+                context.getResources().getBoolean(R.bool.config_default_account_user_changeable),
+                new SystemDefaultAccountReader(context));
     }
 
     @VisibleForTesting
-    ContactsPreferences(Context context, boolean isDefaultAccountUserChangeable) {
+    ContactsPreferences(
+            Context context, boolean isDefaultAccountUserChangeable, DefaultAccountReader reader) {
         mContext = context;
         mIsDefaultAccountUserChangeable = isDefaultAccountUserChangeable;
+        mDefaultAccountReader = reader;
 
         mBackupManager = new BackupManager(mContext);
 
         mHandler = new Handler(Looper.getMainLooper());
-        mPreferences = mContext.getSharedPreferences(context.getPackageName(),
-                Context.MODE_PRIVATE);
-        mDefaultAccountKey = mContext.getResources().getString(
-                R.string.contact_editor_default_account_key);
+        mPreferences =
+                mContext.getSharedPreferences(context.getPackageName(), Context.MODE_PRIVATE);
+        mDefaultAccountKey =
+                mContext.getResources().getString(R.string.contact_editor_default_account_key);
         maybeMigrateSystemSettings();
     }
 
@@ -178,8 +178,8 @@ public class ContactsPreferences implements OnSharedPreferenceChangeListener {
     }
 
     public boolean isPhoneticNameDisplayPreferenceChangeable() {
-        return mContext.getResources().getBoolean(
-                R.bool.config_phonetic_name_display_user_changeable);
+        return mContext.getResources()
+                .getBoolean(R.bool.config_phonetic_name_display_user_changeable);
     }
 
     public void setPhoneticNameDisplayPreference(int phoneticNameDisplayPreference) {
@@ -195,8 +195,9 @@ public class ContactsPreferences implements OnSharedPreferenceChangeListener {
             return getDefaultPhoneticNameDisplayPreference();
         }
         if (mPhoneticNameDisplayPreference == PREFERENCE_UNASSIGNED) {
-            mPhoneticNameDisplayPreference = mPreferences.getInt(PHONETIC_NAME_DISPLAY_KEY,
-                    getDefaultPhoneticNameDisplayPreference());
+            mPhoneticNameDisplayPreference =
+                    mPreferences.getInt(
+                            PHONETIC_NAME_DISPLAY_KEY, getDefaultPhoneticNameDisplayPreference());
         }
         return mPhoneticNameDisplayPreference;
     }
@@ -209,51 +210,99 @@ public class ContactsPreferences implements OnSharedPreferenceChangeListener {
         return mIsDefaultAccountUserChangeable;
     }
 
+    public boolean canInsertIntoLocalAccounts() {
+        return mDefaultAccountReader.getDefaultAccountAndState().getState()
+                != DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD;
+    }
+
+    public boolean isDeviceLocalDefault() {
+        return mDefaultAccountReader.getDefaultAccountAndState().getState()
+                == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_LOCAL;
+    }
+
     public AccountWithDataSet getDefaultAccount() {
         if (!isDefaultAccountUserChangeable()) {
             return mDefaultAccount;
         }
         if (mDefaultAccount == null) {
-            final String accountString = mPreferences
-                    .getString(mDefaultAccountKey, null);
-            if (!TextUtils.isEmpty(accountString)) {
-                mDefaultAccount = AccountWithDataSet.unstringify(accountString);
-            }
+            mDefaultAccount =
+                    getAccountWithDatasetFromDefaultAccountAndState(
+                            mDefaultAccountReader.getDefaultAccountAndState());
         }
         return mDefaultAccount;
     }
 
+    private AccountWithDataSet getAccountWithDatasetFromDefaultAccountAndState(
+            DefaultAccountAndState defaultAccountAndState) {
+        switch (defaultAccountAndState.getState()) {
+            case DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_NOT_SET:
+                return null;
+            case DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_LOCAL:
+                return AccountWithDataSet.getLocalAccount(mContext);
+            case DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD:
+            case DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_SIM:
+                Account accountOrNull = defaultAccountAndState.getAccount();
+                if (accountOrNull == null) {
+                    return null;
+                }
+                return new AccountWithDataSet(accountOrNull.name, accountOrNull.type, null);
+            default:
+                return null;
+        }
+    }
+
+    private boolean hasSetDefaultAccountPermission() {
+        return mContext.checkSelfPermission(SET_DEFAULT_ACCOUNT_FOR_CONTACTS)
+                == PackageManager.PERMISSION_GRANTED;
+    }
+
     public void clearDefaultAccount() {
-        mDefaultAccount = null;
-        mPreferences.edit().remove(mDefaultAccountKey).commit();
+        if (setDefaultAccountAndState(DefaultAccountAndState.ofNotSet())) {
+            mDefaultAccount = null;
+        }
     }
 
-    public void setDefaultAccount(@NonNull AccountWithDataSet accountWithDataSet) {
-        if (accountWithDataSet == null) {
-            throw new IllegalArgumentException(
-                    "argument should not be null");
+    @VisibleForTesting
+    public boolean setDefaultAccountAndState(DefaultAccountAndState defaultAccountAndState) {
+        if (hasSetDefaultAccountPermission()) {
+            StrictMode.ThreadPolicy oldPolicy = StrictMode.getThreadPolicy();
+            StrictMode.setThreadPolicy(
+                    new StrictMode.ThreadPolicy.Builder(oldPolicy)
+                            .permitDiskWrites()
+                            .permitDiskReads()
+                            .build());
+            try {
+                DefaultAccount.setDefaultAccountForNewContacts(
+                        mContext.getContentResolver(), defaultAccountAndState);
+            } finally {
+                StrictMode.setThreadPolicy(oldPolicy);
+            }
+            return true;
         }
-        mDefaultAccount = accountWithDataSet;
-        mPreferences.edit().putString(mDefaultAccountKey, accountWithDataSet.stringify()).commit();
+        return false;
+    }
+
+    public void setDefaultAccountForTest(AccountWithDataSet account) {
+        mDefaultAccount = account;
     }
 
     public boolean isDefaultAccountSet() {
-        return mDefaultAccount != null || mPreferences.contains(mDefaultAccountKey);
+        return mDefaultAccount != null
+                || mDefaultAccountReader.getDefaultAccountAndState().getState()
+                        != DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_NOT_SET;
     }
 
     /**
      * @return false if there is only one writable account or no requirement to return true is met.
-     *         true if the contact editor should show the "accounts changed" notification, that is:
-     *              - If it's the first launch.
-     *              - Or, if the default account has been removed.
-     *              (And some extra soundness check)
-     *
-     * Note if this method returns {@code false}, the caller can safely assume that
-     * {@link #getDefaultAccount} will return a valid account.  (Either an account which still
-     * exists, or {@code null} which should be interpreted as "local only".)
+     *     true if the contact editor should show the "accounts changed" notification, that is: - If
+     *     it's the first launch. - Or, if the default account has been removed. (And some extra
+     *     soundness check)
+     *     <p>Note if this method returns {@code false}, the caller can safely assume that {@link
+     *     #getDefaultAccount} will return a valid account. (Either an account which still exists,
+     *     or {@code null} which should be interpreted as "local only".)
      */
-    public boolean shouldShowAccountChangedNotification(List<AccountWithDataSet>
-            currentWritableAccounts) {
+    public boolean shouldShowAccountChangedNotification(
+            List<AccountWithDataSet> currentWritableAccounts) {
         final AccountWithDataSet defaultAccount = getDefaultAccount();
 
         AccountWithDataSet localAccount = AccountWithDataSet.getLocalAccount(mContext);
@@ -308,17 +357,18 @@ public class ContactsPreferences implements OnSharedPreferenceChangeListener {
     public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, final String key) {
         // This notification is not sent on the Ui thread. Use the previously created Handler
         // to switch to the Ui thread
-        mHandler.post(new Runnable() {
-            @Override
-            public void run() {
-                refreshValue(key);
-            }
-        });
+        mHandler.post(
+                new Runnable() {
+                    @Override
+                    public void run() {
+                        refreshValue(key);
+                    }
+                });
     }
 
     /**
-     * Forces the value for the given key to be looked up from shared preferences and notifies
-     * the registered {@link ChangeListener}
+     * Forces the value for the given key to be looked up from shared preferences and notifies the
+     * registered {@link ChangeListener}
      *
      * @param key the {@link SharedPreferences} key to look up
      */
@@ -343,19 +393,46 @@ public class ContactsPreferences implements OnSharedPreferenceChangeListener {
         void onChange();
     }
 
+    @VisibleForTesting
+    interface DefaultAccountReader {
+
+        DefaultAccountAndState getDefaultAccountAndState();
+    }
+
+    private static class SystemDefaultAccountReader implements DefaultAccountReader {
+
+        private final Context mContext;
+
+        SystemDefaultAccountReader(Context context) {
+            mContext = context;
+        }
+
+        @Override
+        public DefaultAccountAndState getDefaultAccountAndState() {
+            StrictMode.ThreadPolicy oldPolicy = StrictMode.getThreadPolicy();
+            StrictMode.setThreadPolicy(
+                    new StrictMode.ThreadPolicy.Builder(oldPolicy).permitDiskReads().build());
+            try {
+                return DefaultAccount.getDefaultAccountForNewContacts(
+                        mContext.getContentResolver());
+            } finally {
+                StrictMode.setThreadPolicy(oldPolicy);
+            }
+        }
+    }
+
     /**
-     * If there are currently no preferences (which means this is the first time we are run),
-     * For sort order and display order, check to see if there are any preferences stored in
-     * system settings (pre-L) which can be copied into our own SharedPreferences.
-     * For default account setting, check to see if there are any preferences stored in the previous
-     * SharedPreferences which can be copied into current SharedPreferences.
+     * If there are currently no preferences (which means this is the first time we are run), For
+     * sort order and display order, check to see if there are any preferences stored in system
+     * settings (pre-L) which can be copied into our own SharedPreferences. For default account
+     * setting, check to see if there are any preferences stored in the previous SharedPreferences
+     * which can be copied into current SharedPreferences.
      */
     private void maybeMigrateSystemSettings() {
         if (!mPreferences.contains(SORT_ORDER_KEY)) {
             int sortOrder = getDefaultSortOrder();
             try {
-                 sortOrder = Settings.System.getInt(mContext.getContentResolver(),
-                        SORT_ORDER_KEY);
+                sortOrder = Settings.System.getInt(mContext.getContentResolver(), SORT_ORDER_KEY);
             } catch (SettingNotFoundException e) {
             }
             setSortOrder(sortOrder);
@@ -364,8 +441,8 @@ public class ContactsPreferences implements OnSharedPreferenceChangeListener {
         if (!mPreferences.contains(DISPLAY_ORDER_KEY)) {
             int displayOrder = getDefaultDisplayOrder();
             try {
-                displayOrder = Settings.System.getInt(mContext.getContentResolver(),
-                        DISPLAY_ORDER_KEY);
+                displayOrder =
+                        Settings.System.getInt(mContext.getContentResolver(), DISPLAY_ORDER_KEY);
             } catch (SettingNotFoundException e) {
             }
             setDisplayOrder(displayOrder);
@@ -374,23 +451,12 @@ public class ContactsPreferences implements OnSharedPreferenceChangeListener {
         if (!mPreferences.contains(PHONETIC_NAME_DISPLAY_KEY)) {
             int phoneticNameFieldsDisplay = getDefaultPhoneticNameDisplayPreference();
             try {
-                phoneticNameFieldsDisplay = Settings.System.getInt(mContext.getContentResolver(),
-                        PHONETIC_NAME_DISPLAY_KEY);
+                phoneticNameFieldsDisplay =
+                        Settings.System.getInt(
+                                mContext.getContentResolver(), PHONETIC_NAME_DISPLAY_KEY);
             } catch (SettingNotFoundException e) {
             }
             setPhoneticNameDisplayPreference(phoneticNameFieldsDisplay);
         }
-
-        if (!mPreferences.contains(mDefaultAccountKey)) {
-            final SharedPreferences previousPrefs =
-                    PreferenceManager.getDefaultSharedPreferences(mContext);
-            final String defaultAccount = previousPrefs.getString(mDefaultAccountKey, null);
-            if (!TextUtils.isEmpty(defaultAccount)) {
-                final AccountWithDataSet accountWithDataSet = AccountWithDataSet.unstringify(
-                        defaultAccount);
-                setDefaultAccount(accountWithDataSet);
-            }
-        }
     }
-
 }
diff --git a/src/com/android/contacts/preference/DefaultAccountPreference.java b/src/com/android/contacts/preference/DefaultAccountPreference.java
deleted file mode 100644
index d43b8d574..000000000
--- a/src/com/android/contacts/preference/DefaultAccountPreference.java
+++ /dev/null
@@ -1,112 +0,0 @@
-/*
- * Copyright (C) 2015 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License
- */
-
-package com.android.contacts.preference;
-
-import android.app.AlertDialog;
-import android.content.Context;
-import android.content.DialogInterface;
-import android.preference.DialogPreference;
-import android.util.AttributeSet;
-import android.view.View;
-
-import com.android.contacts.model.account.AccountInfo;
-import com.android.contacts.model.account.AccountWithDataSet;
-import com.android.contacts.util.AccountsListAdapter;
-
-import java.util.List;
-
-public class DefaultAccountPreference extends DialogPreference {
-    private ContactsPreferences mPreferences;
-    private AccountsListAdapter mListAdapter;
-    private List<AccountInfo> mAccounts;
-    private int mChosenIndex = -1;
-
-    public DefaultAccountPreference(Context context) {
-        super(context);
-        prepare();
-    }
-
-    public DefaultAccountPreference(Context context, AttributeSet attrs) {
-        super(context, attrs);
-        prepare();
-    }
-
-    public void setAccounts(List<AccountInfo> accounts) {
-        mAccounts = accounts;
-        if (mListAdapter != null) {
-            mListAdapter.setAccounts(accounts, null);
-            notifyChanged();
-        }
-    }
-
-    @Override
-    protected View onCreateDialogView() {
-        prepare();
-        return super.onCreateDialogView();
-    }
-
-    private void prepare() {
-        mPreferences = new ContactsPreferences(getContext());
-        mListAdapter = new AccountsListAdapter(getContext());
-        if (mAccounts != null) {
-            mListAdapter.setAccounts(mAccounts, null);
-        }
-    }
-
-    @Override
-    protected boolean shouldPersist() {
-        return false;   // This preference takes care of its own storage
-    }
-
-    @Override
-    public CharSequence getSummary() {
-        final AccountWithDataSet defaultAccount = mPreferences.getDefaultAccount();
-        if (defaultAccount == null || mAccounts == null ||
-                !AccountInfo.contains(mAccounts, defaultAccount)) {
-            return null;
-        } else {
-            return AccountInfo.getAccount(mAccounts, defaultAccount).getNameLabel();
-        }
-    }
-
-    @Override
-    protected void onPrepareDialogBuilder(AlertDialog.Builder builder) {
-        super.onPrepareDialogBuilder(builder);
-        // UX recommendation is not to show buttons on such lists.
-        builder.setNegativeButton(null, null);
-        builder.setPositiveButton(null, null);
-        builder.setAdapter(mListAdapter, new DialogInterface.OnClickListener() {
-            @Override
-            public void onClick(DialogInterface dialog, int which) {
-                mChosenIndex = which;
-            }
-        });
-    }
-
-    @Override
-    protected void onDialogClosed(boolean positiveResult) {
-        final AccountWithDataSet currentDefault = mPreferences.getDefaultAccount();
-
-        if (mChosenIndex != -1) {
-            final AccountWithDataSet chosenAccount = mListAdapter.getItem(mChosenIndex);
-            if (!chosenAccount.equals(currentDefault)) {
-                mPreferences.setDefaultAccount(chosenAccount);
-                notifyChanged();
-            }
-        } // else the user dismissed this dialog so leave the preference unchanged.
-    }
-}
diff --git a/src/com/android/contacts/preference/DisplayOptionsPreferenceFragment.java b/src/com/android/contacts/preference/DisplayOptionsPreferenceFragment.java
index fd358aa08..eb355d850 100644
--- a/src/com/android/contacts/preference/DisplayOptionsPreferenceFragment.java
+++ b/src/com/android/contacts/preference/DisplayOptionsPreferenceFragment.java
@@ -36,8 +36,7 @@ import android.provider.BlockedNumberContract;
 import android.provider.ContactsContract.Contacts;
 import android.provider.ContactsContract.DisplayNameSources;
 import android.provider.ContactsContract.Profile;
-import com.google.android.material.snackbar.Snackbar;
-import androidx.localbroadcastmanager.content.LocalBroadcastManager;
+import android.provider.ContactsContract.Settings;
 import android.telecom.TelecomManager;
 import android.telephony.TelephonyManager;
 import android.text.BidiFormatter;
@@ -47,6 +46,8 @@ import android.view.View;
 import android.view.ViewGroup;
 import android.widget.FrameLayout;
 
+import androidx.localbroadcastmanager.content.LocalBroadcastManager;
+
 import com.android.contacts.ContactsUtils;
 import com.android.contacts.R;
 import com.android.contacts.SimImportService;
@@ -59,23 +60,26 @@ import com.android.contacts.list.ContactListFilterController;
 import com.android.contacts.logging.ScreenEvent.ScreenType;
 import com.android.contacts.model.AccountTypeManager;
 import com.android.contacts.model.account.AccountInfo;
+import com.android.contacts.model.account.AccountWithDataSet;
 import com.android.contacts.model.account.AccountsLoader;
 import com.android.contacts.util.AccountFilterUtil;
 import com.android.contacts.util.ImplicitIntentsUtil;
 import com.android.contactsbind.HelpUtils;
 
+import com.google.android.material.snackbar.Snackbar;
+
+import java.util.Collections;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Locale;
 import java.util.Map;
 
-/**
- * This fragment shows the preferences for "display options"
- */
+/** This fragment shows the preferences for "display options" */
 public class DisplayOptionsPreferenceFragment extends PreferenceFragment
         implements Preference.OnPreferenceClickListener, AccountsLoader.AccountsListener {
 
     private static final int REQUEST_CODE_CUSTOM_CONTACTS_FILTER = 0;
+    private static final int REQUEST_CODE_SET_DEFAULT_ACCOUNT_CP2 = 1;
 
     private static final String ARG_CONTACTS_AVAILABLE = "are_contacts_available";
     private static final String ARG_NEW_LOCAL_PROFILE = "new_local_profile";
@@ -95,43 +99,37 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
     private static final int LOADER_PROFILE = 0;
     private static final int LOADER_ACCOUNTS = 1;
 
-    /**
-     * Callbacks for hosts of the {@link DisplayOptionsPreferenceFragment}.
-     */
-    public interface ProfileListener  {
-        /**
-         * Invoked after profile has been loaded.
-         */
+    /** Callbacks for hosts of the {@link DisplayOptionsPreferenceFragment}. */
+    public interface ProfileListener {
+        /** Invoked after profile has been loaded. */
         void onProfileLoaded(Cursor data);
     }
 
-    /**
-     * The projections that are used to obtain user profile
-     */
+    /** The projections that are used to obtain user profile */
     public static class ProfileQuery {
-        /**
-         * Not instantiable.
-         */
+        /** Not instantiable. */
         private ProfileQuery() {}
 
-        private static final String[] PROFILE_PROJECTION_PRIMARY = new String[] {
-                Contacts._ID,                           // 0
-                Contacts.DISPLAY_NAME_PRIMARY,          // 1
-                Contacts.IS_USER_PROFILE,               // 2
-                Contacts.DISPLAY_NAME_SOURCE,           // 3
-        };
-
-        private static final String[] PROFILE_PROJECTION_ALTERNATIVE = new String[] {
-                Contacts._ID,                           // 0
-                Contacts.DISPLAY_NAME_ALTERNATIVE,      // 1
-                Contacts.IS_USER_PROFILE,               // 2
-                Contacts.DISPLAY_NAME_SOURCE,           // 3
-        };
-
-        public static final int CONTACT_ID               = 0;
-        public static final int CONTACT_DISPLAY_NAME     = 1;
-        public static final int CONTACT_IS_USER_PROFILE  = 2;
-        public static final int DISPLAY_NAME_SOURCE      = 3;
+        private static final String[] PROFILE_PROJECTION_PRIMARY =
+                new String[] {
+                    Contacts._ID, // 0
+                    Contacts.DISPLAY_NAME_PRIMARY, // 1
+                    Contacts.IS_USER_PROFILE, // 2
+                    Contacts.DISPLAY_NAME_SOURCE, // 3
+                };
+
+        private static final String[] PROFILE_PROJECTION_ALTERNATIVE =
+                new String[] {
+                    Contacts._ID, // 0
+                    Contacts.DISPLAY_NAME_ALTERNATIVE, // 1
+                    Contacts.IS_USER_PROFILE, // 2
+                    Contacts.DISPLAY_NAME_SOURCE, // 3
+                };
+
+        public static final int CONTACT_ID = 0;
+        public static final int CONTACT_DISPLAY_NAME = 1;
+        public static final int CONTACT_IS_USER_PROFILE = 2;
+        public static final int DISPLAY_NAME_SOURCE = 3;
     }
 
     private String mNewLocalProfileExtra;
@@ -147,30 +145,31 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
     private ViewGroup mRootView;
     private SaveServiceResultListener mSaveServiceListener;
 
+    private List<AccountInfo> accounts = Collections.emptyList();
+
     private final LoaderManager.LoaderCallbacks<Cursor> mProfileLoaderListener =
             new LoaderManager.LoaderCallbacks<Cursor>() {
 
-        @Override
-        public CursorLoader onCreateLoader(int id, Bundle args) {
-            final CursorLoader loader = createCursorLoader(getContext());
-            loader.setUri(Profile.CONTENT_URI);
-            loader.setProjection(getProjection(getContext()));
-            return loader;
-        }
+                @Override
+                public CursorLoader onCreateLoader(int id, Bundle args) {
+                    final CursorLoader loader = createCursorLoader(getContext());
+                    loader.setUri(Profile.CONTENT_URI);
+                    loader.setProjection(getProjection(getContext()));
+                    return loader;
+                }
 
-        @Override
-        public void onLoadFinished(Loader<Cursor> loader, Cursor data) {
-            if (mListener != null) {
-                mListener.onProfileLoaded(data);
-            }
-        }
+                @Override
+                public void onLoadFinished(Loader<Cursor> loader, Cursor data) {
+                    if (mListener != null) {
+                        mListener.onProfileLoaded(data);
+                    }
+                }
 
-        public void onLoaderReset(Loader<Cursor> loader) {
-        }
-    };
+                public void onLoaderReset(Loader<Cursor> loader) {}
+            };
 
-    public static DisplayOptionsPreferenceFragment newInstance(String newLocalProfileExtra,
-            boolean areContactsAvailable) {
+    public static DisplayOptionsPreferenceFragment newInstance(
+            String newLocalProfileExtra, boolean areContactsAvailable) {
         final DisplayOptionsPreferenceFragment fragment = new DisplayOptionsPreferenceFragment();
         final Bundle args = new Bundle();
         args.putString(ARG_NEW_LOCAL_PROFILE, newLocalProfileExtra);
@@ -190,7 +189,8 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
     }
 
     @Override
-    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
+    public View onCreateView(
+            LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
         // Wrap the preference view in a FrameLayout so we can show a snackbar
         mRootView = new FrameLayout(getActivity());
         final View list = super.onCreateView(inflater, mRootView, savedInstanceState);
@@ -203,9 +203,10 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
         super.onViewCreated(view, savedInstanceState);
 
         mSaveServiceListener = new SaveServiceResultListener();
-        LocalBroadcastManager.getInstance(getActivity()).registerReceiver(
-                mSaveServiceListener,
-                new IntentFilter(SimImportService.BROADCAST_SIM_IMPORT_COMPLETE));
+        LocalBroadcastManager.getInstance(getActivity())
+                .registerReceiver(
+                        mSaveServiceListener,
+                        new IntentFilter(SimImportService.BROADCAST_SIM_IMPORT_COMPLETE));
     }
 
     @Override
@@ -249,6 +250,12 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
             customFilterPreference.setOnPreferenceClickListener(this);
             setCustomContactsFilterSummary();
         }
+
+        final Preference defaultAccountPreference = findPreference(KEY_DEFAULT_ACCOUNT);
+        if (defaultAccountPreference != null) {
+            defaultAccountPreference.setOnPreferenceClickListener(this);
+            defaultAccountPreference.setSummary(getDefaultAccountSummary());
+        }
     }
 
     @Override
@@ -265,13 +272,15 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
         mRootView = null;
     }
 
-    public void updateMyInfoPreference(boolean hasProfile, String displayName, long contactId,
-            int displayNameSource) {
-        final CharSequence summary = !hasProfile ?
-                getString(R.string.set_up_profile) :
-                displayNameSource == DisplayNameSources.PHONE ?
-                BidiFormatter.getInstance().unicodeWrap(displayName, TextDirectionHeuristics.LTR) :
-                displayName;
+    public void updateMyInfoPreference(
+            boolean hasProfile, String displayName, long contactId, int displayNameSource) {
+        final CharSequence summary =
+                !hasProfile
+                        ? getString(R.string.set_up_profile)
+                        : displayNameSource == DisplayNameSources.PHONE
+                                ? BidiFormatter.getInstance()
+                                        .unicodeWrap(displayName, TextDirectionHeuristics.LTR)
+                                : displayName;
         mMyInfoPreference.setSummary(summary);
         mHasProfile = hasProfile;
         mProfileContactId = contactId;
@@ -298,10 +307,14 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
             getPreferenceScreen().removePreference(findPreference(KEY_DISPLAY_ORDER));
         }
 
-        final boolean isPhone = TelephonyManagerCompat.isVoiceCapable(
-                (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE));
-        final boolean showBlockedNumbers = isPhone && ContactsUtils.FLAG_N_FEATURE
-                && BlockedNumberContract.canCurrentUserBlockNumbers(getContext());
+        final boolean isPhone =
+                TelephonyManagerCompat.isVoiceCapable(
+                        (TelephonyManager)
+                                getContext().getSystemService(Context.TELEPHONY_SERVICE));
+        final boolean showBlockedNumbers =
+                isPhone
+                        && ContactsUtils.FLAG_N_FEATURE
+                        && BlockedNumberContract.canCurrentUserBlockNumbers(getContext());
         if (!showBlockedNumbers) {
             getPreferenceScreen().removePreference(findPreference(KEY_BLOCKED_NUMBERS));
         }
@@ -314,9 +327,9 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
     @Override
     public void onAccountsLoaded(List<AccountInfo> accounts) {
         // Hide accounts preferences if no writable accounts exist
-        final DefaultAccountPreference preference =
-                (DefaultAccountPreference) findPreference(KEY_DEFAULT_ACCOUNT);
-        preference.setAccounts(accounts);
+        this.accounts = accounts;
+        final Preference defaultAccountPreference = findPreference(KEY_DEFAULT_ACCOUNT);
+        defaultAccountPreference.setSummary(getDefaultAccountSummary());
     }
 
     @Override
@@ -357,7 +370,9 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
             ImportDialogFragment.show(getFragmentManager());
             return true;
         } else if (KEY_EXPORT.equals(prefKey)) {
-            ExportDialogFragment.show(getFragmentManager(), ContactsPreferenceActivity.class,
+            ExportDialogFragment.show(
+                    getFragmentManager(),
+                    ContactsPreferenceActivity.class,
                     ExportDialogFragment.EXPORT_MODE_ALL_CONTACTS);
             return true;
         } else if (KEY_MY_INFO.equals(prefKey)) {
@@ -371,12 +386,14 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
             }
             return true;
         } else if (KEY_ACCOUNTS.equals(prefKey)) {
-            ImplicitIntentsUtil.startActivityOutsideApp(getContext(),
-                    ImplicitIntentsUtil.getIntentForAddingAccount());
+            ImplicitIntentsUtil.startActivityOutsideApp(
+                    getContext(), ImplicitIntentsUtil.getIntentForAddingAccount());
             return true;
         } else if (KEY_BLOCKED_NUMBERS.equals(prefKey)) {
-            final Intent intent = TelecomManagerUtil.createManageBlockedNumbersIntent(
-                    (TelecomManager) getContext().getSystemService(Context.TELECOM_SERVICE));
+            final Intent intent =
+                    TelecomManagerUtil.createManageBlockedNumbersIntent(
+                            (TelecomManager)
+                                    getContext().getSystemService(Context.TELECOM_SERVICE));
             startActivity(intent);
             return true;
         } else if (KEY_CUSTOM_CONTACTS_FILTER.equals(prefKey)) {
@@ -384,6 +401,9 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
                     ContactListFilterController.getInstance(getContext()).getFilter();
             AccountFilterUtil.startAccountFilterActivityForResult(
                     this, REQUEST_CODE_CUSTOM_CONTACTS_FILTER, filter);
+        } else if (KEY_DEFAULT_ACCOUNT.equals(prefKey)) {
+            Intent intent = new Intent(Settings.ACTION_SET_DEFAULT_ACCOUNT);
+            startActivityForResult(intent, REQUEST_CODE_SET_DEFAULT_ACCOUNT_CP2);
         }
         return false;
     }
@@ -395,6 +415,11 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
             AccountFilterUtil.handleAccountFilterResult(
                     ContactListFilterController.getInstance(getContext()), resultCode, data);
             setCustomContactsFilterSummary();
+        } else if (requestCode == REQUEST_CODE_SET_DEFAULT_ACCOUNT_CP2) {
+            final Preference defaultAccountPreference = findPreference(KEY_DEFAULT_ACCOUNT);
+            if (defaultAccountPreference != null) {
+                defaultAccountPreference.setSummary(getDefaultAccountSummary());
+            }
         } else {
             super.onActivityResult(requestCode, resultCode, data);
         }
@@ -406,8 +431,8 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
             final ContactListFilter filter =
                     ContactListFilterController.getInstance(getContext()).getPersistedFilter();
             if (filter != null) {
-                if (filter.filterType == ContactListFilter.FILTER_TYPE_DEFAULT ||
-                        filter.filterType == ContactListFilter.FILTER_TYPE_ALL_ACCOUNTS) {
+                if (filter.filterType == ContactListFilter.FILTER_TYPE_DEFAULT
+                        || filter.filterType == ContactListFilter.FILTER_TYPE_ALL_ACCOUNTS) {
                     customFilterPreference.setSummary(R.string.list_filter_all_accounts);
                 } else if (filter.filterType == ContactListFilter.FILTER_TYPE_CUSTOM) {
                     customFilterPreference.setSummary(R.string.listCustomView);
@@ -418,33 +443,45 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
         }
     }
 
+    private CharSequence getDefaultAccountSummary() {
+        ContactsPreferences preferences = new ContactsPreferences(getContext());
+        AccountWithDataSet defaultAccountWithDataSet = preferences.getDefaultAccount();
+        AccountInfo defaultAccountInfo =
+                AccountInfo.getAccount(accounts, defaultAccountWithDataSet);
+        if (defaultAccountInfo != null) {
+            return defaultAccountInfo.getNameLabel();
+        } else {
+            return null;
+        }
+    }
+
     private class SaveServiceResultListener extends BroadcastReceiver {
         @Override
         public void onReceive(Context context, Intent intent) {
             final long now = System.currentTimeMillis();
-            final long opStart = intent.getLongExtra(
-                    SimImportService.EXTRA_OPERATION_REQUESTED_AT_TIME, now);
+            final long opStart =
+                    intent.getLongExtra(SimImportService.EXTRA_OPERATION_REQUESTED_AT_TIME, now);
 
             // If it's been over 30 seconds the user is likely in a different context so suppress
             // the toast message.
-            if (now - opStart > 30*1000) return;
+            if (now - opStart > 30 * 1000) return;
 
-            final int code = intent.getIntExtra(SimImportService.EXTRA_RESULT_CODE,
-                    SimImportService.RESULT_UNKNOWN);
+            final int code =
+                    intent.getIntExtra(
+                            SimImportService.EXTRA_RESULT_CODE, SimImportService.RESULT_UNKNOWN);
             final int count = intent.getIntExtra(SimImportService.EXTRA_RESULT_COUNT, -1);
             if (code == SimImportService.RESULT_SUCCESS && count > 0) {
-                MessageFormat msgFormat = new MessageFormat(
-                    getResources().getString(R.string.sim_import_success_toast_fmt),
-                    Locale.getDefault());
+                MessageFormat msgFormat =
+                        new MessageFormat(
+                                getResources().getString(R.string.sim_import_success_toast_fmt),
+                                Locale.getDefault());
                 Map<String, Object> arguments = new HashMap<>();
                 arguments.put("count", count);
-                Snackbar.make(mRootView, msgFormat.format(arguments),
-                        Snackbar.LENGTH_LONG).show();
+                Snackbar.make(mRootView, msgFormat.format(arguments), Snackbar.LENGTH_LONG).show();
             } else if (code == SimImportService.RESULT_FAILURE) {
-                Snackbar.make(mRootView, R.string.sim_import_failed_toast,
-                        Snackbar.LENGTH_LONG).show();
+                Snackbar.make(mRootView, R.string.sim_import_failed_toast, Snackbar.LENGTH_LONG)
+                        .show();
             }
         }
     }
 }
-
diff --git a/src/com/android/contacts/quickcontact/QuickContactActivity.java b/src/com/android/contacts/quickcontact/QuickContactActivity.java
index 35fc2ccb7..312a5cf85 100644
--- a/src/com/android/contacts/quickcontact/QuickContactActivity.java
+++ b/src/com/android/contacts/quickcontact/QuickContactActivity.java
@@ -1,19 +1,19 @@
 /*
 
- * Copyright (C) 2009 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
+* Copyright (C) 2009 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+*      http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
 
 package com.android.contacts.quickcontact;
 
@@ -93,10 +93,12 @@ import android.view.View.OnCreateContextMenuListener;
 import android.view.WindowManager;
 import android.widget.Toast;
 import android.widget.Toolbar;
+
 import androidx.core.content.res.ResourcesCompat;
 import androidx.core.os.BuildCompat;
 import androidx.localbroadcastmanager.content.LocalBroadcastManager;
 import androidx.palette.graphics.Palette;
+
 import com.android.contacts.CallUtil;
 import com.android.contacts.ClipboardUtils;
 import com.android.contacts.Collapser;
@@ -104,6 +106,8 @@ import com.android.contacts.ContactSaveService;
 import com.android.contacts.ContactsActivity;
 import com.android.contacts.ContactsUtils;
 import com.android.contacts.DynamicShortcuts;
+import com.android.contacts.MoreContactUtils;
+import com.android.contacts.MoreContactUtils.EdgeToEdgeInsetHandler;
 import com.android.contacts.R;
 import com.android.contacts.ShortcutIntentBuilder;
 import com.android.contacts.ShortcutIntentBuilder.OnShortcutIntentCreatedListener;
@@ -167,7 +171,9 @@ import com.android.contacts.widget.MultiShrinkScroller;
 import com.android.contacts.widget.MultiShrinkScroller.MultiShrinkScrollerListener;
 import com.android.contacts.widget.QuickContactImageView;
 import com.android.contactsbind.HelpUtils;
+
 import com.google.common.collect.Lists;
+
 import java.util.ArrayList;
 import java.util.Calendar;
 import java.util.Collections;
@@ -179,27 +185,30 @@ import java.util.Locale;
 import java.util.Map;
 
 /**
- * Mostly translucent {@link Activity} that shows QuickContact dialog. It loads
- * data asynchronously, and then shows a popup with details centered around
- * {@link Intent#getSourceBounds()}.
+ * Mostly translucent {@link Activity} that shows QuickContact dialog. It loads data asynchronously,
+ * and then shows a popup with details centered around {@link Intent#getSourceBounds()}.
  */
 public class QuickContactActivity extends ContactsActivity {
 
     /**
-     * QuickContacts immediately takes up the full screen. All possible information is shown.
-     * This value for {@link android.provider.ContactsContract.QuickContact#EXTRA_MODE}
-     * should only be used by the Contacts app.
+     * QuickContacts immediately takes up the full screen. All possible information is shown. This
+     * value for {@link android.provider.ContactsContract.QuickContact#EXTRA_MODE} should only be
+     * used by the Contacts app.
      */
     public static final int MODE_FULLY_EXPANDED = 4;
 
     /** Used to pass the screen where the user came before launching this Activity. */
     public static final String EXTRA_PREVIOUS_SCREEN_TYPE = "previous_screen_type";
+
     /** Used to pass the Contact card action. */
     public static final String EXTRA_ACTION_TYPE = "action_type";
+
     public static final String EXTRA_THIRD_PARTY_ACTION = "third_party_action";
 
-    /** Used to tell the QuickContact that the previous contact was edited, so it can return an
-     * activity result back to the original Activity that launched it. */
+    /**
+     * Used to tell the QuickContact that the previous contact was edited, so it can return an
+     * activity result back to the original Activity that launched it.
+     */
     public static final String EXTRA_CONTACT_EDITED = "contact_edited";
 
     private static final String TAG = "QuickContact";
@@ -239,8 +248,7 @@ public class QuickContactActivity extends ContactsActivity {
 
     public static final String MIMETYPE_TACHYON =
             "vnd.android.cursor.item/com.google.android.apps.tachyon.phone";
-    private static final String TACHYON_CALL_ACTION =
-            "com.google.android.apps.tachyon.action.CALL";
+    private static final String TACHYON_CALL_ACTION = "com.google.android.apps.tachyon.action.CALL";
     private static final String MIMETYPE_GPLUS_PROFILE =
             "vnd.android.cursor.item/vnd.googleplus.profile";
     private static final String GPLUS_PROFILE_DATA_5_VIEW_PROFILE = "view";
@@ -251,7 +259,7 @@ public class QuickContactActivity extends ContactsActivity {
     private static final String CALL_ORIGIN_QUICK_CONTACTS_ACTIVITY =
             "com.android.contacts.quickcontact.QuickContactActivity";
     private static final String KEY_LOADER_EXTRA_EMAILS =
-        QuickContactActivity.class.getCanonicalName() + ".KEY_LOADER_EXTRA_EMAILS";
+            QuickContactActivity.class.getCanonicalName() + ".KEY_LOADER_EXTRA_EMAILS";
 
     // Set true in {@link #onCreate} after orientation change for later use in processIntent().
     private boolean mIsRecreatedInstance;
@@ -268,6 +276,7 @@ public class QuickContactActivity extends ContactsActivity {
      * instead of referencing this URI.
      */
     private Uri mLookupUri;
+
     private String[] mExcludeMimes;
     private int mExtraMode;
     private String mExtraPrioritizedMimeType;
@@ -292,13 +301,15 @@ public class QuickContactActivity extends ContactsActivity {
      * The last copy of Cp2DataCardModel that was passed to {@link #populateContactAndAboutCard}.
      */
     private Cp2DataCardModel mCachedCp2DataCardModel;
+
     /**
-     *  This scrim's opacity is controlled in two different ways. 1) Before the initial entrance
-     *  animation finishes, the opacity is animated by a value animator. This is designed to
-     *  distract the user from the length of the initial loading time. 2) After the initial
-     *  entrance animation, the opacity is directly related to scroll position.
+     * This scrim's opacity is controlled in two different ways. 1) Before the initial entrance
+     * animation finishes, the opacity is animated by a value animator. This is designed to distract
+     * the user from the length of the initial loading time. 2) After the initial entrance
+     * animation, the opacity is directly related to scroll position.
      */
     private ColorDrawable mWindowScrim;
+
     private boolean mIsEntranceAnimationFinished;
     private MaterialColorMapUtils mMaterialColorMapUtils;
     private boolean mIsExitAnimationInProgress;
@@ -320,26 +331,30 @@ public class QuickContactActivity extends ContactsActivity {
     /**
      * {@link #LEADING_MIMETYPES} is used to sort MIME-types.
      *
-     * <p>The MIME-types in {@link #LEADING_MIMETYPES} appear in the front of the dialog,
-     * in the order specified here.</p>
+     * <p>The MIME-types in {@link #LEADING_MIMETYPES} appear in the front of the dialog, in the
+     * order specified here.
      */
-    private static final List<String> LEADING_MIMETYPES = Lists.newArrayList(
-            Phone.CONTENT_ITEM_TYPE, SipAddress.CONTENT_ITEM_TYPE, Email.CONTENT_ITEM_TYPE,
-            StructuredPostal.CONTENT_ITEM_TYPE);
-
-    private static final List<String> SORTED_ABOUT_CARD_MIMETYPES = Lists.newArrayList(
-            Nickname.CONTENT_ITEM_TYPE,
-            // Phonetic name is inserted after nickname if it is available.
-            // No mimetype for phonetic name exists.
-            Website.CONTENT_ITEM_TYPE,
-            Organization.CONTENT_ITEM_TYPE,
-            Event.CONTENT_ITEM_TYPE,
-            Relation.CONTENT_ITEM_TYPE,
-            Im.CONTENT_ITEM_TYPE,
-            GroupMembership.CONTENT_ITEM_TYPE,
-            Identity.CONTENT_ITEM_TYPE,
-            CustomDataItem.MIMETYPE_CUSTOM_FIELD,
-            Note.CONTENT_ITEM_TYPE);
+    private static final List<String> LEADING_MIMETYPES =
+            Lists.newArrayList(
+                    Phone.CONTENT_ITEM_TYPE,
+                    SipAddress.CONTENT_ITEM_TYPE,
+                    Email.CONTENT_ITEM_TYPE,
+                    StructuredPostal.CONTENT_ITEM_TYPE);
+
+    private static final List<String> SORTED_ABOUT_CARD_MIMETYPES =
+            Lists.newArrayList(
+                    Nickname.CONTENT_ITEM_TYPE,
+                    // Phonetic name is inserted after nickname if it is available.
+                    // No mimetype for phonetic name exists.
+                    Website.CONTENT_ITEM_TYPE,
+                    Organization.CONTENT_ITEM_TYPE,
+                    Event.CONTENT_ITEM_TYPE,
+                    Relation.CONTENT_ITEM_TYPE,
+                    Im.CONTENT_ITEM_TYPE,
+                    GroupMembership.CONTENT_ITEM_TYPE,
+                    Identity.CONTENT_ITEM_TYPE,
+                    CustomDataItem.MIMETYPE_CUSTOM_FIELD,
+                    Note.CONTENT_ITEM_TYPE);
 
     private static final BidiFormatter sBidiFormatter = BidiFormatter.getInstance();
 
@@ -353,78 +368,92 @@ public class QuickContactActivity extends ContactsActivity {
 
     private static final String FRAGMENT_TAG_SELECT_ACCOUNT = "select_account_fragment";
 
-    final OnClickListener mEntryClickHandler = new OnClickListener() {
-        @Override
-        public void onClick(View v) {
-            final Object entryTagObject = v.getTag();
-            if (entryTagObject == null || !(entryTagObject instanceof EntryTag)) {
-                Log.w(TAG, "EntryTag was not used correctly");
-                return;
-            }
-            final EntryTag entryTag = (EntryTag) entryTagObject;
-            final Intent intent = entryTag.getIntent();
-            final int dataId = entryTag.getId();
+    final OnClickListener mEntryClickHandler =
+            new OnClickListener() {
+                @Override
+                public void onClick(View v) {
+                    final Object entryTagObject = v.getTag();
+                    if (entryTagObject == null || !(entryTagObject instanceof EntryTag)) {
+                        Log.w(TAG, "EntryTag was not used correctly");
+                        return;
+                    }
+                    final EntryTag entryTag = (EntryTag) entryTagObject;
+                    final Intent intent = entryTag.getIntent();
+                    final int dataId = entryTag.getId();
 
-            if (dataId == CARD_ENTRY_ID_EDIT_CONTACT) {
-                editContact();
-                return;
-            }
+                    if (dataId == CARD_ENTRY_ID_EDIT_CONTACT) {
+                        editContact();
+                        return;
+                    }
 
-            // Pass the touch point through the intent for use in the InCallUI
-            if (Intent.ACTION_CALL.equals(intent.getAction())) {
-                if (TouchPointManager.getInstance().hasValidPoint()) {
-                    Bundle extras = new Bundle();
-                    extras.putParcelable(TouchPointManager.TOUCH_POINT,
-                            TouchPointManager.getInstance().getPoint());
-                    intent.putExtra(TelecomManager.EXTRA_OUTGOING_CALL_EXTRAS, extras);
-                }
-            }
+                    // Pass the touch point through the intent for use in the InCallUI
+                    if (Intent.ACTION_CALL.equals(intent.getAction())) {
+                        if (TouchPointManager.getInstance().hasValidPoint()) {
+                            Bundle extras = new Bundle();
+                            extras.putParcelable(
+                                    TouchPointManager.TOUCH_POINT,
+                                    TouchPointManager.getInstance().getPoint());
+                            intent.putExtra(TelecomManager.EXTRA_OUTGOING_CALL_EXTRAS, extras);
+                        }
+                    }
 
-            mHasIntentLaunched = true;
-            try {
-                final int actionType = intent.getIntExtra(EXTRA_ACTION_TYPE,
-                        ActionType.UNKNOWN_ACTION);
-                final String thirdPartyAction = intent.getStringExtra(EXTRA_THIRD_PARTY_ACTION);
-                Logger.logQuickContactEvent(mReferrer, mContactType,
-                        CardType.UNKNOWN_CARD, actionType, thirdPartyAction);
-                // For the tachyon call action, we need to use startActivityForResult and not
-                // add FLAG_ACTIVITY_NEW_TASK to the intent.
-                if (TACHYON_CALL_ACTION.equals(intent.getAction())) {
-                    QuickContactActivity.this.startActivityForResult(intent, /* requestCode */ 0);
-                } else {
-                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-                    ImplicitIntentsUtil.startActivityInAppIfPossible(QuickContactActivity.this,
-                            intent);
+                    mHasIntentLaunched = true;
+                    try {
+                        final int actionType =
+                                intent.getIntExtra(EXTRA_ACTION_TYPE, ActionType.UNKNOWN_ACTION);
+                        final String thirdPartyAction =
+                                intent.getStringExtra(EXTRA_THIRD_PARTY_ACTION);
+                        Logger.logQuickContactEvent(
+                                mReferrer,
+                                mContactType,
+                                CardType.UNKNOWN_CARD,
+                                actionType,
+                                thirdPartyAction);
+                        // For the tachyon call action, we need to use startActivityForResult and
+                        // not
+                        // add FLAG_ACTIVITY_NEW_TASK to the intent.
+                        if (TACHYON_CALL_ACTION.equals(intent.getAction())) {
+                            QuickContactActivity.this.startActivityForResult(
+                                    intent, /* requestCode */ 0);
+                        } else {
+                            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+                            ImplicitIntentsUtil.startActivityInAppIfPossible(
+                                    QuickContactActivity.this, intent);
+                        }
+                    } catch (SecurityException ex) {
+                        Toast.makeText(
+                                        QuickContactActivity.this,
+                                        R.string.missing_app,
+                                        Toast.LENGTH_SHORT)
+                                .show();
+                        Log.e(TAG, "QuickContacts does not have permission to launch " + intent);
+                    } catch (ActivityNotFoundException ex) {
+                        Toast.makeText(
+                                        QuickContactActivity.this,
+                                        R.string.missing_app,
+                                        Toast.LENGTH_SHORT)
+                                .show();
+                    }
                 }
-            } catch (SecurityException ex) {
-                Toast.makeText(QuickContactActivity.this, R.string.missing_app,
-                        Toast.LENGTH_SHORT).show();
-                Log.e(TAG, "QuickContacts does not have permission to launch "
-                        + intent);
-            } catch (ActivityNotFoundException ex) {
-                Toast.makeText(QuickContactActivity.this, R.string.missing_app,
-                        Toast.LENGTH_SHORT).show();
-            }
-        }
-    };
+            };
 
-    final ExpandingEntryCardViewListener mExpandingEntryCardViewListener
-            = new ExpandingEntryCardViewListener() {
-        @Override
-        public void onCollapse(int heightDelta) {
-            mScroller.prepareForShrinkingScrollChild(heightDelta);
-        }
+    final ExpandingEntryCardViewListener mExpandingEntryCardViewListener =
+            new ExpandingEntryCardViewListener() {
+                @Override
+                public void onCollapse(int heightDelta) {
+                    mScroller.prepareForShrinkingScrollChild(heightDelta);
+                }
 
-        @Override
-        public void onExpand() {
-            mScroller.setDisableTouchesForSuppressLayout(/* areTouchesDisabled = */ true);
-        }
+                @Override
+                public void onExpand() {
+                    mScroller.setDisableTouchesForSuppressLayout(/* areTouchesDisabled= */ true);
+                }
 
-        @Override
-        public void onExpandDone() {
-            mScroller.setDisableTouchesForSuppressLayout(/* areTouchesDisabled = */ false);
-        }
-    };
+                @Override
+                public void onExpandDone() {
+                    mScroller.setDisableTouchesForSuppressLayout(/* areTouchesDisabled= */ false);
+                }
+            };
 
     private interface ContextMenuIds {
         static final int COPY_TEXT = 0;
@@ -434,43 +463,53 @@ public class QuickContactActivity extends ContactsActivity {
 
     private final OnCreateContextMenuListener mEntryContextMenuListener =
             new OnCreateContextMenuListener() {
-        @Override
-        public void onCreateContextMenu(ContextMenu menu, View v, ContextMenuInfo menuInfo) {
-            if (menuInfo == null) {
-                return;
-            }
-            final EntryContextMenuInfo info = (EntryContextMenuInfo) menuInfo;
-            menu.setHeaderTitle(info.getCopyText());
-            menu.add(ContextMenu.NONE, ContextMenuIds.COPY_TEXT,
-                    ContextMenu.NONE, getString(R.string.copy_text));
-
-            // Don't allow setting or clearing of defaults for non-editable contacts
-            if (!isContactEditable()) {
-                return;
-            }
+                @Override
+                public void onCreateContextMenu(
+                        ContextMenu menu, View v, ContextMenuInfo menuInfo) {
+                    if (menuInfo == null) {
+                        return;
+                    }
+                    final EntryContextMenuInfo info = (EntryContextMenuInfo) menuInfo;
+                    menu.setHeaderTitle(info.getCopyText());
+                    menu.add(
+                            ContextMenu.NONE,
+                            ContextMenuIds.COPY_TEXT,
+                            ContextMenu.NONE,
+                            getString(R.string.copy_text));
+
+                    // Don't allow setting or clearing of defaults for non-editable contacts
+                    if (!isContactEditable()) {
+                        return;
+                    }
 
-            final String selectedMimeType = info.getMimeType();
+                    final String selectedMimeType = info.getMimeType();
 
-            // Defaults to true will only enable the detail to be copied to the clipboard.
-            boolean onlyOneOfMimeType = true;
+                    // Defaults to true will only enable the detail to be copied to the clipboard.
+                    boolean onlyOneOfMimeType = true;
 
-            // Only allow primary support for Phone and Email content types
-            if (Phone.CONTENT_ITEM_TYPE.equals(selectedMimeType)) {
-                onlyOneOfMimeType = mOnlyOnePhoneNumber;
-            } else if (Email.CONTENT_ITEM_TYPE.equals(selectedMimeType)) {
-                onlyOneOfMimeType = mOnlyOneEmail;
-            }
+                    // Only allow primary support for Phone and Email content types
+                    if (Phone.CONTENT_ITEM_TYPE.equals(selectedMimeType)) {
+                        onlyOneOfMimeType = mOnlyOnePhoneNumber;
+                    } else if (Email.CONTENT_ITEM_TYPE.equals(selectedMimeType)) {
+                        onlyOneOfMimeType = mOnlyOneEmail;
+                    }
 
-            // Checking for previously set default
-            if (info.isSuperPrimary()) {
-                menu.add(ContextMenu.NONE, ContextMenuIds.CLEAR_DEFAULT,
-                        ContextMenu.NONE, getString(R.string.clear_default));
-            } else if (!onlyOneOfMimeType) {
-                menu.add(ContextMenu.NONE, ContextMenuIds.SET_DEFAULT,
-                        ContextMenu.NONE, getString(R.string.set_default));
-            }
-        }
-    };
+                    // Checking for previously set default
+                    if (info.isSuperPrimary()) {
+                        menu.add(
+                                ContextMenu.NONE,
+                                ContextMenuIds.CLEAR_DEFAULT,
+                                ContextMenu.NONE,
+                                getString(R.string.clear_default));
+                    } else if (!onlyOneOfMimeType) {
+                        menu.add(
+                                ContextMenu.NONE,
+                                ContextMenuIds.SET_DEFAULT,
+                                ContextMenu.NONE,
+                                getString(R.string.set_default));
+                    }
+                }
+            };
 
     @Override
     public boolean onContextItemSelected(MenuItem item) {
@@ -484,17 +523,17 @@ public class QuickContactActivity extends ContactsActivity {
 
         switch (item.getItemId()) {
             case ContextMenuIds.COPY_TEXT:
-                ClipboardUtils.copyText(this, menuInfo.getCopyLabel(), menuInfo.getCopyText(),
-                        true);
+                ClipboardUtils.copyText(
+                        this, menuInfo.getCopyLabel(), menuInfo.getCopyText(), true);
                 return true;
             case ContextMenuIds.SET_DEFAULT:
-                final Intent setIntent = ContactSaveService.createSetSuperPrimaryIntent(this,
-                        menuInfo.getId());
+                final Intent setIntent =
+                        ContactSaveService.createSetSuperPrimaryIntent(this, menuInfo.getId());
                 this.startService(setIntent);
                 return true;
             case ContextMenuIds.CLEAR_DEFAULT:
-                final Intent clearIntent = ContactSaveService.createClearPrimaryIntent(this,
-                        menuInfo.getId());
+                final Intent clearIntent =
+                        ContactSaveService.createClearPrimaryIntent(this, menuInfo.getId());
                 this.startService(clearIntent);
                 return true;
             default:
@@ -502,107 +541,109 @@ public class QuickContactActivity extends ContactsActivity {
         }
     }
 
-    final MultiShrinkScrollerListener mMultiShrinkScrollerListener
-            = new MultiShrinkScrollerListener() {
-        @Override
-        public void onScrolledOffBottom() {
-            finish();
-        }
-
-        @Override
-        public void onEnterFullscreen() {
-            updateStatusBarColor();
-        }
+    final MultiShrinkScrollerListener mMultiShrinkScrollerListener =
+            new MultiShrinkScrollerListener() {
+                @Override
+                public void onScrolledOffBottom() {
+                    finish();
+                }
 
-        @Override
-        public void onExitFullscreen() {
-            updateStatusBarColor();
-        }
+                @Override
+                public void onEnterFullscreen() {
+                    updateStatusBarColor();
+                }
 
-        @Override
-        public void onStartScrollOffBottom() {
-            mIsExitAnimationInProgress = true;
-        }
+                @Override
+                public void onExitFullscreen() {
+                    updateStatusBarColor();
+                }
 
-        @Override
-        public void onEntranceAnimationDone() {
-            mIsEntranceAnimationFinished = true;
-        }
+                @Override
+                public void onStartScrollOffBottom() {
+                    mIsExitAnimationInProgress = true;
+                }
 
-        @Override
-        public void onTransparentViewHeightChange(float ratio) {
-            if (mIsEntranceAnimationFinished) {
-                mWindowScrim.setAlpha((int) (0xFF * ratio));
-            }
-        }
-    };
+                @Override
+                public void onEntranceAnimationDone() {
+                    mIsEntranceAnimationFinished = true;
+                }
 
+                @Override
+                public void onTransparentViewHeightChange(float ratio) {
+                    if (mIsEntranceAnimationFinished) {
+                        mWindowScrim.setAlpha((int) (0xFF * ratio));
+                    }
+                }
+            };
 
     /**
-     * Data items are compared to the same mimetype based off of three qualities:
-     * 1. Super primary
+     * Data items are compared to the same mimetype based off of three qualities: 1. Super primary
      * 2. Primary
      */
     private final Comparator<DataItem> mWithinMimeTypeDataItemComparator =
             new Comparator<DataItem>() {
-        @Override
-        public int compare(DataItem lhs, DataItem rhs) {
-            if (!lhs.getMimeType().equals(rhs.getMimeType())) {
-                Log.wtf(TAG, "Comparing DataItems with different mimetypes lhs.getMimeType(): " +
-                        lhs.getMimeType() + " rhs.getMimeType(): " + rhs.getMimeType());
-                return 0;
-            }
+                @Override
+                public int compare(DataItem lhs, DataItem rhs) {
+                    if (!lhs.getMimeType().equals(rhs.getMimeType())) {
+                        Log.wtf(
+                                TAG,
+                                "Comparing DataItems with different mimetypes lhs.getMimeType(): "
+                                        + lhs.getMimeType()
+                                        + " rhs.getMimeType(): "
+                                        + rhs.getMimeType());
+                        return 0;
+                    }
 
-            if (lhs.isSuperPrimary()) {
-                return -1;
-            } else if (rhs.isSuperPrimary()) {
-                return 1;
-            } else if (lhs.isPrimary() && !rhs.isPrimary()) {
-                return -1;
-            } else if (!lhs.isPrimary() && rhs.isPrimary()) {
-                return 1;
-            }
-            return 0;
-        }
-    };
+                    if (lhs.isSuperPrimary()) {
+                        return -1;
+                    } else if (rhs.isSuperPrimary()) {
+                        return 1;
+                    } else if (lhs.isPrimary() && !rhs.isPrimary()) {
+                        return -1;
+                    } else if (!lhs.isPrimary() && rhs.isPrimary()) {
+                        return 1;
+                    }
+                    return 0;
+                }
+            };
 
     /**
-     * Sorts among different mimetypes based off:
-     * 1. Whether one of the mimetypes is the prioritized mimetype
-     * 2. Statically defined
+     * Sorts among different mimetypes based off: 1. Whether one of the mimetypes is the prioritized
+     * mimetype 2. Statically defined
      */
     private final Comparator<List<DataItem>> mAmongstMimeTypeDataItemComparator =
-            new Comparator<List<DataItem>> () {
-        @Override
-        public int compare(List<DataItem> lhsList, List<DataItem> rhsList) {
-            final DataItem lhs = lhsList.get(0);
-            final DataItem rhs = rhsList.get(0);
-            final String lhsMimeType = lhs.getMimeType();
-            final String rhsMimeType = rhs.getMimeType();
-
-            // 1. Whether one of the mimetypes is the prioritized mimetype
-            if (!TextUtils.isEmpty(mExtraPrioritizedMimeType) && !lhsMimeType.equals(rhsMimeType)) {
-                if (rhsMimeType.equals(mExtraPrioritizedMimeType)) {
-                    return 1;
-                }
-                if (lhsMimeType.equals(mExtraPrioritizedMimeType)) {
-                    return -1;
-                }
-            }
+            new Comparator<List<DataItem>>() {
+                @Override
+                public int compare(List<DataItem> lhsList, List<DataItem> rhsList) {
+                    final DataItem lhs = lhsList.get(0);
+                    final DataItem rhs = rhsList.get(0);
+                    final String lhsMimeType = lhs.getMimeType();
+                    final String rhsMimeType = rhs.getMimeType();
+
+                    // 1. Whether one of the mimetypes is the prioritized mimetype
+                    if (!TextUtils.isEmpty(mExtraPrioritizedMimeType)
+                            && !lhsMimeType.equals(rhsMimeType)) {
+                        if (rhsMimeType.equals(mExtraPrioritizedMimeType)) {
+                            return 1;
+                        }
+                        if (lhsMimeType.equals(mExtraPrioritizedMimeType)) {
+                            return -1;
+                        }
+                    }
 
-            // 2. Resort to a statically defined mimetype order.
-            if (!lhsMimeType.equals(rhsMimeType)) {
-                for (String mimeType : LEADING_MIMETYPES) {
-                    if (lhsMimeType.equals(mimeType)) {
-                        return -1;
-                    } else if (rhsMimeType.equals(mimeType)) {
-                        return 1;
+                    // 2. Resort to a statically defined mimetype order.
+                    if (!lhsMimeType.equals(rhsMimeType)) {
+                        for (String mimeType : LEADING_MIMETYPES) {
+                            if (lhsMimeType.equals(mimeType)) {
+                                return -1;
+                            } else if (rhsMimeType.equals(mimeType)) {
+                                return 1;
+                            }
+                        }
                     }
+                    return 0;
                 }
-            }
-            return 0;
-        }
-    };
+            };
 
     @Override
     public boolean dispatchTouchEvent(MotionEvent ev) {
@@ -639,14 +680,12 @@ public class QuickContactActivity extends ContactsActivity {
         final IntentFilter intentFilter = new IntentFilter();
         intentFilter.addAction(ContactSaveService.BROADCAST_LINK_COMPLETE);
         intentFilter.addAction(ContactSaveService.BROADCAST_UNLINK_COMPLETE);
-        LocalBroadcastManager.getInstance(this).registerReceiver(mListener,
-                intentFilter);
-
+        LocalBroadcastManager.getInstance(this).registerReceiver(mListener, intentFilter);
 
         mShouldLog = true;
 
-        final int previousScreenType = getIntent().getIntExtra
-                (EXTRA_PREVIOUS_SCREEN_TYPE, ScreenType.UNKNOWN);
+        final int previousScreenType =
+                getIntent().getIntExtra(EXTRA_PREVIOUS_SCREEN_TYPE, ScreenType.UNKNOWN);
         Logger.logScreenView(this, ScreenType.QUICK_CONTACT, previousScreenType);
 
         mReferrer = getCallingPackage();
@@ -662,8 +701,10 @@ public class QuickContactActivity extends ContactsActivity {
         processIntent(getIntent());
 
         // Show QuickContact in front of soft input
-        getWindow().setFlags(WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM,
-                WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM);
+        getWindow()
+                .setFlags(
+                        WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM,
+                        WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM);
 
         setContentView(R.layout.quickcontact_activity);
 
@@ -685,18 +726,21 @@ public class QuickContactActivity extends ContactsActivity {
         mPhotoView = (QuickContactImageView) findViewById(R.id.photo);
         final View transparentView = findViewById(R.id.transparent_view);
         if (mScroller != null) {
-            transparentView.setOnClickListener(new OnClickListener() {
-                @Override
-                public void onClick(View v) {
-                    mScroller.scrollOffBottom();
-                }
-            });
+            transparentView.setOnClickListener(
+                    new OnClickListener() {
+                        @Override
+                        public void onClick(View v) {
+                            mScroller.scrollOffBottom();
+                        }
+                    });
         }
 
         // Allow a shadow to be shown under the toolbar.
         ViewUtil.addRectangularOutlineProvider(findViewById(R.id.toolbar_parent), getResources());
 
         final Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
+        MoreContactUtils.setupEdgeToEdge(
+                this, new EdgeToEdgeInsetHandler(findViewById(R.id.toolbar_parent)));
         setActionBar(toolbar);
         getActionBar().setTitle(null);
         // Put a TextView with a known resource id into the ActionBar. This allows us to easily
@@ -709,7 +753,9 @@ public class QuickContactActivity extends ContactsActivity {
         mWindowScrim.setAlpha(0);
         getWindow().setBackgroundDrawable(mWindowScrim);
 
-        mScroller.initialize(mMultiShrinkScrollerListener, mExtraMode == MODE_FULLY_EXPANDED,
+        mScroller.initialize(
+                mMultiShrinkScrollerListener,
+                mExtraMode == MODE_FULLY_EXPANDED,
                 /* maximumHeaderTextSize */ -1,
                 /* shouldUpdateNameViewHeight */ true);
         // mScroller needs to perform asynchronous measurements after initalize(), therefore
@@ -718,20 +764,26 @@ public class QuickContactActivity extends ContactsActivity {
 
         setHeaderNameText(R.string.missing_name);
 
-        SchedulingUtils.doOnPreDraw(mScroller, /* drawNextFrame = */ true,
+        SchedulingUtils.doOnPreDraw(
+                mScroller,
+                /* drawNextFrame= */ true,
                 new Runnable() {
                     @Override
                     public void run() {
                         if (!mHasAlreadyBeenOpened) {
                             // The initial scrim opacity must match the scrim opacity that would be
                             // achieved by scrolling to the starting position.
-                            final float alphaRatio = mExtraMode == MODE_FULLY_EXPANDED ?
-                                    1 : mScroller.getStartingTransparentHeightRatio();
-                            final int duration = getResources().getInteger(
-                                    android.R.integer.config_shortAnimTime);
+                            final float alphaRatio =
+                                    mExtraMode == MODE_FULLY_EXPANDED
+                                            ? 1
+                                            : mScroller.getStartingTransparentHeightRatio();
+                            final int duration =
+                                    getResources()
+                                            .getInteger(android.R.integer.config_shortAnimTime);
                             final int desiredAlpha = (int) (0xFF * alphaRatio);
-                            ObjectAnimator o = ObjectAnimator.ofInt(mWindowScrim, "alpha", 0,
-                                    desiredAlpha).setDuration(duration);
+                            ObjectAnimator o =
+                                    ObjectAnimator.ofInt(mWindowScrim, "alpha", 0, desiredAlpha)
+                                            .setDuration(duration);
 
                             o.start();
                         }
@@ -740,7 +792,9 @@ public class QuickContactActivity extends ContactsActivity {
 
         if (savedInstanceState != null) {
             final int color = savedInstanceState.getInt(KEY_THEME_COLOR, 0);
-            SchedulingUtils.doOnPreDraw(mScroller, /* drawNextFrame = */ false,
+            SchedulingUtils.doOnPreDraw(
+                    mScroller,
+                    /* drawNextFrame= */ false,
                     new Runnable() {
                         @Override
                         public void run() {
@@ -754,8 +808,9 @@ public class QuickContactActivity extends ContactsActivity {
                             // header tint before the MultiShrinkScroller has been measured will
                             // cause incorrect tinting calculations.
                             if (color != 0) {
-                                setThemeColor(mMaterialColorMapUtils
-                                        .calculatePrimaryAndSecondaryColor(color));
+                                setThemeColor(
+                                        mMaterialColorMapUtils.calculatePrimaryAndSecondaryColor(
+                                                color));
                             }
                         }
                     });
@@ -766,14 +821,15 @@ public class QuickContactActivity extends ContactsActivity {
 
     @Override
     protected void onActivityResult(int requestCode, int resultCode, Intent data) {
-        final boolean deletedOrSplit = requestCode == REQUEST_CODE_CONTACT_EDITOR_ACTIVITY &&
-                (resultCode == ContactDeletionInteraction.RESULT_CODE_DELETED ||
-                resultCode == ContactEditorActivity.RESULT_CODE_SPLIT);
+        final boolean deletedOrSplit =
+                requestCode == REQUEST_CODE_CONTACT_EDITOR_ACTIVITY
+                        && (resultCode == ContactDeletionInteraction.RESULT_CODE_DELETED
+                                || resultCode == ContactEditorActivity.RESULT_CODE_SPLIT);
         setResult(resultCode);
         if (deletedOrSplit) {
             finish();
-        } else if (requestCode == REQUEST_CODE_CONTACT_SELECTION_ACTIVITY &&
-                resultCode != RESULT_CANCELED) {
+        } else if (requestCode == REQUEST_CODE_CONTACT_SELECTION_ACTIVITY
+                && resultCode != RESULT_CANCELED) {
             processIntent(data);
         } else if (requestCode == REQUEST_CODE_JOIN) {
             // Ignore failed requests
@@ -784,16 +840,15 @@ public class QuickContactActivity extends ContactsActivity {
                 joinAggregate(ContentUris.parseId(data.getData()));
             }
         } else if (requestCode == REQUEST_CODE_PICK_RINGTONE && data != null) {
-            final Uri pickedUri = data.getParcelableExtra(
-                        RingtoneManager.EXTRA_RINGTONE_PICKED_URI);
+            final Uri pickedUri =
+                    data.getParcelableExtra(RingtoneManager.EXTRA_RINGTONE_PICKED_URI);
             onRingtonePicked(pickedUri);
         }
     }
 
     private void onRingtonePicked(Uri pickedUri) {
         mCustomRingtone = EditorUiUtils.getRingtoneStringFromUri(pickedUri, CURRENT_API_VERSION);
-        Intent intent = ContactSaveService.createSetRingtone(
-                this, mLookupUri, mCustomRingtone);
+        Intent intent = ContactSaveService.createSetRingtone(this, mLookupUri, mCustomRingtone);
         this.startService(intent);
     }
 
@@ -839,8 +894,10 @@ public class QuickContactActivity extends ContactsActivity {
         // Check to see whether it comes from the old version.
         if (lookupUri != null && LEGACY_AUTHORITY.equals(lookupUri.getAuthority())) {
             final long rawContactId = ContentUris.parseId(lookupUri);
-            lookupUri = RawContacts.getContactLookupUri(getContentResolver(),
-                    ContentUris.withAppendedId(RawContacts.CONTENT_URI, rawContactId));
+            lookupUri =
+                    RawContacts.getContactLookupUri(
+                            getContentResolver(),
+                            ContentUris.withAppendedId(RawContacts.CONTENT_URI, rawContactId));
         }
         mExtraMode = getIntent().getIntExtra(QuickContact.EXTRA_MODE, QuickContact.MODE_LARGE);
         if (isMultiWindowOnPhone()) {
@@ -850,7 +907,6 @@ public class QuickContactActivity extends ContactsActivity {
                 getIntent().getStringExtra(QuickContact.EXTRA_PRIORITIZED_MIMETYPE);
         final Uri oldLookupUri = mLookupUri;
 
-
         if (lookupUri == null) {
             finish();
             return;
@@ -860,15 +916,17 @@ public class QuickContactActivity extends ContactsActivity {
         if (oldLookupUri == null) {
             // Should not log if only orientation changes.
             mShouldLog = !mIsRecreatedInstance;
-            mContactLoader = (ContactLoader) getLoaderManager().initLoader(
-                    LOADER_CONTACT_ID, null, mLoaderContactCallbacks);
+            mContactLoader =
+                    (ContactLoader)
+                            getLoaderManager()
+                                    .initLoader(LOADER_CONTACT_ID, null, mLoaderContactCallbacks);
         } else if (oldLookupUri != mLookupUri) {
             // Should log when reload happens, regardless of orientation change.
             mShouldLog = true;
             // After copying a directory contact, the contact URI changes. Therefore,
             // we need to reload the new contact.
-            mContactLoader = (ContactLoader) (Loader<?>) getLoaderManager().getLoader(
-                    LOADER_CONTACT_ID);
+            mContactLoader =
+                    (ContactLoader) (Loader<?>) getLoaderManager().getLoader(LOADER_CONTACT_ID);
             mContactLoader.setNewLookup(mLookupUri);
             mCachedCp2DataCardModel = null;
         }
@@ -880,8 +938,9 @@ public class QuickContactActivity extends ContactsActivity {
             return;
         }
         mHasAlreadyBeenOpened = true;
-        mScroller.scrollUpForEntranceAnimation(/* scrollToCurrentPosition */ !isMultiWindowOnPhone()
-                && (mExtraMode != MODE_FULLY_EXPANDED));
+        mScroller.scrollUpForEntranceAnimation(
+                /* scrollToCurrentPosition */ !isMultiWindowOnPhone()
+                        && (mExtraMode != MODE_FULLY_EXPANDED));
     }
 
     private boolean isMultiWindowOnPhone() {
@@ -891,7 +950,8 @@ public class QuickContactActivity extends ContactsActivity {
     /** Assign this string to the view if it is not empty. */
     private void setHeaderNameText(int resId) {
         if (mScroller != null) {
-            mScroller.setTitle(getText(resId) == null ? null : getText(resId).toString(),
+            mScroller.setTitle(
+                    getText(resId) == null ? null : getText(resId).toString(),
                     /* isPhoneNumber= */ false);
         }
     }
@@ -906,8 +966,8 @@ public class QuickContactActivity extends ContactsActivity {
     }
 
     /**
-     * Check if the given MIME-type appears in the list of excluded MIME-types
-     * that the most-recent caller requested.
+     * Check if the given MIME-type appears in the list of excluded MIME-types that the most-recent
+     * caller requested.
      */
     private boolean isMimeExcluded(String mimeType) {
         if (mExcludeMimes == null) return false;
@@ -919,9 +979,7 @@ public class QuickContactActivity extends ContactsActivity {
         return false;
     }
 
-    /**
-     * Handle the result from the ContactLoader
-     */
+    /** Handle the result from the ContactLoader */
     private void bindContactData(final Contact data) {
         Trace.beginSection("bindContactData");
 
@@ -939,8 +997,12 @@ public class QuickContactActivity extends ContactsActivity {
             newContactType = ContactType.UNKNOWN_TYPE;
         }
         if (mShouldLog && mContactType != newContactType) {
-            Logger.logQuickContactEvent(mReferrer, newContactType, CardType.UNKNOWN_CARD,
-                    actionType, /* thirdPartyAction */ null);
+            Logger.logQuickContactEvent(
+                    mReferrer,
+                    newContactType,
+                    CardType.UNKNOWN_CARD,
+                    actionType, /* thirdPartyAction */
+                    null);
         }
         mContactType = newContactType;
 
@@ -968,26 +1030,26 @@ public class QuickContactActivity extends ContactsActivity {
 
         Trace.endSection();
 
-        mEntriesAndActionsTask = new AsyncTask<Void, Void, Cp2DataCardModel>() {
+        mEntriesAndActionsTask =
+                new AsyncTask<Void, Void, Cp2DataCardModel>() {
 
-            @Override
-            protected Cp2DataCardModel doInBackground(
-                    Void... params) {
-                return generateDataModelFromContact(data);
-            }
+                    @Override
+                    protected Cp2DataCardModel doInBackground(Void... params) {
+                        return generateDataModelFromContact(data);
+                    }
 
-            @Override
-            protected void onPostExecute(Cp2DataCardModel cardDataModel) {
-                super.onPostExecute(cardDataModel);
-                // Check that original AsyncTask parameters are still valid and the activity
-                // is still running before binding to UI. A new intent could invalidate
-                // the results, for example.
-                if (data == mContactData && !isCancelled()) {
-                    bindDataToCards(cardDataModel);
-                    showActivity();
-                }
-            }
-        };
+                    @Override
+                    protected void onPostExecute(Cp2DataCardModel cardDataModel) {
+                        super.onPostExecute(cardDataModel);
+                        // Check that original AsyncTask parameters are still valid and the activity
+                        // is still running before binding to UI. A new intent could invalidate
+                        // the results, for example.
+                        if (data == mContactData && !isCancelled()) {
+                            bindDataToCards(cardDataModel);
+                            showActivity();
+                        }
+                    }
+                };
         mEntriesAndActionsTask.execute();
     }
 
@@ -1006,7 +1068,9 @@ public class QuickContactActivity extends ContactsActivity {
     private void showActivity() {
         if (mScroller != null) {
             mScroller.setVisibility(View.VISIBLE);
-            SchedulingUtils.doOnPreDraw(mScroller, /* drawNextFrame = */ false,
+            SchedulingUtils.doOnPreDraw(
+                    mScroller,
+                    /* drawNextFrame= */ false,
                     new Runnable() {
                         @Override
                         public void run() {
@@ -1025,8 +1089,8 @@ public class QuickContactActivity extends ContactsActivity {
             }
             // Set aboutCardTitleOut = null, since SORTED_ABOUT_CARD_MIMETYPES doesn't contain
             // the name mimetype.
-            final List<Entry> aboutEntries = dataItemsToEntries(mimeTypeItems,
-                    /* aboutCardTitleOut = */ null);
+            final List<Entry> aboutEntries =
+                    dataItemsToEntries(mimeTypeItems, /* aboutCardTitleOut= */ null);
             if (aboutEntries.size() > 0) {
                 aboutCardEntries.add(aboutEntries);
             }
@@ -1046,15 +1110,14 @@ public class QuickContactActivity extends ContactsActivity {
         maybeShowProgressDialog();
     }
 
-
     @Override
     protected void onPause() {
         super.onPause();
         dismissProgressBar();
     }
 
-    private void populateContactAndAboutCard(Cp2DataCardModel cp2DataCardModel,
-            boolean shouldAddPhoneticName) {
+    private void populateContactAndAboutCard(
+            Cp2DataCardModel cp2DataCardModel, boolean shouldAddPhoneticName) {
         mCachedCp2DataCardModel = cp2DataCardModel;
         if (mHasIntentLaunched || cp2DataCardModel == null) {
             return;
@@ -1066,15 +1129,20 @@ public class QuickContactActivity extends ContactsActivity {
         final String customAboutCardName = cp2DataCardModel.customAboutCardName;
 
         if (contactCardEntries.size() > 0) {
-            mContactCard.initialize(contactCardEntries,
-                    /* numInitialVisibleEntries = */ MIN_NUM_CONTACT_ENTRIES_SHOWN,
-                    /* isExpanded = */ mContactCard.isExpanded(),
-                    /* isAlwaysExpanded = */ true,
+            mContactCard.initialize(
+                    contactCardEntries,
+                    /* numInitialVisibleEntries= */ MIN_NUM_CONTACT_ENTRIES_SHOWN,
+                    /* isExpanded= */ mContactCard.isExpanded(),
+                    /* isAlwaysExpanded= */ true,
                     mExpandingEntryCardViewListener,
                     mScroller);
             if (mContactCard.getVisibility() == View.GONE && mShouldLog) {
-                Logger.logQuickContactEvent(mReferrer, mContactType, CardType.CONTACT,
-                        ActionType.UNKNOWN_ACTION, /* thirdPartyAction */ null);
+                Logger.logQuickContactEvent(
+                        mReferrer,
+                        mContactType,
+                        CardType.CONTACT,
+                        ActionType.UNKNOWN_ACTION, /* thirdPartyAction */
+                        null);
             }
             mContactCard.setVisibility(View.VISIBLE);
         } else {
@@ -1089,35 +1157,44 @@ public class QuickContactActivity extends ContactsActivity {
         // shouldn't be changed. If this is the case, we shouldn't add it again. b/27459294
         final String phoneticName = mContactData.getPhoneticName();
         if (shouldAddPhoneticName && !TextUtils.isEmpty(phoneticName)) {
-            Entry phoneticEntry = new Entry(/* viewId = */ -1,
-                    /* icon = */ null,
-                    getResources().getString(R.string.name_phonetic),
-                    phoneticName,
-                    /* subHeaderIcon = */ null,
-                    /* text = */ null,
-                    /* textIcon = */ null,
-                    /* primaryContentDescription = */ null,
-                    /* intent = */ null,
-                    /* alternateIcon = */ null,
-                    /* alternateIntent = */ null,
-                    /* alternateContentDescription = */ null,
-                    /* shouldApplyColor = */ false,
-                    /* isEditable = */ false,
-                    /* EntryContextMenuInfo = */ new EntryContextMenuInfo(phoneticName,
+            Entry phoneticEntry =
+                    new Entry(
+                            /* viewId= */ -1,
+                            /* icon= */ null,
                             getResources().getString(R.string.name_phonetic),
-                            /* mimeType = */ null, /* id = */ -1, /* isPrimary = */ false),
-                    /* thirdIcon = */ null,
-                    /* thirdIntent = */ null,
-                    /* thirdContentDescription = */ null,
-                    /* thirdAction = */ Entry.ACTION_NONE,
-                    /* thirdExtras = */ null,
-                    /* shouldApplyThirdIconColor = */ true,
-                    /* iconResourceId = */  0);
+                            phoneticName,
+                            /* subHeaderIcon= */ null,
+                            /* text= */ null,
+                            /* textIcon= */ null,
+                            /* primaryContentDescription= */ null,
+                            /* intent= */ null,
+                            /* alternateIcon= */ null,
+                            /* alternateIntent= */ null,
+                            /* alternateContentDescription= */ null,
+                            /* shouldApplyColor= */ false,
+                            /* isEditable= */ false,
+                            /* EntryContextMenuInfo= */ new EntryContextMenuInfo(
+                                    phoneticName,
+                                    getResources().getString(R.string.name_phonetic),
+                                    /* mimeType= */ null,
+                                    /* id= */ -1,
+                                    /* isPrimary= */ false),
+                            /* thirdIcon= */ null,
+                            /* thirdIntent= */ null,
+                            /* thirdContentDescription= */ null,
+                            /* thirdAction= */ Entry.ACTION_NONE,
+                            /* thirdExtras= */ null,
+                            /* shouldApplyThirdIconColor= */ true,
+                            /* iconResourceId= */ 0);
             List<Entry> phoneticList = new ArrayList<>();
             phoneticList.add(phoneticEntry);
             // Phonetic name comes after nickname. Check to see if the first entry type is nickname
-            if (aboutCardEntries.size() > 0 && aboutCardEntries.get(0).get(0).getHeader().equals(
-                    getResources().getString(R.string.header_nickname_entry))) {
+            if (aboutCardEntries.size() > 0
+                    && aboutCardEntries
+                            .get(0)
+                            .get(0)
+                            .getHeader()
+                            .equals(getResources().getString(R.string.header_nickname_entry))) {
                 aboutCardEntries.add(1, phoneticList);
             } else {
                 aboutCardEntries.add(0, phoneticList);
@@ -1128,10 +1205,11 @@ public class QuickContactActivity extends ContactsActivity {
             mAboutCard.setTitle(customAboutCardName);
         }
 
-        mAboutCard.initialize(aboutCardEntries,
-                /* numInitialVisibleEntries = */ 1,
-                /* isExpanded = */ true,
-                /* isAlwaysExpanded = */ true,
+        mAboutCard.initialize(
+                aboutCardEntries,
+                /* numInitialVisibleEntries= */ 1,
+                /* isExpanded= */ true,
+                /* isAlwaysExpanded= */ true,
                 mExpandingEntryCardViewListener,
                 mScroller);
 
@@ -1144,8 +1222,12 @@ public class QuickContactActivity extends ContactsActivity {
         // Show the About card if it has entries
         if (aboutCardEntries.size() > 0) {
             if (mAboutCard.getVisibility() == View.GONE && mShouldLog) {
-                Logger.logQuickContactEvent(mReferrer, mContactType, CardType.ABOUT,
-                        ActionType.UNKNOWN_ACTION, /* thirdPartyAction */ null);
+                Logger.logQuickContactEvent(
+                        mReferrer,
+                        mContactType,
+                        CardType.ABOUT,
+                        ActionType.UNKNOWN_ACTION, /* thirdPartyAction */
+                        null);
             }
             mAboutCard.setVisibility(View.VISIBLE);
         }
@@ -1153,60 +1235,95 @@ public class QuickContactActivity extends ContactsActivity {
     }
 
     /**
-     * Create a card that shows "Add email" and "Add phone number" entries in grey.
-     * When contact is a SIM contact, only shows "Add phone number".
+     * Create a card that shows "Add email" and "Add phone number" entries in grey. When contact is
+     * a SIM contact, only shows "Add phone number".
      */
     private void initializeNoContactDetailCard(boolean areAllRawContactsSimAccounts) {
-        final Drawable phoneIcon = ResourcesCompat.getDrawable(getResources(),
-                R.drawable.quantum_ic_phone_vd_theme_24, null).mutate();
-        final Entry phonePromptEntry = new Entry(CARD_ENTRY_ID_EDIT_CONTACT,
-                phoneIcon, getString(R.string.quickcontact_add_phone_number),
-                /* subHeader = */ null, /* subHeaderIcon = */ null, /* text = */ null,
-                /* textIcon = */ null, /* primaryContentDescription = */ null,
-                getEditContactIntent(),
-                /* alternateIcon = */ null, /* alternateIntent = */ null,
-                /* alternateContentDescription = */ null, /* shouldApplyColor = */ true,
-                /* isEditable = */ false, /* EntryContextMenuInfo = */ null,
-                /* thirdIcon = */ null, /* thirdIntent = */ null,
-                /* thirdContentDescription = */ null,
-                /* thirdAction = */ Entry.ACTION_NONE,
-                /* thirdExtras = */ null,
-                /* shouldApplyThirdIconColor = */ true,
-                R.drawable.quantum_ic_phone_vd_theme_24);
+        final Drawable phoneIcon =
+                ResourcesCompat.getDrawable(
+                                getResources(), R.drawable.quantum_ic_phone_vd_theme_24, null)
+                        .mutate();
+        final Entry phonePromptEntry =
+                new Entry(
+                        CARD_ENTRY_ID_EDIT_CONTACT,
+                        phoneIcon,
+                        getString(R.string.quickcontact_add_phone_number),
+                        /* subHeader= */ null,
+                        /* subHeaderIcon= */ null,
+                        /* text= */ null,
+                        /* textIcon= */ null,
+                        /* primaryContentDescription= */ null,
+                        getEditContactIntent(),
+                        /* alternateIcon= */ null,
+                        /* alternateIntent= */ null,
+                        /* alternateContentDescription= */ null,
+                        /* shouldApplyColor= */ true,
+                        /* isEditable= */ false,
+                        /* EntryContextMenuInfo= */ null,
+                        /* thirdIcon= */ null,
+                        /* thirdIntent= */ null,
+                        /* thirdContentDescription= */ null,
+                        /* thirdAction= */ Entry.ACTION_NONE,
+                        /* thirdExtras= */ null,
+                        /* shouldApplyThirdIconColor= */ true,
+                        R.drawable.quantum_ic_phone_vd_theme_24);
 
         final List<List<Entry>> promptEntries = new ArrayList<>();
         promptEntries.add(new ArrayList<Entry>(1));
         promptEntries.get(0).add(phonePromptEntry);
 
         if (!areAllRawContactsSimAccounts) {
-            final Drawable emailIcon = ResourcesCompat.getDrawable(getResources(),
-                    R.drawable.quantum_ic_email_vd_theme_24, null).mutate();
-            final Entry emailPromptEntry = new Entry(CARD_ENTRY_ID_EDIT_CONTACT,
-                    emailIcon, getString(R.string.quickcontact_add_email), /* subHeader = */ null,
-                    /* subHeaderIcon = */ null,
-                    /* text = */ null, /* textIcon = */ null, /* primaryContentDescription = */ null,
-                    getEditContactIntent(), /* alternateIcon = */ null,
-                    /* alternateIntent = */ null, /* alternateContentDescription = */ null,
-                    /* shouldApplyColor = */ true, /* isEditable = */ false,
-                    /* EntryContextMenuInfo = */ null, /* thirdIcon = */ null,
-                    /* thirdIntent = */ null, /* thirdContentDescription = */ null,
-                    /* thirdAction = */ Entry.ACTION_NONE, /* thirdExtras = */ null,
-                    /* shouldApplyThirdIconColor = */ true,
-                    R.drawable.quantum_ic_email_vd_theme_24);
+            final Drawable emailIcon =
+                    ResourcesCompat.getDrawable(
+                                    getResources(), R.drawable.quantum_ic_email_vd_theme_24, null)
+                            .mutate();
+            final Entry emailPromptEntry =
+                    new Entry(
+                            CARD_ENTRY_ID_EDIT_CONTACT,
+                            emailIcon,
+                            getString(R.string.quickcontact_add_email),
+                            /* subHeader= */ null,
+                            /* subHeaderIcon= */ null,
+                            /* text= */ null,
+                            /* textIcon= */ null,
+                            /* primaryContentDescription= */ null,
+                            getEditContactIntent(),
+                            /* alternateIcon= */ null,
+                            /* alternateIntent= */ null,
+                            /* alternateContentDescription= */ null,
+                            /* shouldApplyColor= */ true,
+                            /* isEditable= */ false,
+                            /* EntryContextMenuInfo= */ null,
+                            /* thirdIcon= */ null,
+                            /* thirdIntent= */ null,
+                            /* thirdContentDescription= */ null,
+                            /* thirdAction= */ Entry.ACTION_NONE,
+                            /* thirdExtras= */ null,
+                            /* shouldApplyThirdIconColor= */ true,
+                            R.drawable.quantum_ic_email_vd_theme_24);
 
             promptEntries.add(new ArrayList<Entry>(1));
             promptEntries.get(1).add(emailPromptEntry);
         }
 
-        final int subHeaderTextColor = getResources().getColor(
-                R.color.quickcontact_entry_sub_header_text_color);
+        final int subHeaderTextColor =
+                getResources().getColor(R.color.quickcontact_entry_sub_header_text_color);
         final PorterDuffColorFilter greyColorFilter =
                 new PorterDuffColorFilter(subHeaderTextColor, PorterDuff.Mode.SRC_ATOP);
-        mNoContactDetailsCard.initialize(promptEntries, 2, /* isExpanded = */ true,
-                /* isAlwaysExpanded = */ true, mExpandingEntryCardViewListener, mScroller);
+        mNoContactDetailsCard.initialize(
+                promptEntries,
+                2,
+                /* isExpanded= */ true,
+                /* isAlwaysExpanded= */ true,
+                mExpandingEntryCardViewListener,
+                mScroller);
         if (mNoContactDetailsCard.getVisibility() == View.GONE && mShouldLog) {
-            Logger.logQuickContactEvent(mReferrer, mContactType, CardType.NO_CONTACT,
-                    ActionType.UNKNOWN_ACTION, /* thirdPartyAction */ null);
+            Logger.logQuickContactEvent(
+                    mReferrer,
+                    mContactType,
+                    CardType.NO_CONTACT,
+                    ActionType.UNKNOWN_ACTION, /* thirdPartyAction */
+                    null);
         }
         mNoContactDetailsCard.setVisibility(View.VISIBLE);
         mNoContactDetailsCard.setEntryHeaderColor(subHeaderTextColor);
@@ -1215,13 +1332,13 @@ public class QuickContactActivity extends ContactsActivity {
 
     /**
      * Builds the {@link DataItem}s Map out of the Contact.
+     *
      * @param data The contact to build the data from.
-     * @return A pair containing a list of data items sorted within mimetype and sorted
-     *  amongst mimetype. The map goes from mimetype string to the sorted list of data items within
-     *  mimetype
+     * @return A pair containing a list of data items sorted within mimetype and sorted amongst
+     *     mimetype. The map goes from mimetype string to the sorted list of data items within
+     *     mimetype
      */
-    private Cp2DataCardModel generateDataModelFromContact(
-            Contact data) {
+    private Cp2DataCardModel generateDataModelFromContact(Contact data) {
         Trace.beginSection("Build data items map");
 
         final Map<String, List<DataItem>> dataItemsMap = new HashMap<>();
@@ -1237,14 +1354,15 @@ public class QuickContactActivity extends ContactsActivity {
                 if (!MIMETYPE_TACHYON.equals(mimeType)) {
                     // Only validate non-Tachyon mimetypes.
                     final AccountType accountType = rawContact.getAccountType(this);
-                    final DataKind dataKind = AccountTypeManager.getInstance(this)
-                            .getKindOrFallback(accountType, mimeType);
+                    final DataKind dataKind =
+                            AccountTypeManager.getInstance(this)
+                                    .getKindOrFallback(accountType, mimeType);
                     if (dataKind == null) continue;
 
                     dataItem.setDataKind(dataKind);
 
-                    final boolean hasData = !TextUtils.isEmpty(dataItem.buildDataString(this,
-                            dataKind));
+                    final boolean hasData =
+                            !TextUtils.isEmpty(dataItem.buildDataString(this, dataKind));
 
                     if (isMimeExcluded(mimeType) || !hasData) continue;
                 } else if (!tachyonEnabled) {
@@ -1299,8 +1417,8 @@ public class QuickContactActivity extends ContactsActivity {
                 // About card mimetypes are built in buildAboutCardEntries, skip here
                 continue;
             } else {
-                List<Entry> contactEntries = dataItemsToEntries(dataItemsList.get(i),
-                        aboutCardName);
+                List<Entry> contactEntries =
+                        dataItemsToEntries(dataItemsList.get(i), aboutCardName);
                 if (contactEntries.size() > 0) {
                     contactCardEntries.add(contactEntries);
                 }
@@ -1329,8 +1447,9 @@ public class QuickContactActivity extends ContactsActivity {
             for (DataItem phone : phoneItems) {
                 if (phone instanceof PhoneDataItem && ((PhoneDataItem) phone).getNumber() != null) {
                     for (DataItem tachyonItem : tachyonItems) {
-                        if (((PhoneDataItem) phone).getNumber().equals(
-                                tachyonItem.getContentValues().getAsString(Data.DATA1))) {
+                        if (((PhoneDataItem) phone)
+                                .getNumber()
+                                .equals(tachyonItem.getContentValues().getAsString(Data.DATA1))) {
                             ((PhoneDataItem) phone).setTachyonReachable(true);
                             ((PhoneDataItem) phone).setReachableDataItem(tachyonItem);
                         }
@@ -1341,8 +1460,8 @@ public class QuickContactActivity extends ContactsActivity {
     }
 
     /**
-     * Class used to hold the About card and Contact cards' data model that gets generated
-     * on a background thread. All data is from CP2.
+     * Class used to hold the About card and Contact cards' data model that gets generated on a
+     * background thread. All data is from CP2.
      */
     private static class Cp2DataCardModel {
         /**
@@ -1350,6 +1469,7 @@ public class QuickContactActivity extends ContactsActivity {
          * are in sorted order using mWithinMimeTypeDataItemComparator.
          */
         public Map<String, List<DataItem>> dataItemsMap;
+
         public List<List<Entry>> aboutCardEntries;
         public List<List<Entry>> contactCardEntries;
         public String customAboutCardName;
@@ -1361,19 +1481,21 @@ public class QuickContactActivity extends ContactsActivity {
     }
 
     /**
-     * Converts a {@link DataItem} into an {@link ExpandingEntryCardView.Entry} for display.
-     * If the {@link ExpandingEntryCardView.Entry} has no visual elements, null is returned.
+     * Converts a {@link DataItem} into an {@link ExpandingEntryCardView.Entry} for display. If the
+     * {@link ExpandingEntryCardView.Entry} has no visual elements, null is returned.
      *
-     * This runs on a background thread. This is set as static to avoid accidentally adding
+     * <p>This runs on a background thread. This is set as static to avoid accidentally adding
      * additional dependencies on unsafe things (like the Activity).
      *
      * @param dataItem The {@link DataItem} to convert.
-     * @param secondDataItem A second {@link DataItem} to help build a full entry for some
-     *  mimetypes
+     * @param secondDataItem A second {@link DataItem} to help build a full entry for some mimetypes
      * @return The {@link ExpandingEntryCardView.Entry}, or null if no visual elements are present.
      */
-    private static Entry dataItemToEntry(DataItem dataItem, DataItem secondDataItem,
-            Context context, Contact contactData,
+    private static Entry dataItemToEntry(
+            DataItem dataItem,
+            DataItem secondDataItem,
+            Context context,
+            Contact contactData,
             final MutableString aboutCardName) {
         if (contactData == null) return null;
         Drawable icon = null;
@@ -1418,66 +1540,99 @@ public class QuickContactActivity extends ContactsActivity {
                 // If the protocol is custom, display the "IM" entry header as well to distinguish
                 // this entry from other ones
                 header = res.getString(R.string.header_im_entry);
-                subHeader = Im.getProtocolLabel(res, protocol,
-                        im.getCustomProtocol()).toString();
+                subHeader = Im.getProtocolLabel(res, protocol, im.getCustomProtocol()).toString();
                 text = im.getData();
             } else {
-                header = Im.getProtocolLabel(res, protocol,
-                        im.getCustomProtocol()).toString();
+                header = Im.getProtocolLabel(res, protocol, im.getCustomProtocol()).toString();
                 subHeader = im.getData();
             }
-            entryContextMenuInfo = new EntryContextMenuInfo(im.getData(), header,
-                    dataItem.getMimeType(), dataItem.getId(), dataItem.isSuperPrimary());
+            entryContextMenuInfo =
+                    new EntryContextMenuInfo(
+                            im.getData(),
+                            header,
+                            dataItem.getMimeType(),
+                            dataItem.getId(),
+                            dataItem.isSuperPrimary());
         } else if (dataItem instanceof OrganizationDataItem) {
             final OrganizationDataItem organization = (OrganizationDataItem) dataItem;
             header = res.getString(R.string.header_organization_entry);
-            entryContextMenuInfo = new EntryContextMenuInfo(subHeader, header,
-                dataItem.getMimeType(), dataItem.getId(), dataItem.isSuperPrimary());
-            text = ContactDisplayUtils
-                .getFormattedCompanyString(context, (OrganizationDataItem) dataItem, false);
+            entryContextMenuInfo =
+                    new EntryContextMenuInfo(
+                            subHeader,
+                            header,
+                            dataItem.getMimeType(),
+                            dataItem.getId(),
+                            dataItem.isSuperPrimary());
+            text =
+                    ContactDisplayUtils.getFormattedCompanyString(
+                            context, (OrganizationDataItem) dataItem, false);
         } else if (dataItem instanceof NicknameDataItem) {
             final NicknameDataItem nickname = (NicknameDataItem) dataItem;
             // Build nickname entries
             final boolean isNameRawContact =
-                (contactData.getNameRawContactId() == dataItem.getRawContactId());
+                    (contactData.getNameRawContactId() == dataItem.getRawContactId());
 
             final boolean duplicatesTitle =
-                isNameRawContact
-                && contactData.getDisplayNameSource() == DisplayNameSources.NICKNAME;
+                    isNameRawContact
+                            && contactData.getDisplayNameSource() == DisplayNameSources.NICKNAME;
 
             if (!duplicatesTitle) {
                 header = res.getString(R.string.header_nickname_entry);
                 subHeader = nickname.getName();
-                entryContextMenuInfo = new EntryContextMenuInfo(subHeader, header,
-                        dataItem.getMimeType(), dataItem.getId(), dataItem.isSuperPrimary());
+                entryContextMenuInfo =
+                        new EntryContextMenuInfo(
+                                subHeader,
+                                header,
+                                dataItem.getMimeType(),
+                                dataItem.getId(),
+                                dataItem.isSuperPrimary());
             }
         } else if (dataItem instanceof CustomDataItem) {
             final CustomDataItem customDataItem = (CustomDataItem) dataItem;
             final String summary = customDataItem.getSummary();
-            header = TextUtils.isEmpty(summary)
-                    ? res.getString(R.string.label_custom_field) : summary;
+            header =
+                    TextUtils.isEmpty(summary)
+                            ? res.getString(R.string.label_custom_field)
+                            : summary;
             subHeader = customDataItem.getContent();
-            entryContextMenuInfo = new EntryContextMenuInfo(subHeader, header,
-                    dataItem.getMimeType(), dataItem.getId(), dataItem.isSuperPrimary());
+            entryContextMenuInfo =
+                    new EntryContextMenuInfo(
+                            subHeader,
+                            header,
+                            dataItem.getMimeType(),
+                            dataItem.getId(),
+                            dataItem.isSuperPrimary());
         } else if (dataItem instanceof NoteDataItem) {
             final NoteDataItem note = (NoteDataItem) dataItem;
             header = res.getString(R.string.header_note_entry);
             subHeader = note.getNote();
-            entryContextMenuInfo = new EntryContextMenuInfo(subHeader, header,
-                    dataItem.getMimeType(), dataItem.getId(), dataItem.isSuperPrimary());
+            entryContextMenuInfo =
+                    new EntryContextMenuInfo(
+                            subHeader,
+                            header,
+                            dataItem.getMimeType(),
+                            dataItem.getId(),
+                            dataItem.isSuperPrimary());
         } else if (dataItem instanceof WebsiteDataItem) {
             final WebsiteDataItem website = (WebsiteDataItem) dataItem;
             header = res.getString(R.string.header_website_entry);
             subHeader = website.getUrl();
-            entryContextMenuInfo = new EntryContextMenuInfo(subHeader, header,
-                    dataItem.getMimeType(), dataItem.getId(), dataItem.isSuperPrimary());
+            entryContextMenuInfo =
+                    new EntryContextMenuInfo(
+                            subHeader,
+                            header,
+                            dataItem.getMimeType(),
+                            dataItem.getId(),
+                            dataItem.isSuperPrimary());
             try {
-                final WebAddress webAddress = new WebAddress(website.buildDataStringForDisplay
-                        (context, kind));
+                final WebAddress webAddress =
+                        new WebAddress(website.buildDataStringForDisplay(context, kind));
                 intent = new Intent(Intent.ACTION_VIEW, Uri.parse(webAddress.toString()));
             } catch (final ParseException e) {
-                Log.e(TAG, "Couldn't parse website: " + website.buildDataStringForDisplay(
-                        context, kind));
+                Log.e(
+                        TAG,
+                        "Couldn't parse website: "
+                                + website.buildDataStringForDisplay(context, kind));
             }
         } else if (dataItem instanceof EventDataItem) {
             final EventDataItem event = (EventDataItem) dataItem;
@@ -1489,8 +1644,7 @@ public class QuickContactActivity extends ContactsActivity {
                     // setting the year to 0 makes a click open the coming birthday
                     cal.set(Calendar.YEAR, 0);
                 }
-                final Date nextAnniversary =
-                        DateUtils.getNextAnnualDate(cal);
+                final Date nextAnniversary = DateUtils.getNextAnnualDate(cal);
                 final Uri.Builder builder = CalendarContract.CONTENT_URI.buildUpon();
                 builder.appendPath("time");
                 ContentUris.appendId(builder, nextAnniversary.getTime());
@@ -1498,12 +1652,19 @@ public class QuickContactActivity extends ContactsActivity {
             }
             header = res.getString(R.string.header_event_entry);
             if (event.hasKindTypeColumn(kind)) {
-                subHeader = EventCompat.getTypeLabel(res, event.getKindTypeColumn(kind),
-                        event.getLabel()).toString();
+                subHeader =
+                        EventCompat.getTypeLabel(
+                                        res, event.getKindTypeColumn(kind), event.getLabel())
+                                .toString();
             }
             text = DateUtils.formatDate(context, dataString);
-            entryContextMenuInfo = new EntryContextMenuInfo(text, header,
-                    dataItem.getMimeType(), dataItem.getId(), dataItem.isSuperPrimary());
+            entryContextMenuInfo =
+                    new EntryContextMenuInfo(
+                            text,
+                            header,
+                            dataItem.getMimeType(),
+                            dataItem.getId(),
+                            dataItem.isSuperPrimary());
         } else if (dataItem instanceof RelationDataItem) {
             final RelationDataItem relation = (RelationDataItem) dataItem;
             final String dataString = relation.buildDataStringForDisplay(context, kind);
@@ -1514,23 +1675,35 @@ public class QuickContactActivity extends ContactsActivity {
             }
             header = res.getString(R.string.header_relation_entry);
             subHeader = relation.getName();
-            entryContextMenuInfo = new EntryContextMenuInfo(subHeader, header,
-                    dataItem.getMimeType(), dataItem.getId(), dataItem.isSuperPrimary());
+            entryContextMenuInfo =
+                    new EntryContextMenuInfo(
+                            subHeader,
+                            header,
+                            dataItem.getMimeType(),
+                            dataItem.getId(),
+                            dataItem.isSuperPrimary());
             if (relation.hasKindTypeColumn(kind)) {
-                text = Relation.getTypeLabel(res,
-                        relation.getKindTypeColumn(kind),
-                        relation.getLabel()).toString();
+                text =
+                        Relation.getTypeLabel(
+                                        res, relation.getKindTypeColumn(kind), relation.getLabel())
+                                .toString();
             }
         } else if (dataItem instanceof PhoneDataItem) {
             final PhoneDataItem phone = (PhoneDataItem) dataItem;
             String phoneLabel = null;
             if (!TextUtils.isEmpty(phone.getNumber())) {
                 primaryContentDescription.append(res.getString(R.string.call_other)).append(" ");
-                header = sBidiFormatter.unicodeWrap(phone.buildDataStringForDisplay(context, kind),
-                        TextDirectionHeuristics.LTR);
-                entryContextMenuInfo = new EntryContextMenuInfo(header,
-                        res.getString(R.string.phoneLabelsGroup), dataItem.getMimeType(),
-                        dataItem.getId(), dataItem.isSuperPrimary());
+                header =
+                        sBidiFormatter.unicodeWrap(
+                                phone.buildDataStringForDisplay(context, kind),
+                                TextDirectionHeuristics.LTR);
+                entryContextMenuInfo =
+                        new EntryContextMenuInfo(
+                                header,
+                                res.getString(R.string.phoneLabelsGroup),
+                                dataItem.getMimeType(),
+                                dataItem.getId(),
+                                dataItem.isSuperPrimary());
                 if (phone.hasKindTypeColumn(kind)) {
                     final int kindTypeColumn = phone.getKindTypeColumn(kind);
                     final String label = phone.getLabel();
@@ -1539,27 +1712,31 @@ public class QuickContactActivity extends ContactsActivity {
                         text = "";
                     } else {
                         text = Phone.getTypeLabel(res, kindTypeColumn, label).toString();
-                        phoneLabel= text;
+                        phoneLabel = text;
                         primaryContentDescription.append(text).append(" ");
                     }
                 }
                 primaryContentDescription.append(header);
-                phoneContentDescription = com.android.contacts.util.ContactDisplayUtils
-                        .getTelephoneTtsSpannable(primaryContentDescription.toString(), header);
+                phoneContentDescription =
+                        com.android.contacts.util.ContactDisplayUtils.getTelephoneTtsSpannable(
+                                primaryContentDescription.toString(), header);
                 iconResourceId = R.drawable.quantum_ic_phone_vd_theme_24;
                 icon = res.getDrawable(iconResourceId);
                 if (PhoneCapabilityTester.isPhone(context)) {
                     intent = CallUtil.getCallIntent(phone.getNumber());
                     intent.putExtra(EXTRA_ACTION_TYPE, ActionType.CALL);
                 }
-                alternateIntent = new Intent(Intent.ACTION_SENDTO,
-                        Uri.fromParts(ContactsUtils.SCHEME_SMSTO, phone.getNumber(), null));
+                alternateIntent =
+                        new Intent(
+                                Intent.ACTION_SENDTO,
+                                Uri.fromParts(ContactsUtils.SCHEME_SMSTO, phone.getNumber(), null));
                 alternateIntent.putExtra(EXTRA_ACTION_TYPE, ActionType.SMS);
 
                 alternateIcon = res.getDrawable(R.drawable.quantum_ic_message_vd_theme_24);
                 alternateContentDescription.append(res.getString(R.string.sms_custom, header));
-                smsContentDescription = com.android.contacts.util.ContactDisplayUtils
-                        .getTelephoneTtsSpannable(alternateContentDescription.toString(), header);
+                smsContentDescription =
+                        com.android.contacts.util.ContactDisplayUtils.getTelephoneTtsSpannable(
+                                alternateContentDescription.toString(), header);
 
                 int videoCapability = CallUtil.getVideoCallingAvailability(context);
                 boolean isPresenceEnabled =
@@ -1572,33 +1749,30 @@ public class QuickContactActivity extends ContactsActivity {
                 if (CallUtil.isCallWithSubjectSupported(context)) {
                     thirdIcon = res.getDrawable(R.drawable.quantum_ic_perm_phone_msg_vd_theme_24);
                     thirdAction = Entry.ACTION_CALL_WITH_SUBJECT;
-                    thirdContentDescription =
-                            res.getString(R.string.call_with_a_note);
+                    thirdContentDescription = res.getString(R.string.call_with_a_note);
                     // Create a bundle containing the data the call subject dialog requires.
                     thirdExtras = new Bundle();
-                    thirdExtras.putLong(CallSubjectDialog.ARG_PHOTO_ID,
-                            contactData.getPhotoId());
-                    thirdExtras.putParcelable(CallSubjectDialog.ARG_PHOTO_URI,
+                    thirdExtras.putLong(CallSubjectDialog.ARG_PHOTO_ID, contactData.getPhotoId());
+                    thirdExtras.putParcelable(
+                            CallSubjectDialog.ARG_PHOTO_URI,
                             UriUtils.parseUriOrNull(contactData.getPhotoUri()));
-                    thirdExtras.putParcelable(CallSubjectDialog.ARG_CONTACT_URI,
-                            contactData.getLookupUri());
-                    thirdExtras.putString(CallSubjectDialog.ARG_NAME_OR_NUMBER,
-                            contactData.getDisplayName());
+                    thirdExtras.putParcelable(
+                            CallSubjectDialog.ARG_CONTACT_URI, contactData.getLookupUri());
+                    thirdExtras.putString(
+                            CallSubjectDialog.ARG_NAME_OR_NUMBER, contactData.getDisplayName());
                     thirdExtras.putBoolean(CallSubjectDialog.ARG_IS_BUSINESS, false);
-                    thirdExtras.putString(CallSubjectDialog.ARG_NUMBER,
-                            phone.getNumber());
-                    thirdExtras.putString(CallSubjectDialog.ARG_DISPLAY_NUMBER,
-                            phone.getFormattedPhoneNumber());
-                    thirdExtras.putString(CallSubjectDialog.ARG_NUMBER_LABEL,
-                            phoneLabel);
+                    thirdExtras.putString(CallSubjectDialog.ARG_NUMBER, phone.getNumber());
+                    thirdExtras.putString(
+                            CallSubjectDialog.ARG_DISPLAY_NUMBER, phone.getFormattedPhoneNumber());
+                    thirdExtras.putString(CallSubjectDialog.ARG_NUMBER_LABEL, phoneLabel);
                 } else if (isVideoEnabled && (!isPresenceEnabled || isPresent)) {
                     thirdIcon = res.getDrawable(R.drawable.quantum_ic_videocam_vd_theme_24);
                     thirdAction = Entry.ACTION_INTENT;
-                    thirdIntent = CallUtil.getVideoCallIntent(phone.getNumber(),
-                            CALL_ORIGIN_QUICK_CONTACTS_ACTIVITY);
+                    thirdIntent =
+                            CallUtil.getVideoCallIntent(
+                                    phone.getNumber(), CALL_ORIGIN_QUICK_CONTACTS_ACTIVITY);
                     thirdIntent.putExtra(EXTRA_ACTION_TYPE, ActionType.VIDEOCALL);
-                    thirdContentDescription =
-                            res.getString(R.string.description_video_call);
+                    thirdContentDescription = res.getString(R.string.description_video_call);
                 } else if (CallUtil.isTachyonEnabled(context)
                         && ((PhoneDataItem) dataItem).isTachyonReachable()) {
                     thirdIcon = res.getDrawable(R.drawable.quantum_ic_videocam_vd_theme_24);
@@ -1606,8 +1780,11 @@ public class QuickContactActivity extends ContactsActivity {
                     thirdIntent = new Intent(TACHYON_CALL_ACTION);
                     thirdIntent.setData(
                             Uri.fromParts(PhoneAccount.SCHEME_TEL, phone.getNumber(), null));
-                    thirdContentDescription = ((PhoneDataItem) dataItem).getReachableDataItem()
-                            .getContentValues().getAsString(Data.DATA2);
+                    thirdContentDescription =
+                            ((PhoneDataItem) dataItem)
+                                    .getReachableDataItem()
+                                    .getContentValues()
+                                    .getAsString(Data.DATA2);
                 }
             }
         } else if (dataItem instanceof EmailDataItem) {
@@ -1619,12 +1796,17 @@ public class QuickContactActivity extends ContactsActivity {
                 intent = new Intent(Intent.ACTION_SENDTO, mailUri);
                 intent.putExtra(EXTRA_ACTION_TYPE, ActionType.EMAIL);
                 header = email.getAddress();
-                entryContextMenuInfo = new EntryContextMenuInfo(header,
-                        res.getString(R.string.emailLabelsGroup), dataItem.getMimeType(),
-                        dataItem.getId(), dataItem.isSuperPrimary());
+                entryContextMenuInfo =
+                        new EntryContextMenuInfo(
+                                header,
+                                res.getString(R.string.emailLabelsGroup),
+                                dataItem.getMimeType(),
+                                dataItem.getId(),
+                                dataItem.isSuperPrimary());
                 if (email.hasKindTypeColumn(kind)) {
-                    text = Email.getTypeLabel(res, email.getKindTypeColumn(kind),
-                            email.getLabel()).toString();
+                    text =
+                            Email.getTypeLabel(res, email.getKindTypeColumn(kind), email.getLabel())
+                                    .toString();
                     primaryContentDescription.append(text).append(" ");
                 }
                 primaryContentDescription.append(header);
@@ -1639,12 +1821,18 @@ public class QuickContactActivity extends ContactsActivity {
                 intent = StructuredPostalUtils.getViewPostalAddressIntent(postalAddress);
                 intent.putExtra(EXTRA_ACTION_TYPE, ActionType.ADDRESS);
                 header = postal.getFormattedAddress();
-                entryContextMenuInfo = new EntryContextMenuInfo(header,
-                        res.getString(R.string.postalLabelsGroup), dataItem.getMimeType(),
-                        dataItem.getId(), dataItem.isSuperPrimary());
+                entryContextMenuInfo =
+                        new EntryContextMenuInfo(
+                                header,
+                                res.getString(R.string.postalLabelsGroup),
+                                dataItem.getMimeType(),
+                                dataItem.getId(),
+                                dataItem.isSuperPrimary());
                 if (postal.hasKindTypeColumn(kind)) {
-                    text = StructuredPostal.getTypeLabel(res,
-                            postal.getKindTypeColumn(kind), postal.getLabel()).toString();
+                    text =
+                            StructuredPostal.getTypeLabel(
+                                            res, postal.getKindTypeColumn(kind), postal.getLabel())
+                                    .toString();
                     primaryContentDescription.append(text).append(" ");
                 }
                 primaryContentDescription.append(header);
@@ -1652,8 +1840,10 @@ public class QuickContactActivity extends ContactsActivity {
                         StructuredPostalUtils.getViewPostalAddressDirectionsIntent(postalAddress);
                 alternateIntent.putExtra(EXTRA_ACTION_TYPE, ActionType.DIRECTIONS);
                 alternateIcon = res.getDrawable(R.drawable.quantum_ic_directions_vd_theme_24);
-                alternateContentDescription.append(res.getString(
-                        R.string.content_description_directions)).append(" ").append(header);
+                alternateContentDescription
+                        .append(res.getString(R.string.content_description_directions))
+                        .append(" ")
+                        .append(header);
                 iconResourceId = R.drawable.quantum_ic_place_vd_theme_24;
                 icon = res.getDrawable(iconResourceId);
             }
@@ -1661,20 +1851,25 @@ public class QuickContactActivity extends ContactsActivity {
             final SipAddressDataItem sip = (SipAddressDataItem) dataItem;
             final String address = sip.getSipAddress();
             if (!TextUtils.isEmpty(address)) {
-                primaryContentDescription.append(res.getString(R.string.call_other)).append(
-                        " ");
+                primaryContentDescription.append(res.getString(R.string.call_other)).append(" ");
                 if (PhoneCapabilityTester.isSipPhone(context)) {
                     final Uri callUri = Uri.fromParts(PhoneAccount.SCHEME_SIP, address, null);
                     intent = CallUtil.getCallIntent(callUri);
                     intent.putExtra(EXTRA_ACTION_TYPE, ActionType.SIPCALL);
                 }
                 header = address;
-                entryContextMenuInfo = new EntryContextMenuInfo(header,
-                        res.getString(R.string.phoneLabelsGroup), dataItem.getMimeType(),
-                        dataItem.getId(), dataItem.isSuperPrimary());
+                entryContextMenuInfo =
+                        new EntryContextMenuInfo(
+                                header,
+                                res.getString(R.string.phoneLabelsGroup),
+                                dataItem.getMimeType(),
+                                dataItem.getId(),
+                                dataItem.isSuperPrimary());
                 if (sip.hasKindTypeColumn(kind)) {
-                    text = SipAddress.getTypeLabel(res,
-                            sip.getKindTypeColumn(kind), sip.getLabel()).toString();
+                    text =
+                            SipAddress.getTypeLabel(
+                                            res, sip.getKindTypeColumn(kind), sip.getLabel())
+                                    .toString();
                     primaryContentDescription.append(text).append(" ");
                 }
                 primaryContentDescription.append(header);
@@ -1684,18 +1879,19 @@ public class QuickContactActivity extends ContactsActivity {
         } else if (dataItem instanceof StructuredNameDataItem) {
             // If the name is already set and this is not the super primary value then leave the
             // current value. This way we show the super primary value when we are able to.
-            if (dataItem.isSuperPrimary() || aboutCardName.value == null
+            if (dataItem.isSuperPrimary()
+                    || aboutCardName.value == null
                     || aboutCardName.value.isEmpty()) {
                 final String givenName = ((StructuredNameDataItem) dataItem).getGivenName();
                 if (!TextUtils.isEmpty(givenName)) {
-                    aboutCardName.value = res.getString(R.string.about_card_title) +
-                            " " + givenName;
+                    aboutCardName.value =
+                            res.getString(R.string.about_card_title) + " " + givenName;
                 } else {
                     aboutCardName.value = res.getString(R.string.about_card_title);
                 }
             }
-        } else if (CallUtil.isTachyonEnabled(context) && MIMETYPE_TACHYON.equals(
-                dataItem.getMimeType())) {
+        } else if (CallUtil.isTachyonEnabled(context)
+                && MIMETYPE_TACHYON.equals(dataItem.getMimeType())) {
             // Skip these actions. They will be placed by the phone number.
             return null;
         } else {
@@ -1716,12 +1912,18 @@ public class QuickContactActivity extends ContactsActivity {
                     // alternate actions
                     if (secondDataItem != null) {
                         icon = res.getDrawable(R.drawable.quantum_ic_hangout_vd_theme_24);
-                        alternateIcon = res.getDrawable(
-                                R.drawable.quantum_ic_hangout_video_vd_theme_24);
+                        alternateIcon =
+                                res.getDrawable(R.drawable.quantum_ic_hangout_video_vd_theme_24);
                         final HangoutsDataItemModel itemModel =
-                                new HangoutsDataItemModel(intent, alternateIntent,
-                                        dataItem, secondDataItem, alternateContentDescription,
-                                        header, text, context);
+                                new HangoutsDataItemModel(
+                                        intent,
+                                        alternateIntent,
+                                        dataItem,
+                                        secondDataItem,
+                                        alternateContentDescription,
+                                        header,
+                                        text,
+                                        context);
 
                         populateHangoutsDataItemModel(itemModel);
                         intent = itemModel.intent;
@@ -1737,8 +1939,9 @@ public class QuickContactActivity extends ContactsActivity {
                         }
                     }
                 } else {
-                    icon = ResolveCache.getInstance(context).getIcon(
-                            dataItem.getMimeType(), intent);
+                    icon =
+                            ResolveCache.getInstance(context)
+                                    .getIcon(dataItem.getMimeType(), intent);
                     // Call mutate to create a new Drawable.ConstantState for color filtering
                     if (icon != null) {
                         icon.mutate();
@@ -1746,9 +1949,13 @@ public class QuickContactActivity extends ContactsActivity {
                     shouldApplyColor = false;
 
                     if (!MIMETYPE_GPLUS_PROFILE.equals(mimetype)) {
-                        entryContextMenuInfo = new EntryContextMenuInfo(header, mimetype,
-                                dataItem.getMimeType(), dataItem.getId(),
-                                dataItem.isSuperPrimary());
+                        entryContextMenuInfo =
+                                new EntryContextMenuInfo(
+                                        header,
+                                        mimetype,
+                                        dataItem.getMimeType(),
+                                        dataItem.getId(),
+                                        dataItem.isSuperPrimary());
                     }
                 }
             }
@@ -1772,30 +1979,49 @@ public class QuickContactActivity extends ContactsActivity {
         }
 
         // If the Entry has no visual elements, return null
-        if (icon == null && TextUtils.isEmpty(header) && TextUtils.isEmpty(subHeader) &&
-                subHeaderIcon == null && TextUtils.isEmpty(text) && textIcon == null) {
+        if (icon == null
+                && TextUtils.isEmpty(header)
+                && TextUtils.isEmpty(subHeader)
+                && subHeaderIcon == null
+                && TextUtils.isEmpty(text)
+                && textIcon == null) {
             return null;
         }
 
         // Ignore dataIds from the Me profile.
-        final int dataId = dataItem.getId() > Integer.MAX_VALUE ?
-                -1 : (int) dataItem.getId();
-
-        return new Entry(dataId, icon, header, subHeader, subHeaderIcon, text, textIcon,
+        final int dataId = dataItem.getId() > Integer.MAX_VALUE ? -1 : (int) dataItem.getId();
+
+        return new Entry(
+                dataId,
+                icon,
+                header,
+                subHeader,
+                subHeaderIcon,
+                text,
+                textIcon,
                 phoneContentDescription == null
                         ? new SpannableString(primaryContentDescription.toString())
                         : phoneContentDescription,
-                intent, alternateIcon, alternateIntent,
+                intent,
+                alternateIcon,
+                alternateIntent,
                 smsContentDescription == null
                         ? new SpannableString(alternateContentDescription.toString())
                         : smsContentDescription,
-                shouldApplyColor, isEditable,
-                entryContextMenuInfo, thirdIcon, thirdIntent, thirdContentDescription, thirdAction,
-                thirdExtras, shouldApplyThirdIconColor, iconResourceId);
-    }
-
-    private List<Entry> dataItemsToEntries(List<DataItem> dataItems,
-            MutableString aboutCardTitleOut) {
+                shouldApplyColor,
+                isEditable,
+                entryContextMenuInfo,
+                thirdIcon,
+                thirdIntent,
+                thirdContentDescription,
+                thirdAction,
+                thirdExtras,
+                shouldApplyThirdIconColor,
+                iconResourceId);
+    }
+
+    private List<Entry> dataItemsToEntries(
+            List<DataItem> dataItems, MutableString aboutCardTitleOut) {
         // Hangouts and G+ use two data items to create one entry.
         if (dataItems.get(0).getMimeType().equals(MIMETYPE_GPLUS_PROFILE)) {
             return gPlusDataItemsToEntries(dataItems);
@@ -1804,8 +2030,13 @@ public class QuickContactActivity extends ContactsActivity {
         } else {
             final List<Entry> entries = new ArrayList<>();
             for (DataItem dataItem : dataItems) {
-                final Entry entry = dataItemToEntry(dataItem, /* secondDataItem = */ null,
-                        this, mContactData, aboutCardTitleOut);
+                final Entry entry =
+                        dataItemToEntry(
+                                dataItem,
+                                /* secondDataItem= */ null,
+                                this,
+                                mContactData,
+                                aboutCardTitleOut);
                 if (entry != null) {
                     entries.add(entry);
                 }
@@ -1814,9 +2045,7 @@ public class QuickContactActivity extends ContactsActivity {
         }
     }
 
-    /**
-     * Put the data items into buckets based on the raw contact id
-     */
+    /** Put the data items into buckets based on the raw contact id */
     private Map<Long, List<DataItem>> dataItemsToBucket(List<DataItem> dataItems) {
         final Map<Long, List<DataItem>> buckets = new HashMap<>();
         for (DataItem dataItem : dataItems) {
@@ -1831,8 +2060,8 @@ public class QuickContactActivity extends ContactsActivity {
     }
 
     /**
-     * For G+ entries, a single ExpandingEntryCardView.Entry consists of two data items. This
-     * method use only the View profile to build entry.
+     * For G+ entries, a single ExpandingEntryCardView.Entry consists of two data items. This method
+     * use only the View profile to build entry.
      */
     private List<Entry> gPlusDataItemsToEntries(List<DataItem> dataItems) {
         final List<Entry> entries = new ArrayList<>();
@@ -1841,8 +2070,13 @@ public class QuickContactActivity extends ContactsActivity {
             for (DataItem dataItem : bucket) {
                 if (GPLUS_PROFILE_DATA_5_VIEW_PROFILE.equals(
                         dataItem.getContentValues().getAsString(Data.DATA5))) {
-                    final Entry entry = dataItemToEntry(dataItem, /* secondDataItem = */ null,
-                            this, mContactData, /* aboutCardName = */ null);
+                    final Entry entry =
+                            dataItemToEntry(
+                                    dataItem,
+                                    /* secondDataItem= */ null,
+                                    this,
+                                    mContactData,
+                                    /* aboutCardName= */ null);
                     if (entry != null) {
                         entries.add(entry);
                     }
@@ -1866,16 +2100,25 @@ public class QuickContactActivity extends ContactsActivity {
         for (List<DataItem> bucket : dataItemsToBucket(dataItems).values()) {
             if (bucket.size() == 2) {
                 // Use the pair to build an entry
-                final Entry entry = dataItemToEntry(bucket.get(0),
-                        /* secondDataItem = */ bucket.get(1), this, mContactData,
-                        /* aboutCardName = */ null);
+                final Entry entry =
+                        dataItemToEntry(
+                                bucket.get(0),
+                                /* secondDataItem= */ bucket.get(1),
+                                this,
+                                mContactData,
+                                /* aboutCardName= */ null);
                 if (entry != null) {
                     entries.add(entry);
                 }
             } else {
                 for (DataItem dataItem : bucket) {
-                    final Entry entry = dataItemToEntry(dataItem, /* secondDataItem = */ null,
-                            this, mContactData, /* aboutCardName = */ null);
+                    final Entry entry =
+                            dataItemToEntry(
+                                    dataItem,
+                                    /* secondDataItem= */ null,
+                                    this,
+                                    mContactData,
+                                    /* aboutCardName= */ null);
                     if (entry != null) {
                         entries.add(entry);
                     }
@@ -1899,9 +2142,15 @@ public class QuickContactActivity extends ContactsActivity {
         public String text;
         public Context context;
 
-        public HangoutsDataItemModel(Intent intent, Intent alternateIntent, DataItem dataItem,
-                DataItem secondDataItem, StringBuilder alternateContentDescription, String header,
-                String text, Context context) {
+        public HangoutsDataItemModel(
+                Intent intent,
+                Intent alternateIntent,
+                DataItem dataItem,
+                DataItem secondDataItem,
+                StringBuilder alternateContentDescription,
+                String header,
+                String text,
+                Context context) {
             this.intent = intent;
             this.alternateIntent = alternateIntent;
             this.dataItem = dataItem;
@@ -1913,11 +2162,11 @@ public class QuickContactActivity extends ContactsActivity {
         }
     }
 
-    private static void populateHangoutsDataItemModel(
-            HangoutsDataItemModel dataModel) {
+    private static void populateHangoutsDataItemModel(HangoutsDataItemModel dataModel) {
         final Intent secondIntent = new Intent(Intent.ACTION_VIEW);
-        secondIntent.setDataAndType(ContentUris.withAppendedId(Data.CONTENT_URI,
-                dataModel.secondDataItem.getId()), dataModel.secondDataItem.getMimeType());
+        secondIntent.setDataAndType(
+                ContentUris.withAppendedId(Data.CONTENT_URI, dataModel.secondDataItem.getId()),
+                dataModel.secondDataItem.getMimeType());
         secondIntent.putExtra(EXTRA_ACTION_TYPE, ActionType.THIRD_PARTY);
         secondIntent.putExtra(EXTRA_THIRD_PARTY_ACTION, dataModel.secondDataItem.getMimeType());
 
@@ -1930,21 +2179,24 @@ public class QuickContactActivity extends ContactsActivity {
             dataModel.alternateContentDescription = new StringBuilder(dataModel.header);
 
             dataModel.intent = secondIntent;
-            dataModel.header = dataModel.secondDataItem.buildDataStringForDisplay(
-                    dataModel.context, dataModel.secondDataItem.getDataKind());
+            dataModel.header =
+                    dataModel.secondDataItem.buildDataStringForDisplay(
+                            dataModel.context, dataModel.secondDataItem.getDataKind());
             dataModel.text = dataModel.secondDataItem.getDataKind().typeColumn;
         } else if (HANGOUTS_DATA_5_MESSAGE.equals(
                 dataModel.dataItem.getContentValues().getAsString(Data.DATA5))) {
             dataModel.alternateIntent = secondIntent;
-            dataModel.alternateContentDescription = new StringBuilder(
-                    dataModel.secondDataItem.buildDataStringForDisplay(dataModel.context,
-                            dataModel.secondDataItem.getDataKind()));
+            dataModel.alternateContentDescription =
+                    new StringBuilder(
+                            dataModel.secondDataItem.buildDataStringForDisplay(
+                                    dataModel.context, dataModel.secondDataItem.getDataKind()));
         }
     }
 
     private static String getIntentResolveLabel(Intent intent, Context context) {
-        final List<ResolveInfo> matches = context.getPackageManager().queryIntentActivities(intent,
-                PackageManager.MATCH_DEFAULT_ONLY);
+        final List<ResolveInfo> matches =
+                context.getPackageManager()
+                        .queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY);
 
         // Pick first match, otherwise best found
         ResolveInfo bestResolve = null;
@@ -1963,9 +2215,8 @@ public class QuickContactActivity extends ContactsActivity {
     }
 
     /**
-     * Asynchronously extract the most vibrant color from the PhotoView. Once extracted,
-     * apply this tint to {@link MultiShrinkScroller}. This operation takes about 20-30ms
-     * on a Nexus 5.
+     * Asynchronously extract the most vibrant color from the PhotoView. Once extracted, apply this
+     * tint to {@link MultiShrinkScroller}. This operation takes about 20-30ms on a Nexus 5.
      */
     private void extractAndApplyTintFromPhotoViewAsynchronously() {
         if (mScroller == null) {
@@ -1976,15 +2227,18 @@ public class QuickContactActivity extends ContactsActivity {
             @Override
             protected MaterialPalette doInBackground(Void... params) {
 
-                if (imageViewDrawable instanceof BitmapDrawable && mContactData != null
+                if (imageViewDrawable instanceof BitmapDrawable
+                        && mContactData != null
                         && mContactData.getThumbnailPhotoBinaryData() != null
                         && mContactData.getThumbnailPhotoBinaryData().length > 0) {
                     // Perform the color analysis on the thumbnail instead of the full sized
                     // image, so that our results will be as similar as possible to the Bugle
                     // app.
-                    final Bitmap bitmap = BitmapFactory.decodeByteArray(
-                            mContactData.getThumbnailPhotoBinaryData(), 0,
-                            mContactData.getThumbnailPhotoBinaryData().length);
+                    final Bitmap bitmap =
+                            BitmapFactory.decodeByteArray(
+                                    mContactData.getThumbnailPhotoBinaryData(),
+                                    0,
+                                    mContactData.getThumbnailPhotoBinaryData().length);
                     try {
                         final int primaryColor = colorFromBitmap(bitmap);
                         if (primaryColor != 0) {
@@ -2030,8 +2284,7 @@ public class QuickContactActivity extends ContactsActivity {
         mStatusBarColor = palette.mSecondaryColor;
         updateStatusBarColor();
 
-        mColorFilter =
-                new PorterDuffColorFilter(mColorFilterColor, PorterDuff.Mode.SRC_ATOP);
+        mColorFilter = new PorterDuffColorFilter(mColorFilterColor, PorterDuff.Mode.SRC_ATOP);
         mContactCard.setColorAndFilter(mColorFilterColor, mColorFilter);
         mAboutCard.setColorAndFilter(mColorFilterColor, mColorFilter);
     }
@@ -2048,8 +2301,12 @@ public class QuickContactActivity extends ContactsActivity {
             desiredStatusBarColor = Color.TRANSPARENT;
         }
         // Animate to the new color.
-        final ObjectAnimator animation = ObjectAnimator.ofInt(getWindow(), "statusBarColor",
-                getWindow().getStatusBarColor(), desiredStatusBarColor);
+        final ObjectAnimator animation =
+                ObjectAnimator.ofInt(
+                        getWindow(),
+                        "statusBarColor",
+                        getWindow().getStatusBarColor(),
+                        desiredStatusBarColor);
         animation.setDuration(ANIMATION_STATUS_BAR_COLOR_CHANGE_DURATION);
         animation.setEvaluator(new ArgbEvaluator());
         animation.start();
@@ -2067,67 +2324,83 @@ public class QuickContactActivity extends ContactsActivity {
 
     private final LoaderCallbacks<Contact> mLoaderContactCallbacks =
             new LoaderCallbacks<Contact>() {
-        @Override
-        public void onLoaderReset(Loader<Contact> loader) {
-            mContactData = null;
-        }
+                @Override
+                public void onLoaderReset(Loader<Contact> loader) {
+                    mContactData = null;
+                }
 
-        @Override
-        public void onLoadFinished(Loader<Contact> loader, Contact data) {
-            Trace.beginSection("onLoadFinished()");
-            try {
+                @Override
+                public void onLoadFinished(Loader<Contact> loader, Contact data) {
+                    Trace.beginSection("onLoadFinished()");
+                    try {
 
-                if (isFinishing()) {
-                    return;
-                }
-                if (data.isError()) {
-                    // This means either the contact is invalid or we had an
-                    // internal error such as an acore crash.
-                    Log.i(TAG, "Failed to load contact: " + ((ContactLoader)loader).getLookupUri());
-                    Toast.makeText(QuickContactActivity.this, R.string.invalidContactMessage,
-                            Toast.LENGTH_LONG).show();
-                    finish();
-                    return;
-                }
-                if (data.isNotFound()) {
-                    Log.i(TAG, "No contact found: " + ((ContactLoader)loader).getLookupUri());
-                    Toast.makeText(QuickContactActivity.this, R.string.invalidContactMessage,
-                            Toast.LENGTH_LONG).show();
-                    finish();
-                    return;
-                }
+                        if (isFinishing()) {
+                            return;
+                        }
+                        if (data.isError()) {
+                            // This means either the contact is invalid or we had an
+                            // internal error such as an acore crash.
+                            Log.i(
+                                    TAG,
+                                    "Failed to load contact: "
+                                            + ((ContactLoader) loader).getLookupUri());
+                            Toast.makeText(
+                                            QuickContactActivity.this,
+                                            R.string.invalidContactMessage,
+                                            Toast.LENGTH_LONG)
+                                    .show();
+                            finish();
+                            return;
+                        }
+                        if (data.isNotFound()) {
+                            Log.i(
+                                    TAG,
+                                    "No contact found: " + ((ContactLoader) loader).getLookupUri());
+                            Toast.makeText(
+                                            QuickContactActivity.this,
+                                            R.string.invalidContactMessage,
+                                            Toast.LENGTH_LONG)
+                                    .show();
+                            finish();
+                            return;
+                        }
 
-                if (!mIsRecreatedInstance && !mShortcutUsageReported && data != null) {
-                    mShortcutUsageReported = true;
-                    DynamicShortcuts.reportShortcutUsed(QuickContactActivity.this,
-                            data.getLookupKey());
-                }
-                bindContactData(data);
+                        if (!mIsRecreatedInstance && !mShortcutUsageReported && data != null) {
+                            mShortcutUsageReported = true;
+                            DynamicShortcuts.reportShortcutUsed(
+                                    QuickContactActivity.this, data.getLookupKey());
+                        }
+                        bindContactData(data);
 
-            } finally {
-                Trace.endSection();
-            }
-        }
+                    } finally {
+                        Trace.endSection();
+                    }
+                }
 
-        @Override
-        public Loader<Contact> onCreateLoader(int id, Bundle args) {
-            if (mLookupUri == null) {
-                Log.wtf(TAG, "Lookup uri wasn't initialized. Loader was started too early");
-            }
-            // Load all contact data. We need loadGroupMetaData=true to determine whether the
-            // contact is invisible. If it is, we need to display an "Add to Contacts" MenuItem.
-            return new ContactLoader(getApplicationContext(), mLookupUri,
-                    true /*loadGroupMetaData*/, true /*postViewNotification*/,
-                    true /*computeFormattedPhoneNumber*/);
-        }
-    };
+                @Override
+                public Loader<Contact> onCreateLoader(int id, Bundle args) {
+                    if (mLookupUri == null) {
+                        Log.wtf(TAG, "Lookup uri wasn't initialized. Loader was started too early");
+                    }
+                    // Load all contact data. We need loadGroupMetaData=true to determine whether
+                    // the
+                    // contact is invisible. If it is, we need to display an "Add to Contacts"
+                    // MenuItem.
+                    return new ContactLoader(
+                            getApplicationContext(),
+                            mLookupUri,
+                            true /*loadGroupMetaData*/,
+                            true /*postViewNotification*/,
+                            true /*computeFormattedPhoneNumber*/);
+                }
+            };
 
     @Override
     public void onBackPressed() {
-        final int previousScreenType = getIntent().getIntExtra
-                (EXTRA_PREVIOUS_SCREEN_TYPE, ScreenType.UNKNOWN);
+        final int previousScreenType =
+                getIntent().getIntExtra(EXTRA_PREVIOUS_SCREEN_TYPE, ScreenType.UNKNOWN);
         if ((previousScreenType == ScreenType.ALL_CONTACTS
-                || previousScreenType == ScreenType.FAVORITES)
+                        || previousScreenType == ScreenType.FAVORITES)
                 && !SharedPreferenceUtil.getHamburgerPromoTriggerActionHappenedBefore(this)) {
             SharedPreferenceUtil.setHamburgerPromoTriggerActionHappenedBefore(this);
         }
@@ -2157,7 +2430,7 @@ public class QuickContactActivity extends ContactsActivity {
             // results on the UI thread. In some circumstances Activities are killed without
             // onStop() being called. This is not a problem, because in these circumstances
             // the entire process will be killed.
-            mEntriesAndActionsTask.cancel(/* mayInterruptIfRunning = */ false);
+            mEntriesAndActionsTask.cancel(/* mayInterruptIfRunning= */ false);
         }
     }
 
@@ -2167,25 +2440,23 @@ public class QuickContactActivity extends ContactsActivity {
         super.onDestroy();
     }
 
-    /**
-     * Returns true if it is possible to edit the current contact.
-     */
+    /** Returns true if it is possible to edit the current contact. */
     private boolean isContactEditable() {
         return mContactData != null && !mContactData.isDirectoryEntry();
     }
 
-    /**
-     * Returns true if it is possible to share the current contact.
-     */
+    /** Returns true if it is possible to share the current contact. */
     private boolean isContactShareable() {
         return mContactData != null && !mContactData.isDirectoryEntry();
     }
 
     private Intent getEditContactIntent() {
-        return EditorIntents.createEditContactIntent(QuickContactActivity.this,
+        return EditorIntents.createEditContactIntent(
+                QuickContactActivity.this,
                 mContactData.getLookupUri(),
                 mHasComputedThemeColor
-                        ? new MaterialPalette(mColorFilterColor, mStatusBarColor) : null,
+                        ? new MaterialPalette(mColorFilterColor, mStatusBarColor)
+                        : null,
                 mContactData.getPhotoId());
     }
 
@@ -2197,22 +2468,27 @@ public class QuickContactActivity extends ContactsActivity {
 
     private void deleteContact() {
         final Uri contactUri = mContactData.getLookupUri();
-        ContactDeletionInteraction.start(this, contactUri, /* finishActivityWhenDone =*/ true);
+        ContactDeletionInteraction.start(this, contactUri, /* finishActivityWhenDone= */ true);
     }
 
     private void toggleStar(MenuItem starredMenuItem, boolean isStarred) {
         // To improve responsiveness, swap out the picture (and tag) in the UI already
-        ContactDisplayUtils.configureStarredMenuItem(starredMenuItem,
-                mContactData.isDirectoryEntry(), mContactData.isUserProfile(), !isStarred);
+        ContactDisplayUtils.configureStarredMenuItem(
+                starredMenuItem,
+                mContactData.isDirectoryEntry(),
+                mContactData.isUserProfile(),
+                !isStarred);
 
         // Now perform the real save
-        final Intent intent = ContactSaveService.createSetStarredIntent(
-                QuickContactActivity.this, mContactData.getLookupUri(), !isStarred);
+        final Intent intent =
+                ContactSaveService.createSetStarredIntent(
+                        QuickContactActivity.this, mContactData.getLookupUri(), !isStarred);
         startService(intent);
 
-        final CharSequence accessibilityText = !isStarred
-                ? getResources().getText(R.string.description_action_menu_add_star)
-                : getResources().getText(R.string.description_action_menu_remove_star);
+        final CharSequence accessibilityText =
+                !isStarred
+                        ? getResources().getText(R.string.description_action_menu_add_star)
+                        : getResources().getText(R.string.description_action_menu_remove_star);
         // Accessibility actions need to have an associated view. We can't access the MenuItem's
         // underlying view, so put this accessibility action on the root view.
         mScroller.announceForAccessibility(accessibilityText);
@@ -2226,9 +2502,9 @@ public class QuickContactActivity extends ContactsActivity {
         intent.putExtra(Intent.EXTRA_STREAM, shareUri);
 
         // Launch chooser to share contact via
-        MessageFormat msgFormat = new MessageFormat(
-            getResources().getString(R.string.title_share_via),
-            Locale.getDefault());
+        MessageFormat msgFormat =
+                new MessageFormat(
+                        getResources().getString(R.string.title_share_via), Locale.getDefault());
         Map<String, Object> arguments = new HashMap<>();
         arguments.put("count", 1);
         CharSequence chooseTitle = msgFormat.format(arguments);
@@ -2242,66 +2518,78 @@ public class QuickContactActivity extends ContactsActivity {
         }
     }
 
-    /**
-     * Creates a launcher shortcut with the current contact.
-     */
+    /** Creates a launcher shortcut with the current contact. */
     private void createLauncherShortcutWithContact() {
         if (BuildCompat.isAtLeastO()) {
-            final ShortcutManager shortcutManager = (ShortcutManager)
-                    getSystemService(SHORTCUT_SERVICE);
-            final DynamicShortcuts shortcuts =
-                    new DynamicShortcuts(QuickContactActivity.this);
+            final ShortcutManager shortcutManager =
+                    (ShortcutManager) getSystemService(SHORTCUT_SERVICE);
+            final DynamicShortcuts shortcuts = new DynamicShortcuts(QuickContactActivity.this);
             String displayName = mContactData.getDisplayName();
             if (displayName == null) {
                 displayName = getString(R.string.missing_name);
             }
-            final ShortcutInfo shortcutInfo = shortcuts.getQuickContactShortcutInfo(
-                    mContactData.getId(), mContactData.getLookupKey(), displayName);
+            final ShortcutInfo shortcutInfo =
+                    shortcuts.getQuickContactShortcutInfo(
+                            mContactData.getId(), mContactData.getLookupKey(), displayName);
             if (shortcutInfo != null) {
                 shortcutManager.requestPinShortcut(shortcutInfo, null);
             }
         } else {
-            final ShortcutIntentBuilder builder = new ShortcutIntentBuilder(this,
-                    new OnShortcutIntentCreatedListener() {
-
-                        @Override
-                        public void onShortcutIntentCreated(Uri uri, Intent shortcutIntent) {
-                            // Broadcast the shortcutIntent to the launcher to create a
-                            // shortcut to this contact
-                            shortcutIntent.setAction(ACTION_INSTALL_SHORTCUT);
-                            QuickContactActivity.this.sendBroadcast(shortcutIntent);
-                            // Send a toast to give feedback to the user that a shortcut to this
-                            // contact was added to the launcher.
-                            final String displayName = shortcutIntent
-                                    .getStringExtra(Intent.EXTRA_SHORTCUT_NAME);
-                            final String toastMessage = TextUtils.isEmpty(displayName)
-                                    ? getString(R.string.createContactShortcutSuccessful_NoName)
-                                    : getString(R.string.createContactShortcutSuccessful,
-                                            displayName);
-                            Toast.makeText(QuickContactActivity.this, toastMessage,
-                                    Toast.LENGTH_SHORT).show();
-                        }
-                    });
+            final ShortcutIntentBuilder builder =
+                    new ShortcutIntentBuilder(
+                            this,
+                            new OnShortcutIntentCreatedListener() {
+
+                                @Override
+                                public void onShortcutIntentCreated(
+                                        Uri uri, Intent shortcutIntent) {
+                                    // Broadcast the shortcutIntent to the launcher to create a
+                                    // shortcut to this contact
+                                    shortcutIntent.setAction(ACTION_INSTALL_SHORTCUT);
+                                    QuickContactActivity.this.sendBroadcast(shortcutIntent);
+                                    // Send a toast to give feedback to the user that a shortcut to
+                                    // this
+                                    // contact was added to the launcher.
+                                    final String displayName =
+                                            shortcutIntent.getStringExtra(
+                                                    Intent.EXTRA_SHORTCUT_NAME);
+                                    final String toastMessage =
+                                            TextUtils.isEmpty(displayName)
+                                                    ? getString(
+                                                            R.string
+                                                                    .createContactShortcutSuccessful_NoName)
+                                                    : getString(
+                                                            R.string
+                                                                    .createContactShortcutSuccessful,
+                                                            displayName);
+                                    Toast.makeText(
+                                                    QuickContactActivity.this,
+                                                    toastMessage,
+                                                    Toast.LENGTH_SHORT)
+                                            .show();
+                                }
+                            });
             builder.createContactShortcutIntent(mContactData.getLookupUri());
         }
     }
 
     private boolean isShortcutCreatable() {
-        if (mContactData == null || mContactData.isUserProfile() ||
-                mContactData.isDirectoryEntry()) {
+        if (mContactData == null
+                || mContactData.isUserProfile()
+                || mContactData.isDirectoryEntry()) {
             return false;
         }
 
         if (BuildCompat.isAtLeastO()) {
-            final ShortcutManager manager = (ShortcutManager)
-                    getSystemService(Context.SHORTCUT_SERVICE);
+            final ShortcutManager manager =
+                    (ShortcutManager) getSystemService(Context.SHORTCUT_SERVICE);
             return manager.isRequestPinShortcutSupported();
         }
 
         final Intent createShortcutIntent = new Intent();
         createShortcutIntent.setAction(ACTION_INSTALL_SHORTCUT);
-        final List<ResolveInfo> receivers = getPackageManager()
-                .queryBroadcastReceivers(createShortcutIntent, 0);
+        final List<ResolveInfo> receivers =
+                getPackageManager().queryBroadcastReceivers(createShortcutIntent, 0);
         return receivers != null && receivers.size() > 0;
     }
 
@@ -2309,8 +2597,7 @@ public class QuickContactActivity extends ContactsActivity {
         if (contact != null) {
             mSendToVoicemailState = contact.isSendToVoicemail();
             mCustomRingtone = contact.getCustomRingtone();
-            mArePhoneOptionsChangable = isContactEditable()
-                    && PhoneCapabilityTester.isPhone(this);
+            mArePhoneOptionsChangable = isContactEditable() && PhoneCapabilityTester.isPhone(this);
         }
     }
 
@@ -2325,15 +2612,17 @@ public class QuickContactActivity extends ContactsActivity {
     public boolean onPrepareOptionsMenu(Menu menu) {
         if (mContactData != null) {
             final MenuItem starredMenuItem = menu.findItem(R.id.menu_star);
-            ContactDisplayUtils.configureStarredMenuItem(starredMenuItem,
-                    mContactData.isDirectoryEntry(), mContactData.isUserProfile(),
+            ContactDisplayUtils.configureStarredMenuItem(
+                    starredMenuItem,
+                    mContactData.isDirectoryEntry(),
+                    mContactData.isUserProfile(),
                     mContactData.getStarred());
 
             // Configure edit MenuItem
             final MenuItem editMenuItem = menu.findItem(R.id.menu_edit);
             editMenuItem.setVisible(true);
-            if (DirectoryContactUtil.isDirectoryContact(mContactData) || InvisibleContactUtil
-                    .isInvisibleAndAddable(mContactData, this)) {
+            if (DirectoryContactUtil.isDirectoryContact(mContactData)
+                    || InvisibleContactUtil.isInvisibleAndAddable(mContactData, this)) {
                 editMenuItem.setIcon(R.drawable.quantum_ic_person_add_vd_theme_24);
                 editMenuItem.setTitle(R.string.menu_add_contact);
             } else if (isContactEditable()) {
@@ -2345,15 +2634,17 @@ public class QuickContactActivity extends ContactsActivity {
 
             // The link menu item is only visible if this has a single raw contact.
             final MenuItem joinMenuItem = menu.findItem(R.id.menu_join);
-            joinMenuItem.setVisible(!InvisibleContactUtil.isInvisibleAndAddable(mContactData, this)
-                    && isContactEditable() && !mContactData.isUserProfile()
-                    && !mContactData.isMultipleRawContacts());
+            joinMenuItem.setVisible(
+                    !InvisibleContactUtil.isInvisibleAndAddable(mContactData, this)
+                            && isContactEditable()
+                            && !mContactData.isUserProfile()
+                            && !mContactData.isMultipleRawContacts());
 
             // Viewing linked contacts can only happen if there are multiple raw contacts and
             // the link menu isn't available.
             final MenuItem linkedContactsMenuItem = menu.findItem(R.id.menu_linked_contacts);
-            linkedContactsMenuItem.setVisible(mContactData.isMultipleRawContacts()
-                    && !joinMenuItem.isVisible());
+            linkedContactsMenuItem.setVisible(
+                    mContactData.isMultipleRawContacts() && !joinMenuItem.isVisible());
 
             final MenuItem deleteMenuItem = menu.findItem(R.id.menu_delete);
             deleteMenuItem.setVisible(isContactEditable() && !mContactData.isUserProfile());
@@ -2374,8 +2665,10 @@ public class QuickContactActivity extends ContactsActivity {
                     Build.VERSION.SDK_INT < Build.VERSION_CODES.M
                             && !mContactData.isUserProfile()
                             && mArePhoneOptionsChangable);
-            sendToVoiceMailMenuItem.setTitle(mSendToVoicemailState
-                    ? R.string.menu_unredirect_calls_to_vm : R.string.menu_redirect_calls_to_vm);
+            sendToVoiceMailMenuItem.setTitle(
+                    mSendToVoicemailState
+                            ? R.string.menu_unredirect_calls_to_vm
+                            : R.string.menu_redirect_calls_to_vm);
 
             final MenuItem helpMenu = menu.findItem(R.id.menu_help);
             helpMenu.setVisible(HelpUtils.isHelpAndFeedbackAvailable());
@@ -2388,21 +2681,28 @@ public class QuickContactActivity extends ContactsActivity {
     @Override
     public boolean onOptionsItemSelected(MenuItem item) {
         final int id = item.getItemId();
-        if (id == R.id.menu_star) {// Make sure there is a contact
+        if (id == R.id.menu_star) { // Make sure there is a contact
             if (mContactData != null) {
                 // Read the current starred value from the UI instead of using the last
                 // loaded state. This allows rapid tapping without writing the same
                 // value several times
                 final boolean isStarred = item.isChecked();
-                Logger.logQuickContactEvent(mReferrer, mContactType, CardType.UNKNOWN_CARD,
+                Logger.logQuickContactEvent(
+                        mReferrer,
+                        mContactType,
+                        CardType.UNKNOWN_CARD,
                         isStarred ? ActionType.UNSTAR : ActionType.STAR,
-                            /* thirdPartyAction */ null);
+                        /* thirdPartyAction */ null);
                 toggleStar(item, isStarred);
             }
         } else if (id == R.id.menu_edit) {
             if (DirectoryContactUtil.isDirectoryContact(mContactData)) {
-                Logger.logQuickContactEvent(mReferrer, mContactType, CardType.UNKNOWN_CARD,
-                        ActionType.ADD, /* thirdPartyAction */ null);
+                Logger.logQuickContactEvent(
+                        mReferrer,
+                        mContactType,
+                        CardType.UNKNOWN_CARD,
+                        ActionType.ADD, /* thirdPartyAction */
+                        null);
 
                 // This action is used to launch the contact selector, with the option of
                 // creating a new contact. Creating a new contact is an INSERT, while selecting
@@ -2418,8 +2718,7 @@ public class QuickContactActivity extends ContactsActivity {
                 // or better (e.g. structured name, nickname)
                 if (mContactData.getDisplayNameSource() >= DisplayNameSources.NICKNAME) {
                     intent.putExtra(Intents.Insert.NAME, mContactData.getDisplayName());
-                } else if (mContactData.getDisplayNameSource()
-                        == DisplayNameSources.ORGANIZATION) {
+                } else if (mContactData.getDisplayNameSource() == DisplayNameSources.ORGANIZATION) {
                     // This is probably an organization. Instead of copying the organization
                     // name into a name entry, copy it into the organization entry. This
                     // way we will still consider the contact an organization.
@@ -2434,30 +2733,40 @@ public class QuickContactActivity extends ContactsActivity {
                 // If the contact can only export to the same account, add it to the intent.
                 // Otherwise the ContactEditorFragment will show a dialog for selecting
                 // an account.
-                if (mContactData.getDirectoryExportSupport() ==
-                        Directory.EXPORT_SUPPORT_SAME_ACCOUNT_ONLY) {
-                    intent.putExtra(Intents.Insert.EXTRA_ACCOUNT,
-                            new Account(mContactData.getDirectoryAccountName(),
+                if (mContactData.getDirectoryExportSupport()
+                        == Directory.EXPORT_SUPPORT_SAME_ACCOUNT_ONLY) {
+                    intent.putExtra(
+                            Intents.Insert.EXTRA_ACCOUNT,
+                            new Account(
+                                    mContactData.getDirectoryAccountName(),
                                     mContactData.getDirectoryAccountType()));
-                    intent.putExtra(Intents.Insert.EXTRA_DATA_SET,
+                    intent.putExtra(
+                            Intents.Insert.EXTRA_DATA_SET,
                             mContactData.getRawContacts().get(0).getDataSet());
                 }
 
                 // Add this flag to disable the delete menu option on directory contact joins
                 // with local contacts. The delete option is ambiguous when joining contacts.
                 intent.putExtra(
-                        ContactEditorFragment.INTENT_EXTRA_DISABLE_DELETE_MENU_OPTION,
-                        true);
+                        ContactEditorFragment.INTENT_EXTRA_DISABLE_DELETE_MENU_OPTION, true);
 
                 intent.setPackage(getPackageName());
                 startActivityForResult(intent, REQUEST_CODE_CONTACT_SELECTION_ACTIVITY);
             } else if (InvisibleContactUtil.isInvisibleAndAddable(mContactData, this)) {
-                Logger.logQuickContactEvent(mReferrer, mContactType, CardType.UNKNOWN_CARD,
-                        ActionType.ADD, /* thirdPartyAction */ null);
+                Logger.logQuickContactEvent(
+                        mReferrer,
+                        mContactType,
+                        CardType.UNKNOWN_CARD,
+                        ActionType.ADD, /* thirdPartyAction */
+                        null);
                 InvisibleContactUtil.addToDefaultGroup(mContactData, this);
             } else if (isContactEditable()) {
-                Logger.logQuickContactEvent(mReferrer, mContactType, CardType.UNKNOWN_CARD,
-                        ActionType.EDIT, /* thirdPartyAction */ null);
+                Logger.logQuickContactEvent(
+                        mReferrer,
+                        mContactType,
+                        CardType.UNKNOWN_CARD,
+                        ActionType.EDIT, /* thirdPartyAction */
+                        null);
                 editContact();
             }
         } else if (id == R.id.menu_join) {
@@ -2465,40 +2774,62 @@ public class QuickContactActivity extends ContactsActivity {
         } else if (id == R.id.menu_linked_contacts) {
             return showRawContactPickerDialog();
         } else if (id == R.id.menu_delete) {
-            Logger.logQuickContactEvent(mReferrer, mContactType, CardType.UNKNOWN_CARD,
-                    ActionType.REMOVE, /* thirdPartyAction */ null);
+            Logger.logQuickContactEvent(
+                    mReferrer,
+                    mContactType,
+                    CardType.UNKNOWN_CARD,
+                    ActionType.REMOVE, /* thirdPartyAction */
+                    null);
             if (isContactEditable()) {
                 deleteContact();
             }
         } else if (id == R.id.menu_share) {
-            Logger.logQuickContactEvent(mReferrer, mContactType, CardType.UNKNOWN_CARD,
-                    ActionType.SHARE, /* thirdPartyAction */ null);
+            Logger.logQuickContactEvent(
+                    mReferrer,
+                    mContactType,
+                    CardType.UNKNOWN_CARD,
+                    ActionType.SHARE, /* thirdPartyAction */
+                    null);
             if (isContactShareable()) {
                 shareContact();
             }
         } else if (id == R.id.menu_create_contact_shortcut) {
-            Logger.logQuickContactEvent(mReferrer, mContactType, CardType.UNKNOWN_CARD,
-                    ActionType.SHORTCUT, /* thirdPartyAction */ null);
+            Logger.logQuickContactEvent(
+                    mReferrer,
+                    mContactType,
+                    CardType.UNKNOWN_CARD,
+                    ActionType.SHORTCUT, /* thirdPartyAction */
+                    null);
             if (isShortcutCreatable()) {
                 createLauncherShortcutWithContact();
             }
         } else if (id == R.id.menu_set_ringtone) {
             doPickRingtone();
-        } else if (id == R.id.menu_send_to_voicemail) {// Update state and save
+        } else if (id == R.id.menu_send_to_voicemail) { // Update state and save
             mSendToVoicemailState = !mSendToVoicemailState;
-            item.setTitle(mSendToVoicemailState
-                    ? R.string.menu_unredirect_calls_to_vm
-                    : R.string.menu_redirect_calls_to_vm);
-            final Intent intent = ContactSaveService.createSetSendToVoicemail(
-                    this, mLookupUri, mSendToVoicemailState);
+            item.setTitle(
+                    mSendToVoicemailState
+                            ? R.string.menu_unredirect_calls_to_vm
+                            : R.string.menu_redirect_calls_to_vm);
+            final Intent intent =
+                    ContactSaveService.createSetSendToVoicemail(
+                            this, mLookupUri, mSendToVoicemailState);
             this.startService(intent);
         } else if (id == R.id.menu_help) {
-            Logger.logQuickContactEvent(mReferrer, mContactType, CardType.UNKNOWN_CARD,
-                    ActionType.HELP, /* thirdPartyAction */ null);
+            Logger.logQuickContactEvent(
+                    mReferrer,
+                    mContactType,
+                    CardType.UNKNOWN_CARD,
+                    ActionType.HELP, /* thirdPartyAction */
+                    null);
             HelpUtils.launchHelpAndFeedbackForContactScreen(this);
         } else {
-            Logger.logQuickContactEvent(mReferrer, mContactType, CardType.UNKNOWN_CARD,
-                    ActionType.UNKNOWN_ACTION, /* thirdPartyAction */ null);
+            Logger.logQuickContactEvent(
+                    mReferrer,
+                    mContactType,
+                    CardType.UNKNOWN_CARD,
+                    ActionType.UNKNOWN_ACTION, /* thirdPartyAction */
+                    null);
             return super.onOptionsItemSelected(item);
         }
         return true;
@@ -2506,12 +2837,13 @@ public class QuickContactActivity extends ContactsActivity {
 
     private boolean showRawContactPickerDialog() {
         if (mContactData == null) return false;
-        startActivityForResult(EditorIntents.createViewLinkedContactsIntent(
-                QuickContactActivity.this,
-                mContactData.getLookupUri(),
-                mHasComputedThemeColor
-                        ? new MaterialPalette(mColorFilterColor, mStatusBarColor)
-                        : null),
+        startActivityForResult(
+                EditorIntents.createViewLinkedContactsIntent(
+                        QuickContactActivity.this,
+                        mContactData.getLookupUri(),
+                        mHasComputedThemeColor
+                                ? new MaterialPalette(mColorFilterColor, mStatusBarColor)
+                                : null),
                 REQUEST_CODE_CONTACT_EDITOR_ACTIVITY);
         return true;
     }
@@ -2527,18 +2859,19 @@ public class QuickContactActivity extends ContactsActivity {
         return true;
     }
 
-    /**
-     * Performs aggregation with the contact selected by the user from suggestions or A-Z list.
-     */
+    /** Performs aggregation with the contact selected by the user from suggestions or A-Z list. */
     private void joinAggregate(final long contactId) {
-        final Intent intent = ContactSaveService.createJoinContactsIntent(
-                this, mPreviousContactId, contactId, QuickContactActivity.class,
-                Intent.ACTION_VIEW);
+        final Intent intent =
+                ContactSaveService.createJoinContactsIntent(
+                        this,
+                        mPreviousContactId,
+                        contactId,
+                        QuickContactActivity.class,
+                        Intent.ACTION_VIEW);
         this.startService(intent);
         showLinkProgressBar();
     }
 
-
     private void doPickRingtone() {
         final Intent intent = new Intent(RingtoneManager.ACTION_RINGTONE_PICKER);
         // Allow user to pick 'Default'
@@ -2548,8 +2881,8 @@ public class QuickContactActivity extends ContactsActivity {
         // Allow the user to pick a silent ringtone
         intent.putExtra(RingtoneManager.EXTRA_RINGTONE_SHOW_SILENT, true);
 
-        final Uri ringtoneUri = EditorUiUtils.getRingtoneUriFromString(mCustomRingtone,
-                CURRENT_API_VERSION);
+        final Uri ringtoneUri =
+                EditorUiUtils.getRingtoneUriFromString(mCustomRingtone, CURRENT_API_VERSION);
 
         // Put checkmark next to the current ringtone for this contact
         intent.putExtra(RingtoneManager.EXTRA_RINGTONE_EXISTING_URI, ringtoneUri);
@@ -2579,11 +2912,11 @@ public class QuickContactActivity extends ContactsActivity {
     }
 
     private void maybeShowProgressDialog() {
-        if (ContactSaveService.getState().isActionPending(
-                ContactSaveService.ACTION_SPLIT_CONTACT)) {
+        if (ContactSaveService.getState()
+                .isActionPending(ContactSaveService.ACTION_SPLIT_CONTACT)) {
             showUnlinkProgressBar();
-        } else if (ContactSaveService.getState().isActionPending(
-                ContactSaveService.ACTION_JOIN_CONTACTS)) {
+        } else if (ContactSaveService.getState()
+                .isActionPending(ContactSaveService.ACTION_JOIN_CONTACTS)) {
             showLinkProgressBar();
         }
     }
diff --git a/src/com/android/contacts/vcard/SelectAccountActivity.java b/src/com/android/contacts/vcard/SelectAccountActivity.java
index 8ead5fab3..797fc8670 100644
--- a/src/com/android/contacts/vcard/SelectAccountActivity.java
+++ b/src/com/android/contacts/vcard/SelectAccountActivity.java
@@ -65,15 +65,6 @@ public class SelectAccountActivity extends Activity {
             Log.w(LOG_TAG, "Account does not exist");
             finish();
             return;
-        } else if (accountList.size() == 1) {
-            final AccountWithDataSet account = accountList.get(0);
-            final Intent intent = new Intent();
-            intent.putExtra(ACCOUNT_NAME, account.name);
-            intent.putExtra(ACCOUNT_TYPE, account.type);
-            intent.putExtra(DATA_SET, account.dataSet);
-            setResult(RESULT_OK, intent);
-            finish();
-            return;
         }
 
         Log.i(LOG_TAG, "The number of available accounts: " + accountList.size());
diff --git a/tests/AndroidManifest.xml b/tests/AndroidManifest.xml
index 9ccfa3f89..2c68442bf 100644
--- a/tests/AndroidManifest.xml
+++ b/tests/AndroidManifest.xml
@@ -17,7 +17,7 @@
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.android.contacts.tests">
 
-    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="29" />
+    <uses-sdk android:minSdkVersion="36" android:targetSdkVersion="36" />
 
     <uses-permission android:name="android.permission.READ_CONTACTS" />
     <uses-permission android:name="android.permission.READ_CALL_LOG"/>
diff --git a/tests/src/com/android/contacts/DynamicShortcutsTests.java b/tests/src/com/android/contacts/DynamicShortcutsTests.java
index df9d33a7a..b781675de 100644
--- a/tests/src/com/android/contacts/DynamicShortcutsTests.java
+++ b/tests/src/com/android/contacts/DynamicShortcutsTests.java
@@ -39,7 +39,6 @@ import android.provider.ContactsContract.Contacts;
 import android.test.AndroidTestCase;
 import android.test.mock.MockContentResolver;
 
-import androidx.test.filters.SdkSuppress;
 import androidx.test.filters.SmallTest;
 
 import com.android.contacts.test.mocks.MockContentProvider;
@@ -56,18 +55,16 @@ import java.util.Collections;
 import java.util.List;
 
 @TargetApi(Build.VERSION_CODES.N_MR1)
-@SdkSuppress(minSdkVersion = Build.VERSION_CODES.N_MR1)
 @SmallTest
 public class DynamicShortcutsTests extends AndroidTestCase {
 
-
     @Override
     protected void tearDown() throws Exception {
         super.tearDown();
 
         // Clean up the job if it was scheduled by these tests.
-        final JobScheduler scheduler = (JobScheduler) getContext()
-                .getSystemService(Context.JOB_SCHEDULER_SERVICE);
+        final JobScheduler scheduler =
+                (JobScheduler) getContext().getSystemService(Context.JOB_SCHEDULER_SERVICE);
         scheduler.cancel(ContactsJobService.DYNAMIC_SHORTCUTS_JOB_ID);
     }
 
@@ -83,17 +80,18 @@ public class DynamicShortcutsTests extends AndroidTestCase {
     public void test_createShortcutFromRow_hasCorrectResult() {
         final DynamicShortcuts sut = createDynamicShortcuts();
 
-        final Cursor row = queryResult(
-                // ID, LOOKUP_KEY, DISPLAY_NAME_PRIMARY
-                1l, "lookup_key", "John Smith"
-        );
+        final Cursor row =
+                queryResult(
+                        // ID, LOOKUP_KEY, DISPLAY_NAME_PRIMARY
+                        1l, "lookup_key", "John Smith");
 
         row.moveToFirst();
         final ShortcutInfo shortcut = sut.builderForContactShortcut(row).build();
 
         assertEquals("lookup_key", shortcut.getId());
         assertEquals(Contacts.getLookupUri(1, "lookup_key"), shortcut.getIntent().getData());
-        assertEquals(ContactsContract.QuickContact.ACTION_QUICK_CONTACT,
+        assertEquals(
+                ContactsContract.QuickContact.ACTION_QUICK_CONTACT,
                 shortcut.getIntent().getAction());
         assertEquals("John Smith", shortcut.getShortLabel());
         assertEquals("John Smith", shortcut.getLongLabel());
@@ -113,8 +111,8 @@ public class DynamicShortcutsTests extends AndroidTestCase {
         sut.setShortLabelMaxLength(5);
         sut.setLongLabelMaxLength(10);
 
-        final ShortcutInfo shortcut = sut.builderForContactShortcut(1l, "lookup_key",
-                "123456789 1011").build();
+        final ShortcutInfo shortcut =
+                sut.builderForContactShortcut(1l, "lookup_key", "123456789 1011").build();
 
         assertEquals("1234…", shortcut.getShortLabel());
         assertEquals("123456789…", shortcut.getLongLabel());
@@ -122,60 +120,76 @@ public class DynamicShortcutsTests extends AndroidTestCase {
 
     public void test_updatePinned_disablesShortcutsForRemovedContacts() throws Exception {
         final ShortcutManager mockShortcutManager = mock(ShortcutManager.class);
-        when(mockShortcutManager.getPinnedShortcuts()).thenReturn(
-                Collections.singletonList(makeDynamic(shortcutFor(1l, "key1", "name1"))));
+        when(mockShortcutManager.getPinnedShortcuts())
+                .thenReturn(
+                        Collections.singletonList(makeDynamic(shortcutFor(1l, "key1", "name1"))));
 
         final DynamicShortcuts sut = createDynamicShortcuts(emptyResolver(), mockShortcutManager);
 
         sut.updatePinned();
 
-        verify(mockShortcutManager).disableShortcuts(
-                eq(Collections.singletonList("key1")), anyString());
+        verify(mockShortcutManager)
+                .disableShortcuts(eq(Collections.singletonList("key1")), anyString());
     }
 
     public void test_updatePinned_updatesExistingShortcutsWithMatchingKeys() throws Exception {
         final ShortcutManager mockShortcutManager = mock(ShortcutManager.class);
-        when(mockShortcutManager.getPinnedShortcuts()).thenReturn(
-                Arrays.asList(
-                        makeDynamic(shortcutFor(1l, "key1", "name1")),
-                        makeDynamic(shortcutFor(2l, "key2", "name2")),
-                        makeDynamic(shortcutFor(3l, "key3", "name3"))
-                ));
-
-        final DynamicShortcuts sut = createDynamicShortcuts(resolverWithExpectedQueries(
-                queryForSingleRow(Contacts.getLookupUri(1l, "key1"), 11l, "key1", "New Name1"),
-                queryForSingleRow(Contacts.getLookupUri(2l, "key2"), 2l, "key2", "name2"),
-                queryForSingleRow(Contacts.getLookupUri(3l, "key3"), 33l, "key3", "name3")
-        ), mockShortcutManager);
+        when(mockShortcutManager.getPinnedShortcuts())
+                .thenReturn(
+                        Arrays.asList(
+                                makeDynamic(shortcutFor(1l, "key1", "name1")),
+                                makeDynamic(shortcutFor(2l, "key2", "name2")),
+                                makeDynamic(shortcutFor(3l, "key3", "name3"))));
+
+        final DynamicShortcuts sut =
+                createDynamicShortcuts(
+                        resolverWithExpectedQueries(
+                                queryForSingleRow(
+                                        Contacts.getLookupUri(1l, "key1"),
+                                        11l,
+                                        "key1",
+                                        "New Name1"),
+                                queryForSingleRow(
+                                        Contacts.getLookupUri(2l, "key2"), 2l, "key2", "name2"),
+                                queryForSingleRow(
+                                        Contacts.getLookupUri(3l, "key3"), 33l, "key3", "name3")),
+                        mockShortcutManager);
 
         sut.updatePinned();
 
         final ArgumentCaptor<List<ShortcutInfo>> updateArgs =
                 ArgumentCaptor.forClass((Class) List.class);
 
-        verify(mockShortcutManager).disableShortcuts(
-                eq(Collections.<String>emptyList()), anyString());
+        verify(mockShortcutManager)
+                .disableShortcuts(eq(Collections.<String>emptyList()), anyString());
         verify(mockShortcutManager).updateShortcuts(updateArgs.capture());
 
         final List<ShortcutInfo> arg = updateArgs.getValue();
         assertThat(arg.size(), equalTo(3));
-        assertThat(arg.get(0),
-                isShortcutForContact(11l, "key1", "New Name1"));
-        assertThat(arg.get(1),
-                isShortcutForContact(2l, "key2", "name2"));
-        assertThat(arg.get(2),
-                isShortcutForContact(33l, "key3", "name3"));
+        assertThat(arg.get(0), isShortcutForContact(11l, "key1", "New Name1"));
+        assertThat(arg.get(1), isShortcutForContact(2l, "key2", "name2"));
+        assertThat(arg.get(2), isShortcutForContact(33l, "key3", "name3"));
     }
 
     public void test_refresh_setsDynamicShortcutsToStrequentContacts() {
         final ShortcutManager mockShortcutManager = mock(ShortcutManager.class);
-        when(mockShortcutManager.getPinnedShortcuts()).thenReturn(
-                Collections.<ShortcutInfo>emptyList());
-        final DynamicShortcuts sut = createDynamicShortcuts(resolverWithExpectedQueries(
-                queryFor(Contacts.CONTENT_STREQUENT_URI,
-                        1l, "starred_key", "starred name",
-                        2l, "freq_key", "freq name",
-                        3l, "starred_2", "Starred Two")), mockShortcutManager);
+        when(mockShortcutManager.getPinnedShortcuts())
+                .thenReturn(Collections.<ShortcutInfo>emptyList());
+        final DynamicShortcuts sut =
+                createDynamicShortcuts(
+                        resolverWithExpectedQueries(
+                                queryFor(
+                                        Contacts.CONTENT_STREQUENT_URI,
+                                        1l,
+                                        "starred_key",
+                                        "starred name",
+                                        2l,
+                                        "freq_key",
+                                        "freq name",
+                                        3l,
+                                        "starred_2",
+                                        "Starred Two")),
+                        mockShortcutManager);
 
         sut.refresh();
 
@@ -193,16 +207,32 @@ public class DynamicShortcutsTests extends AndroidTestCase {
 
     public void test_refresh_skipsContactsWithNullName() {
         final ShortcutManager mockShortcutManager = mock(ShortcutManager.class);
-        when(mockShortcutManager.getPinnedShortcuts()).thenReturn(
-                Collections.<ShortcutInfo>emptyList());
-        final DynamicShortcuts sut = createDynamicShortcuts(resolverWithExpectedQueries(
-                queryFor(Contacts.CONTENT_STREQUENT_URI,
-                        1l, "key1", "first",
-                        2l, "key2", "second",
-                        3l, "key3", null,
-                        4l, null, null,
-                        5l, "key5", "fifth",
-                        6l, "key6", "sixth")), mockShortcutManager);
+        when(mockShortcutManager.getPinnedShortcuts())
+                .thenReturn(Collections.<ShortcutInfo>emptyList());
+        final DynamicShortcuts sut =
+                createDynamicShortcuts(
+                        resolverWithExpectedQueries(
+                                queryFor(
+                                        Contacts.CONTENT_STREQUENT_URI,
+                                        1l,
+                                        "key1",
+                                        "first",
+                                        2l,
+                                        "key2",
+                                        "second",
+                                        3l,
+                                        "key3",
+                                        null,
+                                        4l,
+                                        null,
+                                        null,
+                                        5l,
+                                        "key5",
+                                        "fifth",
+                                        6l,
+                                        "key6",
+                                        "sixth")),
+                        mockShortcutManager);
 
         sut.refresh();
 
@@ -217,42 +247,51 @@ public class DynamicShortcutsTests extends AndroidTestCase {
         assertThat(arg.get(1), isShortcutForContact(2l, "key2", "second"));
         assertThat(arg.get(2), isShortcutForContact(5l, "key5", "fifth"));
 
-
         // Also verify that it doesn't crash if there are fewer than 3 valid strequent contacts
-        createDynamicShortcuts(resolverWithExpectedQueries(
-                queryFor(Contacts.CONTENT_STREQUENT_URI,
-                        1l, "key1", "first",
-                        2l, "key2", "second",
-                        3l, "key3", null,
-                        4l, null, null)), mock(ShortcutManager.class)).refresh();
+        createDynamicShortcuts(
+                        resolverWithExpectedQueries(
+                                queryFor(
+                                        Contacts.CONTENT_STREQUENT_URI,
+                                        1l,
+                                        "key1",
+                                        "first",
+                                        2l,
+                                        "key2",
+                                        "second",
+                                        3l,
+                                        "key3",
+                                        null,
+                                        4l,
+                                        null,
+                                        null)),
+                        mock(ShortcutManager.class))
+                .refresh();
     }
 
-
     public void test_handleFlagDisabled_stopsJob() {
         final ShortcutManager mockShortcutManager = mock(ShortcutManager.class);
         final JobScheduler mockJobScheduler = mock(JobScheduler.class);
-        final DynamicShortcuts sut = createDynamicShortcuts(emptyResolver(), mockShortcutManager,
-                mockJobScheduler);
+        final DynamicShortcuts sut =
+                createDynamicShortcuts(emptyResolver(), mockShortcutManager, mockJobScheduler);
 
         sut.handleFlagDisabled();
 
         verify(mockJobScheduler).cancel(eq(ContactsJobService.DYNAMIC_SHORTCUTS_JOB_ID));
     }
 
-
     public void test_scheduleUpdateJob_schedulesJob() {
         final DynamicShortcuts sut = new DynamicShortcuts(getContext());
         sut.scheduleUpdateJob();
         assertThat(DynamicShortcuts.isJobScheduled(getContext()), Matchers.is(true));
     }
 
-    private Matcher<ShortcutInfo> isShortcutForContact(final long id,
-            final String lookupKey, final String name) {
+    private Matcher<ShortcutInfo> isShortcutForContact(
+            final long id, final String lookupKey, final String name) {
         return new BaseMatcher<ShortcutInfo>() {
             @Override
             public boolean matches(Object o) {
-                if (!(o instanceof  ShortcutInfo)) return false;
-                final ShortcutInfo other = (ShortcutInfo)o;
+                if (!(o instanceof ShortcutInfo)) return false;
+                final ShortcutInfo other = (ShortcutInfo) o;
                 return id == other.getExtras().getLong(Contacts._ID)
                         && lookupKey.equals(other.getId())
                         && name.equals(other.getLongLabel())
@@ -261,15 +300,21 @@ public class DynamicShortcutsTests extends AndroidTestCase {
 
             @Override
             public void describeTo(Description description) {
-                description.appendText("Should be a shortcut for contact with _ID=" + id +
-                        " lookup=" + lookupKey + " and display_name=" + name);
+                description.appendText(
+                        "Should be a shortcut for contact with _ID="
+                                + id
+                                + " lookup="
+                                + lookupKey
+                                + " and display_name="
+                                + name);
             }
         };
     }
 
     private ShortcutInfo shortcutFor(long contactId, String lookupKey, String name) {
         return new DynamicShortcuts(getContext())
-                .builderForContactShortcut(contactId, lookupKey, name).build();
+                .builderForContactShortcut(contactId, lookupKey, name)
+                .build();
     }
 
     private ContentResolver emptyResolver() {
@@ -283,11 +328,11 @@ public class DynamicShortcutsTests extends AndroidTestCase {
     }
 
     private MockContentProvider.Query queryFor(Uri uri, Object... rows) {
-        final MockContentProvider.Query query = MockContentProvider.Query
-                .forUrisMatching(uri.getAuthority(), uri.getPath())
-                .withProjection(DynamicShortcuts.PROJECTION)
-                .withAnySelection()
-                .withAnySortOrder();
+        final MockContentProvider.Query query =
+                MockContentProvider.Query.forUrisMatching(uri.getAuthority(), uri.getPath())
+                        .withProjection(DynamicShortcuts.PROJECTION)
+                        .withAnySelection()
+                        .withAnySortOrder();
 
         populateQueryRows(query, DynamicShortcuts.PROJECTION.length, rows);
         return query;
@@ -319,24 +364,23 @@ public class DynamicShortcutsTests extends AndroidTestCase {
         return createDynamicShortcuts(emptyResolver(), mock(ShortcutManager.class));
     }
 
-
-    private DynamicShortcuts createDynamicShortcuts(ContentResolver resolver,
-            ShortcutManager shortcutManager) {
+    private DynamicShortcuts createDynamicShortcuts(
+            ContentResolver resolver, ShortcutManager shortcutManager) {
         return createDynamicShortcuts(resolver, shortcutManager, mock(JobScheduler.class));
     }
 
-    private DynamicShortcuts createDynamicShortcuts(ContentResolver resolver,
-            ShortcutManager shortcutManager, JobScheduler jobScheduler) {
-        final DynamicShortcuts result = new DynamicShortcuts(getContext(), resolver,
-                shortcutManager, jobScheduler);
+    private DynamicShortcuts createDynamicShortcuts(
+            ContentResolver resolver, ShortcutManager shortcutManager, JobScheduler jobScheduler) {
+        final DynamicShortcuts result =
+                new DynamicShortcuts(getContext(), resolver, shortcutManager, jobScheduler);
         // Use very long label limits to make checking shortcuts easier to understand
         result.setShortLabelMaxLength(100);
         result.setLongLabelMaxLength(100);
         return result;
     }
 
-    private void populateQueryRows(MockContentProvider.Query query, int numColumns,
-            Object... rows) {
+    private void populateQueryRows(
+            MockContentProvider.Query query, int numColumns, Object... rows) {
         for (int i = 0; i < rows.length; i += numColumns) {
             Object[] row = new Object[numColumns];
             for (int j = 0; j < numColumns; j++) {
@@ -360,10 +404,11 @@ public class DynamicShortcutsTests extends AndroidTestCase {
     }
 
     private Cursor queryResult(String[] columns, Object... values) {
-        MatrixCursor result = new MatrixCursor(new String[] {
-                Contacts._ID, Contacts.LOOKUP_KEY,
-                Contacts.DISPLAY_NAME_PRIMARY
-        });
+        MatrixCursor result =
+                new MatrixCursor(
+                        new String[] {
+                            Contacts._ID, Contacts.LOOKUP_KEY, Contacts.DISPLAY_NAME_PRIMARY
+                        });
         for (int i = 0; i < values.length; i += columns.length) {
             MatrixCursor.RowBuilder builder = result.newRow();
             for (int j = 0; j < columns.length; j++) {
diff --git a/tests/src/com/android/contacts/GroupsDaoIntegrationTests.java b/tests/src/com/android/contacts/GroupsDaoIntegrationTests.java
index 179a51edd..7546b3219 100644
--- a/tests/src/com/android/contacts/GroupsDaoIntegrationTests.java
+++ b/tests/src/com/android/contacts/GroupsDaoIntegrationTests.java
@@ -34,13 +34,12 @@ import android.test.InstrumentationTestCase;
 import androidx.test.filters.MediumTest;
 
 import com.android.contacts.model.account.AccountWithDataSet;
+import com.android.contacts.preference.ContactsPreferences;
 
 import java.util.ArrayList;
 import java.util.List;
 
-/**
- * Tests of GroupsDaoImpl that perform DB operations directly against CP2
- */
+/** Tests of GroupsDaoImpl that perform DB operations directly against CP2 */
 @MediumTest
 public class GroupsDaoIntegrationTests extends InstrumentationTestCase {
 
@@ -53,6 +52,7 @@ public class GroupsDaoIntegrationTests extends InstrumentationTestCase {
 
         mTestRecords = new ArrayList<>();
         mResolver = getContext().getContentResolver();
+        new ContactsPreferences(getContext()).clearDefaultAccount();
     }
 
     @Override
@@ -81,8 +81,9 @@ public class GroupsDaoIntegrationTests extends InstrumentationTestCase {
         final Cursor cursor = mResolver.query(uri, null, null, null, null, null);
         try {
             cursor.moveToFirst();
-            assertEquals(1, cursor.getInt(cursor.getColumnIndexOrThrow(
-                    ContactsContract.Groups.DELETED)));
+            assertEquals(
+                    1,
+                    cursor.getInt(cursor.getColumnIndexOrThrow(ContactsContract.Groups.DELETED)));
         } finally {
             cursor.close();
         }
@@ -111,10 +112,14 @@ public class GroupsDaoIntegrationTests extends InstrumentationTestCase {
 
         assertEquals(1, sut.delete(groupUri));
 
-        final Cursor cursor = mResolver.query(Data.CONTENT_URI, null,
-                Data.MIMETYPE + "=? AND " + GroupMembership.GROUP_ROW_ID + "=?",
-                new String[] { GroupMembership.CONTENT_ITEM_TYPE, String.valueOf(groupId) },
-                null, null);
+        final Cursor cursor =
+                mResolver.query(
+                        Data.CONTENT_URI,
+                        null,
+                        Data.MIMETYPE + "=? AND " + GroupMembership.GROUP_ROW_ID + "=?",
+                        new String[] {GroupMembership.CONTENT_ITEM_TYPE, String.valueOf(groupId)},
+                        null,
+                        null);
 
         try {
             cursor.moveToFirst();
@@ -143,10 +148,16 @@ public class GroupsDaoIntegrationTests extends InstrumentationTestCase {
 
         final long newGroupId = ContentUris.parseId(recreatedGroup);
 
-        final Cursor cursor = mResolver.query(Data.CONTENT_URI, null,
-                Data.MIMETYPE + "=? AND " + GroupMembership.GROUP_ROW_ID + "=?",
-                new String[] { GroupMembership.CONTENT_ITEM_TYPE, String.valueOf(newGroupId) },
-                null, null);
+        final Cursor cursor =
+                mResolver.query(
+                        Data.CONTENT_URI,
+                        null,
+                        Data.MIMETYPE + "=? AND " + GroupMembership.GROUP_ROW_ID + "=?",
+                        new String[] {
+                            GroupMembership.CONTENT_ITEM_TYPE, String.valueOf(newGroupId)
+                        },
+                        null,
+                        null);
 
         try {
             assertEquals(2, cursor.getCount());
@@ -174,8 +185,10 @@ public class GroupsDaoIntegrationTests extends InstrumentationTestCase {
         // or nearby values  to cover some special case or boundary condition.
         final long nonExistentId = Integer.MAX_VALUE - 10;
 
-        final Bundle undoData = sut.captureDeletionUndoData(ContentUris
-                .withAppendedId(ContactsContract.Groups.CONTENT_URI, nonExistentId));
+        final Bundle undoData =
+                sut.captureDeletionUndoData(
+                        ContentUris.withAppendedId(
+                                ContactsContract.Groups.CONTENT_URI, nonExistentId));
 
         assertTrue(undoData.isEmpty());
     }
@@ -202,24 +215,37 @@ public class GroupsDaoIntegrationTests extends InstrumentationTestCase {
     }
 
     private void assertGroupHasTitle(Uri groupUri, String title) {
-        final Cursor cursor = mResolver.query(groupUri,
-                new String[] { ContactsContract.Groups.TITLE },
-                ContactsContract.Groups.DELETED + "=?",
-                new String[] { "0" }, null, null);
+        final Cursor cursor =
+                mResolver.query(
+                        groupUri,
+                        new String[] {ContactsContract.Groups.TITLE},
+                        ContactsContract.Groups.DELETED + "=?",
+                        new String[] {"0"},
+                        null,
+                        null);
         try {
-            assertTrue("Group does not have title \"" + title + "\"",
-                    cursor.getCount() == 1 && cursor.moveToFirst() &&
-                            title.equals(cursor.getString(0)));
+            assertTrue(
+                    "Group does not have title \"" + title + "\"",
+                    cursor.getCount() == 1
+                            && cursor.moveToFirst()
+                            && title.equals(cursor.getString(0)));
         } finally {
             cursor.close();
         }
     }
 
     private void assertGroupWithTitleExists(String title) {
-        final Cursor cursor = mResolver.query(ContactsContract.Groups.CONTENT_URI, null,
-                ContactsContract.Groups.TITLE + "=? AND " +
-                        ContactsContract.Groups.DELETED + "=?",
-                new String[] { title, "0" }, null, null);
+        final Cursor cursor =
+                mResolver.query(
+                        ContactsContract.Groups.CONTENT_URI,
+                        null,
+                        ContactsContract.Groups.TITLE
+                                + "=? AND "
+                                + ContactsContract.Groups.DELETED
+                                + "=?",
+                        new String[] {title, "0"},
+                        null,
+                        null);
         try {
             assertTrue("No group exists with title \"" + title + "\"", cursor.getCount() > 0);
         } finally {
@@ -243,8 +269,7 @@ public class GroupsDaoIntegrationTests extends InstrumentationTestCase {
     private Uri addMemberToGroup(long rawContactId, long groupId) {
         final ContentValues values = new ContentValues();
         values.put(Data.RAW_CONTACT_ID, rawContactId);
-        values.put(Data.MIMETYPE,
-                GroupMembership.CONTENT_ITEM_TYPE);
+        values.put(Data.MIMETYPE, GroupMembership.CONTENT_ITEM_TYPE);
         values.put(GroupMembership.GROUP_ROW_ID, groupId);
 
         // Dont' need to add to testRecords because it will be cleaned up when parent raw_contact
@@ -264,11 +289,13 @@ public class GroupsDaoIntegrationTests extends InstrumentationTestCase {
         final ArrayList<ContentProviderOperation> ops = new ArrayList<>();
         for (Uri uri : mTestRecords) {
             if (uri == null) continue;
-            ops.add(ContentProviderOperation
-                    .newDelete(uri.buildUpon()
-                            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
-                            .build())
-                    .build());
+            ops.add(
+                    ContentProviderOperation.newDelete(
+                                    uri.buildUpon()
+                                            .appendQueryParameter(
+                                                    ContactsContract.CALLER_IS_SYNCADAPTER, "true")
+                                            .build())
+                            .build());
         }
         mResolver.applyBatch(ContactsContract.AUTHORITY, ops);
     }
diff --git a/tests/src/com/android/contacts/activities/SimImportActivityTest.java b/tests/src/com/android/contacts/activities/SimImportActivityTest.java
index 4b7060fca..ba03fd1c6 100644
--- a/tests/src/com/android/contacts/activities/SimImportActivityTest.java
+++ b/tests/src/com/android/contacts/activities/SimImportActivityTest.java
@@ -26,7 +26,6 @@ import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.spy;
 
-import android.annotation.TargetApi;
 import android.app.Activity;
 import android.app.Instrumentation;
 import android.content.BroadcastReceiver;
@@ -49,7 +48,6 @@ import androidx.localbroadcastmanager.content.LocalBroadcastManager;
 import androidx.test.InstrumentationRegistry;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.LargeTest;
-import androidx.test.filters.SdkSuppress;
 import androidx.test.uiautomator.By;
 import androidx.test.uiautomator.UiDevice;
 import androidx.test.uiautomator.Until;
@@ -84,14 +82,12 @@ import java.util.concurrent.TimeUnit;
 /**
  * UI Tests for {@link SimImportActivity}
  *
- * These should probably be converted to espresso tests because espresso does a better job of
+ * <p>These should probably be converted to espresso tests because espresso does a better job of
  * waiting for the app to be idle once espresso library is added
  */
-//@Suppress
+// @Suppress
 @LargeTest
 @RunWith(AndroidJUnit4.class)
-@SdkSuppress(minSdkVersion = Build.VERSION_CODES.M)
-@TargetApi(Build.VERSION_CODES.M)
 public class SimImportActivityTest {
 
     public static final int TIMEOUT = 100000;
@@ -135,13 +131,15 @@ public class SimImportActivityTest {
 
     @Test
     public void shouldDisplaySimContacts() {
-        mDao.addSim(someSimCard(),
-                        new SimContact(1, "Sim One", "5550101"),
-                        new SimContact(2, "Sim Two", null),
-                        new SimContact(3, null, "5550103")
-                );
-        mActivity = mInstrumentation.startActivitySync(new Intent(mContext, SimImportActivity.class)
-                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
+        mDao.addSim(
+                someSimCard(),
+                new SimContact(1, "Sim One", "5550101"),
+                new SimContact(2, "Sim Two", null),
+                new SimContact(3, null, "5550103"));
+        mActivity =
+                mInstrumentation.startActivitySync(
+                        new Intent(mContext, SimImportActivity.class)
+                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
 
         mDevice.waitForIdle();
 
@@ -156,8 +154,9 @@ public class SimImportActivityTest {
     public void shouldHaveEmptyState() {
         mDao.addSim(someSimCard());
 
-        mInstrumentation.startActivitySync(new Intent(mContext, SimImportActivity.class)
-                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
+        mInstrumentation.startActivitySync(
+                new Intent(mContext, SimImportActivity.class)
+                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
 
         mDevice.waitForIdle();
 
@@ -168,9 +167,10 @@ public class SimImportActivityTest {
     public void smokeRotateInEmptyState() {
         mDao.addSim(someSimCard());
 
-        mActivity = mInstrumentation.startActivitySync(
-                new Intent(mContext, SimImportActivity.class)
-                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
+        mActivity =
+                mInstrumentation.startActivitySync(
+                        new Intent(mContext, SimImportActivity.class)
+                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
 
         assertTrue(mDevice.wait(Until.hasObject(By.textStartsWith("No contacts")), TIMEOUT));
 
@@ -183,12 +183,15 @@ public class SimImportActivityTest {
 
     @Test
     public void smokeRotateInNonEmptyState() throws Exception {
-        mDao.addSim(someSimCard(), new SimContact(1, "Name One", "5550101"),
+        mDao.addSim(
+                someSimCard(),
+                new SimContact(1, "Name One", "5550101"),
                 new SimContact(2, "Name Two", "5550102"));
 
-        mActivity = mInstrumentation.startActivitySync(
-                new Intent(mContext, SimImportActivity.class)
-                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
+        mActivity =
+                mInstrumentation.startActivitySync(
+                        new Intent(mContext, SimImportActivity.class)
+                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
 
         assertTrue(mDevice.wait(Until.hasObject(By.textStartsWith("Name One")), TIMEOUT));
 
@@ -202,34 +205,35 @@ public class SimImportActivityTest {
     /**
      * Tests a complete import flow
      *
-     * <p>Test case outline:</p>
+     * <p>Test case outline:
+     *
      * <ul>
-     * <li>Load SIM contacts
-     * <li>Change to a specific target account
-     * <li>Deselect 3 specific SIM contacts
-     * <li>Rotate the screen to landscape
-     * <li>Rotate the screen back to portrait
-     * <li>Press the import button
-     * <li>Wait for import to complete
-     * <li>Query contacts in target account and verify that they match selected contacts
-     * <li>Start import activity again
-     * <li>Switch to target account
-     * <li>Verify that previously imported contacts are disabled and not checked
+     *   <li>Load SIM contacts
+     *   <li>Change to a specific target account
+     *   <li>Deselect 3 specific SIM contacts
+     *   <li>Rotate the screen to landscape
+     *   <li>Rotate the screen back to portrait
+     *   <li>Press the import button
+     *   <li>Wait for import to complete
+     *   <li>Query contacts in target account and verify that they match selected contacts
+     *   <li>Start import activity again
+     *   <li>Switch to target account
+     *   <li>Verify that previously imported contacts are disabled and not checked
      * </ul>
      *
      * <p>This mocks out the IccProvider and stubs the canReadSimContacts method to make it work on
      * an emulator but otherwise uses real dependency.
-     * </p>
      */
     @Test
     public void selectionsAreImportedAndDisabledOnSubsequentImports() throws Exception {
-        final AccountWithDataSet targetAccount = mAccountHelper.addTestAccount(
-                mAccountHelper.generateAccountName("SimImportActivity0_targetAccount_"));
+        final AccountWithDataSet targetAccount =
+                mAccountHelper.addTestAccount(
+                        mAccountHelper.generateAccountName("SimImportActivity0_targetAccount_"));
 
         final MockContentProvider simPhonebookProvider = new MockContentProvider();
-        simPhonebookProvider.expect(MockContentProvider.Query.forAnyUri())
-                .withProjection(
-                        SimRecords.RECORD_NUMBER, SimRecords.NAME, SimRecords.PHONE_NUMBER)
+        simPhonebookProvider
+                .expect(MockContentProvider.Query.forAnyUri())
+                .withProjection(SimRecords.RECORD_NUMBER, SimRecords.NAME, SimRecords.PHONE_NUMBER)
                 .anyNumberOfTimes()
                 .returnRow(toCursorRow(new SimContact(1, "Import One", "5550101")))
                 .returnRow(toCursorRow(new SimContact(2, "Skip Two", "5550102")))
@@ -239,29 +243,37 @@ public class SimImportActivityTest {
                 .returnRow(toCursorRow(new SimContact(6, "Import Six", "5550106")));
         final MockContentResolver mockResolver = new MockContentResolver();
         mockResolver.addProvider(SimPhonebookContract.AUTHORITY, simPhonebookProvider);
-        final ContentProviderClient contactsProviderClient = mContext.getContentResolver()
-                .acquireContentProviderClient(ContactsContract.AUTHORITY);
-        mockResolver.addProvider(ContactsContract.AUTHORITY, new ForwardingContentProvider(
-                contactsProviderClient));
-
-        SimContactDao.setFactoryForTest(new Function<Context, SimContactDao>() {
-            @Override
-            public SimContactDao apply(Context input) {
-                final SimContactDaoImpl spy = spy(new SimContactDaoImpl(
-                        mContext, mockResolver,
-                        (TelephonyManager) mContext.getSystemService(Context.TELEPHONY_SERVICE)));
-                final SimCard sim = someSimCard();
-                doReturn(true).when(spy).canReadSimContacts();
-                doReturn(Collections.singletonList(sim)).when(spy).getSimCards();
-                doReturn(sim).when(spy).getSimBySubscriptionId(anyInt());
-                return spy;
-            }
-        });
-
-        mActivity = mInstrumentation.startActivitySync(
-                new Intent(mContext, SimImportActivity.class)
-                        .putExtra(SimImportActivity.EXTRA_SUBSCRIPTION_ID, 1)
-                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
+        final ContentProviderClient contactsProviderClient =
+                mContext.getContentResolver()
+                        .acquireContentProviderClient(ContactsContract.AUTHORITY);
+        mockResolver.addProvider(
+                ContactsContract.AUTHORITY, new ForwardingContentProvider(contactsProviderClient));
+
+        SimContactDao.setFactoryForTest(
+                new Function<Context, SimContactDao>() {
+                    @Override
+                    public SimContactDao apply(Context input) {
+                        final SimContactDaoImpl spy =
+                                spy(
+                                        new SimContactDaoImpl(
+                                                mContext,
+                                                mockResolver,
+                                                (TelephonyManager)
+                                                        mContext.getSystemService(
+                                                                Context.TELEPHONY_SERVICE)));
+                        final SimCard sim = someSimCard();
+                        doReturn(true).when(spy).canReadSimContacts();
+                        doReturn(Collections.singletonList(sim)).when(spy).getSimCards();
+                        doReturn(sim).when(spy).getSimBySubscriptionId(anyInt());
+                        return spy;
+                    }
+                });
+
+        mActivity =
+                mInstrumentation.startActivitySync(
+                        new Intent(mContext, SimImportActivity.class)
+                                .putExtra(SimImportActivity.EXTRA_SUBSCRIPTION_ID, 1)
+                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
 
         assertTrue(mDevice.wait(Until.hasObject(By.desc("Show more")), TIMEOUT));
 
@@ -290,40 +302,50 @@ public class SimImportActivityTest {
         // Block until import completes
         nextImportFuture.get(TIMEOUT, TimeUnit.MILLISECONDS);
 
-        final Cursor cursor = new StringableCursor(
-                mContext.getContentResolver().query(Data.CONTENT_URI, null,
-                        ContactsContract.RawContacts.ACCOUNT_NAME + "=? AND " +
-                                ContactsContract.RawContacts.ACCOUNT_TYPE+ "=?",
-                        new String[] {
-                                targetAccount.name,
-                                targetAccount.type
-                        }, null));
+        final Cursor cursor =
+                new StringableCursor(
+                        mContext.getContentResolver()
+                                .query(
+                                        Data.CONTENT_URI,
+                                        null,
+                                        ContactsContract.RawContacts.ACCOUNT_NAME
+                                                + "=? AND "
+                                                + ContactsContract.RawContacts.ACCOUNT_TYPE
+                                                + "=?",
+                                        new String[] {targetAccount.name, targetAccount.type},
+                                        null));
         // 3 contacts imported with one row for name and one for phone
         assertThat(cursor, ContactsMatchers.hasCount(3 * 2));
 
-        assertThat(cursor, hasRowMatching(allOf(
-                hasMimeType(Phone.CONTENT_ITEM_TYPE),
-                hasValueForColumn(Phone.DISPLAY_NAME, "Import One"),
-                hasValueForColumn(Phone.NUMBER, "5550101")
-        )));
-        assertThat(cursor, hasRowMatching(allOf(
-                hasMimeType(Phone.CONTENT_ITEM_TYPE),
-                hasValueForColumn(Phone.DISPLAY_NAME, "Import Three"),
-                hasValueForColumn(Phone.NUMBER, "5550103")
-        )));
-        assertThat(cursor, hasRowMatching(allOf(
-                hasMimeType(Phone.CONTENT_ITEM_TYPE),
-                hasValueForColumn(Phone.DISPLAY_NAME, "Import Six"),
-                hasValueForColumn(Phone.NUMBER, "5550106")
-        )));
+        assertThat(
+                cursor,
+                hasRowMatching(
+                        allOf(
+                                hasMimeType(Phone.CONTENT_ITEM_TYPE),
+                                hasValueForColumn(Phone.DISPLAY_NAME, "Import One"),
+                                hasValueForColumn(Phone.NUMBER, "5550101"))));
+        assertThat(
+                cursor,
+                hasRowMatching(
+                        allOf(
+                                hasMimeType(Phone.CONTENT_ITEM_TYPE),
+                                hasValueForColumn(Phone.DISPLAY_NAME, "Import Three"),
+                                hasValueForColumn(Phone.NUMBER, "5550103"))));
+        assertThat(
+                cursor,
+                hasRowMatching(
+                        allOf(
+                                hasMimeType(Phone.CONTENT_ITEM_TYPE),
+                                hasValueForColumn(Phone.DISPLAY_NAME, "Import Six"),
+                                hasValueForColumn(Phone.NUMBER, "5550106"))));
 
         cursor.close();
 
-
-        mActivity = mInstrumentation.startActivitySync(
-                new Intent(mContext, SimImportActivity.class)
-                        .putExtra(SimImportActivity.EXTRA_SUBSCRIPTION_ID, 1)
-                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
+        mActivity =
+                mInstrumentation.startActivitySync(
+                        new Intent(mContext, SimImportActivity.class)
+                                .putExtra(SimImportActivity.EXTRA_SUBSCRIPTION_ID, 1)
+                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
 
         assertTrue(mDevice.wait(Until.hasObject(By.text("Import One")), TIMEOUT));
 
@@ -342,20 +364,22 @@ public class SimImportActivityTest {
 
     private ListenableFuture<Intent> nextImportCompleteBroadcast() {
         final SettableFuture<Intent> result = SettableFuture.create();
-        final BroadcastReceiver receiver = new BroadcastReceiver() {
-            @Override
-            public void onReceive(Context context, Intent intent) {
-                result.set(intent);
-                LocalBroadcastManager.getInstance(mContext).unregisterReceiver(this);
-            }
-        };
-        LocalBroadcastManager.getInstance(mContext).registerReceiver(receiver, new IntentFilter(
-                SimImportService.BROADCAST_SIM_IMPORT_COMPLETE));
+        final BroadcastReceiver receiver =
+                new BroadcastReceiver() {
+                    @Override
+                    public void onReceive(Context context, Intent intent) {
+                        result.set(intent);
+                        LocalBroadcastManager.getInstance(mContext).unregisterReceiver(this);
+                    }
+                };
+        LocalBroadcastManager.getInstance(mContext)
+                .registerReceiver(
+                        receiver, new IntentFilter(SimImportService.BROADCAST_SIM_IMPORT_COMPLETE));
         return result;
     }
 
     private Object[] toCursorRow(SimContact contact) {
-        return new Object[]{contact.getRecordNumber(), contact.getName(), contact.getPhone()};
+        return new Object[] {contact.getRecordNumber(), contact.getName(), contact.getPhone()};
     }
 
     private SimCard someSimCard() {
diff --git a/tests/src/com/android/contacts/database/SimContactDaoTests.java b/tests/src/com/android/contacts/database/SimContactDaoTests.java
index 17906af3f..d9bed2f2d 100644
--- a/tests/src/com/android/contacts/database/SimContactDaoTests.java
+++ b/tests/src/com/android/contacts/database/SimContactDaoTests.java
@@ -50,7 +50,6 @@ import android.provider.SimPhonebookContract.SimRecords;
 import android.test.mock.MockContentResolver;
 import android.test.mock.MockContext;
 
-import androidx.annotation.RequiresApi;
 import androidx.test.InstrumentationRegistry;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.LargeTest;
@@ -92,21 +91,13 @@ public class SimContactDaoTests {
 
     // Some random area codes for generating realistic US phones when
     // generating fake data for the SIM contacts or CP2
-    private static final String[] AREA_CODES = 
-            {"360", "509", "416", "831", "212", "208"};
+    private static final String[] AREA_CODES = {"360", "509", "416", "831", "212", "208"};
     private static final Random sRandom = new Random();
 
     // Approximate maximum number of contacts that can be stored on a SIM card for testing
     // boundary cases
     public static final int MAX_SIM_CONTACTS = 600;
 
-    // On pre-M addAccountExplicitly (which we call via AccountsTestHelper) causes a
-    // SecurityException to be thrown unless we add AUTHENTICATE_ACCOUNTS permission to the app
-    // manifest. Instead of adding the extra permission just for tests we'll just only run them
-    // on M or newer
-    @SdkSuppress(minSdkVersion = VERSION_CODES.M)
-    // Lollipop MR1 is required for removeAccountExplicitly
-    @RequiresApi(api = VERSION_CODES.LOLLIPOP_MR1)
     @LargeTest
     @RunWith(AndroidJUnit4.class)
     public static class ImportIntegrationTest {
@@ -130,13 +121,16 @@ public class SimContactDaoTests {
         public void importFromSim() throws Exception {
             final SimContactDao sut = SimContactDao.create(getContext());
 
-            sut.importContacts(Arrays.asList(
-                    new SimContact(1, "Test One", "15095550101"),
-                    new SimContact(2, "Test Two", "15095550102"),
-                    new SimContact(3, "Test Three", "15095550103", new String[] {
-                            "user@example.com", "user2@example.com"
-                    })
-            ), mAccount);
+            sut.importContacts(
+                    Arrays.asList(
+                            new SimContact(1, "Test One", "15095550101"),
+                            new SimContact(2, "Test Two", "15095550102"),
+                            new SimContact(
+                                    3,
+                                    "Test Three",
+                                    "15095550103",
+                                    new String[] {"user@example.com", "user2@example.com"})),
+                    mAccount);
 
             Cursor cursor = queryContactWithName("Test One");
             assertThat(cursor, ContactsMatchers.hasCount(2));
@@ -162,9 +156,8 @@ public class SimContactDaoTests {
         public void importContactWhichOnlyHasName() throws Exception {
             final SimContactDao sut = SimContactDao.create(getContext());
 
-            sut.importContacts(Arrays.asList(
-                    new SimContact(1, "Test importJustName", null, null)
-            ), mAccount);
+            sut.importContacts(
+                    Arrays.asList(new SimContact(1, "Test importJustName", null, null)), mAccount);
 
             Cursor cursor = queryAllDataInAccount();
 
@@ -177,9 +170,8 @@ public class SimContactDaoTests {
         public void importContactWhichOnlyHasPhone() throws Exception {
             final SimContactDao sut = SimContactDao.create(getContext());
 
-            sut.importContacts(Arrays.asList(
-                    new SimContact(1, null, "15095550111", null)
-            ), mAccount);
+            sut.importContacts(
+                    Arrays.asList(new SimContact(1, null, "15095550111", null)), mAccount);
 
             Cursor cursor = queryAllDataInAccount();
 
@@ -194,12 +186,13 @@ public class SimContactDaoTests {
 
             // This probably isn't possible but we'll test it to demonstrate expected behavior and
             // just in case it does occur
-            sut.importContacts(Arrays.asList(
-                    new SimContact(1, null, null, null),
-                    new SimContact(2, null, null, null),
-                    new SimContact(3, null, null, null),
-                    new SimContact(4, "Not null", null, null)
-            ), mAccount);
+            sut.importContacts(
+                    Arrays.asList(
+                            new SimContact(1, null, null, null),
+                            new SimContact(2, null, null, null),
+                            new SimContact(3, null, null, null),
+                            new SimContact(4, "Not null", null, null)),
+                    mAccount);
 
             final Cursor contactsCursor = queryAllRawContactsInAccount();
             assertThat(contactsCursor, ContactsMatchers.hasCount(1));
@@ -214,7 +207,7 @@ public class SimContactDaoTests {
         /**
          * Tests importing a large number of contacts
          *
-         * Make sure that {@link android.os.TransactionTooLargeException} is not thrown
+         * <p>Make sure that {@link android.os.TransactionTooLargeException} is not thrown
          */
         @Test
         public void largeImport() throws Exception {
@@ -223,8 +216,12 @@ public class SimContactDaoTests {
             final List<SimContact> contacts = new ArrayList<>();
 
             for (int i = 0; i < MAX_SIM_CONTACTS; i++) {
-                contacts.add(new SimContact(i + 1, "Contact " + (i + 1), randomPhone(),
-                        new String[] { randomEmail("contact" + (i + 1) + "_")}));
+                contacts.add(
+                        new SimContact(
+                                i + 1,
+                                "Contact " + (i + 1),
+                                randomPhone(),
+                                new String[] {randomEmail("contact" + (i + 1) + "_")}));
             }
 
             sut.importContacts(contacts, mAccount);
@@ -241,47 +238,53 @@ public class SimContactDaoTests {
         }
 
         private Cursor queryAllRawContactsInAccount() {
-            return new StringableCursor(mResolver.query(ContactsContract.RawContacts.CONTENT_URI,
-                    null, ContactsContract.RawContacts.ACCOUNT_NAME + "=? AND " +
-                            ContactsContract.RawContacts.ACCOUNT_TYPE+ "=?",
-                    new String[] {
-                            mAccount.name,
-                            mAccount.type
-                    }, null));
+            return new StringableCursor(
+                    mResolver.query(
+                            ContactsContract.RawContacts.CONTENT_URI,
+                            null,
+                            ContactsContract.RawContacts.ACCOUNT_NAME
+                                    + "=? AND "
+                                    + ContactsContract.RawContacts.ACCOUNT_TYPE
+                                    + "=?",
+                            new String[] {mAccount.name, mAccount.type},
+                            null));
         }
 
         private Cursor queryAllDataInAccount() {
-            return new StringableCursor(mResolver.query(Data.CONTENT_URI, null,
-                    ContactsContract.RawContacts.ACCOUNT_NAME + "=? AND " +
-                            ContactsContract.RawContacts.ACCOUNT_TYPE+ "=?",
-                    new String[] {
-                            mAccount.name,
-                            mAccount.type
-                    }, null));
+            return new StringableCursor(
+                    mResolver.query(
+                            Data.CONTENT_URI,
+                            null,
+                            ContactsContract.RawContacts.ACCOUNT_NAME
+                                    + "=? AND "
+                                    + ContactsContract.RawContacts.ACCOUNT_TYPE
+                                    + "=?",
+                            new String[] {mAccount.name, mAccount.type},
+                            null));
         }
 
         private Cursor queryContactWithName(String name) {
-            return new StringableCursor(mResolver.query(Data.CONTENT_URI, null,
-                    ContactsContract.RawContacts.ACCOUNT_NAME + "=? AND " +
-                            ContactsContract.RawContacts.ACCOUNT_TYPE+ "=? AND " +
-                            Data.DISPLAY_NAME + "=?",
-                    new String[] {
-                            mAccount.name,
-                            mAccount.type,
-                            name
-                    }, null));
+            return new StringableCursor(
+                    mResolver.query(
+                            Data.CONTENT_URI,
+                            null,
+                            ContactsContract.RawContacts.ACCOUNT_NAME
+                                    + "=? AND "
+                                    + ContactsContract.RawContacts.ACCOUNT_TYPE
+                                    + "=? AND "
+                                    + Data.DISPLAY_NAME
+                                    + "=?",
+                            new String[] {mAccount.name, mAccount.type, name},
+                            null));
         }
     }
 
     /**
      * Tests for {@link SimContactDao#findAccountsOfExistingSimContacts(List)}
      *
-     * These are integration tests that query CP2 so that the SQL will be validated in addition
+     * <p>These are integration tests that query CP2 so that the SQL will be validated in addition
      * to the detection algorithm
      */
-    @SdkSuppress(minSdkVersion = VERSION_CODES.M)
-    // Lollipop MR1 is required for removeAccountExplicitly
-    @RequiresApi(api = VERSION_CODES.LOLLIPOP_MR1)
     @LargeTest
     @RunWith(AndroidJUnit4.class)
     public static class FindAccountsIntegrationTests {
@@ -297,8 +300,8 @@ public class SimContactDaoTests {
 
         @BeforeClass
         public static void setUpClass() throws Exception {
-            final AccountsTestHelper helper = new AccountsTestHelper(
-                    InstrumentationRegistry.getContext());
+            final AccountsTestHelper helper =
+                    new AccountsTestHelper(InstrumentationRegistry.getContext());
             sSeedAccount = helper.addTestAccount(helper.generateAccountName("seedAccount"));
 
             seedCp2();
@@ -306,8 +309,8 @@ public class SimContactDaoTests {
 
         @AfterClass
         public static void tearDownClass() {
-            final AccountsTestHelper helper = new AccountsTestHelper(
-                    InstrumentationRegistry.getContext());
+            final AccountsTestHelper helper =
+                    new AccountsTestHelper(InstrumentationRegistry.getContext());
             helper.removeTestAccount(sSeedAccount);
             sSeedAccount = null;
         }
@@ -335,14 +338,15 @@ public class SimContactDaoTests {
 
             final SimContactDao sut = createDao();
 
-            final List<SimContact> contacts = Arrays.asList(
-                    new SimContact(1, "Name 1 " + mNameSuffix, "5550101"),
-                    new SimContact(2, "Name 2 " + mNameSuffix, "5550102"),
-                    new SimContact(3, "Name 3 " + mNameSuffix, "5550103"),
-                    new SimContact(4, "Name 4 " + mNameSuffix, "5550104"));
+            final List<SimContact> contacts =
+                    Arrays.asList(
+                            new SimContact(1, "Name 1 " + mNameSuffix, "5550101"),
+                            new SimContact(2, "Name 2 " + mNameSuffix, "5550102"),
+                            new SimContact(3, "Name 3 " + mNameSuffix, "5550103"),
+                            new SimContact(4, "Name 4 " + mNameSuffix, "5550104"));
 
-            final Map<AccountWithDataSet, Set<SimContact>> existing = sut
-                    .findAccountsOfExistingSimContacts(contacts);
+            final Map<AccountWithDataSet, Set<SimContact>> existing =
+                    sut.findAccountsOfExistingSimContacts(contacts);
 
             assertTrue(existing.isEmpty());
         }
@@ -352,32 +356,29 @@ public class SimContactDaoTests {
                 throws Exception {
             final SimContactDao sut = createDao();
 
-            final AccountWithDataSet account = mAccountHelper.addTestAccount(
-                    mAccountHelper.generateAccountName("primary_"));
+            final AccountWithDataSet account =
+                    mAccountHelper.addTestAccount(mAccountHelper.generateAccountName("primary_"));
             mAccounts.add(account);
 
-            final SimContact existing1 =
-                    new SimContact(2, "Exists 2 " + mNameSuffix, "5550102");
-            final SimContact existing2 =
-                    new SimContact(4, "Exists 4 " + mNameSuffix, "5550104");
-
-            final List<SimContact> contacts = Arrays.asList(
-                    new SimContact(1, "Missing 1 " + mNameSuffix, "5550101"),
-                    new SimContact(existing1),
-                    new SimContact(3, "Missing 3 " + mNameSuffix, "5550103"),
-                    new SimContact(existing2));
+            final SimContact existing1 = new SimContact(2, "Exists 2 " + mNameSuffix, "5550102");
+            final SimContact existing2 = new SimContact(4, "Exists 4 " + mNameSuffix, "5550104");
 
-            sut.importContacts(Arrays.asList(
-                    new SimContact(existing1),
-                    new SimContact(existing2)
-            ), account);
+            final List<SimContact> contacts =
+                    Arrays.asList(
+                            new SimContact(1, "Missing 1 " + mNameSuffix, "5550101"),
+                            new SimContact(existing1),
+                            new SimContact(3, "Missing 3 " + mNameSuffix, "5550103"),
+                            new SimContact(existing2));
 
+            sut.importContacts(
+                    Arrays.asList(new SimContact(existing1), new SimContact(existing2)), account);
 
-            final Map<AccountWithDataSet, Set<SimContact>> existing = sut
-                    .findAccountsOfExistingSimContacts(contacts);
+            final Map<AccountWithDataSet, Set<SimContact>> existing =
+                    sut.findAccountsOfExistingSimContacts(contacts);
 
             assertThat(existing.size(), equalTo(1));
-            assertThat(existing.get(account),
+            assertThat(
+                    existing.get(account),
                     Matchers.<Set<SimContact>>equalTo(ImmutableSet.of(existing1, existing2)));
         }
 
@@ -385,11 +386,11 @@ public class SimContactDaoTests {
         public void hasMultipleAccountsWhenMultipleMatchingContactsExist() throws Exception {
             final SimContactDao sut = createDao();
 
-            final AccountWithDataSet account1 = mAccountHelper.addTestAccount(
-                    mAccountHelper.generateAccountName("account1_"));
+            final AccountWithDataSet account1 =
+                    mAccountHelper.addTestAccount(mAccountHelper.generateAccountName("account1_"));
             mAccounts.add(account1);
-            final AccountWithDataSet account2 = mAccountHelper.addTestAccount(
-                    mAccountHelper.generateAccountName("account2_"));
+            final AccountWithDataSet account2 =
+                    mAccountHelper.addTestAccount(mAccountHelper.generateAccountName("account2_"));
             mAccounts.add(account2);
 
             final SimContact existsInBoth =
@@ -399,64 +400,64 @@ public class SimContactDaoTests {
             final SimContact existsInAccount2 =
                     new SimContact(5, "Exists 2 " + mNameSuffix, "5550105");
 
-            final List<SimContact> contacts = Arrays.asList(
-                    new SimContact(1, "Missing 1 " + mNameSuffix, "5550101"),
-                    new SimContact(existsInBoth),
-                    new SimContact(3, "Missing 3 " + mNameSuffix, "5550103"),
-                    new SimContact(existsInAccount1),
-                    new SimContact(existsInAccount2));
-
-            sut.importContacts(Arrays.asList(
-                    new SimContact(existsInBoth),
-                    new SimContact(existsInAccount1)
-            ), account1);
+            final List<SimContact> contacts =
+                    Arrays.asList(
+                            new SimContact(1, "Missing 1 " + mNameSuffix, "5550101"),
+                            new SimContact(existsInBoth),
+                            new SimContact(3, "Missing 3 " + mNameSuffix, "5550103"),
+                            new SimContact(existsInAccount1),
+                            new SimContact(existsInAccount2));
 
-            sut.importContacts(Arrays.asList(
-                    new SimContact(existsInBoth),
-                    new SimContact(existsInAccount2)
-            ), account2);
+            sut.importContacts(
+                    Arrays.asList(new SimContact(existsInBoth), new SimContact(existsInAccount1)),
+                    account1);
 
+            sut.importContacts(
+                    Arrays.asList(new SimContact(existsInBoth), new SimContact(existsInAccount2)),
+                    account2);
 
-            final Map<AccountWithDataSet, Set<SimContact>> existing = sut
-                    .findAccountsOfExistingSimContacts(contacts);
+            final Map<AccountWithDataSet, Set<SimContact>> existing =
+                    sut.findAccountsOfExistingSimContacts(contacts);
 
             assertThat(existing.size(), equalTo(2));
-            assertThat(existing, Matchers.<Map<AccountWithDataSet, Set<SimContact>>>equalTo(
-                    ImmutableMap.<AccountWithDataSet, Set<SimContact>>of(
-                            account1, ImmutableSet.of(existsInBoth, existsInAccount1),
-                            account2, ImmutableSet.of(existsInBoth, existsInAccount2))));
+            assertThat(
+                    existing,
+                    Matchers.<Map<AccountWithDataSet, Set<SimContact>>>equalTo(
+                            ImmutableMap.<AccountWithDataSet, Set<SimContact>>of(
+                                    account1, ImmutableSet.of(existsInBoth, existsInAccount1),
+                                    account2, ImmutableSet.of(existsInBoth, existsInAccount2))));
         }
 
         @Test
         public void matchesByNameIfSimContactHasNoPhone() throws Exception {
             final SimContactDao sut = createDao();
 
-            final AccountWithDataSet account = mAccountHelper.addTestAccount(
-                    mAccountHelper.generateAccountName("account_"));
+            final AccountWithDataSet account =
+                    mAccountHelper.addTestAccount(mAccountHelper.generateAccountName("account_"));
             mAccounts.add(account);
 
             final SimContact noPhone = new SimContact(1, "Nophone " + mNameSuffix, null);
-            final SimContact otherExisting = new SimContact(
-                    5, "Exists 1 " + mNameSuffix, "5550105");
+            final SimContact otherExisting =
+                    new SimContact(5, "Exists 1 " + mNameSuffix, "5550105");
 
-            final List<SimContact> contacts = Arrays.asList(
-                    new SimContact(noPhone),
-                    new SimContact(2, "Name 2 " + mNameSuffix, "5550102"),
-                    new SimContact(3, "Name 3 " + mNameSuffix, "5550103"),
-                    new SimContact(4, "Name 4 " + mNameSuffix, "5550104"),
-                    new SimContact(otherExisting));
+            final List<SimContact> contacts =
+                    Arrays.asList(
+                            new SimContact(noPhone),
+                            new SimContact(2, "Name 2 " + mNameSuffix, "5550102"),
+                            new SimContact(3, "Name 3 " + mNameSuffix, "5550103"),
+                            new SimContact(4, "Name 4 " + mNameSuffix, "5550104"),
+                            new SimContact(otherExisting));
 
-            sut.importContacts(Arrays.asList(
-                    new SimContact(noPhone),
-                    new SimContact(otherExisting)
-            ), account);
+            sut.importContacts(
+                    Arrays.asList(new SimContact(noPhone), new SimContact(otherExisting)), account);
 
-            final Map<AccountWithDataSet, Set<SimContact>> existing = sut
-                    .findAccountsOfExistingSimContacts(contacts);
+            final Map<AccountWithDataSet, Set<SimContact>> existing =
+                    sut.findAccountsOfExistingSimContacts(contacts);
 
             assertThat(existing.size(), equalTo(1));
-            assertThat(existing.get(account), Matchers.<Set<SimContact>>equalTo(
-                    ImmutableSet.of(noPhone, otherExisting)));
+            assertThat(
+                    existing.get(account),
+                    Matchers.<Set<SimContact>>equalTo(ImmutableSet.of(noPhone, otherExisting)));
         }
 
         @Test
@@ -465,8 +466,9 @@ public class SimContactDaoTests {
 
             final List<SimContact> contacts = new ArrayList<>();
             for (int i = 0; i < MAX_SIM_CONTACTS; i++) {
-                contacts.add(new SimContact(
-                        i + 1, "Contact " + (i + 1) + " " + mNameSuffix, randomPhone()));
+                contacts.add(
+                        new SimContact(
+                                i + 1, "Contact " + (i + 1) + " " + mNameSuffix, randomPhone()));
             }
             // The work has to be split into batches to avoid hitting SQL query parameter limits
             // so test contacts that will be at boundary points
@@ -476,22 +478,24 @@ public class SimContactDaoTests {
             final SimContact imported4 = contacts.get(101);
             final SimContact imported5 = contacts.get(MAX_SIM_CONTACTS - 1);
 
-            final AccountWithDataSet account = mAccountHelper.addTestAccount(
-                    mAccountHelper.generateAccountName("account_"));
+            final AccountWithDataSet account =
+                    mAccountHelper.addTestAccount(mAccountHelper.generateAccountName("account_"));
             mAccounts.add(account);
 
-            sut.importContacts(Arrays.asList(imported1, imported2, imported3, imported4, imported5),
-                    account);
+            sut.importContacts(
+                    Arrays.asList(imported1, imported2, imported3, imported4, imported5), account);
 
             mAccounts.add(account);
 
-            final Map<AccountWithDataSet, Set<SimContact>> existing = sut
-                    .findAccountsOfExistingSimContacts(contacts);
+            final Map<AccountWithDataSet, Set<SimContact>> existing =
+                    sut.findAccountsOfExistingSimContacts(contacts);
 
             assertThat(existing.size(), equalTo(1));
-            assertThat(existing.get(account), Matchers.<Set<SimContact>>equalTo(
-                    ImmutableSet.of(imported1, imported2, imported3, imported4, imported5)));
-
+            assertThat(
+                    existing.get(account),
+                    Matchers.<Set<SimContact>>equalTo(
+                            ImmutableSet.of(
+                                    imported1, imported2, imported3, imported4, imported5)));
         }
 
         private SimContactDao createDao() {
@@ -518,11 +522,12 @@ public class SimContactDaoTests {
             appendCreateContact("Alex Seed", sSeedAccount, ops);
 
             InstrumentationRegistry.getTargetContext()
-                    .getContentResolver().applyBatch(ContactsContract.AUTHORITY, ops);
+                    .getContentResolver()
+                    .applyBatch(ContactsContract.AUTHORITY, ops);
         }
 
-        private static void appendCreateContact(String name, AccountWithDataSet account,
-                ArrayList<ContentProviderOperation> ops) {
+        private static void appendCreateContact(
+                String name, AccountWithDataSet account, ArrayList<ContentProviderOperation> ops) {
             final int emailCount = sRandom.nextInt(10);
             final int phoneCount = sRandom.nextInt(5);
 
@@ -537,9 +542,12 @@ public class SimContactDaoTests {
             appendCreateContact(name, phones, emails, account, ops);
         }
 
-
-        private static void appendCreateContact(String name, List<String> phoneNumbers,
-                List<String> emails, AccountWithDataSet account, List<ContentProviderOperation> ops) {
+        private static void appendCreateContact(
+                String name,
+                List<String> phoneNumbers,
+                List<String> emails,
+                AccountWithDataSet account,
+                List<ContentProviderOperation> ops) {
             int index = ops.size();
 
             ops.add(account.newRawContactOperation());
@@ -552,29 +560,31 @@ public class SimContactDaoTests {
             }
         }
 
-        private static ContentProviderOperation insertIntoData(String value, String mimeType,
-                int idBackReference) {
+        private static ContentProviderOperation insertIntoData(
+                String value, String mimeType, int idBackReference) {
             return ContentProviderOperation.newInsert(Data.CONTENT_URI)
                     .withValue(Data.DATA1, value)
                     .withValue(Data.MIMETYPE, mimeType)
-                    .withValueBackReference(Data.RAW_CONTACT_ID, idBackReference).build();
+                    .withValueBackReference(Data.RAW_CONTACT_ID, idBackReference)
+                    .build();
         }
 
-        private static ContentProviderOperation insertIntoData(String value, String mimeType,
-                int type, int idBackReference) {
+        private static ContentProviderOperation insertIntoData(
+                String value, String mimeType, int type, int idBackReference) {
             return ContentProviderOperation.newInsert(Data.CONTENT_URI)
                     .withValue(Data.DATA1, value)
                     .withValue(ContactsContract.Data.DATA2, type)
                     .withValue(Data.MIMETYPE, mimeType)
-                    .withValueBackReference(Data.RAW_CONTACT_ID, idBackReference).build();
+                    .withValueBackReference(Data.RAW_CONTACT_ID, idBackReference)
+                    .build();
         }
     }
 
     /**
      * Tests for {@link SimContactDao#loadContactsForSim(SimCard)}
      *
-     * These are unit tests that verify that {@link SimContact}s are created correctly from
-     * the cursors that are returned by queries to the IccProvider
+     * <p>These are unit tests that verify that {@link SimContact}s are created correctly from the
+     * cursors that are returned by queries to the IccProvider
      */
     @SmallTest
     @RunWith(AndroidJUnit4.class)
@@ -592,10 +602,10 @@ public class SimContactDaoTests {
             when(mContext.getContentResolver()).thenReturn(mockResolver);
         }
 
-
         @Test
         public void createsContactsFromCursor() {
-            mMockSimPhonebookProvider.expect(MockContentProvider.Query.forAnyUri())
+            mMockSimPhonebookProvider
+                    .expect(MockContentProvider.Query.forAnyUri())
                     .withDefaultProjection(
                             SimRecords.RECORD_NUMBER, SimRecords.NAME, SimRecords.PHONE_NUMBER)
                     .withAnyProjection()
@@ -607,21 +617,23 @@ public class SimContactDaoTests {
                     .returnRow(4, null, "5550104");
 
             final SimContactDao sut = SimContactDao.create(mContext);
-            final List<SimContact> contacts = sut
-                    .loadContactsForSim(new SimCard("123", 1, "carrier", "sim", null, "us"));
+            final List<SimContact> contacts =
+                    sut.loadContactsForSim(new SimCard("123", 1, "carrier", "sim", null, "us"));
 
-            assertThat(contacts, equalTo(
-                    Arrays.asList(
-                            new SimContact(1, "Name One", "5550101", null),
-                            new SimContact(2, "Name Two", "5550102", null),
-                            new SimContact(3, "Name Three", null, null),
-                            new SimContact(4, null, "5550104", null)
-                    )));
+            assertThat(
+                    contacts,
+                    equalTo(
+                            Arrays.asList(
+                                    new SimContact(1, "Name One", "5550101", null),
+                                    new SimContact(2, "Name Two", "5550102", null),
+                                    new SimContact(3, "Name Three", null, null),
+                                    new SimContact(4, null, "5550104", null))));
         }
 
         @Test
         public void excludesEmptyContactsFromResult() {
-            mMockSimPhonebookProvider.expect(MockContentProvider.Query.forAnyUri())
+            mMockSimPhonebookProvider
+                    .expect(MockContentProvider.Query.forAnyUri())
                     .withDefaultProjection(
                             SimRecords.RECORD_NUMBER, SimRecords.NAME, SimRecords.PHONE_NUMBER)
                     .withAnyProjection()
@@ -635,21 +647,24 @@ public class SimContactDaoTests {
                     .returnRow(6, null, "5550102");
 
             final SimContactDao sut = SimContactDao.create(mContext);
-            final List<SimContact> contacts = sut
-                    .loadContactsForSim(new SimCard("123", 1, "carrier", "sim", null, "us"));
+            final List<SimContact> contacts =
+                    sut.loadContactsForSim(new SimCard("123", 1, "carrier", "sim", null, "us"));
 
-            assertThat(contacts, equalTo(
-                    Arrays.asList(
-                            new SimContact(1, "Non Empty1", "5550101", null),
-                            new SimContact(3, "Non Empty2", null, null),
-                            new SimContact(6, null, "5550102", null)
-                    )));
+            assertThat(
+                    contacts,
+                    equalTo(
+                            Arrays.asList(
+                                    new SimContact(1, "Non Empty1", "5550101", null),
+                                    new SimContact(3, "Non Empty2", null, null),
+                                    new SimContact(6, null, "5550102", null))));
         }
 
         @Test
         public void usesSimCardSubscriptionIdIfAvailable() {
-            mMockSimPhonebookProvider.expectQuery(SimRecords.getContentUri(2,
-                    SimPhonebookContract.ElementaryFiles.EF_ADN))
+            mMockSimPhonebookProvider
+                    .expectQuery(
+                            SimRecords.getContentUri(
+                                    2, SimPhonebookContract.ElementaryFiles.EF_ADN))
                     .withDefaultProjection(
                             SimRecords.RECORD_NUMBER, SimRecords.NAME, SimRecords.PHONE_NUMBER)
                     .withAnyProjection()
@@ -664,7 +679,8 @@ public class SimContactDaoTests {
 
         @Test
         public void returnsEmptyListForEmptyCursor() {
-            mMockSimPhonebookProvider.expect(MockContentProvider.Query.forAnyUri())
+            mMockSimPhonebookProvider
+                    .expect(MockContentProvider.Query.forAnyUri())
                     .withDefaultProjection(
                             SimRecords.RECORD_NUMBER, SimRecords.NAME, SimRecords.PHONE_NUMBER)
                     .withAnyProjection()
@@ -673,8 +689,8 @@ public class SimContactDaoTests {
                     .returnEmptyCursor();
 
             final SimContactDao sut = SimContactDao.create(mContext);
-            List<SimContact> result = sut
-                    .loadContactsForSim(new SimCard("123", 1, "carrier", "sim", null, "us"));
+            List<SimContact> result =
+                    sut.loadContactsForSim(new SimCard("123", 1, "carrier", "sim", null, "us"));
             assertTrue(result.isEmpty());
         }
 
@@ -683,19 +699,28 @@ public class SimContactDaoTests {
             mContext = mock(MockContext.class);
             final MockContentResolver mockResolver = new MockContentResolver();
             final ContentProvider mockProvider = mock(android.test.mock.MockContentProvider.class);
-            when(mockProvider.query(any(Uri.class), any(String[].class), anyString(),
-                    any(String[].class), anyString()))
+            when(mockProvider.query(
+                            any(Uri.class),
+                            any(String[].class),
+                            anyString(),
+                            any(String[].class),
+                            anyString()))
                     .thenReturn(null);
-            when(mockProvider.query(any(Uri.class), any(String[].class), anyString(),
-                    any(String[].class), anyString(), any(CancellationSignal.class)))
+            when(mockProvider.query(
+                            any(Uri.class),
+                            any(String[].class),
+                            anyString(),
+                            any(String[].class),
+                            anyString(),
+                            any(CancellationSignal.class)))
                     .thenReturn(null);
 
             mockResolver.addProvider("icc", mockProvider);
             when(mContext.getContentResolver()).thenReturn(mockResolver);
 
             final SimContactDao sut = SimContactDao.create(mContext);
-            final List<SimContact> result = sut
-                    .loadContactsForSim(new SimCard("123", 1, "carrier", "sim", null, "us"));
+            final List<SimContact> result =
+                    sut.loadContactsForSim(new SimCard("123", 1, "carrier", "sim", null, "us"));
             assertTrue(result.isEmpty());
         }
     }
@@ -736,24 +761,26 @@ public class SimContactDaoTests {
 
             assertThat(contacts.get(0), isSimContactWithNameAndPhone("Test Simone", "15095550101"));
             assertThat(contacts.get(1), isSimContactWithNameAndPhone("Test Simtwo", "15095550102"));
-            assertThat(contacts.get(2),
-                    isSimContactWithNameAndPhone("Test Simthree", "15095550103"));
+            assertThat(
+                    contacts.get(2), isSimContactWithNameAndPhone("Test Simthree", "15095550103"));
         }
     }
 
     private static String randomPhone() {
-        return String.format(Locale.US, "1%s55501%02d",
+        return String.format(
+                Locale.US,
+                "1%s55501%02d",
                 AREA_CODES[sRandom.nextInt(AREA_CODES.length)],
                 sRandom.nextInt(100));
     }
 
     private static String randomEmail(String name) {
-        return String.format("%s%d@example.com", name.replace(" ", ".").toLowerCase(Locale.US),
-                1000 + sRandom.nextInt(1000));
+        return String.format(
+                "%s%d@example.com",
+                name.replace(" ", ".").toLowerCase(Locale.US), 1000 + sRandom.nextInt(1000));
     }
 
-
     static Context getContext() {
         return InstrumentationRegistry.getTargetContext();
-   }
+    }
 }
diff --git a/tests/src/com/android/contacts/editor/ContactEditorUtilsTest.java b/tests/src/com/android/contacts/editor/ContactEditorUtilsTest.java
index 06d64a850..898fc7b94 100644
--- a/tests/src/com/android/contacts/editor/ContactEditorUtilsTest.java
+++ b/tests/src/com/android/contacts/editor/ContactEditorUtilsTest.java
@@ -16,9 +16,7 @@
 
 package com.android.contacts.editor;
 
-import static junit.framework.Assert.assertEquals;
 import static junit.framework.Assert.assertFalse;
-import static junit.framework.Assert.assertNull;
 
 import static org.junit.Assert.assertTrue;
 
@@ -40,13 +38,12 @@ import java.util.List;
 /**
  * Test case for {@link ContactEditorUtils}.
  *
- * adb shell am instrument -w -e class com.android.contacts.editor.ContactEditorUtilsTest \
-       com.android.contacts.tests/android.test.InstrumentationTestRunner
-
+ * <p>adb shell am instrument -w -e class com.android.contacts.editor.ContactEditorUtilsTest \
+ * com.android.contacts.tests/android.test.InstrumentationTestRunner
+ *
  * <p>It may make sense to just delete or move these tests since the code under test just forwards
  * calls to {@link com.android.contacts.preference.ContactsPreferences} and that logic is already
  * covered by {@link com.android.contacts.preference.ContactsPreferencesTest}
- * </p>
  */
 @SmallTest
 @RunWith(AndroidJUnit4.class)
@@ -61,8 +58,8 @@ public class ContactEditorUtilsTest {
     private static final AccountWithDataSet ACCOUNT_1_B = new AccountWithDataSet("b", TYPE1, null);
 
     private static final AccountWithDataSet ACCOUNT_2_A = new AccountWithDataSet("a", TYPE2, null);
-    private static final AccountWithDataSet ACCOUNT_2EX_A = new AccountWithDataSet(
-            "a", TYPE2, TYPE2_EXT);
+    private static final AccountWithDataSet ACCOUNT_2EX_A =
+            new AccountWithDataSet("a", TYPE2, TYPE2_EXT);
 
     @Before
     public void setUp() throws Exception {
@@ -73,24 +70,9 @@ public class ContactEditorUtilsTest {
     }
 
     /**
-     * Test for
-     * - {@link ContactEditorUtils#saveDefaultAccount}
-     * - {@link ContactEditorUtils#getOnlyOrDefaultAccount}
-     */
-    @Test
-    public void testSaveDefaultAccount() {
-        mTarget.saveDefaultAccount(null);
-        assertNull(mTarget.getOnlyOrDefaultAccount(Collections.<AccountWithDataSet>emptyList()));
-
-        mTarget.saveDefaultAccount(ACCOUNT_1_A);
-        assertEquals(ACCOUNT_1_A, mTarget.getOnlyOrDefaultAccount(Collections.
-                <AccountWithDataSet>emptyList()));
-    }
-
-    /**
-     * Tests for
-     * {@link ContactEditorUtils#shouldShowAccountChangedNotification(List<AccountWithDataSet>)},
-     * starting with 0 accounts.
+     * Tests for {@link
+     * ContactEditorUtils#shouldShowAccountChangedNotification(List<AccountWithDataSet>)}, starting
+     * with 0 accounts.
      */
     @Test
     public void testShouldShowAccountChangedNotification_0Accounts() {
@@ -103,7 +85,7 @@ public class ContactEditorUtilsTest {
         // Now we open the contact editor with the new account.
 
         // When closing the editor, we save the default account.
-        mTarget.saveDefaultAccount(ACCOUNT_1_A);
+        setDefaultAccountForTest(ACCOUNT_1_A);
 
         // Next time the user creates a contact, we don't show the notification.
         assertFalse(mTarget.shouldShowAccountChangedNotification(currentAccounts));
@@ -115,7 +97,7 @@ public class ContactEditorUtilsTest {
         assertFalse(mTarget.shouldShowAccountChangedNotification(currentAccounts));
 
         // User saved a new contact.  We update the account list and the default account.
-        mTarget.saveDefaultAccount(ACCOUNT_1_B);
+        setDefaultAccountForTest(ACCOUNT_1_B);
 
         // User created another contact.  Now we don't show the notification.
         assertFalse(mTarget.shouldShowAccountChangedNotification(currentAccounts));
@@ -130,7 +112,7 @@ public class ContactEditorUtilsTest {
         assertFalse(mTarget.shouldShowAccountChangedNotification(currentAccounts));
 
         // User saves a new contact, with a different default account.
-        mTarget.saveDefaultAccount(ACCOUNT_2_A);
+        setDefaultAccountForTest(ACCOUNT_2_A);
 
         // Next time user creates a contact, no notification.
         assertFalse(mTarget.shouldShowAccountChangedNotification(currentAccounts));
@@ -155,63 +137,69 @@ public class ContactEditorUtilsTest {
     }
 
     /**
-     * Tests for
-     * {@link ContactEditorUtils#shouldShowAccountChangedNotification(List<AccountWithDataSet>)},
-     * starting with 1 accounts.
+     * Tests for {@link
+     * ContactEditorUtils#shouldShowAccountChangedNotification(List<AccountWithDataSet>)}, starting
+     * with 1 accounts.
      */
     @Test
     public void testShouldShowAccountChangedNotification_1Account() {
         // Always returns false when 1 writable account.
-        assertFalse(mTarget.shouldShowAccountChangedNotification(
-                Collections.singletonList(ACCOUNT_1_A)));
+        assertFalse(
+                mTarget.shouldShowAccountChangedNotification(
+                        Collections.singletonList(ACCOUNT_1_A)));
 
         // User saves a new contact.
-        mTarget.saveDefaultAccount(ACCOUNT_1_A);
+        setDefaultAccountForTest(ACCOUNT_1_A);
 
         // Next time, no notification.
-        assertFalse(mTarget.shouldShowAccountChangedNotification(
-                Collections.singletonList(ACCOUNT_1_A)));
+        assertFalse(
+                mTarget.shouldShowAccountChangedNotification(
+                        Collections.singletonList(ACCOUNT_1_A)));
 
         // The rest is the same...
     }
 
     /**
-     * Tests for
-     * {@link ContactEditorUtils#shouldShowAccountChangedNotification(List<AccountWithDataSet>)},
-     * starting with 0 accounts, and the user selected "local only".
+     * Tests for {@link
+     * ContactEditorUtils#shouldShowAccountChangedNotification(List<AccountWithDataSet>)}, starting
+     * with 0 accounts, and the user selected "local only".
      */
     @Test
     public void testShouldShowAccountChangedNotification_0Account_localOnly() {
         // First launch -- always true.
-        assertTrue(mTarget.shouldShowAccountChangedNotification(Collections.
-                <AccountWithDataSet>emptyList()));
+        assertTrue(
+                mTarget.shouldShowAccountChangedNotification(
+                        Collections.<AccountWithDataSet>emptyList()));
 
         // We show the notification here, and user clicked "keep local" and saved an contact.
-        mTarget.saveDefaultAccount(AccountWithDataSet.getNullAccount());
+        setDefaultAccountForTest(AccountWithDataSet.getNullAccount());
 
         // Now there are no accounts, and default account is null.
 
         // The user created another contact, but this we shouldn't show the notification.
-        assertFalse(mTarget.shouldShowAccountChangedNotification(Collections.
-                <AccountWithDataSet>emptyList()));
+        assertFalse(
+                mTarget.shouldShowAccountChangedNotification(
+                        Collections.<AccountWithDataSet>emptyList()));
     }
 
     @Test
     public void testShouldShowAccountChangedNotification_initial_check() {
         // Prepare 1 account and save it as the default.
-        mTarget.saveDefaultAccount(ACCOUNT_1_A);
+        setDefaultAccountForTest(ACCOUNT_1_A);
 
         // Right after a save, the dialog shouldn't show up.
-        assertFalse(mTarget.shouldShowAccountChangedNotification(
-                Collections.singletonList(ACCOUNT_1_A)));
+        assertFalse(
+                mTarget.shouldShowAccountChangedNotification(
+                        Collections.singletonList(ACCOUNT_1_A)));
 
         // Remove the default account to emulate broken preferences.
         mTarget.removeDefaultAccountForTest();
 
         // The dialog shouldn't show up.
         // The logic is, if there's a writable account, we'll pick it as default
-        assertFalse(mTarget.shouldShowAccountChangedNotification(
-                Collections.singletonList(ACCOUNT_1_A)));
+        assertFalse(
+                mTarget.shouldShowAccountChangedNotification(
+                        Collections.singletonList(ACCOUNT_1_A)));
     }
 
     @Test
@@ -223,12 +211,16 @@ public class ContactEditorUtilsTest {
         assertTrue(mTarget.shouldShowAccountChangedNotification(currentAccounts));
 
         // User chooses to keep the "device" account as the default
-        mTarget.saveDefaultAccount(nullAccount);
+        setDefaultAccountForTest(nullAccount);
 
         // Right after a save, the dialog shouldn't show up.
         assertFalse(mTarget.shouldShowAccountChangedNotification(currentAccounts));
     }
 
+    private void setDefaultAccountForTest(AccountWithDataSet account) {
+        mTarget.setDefaultAccountForTest(account);
+    }
+
     private static class MockAccountType extends AccountType {
         private boolean mAreContactsWritable;
 
diff --git a/tests/src/com/android/contacts/preference/ContactsPreferencesTest.java b/tests/src/com/android/contacts/preference/ContactsPreferencesTest.java
index d2fd13e61..858a6bca7 100644
--- a/tests/src/com/android/contacts/preference/ContactsPreferencesTest.java
+++ b/tests/src/com/android/contacts/preference/ContactsPreferencesTest.java
@@ -16,15 +16,18 @@
 
 package com.android.contacts.preference;
 
+import android.accounts.Account;
 import android.content.Context;
 import android.content.SharedPreferences;
 import android.content.res.Resources;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
 import android.test.InstrumentationTestCase;
 
 import androidx.test.InstrumentationRegistry;
 import androidx.test.filters.SmallTest;
 
 import com.android.contacts.model.account.AccountWithDataSet;
+import com.android.contacts.preference.ContactsPreferences.DefaultAccountReader;
 
 import junit.framework.Assert;
 
@@ -42,13 +45,15 @@ public class ContactsPreferencesTest extends InstrumentationTestCase {
     @Mock private Context mContext;
     @Mock private Resources mResources;
     @Mock private SharedPreferences mSharedPreferences;
+    @Mock private DefaultAccountReader mDefaultAccountReader;
 
     private ContactsPreferences mContactsPreferences;
 
     @Override
     public void setUp() throws Exception {
         super.setUp();
-        System.setProperty("dexmaker.dexcache",
+        System.setProperty(
+                "dexmaker.dexcache",
                 getInstrumentation().getTargetContext().getCacheDir().getPath());
         MockitoAnnotations.initMocks(this);
 
@@ -65,176 +70,223 @@ public class ContactsPreferencesTest extends InstrumentationTestCase {
         Mockito.when(mSharedPreferences.contains(ContactsPreferences.PHONETIC_NAME_DISPLAY_KEY))
                 .thenReturn(true);
 
-        InstrumentationRegistry.getInstrumentation().runOnMainSync(new Runnable() {
-            @Override
-            public void run() {
-                mContactsPreferences = new ContactsPreferences(mContext);
-            }
-        });
+        InstrumentationRegistry.getInstrumentation()
+                .runOnMainSync(
+                        new Runnable() {
+                            @Override
+                            public void run() {
+                                mContactsPreferences = new ContactsPreferences(mContext);
+                            }
+                        });
     }
 
     public void testGetSortOrderDefault() {
-        Mockito.when(mResources.getBoolean(Mockito.anyInt())).thenReturn(
-                false, // R.bool.config_sort_order_user_changeable
-                true // R.bool.config_default_sort_order_primary
-        );
-        Assert.assertEquals(ContactsPreferences.SORT_ORDER_PRIMARY,
-                mContactsPreferences.getSortOrder());
+        Mockito.when(mResources.getBoolean(Mockito.anyInt()))
+                .thenReturn(
+                        false, // R.bool.config_sort_order_user_changeable
+                        true // R.bool.config_default_sort_order_primary
+                        );
+        Assert.assertEquals(
+                ContactsPreferences.SORT_ORDER_PRIMARY, mContactsPreferences.getSortOrder());
     }
 
     public void testGetSortOrder() {
-        Mockito.when(mResources.getBoolean(Mockito.anyInt())).thenReturn(
-                true // R.bool.config_sort_order_user_changeable
-        );
-        Mockito.when(mSharedPreferences.getInt(Mockito.eq(ContactsPreferences.SORT_ORDER_KEY),
-                Mockito.anyInt())).thenReturn(ContactsPreferences.SORT_ORDER_PRIMARY);
-        Assert.assertEquals(ContactsPreferences.SORT_ORDER_PRIMARY,
-                mContactsPreferences.getSortOrder());
+        Mockito.when(mResources.getBoolean(Mockito.anyInt()))
+                .thenReturn(
+                        true // R.bool.config_sort_order_user_changeable
+                        );
+        Mockito.when(
+                        mSharedPreferences.getInt(
+                                Mockito.eq(ContactsPreferences.SORT_ORDER_KEY), Mockito.anyInt()))
+                .thenReturn(ContactsPreferences.SORT_ORDER_PRIMARY);
+        Assert.assertEquals(
+                ContactsPreferences.SORT_ORDER_PRIMARY, mContactsPreferences.getSortOrder());
     }
 
     public void testGetDisplayOrderDefault() {
-        Mockito.when(mResources.getBoolean(Mockito.anyInt())).thenReturn(
-                false, // R.bool.config_display_order_user_changeable
-                true // R.bool.config_default_display_order_primary
-        );
-        Assert.assertEquals(ContactsPreferences.DISPLAY_ORDER_PRIMARY,
-                mContactsPreferences.getDisplayOrder());
+        Mockito.when(mResources.getBoolean(Mockito.anyInt()))
+                .thenReturn(
+                        false, // R.bool.config_display_order_user_changeable
+                        true // R.bool.config_default_display_order_primary
+                        );
+        Assert.assertEquals(
+                ContactsPreferences.DISPLAY_ORDER_PRIMARY, mContactsPreferences.getDisplayOrder());
     }
 
     public void testGetDisplayOrder() {
-        Mockito.when(mResources.getBoolean(Mockito.anyInt())).thenReturn(
-                true // R.bool.config_display_order_user_changeable
-        );
-        Mockito.when(mSharedPreferences.getInt(Mockito.eq(ContactsPreferences.DISPLAY_ORDER_KEY),
-                Mockito.anyInt())).thenReturn(ContactsPreferences.DISPLAY_ORDER_PRIMARY);
-        Assert.assertEquals(ContactsPreferences.DISPLAY_ORDER_PRIMARY,
-                mContactsPreferences.getDisplayOrder());
+        Mockito.when(mResources.getBoolean(Mockito.anyInt()))
+                .thenReturn(
+                        true // R.bool.config_display_order_user_changeable
+                        );
+        Mockito.when(
+                        mSharedPreferences.getInt(
+                                Mockito.eq(ContactsPreferences.DISPLAY_ORDER_KEY),
+                                Mockito.anyInt()))
+                .thenReturn(ContactsPreferences.DISPLAY_ORDER_PRIMARY);
+        Assert.assertEquals(
+                ContactsPreferences.DISPLAY_ORDER_PRIMARY, mContactsPreferences.getDisplayOrder());
     }
 
     public void testGetPhoneticNameDisplayDefault() {
-        Mockito.when(mResources.getBoolean(Mockito.anyInt())).thenReturn(
-                false, // R.bool.config_phonetic_name_display_user_changeable
-                true // R.bool.config_default_hide_phonetic_name_if_empty
-        );
-        Assert.assertEquals(PhoneticNameDisplayPreference.HIDE_IF_EMPTY,
+        Mockito.when(mResources.getBoolean(Mockito.anyInt()))
+                .thenReturn(
+                        false, // R.bool.config_phonetic_name_display_user_changeable
+                        true // R.bool.config_default_hide_phonetic_name_if_empty
+                        );
+        Assert.assertEquals(
+                PhoneticNameDisplayPreference.HIDE_IF_EMPTY,
                 mContactsPreferences.getPhoneticNameDisplayPreference());
     }
 
     public void testGetPhoneticNameDisplay() {
-        Mockito.when(mResources.getBoolean(Mockito.anyInt())).thenReturn(
-                true // R.bool.config_phonetic_name_display_user_changeable
-        );
-        Mockito.when(mSharedPreferences.getInt(
-                Mockito.eq(ContactsPreferences.PHONETIC_NAME_DISPLAY_KEY),
-                Mockito.anyInt())).thenReturn(PhoneticNameDisplayPreference.HIDE_IF_EMPTY);
-        Assert.assertEquals(PhoneticNameDisplayPreference.HIDE_IF_EMPTY,
+        Mockito.when(mResources.getBoolean(Mockito.anyInt()))
+                .thenReturn(
+                        true // R.bool.config_phonetic_name_display_user_changeable
+                        );
+        Mockito.when(
+                        mSharedPreferences.getInt(
+                                Mockito.eq(ContactsPreferences.PHONETIC_NAME_DISPLAY_KEY),
+                                Mockito.anyInt()))
+                .thenReturn(PhoneticNameDisplayPreference.HIDE_IF_EMPTY);
+        Assert.assertEquals(
+                PhoneticNameDisplayPreference.HIDE_IF_EMPTY,
                 mContactsPreferences.getPhoneticNameDisplayPreference());
     }
 
     public void testRefreshPhoneticNameDisplay() throws InterruptedException {
-        Mockito.when(mResources.getBoolean(Mockito.anyInt())).thenReturn(
-                true // R.bool.config_phonetic_name_display_user_changeable
-        );
-        Mockito.when(mSharedPreferences.getInt(
-                Mockito.eq(ContactsPreferences.PHONETIC_NAME_DISPLAY_KEY),
-                Mockito.anyInt())).thenReturn(PhoneticNameDisplayPreference.HIDE_IF_EMPTY,
-                PhoneticNameDisplayPreference.SHOW_ALWAYS);
-
-        Assert.assertEquals(PhoneticNameDisplayPreference.HIDE_IF_EMPTY,
+        Mockito.when(mResources.getBoolean(Mockito.anyInt()))
+                .thenReturn(
+                        true // R.bool.config_phonetic_name_display_user_changeable
+                        );
+        Mockito.when(
+                        mSharedPreferences.getInt(
+                                Mockito.eq(ContactsPreferences.PHONETIC_NAME_DISPLAY_KEY),
+                                Mockito.anyInt()))
+                .thenReturn(
+                        PhoneticNameDisplayPreference.HIDE_IF_EMPTY,
+                        PhoneticNameDisplayPreference.SHOW_ALWAYS);
+
+        Assert.assertEquals(
+                PhoneticNameDisplayPreference.HIDE_IF_EMPTY,
                 mContactsPreferences.getPhoneticNameDisplayPreference());
         mContactsPreferences.refreshValue(ContactsPreferences.PHONETIC_NAME_DISPLAY_KEY);
 
-        Assert.assertEquals(PhoneticNameDisplayPreference.SHOW_ALWAYS,
+        Assert.assertEquals(
+                PhoneticNameDisplayPreference.SHOW_ALWAYS,
                 mContactsPreferences.getPhoneticNameDisplayPreference());
     }
 
     public void testRefreshSortOrder() throws InterruptedException {
-        Mockito.when(mResources.getBoolean(Mockito.anyInt())).thenReturn(
-                true // R.bool.config_sort_order_user_changeable
-        );
-        Mockito.when(mSharedPreferences.getInt(Mockito.eq(ContactsPreferences.SORT_ORDER_KEY),
-                Mockito.anyInt())).thenReturn(ContactsPreferences.SORT_ORDER_PRIMARY,
-                ContactsPreferences.SORT_ORDER_ALTERNATIVE);
-
-        Assert.assertEquals(ContactsPreferences.SORT_ORDER_PRIMARY,
-                mContactsPreferences.getSortOrder());
+        Mockito.when(mResources.getBoolean(Mockito.anyInt()))
+                .thenReturn(
+                        true // R.bool.config_sort_order_user_changeable
+                        );
+        Mockito.when(
+                        mSharedPreferences.getInt(
+                                Mockito.eq(ContactsPreferences.SORT_ORDER_KEY), Mockito.anyInt()))
+                .thenReturn(
+                        ContactsPreferences.SORT_ORDER_PRIMARY,
+                        ContactsPreferences.SORT_ORDER_ALTERNATIVE);
+
+        Assert.assertEquals(
+                ContactsPreferences.SORT_ORDER_PRIMARY, mContactsPreferences.getSortOrder());
         mContactsPreferences.refreshValue(ContactsPreferences.SORT_ORDER_KEY);
 
-        Assert.assertEquals(ContactsPreferences.SORT_ORDER_ALTERNATIVE,
-                mContactsPreferences.getSortOrder());
+        Assert.assertEquals(
+                ContactsPreferences.SORT_ORDER_ALTERNATIVE, mContactsPreferences.getSortOrder());
     }
 
     public void testRefreshDisplayOrder() throws InterruptedException {
-        Mockito.when(mResources.getBoolean(Mockito.anyInt())).thenReturn(
-                true // R.bool.config_display_order_user_changeable
-        );
-        Mockito.when(mSharedPreferences.getInt(Mockito.eq(ContactsPreferences.DISPLAY_ORDER_KEY),
-                Mockito.anyInt())).thenReturn(ContactsPreferences.DISPLAY_ORDER_PRIMARY,
-                ContactsPreferences.DISPLAY_ORDER_ALTERNATIVE);
-
-        Assert.assertEquals(ContactsPreferences.DISPLAY_ORDER_PRIMARY,
-                mContactsPreferences.getDisplayOrder());
+        Mockito.when(mResources.getBoolean(Mockito.anyInt()))
+                .thenReturn(
+                        true // R.bool.config_display_order_user_changeable
+                        );
+        Mockito.when(
+                        mSharedPreferences.getInt(
+                                Mockito.eq(ContactsPreferences.DISPLAY_ORDER_KEY),
+                                Mockito.anyInt()))
+                .thenReturn(
+                        ContactsPreferences.DISPLAY_ORDER_PRIMARY,
+                        ContactsPreferences.DISPLAY_ORDER_ALTERNATIVE);
+
+        Assert.assertEquals(
+                ContactsPreferences.DISPLAY_ORDER_PRIMARY, mContactsPreferences.getDisplayOrder());
         mContactsPreferences.refreshValue(ContactsPreferences.DISPLAY_ORDER_KEY);
 
-        Assert.assertEquals(ContactsPreferences.DISPLAY_ORDER_ALTERNATIVE,
+        Assert.assertEquals(
+                ContactsPreferences.DISPLAY_ORDER_ALTERNATIVE,
                 mContactsPreferences.getDisplayOrder());
     }
 
     public void testRefreshDefaultAccount() throws InterruptedException {
-        mContactsPreferences = new ContactsPreferences(mContext,
-                /* isDefaultAccountUserChangeable */ true);
+        mContactsPreferences =
+                new ContactsPreferences(
+                        mContext, /* isDefaultAccountUserChangeable */ true, mDefaultAccountReader);
 
-        Mockito.when(mSharedPreferences.getString(Mockito.eq(ACCOUNT_KEY), Mockito.any()))
-                .thenReturn(new AccountWithDataSet("name1", "type1", "dataset1").stringify(),
-                        new AccountWithDataSet("name2", "type2", "dataset2").stringify());
+        Mockito.when(mDefaultAccountReader.getDefaultAccountAndState())
+                .thenReturn(
+                        DefaultAccountAndState.ofCloud(new Account("name1", "type1")),
+                        DefaultAccountAndState.ofCloud(new Account("name2", "type2")));
 
-        Assert.assertEquals(new AccountWithDataSet("name1", "type1", "dataset1"),
+        Assert.assertEquals(
+                new AccountWithDataSet("name1", "type1", null),
                 mContactsPreferences.getDefaultAccount());
         mContactsPreferences.refreshValue(ACCOUNT_KEY);
 
-        Assert.assertEquals(new AccountWithDataSet("name2", "type2", "dataset2"),
+        Assert.assertEquals(
+                new AccountWithDataSet("name2", "type2", null),
                 mContactsPreferences.getDefaultAccount());
     }
 
     public void testShouldShowAccountChangedNotificationIfAccountNotSaved() {
-        mContactsPreferences = new ContactsPreferences(mContext,
-                /* isDefaultAccountUserChangeable */ true);
-        Mockito.when(mSharedPreferences.getString(Mockito.eq(ACCOUNT_KEY), Mockito.any()))
-                .thenReturn(null);
-
-        assertTrue("Should prompt to change default if no default is saved",
-                mContactsPreferences.shouldShowAccountChangedNotification(Arrays.asList(
-                        new AccountWithDataSet("name1", "type1", "dataset1"),
-                        new AccountWithDataSet("name2", "type2", "dataset2"))));
+        mContactsPreferences =
+                new ContactsPreferences(
+                        mContext, /* isDefaultAccountUserChangeable */ true, mDefaultAccountReader);
+        Mockito.when(mDefaultAccountReader.getDefaultAccountAndState())
+                .thenReturn(DefaultAccountAndState.ofNotSet());
+
+        assertTrue(
+                "Should prompt to change default if no default is saved",
+                mContactsPreferences.shouldShowAccountChangedNotification(
+                        Arrays.asList(
+                                new AccountWithDataSet("name1", "type1", "dataset1"),
+                                new AccountWithDataSet("name2", "type2", "dataset2"))));
     }
 
     public void testShouldShowAccountChangedNotification() {
-        mContactsPreferences = new ContactsPreferences(mContext,
-                /* isDefaultAccountUserChangeable */ true);
-        Mockito.when(mSharedPreferences.getString(Mockito.eq(ACCOUNT_KEY), Mockito.any()))
-                .thenReturn(new AccountWithDataSet("name", "type", "dataset").stringify());
-
-        assertFalse("Should not prompt to change default if current default exists",
-                mContactsPreferences.shouldShowAccountChangedNotification(Arrays.asList(
-                        new AccountWithDataSet("name", "type", "dataset"),
-                        new AccountWithDataSet("name1", "type1", "dataset1"))));
-
-        assertTrue("Should prompt to change default if current default does not exist",
-                mContactsPreferences.shouldShowAccountChangedNotification(Arrays.asList(
-                        new AccountWithDataSet("name1", "type1", "dataset1"),
-                        new AccountWithDataSet("name2", "type2", "dataset2"))));
+        mContactsPreferences =
+                new ContactsPreferences(
+                        mContext, /* isDefaultAccountUserChangeable */ true, mDefaultAccountReader);
+        Mockito.when(mDefaultAccountReader.getDefaultAccountAndState())
+                .thenReturn(DefaultAccountAndState.ofCloud(new Account("name", "type")));
+
+        assertFalse(
+                "Should not prompt to change default if current default exists",
+                mContactsPreferences.shouldShowAccountChangedNotification(
+                        Arrays.asList(
+                                new AccountWithDataSet("name", "type", null),
+                                new AccountWithDataSet("name1", "type1", "dataset1"))));
+
+        assertTrue(
+                "Should prompt to change default if current default does not exist",
+                mContactsPreferences.shouldShowAccountChangedNotification(
+                        Arrays.asList(
+                                new AccountWithDataSet("name1", "type1", "dataset1"),
+                                new AccountWithDataSet("name2", "type2", "dataset2"))));
     }
 
     public void testShouldShowAccountChangedNotificationWhenThereIsOneAccount() {
-        mContactsPreferences = new ContactsPreferences(mContext,
-                /* isDefaultAccountUserChangeable */ true);
-        Mockito.when(mSharedPreferences.getString(Mockito.eq(ACCOUNT_KEY), Mockito.any()))
-                .thenReturn(null);
+        mContactsPreferences =
+                new ContactsPreferences(
+                        mContext, /* isDefaultAccountUserChangeable */ true, mDefaultAccountReader);
+        Mockito.when(mDefaultAccountReader.getDefaultAccountAndState())
+                .thenReturn(DefaultAccountAndState.ofNotSet());
 
         // Normally we would prompt because there is no default set but if there is just one
         // account we should just use it.
-        assertFalse("Should not prompt to change default if there is only one account available",
-                mContactsPreferences.shouldShowAccountChangedNotification(Arrays.asList(
-                        new AccountWithDataSet("name", "type", "dataset"))));
+        assertFalse(
+                "Should not prompt to change default if there is only one account available",
+                mContactsPreferences.shouldShowAccountChangedNotification(
+                        Arrays.asList(new AccountWithDataSet("name", "type", "dataset"))));
     }
 }
diff --git a/tests/src/com/android/contacts/tests/AdbHelpers.java b/tests/src/com/android/contacts/tests/AdbHelpers.java
index 28a22f3b4..9936b9c78 100644
--- a/tests/src/com/android/contacts/tests/AdbHelpers.java
+++ b/tests/src/com/android/contacts/tests/AdbHelpers.java
@@ -15,11 +15,13 @@
  */
 package com.android.contacts.tests;
 
+import android.accounts.Account;
 import android.content.Context;
 import android.content.OperationApplicationException;
 import android.os.Build;
 import android.os.Bundle;
 import android.os.RemoteException;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
 import android.util.Log;
 
 import androidx.annotation.RequiresApi;
@@ -32,9 +34,8 @@ import com.android.contacts.util.SharedPreferenceUtil;
 /**
  * Contains utility methods that can be invoked directly from adb using RunMethodInstrumentation.
  *
- * Example usage:
- * adb shell am instrument -e method addTestAccount -e accountName fooAccount\
- *   -w com.android.contacts.tests/com.android.contacts.RunMethodInstrumentation
+ * <p>Example usage: adb shell am instrument -e method addTestAccount -e accountName fooAccount\ -w
+ * com.android.contacts.tests/com.android.contacts.RunMethodInstrumentation
  */
 public class AdbHelpers {
     private static final String TAG = "AdbHelpers";
@@ -57,8 +58,8 @@ public class AdbHelpers {
             return;
         }
 
-        final AccountWithDataSet account = new AccountWithDataSet(accountName,
-                AccountsTestHelper.TEST_ACCOUNT_TYPE, null);
+        final AccountWithDataSet account =
+                new AccountWithDataSet(accountName, AccountsTestHelper.TEST_ACCOUNT_TYPE, null);
         new AccountsTestHelper(context).removeTestAccount(account);
     }
 
@@ -71,8 +72,13 @@ public class AdbHelpers {
             return;
         }
 
-        new ContactsPreferences(context).setDefaultAccount(
-                new AccountWithDataSet(name, type, null));
+        AccountWithDataSet localDeviceAccount = AccountWithDataSet.getLocalAccount(context);
+        DefaultAccountAndState defaultAccountAndState =
+                name.equals(localDeviceAccount.name) && type.equals(localDeviceAccount.type)
+                        ? DefaultAccountAndState.ofLocal()
+                        : DefaultAccountAndState.ofCloud(new Account(name, type));
+
+        new ContactsPreferences(context).setDefaultAccountAndState(defaultAccountAndState);
     }
 
     public static void clearDefaultAccount(Context context) {
@@ -85,8 +91,13 @@ public class AdbHelpers {
 
     public static void dumpPreferences(Context context) {
         if (Log.isLoggable(TAG, Log.DEBUG)) {
-            Log.d(TAG, "preferences=" + getAppContext().getSharedPreferences(
-                    getAppContext().getPackageName(), Context.MODE_PRIVATE).getAll());
+            Log.d(
+                    TAG,
+                    "preferences="
+                            + getAppContext()
+                                    .getSharedPreferences(
+                                            getAppContext().getPackageName(), Context.MODE_PRIVATE)
+                                    .getAll());
         }
     }
 
```

