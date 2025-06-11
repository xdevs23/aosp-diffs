```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 66d5767f1..e0d9ece0a 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -263,17 +263,6 @@
             android:launchMode="singleTop"
             android:theme="@style/ContactsPreferencesTheme"/>
 
-        <activity
-            android:name=".preference.SetDefaultAccountActivity"
-            android:exported="true"
-            android:theme="@style/BackgroundOnlyTheme"
-            android:excludeFromRecents="true">
-            <intent-filter>
-                <action android:name="android.provider.action.SET_DEFAULT_ACCOUNT"/>
-                <category android:name="android.intent.category.DEFAULT"/>
-            </intent-filter>
-        </activity>
-
         <activity
             android:name=".activities.LicenseActivity"
             android:exported="true"
diff --git a/OWNERS b/OWNERS
index a338d4f5d..6d4ba83d2 100644
--- a/OWNERS
+++ b/OWNERS
@@ -4,4 +4,3 @@ garymai@google.com
 mhagerott@google.com
 wjang@google.com
 johnshao@google.com
-yaolu@google.com
diff --git a/proguard.flags b/proguard.flags
index 9543f9d66..cdd4a9fb8 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -107,13 +107,19 @@
 -keep class com.android.common.widget.CompositeCursorAdapter { *; }
 
 # Any class or method annotated with NeededForReflection.
--keep @com.android.contacts.test.NeededForReflection class *
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @com.android.contacts.test.NeededForReflection class * {
+  void <init>();
+}
 -keepclassmembers class * {
-@com.android.contacts.test.NeededForReflection *;
+  @com.android.contacts.test.NeededForReflection *;
 }
 
 # Keep classes and methods that have the guava @VisibleForTesting annotation
--keep @com.google.common.annotations.VisibleForTesting class *
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @com.google.common.annotations.VisibleForTesting class * {
+  void <init>();
+}
 -keepclassmembers class * {
   @com.google.common.annotations.VisibleForTesting *;
 }
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 60261cfa7..9d85766f5 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -115,7 +115,7 @@
     <string name="groupSomeContactsNoPhonesToast" msgid="2454029254458875746">"بعض جهات الاتصال ليست لديها أرقام هواتف."</string>
     <string name="menu_sendEmailOption" msgid="8600335923636486825">"إرسال رسالة إلكترونية"</string>
     <string name="menu_sendMessageOption" msgid="8051852013078110910">"إرسال رسالة"</string>
-    <string name="pickerSelectContactsActivityTitle" msgid="8265907544009447967">"اختيار جهات الاتصال"</string>
+    <string name="pickerSelectContactsActivityTitle" msgid="8265907544009447967">"يُرجى اختيار جهات الاتصال"</string>
     <string name="send_to_selection" msgid="3655197947726443720">"إرسال"</string>
     <string name="listFoundAllContactsZero" msgid="1933842282916988563">"ليست هناك جهات اتصال"</string>
     <string name="add_contact_dlg_message_fmt" msgid="7498024710169591375">"هل ترغب في إضافة \"<xliff:g id="EMAIL">%s</xliff:g>\" إلى جهات الاتصال؟"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 117e9083f..192320cc5 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -41,7 +41,7 @@
     <string name="menu_renameGroup" msgid="2685886609399776475">"লেবেলের পুনঃনামকরণ করুন"</string>
     <string name="menu_deleteGroup" msgid="1180215594530228294">"লেবেল মুছুন"</string>
     <string name="menu_addToGroup" msgid="5034813446697655310">"পরিচিতি যোগ করুন"</string>
-    <string name="menu_selectForGroup" msgid="6386553337569514850">"পরিচিতিগুলিকে বেছে নিন"</string>
+    <string name="menu_selectForGroup" msgid="6386553337569514850">"পরিচিতি বেছে নিন"</string>
     <string name="menu_addContactsToGroup" msgid="4549318978482280577">"পরিচিতিগুলি যোগ করুন"</string>
     <string name="menu_removeFromGroup" msgid="8753799091967887958">"লেবেল থেকে সরান"</string>
     <string name="menu_new_group_action_bar" msgid="1670312283925872483">"লেবেল তৈরি করুন"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 639c1f115..d2c58cdb1 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -20,7 +20,7 @@
     <string name="contactsList" msgid="4456188358262700898">"સંપર્કો"</string>
     <string name="shortcut_add_contact" msgid="7949342235528657981">"સંપર્ક ઉમેરો"</string>
     <string name="shortcutContact" msgid="8009736387364461511">"સંપર્ક"</string>
-    <string name="shortcutDialContact" msgid="155367248069127153">"સીધું જ ડાયલ"</string>
+    <string name="shortcutDialContact" msgid="155367248069127153">"ડિરેક્ટ ડાયલ"</string>
     <string name="shortcutMessageContact" msgid="9123517151981679277">"ડિરેક્ટ મેસેજ"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"સંપર્ક પસંદ કરો"</string>
     <string name="contactInsertOrEditActivityTitle" msgid="1788154962629911262">"સંપર્કમાં ઉમેરો"</string>
@@ -165,8 +165,8 @@
     <string name="delete_group_dialog_message" msgid="754082019928025404">"\"<xliff:g id="GROUP_LABEL">%1$s</xliff:g>\" લેબલ કાઢી નાખીએ? (સંપર્કો સ્વયં કાઢી નાખવામાં આવશે નહીં.)"</string>
     <string name="toast_join_with_empty_contact" msgid="3886468280665325350">"બીજા સાથે લિંક કરતાં પહેલાં સંપર્કનું નામ લખો."</string>
     <string name="copy_text" msgid="6835250673373028909">"ક્લિપબોર્ડ પર કૉપિ કરો"</string>
-    <string name="set_default" msgid="3704074175618702225">"ડિફોલ્ટ સેટ કરો"</string>
-    <string name="clear_default" msgid="2055883863621491533">"ડિફોલ્ટ સાફ કરો"</string>
+    <string name="set_default" msgid="3704074175618702225">"ડિફૉલ્ટ સેટ કરો"</string>
+    <string name="clear_default" msgid="2055883863621491533">"ડિફૉલ્ટ સાફ કરો"</string>
     <string name="toast_text_copied" msgid="845906090076228771">"ટેક્સ્ટ કૉપિ કર્યો"</string>
     <string name="cancel_confirmation_dialog_message" msgid="7486892574762212762">"ફેરફારો નિકાળીએ?"</string>
     <string name="cancel_confirmation_dialog_cancel_editing_button" msgid="8280294641821133477">"નિકાળો"</string>
@@ -424,7 +424,7 @@
     <string name="display_options_view_given_name_first" msgid="383885125505521383">"પ્રથમ નામ પહેલા"</string>
     <string name="display_options_view_family_name_first" msgid="6597077054231296007">"છેલ્લું નામ પહેલા"</string>
     <string name="settings_accounts" msgid="119582613811929994">"એકાઉન્ટ્સ"</string>
-    <string name="default_editor_account" msgid="4810392921888877149">"નવા સંપર્કો માટે ડિફોલ્ટ એકાઉન્ટ"</string>
+    <string name="default_editor_account" msgid="4810392921888877149">"નવા સંપર્કો માટે ડિફૉલ્ટ એકાઉન્ટ"</string>
     <string name="settings_my_info_title" msgid="6236848378653551341">"મારી માહિતી"</string>
     <string name="set_up_profile" msgid="3554999219868611431">"તમારી પ્રોફાઇલ સેટ કરો"</string>
     <string name="setting_about" msgid="2941859292287597555">"સંપર્કો વિશે"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 84610c2bd..8d66b5b4f 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -41,7 +41,7 @@
     <string name="menu_renameGroup" msgid="2685886609399776475">"Promjena naziva oznake"</string>
     <string name="menu_deleteGroup" msgid="1180215594530228294">"Brisanje oznake"</string>
     <string name="menu_addToGroup" msgid="5034813446697655310">"Dodavanje kontakta"</string>
-    <string name="menu_selectForGroup" msgid="6386553337569514850">"Odabir kontakata"</string>
+    <string name="menu_selectForGroup" msgid="6386553337569514850">"Odaberite kontakte"</string>
     <string name="menu_addContactsToGroup" msgid="4549318978482280577">"Dodavanje kontakata"</string>
     <string name="menu_removeFromGroup" msgid="8753799091967887958">"Uklanjanje iz oznake"</string>
     <string name="menu_new_group_action_bar" msgid="1670312283925872483">"Izrada oznake"</string>
@@ -115,7 +115,7 @@
     <string name="groupSomeContactsNoPhonesToast" msgid="2454029254458875746">"Neki kontakti nemaju telefonske brojeve."</string>
     <string name="menu_sendEmailOption" msgid="8600335923636486825">"Slanje e-poruke"</string>
     <string name="menu_sendMessageOption" msgid="8051852013078110910">"Slanje poruke"</string>
-    <string name="pickerSelectContactsActivityTitle" msgid="8265907544009447967">"Odabir kontakata"</string>
+    <string name="pickerSelectContactsActivityTitle" msgid="8265907544009447967">"Odaberite kontakte"</string>
     <string name="send_to_selection" msgid="3655197947726443720">"Slanje"</string>
     <string name="listFoundAllContactsZero" msgid="1933842282916988563">"Nema kontakata"</string>
     <string name="add_contact_dlg_message_fmt" msgid="7498024710169591375">"Dodati \"<xliff:g id="EMAIL">%s</xliff:g>\" kontaktima?"</string>
@@ -470,7 +470,7 @@
     <string name="dynamic_shortcut_disabled_message" msgid="8770462908102469878">"Ovaj je prečac onemogućen"</string>
     <string name="dynamic_shortcut_contact_removed_message" msgid="8331735243566193974">"Kontakt je uklonjen"</string>
     <string name="sim_import_button_text" msgid="2845608246304396009">"Uvezi"</string>
-    <string name="sim_import_title_none_selected" msgid="3527680774575468781">"Odabir kontakata"</string>
+    <string name="sim_import_title_none_selected" msgid="3527680774575468781">"Odaberite kontakte"</string>
     <string name="sim_import_empty_message" msgid="7238368542566545854">"Nema kontakata na vašoj SIM kartici"</string>
     <string name="sim_import_contact_exists_toast" msgid="8423212007841229749">"Kontakt već postoji na vašem popisu"</string>
     <string name="sim_import_success_toast_fmt" msgid="7645974841482481503">"{count,plural, =1{Uvezen je # SIM kontakt}one{Uvezen je # SIM kontakt}few{Uvezena su # SIM kontakta}other{Uvezeno je # SIM kontakata}}"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index a087d99a6..f846babc1 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -27,7 +27,7 @@
     <string name="contactPickerActivityTitle" msgid="1842634991247618890">"בחר איש קשר"</string>
     <string name="groupMemberPickerActivityTitle" msgid="8745419913947478380">"בחר"</string>
     <string name="header_entry_contact_list_adapter_header_title" msgid="4098233078586958762">"איש קשר חדש"</string>
-    <string name="searchHint" msgid="1487501532610025473">"חפש אנשי קשר"</string>
+    <string name="searchHint" msgid="1487501532610025473">"חיפוש אנשי קשר"</string>
     <string name="menu_addStar" msgid="4903812703386825130">"הוספה למועדפים"</string>
     <string name="menu_removeStar" msgid="3707373931808303701">"הסרה מהמועדפים"</string>
     <string name="description_action_menu_remove_star" msgid="4044390281910122890">"הוסר מהמועדפים"</string>
@@ -180,7 +180,7 @@
     <string name="contact_editor_prompt_one_account" msgid="765343809177951169">"אנשי קשר חדשים יישמרו ב-<xliff:g id="ACCOUNT_NAME">%1$s</xliff:g>."</string>
     <string name="contact_editor_prompt_multiple_accounts" msgid="1543322760761168351">"בחר חשבון ברירת מחדל לאנשי קשר חדשים:"</string>
     <string name="contact_editor_title_new_contact" msgid="7534775011591770343">"איש קשר חדש"</string>
-    <string name="contact_editor_title_existing_contact" msgid="3647774955741654029">"ערוך איש קשר"</string>
+    <string name="contact_editor_title_existing_contact" msgid="3647774955741654029">"עריכת איש קשר"</string>
     <string name="contact_editor_title_read_only_contact" msgid="5494810291515292596">"תצוגה בלבד"</string>
     <string name="contact_editor_pick_raw_contact_to_edit_dialog_title" msgid="4478782370280424187">"בחר איש קשר לעריכה"</string>
     <string name="contact_editor_pick_linked_contact_dialog_title" msgid="3332134735168016293">"אנשי קשר מקושרים"</string>
@@ -439,7 +439,7 @@
     <string name="activity_title_contacts_filter" msgid="6340531582631006680">"אנשי קשר להצגה"</string>
     <string name="custom_list_filter" msgid="2544327670202891979">"התאמה אישית של התצוגה"</string>
     <string name="menu_custom_filter_save" msgid="2412959737200856930">"שמירה"</string>
-    <string name="hint_findContacts" msgid="5554298639062659655">"חפש אנשי קשר"</string>
+    <string name="hint_findContacts" msgid="5554298639062659655">"חיפוש אנשי קשר"</string>
     <string name="contactsFavoritesLabel" msgid="8339645684721732714">"מועדפים"</string>
     <string name="menu_import" msgid="2206768098740726906">"ייבוא"</string>
     <string name="menu_export" msgid="1217402092617629429">"ייצוא"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 91e8b3334..8640f30af 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -17,11 +17,11 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="applicationLabel" msgid="8908212014470937609">"कन्ट्याक्टहरू"</string>
-    <string name="contactsList" msgid="4456188358262700898">"सम्पर्क"</string>
+    <string name="contactsList" msgid="4456188358262700898">"कन्ट्याक्टहरू"</string>
     <string name="shortcut_add_contact" msgid="7949342235528657981">"सम्पर्क थप्नुहोस्"</string>
-    <string name="shortcutContact" msgid="8009736387364461511">"ठेगाना"</string>
+    <string name="shortcutContact" msgid="8009736387364461511">"कन्ट्याक्ट"</string>
     <string name="shortcutDialContact" msgid="155367248069127153">"सीधा डायल गर्नुहोस्"</string>
-    <string name="shortcutMessageContact" msgid="9123517151981679277">"सीधा सन्देश"</string>
+    <string name="shortcutMessageContact" msgid="9123517151981679277">"डाइरेक्ट म्यासेज"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"सम्पर्क छनौट गर्नुहोस्"</string>
     <string name="contactInsertOrEditActivityTitle" msgid="1788154962629911262">"सम्पर्कमा थप्नुहोस्"</string>
     <string name="contactPickerActivityTitle" msgid="1842634991247618890">"एउटा सम्पर्क छान्नुहोस्"</string>
@@ -291,7 +291,7 @@
     <string name="list_filter_phones" msgid="6839133198968393843">"फोन नम्बर भएका सबै कन्ट्याक्टहरू"</string>
     <string name="list_filter_phones_work" msgid="5583425697781385616">"कार्य प्रोफाइलका कन्ट्याक्टहरू"</string>
     <string name="view_updates_from_group" msgid="6233444629074835594">"अपडेटहरू हेर्नुहोस्"</string>
-    <string name="account_phone" msgid="8044426231251817556">"यन्त्र"</string>
+    <string name="account_phone" msgid="8044426231251817556">"डिभाइस"</string>
     <string name="account_sim" msgid="3200457113308694663">"SIM"</string>
     <string name="nameLabelsGroup" msgid="513809148312046843">"नाम"</string>
     <string name="nicknameLabelsGroup" msgid="794390116782033956">"उपनाम"</string>
@@ -357,7 +357,7 @@
     <string name="list_filter_all_accounts" msgid="6173785387972096770">"सबै कन्ट्याक्टहरू"</string>
     <string name="list_filter_all_starred" msgid="2582865760150432568">"ताराङ्कित"</string>
     <string name="list_filter_customize" msgid="2368900508906139537">" कस्टम बनाउनुहोस्"</string>
-    <string name="list_filter_single" msgid="6003845379327432129">"ठेगाना"</string>
+    <string name="list_filter_single" msgid="6003845379327432129">"कन्ट्याक्ट"</string>
     <string name="display_ungrouped" msgid="4823012484407759332">"अन्य सबै कन्ट्याक्टहरू"</string>
     <string name="display_all_contacts" msgid="1281067776483704512">"सबै कन्ट्याक्टहरू"</string>
     <string name="menu_sync_remove" msgid="7523335046562082188">"सिंक समूह हटाउनुहोस्"</string>
@@ -407,7 +407,7 @@
     <string name="vcard_import_request_rejected_message" msgid="4754292694777189540">"vCard निर्यात अनुरोध अस्वीकार गरिएको छ । कृपया पछि पर्यास गर्नुहोस्"</string>
     <string name="contacts_export_will_start_message" msgid="6428126265599715944">"सम्पर्कहरूलाई चॉंडै निर्यात गरिने छ।"</string>
     <string name="vcard_export_request_rejected_message" msgid="6455336845734884740">"vCard निर्यात अनुरोध अस्वीकार गरियो। पछि पुनःप्रयास गर्नुहोस्।"</string>
-    <string name="vcard_unknown_filename" msgid="8320954544777782497">"सम्पर्क"</string>
+    <string name="vcard_unknown_filename" msgid="8320954544777782497">"कन्ट्याक्ट"</string>
     <string name="caching_vcard_message" msgid="1879339732783666517">"vCard(s) लाई स्थानीय अस्थायी भण्डारणमा क्यास गर्दै। वास्तविक आयात छिट्टै सुरु हुन्छ।"</string>
     <string name="vcard_import_failed" msgid="37313715326741013">"VCard इम्पोर्ट गर्न सकेन।"</string>
     <string name="nfc_vcard_file_name" msgid="2113518216329123152">"NFCमा सम्पर्क प्राप्त गरियो"</string>
@@ -490,7 +490,7 @@
     <string name="importing_sim_failed_title" msgid="1046154274170241788">"इम्पोर्ट गर्न सकिएन"</string>
     <string name="importing_sim_failed_message" msgid="55568522164349044">"SIM कार्डबाट कन्ट्याक्टहरू इम्पोर्ट गर्न सकिएन"</string>
     <string name="importing_sim_in_progress_title" msgid="7647907413920018595">"SIM आयात गरिँदै"</string>
-    <string name="contacts_default_notification_channel" msgid="5116916969874075866">"सूचनाहरू"</string>
+    <string name="contacts_default_notification_channel" msgid="5116916969874075866">"नोटिफिकेसनहरू"</string>
     <string name="yes_button" msgid="1120514817091581293">"हुन्छ"</string>
     <string name="no_button" msgid="8965841385742548947">"हुँदैन"</string>
     <string name="sdn_contacts_directory_search_label" msgid="9146122809408008443">"मोबाइल सेवा प्रदायकका सर्भिस नम्बरहरू"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 056ed3539..966f83be6 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -16,10 +16,10 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="applicationLabel" msgid="8908212014470937609">"ଯୋଗାଯୋଗ"</string>
+    <string name="applicationLabel" msgid="8908212014470937609">"କଣ୍ଟାକ୍ଟ"</string>
     <string name="contactsList" msgid="4456188358262700898">"ଯୋଗାଯୋଗ"</string>
     <string name="shortcut_add_contact" msgid="7949342235528657981">"ଯୋଗାଯୋଗକୁ ଯୋଗ କରନ୍ତୁ"</string>
-    <string name="shortcutContact" msgid="8009736387364461511">"ଯୋଗାଯୋଗ"</string>
+    <string name="shortcutContact" msgid="8009736387364461511">"କଣ୍ଟାକ୍ଟ"</string>
     <string name="shortcutDialContact" msgid="155367248069127153">"ଡାଇରେକ୍ଟ କଲ୍ କରନ୍ତୁ"</string>
     <string name="shortcutMessageContact" msgid="9123517151981679277">"ଡାଇରେକ୍ଟ ମେସେଜ୍‍ ପଠାନ୍ତୁ"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"ଯୋଗାଯୋଗ ଚୟନ କରନ୍ତୁ"</string>
@@ -41,7 +41,7 @@
     <string name="menu_renameGroup" msgid="2685886609399776475">"ଲେବଲ୍‌ର ନାମ ବଦଳାନ୍ତୁ"</string>
     <string name="menu_deleteGroup" msgid="1180215594530228294">"ଲେବଲ୍ ଡିଲିଟ୍ କରନ୍ତୁ"</string>
     <string name="menu_addToGroup" msgid="5034813446697655310">"ଯୋଗାଯୋଗଙ୍କୁ ଯୋଡ଼ନ୍ତୁ"</string>
-    <string name="menu_selectForGroup" msgid="6386553337569514850">"ଯୋଗାଯୋଗ ଚୟନ କରନ୍ତୁ"</string>
+    <string name="menu_selectForGroup" msgid="6386553337569514850">"କଣ୍ଟାକ୍ଟଗୁଡ଼ିକୁ ଚୟନ କରନ୍ତୁ"</string>
     <string name="menu_addContactsToGroup" msgid="4549318978482280577">"ଯୋଗାଯୋଗଙ୍କୁ ଯୋଡ଼ନ୍ତୁ"</string>
     <string name="menu_removeFromGroup" msgid="8753799091967887958">"ଲେବଲ୍‌ରୁ କାଢ଼ିଦିଅନ୍ତୁ"</string>
     <string name="menu_new_group_action_bar" msgid="1670312283925872483">"ଲେବଲ୍ ତିଆରି କରନ୍ତୁ"</string>
@@ -229,7 +229,7 @@
     <string name="menu_title_filters" msgid="349866121417914494">"ଆକାଉଣ୍ଟ"</string>
     <string name="hamburger_feature_highlight_header" msgid="1786641424099282909">"ପରାମର୍ଶ"</string>
     <string name="hamburger_feature_highlight_body" msgid="782935036630531528">"ନିଜ ଯୋଗାଯୋଗଙ୍କୁ ବ୍ୟବସ୍ଥିତ ଓ ଉପଯୋଗୀ କରି ରଖନ୍ତୁ"</string>
-    <string name="undo" msgid="2446931036220975026">"ଅନ୍-ଡୁ କରନ୍ତୁ"</string>
+    <string name="undo" msgid="2446931036220975026">"ଅନଡୁ କରନ୍ତୁ"</string>
     <string name="call_custom" msgid="2844900154492073207">"<xliff:g id="CUSTOM_LABEL">%s</xliff:g>ରେ କଲ୍ କରନ୍ତୁ"</string>
     <string name="call_home" msgid="2443904771140750492">"ଘର ନମ୍ବର୍‌କୁ କଲ୍ କରନ୍ତୁ"</string>
     <string name="call_mobile" msgid="6504312789160309832">"ମୋବାଇଲ୍‍କୁ କଲ୍‍ କରନ୍ତୁ"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 2cc5aba49..b966bc9b7 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -20,7 +20,7 @@
     <string name="contactsList" msgid="4456188358262700898">"Contactos"</string>
     <string name="shortcut_add_contact" msgid="7949342235528657981">"Adicionar contacto"</string>
     <string name="shortcutContact" msgid="8009736387364461511">"Contacto"</string>
-    <string name="shortcutDialContact" msgid="155367248069127153">"Reserva direta"</string>
+    <string name="shortcutDialContact" msgid="155367248069127153">"Marcação direta"</string>
     <string name="shortcutMessageContact" msgid="9123517151981679277">"Mensagem direta"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"Escolher contacto"</string>
     <string name="contactInsertOrEditActivityTitle" msgid="1788154962629911262">"Adicionar ao contacto"</string>
@@ -41,7 +41,7 @@
     <string name="menu_renameGroup" msgid="2685886609399776475">"Mudar o nome da etiqueta"</string>
     <string name="menu_deleteGroup" msgid="1180215594530228294">"Eliminar etiqueta"</string>
     <string name="menu_addToGroup" msgid="5034813446697655310">"Adicionar contacto"</string>
-    <string name="menu_selectForGroup" msgid="6386553337569514850">"Selecionar contactos"</string>
+    <string name="menu_selectForGroup" msgid="6386553337569514850">"Selecione os contactos"</string>
     <string name="menu_addContactsToGroup" msgid="4549318978482280577">"Adicionar contactos"</string>
     <string name="menu_removeFromGroup" msgid="8753799091967887958">"Remover da etiqueta"</string>
     <string name="menu_new_group_action_bar" msgid="1670312283925872483">"Criar etiqueta"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index e6cb4f8af..e66a87f6d 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -115,7 +115,7 @@
     <string name="groupSomeContactsNoPhonesToast" msgid="2454029254458875746">"Unele persoane de contact nu au numere de telefon."</string>
     <string name="menu_sendEmailOption" msgid="8600335923636486825">"Trimiteți un e-mail"</string>
     <string name="menu_sendMessageOption" msgid="8051852013078110910">"Trimiteți un mesaj"</string>
-    <string name="pickerSelectContactsActivityTitle" msgid="8265907544009447967">"Alegeți persoane de contact"</string>
+    <string name="pickerSelectContactsActivityTitle" msgid="8265907544009447967">"Alege persoane de contact"</string>
     <string name="send_to_selection" msgid="3655197947726443720">"Trimiteți"</string>
     <string name="listFoundAllContactsZero" msgid="1933842282916988563">"Nu există persoane în agendă"</string>
     <string name="add_contact_dlg_message_fmt" msgid="7498024710169591375">"Adăugați „<xliff:g id="EMAIL">%s</xliff:g>” în agendă?"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 586207fb2..aedcf6e85 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -20,8 +20,8 @@
     <string name="contactsList" msgid="4456188358262700898">"Контакты"</string>
     <string name="shortcut_add_contact" msgid="7949342235528657981">"Добавить контакт"</string>
     <string name="shortcutContact" msgid="8009736387364461511">"Контакт"</string>
-    <string name="shortcutDialContact" msgid="155367248069127153">"Быстрый звонок"</string>
-    <string name="shortcutMessageContact" msgid="9123517151981679277">"Быстрое SMS"</string>
+    <string name="shortcutDialContact" msgid="155367248069127153">"Позвонить"</string>
+    <string name="shortcutMessageContact" msgid="9123517151981679277">"Написать"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"Выбрать контакт"</string>
     <string name="contactInsertOrEditActivityTitle" msgid="1788154962629911262">"Добавление данных"</string>
     <string name="contactPickerActivityTitle" msgid="1842634991247618890">"Выберите контакт"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index a232ab2f3..0257ed3a6 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -19,8 +19,8 @@
     <string name="applicationLabel" msgid="8908212014470937609">"Stiki"</string>
     <string name="contactsList" msgid="4456188358262700898">"Stiki"</string>
     <string name="shortcut_add_contact" msgid="7949342235528657981">"Dodaj stik"</string>
-    <string name="shortcutContact" msgid="8009736387364461511">"Vizitka"</string>
-    <string name="shortcutDialContact" msgid="155367248069127153">"Bližnjice za klicanje"</string>
+    <string name="shortcutContact" msgid="8009736387364461511">"Stik"</string>
+    <string name="shortcutDialContact" msgid="155367248069127153">"Neposredni klic"</string>
     <string name="shortcutMessageContact" msgid="9123517151981679277">"Neposredno sporočilo"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"Izbira stika"</string>
     <string name="contactInsertOrEditActivityTitle" msgid="1788154962629911262">"Dodajanje v stik"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index df03f15ad..e03577ca8 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -19,7 +19,7 @@
     <string name="applicationLabel" msgid="8908212014470937609">"รายชื่อติดต่อ"</string>
     <string name="contactsList" msgid="4456188358262700898">"รายชื่อติดต่อ"</string>
     <string name="shortcut_add_contact" msgid="7949342235528657981">"เพิ่มรายชื่อติดต่อ"</string>
-    <string name="shortcutContact" msgid="8009736387364461511">"สมุดโทรศัพท์"</string>
+    <string name="shortcutContact" msgid="8009736387364461511">"รายชื่อติดต่อ"</string>
     <string name="shortcutDialContact" msgid="155367248069127153">"สายตรง"</string>
     <string name="shortcutMessageContact" msgid="9123517151981679277">"ข้อความส่วนตัว"</string>
     <string name="shortcutActivityTitle" msgid="5407832911005090417">"เลือกรายชื่อติดต่อ"</string>
diff --git a/res/xml/preference_display_options.xml b/res/xml/preference_display_options.xml
index 998725087..c969cd24f 100644
--- a/res/xml/preference_display_options.xml
+++ b/res/xml/preference_display_options.xml
@@ -26,7 +26,7 @@
         android:title="@string/settings_accounts">
     </Preference>
 
-    <Preference
+    <com.android.contacts.preference.DefaultAccountPreference
         android:icon="@null"
         android:key="defaultAccount"
         android:title="@string/default_editor_account"
diff --git a/src/com/android/contacts/model/RawContactModifier.java b/src/com/android/contacts/model/RawContactModifier.java
index 789bd10f5..171a810dd 100644
--- a/src/com/android/contacts/model/RawContactModifier.java
+++ b/src/com/android/contacts/model/RawContactModifier.java
@@ -1038,10 +1038,30 @@ public class RawContactModifier {
             return;
         }
 
+        boolean supportPrefix = false;
+        boolean supportFamilyName = false;
+        boolean supportMiddleName = false;
+        boolean supportGivenName = false;
+        boolean supportSuffix = false;
         boolean supportPhoneticFamilyName = false;
         boolean supportPhoneticMiddleName = false;
         boolean supportPhoneticGivenName = false;
         for (EditField editField : newDataKind.fieldList) {
+            if (StructuredName.PREFIX.equals(editField.column)) {
+                supportPrefix = true;
+            }
+            if (StructuredName.FAMILY_NAME.equals(editField.column)) {
+                supportFamilyName = true;
+            }
+            if (StructuredName.MIDDLE_NAME.equals(editField.column)) {
+                supportMiddleName = true;
+            }
+            if (StructuredName.GIVEN_NAME.equals(editField.column)) {
+                supportGivenName = true;
+            }
+            if (StructuredName.SUFFIX.equals(editField.column)) {
+                supportSuffix = true;
+            }
             if (StructuredName.PHONETIC_FAMILY_NAME.equals(editField.column)) {
                 supportPhoneticFamilyName = true;
             }
@@ -1053,6 +1073,21 @@ public class RawContactModifier {
             }
         }
 
+        if (!supportPrefix) {
+            values.remove(StructuredName.PREFIX);
+        }
+        if (!supportFamilyName) {
+            values.remove(StructuredName.FAMILY_NAME);
+        }
+        if (!supportMiddleName) {
+            values.remove(StructuredName.MIDDLE_NAME);
+        }
+        if (!supportGivenName) {
+            values.remove(StructuredName.GIVEN_NAME);
+        }
+        if (!supportSuffix) {
+            values.remove(StructuredName.SUFFIX);
+        }
         if (!supportPhoneticFamilyName) {
             values.remove(StructuredName.PHONETIC_FAMILY_NAME);
         }
diff --git a/src/com/android/contacts/preference/ContactsPreferences.java b/src/com/android/contacts/preference/ContactsPreferences.java
index e5f0cda84..e1a58d37b 100644
--- a/src/com/android/contacts/preference/ContactsPreferences.java
+++ b/src/com/android/contacts/preference/ContactsPreferences.java
@@ -16,29 +16,20 @@
 
 package com.android.contacts.preference;
 
-import static android.Manifest.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS;
-
-import android.accounts.Account;
-import android.annotation.SuppressLint;
 import android.app.backup.BackupManager;
 import android.content.Context;
-import android.content.pm.PackageManager;
 import android.content.SharedPreferences;
 import android.content.SharedPreferences.Editor;
 import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
 import android.os.Handler;
 import android.os.Looper;
-import android.os.StrictMode;
 import android.preference.PreferenceManager;
-import android.provider.ContactsContract;
 import android.provider.Settings;
 import android.provider.Settings.SettingNotFoundException;
 import android.text.TextUtils;
 
 import androidx.annotation.NonNull;
-import androidx.annotation.RequiresApi;
 import androidx.annotation.VisibleForTesting;
-import androidx.core.os.BuildCompat;
 
 import com.android.contacts.R;
 import com.android.contacts.model.account.AccountWithDataSet;
@@ -218,45 +209,23 @@ public class ContactsPreferences implements OnSharedPreferenceChangeListener {
         return mIsDefaultAccountUserChangeable;
     }
 
-    @SuppressLint("NewApi")
     public AccountWithDataSet getDefaultAccount() {
         if (!isDefaultAccountUserChangeable()) {
             return mDefaultAccount;
         }
         if (mDefaultAccount == null) {
-            Account cp2DefaultAccount = null;
-            if (BuildCompat.isAtLeastT()) {
-                cp2DefaultAccount = getDefaultAccountFromCp2();
+            final String accountString = mPreferences
+                    .getString(mDefaultAccountKey, null);
+            if (!TextUtils.isEmpty(accountString)) {
+                mDefaultAccount = AccountWithDataSet.unstringify(accountString);
             }
-
-            mDefaultAccount = cp2DefaultAccount == null
-                    ? AccountWithDataSet.getNullAccount()
-                    : new AccountWithDataSet(cp2DefaultAccount.name, cp2DefaultAccount.type, null);
         }
         return mDefaultAccount;
     }
 
-    @RequiresApi(33)
-    private Account getDefaultAccountFromCp2() {
-        StrictMode.ThreadPolicy oldPolicy = StrictMode.getThreadPolicy();
-        StrictMode.setThreadPolicy(
-                new StrictMode.ThreadPolicy.Builder(oldPolicy)
-                .permitDiskReads()
-                .build());
-        try {
-            return ContactsContract.Settings.getDefaultAccount(
-                    mContext.getContentResolver());
-        } finally {
-            StrictMode.setThreadPolicy(oldPolicy);
-        }
-    }
-
     public void clearDefaultAccount() {
-        if (mContext.checkSelfPermission(SET_DEFAULT_ACCOUNT_FOR_CONTACTS)
-                == PackageManager.PERMISSION_GRANTED) {
-            mDefaultAccount = null;
-            setDefaultAccountToCp2(null);
-        }
+        mDefaultAccount = null;
+        mPreferences.edit().remove(mDefaultAccountKey).commit();
     }
 
     public void setDefaultAccount(@NonNull AccountWithDataSet accountWithDataSet) {
@@ -264,30 +233,12 @@ public class ContactsPreferences implements OnSharedPreferenceChangeListener {
             throw new IllegalArgumentException(
                     "argument should not be null");
         }
-        if (mContext.checkSelfPermission(SET_DEFAULT_ACCOUNT_FOR_CONTACTS)
-                == PackageManager.PERMISSION_GRANTED) {
-            mDefaultAccount = accountWithDataSet;
-            setDefaultAccountToCp2(accountWithDataSet);
-        }
-    }
-
-    private void setDefaultAccountToCp2(AccountWithDataSet accountWithDataSet) {
-        StrictMode.ThreadPolicy oldPolicy = StrictMode.getThreadPolicy();
-        StrictMode.setThreadPolicy(
-                new StrictMode.ThreadPolicy.Builder(oldPolicy)
-                        .permitDiskWrites()
-                        .permitDiskReads()
-                        .build());
-        try {
-            ContactsContract.Settings.setDefaultAccount(mContext.getContentResolver(),
-                    accountWithDataSet == null ? null : accountWithDataSet.getAccountOrNull());
-        } finally {
-            StrictMode.setThreadPolicy(oldPolicy);
-        }
+        mDefaultAccount = accountWithDataSet;
+        mPreferences.edit().putString(mDefaultAccountKey, accountWithDataSet.stringify()).commit();
     }
 
     public boolean isDefaultAccountSet() {
-        return mDefaultAccount != null;
+        return mDefaultAccount != null || mPreferences.contains(mDefaultAccountKey);
     }
 
     /**
@@ -440,15 +391,6 @@ public class ContactsPreferences implements OnSharedPreferenceChangeListener {
                 setDefaultAccount(accountWithDataSet);
             }
         }
-
-        if (mPreferences.contains(mDefaultAccountKey) && getDefaultAccount() == null) {
-            String defaultAccount = mPreferences.getString(mDefaultAccountKey, null);
-            if (!TextUtils.isEmpty(defaultAccount)) {
-                final AccountWithDataSet accountWithDataSet = AccountWithDataSet.unstringify(
-                        defaultAccount);
-                setDefaultAccount(accountWithDataSet);
-            }
-        }
     }
 
 }
diff --git a/src/com/android/contacts/preference/DefaultAccountPreference.java b/src/com/android/contacts/preference/DefaultAccountPreference.java
new file mode 100644
index 000000000..d43b8d574
--- /dev/null
+++ b/src/com/android/contacts/preference/DefaultAccountPreference.java
@@ -0,0 +1,112 @@
+/*
+ * Copyright (C) 2015 The Android Open Source Project
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
+ * limitations under the License
+ */
+
+package com.android.contacts.preference;
+
+import android.app.AlertDialog;
+import android.content.Context;
+import android.content.DialogInterface;
+import android.preference.DialogPreference;
+import android.util.AttributeSet;
+import android.view.View;
+
+import com.android.contacts.model.account.AccountInfo;
+import com.android.contacts.model.account.AccountWithDataSet;
+import com.android.contacts.util.AccountsListAdapter;
+
+import java.util.List;
+
+public class DefaultAccountPreference extends DialogPreference {
+    private ContactsPreferences mPreferences;
+    private AccountsListAdapter mListAdapter;
+    private List<AccountInfo> mAccounts;
+    private int mChosenIndex = -1;
+
+    public DefaultAccountPreference(Context context) {
+        super(context);
+        prepare();
+    }
+
+    public DefaultAccountPreference(Context context, AttributeSet attrs) {
+        super(context, attrs);
+        prepare();
+    }
+
+    public void setAccounts(List<AccountInfo> accounts) {
+        mAccounts = accounts;
+        if (mListAdapter != null) {
+            mListAdapter.setAccounts(accounts, null);
+            notifyChanged();
+        }
+    }
+
+    @Override
+    protected View onCreateDialogView() {
+        prepare();
+        return super.onCreateDialogView();
+    }
+
+    private void prepare() {
+        mPreferences = new ContactsPreferences(getContext());
+        mListAdapter = new AccountsListAdapter(getContext());
+        if (mAccounts != null) {
+            mListAdapter.setAccounts(mAccounts, null);
+        }
+    }
+
+    @Override
+    protected boolean shouldPersist() {
+        return false;   // This preference takes care of its own storage
+    }
+
+    @Override
+    public CharSequence getSummary() {
+        final AccountWithDataSet defaultAccount = mPreferences.getDefaultAccount();
+        if (defaultAccount == null || mAccounts == null ||
+                !AccountInfo.contains(mAccounts, defaultAccount)) {
+            return null;
+        } else {
+            return AccountInfo.getAccount(mAccounts, defaultAccount).getNameLabel();
+        }
+    }
+
+    @Override
+    protected void onPrepareDialogBuilder(AlertDialog.Builder builder) {
+        super.onPrepareDialogBuilder(builder);
+        // UX recommendation is not to show buttons on such lists.
+        builder.setNegativeButton(null, null);
+        builder.setPositiveButton(null, null);
+        builder.setAdapter(mListAdapter, new DialogInterface.OnClickListener() {
+            @Override
+            public void onClick(DialogInterface dialog, int which) {
+                mChosenIndex = which;
+            }
+        });
+    }
+
+    @Override
+    protected void onDialogClosed(boolean positiveResult) {
+        final AccountWithDataSet currentDefault = mPreferences.getDefaultAccount();
+
+        if (mChosenIndex != -1) {
+            final AccountWithDataSet chosenAccount = mListAdapter.getItem(mChosenIndex);
+            if (!chosenAccount.equals(currentDefault)) {
+                mPreferences.setDefaultAccount(chosenAccount);
+                notifyChanged();
+            }
+        } // else the user dismissed this dialog so leave the preference unchanged.
+    }
+}
diff --git a/src/com/android/contacts/preference/DisplayOptionsPreferenceFragment.java b/src/com/android/contacts/preference/DisplayOptionsPreferenceFragment.java
index 7097be3be..fd358aa08 100644
--- a/src/com/android/contacts/preference/DisplayOptionsPreferenceFragment.java
+++ b/src/com/android/contacts/preference/DisplayOptionsPreferenceFragment.java
@@ -16,7 +16,6 @@
 
 package com.android.contacts.preference;
 
-import android.accounts.Account;
 import android.app.Activity;
 import android.app.LoaderManager;
 import android.content.BroadcastReceiver;
@@ -26,21 +25,17 @@ import android.content.CursorLoader;
 import android.content.Intent;
 import android.content.IntentFilter;
 import android.content.Loader;
-import android.content.pm.PackageManager;
-import android.content.pm.ResolveInfo;
 import android.content.res.Resources;
 import android.database.Cursor;
 import android.icu.text.MessageFormat;
 import android.net.Uri;
 import android.os.Bundle;
-import android.os.StrictMode;
 import android.preference.Preference;
 import android.preference.PreferenceFragment;
 import android.provider.BlockedNumberContract;
 import android.provider.ContactsContract.Contacts;
 import android.provider.ContactsContract.DisplayNameSources;
 import android.provider.ContactsContract.Profile;
-import android.provider.ContactsContract.Settings;
 import com.google.android.material.snackbar.Snackbar;
 import androidx.localbroadcastmanager.content.LocalBroadcastManager;
 import android.telecom.TelecomManager;
@@ -64,13 +59,11 @@ import com.android.contacts.list.ContactListFilterController;
 import com.android.contacts.logging.ScreenEvent.ScreenType;
 import com.android.contacts.model.AccountTypeManager;
 import com.android.contacts.model.account.AccountInfo;
-import com.android.contacts.model.account.AccountWithDataSet;
 import com.android.contacts.model.account.AccountsLoader;
 import com.android.contacts.util.AccountFilterUtil;
 import com.android.contacts.util.ImplicitIntentsUtil;
 import com.android.contactsbind.HelpUtils;
 
-import java.util.Collections;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Locale;
@@ -83,7 +76,6 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
         implements Preference.OnPreferenceClickListener, AccountsLoader.AccountsListener {
 
     private static final int REQUEST_CODE_CUSTOM_CONTACTS_FILTER = 0;
-    private static final int REQUEST_CODE_SET_DEFAULT_ACCOUNT_CP2 = 1;
 
     private static final String ARG_CONTACTS_AVAILABLE = "are_contacts_available";
     private static final String ARG_NEW_LOCAL_PROFILE = "new_local_profile";
@@ -155,8 +147,6 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
     private ViewGroup mRootView;
     private SaveServiceResultListener mSaveServiceListener;
 
-    private List<AccountInfo> accounts = Collections.emptyList();
-
     private final LoaderManager.LoaderCallbacks<Cursor> mProfileLoaderListener =
             new LoaderManager.LoaderCallbacks<Cursor>() {
 
@@ -259,12 +249,6 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
             customFilterPreference.setOnPreferenceClickListener(this);
             setCustomContactsFilterSummary();
         }
-
-        final Preference defaultAccountPreference = findPreference(KEY_DEFAULT_ACCOUNT);
-        if (defaultAccountPreference != null) {
-            defaultAccountPreference.setOnPreferenceClickListener(this);
-            defaultAccountPreference.setSummary(getDefaultAccountSummary());
-        }
     }
 
     @Override
@@ -330,10 +314,9 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
     @Override
     public void onAccountsLoaded(List<AccountInfo> accounts) {
         // Hide accounts preferences if no writable accounts exist
-        this.accounts = accounts;
-        final Preference defaultAccountPreference =
-                findPreference(KEY_DEFAULT_ACCOUNT);
-        defaultAccountPreference.setSummary(getDefaultAccountSummary());
+        final DefaultAccountPreference preference =
+                (DefaultAccountPreference) findPreference(KEY_DEFAULT_ACCOUNT);
+        preference.setAccounts(accounts);
     }
 
     @Override
@@ -401,13 +384,6 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
                     ContactListFilterController.getInstance(getContext()).getFilter();
             AccountFilterUtil.startAccountFilterActivityForResult(
                     this, REQUEST_CODE_CUSTOM_CONTACTS_FILTER, filter);
-        } else if (KEY_DEFAULT_ACCOUNT.equals(prefKey)) {
-            String packageName = getSetDefaultAccountActivityPackage();
-            Intent intent = new Intent(Settings.ACTION_SET_DEFAULT_ACCOUNT);
-            if (packageName != null) {
-                intent.setPackage(packageName);
-                startActivityForResult(intent, REQUEST_CODE_SET_DEFAULT_ACCOUNT_CP2);
-            }
         }
         return false;
     }
@@ -419,12 +395,6 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
             AccountFilterUtil.handleAccountFilterResult(
                     ContactListFilterController.getInstance(getContext()), resultCode, data);
             setCustomContactsFilterSummary();
-        } else if (requestCode == REQUEST_CODE_SET_DEFAULT_ACCOUNT_CP2
-                && resultCode == Activity.RESULT_OK) {
-            final Preference defaultAccountPreference = findPreference(KEY_DEFAULT_ACCOUNT);
-            if (defaultAccountPreference != null) {
-                defaultAccountPreference.setSummary(getDefaultAccountSummary());
-            }
         } else {
             super.onActivityResult(requestCode, resultCode, data);
         }
@@ -448,34 +418,6 @@ public class DisplayOptionsPreferenceFragment extends PreferenceFragment
         }
     }
 
-    private CharSequence getDefaultAccountSummary() {
-        ContactsPreferences preferences = new ContactsPreferences(getContext());
-        AccountWithDataSet defaultAccountWithDataSet = preferences.getDefaultAccount();
-        AccountInfo defaultAccountInfo = AccountInfo.getAccount(
-                accounts, defaultAccountWithDataSet);
-        if (defaultAccountInfo != null) {
-            return defaultAccountInfo.getNameLabel();
-        } else {
-            return null;
-        }
-    }
-
-    private String getSetDefaultAccountActivityPackage() {
-        // Only preloaded Contacts App has the permission to call setDefaultAccount.
-        Intent intent = new Intent(Settings.ACTION_SET_DEFAULT_ACCOUNT);
-        PackageManager packageManager = getContext().getPackageManager();
-        List<ResolveInfo> resolveInfos = packageManager.queryIntentActivities(intent, 0);
-        for (ResolveInfo resolveInfo : resolveInfos) {
-            String packageName = resolveInfo.activityInfo.packageName;
-            if (packageManager.checkPermission(
-                    android.Manifest.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS, packageName)
-                    == PackageManager.PERMISSION_GRANTED) {
-                return packageName;
-            }
-        }
-        return null;
-    }
-
     private class SaveServiceResultListener extends BroadcastReceiver {
         @Override
         public void onReceive(Context context, Intent intent) {
diff --git a/src/com/android/contacts/preference/SetDefaultAccountActivity.java b/src/com/android/contacts/preference/SetDefaultAccountActivity.java
deleted file mode 100644
index b636ac336..000000000
--- a/src/com/android/contacts/preference/SetDefaultAccountActivity.java
+++ /dev/null
@@ -1,35 +0,0 @@
-package com.android.contacts.preference;
-
-import android.app.Activity;
-import android.os.Bundle;
-
-import com.android.contacts.R;
-import com.android.contacts.editor.SelectAccountDialogFragment;
-import com.android.contacts.model.AccountTypeManager.AccountFilter;
-import com.android.contacts.model.account.AccountWithDataSet;
-
-/** Activity to open a dialog for default account selection. */
-public final class SetDefaultAccountActivity extends Activity
-        implements SelectAccountDialogFragment.Listener {
-
-  @Override
-  protected void onCreate(Bundle savedInstanceState) {
-      super.onCreate(savedInstanceState);
-      SelectAccountDialogFragment.show(getFragmentManager(),
-              R.string.default_editor_account, AccountFilter.CONTACTS_WRITABLE, null);
-  }
-
-  @Override
-  public void onAccountChosen(AccountWithDataSet account, Bundle extraArgs) {
-      ContactsPreferences preferences = new ContactsPreferences(this);
-      preferences.setDefaultAccount(account);
-      setResult(Activity.RESULT_OK);
-      finish();
-  }
-
-  @Override
-  public void onAccountSelectorCancelled() {
-      setResult(Activity.RESULT_CANCELED);
-      finish();
-  }
-}
diff --git a/tests/src/com/android/contacts/DynamicShortcutsTests.java b/tests/src/com/android/contacts/DynamicShortcutsTests.java
index 8673c5e71..df9d33a7a 100644
--- a/tests/src/com/android/contacts/DynamicShortcutsTests.java
+++ b/tests/src/com/android/contacts/DynamicShortcutsTests.java
@@ -17,8 +17,8 @@ package com.android.contacts;
 
 import static org.hamcrest.MatcherAssert.assertThat;
 import static org.hamcrest.Matchers.equalTo;
-import static org.mockito.Matchers.anyString;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
diff --git a/tests/src/com/android/contacts/activities/SimImportActivityTest.java b/tests/src/com/android/contacts/activities/SimImportActivityTest.java
index 9e2f73b0f..4b7060fca 100644
--- a/tests/src/com/android/contacts/activities/SimImportActivityTest.java
+++ b/tests/src/com/android/contacts/activities/SimImportActivityTest.java
@@ -22,7 +22,7 @@ import static com.android.contacts.tests.ContactsMatchers.hasValueForColumn;
 import static org.hamcrest.MatcherAssert.assertThat;
 import static org.hamcrest.Matchers.allOf;
 import static org.junit.Assert.assertTrue;
-import static org.mockito.Matchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.spy;
 
diff --git a/tests/src/com/android/contacts/database/SimContactDaoTests.java b/tests/src/com/android/contacts/database/SimContactDaoTests.java
index 680ba106e..17906af3f 100644
--- a/tests/src/com/android/contacts/database/SimContactDaoTests.java
+++ b/tests/src/com/android/contacts/database/SimContactDaoTests.java
@@ -26,8 +26,8 @@ import static org.hamcrest.Matchers.allOf;
 import static org.hamcrest.Matchers.equalTo;
 import static org.junit.Assert.assertThat;
 import static org.junit.Assert.assertTrue;
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.anyString;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.when;
 
```

