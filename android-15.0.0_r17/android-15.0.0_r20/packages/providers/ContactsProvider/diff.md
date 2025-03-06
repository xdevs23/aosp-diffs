```diff
diff --git a/Android.bp b/Android.bp
index 17f5d8e5..e056c835 100644
--- a/Android.bp
+++ b/Android.bp
@@ -15,11 +15,13 @@ android_app {
         "ext",
     ],
     static_libs: [
+        "ContactsProvider-change-ids",
         "android-common",
         "com.android.vcard",
         "contactsprovider_flags_java_lib",
         "guava",
         "android.content.pm.flags-aconfig-java",
+        "android.provider.flags-aconfig-java",
     ],
 
     // The Jacoco tool analyzes code coverage when running unit tests on the
@@ -38,9 +40,18 @@ android_app {
     },
 }
 
+
+java_library {
+    name: "ContactsProvider-change-ids",
+    srcs: ["src/com/android/providers/contacts/ChangeIds.java"],
+    libs: [
+        "app-compat-annotations",
+    ],
+}
+
 platform_compat_config {
     name: "contacts-provider-platform-compat-config",
-    src: ":ContactsProvider",
+    src: ":ContactsProvider-change-ids",
 }
 
 aconfig_declarations {
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 05b3371b..4ac4563b 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -27,6 +27,9 @@
     <!-- Permissions required for reading and logging compat changes -->
     <uses-permission android:name="android.permission.READ_COMPAT_CHANGE_CONFIG" />
     <uses-permission android:name="android.permission.LOG_COMPAT_CHANGE" />
+    <!-- Permissions required for setting default account  -->
+    <uses-permission android:name="android.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS" />
+
 
     <permission
             android:name="android.permission.SEND_CALL_LOG_CHANGE"
@@ -131,10 +134,21 @@
             </intent-filter>
         </activity>
 
+        <activity android:name=".MoveContactsToDefaultAccountActivity"
+                  android:excludeFromRecents="true"
+                  android:exported="true"
+                  android:filterTouchesWhenObscured="true"
+                  android:theme="@android:style/Theme.Material.Dialog"
+                  android:windowActionBar="false">
+            <intent-filter>
+                <action android:name="android.provider.action.MOVE_CONTACTS_TO_DEFAULT_ACCOUNT"/>
+                <category android:name="android.intent.category.DEFAULT"/>
+            </intent-filter>
+        </activity>
+
         <provider android:name=".debug.DumpFileProvider"
-            android:authorities="com.android.contacts.dumpfile"
-            android:exported="true">
-        </provider>
+                  android:authorities="com.android.contacts.dumpfile"
+                  android:exported="true"/>
 
     </application>
 </manifest>
diff --git a/OWNERS b/OWNERS
index b244519c..ddf8f853 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,6 +1,8 @@
 aibra@google.com
-omakoto@google.com
-yamasani@google.com
+oeissa@google.com
+
+# Backup for CP2
+omakoto@google.com #{LAST_RESORT_SUGGESTION}
 
 # For calllog provider
 breadley@google.com
diff --git a/contactsprovider_flags.aconfig b/contactsprovider_flags.aconfig
index 7eee666a..22498b6c 100644
--- a/contactsprovider_flags.aconfig
+++ b/contactsprovider_flags.aconfig
@@ -25,3 +25,15 @@ flag {
     description: "Refactor to update search index during account removal and contact aggregation"
     bug: "363260703"
 }
+flag {
+    name: "disable_move_to_ineligible_default_account_flag"
+    namespace: "contacts"
+    description: "Disable move api to ineligible cloud default accounts"
+    bug: "372270980"
+}
+flag {
+    name: "cp2_account_move_delete_non_common_data_rows_flag"
+    namespace: "contacts"
+    description: "Delete data rows not included in CommonDataKinds when moving between account types"
+    bug: "330324156"
+}
\ No newline at end of file
diff --git a/res/values-af/arrays.xml b/res/values-af/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-af/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index b3d1c7e6..e7ad3299 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontakte"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Ander"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Stemboodskap van "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sinkroniseer bestaande kontakte?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Jy kan %1$s sinkroniseer om te verseker dat hulle na %2$s (%3$s) gerugsteun is"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# bestaande kontak}other{# bestaande kontakte}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinkroniseer"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Moenie sinkroniseer nie"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopieer kontaktedatabasis"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Jy is op die punt om 1) \'n afskrif van jou databasis te maak wat alle inligting insluit wat verband hou met kontakte en alle oproeploglêers na die interne berging, en 2) dit te e-pos. Onthou om die kopie uit te vee sodra jy dit suksesvol van die toestel af gekopieer het, of sodra die e-pos ontvang is."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Vee nou uit"</string>
diff --git a/res/values-am/arrays.xml b/res/values-am/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-am/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index c16cd152..29e0f210 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"እውቅያዎች"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"ሌላ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ከ....የድምፅ መልዕክት "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ነባር ዕውቂያዎች ይስመሩ?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"ወደ %2$s (%3$s) ምትኬ እንደተቀመጠላቸው ለማረጋገጥ %1$s ማስመር ይችላሉ"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# ነባር ዕውቂያ}one{# ነባር ዕውቂያ}other{# ነባር ዕውቂያዎች}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"አስምር"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"አታመሳስል"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"የእውቂያዎች የውሂብ ጎታ ገልብጥ"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"ይህንን ሊያደርጉ ነው፦ 1) ሁሉንም ከእውቂያዎች ጋር የተያያዙ መረጃዎችንና ሁሉንም የጥሪ ምዝግብ ማስታወሻዎችን የያዘው የውሂብ ጎታዎ ቅጂ በውስጣዊ ማከማቻው ላይ ሊያስቀምጡ ነው፤ እና 2) በኢሜይል ሊልኩት። ከመሣሪያው በተገለበጠ ጊዜ ወይም ኢሜይሉ ሲደርስ ወዲያውንኑ ቅጂውን መሰረዝ እንዳለብዎት ያስታውሱ።"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"አሁን ሰርዝ"</string>
diff --git a/res/values-ar/arrays.xml b/res/values-ar/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ar/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index d142f75b..f31f984d 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"جهات الاتصال"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"غير ذلك"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"بريد صوتي من "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"هل تريد مزامنة جهات الاتصال الحالية؟"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"‏يمكنك مزامنة %1$s لضمان الاحتفاظ بنسخة احتياطية منها في %2$s‏ (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{جهة اتصال واحدة حالية}zero{‫# جهة اتصال حالية}two{جهتي اتصال حاليتين}few{‫# جهات اتصال حالية}many{‫# جهة اتصال حالية}other{‫# جهة اتصال حالية}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"مزامنة"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"عدم المزامنة"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"نسخ قاعدة بيانات جهات الاتصال"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"أنت على وشك 1) إنشاء نسخة من قاعدة بياناتك التي تتضمن جميع المعلومات المرتبطة بجهات الاتصال وجميع سجلات المكالمات إلى وحدة التخزين الداخلية و2) إرسالها بالبريد الإلكتروني. تذكر حذف النسخة بمجرد إتمام نسخها من الجهاز أو تلقي الرسالة الإلكترونية."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"الحذف الآن"</string>
diff --git a/res/values-as/arrays.xml b/res/values-as/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-as/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 7843081c..7ce7e47c 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"সম্পর্কসূচী"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"অন্যান্য"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ইয়াৰ পৰা অহা ভইচমেল "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ইতিমধ্যে থকা সম্পৰ্কসমূহ ছিংক কৰিবনে?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"আপুনি %1$sক ছিংক কৰিব পাৰে যাতে সেইসমূহ %2$s (%3$s)ত বেক আপ কৰা বুলি নিশ্চিত কৰিব পাৰি"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# টা ইতিমধ্যে থকা সম্পৰ্ক}one{# টা ইতিমধ্যে থকা সম্পৰ্ক}other{# টা ইতিমধ্যে থকা সম্পৰ্ক}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ছিংক কৰক"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ছিংক নকৰিব"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"সম্পৰ্কসূচীৰ ডেটাবেছ প্ৰতিলিপি কৰক"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"আপুনি এই কাৰ্যবোৰ কৰিবলৈ লৈছে ১) আটাইবোৰ সম্পৰ্ক সম্বন্ধীয় তথ্য আৰু কল লগ সন্নিবিষ্ট থকা আপোনাৰ ডেটাবেছক আভ্য়ন্তৰীণ ষ্ট’ৰেজলৈ প্ৰতিলিপি কৰা আৰু ২) ইয়াক ইমেইল কৰা। ডিভাইচৰ পৰা সফলতাৰে প্ৰতিলিপি কৰাৰ বা ইমেইল পোৱাৰ পাছত উক্ত প্ৰতিলিপি মচিবলৈ নাপাহৰিব।"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"এতিয়াই মচক"</string>
diff --git a/res/values-az/arrays.xml b/res/values-az/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-az/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 9088a5c2..05d00e10 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontaktlar"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Digər"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Səsli mesaj göndərən: "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Mövcud kontaktlar sinxronlaşdırılsın?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s sinxronlaşdıraraq %2$s (%3$s) hesabına yedəkləndiyinə əmin olun"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# mövcud kontakt}other{# mövcud kontakt}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinxronlaşdırın"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Sinxronlaşdırmayın"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kontakt data bazasını kopyalayın"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Siz 1) informasiyaya və daxili yaddaş ehtiyatındakı zəng jurnalına bağlı data bazanızın nüsxəsini hazırlamaq 2) və onu e-poçt ilə göndərmək üzrəsiniz. Onu cihazdan kənarda və ya alınmış e-məktubda uğurla kopyalayandan sonra nüsxəsini silməyi unutmayın."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"İndi silin"</string>
diff --git a/res/values-b+sr+Latn/arrays.xml b/res/values-b+sr+Latn/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-b+sr+Latn/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index b9427e4c..39edec9c 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontakti"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Drugo"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Govorna pošta od "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Želite da sinhronizujete postojeće kontakte?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Možete da sinhronizujete %1$s da biste se uverili da se rezervne kopije prave na %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# postojeći kontakt}one{# postojeći kontakti}few{# postojeća kontakta}other{# postojećih kontakata}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinhronizuj"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nemoj da sinhronizuješ"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiranje baze podataka sa kontaktima"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Upravo ćete 1) napraviti kopiju baze podataka koja sadrži sve informacije u vezi sa kontaktima i celokupnu evidenciju poziva u internoj memoriji i 2) poslati je imejlom. Ne zaboravite da izbrišete kopiju čim je budete kopirali sa uređaja ili čim budete primili imejl."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Izbriši odmah"</string>
diff --git a/res/values-be/arrays.xml b/res/values-be/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-be/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 0eeb7d44..d5e6fad1 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Кантакты"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Іншае"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Галасавое паведамленне ад "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Сінхранізаваць існуючыя кантакты?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Вы можаце сінхранізаваць %1$s, каб гарантаваць рэзервовае капіраванне ва ўліковы запіс %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# існуючы кантакт}one{# існуючы кантакт}few{# існуючыя кантакты}many{# існуючых кантактаў}other{# існуючага кантакту}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Сінхранізаваць"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Не сінхранізаваць"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Капiраваць базу дадзеных кантактаў"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Вы збіраецеся 1) зрабіць копію базы дадзеных, якая ўключае ў сябе ўсе звесткi пра кантакты і званкi на ўнутранай памяці, і 2) адправiць яго па электроннай пошце. Не забудзьцеся выдаліць копію, як толькі вы паспяхова скапіруеце іх на прыладу ці атрымаеце па электроннай пошце."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Выдаліць зараз"</string>
diff --git a/res/values-bg/arrays.xml b/res/values-bg/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-bg/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index fe07e03c..a9c6e87d 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Контакти"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Други"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Гласова поща от "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Да се синхронизират ли съществуващите контакти?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Можете да синхронизирате %1$s, за да бъдат създадени съответните резервни копия в %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# съществуващ контакт}other{# съществуващи контакта}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синхронизиране"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Без синхронизиране"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Копиране на базата от данни на контактите"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"На път сте 1) да направите копие във вътрешното хранилище на базата си от данни, което включва цялата свързана с контактите информация и всички списъци с обаждания, и 2) да го изпратите по имейл. Не забравяйте да го изтриете веднага след като го копирате успешно от устройството или когато имейлът е получен."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Изтриване сега"</string>
diff --git a/res/values-bn/arrays.xml b/res/values-bn/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-bn/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 49646f3f..f535108b 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"পরিচিতিগুলি"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"অন্যান্য"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"এর থেকে ভয়েসমেল "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"বর্তমান পরিচিতি সিঙ্ক করতে চান?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s যাতে %2$s (%3$s)-এ ব্যাক-আপ করা যায় তা নিশ্চিত করতে, আপনি এটি সিঙ্ক করতে পারবেন"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{#টি বর্তমান পরিচিতি}one{#টি বর্তমান পরিচিতি}other{#টি বর্তমান পরিচিতি}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"সিঙ্ক করুন"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"সিঙ্ক করবেন না"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"পরিচিতির ডেটাবেস কপি করুন"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"আপনি ১) আপনার ডেটাবেসের সমস্ত পরিচিতি সংক্রান্ত তথ্য এবং অভ্যন্তরীণ সংগ্রহস্থলের সমস্ত কল লগ রয়েছে এমন একটি অনুলিপি, এবং ২) এটিকে ইমেল করতে চলেছেন৷ আপনি ডিভাইস থেকে সফলভাবে অনুলিপি করে এবং ইমেলটি পেয়ে যাবার সাথে সাথে অনুলিপিটি মুছে ফেলতে ভুলবেন না৷"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"এখনই মুছে দিন"</string>
diff --git a/res/values-bs/arrays.xml b/res/values-bs/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-bs/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index a8d402dc..0389ff35 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontakti"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Ostalo"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Govorna pošta od "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sinhronizirati postojeće kontakte?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Možete sinhronizirati %1$s da osigurate da se napravi sigurnosna kopija na usluzi %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# postojeći kontakt}one{# postojeći kontakt}few{# postojeća kontakta}other{# postojećih kontakata}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinhroniziraj"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nemoj sinhronizirati"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiraj bazu podataka kontakata"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Upravo ćete 1) napraviti kopiju svoje baze podataka koja sadrži sve informacije o kontaktima i sve zapisnike poziva u unutrašnjoj pohrani i 2) poslati tu kopiju e-poštom. Ne zaboravite izbrisati kopiju čim je uspješno kopirate s uređaja ili čim primite e-poruku."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Izbriši sada"</string>
diff --git a/res/values-ca/arrays.xml b/res/values-ca/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ca/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 9802e659..9bb890fb 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contactes"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Altres"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Missatge de veu de "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vols sincronitzar els contactes existents?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Pots sincronitzar %1$s per assegurar-te que se\'n creï una còpia de seguretat a %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contacte existent}other{# contactes existents}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronitza"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"No sincronitzis"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copia la base de dades de contactes"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Estàs a punt de: 1) fer una còpia de la teva base de dades, que inclou tota la informació relacionada amb els contactes i tots els registres de trucades de l\'emmagatzematge intern, i 2) d\'enviar-la per correu electrònic. Recorda suprimir la còpia de seguida que l\'hagis copiat correctament al dispositiu o quan hagis rebut el correu electrònic."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Suprimeix ara"</string>
diff --git a/res/values-cs/arrays.xml b/res/values-cs/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-cs/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 47fc9312..1bf42b3c 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontakty"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Jiné"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Hlasová zpráva od uživatele "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Synchronizovat stávající kontakty?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Můžete synchronizovat %1$s, aby došlo k zálohování do: %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# stávající kontakt}few{# stávající kontakty}many{# stávajícího kontaktu}other{# stávajících kontaktů}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchronizovat"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nesynchronizovat"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopírování databáze kontaktů"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Chystáte se 1) vytvořit v interním úložišti kopii databáze obsahující všechny informace o kontaktech a veškerou historii hovorů a 2) odeslat ji e-mailem. Po úspěšném zkopírování ze zařízení nebo přijetí e-mailem ji nezapomeňte ihned odstranit."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Smazat teď"</string>
diff --git a/res/values-da/arrays.xml b/res/values-da/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-da/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 1b8b54e4..9a70c6cd 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontakter"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Andre"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Telefonsvarerbesked fra "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vil du synkronisere eksisterende kontakter?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Du kan synkronisere %1$s for at sikre, at de sikkerhedskopieres til %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# eksisterende kontakt}one{# eksisterende kontakt}other{# eksisterende kontakter}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synkroniser"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Synkroniser ikke"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiér database med kontakter"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Du er ved at 1) lave en kopi af din database, som indeholder alle oplysninger om dine kontakter og al opkaldshistorik, til det interne lager, og 2) sende den som mail. Husk at slette kopien, så snart du har kopieret den fra enheden, eller mailen er modtaget."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Slet nu"</string>
diff --git a/res/values-de/arrays.xml b/res/values-de/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-de/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index eb68085d..9c321d85 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontakte"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Sonstige"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Mailboxnachricht von "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vorhandene Kontakte synchronisieren?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"#%1$s können synchronisiert werden, um sicherzustellen, dass sie in %2$s (%3$s) gesichert werden"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# vorhandener Kontakt}other{# vorhandene Kontakte}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchronisieren"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nicht synchronisieren"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kontaktdatenbank kopieren"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Du 1) erstellst eine Kopie deiner Datenbank, die alle Kontaktinformationen und Anruflisteneinträge auf dem internen Speicher enthält, und 2) sendest diese Kopie per E-Mail. Denke daran, die Kopie so schnell wie möglich zu löschen, nachdem du sie vom Gerät kopiert hast oder die E-Mail empfangen wurde."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Jetzt löschen"</string>
diff --git a/res/values-el/arrays.xml b/res/values-el/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-el/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index faa014a1..f22fb79b 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Επαφές"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Άλλο"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Μήνυμα αυτόματου τηλεφωνητή από "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Συγχρονισμός υπαρχουσών επαφών;"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Μπορείτε να συγχρονίσετε %1$s για να διασφαλίσετε ότι έχουν δημιουργηθεί αντίγραφα ασφαλείας στο %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# υπάρχουσα επαφή}other{# υπάρχουσες επαφές}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Συγχρονισμός"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Χωρίς συγχρονισμό"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Αντιγραφή βάσης δεδομένων επαφών"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Πρόκειται να 1) δημιουργήσετε ένα αντίγραφο της βάσης δεδομένων σας το οποίο περιλαμβάνει όλες τις πληροφορίες που σχετίζονται με τις επαφές και όλα τα αρχεία καταγραφής κλήσεων στον εσωτερικό αποθηκευτικό χώρο και να το 2) αποστείλετε με μήνυμα ηλεκτρονικού ταχυδρομείου. Μην ξεχάσετε να διαγράψετε από τη συσκευή σας το αντίγραφο μόλις το αντιγράψετε επιτυχώς ή μόλις παραδοθεί το μήνυμα ηλεκτρονικού ταχυδρομείου."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Διαγραφή τώρα"</string>
diff --git a/res/values-en-rAU/arrays.xml b/res/values-en-rAU/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-en-rAU/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index c62b699a..bd654c15 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contacts"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Other"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Voicemail from "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sync existing contacts?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"You can sync %1$s to ensure that they\'re backed up to %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# existing contact}other{# existing contacts}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sync"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Don\'t sync"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copy contacts database"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"You are about to 1) make a copy of your database which includes all contacts related information and all call log to the internal storage, and 2) email it. Remember to delete the copy as soon as you have successfully copied it off the device or the email is received."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Delete now"</string>
diff --git a/res/values-en-rCA/arrays.xml b/res/values-en-rCA/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-en-rCA/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 4b621199..a2be51f5 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contacts"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Other"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Voicemail from "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sync existing contacts?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"You can sync %1$s to ensure they\'re backed up to %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# existing contact}other{# existing contacts}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sync"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Don\'t sync"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copy contacts database"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"You are about to 1) make a copy of your database which includes all contacts related information and all call log to the internal storage, and 2) email it. Remember to delete the copy as soon as you have successfully copied it off the device or the email is received."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Delete now"</string>
diff --git a/res/values-en-rGB/arrays.xml b/res/values-en-rGB/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-en-rGB/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index c62b699a..bd654c15 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contacts"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Other"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Voicemail from "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sync existing contacts?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"You can sync %1$s to ensure that they\'re backed up to %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# existing contact}other{# existing contacts}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sync"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Don\'t sync"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copy contacts database"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"You are about to 1) make a copy of your database which includes all contacts related information and all call log to the internal storage, and 2) email it. Remember to delete the copy as soon as you have successfully copied it off the device or the email is received."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Delete now"</string>
diff --git a/res/values-en-rIN/arrays.xml b/res/values-en-rIN/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-en-rIN/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index c62b699a..bd654c15 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contacts"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Other"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Voicemail from "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sync existing contacts?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"You can sync %1$s to ensure that they\'re backed up to %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# existing contact}other{# existing contacts}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sync"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Don\'t sync"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copy contacts database"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"You are about to 1) make a copy of your database which includes all contacts related information and all call log to the internal storage, and 2) email it. Remember to delete the copy as soon as you have successfully copied it off the device or the email is received."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Delete now"</string>
diff --git a/res/values-en-rXC/arrays.xml b/res/values-en-rXC/arrays.xml
deleted file mode 100644
index 9df5737d..00000000
--- a/res/values-en-rXC/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‎‏‎‎‏‏‏‏‏‏‏‏‏‏‎‎‎‏‎‏‏‏‏‎‏‎‎‏‎‎‎‏‎‎‏‎‏‏‎‎‎‏‎‏‎‎‏‎‎‎‏‎‎‎‎‏‏‏‎‎‏‏‎‎‎‎‎‏‎‏‏‏‎‏‎‎com.google‎‏‎‎‏‎"</item>
-  </string-array>
-</resources>
diff --git a/res/values-es-rUS/arrays.xml b/res/values-es-rUS/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-es-rUS/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 603e6d60..f87c885e 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contactos"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Otro"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Mensaje de voz de "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"¿Quieres sincronizar los contactos existentes?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Puedes sincronizar %1$s para garantizar que se cree una copia de seguridad en %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contacto existente}other{# contactos existentes}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizar"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"No sincronizar"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiar base de datos de contactos"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Estás a punto de 1) copiar tu base datos, que incluye información de todos los contactos y el registro de todas las llamadas, en el almacenamiento interno; y de 2) enviar la copia por correo. Recuerda borrar la copia inmediatamente después de guardarla fuera del dispositivo o de que se reciba el correo."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Borrar ahora"</string>
diff --git a/res/values-es/arrays.xml b/res/values-es/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-es/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 8157199c..38edd14f 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contactos"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Otro"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Mensaje de voz de "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"¿Sincronizar contactos?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Puedes sincronizar %1$s para asegurarte de que hay una copia de seguridad en %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contacto}other{# contactos}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizar"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"No sincronizar"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiar base de datos de contactos"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Vas a 1) hacer una copia de tu base de datos, que incluye la información relacionada con tus contactos y el registro de llamadas, en el almacenamiento interno y a 2) enviarla por correo electrónico. No olvides eliminar la copia en cuanto la hayas copiado en otro dispositivo o hayas recibido el correo electrónico."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Eliminar ahora"</string>
diff --git a/res/values-et/arrays.xml b/res/values-et/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-et/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index bcaedf7a..86108642 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontaktid"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Muu"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Kõnepost kontaktilt "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Kas sünkroonida olemasolevad kontaktid?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Saate sünkroonida %1$s, et tagada nende varundamine asukohas %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# olemasolev kontakt}other{# olemasolevat kontakti}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sünkrooni"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ära sünkrooni"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kontaktide andmebaasi kopeerimine"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Soovite teha 1) sisemisse salvestusruumi koopia andmebaasist, mis sisaldab kogu kontaktidega seotud teavet ja kõikide kõnede logi ning 2) saata koopia meiliga. Kustutage koopia niipea, kui olete selle seadmest kopeerinud või meil on kohale jõudnud."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Kustuta kohe"</string>
diff --git a/res/values-eu/arrays.xml b/res/values-eu/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-eu/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index b1c74313..d3d8ee41 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontaktuak"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Beste bat"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Mezu bat utzi du erantzungailuan honek: "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Lehendik dauden kontaktuak sinkronizatu nahi dituzu?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s sinkronizatzeko aukera duzu, %2$s zerbitzuan babeskopia dutela ziurtatzeko (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{Lehendik dagoen # kontaktu}other{Lehendik dauden # kontaktu}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinkronizatu"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ez sinkronizatu"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiatu kontaktuen datu-basea"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Bi gauza egitera zoaz: 1) kontaktuekin erlazionatutako informazio guztia eta deien erregistro osoa jasotzen dituen datu-basearen kopia bat egingo duzu eta barneko memorian gordeko duzu eta 2) posta elektronikoz bidaliko duzu. Gogoratu kopia ezabatu behar duzula gailutik kopiatu edo mezu elektronikoa jaso bezain laster."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Ezabatu"</string>
diff --git a/res/values-fa/arrays.xml b/res/values-fa/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-fa/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index b35d7cae..370d96c7 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"مخاطبین"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"سایر موارد"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"پست صوتی از "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"مخاطبین موجود همگام‌سازی شوند؟"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"‏می‌توانید %1$s را همگام‌سازی کنید تا مطمئن شوید در ‏%2$s ‏(%3$s) پشتیبان‌گیری می‌شوند."</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# مخاطب موجود}one{# مخاطب موجود}other{# مخاطب موجود}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"همگام‌سازی"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"همگام‌سازی نشود"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"کپی پایگاه داده مخاطبین"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"شما در شرف ۱) ایجاد یک نسخه از پایگاه داده‌ در حافظه داخلی هستید، این کپی حاوی همه اطلاعات مربوط به مخاطبین و همه گزارش‌های تماس است و همچنین می‌خواهید ۲) آن را ایمیل کنید. به‌خاطر داشته باشید که به محض تهیه این نسخه در دستگاه یا دریافت ایمیل، آن را حذف کنید."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"اکنون حذف شود"</string>
diff --git a/res/values-fi/arrays.xml b/res/values-fi/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-fi/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 29ce0104..032887b9 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Yhteystiedot"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Muu"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Vastaajaviesti henkilöltä "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Synkronoidaanko nykyiset kontaktit?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Voit synkronoida %1$s ja varmistaa varmuuskopioitumisen (%2$s – %3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# nykyinen kontakti}other{# nykyistä kontaktia}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synkronoi"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Älä synkronoi"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopioi kontaktitietokanta"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Olet aikeissa 1) tehdä sisäiseen tallennustilaan kopion tietokannasta, joka sisältää kaikki yhteystietoihin liittyvät tiedot ja puhelulokit ja 2) lähettää sen. Muista poistaa kopio heti kopioituasi sen laitteelta tai kun sähköposti on vastaanotettu."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Poista nyt"</string>
diff --git a/res/values-fr-rCA/arrays.xml b/res/values-fr-rCA/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-fr-rCA/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index cb7f6c8d..551505d6 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contacts"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Autre"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Message vocal de "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Synchroniser les contacts existants?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Vous pouvez synchroniser %1$s pour vous assurer qu\'ils sont sauvegardés sur %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contact existant}one{# contact existant}other{# contacts existants}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchroniser"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ne pas synchroniser"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copier la base de données de contacts"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Vous êtes sur le point de 1) faire une copie de votre base de données (qui inclut toutes les données relatives aux contacts et l\'intégralité du journal d\'appels) dans la mémoire de stockage interne, puis de 2) l\'envoyer par courriel. N\'oubliez pas de supprimer la copie une fois qu\'elle a été dupliquée ou dès que le courriel a été reçu."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Supprimer maintenant"</string>
diff --git a/res/values-fr/arrays.xml b/res/values-fr/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-fr/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 8be5ef14..a3f35789 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contacts"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Autre"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Message vocal de "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Synchroniser les contacts existants ?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Vous pouvez synchroniser %1$s pour vous assurer qu\'ils sont sauvegardés sur %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contact existant}one{# contact existant}other{# contacts existants}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchroniser"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ne pas synchroniser"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copier la base de données de contacts"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Vous êtes sur le point de 1) faire une copie de votre base de données (qui inclut toutes les données relatives aux contacts et l\'intégralité du journal d\'appels) dans la mémoire de stockage interne, puis de 2) l\'envoyer par e-mail. N\'oubliez pas de supprimer la copie une fois qu\'elle a été dupliquée ou dès que l\'e-mail a été reçu."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Supprimer"</string>
diff --git a/res/values-gl/arrays.xml b/res/values-gl/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-gl/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 121853dc..1c21366e 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contactos"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Outro"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Correo de voz de "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Queres sincronizar os contactos?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Podes sincronizar %1$s para garantir que o teñas almacenado nunha copia de seguranza en %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contacto}other{# contactos}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizar"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Non sincronizar"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiar base de datos dos contactos"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Estás a punto de 1) realizar unha copia da túa base de datos que inclúe toda a información relacionada cos contactos e todos os rexistros de chamadas no almacenamento interno, e de 2) envialo por correo electrónico. Non esquezas eliminar a copia en canto a copies correctamente fóra do dispositivo ou en canto se reciba o correo electrónico."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Eliminar agora"</string>
diff --git a/res/values-gu/arrays.xml b/res/values-gu/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-gu/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 087ccc2b..fd37d2a0 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"સંપર્કો"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"અન્ય"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"આમના તરફથી વૉઇસમેઇલ "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"શું હાલના સંપર્કો સિંક કરીએ?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%2$s (%3$s)માં તેનું બૅકઅપ લેવામાં આવ્યું હોય, તેની ખાતરી કરવા માટે તમે %1$sને સિંક કરી શકો છો"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{હાલનો # સંપર્ક}one{હાલનો # સંપર્ક}other{હાલના # સંપર્ક}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"સિંક કરો"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"સિંક કરશો નહીં"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"સંપર્કો ડેટાબેસ કૉપિ કરો"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"તમે 1) તમારા ડેટાબેસની કૉપિ આંતરિક સ્ટોરેજ પર કરવામાં છો કે જેમાં બધા સંપર્કોથી સંબંધિત માહિતી અને તમામ કૉલ લૉગ શામેલ છે અને 2) તેને ઇમેઇલ કરવામાં છો. જેમ જ તમે ઉપકરણ પરથી તેની સફળતાપૂર્વક કૉપિ કરી લો અથવા ઇમેઇલ પ્રાપ્ત થઈ જાય તે પછી કૉપિને કાઢી નાખવાનું યાદ રાખો."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"હમણાં કાઢી નાખો"</string>
diff --git a/res/values-hi/arrays.xml b/res/values-hi/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-hi/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 8ce3b7d0..11a2cc53 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"संपर्क"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"अन्य"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"इनका ध्‍वनि‍मेल: "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"क्या आपको मौजूदा संपर्कों को सिंक करना है?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s को सिंक करके, यह पक्का किया जा सकता है कि उनका बैक अप %2$s (%3$s) में सेव किया गया है"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# मौजूदा संपर्क}one{# मौजूदा संपर्क}other{# मौजूदा संपर्क}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"सिंक करें"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"सिंक न करें"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"संपर्क डेटाबेस की कॉपी बनाएं"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"आप 1) मोबाइल मेमोरी में अपने उस डेटाबेस की कॉपी बनाने वाले हैं जिसमें सभी संपर्कों से जुड़ी जानकारी और सभी कॉल लॉग शामिल हैं, और 2) उसे ईमेल करने वाले हैं. जैसे ही आप डिवाइस से इसकी कॉपी सफलतापूर्वक बना लें या ईमेल मिल जाए तो कॉपी हटाना न भूलें."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"अभी हटाएं"</string>
diff --git a/res/values-hr/arrays.xml b/res/values-hr/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-hr/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 17ee9285..9d70e24a 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontakti"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Drugo"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Govorna pošta od "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Želite li sinkronizirati postojeće kontakte?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Možete sinkronizirati %1$s kako biste bili sigurni da su ti podaci sigurnosno kopirani na %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# postojeći kontakt}one{# postojeći kontakt}few{# postojeća kontakta}other{# postojećih kontakata}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinkroniziraj"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nemoj sinkronizirati"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiranje podatkovne baze kontakata"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Upravo ćete 1) napraviti kopiju svoje baze podataka koja uključuje sve podatke koji se odnose na kontakte i sve dnevnike poziva u internoj pohrani i 2) poslat ćete tu kopiju e-poštom. Ne zaboravite izbrisati kopiju čim ju uspješno kopirate s uređaja ili čim primite e-poruku."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Izbriši sada"</string>
diff --git a/res/values-hu/arrays.xml b/res/values-hu/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-hu/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 0721d50b..0dd6e242 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Névjegyek"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Egyéb"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Hangüzenet tőle: "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Szinkronizálja a meglévő névjegyeket?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Szinkronizálhat %1$s, hogy biztonsági mentést készítsen róluk ide: %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# meglévő névjegyet}other{# meglévő névjegyet}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Szinkronizálás"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Szinkronizálás mellőzése"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Névjegyadatbázis másolása"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Ön arra készül, hogy 1) másolatot készítsen a belső tárhelyre az adatbázisról, amely magában foglalja az összes névjegyet és minden kapcsolódó adatot, valamint a hívásnaplót, illetve hogy 2) e-mailben elküldje azt. Ne feledje azonnal törölni a másolatot, amint sikeresen átmásolta a készülékről, vagy amint megkapta az e-mailt."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Törlés most"</string>
diff --git a/res/values-hy/arrays.xml b/res/values-hy/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-hy/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 2d31277f..f63fda13 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Կոնտակտներ"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Այլ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Ձայնային փոստ "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Համաժամացնե՞լ առկա կոնտակտները"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Դուք կարող եք համաժամացնել %1$s՝ համոզված լինելու, որ դրանք պահուստավորված են %2$s (%3$s) հաշվում"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# առկա կոնտակտ}one{# առկա կոնտակտ}other{# առկա կոնտակտ}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Համաժամացնել"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Չհամաժամացնել"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Պատճենել կոնտակտային տվյալների շտեմարաը"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Դուք պատրաստվում եք 1) պատճենել ձեր տվյալների շտեմարանը ներքին պահոցում, որը կներառի բոլոր կոնտակտային տվյալները և բոլոր զանգերի գրանցումները, ապա 2) ուղարկել այն էլփոստով:  Չմոռանաք սարքի վրա հաջողությամբ այդ ամենը պատճենելուց կամ էլփոստը ստանալուց հետո անհապաղ ջնջել պատճենը:"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Ջնջել հիմա"</string>
diff --git a/res/values-in/arrays.xml b/res/values-in/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-in/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 76ca82ca..7f34a223 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontak"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Lainnya"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Kotak pesan dari "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sinkronkan kontak yang ada?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Anda dapat menyinkronkan %1$s untuk memastikan data tersebut dicadangkan ke %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# kontak yang ada}other{# kontak yang ada}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinkronkan"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Jangan sinkronkan"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Salin basis data kontak"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Anda akan 1) membuat salinan basis data yang mencakup semua informasi terkait kontak dan semua log panggilan ke penyimpanan internal, dan 2) mengirimkannya sebagai email. Ingat untuk menghapus salinan secepatnya setelah Anda selesai menyalinnya dari perangkat atau saat email telah diterima."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Hapus sekarang"</string>
diff --git a/res/values-is/arrays.xml b/res/values-is/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-is/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 7e9feac0..86c64291 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Tengiliðir"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Annað"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Talhólfsskilaboð frá "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Samstilla núverandi tengiliði?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Þú getur samstillt %1$s til að tryggja að þeir séu afritaðir í %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# núverandi tengiliður}one{# núverandi tengiliður}other{# núverandi tengiliðir}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Samstilla"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ekki samstilla"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Afrita tengiliðagagnagrunn"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Þú ert um það bil að fara að 1) taka afrit af gagnagrunninum þínum, sem inniheldur allar upplýsingar um tengiliði og símtalaferilinn í heild sinni, inn á innbyggða geymslu og 2) senda þessi gögn með tölvupósti. Mundu að eyða afritinu um leið og þú hefur afritað það af tækinu eða þegar tölvupósturinn hefur komist til skila."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Eyða núna"</string>
diff --git a/res/values-it/arrays.xml b/res/values-it/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-it/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 4d52cea0..a8eff94a 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contatti"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Altro"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Messaggio vocale da "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sincronizzare i contatti esistenti?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Puoi sincronizzare %1$s per assicurarti che il backup sia stato eseguito su %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contatto esistente}other{# contatti esistenti}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizza"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Non sincronizzare"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copia database di contatti"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Stai per 1) creare una copia del tuo database che include tutte le informazioni di contatto e tutti i registri chiamate nella memoria interna e 2) inviarla tramite email. Ricorda di eliminare la copia non appena è stata correttamente copiata dal dispositivo o non appena ricevi l\'email."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Elimina adesso"</string>
diff --git a/res/values-iw/arrays.xml b/res/values-iw/arrays.xml
deleted file mode 100644
index cd38f267..00000000
--- a/res/values-iw/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"‎com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index d9f36661..d1f5f29c 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"אנשי קשר"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"אחר"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"הודעה קולית מאת "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"רוצה לסנכרן את אנשי הקשר הקיימים?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"‏רוצה לסנכרן %1$s כדי לוודא שיש לך גיבוי בחשבון %2$s ‏(%3$s)?"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{איש קשר אחד}one{‫# אנשי קשר}two{‫# אנשי קשר}other{‫# אנשי קשר}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"סנכרון"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"אני לא רוצה לסנכרן"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"העתקת מסד נתוני אנשי קשר"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"אתה עומד 1) ליצור עותק באחסון הפנימי של מסד הנתונים שכולל את כל המידע הקשור לאנשי הקשר וכל יומני השיחות, 2) לשלוח אותו באימייל. זכור למחוק את העותק מיד לאחר שתעתיק אותו בהצלחה מהמכשיר או כשהודעת האימייל מתקבלת."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"מחק עכשיו"</string>
diff --git a/res/values-ja/arrays.xml b/res/values-ja/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ja/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 4e7a44cd..e4ca3f2d 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"連絡先"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"その他"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"受信ボイスメール: "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"既存の連絡先を同期しますか？"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$sを同期して、%2$s（%3$s）にバックアップできます"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# 件の既存の連絡先}other{# 件の既存の連絡先}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"同期"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"同期しない"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"連絡先データベースをコピー"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"1）すべての連絡先関連情報とすべての通話履歴を格納したデータベースを内部ストレージにコピーし、2）メールで送信しようとしています。デバイスからのコピーが完了した時点またはメールが受信された時点ですぐにコピーを削除してください。"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"今すぐ削除"</string>
diff --git a/res/values-ka/arrays.xml b/res/values-ka/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ka/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index 28599979..3c6dff40 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"კონტაქტები"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"სხვა"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ხმოვანი ფოსტა "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"გსურთ არსებული კონტაქტების სინქრონიზაცია?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"თქვენ შეგიძლიათ, დაასინქრონოთ %1$s, რათა დარწმუნდეთ, რომ მათი სარეზერვო ასლები შექმნილია %2$s-ში (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# არსებული კონტაქტი}other{# არსებული კონტაქტი}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"სინქრონიზაცია"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"არ დასინქრონდეს"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"კონტაქტების მონაცემთა ბაზის კოპირება"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"თქვენ აპირებთ 1) შიდა მეხსიერებაში მონაცემთა ბაზის კოპირებას, რომელიც შეიცავს ყველა კონტაქტთან დაკავშირებულ ინფორმაციას და ზარების ჟურნალს და 2) მის გაგზავნას ელფოსტის საშუალებით. გახსოვდეთ, რომ კოპირების წარმატებით დასრულებისთანავე ან ელფოსტის მიღებისთანავე უნდა წაშალოთ მოწყობილობიდან ასლი."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"წაიშალოს ახლა"</string>
diff --git a/res/values-kk/arrays.xml b/res/values-kk/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-kk/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index b8cd1676..3cdc2e58 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Контактілер"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Басқа"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Келесі нөмірден келген дауыс-хабар "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Бұрыннан бар контактілерді синхрондау керек пе?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Контактіні (%1$s) синхрондай аласыз, осылайша оның сақтық көшірмесі %2$s (%3$s) аккаунтына жасалады."</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# бұрыннан бар контакт}other{# бұрыннан бар контакт}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синхрондау"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Синхрондамау"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Контактілер дерекқорын көшіру"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Сіз қазір 1) барлық контактілерге қатысты ақпаратты қамтитын дерекқорыңыздың және барлық қоңыраулар тіркелімінің көшірмесін интернет жадына сақтайсыз және 2) оларды э-пошта арқылы жібересіз. Құрылғыдан сәтті көшірілгеннен кейін немесе эл.хатты алған соң, көшірмені жоюды ұмытпаңыз."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Қазір жою"</string>
diff --git a/res/values-km/arrays.xml b/res/values-km/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-km/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 2a2b50ad..a2bb7653 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"ទំនាក់ទំនង"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"ផ្សេងៗ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"សារ​ជា​សំឡេង​ពី "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ធ្វើសម​កាលកម្ម​ទំនាក់ទំនង​ដែលមាន​ស្រាប់ឬ?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"អ្នកអាច​ធ្វើសម​កាលកម្ម %1$s ដើម្បី​ធានាថា​ទំនាក់ទំនង​ត្រូវបាន​បម្រុងទុកទៅ %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{ទំនាក់ទំនង​ដែលមានស្រាប់​ចំនួន #}other{ទំនាក់ទំនង​ដែលមានស្រាប់​ចំនួន #}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ធ្វើ​សមកាលកម្ម"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"កុំធ្វើ​សមកាលកម្ម"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"ចម្លង​មូលដ្ឋាន​ទិន្នន័យ​ទំនាក់ទំនង"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"អ្នក​ហៀបនឹង ១) ចម្លង​មូលដ្ឋាន​ទិន្នន័យ​របស់​អ្នក​ដែល​រួម​មាន​ព័ត៌មាន​ទំនាក់ទំនង និង​កំណត់ហេតុ​ហៅ​ទាំងអស់​ទៅកាន់​ឧបករណ៍​ផ្ទុក​ខាងក្នុង ២) ផ្ញើ​អ៊ីមែល​វា​។ ចងចាំ​ថា​អ្នក​ត្រូវ​លុប​ច្បាប់​ចម្លង​ភ្លាមៗ បន្ទាប់ពី​បាន​ចម្លង​ចេញពី​ឧបករណ៍ ឬ​បាន​ទទួល​អ៊ីមែល។"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"លុប​ឥឡូវ"</string>
diff --git a/res/values-kn/arrays.xml b/res/values-kn/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-kn/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 0e37eae9..2a65684a 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"ಸಂಪರ್ಕಗಳು"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"ಇತರೆ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ಇದರಿಂದ ಧ್ವನಿಮೇಲ್‌ "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕಗಳನ್ನು ಸಿಂಕ್ ಮಾಡಬೇಕೆ?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%2$s (%3$s) ಅನ್ನು ಬ್ಯಾಕಪ್ ಮಾಡಲಾಗಿದೆಯೇ ಎಂದು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಲು ನೀವು %1$s ಅನ್ನು ಸಿಂಕ್ ಮಾಡಬಹುದು"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕ}one{# ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕಗಳು}other{# ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕಗಳು}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ಸಿಂಕ್ ಮಾಡಿ"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ಸಿಂಕ್ ಮಾಡಬೇಡಿ"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"ಸಂಪರ್ಕಗಳ ಡೇಟಾಬೇಸ್‌‌ ನಕಲಿಸಿ"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"ನೀವು 1) ಎಲ್ಲಾ ಸಂಪರ್ಕಗಳ ಸಂಬಂಧಿಸಿದ ಮಾಹಿತಿಯನ್ನು ಒಳಗೊಂಡಿರುವ ನಿಮ್ಮ ಡೇಟಾಬೇಸ್ ನಕಲು ಮಾಡಲು ಮತ್ತು ಆಂತರಿಕ ಸಂಗ್ರಹಣೆಗೆ ಎಲ್ಲ ಕರೆಯ ಲಾಗ್‌ ಮಾಡಲು ಮತ್ತು 2) ಇಮೇಲ್‌‌ ಮಾಡಲಿರುವಿರಿ. ನೀವು ಸಾಧನವನ್ನು ಯಶಸ್ವಿಯಾಗಿ ನಕಲು ಮಾಡಿದ ಬಳಿಕ ಅಥವಾ ಇಮೇಲ್‌ ಸ್ವೀಕರಿಸಿದ ಕೂಡಲೇ ನಕಲು ಅಳಿಸುವುದನ್ನು ನೆನಪಿನಲ್ಲಿರಿಸಿಕೊಳ್ಳಿ."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"ಈಗ ಅಳಿಸಿ"</string>
diff --git a/res/values-ko/arrays.xml b/res/values-ko/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ko/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index d5c8a947..0d0e68dc 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"주소록"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"기타"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"음성사서함 발신자 "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"기존 연락처를 동기화할까요?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s를 동기화하여 %2$s(%3$s)에 백업할 수 있습니다."</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{기존 연락처 #개}other{기존 연락처 #개}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"동기화"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"동기화 안함"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"주소록 데이터베이스 복사"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"내부 저장소에 모든 주소록 관련 정보와 통화 기록을 포함하는 데이터베이스의 1) 사본을 만들고 2) 이메일로 보내려고 합니다. 기기 이외의 장소에 사본을 만들거나 사본의 이메일 수신이 완료된 후에는 해당 사본을 즉시 삭제하시기 바랍니다."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"지금 삭제"</string>
diff --git a/res/values-ky/arrays.xml b/res/values-ky/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ky/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 4798476d..3817137a 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Байланыштар"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Башка"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Келген үнкат "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Учурдагы байланыштар шайкештирилсинби?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Камдык көчүрмөсүн %2$s (%3$s) аккаунтуна сактоо үчүн %1$s шайкештире аласыз"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# учурдагы байланыш}other{# учурдагы байланыш}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Шайкештирүү"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Шайкештирилбесин"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Байланыштар корун көчүрүү"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Сиз буларды кылайын деп жатасыз: 1) Ичинде бардык байланыштарга тийиштүү маалыматтар жана чалуу тизмелери бар берилиштер корун тышкы сактагычка  көчүрмөлөө, 2) жана аны эмейлге жөнөтүү. Көчүрмөнү, түзмөктөн ийгиликтүү көчүрүп же эмейлден алаарыңыз менен, жок кылууну унутпаңыз."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Өчүрүү"</string>
diff --git a/res/values-lo/arrays.xml b/res/values-lo/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-lo/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 1efef338..ac1fa3d3 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"ລາຍຊື່ຜູ້ຕິດຕໍ່"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"ອື່ນໆ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ຂໍ້ຄວາມສຽງຈາກ "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ຊິ້ງລາຍຊື່ຜູ້ຕິດຕໍ່ທີ່ມີຢູ່ບໍ?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"ທ່ານສາມາດຊິ້ງ %1$s ເພື່ອໃຫ້ແນ່ໃຈວ່າມີການສຳຮອງຂໍ້ມູນດັ່ງກ່າວໄວ້ໃນ %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{ລາຍຊື່ຜູ້ຕິດຕໍ່ທີ່ມີຢູ່ # ລາຍການ}other{ລາຍຊື່ຜູ້ຕິດຕໍ່ທີ່ມີຢູ່ # ລາຍການ}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ຊິ້ງ"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ບໍ່ຕ້ອງຊິ້ງ"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"ສຳເນົາຖານຂໍ້ມູນລາຍຊື່ຜູ່ຕິດຕໍ່"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"ທ່ານກຳລັງຈະ 1) ສ້າງສຳເນົາຂອງຖານຂໍ້ມູນເຊິ່ງຈະມີ ຂໍ້ມູນທີ່ກ່ຽວຂ້ອງກັບລາຍຊື່ຜູ່ຕິດຕໍ່ ແລະບັນທຶກການໂທທັງໝົດ ເພື່ອຈັດເກັບໃນບ່ອນຈັດເກັບຂໍ້ມູນພາຍໃນ ແລະ 2) ສົ່ງມັນໄປທາງອີເມວ. ຫຼັງຈາກທ່ານສຳເນົາຂໍ້ມູນທີ່ສ້າງອອກຈາກອຸປະກອນນີ້ ຫຼືສົ່ງມັນຜ່ານທາງອີເມວສຳເລັດແລ້ວ ຢ່າລືມລຶບມັນອອກໂດຍທັນທີ."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"ລຶບອອກດຽວນີ້"</string>
diff --git a/res/values-lt/arrays.xml b/res/values-lt/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-lt/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index 2681de81..4d66d59c 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontaktai"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Kita"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Balso pašto pranešimas nuo "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sinchronizuoti esamus kontaktus?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Galite sinchronizuoti %1$s, kad užtikrintumėte atsarginių kopijų kūrimą %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# esamas kontaktas}one{# esamas kontaktas}few{# esami kontaktai}many{# esamo kontakto}other{# esamų kontaktų}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinchronizuoti"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nesinchronizuoti"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopijuoti kontaktų duomenis"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Ketinate 1. sukurti duomenų, į kuriuos įtraukta visa su kontaktais susijusi informacija ir visi skambučių žurnalai, kopiją vidinėje atmintyje ir 2. išsiųsti ją el. paštu. Nepamirškite ištrinti kopijos, kai ją sėkmingai nukopijuosite iš įrenginio ar gausite el. laišką."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Ištrinti dabar"</string>
diff --git a/res/values-lv/arrays.xml b/res/values-lv/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-lv/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 4593240a..d09d6e8a 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontaktpersonas"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Cits"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Balss pasta ziņojums no "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vai sinhronizēt esošās kontaktpersonas?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Varat sinhronizēt %1$s, lai nodrošinātu dublēšanu kontā %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# esošo kontaktpersonu}zero{# esošās kontaktpersonas}one{# esošo kontaktpersonu}other{# esošās kontaktpersonas}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinhronizēt"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nesinhronizēt"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kontaktpersonu datu bāzes kopēšana"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Jūs gatavojaties 1) iekšējā atmiņā izveidot savas datu bāzes kopiju, ietverot visu kontaktpersonu informāciju un visu zvanu žurnālu, un 2) nosūtīt to pa e-pastu. Dzēsiet kopiju, tiklīdz tā būs veiksmīgi kopēta no ierīces vai tiks saņemts attiecīgais e-pasta ziņojums."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Dzēst tūlīt"</string>
diff --git a/res/values-mk/arrays.xml b/res/values-mk/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-mk/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 84ff8712..9c11a910 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Контакти"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Друг"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Говорна пошта од "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Да се синхронизираат постојните контакти?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s може да се синхронизира за да се направи бекап во %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# постоен контакт}one{# постоен контакт}other{# постојни контакти}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синхронизирај"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Не синхронизирај"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Копирај база на податоци со контакти"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Вие 1) ќе направите копија на вашата база на податоци која ги опфаќа сите информации поврзани со контакти и сета евиденција на повици во внатрешната меморија и 2) ќе ја испратите по е-пошта. Не заборавајте да ја избришете копијата откако успешно сте ја ископирале од уредот или електронската порака е примена."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Избриши сега"</string>
diff --git a/res/values-ml/arrays.xml b/res/values-ml/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ml/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 1ed08d23..ee76a8ee 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"കോണ്‍‌ടാക്റ്റുകള്‍"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"മറ്റുള്ളവ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ഈ നമ്പറിൽ നിന്നുള്ള വോയ്‌സ്‌മെയിൽ "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"നിലവിലുള്ള കോൺടാക്റ്റുകൾ സമന്വയിപ്പിക്കണോ?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%2$s (%3$s) വരെ ബാക്കപ്പ് ചെയ്തിട്ടുണ്ടെന്ന് ഉറപ്പാക്കാൻ നിങ്ങൾക്ക് %1$s സമന്വയിപ്പിക്കാനാകും"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{നിലവിലുള്ള # കോൺടാക്റ്റ്}other{നിലവിലുള്ള # കോൺടാക്റ്റുകൾ}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"സമന്വയിപ്പിക്കുക"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"സമന്വയിപ്പിക്കരുത്"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"കോൺടാക്റ്റുകളുടെ ഡാറ്റാബേസ് പകർത്തുക"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"നിങ്ങൾ 1) എല്ലാ കോൺടാക്റ്റുകളുമായും ബന്ധപ്പെട്ട വിവരങ്ങളും എല്ലാ കോൾ ലോഗും ഉൾപ്പെടുന്ന നിങ്ങളുടെ ഡാറ്റാബേസിന്റെ ഒരു പകർപ്പ് ആന്തരിക സംഭരണത്തിൽ സൃഷ്‌ടിക്കാനും 2) അത് ഇമെയിൽ ചെയ്യാനും പോകുന്നു. ഉപകരണത്തിൽ നിന്ന് പകർപ്പ് നിങ്ങൾ പകർത്തിക്കഴിഞ്ഞാലോ ഇമെയിൽ ലഭിച്ചുകഴിഞ്ഞാലോ ഉടൻ തന്നെ അത് ഇല്ലാതാക്കാൻ ശ്രദ്ധിക്കുക."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"ഇപ്പോൾ ഇല്ലാതാക്കുക"</string>
diff --git a/res/values-mn/arrays.xml b/res/values-mn/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-mn/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 0bbd0715..92db3b2a 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Харилцагчид"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Бусад"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Дуут шуудан илгээгч "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Одоо байгаа харилцагчдыг синк хийх үү?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Та тэдгээр харилцагчийг %2$s-д (%3$s) нөөцөлсөн эсэхийг нягтлахын тулд %1$s-г синк хийх боломжтой"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{Одоо байгаа # харилцагч}other{Одоо байгаа # харилцагч}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синк хийх"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Бүү синк хий"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Харилцагчдын мэдээллийн санг хуулах"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Та 1) бүх харилцагчидтай холбоотой мэдээллүүд болон ярианы жагсаалтыг агуулсан өөрийн өгөгдлийн сангийн хуулбарыг дотоод санд хадгалах, мөн 2) имэйлдэх гэж байна. Та үүнийг төхөөрөмжөөсөө амжилттай хуулж дуусах буюу имэйлээр хүлээж авсны дараа устгах хэрэгтэйг санаарай."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Одоо устгах"</string>
diff --git a/res/values-mr/arrays.xml b/res/values-mr/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-mr/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 59246564..99a1ca37 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"संपर्क"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"इतर"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"कडून व्हॉईसमेल "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"सध्याचे संपर्क सिंक करायचे आहेत का?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"त्यांचा %2$s (%3$s) वर बॅकअप घेतला आहे याची खात्री करण्यासाठी तुम्ही %1$s सिंक करू शकता"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{सध्याचा # संपर्क}other{सध्याचे # संपर्क}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"सिंक करा"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"सिंक करू नका"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"संपर्क डेटाबेस कॉपी करा"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"तुम्ही 1) आपल्‍या डेटाबेसची प्रत बनवणार आहात जिच्‍यामध्‍ये सर्व संपर्कांसंबंधी माहिती आणि अंतर्गत संचयनावरील कॉल लॉग समाविष्‍ट असतात आणि 2) ती ईमेल करणार आहात. तुम्ही डिव्‍हाइसवरून यशस्‍वीरित्‍या प्रत कॉपी केल्‍यानंतर किंवा ईमेल प्राप्त केल्‍यानंतर लगेच ती हटविण्‍याचे लक्षात ठेवा."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"आता हटवा"</string>
diff --git a/res/values-ms/arrays.xml b/res/values-ms/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ms/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index b638974f..2ac07a06 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kenalan"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Lain-lain"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Mel suara daripada "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Segerakkan kenalan sedia ada?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Anda boleh menyegerakkan %1$s untuk memastikan %1$s disandarkan kepada %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# kenalan sedia ada}other{# kenalan sedia ada}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Segerakkan"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Jangan segerakkan"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Salin pangkalan data kenalan"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Anda akan 1) membuat salinan pangkalan data anda yang termasuk semua maklumat berkaitan kenalan dan semua log panggilan ke storan dalaman dan 2) hantar melalui e-mel. Jangan lupa untuk memadam salinan ini sebaik sahaja anda telah berjaya menyalin daripada peranti atau apabila e-mel diterima."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Padamkan sekarang"</string>
diff --git a/res/values-my/arrays.xml b/res/values-my/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-my/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 1efa6e93..0acec776 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"အဆက်အသွယ်များ"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"တစ်ခြား"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"မှ အသံစာ "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"လက်ရှိ အဆက်အသွယ်များကို စင့်ခ်လုပ်မလား။"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%2$s (%3$s) သို့ အရန်သိမ်းထားကြောင်း သေချာစေရန် %1$s ကို စင့်ခ်လုပ်နိုင်ပါသည်"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{လက်ရှိ အဆက်အသွယ် # ခု}other{လက်ရှိ အဆက်အသွယ် # ခု}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"စင့်ခ်လုပ်ရန်"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"စင့်ခ်မလုပ်ပါနှင့်"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"လိပ်စာဒေတာဘေ့စ်ကို ကူးရန်"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"သင်သည် ၁) အဆက်အသွယ်အားလုံးနှင့်ဆိုင်သော အချက်အလက်များ၊ ဖုန်းခေါ်မှု မှတ်တမ်းများ ပါဝင်သည့် ဒေတာဘေ့စ်ကို စက်တွင်းသိုလှောင်ခန်းသို့ မိတ္တူကူးပြီး ၂) အီးမေးလ်ပို့ပါတော့မည်။ စက်တွင်းမှ မိတ္တူကူးယူပြီးသည်နှင့်၊ သို့မဟုတ် အီးမေးလ်ရောက်ရှိသည်နှင့် ဤမိတ္တူကို ဖျက်ရန် မမေ့ပါနှင့်။"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"အခုဖျက်ပါ"</string>
diff --git a/res/values-nb/arrays.xml b/res/values-nb/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-nb/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index d2e13dd6..85643ac4 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontakter"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Annet"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Talemelding fra "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vil du synkronisere eksisterende kontakter?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Du kan synkronisere %1$s for å sikre at de blir sikkerhetskopiert til %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# eksisterende kontakt}other{# eksisterende kontakter}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synkroniser"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ikke synkroniser"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiér kontaktdatabasen"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Du er i ferd med å 1) lage en kopi av databasen som omfatter all kontaktrelatert informasjon og alle anropslogger til den interne lagringsplassen, og 2) sende kopien med e-post. Husk å slette kopien så snart du har kopiert den fra enheten eller når e-posten er mottatt."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Slett nå"</string>
diff --git a/res/values-ne/arrays.xml b/res/values-ne/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ne/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 844360ec..26b4a922 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"कन्ट्याक्टहरू"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"अन्य"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"बाट भ्वाइसमेल "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"विद्यमान कन्ट्याक्टहरू सिंक गर्ने हो?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s लाई %2$s (%3$s) मा ब्याकअप गर्न तपाईं तिनलाई सिंक गर्न सक्नुहुन्छ"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# विद्यमान कन्ट्याक्ट}other{# वटा विद्यमान कन्ट्याक्ट}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"सिंक गर्नुहोस्"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"सिंक नगर्नुहोस्"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"सम्पर्क डेटाबेस प्रतिलिप गर्नुहोस्"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"तपाईँले केही बेरमा १) आन्तरिक भण्डारणमा सम्पुर्ण सम्पर्क सम्बन्धी जानकारी र कल लग भएको डेटाबेसको एउटा प्रतिलिपी बनाउनुहोस्, र  2) उनीहरूलाई इमेल गर्नुहोस्। उपरकणमा प्रतिलिपीको नक्कल पार्ना साथ अथवा इमेल प्राप्त हुने बित्तिकै प्रतिलिपी मेटाउन ख्याल गर्नुहोस्।"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"अहिले हटाउनुहोस्"</string>
diff --git a/res/values-nl/arrays.xml b/res/values-nl/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-nl/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index f2bcb5ab..7edee0b2 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contacten"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Overig"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Voicemail van "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Bestaande contacten synchroniseren?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"U kunt %1$s synchroniseren om ervoor te zorgen dat er een back-up van wordt gemaakt in %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# bestaand contact}other{# bestaande contacten}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchroniseren"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Niet synchroniseren"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Contactendatabase kopiëren"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Je staat op het punt 1) een kopie van je database met alle contactgegevens en oproeplogboeken te maken in de interne opslag, en 2) deze te e-mailen. Verwijder de kopie zodra je deze van het apparaat hebt gekopieerd of de e-mail is ontvangen."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Nu verwijderen"</string>
diff --git a/res/values-or/arrays.xml b/res/values-or/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-or/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index ab8efb16..6408b2c5 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"ଯୋଗାଯୋଗ"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"ଅନ୍ଯ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ଏହାଙ୍କଠାରୁ ଭଏସମେଲ୍‌ "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ପୂର୍ବରୁ ଥିବା କଣ୍ଟାକ୍ଟଗୁଡ଼ିକୁ ସିଙ୍କ କରିବେ?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%2$s (%3$s)ରେ %1$sର ବେକଅପ ନିଆଯାଇଥିବା ସୁନିଶ୍ଚିତ କରିବାକୁ ଆପଣ ସେଗୁଡ଼ିକୁ ସିଙ୍କ କରିପାରିବେ"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{ପୂର୍ବରୁ ଥିବା # କଣ୍ଟାକ୍ଟ}other{ପୂର୍ବରୁ ଥିବା # କଣ୍ଟାକ୍ଟ}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ସିଙ୍କ କରନ୍ତୁ"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ସିଙ୍କ କରନ୍ତୁ ନାହିଁ"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"କଣ୍ଟାକ୍ଟ ଡାଟାବେସକୁ କପି କରନ୍ତୁ"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"ଆପଣ 1) ଇଣ୍ଟର୍ନଲ ଷ୍ଟୋରେଜରେ ନିଜ ଡାଟାବେସର ଏକ କପି ବନାନ୍ତୁ, ଯେଉଁଥିରେ କଣ୍ଟାକ୍ଟ ସମ୍ବନ୍ଧିତ ସମସ୍ତ ତଥ୍ୟ ଏବଂ କଲ ଲଗ ରହିବ, ଏବଂ 2) ଏହାକୁ ଇମେଲ କରନ୍ତୁ। ମନେରଖନ୍ତୁ, ଡିଭାଇସରୁ ସଫଳତାର ସହ ଏହାକୁ କପି କରିସାରିବା ପରେ କିମ୍ୱା ଇମେଲ ମିଳିବା ପରେ, ଏହି କପିକୁ ଡିଲିଟ କରିଦେବେ।"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"ବର୍ତ୍ତମାନ ଡିଲିଟ୍ କରନ୍ତୁ"</string>
diff --git a/res/values-pa/arrays.xml b/res/values-pa/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-pa/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 12a5c6e5..08df27c2 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"ਸੰਪਰਕ"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"ਹੋਰ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ਇਸ ਤੋਂ ਵੌਇਸਮੇਲ "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ਕੀ ਮੌਜੂਦਾ ਸੰਪਰਕਾਂ ਨੂੰ ਸਿੰਕ ਕਰਨਾ ਹੈ?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"ਤੁਸੀਂ ਇਹ ਪੱਕਾ ਕਰਨ ਲਈ %1$s ਨੂੰ ਸਿੰਕ ਕਰ ਸਕਦੇ ਹੋ ਕਿ ਉਨ੍ਹਾਂ ਦਾ %2$s (%3$s) ਵਿੱਚ ਬੈਕਅੱਪ ਲਿਆ ਗਿਆ ਹੈ"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# ਮੌਜੂਦਾ ਸੰਪਰਕ}one{# ਮੌਜੂਦਾ ਸੰਪਰਕ}other{# ਮੌਜੂਦਾ ਸੰਪਰਕ}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ਸਿੰਕ ਕਰੋ"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ਸਿੰਕ ਨਾ ਕਰੋ"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"ਸੰਪਰਕ ਡਾਟਾਬੇਸ ਕਾਪੀ ਕਰੋ"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"ਤੁਸੀਂ ਇਹ ਕਰਨ ਵਾਲੇ ਹੋ 1) ਆਪਣੇ ਡਾਟਾਬੇਸ ਦੀ ਇੱਕ ਕਾਪੀ ਬਣਾਓ ਜਿਸ ਵਿੱਚ ਸਾਰੀ ਸੰਪਰਕ ਸੰਬੰਧਿਤ ਜਾਣਕਾਰੀ ਅਤੇ ਅੰਦਰੂਨੀ ਸਟੋਰੇਜ ਵਿੱਚ ਸਾਰਾ ਕਾਲ ਲੌਗ ਸ਼ਾਮਲ ਹੋਵੇ ਅਤੇ 2) ਇਸਨੂੰ ਈਮੇਲ ਕਰੋ। ਜਿਵੇਂ ਹੀ ਤੁਸੀਂ ਇਸਨੂੰ ਸਫਲਤਾਪੂਰਵਕ ਕਾਪੀ ਕਰ ਲਓ ਜਾਂ ਈਮੇਲ ਪ੍ਰਾਪਤ ਕਰ ਲਓ, ਕਾਪੀ ਮਿਟਾਉਣਾ ਯਾਦ ਰੱਖੋ।"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"ਹੁਣ ਮਿਟਾਓ"</string>
diff --git a/res/values-pl/arrays.xml b/res/values-pl/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-pl/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 232b4b79..8942ec4f 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontakty"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Inne"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Poczta głosowa od "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Zsynchronizować istniejące kontakty?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Możesz zsynchronizować te dane (%1$s), aby mieć pewność, że ich kopia zapasowa jest przechowywana w usługach %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# zapisany kontakt}few{# zapisane kontakty}many{# zapisanych kontaktów}other{# zapisanego kontaktu}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchronizuj"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nie synchronizuj"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiuj bazę danych kontaktów"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Zamierzasz: 1) utworzyć w pamięci wewnętrznej kopię bazy danych ze wszystkimi informacjami o kontaktach i rejestrem połączeń, 2) wysłać ją e-mailem. Pamiętaj, by usunąć kopię zaraz po zapisaniu jej na innym nośniku lub odebraniu e-maila."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Usuń teraz"</string>
diff --git a/res/values-pt-rBR/arrays.xml b/res/values-pt-rBR/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-pt-rBR/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-pt-rBR/strings.xml b/res/values-pt-rBR/strings.xml
index 5cee4f36..49fd5616 100644
--- a/res/values-pt-rBR/strings.xml
+++ b/res/values-pt-rBR/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contatos"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Outros"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Correio de voz de "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sincronizar contatos atuais?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Sincronize %1$s para garantir que eles sejam armazenados em backup na conta %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contato atual}one{# contato atual}other{# contatos atuais}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizar"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Não sincronizar"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiar banco de dados de contatos"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Você está prestes a 1) fazer uma cópia de seu banco de dados no armazenamento interno, com todas as informações relacionadas aos contatos e todo o histórico de ligações e 2) enviar essa cópia por e-mail. Lembre-se de excluir a cópia, logo que você a tiver copiado do dispositivo ou que o e-mail for recebido."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Excluir agora"</string>
diff --git a/res/values-pt-rPT/arrays.xml b/res/values-pt-rPT/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-pt-rPT/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 8d94fbbb..08098f4b 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contactos"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Outro"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Correio de voz de "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sincronizar contactos existentes?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Pode sincronizar %1$s para garantir que é feita uma cópia de segurança em %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contacto existente}other{# contactos existentes}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizar"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Não sincronizar"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiar base de dados de contactos"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Está prestes a 1) fazer uma cópia da sua base de dados que inclui todas as informações relativas aos contactos e todo o registo de chamadas para armazenamento interno, e a 2) enviá-los por email. Não se esqueça de eliminar a cópia logo que a tenha copiado com êxito para fora do dispositivo ou que o email tenha sido recebido."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Eliminar agora"</string>
diff --git a/res/values-pt/arrays.xml b/res/values-pt/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-pt/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index 5cee4f36..49fd5616 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Contatos"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Outros"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Correio de voz de "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sincronizar contatos atuais?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Sincronize %1$s para garantir que eles sejam armazenados em backup na conta %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contato atual}one{# contato atual}other{# contatos atuais}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizar"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Não sincronizar"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiar banco de dados de contatos"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Você está prestes a 1) fazer uma cópia de seu banco de dados no armazenamento interno, com todas as informações relacionadas aos contatos e todo o histórico de ligações e 2) enviar essa cópia por e-mail. Lembre-se de excluir a cópia, logo que você a tiver copiado do dispositivo ou que o e-mail for recebido."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Excluir agora"</string>
diff --git a/res/values-ro/arrays.xml b/res/values-ro/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ro/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 3e7cb605..9866ee5e 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Agendă"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Altul"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Mesaj vocal de la "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sincronizați persoanele de contact existente?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Puteți sincroniza %1$s pentru a vă asigura că au backup în %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{O persoană de contact existentă}few{# persoane de contact existente}other{# de persoane de contact existente}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizați"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nu sincronizați"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiați baza de date a agendei"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Sunteți pe cale 1) să faceți o copie, pe stocarea internă, a bazei dvs. de date care include toate informațiile referitoare la agendă și întregul jurnal de apeluri și 2) să trimiteți această copie prin e-mail. Nu uitați să ștergeți această copie după ce ați copiat-o de pe dispozitiv sau după ce a fost primit e-mailul."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Ștergeți acum"</string>
diff --git a/res/values-ru/arrays.xml b/res/values-ru/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ru/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 75263280..fe82d8e0 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Контакты"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Другое"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Голосовое сообщение от абонента "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Синхронизировать существующие контакты?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Вы можете синхронизировать контакты (не более %1$s), чтобы создать их резервные копии в %2$s (%3$s)."</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# существующий контакт}one{# существующий контакт}few{# существующих контакта}many{# существующих контактов}other{# существующего контакта}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синхронизировать"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Не синхронизировать"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Копирование базы данных контактов"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Вы собираетесь скопировать базу данных ваших контактов и списка вызовов во внутреннюю память устройства. При этом копия базы будет отправлена по электронной почте. Обязательно удалите эти данные с устройства после того, как они будут скопированы с него либо получены в письме."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Удалить"</string>
diff --git a/res/values-si/arrays.xml b/res/values-si/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-si/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 906978b0..d431a691 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"සම්බන්ධතා"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"වෙනත්"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"හඬ තැපෑල ලැබෙන්නේ "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"පවතින සම්බන්ධතා සමමුහුර්ත කරන්න ද?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"ඔබට ඒවා %2$s (%3$s) දක්වා උපස්ථ කර ඇති බව සහතික කිරීමට %1$s සමමුහුර්ත කළ හැක"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# පවතින සම්බන්ධතාවක්}one{පවතින සම්බන්ධතා #ක්}other{පවතින සම්බන්ධතා #ක්}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"සමමුහුර්ත කරන්න"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"සමමුහූර්ත නොකරන්න"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"සම්බන්ධතා දත්ත සමුදාය පිටපත් කරන්න"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"ඔබ සදන්නේ 1) සම්බන්ධතා ආශ්‍රිත තොරතුරු සහ සියලු ඇමතුම් ලොගයේ තිබෙන ඔබගේ දත්ත සමුදායේ පිටපතක් අභ්‍යන්තර ආචයනයට ගැනීමට, සහ 2) එය ඊ-තැපැල් කිරීමටයි. ඔබ සාර්ථකව උපාංගයෙන් පිටපත් කර විට හෝ ඊ-තැපෑල ලැබුණු විට පිටපත මකා දැමීමට මතක තබාගන්න."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"දැන් මකන්න"</string>
diff --git a/res/values-sk/arrays.xml b/res/values-sk/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-sk/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index abfa1c55..6cebef99 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontakty"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Iné"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Hlasová správa od "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Chcete synchronizovať existujúce kontakty?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Môžete synchronizovať %1$s, aby sa vytvorila záloha v účte %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# existujúci kontakt}few{# existujúce kontakty}many{# existing contacts}other{# existujúcich kontaktov}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchronizovať"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nesynchronizovať"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopírovanie databázy kontaktov"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Práve sa chystáte 1) vytvoriť v internom ukladacom priestore kópiu svojej databázy, ktorá obsahuje všetky informácie týkajúce sa kontaktov a všetky hovory, a 2) poslať túto databázu e-mailom. Nezabudnite odstrániť kópiu hneď po úspešnom skopírovaní do zariadenia alebo doručení e-mailu."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Odstrániť"</string>
diff --git a/res/values-sl/arrays.xml b/res/values-sl/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-sl/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index fe5ea9ef..e78b0148 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Stiki"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Drugo"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Govorna pošta s številke "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Želite sinhronizirati obstoječe stike?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Sinhronizirate lahko %1$s, da zagotovite, da so varnostno kopirani v: %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# obstoječi stik}one{# obstoječi stik}two{# obstoječa stika}few{# obstoječi stiki}other{# obstoječih stikov}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinhroniziraj"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ne sinhroniziraj"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiraj zbirko podatkov o stikih"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"V naslednjem koraku boste 1) naredili kopijo zbirke podatkov, ki vključuje vse informacije o stikih in celoten dnevnik klicev, v notranji pomnilnik ter 2) jo poslali. Ne pozabite izbrisati kopije iz naprave, ko jo boste uspešno kopirali oziroma ko jo boste prejeli po e-pošti."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Izbriši zdaj"</string>
diff --git a/res/values-sq/arrays.xml b/res/values-sq/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-sq/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 37830ff6..8800780c 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontaktet"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Tjetër"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Postë zanore nga "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Të sinkronizohen kontaktet ekzistuese?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Mund të sinkronizosh %1$s për t\'u siguruar që është rezervuar në %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# kontakt ekzistues}other{# kontakte ekzistuese}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinkronizo"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Mos sinkronizo"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopjo bazën e të dhënave me kontaktet"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Je gati që 1) të bësh një kopje të bazës tënde të të dhënave që përfshin të gjitha informacionet në lidhje me kontaktet dhe evidencat e telefonatave në hapësirën ruajtëse të brendshme dhe 2) ta dërgosh atë me mail. Mos harro që ta fshish kopjen sapo ta kesh kopjuar me sukses nga pajisja ose të kesh marrë mail-in."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Fshi tani"</string>
diff --git a/res/values-sr/arrays.xml b/res/values-sr/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-sr/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 8230513a..2317cdfa 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Контакти"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Другo"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Говорна пошта од "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Желите да синхронизујете постојеће контакте?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Можете да синхронизујете %1$s да бисте се уверили да се резервне копије праве на %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# постојећи контакт}one{# постојећи контакти}few{# постојећа контакта}other{# постојећих контаката}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синхронизуј"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Немој да синхронизујеш"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Копирање базе података са контактима"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Управо ћете 1) направити копију базе података која садржи све информације у вези са контактима и целокупну евиденцију позива у интерној меморији и 2) послати је имејлом. Не заборавите да избришете копију чим је будете копирали са уређаја или чим будете примили имејл."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Избриши одмах"</string>
diff --git a/res/values-sv/arrays.xml b/res/values-sv/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-sv/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index e1d20231..4589f3fb 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontakter"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Övrigt"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Röstmeddelande från "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vill du synkronisera befintliga kontakter?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Du kan synkronisera %1$s för att säkerställa säkerhetskopiering till %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# befintlig kontakt}other{# befintliga kontakter}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synkronisera"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Synkronisera inte"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiera kontaktdatabas"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Du kommer att 1) kopiera din databas, inklusive alla kontaktuppgifter och samtalsloggar till det interna lagringsutrymmet, och 2) skicka det via e-post. Kom ihåg att ta bort kopian från enheten när kopieringen har slutförts eller när du har fått e-postmeddelandet."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Ta bort nu"</string>
diff --git a/res/values-sw/arrays.xml b/res/values-sw/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-sw/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 92bd391f..6c9db339 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Anwani"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Nyingineyo"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Barua ya sauti kutoka "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Ungependa kusawazisha anwani zilizopo?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Unaweza kusawazisha %1$s ili uhakikishe kuwa nakala zimehifadhiwa kwenye %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{Anwani # iliyopo}other{Anwani # zilizopo}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sawazisha"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Usisawazishe"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Nakili hifadhidata ya anwani"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Unaelekea 1) kuunda nakala ya hifadhidata yako ambayo inajumuisha maelezo yote yanayohusiana na anwani na kumbukumbu zote za simu katika hifadhi ya ndani, na 2) uitume kwa barua pepe. Kumbuka kufuta nakala pindi tu utakapomaliza kuinakili kutoka kwenye kifaa au barua pepe itakapopokewa."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Futa sasa"</string>
diff --git a/res/values-ta/arrays.xml b/res/values-ta/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ta/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 4b7bd769..067d22f5 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"தொடர்புகள்"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"மற்றவை"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"இவரிடமிருந்து குரலஞ்சல் "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ஏற்கெனவே உள்ள தொடர்புகளை ஒத்திசைக்க வேண்டுமா?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%2$s (%3$s) இல் காப்புப் பிரதி எடுக்கப்பட்டிருப்பதை உறுதிசெய்ய %1$s ஐ ஒத்திசைக்கலாம்"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{ஏற்கெனவே உள்ள தொடர்பு: #}other{ஏற்கெனவே உள்ள தொடர்புகள்: #}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ஒத்திசை"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ஒத்திசைக்காதே"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"தொடர்புகளின் தரவுத்தளத்தை நகலெடு"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"நீங்கள் செய்யக்கூடியவை 1) தொடர்புகள் தொடர்பான எல்லா தகவலும், அழைப்பின் எல்லா பதிவையும் உள்ளடக்கும் உங்கள் தரவுத்தளத்தை அகச் சேமிப்பிடத்தில் நகலெடுக்கலாம், பின்னர் 2) அதை மின்னஞ்சல் செய்யலாம். அதைச் சாதனத்திலிருந்து வெற்றிகரமாக நகலெடுத்தவுடன் அல்லது மின்னஞ்சலைப் பெற்றவுடன் அதன் நகலை மறக்காமல் நீக்கிவிடவும் செய்யலாம்."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"இப்போதே நீக்கு"</string>
diff --git a/res/values-te/arrays.xml b/res/values-te/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-te/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 951bad9c..ef4ca175 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"కాంటాక్ట్‌లు"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"ఇతరం"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"దీని నుండి వాయిస్ మెయిల్ "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ఇప్పటికే ఉన్న కాంటాక్ట్‌లను సింక్ చేయాలా?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"మీరు %1$s‌ను సింక్ చేసి, అవి %2$s (%3$s)లో బ్యాకప్ అయ్యేలా చూసుకోవచ్చు"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{ఇప్పటికే ఉన్న # కాంటాక్ట్}other{ఇప్పటికే ఉన్న # కాంటాక్ట్‌లు}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"సింక్ చేయండి"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"సింక్ చేయవద్దు"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"కాంటాక్ట్‌ల డేటాబేస్‌ను కాపీ చేయండి"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"మీరు 1) అన్ని కాంటాక్ట్‌లకు సంబంధించిన సమాచారాన్ని మరియు మొత్తం కాల్ లాగ్‌ను కలిగి ఉండే మీ డేటాబేస్ యొక్క కాపీని అంతర్గత స్టోరేజ్‌లో రూపొందించి 2) దాన్ని ఈమెయిల్‌ చేయబోతున్నారు. మీరు దాన్ని పరికరం నుండి విజయవంతంగా కాపీ చేసిన తర్వాత లేదా ఈమెయిల్‌ను స్వీకరించిన తర్వాత కాపీని తొలగించడం మర్చిపోవద్దు."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"ఇప్పుడే తొలగించండి"</string>
diff --git a/res/values-th/arrays.xml b/res/values-th/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-th/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index e3b384db..662dfb34 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"สมุดโทรศัพท์"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"อื่นๆ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ข้อความเสียงจาก "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ซิงค์รายชื่อติดต่อที่มีอยู่ไหม"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"คุณสามารถซิงค์ %1$s เพื่อให้แน่ใจว่าข้อมูลได้รับการสำรองข้อมูลไปยัง %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{รายชื่อติดต่อที่มีอยู่ # รายการ}other{รายชื่อติดต่อที่มีอยู่ # รายการ}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ซิงค์"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ไม่ต้องซิงค์"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"คัดลอกฐานข้อมูลผู้ติดต่อ"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"คุณกำลังจะ 1) ทำสำเนาฐานข้อมูลของคุณซึ่งรวมถึงข้อมูลที่เกี่ยวข้องกับผู้ติดต่อทั้งหมดและบันทึกการโทรทั้งหมดลงในที่จัดเก็บข้อมูลภายใน และ 2) ส่งอีเมล อย่าลืมลบสำเนาออกจากอุปกรณ์ทันทีที่คุณคัดลอกเสร็จเรียบร้อยแล้วหรือเมื่ออีเมลส่งไปถึงผู้รับแล้ว"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"ลบเดี๋ยวนี้"</string>
diff --git a/res/values-tl/arrays.xml b/res/values-tl/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-tl/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 6a1b6d9f..880f585c 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Mga Contact"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Iba pa"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Voicemail mula sa/kay "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"I-sync ang mga kasalukuyang contact?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Puwede mong i-sync si %1$s para matiyak na naba-back up siya sa %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# kasalukuyang contact}one{# kasalukuyang contact}other{# na kasalukuyang contact}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"I-sync"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Huwag i-sync"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopyahin ang database ng mga contact"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Ikaw ay 1) gagawa na ng kopya ng iyong database na kinapapalooban ng lahat ng impormasyong nauugnay sa mga contact at ng lahat ng log ng tawag sa panloob na storage, at 2) ipapadala mo na ito sa email. Alalahaning tanggalin ang kopya sa sandaling matagumpay mo na itong nakopya mula sa device o sa sandaling natanggap na ang email."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Tanggalin ngayon"</string>
diff --git a/res/values-tr/arrays.xml b/res/values-tr/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-tr/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 17a6f2fe..7058b4b3 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kişiler"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Diğer"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Sesli mesaj gönderen: "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Mevcut kişiler senkronize edilsin mi?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s adlı kişiyi senkronize ederek %2$s (%3$s) ile yedekleyebilirsiniz."</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# mevcut kişi}other{# mevcut kişi}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Senkronize et"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Senkronize etme"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kişiler veritabanını kopyala"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Birazdan 1) veritabanınızın kişilerle ilgili tüm bilgilerini ve çağrı günlüğünün tamamını içeren bir kopyasını dahili depolama birimine kaydetmek ve 2) bunu e-postayla göndermek üzeresiniz. Bu kopyayı cihazın dışına aktardıktan veya e-posta alındıktan sonra hemen silmeyi unutmayın."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Şimdi sil"</string>
diff --git a/res/values-uk/arrays.xml b/res/values-uk/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-uk/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 187e4c87..f1ad562a 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Контакти"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Інші"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Голосова пошта від "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Синхронізувати наявні контакти?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Ви можете синхронізувати %1$s для автоматичного резервного копіювання в %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# наявний контакт}one{# наявний контакт}few{# наявні контакти}many{# наявних контактів}other{наявні контакти (#)}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синхронізувати"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Не синхронізувати"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Копіювати базу даних контактів"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Ви збираєтеся: 1) скопіювати у внутрішню пам’ять свою базу даних, яка містить усю інформацію про контакти та весь журнал дзвінків; 2) надіслати копію електронною поштою. Не забудьте видалити копію, щойно її буде перенесено з пристрою або отримано електронним листом."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Видалити зараз"</string>
diff --git a/res/values-ur/arrays.xml b/res/values-ur/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-ur/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 16e28332..8cb0e36a 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"رابطے"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"دیگر"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"صوتی میل منجانب "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"موجودہ رابطوں کو مطابقت پذیر بنائیں؟"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"‏آپ %1$s کو مطابقت پذیر بنا سکتے تاکہ یہ یقینی بنایا جا سکے کہ ‎%2$s (%3$s) میں بیک ان کا بیک لیا جائے"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{موجودہ # رابطہ}other{موجودہ # رابطے}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"مطابقت پذیر بنائیں"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"مطابقت پذیر نہ بنائیں"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"رابطوں کا ڈیٹابیس کاپی کریں"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"آپ 1) اپنے اس ڈیٹابیس کو جس میں رابطوں سے متعلق سبھی معلومات اور داخلی اسٹوریج میں کال لاگ کی معلومات شامل ہے کاپی کرنے اور 2) اسے ای میل کرنے والے ہیں۔ آلے سے باہر کامیابی کے ساتھ کاپی کر لینے یا ای میل موصول ہو جانے کے ساتھ ہی کاپی کو یاد سے حذف کر دیں۔"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"ابھی حذف کریں"</string>
diff --git a/res/values-uz/arrays.xml b/res/values-uz/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-uz/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index ae88a57d..2746184c 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Kontaktlar"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Boshqa"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Ovozli xabar egasi: "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Mavjud kontaktlar sinxronlansinmi?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s %2$s (%3$s) hisobiga zaxiralanganiga ishonch hosil qilish uchun ularni sinxronlashingiz mumkin"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# ta mavjud kontakt}other{# ta mavjud kontakt}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinxronlash"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Sinxronlanmasin"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kontaktlar ma’lumotlar bazasidan nusxa ko‘chirish"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Siz 1) barcha qo‘ng‘iroqlar jurnali va barcha kontaktlarga aloqador ma’lumotlar ni o‘z ichiga olgan ma’lumotlar bazangizdan ichki xotiraga nusxa ko‘chirish va 2) uni e-pochta orqali jo‘natmoqchisiz. Ularni muvaffaqiyatli nusxa ko‘chirib yoki elektron xat qabul qilingandan so‘ng nusxasini o‘chirishni unutmang."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Hozir o‘chirish"</string>
diff --git a/res/values-vi/arrays.xml b/res/values-vi/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-vi/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 7aa9943c..42fc9ba1 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Danh bạ"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Khác"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Thư thoại từ "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Đồng bộ hoá danh bạ hiện có?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Bạn có thể đồng bộ hoá %1$s để đảm bảo những thông tin này được sao lưu vào %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# người liên hệ hiện có}other{# người liên hệ hiện có}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Đồng bộ hoá"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Không đồng bộ hoá"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Sao chép cơ sở dữ liệu người liên hệ"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Bạn sắp 1) thực hiện sao chép cơ sở dữ liệu của mình bao gồm tất cả thông tin liên quan đến địa chỉ liên hệ và tất cả nhật ký cuộc gọi sang bộ nhớ trong, và 2) gửi bản sao đó qua email. Hãy nhớ xóa bản sao khỏi thiết bị hoặc email nhận được ngay khi bạn đã sao chép thành công."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Xóa ngay"</string>
diff --git a/res/values-zh-rCN/arrays.xml b/res/values-zh-rCN/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-zh-rCN/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 2284634b..8c7438c8 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"通讯录"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"其他"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"语音信息发送人 "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"要同步现有联系人吗？"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"您可以同步处理 %1$s，以确保系统将其备份到%2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# 位现有联系人}other{# 位现有联系人}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"同步"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"不同步"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"复制通讯录数据库"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"您将要执行以下操作：1) 在内部存储设备中，创建包括通讯录相关信息和所有通话记录的数据库的副本；2) 通过电子邮件发送该副本。从设备中成功复制该副本或在电子邮件送达之后，请务必及时删除该副本。"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"立即删除"</string>
diff --git a/res/values-zh-rHK/arrays.xml b/res/values-zh-rHK/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-zh-rHK/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 291100d8..16245667 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"通訊錄"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"其他"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"留言來自 "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"要同步處理現有聯絡人嗎？"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"你可同步處理 %1$s，確保系統將這些資料備份至%2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# 個現有聯絡人}other{# 個現有聯絡人}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"同步處理"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"不要同步處理"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"複製通訊錄資料庫"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"您即將要 1) 把您的資料庫 (包括所有聯絡人相關資料及所有通話記錄) 複製到內部儲存空間，然後 2) 以電郵寄出。當您成功從裝置複製這個資料庫的副本或收到電子郵件後，別忘記立即刪除這個副本。"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"立即刪除"</string>
diff --git a/res/values-zh-rTW/arrays.xml b/res/values-zh-rTW/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-zh-rTW/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index decb5b6a..0acfef37 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"聯絡人"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"其他"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"語音郵件寄件者： "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"要同步處理現有聯絡人嗎？"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"你可以同步處理 %1$s，確保系統將這些資料備份到%2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# 位現有聯絡人}other{# 位現有聯絡人}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"同步處理"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"不要同步處理"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"複製聯絡人資料庫"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"您即將要 1) 將您的資料庫 (包含所有聯絡人相關資訊及所有通話記錄) 複製到內部儲存空間，以及 2) 透過電子郵件傳送副本。提醒您，當您順利複製裝置上的資料或收到電子郵件後，請儘快刪除副本。"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"立即刪除"</string>
diff --git a/res/values-zu/arrays.xml b/res/values-zu/arrays.xml
deleted file mode 100644
index 944e2035..00000000
--- a/res/values-zu/arrays.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<resources xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-  <string-array name="eligible_system_cloud_account_types">
-    <item msgid="7130475166467776698">"com.google"</item>
-  </string-array>
-</resources>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 5fa1316e..c27c13da 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -25,6 +25,11 @@
     <string name="default_directory" msgid="93961630309570294">"Othintana nabo"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"Okunye"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Imeyili yezwi kusuka "</string>
+    <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vumelanisa oxhumana nabo abakhona?"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Ungakwazi ukuvumelanisa okuthi %1$s ukuze uqinisekise ukuthi kwenzelwe isipele ku-%2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{Oxhumana naye okhona ongu-#}one{Oxhumana nabo abakhona abangu-#}other{Oxhumana nabo abakhona abangu-#}}"</string>
+    <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Vumelanisa"</string>
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ungavumelanisi"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopisha imininingo egciniwe yoxhumana nabo"</string>
     <string name="debug_dump_database_message" msgid="406438635002392290">"Useduze nokuthi 1) wenze ikhophi yemininingwane yakho egciniwe ebandakanya yonke imininingwane ehlobene noxhumana nabo kanye nohlu lokushaya ucingo kokokulondoloza kwangaphakathi, kanti futhi 2) uzoyYou are about to 1) make a copy of youithumela nge-imeyili. Khumbula ukuthi ususe ikhophi ngokushesha emumva kokuba uphumelele ukuyikopisha isuka edivayisini noma emumva kokuba kutholakale i-imeyili."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"Susa manje"</string>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index e367f5a4..726894a2 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -47,7 +47,20 @@
          Note that the trailing space is important, and that to achieve it we have to wrap the
          string in double quotes. -->
     <string name="voicemail_from_column">"Voicemail from "</string>
-
+    <!-- The title for move contacts to default account dialog. [CHAR LIMIT=NONE] -->
+    <string name="move_contacts_to_default_account_dialog_title">Sync existing contacts?</string>
+    <!-- The message text for move contacts to default account dialog. [CHAR LIMIT=NONE] -->
+    <string name="move_contacts_to_default_account_dialog_message">You can sync %1$s to ensure they\'re backed up to %2$s (%3$s)</string>
+    <!-- The message text for total movable contacts count. [CHAR LIMIT=NONE] -->
+    <string name="movable_contacts_count"> {contacts_count, plural,
+        =1    {# existing contact}
+        other {# existing contacts}
+        }
+    </string>
+    <!-- The text for move contacts to default account dialog confirm button. [CHAR LIMIT=NONE] -->
+    <string name="move_contacts_to_default_account_dialog_sync_button_text">Sync</string>
+    <!-- The text for move contacts to default account dialog  cancel button. [CHAR LIMIT=NONE] -->
+    <string name="move_contacts_to_default_account_dialog_cancel_button_text">Don\'t sync</string>
     <!-- Debug tool - title of the dialog which copies the contact database into the external storage. [CHAR LIMIT=NONE] -->
     <string name="debug_dump_title">Copy contacts database</string>
 
diff --git a/src/com/android/providers/contacts/AccountResolver.java b/src/com/android/providers/contacts/AccountResolver.java
index 5372cf06..bb983c0f 100644
--- a/src/com/android/providers/contacts/AccountResolver.java
+++ b/src/com/android/providers/contacts/AccountResolver.java
@@ -19,11 +19,10 @@ import android.accounts.Account;
 import android.content.ContentValues;
 import android.net.Uri;
 import android.provider.ContactsContract.RawContacts;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
 import android.provider.ContactsContract.SimAccount;
 import android.text.TextUtils;
 
-import com.android.providers.contacts.DefaultAccount.AccountCategory;
-
 import java.util.List;
 
 public class AccountResolver {
@@ -38,18 +37,37 @@ public class AccountResolver {
         mDefaultAccountManager = defaultAccountManager;
     }
 
+    private static Account getLocalAccount() {
+        if (TextUtils.isEmpty(AccountWithDataSet.LOCAL.getAccountName())) {
+            // AccountWithDataSet.LOCAL's getAccountType() must be null as well, thus we return
+            // the NULL account.
+            return null;
+        } else {
+            // AccountWithDataSet.LOCAL's getAccountType() must not be null as well, thus we return
+            // the customized local account.
+            return new Account(AccountWithDataSet.LOCAL.getAccountName(),
+                    AccountWithDataSet.LOCAL.getAccountType());
+        }
+    }
+
     /**
      * Resolves the account and builds an {@link AccountWithDataSet} based on the data set specified
      * in the URI or values (if any).
-     * @param uri Current {@link Uri} being operated on.
-     * @param values {@link ContentValues} to read and possibly update.
-     * @param applyDefaultAccount Whether to look up default account during account resolution.
+     *
+     * @param uri                                     Current {@link Uri} being operated on.
+     * @param values                                  {@link ContentValues} to read and possibly
+     *                                                update.
+     * @param applyDefaultAccount                     Whether to look up default account during
+     *                                                account resolution.
+     * @param shouldValidateAccountForContactAddition Whether to validate the account accepts new
+     *                                                contacts.
      */
     public AccountWithDataSet resolveAccountWithDataSet(Uri uri, ContentValues values,
-            boolean applyDefaultAccount) {
+            boolean applyDefaultAccount, boolean shouldValidateAccountForContactAddition) {
         final Account[] accounts = resolveAccount(uri, values);
-        final Account account =  applyDefaultAccount
-                ? getAccountWithDefaultAccountApplied(uri, accounts)
+        final Account account = applyDefaultAccount
+                ? getAccountWithDefaultAccountApplied(accounts,
+                shouldValidateAccountForContactAddition)
                 : getFirstAccountOrNull(accounts);
 
         AccountWithDataSet accountWithDataSet = null;
@@ -70,87 +88,76 @@ public class AccountResolver {
      * Resolves the account to be used, taking into consideration the default account settings.
      *
      * @param accounts 1-size array which contains specified account, or empty array if account is
-     *                not specified.
-     * @param uri The URI used for resolving accounts.
+     *                 not specified.
      * @return The resolved account, or null if it's the default device (aka "NULL") account.
      * @throws IllegalArgumentException If there's an issue with the account resolution due to
-     *  default account incompatible account types.
+     *                                  default account incompatible account types.
      */
-    private Account getAccountWithDefaultAccountApplied(Uri uri, Account[] accounts)
+    private Account getAccountWithDefaultAccountApplied(Account[] accounts,
+            boolean shouldValidateAccountForContactAddition)
             throws IllegalArgumentException {
         if (accounts.length == 0) {
-            DefaultAccount defaultAccount = mDefaultAccountManager.pullDefaultAccount();
-            if (defaultAccount.getAccountCategory() == AccountCategory.UNKNOWN) {
-                String exceptionMessage = mDbHelper.exceptionMessage(
-                        "Must specify ACCOUNT_NAME and ACCOUNT_TYPE",
-                        uri);
-                throw new IllegalArgumentException(exceptionMessage);
-            } else if (defaultAccount.getAccountCategory() == AccountCategory.DEVICE) {
+            DefaultAccountAndState defaultAccountAndState =
+                    mDefaultAccountManager.pullDefaultAccount();
+            if (defaultAccountAndState.getState()
+                    == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_NOT_SET
+                    || defaultAccountAndState.getState()
+                    == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_LOCAL) {
                 return getLocalAccount();
             } else {
-                return defaultAccount.getCloudAccount();
+                return defaultAccountAndState.getAccount();
             }
         } else {
-            checkAccountIsWritableInternal(accounts[0]);
+            if (shouldValidateAccountForContactAddition) {
+                validateAccountForContactAdditionInternal(accounts[0]);
+            }
             return accounts[0];
         }
     }
 
     /**
-     * Checks if the specified account is writable.
+     * Checks if new contacts in specified account is accepted.
      *
-     * <p>This method verifies if contacts can be written to the given account based on the
+     * <p>This method checks if contacts can be written to the given account based on the
      * current default account settings. It throws an {@link IllegalArgumentException} if
-     * the account is not writable.</p>
+     * the contacts cannot be created in the given account .</p>
      *
      * @param accountName The name of the account to check.
      * @param accountType The type of the account to check.
-     *
      * @throws IllegalArgumentException if either of the following conditions are met:
-     *     <ul>
-     *         <li>Only one of <code>accountName</code> or <code>accountType</code> is
-     *             specified.</li>
-     *         <li>The default account is set to cloud and the specified account is a local
-     *             (device or SIM) account.</li>
-     *     </ul>
+     *                                  <ul>
+     *                                      <li>Only one of <code>accountName</code> or
+     *                                      <code>accountType</code> is
+     *                                          specified.</li>
+     *                                      <li>The default account is set to cloud and the
+     *                                      specified account is a local
+     *                                          (device or SIM) account.</li>
+     *                                  </ul>
      */
-    public void checkAccountIsWritable(String accountName, String accountType) {
+    public void validateAccountForContactAddition(String accountName, String accountType) {
         if (TextUtils.isEmpty(accountName) ^ TextUtils.isEmpty(accountType)) {
             throw new IllegalArgumentException(
                     "Must specify both or neither of ACCOUNT_NAME and ACCOUNT_TYPE");
         }
         if (TextUtils.isEmpty(accountName)) {
-            checkAccountIsWritableInternal(/*account=*/null);
+            validateAccountForContactAdditionInternal(/*account=*/null);
         } else {
-            checkAccountIsWritableInternal(new Account(accountName, accountType));
+            validateAccountForContactAdditionInternal(new Account(accountName, accountType));
         }
     }
 
-    private void checkAccountIsWritableInternal(Account account)
+    private void validateAccountForContactAdditionInternal(Account account)
             throws IllegalArgumentException {
-        DefaultAccount defaultAccount = mDefaultAccountManager.pullDefaultAccount();
+        DefaultAccountAndState defaultAccount = mDefaultAccountManager.pullDefaultAccount();
 
-        if (defaultAccount.getAccountCategory() == AccountCategory.CLOUD) {
+        if (defaultAccount.getState() == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD) {
             if (isDeviceOrSimAccount(account)) {
-                throw new IllegalArgumentException("Cannot write contacts to local accounts "
+                throw new IllegalArgumentException("Cannot add contacts to local or SIM accounts "
                         + "when default account is set to cloud");
             }
         }
     }
 
-    private static Account getLocalAccount() {
-        if (TextUtils.isEmpty(AccountWithDataSet.LOCAL.getAccountName())) {
-            // AccountWithDataSet.LOCAL's getAccountType() must be null as well, thus we return
-            // the NULL account.
-            return null;
-        } else {
-            // AccountWithDataSet.LOCAL's getAccountType() must not be null as well, thus we return
-            // the customized local account.
-            return new Account(AccountWithDataSet.LOCAL.getAccountName(),
-                    AccountWithDataSet.LOCAL.getAccountType());
-        }
-    }
-
     /**
      * Gets the first account from the array, or null if the array is empty.
      *
@@ -176,17 +183,18 @@ public class AccountResolver {
      * already specified in the values then it must be consistent with the
      * account, if it is non-null.
      *
-     * @param uri Current {@link Uri} being operated on.
+     * @param uri    Current {@link Uri} being operated on.
      * @param values {@link ContentValues} to read and possibly update.
      * @return 1-size array which contains account specified by {@link Uri} and
-     *             {@link ContentValues}, or empty array if account is not specified.
+     * {@link ContentValues}, or empty array if account is not specified.
      * @throws IllegalArgumentException when only one of
-     *             {@link RawContacts#ACCOUNT_NAME} or
-     *             {@link RawContacts#ACCOUNT_TYPE} is specified, leaving the
-     *             other undefined.
+     *                                  {@link RawContacts#ACCOUNT_NAME} or
+     *                                  {@link RawContacts#ACCOUNT_TYPE} is specified, leaving the
+     *                                  other undefined.
      * @throws IllegalArgumentException when {@link RawContacts#ACCOUNT_NAME}
-     *             and {@link RawContacts#ACCOUNT_TYPE} are inconsistent between
-     *             the given {@link Uri} and {@link ContentValues}.
+     *                                  and {@link RawContacts#ACCOUNT_TYPE} are inconsistent
+     *                                  between
+     *                                  the given {@link Uri} and {@link ContentValues}.
      */
     private Account[] resolveAccount(Uri uri, ContentValues values)
             throws IllegalArgumentException {
diff --git a/src/com/android/providers/contacts/ChangeIds.java b/src/com/android/providers/contacts/ChangeIds.java
new file mode 100644
index 00000000..5be65c4e
--- /dev/null
+++ b/src/com/android/providers/contacts/ChangeIds.java
@@ -0,0 +1,33 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.providers.contacts;
+
+import android.compat.annotation.ChangeId;
+import android.compat.annotation.EnabledSince;
+import android.os.Build;
+
+/** All the {@link ChangeId} used for the Contacts Provider. */
+public class ChangeIds {
+    /**
+     * Restricts contact creation in specific accounts, starting from
+     * {@link android.os.Build.VERSION_CODES#BAKLAVA}.
+     * <p>When enabled, this feature prevents the creation of contacts under local or SIM accounts
+     * if the default account is associated with a cloud provider.
+     */
+    @ChangeId
+    @EnabledSince(targetSdkVersion = Build.VERSION_CODES.BAKLAVA)
+    public static final long RESTRICT_CONTACTS_CREATION_IN_ACCOUNTS = 352312780L;
+}
diff --git a/src/com/android/providers/contacts/ContactMover.java b/src/com/android/providers/contacts/ContactMover.java
index 2ab7e8fe..33caecd1 100644
--- a/src/com/android/providers/contacts/ContactMover.java
+++ b/src/com/android/providers/contacts/ContactMover.java
@@ -18,6 +18,8 @@ package com.android.providers.contacts;
 
 import static com.android.providers.contacts.flags.Flags.cp2AccountMoveFlag;
 import static com.android.providers.contacts.flags.Flags.cp2AccountMoveSyncStubFlag;
+import static com.android.providers.contacts.flags.Flags.cp2AccountMoveDeleteNonCommonDataRowsFlag;
+import static com.android.providers.contacts.flags.Flags.disableMoveToIneligibleDefaultAccountFlag;
 
 import android.accounts.Account;
 import android.content.ContentUris;
@@ -28,6 +30,7 @@ import android.provider.ContactsContract.CommonDataKinds;
 import android.provider.ContactsContract.Data;
 import android.provider.ContactsContract.Groups;
 import android.provider.ContactsContract.RawContacts;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
 import android.text.TextUtils;
 import android.util.Log;
 import android.util.Pair;
@@ -78,7 +81,7 @@ public class ContactMover {
                 RawContacts.CONTENT_URI,
                 values,
                 RawContacts._ID + " IN (" + TextUtils.join(",", rawContactIds) + ")",
-                new String[] {});
+                new String[]{});
     }
 
     private void updateGroupAccount(
@@ -101,12 +104,12 @@ public class ContactMover {
                 Groups.CONTENT_URI,
                 values,
                 Groups._ID + " IN (" + TextUtils.join(",", groupIds) + ")",
-                new String[] {});
+                new String[]{});
     }
 
     private void updateGroupDataRows(Map<Long, Long> groupIdMap) {
         // for each group in the groupIdMap, update all Group Membership data rows from key to value
-        for (Map.Entry<Long, Long> groupIds: groupIdMap.entrySet()) {
+        for (Map.Entry<Long, Long> groupIds : groupIdMap.entrySet()) {
             mDbHelper.updateGroupMemberships(groupIds.getKey(), groupIds.getValue());
         }
 
@@ -141,7 +144,7 @@ public class ContactMover {
         // 1. update contact data rows (to point do the group in dest)
         // 2. Set deleted = 1 for dupe groups in source
         updateGroupDataRows(nonSystemDuplicateGroupMap);
-        for (Map.Entry<Long, Long> groupIds: nonSystemDuplicateGroupMap.entrySet()) {
+        for (Map.Entry<Long, Long> groupIds : nonSystemDuplicateGroupMap.entrySet()) {
             mCp2.deleteGroup(Groups.CONTENT_URI, groupIds.getKey(), false);
         }
 
@@ -172,7 +175,7 @@ public class ContactMover {
         Map<Long, ContentValues> oldIdToNewValues = mDbHelper
                 .getGroupContentValuesForMoveCopy(destAccount, systemUniqueGroups);
         Map<Long, Long> systemGroupIdMap = new HashMap<>();
-        for (Map.Entry<Long, ContentValues> idToValues: oldIdToNewValues.entrySet()) {
+        for (Map.Entry<Long, ContentValues> idToValues : oldIdToNewValues.entrySet()) {
             Uri newGroupUri = mCp2.insert(Groups.CONTENT_URI, idToValues.getValue());
             if (newGroupUri != null) {
                 Long newGroupId = ContentUris.parseId(newGroupUri);
@@ -190,7 +193,7 @@ public class ContactMover {
                 CommonDataKinds.GroupMembership.GROUP_ROW_ID
                         + " IN (" + TextUtils.join(",", systemUniqueGroups) + ")"
                         + " AND " + Data.MIMETYPE + " = ?",
-                new String[] {CommonDataKinds.GroupMembership.CONTENT_ITEM_TYPE}
+                new String[]{CommonDataKinds.GroupMembership.CONTENT_ITEM_TYPE}
         );
     }
 
@@ -219,6 +222,23 @@ public class ContactMover {
                 .collect(Collectors.toSet());
     }
 
+    Account getCloudDefaultAccount() {
+        DefaultAccountAndState defaultAccount = mDefaultAccountManager.pullDefaultAccount();
+        if (defaultAccount.getState() != DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD) {
+            Log.w(TAG, "No default cloud account set");
+            return null;
+        }
+        Account account = defaultAccount.getAccount();
+        assert account != null;
+        if (disableMoveToIneligibleDefaultAccountFlag()
+                && !mDefaultAccountManager.getEligibleCloudAccounts().contains(account)) {
+            Log.w(TAG, "Ineligible default cloud account set");
+            return null;
+        }
+
+        return account;
+    }
+
     /**
      * Moves {@link RawContacts} and {@link Groups} from the local account(s) to the Cloud Default
      * Account (if any).
@@ -234,11 +254,13 @@ public class ContactMover {
         // Check if there is a cloud default account set
         // - if not, then we don't need to do anything
         // - if there is, then that's our destAccount, get the AccountWithDataSet
-        Account account = mDefaultAccountManager.pullDefaultAccount().getCloudAccount();
+        Account account = getCloudDefaultAccount();
         if (account == null) {
-            Log.w(TAG, "moveToDefaultCloudAccount with no default cloud account set");
+            Log.w(TAG,
+                    "moveLocalToCloudDefaultAccount with no eligible cloud default account set");
             return;
         }
+
         AccountWithDataSet destAccount = new AccountWithDataSet(
                 account.name, account.type, /* dataSet= */ null);
 
@@ -254,18 +276,19 @@ public class ContactMover {
     @NeededForTesting
     void moveSimToCloudDefaultAccount() {
         if (!cp2AccountMoveFlag()) {
-            Log.w(TAG, "moveLocalToCloudDefaultAccount: flag disabled");
+            Log.w(TAG, "moveSimToCloudDefaultAccount: flag disabled");
             return;
         }
 
         // Check if there is a cloud default account set
         // - if not, then we don't need to do anything
         // - if there is, then that's our destAccount, get the AccountWithDataSet
-        Account account = mDefaultAccountManager.pullDefaultAccount().getCloudAccount();
+        Account account = getCloudDefaultAccount();
         if (account == null) {
-            Log.w(TAG, "moveToDefaultCloudAccount with no default cloud account set");
+            Log.w(TAG, "moveSimToCloudDefaultAccount with no eligible cloud default account set");
             return;
         }
+
         AccountWithDataSet destAccount = new AccountWithDataSet(
                 account.name, account.type, /* dataSet= */ null);
 
@@ -276,6 +299,7 @@ public class ContactMover {
     /**
      * Gets the number of {@link RawContacts} in the local account(s) which may be moved using
      * {@link ContactMover#moveLocalToCloudDefaultAccount} (if any).
+     *
      * @return the number of {@link RawContacts} in the local account(s), or 0 if there is no Cloud
      * Default Account.
      */
@@ -290,9 +314,9 @@ public class ContactMover {
         // Check if there is a cloud default account set
         // - if not, then we don't need to do anything, count = 0
         // - if there is, then do the count
-        Account account = mDefaultAccountManager.pullDefaultAccount().getCloudAccount();
+        Account account = getCloudDefaultAccount();
         if (account == null) {
-            Log.w(TAG, "getNumberLocalContacts with no default cloud account set");
+            Log.w(TAG, "getNumberLocalContacts with no eligible cloud default account set");
             return 0;
         }
 
@@ -303,6 +327,7 @@ public class ContactMover {
     /**
      * Gets the number of {@link RawContacts} in the SIM account(s) which may be moved using
      * {@link ContactMover#moveSimToCloudDefaultAccount} (if any).
+     *
      * @return the number of {@link RawContacts} in the SIM account(s), or 0 if there is no Cloud
      * Default Account.
      */
@@ -317,9 +342,9 @@ public class ContactMover {
         // Check if there is a cloud default account set
         // - if not, then we don't need to do anything, count = 0
         // - if there is, then do the count
-        Account account = mDefaultAccountManager.pullDefaultAccount().getCloudAccount();
+        Account account = getCloudDefaultAccount();
         if (account == null) {
-            Log.w(TAG, "getNumberSimContacts with no default cloud account set");
+            Log.w(TAG, "getNumberSimContacts with no eligible cloud default account set");
             return 0;
         }
 
@@ -329,9 +354,11 @@ public class ContactMover {
 
     /**
      * Moves {@link RawContacts} and {@link Groups} from one account to another.
+     *
      * @param sourceAccounts the source {@link AccountWithDataSet}s to move contacts and groups
      *                       from.
-     * @param destAccount the destination {@link AccountWithDataSet} to move contacts and groups to.
+     * @param destAccount    the destination {@link AccountWithDataSet} to move contacts and groups
+     *                       to.
      */
     // Keep it in proguard for testing: once it's used in production code, remove this annotation.
     @NeededForTesting
@@ -348,9 +375,11 @@ public class ContactMover {
      * Moves {@link RawContacts} and {@link Groups} from one account to another, while writing sync
      * stubs in the source account to notify relevant sync adapters in the source account of the
      * move.
+     *
      * @param sourceAccounts the source {@link AccountWithDataSet}s to move contacts and groups
      *                       from.
-     * @param destAccount the destination {@link AccountWithDataSet} to move contacts and groups to.
+     * @param destAccount    the destination {@link AccountWithDataSet} to move contacts and groups
+     *                       to.
      */
     // Keep it in proguard for testing: once it's used in production code, remove this annotation.
     @NeededForTesting
@@ -376,7 +405,7 @@ public class ContactMover {
         final SQLiteDatabase db = mDbHelper.getWritableDatabase();
         db.beginTransaction();
         try {
-            for (AccountWithDataSet source: sourceAccounts) {
+            for (AccountWithDataSet source : sourceAccounts) {
                 moveRawContactsInternal(source, destAccount, insertSyncStubs);
             }
 
@@ -390,8 +419,9 @@ public class ContactMover {
             AccountWithDataSet destAccount, boolean insertSyncStubs) {
         // If we are moving between account types or data sets, delete non-portable data rows
         // from the source
-        if (!isAccountTypeMatch(sourceAccount, destAccount)
-                || !isDataSetMatch(sourceAccount, destAccount)) {
+        if (cp2AccountMoveDeleteNonCommonDataRowsFlag()
+                && (!isAccountTypeMatch(sourceAccount, destAccount)
+                || !isDataSetMatch(sourceAccount, destAccount))) {
             mDbHelper.deleteNonCommonDataRows(sourceAccount);
         }
 
@@ -420,7 +450,7 @@ public class ContactMover {
 
         // Last, clear the duplicates.
         // Since these are duplicates, we don't need to do anything else with them
-        for (long rawContactId: duplicates) {
+        for (long rawContactId : duplicates) {
             mCp2.deleteRawContact(
                     rawContactId,
                     mDbHelper.getContactId(rawContactId),
diff --git a/src/com/android/providers/contacts/ContactsDatabaseHelper.java b/src/com/android/providers/contacts/ContactsDatabaseHelper.java
index eabadd4a..607732f2 100644
--- a/src/com/android/providers/contacts/ContactsDatabaseHelper.java
+++ b/src/com/android/providers/contacts/ContactsDatabaseHelper.java
@@ -4382,7 +4382,7 @@ public class ContactsDatabaseHelper extends SQLiteOpenHelper {
         if (newVisibility) {
             db.execSQL("INSERT OR IGNORE INTO " + Tables.DEFAULT_DIRECTORY + " VALUES(?)",
                     new String[] {contactIdAsString});
-            txContext.invalidateSearchIndexForContact(contactId);
+            txContext.invalidateSearchIndexForContact(db, contactId);
         } else {
             db.execSQL("DELETE FROM " + Tables.DEFAULT_DIRECTORY +
                         " WHERE " + Contacts._ID + "=?",
diff --git a/src/com/android/providers/contacts/ContactsProvider2.java b/src/com/android/providers/contacts/ContactsProvider2.java
index f15ade66..3846a5a7 100644
--- a/src/com/android/providers/contacts/ContactsProvider2.java
+++ b/src/com/android/providers/contacts/ContactsProvider2.java
@@ -19,9 +19,10 @@ package com.android.providers.contacts;
 import static android.Manifest.permission.INTERACT_ACROSS_USERS;
 import static android.Manifest.permission.INTERACT_ACROSS_USERS_FULL;
 import static android.content.pm.PackageManager.PERMISSION_GRANTED;
+import static android.provider.Flags.newDefaultAccountApiEnabled;
 
+import static com.android.providers.contacts.flags.Flags.cp2AccountMoveFlag;
 import static com.android.providers.contacts.flags.Flags.cp2SyncSearchIndexFlag;
-import static com.android.providers.contacts.flags.Flags.enableNewDefaultAccountRuleFlag;
 import static com.android.providers.contacts.util.PhoneAccountHandleMigrationUtils.TELEPHONY_COMPONENT_NAME;
 
 import android.accounts.Account;
@@ -29,11 +30,13 @@ import android.accounts.AccountManager;
 import android.accounts.OnAccountsUpdateListener;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
+import android.annotation.RequiresPermission;
 import android.annotation.SuppressLint;
 import android.annotation.WorkerThread;
 import android.app.AppOpsManager;
 import android.app.BroadcastOptions;
 import android.app.SearchManager;
+import android.app.compat.CompatChanges;
 import android.content.BroadcastReceiver;
 import android.content.ContentProviderOperation;
 import android.content.ContentProviderResult;
@@ -81,6 +84,7 @@ import android.os.ParcelFileDescriptor.AutoCloseInputStream;
 import android.os.RemoteException;
 import android.os.StrictMode;
 import android.os.SystemClock;
+import android.os.Trace;
 import android.os.UserHandle;
 import android.preference.PreferenceManager;
 import android.provider.BaseColumns;
@@ -115,6 +119,8 @@ import android.provider.ContactsContract.PinnedPositions;
 import android.provider.ContactsContract.Profile;
 import android.provider.ContactsContract.ProviderStatus;
 import android.provider.ContactsContract.RawContacts;
+import android.provider.ContactsContract.RawContacts.DefaultAccount;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
 import android.provider.ContactsContract.RawContactsEntity;
 import android.provider.ContactsContract.SearchSnippets;
 import android.provider.ContactsContract.Settings;
@@ -1502,6 +1508,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
 
     private DefaultAccountManager mDefaultAccountManager;
     private AccountResolver mAccountResolver;
+    private ContactMover mContactMover;
 
     private int mProviderStatus = STATUS_NORMAL;
     private boolean mProviderStatusUpdateNeeded;
@@ -1631,6 +1638,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
 
         mDefaultAccountManager = new DefaultAccountManager(getContext(), mContactsHelper);
         mAccountResolver = new AccountResolver(mContactsHelper, mDefaultAccountManager);
+        mContactMover = new ContactMover(this, mContactsHelper, mDefaultAccountManager);
 
         if (mContactsHelper.getPhoneAccountHandleMigrationUtils()
                 .isPhoneAccountMigrationPending()) {
@@ -2593,12 +2601,132 @@ public class ContactsProvider2 extends AbstractContactsProvider
             }
 
             return response;
+        } else if (DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD.equals(
+                method)) {
+            if (newDefaultAccountApiEnabled()) {
+                return queryDefaultAccountForNewContacts();
+            } else {
+                // Ignore the call if the flag is disabled.
+                Log.w(TAG, "Query default account for new contacts is not supported.");
+            }
+        } else if (DefaultAccount.QUERY_ELIGIBLE_DEFAULT_ACCOUNTS_METHOD.equals(method)) {
+            if (newDefaultAccountApiEnabled()) {
+                return queryEligibleDefaultAccounts();
+            } else {
+                Log.w(TAG, "Query eligible account that can be set as cloud default account "
+                        + "is not supported.");
+            }
         } else if (Settings.SET_DEFAULT_ACCOUNT_METHOD.equals(method)) {
             return setDefaultAccountSetting(extras);
+        } else if (DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD.equals(
+                method)) {
+            if (newDefaultAccountApiEnabled()) {
+                return setDefaultAccountForNewContactsSetting(extras);
+            } else {
+                // Ignore the call if the flag is disabled.
+                Log.w(TAG, "Set default account for new contacts is not supported.");
+            }
+        } else if (RawContacts.DefaultAccount.MOVE_LOCAL_CONTACTS_TO_CLOUD_DEFAULT_ACCOUNT_METHOD
+                .equals(method)) {
+            if (!cp2AccountMoveFlag() || !newDefaultAccountApiEnabled()) {
+                return null;
+            }
+            ContactsPermissions.enforceCallingOrSelfPermission(getContext(), WRITE_PERMISSION);
+            ContactsPermissions.enforceCallingOrSelfPermission(getContext(),
+                    SET_DEFAULT_ACCOUNT_PERMISSION);
+            final Bundle response = new Bundle();
+            mContactMover.moveLocalToCloudDefaultAccount();
+            return response;
+
+        } else if (RawContacts.DefaultAccount.GET_NUMBER_OF_MOVABLE_LOCAL_CONTACTS_METHOD
+                .equals(method)) {
+            if (!newDefaultAccountApiEnabled()) {
+                return null;
+            }
+            if (!cp2AccountMoveFlag()) {
+                return new Bundle();
+            }
+            ContactsPermissions.enforceCallingOrSelfPermission(getContext(), READ_PERMISSION);
+            ContactsPermissions.enforceCallingOrSelfPermission(getContext(),
+                    SET_DEFAULT_ACCOUNT_PERMISSION);
+            final Bundle response = new Bundle();
+            int count = mContactMover.getNumberLocalContacts();
+            response.putInt(RawContacts.DefaultAccount.KEY_NUMBER_OF_MOVABLE_LOCAL_CONTACTS,
+                    count);
+            return response;
+
+        } else if (RawContacts.DefaultAccount.MOVE_SIM_CONTACTS_TO_CLOUD_DEFAULT_ACCOUNT_METHOD
+                .equals(method)) {
+            if (!cp2AccountMoveFlag() || !newDefaultAccountApiEnabled()) {
+                return null;
+            }
+            ContactsPermissions.enforceCallingOrSelfPermission(getContext(), WRITE_PERMISSION);
+            ContactsPermissions.enforceCallingOrSelfPermission(getContext(),
+                    SET_DEFAULT_ACCOUNT_PERMISSION);
+            final Bundle response = new Bundle();
+            mContactMover.moveSimToCloudDefaultAccount();
+            return response;
+
+        } else if (RawContacts.DefaultAccount.GET_NUMBER_OF_MOVABLE_SIM_CONTACTS_METHOD
+                .equals(method)) {
+            if (!newDefaultAccountApiEnabled()) {
+                return null;
+            }
+            if (!cp2AccountMoveFlag()) {
+                return new Bundle();
+            }
+            ContactsPermissions.enforceCallingOrSelfPermission(getContext(), READ_PERMISSION);
+            ContactsPermissions.enforceCallingOrSelfPermission(getContext(),
+                    SET_DEFAULT_ACCOUNT_PERMISSION);
+            final Bundle response = new Bundle();
+            int count = mContactMover.getNumberSimContacts();
+            response.putInt(RawContacts.DefaultAccount.KEY_NUMBER_OF_MOVABLE_SIM_CONTACTS,
+                    count);
+            return response;
+
         }
         return null;
     }
 
+    private @NonNull Bundle queryDefaultAccountForNewContacts() {
+        ContactsPermissions.enforceCallingOrSelfPermission(getContext(), READ_PERMISSION);
+        final Bundle response = new Bundle();
+
+        DefaultAccountAndState defaultAccount = mDefaultAccountManager.pullDefaultAccount();
+
+        if (defaultAccount.getState() == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD
+                || defaultAccount.getState() == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_SIM) {
+            response.putInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE, defaultAccount.getState());
+            assert defaultAccount.getAccount() != null;
+
+            response.putString(Settings.ACCOUNT_NAME, defaultAccount.getAccount().name);
+            response.putString(Settings.ACCOUNT_TYPE, defaultAccount.getAccount().type);
+        } else if (defaultAccount.getState()
+                == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_LOCAL) {
+            response.putInt(ContactsContract.RawContacts.DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE,
+                    DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_LOCAL);
+        } else if (defaultAccount.getState()
+                == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_NOT_SET) {
+            response.putInt(ContactsContract.RawContacts.DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE,
+                    DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_NOT_SET);
+        } else {
+            throw new IllegalStateException(
+                    "queryDefaultAccountForNewContacts: Invalid default account state");
+        }
+        return response;
+    }
+
+    private Bundle queryEligibleDefaultAccounts() {
+        ContactsPermissions.enforceCallingOrSelfPermission(getContext(),
+                SET_DEFAULT_ACCOUNT_PERMISSION);
+        final Bundle response = new Bundle();
+        final List<Account> eligibleCloudAccounts =
+                mDefaultAccountManager.getEligibleCloudAccounts();
+        response.putParcelableList(DefaultAccount.KEY_ELIGIBLE_DEFAULT_ACCOUNTS,
+                eligibleCloudAccounts);
+        return response;
+    }
+
     private Bundle setDefaultAccountSetting(Bundle extras) {
         ContactsPermissions.enforceCallingOrSelfPermission(getContext(),
                 SET_DEFAULT_ACCOUNT_PERMISSION);
@@ -2645,6 +2773,69 @@ public class ContactsProvider2 extends AbstractContactsProvider
         return response;
     }
 
+
+    private Bundle setDefaultAccountForNewContactsSetting(Bundle extras) {
+        ContactsPermissions.enforceCallingOrSelfPermission(getContext(),
+                SET_DEFAULT_ACCOUNT_PERMISSION);
+        final int defaultAccountState = extras.getInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE);
+        final String accountName = extras.getString(Settings.ACCOUNT_NAME);
+        final String accountType = extras.getString(Settings.ACCOUNT_TYPE);
+        final String dataSet = extras.getString(Settings.DATA_SET);
+
+        if (VERBOSE_LOGGING) {
+            Log.v(TAG, String.format(
+                    "setDefaultAccountSettings: name = %s, type = %s, data_set = %s",
+                    TextUtils.emptyIfNull(accountName), TextUtils.emptyIfNull(accountType),
+                    TextUtils.emptyIfNull(dataSet)));
+        }
+
+        if (TextUtils.isEmpty(accountName) ^ TextUtils.isEmpty(accountType)) {
+            throw new IllegalArgumentException(
+                    "Must specify both or neither of ACCOUNT_NAME and ACCOUNT_TYPE");
+        }
+        if (!TextUtils.isEmpty(dataSet)) {
+            throw new IllegalArgumentException(
+                    "Cannot set default account with non-null data set.");
+        }
+
+        if ((defaultAccountState == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD
+                || defaultAccountState == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_SIM)
+                ^ !TextUtils.isEmpty(accountName)) {
+            throw new IllegalArgumentException(
+                    "Must provide non-null account name when Default Contacts Account "
+                            + "is set to cloud or SIM, and vice versa");
+        }
+
+        DefaultAccountAndState defaultAccount;
+        if (defaultAccountState == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD) {
+            assert accountType != null;
+            defaultAccount = DefaultAccountAndState.ofCloud(new Account(accountName, accountType));
+        } else if (defaultAccountState == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_LOCAL) {
+            defaultAccount = DefaultAccountAndState.ofLocal();
+        } else if (defaultAccountState == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_SIM) {
+            assert accountType != null;
+            defaultAccount = DefaultAccountAndState.ofSim(new Account(accountName, accountType));
+        } else if (defaultAccountState == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_NOT_SET) {
+            defaultAccount = DefaultAccountAndState.ofNotSet();
+        } else {
+            throw new IllegalArgumentException(String.format(
+                    "Invalid Default contacts account state: %d", defaultAccountState));
+        }
+
+        final Bundle response = new Bundle();
+        final SQLiteDatabase db = mDbHelper.get().getWritableDatabase();
+        db.beginTransaction();
+        try {
+            if (!mDefaultAccountManager.tryPushDefaultAccount(defaultAccount)) {
+                throw new IllegalArgumentException("Failed to set the Default Contacts Account");
+            }
+            db.setTransactionSuccessful();
+        } finally {
+            db.endTransaction();
+        }
+        return response;
+    }
+
     /**
      * Pre-authorizes the given URI, adding an expiring permission token to it and placing that
      * in our map of pre-authorized URIs.
@@ -2790,7 +2981,9 @@ public class ContactsProvider2 extends AbstractContactsProvider
             invalidateFastScrollingIndexCache();
         }
 
-        updateSearchIndexInTransaction();
+        if (!forProfile) {
+            updateSearchIndexInTransaction(db);
+        }
 
         if (mProviderStatusUpdateNeeded) {
             updateProviderStatus();
@@ -2815,12 +3008,22 @@ public class ContactsProvider2 extends AbstractContactsProvider
         }
     }
 
-    private void updateSearchIndexInTransaction() {
-        Set<Long> staleContacts = mTransactionContext.get().getStaleSearchIndexContactIds();
-        Set<Long> staleRawContacts = mTransactionContext.get().getStaleSearchIndexRawContactIds();
-        if (!staleContacts.isEmpty() || !staleRawContacts.isEmpty()) {
-            mSearchIndexManager.updateIndexForRawContacts(staleContacts, staleRawContacts);
-            mTransactionContext.get().clearSearchIndexUpdates();
+    private void updateSearchIndexInTransaction(SQLiteDatabase db) {
+        if (cp2SyncSearchIndexFlag()) {
+            long staleContactsCount =
+                    mTransactionContext.get().getStaleSearchIndexContactIdsCount(db);
+            if (staleContactsCount > 0) {
+                mSearchIndexManager.updateIndexForRawContacts(staleContactsCount);
+                mTransactionContext.get().clearSearchIndexUpdates(db);
+            }
+        } else {
+            Set<Long> staleContacts = mTransactionContext.get().getStaleSearchIndexContactIds();
+            Set<Long> staleRawContacts =
+                    mTransactionContext.get().getStaleSearchIndexRawContactIds();
+            if (!staleContacts.isEmpty() || !staleRawContacts.isEmpty()) {
+                mSearchIndexManager.updateIndexForRawContacts(staleContacts, staleRawContacts);
+                mTransactionContext.get().clearSearchIndexUpdates(db);
+            }
         }
     }
 
@@ -2989,7 +3192,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
             case PROFILE_RAW_CONTACTS: {
                 invalidateFastScrollingIndexCache();
                 id = insertRawContact(uri, values, callerIsSyncAdapter,
-                        enableNewDefaultAccountRuleFlag() && match == RAW_CONTACTS);
+                        newDefaultAccountApiEnabled() && match == RAW_CONTACTS);
                 mSyncToNetwork |= !callerIsSyncAdapter;
                 break;
             }
@@ -3021,7 +3224,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
 
             case GROUPS: {
                 id = insertGroup(uri, values, callerIsSyncAdapter,
-                        enableNewDefaultAccountRuleFlag());
+                        newDefaultAccountApiEnabled());
                 mSyncToNetwork |= !callerIsSyncAdapter;
                 break;
             }
@@ -3508,7 +3711,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
 
     private Uri insertSettings(Uri uri, ContentValues values) {
         final AccountWithDataSet account = mAccountResolver.resolveAccountWithDataSet(uri, values,
-                /*applyDefaultAccount=*/false);
+                /*applyDefaultAccount=*/false, /*shouldValidateAccountForContactAddition=*/ false);
 
         // Note that the following check means the local account settings cannot be created with
         // an insert because resolveAccountWithDataSet returns null for it. However, the settings
@@ -4144,6 +4347,15 @@ public class ContactsProvider2 extends AbstractContactsProvider
             return 0;
         }
 
+        for (Long rawContactId : rawContactIds) {
+            // Invalidate the raw contacts in the search index before deleting the raw contacts
+            // from the "raw_contacts" table. When invalidating a contact through a raw contact
+            // the database is queried to obtain the contact_id. If the raw contact is not in the
+            // "raw_contacts" table, then the contact won't be marked as stale and will remain in
+            // the search_index table, even after the raw contact is deleted.
+            mTransactionContext.get().invalidateSearchIndexForRawContact(db, rawContactId);
+        }
+
         // Build the where clause for the raw contacts to be deleted
         ArrayList<String> whereArgs = new ArrayList<>();
         StringBuilder whereClause = new StringBuilder(rawContactIds.size() * 2 - 1);
@@ -4383,7 +4595,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
                 invalidateFastScrollingIndexCache();
                 selection = appendAccountIdToSelection(uri, selection);
                 count = updateRawContacts(values, selection, selectionArgs, callerIsSyncAdapter,
-                         enableNewDefaultAccountRuleFlag() && match == RAW_CONTACTS);
+                         newDefaultAccountApiEnabled() && match == RAW_CONTACTS);
                 break;
             }
 
@@ -4394,11 +4606,11 @@ public class ContactsProvider2 extends AbstractContactsProvider
                     selectionArgs = insertSelectionArg(selectionArgs, String.valueOf(rawContactId));
                     count = updateRawContacts(values, RawContacts._ID + "=?"
                                     + " AND(" + selection + ")", selectionArgs,
-                            callerIsSyncAdapter, enableNewDefaultAccountRuleFlag());
+                            callerIsSyncAdapter, newDefaultAccountApiEnabled());
                 } else {
                     mSelectionArgs1[0] = String.valueOf(rawContactId);
                     count = updateRawContacts(values, RawContacts._ID + "=?", mSelectionArgs1,
-                            callerIsSyncAdapter, enableNewDefaultAccountRuleFlag());
+                            callerIsSyncAdapter, newDefaultAccountApiEnabled());
                 }
                 break;
             }
@@ -4636,6 +4848,12 @@ public class ContactsProvider2 extends AbstractContactsProvider
         int DATA_SET = 3;
     }
 
+
+    @RequiresPermission(
+            allOf = {
+                    android.Manifest.permission.READ_COMPAT_CHANGE_CONFIG,
+                    android.Manifest.permission.LOG_COMPAT_CHANGE
+            })
     private int updateGroups(ContentValues originalValues, String selectionWithId,
             String[] selectionArgs, boolean callerIsSyncAdapter) {
         mGroupIdCache.clear();
@@ -4689,8 +4907,10 @@ public class ContactsProvider2 extends AbstractContactsProvider
                         ? updatedDataSet : c.getString(GroupAccountQuery.DATA_SET);
 
                 if (isAccountChanging) {
-                    if (enableNewDefaultAccountRuleFlag()) {
-                        mAccountResolver.checkAccountIsWritable(updatedAccountName,
+                    if (newDefaultAccountApiEnabled() && CompatChanges.isChangeEnabled(
+                            ChangeIds.RESTRICT_CONTACTS_CREATION_IN_ACCOUNTS,
+                            Binder.getCallingUid())) {
+                        mAccountResolver.validateAccountForContactAddition(updatedAccountName,
                                 updatedAccountType);
                     }
 
@@ -4802,6 +5022,11 @@ public class ContactsProvider2 extends AbstractContactsProvider
         return ret;
     }
 
+    @RequiresPermission(
+            allOf = {
+                    android.Manifest.permission.READ_COMPAT_CHANGE_CONFIG,
+                    android.Manifest.permission.LOG_COMPAT_CHANGE
+            })
     private int updateRawContact(SQLiteDatabase db, long rawContactId, ContentValues values,
             boolean callerIsSyncAdapter, boolean applyDefaultAccount) {
         final String selection = RawContactsColumns.CONCRETE_ID + " = ?";
@@ -4860,9 +5085,9 @@ public class ContactsProvider2 extends AbstractContactsProvider
                             ? values.getAsString(RawContacts.DATA_SET) : oldDataSet
                         );
 
-                // The checkAccountIsWritable has to be done at the level of attempting to update
-                // each raw contacts, rather than at the beginning of attempting all selected raw
-                // contacts:
+                // The validateAccountForContactAddition has to be done at the level of attempting
+                // to update each raw contacts, rather than at the beginning of attempting all
+                // selected raw contacts:
                 // since not all of account field (name, type, data_set) are provided in the
                 // ContentValues @param, the destination account of each raw contact can be
                 // partially derived from the their existing account info, and thus can be
@@ -4871,8 +5096,11 @@ public class ContactsProvider2 extends AbstractContactsProvider
                 // a single transaction, failing checkAccountIsWritable will fail the entire update
                 // operation, which is clean such that no partial updated will be committed to the
                 // DB.
-                if (applyDefaultAccount) {
-                    mAccountResolver.checkAccountIsWritable(newAccountWithDataSet.getAccountName(),
+                if (applyDefaultAccount && CompatChanges.isChangeEnabled(
+                        ChangeIds.RESTRICT_CONTACTS_CREATION_IN_ACCOUNTS,
+                        Binder.getCallingUid())) {
+                    mAccountResolver.validateAccountForContactAddition(
+                            newAccountWithDataSet.getAccountName(),
                             newAccountWithDataSet.getAccountType());
                 }
 
@@ -5347,60 +5575,68 @@ public class ContactsProvider2 extends AbstractContactsProvider
     }
 
     private boolean updateAccountsInBackground(Account[] systemAccounts) {
-        if (!haveAccountsChanged(systemAccounts)) {
-            return false;
-        }
-        if (ContactsProperties.keep_stale_account_data().orElse(false)) {
-            Log.w(TAG, "Accounts changed, but not removing stale data for debug.contacts.ksad");
-            return true;
-        }
-        Log.i(TAG, "Accounts changed");
+        Trace.beginSection("updateAccountsInBackground");
+        try {
+            if (!haveAccountsChanged(systemAccounts)) {
+                return false;
+            }
+            if (ContactsProperties.keep_stale_account_data().orElse(false)) {
+                Log.w(TAG,
+                        "Accounts changed, but not removing stale data for debug.contacts.ksad");
+                return true;
+            }
+            Log.i(TAG, "Accounts changed");
 
-        invalidateFastScrollingIndexCache();
+            invalidateFastScrollingIndexCache();
 
-        final ContactsDatabaseHelper dbHelper = mDbHelper.get();
-        final SQLiteDatabase db = dbHelper.getWritableDatabase();
-        db.beginTransaction();
+            final ContactsDatabaseHelper dbHelper = mDbHelper.get();
+            final SQLiteDatabase db = dbHelper.getWritableDatabase();
+            db.beginTransaction();
 
-        // WARNING: This method can be run in either contacts mode or profile mode.  It is
-        // absolutely imperative that no calls be made inside the following try block that can
-        // interact with a specific contacts or profile DB.  Otherwise it is quite possible for a
-        // deadlock to occur.  i.e. always use the current database in mDbHelper and do not access
-        // mContactsHelper or mProfileHelper directly.
-        //
-        // The problem may be a bit more subtle if you also access something that stores the current
-        // db instance in its constructor.  updateSearchIndexInTransaction relies on the
-        // SearchIndexManager which upon construction, stores the current db. In this case,
-        // SearchIndexManager always contains the contact DB. This is why the
-        // updateSearchIndexInTransaction is protected with !isInProfileMode now.
-        try {
-            // First, remove stale rows from raw_contacts, groups, and related tables.
-
-            // All accounts that are used in raw_contacts and/or groups.
-            final Set<AccountWithDataSet> knownAccountsWithDataSets
-                    = dbHelper.getAllAccountsWithDataSets();
-            // All known SIM accounts
-            final List<SimAccount> simAccounts = getDatabaseHelper().getAllSimAccounts();
-            // Find the accounts that have been removed.
-            final List<AccountWithDataSet> accountsWithDataSetsToDelete = Lists.newArrayList();
-            for (AccountWithDataSet knownAccountWithDataSet : knownAccountsWithDataSets) {
-                if (knownAccountWithDataSet.isLocalAccount()
-                        || knownAccountWithDataSet.inSystemAccounts(systemAccounts)
-                        || knownAccountWithDataSet.inSimAccounts(simAccounts)) {
-                    continue;
+            // WARNING: This method can be run in either contacts mode or profile mode.  It is
+            // absolutely imperative that no calls be made inside the following try block that can
+            // interact with a specific contacts or profile DB.  Otherwise it is quite possible for
+            // a deadlock to occur.  i.e. always use the current database in mDbHelper and do not
+            // access mContactsHelper or mProfileHelper directly.
+            //
+            // The problem may be a bit more subtle if you also access something that stores the
+            // current db instance in its constructor.  updateSearchIndexInTransaction relies on the
+            // SearchIndexManager which upon construction, stores the current db. In this case,
+            // SearchIndexManager always contains the contact DB. This is why the
+            // updateSearchIndexInTransaction is protected with !isInProfileMode now.
+            try {
+                Trace.beginSection("removeDataOfAccount");
+                // First, remove stale rows from raw_contacts, groups, and related tables.
+
+                // All accounts that are used in raw_contacts and/or groups.
+                final Set<AccountWithDataSet> knownAccountsWithDataSets =
+                        dbHelper.getAllAccountsWithDataSets();
+                // All known SIM accounts
+                final List<SimAccount> simAccounts = getDatabaseHelper().getAllSimAccounts();
+                // Find the accounts that have been removed.
+                final List<AccountWithDataSet> accountsWithDataSetsToDelete = Lists.newArrayList();
+                for (AccountWithDataSet knownAccountWithDataSet : knownAccountsWithDataSets) {
+                    if (knownAccountWithDataSet.isLocalAccount()
+                            || knownAccountWithDataSet.inSystemAccounts(systemAccounts)
+                            || knownAccountWithDataSet.inSimAccounts(simAccounts)) {
+                        continue;
+                    }
+                    accountsWithDataSetsToDelete.add(knownAccountWithDataSet);
                 }
-                accountsWithDataSetsToDelete.add(knownAccountWithDataSet);
+
+                removeDataOfAccount(systemAccounts, accountsWithDataSetsToDelete, dbHelper, db);
+            } finally {
+                db.endTransaction();
+                Trace.endSection();
             }
+            mAccountWritability.clear();
 
-            removeDataOfAccount(systemAccounts, accountsWithDataSetsToDelete, dbHelper, db);
+            updateContactsAccountCount(systemAccounts);
+            updateProviderStatus();
+            return true;
         } finally {
-            db.endTransaction();
+            Trace.endSection();
         }
-        mAccountWritability.clear();
-
-        updateContactsAccountCount(systemAccounts);
-        updateProviderStatus();
-        return true;
     }
 
     private void removeDataOfAccount(Account[] systemAccounts,
@@ -5475,7 +5711,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
                                 ContactsTableUtil.deleteContact(db, contactId);
                                 if (cp2SyncSearchIndexFlag()) {
                                     mTransactionContext.get()
-                                            .invalidateSearchIndexForContact(contactId);
+                                            .invalidateSearchIndexForContact(db, contactId);
                                 }
                             }
                         } finally {
@@ -5503,7 +5739,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
                                         db, contactId);
                                 if (cp2SyncSearchIndexFlag()) {
                                     mTransactionContext.get()
-                                            .invalidateSearchIndexForContact(contactId);
+                                            .invalidateSearchIndexForContact(db, contactId);
                                 }
                             }
                         } finally {
@@ -5555,7 +5791,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
             if (!inProfileMode()) {
                 // Will remove the deleted contact ids of the account from the search index and
                 // will update the contacts in the search index which had a raw contact deleted.
-                updateSearchIndexInTransaction();
+                updateSearchIndexInTransaction(db);
             }
         }
 
@@ -10137,7 +10373,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
                 count = mContactAggregator.markAllVisibleForAggregation(db);
                 mContactAggregator.aggregateInTransaction(mTransactionContext.get(), db);
 
-                updateSearchIndexInTransaction();
+                updateSearchIndexInTransaction(db);
 
                 updateAggregationAlgorithmVersion();
 
@@ -10145,7 +10381,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
 
                 success = true;
             } finally {
-                mTransactionContext.get().clearAll();
+                mTransactionContext.get().clearAll(db);
                 if (transactionStarted) {
                     db.endTransaction();
                 }
@@ -10290,10 +10526,20 @@ public class ContactsProvider2 extends AbstractContactsProvider
      * @param values The {@link ContentValues} object to operate on.
      * @return The corresponding account ID.
      */
+    @RequiresPermission(
+            allOf = {
+                    android.Manifest.permission.READ_COMPAT_CHANGE_CONFIG,
+                    android.Manifest.permission.LOG_COMPAT_CHANGE
+            })
     private long replaceAccountInfoByAccountId(Uri uri, ContentValues values,
             boolean applyDefaultAccount) {
+        boolean shouldValidateAccountForContactAddition =
+                applyDefaultAccount && CompatChanges.isChangeEnabled(
+                        ChangeIds.RESTRICT_CONTACTS_CREATION_IN_ACCOUNTS,
+                        Binder.getCallingUid());
+
         final AccountWithDataSet account = mAccountResolver.resolveAccountWithDataSet(uri, values,
-                applyDefaultAccount);
+                applyDefaultAccount, shouldValidateAccountForContactAddition);
         final long id = mDbHelper.get().getOrCreateAccountIdInTransaction(account);
         values.put(RawContactsColumns.ACCOUNT_ID, id);
 
diff --git a/src/com/android/providers/contacts/DataRowHandler.java b/src/com/android/providers/contacts/DataRowHandler.java
index b1295c1f..b9becf16 100644
--- a/src/com/android/providers/contacts/DataRowHandler.java
+++ b/src/com/android/providers/contacts/DataRowHandler.java
@@ -28,7 +28,6 @@ import android.provider.ContactsContract.CommonDataKinds.StructuredName;
 import android.provider.ContactsContract.Data;
 import android.text.TextUtils;
 import android.util.Log;
-import android.util.LogWriter;
 
 import com.android.providers.contacts.ContactsDatabaseHelper.DataColumns;
 import com.android.providers.contacts.ContactsDatabaseHelper.MimetypesColumns;
@@ -144,7 +143,7 @@ public abstract class DataRowHandler {
         }
 
         if (containsSearchableColumns(values)) {
-            txContext.invalidateSearchIndexForRawContact(rawContactId);
+            txContext.invalidateSearchIndexForRawContact(db, rawContactId);
         }
 
         return dataId;
@@ -170,7 +169,7 @@ public abstract class DataRowHandler {
         }
 
         if (containsSearchableColumns(values)) {
-            txContext.invalidateSearchIndexForRawContact(rawContactId);
+            txContext.invalidateSearchIndexForRawContact(db, rawContactId);
         }
 
         txContext.markRawContactDirtyAndChanged(rawContactId, callerIsSyncAdapter);
@@ -327,7 +326,7 @@ public abstract class DataRowHandler {
         }
 
         if (hasSearchableData()) {
-            txContext.invalidateSearchIndexForRawContact(rawContactId);
+            txContext.invalidateSearchIndexForRawContact(db, rawContactId);
         }
 
         return count;
diff --git a/src/com/android/providers/contacts/DefaultAccount.java b/src/com/android/providers/contacts/DefaultAccount.java
deleted file mode 100644
index a8b41641..00000000
--- a/src/com/android/providers/contacts/DefaultAccount.java
+++ /dev/null
@@ -1,141 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-
-package com.android.providers.contacts;
-
-import android.accounts.Account;
-
-/**
- * Represents a default account with a category (UNKNOWN, DEVICE, or CLOUD)
- * and an optional associated Android Account object.
- */
-public class DefaultAccount {
-    /**
-     * The possible categories for a DefaultAccount.
-     */
-    public enum AccountCategory {
-        /**
-         * The account category is unknown. This is usually a temporary state.
-         */
-        UNKNOWN,
-
-        /**
-         * The account is a device-only account and not synced to the cloud.
-         */
-        DEVICE,
-
-        /**
-         * The account is synced to the cloud.
-         */
-        CLOUD
-    }
-
-
-    public static final DefaultAccount UNKNOWN_DEFAULT_ACCOUNT = new DefaultAccount(
-            AccountCategory.UNKNOWN, null);
-    public static final DefaultAccount DEVICE_DEFAULT_ACCOUNT = new DefaultAccount(
-            AccountCategory.DEVICE, null);
-
-    /**
-     * Create a DefaultAccount object which points to the cloud.
-     * @param cloudAccount The cloud account that is being set as the default account.
-     * @return The DefaultAccount object.
-     */
-    public static DefaultAccount ofCloud(Account cloudAccount) {
-        return new DefaultAccount(AccountCategory.CLOUD, cloudAccount);
-    }
-
-    private final AccountCategory mAccountCategory;
-    private final Account mCloudAccount;
-
-    /**
-     * Constructs a DefaultAccount object.
-     *
-     * @param accountCategory The category of the default account.
-     * @param cloudAccount    The account when mAccountCategory is CLOUD (null for
-     *                        DEVICE/UNKNOWN).
-     * @throws IllegalArgumentException If cloudAccount is null when accountCategory is
-     *                                  CLOUD,
-     *                                  or if cloudAccount is not null when accountCategory is not
-     *                                  CLOUD.
-     */
-    public DefaultAccount(AccountCategory accountCategory, Account cloudAccount) {
-        this.mAccountCategory = accountCategory;
-
-        // Validate cloudAccount based on accountCategory
-        if (accountCategory == AccountCategory.CLOUD && cloudAccount == null) {
-            throw new IllegalArgumentException(
-                    "Cloud account cannot be null when category is CLOUD");
-        } else if (accountCategory != AccountCategory.CLOUD && cloudAccount != null) {
-            throw new IllegalArgumentException(
-                    "Cloud account should be null when category is not CLOUD");
-        }
-
-        this.mCloudAccount = cloudAccount;
-    }
-
-    /**
-     * Gets the category of the account.
-     *
-     * @return The current category (UNKNOWN, DEVICE, or CLOUD).
-     */
-    public AccountCategory getAccountCategory() {
-        return mAccountCategory;
-    }
-
-    /**
-     * Gets the associated cloud account, if available.
-     *
-     * @return The Android Account object, or null if the category is not CLOUD.
-     */
-    public Account getCloudAccount() {
-        return mCloudAccount;
-    }
-
-    @Override
-    public boolean equals(Object o) {
-        if (this == o) return true; // Same object
-        if (o == null || getClass() != o.getClass()) return false; // Null or different class
-
-        DefaultAccount that = (DefaultAccount) o;
-
-        // Compare account categories first for efficiency
-        if (mAccountCategory != that.mAccountCategory) return false;
-
-        // If categories match, compare cloud accounts depending on category
-        if (mAccountCategory == AccountCategory.CLOUD) {
-            return mCloudAccount.equals(that.mCloudAccount); // Use Account's equals
-        } else {
-            return true; // Categories match and cloud account is irrelevant
-        }
-    }
-
-    @Override
-    public int hashCode() {
-        int result = mAccountCategory.hashCode();
-        if (mAccountCategory == AccountCategory.CLOUD) {
-            result = 31 * result + mCloudAccount.hashCode(); // Use Account's hashCode
-        }
-        return result;
-    }
-
-    @Override
-    public String toString() {
-        return String.format("{mAccountCategory: %s, mCloudAccount: %s}",
-                mAccountCategory, mCloudAccount);
-    }
-
-}
diff --git a/src/com/android/providers/contacts/DefaultAccountManager.java b/src/com/android/providers/contacts/DefaultAccountManager.java
index c42aac17..9c0545b8 100644
--- a/src/com/android/providers/contacts/DefaultAccountManager.java
+++ b/src/com/android/providers/contacts/DefaultAccountManager.java
@@ -19,13 +19,17 @@ import android.accounts.Account;
 import android.accounts.AccountManager;
 import android.content.Context;
 import android.content.res.Resources;
+import android.provider.ContactsContract;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
 import android.util.Log;
 
 import com.android.internal.R;
 import com.android.providers.contacts.util.NeededForTesting;
 
+import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashSet;
+import java.util.List;
 import java.util.Set;
 
 /**
@@ -78,65 +82,84 @@ public class DefaultAccountManager {
      * Try to push an account as the default account.
      *
      * @param defaultAccount account to be set as the default account.
-     * @return true if the default account is successfully updated.
+     * @return true if the default account is successfully updated, or no update is needed.
      */
     @NeededForTesting
-    public boolean tryPushDefaultAccount(DefaultAccount defaultAccount) {
+    public boolean tryPushDefaultAccount(DefaultAccountAndState defaultAccount) {
         if (!isValidDefaultAccount(defaultAccount)) {
             Log.w(TAG, "Attempt to push an invalid default account.");
             return false;
         }
 
-        DefaultAccount previousDefaultAccount = pullDefaultAccount();
+        DefaultAccountAndState previousDefaultAccount = pullDefaultAccount();
 
         if (defaultAccount.equals(previousDefaultAccount)) {
             Log.w(TAG, "Account has already been set as default before");
-            return false;
+        } else {
+            directlySetDefaultAccountInDb(defaultAccount);
         }
-
-        directlySetDefaultAccountInDb(defaultAccount);
         return true;
     }
 
-    private boolean isValidDefaultAccount(DefaultAccount defaultAccount) {
-        if (defaultAccount.getAccountCategory() == DefaultAccount.AccountCategory.CLOUD) {
-            return defaultAccount.getCloudAccount() != null
-                    && isSystemCloudAccount(defaultAccount.getCloudAccount())
-                    && !mSyncSettingsHelper.isSyncOff(defaultAccount.getCloudAccount());
+    private boolean isValidDefaultAccount(DefaultAccountAndState defaultAccount) {
+        if (defaultAccount.getState() == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD) {
+            return defaultAccount.getAccount() != null
+                    && isCloudAccount(defaultAccount.getAccount());
+
+        }
+        if (defaultAccount.getState() == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_SIM) {
+            return defaultAccount.getAccount() != null && isSimAccount(defaultAccount.getAccount());
+        }
+        return defaultAccount.getAccount() == null;
+    }
+
+    /**
+     * Get a list of cloud accounts that is eligible to set as the default account.
+     * @return the list of cloud accounts.
+     */
+    public List<Account> getEligibleCloudAccounts() {
+        List<Account> eligibleAccounts = new ArrayList<>();
+        Account[] accounts = mAccountManager.getAccounts();
+        for (Account account : accounts) {
+            if (isEligibleSystemCloudAccount(account)) {
+                eligibleAccounts.add(account);
+            }
         }
-        return defaultAccount.getCloudAccount() == null;
+        return eligibleAccounts;
     }
 
+
     /**
      * Pull the default account from the DB.
      */
     @NeededForTesting
-    public DefaultAccount pullDefaultAccount() {
-        DefaultAccount defaultAccount = getDefaultAccountFromDb();
-
+    public DefaultAccountAndState pullDefaultAccount() {
+        DefaultAccountAndState defaultAccount = getDefaultAccountFromDb();
         if (isValidDefaultAccount(defaultAccount)) {
             return defaultAccount;
         } else {
             Log.w(TAG, "Default account stored in the DB is no longer valid.");
-            directlySetDefaultAccountInDb(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
-            return DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT;
+            directlySetDefaultAccountInDb(DefaultAccountAndState.ofNotSet());
+            return DefaultAccountAndState.ofNotSet();
         }
     }
 
-    private void directlySetDefaultAccountInDb(DefaultAccount defaultAccount) {
-        switch (defaultAccount.getAccountCategory()) {
-            case UNKNOWN: {
+    private void directlySetDefaultAccountInDb(DefaultAccountAndState defaultAccount) {
+        switch (defaultAccount.getState()) {
+            case DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_NOT_SET: {
                 mDbHelper.clearDefaultAccount();
                 break;
             }
-            case DEVICE: {
+            case DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_LOCAL: {
                 mDbHelper.setDefaultAccount(AccountWithDataSet.LOCAL.getAccountName(),
                         AccountWithDataSet.LOCAL.getAccountType());
                 break;
             }
-            case CLOUD:
-                mDbHelper.setDefaultAccount(defaultAccount.getCloudAccount().name,
-                        defaultAccount.getCloudAccount().type);
+            case DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD:
+            case DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_SIM:
+                assert defaultAccount.getAccount() != null;
+                mDbHelper.setDefaultAccount(defaultAccount.getAccount().name,
+                        defaultAccount.getAccount().type);
                 break;
             default:
                 Log.e(TAG, "Incorrect default account category");
@@ -144,8 +167,24 @@ public class DefaultAccountManager {
         }
     }
 
-    private boolean isSystemCloudAccount(Account account) {
-        if (account == null || !getEligibleSystemAccountTypes(mContext).contains(account.type)) {
+    private boolean isSimAccount(Account account) {
+        if (account == null) {
+            return false;
+        }
+
+        final List<ContactsContract.SimAccount> simAccounts = mDbHelper.getAllSimAccounts();
+        AccountWithDataSet accountWithDataSet = new AccountWithDataSet(account.name, account.type,
+                null);
+        return accountWithDataSet.inSimAccounts(simAccounts);
+    }
+
+    private boolean isLocalAccount(Account account) {
+        return (account == null) || ((account.name.equals(AccountWithDataSet.LOCAL.getAccountName())
+                && account.type.equals(AccountWithDataSet.LOCAL.getAccountType())));
+    }
+
+    private boolean isCloudAccount(Account account) {
+        if (account == null) {
             return false;
         }
 
@@ -158,21 +197,27 @@ public class DefaultAccountManager {
         return false;
     }
 
-    private DefaultAccount getDefaultAccountFromDb() {
+    private boolean isEligibleSystemCloudAccount(Account account) {
+        return account != null && getEligibleSystemAccountTypes(mContext).contains(account.type)
+                && !mSyncSettingsHelper.isSyncOff(account);
+    }
+
+    private DefaultAccountAndState getDefaultAccountFromDb() {
         Account[] defaultAccountFromDb = mDbHelper.getDefaultAccountIfAny();
         if (defaultAccountFromDb.length == 0) {
-            return DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT;
+            return DefaultAccountAndState.ofNotSet();
         }
 
-        if (defaultAccountFromDb[0] == null) {
-            return DefaultAccount.DEVICE_DEFAULT_ACCOUNT;
+        Account account = defaultAccountFromDb[0];
+        if (isLocalAccount(account)) {
+            return DefaultAccountAndState.ofLocal();
         }
 
-        if (defaultAccountFromDb[0].name.equals(AccountWithDataSet.LOCAL.getAccountName())
-                && defaultAccountFromDb[0].type.equals(AccountWithDataSet.LOCAL.getAccountType())) {
-            return DefaultAccount.DEVICE_DEFAULT_ACCOUNT;
+        if (isSimAccount(account)) {
+            return DefaultAccountAndState.ofSim(account);
         }
 
-        return DefaultAccount.ofCloud(defaultAccountFromDb[0]);
+        // Assume it's cloud account.
+        return DefaultAccountAndState.ofCloud(account);
     }
 }
diff --git a/src/com/android/providers/contacts/EventLogTags.logtags b/src/com/android/providers/contacts/EventLogTags.logtags
index 823b5170..9dbf6b5e 100644
--- a/src/com/android/providers/contacts/EventLogTags.logtags
+++ b/src/com/android/providers/contacts/EventLogTags.logtags
@@ -1,4 +1,4 @@
-# See system/core/logcat/event.logtags for a description of the format of this file.
+# See system/logging/logcat/event.logtags for a description of the format of this file.
 
 option java_package com.android.providers.contacts;
 
diff --git a/src/com/android/providers/contacts/MoveContactsToDefaultAccountActivity.java b/src/com/android/providers/contacts/MoveContactsToDefaultAccountActivity.java
new file mode 100644
index 00000000..a7219051
--- /dev/null
+++ b/src/com/android/providers/contacts/MoveContactsToDefaultAccountActivity.java
@@ -0,0 +1,210 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+
+package com.android.providers.contacts;
+
+import static android.Manifest.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS;
+import static android.Manifest.permission.WRITE_CONTACTS;
+import static android.provider.ContactsContract.RawContacts.DefaultAccount;
+import static android.provider.Flags.newDefaultAccountApiEnabled;
+
+import android.accounts.Account;
+import android.accounts.AccountManager;
+import android.accounts.AuthenticatorDescription;
+import android.annotation.RequiresPermission;
+import android.app.Activity;
+import android.app.AlertDialog;
+import android.content.Context;
+import android.content.pm.PackageManager;
+import android.content.res.Resources;
+import android.icu.text.MessageFormat;
+import android.os.Bundle;
+import android.os.UserHandle;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
+import android.util.Log;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.providers.contacts.util.ContactsPermissions;
+import com.android.providers.contacts.util.NeededForTesting;
+
+import java.util.HashMap;
+import java.util.Locale;
+import java.util.Map;
+
+public class MoveContactsToDefaultAccountActivity extends Activity {
+    @VisibleForTesting
+    static final String MOVABLE_CONTACTS_MESSAGE_KEY = "contacts_count";
+    private static final String TAG = "MoveContactsToDefaultAccountActivity";
+    private Map<String, AuthenticatorDescription> mTypeToAuthDescription;
+
+    private UserHandle mUserHandle;
+
+    private int movableLocalContactsCount;
+
+    private int movableSimContactsCount;
+
+    @RequiresPermission(android.Manifest.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS)
+    @Override
+    protected void onCreate(Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
+        if (!newDefaultAccountApiEnabled()) {
+            Log.w(TAG, "Default Account API flag not enabled, bailing out.");
+            setResultAndFinish(RESULT_CANCELED);
+            return;
+        }
+        try {
+            DefaultAccountAndState currentDefaultAccount =
+                    DefaultAccount.getDefaultAccountForNewContacts(getContentResolver());
+            if (currentDefaultAccount.getState()
+                    == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD) {
+                mTypeToAuthDescription = new HashMap<>();
+                mUserHandle = new UserHandle(UserHandle.myUserId());
+                movableLocalContactsCount = DefaultAccount.getNumberOfMovableLocalContacts(
+                        getContentResolver());
+                movableSimContactsCount = DefaultAccount.getNumberOfMovableSimContacts(
+                        getContentResolver());
+                if (movableLocalContactsCount + movableSimContactsCount <= 0) {
+                    Log.i(TAG, "There's no movable contacts.");
+                    setResultAndFinish(RESULT_CANCELED);
+                    return;
+                } else if (!checkPermission(this)) {
+                    Log.e(TAG, "There's no contacts permission.");
+                    setResultAndFinish(RESULT_CANCELED);
+                    return;
+                }
+                showMoveContactsToDefaultAccountDialog(this, currentDefaultAccount);
+            } else {
+                Log.w(TAG, "Account is not cloud account, not eligible for moving local contacts.");
+                setResultAndFinish(RESULT_CANCELED);
+            }
+        } catch (IllegalStateException e) {
+            Log.e(TAG, "The default account is in an invalid state: " + e);
+            setResultAndFinish(RESULT_CANCELED);
+        } catch (RuntimeException e) {
+            Log.e(TAG, "Failed to look up the default account: " + e);
+            setResultAndFinish(RESULT_CANCELED);
+        }
+    }
+
+    private void showMoveContactsToDefaultAccountDialog(Context context,
+            DefaultAccountAndState currentDefaultAccount) {
+        Account account = currentDefaultAccount.getAccount();
+        if (account == null) {
+            Log.e(TAG, "The default account is null.");
+            setResultAndFinish(RESULT_CANCELED);
+            return;
+        }
+        String accountLabel = (String) getLabelForType(context, account.type);
+        if (accountLabel == null) {
+            Log.e(TAG, "Cannot get account label.");
+            setResultAndFinish(RESULT_CANCELED);
+            return;
+        }
+        AlertDialog.Builder builder = new AlertDialog.Builder(context);
+        int totalMovableContactsCount = movableSimContactsCount + movableLocalContactsCount;
+        builder.setTitle(getTitleText()).setMessage(
+                        getMessageText(totalMovableContactsCount, accountLabel, account.name))
+                .setPositiveButton(getSyncButtonText(), (dialog, which) -> {
+                    try {
+                        DefaultAccount.moveLocalContactsToCloudDefaultAccount(getContentResolver());
+                        DefaultAccount.moveSimContactsToCloudDefaultAccount(getContentResolver());
+                        Log.i(TAG,
+                                "Successfully moved all local and sim contacts to cloud account.");
+                        setResultAndFinish(RESULT_OK);
+                    } catch (RuntimeException e) {
+                        Log.e(TAG, "Failed to move contacts to cloud account.");
+                        setResultAndFinish(RESULT_CANCELED);
+                    }
+                })
+                .setNegativeButton(getCancelButtonText(),
+                        (dialog, choice) -> setResultAndFinish(RESULT_CANCELED))
+                .setOnDismissListener(dialog -> {
+                    dialog.dismiss();
+                    finish();
+                });
+        AlertDialog dialog = builder.create();
+        dialog.show();
+    }
+
+    private void setResultAndFinish(int resultCode) {
+        setResult(resultCode);
+        finish();
+    }
+
+    private boolean checkPermission(Context context) {
+        ContactsPermissions.enforceCallingOrSelfPermission(context, WRITE_CONTACTS);
+        ContactsPermissions.enforceCallingOrSelfPermission(context,
+                SET_DEFAULT_ACCOUNT_FOR_CONTACTS);
+        return true;
+    }
+
+    @NeededForTesting
+    String getMessageText(int movableContactsCount, String accountLabel,
+            String accountName) {
+        MessageFormat msgFormat = new MessageFormat(
+                getString(R.string.movable_contacts_count),
+                Locale.getDefault());
+        Map<String, Object> msgArgs = new HashMap<>();
+        msgArgs.put(MOVABLE_CONTACTS_MESSAGE_KEY, movableContactsCount);
+        String movableContactsCountText = msgFormat.format(msgArgs);
+        return getString(R.string.move_contacts_to_default_account_dialog_message,
+                movableContactsCountText, accountLabel, accountName);
+    }
+
+    @NeededForTesting
+    String getTitleText() {
+        return getString(R.string.move_contacts_to_default_account_dialog_title);
+    }
+
+    @NeededForTesting
+    String getSyncButtonText() {
+        return getString(R.string.move_contacts_to_default_account_dialog_sync_button_text);
+    }
+
+    @NeededForTesting
+    String getCancelButtonText() {
+        return getString(R.string.move_contacts_to_default_account_dialog_cancel_button_text);
+    }
+
+    /**
+     * Gets the label associated with a particular account type. If none found, return null.
+     *
+     * @param accountType the type of account
+     * @return a CharSequence for the label or null if one cannot be found.
+     */
+    @NeededForTesting
+    public CharSequence getLabelForType(Context context, final String accountType) {
+        AuthenticatorDescription[] authDescs = AccountManager.get(context)
+                .getAuthenticatorTypesAsUser(mUserHandle.getIdentifier());
+        for (AuthenticatorDescription authDesc : authDescs) {
+            mTypeToAuthDescription.put(authDesc.type, authDesc);
+        }
+        CharSequence label = null;
+        if (mTypeToAuthDescription.containsKey(accountType)) {
+            try {
+                AuthenticatorDescription desc = mTypeToAuthDescription.get(accountType);
+                Context authContext = context.createPackageContextAsUser(desc.packageName, 0,
+                        mUserHandle);
+                label = authContext.getResources().getText(desc.labelId);
+            } catch (PackageManager.NameNotFoundException e) {
+                Log.w(TAG, "No label name for account type " + accountType);
+            } catch (Resources.NotFoundException e) {
+                Log.w(TAG, "No label icon for account type " + accountType);
+            }
+        }
+        return label;
+    }
+}
diff --git a/src/com/android/providers/contacts/SearchIndexManager.java b/src/com/android/providers/contacts/SearchIndexManager.java
index 38a91f1a..4f6a5949 100644
--- a/src/com/android/providers/contacts/SearchIndexManager.java
+++ b/src/com/android/providers/contacts/SearchIndexManager.java
@@ -295,75 +295,101 @@ public class SearchIndexManager {
         }
     }
 
+    /**
+     * Updates the stale contact ids in the search index.
+     *
+     * <p>
+     * The stale contact ids used by this method are cached in the
+     * stale_search_index_contacts temp table. If the count of stale contacts
+     * is greater than the maximum amount of stale contacts, the search index
+     * is rebuilt completely. If not then only the stale contacts are updated.
+     *
+     * Stale contacts are contacts which have been either added, updated or deleted.
+     * Meaning the information in the search index for those contacts needs to be
+     * updated.
+     * </p>
+     *
+     * @param staleContactsCount The amount of cached stale contacts ids. Passing a
+     *          negative value or a value greater than the max amount of allowed stale
+     *          contacts will rebuild the entire search index.
+     */
+    public void updateIndexForRawContacts(long staleContactsCount) {
+        if (VERBOSE_LOGGING) {
+            Log.v(TAG, "Updating search index for " + staleContactsCount + " contacts");
+        }
+
+        final SQLiteDatabase db = mDbHelper.getWritableDatabase();
+
+        String contactIdsSelection = null;
+        String whereClause = null;
+
+        // If the amount of contacts which need to be re-synced in the search index
+        // surpasses the limit, then simply clear the entire search index table and
+        // and rebuild it.
+        if (staleContactsCount > 0 && staleContactsCount <= mMaxUpdateFilterContacts) {
+            // Selects all raw_contacts which contain a stale contact id in search index
+            contactIdsSelection =
+                    "raw_contacts.contact_id IN (SELECT id FROM stale_search_index_contacts)";
+            // Only remove the provided contacts
+            whereClause = "rowid IN (SELECT id FROM stale_search_index_contacts)";
+        }
+        db.delete(Tables.SEARCH_INDEX, whereClause, null);
+
+        // Rebuild search index. The selection is used to select raw_contacts. If the selection
+        // string is null the entire search index table will be rebuilt.
+        final int count = buildAndInsertIndex(db, contactIdsSelection);
+
+        if (VERBOSE_LOGGING) {
+            Log.v(TAG, "Updated search index for " + count + " contacts");
+        }
+    }
+
     public void updateIndexForRawContacts(Set<Long> contactIds, Set<Long> rawContactIds) {
+        if (cp2SyncSearchIndexFlag()) {
+            throw new UnsupportedOperationException();
+        }
         if (VERBOSE_LOGGING) {
             Log.v(TAG, "Updating search index for " + contactIds.size() +
                     " contacts / " + rawContactIds.size() + " raw contacts");
         }
-
-        final long contactsCount = contactIds.size() + rawContactIds.size();
-
         StringBuilder sb = new StringBuilder();
-        if (!cp2SyncSearchIndexFlag() || contactsCount <= mMaxUpdateFilterContacts) {
-            sb.append("(");
+        sb.append("(");
+        if (!contactIds.isEmpty()) {
+            // Select all raw contacts that belong to all contacts in contactIds
+            sb.append(RawContacts.CONTACT_ID + " IN (");
+            sb.append(TextUtils.join(",", contactIds));
+            sb.append(')');
+        }
+        if (!rawContactIds.isEmpty()) {
             if (!contactIds.isEmpty()) {
-                // Select all raw contacts that belong to all contacts in contactIds
-                sb.append(RawContacts.CONTACT_ID + " IN (");
-                sb.append(TextUtils.join(",", contactIds));
-                sb.append(')');
+                sb.append(" OR ");
             }
-            if (!rawContactIds.isEmpty()) {
-                if (!contactIds.isEmpty()) {
-                    sb.append(" OR ");
-                }
-                // Select all raw contacts that belong to the same contact as all raw contacts
-                // in rawContactIds. For every raw contact in rawContactIds that we are updating
-                // the index for, we need to rebuild the search index for all raw contacts belonging
-                // to the same contact, because we can only update the search index on a per-contact
-                // basis.
-                sb.append(RawContacts.CONTACT_ID + " IN "
-                        + "(SELECT " + RawContacts.CONTACT_ID + " FROM " + Tables.RAW_CONTACTS
-                        + " WHERE " + RawContactsColumns.CONCRETE_ID + " IN (");
-                sb.append(TextUtils.join(",", rawContactIds));
-                sb.append("))");
-            }
-            sb.append(")");
+            // Select all raw contacts that belong to the same contact as all raw contacts
+            // in rawContactIds. For every raw contact in rawContactIds that we are updating
+            // the index for, we need to rebuild the search index for all raw contacts belonging
+            // to the same contact, because we can only update the search index on a per-contact
+            // basis.
+            sb.append(RawContacts.CONTACT_ID + " IN "
+                    + "(SELECT " + RawContacts.CONTACT_ID + " FROM " + Tables.RAW_CONTACTS
+                    + " WHERE " + RawContactsColumns.CONCRETE_ID + " IN (");
+            sb.append(TextUtils.join(",", rawContactIds));
+            sb.append("))");
         }
 
-        // The selection to select raw_contacts. If the selection string is empty
-        // the entire search index table will be rebuilt.
-        String rawContactsSelection = sb.toString();
+        sb.append(")");
+
+        // The selection to select raw_contacts.
+        final String rawContactsSelection = sb.toString();
 
         // Remove affected search_index rows.
         final SQLiteDatabase db = mDbHelper.getWritableDatabase();
-        if (cp2SyncSearchIndexFlag()) {
-            // If the amount of contacts which need to be re-synced in the search index
-            // surpasses the limit, then simply clear the entire search index table and
-            // and rebuild it.
-            String whereClause = null;
-            if (contactsCount <= mMaxUpdateFilterContacts) {
-                // Only remove the provided contacts
-                whereClause =
-                    "rowid IN ("
-                        + TextUtils.join(",", contactIds)
-                    + """
-                    ) OR rowid IN (
-                        SELECT contact_id
-                        FROM raw_contacts
-                        WHERE raw_contacts._id IN ("""
-                            + TextUtils.join(",", rawContactIds)
-                    + "))";
-            }
-            db.delete(Tables.SEARCH_INDEX, whereClause, null);
-        } else {
-            db.delete(Tables.SEARCH_INDEX,
-                    ROW_ID_KEY + " IN (SELECT "
-                        + RawContacts.CONTACT_ID
-                        + " FROM " + Tables.RAW_CONTACTS
-                        + " WHERE " + rawContactsSelection
-                        + ")",
-                    null);
-        }
+        final int deleted = db.delete(Tables.SEARCH_INDEX,
+                ROW_ID_KEY + " IN (SELECT "
+                    + RawContacts.CONTACT_ID
+                    + " FROM " + Tables.RAW_CONTACTS
+                    + " WHERE " + rawContactsSelection
+                    + ")",
+                null);
 
         // Then rebuild index for them.
         final int count = buildAndInsertIndex(db, rawContactsSelection);
diff --git a/src/com/android/providers/contacts/TransactionContext.java b/src/com/android/providers/contacts/TransactionContext.java
index 86dae01b..91540a5c 100644
--- a/src/com/android/providers/contacts/TransactionContext.java
+++ b/src/com/android/providers/contacts/TransactionContext.java
@@ -16,12 +16,14 @@
 
 package com.android.providers.contacts;
 
+import static com.android.providers.contacts.flags.Flags.cp2SyncSearchIndexFlag;
+
+import android.database.Cursor;
+import android.database.sqlite.SQLiteDatabase;
+import android.database.sqlite.SQLiteStatement;
 import android.util.ArrayMap;
 import android.util.ArraySet;
 
-import com.google.android.collect.Maps;
-import com.google.android.collect.Sets;
-
 import java.util.Map.Entry;
 import java.util.Set;
 
@@ -89,14 +91,32 @@ public class TransactionContext  {
         mUpdatedSyncStates.put(rowId, data);
     }
 
-    public void invalidateSearchIndexForRawContact(long rawContactId) {
-        if (mStaleSearchIndexRawContacts == null) mStaleSearchIndexRawContacts = new ArraySet<>();
-        mStaleSearchIndexRawContacts.add(rawContactId);
-    }
-
-    public void invalidateSearchIndexForContact(long contactId) {
-        if (mStaleSearchIndexContacts == null) mStaleSearchIndexContacts = new ArraySet<>();
-        mStaleSearchIndexContacts.add(contactId);
+    public void invalidateSearchIndexForRawContact(SQLiteDatabase db, long rawContactId) {
+        if (!cp2SyncSearchIndexFlag()) {
+            if (mStaleSearchIndexRawContacts == null) {
+                mStaleSearchIndexRawContacts = new ArraySet<>();
+            }
+            mStaleSearchIndexRawContacts.add(rawContactId);
+            return;
+        }
+        createStaleSearchIndexTableIfNotExists(db);
+        db.execSQL("""
+                INSERT OR IGNORE INTO stale_search_index_contacts
+                    SELECT raw_contacts.contact_id
+                    FROM raw_contacts
+                    WHERE raw_contacts._id = ?""",
+                new Long[]{rawContactId});
+    }
+
+    public void invalidateSearchIndexForContact(SQLiteDatabase db, long contactId) {
+        if (!cp2SyncSearchIndexFlag()) {
+            if (mStaleSearchIndexContacts == null) mStaleSearchIndexContacts = new ArraySet<>();
+            mStaleSearchIndexContacts.add(contactId);
+            return;
+        }
+        createStaleSearchIndexTableIfNotExists(db);
+        db.execSQL("INSERT OR IGNORE INTO stale_search_index_contacts VALUES (?)",
+                new Long[]{contactId});
     }
 
     public Set<Long> getInsertedRawContactIds() {
@@ -120,15 +140,29 @@ public class TransactionContext  {
     }
 
     public Set<Long> getStaleSearchIndexRawContactIds() {
+        if (cp2SyncSearchIndexFlag()) {
+            throw new UnsupportedOperationException();
+        }
         if (mStaleSearchIndexRawContacts == null) mStaleSearchIndexRawContacts = new ArraySet<>();
         return mStaleSearchIndexRawContacts;
     }
 
     public Set<Long> getStaleSearchIndexContactIds() {
+        if (cp2SyncSearchIndexFlag()) {
+            throw new UnsupportedOperationException();
+        }
         if (mStaleSearchIndexContacts == null) mStaleSearchIndexContacts = new ArraySet<>();
         return mStaleSearchIndexContacts;
     }
 
+    public long getStaleSearchIndexContactIdsCount(SQLiteDatabase db) {
+        createStaleSearchIndexTableIfNotExists(db);
+        try (Cursor cursor =
+                db.rawQuery("SELECT COUNT(*) FROM stale_search_index_contacts", null)) {
+            return cursor.moveToFirst() ? cursor.getLong(0) : 0;
+        }
+    }
+
     public Set<Entry<Long, Object>> getUpdatedSyncStates() {
         if (mUpdatedSyncStates == null) mUpdatedSyncStates = new ArrayMap<>();
         return mUpdatedSyncStates.entrySet();
@@ -153,13 +187,30 @@ public class TransactionContext  {
         mBackupIdChangedRawContacts = null;
     }
 
-    public void clearSearchIndexUpdates() {
-        mStaleSearchIndexRawContacts = null;
-        mStaleSearchIndexContacts = null;
+    public void clearSearchIndexUpdates(SQLiteDatabase db) {
+        if (cp2SyncSearchIndexFlag()) {
+            db.delete("stale_search_index_contacts", null, null);
+        } else {
+            mStaleSearchIndexRawContacts = null;
+            mStaleSearchIndexContacts = null;
+        }
     }
 
-    public void clearAll() {
+    public void clearAll(SQLiteDatabase db) {
         clearExceptSearchIndexUpdates();
-        clearSearchIndexUpdates();
+        clearSearchIndexUpdates(db);
+    }
+
+    private void createStaleSearchIndexTableIfNotExists(SQLiteDatabase db) {
+        // Given the SQL query is a DDL statement if one uses SQLiteDatabase#execSQL
+        // to run it, it will trigger a clearing of the SQLite prepared statement cache.
+        // Clearing the cache results in worst performance when running recurring SQL
+        // queries. For this reason prefer to use a pre-compiled SQL statement, which
+        // bypasses the cache clearing.
+        try (SQLiteStatement statement = db.compileStatement("""
+                CREATE TEMP TABLE IF NOT EXISTS
+                 stale_search_index_contacts (id INTEGER PRIMARY KEY)""")) {
+            statement.execute();
+        }
     }
 }
diff --git a/src/com/android/providers/contacts/aggregation/ContactAggregator2.java b/src/com/android/providers/contacts/aggregation/ContactAggregator2.java
index 0accfb0e..147fd78b 100644
--- a/src/com/android/providers/contacts/aggregation/ContactAggregator2.java
+++ b/src/com/android/providers/contacts/aggregation/ContactAggregator2.java
@@ -390,7 +390,7 @@ public class ContactAggregator2 extends AbstractContactAggregator {
                     mAggregatedPresenceDelete.execute();
                     if (cp2SyncSearchIndexFlag()) {
                         // Make sure we remove the obsolete contact id from search index
-                        txContext.invalidateSearchIndexForContact(cid);
+                        txContext.invalidateSearchIndexForContact(db, cid);
                     }
                 } else {
                     updateAggregateData(txContext, cid);
diff --git a/tests/Android.bp b/tests/Android.bp
index 96a0cc1b..7a6dabb4 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -9,10 +9,14 @@ android_test {
     static_libs: [
         "ContactsProviderTestUtils",
         "androidx.test.rules",
+        "androidx.test.core",
+        "androidx.test.ext.junit",
+        "androidx.test.uiautomator_uiautomator",
         "mockito-target-minus-junit4",
         "flag-junit",
         "android.content.pm.flags-aconfig-java",
         "contactsprovider_flags_java_lib",
+        "platform-compat-test-rules",
     ],
     libs: [
         "android.test.runner.stubs.system",
@@ -45,9 +49,8 @@ test_module_config {
         },
         {
             name: "feature-flags:flag-value",
-            value: "contacts/com.android.providers.contacts.flags.enable_new_default_account_rule_flag=true",
+            value: "contacts/android.provider.new_default_account_api_enabled=true",
         },
-
     ],
 }
 
@@ -65,7 +68,7 @@ test_module_config {
         },
         {
             name: "feature-flags:flag-value",
-            value: "contacts/com.android.providers.contacts.flags.enable_new_default_account_rule_flag=false",
+            value: "contacts/android.provider.new_default_account_api_enabled=false",
         },
     ],
 }
diff --git a/tests/AndroidManifest.xml b/tests/AndroidManifest.xml
index 4d81c5f7..95b21b01 100644
--- a/tests/AndroidManifest.xml
+++ b/tests/AndroidManifest.xml
@@ -20,8 +20,12 @@
 
     <uses-permission android:name="android.permission.GET_ACCOUNTS" />
     <uses-permission android:name="android.permission.READ_SYNC_SETTINGS" />
+    <uses-permission android:name="android.permission.WRITE_CONTACTS" />
+    <uses-permission android:name="android.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS" />
 
-    <application>
+    <application
+        android:process="android.process.acore"
+        android:label="app_label">
         <uses-library android:name="android.test.runner" />
 
         <!-- Mock contacts sync adapter -->
@@ -34,6 +38,12 @@
             <meta-data android:name="android.provider.CONTACTS_STRUCTURE"
                 android:resource="@xml/contacts" />
         </service>
+
+        <activity
+            android:name="com.android.providers.contacts.MoveContactsToDefaultAccountActivityTest$TestMoveContactsToDefaultAccountActivity"
+            android:enabled="true"
+            android:exported="true">
+        </activity>
     </application>
 
     <instrumentation
diff --git a/tests/src/com/android/providers/contacts/AccountResolverTest.java b/tests/src/com/android/providers/contacts/AccountResolverTest.java
index c0f82f3a..7505f1ca 100644
--- a/tests/src/com/android/providers/contacts/AccountResolverTest.java
+++ b/tests/src/com/android/providers/contacts/AccountResolverTest.java
@@ -16,6 +16,8 @@
 
 package com.android.providers.contacts;
 
+import static android.provider.ContactsContract.SimAccount.SDN_EF_TYPE;
+
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertThrows;
@@ -24,12 +26,12 @@ import static org.mockito.Mockito.when;
 import android.accounts.Account;
 import android.content.ContentValues;
 import android.net.Uri;
+import android.provider.ContactsContract;
 import android.provider.ContactsContract.RawContacts;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
 
 import androidx.test.filters.SmallTest;
 
-import com.android.providers.contacts.DefaultAccount.AccountCategory;
-
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -37,6 +39,8 @@ import org.junit.runners.JUnit4;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
+import java.util.List;
+
 @SmallTest
 @RunWith(JUnit4.class)
 public class AccountResolverTest {
@@ -47,12 +51,22 @@ public class AccountResolverTest {
 
     private AccountResolver mAccountResolver;
 
+    private static final Account SIM_ACCOUNT_1 = new Account("simName1", "SIM");
+
     @Before
     public void setUp() {
         MockitoAnnotations.initMocks(this);
         mAccountResolver = new AccountResolver(mDbHelper, mDefaultAccountManager);
+
+        when(mDbHelper.getAllSimAccounts()).thenReturn(List.of(new ContactsContract.SimAccount(
+                SIM_ACCOUNT_1.name, SIM_ACCOUNT_1.type, 1, SDN_EF_TYPE
+        )));
+
     }
 
+    private static final boolean FALSE_UNUSED = false;
+    private static final boolean TRUE_UNUSED = true;
+
     @Test
     public void testResolveAccountWithDataSet_ignoreDefaultAccount_accountAndDataSetInUri() {
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
@@ -64,7 +78,8 @@ public class AccountResolverTest {
         ContentValues values = new ContentValues();
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                false, /*shouldValidateAccountForContactAddition=*/TRUE_UNUSED);
 
         assertEquals("test_account", result.getAccountName());
         assertEquals("com.google", result.getAccountType());
@@ -73,9 +88,9 @@ public class AccountResolverTest {
     }
 
     @Test
-    public void testResolveAccountWithDataSet_defaultAccountIsUnknown_accountAndDataSetInUri() {
+    public void testResolveAccountWithDataSet_defaultAccountIsNotSet_accountAndDataSetInUri() {
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
 
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
                 .buildUpon()
@@ -86,7 +101,8 @@ public class AccountResolverTest {
         ContentValues values = new ContentValues();
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/true);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
 
         assertEquals("test_account", result.getAccountName());
         assertEquals("com.google", result.getAccountType());
@@ -105,7 +121,8 @@ public class AccountResolverTest {
         values.put(RawContacts.DATA_SET, "test_data_set");
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
 
         assertEquals("test_account", result.getAccountName());
         assertEquals("com.google", result.getAccountType());
@@ -115,8 +132,8 @@ public class AccountResolverTest {
 
     @Test
     public void testResolveAccountWithDataSet_applyDefaultAccount_accountInUriDataSetInValues() {
-        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(new DefaultAccount(
-                AccountCategory.CLOUD, new Account("randomaccount1@gmail.com", "com.google")));
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(DefaultAccountAndState.ofCloud(
+                new Account("randomaccount1@gmail.com", "com.google")));
 
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
                 .buildUpon()
@@ -127,7 +144,8 @@ public class AccountResolverTest {
         values.put(RawContacts.DATA_SET, "test_data_set");
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
 
         assertEquals("test_account", result.getAccountName());
         assertEquals("com.google", result.getAccountType());
@@ -141,51 +159,68 @@ public class AccountResolverTest {
         ContentValues values = new ContentValues();
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                false, /*shouldValidateAccountForContactAddition=*/TRUE_UNUSED);
 
+        // When default account is not used, uri/values without account is always resolved as
+        // the local account, which is null AccountWithDataSet in this case.
         assertNull(result);
     }
 
     @Test
-    public void testResolveAccountWithDataSet_defaultAccountIsUnknown_noAccount() {
+    public void testResolveAccountWithDataSet_defaultAccountIsNotSet_noAccount() {
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
 
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
         ContentValues values = new ContentValues();
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
 
+        // When default account is used and the default account is not set, uri/values without
+        // account is always resolved as the local account, which is null AccountWithDataSet in this
+        // case.
         assertNull(result);
     }
 
     @Test
     public void testResolveAccountWithDataSet_defaultAccountIsDevice_noAccount() {
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofLocal());
 
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
         ContentValues values = new ContentValues();
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
 
+        // When default account is used and the default account is set to 'local', uri/values
+        // without account is always resolved as the local account, which is null
+        // AccountWithDataSet in this case.
         assertNull(result);
     }
 
     @Test
     public void testResolveAccountWithDataSet_defaultAccountIsCloud_noAccount() {
-        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(new DefaultAccount(
-                AccountCategory.CLOUD, new Account("randomaccount1@gmail.com", "com.google")));
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(DefaultAccountAndState.ofCloud(
+                new Account("test_account", "com.google")));
 
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
         ContentValues values = new ContentValues();
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
 
-        assertNull(result);
+        // When default account is used and the default account is set to 'cloud', uri/values
+        // without account is always resolved as the cloud account, which is null
+        // AccountWithDataSet in this case.
+        assertEquals("test_account", result.getAccountName());
+        assertEquals("com.google", result.getAccountType());
+        assertNull(result.getDataSet());
     }
 
     @Test
@@ -197,17 +232,19 @@ public class AccountResolverTest {
         values.put(RawContacts.DATA_SET, "test_data_set");
 
         AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
 
         assertEquals("test_account", result1.getAccountName());
         assertEquals("com.google", result1.getAccountType());
         assertEquals("test_data_set", result1.getDataSet());
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
 
         AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/true);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
 
         assertEquals("test_account", result2.getAccountName());
         assertEquals("com.google", result2.getAccountType());
@@ -232,15 +269,16 @@ public class AccountResolverTest {
         // Expecting an exception due to the invalid account in the URI
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values,
-                    /*applyDefaultAccount=*/false);
+                    /*applyDefaultAccount=*/false, /*shouldValidateAccountForContactAddition=*/
+                    TRUE_UNUSED);
         });
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
         // Expecting an exception due to the invalid account in the URI
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values,
-                    /*applyDefaultAccount=*/true);
+                    /*applyDefaultAccount=*/true, /*shouldValidateAccountForContactAddition=*/true);
         });
     }
 
@@ -261,14 +299,16 @@ public class AccountResolverTest {
 
         // Expecting an exception due to the invalid account in the values
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
         });
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofLocal());
         // Expecting an exception due to the invalid account in the URI
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
     }
 
@@ -285,17 +325,19 @@ public class AccountResolverTest {
         values.put(RawContacts.DATA_SET, "test_data_set");
 
         AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                false, /*shouldValidateAccountForContactAddition=*/TRUE_UNUSED);
 
         assertEquals("test_account", result1.getAccountName());
         assertEquals("com.google", result1.getAccountType());
         assertEquals("test_data_set", result1.getDataSet());
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofLocal());
 
         AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
 
         assertEquals("test_account", result2.getAccountName());
         assertEquals("com.google", result2.getAccountType());
@@ -318,27 +360,31 @@ public class AccountResolverTest {
 
         // Expecting an exception due to the invalid account in the URI
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
         });
 
         // Expecting an exception due to the invalid account in the URI, regardless of what is the
         // default account
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofLocal());
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, new Account(
+                DefaultAccountAndState.ofCloud(new Account(
                         "test_account", "com.google"
                 )));
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
     }
 
@@ -355,28 +401,32 @@ public class AccountResolverTest {
                 .thenReturn("Test Exception Message");
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    false, /*shouldValidateAccountForContactAddition=*/TRUE_UNUSED);
         });
         assertEquals("Test Exception Message", exception.getMessage());
 
         // Expecting an exception due to the partial account in uri, regardless of what is the
         // default account
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofLocal());
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, new Account(
+                DefaultAccountAndState.ofCloud(new Account(
                         "test_account", "com.google"
                 )));
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
     }
 
@@ -391,32 +441,36 @@ public class AccountResolverTest {
                 .thenReturn("Test Exception Message");
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
         });
         assertEquals("Test Exception Message", exception.getMessage());
 
         // Expecting an exception due to the partial account in uri, regardless of what is the
         // default account
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofLocal());
         exception = assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
         assertEquals("Test Exception Message", exception.getMessage());
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
         exception = assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
         assertEquals("Test Exception Message", exception.getMessage());
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, new Account(
+                DefaultAccountAndState.ofCloud(new Account(
                         "test_account", "com.google"
                 )));
         exception = assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
         assertEquals("Test Exception Message", exception.getMessage());
     }
@@ -437,25 +491,28 @@ public class AccountResolverTest {
                 .thenReturn("Test Exception Message");
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    false, /*shouldValidateAccountForContactAddition=*/TRUE_UNUSED);
         });
         assertEquals("Test Exception Message", exception.getMessage());
 
         // Expecting an exception due to the uri and content value's account info mismatching,
         // regardless of what is the default account
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
         exception = assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
         assertEquals("Test Exception Message", exception.getMessage());
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, new Account(
+                DefaultAccountAndState.ofCloud(new Account(
                         "test_account", "com.google"
                 )));
         exception = assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
         assertEquals("Test Exception Message", exception.getMessage());
     }
@@ -470,13 +527,14 @@ public class AccountResolverTest {
         ContentValues values = new ContentValues();
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
 
         assertNull(result); // Expect null result as account is effectively absent
     }
 
     @Test
-    public void testResolveAccountWithDataSet_defaultAccountIsDeviceOrUnknown_emptyAccountInUri() {
+    public void testResolveAccountWithDataSet_defaultAccountIsDeviceOrNotSet_emptyAccountInUri() {
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
                 .buildUpon()
                 .appendQueryParameter(RawContacts.ACCOUNT_NAME, "")
@@ -485,15 +543,17 @@ public class AccountResolverTest {
         ContentValues values = new ContentValues();
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
         AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/true);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
         assertNull(result1); // Expect null result as account is effectively absent
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofLocal());
         AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/true);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
         assertNull(result2); // Expect null result as account is effectively absent
     }
 
@@ -507,16 +567,80 @@ public class AccountResolverTest {
         ContentValues values = new ContentValues();
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                new DefaultAccount(AccountCategory.CLOUD,
+                DefaultAccountAndState.ofCloud(
+                        new Account("test_user2", "com.google")));
+
+        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
+        });
+        assertEquals(
+                "Cannot add contacts to local or SIM accounts when default account is set to cloud",
+                exception.getMessage());
+    }
+
+    @Test
+    public void testResolveAccount_defaultAccountIsCloud_emptyAccountInUri_skipAccountValidation() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "")
+                .build();
+        ContentValues values = new ContentValues();
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccountAndState.ofCloud(
+                        new Account("test_user2", "com.google")));
+
+        AccountWithDataSet result =
+                mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                        true, /*shouldValidateAccountForContactAddition=*/false);
+        assertNull(result);
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_defaultAccountIsCloud_simAccountInUri() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, SIM_ACCOUNT_1.name)
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, SIM_ACCOUNT_1.type)
+                .build();
+        ContentValues values = new ContentValues();
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccountAndState.ofCloud(
                         new Account("test_user2", "com.google")));
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
-        assertEquals("Cannot write contacts to local accounts when default account is set to cloud",
+        assertEquals(
+                "Cannot add contacts to local or SIM accounts when default account is set to cloud",
                 exception.getMessage());
     }
 
+    @Test
+    public void testResolveAccount_defaultAccountIsCloud_simAccountInUri_skipAccountValidation() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, SIM_ACCOUNT_1.name)
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, SIM_ACCOUNT_1.type)
+                .build();
+        ContentValues values = new ContentValues();
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccountAndState.ofCloud(
+                        new Account("test_user2", "com.google")));
+
+        AccountWithDataSet result =
+                mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                        true, /*shouldValidateAccountForContactAddition=*/false);
+        assertEquals(SIM_ACCOUNT_1.name, result.getAccountName());
+        assertEquals(SIM_ACCOUNT_1.type, result.getAccountType());
+        assertNull(result.getDataSet());
+    }
+
     @Test
     public void testResolveAccountWithDataSet_ignoreDefaultAccount_emptyAccountInValues() {
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
@@ -525,29 +649,32 @@ public class AccountResolverTest {
         values.put(RawContacts.ACCOUNT_TYPE, "");
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
 
         assertNull(result); // Expect null result as account is effectively absent
     }
 
 
     @Test
-    public void testResolveAccountWithDataSet_defaultAccountDeviceOrUnknown_emptyAccountInValues() {
+    public void testResolveAccountWithDataSet_defaultAccountDeviceOrNotSet_emptyAccountInValues() {
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
         ContentValues values = new ContentValues();
         values.put(RawContacts.ACCOUNT_NAME, "");
         values.put(RawContacts.ACCOUNT_TYPE, "");
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
         AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/true);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
         assertNull(result1); // Expect null result as account is effectively absent
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofLocal());
         AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/true);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
         assertNull(result2); // Expect null result as account is effectively absent
     }
 
@@ -560,18 +687,37 @@ public class AccountResolverTest {
         values.put(RawContacts.ACCOUNT_TYPE, "");
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                new DefaultAccount(AccountCategory.CLOUD,
+                DefaultAccountAndState.ofCloud(
                         new Account("test_user2", "com.google")));
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
-        assertEquals("Cannot write contacts to local accounts when default account is set to cloud",
+        assertEquals(
+                "Cannot add contacts to local or SIM accounts when default account is set to cloud",
                 exception.getMessage());
     }
 
     @Test
-    public void testResolveAccountWithDataSet_ignoreDefaultAccount_emptyAccountInUriAndValues() {
+    public void testResolveAccount_defaultAccountIsCloud_emptyAccountInValues_skipAccountCheck() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "");
+        values.put(RawContacts.ACCOUNT_TYPE, "");
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccountAndState.ofCloud(
+                        new Account("test_user2", "com.google")));
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(uri,
+                values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/false);
+        assertNull(result);
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_ignoreDefaultAccount_emptyAccount() {
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
                 .buildUpon()
                 .appendQueryParameter(RawContacts.ACCOUNT_NAME, "")
@@ -582,13 +728,14 @@ public class AccountResolverTest {
         values.put(RawContacts.ACCOUNT_TYPE, "");
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                false, /*shouldValidateAccountForContactAddition=*/TRUE_UNUSED);
 
         assertNull(result); // Expect null result as account is effectively absent
     }
 
     @Test
-    public void testResolveAccountWithDataSet_defaultDeviceOrUnknown_emptyAccountInUriAndValues() {
+    public void testResolveAccountWithDataSet_defaultDeviceOrNotSet_emptyAccount() {
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
                 .buildUpon()
                 .appendQueryParameter(RawContacts.ACCOUNT_NAME, "")
@@ -599,20 +746,22 @@ public class AccountResolverTest {
         values.put(RawContacts.ACCOUNT_TYPE, "");
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
         AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/true);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
         assertNull(result1); // Expect null result as account is effectively absent
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofLocal());
         AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/true);
+                uri, values, /*applyDefaultAccount=*/
+                true, /*shouldValidateAccountForContactAddition=*/true);
         assertNull(result2); // Expect null result as account is effectively absent
     }
 
     @Test
-    public void testResolveAccountWithDataSet_defaultAccountIsCloud_emptyAccountInUriAndValues() {
+    public void testResolveAccountWithDataSet_defaultAccountIsCloud_emptyAccount() {
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
                 .buildUpon()
                 .appendQueryParameter(RawContacts.ACCOUNT_NAME, "")
@@ -623,95 +772,126 @@ public class AccountResolverTest {
         values.put(RawContacts.ACCOUNT_TYPE, "");
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
-                uri, values, /*applyDefaultAccount=*/false);
+                uri, values, /*applyDefaultAccount=*/
+                false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
 
         assertNull(result); // Expect null result as account is effectively absent
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                new DefaultAccount(AccountCategory.CLOUD,
+                DefaultAccountAndState.ofCloud(
                         new Account("test_user2", "com.google")));
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/true);
         });
-        assertEquals("Cannot write contacts to local accounts when default account is set to cloud",
+        assertEquals(
+                "Cannot add contacts to local or SIM accounts when default account is set to cloud",
                 exception.getMessage());
     }
 
 
     @Test
-    public void testCheckAccountIsWritable_bothAccountNameAndTypeAreNullOrEmpty_NoException() {
+    public void testResolveAccount_defaultAccountIsCloud_emptyAccount_skipAccountCheck() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "")
+                .build();
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "");
+        values.put(RawContacts.ACCOUNT_TYPE, "");
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/
+                false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
+
+        assertNull(result); // Expect null result as account is effectively absent
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccountAndState.ofCloud(
+                        new Account("test_user2", "com.google")));
+
+        result = mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
+                    true, /*shouldValidateAccountForContactAddition=*/false);
+
+        assertNull(result);
+    }
+
+
+    @Test
+    public void testValidateAccountIsWritable_bothAccountNameAndTypeAreNullOrEmpty_NoException() {
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
 
-        mAccountResolver.checkAccountIsWritable("", "");
-        mAccountResolver.checkAccountIsWritable(null, "");
-        mAccountResolver.checkAccountIsWritable("", null);
-        mAccountResolver.checkAccountIsWritable(null, null);
+        mAccountResolver.validateAccountForContactAddition("", "");
+        mAccountResolver.validateAccountForContactAddition(null, "");
+        mAccountResolver.validateAccountForContactAddition("", null);
+        mAccountResolver.validateAccountForContactAddition(null, null);
         // No exception expected
     }
 
     @Test
-    public void testCheckAccountIsWritable_eitherAccountNameOrTypeEmpty_ThrowsException() {
+    public void testValidateAccountIsWritable_eitherAccountNameOrTypeEmpty_ThrowsException() {
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
 
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.checkAccountIsWritable("accountName", "");
+            mAccountResolver.validateAccountForContactAddition("accountName", "");
         });
 
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.checkAccountIsWritable("accountName", null);
+            mAccountResolver.validateAccountForContactAddition("accountName", null);
         });
 
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.checkAccountIsWritable("", "accountType");
+            mAccountResolver.validateAccountForContactAddition("", "accountType");
         });
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.checkAccountIsWritable(null, "accountType");
+            mAccountResolver.validateAccountForContactAddition(null, "accountType");
         });
     }
 
     @Test
-    public void testCheckAccountIsWritable_defaultAccountIsCloud() {
+    public void testValidateAccountIsWritable_defaultAccountIsCloud() {
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                new DefaultAccount(AccountCategory.CLOUD,
+                DefaultAccountAndState.ofCloud(
                         new Account("test_user1", "com.google")));
 
-        mAccountResolver.checkAccountIsWritable("test_user1", "com.google");
-        mAccountResolver.checkAccountIsWritable("test_user2", "com.google");
-        mAccountResolver.checkAccountIsWritable("test_user3", "com.whatsapp");
+        mAccountResolver.validateAccountForContactAddition("test_user1", "com.google");
+        mAccountResolver.validateAccountForContactAddition("test_user2", "com.google");
+        mAccountResolver.validateAccountForContactAddition("test_user3", "com.whatsapp");
         assertThrows(IllegalArgumentException.class, () ->
-                mAccountResolver.checkAccountIsWritable("", ""));
+                mAccountResolver.validateAccountForContactAddition("", ""));
         assertThrows(IllegalArgumentException.class, () ->
-                mAccountResolver.checkAccountIsWritable(null, null));
+                mAccountResolver.validateAccountForContactAddition(null, null));
         // No exception expected
     }
 
     @Test
-    public void testCheckAccountIsWritable_defaultAccountIsDevice() {
+    public void testValidateAccountIsWritable_defaultAccountIsDevice() {
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofLocal());
 
-        mAccountResolver.checkAccountIsWritable("test_user1", "com.google");
-        mAccountResolver.checkAccountIsWritable("test_user2", "com.google");
-        mAccountResolver.checkAccountIsWritable("test_user3", "com.whatsapp");
-        mAccountResolver.checkAccountIsWritable("", "");
-        mAccountResolver.checkAccountIsWritable(null, null);
+        mAccountResolver.validateAccountForContactAddition("test_user1", "com.google");
+        mAccountResolver.validateAccountForContactAddition("test_user2", "com.google");
+        mAccountResolver.validateAccountForContactAddition("test_user3", "com.whatsapp");
+        mAccountResolver.validateAccountForContactAddition("", "");
+        mAccountResolver.validateAccountForContactAddition(null, null);
         // No exception expected
     }
 
 
     @Test
-    public void testCheckAccountIsWritable_defaultAccountIsUnknown() {
+    public void testValidateAccountIsWritable_defaultAccountIsNotSet() {
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
-                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+                DefaultAccountAndState.ofNotSet());
 
-        mAccountResolver.checkAccountIsWritable("test_user1", "com.google");
-        mAccountResolver.checkAccountIsWritable("test_user2", "com.google");
-        mAccountResolver.checkAccountIsWritable("test_user3", "com.whatsapp");
-        mAccountResolver.checkAccountIsWritable("", "");
-        mAccountResolver.checkAccountIsWritable(null, null);
+        mAccountResolver.validateAccountForContactAddition("test_user1", "com.google");
+        mAccountResolver.validateAccountForContactAddition("test_user2", "com.google");
+        mAccountResolver.validateAccountForContactAddition("test_user3", "com.whatsapp");
+        mAccountResolver.validateAccountForContactAddition("", "");
+        mAccountResolver.validateAccountForContactAddition(null, null);
         // No exception expected
     }
 }
diff --git a/tests/src/com/android/providers/contacts/BaseContactsProvider2Test.java b/tests/src/com/android/providers/contacts/BaseContactsProvider2Test.java
index 9f433987..dc8c917b 100644
--- a/tests/src/com/android/providers/contacts/BaseContactsProvider2Test.java
+++ b/tests/src/com/android/providers/contacts/BaseContactsProvider2Test.java
@@ -899,6 +899,20 @@ public abstract class BaseContactsProvider2Test extends PhotoLoadingTestCase {
         mResolver.update(contentUri, values, null, null);
     }
 
+
+    protected void storeValues(Uri contentUri, long id, Map<String, String> columnValueMap) {
+        storeValues(ContentUris.withAppendedId(contentUri, id), columnValueMap);
+    }
+
+    protected void storeValues(Uri contentUri, Map<String, String> columnValueMap) {
+        ContentValues values = new ContentValues();
+        for (String key : columnValueMap.keySet()) {
+            values.put(key, columnValueMap.get(key));
+        }
+        mResolver.update(contentUri, values, null, null);
+    }
+
+
     protected void storeValue(Uri contentUri, long id, String column, long value) {
         storeValue(ContentUris.withAppendedId(contentUri, id), column, value);
     }
diff --git a/tests/src/com/android/providers/contacts/ContactLookupKeyTest.java b/tests/src/com/android/providers/contacts/ContactLookupKeyTest.java
index f5a3d725..0aec4bf7 100644
--- a/tests/src/com/android/providers/contacts/ContactLookupKeyTest.java
+++ b/tests/src/com/android/providers/contacts/ContactLookupKeyTest.java
@@ -27,6 +27,8 @@ import androidx.test.filters.MediumTest;
 import com.android.providers.contacts.ContactLookupKey.LookupKeySegment;
 import com.android.providers.contacts.testutil.RawContactUtil;
 
+import com.google.common.collect.ImmutableMap;
+
 import java.util.ArrayList;
 
 /**
@@ -108,13 +110,13 @@ public class ContactLookupKeyTest extends BaseContactsProvider2Test {
 
     public void testLookupKeySameSourceIdDifferentAccounts() {
         long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, "Dear", "Doe");
-        storeValue(RawContacts.CONTENT_URI, rawContactId1, RawContacts.ACCOUNT_TYPE, "foo");
-        storeValue(RawContacts.CONTENT_URI, rawContactId1, RawContacts.ACCOUNT_NAME, "FOO");
+        storeValues(RawContacts.CONTENT_URI, rawContactId1,
+                ImmutableMap.of(RawContacts.ACCOUNT_TYPE, "foo", RawContacts.ACCOUNT_NAME, "FOO"));
         storeValue(RawContacts.CONTENT_URI, rawContactId1, RawContacts.SOURCE_ID, "1");
 
         long rawContactId2 = RawContactUtil.createRawContactWithName(mResolver, "Deer", "Dough");
-        storeValue(RawContacts.CONTENT_URI, rawContactId2, RawContacts.ACCOUNT_TYPE, "bar");
-        storeValue(RawContacts.CONTENT_URI, rawContactId2, RawContacts.ACCOUNT_NAME, "BAR");
+        storeValues(RawContacts.CONTENT_URI, rawContactId2,
+                ImmutableMap.of(RawContacts.ACCOUNT_TYPE, "bar", RawContacts.ACCOUNT_NAME, "BAR"));
         storeValue(RawContacts.CONTENT_URI, rawContactId2, RawContacts.SOURCE_ID, "1");
 
         assertNotAggregated(rawContactId1, rawContactId2);
diff --git a/tests/src/com/android/providers/contacts/ContactsActor.java b/tests/src/com/android/providers/contacts/ContactsActor.java
index 9e5c69a5..53511a65 100644
--- a/tests/src/com/android/providers/contacts/ContactsActor.java
+++ b/tests/src/com/android/providers/contacts/ContactsActor.java
@@ -85,8 +85,10 @@ import java.io.IOException;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
+import java.util.HashMap;
 import java.util.List;
 import java.util.Locale;
+import java.util.Map;
 import java.util.Set;
 
 /**
@@ -148,6 +150,25 @@ public class ContactsActor {
             return mAccounts;
         }
 
+        @Override
+        public Account[] getAccountsByType(final String type) {
+            Map<String, List<Account>> accountTypeMap = new HashMap<>();
+            for (Account account : mAccounts) {
+                if (accountTypeMap.containsKey(account.type)) {
+                    accountTypeMap.get(account.type).add(account);
+                } else {
+                    List<Account> accountList = new ArrayList<>();
+                    accountList.add(account);
+                    accountTypeMap.put(account.type, accountList);
+                }
+            }
+            if (accountTypeMap.containsKey(type)) {
+                return accountTypeMap.get(type).toArray(new Account[0]);
+            } else {
+                return new Account[0];
+            }
+        }
+
         @Override
         public AccountManagerFuture<Account[]> getAccountsByTypeAndFeatures(
                 final String type, final String[] features,
@@ -293,11 +314,11 @@ public class ContactsActor {
         }
 
         @Override
-        public List<String> getPackagesWithCarrierPrivileges() {
+        public Set<String> getPackagesWithCarrierPrivileges() {
             if (!mHasCarrierPrivileges) {
-                return Collections.emptyList();
+                return Collections.emptySet();
             }
-            return Collections.singletonList(packageName);
+            return Collections.singleton(packageName);
         }
     }
 
diff --git a/tests/src/com/android/providers/contacts/ContactsProvider2DefaultAccountTest.java b/tests/src/com/android/providers/contacts/ContactsProvider2DefaultAccountTest.java
new file mode 100644
index 00000000..bab73f47
--- /dev/null
+++ b/tests/src/com/android/providers/contacts/ContactsProvider2DefaultAccountTest.java
@@ -0,0 +1,585 @@
+/*
+ * Copyright (C) 2009 The Android Open Source Project
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
+
+package com.android.providers.contacts;
+
+import static android.provider.ContactsContract.SimAccount.SDN_EF_TYPE;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertThrows;
+
+import android.accounts.Account;
+import android.compat.testing.PlatformCompatChangeRule;
+import android.content.ContentUris;
+import android.content.ContentValues;
+import android.database.sqlite.SQLiteDatabase;
+import android.os.Bundle;
+import android.platform.test.annotations.RequiresFlagsDisabled;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+import android.provider.ContactsContract;
+import android.provider.ContactsContract.RawContacts.DefaultAccount;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
+import android.provider.ContactsContract.Settings;
+import android.provider.Flags;
+
+import androidx.annotation.NonNull;
+import androidx.test.filters.MediumTest;
+
+import libcore.junit.util.compat.CoreCompatChangeRule.DisableCompatChanges;
+import libcore.junit.util.compat.CoreCompatChangeRule.EnableCompatChanges;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.List;
+import java.util.Objects;
+
+/**
+ * Unit tests for {@link ContactsProvider2} Default Account Handling.
+ *
+ * Run the test like this:
+ * <code>
+ * adb shell am instrument -e class
+ * com.android.providers.contacts.ContactsProvider2DefaultAccountTest -w \
+ * com.android.providers.contacts.tests/android.test.InstrumentationTestRunner
+ * </code>
+ */
+@MediumTest
+@RunWith(JUnit4.class)
+public class ContactsProvider2DefaultAccountTest extends BaseContactsProvider2Test {
+    static final Account SYSTEM_CLOUD_ACCOUNT_1 = new Account("sourceName1", "com.google");
+    static final Account SYSTEM_CLOUD_ACCOUNT_2 = new Account("sourceName2", "com.google");
+    static final Account SYSTEM_CLOUD_ACCOUNT_NOT_SIGNED_IN = new Account("sourceName3",
+            "com.google");
+    static final Account NON_SYSTEM_CLOUD_ACCOUNT_1 = new Account("sourceName1", "com.whatsapp");
+    static final Account SIM_ACCOUNT_1 = new Account("simName1", "SIM");
+
+    static final String RES_PACKAGE = "testpackage";
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+
+    @Rule
+    public TestRule compatChangeRule = new PlatformCompatChangeRule();
+
+    ContactsProvider2 mCp;
+
+    @Override
+    @Before
+    public void setUp() throws Exception {
+        super.setUp();
+        mCp = (ContactsProvider2) getContactsProvider();
+        createSimAccount(SIM_ACCOUNT_1);
+        DefaultAccountManager.setEligibleSystemCloudAccountTypesForTesting(
+                new String[]{"com.google"});
+    }
+
+    @After
+    @Override
+    public void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    private void assertResponseContainsDefaultAccount(DefaultAccountAndState expectedDefaultAccount,
+            Bundle response) {
+        assertEquals(expectedDefaultAccount.getState(),
+                response.getInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE, -1));
+        if (expectedDefaultAccount.getState()
+                == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD
+                || expectedDefaultAccount.getState()
+                == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_SIM) {
+            assertEquals(expectedDefaultAccount.getAccount().name,
+                    response.getString(Settings.ACCOUNT_NAME));
+            assertEquals(expectedDefaultAccount.getAccount().type,
+                    response.getString(Settings.ACCOUNT_TYPE));
+        } else {
+            assertNull(response.getString(Settings.ACCOUNT_NAME));
+            assertNull(response.getString(Settings.ACCOUNT_TYPE));
+        }
+    }
+
+    private Bundle bundleToSetDefaultAccountForNewContacts(
+            DefaultAccountAndState expectedDefaultAccount) {
+        Bundle bundle = new Bundle();
+        bundle.putInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE, expectedDefaultAccount.getState());
+        if (expectedDefaultAccount.getState()
+                == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD
+                || expectedDefaultAccount.getState()
+                == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_SIM) {
+            bundle.putString(Settings.ACCOUNT_NAME, expectedDefaultAccount.getAccount().name);
+            bundle.putString(Settings.ACCOUNT_TYPE, expectedDefaultAccount.getAccount().type);
+        }
+        return bundle;
+    }
+
+    private void createSimAccount(Account account) {
+        AccountWithDataSet accountWithDataSet =
+                new AccountWithDataSet(account.name, account.type, null);
+        final SQLiteDatabase db = mCp.getDatabaseHelper().getWritableDatabase();
+        db.beginTransaction();
+        try {
+            mCp.getDatabaseHelper().createSimAccountIdInTransaction(accountWithDataSet, 1,
+                    SDN_EF_TYPE);
+            db.setTransactionSuccessful();
+        } finally {
+            db.endTransaction();
+        }
+    }
+
+    @Test
+    @RequiresFlagsDisabled(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testSetAndGetDefaultAccountForNewContacts_flagOff() throws Exception {
+        // Default account is Unknown initially.
+        assertEquals(0, mCp.getDatabaseHelper().getDefaultAccountIfAny().length);
+
+        assertNull(mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null, null));
+
+        // Attempt to set default account to a cloud account.
+        assertNull(mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                bundleToSetDefaultAccountForNewContacts(
+                        DefaultAccountAndState.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1))));
+        // Default account is not changed.
+        assertEquals(0, mCp.getDatabaseHelper().getDefaultAccountIfAny().length);
+
+        // Attempt to set default account to local.
+        assertNull(mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                bundleToSetDefaultAccountForNewContacts(DefaultAccountAndState.ofLocal())));
+        // Default account is not changed.
+        assertEquals(0, mCp.getDatabaseHelper().getDefaultAccountIfAny().length);
+
+        // Attempt to set default account to "not set".
+        assertNull(mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                bundleToSetDefaultAccountForNewContacts(DefaultAccountAndState.ofNotSet())));
+        // Default account is not changed.
+        assertEquals(0, mCp.getDatabaseHelper().getDefaultAccountIfAny().length);
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testSetDefaultAccountForNewContacts_flagOn_permissionDenied() throws Exception {
+        mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+        assertThrows(SecurityException.class, () ->
+                mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, null));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testSetDefaultAccountForNewContacts_flagOn_invalidRequests() throws Exception {
+        mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+        mActor.addPermissions("android.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS");
+
+        // Account name is null and account type is not null.
+        Bundle bundleWithNoAccountType = new Bundle();
+        bundleWithNoAccountType.putString(Settings.ACCOUNT_NAME, SYSTEM_CLOUD_ACCOUNT_1.name);
+        bundleWithNoAccountType.putInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE,
+                DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD);
+        assertThrows(IllegalArgumentException.class,
+                () -> mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, bundleWithNoAccountType));
+        bundleWithNoAccountType.putInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE,
+                DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_LOCAL);
+        assertThrows(IllegalArgumentException.class,
+                () -> mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, bundleWithNoAccountType));
+        bundleWithNoAccountType.putInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE,
+                DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_NOT_SET);
+        assertThrows(IllegalArgumentException.class,
+                () -> mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, bundleWithNoAccountType));
+
+        // Account type is null and account name is not null.
+        Bundle bundleAccountWithNoAccountName = new Bundle();
+        bundleAccountWithNoAccountName.putString(Settings.ACCOUNT_TYPE,
+                SYSTEM_CLOUD_ACCOUNT_1.type);
+        bundleAccountWithNoAccountName.putInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE,
+                DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD);
+        assertThrows(IllegalArgumentException.class,
+                () -> mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, bundleAccountWithNoAccountName));
+        bundleAccountWithNoAccountName.putInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE,
+                DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_LOCAL);
+        assertThrows(IllegalArgumentException.class,
+                () -> mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, bundleAccountWithNoAccountName));
+
+        bundleAccountWithNoAccountName.putInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE,
+                DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_NOT_SET);
+        assertThrows(IllegalArgumentException.class,
+                () -> mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, bundleAccountWithNoAccountName));
+
+        // Cloud account with null account name and type
+        Bundle bundleCloudAccountWithNoAccount = new Bundle();
+        bundleCloudAccountWithNoAccount.putInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE,
+                DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD);
+        assertThrows(IllegalArgumentException.class,
+                () -> mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, bundleCloudAccountWithNoAccount));
+
+        // Non-cloud account with non-null account name and type
+        Bundle bundleLocalDefaultAccountStateWithAccount = new Bundle();
+        bundleLocalDefaultAccountStateWithAccount.putInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE,
+                DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_LOCAL);
+        bundleLocalDefaultAccountStateWithAccount.putString(Settings.ACCOUNT_TYPE,
+                SYSTEM_CLOUD_ACCOUNT_1.name);
+        bundleLocalDefaultAccountStateWithAccount.putString(Settings.ACCOUNT_TYPE,
+                SYSTEM_CLOUD_ACCOUNT_1.type);
+        assertThrows(IllegalArgumentException.class,
+                () -> mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, bundleLocalDefaultAccountStateWithAccount));
+
+        Bundle bundleNotSetDefaultAccountStateWithAccount = new Bundle();
+        bundleNotSetDefaultAccountStateWithAccount.putInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE,
+                DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_NOT_SET);
+        bundleNotSetDefaultAccountStateWithAccount.putString(Settings.ACCOUNT_TYPE,
+                SYSTEM_CLOUD_ACCOUNT_1.name);
+        bundleNotSetDefaultAccountStateWithAccount.putString(Settings.ACCOUNT_TYPE,
+                SYSTEM_CLOUD_ACCOUNT_1.type);
+        assertThrows(IllegalArgumentException.class,
+                () -> mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, bundleNotSetDefaultAccountStateWithAccount));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testSetAndGetDefaultAccountForNewContacts_flagOn_normal() throws Exception {
+        // Default account is Unknown initially.
+        assertEquals(0, mCp.getDatabaseHelper().getDefaultAccountIfAny().length);
+
+        Bundle response = mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null, null);
+        assertResponseContainsDefaultAccount(DefaultAccountAndState.ofNotSet(), response);
+
+        mActor.addPermissions("android.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS");
+        mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1, SYSTEM_CLOUD_ACCOUNT_2,
+                NON_SYSTEM_CLOUD_ACCOUNT_1});
+
+        // Set the default account (for new contacts) to a cloud account and then query.
+        mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                bundleToSetDefaultAccountForNewContacts(
+                        DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+
+        response = mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null, null);
+        assertResponseContainsDefaultAccount(DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1),
+                response);
+
+        assertArrayEquals(new Account[]{SYSTEM_CLOUD_ACCOUNT_1},
+                mCp.getDatabaseHelper().getDefaultAccountIfAny());
+
+        // Set the default account (for new contacts) to a different cloud account and then query.
+        mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                bundleToSetDefaultAccountForNewContacts(
+                        DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_2)));
+
+        response = mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null, null);
+        assertResponseContainsDefaultAccount(DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_2),
+                response);
+        assertArrayEquals(new Account[]{SYSTEM_CLOUD_ACCOUNT_2},
+                mCp.getDatabaseHelper().getDefaultAccountIfAny());
+
+        // Attempt to set the default account (for new contacts) to a system cloud account which
+        // is not signed in.
+        assertThrows(IllegalArgumentException.class,
+                () -> mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                        bundleToSetDefaultAccountForNewContacts(DefaultAccountAndState.ofCloud(
+                                SYSTEM_CLOUD_ACCOUNT_NOT_SIGNED_IN))));
+
+        response = mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null, null);
+        // Default account for new contacts is not changed.
+        assertResponseContainsDefaultAccount(DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_2),
+                response);
+        assertArrayEquals(new Account[]{SYSTEM_CLOUD_ACCOUNT_2},
+                mCp.getDatabaseHelper().getDefaultAccountIfAny());
+
+        // Attempt to set the default account (for new contacts) to a non-system cloud account.
+        mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                bundleToSetDefaultAccountForNewContacts(
+                        DefaultAccountAndState.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1)));
+
+        response = mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null, null);
+        // Default account for new contacts is changed to non-system cloud account.
+        assertResponseContainsDefaultAccount(
+                DefaultAccountAndState.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1),
+                response);
+        assertArrayEquals(new Account[]{NON_SYSTEM_CLOUD_ACCOUNT_1},
+                mCp.getDatabaseHelper().getDefaultAccountIfAny());
+
+        // Set the default account (for new contacts) to the local account and then query.
+        mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                bundleToSetDefaultAccountForNewContacts(DefaultAccountAndState.ofLocal()));
+
+        response = mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null, null);
+        assertResponseContainsDefaultAccount(DefaultAccountAndState.ofLocal(), response);
+        assertArrayEquals(new Account[]{null}, mCp.getDatabaseHelper().getDefaultAccountIfAny());
+
+        // Set the default account (for new contacts) to a SIM account.
+        mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                bundleToSetDefaultAccountForNewContacts(
+                        DefaultAccountAndState.ofSim(SIM_ACCOUNT_1)));
+        response = mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null, null);
+        assertResponseContainsDefaultAccount(DefaultAccountAndState.ofSim(SIM_ACCOUNT_1), response);
+        assertArrayEquals(new Account[]{SIM_ACCOUNT_1},
+                mCp.getDatabaseHelper().getDefaultAccountIfAny());
+
+        // Set the default account (for new contacts) to a "not set" state
+        mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                bundleToSetDefaultAccountForNewContacts(DefaultAccountAndState.ofNotSet()));
+
+        response = mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null, null);
+        assertResponseContainsDefaultAccount(DefaultAccountAndState.ofNotSet(), response);
+        assertEquals(0, mCp.getDatabaseHelper().getDefaultAccountIfAny().length);
+    }
+
+
+    @Test
+    @RequiresFlagsDisabled(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testGetEligibleCloudAccounts_flagOff() throws Exception {
+        mActor.setAccounts(new Account[0]);
+        assertNull(mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, null));
+
+        mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+        assertNull(mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, null));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testGetEligibleCloudAccounts_flagOn_permissionDenied() throws Exception {
+        mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+        assertThrows(SecurityException.class, () ->
+                mResolver.call(ContactsContract.AUTHORITY_URI,
+                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                        null, null));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testGetEligibleCloudAccounts_flagOn_normal() throws Exception {
+        mActor.addPermissions("android.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS");
+        Bundle response = mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_ELIGIBLE_DEFAULT_ACCOUNTS_METHOD, null, null);
+
+        // No account is present on the device,
+        List<Account> accounts = response.getParcelableArrayList(
+                DefaultAccount.KEY_ELIGIBLE_DEFAULT_ACCOUNTS, Account.class);
+        assertEquals(new ArrayList<>(), accounts);
+
+        // 1 system cloud account is present on the device.
+        mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+        response = mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_ELIGIBLE_DEFAULT_ACCOUNTS_METHOD, null, null);
+        accounts = response.getParcelableArrayList(
+                DefaultAccount.KEY_ELIGIBLE_DEFAULT_ACCOUNTS, Account.class);
+        assertEquals(Arrays.asList(new Account[]{SYSTEM_CLOUD_ACCOUNT_1}), accounts);
+
+        // 2 system cloud accounts are present on the device.
+        mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1, SYSTEM_CLOUD_ACCOUNT_2});
+        response = mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_ELIGIBLE_DEFAULT_ACCOUNTS_METHOD, null, null);
+        accounts = response.getParcelableArrayList(
+                DefaultAccount.KEY_ELIGIBLE_DEFAULT_ACCOUNTS, Account.class);
+        assertEquals(Arrays.asList(new Account[]{SYSTEM_CLOUD_ACCOUNT_1, SYSTEM_CLOUD_ACCOUNT_2}),
+                accounts);
+
+        // 2 system cloud and 1 non-system cloud account are present on the device.
+        mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1, SYSTEM_CLOUD_ACCOUNT_2,
+                NON_SYSTEM_CLOUD_ACCOUNT_1});
+        response = mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.QUERY_ELIGIBLE_DEFAULT_ACCOUNTS_METHOD, null, null);
+        accounts = response.getParcelableArrayList(
+                DefaultAccount.KEY_ELIGIBLE_DEFAULT_ACCOUNTS, Account.class);
+        assertEquals(Arrays.asList(new Account[]{SYSTEM_CLOUD_ACCOUNT_1, SYSTEM_CLOUD_ACCOUNT_2}),
+                accounts);
+    }
+
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    @DisableCompatChanges({ChangeIds.RESTRICT_CONTACTS_CREATION_IN_ACCOUNTS})
+    public void testRawContactInsert_whenDefaultAccountSetToCloud_contactCreationNotRestricted() {
+        mActor.addPermissions("android.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS");
+        mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+
+        // Set the default account (for new contacts) to a cloud account.
+        mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                bundleToSetDefaultAccountForNewContacts(
+                        DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+
+        // Okay to insert raw contact in cloud account.
+        long rawContactId1 = insertRawContact(SYSTEM_CLOUD_ACCOUNT_1);
+
+        // Okay to insert raw contact in NULL account.
+        long rawContactId2 = insertRawContact((Account) null);
+
+        // Okay to update raw contact to a different cloud account.
+        assertEquals(1, updateRawContactAccount(rawContactId1, SYSTEM_CLOUD_ACCOUNT_2));
+        assertEquals(1, updateRawContactAccount(rawContactId2, SYSTEM_CLOUD_ACCOUNT_2));
+
+        // Okay to update raw contact to NULL account.
+        assertEquals(1, updateRawContactAccount(rawContactId2, null));
+
+        // Okay to insert group in cloud account.
+        long groupId1 = insertGroup(SYSTEM_CLOUD_ACCOUNT_1);
+
+        // Okay to insert group in NULL account.
+        long groupId2 = insertGroup((Account) null);
+
+        // Okay to update raw contact to a different cloud account.
+        assertEquals(1, updateGroupAccount(groupId1, SYSTEM_CLOUD_ACCOUNT_2));
+        assertEquals(1, updateGroupAccount(groupId2, SYSTEM_CLOUD_ACCOUNT_2));
+
+        // Okay to update raw contact to NULL account.
+        assertEquals(1, updateGroupAccount(groupId1, null));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    @EnableCompatChanges({ChangeIds.RESTRICT_CONTACTS_CREATION_IN_ACCOUNTS})
+    public void testRawContactInsert_whenDefaultAccountSetToCloud_contactCreationRestricted() {
+        mActor.addPermissions("android.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS");
+        mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1, SYSTEM_CLOUD_ACCOUNT_2});
+
+        // Set the default account (for new contacts) to a cloud account.
+        mResolver.call(ContactsContract.AUTHORITY_URI,
+                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                bundleToSetDefaultAccountForNewContacts(
+                        DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+
+        // Okay to insert raw contact in cloud account.
+        long rawContactId1 = insertRawContact(SYSTEM_CLOUD_ACCOUNT_1);
+
+        // Exception expected when inserting raw contact in NULL account.
+        assertThrows(IllegalArgumentException.class, () ->
+                insertRawContact((Account) null));
+
+        // Okay to update the raw contact to a different cloud account
+        assertEquals(1, updateRawContactAccount(rawContactId1, SYSTEM_CLOUD_ACCOUNT_2));
+
+        // Exception expected when updating raw contact to NULL account.
+        assertThrows(IllegalArgumentException.class,
+                () -> updateRawContactAccount(rawContactId1, null));
+
+        // Okay to insert group in cloud account.
+        long groupId1 = insertGroup(SYSTEM_CLOUD_ACCOUNT_1);
+
+        // Exception expected when inserting group in NULL account.
+        assertThrows(IllegalArgumentException.class, () ->
+                insertGroup((Account) null));
+
+        // Okay to update the group to a different cloud account
+        assertEquals(1, updateGroupAccount(groupId1, SYSTEM_CLOUD_ACCOUNT_2));
+
+        // Exception expected when updating group to NULL account.
+        assertThrows(IllegalArgumentException.class, () -> updateGroupAccount(groupId1, null));
+
+    }
+
+    private long insertRawContact(Account account) {
+        ContentValues values = getRawContactContactValuesFromAccount(account);
+        return ContentUris.parseId(
+                Objects.requireNonNull(
+                        mResolver.insert(ContactsContract.RawContacts.CONTENT_URI, values)));
+    }
+
+    private long insertGroup(Account account) {
+        ContentValues values = getGroupContentValuesFromAccount(account);
+        return ContentUris.parseId(
+                Objects.requireNonNull(
+                        mResolver.insert(ContactsContract.Groups.CONTENT_URI, values)));
+    }
+
+    private long updateRawContactAccount(long rawContactId, Account destinationAccount) {
+        ContentValues values = getRawContactContactValuesFromAccount(destinationAccount);
+        return mResolver.update(
+                ContentUris.withAppendedId(ContactsContract.RawContacts.CONTENT_URI, rawContactId),
+                values, null, null);
+    }
+
+    private long updateGroupAccount(long groupId, Account destinationAccount) {
+        ContentValues values = getGroupContentValuesFromAccount(destinationAccount);
+        return mResolver.update(
+                ContentUris.withAppendedId(ContactsContract.Groups.CONTENT_URI, groupId), values,
+                null, null);
+    }
+
+    @NonNull
+    private static ContentValues getRawContactContactValuesFromAccount(Account account) {
+        ContentValues values = new ContentValues();
+        if (account == null) {
+            values.put(ContactsContract.RawContacts.ACCOUNT_NAME, (String) null);
+            values.put(ContactsContract.RawContacts.ACCOUNT_TYPE, (String) null);
+        } else {
+            values.put(ContactsContract.RawContacts.ACCOUNT_NAME, account.name);
+            values.put(ContactsContract.RawContacts.ACCOUNT_TYPE, account.type);
+        }
+        return values;
+    }
+
+
+    @NonNull
+    private static ContentValues getGroupContentValuesFromAccount(Account account) {
+        ContentValues values = new ContentValues();
+        if (account == null) {
+            values.put(ContactsContract.RawContacts.ACCOUNT_NAME, (String) null);
+            values.put(ContactsContract.RawContacts.ACCOUNT_TYPE, (String) null);
+        } else {
+            values.put(ContactsContract.RawContacts.ACCOUNT_NAME, account.name);
+            values.put(ContactsContract.RawContacts.ACCOUNT_TYPE, account.type);
+        }
+        return values;
+    }
+}
diff --git a/tests/src/com/android/providers/contacts/ContactsProvider2Test.java b/tests/src/com/android/providers/contacts/ContactsProvider2Test.java
index 8696c59a..59f37771 100644
--- a/tests/src/com/android/providers/contacts/ContactsProvider2Test.java
+++ b/tests/src/com/android/providers/contacts/ContactsProvider2Test.java
@@ -7076,6 +7076,50 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(10, DatabaseUtils.longForQuery(db, "SELECT count(*) FROM search_index", null));
     }
 
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_CP2_SYNC_SEARCH_INDEX_FLAG)
+    public void testSearchIndexUpdatedOnRawContactOperations() {
+        ContactsProvider2 cp = (ContactsProvider2) getProvider();
+        SQLiteDatabase db = cp.getDatabaseHelper().getReadableDatabase();
+
+        assertEquals(0, DatabaseUtils.longForQuery(db, "SELECT COUNT(*) FROM search_index", null));
+
+        long rawContactId = RawContactUtil.createRawContactWithName(mResolver, "John", "Wick");
+        Uri emailUri = insertEmail(rawContactId, "john@movie.com");
+
+        // Assert contact is in the search index
+        assertStoredValue(buildFilterUri("wick", false), SearchSnippets.SNIPPET, null);
+        assertStoredValue(buildFilterUri("movie", false), SearchSnippets.SNIPPET,
+                "john@[movie].com");
+        assertEquals(1, DatabaseUtils.longForQuery(db, "SELECT COUNT(*) FROM search_index", null));
+        assertEquals(0, DatabaseUtils.longForQuery(db,
+                    "SELECT COUNT(*) FROM stale_search_index_contacts", null));
+
+        // Update raw contact with email
+        ContentValues values = new ContentValues();
+        values.put(Data.RAW_CONTACT_ID, rawContactId);
+        values.put(Email.DATA, "john@continental.com");
+        mResolver.update(emailUri, values, null);
+
+        // Assert contact is updated in the search index
+        assertStoredValue(buildFilterUri("wick", false), SearchSnippets.SNIPPET, null);
+        assertRowCount(0, buildFilterUri("movie", false), null, null);
+        assertStoredValue(buildFilterUri("continental", false), SearchSnippets.SNIPPET,
+                "john@[continental].com");
+        assertEquals(1, DatabaseUtils.longForQuery(db, "SELECT COUNT(*) FROM search_index", null));
+        assertEquals(0, DatabaseUtils.longForQuery(db,
+                    "SELECT COUNT(*) FROM stale_search_index_contacts", null));
+
+        // Delete the raw contact
+        RawContactUtil.delete(mResolver, rawContactId, true);
+
+        // Assert the contact is no longer searchable
+        assertRowCount(0, buildFilterUri("wick", false), null, null);
+        assertEquals(0, DatabaseUtils.longForQuery(db, "SELECT COUNT(*) FROM search_index", null));
+        assertEquals(0, DatabaseUtils.longForQuery(db,
+                    "SELECT COUNT(*) FROM stale_search_index_contacts", null));
+    }
+
     @Test
     public void testStreamItemsCleanedUpOnAccountRemoval() {
         Account doomedAccount = new Account("doom", "doom");
diff --git a/tests/src/com/android/providers/contacts/DefaultAccountManagerTest.java b/tests/src/com/android/providers/contacts/DefaultAccountManagerTest.java
index bb9a1b17..6f2ad407 100644
--- a/tests/src/com/android/providers/contacts/DefaultAccountManagerTest.java
+++ b/tests/src/com/android/providers/contacts/DefaultAccountManagerTest.java
@@ -16,10 +16,14 @@
 
 package com.android.providers.contacts;
 
+import static android.provider.ContactsContract.SimAccount.SDN_EF_TYPE;
+
 import static org.mockito.Mockito.argThat;
 
 import android.accounts.Account;
 import android.accounts.AccountManager;
+import android.database.sqlite.SQLiteDatabase;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
 
 import androidx.test.filters.SmallTest;
 
@@ -38,6 +42,9 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
     private static final Account NON_SYSTEM_CLOUD_ACCOUNT_1 = new Account("user2@whatsapp.com",
             "com.whatsapp");
 
+    private static final Account SIM_ACCOUNT_1 = new Account("SIM_ACCOUNT_NAME",
+            "SIM_ACCOUNT_TYPE");
+
     private ContactsDatabaseHelper mDbHelper;
     private DefaultAccountManager mDefaultAccountManager;
     private SyncSettingsHelper mSyncSettingsHelper;
@@ -87,179 +94,282 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
     }
 
     public void testPushDca_noCloudAccountsSignedIn() {
-        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+        assertEquals(DefaultAccountAndState.ofNotSet(),
                 mDefaultAccountManager.pullDefaultAccount());
+        assertEquals(List.of(), mDefaultAccountManager.getEligibleCloudAccounts());
 
         // Push the DCA which is device account, which should succeed.
         assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT));
-        assertEquals(DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                DefaultAccountAndState.ofLocal()));
+        assertEquals(DefaultAccountAndState.ofLocal(),
                 mDefaultAccountManager.pullDefaultAccount());
 
         // Push the DCA which is not signed in, expect failure.
         assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
-        assertEquals(DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+        assertEquals(DefaultAccountAndState.ofLocal(),
                 mDefaultAccountManager.pullDefaultAccount());
+
+        // Cloud account eligible for default accounts doesn't change.
+        assertEquals(List.of(), mDefaultAccountManager.getEligibleCloudAccounts());
     }
 
     public void testPushDeviceAccountAsDca_cloudSyncIsOff() {
         setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
 
+        mSyncSettingsHelper.turnOffSync(SYSTEM_CLOUD_ACCOUNT_1);
+
+        // SYSTEM_CLOUD_ACCOUNT_1 is signed in, but sync is turned off, thus no account is eligible
+        // to be set as cloud default account.
+        assertEquals(List.of(), mDefaultAccountManager.getEligibleCloudAccounts());
+
         // The initial DCA should be unknown, regardless of the cloud account existence and their
         // sync status.
         mSyncSettingsHelper.turnOffSync(SYSTEM_CLOUD_ACCOUNT_1);
-        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+        assertEquals(DefaultAccountAndState.ofNotSet(),
                 mDefaultAccountManager.pullDefaultAccount());
 
         // Try to set the DCA as DEVICE account, which should succeed
         assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT));
-        assertEquals(DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                DefaultAccountAndState.ofLocal()));
+        assertEquals(DefaultAccountAndState.ofLocal(),
                 mDefaultAccountManager.pullDefaultAccount());
 
-        // Try to set the DCA as the system cloud account which sync is currently off, should fail.
-        assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+        // Sync-off system cloud account will be treated as non-eligible cloud account.
+        // Despite that, setting DCA to be a non-eligible cloud account, should succeed.
+        assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
         assertEquals(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.pullDefaultAccount());
+
+        // Sync remains off.
         assertTrue(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+
+        // Cloud account eligible for default accounts doesn't change.
+        assertEquals(List.of(), mDefaultAccountManager.getEligibleCloudAccounts());
     }
 
     public void testPushCustomizedDeviceAccountAsDca_cloudSyncIsOff() {
         setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
         mSyncSettingsHelper.turnOffSync(SYSTEM_CLOUD_ACCOUNT_1);
 
+        // SYSTEM_CLOUD_ACCOUNT_1 is signed in, but sync is turned off, thus no account is eligible
+        // to be set as cloud default account.
+        assertEquals(List.of(), mDefaultAccountManager.getEligibleCloudAccounts());
+
         // No cloud account remains sync on, and thus DCA reverts to the DEVICE.
-        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+        assertEquals(DefaultAccountAndState.ofNotSet(),
                 mDefaultAccountManager.pullDefaultAccount());
 
         // Try to set DCA to be device account, which should succeed.
         assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT));
-        assertEquals(DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                DefaultAccountAndState.ofLocal()));
+        assertEquals(DefaultAccountAndState.ofLocal(),
                 mDefaultAccountManager.pullDefaultAccount());
 
-        // Try to set DCA to be a system cloud account which sync is off, should fail.
-        assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+        // Sync-off system cloud account will be treated as non-eligible cloud account.
+        // Despite that, setting DCA to be a non-eligible cloud account, should succeed.
+        assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
         assertEquals(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.pullDefaultAccount());
-        // Sync state should still remains off.
+
+        // Sync remains off.
         assertTrue(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+
+        // Cloud account eligible for default accounts doesn't change.
+        assertEquals(List.of(), mDefaultAccountManager.getEligibleCloudAccounts());
     }
 
     public void testPushDca_dcaWasUnknown_tryPushDeviceAndThenCloudAccount() {
         setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
         mSyncSettingsHelper.turnOnSync(SYSTEM_CLOUD_ACCOUNT_1);
 
+        assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.getEligibleCloudAccounts());
+
         // 1 system cloud account with sync on. DCA was set to cloud before, and thus it's in
         // a UNKNOWN state.
-        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+        assertEquals(DefaultAccountAndState.ofNotSet(),
                 mDefaultAccountManager.pullDefaultAccount());
 
         // Try to set the DCA to be local, which should succeed. In addition, it should turn
         // all system cloud account's sync off.
         assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT));
-        assertEquals(DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                DefaultAccountAndState.ofLocal()));
+        assertEquals(DefaultAccountAndState.ofLocal(),
                 mDefaultAccountManager.pullDefaultAccount());
         // Sync setting should remain to be on.
         assertFalse(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
 
         // Try to set the DCA to be system cloud account, which should succeed.
         assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
         assertEquals(
-                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.pullDefaultAccount());
         // Sync setting should remain to be on.
         assertFalse(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+
+        // Cloud account eligible for default accounts doesn't change.
+        assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.getEligibleCloudAccounts());
+
+    }
+
+    public void testPushDca_dcaWasUnknown_tryPushSimAccount() {
+        createSimAccount(SIM_ACCOUNT_1);
+
+        assertEquals(DefaultAccountAndState.ofNotSet(),
+                mDefaultAccountManager.pullDefaultAccount());
+
+        assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofSim(SIM_ACCOUNT_1)));
+
+        assertEquals(DefaultAccountAndState.ofSim(SIM_ACCOUNT_1),
+                mDefaultAccountManager.pullDefaultAccount());
     }
 
     public void testPushDca_dcaWasCloud() {
         setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
         mSyncSettingsHelper.turnOnSync(SYSTEM_CLOUD_ACCOUNT_1);
 
+        assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.getEligibleCloudAccounts());
+
         // DCA was a system cloud initially.
         mDbHelper.setDefaultAccount(SYSTEM_CLOUD_ACCOUNT_1.name, SYSTEM_CLOUD_ACCOUNT_1.type);
         assertEquals(
-                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.pullDefaultAccount());
 
         // Try to set DCA to a device (null) account, which should succeed, and it shouldn't
         // change the cloud account's sync status.
         assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT));
+                DefaultAccountAndState.ofLocal()));
         assertEquals(
-                DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                DefaultAccountAndState.ofLocal(),
                 mDefaultAccountManager.pullDefaultAccount());
         assertFalse(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
 
         // Try to set DCA to the same system cloud account again, which should succeed
         assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
         assertEquals(
-                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.pullDefaultAccount());
         assertFalse(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+
+        // Cloud account eligible for default accounts doesn't change.
+        assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.getEligibleCloudAccounts());
+
     }
 
     public void testPushDca_dcaWasUnknown_tryPushAccountNotSignedIn() {
         setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
-        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+
+        assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.getEligibleCloudAccounts());
+
+        assertEquals(DefaultAccountAndState.ofNotSet(),
                 mDefaultAccountManager.pullDefaultAccount());
 
         // Try to set the DCA to be an account not signed in, which should fail.
         assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.ofCloud(new Account("unknown1@gmail.com", "com.google"))));
-        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+                DefaultAccountAndState.ofCloud(new Account("unknown1@gmail.com", "com.google"))));
+        assertEquals(DefaultAccountAndState.ofNotSet(),
                 mDefaultAccountManager.pullDefaultAccount());
+
+        // Cloud account eligible for default accounts doesn't change.
+        assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.getEligibleCloudAccounts());
+
     }
 
     public void testPushDca_dcaWasUnknown_tryPushNonSystemCloudAccount() {
         setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1, NON_SYSTEM_CLOUD_ACCOUNT_1});
-        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+
+        // Only SYSTEM_CLOUD_ACCOUNT_1 is eligible to be set as cloud default account.
+        assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.getEligibleCloudAccounts());
+
+        assertEquals(DefaultAccountAndState.ofNotSet(),
                 mDefaultAccountManager.pullDefaultAccount());
 
         // Try to set the DCA to be an account which is not a system cloud account, which should
         // fail.
-        assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1)));
-        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+        assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1)));
+        assertEquals(DefaultAccountAndState.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.pullDefaultAccount());
+
+        // Cloud account eligible for default accounts doesn't change.
+        assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.getEligibleCloudAccounts());
+
     }
 
     public void testPushDca_dcaWasCloud_tryPushAccountNotSignedIn() {
         setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+
+        assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.getEligibleCloudAccounts());
+
         mDbHelper.setDefaultAccount(SYSTEM_CLOUD_ACCOUNT_1.name, SYSTEM_CLOUD_ACCOUNT_1.type);
         assertEquals(
-                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.pullDefaultAccount());
 
         // Try to set the DCA to be an account not signed in, which should fail.
         assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.ofCloud(new Account("unknown1@gmail.com", "com.google"))));
+                DefaultAccountAndState.ofCloud(new Account("unknown1@gmail.com", "com.google"))));
         assertEquals(
-                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.pullDefaultAccount());
+
+        // Cloud account eligible for default accounts doesn't change.
+        assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.getEligibleCloudAccounts());
+
     }
 
     public void testPushDca_dcaWasCloud_tryPushNonSystemCloudAccount() {
         setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1, NON_SYSTEM_CLOUD_ACCOUNT_1});
+
+        assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.getEligibleCloudAccounts());
+
         mDbHelper.setDefaultAccount(SYSTEM_CLOUD_ACCOUNT_1.name, SYSTEM_CLOUD_ACCOUNT_1.type);
         assertEquals(
-                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.pullDefaultAccount());
 
         // Try to set the DCA to be an account which is not a system cloud account, which should
         // fail.
-        assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
-                DefaultAccount.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1)));
+        assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1)));
         assertEquals(
-                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                DefaultAccountAndState.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.pullDefaultAccount());
+
+        // Cloud account eligible for default accounts doesn't change.
+        assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.getEligibleCloudAccounts());
+    }
+
+    private void createSimAccount(Account account) {
+        AccountWithDataSet accountWithDataSet =
+                new AccountWithDataSet(account.name, account.type, null);
+        final SQLiteDatabase db = mDbHelper.getWritableDatabase();
+        db.beginTransaction();
+        try {
+            mDbHelper.createSimAccountIdInTransaction(accountWithDataSet, 1, SDN_EF_TYPE);
+            db.setTransactionSuccessful();
+        } finally {
+            db.endTransaction();
+        }
     }
 }
diff --git a/tests/src/com/android/providers/contacts/MoveContactsToDefaultAccountActivityTest.java b/tests/src/com/android/providers/contacts/MoveContactsToDefaultAccountActivityTest.java
new file mode 100644
index 00000000..9edba262
--- /dev/null
+++ b/tests/src/com/android/providers/contacts/MoveContactsToDefaultAccountActivityTest.java
@@ -0,0 +1,392 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+
+package com.android.providers.contacts;
+
+import static android.app.Activity.RESULT_CANCELED;
+import static android.app.Activity.RESULT_OK;
+import static android.provider.ContactsContract.RawContacts.DefaultAccount;
+
+import static androidx.test.platform.app.InstrumentationRegistry.getInstrumentation;
+
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.spy;
+import static org.mockito.Mockito.verify;
+
+import static java.util.regex.Pattern.CASE_INSENSITIVE;
+
+import android.accounts.Account;
+import android.app.Instrumentation;
+import android.content.ContentResolver;
+import android.content.Context;
+import android.content.Intent;
+import android.database.Cursor;
+import android.icu.text.MessageFormat;
+import android.net.Uri;
+import android.os.Bundle;
+import android.platform.test.annotations.EnableFlags;
+import android.platform.test.annotations.RequiresFlagsDisabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+import android.platform.test.flag.junit.SetFlagsRule;
+import android.provider.ContactsContract;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
+import android.provider.ContactsContract.Settings;
+import android.provider.Flags;
+import android.test.mock.MockContentProvider;
+import android.test.mock.MockContentResolver;
+
+import androidx.test.InstrumentationRegistry;
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.uiautomator.By;
+import androidx.test.uiautomator.BySelector;
+import androidx.test.uiautomator.UiDevice;
+import androidx.test.uiautomator.Until;
+
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Spy;
+import org.mockito.junit.MockitoJUnit;
+import org.mockito.junit.MockitoRule;
+
+import java.util.HashMap;
+import java.util.Locale;
+import java.util.Map;
+import java.util.regex.Pattern;
+
+@RunWith(AndroidJUnit4.class)
+public class MoveContactsToDefaultAccountActivityTest {
+
+    private static final String TEST_MOVE_LOCAL_CONTACTS_METHOD = "test_move_local_contacts";
+
+    private static final String TEST_MOVE_LOCAL_CONTACTS_BUNDLE_KEY = "move_local_contacts_key";
+
+    private static final String TEST_MOVE_SIM_CONTACTS_BUNDLE_KEY = "move_sim_contacts_key";
+
+    private static final Account TEST_ACCOUNT = new Account("test@gmail.com", "Google");
+
+    @Rule
+    public final MockitoRule mockito = MockitoJUnit.rule();
+
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+
+    @Rule
+    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
+    private final MockContentResolver mContentResolver = new MockContentResolver();
+    private final Instrumentation mInstrumentation = getInstrumentation();
+    @Spy
+    private TestMoveContactsToDefaultAccountActivity mActivity;
+    private UiDevice mDevice;
+
+    @Before
+    public void setUp() throws Exception {
+        mInstrumentation.getUiAutomation()
+                .adoptShellPermissionIdentity(
+                        "android.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS");
+        mDevice = UiDevice.getInstance(mInstrumentation);
+        mContentResolver.addProvider("settings", new MockContentProvider() {
+            @Override
+            public Bundle call(String method, String arg, Bundle extras) {
+                return null;
+            }
+
+            @Override
+            public Cursor query(
+                    Uri uri,
+                    String[] projection,
+                    String selection,
+                    String[] selectionArgs,
+                    String sortOrder) {
+                return null;
+            }
+        });
+    }
+
+    @Test
+    @EnableFlags(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testMoveLocalContactsDialog_eligibleAccount_clickConfirm() throws Exception {
+        MockContentProvider mockContentProvider = setupMockContentProvider(
+                DefaultAccountAndState.ofCloud(TEST_ACCOUNT), 1, 1);
+        mContentResolver.addProvider(ContactsContract.AUTHORITY_URI.getAuthority(),
+                mockContentProvider);
+        TestMoveContactsToDefaultAccountActivity.setupForTesting(mContentResolver);
+
+        Intent intent = new Intent(InstrumentationRegistry.getContext(),
+                TestMoveContactsToDefaultAccountActivity.class);
+        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+        mActivity = spy(
+                (TestMoveContactsToDefaultAccountActivity) mInstrumentation.startActivitySync(
+                        intent));
+        mDevice.waitForIdle();
+
+        assertTrue(mDevice.hasObject(By.text(mActivity.getTitleText())));
+        assertTrue(mDevice.hasObject(getCaseInsensitiveSelector(mActivity.getSyncButtonText())));
+        assertTrue(mDevice.hasObject(getCaseInsensitiveSelector(mActivity.getCancelButtonText())));
+        assertTrue(mDevice.hasObject(
+                By.text(mActivity.getMessageText(2, "Google", "test@gmail.com"))));
+
+        mDevice.findObject(getCaseInsensitiveSelector(mActivity.getSyncButtonText())).click();
+        // Wait for action to be performed.
+        Thread.sleep(1000);
+
+        assertTrue(mContentResolver.call(ContactsContract.AUTHORITY_URI,
+                TEST_MOVE_LOCAL_CONTACTS_METHOD, null, null).getBoolean(
+                TEST_MOVE_LOCAL_CONTACTS_BUNDLE_KEY));
+        assertTrue(mContentResolver.call(ContactsContract.AUTHORITY_URI,
+                TEST_MOVE_LOCAL_CONTACTS_METHOD, null, null).getBoolean(
+                TEST_MOVE_SIM_CONTACTS_BUNDLE_KEY));
+        verify(mActivity).setResult(eq(RESULT_OK));
+    }
+
+    @Test
+    @EnableFlags(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testMoveLocalContactsDialog_eligibleAccount_clickCancel() {
+        MockContentProvider mockContentProvider = setupMockContentProvider(
+                DefaultAccountAndState.ofCloud(TEST_ACCOUNT), 1, 0);
+        mContentResolver.addProvider(ContactsContract.AUTHORITY_URI.getAuthority(),
+                mockContentProvider);
+        TestMoveContactsToDefaultAccountActivity.setupForTesting(mContentResolver);
+
+        Intent intent = new Intent(InstrumentationRegistry.getContext(),
+                TestMoveContactsToDefaultAccountActivity.class);
+        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+        mActivity = spy(
+                (TestMoveContactsToDefaultAccountActivity) mInstrumentation.startActivitySync(
+                        intent));
+        mDevice.waitForIdle();
+
+        assertTrue(mDevice.hasObject(By.text(mActivity.getTitleText())));
+        assertTrue(mDevice.hasObject(getCaseInsensitiveSelector(mActivity.getSyncButtonText())));
+        assertTrue(mDevice.hasObject(getCaseInsensitiveSelector(mActivity.getCancelButtonText())));
+        assertTrue(mDevice.hasObject(
+                By.text(mActivity.getMessageText(1, "Google", "test@gmail.com"))));
+
+        mDevice.findObject(getCaseInsensitiveSelector(mActivity.getCancelButtonText())).click();
+
+        assertFalse(mContentResolver.call(ContactsContract.AUTHORITY_URI,
+                TEST_MOVE_LOCAL_CONTACTS_METHOD, null, null).getBoolean(
+                TEST_MOVE_LOCAL_CONTACTS_BUNDLE_KEY));
+        assertFalse(mContentResolver.call(ContactsContract.AUTHORITY_URI,
+                TEST_MOVE_LOCAL_CONTACTS_METHOD, null, null).getBoolean(
+                TEST_MOVE_SIM_CONTACTS_BUNDLE_KEY));
+        verify(mActivity).setResult(eq(RESULT_CANCELED));
+    }
+
+    @Test
+    @EnableFlags(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testMoveLocalContactsDialog_noDefaultAccount_dontShowDialog() {
+        MockContentProvider mockContentProvider = setupMockContentProvider(
+                DefaultAccountAndState.ofNotSet(), 1, 1);
+        mContentResolver.addProvider(ContactsContract.AUTHORITY_URI.getAuthority(),
+                mockContentProvider);
+        TestMoveContactsToDefaultAccountActivity.setupForTesting(mContentResolver);
+
+        Intent intent = new Intent(InstrumentationRegistry.getContext(),
+                TestMoveContactsToDefaultAccountActivity.class);
+        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+
+        mActivity = spy(
+                (TestMoveContactsToDefaultAccountActivity) mInstrumentation.startActivitySync(
+                        intent));
+        mDevice.waitForIdle();
+
+        assertFalse(mDevice.hasObject(By.text(mActivity.getTitleText())));
+        assertFalse(mDevice.hasObject(getCaseInsensitiveSelector(mActivity.getSyncButtonText())));
+        assertFalse(mDevice.hasObject(getCaseInsensitiveSelector(mActivity.getCancelButtonText())));
+
+        verify(mActivity).setResult(eq(RESULT_CANCELED));
+    }
+
+    @Test
+    @EnableFlags(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testMoveLocalContactsDialog_noCloudAccount_dontShowDialog() {
+        MockContentProvider mockContentProvider = setupMockContentProvider(
+                DefaultAccountAndState.ofLocal(), 1, 1);
+        mContentResolver.addProvider(ContactsContract.AUTHORITY_URI.getAuthority(),
+                mockContentProvider);
+        TestMoveContactsToDefaultAccountActivity.setupForTesting(mContentResolver);
+
+        Intent intent = new Intent(InstrumentationRegistry.getContext(),
+                TestMoveContactsToDefaultAccountActivity.class);
+        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+        mActivity = spy(
+                (TestMoveContactsToDefaultAccountActivity) mInstrumentation.startActivitySync(
+                        intent));
+        mDevice.waitForIdle();
+
+        assertFalse(mDevice.hasObject(By.text(mActivity.getTitleText())));
+        assertFalse(mDevice.hasObject(getCaseInsensitiveSelector(mActivity.getSyncButtonText())));
+        assertFalse(mDevice.hasObject(getCaseInsensitiveSelector(mActivity.getCancelButtonText())));
+
+        verify(mActivity).setResult(eq(RESULT_CANCELED));
+    }
+
+    @Test
+    @RequiresFlagsDisabled(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testMoveLocalContactsDialog_flagOff_dontShowDialog() {
+        MockContentProvider mockContentProvider = setupMockContentProvider(
+                DefaultAccountAndState.ofCloud(TEST_ACCOUNT), 1, 1);
+        mContentResolver.addProvider(ContactsContract.AUTHORITY_URI.getAuthority(),
+                mockContentProvider);
+        TestMoveContactsToDefaultAccountActivity.setupForTesting(mContentResolver);
+
+        Intent intent = new Intent(InstrumentationRegistry.getContext(),
+                TestMoveContactsToDefaultAccountActivity.class);
+        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+        mActivity = spy(
+                (TestMoveContactsToDefaultAccountActivity) mInstrumentation.startActivitySync(
+                        intent));
+        mDevice.wait(Until.hasObject(By.text(mActivity.getTitleText())), /*timeout=*/2000L);
+
+        assertFalse(mDevice.hasObject(getCaseInsensitiveSelector(mActivity.getSyncButtonText())));
+        assertFalse(mDevice.hasObject(getCaseInsensitiveSelector(mActivity.getCancelButtonText())));
+
+        verify(mActivity).setResult(eq(RESULT_CANCELED));
+    }
+
+    @Test
+    @EnableFlags(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    public void testMoveLocalContactsDialog_noMovableContacts_dontShowDialog() {
+        MockContentProvider mockContentProvider = setupMockContentProvider(
+                DefaultAccountAndState.ofCloud(TEST_ACCOUNT), 0, 0);
+        mContentResolver.addProvider(ContactsContract.AUTHORITY_URI.getAuthority(),
+                mockContentProvider);
+        TestMoveContactsToDefaultAccountActivity.setupForTesting(mContentResolver);
+
+        Intent intent = new Intent(InstrumentationRegistry.getContext(),
+                TestMoveContactsToDefaultAccountActivity.class);
+        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+        mActivity = spy(
+                (TestMoveContactsToDefaultAccountActivity) mInstrumentation.startActivitySync(
+                        intent));
+        mDevice.waitForIdle();
+
+        assertFalse(mDevice.hasObject(By.text(mActivity.getTitleText())));
+        assertFalse(mDevice.hasObject(getCaseInsensitiveSelector(mActivity.getSyncButtonText())));
+        assertFalse(mDevice.hasObject(getCaseInsensitiveSelector(mActivity.getCancelButtonText())));
+
+        verify(mActivity).setResult(eq(RESULT_CANCELED));
+    }
+
+    private BySelector getCaseInsensitiveSelector(String text) {
+        return By.text(Pattern.compile(text, CASE_INSENSITIVE));
+    }
+
+    private MockContentProvider setupMockContentProvider(
+            DefaultAccountAndState defaultAccountAndState, int localContactsCount,
+            int simContactsCount) {
+        MockContentProvider mockContentProvider = new MockContentProvider() {
+            final Bundle moveLocalContactsBundle = new Bundle();
+
+            @Override
+            public Bundle call(String method, String arg, Bundle extras) {
+                Bundle bundle = new Bundle();
+                if (DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD.equals(method)) {
+                    bundle.putInt(DefaultAccount.KEY_DEFAULT_ACCOUNT_STATE,
+                            defaultAccountAndState.getState());
+                    Account defaultAccount = defaultAccountAndState.getAccount();
+                    if (defaultAccount != null) {
+                        bundle.putString(Settings.ACCOUNT_NAME, defaultAccount.name);
+                        bundle.putString(Settings.ACCOUNT_TYPE, defaultAccount.type);
+                    }
+                    return bundle;
+                } else if (
+                        DefaultAccount.MOVE_LOCAL_CONTACTS_TO_CLOUD_DEFAULT_ACCOUNT_METHOD.equals(
+                                method)) {
+                    moveLocalContactsBundle.putBoolean(TEST_MOVE_LOCAL_CONTACTS_BUNDLE_KEY, true);
+                    return moveLocalContactsBundle;
+                } else if (DefaultAccount.MOVE_SIM_CONTACTS_TO_CLOUD_DEFAULT_ACCOUNT_METHOD.equals(
+                        method)) {
+                    moveLocalContactsBundle.putBoolean(TEST_MOVE_SIM_CONTACTS_BUNDLE_KEY, true);
+                    return moveLocalContactsBundle;
+                } else if (DefaultAccount.GET_NUMBER_OF_MOVABLE_LOCAL_CONTACTS_METHOD.equals(
+                        method)) {
+                    bundle.putInt(DefaultAccount.KEY_NUMBER_OF_MOVABLE_LOCAL_CONTACTS,
+                            localContactsCount);
+                    return bundle;
+                } else if (DefaultAccount.GET_NUMBER_OF_MOVABLE_SIM_CONTACTS_METHOD.equals(
+                        method)) {
+                    bundle.putInt(DefaultAccount.KEY_NUMBER_OF_MOVABLE_SIM_CONTACTS,
+                            simContactsCount);
+                    return bundle;
+                } else if (TEST_MOVE_LOCAL_CONTACTS_METHOD.equals(method)) {
+                    // Created this action to verify the move local contacts call.
+                    return moveLocalContactsBundle;
+                }
+                return bundle;
+            }
+        };
+        return mockContentProvider;
+    }
+
+    public static class TestMoveContactsToDefaultAccountActivity extends
+            MoveContactsToDefaultAccountActivity {
+        private static ContentResolver mContentResolver;
+
+        public static void setupForTesting(
+                ContentResolver contentResolver) {
+            mContentResolver = contentResolver;
+        }
+
+        @Override
+        public ContentResolver getContentResolver() {
+            return mContentResolver;
+        }
+
+        @Override
+        public String getMessageText(int movableContactsCount, String accountLabel,
+                String accountName) {
+            MessageFormat msgFormat = new MessageFormat(
+                    InstrumentationRegistry.getTargetContext().getString(
+                            R.string.movable_contacts_count),
+                    Locale.getDefault());
+            Map<String, Object> msgArgs = new HashMap<>();
+            msgArgs.put("contacts_count", movableContactsCount);
+            String movableContactsCountText = msgFormat.format(msgArgs);
+            return InstrumentationRegistry.getTargetContext().getString(
+                    R.string.move_contacts_to_default_account_dialog_message,
+                    movableContactsCountText, accountLabel, accountName);
+        }
+
+        @Override
+        String getTitleText() {
+            return InstrumentationRegistry.getTargetContext().getString(
+                    R.string.move_contacts_to_default_account_dialog_title);
+        }
+
+        @Override
+        String getSyncButtonText() {
+            return InstrumentationRegistry.getTargetContext().getString(
+                    R.string.move_contacts_to_default_account_dialog_sync_button_text);
+        }
+
+        @Override
+        String getCancelButtonText() {
+            return InstrumentationRegistry.getTargetContext().getString(
+                    R.string.move_contacts_to_default_account_dialog_cancel_button_text);
+        }
+
+        @Override
+        public CharSequence getLabelForType(Context context, final String accountType) {
+            return accountType;
+        }
+    }
+}
diff --git a/tests/src/com/android/providers/contacts/MoveRawContactsTest.java b/tests/src/com/android/providers/contacts/MoveRawContactsTest.java
index f4ce0dce..c3e022e5 100644
--- a/tests/src/com/android/providers/contacts/MoveRawContactsTest.java
+++ b/tests/src/com/android/providers/contacts/MoveRawContactsTest.java
@@ -26,6 +26,7 @@ import android.content.ContentResolver;
 import android.content.ContentValues;
 import android.database.Cursor;
 import android.database.sqlite.SQLiteDatabase;
+import android.platform.test.annotations.DisableFlags;
 import android.platform.test.annotations.EnableFlags;
 import android.platform.test.flag.junit.SetFlagsRule;
 import android.provider.ContactsContract.CommonDataKinds.GroupMembership;
@@ -33,6 +34,7 @@ import android.provider.ContactsContract.CommonDataKinds.StructuredName;
 import android.provider.ContactsContract.Data;
 import android.provider.ContactsContract.Groups;
 import android.provider.ContactsContract.RawContacts;
+import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
 
 import androidx.test.filters.MediumTest;
 
@@ -60,29 +62,26 @@ import java.util.Set;
  *
  * Run the test like this:
  * <code>
-   adb shell am instrument -e class com.android.providers.contacts.MoveRawContactsTest -w \
-           com.android.providers.contacts.tests/android.test.InstrumentationTestRunner
+ * adb shell am instrument -e class com.android.providers.contacts.MoveRawContactsTest -w \
+ * com.android.providers.contacts.tests/android.test.InstrumentationTestRunner
  * </code>
  */
 @MediumTest
 @RunWith(JUnit4.class)
 public class MoveRawContactsTest extends BaseContactsProvider2Test {
-    @ClassRule public static final SetFlagsRule.ClassRule mClassRule = new SetFlagsRule.ClassRule();
-
-    @Rule public final SetFlagsRule mSetFlagsRule = mClassRule.createSetFlagsRule();
-
+    @ClassRule
+    public static final SetFlagsRule.ClassRule mClassRule = new SetFlagsRule.ClassRule();
+    static final String CLOUD_ACCOUNT_TYPE = "cloudAccountType";
     static final Account SOURCE_ACCOUNT = new Account("sourceName", "sourceType");
     static final Account DEST_ACCOUNT = new Account("destName", "destType");
     static final Account DEST_ACCOUNT_WITH_SOURCE_TYPE = new Account("destName", "sourceType");
-    static final Account DEST_CLOUD_ACCOUNT = new Account("destName", "com.google");
+    static final Account DEST_CLOUD_ACCOUNT = new Account("destName", CLOUD_ACCOUNT_TYPE);
     static final Account SIM_ACCOUNT = new Account("simName", "simType");
-
     static final String SOURCE_ID = "uniqueSourceId";
-
     static final String NON_PORTABLE_MIMETYPE = "test/mimetype";
-
     static final String RES_PACKAGE = "testpackage";
-
+    @Rule
+    public final SetFlagsRule mSetFlagsRule = mClassRule.createSetFlagsRule();
     ContactsProvider2 mCp;
     AccountWithDataSet mSource;
     AccountWithDataSet mDest;
@@ -107,11 +106,14 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         mCloudDest = AccountWithDataSet.get(
                 DEST_CLOUD_ACCOUNT.name, DEST_CLOUD_ACCOUNT.type, null);
         DefaultAccountManager.setEligibleSystemCloudAccountTypesForTesting(new String[]{
-                DEST_CLOUD_ACCOUNT.type,
+                CLOUD_ACCOUNT_TYPE,
         });
 
         mMover = new ContactMover(mCp, mCp.getDatabaseHelper(), mDefaultAccountManager);
         mSimAcct = createSimAccount(SIM_ACCOUNT);
+
+        mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofNotSet());
     }
 
     @After
@@ -198,7 +200,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
                 RawContacts._ID + " <> ? and " + RawContacts.SOURCE_ID + " = ? and "
                         + RawContacts.DELETED + " = 1 and " + RawContacts.ACCOUNT_NAME + " = ? and "
                         + RawContacts.ACCOUNT_TYPE + " = ? and " + RawContacts.DIRTY + " = 1",
-                new String[] {
+                new String[]{
                         Long.toString(rawContactId),
                         sourceId,
                         account.getAccountName(),
@@ -211,7 +213,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
                 RawContacts._ID + " <> ? and "
                         + RawContacts.DELETED + " = 1 and " + RawContacts.ACCOUNT_NAME + " = ? and "
                         + RawContacts.ACCOUNT_TYPE + " = ?",
-                new String[] {
+                new String[]{
                         Long.toString(rawContactId),
                         account.getAccountName(),
                         account.getAccountType()
@@ -252,7 +254,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
                 Data.RAW_CONTACT_ID + " == ? AND "
                         + Data.MIMETYPE + " = ? AND "
                         + Data.DATA1 + " = ?",
-                new String[] {
+                new String[]{
                         Long.toString(rawContactId),
                         mimetype,
                         data1
@@ -279,7 +281,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         mResolver.insert(Groups.CONTENT_URI, values);
         Long groupId = getGroupWithName(account, title, titleRes);
 
-        for (Long rawContactId: memberIds) {
+        for (Long rawContactId : memberIds) {
             values = new ContentValues();
             values.put(GroupMembership.GROUP_ROW_ID, groupId);
             values.put(GroupMembership.RAW_CONTACT_ID, rawContactId);
@@ -315,7 +317,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
                 GroupMembership.GROUP_ROW_ID + " == ? AND "
                         + Data.MIMETYPE + " = ? AND "
                         + GroupMembership.RAW_CONTACT_ID + " = ?",
-                new String[] {
+                new String[]{
                         Long.toString(groupId),
                         GroupMembership.CONTENT_ITEM_TYPE,
                         Long.toString(rawContactId)
@@ -339,12 +341,12 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         assertEquals(members.size(), getCount(Data.CONTENT_URI,
                 GroupMembership.GROUP_ROW_ID + " == ? AND "
                         + Data.MIMETYPE + " = ?",
-                new String[] {
+                new String[]{
                         Long.toString(groupId),
                         GroupMembership.CONTENT_ITEM_TYPE
                 }));
 
-        for (Long member: members) {
+        for (Long member : members) {
             assertInGroup(member, groupId);
         }
     }
@@ -363,7 +365,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
                 Groups._ID + " <> ? and " + Groups.SOURCE_ID + " = ? and "
                         + Groups.DELETED + " = 1 and " + Groups.ACCOUNT_NAME + " = ? and "
                         + Groups.ACCOUNT_TYPE + " = ? and " + Groups.DIRTY + " = 1",
-                new String[] {
+                new String[]{
                         Long.toString(groupId),
                         sourceId,
                         account.getAccountName(),
@@ -373,12 +375,12 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
 
     private Long getGroupWithName(AccountWithDataSet account, String title, String titleRes) {
         try (Cursor c = mResolver.query(Groups.CONTENT_URI,
-                new String[] { Groups._ID, },
+                new String[]{Groups._ID, },
                 Groups.ACCOUNT_NAME + " = ? AND "
                         + Groups.ACCOUNT_TYPE + " = ? AND "
                         + Groups.TITLE + " = ? AND "
                         + Groups.TITLE_RES + " = ?",
-                new String[] {
+                new String[]{
                         account.getAccountName(),
                         account.getAccountType(),
                         title,
@@ -512,7 +514,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
                 RawContacts._ID + " <> ? and " + RawContacts.SOURCE_ID + " = ? and "
                         + RawContacts.DELETED + " = 1 and " + RawContacts.ACCOUNT_NAME + " IS NULL"
                         + " and " + RawContacts.ACCOUNT_TYPE + " IS NULL",
-                new String[] {
+                new String[]{
                         Long.toString(uniqueContactId),
                         SOURCE_ID
                 }));
@@ -543,7 +545,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
                 RawContacts._ID + " <> ? and " + RawContacts.SOURCE_ID + " = ? and "
                         + RawContacts.DELETED + " = 1 and " + RawContacts.ACCOUNT_NAME + " IS NULL"
                         + " and " + RawContacts.ACCOUNT_TYPE + " IS NULL",
-                new String[] {
+                new String[]{
                         Long.toString(uniqueContactId),
                         SOURCE_ID
                 }));
@@ -598,8 +600,9 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
      * will be deleted as a duplicate.
      */
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
-    public void testMoveUniqueRawContactWithNonPortableDataRows() {
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG,
+            Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
+    public void testMoveUniqueRawContactWithNonPortableDataRowsFlagEnabled() {
         // create a duplicate pair of contacts
         long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
                 SOURCE_ACCOUNT);
@@ -631,13 +634,54 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     /**
-     * Moves a contact between source and dest where both accounts have the same account type.
-    *  The contact is unique because of a non-portable data row. Because the account types match,
-    *  the non-portable data row will be considered while matching the contacts and the contact will
-    *  be treated as unique.
+     * Move a contact between source and dest where both account have different account types, but
+     * the delete non-common data rows flag is disabled.
+     * The contact is unique because of a custom data row. Because the account types match,
+     * the non-portable data row will be considered while matching the contacts and the contact will
+     * be treated as unique.
      */
     @Test
     @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @DisableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
+    public void testMoveUniqueRawContactWithNonPortableDataRowsFlagDisabled() {
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long destRawContactId = RawContactUtil.createRawContactWithName(mResolver, DEST_ACCOUNT);
+        // create a combination of data rows
+        DataUtil.insertStructuredName(mResolver, sourceRawContactId, "firstA", "lastA");
+        insertNonPortableData(mResolver, sourceRawContactId, "foo");
+        DataUtil.insertStructuredName(mResolver, destRawContactId, "firstA", "lastA");
+
+        // trigger the move
+        mMover.moveRawContactsWithSyncStubs(Set.of(mSource), mDest);
+
+        // Verify no stub was written since no source ID existed
+        assertMoveStubDoesNotExist(sourceRawContactId, mSource);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(sourceRawContactId, mDest, false);
+        // all data rows should have moved with the source
+        assertDataExists(sourceRawContactId, NON_PORTABLE_MIMETYPE, "foo");
+        assertDataExists(sourceRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
+
+        // verify the original near duplicate contact remains unchanged
+        assertMovedRawContact(destRawContactId, mDest, false);
+        // the non portable data should still not exist on the destination account
+        assertDataDoesNotExist(destRawContactId, NON_PORTABLE_MIMETYPE, "foo");
+        // the existing data row in the destination account should be unaffected
+        assertDataExists(destRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
+    }
+
+    /**
+     * Moves a contact between source and dest where both accounts have the same account type.
+     * The contact is unique because of a non-portable data row. Because the account types match,
+     * the non-portable data row will be considered while matching the contacts and the contact will
+     * be treated as unique.
+     */
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG,
+            Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
     public void testMoveUniqueRawContactsWithNonPortableDataRowsAccountTypesMatch() {
         mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_ACCOUNT_WITH_SOURCE_TYPE});
         AccountWithDataSet dest =
@@ -674,6 +718,51 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         assertDataExists(destRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
     }
 
+    /**
+     * Moves a contact between source and dest where both accounts have the same account type.
+     * The contact is unique because of a non-portable data row. Because the account types match,
+     * the non-portable data row will be considered while matching the contacts and the contact will
+     * be treated as unique.
+     */
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @DisableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
+    public void testMoveUniqueRawContactsWithNonPortableDataRowsAccountTypesMatchFlagDisabled() {
+        mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_ACCOUNT_WITH_SOURCE_TYPE});
+        AccountWithDataSet dest =
+                AccountWithDataSet.get(DEST_ACCOUNT_WITH_SOURCE_TYPE.name,
+                        DEST_ACCOUNT_WITH_SOURCE_TYPE.type, null);
+
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long destRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                DEST_ACCOUNT_WITH_SOURCE_TYPE);
+        // create a combination of data rows
+        DataUtil.insertStructuredName(mResolver, sourceRawContactId, "firstA", "lastA");
+        insertNonPortableData(mResolver, sourceRawContactId, "foo");
+        DataUtil.insertStructuredName(mResolver, destRawContactId, "firstA", "lastA");
+
+        // trigger the move
+        mMover.moveRawContactsWithSyncStubs(Set.of(mSource), dest);
+
+        // Verify no stub was written since no source ID existed
+        assertMoveStubDoesNotExist(sourceRawContactId, mSource);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(sourceRawContactId, dest, false);
+        // all data rows should have moved with the source
+        assertDataExists(sourceRawContactId, NON_PORTABLE_MIMETYPE, "foo");
+        assertDataExists(sourceRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
+
+        // verify the original near duplicate contact remains unchanged
+        assertMovedRawContact(destRawContactId, dest, false);
+        // the non portable data should still not exist on the destination account
+        assertDataDoesNotExist(destRawContactId, NON_PORTABLE_MIMETYPE, "foo");
+        // the existing data row in the destination account should be unaffected
+        assertDataExists(destRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
+    }
+
     /**
      * Moves a contact between source and dest where both accounts have the same account type.
      * The contact is unique because of a non-portable data row. Because the account types match,
@@ -681,7 +770,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
      * be treated as a duplicate.
      */
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG,
+            Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
     public void testMoveDuplicateRawContactsWithNonPortableDataRowsAccountTypesMatch() {
         mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_ACCOUNT_WITH_SOURCE_TYPE});
         AccountWithDataSet dest =
@@ -714,6 +804,47 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         assertDataExists(destRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
     }
 
+    /**
+     * Moves a contact between source and dest where both accounts have the same account type.
+     * The contact is unique because of a non-portable data row. Because the account types match,
+     * the non-portable data row will be considered while matching the contacts and the contact will
+     * be treated as a duplicate.
+     */
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
+    public void testMoveDuplicateRawContactsWithNonPortableDataRowsAccountTypesMatchFlagDisabled() {
+        mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_ACCOUNT_WITH_SOURCE_TYPE});
+        AccountWithDataSet dest =
+                AccountWithDataSet.get(DEST_ACCOUNT_WITH_SOURCE_TYPE.name,
+                        DEST_ACCOUNT_WITH_SOURCE_TYPE.type, null);
+
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long destRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                DEST_ACCOUNT_WITH_SOURCE_TYPE);
+        // create a combination of data rows
+        DataUtil.insertStructuredName(mResolver, sourceRawContactId, "firstA", "lastA");
+        insertNonPortableData(mResolver, sourceRawContactId, "foo");
+        DataUtil.insertStructuredName(mResolver, destRawContactId, "firstA", "lastA");
+        insertNonPortableData(mResolver, destRawContactId, "foo");
+
+        // trigger the move
+        mMover.moveRawContacts(Set.of(mSource), dest);
+
+        // verify the duplicate contact has been deleted
+        assertMovedContactIsDeleted(sourceRawContactId, mSource);
+        assertDataDoesNotExist(sourceRawContactId, NON_PORTABLE_MIMETYPE, "foo");
+        assertDataDoesNotExist(
+                sourceRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
+
+        // verify the original near duplicate contact remains unchanged
+        assertMovedRawContact(destRawContactId, dest, false);
+        assertDataExists(destRawContactId, NON_PORTABLE_MIMETYPE, "foo");
+        assertDataExists(destRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
+    }
+
     @Test
     @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
     public void testMoveDuplicateNonSystemGroup() {
@@ -764,7 +895,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         assertEquals(0, getCount(Groups.CONTENT_URI,
                 Groups.ACCOUNT_NAME + " = ? AND "
                         + Groups.ACCOUNT_TYPE + " = ?",
-                new String[] {
+                new String[]{
                         mSource.getAccountName(),
                         mSource.getAccountType()
                 }));
@@ -815,7 +946,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         assertEquals(0, getCount(Groups.CONTENT_URI,
                 Groups.ACCOUNT_NAME + " = ? AND "
                         + Groups.ACCOUNT_TYPE + " = ?",
-                new String[] {
+                new String[]{
                         mSource.getAccountName(),
                         mSource.getAccountType()
                 }));
@@ -946,7 +1077,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
                         + Groups.ACCOUNT_TYPE + " = ? AND "
                         + Groups.TITLE + " = ? AND "
                         + Groups.TITLE_RES + " = ?",
-                new String[] {
+                new String[]{
                         mDest.getAccountName(),
                         mDest.getAccountType(),
                         "groupTitle",
@@ -986,7 +1117,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
                         + Groups.ACCOUNT_TYPE + " = ? AND "
                         + Groups.TITLE + " = ? AND "
                         + Groups.TITLE_RES + " = ?",
-                new String[] {
+                new String[]{
                         mDest.getAccountName(),
                         mDest.getAccountType(),
                         "groupTitle",
@@ -1001,12 +1132,14 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         setDefaultAccountManagerAccounts(new Account[]{
                 DEST_CLOUD_ACCOUNT,
         });
-        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccount.ofCloud(DEST_CLOUD_ACCOUNT));
 
         // create a unique contact in the (null/local) source account
         long uniqueContactId = createStarredRawContactForMove(
                 "Foo", "Bar",  /* sourceId= */ null, /* account= */ null);
 
+        mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(DEST_CLOUD_ACCOUNT));
+
         // trigger the move
         mMover.moveLocalToCloudDefaultAccount();
 
@@ -1014,6 +1147,85 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         assertMovedRawContact(uniqueContactId, mCloudDest, true);
     }
 
+    @Test
+    @EnableFlags({
+            Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG,
+            Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    public void testMoveLocalToDefaultCloudAccount_disableIneligibleAccountMove_flagOn() {
+        mActor.setAccounts(new Account[]{DEST_CLOUD_ACCOUNT});
+        setDefaultAccountManagerAccounts(new Account[]{
+                DEST_CLOUD_ACCOUNT,
+        });
+
+        // create a unique contact in the (null/local) source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar",  /* sourceId= */ null, /* account= */ null);
+
+        mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(DEST_CLOUD_ACCOUNT));
+
+        int count = mMover.getNumberLocalContacts();
+        mMover.moveLocalToCloudDefaultAccount();
+
+        assertEquals(1, count);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(uniqueContactId, mCloudDest, true);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    public void testMoveLocalToIneligibleCloudAccount_disableIneligibleAccountMove_flagOff() {
+        mActor.setAccounts(new Account[]{DEST_ACCOUNT});
+        setDefaultAccountManagerAccounts(new Account[]{
+                DEST_ACCOUNT,
+        });
+
+        // create a unique contact in the (null/local) source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar",  /* sourceId= */ null, /* account= */ null);
+
+        mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(DEST_ACCOUNT));
+
+        int count = mMover.getNumberLocalContacts();
+        mMover.moveLocalToCloudDefaultAccount();
+
+        assertEquals(1, count);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(uniqueContactId, mDest, true);
+    }
+
+    @Test
+    @EnableFlags({
+            Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG,
+            Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    public void testMoveLocalToIneligibleCloudAccount_disableIneligibleAccountMove_flagOn() {
+        mActor.setAccounts(new Account[]{DEST_ACCOUNT});
+        setDefaultAccountManagerAccounts(new Account[]{
+                DEST_ACCOUNT,
+        });
+        AccountWithDataSet source =
+                AccountWithDataSet.get(null, null, null);
+
+        // create a unique contact in the (null/local) source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar",  /* sourceId= */ null, /* account= */ null);
+
+        mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(DEST_ACCOUNT));
+
+        int count = mMover.getNumberLocalContacts();
+        mMover.moveLocalToCloudDefaultAccount();
+
+        assertEquals(0, count);
+
+        // verify the unique raw contact has *not* been moved
+        assertMovedRawContact(uniqueContactId, source, true);
+    }
+
     @Test
     @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveToDefaultNonCloudAccount() {
@@ -1023,7 +1235,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         setDefaultAccountManagerAccounts(new Account[]{
                 DEST_ACCOUNT,
         });
-        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccount.ofCloud(DEST_ACCOUNT));
+        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccountAndState.ofLocal());
 
         // create a unique contact in the (null/local) source account
         long uniqueContactId = createStarredRawContactForMove(
@@ -1044,12 +1256,13 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
                 SOURCE_ACCOUNT,
                 DEST_ACCOUNT,
         });
-        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccount.ofCloud(DEST_ACCOUNT));
 
         // create a unique contact in the source account
         long uniqueContactId = createStarredRawContactForMove(
                 "Foo", "Bar", /* sourceId= */ null, SOURCE_ACCOUNT);
 
+        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccountAndState.ofCloud(DEST_ACCOUNT));
+
         // trigger the move
         mMover.moveLocalToCloudDefaultAccount();
 
@@ -1061,17 +1274,18 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveSimToDefaultCloudAccount() {
         mActor.setAccounts(new Account[]{SIM_ACCOUNT, DEST_CLOUD_ACCOUNT});
-
         setDefaultAccountManagerAccounts(new Account[]{
                 SIM_ACCOUNT,
                 DEST_CLOUD_ACCOUNT,
         });
-        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccount.ofCloud(DEST_CLOUD_ACCOUNT));
 
         // create a unique contact in the (null/local) source account
         long uniqueContactId = createStarredRawContactForMove(
                 "Foo", "Bar",  /* sourceId= */ null, /* account= */ SIM_ACCOUNT);
 
+        mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(DEST_CLOUD_ACCOUNT));
+
         // trigger the move
         mMover.moveSimToCloudDefaultAccount();
 
@@ -1079,6 +1293,89 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         assertMovedRawContact(uniqueContactId, mCloudDest, true);
     }
 
+
+    @Test
+    @EnableFlags({
+            Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG,
+            Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    public void testMoveSimToDefaultCloudAccount_disableIneligibleAccountMove_flagOn() {
+        mActor.setAccounts(new Account[]{SIM_ACCOUNT, DEST_CLOUD_ACCOUNT});
+        setDefaultAccountManagerAccounts(new Account[]{
+                SIM_ACCOUNT,
+                DEST_CLOUD_ACCOUNT,
+        });
+
+        // create a unique contact in the (null/local) source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar",  /* sourceId= */ null, SIM_ACCOUNT);
+
+        mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(DEST_CLOUD_ACCOUNT));
+
+        int count = mMover.getNumberSimContacts();
+        mMover.moveSimToCloudDefaultAccount();
+
+        assertEquals(1, count);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(uniqueContactId, mCloudDest, true);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    public void testMoveSimToIneligibleCloudAccount_disableIneligibleAccountMove_flagOff() {
+        mActor.setAccounts(new Account[]{SIM_ACCOUNT, DEST_ACCOUNT});
+        setDefaultAccountManagerAccounts(new Account[]{
+                SIM_ACCOUNT,
+                DEST_ACCOUNT,
+        });
+
+        // create a unique contact in the (null/local) source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar",  /* sourceId= */ null, SIM_ACCOUNT);
+
+        mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(DEST_ACCOUNT));
+
+        int count = mMover.getNumberSimContacts();
+        mMover.moveSimToCloudDefaultAccount();
+
+        assertEquals(1, count);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(uniqueContactId, mDest, true);
+    }
+
+    @Test
+    @EnableFlags({
+            Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG,
+            Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG
+    })
+    public void testMoveSimToIneligibleCloudAccount_disableIneligibleAccountMove_flagOn() {
+        mActor.setAccounts(new Account[]{DEST_ACCOUNT});
+        setDefaultAccountManagerAccounts(new Account[]{
+                DEST_ACCOUNT,
+        });
+
+        // create a unique contact in the (null/local) source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar",  /* sourceId= */ null, SIM_ACCOUNT);
+
+        mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(DEST_ACCOUNT));
+
+        int count = mMover.getNumberSimContacts();
+        mMover.moveLocalToCloudDefaultAccount();
+
+        assertEquals(0, count);
+
+        // verify the unique raw contact has not been moved
+        assertMovedRawContact(uniqueContactId,
+                new AccountWithDataSet(SIM_ACCOUNT.name, SIM_ACCOUNT.type, /* dataSet= */ null),
+                /* isStarred= */ true);
+    }
+
     @Test
     @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
     public void testGetNumberContactsWithSimContacts() {
@@ -1088,7 +1385,6 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
                 SIM_ACCOUNT,
                 DEST_CLOUD_ACCOUNT,
         });
-        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccount.ofCloud(DEST_CLOUD_ACCOUNT));
 
         // create a unique contact in a sim account
         createStarredRawContactForMove(
@@ -1097,6 +1393,9 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         createStarredRawContactForMove(
                 "Bar", "Baz",  /* sourceId= */ null, /* account= */ DEST_CLOUD_ACCOUNT);
 
+        mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(DEST_CLOUD_ACCOUNT));
+
         // get the counts
         int localCount = mMover.getNumberLocalContacts();
         int simCount = mMover.getNumberSimContacts();
@@ -1113,12 +1412,14 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
         setDefaultAccountManagerAccounts(new Account[]{
                 DEST_CLOUD_ACCOUNT,
         });
-        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccount.ofCloud(DEST_CLOUD_ACCOUNT));
 
         // create a unique contact in the (null/local) source account
         createStarredRawContactForMove(
                 "Foo", "Bar",  /* sourceId= */ null, /* account= */ null);
 
+        mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccountAndState.ofCloud(DEST_CLOUD_ACCOUNT));
+
         // trigger the move
         int localCount = mMover.getNumberLocalContacts();
         int simCount = mMover.getNumberSimContacts();
```

