```diff
diff --git a/contactsprovider_flags.aconfig b/contactsprovider_flags.aconfig
index 22498b6c..4bd66b2b 100644
--- a/contactsprovider_flags.aconfig
+++ b/contactsprovider_flags.aconfig
@@ -36,4 +36,28 @@ flag {
     namespace: "contacts"
     description: "Delete data rows not included in CommonDataKinds when moving between account types"
     bug: "330324156"
-}
\ No newline at end of file
+}
+flag {
+    name: "disable_cp2_account_move_flag"
+    namespace: "contacts"
+    description: "Disable bulk move of contacts between accounts"
+    bug: "382359013"
+}
+flag {
+   name: "log_contact_save_invalid_account_error"
+   namespace: "contacts"
+   description: "Log the error of saving contacts to invalid account"
+   bug: "399412962"
+   metadata {
+       purpose: PURPOSE_BUGFIX
+   }
+}
+flag {
+   name: "log_call_method"
+   namespace: "contacts"
+   description: "Log the call method"
+   bug: "400528898"
+   metadata {
+       purpose: PURPOSE_BUGFIX
+   }
+}
diff --git a/proguard.flags b/proguard.flags
index 308513b9..0b79594c 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -8,9 +8,10 @@
 }
 
 # Any class or method annotated with NeededForTesting.
--keep @com.android.providers.contacts.util.NeededForTesting class *
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @com.android.providers.contacts.util.NeededForTesting class * {
+  void <init>();
+}
 -keepclassmembers class * {
-@com.android.providers.contacts.util.NeededForTesting *;
+  @com.android.providers.contacts.util.NeededForTesting *;
 }
-
--verbose
\ No newline at end of file
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index e7ad3299..ff16101f 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Ander"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Stemboodskap van "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sinkroniseer bestaande kontakte?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Jy kan %1$s sinkroniseer om te verseker dat hulle na %2$s (%3$s) gerugsteun is"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# bestaande kontak}other{# bestaande kontakte}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Jy kan %1$s sinkroniseer wat na %2$s gerugsteun is (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# bestaande kontak om te verseker dit is}other{# bestaande kontakte om te verseker hulle is}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinkroniseer"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Moenie sinkroniseer nie"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopieer kontaktedatabasis"</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index 29e0f210..298d1c7c 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"ሌላ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ከ....የድምፅ መልዕክት "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ነባር ዕውቂያዎች ይስመሩ?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"ወደ %2$s (%3$s) ምትኬ እንደተቀመጠላቸው ለማረጋገጥ %1$s ማስመር ይችላሉ"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# ነባር ዕውቂያ}one{# ነባር ዕውቂያ}other{# ነባር ዕውቂያዎች}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%2$s (%3$s) ላይ ምትኬ የተቀመጠላቸው %1$s ማሥመር ይችላሉ"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{መሆኑን ለማረጋገጥ # ነባር ዕውቂያ}one{መሆኑን ለማረጋገጥ # ነባር ዕውቂያ}other{መሆናቸውን ለማረጋገጥ # ነባር ዕውቂያዎች}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"አስምር"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"አታመሳስል"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"የእውቂያዎች የውሂብ ጎታ ገልብጥ"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index f31f984d..a78bfad7 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"غير ذلك"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"بريد صوتي من "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"هل تريد مزامنة جهات الاتصال الحالية؟"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"‏يمكنك مزامنة %1$s لضمان الاحتفاظ بنسخة احتياطية منها في %2$s‏ (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{جهة اتصال واحدة حالية}zero{‫# جهة اتصال حالية}two{جهتي اتصال حاليتين}few{‫# جهات اتصال حالية}many{‫# جهة اتصال حالية}other{‫# جهة اتصال حالية}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"‏يمكنك مزامنة %1$s التي تم الاحتفاظ بنسخة احتياطية منها في %2$s‏ (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{جهة اتصال حالية واحدة للتأكّد من أنّها}zero{‫# جهة اتصال حالية للتأكّد من أنّها}two{جهتا اتصال حاليتان للتأكّد من أنّهما}few{‫# جهات اتصال حالية للتأكّد من أنّها}many{‫# جهة اتصال حالية للتأكّد من أنّها}other{‫# جهة اتصال حالية للتأكّد من أنّها}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"مزامنة"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"عدم المزامنة"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"نسخ قاعدة بيانات جهات الاتصال"</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 7ce7e47c..18e82fb5 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"অন্যান্য"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ইয়াৰ পৰা অহা ভইচমেল "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ইতিমধ্যে থকা সম্পৰ্কসমূহ ছিংক কৰিবনে?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"আপুনি %1$sক ছিংক কৰিব পাৰে যাতে সেইসমূহ %2$s (%3$s)ত বেক আপ কৰা বুলি নিশ্চিত কৰিব পাৰি"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# টা ইতিমধ্যে থকা সম্পৰ্ক}one{# টা ইতিমধ্যে থকা সম্পৰ্ক}other{# টা ইতিমধ্যে থকা সম্পৰ্ক}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"আপুনি %2$s (%3$s)ত বেক আপ কৰি থোৱা %1$sক ছিংক কৰিব পাৰে"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{এয়া নিশ্চিত কৰিবলৈ # টা ইতিমধ্যে থকা সম্পৰ্ক}one{এয়া নিশ্চিত কৰিবলৈ # টা ইতিমধ্যে থকা সম্পৰ্ক}other{এয়া নিশ্চিত কৰিবলৈ # টা ইতিমধ্যে থকা সম্পৰ্ক}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ছিংক কৰক"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ছিংক নকৰিব"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"সম্পৰ্কসূচীৰ ডেটাবেছ প্ৰতিলিপি কৰক"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 05d00e10..47bbdd3c 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Digər"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Səsli mesaj göndərən: "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Mövcud kontaktlar sinxronlaşdırılsın?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s sinxronlaşdıraraq %2$s (%3$s) hesabına yedəkləndiyinə əmin olun"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# mövcud kontakt}other{# mövcud kontakt}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%1$s %2$s (%3$s) hesabına yedəklənməsini təmin edə bilərsiniz"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# mövcud kontaktı sinxronlaşdıraraq onun}other{# mövcud kontaktı sinxronlaşdıraraq onların}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinxronlaşdırın"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Sinxronlaşdırmayın"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kontakt data bazasını kopyalayın"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 39edec9c..dedd6f76 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Drugo"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Govorna pošta od "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Želite da sinhronizujete postojeće kontakte?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Možete da sinhronizujete %1$s da biste se uverili da se rezervne kopije prave na %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# postojeći kontakt}one{# postojeći kontakti}few{# postojeća kontakta}other{# postojećih kontakata}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Možete da sinhronizujete %1$s se rezervne kopije prave na %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# postojeći kontakt da biste se uverili da}one{# postojeći kontakt da biste se uverili da}few{# postojeća kontakta da biste se uverili da}other{# postojećih kontakata da biste se uverili da}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinhronizuj"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nemoj da sinhronizuješ"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiranje baze podataka sa kontaktima"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index d5e6fad1..5024055c 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Іншае"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Галасавое паведамленне ад "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Сінхранізаваць існуючыя кантакты?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Вы можаце сінхранізаваць %1$s, каб гарантаваць рэзервовае капіраванне ва ўліковы запіс %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# існуючы кантакт}one{# існуючы кантакт}few{# існуючыя кантакты}many{# існуючых кантактаў}other{# існуючага кантакту}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Вы можаце сінхранізаваць %1$s ў %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# існуючы кантакт, каб стварыць яго рэзервовую копію}one{# існуючы кантакт, каб стварыць іх рэзервовыя копіі}few{# існуючыя кантакты, каб стварыць іх рэзервовыя копіі}many{# існуючых кантактаў, каб стварыць іх рэзервовыя копіі}other{# існуючага кантакту, каб стварыць іх рэзервовыя копіі}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Сінхранізаваць"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Не сінхранізаваць"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Капiраваць базу дадзеных кантактаў"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index a9c6e87d..f446c0b6 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Други"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Гласова поща от "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Да се синхронизират ли съществуващите контакти?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Можете да синхронизирате %1$s, за да бъдат създадени съответните резервни копия в %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# съществуващ контакт}other{# съществуващи контакта}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Можете да синхронизирате %1$s резервно копие в(ъв) %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# съществуващ контакт, за да е сигурно, че има}other{# съществуващ контакт, за да е сигурно, че имат}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синхронизиране"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Без синхронизиране"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Копиране на базата от данни на контактите"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index f535108b..7c1babbb 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"অন্যান্য"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"এর থেকে ভয়েসমেল "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"বর্তমান পরিচিতি সিঙ্ক করতে চান?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s যাতে %2$s (%3$s)-এ ব্যাক-আপ করা যায় তা নিশ্চিত করতে, আপনি এটি সিঙ্ক করতে পারবেন"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{#টি বর্তমান পরিচিতি}one{#টি বর্তমান পরিচিতি}other{#টি বর্তমান পরিচিতি}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"আপনি %2$s (%3$s) ব্যাক-আপ নিতে %1$s সিঙ্ক করতে পারবেন"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{বর্তমানে থাকা #টি পরিচিতিকে নিশ্চিত করতে হবে যে এটি}one{বর্তমানে থাকা #টি পরিচিতিকে নিশ্চিত করতে হবে যে এগুলি}other{বর্তমানে থাকা #টি পরিচিতিকে নিশ্চিত করতে হবে যে এগুলি}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"সিঙ্ক করুন"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"সিঙ্ক করবেন না"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"পরিচিতির ডেটাবেস কপি করুন"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 0389ff35..817b0416 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Ostalo"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Govorna pošta od "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sinhronizirati postojeće kontakte?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Možete sinhronizirati %1$s da osigurate da se napravi sigurnosna kopija na usluzi %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# postojeći kontakt}one{# postojeći kontakt}few{# postojeća kontakta}other{# postojećih kontakata}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Možete sinhronizirati %1$s izradu sigurnosne kopije na uslugu %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# postojeći kontakt da osigurate}one{# postojeći kontakt da osigurate}few{# postojeća kontakta da osigurate}other{# postojećih kontakata da osigurate}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinhroniziraj"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nemoj sinhronizirati"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiraj bazu podataka kontakata"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 9bb890fb..8d3f266c 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Altres"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Missatge de veu de "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vols sincronitzar els contactes existents?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Pots sincronitzar %1$s per assegurar-te que se\'n creï una còpia de seguretat a %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contacte existent}other{# contactes existents}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Pots sincronitzar %1$s se\'n creï una còpia de seguretat a %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# contacte existent per assegurar-te que}other{# contactes existents per assegurar-te que}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronitza"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"No sincronitzis"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copia la base de dades de contactes"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 1bf42b3c..cc9611f8 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Jiné"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Hlasová zpráva od uživatele "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Synchronizovat stávající kontakty?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Můžete synchronizovat %1$s, aby došlo k zálohování do: %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# stávající kontakt}few{# stávající kontakty}many{# stávajícího kontaktu}other{# stávajících kontaktů}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Můžete synchronizovat %1$s zazálohování v účtu %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# existující kontakt a zajistit tak jeho}few{# existující kontakty a zajistit tak jejich}many{# existujícího kontaktu a zajistit tak jejich}other{# existujících kontaktů a zajistit tak jejich}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchronizovat"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nesynchronizovat"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopírování databáze kontaktů"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 9a70c6cd..d8cb7e0e 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Andre"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Telefonsvarerbesked fra "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vil du synkronisere eksisterende kontakter?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Du kan synkronisere %1$s for at sikre, at de sikkerhedskopieres til %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# eksisterende kontakt}one{# eksisterende kontakt}other{# eksisterende kontakter}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Du kan synkronisere %1$s er sikkerhedskopieret til %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# eksisterende kontakt for at sikre, at vedkommende er}one{# eksisterende kontakt for at sikre, at vedkommende er}other{# eksisterende kontakter for at sikre, at de er}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synkroniser"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Synkroniser ikke"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiér database med kontakter"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 9c321d85..6ac44871 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Sonstige"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Mailboxnachricht von "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vorhandene Kontakte synchronisieren?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"#%1$s können synchronisiert werden, um sicherzustellen, dass sie in %2$s (%3$s) gesichert werden"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# vorhandener Kontakt}other{# vorhandene Kontakte}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Du kannst %1$s synchronisieren und in %2$s (%3$s) sichern"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# vorhandenen Kontakt}other{# vorhandene Kontakte}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchronisieren"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nicht synchronisieren"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kontaktdatenbank kopieren"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index f22fb79b..c1f29ad9 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Άλλο"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Μήνυμα αυτόματου τηλεφωνητή από "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Συγχρονισμός υπαρχουσών επαφών;"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Μπορείτε να συγχρονίσετε %1$s για να διασφαλίσετε ότι έχουν δημιουργηθεί αντίγραφα ασφαλείας στο %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# υπάρχουσα επαφή}other{# υπάρχουσες επαφές}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Μπορείτε να συγχρονίσετε %1$s για τα οποία έχουν δημιουργηθεί αντίγραφα ασφαλείας στο %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# υπάρχουσα επαφή για να βεβαιωθείτε ότι είναι}other{# υπάρχουσες επαφές για να βεβαιωθείτε ότι είναι}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Συγχρονισμός"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Χωρίς συγχρονισμό"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Αντιγραφή βάσης δεδομένων επαφών"</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index bd654c15..71cfddab 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Other"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Voicemail from "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sync existing contacts?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"You can sync %1$s to ensure that they\'re backed up to %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# existing contact}other{# existing contacts}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"You can sync %1$s backed up to %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# existing contact to ensure that it\'s}other{# existing contacts to ensure that they\'re}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sync"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Don\'t sync"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copy contacts database"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index a2be51f5..3d94b326 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Other"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Voicemail from "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sync existing contacts?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"You can sync %1$s to ensure they\'re backed up to %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# existing contact}other{# existing contacts}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"You can sync %1$s backed up to %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# existing contact to ensure it\'s}other{# existing contacts to ensure they\'re}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sync"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Don\'t sync"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copy contacts database"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index bd654c15..71cfddab 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Other"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Voicemail from "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sync existing contacts?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"You can sync %1$s to ensure that they\'re backed up to %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# existing contact}other{# existing contacts}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"You can sync %1$s backed up to %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# existing contact to ensure that it\'s}other{# existing contacts to ensure that they\'re}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sync"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Don\'t sync"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copy contacts database"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index bd654c15..71cfddab 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Other"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Voicemail from "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sync existing contacts?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"You can sync %1$s to ensure that they\'re backed up to %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# existing contact}other{# existing contacts}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"You can sync %1$s backed up to %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# existing contact to ensure that it\'s}other{# existing contacts to ensure that they\'re}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sync"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Don\'t sync"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copy contacts database"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index f87c885e..8f258271 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Otro"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Mensaje de voz de "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"¿Quieres sincronizar los contactos existentes?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Puedes sincronizar %1$s para garantizar que se cree una copia de seguridad en %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contacto existente}other{# contactos existentes}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Puedes sincronizar %1$s cree una copia de seguridad en %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# contacto existente para garantizar que se}other{# contactos existentes para garantizar que se}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizar"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"No sincronizar"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiar base de datos de contactos"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 38edd14f..7040d392 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Otro"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Mensaje de voz de "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"¿Sincronizar contactos?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Puedes sincronizar %1$s para asegurarte de que hay una copia de seguridad en %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contacto}other{# contactos}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Puedes sincronizar %1$s hay una copia de seguridad en %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# contacto para asegurarte de que}other{# contactos para asegurarte de que}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizar"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"No sincronizar"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiar base de datos de contactos"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 86108642..b7b3800d 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Muu"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Kõnepost kontaktilt "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Kas sünkroonida olemasolevad kontaktid?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Saate sünkroonida %1$s, et tagada nende varundamine asukohas %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# olemasolev kontakt}other{# olemasolevat kontakti}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Saate sünkroonida %1$s varundamine asukohta %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# olemasoleva kontakti, et tagada tema}other{# olemasolevat kontakti, et tagada nende}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sünkrooni"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ära sünkrooni"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kontaktide andmebaasi kopeerimine"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index d3d8ee41..e6b87baa 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Beste bat"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Mezu bat utzi du erantzungailuan honek: "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Lehendik dauden kontaktuak sinkronizatu nahi dituzu?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s sinkronizatzeko aukera duzu, %2$s zerbitzuan babeskopia dutela ziurtatzeko (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{Lehendik dagoen # kontaktu}other{Lehendik dauden # kontaktu}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Sinkronizatu %1$s %2$s zerbitzuan babeskopiak dauzkatela (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{lehendik duzun # kontaktu, ziurtatzeko}other{lehendik dituzun # kontaktu, ziurtatzeko}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinkronizatu"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ez sinkronizatu"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiatu kontaktuen datu-basea"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 370d96c7..1828f7c4 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -26,12 +26,12 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"سایر موارد"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"پست صوتی از "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"مخاطبین موجود همگام‌سازی شوند؟"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"‏می‌توانید %1$s را همگام‌سازی کنید تا مطمئن شوید در ‏%2$s ‏(%3$s) پشتیبان‌گیری می‌شوند."</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# مخاطب موجود}one{# مخاطب موجود}other{# مخاطب موجود}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"‏می‌توانید %1$s همگام‌سازی کنید تا مطمئن شوید در %2$s‏ (%3$s) پشتیبان‌گیری شده باشد"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{‫# مخاطب موجود را}one{‫# مخاطب موجود را}other{‫# مخاطب موجود را}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"همگام‌سازی"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"همگام‌سازی نشود"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"کپی پایگاه داده مخاطبین"</string>
-    <string name="debug_dump_database_message" msgid="406438635002392290">"شما در شرف ۱) ایجاد یک نسخه از پایگاه داده‌ در حافظه داخلی هستید، این کپی حاوی همه اطلاعات مربوط به مخاطبین و همه گزارش‌های تماس است و همچنین می‌خواهید ۲) آن را ایمیل کنید. به‌خاطر داشته باشید که به محض تهیه این نسخه در دستگاه یا دریافت ایمیل، آن را حذف کنید."</string>
+    <string name="debug_dump_database_message" msgid="406438635002392290">"شما در شرف ۱) ایجاد یک نسخه از پایگاه داده‌ در فضای ذخیره‌سازی داخلی هستید، این کپی حاوی همه اطلاعات مربوط به مخاطبین و همه گزارش‌های تماس است و همچنین می‌خواهید ۲) آن را ایمیل کنید. به‌خاطر داشته باشید که به محض تهیه این نسخه در دستگاه یا دریافت ایمیل، آن را حذف کنید."</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"اکنون حذف شود"</string>
     <string name="debug_dump_start_button" msgid="2837506913757600001">"شروع"</string>
     <string name="debug_dump_email_sender_picker" msgid="3534420908672176460">"یک برنامه را برای ارسال فایل خود انتخاب کنید"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 032887b9..2345e47e 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Muu"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Vastaajaviesti henkilöltä "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Synkronoidaanko nykyiset kontaktit?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Voit synkronoida %1$s ja varmistaa varmuuskopioitumisen (%2$s – %3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# nykyinen kontakti}other{# nykyistä kontaktia}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Voit synkronoida %1$s varmuuskopioitu %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# nykyisen kontaktin varmistaaksesi, että se on}other{# nykyistä kontaktia varmistaaksesi, että ne on}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synkronoi"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Älä synkronoi"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopioi kontaktitietokanta"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 551505d6..36daf181 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Autre"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Message vocal de "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Synchroniser les contacts existants?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Vous pouvez synchroniser %1$s pour vous assurer qu\'ils sont sauvegardés sur %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contact existant}one{# contact existant}other{# contacts existants}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Vous pouvez synchroniser %1$s sauvegardés sur %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# contact existant pour vous assurer qu\'il est}one{# contact existant pour vous assurer qu\'il est}other{# contacts existants pour vous assurer qu\'ils sont}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchroniser"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ne pas synchroniser"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copier la base de données de contacts"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index a3f35789..01cc923d 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Autre"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Message vocal de "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Synchroniser les contacts existants ?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Vous pouvez synchroniser %1$s pour vous assurer qu\'ils sont sauvegardés sur %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contact existant}one{# contact existant}other{# contacts existants}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Vous pouvez synchroniser %1$s sauvegarde sur %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# contact existant pour vous assurer de sa}one{# contact existant pour vous assurer de sa}other{# contacts existants pour vous assurer de leur}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchroniser"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ne pas synchroniser"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copier la base de données de contacts"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 1c21366e..695a3fa6 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Outro"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Correo de voz de "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Queres sincronizar os contactos?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Podes sincronizar %1$s para garantir que o teñas almacenado nunha copia de seguranza en %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contacto}other{# contactos}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Podes sincronizar %1$s hai unha copia de seguranza feita en %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# contacto existente para comprobar que}other{# contactos existentes para comprobar que}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizar"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Non sincronizar"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiar base de datos dos contactos"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index fd37d2a0..06d5ca6e 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"અન્ય"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"આમના તરફથી વૉઇસમેઇલ "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"શું હાલના સંપર્કો સિંક કરીએ?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%2$s (%3$s)માં તેનું બૅકઅપ લેવામાં આવ્યું હોય, તેની ખાતરી કરવા માટે તમે %1$sને સિંક કરી શકો છો"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{હાલનો # સંપર્ક}one{હાલનો # સંપર્ક}other{હાલના # સંપર્ક}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%2$s (%3$s)માં બૅકઅપ લેવા માટે તમે %1$sને સિંક કરી શકો છો"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{તેની ખાતરી કરવા માટે અસ્તિત્વ ધરાવતો # સંપર્ક}one{તેની ખાતરી કરવા માટે અસ્તિત્વ ધરાવતો # સંપર્ક}other{તેમની ખાતરી કરવા માટે અસ્તિત્વ ધરાવતા # સંપર્ક}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"સિંક કરો"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"સિંક કરશો નહીં"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"સંપર્કો ડેટાબેસ કૉપિ કરો"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 11a2cc53..5d0600f8 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"अन्य"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"इनका ध्‍वनि‍मेल: "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"क्या आपको मौजूदा संपर्कों को सिंक करना है?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s को सिंक करके, यह पक्का किया जा सकता है कि उनका बैक अप %2$s (%3$s) में सेव किया गया है"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# मौजूदा संपर्क}one{# मौजूदा संपर्क}other{# मौजूदा संपर्क}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%1$s को सिंक करके, यह पक्का किया जा सकता है कि उनका बैक अप %2$s (%3$s) में सेव किया गया है"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# मौजूदा संपर्क}one{# मौजूदा संपर्क}other{# मौजूदा संपर्कों}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"सिंक करें"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"सिंक न करें"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"संपर्क डेटाबेस की कॉपी बनाएं"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 9d70e24a..30d8014a 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Drugo"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Govorna pošta od "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Želite li sinkronizirati postojeće kontakte?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Možete sinkronizirati %1$s kako biste bili sigurni da su ti podaci sigurnosno kopirani na %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# postojeći kontakt}one{# postojeći kontakt}few{# postojeća kontakta}other{# postojećih kontakata}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Možete sinkronizirati %1$s sigurnosno kopiranje na %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# postojeći kontakt kako bi se osiguralo}one{# postojeći kontakt kako bi se osiguralo}few{# postojeća kontakta kako bi se osiguralo}other{# postojećih kontakata kako bi se osiguralo}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinkroniziraj"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nemoj sinkronizirati"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiranje podatkovne baze kontakata"</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 0dd6e242..a5eb6f51 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Egyéb"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Hangüzenet tőle: "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Szinkronizálja a meglévő névjegyeket?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Szinkronizálhat %1$s, hogy biztonsági mentést készítsen róluk ide: %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# meglévő névjegyet}other{# meglévő névjegyet}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Szinkronizálhat %1$s biztonsági mentés készüljön ide: %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# meglévő névjegyet, így biztosítva, hogy arról}other{# meglévő névjegyet, így biztosítva, hogy azokról}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Szinkronizálás"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Szinkronizálás mellőzése"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Névjegyadatbázis másolása"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index f63fda13..1d0e5f44 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Այլ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Ձայնային փոստ "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Համաժամացնե՞լ առկա կոնտակտները"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Դուք կարող եք համաժամացնել %1$s՝ համոզված լինելու, որ դրանք պահուստավորված են %2$s (%3$s) հաշվում"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# առկա կոնտակտ}one{# առկա կոնտակտ}other{# առկա կոնտակտ}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Դուք կարող եք համաժամացնել %1$s՝ համոզված լինելու որ դրանք պահուստավորված են %2$s (%3$s) հաշվում"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# առկա կոնտակտ}one{# առկա կոնտակտ}other{# առկա կոնտակտ}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Համաժամացնել"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Չհամաժամացնել"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Պատճենել կոնտակտային տվյալների շտեմարաը"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 7f34a223..2e2b6a96 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Lainnya"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Kotak pesan dari "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sinkronkan kontak yang ada?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Anda dapat menyinkronkan %1$s untuk memastikan data tersebut dicadangkan ke %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# kontak yang ada}other{# kontak yang ada}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Anda dapat menyinkronkan %1$s yang dicadangkan ke %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# kontak yang ada untuk memastikan kontak tersebut}other{# kontak yang ada untuk memastikan kontak tersebut}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinkronkan"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Jangan sinkronkan"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Salin basis data kontak"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 86c64291..dae0dddb 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Annað"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Talhólfsskilaboð frá "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Samstilla núverandi tengiliði?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Þú getur samstillt %1$s til að tryggja að þeir séu afritaðir í %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# núverandi tengiliður}one{# núverandi tengiliður}other{# núverandi tengiliðir}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Þú getur samstillt %1$s afritað í %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# núverandi tengiliður til að tryggja að hann sé}one{# núverandi tengiliður til að tryggja að hann sé}other{# núverandi tengiliðir til að tryggja að þeir séu}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Samstilla"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ekki samstilla"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Afrita tengiliðagagnagrunn"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index a8eff94a..3da3f091 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Altro"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Messaggio vocale da "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sincronizzare i contatti esistenti?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Puoi sincronizzare %1$s per assicurarti che il backup sia stato eseguito su %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contatto esistente}other{# contatti esistenti}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Puoi sincronizzare %1$s ne venga eseguito il backup su %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# contatto esistente per assicurarti che}other{# contatti esistenti per assicurarti che}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizza"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Non sincronizzare"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copia database di contatti"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index d1f5f29c..96ff9a23 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -21,13 +21,13 @@
     <string name="provider_label" msgid="6012150850819899907">"אנשי קשר"</string>
     <string name="upgrade_out_of_memory_notification_ticker" msgid="7638747231223520477">"שדרוג אנשי הקשר מחייב זיכרון נוסף."</string>
     <string name="upgrade_out_of_memory_notification_title" msgid="8888171924684998531">"משדרג את האחסון של אנשי קשר"</string>
-    <string name="upgrade_out_of_memory_notification_text" msgid="2581831842693151968">"הקש כדי להשלים את השדרוג."</string>
+    <string name="upgrade_out_of_memory_notification_text" msgid="2581831842693151968">"יש ללחוץ כדי להשלים את השדרוג."</string>
     <string name="default_directory" msgid="93961630309570294">"אנשי קשר"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"אחר"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"הודעה קולית מאת "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"רוצה לסנכרן את אנשי הקשר הקיימים?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"‏רוצה לסנכרן %1$s כדי לוודא שיש לך גיבוי בחשבון %2$s ‏(%3$s)?"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{איש קשר אחד}one{‫# אנשי קשר}two{‫# אנשי קשר}other{‫# אנשי קשר}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"‏רוצה לסנכרן %1$s שכל אנשי הקשר שלך מסונכרנים בחשבון %2$s‏ (%3$s)?"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{איש קשר אחד כדי לוודא}one{‫# אנשי קשר כדי לוודא}two{‫# אנשי קשר כדי לוודא}other{‫# אנשי קשר כדי לוודא}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"סנכרון"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"אני לא רוצה לסנכרן"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"העתקת מסד נתוני אנשי קשר"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index e4ca3f2d..56017a98 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"その他"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"受信ボイスメール: "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"既存の連絡先を同期しますか？"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$sを同期して、%2$s（%3$s）にバックアップできます"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# 件の既存の連絡先}other{# 件の既存の連絡先}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%1$sを同期して、%2$s（%3$s）にバックアップできます"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# 件の既存の連絡先}other{# 件の既存の連絡先}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"同期"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"同期しない"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"連絡先データベースをコピー"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index 3c6dff40..9f1e2fb1 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"სხვა"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ხმოვანი ფოსტა "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"გსურთ არსებული კონტაქტების სინქრონიზაცია?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"თქვენ შეგიძლიათ, დაასინქრონოთ %1$s, რათა დარწმუნდეთ, რომ მათი სარეზერვო ასლები შექმნილია %2$s-ში (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# არსებული კონტაქტი}other{# არსებული კონტაქტი}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"თქვენ შეგიძლიათ, დაასინქრონოთ %1$s სარეზერვოდ კოპირებულია %2$s-ში (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# არსებული კონტაქტი, რათა დარწმუნდეთ, რომ ის}other{# არსებული კონტაქტი, რათა დარწმუნდეთ, რომ ისინი}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"სინქრონიზაცია"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"არ დასინქრონდეს"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"კონტაქტების მონაცემთა ბაზის კოპირება"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 3cdc2e58..0d6998b7 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Басқа"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Келесі нөмірден келген дауыс-хабар "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Бұрыннан бар контактілерді синхрондау керек пе?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Контактіні (%1$s) синхрондай аласыз, осылайша оның сақтық көшірмесі %2$s (%3$s) аккаунтына жасалады."</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# бұрыннан бар контакт}other{# бұрыннан бар контакт}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%1$s синхрондай аласыз, сол кезде сақтық көшірмесі мына жерге сақталады: %2$s (%3$s)."</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{бұрыннан бар # контактіні}other{бұрыннан бар # контактіні}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синхрондау"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Синхрондамау"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Контактілер дерекқорын көшіру"</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index a2bb7653..aabd88a7 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"ផ្សេងៗ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"សារ​ជា​សំឡេង​ពី "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ធ្វើសម​កាលកម្ម​ទំនាក់ទំនង​ដែលមាន​ស្រាប់ឬ?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"អ្នកអាច​ធ្វើសម​កាលកម្ម %1$s ដើម្បី​ធានាថា​ទំនាក់ទំនង​ត្រូវបាន​បម្រុងទុកទៅ %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{ទំនាក់ទំនង​ដែលមានស្រាប់​ចំនួន #}other{ទំនាក់ទំនង​ដែលមានស្រាប់​ចំនួន #}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"អ្នកអាច​ធ្វើសម​កាលកម្ម%1$sត្រូវបាន​បម្រុងទុកទៅ %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{ទំនាក់ទំនងដែលមានស្រាប់ # ដើម្បីធានាថាទំនាក់ទំនងនេះ}other{ទំនាក់ទំនងដែលមានស្រាប់ # ដើម្បីធានាថាទំនាក់ទំនងទាំងនេះ}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ធ្វើ​សមកាលកម្ម"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"កុំធ្វើ​សមកាលកម្ម"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"ចម្លង​មូលដ្ឋាន​ទិន្នន័យ​ទំនាក់ទំនង"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 2a65684a..fabbc1a2 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"ಇತರೆ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ಇದರಿಂದ ಧ್ವನಿಮೇಲ್‌ "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕಗಳನ್ನು ಸಿಂಕ್ ಮಾಡಬೇಕೆ?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%2$s (%3$s) ಅನ್ನು ಬ್ಯಾಕಪ್ ಮಾಡಲಾಗಿದೆಯೇ ಎಂದು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಲು ನೀವು %1$s ಅನ್ನು ಸಿಂಕ್ ಮಾಡಬಹುದು"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕ}one{# ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕಗಳು}other{# ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕಗಳು}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"ನೀವು %2$s (%3$s) ಗೆ ಬ್ಯಾಕಪ್ ಮಾಡಲಾದ %1$s ಅನ್ನು ಸಿಂಕ್ ಮಾಡಬಹುದು"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{ಅದನ್ನು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಲು # ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕ}one{# ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕಗಳು ಇವೆ ಎಂದು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಲು}other{# ಅಸ್ತಿತ್ವದಲ್ಲಿರುವ ಸಂಪರ್ಕಗಳು ಇವೆ ಎಂದು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಲು}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ಸಿಂಕ್ ಮಾಡಿ"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ಸಿಂಕ್ ಮಾಡಬೇಡಿ"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"ಸಂಪರ್ಕಗಳ ಡೇಟಾಬೇಸ್‌‌ ನಕಲಿಸಿ"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index 0d0e68dc..0aa48f96 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"기타"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"음성사서함 발신자 "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"기존 연락처를 동기화할까요?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s를 동기화하여 %2$s(%3$s)에 백업할 수 있습니다."</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{기존 연락처 #개}other{기존 연락처 #개}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%1$s를 동기화하여 %2$s(%3$s)에 백업할 수 있습니다."</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{기존 연락처 #개}other{기존 연락처 #개}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"동기화"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"동기화 안함"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"주소록 데이터베이스 복사"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 3817137a..69d8ef0b 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Башка"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Келген үнкат "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Учурдагы байланыштар шайкештирилсинби?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Камдык көчүрмөсүн %2$s (%3$s) аккаунтуна сактоо үчүн %1$s шайкештире аласыз"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# учурдагы байланыш}other{# учурдагы байланыш}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%2$s (%3$s) кызматына камдык көчүрмөсүн сактоо үчүн %1$s"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# учурдагы байланышты шайкештире аласыз}other{# учурдагы байланышты шайкештире аласыз}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Шайкештирүү"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Шайкештирилбесин"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Байланыштар корун көчүрүү"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index ac1fa3d3..7770db36 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"ອື່ນໆ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ຂໍ້ຄວາມສຽງຈາກ "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ຊິ້ງລາຍຊື່ຜູ້ຕິດຕໍ່ທີ່ມີຢູ່ບໍ?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"ທ່ານສາມາດຊິ້ງ %1$s ເພື່ອໃຫ້ແນ່ໃຈວ່າມີການສຳຮອງຂໍ້ມູນດັ່ງກ່າວໄວ້ໃນ %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{ລາຍຊື່ຜູ້ຕິດຕໍ່ທີ່ມີຢູ່ # ລາຍການ}other{ລາຍຊື່ຜູ້ຕິດຕໍ່ທີ່ມີຢູ່ # ລາຍການ}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"ທ່ານສາມາດຊິ້ງ %1$s ທີ່ໄດ້ສຳຮອງຂໍ້ມູນໃສ່ %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{ລາຍຊື່ຜູ້ຕິດຕໍ່ທີ່ມີຢູ່ # ລາຍການເພື່ອຮັບປະກັນວ່າມັນ}other{ລາຍຊື່ຜູ້ຕິດຕໍ່ທີ່ມີຢູ່ # ລາຍການເພື່ອຮັບປະກັນວ່າພວກມັນ}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ຊິ້ງ"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ບໍ່ຕ້ອງຊິ້ງ"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"ສຳເນົາຖານຂໍ້ມູນລາຍຊື່ຜູ່ຕິດຕໍ່"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index 4d66d59c..dbfa0a2a 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Kita"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Balso pašto pranešimas nuo "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sinchronizuoti esamus kontaktus?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Galite sinchronizuoti %1$s, kad užtikrintumėte atsarginių kopijų kūrimą %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# esamas kontaktas}one{# esamas kontaktas}few{# esami kontaktai}many{# esamo kontakto}other{# esamų kontaktų}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Galite sinchronizuoti %1$s, kurio atsarginė kopija sukurta %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# esamas kontaktas, kad įsitikintumėte, jog jis}one{# esamas kontaktas, kad įsitikintumėte, jog jie}few{# esami kontaktai, kad įsitikintumėte, jog jie}many{# esamo kontakto, kad įsitikintumėte, jog jie}other{# esamų kontaktų, kad įsitikintumėte, jog jie}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinchronizuoti"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nesinchronizuoti"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopijuoti kontaktų duomenis"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index d09d6e8a..ffad7e8b 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Cits"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Balss pasta ziņojums no "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vai sinhronizēt esošās kontaktpersonas?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Varat sinhronizēt %1$s, lai nodrošinātu dublēšanu kontā %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# esošo kontaktpersonu}zero{# esošās kontaktpersonas}one{# esošo kontaktpersonu}other{# esošās kontaktpersonas}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Varat sinhronizēt %1$s dublēšanu kontā %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# esošo kontaktpersonu, lai nodrošinātu tās}zero{# esošās kontaktpersonas, lai nodrošinātu to}one{# esošo kontaktpersonu, lai nodrošinātu tās}other{# esošās kontaktpersonas, lai nodrošinātu to}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinhronizēt"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nesinhronizēt"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kontaktpersonu datu bāzes kopēšana"</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 9c11a910..6337b285 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Друг"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Говорна пошта од "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Да се синхронизираат постојните контакти?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s може да се синхронизира за да се направи бекап во %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# постоен контакт}one{# постоен контакт}other{# постојни контакти}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Може да синхронизирате %1$s направи бекап на %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# постоен контакт за да се погрижите да се}one{# постоен контакт за да се погрижите да се}other{# постојни контакти за да се погрижите да се}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синхронизирај"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Не синхронизирај"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Копирај база на податоци со контакти"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index ee76a8ee..ee1f57ef 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"മറ്റുള്ളവ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ഈ നമ്പറിൽ നിന്നുള്ള വോയ്‌സ്‌മെയിൽ "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"നിലവിലുള്ള കോൺടാക്റ്റുകൾ സമന്വയിപ്പിക്കണോ?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%2$s (%3$s) വരെ ബാക്കപ്പ് ചെയ്തിട്ടുണ്ടെന്ന് ഉറപ്പാക്കാൻ നിങ്ങൾക്ക് %1$s സമന്വയിപ്പിക്കാനാകും"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{നിലവിലുള്ള # കോൺടാക്റ്റ്}other{നിലവിലുള്ള # കോൺടാക്റ്റുകൾ}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"ബാക്കപ്പ് ചെയ്ത %1$s അക്കൗണ്ടുകൾ %2$s (%3$s) എന്നതിലേക്ക് നിങ്ങൾക്ക് സമന്വയിപ്പിക്കാനാകും."</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{ഇനിപ്പറയുന്ന തരത്തിലുള്ളതാണെന്ന് ഉറപ്പാക്കാൻ # കോൺടാക്റ്റ് ഉണ്ട്:}other{ഇനിപ്പറയുന്ന തരത്തിലുള്ളവയാണെന്ന് ഉറപ്പാക്കാൻ # കോൺടാക്റ്റുകളുണ്ട്:}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"സമന്വയിപ്പിക്കുക"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"സമന്വയിപ്പിക്കരുത്"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"കോൺടാക്റ്റുകളുടെ ഡാറ്റാബേസ് പകർത്തുക"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 92db3b2a..6f362664 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Бусад"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Дуут шуудан илгээгч "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Одоо байгаа харилцагчдыг синк хийх үү?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Та тэдгээр харилцагчийг %2$s-д (%3$s) нөөцөлсөн эсэхийг нягтлахын тулд %1$s-г синк хийх боломжтой"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{Одоо байгаа # харилцагч}other{Одоо байгаа # харилцагч}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Та %1$s-г %2$s (%3$s) хүртэл нөөцөлсөн болохыг баталгаажуулахын тулд синк хийх боломжтой"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{одоо байгаа # харилцагчийг}other{одоо байгаа # харилцагчийг}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синк хийх"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Бүү синк хий"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Харилцагчдын мэдээллийн санг хуулах"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 99a1ca37..b3eacc1d 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"इतर"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"कडून व्हॉईसमेल "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"सध्याचे संपर्क सिंक करायचे आहेत का?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"त्यांचा %2$s (%3$s) वर बॅकअप घेतला आहे याची खात्री करण्यासाठी तुम्ही %1$s सिंक करू शकता"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{सध्याचा # संपर्क}other{सध्याचे # संपर्क}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%2$s (%3$s) वर बॅकअप घेतलेला ठेवण्यासाठी तुम्ही %1$s सिंक करू शकता"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{याची खात्री करण्यासाठी # सद्य संपर्क}other{याची खात्री करण्यासाठी # सद्य संपर्क}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"सिंक करा"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"सिंक करू नका"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"संपर्क डेटाबेस कॉपी करा"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 2ac07a06..2495bdb4 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Lain-lain"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Mel suara daripada "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Segerakkan kenalan sedia ada?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Anda boleh menyegerakkan %1$s untuk memastikan %1$s disandarkan kepada %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# kenalan sedia ada}other{# kenalan sedia ada}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Anda boleh menyegerakkan %1$s untuk disandarkan kepada %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# kenalan sedia ada untuk memastikan}other{# kenalan sedia ada untuk memastikan mereka}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Segerakkan"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Jangan segerakkan"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Salin pangkalan data kenalan"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 0acec776..4ccd278a 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"တစ်ခြား"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"မှ အသံစာ "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"လက်ရှိ အဆက်အသွယ်များကို စင့်ခ်လုပ်မလား။"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%2$s (%3$s) သို့ အရန်သိမ်းထားကြောင်း သေချာစေရန် %1$s ကို စင့်ခ်လုပ်နိုင်ပါသည်"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{လက်ရှိ အဆက်အသွယ် # ခု}other{လက်ရှိ အဆက်အသွယ် # ခု}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%2$s (%3$s) တွင် အရန်သိမ်းထားကြောင်း %1$s ကို စင့်ခ်လုပ်နိုင်သည်"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{သေချာစေရန် လက်ရှိအဆက်အသွယ် # ခု}other{သေချာစေရန် လက်ရှိအဆက်အသွယ် # ခု}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"စင့်ခ်လုပ်ရန်"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"စင့်ခ်မလုပ်ပါနှင့်"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"လိပ်စာဒေတာဘေ့စ်ကို ကူးရန်"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index 85643ac4..143e4d56 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Annet"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Talemelding fra "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vil du synkronisere eksisterende kontakter?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Du kan synkronisere %1$s for å sikre at de blir sikkerhetskopiert til %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# eksisterende kontakt}other{# eksisterende kontakter}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Du kan synkronisere %1$s sikkerhetskopieres til %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# eksisterende kontakt for å sikre at den}other{# eksisterende kontakter for å sikre at de}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synkroniser"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ikke synkroniser"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiér kontaktdatabasen"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 26b4a922..04d744ff 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"अन्य"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"बाट भ्वाइसमेल "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"विद्यमान कन्ट्याक्टहरू सिंक गर्ने हो?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s लाई %2$s (%3$s) मा ब्याकअप गर्न तपाईं तिनलाई सिंक गर्न सक्नुहुन्छ"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# विद्यमान कन्ट्याक्ट}other{# वटा विद्यमान कन्ट्याक्ट}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%1$s %2$s (%3$s) मा ब्याकअप गर्न तपाईं तिनलाई सिंक गर्न सक्नुहुन्छ"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# विद्यमान कन्ट्याक्ट}other{# वटा विद्यमान कन्ट्याक्ट}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"सिंक गर्नुहोस्"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"सिंक नगर्नुहोस्"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"सम्पर्क डेटाबेस प्रतिलिप गर्नुहोस्"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index 7edee0b2..203f9c2f 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Overig"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Voicemail van "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Bestaande contacten synchroniseren?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"U kunt %1$s synchroniseren om ervoor te zorgen dat er een back-up van wordt gemaakt in %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# bestaand contact}other{# bestaande contacten}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Je kunt %1$s synchroniseren waarvan een back-up is gemaakt in %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# bestaand contact dat ervoor zorgt dat}other{# bestaande contacten die ervoor zorgen dat}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchroniseren"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Niet synchroniseren"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Contactendatabase kopiëren"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 6408b2c5..131a10e7 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"ଅନ୍ଯ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ଏହାଙ୍କଠାରୁ ଭଏସମେଲ୍‌ "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ପୂର୍ବରୁ ଥିବା କଣ୍ଟାକ୍ଟଗୁଡ଼ିକୁ ସିଙ୍କ କରିବେ?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%2$s (%3$s)ରେ %1$sର ବେକଅପ ନିଆଯାଇଥିବା ସୁନିଶ୍ଚିତ କରିବାକୁ ଆପଣ ସେଗୁଡ଼ିକୁ ସିଙ୍କ କରିପାରିବେ"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{ପୂର୍ବରୁ ଥିବା # କଣ୍ଟାକ୍ଟ}other{ପୂର୍ବରୁ ଥିବା # କଣ୍ଟାକ୍ଟ}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"ଆପଣ %2$s (%3$s)ରେ ବେକ ଅପ ନେବା ପାଇଁ %1$sକୁ ସିଙ୍କ କରିପାରିବେ"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{ପୂର୍ବରୁ ଥିବା # କଣ୍ଟାକ୍ଟକୁ ନିଶ୍ଚିତ କରିବାକୁ ହେବ ଯେ ଏହା}other{ପୂର୍ବରୁ ଥିବା # କଣ୍ଟାକ୍ଟକୁ ନିଶ୍ଚିତ କରିବାକୁ ହେବ ଯେ ଏଗୁଡ଼ିକ}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ସିଙ୍କ କରନ୍ତୁ"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ସିଙ୍କ କରନ୍ତୁ ନାହିଁ"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"କଣ୍ଟାକ୍ଟ ଡାଟାବେସକୁ କପି କରନ୍ତୁ"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 08df27c2..ff6eebf7 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"ਹੋਰ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ਇਸ ਤੋਂ ਵੌਇਸਮੇਲ "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ਕੀ ਮੌਜੂਦਾ ਸੰਪਰਕਾਂ ਨੂੰ ਸਿੰਕ ਕਰਨਾ ਹੈ?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"ਤੁਸੀਂ ਇਹ ਪੱਕਾ ਕਰਨ ਲਈ %1$s ਨੂੰ ਸਿੰਕ ਕਰ ਸਕਦੇ ਹੋ ਕਿ ਉਨ੍ਹਾਂ ਦਾ %2$s (%3$s) ਵਿੱਚ ਬੈਕਅੱਪ ਲਿਆ ਗਿਆ ਹੈ"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# ਮੌਜੂਦਾ ਸੰਪਰਕ}one{# ਮੌਜੂਦਾ ਸੰਪਰਕ}other{# ਮੌਜੂਦਾ ਸੰਪਰਕ}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"ਤੁਸੀਂ %1$s ਸਿੰਕ ਕਰ ਸਕਦੇ ਹੋ ਕਿ ਉਨ੍ਹਾਂ ਦਾ ਬੈਕਅੱਪ %2$s (%3$s) ਵਿੱਚ ਲਿਆ ਗਿਆ ਹੈ"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{ਇਹ ਪੱਕਾ ਕਰਨ ਲਈ # ਮੌਜੂਦਾ ਸੰਪਰਕ}one{ਇਹ ਪੱਕਾ ਕਰਨ ਲਈ # ਮੌਜੂਦਾ ਸੰਪਰਕ}other{ਇਹ ਪੱਕਾ ਕਰਨ ਲਈ # ਮੌਜੂਦਾ ਸੰਪਰਕ}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ਸਿੰਕ ਕਰੋ"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ਸਿੰਕ ਨਾ ਕਰੋ"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"ਸੰਪਰਕ ਡਾਟਾਬੇਸ ਕਾਪੀ ਕਰੋ"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 8942ec4f..7fde363d 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Inne"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Poczta głosowa od "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Zsynchronizować istniejące kontakty?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Możesz zsynchronizować te dane (%1$s), aby mieć pewność, że ich kopia zapasowa jest przechowywana w usługach %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# zapisany kontakt}few{# zapisane kontakty}many{# zapisanych kontaktów}other{# zapisanego kontaktu}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Możesz zsynchronizować %1$s kopia zapasowa jest przechowywana w usługach %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# kontakt, aby mieć pewność, że jego}few{# kontakty, aby mieć pewność, że ich}many{# kontaktów, aby mieć pewność, że ich}other{# kontaktu, aby mieć pewność, że ich}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchronizuj"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nie synchronizuj"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiuj bazę danych kontaktów"</string>
diff --git a/res/values-pt-rBR/strings.xml b/res/values-pt-rBR/strings.xml
index 49fd5616..e2d2232c 100644
--- a/res/values-pt-rBR/strings.xml
+++ b/res/values-pt-rBR/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Outros"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Correio de voz de "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sincronizar contatos atuais?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Sincronize %1$s para garantir que eles sejam armazenados em backup na conta %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contato atual}one{# contato atual}other{# contatos atuais}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Você pode sincronizar %1$s o armazenamento em backup na conta %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# contato atual para garantir}one{# contato atual para garantir}other{# contatos atuais para garantir}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizar"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Não sincronizar"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiar banco de dados de contatos"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 08098f4b..9e88c4ea 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Outro"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Correio de voz de "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sincronizar contactos existentes?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Pode sincronizar %1$s para garantir que é feita uma cópia de segurança em %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contacto existente}other{# contactos existentes}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Pode sincronizar %1$s existe uma cópia de segurança em %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# contacto existente para garantir que}other{# contactos existentes para garantir que}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizar"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Não sincronizar"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiar base de dados de contactos"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index 49fd5616..e2d2232c 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Outros"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Correio de voz de "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sincronizar contatos atuais?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Sincronize %1$s para garantir que eles sejam armazenados em backup na conta %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# contato atual}one{# contato atual}other{# contatos atuais}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Você pode sincronizar %1$s o armazenamento em backup na conta %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# contato atual para garantir}one{# contato atual para garantir}other{# contatos atuais para garantir}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizar"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Não sincronizar"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiar banco de dados de contatos"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 9866ee5e..61006d06 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Altul"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Mesaj vocal de la "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Sincronizați persoanele de contact existente?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Puteți sincroniza %1$s pentru a vă asigura că au backup în %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{O persoană de contact existentă}few{# persoane de contact existente}other{# de persoane de contact existente}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Puteți sincroniza %1$s backup în %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{o persoană de contact existentă pentru a vă asigura că are}few{# persoane de contact existente pentru a vă asigura că au}other{# de persoane de contact existente pentru a vă asigura că au}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sincronizați"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nu sincronizați"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Copiați baza de date a agendei"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index fe82d8e0..fd2319a9 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Другое"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Голосовое сообщение от абонента "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Синхронизировать существующие контакты?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Вы можете синхронизировать контакты (не более %1$s), чтобы создать их резервные копии в %2$s (%3$s)."</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# существующий контакт}one{# существующий контакт}few{# существующих контакта}many{# существующих контактов}other{# существующего контакта}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Вы можете синхронизировать %1$s в %2$s (%3$s)."</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# существующий контакт, чтобы создать его резервную копию}one{# существующий контакт, чтобы создать их резервные копии}few{# существующих контакта, чтобы создать их резервные копии}many{# существующих контактов, чтобы создать их резервные копии}other{# существующего контакта, чтобы создать их резервные копии}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синхронизировать"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Не синхронизировать"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Копирование базы данных контактов"</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index d431a691..894e5417 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"වෙනත්"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"හඬ තැපෑල ලැබෙන්නේ "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"පවතින සම්බන්ධතා සමමුහුර්ත කරන්න ද?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"ඔබට ඒවා %2$s (%3$s) දක්වා උපස්ථ කර ඇති බව සහතික කිරීමට %1$s සමමුහුර්ත කළ හැක"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# පවතින සම්බන්ධතාවක්}one{පවතින සම්බන්ධතා #ක්}other{පවතින සම්බන්ධතා #ක්}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"ඔබට %2$s (%3$s) දක්වා උපස්ථ කර ඇති %1$s සමමුහුර්ත කළ හැක"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{එය සහතික කිරීමට # පවතින සම්බන්ධතාවක්}one{ඒවා සහතික කිරීමට පවතින සම්බන්ධතා #ක්}other{ඒවා සහතික කිරීමට පවතින සම්බන්ධතා #ක්}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"සමමුහුර්ත කරන්න"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"සමමුහූර්ත නොකරන්න"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"සම්බන්ධතා දත්ත සමුදාය පිටපත් කරන්න"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 6cebef99..bd655937 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Iné"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Hlasová správa od "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Chcete synchronizovať existujúce kontakty?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Môžete synchronizovať %1$s, aby sa vytvorila záloha v účte %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# existujúci kontakt}few{# existujúce kontakty}many{# existing contacts}other{# existujúcich kontaktov}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Môžete synchronizovať %1$s záloha v účte %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# existujúci kontakt, aby sa vytvorila jeho}few{# existujúce kontakty, aby sa vytvorila ich}many{# existing contacts to ensure they\'re}other{# existujúcich kontaktov, aby sa vytvorila ich}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synchronizovať"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Nesynchronizovať"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopírovanie databázy kontaktov"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index e78b0148..c991a3f6 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Drugo"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Govorna pošta s številke "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Želite sinhronizirati obstoječe stike?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Sinhronizirate lahko %1$s, da zagotovite, da so varnostno kopirani v: %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# obstoječi stik}one{# obstoječi stik}two{# obstoječa stika}few{# obstoječi stiki}other{# obstoječih stikov}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Sinhronizirate lahko %1$s v: %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# obstoječi stik, da poskrbite, da se varnostno kopira}one{# obstoječi stik, da poskrbite, da se varnostno kopira}two{# obstoječa stika, da poskrbite, da se varnostno kopirata}few{# obstoječe stike, da poskrbite, da se varnostno kopirajo}other{# obstoječih stikov, da poskrbite, da se varnostno kopirajo}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinhroniziraj"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ne sinhroniziraj"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiraj zbirko podatkov o stikih"</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 8800780c..d572ac1b 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Tjetër"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Postë zanore nga "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Të sinkronizohen kontaktet ekzistuese?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Mund të sinkronizosh %1$s për t\'u siguruar që është rezervuar në %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# kontakt ekzistues}other{# kontakte ekzistuese}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Mund të sinkronizosh %1$s rezervuar në %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# kontakt ekzistues për të siguruar që është}other{# kontakte ekzistuese për të siguruar që janë}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinkronizo"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Mos sinkronizo"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopjo bazën e të dhënave me kontaktet"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 2317cdfa..790d2df0 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Другo"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Говорна пошта од "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Желите да синхронизујете постојеће контакте?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Можете да синхронизујете %1$s да бисте се уверили да се резервне копије праве на %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# постојећи контакт}one{# постојећи контакти}few{# постојећа контакта}other{# постојећих контаката}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Можете да синхронизујете %1$s се резервне копије праве на %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# постојећи контакт да бисте се уверили да}one{# постојећи контакт да бисте се уверили да}few{# постојећа контакта да бисте се уверили да}other{# постојећих контаката да бисте се уверили да}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синхронизуј"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Немој да синхронизујеш"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Копирање базе података са контактима"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 4589f3fb..f908656a 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Övrigt"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Röstmeddelande från "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vill du synkronisera befintliga kontakter?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Du kan synkronisera %1$s för att säkerställa säkerhetskopiering till %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# befintlig kontakt}other{# befintliga kontakter}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Du kan synkronisera %1$s som har säkerhetskopierats till %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# befintlig kontakt för att säkerställa att den är}other{# befintliga kontakter för att säkerställa att de är}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Synkronisera"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Synkronisera inte"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopiera kontaktdatabas"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 6c9db339..b3915658 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Nyingineyo"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Barua ya sauti kutoka "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Ungependa kusawazisha anwani zilizopo?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Unaweza kusawazisha %1$s ili uhakikishe kuwa nakala zimehifadhiwa kwenye %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{Anwani # iliyopo}other{Anwani # zilizopo}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Unaweza kusawazisha %1$s umehifadhi nakala kwenye %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{anwani # iliyopo ili uhakikishe kuwa}other{anwani # zilizopo ili uhakikishe kuwa}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sawazisha"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Usisawazishe"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Nakili hifadhidata ya anwani"</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 067d22f5..114775dc 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"மற்றவை"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"இவரிடமிருந்து குரலஞ்சல் "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ஏற்கெனவே உள்ள தொடர்புகளை ஒத்திசைக்க வேண்டுமா?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%2$s (%3$s) இல் காப்புப் பிரதி எடுக்கப்பட்டிருப்பதை உறுதிசெய்ய %1$s ஐ ஒத்திசைக்கலாம்"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{ஏற்கெனவே உள்ள தொடர்பு: #}other{ஏற்கெனவே உள்ள தொடர்புகள்: #}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%2$s (%3$s)க்குக் காப்புப் பிரதி எடுக்கப்படுவதை உறுதிசெய்ய %1$s ஒத்திசைக்கலாம்"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{ஏற்கெனவே இருக்கும் # தொடர்பை}other{ஏற்கெனவே இருக்கும் # தொடர்புகளை}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ஒத்திசை"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ஒத்திசைக்காதே"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"தொடர்புகளின் தரவுத்தளத்தை நகலெடு"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index ef4ca175..74385be3 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"ఇతరం"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"దీని నుండి వాయిస్ మెయిల్ "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ఇప్పటికే ఉన్న కాంటాక్ట్‌లను సింక్ చేయాలా?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"మీరు %1$s‌ను సింక్ చేసి, అవి %2$s (%3$s)లో బ్యాకప్ అయ్యేలా చూసుకోవచ్చు"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{ఇప్పటికే ఉన్న # కాంటాక్ట్}other{ఇప్పటికే ఉన్న # కాంటాక్ట్‌లు}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"మీరు %2$s (%3$s)కు బ్యాకప్ అయిన %1$s‌ను సింక్ చేయవచ్చు"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{ఇప్పటికే ఉన్న # కాంటాక్ట్‌ను, నిర్ధారించుకోవడానికి అది}other{ఇప్పటికే ఉన్న # కాంటాక్ట్‌లను, నిర్ధారించుకోవడానికి అవి}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"సింక్ చేయండి"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"సింక్ చేయవద్దు"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"కాంటాక్ట్‌ల డేటాబేస్‌ను కాపీ చేయండి"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 662dfb34..b869c8e5 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"อื่นๆ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ข้อความเสียงจาก "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"ซิงค์รายชื่อติดต่อที่มีอยู่ไหม"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"คุณสามารถซิงค์ %1$s เพื่อให้แน่ใจว่าข้อมูลได้รับการสำรองข้อมูลไปยัง %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{รายชื่อติดต่อที่มีอยู่ # รายการ}other{รายชื่อติดต่อที่มีอยู่ # รายการ}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"คุณสามารถซิงค์ %1$s จะได้รับการสำรองข้อมูลไปยัง %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{รายชื่อติดต่อที่มีอยู่ # รายการเพื่อให้แน่ใจว่ารายการดังกล่าว}other{รายชื่อติดต่อที่มีอยู่ # รายการเพื่อให้แน่ใจว่ารายการดังกล่าว}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"ซิงค์"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"ไม่ต้องซิงค์"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"คัดลอกฐานข้อมูลผู้ติดต่อ"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 880f585c..84206ee4 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Iba pa"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Voicemail mula sa/kay "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"I-sync ang mga kasalukuyang contact?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Puwede mong i-sync si %1$s para matiyak na naba-back up siya sa %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# kasalukuyang contact}one{# kasalukuyang contact}other{# na kasalukuyang contact}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Puwede kang mag-sync ng %1$s sa %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# dati nang contact para masiguradong naka-back up siya}one{# dati nang contact para masiguradong naka-back up sila}other{# na dati nang contact para masiguradong naka-back up sila}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"I-sync"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Huwag i-sync"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopyahin ang database ng mga contact"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 7058b4b3..e27682e2 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Diğer"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Sesli mesaj gönderen: "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Mevcut kişiler senkronize edilsin mi?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s adlı kişiyi senkronize ederek %2$s (%3$s) ile yedekleyebilirsiniz."</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# mevcut kişi}other{# mevcut kişi}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%2$s (%3$s) adlı hesaba yedeklemek için %1$s senkronize edebilirsiniz."</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{mevcut # kişiyi}other{mevcut # kişiyi}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Senkronize et"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Senkronize etme"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kişiler veritabanını kopyala"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index f1ad562a..66820be5 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -17,7 +17,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="sharedUserLabel" msgid="8024311725474286801">"Android Core Apps"</string>
-    <string name="app_label" msgid="3389954322874982620">"Пам\'ять контактів"</string>
+    <string name="app_label" msgid="3389954322874982620">"Сховище контактів"</string>
     <string name="provider_label" msgid="6012150850819899907">"Контакти"</string>
     <string name="upgrade_out_of_memory_notification_ticker" msgid="7638747231223520477">"Оновлення контактів потребує більше пам’яті."</string>
     <string name="upgrade_out_of_memory_notification_title" msgid="8888171924684998531">"Оновлення пам’яті для контактів"</string>
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Інші"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Голосова пошта від "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Синхронізувати наявні контакти?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Ви можете синхронізувати %1$s для автоматичного резервного копіювання в %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# наявний контакт}one{# наявний контакт}few{# наявні контакти}many{# наявних контактів}other{наявні контакти (#)}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Ви можете синхронізувати %1$s резервне копіювання в %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# наявний контакт, щоб забезпечити його}one{# наявний контакт, щоб забезпечити їх}few{# наявні контакти, щоб забезпечити їх}many{# наявних контактів, щоб забезпечити їх}other{# наявного контакта, щоб забезпечити їх}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Синхронізувати"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Не синхронізувати"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Копіювати базу даних контактів"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 8cb0e36a..05adb5dc 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"دیگر"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"صوتی میل منجانب "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"موجودہ رابطوں کو مطابقت پذیر بنائیں؟"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"‏آپ %1$s کو مطابقت پذیر بنا سکتے تاکہ یہ یقینی بنایا جا سکے کہ ‎%2$s (%3$s) میں بیک ان کا بیک لیا جائے"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{موجودہ # رابطہ}other{موجودہ # رابطے}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"‏آپ ‎%2$s (%3$s) میں بیک اپ لیے گئے ‎%1$s کو مطابقت پذیر بنا سکتے ہیں"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{یہ یقینی بنانے کے لیے # موجودہ رابطہ}other{یہ یقینی بنانے کے لیے # موجودہ رابطے}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"مطابقت پذیر بنائیں"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"مطابقت پذیر نہ بنائیں"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"رابطوں کا ڈیٹابیس کاپی کریں"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index 2746184c..05a5d4b9 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Boshqa"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Ovozli xabar egasi: "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Mavjud kontaktlar sinxronlansinmi?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"%1$s %2$s (%3$s) hisobiga zaxiralanganiga ishonch hosil qilish uchun ularni sinxronlashingiz mumkin"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# ta mavjud kontakt}other{# ta mavjud kontakt}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"%2$s (%3$s) hisobiga %1$s uchun ularni sinxronlashingiz mumkin"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# ta mavjud kontakt zaxiralanganiga ishonch hosil qilish}other{# ta mavjud kontakt zaxiralanganiga ishonch hosil qilish}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Sinxronlash"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Sinxronlanmasin"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kontaktlar ma’lumotlar bazasidan nusxa ko‘chirish"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 42fc9ba1..7ab62039 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Khác"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Thư thoại từ "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Đồng bộ hoá danh bạ hiện có?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Bạn có thể đồng bộ hoá %1$s để đảm bảo những thông tin này được sao lưu vào %2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# người liên hệ hiện có}other{# người liên hệ hiện có}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Bạn có thể đồng bộ hoá %1$s đã sao lưu vào %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# người liên hệ hiện có để đảm bảo người này}other{# người liên hệ hiện có để đảm bảo họ}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Đồng bộ hoá"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Không đồng bộ hoá"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Sao chép cơ sở dữ liệu người liên hệ"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 8c7438c8..c53d899d 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"其他"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"语音信息发送人 "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"要同步现有联系人吗？"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"您可以同步处理 %1$s，以确保系统将其备份到%2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# 位现有联系人}other{# 位现有联系人}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"您可以同步已备份到%2$s (%3$s) 的%1$s"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# 位现有联系人，确保其}other{# 位现有联系人，确保其}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"同步"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"不同步"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"复制通讯录数据库"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 16245667..0a3f4f31 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"其他"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"留言來自 "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"要同步處理現有聯絡人嗎？"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"你可同步處理 %1$s，確保系統將這些資料備份至%2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# 個現有聯絡人}other{# 個現有聯絡人}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"你可同步處理 %1$s 系統將這些資訊備份至 %2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# 個現有聯絡人以確保}other{# 個現有聯絡人以確保}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"同步處理"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"不要同步處理"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"複製通訊錄資料庫"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 0acfef37..13b25bed 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"其他"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"語音郵件寄件者： "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"要同步處理現有聯絡人嗎？"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"你可以同步處理 %1$s，確保系統將這些資料備份到%2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{# 位現有聯絡人}other{# 位現有聯絡人}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"你可以同步處理 %1$s，備份到%2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{# 位現有聯絡人，確保系統將這些資料}other{# 位現有聯絡人，確保系統將這些資料}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"同步處理"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"不要同步處理"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"複製聯絡人資料庫"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index c27c13da..6be9acf6 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -26,8 +26,8 @@
     <string name="local_invisible_directory" msgid="705244318477396120">"Okunye"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"Imeyili yezwi kusuka "</string>
     <string name="move_contacts_to_default_account_dialog_title" msgid="1691634911830971868">"Vumelanisa oxhumana nabo abakhona?"</string>
-    <string name="move_contacts_to_default_account_dialog_message" msgid="2005758519299826267">"Ungakwazi ukuvumelanisa okuthi %1$s ukuze uqinisekise ukuthi kwenzelwe isipele ku-%2$s (%3$s)"</string>
-    <string name="movable_contacts_count" msgid="7367420913436438253">"{contacts_count,plural, =1{Oxhumana naye okhona ongu-#}one{Oxhumana nabo abakhona abangu-#}other{Oxhumana nabo abakhona abangu-#}}"</string>
+    <string name="move_contacts_to_default_account_dialog_message" msgid="8979541503037221359">"Ungavumelanisa u-%1$s owenzelwe isipele ku-%2$s (%3$s)"</string>
+    <string name="movable_contacts_count" msgid="5238731486523789939">"{contacts_count,plural, =1{Oxhumana naye ongu-# okhona ukuze kuqinisekiswe ukuthi}one{Oxhumana nabo abangu-# abakhona ukuze kuqinisekiswe ukuthi}other{Oxhumana nabo abangu-# abakhona ukuze kuqinisekiswe ukuthi}}"</string>
     <string name="move_contacts_to_default_account_dialog_sync_button_text" msgid="6214724007562800237">"Vumelanisa"</string>
     <string name="move_contacts_to_default_account_dialog_cancel_button_text" msgid="1022518096709643659">"Ungavumelanisi"</string>
     <string name="debug_dump_title" msgid="4916885724165570279">"Kopisha imininingo egciniwe yoxhumana nabo"</string>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 726894a2..465d6401 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -50,11 +50,11 @@
     <!-- The title for move contacts to default account dialog. [CHAR LIMIT=NONE] -->
     <string name="move_contacts_to_default_account_dialog_title">Sync existing contacts?</string>
     <!-- The message text for move contacts to default account dialog. [CHAR LIMIT=NONE] -->
-    <string name="move_contacts_to_default_account_dialog_message">You can sync %1$s to ensure they\'re backed up to %2$s (%3$s)</string>
+    <string name="move_contacts_to_default_account_dialog_message">You can sync %1$s backed up to %2$s (%3$s)</string>
     <!-- The message text for total movable contacts count. [CHAR LIMIT=NONE] -->
     <string name="movable_contacts_count"> {contacts_count, plural,
-        =1    {# existing contact}
-        other {# existing contacts}
+        =1    {# existing contact to ensure it\'s}
+        other {# existing contacts to ensure they\'re}
         }
     </string>
     <!-- The text for move contacts to default account dialog confirm button. [CHAR LIMIT=NONE] -->
diff --git a/src/com/android/providers/contacts/AccountResolver.java b/src/com/android/providers/contacts/AccountResolver.java
index bb983c0f..46123478 100644
--- a/src/com/android/providers/contacts/AccountResolver.java
+++ b/src/com/android/providers/contacts/AccountResolver.java
@@ -22,10 +22,13 @@ import android.provider.ContactsContract.RawContacts;
 import android.provider.ContactsContract.RawContacts.DefaultAccount.DefaultAccountAndState;
 import android.provider.ContactsContract.SimAccount;
 import android.text.TextUtils;
+import android.util.Log;
 
 import java.util.List;
 
 public class AccountResolver {
+    public static final String UNABLE_TO_WRITE_TO_LOCAL_OR_SIM_EXCEPTION_MESSAGE =
+            "Cannot add contacts to local or SIM accounts when default account is set to cloud";
     private static final String TAG = "AccountResolver";
 
     private final ContactsDatabaseHelper mDbHelper;
@@ -63,11 +66,12 @@ public class AccountResolver {
      *                                                contacts.
      */
     public AccountWithDataSet resolveAccountWithDataSet(Uri uri, ContentValues values,
-            boolean applyDefaultAccount, boolean shouldValidateAccountForContactAddition) {
+            boolean applyDefaultAccount, boolean shouldValidateAccountForContactAddition,
+            boolean allowSimWriteOnCloudDcaBypassEnabled) {
         final Account[] accounts = resolveAccount(uri, values);
         final Account account = applyDefaultAccount
                 ? getAccountWithDefaultAccountApplied(accounts,
-                shouldValidateAccountForContactAddition)
+                shouldValidateAccountForContactAddition, allowSimWriteOnCloudDcaBypassEnabled)
                 : getFirstAccountOrNull(accounts);
 
         AccountWithDataSet accountWithDataSet = null;
@@ -94,7 +98,8 @@ public class AccountResolver {
      *                                  default account incompatible account types.
      */
     private Account getAccountWithDefaultAccountApplied(Account[] accounts,
-            boolean shouldValidateAccountForContactAddition)
+            boolean shouldValidateAccountForContactAddition,
+            boolean allowSimWriteOnCloudDcaBypassEnabled)
             throws IllegalArgumentException {
         if (accounts.length == 0) {
             DefaultAccountAndState defaultAccountAndState =
@@ -108,9 +113,9 @@ public class AccountResolver {
                 return defaultAccountAndState.getAccount();
             }
         } else {
-            if (shouldValidateAccountForContactAddition) {
-                validateAccountForContactAdditionInternal(accounts[0]);
-            }
+            validateAccountForContactAdditionInternal(accounts[0],
+                        shouldValidateAccountForContactAddition,
+                        allowSimWriteOnCloudDcaBypassEnabled);
             return accounts[0];
         }
     }
@@ -134,26 +139,46 @@ public class AccountResolver {
      *                                          (device or SIM) account.</li>
      *                                  </ul>
      */
-    public void validateAccountForContactAddition(String accountName, String accountType) {
-        if (TextUtils.isEmpty(accountName) ^ TextUtils.isEmpty(accountType)) {
-            throw new IllegalArgumentException(
-                    "Must specify both or neither of ACCOUNT_NAME and ACCOUNT_TYPE");
+    public void validateAccountForContactAddition(String accountName, String accountType,
+            boolean shouldValidateAccountForContactAddition,
+            boolean allowSimWriteOnCloudDcaBypassEnabled) {
+        if (shouldValidateAccountForContactAddition) {
+            if (TextUtils.isEmpty(accountName) ^ TextUtils.isEmpty(accountType)) {
+                throw new IllegalArgumentException(
+                        "Must specify both or neither of ACCOUNT_NAME and ACCOUNT_TYPE");
+            }
         }
+
         if (TextUtils.isEmpty(accountName)) {
-            validateAccountForContactAdditionInternal(/*account=*/null);
+            validateAccountForContactAdditionInternal(/*account=*/null,
+                    shouldValidateAccountForContactAddition,
+                    allowSimWriteOnCloudDcaBypassEnabled);
         } else {
-            validateAccountForContactAdditionInternal(new Account(accountName, accountType));
+            validateAccountForContactAdditionInternal(new Account(accountName, accountType),
+                    shouldValidateAccountForContactAddition,
+                    allowSimWriteOnCloudDcaBypassEnabled);
         }
     }
 
-    private void validateAccountForContactAdditionInternal(Account account)
+    private void validateAccountForContactAdditionInternal(Account account,
+            boolean enforceCloudDefaultAccountRestriction,
+            boolean allowSimWriteOnCloudDcaBypassEnabled)
             throws IllegalArgumentException {
         DefaultAccountAndState defaultAccount = mDefaultAccountManager.pullDefaultAccount();
 
         if (defaultAccount.getState() == DefaultAccountAndState.DEFAULT_ACCOUNT_STATE_CLOUD) {
-            if (isDeviceOrSimAccount(account)) {
-                throw new IllegalArgumentException("Cannot add contacts to local or SIM accounts "
-                        + "when default account is set to cloud");
+            if (allowSimWriteOnCloudDcaBypassEnabled
+                    ? isDeviceAccount(account)
+                    : isDeviceOrSimAccount(account)) {
+                if (enforceCloudDefaultAccountRestriction) {
+                    throw new IllegalArgumentException(
+                            UNABLE_TO_WRITE_TO_LOCAL_OR_SIM_EXCEPTION_MESSAGE);
+                } else {
+                    Log.w(TAG,
+                            "Cloud default account: Local/SIM contact creation allowed (target "
+                                    + "SDK <36), but restricted in target SDK 36+. Avoid "
+                                    + "local/SIM writes in target SDK 36+.");
+                }
             }
         }
     }
@@ -178,6 +203,14 @@ public class AccountResolver {
         return accountWithDataSet.isLocalAccount() || accountWithDataSet.inSimAccounts(simAccounts);
     }
 
+    private boolean isDeviceAccount(Account account) {
+        AccountWithDataSet accountWithDataSet = account == null
+                ? new AccountWithDataSet(null, null, null)
+                : new AccountWithDataSet(account.name, account.type, null);
+
+        return accountWithDataSet.isLocalAccount();
+    }
+
     /**
      * If account is non-null then store it in the values. If the account is
      * already specified in the values then it must be consistent with the
diff --git a/src/com/android/providers/contacts/ContactMover.java b/src/com/android/providers/contacts/ContactMover.java
index 33caecd1..ff7cdb76 100644
--- a/src/com/android/providers/contacts/ContactMover.java
+++ b/src/com/android/providers/contacts/ContactMover.java
@@ -16,7 +16,7 @@
 
 package com.android.providers.contacts;
 
-import static com.android.providers.contacts.flags.Flags.cp2AccountMoveFlag;
+import static com.android.providers.contacts.flags.Flags.disableCp2AccountMoveFlag;
 import static com.android.providers.contacts.flags.Flags.cp2AccountMoveSyncStubFlag;
 import static com.android.providers.contacts.flags.Flags.cp2AccountMoveDeleteNonCommonDataRowsFlag;
 import static com.android.providers.contacts.flags.Flags.disableMoveToIneligibleDefaultAccountFlag;
@@ -246,7 +246,7 @@ public class ContactMover {
     // Keep it in proguard for testing: once it's used in production code, remove this annotation.
     @NeededForTesting
     void moveLocalToCloudDefaultAccount() {
-        if (!cp2AccountMoveFlag()) {
+        if (disableCp2AccountMoveFlag()) {
             Log.w(TAG, "moveLocalToCloudDefaultAccount: flag disabled");
             return;
         }
@@ -275,7 +275,7 @@ public class ContactMover {
     // Keep it in proguard for testing: once it's used in production code, remove this annotation.
     @NeededForTesting
     void moveSimToCloudDefaultAccount() {
-        if (!cp2AccountMoveFlag()) {
+        if (disableCp2AccountMoveFlag()) {
             Log.w(TAG, "moveSimToCloudDefaultAccount: flag disabled");
             return;
         }
@@ -306,7 +306,7 @@ public class ContactMover {
     // Keep it in proguard for testing: once it's used in production code, remove this annotation.
     @NeededForTesting
     int getNumberLocalContacts() {
-        if (!cp2AccountMoveFlag()) {
+        if (disableCp2AccountMoveFlag()) {
             Log.w(TAG, "getNumberLocalContacts: flag disabled");
             return 0;
         }
@@ -334,7 +334,7 @@ public class ContactMover {
     // Keep it in proguard for testing: once it's used in production code, remove this annotation.
     @NeededForTesting
     int getNumberSimContacts() {
-        if (!cp2AccountMoveFlag()) {
+        if (disableCp2AccountMoveFlag()) {
             Log.w(TAG, "getNumberSimContacts: flag disabled");
             return 0;
         }
@@ -363,7 +363,7 @@ public class ContactMover {
     // Keep it in proguard for testing: once it's used in production code, remove this annotation.
     @NeededForTesting
     void moveRawContacts(Set<AccountWithDataSet> sourceAccounts, AccountWithDataSet destAccount) {
-        if (!cp2AccountMoveFlag()) {
+        if (disableCp2AccountMoveFlag()) {
             Log.w(TAG, "moveRawContacts: flag disabled");
             return;
         }
@@ -385,7 +385,7 @@ public class ContactMover {
     @NeededForTesting
     void moveRawContactsWithSyncStubs(Set<AccountWithDataSet> sourceAccounts,
             AccountWithDataSet destAccount) {
-        if (!cp2AccountMoveFlag() || !cp2AccountMoveSyncStubFlag()) {
+        if (disableCp2AccountMoveFlag() || !cp2AccountMoveSyncStubFlag()) {
             Log.w(TAG, "moveRawContactsWithSyncStubs: flags disabled");
             return;
         }
@@ -419,10 +419,11 @@ public class ContactMover {
             AccountWithDataSet destAccount, boolean insertSyncStubs) {
         // If we are moving between account types or data sets, delete non-portable data rows
         // from the source
-        if (cp2AccountMoveDeleteNonCommonDataRowsFlag()
-                && (!isAccountTypeMatch(sourceAccount, destAccount)
-                || !isDataSetMatch(sourceAccount, destAccount))) {
-            mDbHelper.deleteNonCommonDataRows(sourceAccount);
+        if (cp2AccountMoveDeleteNonCommonDataRowsFlag()) {
+            if (!isAccountTypeMatch(sourceAccount, destAccount)
+                    || !isDataSetMatch(sourceAccount, destAccount)) {
+                mDbHelper.deleteNonCommonDataRows(sourceAccount);
+            }
         }
 
         // Move any groups and group memberships from the source to destination account
diff --git a/src/com/android/providers/contacts/ContactsProvider2.java b/src/com/android/providers/contacts/ContactsProvider2.java
index 3846a5a7..1764fb52 100644
--- a/src/com/android/providers/contacts/ContactsProvider2.java
+++ b/src/com/android/providers/contacts/ContactsProvider2.java
@@ -21,8 +21,9 @@ import static android.Manifest.permission.INTERACT_ACROSS_USERS_FULL;
 import static android.content.pm.PackageManager.PERMISSION_GRANTED;
 import static android.provider.Flags.newDefaultAccountApiEnabled;
 
-import static com.android.providers.contacts.flags.Flags.cp2AccountMoveFlag;
 import static com.android.providers.contacts.flags.Flags.cp2SyncSearchIndexFlag;
+import static com.android.providers.contacts.flags.Flags.disableCp2AccountMoveFlag;
+import static com.android.providers.contacts.flags.Flags.logCallMethod;
 import static com.android.providers.contacts.util.PhoneAccountHandleMigrationUtils.TELEPHONY_COMPONENT_NAME;
 
 import android.accounts.Account;
@@ -2220,6 +2221,15 @@ public class ContactsProvider2 extends AbstractContactsProvider
                 && mAppCloningDeviceConfigHelper.getEnableAppCloningBuildingBlocks();
     }
 
+    @VisibleForTesting
+    protected boolean isAccountRestrictionEnabled() {
+        return
+                getContext().getResources()
+                        .getBoolean(R.bool.config_rawContactsAccountRestrictionEnabled);
+
+    }
+
+
     /**
      * Maximum dimension (height or width) of photo thumbnails.
      */
@@ -2510,6 +2520,9 @@ public class ContactsProvider2 extends AbstractContactsProvider
             return Bundle.EMPTY;
         }
         switchToContactMode();
+
+        boolean enableCallMethodLogging = logCallMethod();
+
         if (Authorization.AUTHORIZATION_METHOD.equals(method)) {
             Uri uri = extras.getParcelable(Authorization.KEY_URI_TO_AUTHORIZE);
 
@@ -2603,47 +2616,113 @@ public class ContactsProvider2 extends AbstractContactsProvider
             return response;
         } else if (DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD.equals(
                 method)) {
-            if (newDefaultAccountApiEnabled()) {
-                return queryDefaultAccountForNewContacts();
-            } else {
-                // Ignore the call if the flag is disabled.
-                Log.w(TAG, "Query default account for new contacts is not supported.");
+            final LogFields.Builder logBuilder =
+                    enableCallMethodLogging ? getCallMethodLogBuilder()
+                            .setMethodCalled(
+                                    LogUtils.MethodCall.GET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS)
+                            : null;
+            try {
+                if (newDefaultAccountApiEnabled()) {
+                    return queryDefaultAccountForNewContacts();
+                } else {
+                    throw new UnsupportedOperationException(
+                            "Query default account for new contacts is not supported.");
+                }
+            } catch (Exception e) {
+                if (enableCallMethodLogging) {
+                    logBuilder.setException(e);
+                }
+                throw e;
+            } finally {
+                if (enableCallMethodLogging) {
+                    LogUtils.log(logBuilder.build());
+                }
             }
         } else if (DefaultAccount.QUERY_ELIGIBLE_DEFAULT_ACCOUNTS_METHOD.equals(method)) {
-            if (newDefaultAccountApiEnabled()) {
-                return queryEligibleDefaultAccounts();
-            } else {
-                Log.w(TAG, "Query eligible account that can be set as cloud default account "
-                        + "is not supported.");
+            final LogFields.Builder logBuilder =
+                    enableCallMethodLogging ? getCallMethodLogBuilder()
+                            .setMethodCalled(LogUtils.MethodCall.GET_ELIGIBLE_CLOUD_ACCOUNTS)
+                            : null;
+            try {
+                if (newDefaultAccountApiEnabled()) {
+                    return queryEligibleDefaultAccounts();
+                } else {
+                    throw new UnsupportedOperationException(
+                            "Query eligible account that can be set as cloud default account "
+                                    + "is not supported.");
+                }
+            } catch (Exception e) {
+                if (enableCallMethodLogging) {
+                    logBuilder.setException(e);
+                }
+                throw e;
+            } finally {
+                if (enableCallMethodLogging) {
+                    LogUtils.log(logBuilder.build());
+                }
             }
         } else if (Settings.SET_DEFAULT_ACCOUNT_METHOD.equals(method)) {
             return setDefaultAccountSetting(extras);
         } else if (DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD.equals(
                 method)) {
-            if (newDefaultAccountApiEnabled()) {
-                return setDefaultAccountForNewContactsSetting(extras);
-            } else {
-                // Ignore the call if the flag is disabled.
-                Log.w(TAG, "Set default account for new contacts is not supported.");
+            final LogFields.Builder logBuilder =
+                    enableCallMethodLogging ? getCallMethodLogBuilder()
+                            .setMethodCalled(
+                                    LogUtils.MethodCall.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS)
+                            : null;
+            try {
+                if (newDefaultAccountApiEnabled()) {
+                    return setDefaultAccountForNewContactsSetting(extras);
+                } else {
+                    throw new UnsupportedOperationException(
+                            "Set default account for new contacts is not supported.");
+                }
+            } catch (Exception e) {
+                if (enableCallMethodLogging) {
+                    logBuilder.setException(e);
+                }
+                throw e;
+            } finally {
+                if (enableCallMethodLogging) {
+                    LogUtils.log(logBuilder.build());
+                }
             }
         } else if (RawContacts.DefaultAccount.MOVE_LOCAL_CONTACTS_TO_CLOUD_DEFAULT_ACCOUNT_METHOD
                 .equals(method)) {
-            if (!cp2AccountMoveFlag() || !newDefaultAccountApiEnabled()) {
-                return null;
+            final LogFields.Builder logBuilder =
+                    enableCallMethodLogging ? getCallMethodLogBuilder()
+                            .setMethodCalled(
+                                    LogUtils.MethodCall.MOVE_LOCAL_CONTACTS_TO_DEFAULT_ACCOUNT)
+                            : null;
+            try {
+                if (!newDefaultAccountApiEnabled() || disableCp2AccountMoveFlag()) {
+                    throw new UnsupportedOperationException(
+                            "Move local contacts to cloud default account is not supported");
+                }
+                ContactsPermissions.enforceCallingOrSelfPermission(getContext(), WRITE_PERMISSION);
+                ContactsPermissions.enforceCallingOrSelfPermission(getContext(),
+                        SET_DEFAULT_ACCOUNT_PERMISSION);
+                final Bundle response = new Bundle();
+                mContactMover.moveLocalToCloudDefaultAccount();
+                return response;
+            } catch (Exception e) {
+                if (enableCallMethodLogging) {
+                    logBuilder.setException(e);
+                }
+                throw e;
+            } finally {
+                if (enableCallMethodLogging) {
+                    LogUtils.log(logBuilder.build());
+                }
             }
-            ContactsPermissions.enforceCallingOrSelfPermission(getContext(), WRITE_PERMISSION);
-            ContactsPermissions.enforceCallingOrSelfPermission(getContext(),
-                    SET_DEFAULT_ACCOUNT_PERMISSION);
-            final Bundle response = new Bundle();
-            mContactMover.moveLocalToCloudDefaultAccount();
-            return response;
-
         } else if (RawContacts.DefaultAccount.GET_NUMBER_OF_MOVABLE_LOCAL_CONTACTS_METHOD
                 .equals(method)) {
             if (!newDefaultAccountApiEnabled()) {
-                return null;
+                throw new UnsupportedOperationException(
+                        "Getting the count of local contacts to move is not supported");
             }
-            if (!cp2AccountMoveFlag()) {
+            if (disableCp2AccountMoveFlag()) {
+                Log.w(TAG, "Cp2AccountMoveFlag disabled");
                 return new Bundle();
             }
             ContactsPermissions.enforceCallingOrSelfPermission(getContext(), READ_PERMISSION);
@@ -2654,25 +2733,41 @@ public class ContactsProvider2 extends AbstractContactsProvider
             response.putInt(RawContacts.DefaultAccount.KEY_NUMBER_OF_MOVABLE_LOCAL_CONTACTS,
                     count);
             return response;
-
         } else if (RawContacts.DefaultAccount.MOVE_SIM_CONTACTS_TO_CLOUD_DEFAULT_ACCOUNT_METHOD
                 .equals(method)) {
-            if (!cp2AccountMoveFlag() || !newDefaultAccountApiEnabled()) {
-                return null;
+            final LogFields.Builder logBuilder =
+                    enableCallMethodLogging ? getCallMethodLogBuilder()
+                            .setMethodCalled(
+                                    LogUtils.MethodCall.MOVE_SIM_CONTACTS_TO_DEFAULT_ACCOUNT)
+                            : null;
+            try {
+                if (!newDefaultAccountApiEnabled() || disableCp2AccountMoveFlag()) {
+                    throw new UnsupportedOperationException(
+                            "Move SIM contacts to cloud default account is not supported");
+                }
+                ContactsPermissions.enforceCallingOrSelfPermission(getContext(), WRITE_PERMISSION);
+                ContactsPermissions.enforceCallingOrSelfPermission(getContext(),
+                        SET_DEFAULT_ACCOUNT_PERMISSION);
+                final Bundle response = new Bundle();
+                mContactMover.moveSimToCloudDefaultAccount();
+                return response;
+            } catch (Exception e) {
+                if (enableCallMethodLogging) {
+                    logBuilder.setException(e);
+                }
+                throw e;
+            } finally {
+                if (enableCallMethodLogging) {
+                    LogUtils.log(logBuilder.build());
+                }
             }
-            ContactsPermissions.enforceCallingOrSelfPermission(getContext(), WRITE_PERMISSION);
-            ContactsPermissions.enforceCallingOrSelfPermission(getContext(),
-                    SET_DEFAULT_ACCOUNT_PERMISSION);
-            final Bundle response = new Bundle();
-            mContactMover.moveSimToCloudDefaultAccount();
-            return response;
-
         } else if (RawContacts.DefaultAccount.GET_NUMBER_OF_MOVABLE_SIM_CONTACTS_METHOD
                 .equals(method)) {
             if (!newDefaultAccountApiEnabled()) {
-                return null;
+                throw new UnsupportedOperationException(
+                        "Getting the count of SIM contacts to move is not supported");
             }
-            if (!cp2AccountMoveFlag()) {
+            if (disableCp2AccountMoveFlag()) {
                 return new Bundle();
             }
             ContactsPermissions.enforceCallingOrSelfPermission(getContext(), READ_PERMISSION);
@@ -2683,11 +2778,17 @@ public class ContactsProvider2 extends AbstractContactsProvider
             response.putInt(RawContacts.DefaultAccount.KEY_NUMBER_OF_MOVABLE_SIM_CONTACTS,
                     count);
             return response;
-
         }
         return null;
     }
 
+    private static LogFields.Builder getCallMethodLogBuilder() {
+        return LogFields.Builder.aLogFields()
+                .setApiType(LogUtils.ApiType.CALL)
+                .setStartNanos(SystemClock.elapsedRealtimeNanos())
+                .setUid(Binder.getCallingUid());
+    }
+
     private @NonNull Bundle queryDefaultAccountForNewContacts() {
         ContactsPermissions.enforceCallingOrSelfPermission(getContext(), READ_PERMISSION);
         final Bundle response = new Bundle();
@@ -3711,7 +3812,8 @@ public class ContactsProvider2 extends AbstractContactsProvider
 
     private Uri insertSettings(Uri uri, ContentValues values) {
         final AccountWithDataSet account = mAccountResolver.resolveAccountWithDataSet(uri, values,
-                /*applyDefaultAccount=*/false, /*shouldValidateAccountForContactAddition=*/ false);
+                /*applyDefaultAccount=*/false, /*shouldValidateAccountForContactAddition=*/ false,
+                false);
 
         // Note that the following check means the local account settings cannot be created with
         // an insert because resolveAccountWithDataSet returns null for it. However, the settings
@@ -4907,11 +5009,13 @@ public class ContactsProvider2 extends AbstractContactsProvider
                         ? updatedDataSet : c.getString(GroupAccountQuery.DATA_SET);
 
                 if (isAccountChanging) {
-                    if (newDefaultAccountApiEnabled() && CompatChanges.isChangeEnabled(
-                            ChangeIds.RESTRICT_CONTACTS_CREATION_IN_ACCOUNTS,
-                            Binder.getCallingUid())) {
+                    if (newDefaultAccountApiEnabled() && isAccountRestrictionEnabled()) {
                         mAccountResolver.validateAccountForContactAddition(updatedAccountName,
-                                updatedAccountType);
+                                updatedAccountType,
+                                CompatChanges.isChangeEnabled(
+                                        ChangeIds.RESTRICT_CONTACTS_CREATION_IN_ACCOUNTS,
+                                        Binder.getCallingUid()),
+                                isAppAllowedToSyncSimContacts());
                     }
 
                     final long accountId = dbHelper.getOrCreateAccountIdInTransaction(
@@ -5096,12 +5200,14 @@ public class ContactsProvider2 extends AbstractContactsProvider
                 // a single transaction, failing checkAccountIsWritable will fail the entire update
                 // operation, which is clean such that no partial updated will be committed to the
                 // DB.
-                if (applyDefaultAccount && CompatChanges.isChangeEnabled(
-                        ChangeIds.RESTRICT_CONTACTS_CREATION_IN_ACCOUNTS,
-                        Binder.getCallingUid())) {
+                if (applyDefaultAccount && isAccountRestrictionEnabled()) {
                     mAccountResolver.validateAccountForContactAddition(
                             newAccountWithDataSet.getAccountName(),
-                            newAccountWithDataSet.getAccountType());
+                            newAccountWithDataSet.getAccountType(),
+                            CompatChanges.isChangeEnabled(
+                                    ChangeIds.RESTRICT_CONTACTS_CREATION_IN_ACCOUNTS,
+                                    Binder.getCallingUid()),
+                            isAppAllowedToSyncSimContacts());
                 }
 
                 accountId = dbHelper.getOrCreateAccountIdInTransaction(newAccountWithDataSet);
@@ -5983,6 +6089,11 @@ public class ContactsProvider2 extends AbstractContactsProvider
                 isAppAllowedToUseParentUsersContacts(getCallingPackage());
     }
 
+    private boolean isAppAllowedToSyncSimContacts() {
+        return ContactsPermissions.hasCallerOrSelfPermission(getContext(),
+                MANAGE_SIM_ACCOUNTS_PERMISSION);
+    }
+
     /**
      * Check if the app with the given package name is allowed to use parent user's contacts to
      * serve the contacts read queries.
@@ -10534,12 +10645,14 @@ public class ContactsProvider2 extends AbstractContactsProvider
     private long replaceAccountInfoByAccountId(Uri uri, ContentValues values,
             boolean applyDefaultAccount) {
         boolean shouldValidateAccountForContactAddition =
-                applyDefaultAccount && CompatChanges.isChangeEnabled(
+                applyDefaultAccount && isAccountRestrictionEnabled()
+                        && CompatChanges.isChangeEnabled(
                         ChangeIds.RESTRICT_CONTACTS_CREATION_IN_ACCOUNTS,
                         Binder.getCallingUid());
 
         final AccountWithDataSet account = mAccountResolver.resolveAccountWithDataSet(uri, values,
-                applyDefaultAccount, shouldValidateAccountForContactAddition);
+                applyDefaultAccount, shouldValidateAccountForContactAddition,
+                isAppAllowedToSyncSimContacts());
         final long id = mDbHelper.get().getOrCreateAccountIdInTransaction(account);
         values.put(RawContactsColumns.ACCOUNT_ID, id);
 
diff --git a/src/com/android/providers/contacts/SyncSettingsHelper.java b/src/com/android/providers/contacts/SyncSettingsHelper.java
index 1e950c41..856ff388 100644
--- a/src/com/android/providers/contacts/SyncSettingsHelper.java
+++ b/src/com/android/providers/contacts/SyncSettingsHelper.java
@@ -17,45 +17,13 @@
 package com.android.providers.contacts;
 
 import android.accounts.Account;
+import android.content.ContentResolver;
+import android.provider.ContactsContract;
 
 import com.android.providers.contacts.util.NeededForTesting;
 
-import java.util.HashMap;
-import java.util.Map;
-
 @NeededForTesting
 public class SyncSettingsHelper {
-    @NeededForTesting
-    public enum SyncState { ON, OFF }
-
-    // TODO: Currently the sync state are stored in memory, which will be hooked up with the real
-    // sync settings.
-    private final Map<Account, SyncState> mSyncStates;
-
-    public SyncSettingsHelper() {
-        mSyncStates = new HashMap<>();
-    }
-
-    /**
-     * Turns on sync for the given account.
-     *
-     * @param account The account for which sync should be turned on.
-     */
-    @NeededForTesting
-    public void turnOnSync(Account account) {
-        mSyncStates.put(account, SyncState.ON);
-    }
-
-    /**
-     * Turns off sync for the given account.
-     *
-     * @param account The account for which sync should be turned off.
-     */
-    @NeededForTesting
-    public void turnOffSync(Account account) {
-        mSyncStates.put(account, SyncState.OFF);
-    }
-
     /**
      * Checks if sync is turned off for the given account.
      *
@@ -64,7 +32,7 @@ public class SyncSettingsHelper {
      */
     @NeededForTesting
     public boolean isSyncOff(Account account) {
-        return mSyncStates.get(account) == SyncState.OFF;
+        return ContentResolver.getIsSyncable(account, ContactsContract.AUTHORITY) <= 0;
     }
 }
 
diff --git a/src/com/android/providers/contacts/util/LogFields.java b/src/com/android/providers/contacts/util/LogFields.java
index 1672d3db..ed721da4 100644
--- a/src/com/android/providers/contacts/util/LogFields.java
+++ b/src/com/android/providers/contacts/util/LogFields.java
@@ -37,6 +37,8 @@ public final class LogFields {
 
     private int resultCount;
 
+    private int mMethodCalled;
+
     private int uid;
 
     public LogFields(
@@ -80,6 +82,10 @@ public final class LogFields {
         return resultCount;
     }
 
+    public int getMethodCalled() {
+        return mMethodCalled;
+    }
+
     public int getUid() {
         return uid;
     }
@@ -93,6 +99,7 @@ public final class LogFields {
         private Exception exception;
         private Uri resultUri;
         private int resultCount;
+        private int mMethodCalled;
 
         private int uid;
 
@@ -143,6 +150,17 @@ public final class LogFields {
             return this;
         }
 
+        /**
+         * Sets the method called.
+         *
+         * @param methodCalled The method called.
+         * @return This {@code Builder} object for chaining.
+         */
+        public Builder setMethodCalled(int methodCalled) {
+            this.mMethodCalled = methodCalled;
+            return this;
+        }
+
         public Builder setUid(int uid) {
             this.uid = uid;
             return this;
@@ -155,6 +173,7 @@ public final class LogFields {
             logFields.exception = this.exception;
             logFields.resultUri = this.resultUri;
             logFields.uid = this.uid;
+            logFields.mMethodCalled = this.mMethodCalled;
             return logFields;
         }
     }
diff --git a/src/com/android/providers/contacts/util/LogUtils.java b/src/com/android/providers/contacts/util/LogUtils.java
index 41409645..f8d0a137 100644
--- a/src/com/android/providers/contacts/util/LogUtils.java
+++ b/src/com/android/providers/contacts/util/LogUtils.java
@@ -16,10 +16,15 @@
 
 package com.android.providers.contacts.util;
 
+import static com.android.providers.contacts.flags.Flags.logCallMethod;
+import static com.android.providers.contacts.flags.Flags.logContactSaveInvalidAccountError;
+
 import android.os.SystemClock;
 import android.util.StatsEvent;
 import android.util.StatsLog;
 
+import com.android.providers.contacts.AccountResolver;
+
 public class LogUtils {
     // Keep in sync with ContactsProviderStatus#ResultType in
     // frameworks/proto_logging/stats/atoms.proto file.
@@ -28,6 +33,7 @@ public class LogUtils {
         int FAIL = 2;
         int ILLEGAL_ARGUMENT = 3;
         int UNSUPPORTED_OPERATION = 4;
+        int INVALID_ACCOUNT = 5;
     }
 
     // Keep in sync with ContactsProviderStatus#ApiType in
@@ -47,6 +53,20 @@ public class LogUtils {
         int DANGLING_CONTACTS_CLEANUP_TASK = 1;
     }
 
+    // Keep in sync with ContactsProviderStatus#MethodCall in
+    // frameworks/proto_logging/stats/atoms.proto file.
+    public interface MethodCall {
+        int UNKNOWN_METHOD = 0;
+        int ADD_SIM_ACCOUNTS = 1;
+        int REMOVE_SIM_ACCOUNTS = 2;
+        int GET_SIM_ACCOUNTS = 3;
+        int SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS = 4;
+        int GET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS = 5;
+        int MOVE_LOCAL_CONTACTS_TO_DEFAULT_ACCOUNT = 6;
+        int MOVE_SIM_CONTACTS_TO_DEFAULT_ACCOUNT = 7;
+        int GET_ELIGIBLE_CLOUD_ACCOUNTS = 8;
+    }
+
     // Keep in sync with ContactsProviderStatus#CallerType in
     // frameworks/proto_logging/stats/atoms.proto file.
     public interface CallerType {
@@ -68,7 +88,7 @@ public class LogUtils {
                 .writeInt(logFields.getResultCount())
                 .writeLong(getLatencyMicros(logFields.getStartNanos()))
                 .writeInt(logFields.getTaskType())
-                .writeInt(0) // Not used yet.
+                .writeInt(logCallMethod() ? logFields.getMethodCalled() : 0)
                 .writeInt(logFields.getUid())
                 .usePooledBuffer()
                 .build());
@@ -79,10 +99,16 @@ public class LogUtils {
                 ? CallerType.CALLER_IS_SYNC_ADAPTER : CallerType.CALLER_IS_NOT_SYNC_ADAPTER;
     }
 
+
     private static int getResultType(Exception exception) {
         if (exception == null) {
             return ResultType.SUCCESS;
         } else if (exception instanceof IllegalArgumentException) {
+            if (logContactSaveInvalidAccountError()
+                    && AccountResolver.UNABLE_TO_WRITE_TO_LOCAL_OR_SIM_EXCEPTION_MESSAGE.equals(
+                    exception.getMessage())) {
+                return ResultType.INVALID_ACCOUNT;
+            }
             return ResultType.ILLEGAL_ARGUMENT;
         } else if (exception instanceof UnsupportedOperationException) {
             return ResultType.UNSUPPORTED_OPERATION;
diff --git a/tests/Android.bp b/tests/Android.bp
index 7a6dabb4..3567acb0 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -45,7 +45,7 @@ test_module_config {
     options: [
         {
             name: "feature-flags:flag-value",
-            value: "contacts/com.android.providers.contacts.flags.cp2_account_move_flag=true",
+            value: "contacts/com.android.providers.contacts.flags.disable_cp2_account_move_flag=false",
         },
         {
             name: "feature-flags:flag-value",
@@ -64,7 +64,7 @@ test_module_config {
     options: [
         {
             name: "feature-flags:flag-value",
-            value: "contacts/com.android.providers.contacts.flags.cp2_account_move_flag=false",
+            value: "contacts/com.android.providers.contacts.flags.disable_cp2_account_move_flag=true",
         },
         {
             name: "feature-flags:flag-value",
diff --git a/tests/AndroidManifest.xml b/tests/AndroidManifest.xml
index 95b21b01..9639eb2a 100644
--- a/tests/AndroidManifest.xml
+++ b/tests/AndroidManifest.xml
@@ -20,6 +20,7 @@
 
     <uses-permission android:name="android.permission.GET_ACCOUNTS" />
     <uses-permission android:name="android.permission.READ_SYNC_SETTINGS" />
+    <uses-permission android:name="android.permission.WRITE_SYNC_SETTINGS" />
     <uses-permission android:name="android.permission.WRITE_CONTACTS" />
     <uses-permission android:name="android.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS" />
 
diff --git a/tests/src/com/android/providers/contacts/AccountResolverTest.java b/tests/src/com/android/providers/contacts/AccountResolverTest.java
index 7505f1ca..2d674f6b 100644
--- a/tests/src/com/android/providers/contacts/AccountResolverTest.java
+++ b/tests/src/com/android/providers/contacts/AccountResolverTest.java
@@ -79,7 +79,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                false, /*shouldValidateAccountForContactAddition=*/TRUE_UNUSED);
+                false, /*shouldValidateAccountForContactAddition=*/
+                TRUE_UNUSED, /*allowSimWriteOnCloudDcaBypassEnabled=*/ TRUE_UNUSED);
 
         assertEquals("test_account", result.getAccountName());
         assertEquals("com.google", result.getAccountType());
@@ -102,7 +103,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
 
         assertEquals("test_account", result.getAccountName());
         assertEquals("com.google", result.getAccountType());
@@ -122,7 +124,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
+                false, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ FALSE_UNUSED);
 
         assertEquals("test_account", result.getAccountName());
         assertEquals("com.google", result.getAccountType());
@@ -145,7 +148,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
 
         assertEquals("test_account", result.getAccountName());
         assertEquals("com.google", result.getAccountType());
@@ -160,7 +164,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                false, /*shouldValidateAccountForContactAddition=*/TRUE_UNUSED);
+                false, /*shouldValidateAccountForContactAddition=*/
+                TRUE_UNUSED, /*allowSimWriteOnCloudDcaBypassEnabled=*/ TRUE_UNUSED);
 
         // When default account is not used, uri/values without account is always resolved as
         // the local account, which is null AccountWithDataSet in this case.
@@ -177,7 +182,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
 
         // When default account is used and the default account is not set, uri/values without
         // account is always resolved as the local account, which is null AccountWithDataSet in this
@@ -195,7 +201,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
 
         // When default account is used and the default account is set to 'local', uri/values
         // without account is always resolved as the local account, which is null
@@ -213,7 +220,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
 
         // When default account is used and the default account is set to 'cloud', uri/values
         // without account is always resolved as the cloud account, which is null
@@ -233,7 +241,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
+                false, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ FALSE_UNUSED);
 
         assertEquals("test_account", result1.getAccountName());
         assertEquals("com.google", result1.getAccountType());
@@ -244,7 +253,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
 
         assertEquals("test_account", result2.getAccountName());
         assertEquals("com.google", result2.getAccountType());
@@ -270,7 +280,7 @@ public class AccountResolverTest {
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values,
                     /*applyDefaultAccount=*/false, /*shouldValidateAccountForContactAddition=*/
-                    TRUE_UNUSED);
+                    TRUE_UNUSED, /*allowSimWriteOnCloudDcaBypassEnabled=*/ TRUE_UNUSED);
         });
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
@@ -278,7 +288,8 @@ public class AccountResolverTest {
         // Expecting an exception due to the invalid account in the URI
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values,
-                    /*applyDefaultAccount=*/true, /*shouldValidateAccountForContactAddition=*/true);
+                    /*applyDefaultAccount=*/true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
     }
 
@@ -300,7 +311,8 @@ public class AccountResolverTest {
         // Expecting an exception due to the invalid account in the values
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
+                    false, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ FALSE_UNUSED);
         });
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
@@ -308,7 +320,8 @@ public class AccountResolverTest {
         // Expecting an exception due to the invalid account in the URI
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
     }
 
@@ -326,7 +339,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                false, /*shouldValidateAccountForContactAddition=*/TRUE_UNUSED);
+                false, /*shouldValidateAccountForContactAddition=*/
+                TRUE_UNUSED, /*allowSimWriteOnCloudDcaBypassEnabled=*/ TRUE_UNUSED);
 
         assertEquals("test_account", result1.getAccountName());
         assertEquals("com.google", result1.getAccountType());
@@ -337,7 +351,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
 
         assertEquals("test_account", result2.getAccountName());
         assertEquals("com.google", result2.getAccountType());
@@ -361,7 +376,8 @@ public class AccountResolverTest {
         // Expecting an exception due to the invalid account in the URI
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
+                    false, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ FALSE_UNUSED);
         });
 
         // Expecting an exception due to the invalid account in the URI, regardless of what is the
@@ -370,13 +386,15 @@ public class AccountResolverTest {
                 DefaultAccountAndState.ofLocal());
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
                 DefaultAccountAndState.ofNotSet());
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
                 DefaultAccountAndState.ofCloud(new Account(
@@ -384,7 +402,8 @@ public class AccountResolverTest {
                 )));
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
     }
 
@@ -402,7 +421,8 @@ public class AccountResolverTest {
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    false, /*shouldValidateAccountForContactAddition=*/TRUE_UNUSED);
+                    false, /*shouldValidateAccountForContactAddition=*/
+                    TRUE_UNUSED, /*allowSimWriteOnCloudDcaBypassEnabled=*/ TRUE_UNUSED);
         });
         assertEquals("Test Exception Message", exception.getMessage());
 
@@ -412,13 +432,15 @@ public class AccountResolverTest {
                 DefaultAccountAndState.ofLocal());
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
                 DefaultAccountAndState.ofNotSet());
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
                 DefaultAccountAndState.ofCloud(new Account(
@@ -426,7 +448,8 @@ public class AccountResolverTest {
                 )));
         assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
     }
 
@@ -442,7 +465,8 @@ public class AccountResolverTest {
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
+                    false, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ FALSE_UNUSED);
         });
         assertEquals("Test Exception Message", exception.getMessage());
 
@@ -452,7 +476,8 @@ public class AccountResolverTest {
                 DefaultAccountAndState.ofLocal());
         exception = assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         assertEquals("Test Exception Message", exception.getMessage());
 
@@ -460,7 +485,8 @@ public class AccountResolverTest {
                 DefaultAccountAndState.ofNotSet());
         exception = assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         assertEquals("Test Exception Message", exception.getMessage());
 
@@ -470,7 +496,8 @@ public class AccountResolverTest {
                 )));
         exception = assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         assertEquals("Test Exception Message", exception.getMessage());
     }
@@ -492,7 +519,8 @@ public class AccountResolverTest {
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    false, /*shouldValidateAccountForContactAddition=*/TRUE_UNUSED);
+                    false, /*shouldValidateAccountForContactAddition=*/
+                    TRUE_UNUSED, /*allowSimWriteOnCloudDcaBypassEnabled=*/ TRUE_UNUSED);
         });
         assertEquals("Test Exception Message", exception.getMessage());
 
@@ -502,7 +530,8 @@ public class AccountResolverTest {
                 DefaultAccountAndState.ofNotSet());
         exception = assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         assertEquals("Test Exception Message", exception.getMessage());
 
@@ -512,7 +541,8 @@ public class AccountResolverTest {
                 )));
         exception = assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         assertEquals("Test Exception Message", exception.getMessage());
     }
@@ -528,7 +558,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
+                false, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ FALSE_UNUSED);
 
         assertNull(result); // Expect null result as account is effectively absent
     }
@@ -546,14 +577,16 @@ public class AccountResolverTest {
                 DefaultAccountAndState.ofNotSet());
         AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         assertNull(result1); // Expect null result as account is effectively absent
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
                 DefaultAccountAndState.ofLocal());
         AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         assertNull(result2); // Expect null result as account is effectively absent
     }
 
@@ -572,7 +605,8 @@ public class AccountResolverTest {
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         assertEquals(
                 "Cannot add contacts to local or SIM accounts when default account is set to cloud",
@@ -594,12 +628,14 @@ public class AccountResolverTest {
 
         AccountWithDataSet result =
                 mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                        true, /*shouldValidateAccountForContactAddition=*/false);
+                        true, /*shouldValidateAccountForContactAddition=*/
+                        false, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         assertNull(result);
     }
 
     @Test
-    public void testResolveAccountWithDataSet_defaultAccountIsCloud_simAccountInUri() {
+    public void
+            testResolveAccountWithDataSet_defaultAccountIsCloud_simWriteOnCloudDcaBypassDisabled() {
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
                 .buildUpon()
                 .appendQueryParameter(RawContacts.ACCOUNT_NAME, SIM_ACCOUNT_1.name)
@@ -613,13 +649,37 @@ public class AccountResolverTest {
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         assertEquals(
                 "Cannot add contacts to local or SIM accounts when default account is set to cloud",
                 exception.getMessage());
     }
 
+    @Test
+    public void
+            testResolveAccountWithDataSet_defaultAccountIsCloud_simWriteOnCloudDcaBypassEnabled() {
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
+                        true, /*shouldValidateAccountForContactAddition=*/
+                        true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ true);
+        assertEquals(SIM_ACCOUNT_1.name, result.getAccountName());
+        assertEquals(SIM_ACCOUNT_1.type, result.getAccountType());
+        assertNull(result.getDataSet());
+    }
+
     @Test
     public void testResolveAccount_defaultAccountIsCloud_simAccountInUri_skipAccountValidation() {
         Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
@@ -635,7 +695,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result =
                 mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                        true, /*shouldValidateAccountForContactAddition=*/false);
+                        true, /*shouldValidateAccountForContactAddition=*/
+                        false, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         assertEquals(SIM_ACCOUNT_1.name, result.getAccountName());
         assertEquals(SIM_ACCOUNT_1.type, result.getAccountType());
         assertNull(result.getDataSet());
@@ -650,7 +711,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
+                false, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ FALSE_UNUSED);
 
         assertNull(result); // Expect null result as account is effectively absent
     }
@@ -667,14 +729,16 @@ public class AccountResolverTest {
                 DefaultAccountAndState.ofNotSet());
         AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         assertNull(result1); // Expect null result as account is effectively absent
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
                 DefaultAccountAndState.ofLocal());
         AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         assertNull(result2); // Expect null result as account is effectively absent
     }
 
@@ -692,7 +756,8 @@ public class AccountResolverTest {
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         assertEquals(
                 "Cannot add contacts to local or SIM accounts when default account is set to cloud",
@@ -712,7 +777,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(uri,
                 values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/false);
+                true, /*shouldValidateAccountForContactAddition=*/
+                false, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         assertNull(result);
     }
 
@@ -729,7 +795,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                false, /*shouldValidateAccountForContactAddition=*/TRUE_UNUSED);
+                false, /*shouldValidateAccountForContactAddition=*/
+                TRUE_UNUSED, /*allowSimWriteOnCloudDcaBypassEnabled=*/ TRUE_UNUSED);
 
         assertNull(result); // Expect null result as account is effectively absent
     }
@@ -749,14 +816,16 @@ public class AccountResolverTest {
                 DefaultAccountAndState.ofNotSet());
         AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         assertNull(result1); // Expect null result as account is effectively absent
 
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
                 DefaultAccountAndState.ofLocal());
         AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                true, /*shouldValidateAccountForContactAddition=*/true);
+                true, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         assertNull(result2); // Expect null result as account is effectively absent
     }
 
@@ -773,7 +842,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
+                false, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ FALSE_UNUSED);
 
         assertNull(result); // Expect null result as account is effectively absent
 
@@ -783,7 +853,8 @@ public class AccountResolverTest {
 
         IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
             mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/true);
+                    true, /*shouldValidateAccountForContactAddition=*/
+                    true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
         });
         assertEquals(
                 "Cannot add contacts to local or SIM accounts when default account is set to cloud",
@@ -804,7 +875,8 @@ public class AccountResolverTest {
 
         AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
                 uri, values, /*applyDefaultAccount=*/
-                false, /*shouldValidateAccountForContactAddition=*/FALSE_UNUSED);
+                false, /*shouldValidateAccountForContactAddition=*/
+                true, /*allowSimWriteOnCloudDcaBypassEnabled=*/ FALSE_UNUSED);
 
         assertNull(result); // Expect null result as account is effectively absent
 
@@ -813,7 +885,8 @@ public class AccountResolverTest {
                         new Account("test_user2", "com.google")));
 
         result = mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/
-                    true, /*shouldValidateAccountForContactAddition=*/false);
+                true, /*shouldValidateAccountForContactAddition=*/
+                false, /*allowSimWriteOnCloudDcaBypassEnabled=*/ false);
 
         assertNull(result);
     }
@@ -824,10 +897,10 @@ public class AccountResolverTest {
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
                 DefaultAccountAndState.ofNotSet());
 
-        mAccountResolver.validateAccountForContactAddition("", "");
-        mAccountResolver.validateAccountForContactAddition(null, "");
-        mAccountResolver.validateAccountForContactAddition("", null);
-        mAccountResolver.validateAccountForContactAddition(null, null);
+        mAccountResolver.validateAccountForContactAddition("", "", true, false);
+        mAccountResolver.validateAccountForContactAddition(null, "", true, false);
+        mAccountResolver.validateAccountForContactAddition("", null, true, false);
+        mAccountResolver.validateAccountForContactAddition(null, null, true, false);
         // No exception expected
     }
 
@@ -837,18 +910,18 @@ public class AccountResolverTest {
                 DefaultAccountAndState.ofNotSet());
 
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.validateAccountForContactAddition("accountName", "");
+            mAccountResolver.validateAccountForContactAddition("accountName", "", true, false);
         });
 
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.validateAccountForContactAddition("accountName", null);
+            mAccountResolver.validateAccountForContactAddition("accountName", null, true, false);
         });
 
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.validateAccountForContactAddition("", "accountType");
+            mAccountResolver.validateAccountForContactAddition("", "accountType", true, false);
         });
         assertThrows(IllegalArgumentException.class, () -> {
-            mAccountResolver.validateAccountForContactAddition(null, "accountType");
+            mAccountResolver.validateAccountForContactAddition(null, "accountType", true, false);
         });
     }
 
@@ -858,13 +931,14 @@ public class AccountResolverTest {
                 DefaultAccountAndState.ofCloud(
                         new Account("test_user1", "com.google")));
 
-        mAccountResolver.validateAccountForContactAddition("test_user1", "com.google");
-        mAccountResolver.validateAccountForContactAddition("test_user2", "com.google");
-        mAccountResolver.validateAccountForContactAddition("test_user3", "com.whatsapp");
+        mAccountResolver.validateAccountForContactAddition("test_user1", "com.google", true, false);
+        mAccountResolver.validateAccountForContactAddition("test_user2", "com.google", true, false);
+        mAccountResolver.validateAccountForContactAddition("test_user3", "com.whatsapp", true,
+                false);
         assertThrows(IllegalArgumentException.class, () ->
-                mAccountResolver.validateAccountForContactAddition("", ""));
+                mAccountResolver.validateAccountForContactAddition("", "", true, false));
         assertThrows(IllegalArgumentException.class, () ->
-                mAccountResolver.validateAccountForContactAddition(null, null));
+                mAccountResolver.validateAccountForContactAddition(null, null, true, false));
         // No exception expected
     }
 
@@ -873,11 +947,12 @@ public class AccountResolverTest {
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
                 DefaultAccountAndState.ofLocal());
 
-        mAccountResolver.validateAccountForContactAddition("test_user1", "com.google");
-        mAccountResolver.validateAccountForContactAddition("test_user2", "com.google");
-        mAccountResolver.validateAccountForContactAddition("test_user3", "com.whatsapp");
-        mAccountResolver.validateAccountForContactAddition("", "");
-        mAccountResolver.validateAccountForContactAddition(null, null);
+        mAccountResolver.validateAccountForContactAddition("test_user1", "com.google", true, false);
+        mAccountResolver.validateAccountForContactAddition("test_user2", "com.google", true, false);
+        mAccountResolver.validateAccountForContactAddition("test_user3", "com.whatsapp", true,
+                false);
+        mAccountResolver.validateAccountForContactAddition("", "", true, false);
+        mAccountResolver.validateAccountForContactAddition(null, null, true, false);
         // No exception expected
     }
 
@@ -887,11 +962,12 @@ public class AccountResolverTest {
         when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
                 DefaultAccountAndState.ofNotSet());
 
-        mAccountResolver.validateAccountForContactAddition("test_user1", "com.google");
-        mAccountResolver.validateAccountForContactAddition("test_user2", "com.google");
-        mAccountResolver.validateAccountForContactAddition("test_user3", "com.whatsapp");
-        mAccountResolver.validateAccountForContactAddition("", "");
-        mAccountResolver.validateAccountForContactAddition(null, null);
+        mAccountResolver.validateAccountForContactAddition("test_user1", "com.google", true, false);
+        mAccountResolver.validateAccountForContactAddition("test_user2", "com.google", true, false);
+        mAccountResolver.validateAccountForContactAddition("test_user3", "com.whatsapp", true,
+                false);
+        mAccountResolver.validateAccountForContactAddition("", "", true, false);
+        mAccountResolver.validateAccountForContactAddition(null, null, true, false);
         // No exception expected
     }
 }
diff --git a/tests/src/com/android/providers/contacts/ContactsProvider2DefaultAccountTest.java b/tests/src/com/android/providers/contacts/ContactsProvider2DefaultAccountTest.java
index bab73f47..83d4e113 100644
--- a/tests/src/com/android/providers/contacts/ContactsProvider2DefaultAccountTest.java
+++ b/tests/src/com/android/providers/contacts/ContactsProvider2DefaultAccountTest.java
@@ -20,9 +20,11 @@ import static android.provider.ContactsContract.SimAccount.SDN_EF_TYPE;
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertThrows;
+import static org.junit.Assume.assumeTrue;
 
 import android.accounts.Account;
 import android.compat.testing.PlatformCompatChangeRule;
+import android.content.ContentResolver;
 import android.content.ContentUris;
 import android.content.ContentValues;
 import android.database.sqlite.SQLiteDatabase;
@@ -153,28 +155,36 @@ public class ContactsProvider2DefaultAccountTest extends BaseContactsProvider2Te
         // Default account is Unknown initially.
         assertEquals(0, mCp.getDatabaseHelper().getDefaultAccountIfAny().length);
 
-        assertNull(mResolver.call(ContactsContract.AUTHORITY_URI,
-                DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null, null));
+        assertThrows(UnsupportedOperationException.class, () -> {
+            mResolver.call(ContactsContract.AUTHORITY_URI,
+                    DefaultAccount.QUERY_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null, null);
+        });
 
         // Attempt to set default account to a cloud account.
-        assertNull(mResolver.call(ContactsContract.AUTHORITY_URI,
-                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
-                bundleToSetDefaultAccountForNewContacts(
-                        DefaultAccountAndState.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1))));
+        assertThrows(UnsupportedOperationException.class, () -> {
+            mResolver.call(ContactsContract.AUTHORITY_URI,
+                    DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                    bundleToSetDefaultAccountForNewContacts(
+                            DefaultAccountAndState.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1)));
+        });
         // Default account is not changed.
         assertEquals(0, mCp.getDatabaseHelper().getDefaultAccountIfAny().length);
 
         // Attempt to set default account to local.
-        assertNull(mResolver.call(ContactsContract.AUTHORITY_URI,
-                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
-                bundleToSetDefaultAccountForNewContacts(DefaultAccountAndState.ofLocal())));
+        assertThrows(UnsupportedOperationException.class, () -> {
+            mResolver.call(ContactsContract.AUTHORITY_URI,
+                    DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                    bundleToSetDefaultAccountForNewContacts(DefaultAccountAndState.ofLocal()));
+        });
         // Default account is not changed.
         assertEquals(0, mCp.getDatabaseHelper().getDefaultAccountIfAny().length);
 
         // Attempt to set default account to "not set".
-        assertNull(mResolver.call(ContactsContract.AUTHORITY_URI,
-                DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
-                bundleToSetDefaultAccountForNewContacts(DefaultAccountAndState.ofNotSet())));
+        assertThrows(UnsupportedOperationException.class, () -> {
+            mResolver.call(ContactsContract.AUTHORITY_URI,
+                    DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD, null,
+                    bundleToSetDefaultAccountForNewContacts(DefaultAccountAndState.ofNotSet()));
+        });
         // Default account is not changed.
         assertEquals(0, mCp.getDatabaseHelper().getDefaultAccountIfAny().length);
     }
@@ -385,14 +395,18 @@ public class ContactsProvider2DefaultAccountTest extends BaseContactsProvider2Te
     @RequiresFlagsDisabled(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
     public void testGetEligibleCloudAccounts_flagOff() throws Exception {
         mActor.setAccounts(new Account[0]);
-        assertNull(mResolver.call(ContactsContract.AUTHORITY_URI,
-                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
-                        null, null));
+        assertThrows(UnsupportedOperationException.class, () -> {
+            mResolver.call(ContactsContract.AUTHORITY_URI,
+                    DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                    null, null);
+        });
 
         mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
-        assertNull(mResolver.call(ContactsContract.AUTHORITY_URI,
-                        DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
-                        null, null));
+        assertThrows(UnsupportedOperationException.class, () -> {
+            mResolver.call(ContactsContract.AUTHORITY_URI,
+                    DefaultAccount.SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS_METHOD,
+                    null, null);
+        });
     }
 
     @Test
@@ -419,6 +433,14 @@ public class ContactsProvider2DefaultAccountTest extends BaseContactsProvider2Te
 
         // 1 system cloud account is present on the device.
         mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+
+        // The setIsSyncable operation may not be effective on some environments. Skip the remaining
+        // tests if setIsSyncable is not effective.
+        ContentResolver.setIsSyncable(SYSTEM_CLOUD_ACCOUNT_1, ContactsContract.AUTHORITY, 1);
+        Thread.sleep(1000);
+        assumeTrue(ContentResolver.getIsSyncable(SYSTEM_CLOUD_ACCOUNT_1, ContactsContract.AUTHORITY)
+                > 0);
+
         response = mResolver.call(ContactsContract.AUTHORITY_URI,
                 DefaultAccount.QUERY_ELIGIBLE_DEFAULT_ACCOUNTS_METHOD, null, null);
         accounts = response.getParcelableArrayList(
@@ -427,6 +449,14 @@ public class ContactsProvider2DefaultAccountTest extends BaseContactsProvider2Te
 
         // 2 system cloud accounts are present on the device.
         mActor.setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1, SYSTEM_CLOUD_ACCOUNT_2});
+
+        // The setIsSyncable operation may not be effective on some environments. Skip the remaining
+        // tests if setIsSyncable is not effective.
+        ContentResolver.setIsSyncable(SYSTEM_CLOUD_ACCOUNT_2, ContactsContract.AUTHORITY, 1);
+        Thread.sleep(1000);
+        assumeTrue(ContentResolver.getIsSyncable(SYSTEM_CLOUD_ACCOUNT_2, ContactsContract.AUTHORITY)
+                > 0);
+
         response = mResolver.call(ContactsContract.AUTHORITY_URI,
                 DefaultAccount.QUERY_ELIGIBLE_DEFAULT_ACCOUNTS_METHOD, null, null);
         accounts = response.getParcelableArrayList(
@@ -506,6 +536,62 @@ public class ContactsProvider2DefaultAccountTest extends BaseContactsProvider2Te
         assertThrows(IllegalArgumentException.class, () ->
                 insertRawContact((Account) null));
 
+        assertThrows(IllegalArgumentException.class, () -> insertRawContact(SIM_ACCOUNT_1));
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
+        // Exception expected when inserting group in SIM account.
+        assertThrows(IllegalArgumentException.class, () -> insertGroup(SIM_ACCOUNT_1));
+
+        // Okay to update the group to a different cloud account
+        assertEquals(1, updateGroupAccount(groupId1, SYSTEM_CLOUD_ACCOUNT_2));
+
+        // Exception expected when updating group to NULL account.
+        assertThrows(IllegalArgumentException.class, () -> updateGroupAccount(groupId1, null));
+
+        // Exception expected when updating group to SIM account.
+        assertThrows(IllegalArgumentException.class,
+                () -> updateGroupAccount(groupId1, SIM_ACCOUNT_1));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NEW_DEFAULT_ACCOUNT_API_ENABLED)
+    @EnableCompatChanges({ChangeIds.RESTRICT_CONTACTS_CREATION_IN_ACCOUNTS})
+    public void
+            testRawContactInsert_whenDefaultAccountSetToCloud_withManageSimAccountsPermission() {
+        mActor.addPermissions("android.permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS");
+        mActor.addPermissions("android.contacts.permission.MANAGE_SIM_ACCOUNTS");
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
+        // No exception expected when inserting raw contact in SIM account by MANAGE_SIM_ACCOUNTS
+        // permission holder.
+        insertRawContact(SIM_ACCOUNT_1);
+
         // Okay to update the raw contact to a different cloud account
         assertEquals(1, updateRawContactAccount(rawContactId1, SYSTEM_CLOUD_ACCOUNT_2));
 
@@ -520,12 +606,19 @@ public class ContactsProvider2DefaultAccountTest extends BaseContactsProvider2Te
         assertThrows(IllegalArgumentException.class, () ->
                 insertGroup((Account) null));
 
+        // No exception expected when inserting group in SIM account by MANAGE_SIM_ACCOUNTS
+        // permission holder.
+        insertGroup(SIM_ACCOUNT_1);
+
         // Okay to update the group to a different cloud account
         assertEquals(1, updateGroupAccount(groupId1, SYSTEM_CLOUD_ACCOUNT_2));
 
         // Exception expected when updating group to NULL account.
         assertThrows(IllegalArgumentException.class, () -> updateGroupAccount(groupId1, null));
 
+        // No exception expected when updating group to SIM account by MANAGE_SIM_ACCOUNTS
+        // permission holder.
+        assertEquals(1, updateGroupAccount(groupId1, SIM_ACCOUNT_1));
     }
 
     private long insertRawContact(Account account) {
diff --git a/tests/src/com/android/providers/contacts/DefaultAccountManagerTest.java b/tests/src/com/android/providers/contacts/DefaultAccountManagerTest.java
index 6f2ad407..b9254f55 100644
--- a/tests/src/com/android/providers/contacts/DefaultAccountManagerTest.java
+++ b/tests/src/com/android/providers/contacts/DefaultAccountManagerTest.java
@@ -37,8 +37,8 @@ import java.util.Map;
 @SmallTest
 public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
     private static final String TAG = "DefaultAccountManagerTest";
-    private static final Account SYSTEM_CLOUD_ACCOUNT_1 = new Account("user1@gmail.com",
-            "com.google");
+    private static final Account SYSTEM_CLOUD_ACCOUNT_1 = new Account("user1@xyz.com",
+            "com.xyz");
     private static final Account NON_SYSTEM_CLOUD_ACCOUNT_1 = new Account("user2@whatsapp.com",
             "com.whatsapp");
 
@@ -47,22 +47,25 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
 
     private ContactsDatabaseHelper mDbHelper;
     private DefaultAccountManager mDefaultAccountManager;
-    private SyncSettingsHelper mSyncSettingsHelper;
     private AccountManager mMockAccountManager;
 
+    private SyncSettingsHelper mSyncSettingsHelper;
+
     @Override
     protected void setUp() throws Exception {
         super.setUp();
 
         mDbHelper = getContactsProvider().getDatabaseHelper();
-        mSyncSettingsHelper = new SyncSettingsHelper();
         mMockAccountManager = Mockito.mock(AccountManager.class);
+        mSyncSettingsHelper = Mockito.mock(SyncSettingsHelper.class);
         mDefaultAccountManager = new DefaultAccountManager(getContactsProvider().getContext(),
                 mDbHelper, mSyncSettingsHelper, mMockAccountManager); // Inject mockAccountManager
 
         setAccounts(new Account[0]);
         DefaultAccountManager.setEligibleSystemCloudAccountTypesForTesting(
                 new String[]{SYSTEM_CLOUD_ACCOUNT_1.type});
+
+        turnOnSync(SYSTEM_CLOUD_ACCOUNT_1);
     }
 
     private void setAccounts(Account[] accounts) {
@@ -117,7 +120,7 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
     public void testPushDeviceAccountAsDca_cloudSyncIsOff() {
         setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
 
-        mSyncSettingsHelper.turnOffSync(SYSTEM_CLOUD_ACCOUNT_1);
+        turnOffSync(SYSTEM_CLOUD_ACCOUNT_1);
 
         // SYSTEM_CLOUD_ACCOUNT_1 is signed in, but sync is turned off, thus no account is eligible
         // to be set as cloud default account.
@@ -125,7 +128,7 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
 
         // The initial DCA should be unknown, regardless of the cloud account existence and their
         // sync status.
-        mSyncSettingsHelper.turnOffSync(SYSTEM_CLOUD_ACCOUNT_1);
+        turnOffSync(SYSTEM_CLOUD_ACCOUNT_1);
         assertEquals(DefaultAccountAndState.ofNotSet(),
                 mDefaultAccountManager.pullDefaultAccount());
 
@@ -144,7 +147,7 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
                 mDefaultAccountManager.pullDefaultAccount());
 
         // Sync remains off.
-        assertTrue(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+        assertTrue(isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
 
         // Cloud account eligible for default accounts doesn't change.
         assertEquals(List.of(), mDefaultAccountManager.getEligibleCloudAccounts());
@@ -152,7 +155,7 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
 
     public void testPushCustomizedDeviceAccountAsDca_cloudSyncIsOff() {
         setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
-        mSyncSettingsHelper.turnOffSync(SYSTEM_CLOUD_ACCOUNT_1);
+        turnOffSync(SYSTEM_CLOUD_ACCOUNT_1);
 
         // SYSTEM_CLOUD_ACCOUNT_1 is signed in, but sync is turned off, thus no account is eligible
         // to be set as cloud default account.
@@ -177,7 +180,7 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
                 mDefaultAccountManager.pullDefaultAccount());
 
         // Sync remains off.
-        assertTrue(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+        assertTrue(isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
 
         // Cloud account eligible for default accounts doesn't change.
         assertEquals(List.of(), mDefaultAccountManager.getEligibleCloudAccounts());
@@ -185,7 +188,7 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
 
     public void testPushDca_dcaWasUnknown_tryPushDeviceAndThenCloudAccount() {
         setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
-        mSyncSettingsHelper.turnOnSync(SYSTEM_CLOUD_ACCOUNT_1);
+        turnOnSync(SYSTEM_CLOUD_ACCOUNT_1);
 
         assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.getEligibleCloudAccounts());
@@ -202,7 +205,7 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
         assertEquals(DefaultAccountAndState.ofLocal(),
                 mDefaultAccountManager.pullDefaultAccount());
         // Sync setting should remain to be on.
-        assertFalse(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+        assertFalse(isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
 
         // Try to set the DCA to be system cloud account, which should succeed.
         assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
@@ -211,7 +214,7 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
                 DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.pullDefaultAccount());
         // Sync setting should remain to be on.
-        assertFalse(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+        assertFalse(isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
 
         // Cloud account eligible for default accounts doesn't change.
         assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
@@ -234,7 +237,7 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
 
     public void testPushDca_dcaWasCloud() {
         setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
-        mSyncSettingsHelper.turnOnSync(SYSTEM_CLOUD_ACCOUNT_1);
+        turnOnSync(SYSTEM_CLOUD_ACCOUNT_1);
 
         assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.getEligibleCloudAccounts());
@@ -252,7 +255,7 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
         assertEquals(
                 DefaultAccountAndState.ofLocal(),
                 mDefaultAccountManager.pullDefaultAccount());
-        assertFalse(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+        assertFalse(isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
 
         // Try to set DCA to the same system cloud account again, which should succeed
         assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
@@ -260,7 +263,7 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
         assertEquals(
                 DefaultAccountAndState.ofCloud(SYSTEM_CLOUD_ACCOUNT_1),
                 mDefaultAccountManager.pullDefaultAccount());
-        assertFalse(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+        assertFalse(isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
 
         // Cloud account eligible for default accounts doesn't change.
         assertEquals(List.of(SYSTEM_CLOUD_ACCOUNT_1),
@@ -372,4 +375,16 @@ public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
             db.endTransaction();
         }
     }
+
+    private void turnOffSync(Account account) {
+        Mockito.when(mSyncSettingsHelper.isSyncOff(account)).thenReturn(true);
+    }
+
+    private void turnOnSync(Account account) {
+        Mockito.when(mSyncSettingsHelper.isSyncOff(account)).thenReturn(false);
+    }
+
+    private boolean isSyncOff(Account account) {
+        return mSyncSettingsHelper.isSyncOff(account);
+    }
 }
diff --git a/tests/src/com/android/providers/contacts/MoveRawContactsTest.java b/tests/src/com/android/providers/contacts/MoveRawContactsTest.java
index c3e022e5..b2d3c1b4 100644
--- a/tests/src/com/android/providers/contacts/MoveRawContactsTest.java
+++ b/tests/src/com/android/providers/contacts/MoveRawContactsTest.java
@@ -91,6 +91,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     DefaultAccountManager mDefaultAccountManager;
     AccountManager mMockAccountManager;
 
+    SyncSettingsHelper mSyncSettingsHelper;
+
     @Before
     @Override
     public void setUp() throws Exception {
@@ -98,8 +100,9 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
 
         mCp = (ContactsProvider2) getProvider();
         mMockAccountManager = Mockito.mock(AccountManager.class);
+        mSyncSettingsHelper = Mockito.mock(SyncSettingsHelper.class);
         mDefaultAccountManager = new DefaultAccountManager(mCp.getContext(),
-                mCp.getDatabaseHelper(), new SyncSettingsHelper(), mMockAccountManager);
+                mCp.getDatabaseHelper(), mSyncSettingsHelper, mMockAccountManager);
         mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_ACCOUNT});
         mSource = AccountWithDataSet.get(SOURCE_ACCOUNT.name, SOURCE_ACCOUNT.type, null);
         mDest = AccountWithDataSet.get(DEST_ACCOUNT.name, DEST_ACCOUNT.type, null);
@@ -114,6 +117,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
 
         mDefaultAccountManager.tryPushDefaultAccount(
                 DefaultAccountAndState.ofNotSet());
+
+        Mockito.when(mSyncSettingsHelper.isSyncOff(DEST_CLOUD_ACCOUNT)).thenReturn(false);
     }
 
     @After
@@ -394,7 +399,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveDuplicateRawContacts() {
         // create a duplicate pair of contacts
         long sourceDupeRawContactId = RawContactUtil.createRawContactWithName(mResolver,
@@ -413,7 +418,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueRawContactsWithDataRows() {
         // create a duplicate pair of contacts
         long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
@@ -441,7 +446,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueRawContacts() {
         // create a near duplicate in the destination account
         long destContactId = RawContactUtil.createRawContactWithName(
@@ -465,7 +471,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueRawContactsStubDisabled() {
         // create a near duplicate in the destination account
         long destContactId = RawContactUtil.createRawContactWithName(
@@ -489,7 +495,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueRawContactsFromNullAccount() {
         mActor.setAccounts(new Account[]{DEST_ACCOUNT});
         AccountWithDataSet source =
@@ -524,7 +531,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueRawContactsFromNullAccountToEmptyDestination() {
         mActor.setAccounts(new Account[]{DEST_ACCOUNT});
         AccountWithDataSet source =
@@ -552,7 +560,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueRawContactsToNullAccount() {
         mActor.setAccounts(new Account[]{SOURCE_ACCOUNT});
         AccountWithDataSet dest =
@@ -573,7 +582,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueRawContactsToNullAccountStubDisabled() {
         mActor.setAccounts(new Account[]{SOURCE_ACCOUNT});
         AccountWithDataSet dest =
@@ -600,7 +609,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
      * will be deleted as a duplicate.
      */
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG,
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG,
             Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
     public void testMoveUniqueRawContactWithNonPortableDataRowsFlagEnabled() {
         // create a duplicate pair of contacts
@@ -641,8 +650,9 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
      * be treated as unique.
      */
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
-    @DisableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG,
+            Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
     public void testMoveUniqueRawContactWithNonPortableDataRowsFlagDisabled() {
         // create a duplicate pair of contacts
         long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
@@ -661,13 +671,13 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
 
         // verify the unique raw contact has been moved from the old -> new account
         assertMovedRawContact(sourceRawContactId, mDest, false);
-        // all data rows should have moved with the source
+        // all data rows should have moved with the source (including the custom mimetype)
         assertDataExists(sourceRawContactId, NON_PORTABLE_MIMETYPE, "foo");
         assertDataExists(sourceRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
 
         // verify the original near duplicate contact remains unchanged
         assertMovedRawContact(destRawContactId, mDest, false);
-        // the non portable data should still not exist on the destination account
+        // the non portable data should still not exist on the old destination account contact
         assertDataDoesNotExist(destRawContactId, NON_PORTABLE_MIMETYPE, "foo");
         // the existing data row in the destination account should be unaffected
         assertDataExists(destRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
@@ -680,8 +690,9 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
      * be treated as unique.
      */
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG,
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG,
             Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueRawContactsWithNonPortableDataRowsAccountTypesMatch() {
         mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_ACCOUNT_WITH_SOURCE_TYPE});
         AccountWithDataSet dest =
@@ -719,14 +730,14 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     /**
-     * Moves a contact between source and dest where both accounts have the same account type.
-     * The contact is unique because of a non-portable data row. Because the account types match,
-     * the non-portable data row will be considered while matching the contacts and the contact will
-     * be treated as unique.
+     * Move a contact between source and dest where both account have the same account types, but
+     * the delete non-common data rows flag is disabled (so we were never going to delete custom
+     * data rows).
      */
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
-    @DisableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG,
+            Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
     public void testMoveUniqueRawContactsWithNonPortableDataRowsAccountTypesMatchFlagDisabled() {
         mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_ACCOUNT_WITH_SOURCE_TYPE});
         AccountWithDataSet dest =
@@ -765,13 +776,13 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
 
     /**
      * Moves a contact between source and dest where both accounts have the same account type.
-     * The contact is unique because of a non-portable data row. Because the account types match,
-     * the non-portable data row will be considered while matching the contacts and the contact will
-     * be treated as a duplicate.
+     * The contact is a duplicate and includes non-portable data rows. Because the account types
+     * match, the non-portable data row will be considered while matching the contacts and the
+     * contact will be treated as a duplicate.
      */
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG,
-            Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveDuplicateRawContactsWithNonPortableDataRowsAccountTypesMatch() {
         mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_ACCOUNT_WITH_SOURCE_TYPE});
         AccountWithDataSet dest =
@@ -805,14 +816,11 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     /**
-     * Moves a contact between source and dest where both accounts have the same account type.
-     * The contact is unique because of a non-portable data row. Because the account types match,
-     * the non-portable data row will be considered while matching the contacts and the contact will
-     * be treated as a duplicate.
+     * Moves a contact between source and dest where both accounts have the same account type, but
+     * the delete non-common data rows flag is disabled (so we never delete custom data rows).
      */
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
-    @DisableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_DELETE_NON_COMMON_DATA_ROWS_FLAG})
     public void testMoveDuplicateRawContactsWithNonPortableDataRowsAccountTypesMatchFlagDisabled() {
         mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_ACCOUNT_WITH_SOURCE_TYPE});
         AccountWithDataSet dest =
@@ -846,7 +854,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveDuplicateNonSystemGroup() {
         // create a duplicate pair of contacts
         long sourceDupeRawContactId = RawContactUtil.createRawContactWithName(mResolver,
@@ -876,7 +885,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueNonSystemGroup() {
         long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
                 SOURCE_ACCOUNT);
@@ -902,7 +912,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueNonSystemGroupWithSourceId() {
         // create a duplicate pair of contacts
         long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
@@ -924,7 +935,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueNonSystemGroupWithSourceIdStubsDisabled() {
         // create a duplicate pair of contacts
         long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
@@ -953,7 +964,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueRawContactsWithGroups() {
         // create a duplicate pair of contacts
         long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
@@ -996,7 +1008,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveDuplicateSystemGroup() {
         // create a duplicate pair of contacts
         long sourceDupeRawContactId = RawContactUtil.createRawContactWithName(mResolver,
@@ -1028,7 +1040,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveUniqueSystemGroup() {
         // create a duplicate pair of contacts
         long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
@@ -1053,7 +1065,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testDoNotMoveEmptyUniqueSystemGroup() {
         // create a duplicate pair of contacts
         long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
@@ -1086,7 +1098,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testDoNotMoveAutoAddSystemGroup() {
         // create a duplicate pair of contacts
         long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
@@ -1126,7 +1138,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveLocalToDefaultCloudAccount() {
         mActor.setAccounts(new Account[]{DEST_CLOUD_ACCOUNT});
         setDefaultAccountManagerAccounts(new Account[]{
@@ -1148,9 +1160,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({
-            Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG,
-            Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    @EnableFlags({Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveLocalToDefaultCloudAccount_disableIneligibleAccountMove_flagOn() {
         mActor.setAccounts(new Account[]{DEST_CLOUD_ACCOUNT});
         setDefaultAccountManagerAccounts(new Account[]{
@@ -1174,8 +1185,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
-    @DisableFlags({Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG,
+            Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
     public void testMoveLocalToIneligibleCloudAccount_disableIneligibleAccountMove_flagOff() {
         mActor.setAccounts(new Account[]{DEST_ACCOUNT});
         setDefaultAccountManagerAccounts(new Account[]{
@@ -1199,9 +1210,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({
-            Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG,
-            Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    @EnableFlags({Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveLocalToIneligibleCloudAccount_disableIneligibleAccountMove_flagOn() {
         mActor.setAccounts(new Account[]{DEST_ACCOUNT});
         setDefaultAccountManagerAccounts(new Account[]{
@@ -1227,7 +1237,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveToDefaultNonCloudAccount() {
         mActor.setAccounts(new Account[]{DEST_ACCOUNT});
         AccountWithDataSet source =
@@ -1249,7 +1259,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveFromNonLocalAccount() {
         mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_CLOUD_ACCOUNT});
         setDefaultAccountManagerAccounts(new Account[]{
@@ -1271,7 +1281,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveSimToDefaultCloudAccount() {
         mActor.setAccounts(new Account[]{SIM_ACCOUNT, DEST_CLOUD_ACCOUNT});
         setDefaultAccountManagerAccounts(new Account[]{
@@ -1295,9 +1305,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
 
 
     @Test
-    @EnableFlags({
-            Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG,
-            Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    @EnableFlags({Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveSimToDefaultCloudAccount_disableIneligibleAccountMove_flagOn() {
         mActor.setAccounts(new Account[]{SIM_ACCOUNT, DEST_CLOUD_ACCOUNT});
         setDefaultAccountManagerAccounts(new Account[]{
@@ -1322,8 +1331,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
-    @DisableFlags({Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG,
+            Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
     public void testMoveSimToIneligibleCloudAccount_disableIneligibleAccountMove_flagOff() {
         mActor.setAccounts(new Account[]{SIM_ACCOUNT, DEST_ACCOUNT});
         setDefaultAccountManagerAccounts(new Account[]{
@@ -1348,10 +1357,8 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({
-            Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG,
-            Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG
-    })
+    @EnableFlags({Flags.FLAG_DISABLE_MOVE_TO_INELIGIBLE_DEFAULT_ACCOUNT_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testMoveSimToIneligibleCloudAccount_disableIneligibleAccountMove_flagOn() {
         mActor.setAccounts(new Account[]{DEST_ACCOUNT});
         setDefaultAccountManagerAccounts(new Account[]{
@@ -1377,7 +1384,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testGetNumberContactsWithSimContacts() {
         mActor.setAccounts(new Account[]{SIM_ACCOUNT, DEST_CLOUD_ACCOUNT});
 
@@ -1406,7 +1413,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testGetNumberContactsWithLocalContacts() {
         mActor.setAccounts(new Account[]{DEST_CLOUD_ACCOUNT});
         setDefaultAccountManagerAccounts(new Account[]{
@@ -1430,7 +1437,7 @@ public class MoveRawContactsTest extends BaseContactsProvider2Test {
     }
 
     @Test
-    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    @DisableFlags({Flags.FLAG_DISABLE_CP2_ACCOUNT_MOVE_FLAG})
     public void testGetNumberContactsWithoutCloudAccount() {
         mActor.setAccounts(new Account[]{SIM_ACCOUNT});
 
diff --git a/tests/src/com/android/providers/contacts/enterprise/EnterprisePolicyGuardTest.java b/tests/src/com/android/providers/contacts/enterprise/EnterprisePolicyGuardTest.java
index cb658644..cf2ba53c 100644
--- a/tests/src/com/android/providers/contacts/enterprise/EnterprisePolicyGuardTest.java
+++ b/tests/src/com/android/providers/contacts/enterprise/EnterprisePolicyGuardTest.java
@@ -36,7 +36,7 @@ import androidx.test.filters.SmallTest;
 
 import com.android.providers.contacts.FixedAndroidTestCase;
 
-import org.mockito.Matchers;
+import org.mockito.ArgumentMatchers;
 
 import java.util.Arrays;
 import java.util.List;
@@ -294,16 +294,16 @@ public class EnterprisePolicyGuardTest extends FixedAndroidTestCase {
     private Context getMockContext(boolean isCallerIdEnabled, boolean isContactsSearchEnabled,
             boolean isManagedProfileEnabled) {
         DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
-        when(mockDpm.hasManagedProfileCallerIdAccess(Matchers.any(),Matchers.any()))
+        when(mockDpm.hasManagedProfileCallerIdAccess(ArgumentMatchers.any(),ArgumentMatchers.any()))
                 .thenReturn(isCallerIdEnabled);
-        when(mockDpm.hasManagedProfileContactsAccess(Matchers.any(),Matchers.any()))
+        when(mockDpm.hasManagedProfileContactsAccess(ArgumentMatchers.any(),ArgumentMatchers.any()))
                 .thenReturn(isContactsSearchEnabled);
 
         List<UserInfo> userInfos = MANAGED_USERINFO_LIST;
         UserManager mockUm = mock(UserManager.class);
         when(mockUm.getProcessUserId()).thenReturn(CURRENT_USER_ID);
         when(mockUm.getUsers()).thenReturn(userInfos);
-        when(mockUm.getProfiles(Matchers.anyInt())).thenReturn(userInfos);
+        when(mockUm.getProfiles(ArgumentMatchers.anyInt())).thenReturn(userInfos);
         when(mockUm.getProfileParent(WORK_USER_ID)).thenReturn(CURRENT_USER_INFO);
         when(mockUm.isQuietModeEnabled(UserHandle.of(WORK_USER_ID)))
                 .thenReturn(!isManagedProfileEnabled);
```

