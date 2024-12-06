```diff
diff --git a/Android.bp b/Android.bp
index ea7a62a..cb33ffc 100644
--- a/Android.bp
+++ b/Android.bp
@@ -57,8 +57,8 @@ android_library {
     ],
 
     libs: [
-        "framework-configinfrastructure",
-        "framework-connectivity",
+        "framework-configinfrastructure.stubs.module_lib",
+        "framework-connectivity.stubs.module_lib",
     ],
 
     lint: {
diff --git a/java/res/values-af/strings.xml b/java/res/values-af/strings.xml
index 1eadce5..75be425 100644
--- a/java/res/values-af/strings.xml
+++ b/java/res/values-af/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android se aanpasbare kennisgewings"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"speld vas"</item>
+    <item msgid="7174505163902448507">"wagwoord"</item>
+    <item msgid="3917837442156595568">"wagkode"</item>
+    <item msgid="6971032950332150936">"tweefaktor"</item>
+    <item msgid="826248726164877615">"twee-faktor"</item>
+    <item msgid="2156400793251117724">"aanmeld"</item>
+    <item msgid="3621495493711216796">"aanmelding"</item>
+    <item msgid="4652629344958695406">"meld aan"</item>
+    <item msgid="6021138326345874403">"staaf"</item>
+    <item msgid="301989899519648952">"stawing"</item>
+    <item msgid="2409846400635400651">"kode"</item>
+    <item msgid="3362500960690003002">"geheim"</item>
+    <item msgid="1542192064842556988">"verifieer"</item>
+    <item msgid="2052362882225775298">"verifikasie"</item>
+    <item msgid="4759495520595696444">"bevestig"</item>
+    <item msgid="4360404417991731370">"bevestiging"</item>
+    <item msgid="5135302120938115660">"een keer"</item>
+    <item msgid="405482768547359066">"toegang"</item>
+    <item msgid="7962233525908588330">"bekragtiging"</item>
+    <item msgid="9095545913763732113">"staaf"</item>
+    <item msgid="2601700967903477651">"enkelgebruik"</item>
+    <item msgid="1775341814323929840">"magtig"</item>
+    <item msgid="4159587727958533896">"magtiging"</item>
+    <item msgid="7199374258785307822">"persoonlike identifikasienommer"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-am/strings.xml b/java/res/values-am/strings.xml
index 6f47ddd..17c08a4 100644
--- a/java/res/values-am/strings.xml
+++ b/java/res/values-am/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"የAndroid ራስ-አስማሚ ማሳወቂያዎች"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"ፒን"</item>
+    <item msgid="7174505163902448507">"የይለፍ ቃል"</item>
+    <item msgid="3917837442156595568">"የይለፍ ኮድ"</item>
+    <item msgid="6971032950332150936">"ባለ ሁለት ደረጃ"</item>
+    <item msgid="826248726164877615">"ባለ-ሁለት ደረጃ"</item>
+    <item msgid="2156400793251117724">"መግቢያ"</item>
+    <item msgid="3621495493711216796">"ግባ"</item>
+    <item msgid="4652629344958695406">"ግባ"</item>
+    <item msgid="6021138326345874403">"ያረጋግጡ"</item>
+    <item msgid="301989899519648952">"ማረጋገጫ"</item>
+    <item msgid="2409846400635400651">"ኮድ"</item>
+    <item msgid="3362500960690003002">"ሚስጥር"</item>
+    <item msgid="1542192064842556988">"አረጋግጥ"</item>
+    <item msgid="2052362882225775298">"ማረጋገጫ"</item>
+    <item msgid="4759495520595696444">"አረጋግጥ"</item>
+    <item msgid="4360404417991731370">"ማረጋገጫ"</item>
+    <item msgid="5135302120938115660">"አንድ ጊዜ"</item>
+    <item msgid="405482768547359066">"መዳረሻ"</item>
+    <item msgid="7962233525908588330">"ማረጋገጫ"</item>
+    <item msgid="9095545913763732113">"አረጋግጥ"</item>
+    <item msgid="2601700967903477651">"ለአንድ ጊዜ ብቻ መጠቀሚያ"</item>
+    <item msgid="1775341814323929840">"ፈቃድ ይስጡ"</item>
+    <item msgid="4159587727958533896">"ፈቃድ መስጠት"</item>
+    <item msgid="7199374258785307822">"የግል መለያ ቁጥር"</item>
+    <item msgid="3860872742161492043">"ፒን"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ar/strings.xml b/java/res/values-ar/strings.xml
index 3437953..49b8f9e 100644
--- a/java/res/values-ar/strings.xml
+++ b/java/res/values-ar/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"‏الإشعارات التكيّفية لنظام Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"رقم تعريف شخصي"</item>
+    <item msgid="7174505163902448507">"كلمة مرور"</item>
+    <item msgid="3917837442156595568">"رمز مرور"</item>
+    <item msgid="6971032950332150936">"ثنائية"</item>
+    <item msgid="826248726164877615">"مصفوفة ثنائية"</item>
+    <item msgid="2156400793251117724">"تسجيل دخول"</item>
+    <item msgid="3621495493711216796">"تسجيل الدخول"</item>
+    <item msgid="4652629344958695406">"تسجيل الدخول"</item>
+    <item msgid="6021138326345874403">"مصادقة"</item>
+    <item msgid="301989899519648952">"المصادقة"</item>
+    <item msgid="2409846400635400651">"رمز"</item>
+    <item msgid="3362500960690003002">"مصفوفة سرّية"</item>
+    <item msgid="1542192064842556988">"تحقُّق"</item>
+    <item msgid="2052362882225775298">"التحقُّق"</item>
+    <item msgid="4759495520595696444">"تأكيد"</item>
+    <item msgid="4360404417991731370">"التأكيد"</item>
+    <item msgid="5135302120938115660">"مرة واحدة"</item>
+    <item msgid="405482768547359066">"دخول"</item>
+    <item msgid="7962233525908588330">"الإثبات"</item>
+    <item msgid="9095545913763732113">"إثبات"</item>
+    <item msgid="2601700967903477651">"يمكن استخدامها مرة واحدة"</item>
+    <item msgid="1775341814323929840">"سماح"</item>
+    <item msgid="4159587727958533896">"السماح"</item>
+    <item msgid="7199374258785307822">"رقم التعريف الشخصي"</item>
+    <item msgid="3860872742161492043">"‏رقم PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-as/strings.xml b/java/res/values-as/strings.xml
index 6692018..3ad596f 100644
--- a/java/res/values-as/strings.xml
+++ b/java/res/values-as/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android অভিযোজিত জাননী"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"পিন"</item>
+    <item msgid="7174505163902448507">"পাছৱৰ্ড"</item>
+    <item msgid="3917837442156595568">"পাছক’ড"</item>
+    <item msgid="6971032950332150936">"দুই পৰ্যায়"</item>
+    <item msgid="826248726164877615">"দুই পৰ্যায়"</item>
+    <item msgid="2156400793251117724">"লগ ইন কৰক"</item>
+    <item msgid="3621495493711216796">"লগ ইন কৰক"</item>
+    <item msgid="4652629344958695406">"লগ ইন কৰক"</item>
+    <item msgid="6021138326345874403">"বিশ্বাসযোগ্যতা প্ৰমাণ কৰক"</item>
+    <item msgid="301989899519648952">"বিশ্বাসযোগ্যতা প্ৰমাণীকৰণ"</item>
+    <item msgid="2409846400635400651">"ক’ড"</item>
+    <item msgid="3362500960690003002">"গোপন"</item>
+    <item msgid="1542192064842556988">"সত্যাপন কৰক"</item>
+    <item msgid="2052362882225775298">"সত্যাপন"</item>
+    <item msgid="4759495520595696444">"নিশ্চিত কৰক"</item>
+    <item msgid="4360404417991731370">"নিশ্চিতি"</item>
+    <item msgid="5135302120938115660">"এবাৰ"</item>
+    <item msgid="405482768547359066">"এক্সেছ"</item>
+    <item msgid="7962233525908588330">"মান্যতা নিৰূপণ"</item>
+    <item msgid="9095545913763732113">"মান্যতা নিৰূপণ কৰক"</item>
+    <item msgid="2601700967903477651">"এবাৰ ব্যৱহাৰ কৰিব পৰা"</item>
+    <item msgid="1775341814323929840">"কৰ্তৃত্ব প্ৰদান কৰক"</item>
+    <item msgid="4159587727958533896">"কৰ্তৃত্ব প্ৰদান কৰা"</item>
+    <item msgid="7199374258785307822">"ব্যক্তিগতভাৱে চিনি পাব পৰা নম্বৰ"</item>
+    <item msgid="3860872742161492043">"পিন"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-az/strings.xml b/java/res/values-az/strings.xml
index 23fbde4..54a2247 100644
--- a/java/res/values-az/strings.xml
+++ b/java/res/values-az/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android Adaptiv Bildirişləri"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"parol"</item>
+    <item msgid="3917837442156595568">"parol"</item>
+    <item msgid="6971032950332150936">"iki faktor"</item>
+    <item msgid="826248726164877615">"iki faktor"</item>
+    <item msgid="2156400793251117724">"giriş"</item>
+    <item msgid="3621495493711216796">"giriş"</item>
+    <item msgid="4652629344958695406">"giriş"</item>
+    <item msgid="6021138326345874403">"doğrulayın"</item>
+    <item msgid="301989899519648952">"doğrulama"</item>
+    <item msgid="2409846400635400651">"kod"</item>
+    <item msgid="3362500960690003002">"açar"</item>
+    <item msgid="1542192064842556988">"doğrulayın"</item>
+    <item msgid="2052362882225775298">"doğrulama"</item>
+    <item msgid="4759495520595696444">"təsdiqləyin"</item>
+    <item msgid="4360404417991731370">"təsdiq"</item>
+    <item msgid="5135302120938115660">"birdəfəlik"</item>
+    <item msgid="405482768547359066">"giriş"</item>
+    <item msgid="7962233525908588330">"yoxlama"</item>
+    <item msgid="9095545913763732113">"yoxlayın"</item>
+    <item msgid="2601700967903477651">"birdəfəlik istifadə"</item>
+    <item msgid="1775341814323929840">"icazə verin"</item>
+    <item msgid="4159587727958533896">"icazə"</item>
+    <item msgid="7199374258785307822">"şəxsi identifikasiya nömrəsi"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-b+sr+Latn/strings.xml b/java/res/values-b+sr+Latn/strings.xml
index a1ab8fc..82c7d40 100644
--- a/java/res/values-b+sr+Latn/strings.xml
+++ b/java/res/values-b+sr+Latn/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Prilagodljiva obaveštenja za Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"lozinka"</item>
+    <item msgid="3917837442156595568">"šifra"</item>
+    <item msgid="6971032950332150936">"u dva koraka"</item>
+    <item msgid="826248726164877615">"u dva koraka"</item>
+    <item msgid="2156400793251117724">"prijavljivanje"</item>
+    <item msgid="3621495493711216796">"prijavi me"</item>
+    <item msgid="4652629344958695406">"prijava"</item>
+    <item msgid="6021138326345874403">"potvrdite identitet"</item>
+    <item msgid="301989899519648952">"potvrda autentičnosti"</item>
+    <item msgid="2409846400635400651">"kôd"</item>
+    <item msgid="3362500960690003002">"tajna"</item>
+    <item msgid="1542192064842556988">"verifikuj"</item>
+    <item msgid="2052362882225775298">"verifikacija"</item>
+    <item msgid="4759495520595696444">"potvrdi"</item>
+    <item msgid="4360404417991731370">"potvrda"</item>
+    <item msgid="5135302120938115660">"jednokratno"</item>
+    <item msgid="405482768547359066">"pristup"</item>
+    <item msgid="7962233525908588330">"validacija"</item>
+    <item msgid="9095545913763732113">"proveri"</item>
+    <item msgid="2601700967903477651">"jedno korišćenje"</item>
+    <item msgid="1775341814323929840">"ovlasti"</item>
+    <item msgid="4159587727958533896">"ovlašćenje"</item>
+    <item msgid="7199374258785307822">"lični identifikacioni broj"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-be/strings.xml b/java/res/values-be/strings.xml
index 9043dad..973ecbb 100644
--- a/java/res/values-be/strings.xml
+++ b/java/res/values-be/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Адаптыўныя апавяшчэнні Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN-код"</item>
+    <item msgid="7174505163902448507">"пароль"</item>
+    <item msgid="3917837442156595568">"код доступу"</item>
+    <item msgid="6971032950332150936">"двухфактарная"</item>
+    <item msgid="826248726164877615">"двухфактарная"</item>
+    <item msgid="2156400793251117724">"увайсці"</item>
+    <item msgid="3621495493711216796">"уваход"</item>
+    <item msgid="4652629344958695406">"увайсці"</item>
+    <item msgid="6021138326345874403">"правесці аўтэнтыфікацыю"</item>
+    <item msgid="301989899519648952">"аўтэнтыфікацыя"</item>
+    <item msgid="2409846400635400651">"код"</item>
+    <item msgid="3362500960690003002">"сакрэт"</item>
+    <item msgid="1542192064842556988">"спраўдзіць"</item>
+    <item msgid="2052362882225775298">"спраўджанне"</item>
+    <item msgid="4759495520595696444">"пацвердзіць"</item>
+    <item msgid="4360404417991731370">"пацвярджэнне"</item>
+    <item msgid="5135302120938115660">"аднаразовы"</item>
+    <item msgid="405482768547359066">"доступ"</item>
+    <item msgid="7962233525908588330">"праверка"</item>
+    <item msgid="9095545913763732113">"праверыць"</item>
+    <item msgid="2601700967903477651">"аднаразовы"</item>
+    <item msgid="1775341814323929840">"аўтарызаваць"</item>
+    <item msgid="4159587727958533896">"аўтарызацыя"</item>
+    <item msgid="7199374258785307822">"персанальны ідэнтыфікацыйны нумар"</item>
+    <item msgid="3860872742161492043">"PIN-код"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-bg/strings.xml b/java/res/values-bg/strings.xml
index a264b88..19e62b5 100644
--- a/java/res/values-bg/strings.xml
+++ b/java/res/values-bg/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Адаптивни известия за Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"ПИН"</item>
+    <item msgid="7174505163902448507">"парола"</item>
+    <item msgid="3917837442156595568">"код за достъп"</item>
+    <item msgid="6971032950332150936">"две стъпки"</item>
+    <item msgid="826248726164877615">"две стъпки"</item>
+    <item msgid="2156400793251117724">"вход"</item>
+    <item msgid="3621495493711216796">"влизане"</item>
+    <item msgid="4652629344958695406">"влизане"</item>
+    <item msgid="6021138326345874403">"удостоверяване"</item>
+    <item msgid="301989899519648952">"удостоверение"</item>
+    <item msgid="2409846400635400651">"код"</item>
+    <item msgid="3362500960690003002">"тайно"</item>
+    <item msgid="1542192064842556988">"проверка"</item>
+    <item msgid="2052362882225775298">"удостоверение"</item>
+    <item msgid="4759495520595696444">"потвърждаване"</item>
+    <item msgid="4360404417991731370">"потвърждение"</item>
+    <item msgid="5135302120938115660">"еднократно"</item>
+    <item msgid="405482768547359066">"достъп"</item>
+    <item msgid="7962233525908588330">"утвърждение"</item>
+    <item msgid="9095545913763732113">"утвърждаване"</item>
+    <item msgid="2601700967903477651">"еднократна употреба"</item>
+    <item msgid="1775341814323929840">"оторизиране"</item>
+    <item msgid="4159587727958533896">"упълномощаване"</item>
+    <item msgid="7199374258785307822">"персонален идентификационен номер"</item>
+    <item msgid="3860872742161492043">"ПИН"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-bn/strings.xml b/java/res/values-bn/strings.xml
index 0e1c7a4..1385bb1 100644
--- a/java/res/values-bn/strings.xml
+++ b/java/res/values-bn/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android অ্যাডাপ্টিভ বিজ্ঞপ্তি"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"পিন"</item>
+    <item msgid="7174505163902448507">"পাসওয়ার্ড"</item>
+    <item msgid="3917837442156595568">"পাসকোড"</item>
+    <item msgid="6971032950332150936">"দুই ধাপে"</item>
+    <item msgid="826248726164877615">"দুই-ধাপে"</item>
+    <item msgid="2156400793251117724">"লগ-ইন"</item>
+    <item msgid="3621495493711216796">"লগ-ইন করুন"</item>
+    <item msgid="4652629344958695406">"লগ-ইন করুন"</item>
+    <item msgid="6021138326345874403">"যাচাইকরণ করুন"</item>
+    <item msgid="301989899519648952">"যাচাইকরণ"</item>
+    <item msgid="2409846400635400651">"কোড"</item>
+    <item msgid="3362500960690003002">"গোপন"</item>
+    <item msgid="1542192064842556988">"যাচাই করুন"</item>
+    <item msgid="2052362882225775298">"যাচাইকরণ"</item>
+    <item msgid="4759495520595696444">"কনফার্ম করুন"</item>
+    <item msgid="4360404417991731370">"কনফার্মেশন"</item>
+    <item msgid="5135302120938115660">"একবার"</item>
+    <item msgid="405482768547359066">"অ্যাক্সেস করুন"</item>
+    <item msgid="7962233525908588330">"যাচাইকরণ"</item>
+    <item msgid="9095545913763732113">"যাচাই করুন"</item>
+    <item msgid="2601700967903477651">"একবার ব্যবহারের জন্য"</item>
+    <item msgid="1775341814323929840">"অনুমতি দিন"</item>
+    <item msgid="4159587727958533896">"অনুমোদন"</item>
+    <item msgid="7199374258785307822">"ব্যক্তিগত শনাক্তকরণ নম্বর"</item>
+    <item msgid="3860872742161492043">"পিন"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-bs/strings.xml b/java/res/values-bs/strings.xml
index 1ebdf18..760e611 100644
--- a/java/res/values-bs/strings.xml
+++ b/java/res/values-bs/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Prilagodljiva obavještenja Androida"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"lozinka"</item>
+    <item msgid="3917837442156595568">"šifra"</item>
+    <item msgid="6971032950332150936">"dva faktora"</item>
+    <item msgid="826248726164877615">"pomoću dva faktora"</item>
+    <item msgid="2156400793251117724">"prijava"</item>
+    <item msgid="3621495493711216796">"prijava"</item>
+    <item msgid="4652629344958695406">"prijava"</item>
+    <item msgid="6021138326345874403">"autentificiraj"</item>
+    <item msgid="301989899519648952">"autentifikacija"</item>
+    <item msgid="2409846400635400651">"kôd"</item>
+    <item msgid="3362500960690003002">"tajna"</item>
+    <item msgid="1542192064842556988">"potvrdi"</item>
+    <item msgid="2052362882225775298">"potvrda"</item>
+    <item msgid="4759495520595696444">"potvrdi"</item>
+    <item msgid="4360404417991731370">"potvrda"</item>
+    <item msgid="5135302120938115660">"jednom"</item>
+    <item msgid="405482768547359066">"pristup"</item>
+    <item msgid="7962233525908588330">"potvrda"</item>
+    <item msgid="9095545913763732113">"potvrdi"</item>
+    <item msgid="2601700967903477651">"jednokratno"</item>
+    <item msgid="1775341814323929840">"odobri"</item>
+    <item msgid="4159587727958533896">"odobrenje"</item>
+    <item msgid="7199374258785307822">"lični identifikacijski broj"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ca/strings.xml b/java/res/values-ca/strings.xml
index 8e99276..c246859 100644
--- a/java/res/values-ca/strings.xml
+++ b/java/res/values-ca/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Notificacions adaptatives d\'Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"contrasenya"</item>
+    <item msgid="3917837442156595568">"contrasenya"</item>
+    <item msgid="6971032950332150936">"dos factors"</item>
+    <item msgid="826248726164877615">"dos factors"</item>
+    <item msgid="2156400793251117724">"inici de sessió"</item>
+    <item msgid="3621495493711216796">"inici de sessió"</item>
+    <item msgid="4652629344958695406">"inici de sessió"</item>
+    <item msgid="6021138326345874403">"autenticar"</item>
+    <item msgid="301989899519648952">"autenticació"</item>
+    <item msgid="2409846400635400651">"codi"</item>
+    <item msgid="3362500960690003002">"secret"</item>
+    <item msgid="1542192064842556988">"verifica"</item>
+    <item msgid="2052362882225775298">"verificació"</item>
+    <item msgid="4759495520595696444">"confirma"</item>
+    <item msgid="4360404417991731370">"confirmació"</item>
+    <item msgid="5135302120938115660">"una vegada"</item>
+    <item msgid="405482768547359066">"accés"</item>
+    <item msgid="7962233525908588330">"validació"</item>
+    <item msgid="9095545913763732113">"valida"</item>
+    <item msgid="2601700967903477651">"ús únic"</item>
+    <item msgid="1775341814323929840">"autoritza"</item>
+    <item msgid="4159587727958533896">"autorització"</item>
+    <item msgid="7199374258785307822">"número d\'identificació personal"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-cs/strings.xml b/java/res/values-cs/strings.xml
index bfe60ef..3eefeea 100644
--- a/java/res/values-cs/strings.xml
+++ b/java/res/values-cs/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Adaptivní oznámení pro Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"heslo"</item>
+    <item msgid="3917837442156595568">"kód"</item>
+    <item msgid="6971032950332150936">"dvoufázové"</item>
+    <item msgid="826248726164877615">"dvoufázové"</item>
+    <item msgid="2156400793251117724">"přihlásit se"</item>
+    <item msgid="3621495493711216796">"přihlášení"</item>
+    <item msgid="4652629344958695406">"přihlásit se"</item>
+    <item msgid="6021138326345874403">"ověřit"</item>
+    <item msgid="301989899519648952">"ověření"</item>
+    <item msgid="2409846400635400651">"kód"</item>
+    <item msgid="3362500960690003002">"tajné"</item>
+    <item msgid="1542192064842556988">"ověřit"</item>
+    <item msgid="2052362882225775298">"ověření"</item>
+    <item msgid="4759495520595696444">"potvrdit"</item>
+    <item msgid="4360404417991731370">"potvrzení"</item>
+    <item msgid="5135302120938115660">"jednorázové"</item>
+    <item msgid="405482768547359066">"přístup"</item>
+    <item msgid="7962233525908588330">"ověření"</item>
+    <item msgid="9095545913763732113">"ověřit"</item>
+    <item msgid="2601700967903477651">"jedno použití"</item>
+    <item msgid="1775341814323929840">"schválit"</item>
+    <item msgid="4159587727958533896">"autorizace"</item>
+    <item msgid="7199374258785307822">"osobní identifikační číslo"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-da/strings.xml b/java/res/values-da/strings.xml
index af1d3a0..cff7894 100644
--- a/java/res/values-da/strings.xml
+++ b/java/res/values-da/strings.xml
@@ -16,5 +16,32 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="notification_assistant" msgid="9160940242838910547">"Tilpassede Android-notifikationer"</string>
+    <string name="notification_assistant" msgid="9160940242838910547">"Adaptive Android-notifikationer"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pinkode"</item>
+    <item msgid="7174505163902448507">"adgangskode"</item>
+    <item msgid="3917837442156595568">"adgangskode"</item>
+    <item msgid="6971032950332150936">"to trin"</item>
+    <item msgid="826248726164877615">"totrins"</item>
+    <item msgid="2156400793251117724">"logge ind"</item>
+    <item msgid="3621495493711216796">"log ind"</item>
+    <item msgid="4652629344958695406">"login"</item>
+    <item msgid="6021138326345874403">"godkende"</item>
+    <item msgid="301989899519648952">"godkendelse"</item>
+    <item msgid="2409846400635400651">"kode"</item>
+    <item msgid="3362500960690003002">"hemmelig"</item>
+    <item msgid="1542192064842556988">"verificere"</item>
+    <item msgid="2052362882225775298">"verificering"</item>
+    <item msgid="4759495520595696444">"bekræft"</item>
+    <item msgid="4360404417991731370">"bekræftelse"</item>
+    <item msgid="5135302120938115660">"engangs"</item>
+    <item msgid="405482768547359066">"adgang"</item>
+    <item msgid="7962233525908588330">"validering"</item>
+    <item msgid="9095545913763732113">"validere"</item>
+    <item msgid="2601700967903477651">"engangsbrug"</item>
+    <item msgid="1775341814323929840">"godkend"</item>
+    <item msgid="4159587727958533896">"godkendelse"</item>
+    <item msgid="7199374258785307822">"personligt identifikationsnummer"</item>
+    <item msgid="3860872742161492043">"pinkode"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-de/strings.xml b/java/res/values-de/strings.xml
index 3be1595..78ee2d7 100644
--- a/java/res/values-de/strings.xml
+++ b/java/res/values-de/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Adaptive Benachrichtigungen für Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"Passwort"</item>
+    <item msgid="3917837442156595568">"Sicherheitscode"</item>
+    <item msgid="6971032950332150936">"Zwei-Faktor"</item>
+    <item msgid="826248726164877615">"Zwei-Faktor"</item>
+    <item msgid="2156400793251117724">"Anmeldung"</item>
+    <item msgid="3621495493711216796">"anmelden"</item>
+    <item msgid="4652629344958695406">"anmelden"</item>
+    <item msgid="6021138326345874403">"authentifizieren"</item>
+    <item msgid="301989899519648952">"Authentifizierung"</item>
+    <item msgid="2409846400635400651">"Code"</item>
+    <item msgid="3362500960690003002">"geheim"</item>
+    <item msgid="1542192064842556988">"bestätigen"</item>
+    <item msgid="2052362882225775298">"Bestätigung"</item>
+    <item msgid="4759495520595696444">"bestätigen"</item>
+    <item msgid="4360404417991731370">"Bestätigung"</item>
+    <item msgid="5135302120938115660">"einmalig"</item>
+    <item msgid="405482768547359066">"Zugriff"</item>
+    <item msgid="7962233525908588330">"Validierung"</item>
+    <item msgid="9095545913763732113">"validieren"</item>
+    <item msgid="2601700967903477651">"einmalig"</item>
+    <item msgid="1775341814323929840">"autorisieren"</item>
+    <item msgid="4159587727958533896">"Autorisierung"</item>
+    <item msgid="7199374258785307822">"Persönliche Identifikationsnummer"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-el/strings.xml b/java/res/values-el/strings.xml
index 0dc0b8e..57133b0 100644
--- a/java/res/values-el/strings.xml
+++ b/java/res/values-el/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Προσαρμοστικές ειδοποιήσεις Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"κωδικός πρόσβασης"</item>
+    <item msgid="3917837442156595568">"κωδικός πρόσβασης"</item>
+    <item msgid="6971032950332150936">"δύο παραγόντων"</item>
+    <item msgid="826248726164877615">"δύο παραγόντων"</item>
+    <item msgid="2156400793251117724">"σύνδεση"</item>
+    <item msgid="3621495493711216796">"σύνδεση"</item>
+    <item msgid="4652629344958695406">"σύνδεση"</item>
+    <item msgid="6021138326345874403">"έλεγχος ταυτότητας"</item>
+    <item msgid="301989899519648952">"έλεγχος ταυτότητας"</item>
+    <item msgid="2409846400635400651">"κωδικός"</item>
+    <item msgid="3362500960690003002">"μυστικό"</item>
+    <item msgid="1542192064842556988">"επαλήθευση"</item>
+    <item msgid="2052362882225775298">"επαλήθευση"</item>
+    <item msgid="4759495520595696444">"επιβεβαίωση"</item>
+    <item msgid="4360404417991731370">"επιβεβαίωση"</item>
+    <item msgid="5135302120938115660">"μία φορά"</item>
+    <item msgid="405482768547359066">"πρόσβαση"</item>
+    <item msgid="7962233525908588330">"επικύρωση"</item>
+    <item msgid="9095545913763732113">"επικύρωση"</item>
+    <item msgid="2601700967903477651">"μίας χρήσης"</item>
+    <item msgid="1775341814323929840">"εξουσιοδότηση"</item>
+    <item msgid="4159587727958533896">"εξουσιοδότηση"</item>
+    <item msgid="7199374258785307822">"προσωπικός αριθμός ταυτοποίησης"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-en-rAU/strings.xml b/java/res/values-en-rAU/strings.xml
index 24f8581..0604689 100644
--- a/java/res/values-en-rAU/strings.xml
+++ b/java/res/values-en-rAU/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android adaptive notifications"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"password"</item>
+    <item msgid="3917837442156595568">"passcode"</item>
+    <item msgid="6971032950332150936">"two factor"</item>
+    <item msgid="826248726164877615">"two-factor"</item>
+    <item msgid="2156400793251117724">"login"</item>
+    <item msgid="3621495493711216796">"log-in"</item>
+    <item msgid="4652629344958695406">"log in"</item>
+    <item msgid="6021138326345874403">"authenticate"</item>
+    <item msgid="301989899519648952">"authentication"</item>
+    <item msgid="2409846400635400651">"code"</item>
+    <item msgid="3362500960690003002">"secret"</item>
+    <item msgid="1542192064842556988">"verify"</item>
+    <item msgid="2052362882225775298">"verification"</item>
+    <item msgid="4759495520595696444">"confirm"</item>
+    <item msgid="4360404417991731370">"confirmation"</item>
+    <item msgid="5135302120938115660">"one time"</item>
+    <item msgid="405482768547359066">"access"</item>
+    <item msgid="7962233525908588330">"validation"</item>
+    <item msgid="9095545913763732113">"validate"</item>
+    <item msgid="2601700967903477651">"single use"</item>
+    <item msgid="1775341814323929840">"authorise"</item>
+    <item msgid="4159587727958533896">"authorisation"</item>
+    <item msgid="7199374258785307822">"personal identification number"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-en-rCA/strings.xml b/java/res/values-en-rCA/strings.xml
index 70258ea..b4fb261 100644
--- a/java/res/values-en-rCA/strings.xml
+++ b/java/res/values-en-rCA/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android Adaptive Notifications"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"password"</item>
+    <item msgid="3917837442156595568">"passcode"</item>
+    <item msgid="6971032950332150936">"two factor"</item>
+    <item msgid="826248726164877615">"two-factor"</item>
+    <item msgid="2156400793251117724">"login"</item>
+    <item msgid="3621495493711216796">"log-in"</item>
+    <item msgid="4652629344958695406">"log in"</item>
+    <item msgid="6021138326345874403">"authenticate"</item>
+    <item msgid="301989899519648952">"authentication"</item>
+    <item msgid="2409846400635400651">"code"</item>
+    <item msgid="3362500960690003002">"secret"</item>
+    <item msgid="1542192064842556988">"verify"</item>
+    <item msgid="2052362882225775298">"verification"</item>
+    <item msgid="4759495520595696444">"confirm"</item>
+    <item msgid="4360404417991731370">"confirmation"</item>
+    <item msgid="5135302120938115660">"one time"</item>
+    <item msgid="405482768547359066">"access"</item>
+    <item msgid="7962233525908588330">"validation"</item>
+    <item msgid="9095545913763732113">"validate"</item>
+    <item msgid="2601700967903477651">"single use"</item>
+    <item msgid="1775341814323929840">"authorize"</item>
+    <item msgid="4159587727958533896">"authorization"</item>
+    <item msgid="7199374258785307822">"personal identification number"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-en-rGB/strings.xml b/java/res/values-en-rGB/strings.xml
index 24f8581..0604689 100644
--- a/java/res/values-en-rGB/strings.xml
+++ b/java/res/values-en-rGB/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android adaptive notifications"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"password"</item>
+    <item msgid="3917837442156595568">"passcode"</item>
+    <item msgid="6971032950332150936">"two factor"</item>
+    <item msgid="826248726164877615">"two-factor"</item>
+    <item msgid="2156400793251117724">"login"</item>
+    <item msgid="3621495493711216796">"log-in"</item>
+    <item msgid="4652629344958695406">"log in"</item>
+    <item msgid="6021138326345874403">"authenticate"</item>
+    <item msgid="301989899519648952">"authentication"</item>
+    <item msgid="2409846400635400651">"code"</item>
+    <item msgid="3362500960690003002">"secret"</item>
+    <item msgid="1542192064842556988">"verify"</item>
+    <item msgid="2052362882225775298">"verification"</item>
+    <item msgid="4759495520595696444">"confirm"</item>
+    <item msgid="4360404417991731370">"confirmation"</item>
+    <item msgid="5135302120938115660">"one time"</item>
+    <item msgid="405482768547359066">"access"</item>
+    <item msgid="7962233525908588330">"validation"</item>
+    <item msgid="9095545913763732113">"validate"</item>
+    <item msgid="2601700967903477651">"single use"</item>
+    <item msgid="1775341814323929840">"authorise"</item>
+    <item msgid="4159587727958533896">"authorisation"</item>
+    <item msgid="7199374258785307822">"personal identification number"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-en-rIN/strings.xml b/java/res/values-en-rIN/strings.xml
index 24f8581..0604689 100644
--- a/java/res/values-en-rIN/strings.xml
+++ b/java/res/values-en-rIN/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android adaptive notifications"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"password"</item>
+    <item msgid="3917837442156595568">"passcode"</item>
+    <item msgid="6971032950332150936">"two factor"</item>
+    <item msgid="826248726164877615">"two-factor"</item>
+    <item msgid="2156400793251117724">"login"</item>
+    <item msgid="3621495493711216796">"log-in"</item>
+    <item msgid="4652629344958695406">"log in"</item>
+    <item msgid="6021138326345874403">"authenticate"</item>
+    <item msgid="301989899519648952">"authentication"</item>
+    <item msgid="2409846400635400651">"code"</item>
+    <item msgid="3362500960690003002">"secret"</item>
+    <item msgid="1542192064842556988">"verify"</item>
+    <item msgid="2052362882225775298">"verification"</item>
+    <item msgid="4759495520595696444">"confirm"</item>
+    <item msgid="4360404417991731370">"confirmation"</item>
+    <item msgid="5135302120938115660">"one time"</item>
+    <item msgid="405482768547359066">"access"</item>
+    <item msgid="7962233525908588330">"validation"</item>
+    <item msgid="9095545913763732113">"validate"</item>
+    <item msgid="2601700967903477651">"single use"</item>
+    <item msgid="1775341814323929840">"authorise"</item>
+    <item msgid="4159587727958533896">"authorisation"</item>
+    <item msgid="7199374258785307822">"personal identification number"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-en-rXC/strings.xml b/java/res/values-en-rXC/strings.xml
index 5fa6491..ffb4235 100644
--- a/java/res/values-en-rXC/strings.xml
+++ b/java/res/values-en-rXC/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‏‎‎‎‏‎‎‎‏‏‎‎‏‎‏‎‎‏‏‏‎‏‎‎‏‏‎‏‏‎‏‏‏‏‏‏‏‎‎‏‏‏‎‏‏‎‎‏‎‏‎‎‏‏‎Android Adaptive Notifications‎‏‎‎‏‎"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‎‏‎‎‏‏‎‏‏‎‎‎‎‏‎‏‎‏‏‎‏‏‏‏‎‏‏‏‎‎‎‏‏‎‏‎‎‎‏‎‏‎‎‎‏‎‎‏‏‎‎‎‎‎‎‏‏‎‎‏‏‎pin‎‏‎‎‏‎"</item>
+    <item msgid="7174505163902448507">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‎‎‎‏‏‏‎‎‏‎‎‎‎‏‏‏‏‎‏‏‎‎‏‏‎‏‏‏‏‎‎‏‏‎‏‎‏‏‎‎‏‏‏‎‎‎‏‏‏‎‎‏‏‎‏‏‏‏‎‏‏‎password‎‏‎‎‏‎"</item>
+    <item msgid="3917837442156595568">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‎‏‏‎‎‏‎‏‏‏‏‎‏‏‏‏‎‏‎‎‎‏‏‎‎‏‎‏‎‏‏‎‎‎‏‏‎‏‏‏‏‎‎‎‎‎‎‎‏‎‎‏‎‏‏‏‎‎‎‎‎passcode‎‏‎‎‏‎"</item>
+    <item msgid="6971032950332150936">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‎‎‎‎‎‏‎‏‏‏‏‏‎‎‎‎‏‎‏‎‏‏‎‎‎‏‎‎‎‏‏‎‎‎‎‏‎‎‎‎‏‎‏‏‏‎‏‎‏‎‏‎‎‏‎‎‏‏‎‎‎‎two factor‎‏‎‎‏‎"</item>
+    <item msgid="826248726164877615">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‎‏‎‏‏‎‏‏‏‎‏‏‏‎‏‏‎‏‏‎‎‏‏‎‏‎‏‏‎‏‎‏‏‏‎‏‏‎‎‏‎‏‏‎‏‎‎‏‏‎‎‎‏‎‎‏‎‏‏‏‏‎two-factor‎‏‎‎‏‎"</item>
+    <item msgid="2156400793251117724">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‏‏‎‏‏‏‏‎‏‏‎‏‎‎‎‏‎‎‏‏‎‎‎‏‏‎‎‎‏‎‏‎‏‎‏‏‎‎‎‏‏‎‏‎‎‏‏‏‏‎‏‎‏‎‎‏‏‏‎‎‎login‎‏‎‎‏‎"</item>
+    <item msgid="3621495493711216796">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‎‎‏‎‎‏‎‎‎‎‏‎‎‎‏‎‎‎‏‎‏‏‏‏‎‏‏‎‏‏‎‎‏‎‏‎‎‏‎‏‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‏‏‎‎‎log-in‎‏‎‎‏‎"</item>
+    <item msgid="4652629344958695406">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‎‏‎‏‏‎‏‏‏‏‎‏‎‎‎‏‎‎‎‏‏‏‎‏‎‎‏‎‎‏‎‎‎‏‏‏‏‏‏‎‏‏‏‎‎log in‎‏‎‎‏‎"</item>
+    <item msgid="6021138326345874403">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‎‏‎‎‏‏‏‎‎‎‏‏‏‏‎‏‏‎‎‎‎‏‎‏‏‎‏‎‎‎‎‎‎‎‏‏‎‏‎‏‎‏‎‏‎‏‏‏‏‏‏‎‏‏‏‏‏‎‎‎‏‏‎authenticate‎‏‎‎‏‎"</item>
+    <item msgid="301989899519648952">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‎‏‏‏‎‎‎‎‏‏‎‎‎‎‏‏‏‎‎‎‏‎‎‎‏‏‎‏‏‎‏‎‏‎‏‏‏‎‏‎‎‏‏‏‏‏‏‏‏‎‎‏‎‎‏‎‏‏‏‎‎‎‎authentication‎‏‎‎‏‎"</item>
+    <item msgid="2409846400635400651">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‎‎‎‎‏‎‏‏‏‎‎‎‏‎‏‏‏‏‏‏‎‏‎‎‎‏‎‎‎‏‎‎‏‎‎‎‏‎‎‏‎‎‎‎‎‎‏‏‏‎‎‎‏‏‏‎‎‏‎‏‏‎code‎‏‎‎‏‎"</item>
+    <item msgid="3362500960690003002">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‎‏‏‏‎‏‎‏‎‏‎‏‎‎‎‎‎‎‎‎‎‏‏‎‎‏‏‏‎‏‏‏‏‎‏‏‎‏‏‎‏‎‏‏‎‎‏‎‏‏‏‎‎‎‎‏‏‏‎‏‎‎secret‎‏‎‎‏‎"</item>
+    <item msgid="1542192064842556988">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‎‏‎‏‎‏‏‎‎‏‏‎‏‏‏‏‎‏‏‏‏‎‎‎‎‎‏‏‎‎‎‏‏‎‎‎‎‏‎‏‏‏‎‏‏‏‏‎‎‏‏‎‎‎‏‏‏‏‎‎‎verify‎‏‎‎‏‎"</item>
+    <item msgid="2052362882225775298">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‏‏‎‎‎‏‏‏‏‎‏‏‎‏‏‏‎‏‎‏‎‎‏‎‏‎‏‎‏‏‏‎‎‎‎‏‎‏‎‎‎‎‏‏‏‎‏‎‎‎‏‎‏‏‎‎‎‎‏‎‎verification‎‏‎‎‏‎"</item>
+    <item msgid="4759495520595696444">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‎‎‎‎‏‎‎‎‎‎‏‏‎‏‎‎‎‏‏‏‏‏‏‏‏‏‎‏‎‏‏‎‎‎‎‏‏‏‎‎‏‎‏‎‏‏‎‏‎‏‏‎‏‏‎‎‏‏‏‏‎‎‎confirm‎‏‎‎‏‎"</item>
+    <item msgid="4360404417991731370">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‏‏‎‎‏‎‎‎‎‎‏‏‎‏‎‎‎‏‎‎‏‎‏‏‎‏‏‏‎‎‏‏‏‎‏‏‎‏‏‏‎‎‎‎‏‏‏‎‏‎‎‎‏‎‏‎‏‎‏‎‎confirmation‎‏‎‎‏‎"</item>
+    <item msgid="5135302120938115660">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‎‎‎‏‏‏‎‏‎‎‎‏‎‎‎‏‎‎‎‎‏‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‎‎‏‏‎‏‎‎‏‏‏‎‎‏‎‎‏‎‎‏‎‎‏‏‎‎‎one time‎‏‎‎‏‎"</item>
+    <item msgid="405482768547359066">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‎‏‏‏‎‏‏‎‏‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‎‏‏‎‏‏‏‏‏‏‏‎‏‏‏‎‎‏‏‏‎‏‎‏‎‏‎‎‏‎‏‎‏‏‎‏‎‎access‎‏‎‎‏‎"</item>
+    <item msgid="7962233525908588330">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‎‏‏‏‎‎‏‏‏‏‏‏‏‏‎‎‎‏‎‎‏‎‎‏‏‎‏‎‎‏‏‎‎‎‎‏‎‎‏‏‏‏‏‎‎‏‏‎‎‎‏‏‏‎‎‏‎‏‎‏‎‎validation‎‏‎‎‏‎"</item>
+    <item msgid="9095545913763732113">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‎‏‏‏‎‎‏‏‏‎‏‏‏‏‎‏‏‎‏‎‎‎‏‎‏‏‏‏‏‎‎‎‎‏‎‎‏‎‎‏‎‎‏‏‎‏‎‏‎‎‏‎‎‎‏‎validate‎‏‎‎‏‎"</item>
+    <item msgid="2601700967903477651">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‎‎‏‎‎‎‎‎‏‏‎‏‏‎‎‎‏‏‎‎‏‎‎‏‏‏‏‏‎‏‏‏‏‎‎‏‏‏‎‏‎‏‏‎‏‎‎‏‏‏‏‏‏‏‎‎‏‎‎‏‏‎single use‎‏‎‎‏‎"</item>
+    <item msgid="1775341814323929840">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‏‎‎‎‏‎‏‎‎‎‏‏‎‏‎‎‎‏‏‏‏‏‏‏‏‎‎‏‎‏‎‏‎‏‎‏‏‎‏‎‏‏‎‎‏‏‏‎‎‎‏‎‏‏‏‏‎‎‎‎‎authorize‎‏‎‎‏‎"</item>
+    <item msgid="4159587727958533896">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‏‎‎‏‏‎‏‏‏‎‎‏‏‏‎‏‎‎‏‏‎‎‎‎‎‎‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‎‏‎‏‏‏‎‎‏‏‏‎‎‎‎‏‎‎‎‎authorization‎‏‎‎‏‎"</item>
+    <item msgid="7199374258785307822">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‎‎‎‏‏‏‏‏‎‏‎‎‏‎‏‎‏‎‎‎‎‏‎‏‏‏‏‏‎‏‎‎‏‎‎‏‏‏‏‏‏‏‏‎‏‎‏‎‎‏‏‎‎‏‎‏‎‏‏‏‎‎personal identification number‎‏‎‎‏‎"</item>
+    <item msgid="3860872742161492043">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‎‏‎‏‏‎‎‏‎‏‎‎‏‎‎‏‎‎‏‏‎‏‎‎‏‏‎‏‏‎‎‏‏‏‏‏‏‎‎‎‎‏‏‎‎‎‏‎‏‎‎‎‎‏‎‎‏‎‏‏‎PIN‎‏‎‎‏‎"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-es-rUS/strings.xml b/java/res/values-es-rUS/strings.xml
index 76c69db..1ae7a0b 100644
--- a/java/res/values-es-rUS/strings.xml
+++ b/java/res/values-es-rUS/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Notificaciones adaptables de Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"contraseña"</item>
+    <item msgid="3917837442156595568">"contraseña"</item>
+    <item msgid="6971032950332150936">"de dos factores"</item>
+    <item msgid="826248726164877615">"de dos factores"</item>
+    <item msgid="2156400793251117724">"acceso"</item>
+    <item msgid="3621495493711216796">"acceder"</item>
+    <item msgid="4652629344958695406">"acceder"</item>
+    <item msgid="6021138326345874403">"autenticar"</item>
+    <item msgid="301989899519648952">"autenticación"</item>
+    <item msgid="2409846400635400651">"código"</item>
+    <item msgid="3362500960690003002">"secreta"</item>
+    <item msgid="1542192064842556988">"verificar"</item>
+    <item msgid="2052362882225775298">"verificación"</item>
+    <item msgid="4759495520595696444">"confirmar"</item>
+    <item msgid="4360404417991731370">"confirmación"</item>
+    <item msgid="5135302120938115660">"una vez"</item>
+    <item msgid="405482768547359066">"acceder"</item>
+    <item msgid="7962233525908588330">"validación"</item>
+    <item msgid="9095545913763732113">"validar"</item>
+    <item msgid="2601700967903477651">"uso único"</item>
+    <item msgid="1775341814323929840">"autorizar"</item>
+    <item msgid="4159587727958533896">"autorización"</item>
+    <item msgid="7199374258785307822">"número de identificación personal"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-es/strings.xml b/java/res/values-es/strings.xml
index eb08c2b..93bff01 100644
--- a/java/res/values-es/strings.xml
+++ b/java/res/values-es/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Notificaciones adaptativas de Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"contraseña"</item>
+    <item msgid="3917837442156595568">"contraseña"</item>
+    <item msgid="6971032950332150936">"dos factores"</item>
+    <item msgid="826248726164877615">"dos factores"</item>
+    <item msgid="2156400793251117724">"iniciar sesión"</item>
+    <item msgid="3621495493711216796">"iniciar sesión"</item>
+    <item msgid="4652629344958695406">"iniciar sesión"</item>
+    <item msgid="6021138326345874403">"autenticar"</item>
+    <item msgid="301989899519648952">"autenticación"</item>
+    <item msgid="2409846400635400651">"código"</item>
+    <item msgid="3362500960690003002">"secreto"</item>
+    <item msgid="1542192064842556988">"verificar"</item>
+    <item msgid="2052362882225775298">"verificación"</item>
+    <item msgid="4759495520595696444">"confirmar"</item>
+    <item msgid="4360404417991731370">"confirmación"</item>
+    <item msgid="5135302120938115660">"una vez"</item>
+    <item msgid="405482768547359066">"acceder"</item>
+    <item msgid="7962233525908588330">"validación"</item>
+    <item msgid="9095545913763732113">"validar"</item>
+    <item msgid="2601700967903477651">"para uso específico"</item>
+    <item msgid="1775341814323929840">"autorizar"</item>
+    <item msgid="4159587727958533896">"autorización"</item>
+    <item msgid="7199374258785307822">"número de identificación personal"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-et/strings.xml b/java/res/values-et/strings.xml
index 1be975f..2d0eca0 100644
--- a/java/res/values-et/strings.xml
+++ b/java/res/values-et/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Androidi kohanduvad märguanded"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN-kood"</item>
+    <item msgid="7174505163902448507">"parool"</item>
+    <item msgid="3917837442156595568">"pääsukood"</item>
+    <item msgid="6971032950332150936">"kaheastmeline"</item>
+    <item msgid="826248726164877615">"kahe astmega"</item>
+    <item msgid="2156400793251117724">"sisselogimine"</item>
+    <item msgid="3621495493711216796">"sisse logimine"</item>
+    <item msgid="4652629344958695406">"logi sisse"</item>
+    <item msgid="6021138326345874403">"autendi"</item>
+    <item msgid="301989899519648952">"autentimine"</item>
+    <item msgid="2409846400635400651">"kood"</item>
+    <item msgid="3362500960690003002">"salajane"</item>
+    <item msgid="1542192064842556988">"kinnita"</item>
+    <item msgid="2052362882225775298">"kinnitamine"</item>
+    <item msgid="4759495520595696444">"kinnita"</item>
+    <item msgid="4360404417991731370">"kinnitus"</item>
+    <item msgid="5135302120938115660">"ühekordne"</item>
+    <item msgid="405482768547359066">"juurdepääs"</item>
+    <item msgid="7962233525908588330">"valideerimine"</item>
+    <item msgid="9095545913763732113">"valideeri"</item>
+    <item msgid="2601700967903477651">"ühekordne kasutus"</item>
+    <item msgid="1775341814323929840">"volita"</item>
+    <item msgid="4159587727958533896">"volitamine"</item>
+    <item msgid="7199374258785307822">"personaalne identifitseerimisnumber"</item>
+    <item msgid="3860872742161492043">"PIN-kood"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-eu/strings.xml b/java/res/values-eu/strings.xml
index 76e228b..a8c3b6e 100644
--- a/java/res/values-eu/strings.xml
+++ b/java/res/values-eu/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android-en jakinarazpen egokituak"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PINa"</item>
+    <item msgid="7174505163902448507">"pasahitza"</item>
+    <item msgid="3917837442156595568">"pasakodea"</item>
+    <item msgid="6971032950332150936">"2 faktorekoa"</item>
+    <item msgid="826248726164877615">"2 faktorekoa"</item>
+    <item msgid="2156400793251117724">"hasi saioa"</item>
+    <item msgid="3621495493711216796">"saio-hasiera"</item>
+    <item msgid="4652629344958695406">"hasi saioa"</item>
+    <item msgid="6021138326345874403">"autentifikatu"</item>
+    <item msgid="301989899519648952">"autentifikazioa"</item>
+    <item msgid="2409846400635400651">"kodea"</item>
+    <item msgid="3362500960690003002">"sekretua"</item>
+    <item msgid="1542192064842556988">"egiaztatu"</item>
+    <item msgid="2052362882225775298">"egiaztapena"</item>
+    <item msgid="4759495520595696444">"berretsi"</item>
+    <item msgid="4360404417991731370">"berrespena"</item>
+    <item msgid="5135302120938115660">"behin"</item>
+    <item msgid="405482768547359066">"sarbidea"</item>
+    <item msgid="7962233525908588330">"baliozkotzea"</item>
+    <item msgid="9095545913763732113">"baliozkotu"</item>
+    <item msgid="2601700967903477651">"erabilera bakarrekoa"</item>
+    <item msgid="1775341814323929840">"baimena eman"</item>
+    <item msgid="4159587727958533896">"baimena"</item>
+    <item msgid="7199374258785307822">"identifikazio-zenbaki pertsonala"</item>
+    <item msgid="3860872742161492043">"PINa"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-fa/strings.xml b/java/res/values-fa/strings.xml
index bc4ce1d..b34184b 100644
--- a/java/res/values-fa/strings.xml
+++ b/java/res/values-fa/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"‏اعلان‌های تطبیقی Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"پین"</item>
+    <item msgid="7174505163902448507">"گذرواژه"</item>
+    <item msgid="3917837442156595568">"گذرنویسه"</item>
+    <item msgid="6971032950332150936">"دوعاملی"</item>
+    <item msgid="826248726164877615">"دوعاملی"</item>
+    <item msgid="2156400793251117724">"ورود به سیستم"</item>
+    <item msgid="3621495493711216796">"وارد شدن به سیستم"</item>
+    <item msgid="4652629344958695406">"به سیستم وارد شدن"</item>
+    <item msgid="6021138326345874403">"اصالت‌سنجی کردن"</item>
+    <item msgid="301989899519648952">"اصالت‌سنجی"</item>
+    <item msgid="2409846400635400651">"کد"</item>
+    <item msgid="3362500960690003002">"مخفی"</item>
+    <item msgid="1542192064842556988">"درستی‌سنجی کردن"</item>
+    <item msgid="2052362882225775298">"درستی‌سنجی"</item>
+    <item msgid="4759495520595696444">"تأیید کردن"</item>
+    <item msgid="4360404417991731370">"تأیید"</item>
+    <item msgid="5135302120938115660">"یک‌بارمصرف"</item>
+    <item msgid="405482768547359066">"دسترسی"</item>
+    <item msgid="7962233525908588330">"اعتبارسنجی"</item>
+    <item msgid="9095545913763732113">"اعتبارسنجی کردن"</item>
+    <item msgid="2601700967903477651">"تک‌مصرف"</item>
+    <item msgid="1775341814323929840">"تنفیذ کردن"</item>
+    <item msgid="4159587727958533896">"تنفیذ"</item>
+    <item msgid="7199374258785307822">"شماره شناسایی شخصی"</item>
+    <item msgid="3860872742161492043">"پین"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-fi/strings.xml b/java/res/values-fi/strings.xml
index c3ba10c..feb25ef 100644
--- a/java/res/values-fi/strings.xml
+++ b/java/res/values-fi/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Androidin mukautuvat ilmoitukset"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin-koodi"</item>
+    <item msgid="7174505163902448507">"salasana"</item>
+    <item msgid="3917837442156595568">"tunnuskoodi"</item>
+    <item msgid="6971032950332150936">"kaksivaiheinen"</item>
+    <item msgid="826248726164877615">"kaksivaiheinen"</item>
+    <item msgid="2156400793251117724">"kirjautuminen"</item>
+    <item msgid="3621495493711216796">"kirjautua sisään"</item>
+    <item msgid="4652629344958695406">"kirjautua sisään"</item>
+    <item msgid="6021138326345874403">"todenna"</item>
+    <item msgid="301989899519648952">"todennus"</item>
+    <item msgid="2409846400635400651">"koodi"</item>
+    <item msgid="3362500960690003002">"salainen"</item>
+    <item msgid="1542192064842556988">"vahvista"</item>
+    <item msgid="2052362882225775298">"vahvistus"</item>
+    <item msgid="4759495520595696444">"vahvista"</item>
+    <item msgid="4360404417991731370">"vahvistus"</item>
+    <item msgid="5135302120938115660">"kerran"</item>
+    <item msgid="405482768547359066">"pääsy"</item>
+    <item msgid="7962233525908588330">"vahvistaminen"</item>
+    <item msgid="9095545913763732113">"vahvista"</item>
+    <item msgid="2601700967903477651">"kertakäyttöinen"</item>
+    <item msgid="1775341814323929840">"valtuuta"</item>
+    <item msgid="4159587727958533896">"valtuutus"</item>
+    <item msgid="7199374258785307822">"henkilötunnus"</item>
+    <item msgid="3860872742161492043">"PIN-koodi"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-fr-rCA/strings.xml b/java/res/values-fr-rCA/strings.xml
index b1d4474..0449558 100644
--- a/java/res/values-fr-rCA/strings.xml
+++ b/java/res/values-fr-rCA/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Notifications adaptatives Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"nip"</item>
+    <item msgid="7174505163902448507">"mot de passe"</item>
+    <item msgid="3917837442156595568">"mot de passe"</item>
+    <item msgid="6971032950332150936">"deux facteurs"</item>
+    <item msgid="826248726164877615">"à deux facteurs"</item>
+    <item msgid="2156400793251117724">"connexion"</item>
+    <item msgid="3621495493711216796">"connexion"</item>
+    <item msgid="4652629344958695406">"se connecter"</item>
+    <item msgid="6021138326345874403">"authentifier"</item>
+    <item msgid="301989899519648952">"authentification"</item>
+    <item msgid="2409846400635400651">"code"</item>
+    <item msgid="3362500960690003002">"secret"</item>
+    <item msgid="1542192064842556988">"vérifier"</item>
+    <item msgid="2052362882225775298">"vérification"</item>
+    <item msgid="4759495520595696444">"confirmer"</item>
+    <item msgid="4360404417991731370">"confirmation"</item>
+    <item msgid="5135302120938115660">"une fois"</item>
+    <item msgid="405482768547359066">"accès"</item>
+    <item msgid="7962233525908588330">"vérification"</item>
+    <item msgid="9095545913763732113">"vérifier"</item>
+    <item msgid="2601700967903477651">"usage unique"</item>
+    <item msgid="1775341814323929840">"autoriser"</item>
+    <item msgid="4159587727958533896">"autorisation"</item>
+    <item msgid="7199374258785307822">"numéro d\'identification personnel"</item>
+    <item msgid="3860872742161492043">"NIP"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-fr/strings.xml b/java/res/values-fr/strings.xml
index 6143ef4..f1ca83f 100644
--- a/java/res/values-fr/strings.xml
+++ b/java/res/values-fr/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Notifications intelligentes Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"code"</item>
+    <item msgid="7174505163902448507">"mot de passe"</item>
+    <item msgid="3917837442156595568">"code secret"</item>
+    <item msgid="6971032950332150936">"deux facteurs"</item>
+    <item msgid="826248726164877615">"à deux facteurs"</item>
+    <item msgid="2156400793251117724">"connexion"</item>
+    <item msgid="3621495493711216796">"connexion"</item>
+    <item msgid="4652629344958695406">"connecter"</item>
+    <item msgid="6021138326345874403">"s\'authentifier"</item>
+    <item msgid="301989899519648952">"authentification"</item>
+    <item msgid="2409846400635400651">"code"</item>
+    <item msgid="3362500960690003002">"secret"</item>
+    <item msgid="1542192064842556988">"valider"</item>
+    <item msgid="2052362882225775298">"validation"</item>
+    <item msgid="4759495520595696444">"confirmer"</item>
+    <item msgid="4360404417991731370">"confirmation"</item>
+    <item msgid="5135302120938115660">"ponctuel"</item>
+    <item msgid="405482768547359066">"accès"</item>
+    <item msgid="7962233525908588330">"validation"</item>
+    <item msgid="9095545913763732113">"valider"</item>
+    <item msgid="2601700967903477651">"usage unique"</item>
+    <item msgid="1775341814323929840">"autoriser"</item>
+    <item msgid="4159587727958533896">"autorisation"</item>
+    <item msgid="7199374258785307822">"numéro d\'identification personnel"</item>
+    <item msgid="3860872742161492043">"code"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-gl/strings.xml b/java/res/values-gl/strings.xml
index d01392e..f92cc03 100644
--- a/java/res/values-gl/strings.xml
+++ b/java/res/values-gl/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Notificacións intelixentes de Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"contrasinal"</item>
+    <item msgid="3917837442156595568">"contrasinal"</item>
+    <item msgid="6971032950332150936">"dous factores"</item>
+    <item msgid="826248726164877615">"dous factores"</item>
+    <item msgid="2156400793251117724">"inicio de sesión"</item>
+    <item msgid="3621495493711216796">"acceso"</item>
+    <item msgid="4652629344958695406">"iniciar sesión"</item>
+    <item msgid="6021138326345874403">"autenticar"</item>
+    <item msgid="301989899519648952">"autenticación"</item>
+    <item msgid="2409846400635400651">"código"</item>
+    <item msgid="3362500960690003002">"segredo"</item>
+    <item msgid="1542192064842556988">"verificar"</item>
+    <item msgid="2052362882225775298">"verificación"</item>
+    <item msgid="4759495520595696444">"confirmar"</item>
+    <item msgid="4360404417991731370">"confirmación"</item>
+    <item msgid="5135302120938115660">"unha vez"</item>
+    <item msgid="405482768547359066">"acceso"</item>
+    <item msgid="7962233525908588330">"validación"</item>
+    <item msgid="9095545913763732113">"validar"</item>
+    <item msgid="2601700967903477651">"uso único"</item>
+    <item msgid="1775341814323929840">"autorizar"</item>
+    <item msgid="4159587727958533896">"autorización"</item>
+    <item msgid="7199374258785307822">"número de identificación persoal"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-gu/strings.xml b/java/res/values-gu/strings.xml
index 78a29ac..8dc6953 100644
--- a/java/res/values-gu/strings.xml
+++ b/java/res/values-gu/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android માટે અનુકૂળ નોટિફિકેશન"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"પિન"</item>
+    <item msgid="7174505163902448507">"પાસવર્ડ"</item>
+    <item msgid="3917837442156595568">"પાસકોડ"</item>
+    <item msgid="6971032950332150936">"બે પરિબળ"</item>
+    <item msgid="826248726164877615">"બે-પરિબળ"</item>
+    <item msgid="2156400793251117724">"લૉગ ઇન"</item>
+    <item msgid="3621495493711216796">"લૉગ-ઇન"</item>
+    <item msgid="4652629344958695406">"લૉગ ઇન કરો"</item>
+    <item msgid="6021138326345874403">"ખાતરી કરો"</item>
+    <item msgid="301989899519648952">"પ્રમાણીકરણ"</item>
+    <item msgid="2409846400635400651">"કોડ"</item>
+    <item msgid="3362500960690003002">"ગુપ્ત"</item>
+    <item msgid="1542192064842556988">"ચકાસણી કરો"</item>
+    <item msgid="2052362882225775298">"ચકાસણી"</item>
+    <item msgid="4759495520595696444">"કન્ફર્મ કરો"</item>
+    <item msgid="4360404417991731370">"કન્ફર્મેશન"</item>
+    <item msgid="5135302120938115660">"એક વખત"</item>
+    <item msgid="405482768547359066">"ઍક્સેસ"</item>
+    <item msgid="7962233525908588330">"પ્રમાણીકરણ"</item>
+    <item msgid="9095545913763732113">"પ્રમાણિત કરો"</item>
+    <item msgid="2601700967903477651">"એક વખતના ઉપયોગ માટે"</item>
+    <item msgid="1775341814323929840">"અધિકૃત કરો"</item>
+    <item msgid="4159587727958533896">"અધિકરણ"</item>
+    <item msgid="7199374258785307822">"વ્યક્તિગત ઓળખાણ નંબર"</item>
+    <item msgid="3860872742161492043">"પિન"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-hi/strings.xml b/java/res/values-hi/strings.xml
index 8ea5adb..4899fd3 100644
--- a/java/res/values-hi/strings.xml
+++ b/java/res/values-hi/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"ज़रूरत के हिसाब से सूचनाएं पाने की Android की सुविधा"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"पिन"</item>
+    <item msgid="7174505163902448507">"पासवर्ड"</item>
+    <item msgid="3917837442156595568">"पासवर्ड"</item>
+    <item msgid="6971032950332150936">"टू फ़ैक्टर"</item>
+    <item msgid="826248726164877615">"टू-फ़ैक्टर"</item>
+    <item msgid="2156400793251117724">"लॉगिन"</item>
+    <item msgid="3621495493711216796">"लॉग-इन"</item>
+    <item msgid="4652629344958695406">"लॉग इन"</item>
+    <item msgid="6021138326345874403">"ऑथेंटिकेट करें"</item>
+    <item msgid="301989899519648952">"ऑथेंटिकेशन"</item>
+    <item msgid="2409846400635400651">"कोड"</item>
+    <item msgid="3362500960690003002">"सीक्रेट"</item>
+    <item msgid="1542192064842556988">"वेरिफ़ाई करें"</item>
+    <item msgid="2052362882225775298">"वेरिफ़िकेशन"</item>
+    <item msgid="4759495520595696444">"कंफ़र्म करें"</item>
+    <item msgid="4360404417991731370">"कंफ़र्मेशन"</item>
+    <item msgid="5135302120938115660">"एक बार"</item>
+    <item msgid="405482768547359066">"ऐक्सेस करें"</item>
+    <item msgid="7962233525908588330">"वैलिडेशन"</item>
+    <item msgid="9095545913763732113">"वैलिडेट करें"</item>
+    <item msgid="2601700967903477651">"एक बार इस्तेमाल किया जा सकने वाला"</item>
+    <item msgid="1775341814323929840">"ऑथराइज़ करें"</item>
+    <item msgid="4159587727958533896">"ऑथराइज़ेशन"</item>
+    <item msgid="7199374258785307822">"व्यक्तिगत पहचान संख्या"</item>
+    <item msgid="3860872742161492043">"पिन"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-hr/strings.xml b/java/res/values-hr/strings.xml
index c56e363..631820c 100644
--- a/java/res/values-hr/strings.xml
+++ b/java/res/values-hr/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Prilagodljive obavijesti za Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"zaporka"</item>
+    <item msgid="3917837442156595568">"šifra"</item>
+    <item msgid="6971032950332150936">"u dva koraka"</item>
+    <item msgid="826248726164877615">"u dva koraka"</item>
+    <item msgid="2156400793251117724">"prijava"</item>
+    <item msgid="3621495493711216796">"prijavljivanje"</item>
+    <item msgid="4652629344958695406">"prijavljivanje"</item>
+    <item msgid="6021138326345874403">"autentificiraj"</item>
+    <item msgid="301989899519648952">"autentifikacija"</item>
+    <item msgid="2409846400635400651">"kôd"</item>
+    <item msgid="3362500960690003002">"tajna"</item>
+    <item msgid="1542192064842556988">"potvrdi"</item>
+    <item msgid="2052362882225775298">"potvrda"</item>
+    <item msgid="4759495520595696444">"potvrdi"</item>
+    <item msgid="4360404417991731370">"potvrda"</item>
+    <item msgid="5135302120938115660">"jednokratno"</item>
+    <item msgid="405482768547359066">"pristup"</item>
+    <item msgid="7962233525908588330">"provjera valjanosti"</item>
+    <item msgid="9095545913763732113">"provjeri valjanost"</item>
+    <item msgid="2601700967903477651">"jednokratna upotreba"</item>
+    <item msgid="1775341814323929840">"autoriziraj"</item>
+    <item msgid="4159587727958533896">"autorizacija"</item>
+    <item msgid="7199374258785307822">"osobni identifikacijski broj"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-hu/strings.xml b/java/res/values-hu/strings.xml
index cd8c1c8..b668e7b 100644
--- a/java/res/values-hu/strings.xml
+++ b/java/res/values-hu/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android Alkalmazkodó értesítések"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN-kód"</item>
+    <item msgid="7174505163902448507">"jelszó"</item>
+    <item msgid="3917837442156595568">"biztonsági kód"</item>
+    <item msgid="6971032950332150936">"kétlépcsős"</item>
+    <item msgid="826248726164877615">"kétlépcsős"</item>
+    <item msgid="2156400793251117724">"bejelentkezés"</item>
+    <item msgid="3621495493711216796">"bejelentkezés"</item>
+    <item msgid="4652629344958695406">"bejelentkezik"</item>
+    <item msgid="6021138326345874403">"hitelesít"</item>
+    <item msgid="301989899519648952">"hitelesítés"</item>
+    <item msgid="2409846400635400651">"kód"</item>
+    <item msgid="3362500960690003002">"titok"</item>
+    <item msgid="1542192064842556988">"ellenőriz"</item>
+    <item msgid="2052362882225775298">"ellenőrzés"</item>
+    <item msgid="4759495520595696444">"megerősít"</item>
+    <item msgid="4360404417991731370">"megerősítés"</item>
+    <item msgid="5135302120938115660">"egyszeri"</item>
+    <item msgid="405482768547359066">"hozzáférés"</item>
+    <item msgid="7962233525908588330">"érvényesítés"</item>
+    <item msgid="9095545913763732113">"érvényesít"</item>
+    <item msgid="2601700967903477651">"egyszer használatos"</item>
+    <item msgid="1775341814323929840">"engedélyez"</item>
+    <item msgid="4159587727958533896">"engedélyezés"</item>
+    <item msgid="7199374258785307822">"személyi azonosító szám"</item>
+    <item msgid="3860872742161492043">"PIN-kód"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-hy/strings.xml b/java/res/values-hy/strings.xml
index 7b3317e..5e4828f 100644
--- a/java/res/values-hy/strings.xml
+++ b/java/res/values-hy/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android-ի հարմարվող ծանուցումներ"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN կոդ"</item>
+    <item msgid="7174505163902448507">"գաղտնաբառ"</item>
+    <item msgid="3917837442156595568">"անցակոդ"</item>
+    <item msgid="6971032950332150936">"երկգործոն"</item>
+    <item msgid="826248726164877615">"երկգործոն"</item>
+    <item msgid="2156400793251117724">"մուտք"</item>
+    <item msgid="3621495493711216796">"մտնել"</item>
+    <item msgid="4652629344958695406">"մուտք գործել"</item>
+    <item msgid="6021138326345874403">"իսկորոշել"</item>
+    <item msgid="301989899519648952">"իսկորոշում"</item>
+    <item msgid="2409846400635400651">"կոդ"</item>
+    <item msgid="3362500960690003002">"գաղտնի"</item>
+    <item msgid="1542192064842556988">"ստուգել"</item>
+    <item msgid="2052362882225775298">"ստուգում"</item>
+    <item msgid="4759495520595696444">"հաստատել"</item>
+    <item msgid="4360404417991731370">"հաստատում"</item>
+    <item msgid="5135302120938115660">"մեկ անգամ"</item>
+    <item msgid="405482768547359066">"հասանելիություն"</item>
+    <item msgid="7962233525908588330">"ստուգում"</item>
+    <item msgid="9095545913763732113">"ստուգել"</item>
+    <item msgid="2601700967903477651">"մեկանգամյա օգտագործում"</item>
+    <item msgid="1775341814323929840">"թույլատրել"</item>
+    <item msgid="4159587727958533896">"թույլտվություն"</item>
+    <item msgid="7199374258785307822">"անձնական նույնականացման համար"</item>
+    <item msgid="3860872742161492043">"PIN կոդ"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-in/strings.xml b/java/res/values-in/strings.xml
index b9807cd..c5db50f 100644
--- a/java/res/values-in/strings.xml
+++ b/java/res/values-in/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Notifikasi Adaptif Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"sandi"</item>
+    <item msgid="3917837442156595568">"kode sandi"</item>
+    <item msgid="6971032950332150936">"dua faktor"</item>
+    <item msgid="826248726164877615">"dua faktor"</item>
+    <item msgid="2156400793251117724">"login"</item>
+    <item msgid="3621495493711216796">"login"</item>
+    <item msgid="4652629344958695406">"login"</item>
+    <item msgid="6021138326345874403">"autentikasi"</item>
+    <item msgid="301989899519648952">"autentikasi"</item>
+    <item msgid="2409846400635400651">"kode"</item>
+    <item msgid="3362500960690003002">"rahasia"</item>
+    <item msgid="1542192064842556988">"verifikasi"</item>
+    <item msgid="2052362882225775298">"verifikasi"</item>
+    <item msgid="4759495520595696444">"konfirmasi"</item>
+    <item msgid="4360404417991731370">"konfirmasi"</item>
+    <item msgid="5135302120938115660">"satu kali"</item>
+    <item msgid="405482768547359066">"akses"</item>
+    <item msgid="7962233525908588330">"validasi"</item>
+    <item msgid="9095545913763732113">"validasi"</item>
+    <item msgid="2601700967903477651">"sekali pakai"</item>
+    <item msgid="1775341814323929840">"otorisasi"</item>
+    <item msgid="4159587727958533896">"otorisasi"</item>
+    <item msgid="7199374258785307822">"nomor identifikasi pribadi"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-is/strings.xml b/java/res/values-is/strings.xml
index 9ac90c4..90afae0 100644
--- a/java/res/values-is/strings.xml
+++ b/java/res/values-is/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Breytilegar tilkynningar í Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"festa"</item>
+    <item msgid="7174505163902448507">"aðgangsorð"</item>
+    <item msgid="3917837442156595568">"aðgangskóði"</item>
+    <item msgid="6971032950332150936">"tvíþætt"</item>
+    <item msgid="826248726164877615">"tvíþætt"</item>
+    <item msgid="2156400793251117724">"innskráning"</item>
+    <item msgid="3621495493711216796">"innskráning"</item>
+    <item msgid="4652629344958695406">"skrá inn"</item>
+    <item msgid="6021138326345874403">"auðkenna"</item>
+    <item msgid="301989899519648952">"auðkenning"</item>
+    <item msgid="2409846400635400651">"kóði"</item>
+    <item msgid="3362500960690003002">"leyndarmál"</item>
+    <item msgid="1542192064842556988">"staðfesta"</item>
+    <item msgid="2052362882225775298">"staðfesting"</item>
+    <item msgid="4759495520595696444">"staðfesta"</item>
+    <item msgid="4360404417991731370">"staðfesting"</item>
+    <item msgid="5135302120938115660">"einu sinni"</item>
+    <item msgid="405482768547359066">"aðgangur"</item>
+    <item msgid="7962233525908588330">"staðfesting"</item>
+    <item msgid="9095545913763732113">"staðfesta"</item>
+    <item msgid="2601700967903477651">"einnota"</item>
+    <item msgid="1775341814323929840">"heimila"</item>
+    <item msgid="4159587727958533896">"heimild"</item>
+    <item msgid="7199374258785307822">"persónulegt auðkenningarnúmer"</item>
+    <item msgid="3860872742161492043">"PIN-númer"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-it/strings.xml b/java/res/values-it/strings.xml
index 5515447..36a5045 100644
--- a/java/res/values-it/strings.xml
+++ b/java/res/values-it/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Notifiche adattive Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"password"</item>
+    <item msgid="3917837442156595568">"passcode"</item>
+    <item msgid="6971032950332150936">"a due fattori"</item>
+    <item msgid="826248726164877615">"due fattori"</item>
+    <item msgid="2156400793251117724">"accedere"</item>
+    <item msgid="3621495493711216796">"accesso"</item>
+    <item msgid="4652629344958695406">"fare il login"</item>
+    <item msgid="6021138326345874403">"effettuare l\'autenticazione"</item>
+    <item msgid="301989899519648952">"autenticazione"</item>
+    <item msgid="2409846400635400651">"codice"</item>
+    <item msgid="3362500960690003002">"secret"</item>
+    <item msgid="1542192064842556988">"verificare"</item>
+    <item msgid="2052362882225775298">"verifica"</item>
+    <item msgid="4759495520595696444">"confermare"</item>
+    <item msgid="4360404417991731370">"conferma"</item>
+    <item msgid="5135302120938115660">"una volta"</item>
+    <item msgid="405482768547359066">"accesso"</item>
+    <item msgid="7962233525908588330">"convalida"</item>
+    <item msgid="9095545913763732113">"convalidare"</item>
+    <item msgid="2601700967903477651">"monouso"</item>
+    <item msgid="1775341814323929840">"autorizzare"</item>
+    <item msgid="4159587727958533896">"autorizzazione"</item>
+    <item msgid="7199374258785307822">"numero di identificazione personale"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-iw/strings.xml b/java/res/values-iw/strings.xml
index 4963f43..b387785 100644
--- a/java/res/values-iw/strings.xml
+++ b/java/res/values-iw/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"‏התראות מותאמות ל-Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"קוד אימות"</item>
+    <item msgid="7174505163902448507">"סיסמה"</item>
+    <item msgid="3917837442156595568">"קוד גישה"</item>
+    <item msgid="6971032950332150936">"אימות דו-שלבי"</item>
+    <item msgid="826248726164877615">"אימות דו-שלבי"</item>
+    <item msgid="2156400793251117724">"התחברות"</item>
+    <item msgid="3621495493711216796">"התחברות לחשבון"</item>
+    <item msgid="4652629344958695406">"התחברות לחשבון"</item>
+    <item msgid="6021138326345874403">"אימות"</item>
+    <item msgid="301989899519648952">"אימות"</item>
+    <item msgid="2409846400635400651">"קוד"</item>
+    <item msgid="3362500960690003002">"סודי"</item>
+    <item msgid="1542192064842556988">"אימות"</item>
+    <item msgid="2052362882225775298">"אימות"</item>
+    <item msgid="4759495520595696444">"אישור"</item>
+    <item msgid="4360404417991731370">"אישור"</item>
+    <item msgid="5135302120938115660">"פעם אחת"</item>
+    <item msgid="405482768547359066">"גישה"</item>
+    <item msgid="7962233525908588330">"אימות"</item>
+    <item msgid="9095545913763732113">"בדיקה"</item>
+    <item msgid="2601700967903477651">"לשימוש חד-פעמי"</item>
+    <item msgid="1775341814323929840">"הרשאה"</item>
+    <item msgid="4159587727958533896">"הרשאה"</item>
+    <item msgid="7199374258785307822">"מספר תעודת זהות אישי"</item>
+    <item msgid="3860872742161492043">"קוד אימות"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ja/strings.xml b/java/res/values-ja/strings.xml
index 1bb6b7a..c75eb92 100644
--- a/java/res/values-ja/strings.xml
+++ b/java/res/values-ja/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android 通知の自動調整"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"パスワード"</item>
+    <item msgid="3917837442156595568">"パスコード"</item>
+    <item msgid="6971032950332150936">"2 要素"</item>
+    <item msgid="826248726164877615">"2 要素"</item>
+    <item msgid="2156400793251117724">"ログイン"</item>
+    <item msgid="3621495493711216796">"ログイン"</item>
+    <item msgid="4652629344958695406">"ログイン"</item>
+    <item msgid="6021138326345874403">"認証する"</item>
+    <item msgid="301989899519648952">"認証"</item>
+    <item msgid="2409846400635400651">"コード"</item>
+    <item msgid="3362500960690003002">"シークレット"</item>
+    <item msgid="1542192064842556988">"確認する"</item>
+    <item msgid="2052362882225775298">"確認"</item>
+    <item msgid="4759495520595696444">"確認する"</item>
+    <item msgid="4360404417991731370">"確認"</item>
+    <item msgid="5135302120938115660">"ワンタイム"</item>
+    <item msgid="405482768547359066">"アクセス"</item>
+    <item msgid="7962233525908588330">"検証"</item>
+    <item msgid="9095545913763732113">"検証する"</item>
+    <item msgid="2601700967903477651">"1 回限り"</item>
+    <item msgid="1775341814323929840">"認証する"</item>
+    <item msgid="4159587727958533896">"認証"</item>
+    <item msgid="7199374258785307822">"個人識別番号"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ka/strings.xml b/java/res/values-ka/strings.xml
index b2ba28e..ef65eef 100644
--- a/java/res/values-ka/strings.xml
+++ b/java/res/values-ka/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android-ის ადაპტირებადი შეტყობინებები"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN-კოდი"</item>
+    <item msgid="7174505163902448507">"პაროლი"</item>
+    <item msgid="3917837442156595568">"საიდუმლო კოდი"</item>
+    <item msgid="6971032950332150936">"ორფაქტორიანი"</item>
+    <item msgid="826248726164877615">"ორფაქტორიანი"</item>
+    <item msgid="2156400793251117724">"სისტემაში შესვლა"</item>
+    <item msgid="3621495493711216796">"სისტემაში შესვლა"</item>
+    <item msgid="4652629344958695406">"სისტემაში შესვლა"</item>
+    <item msgid="6021138326345874403">"ავტორიზაცია"</item>
+    <item msgid="301989899519648952">"ავტორიზაცია"</item>
+    <item msgid="2409846400635400651">"კოდი"</item>
+    <item msgid="3362500960690003002">"საიდუმლო"</item>
+    <item msgid="1542192064842556988">"დადასტურება"</item>
+    <item msgid="2052362882225775298">"დადასტურება"</item>
+    <item msgid="4759495520595696444">"დადასტურება"</item>
+    <item msgid="4360404417991731370">"დადასტურება"</item>
+    <item msgid="5135302120938115660">"ერთჯერადი"</item>
+    <item msgid="405482768547359066">"წვდომა"</item>
+    <item msgid="7962233525908588330">"გადამოწმება"</item>
+    <item msgid="9095545913763732113">"გადამოწმება"</item>
+    <item msgid="2601700967903477651">"მხოლოდ ერთხელ გამოყენება"</item>
+    <item msgid="1775341814323929840">"ავტორიზაცია"</item>
+    <item msgid="4159587727958533896">"ავტორიზაცია"</item>
+    <item msgid="7199374258785307822">"პერსონალური საიდენტიფიკაციო ნომერი"</item>
+    <item msgid="3860872742161492043">"PIN-კოდი"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-kk/strings.xml b/java/res/values-kk/strings.xml
index 7e91339..776f565 100644
--- a/java/res/values-kk/strings.xml
+++ b/java/res/values-kk/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android бейімделетін хабарландырулары"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"құпия сөз"</item>
+    <item msgid="3917837442156595568">"рұқсат коды"</item>
+    <item msgid="6971032950332150936">"екі факторлы"</item>
+    <item msgid="826248726164877615">"екі фактор"</item>
+    <item msgid="2156400793251117724">"кіру"</item>
+    <item msgid="3621495493711216796">"жүйеге кіру"</item>
+    <item msgid="4652629344958695406">"аккаунтқа кіру"</item>
+    <item msgid="6021138326345874403">"аутентификациялау"</item>
+    <item msgid="301989899519648952">"аутентификация"</item>
+    <item msgid="2409846400635400651">"код"</item>
+    <item msgid="3362500960690003002">"құпия"</item>
+    <item msgid="1542192064842556988">"тексеру"</item>
+    <item msgid="2052362882225775298">"тексеру процесі"</item>
+    <item msgid="4759495520595696444">"растау"</item>
+    <item msgid="4360404417991731370">"растау процесі"</item>
+    <item msgid="5135302120938115660">"бір реттік"</item>
+    <item msgid="405482768547359066">"пайдалану рұқсаты"</item>
+    <item msgid="7962233525908588330">"дұрыстығын тексеру процесі"</item>
+    <item msgid="9095545913763732113">"дұрыстығын тексеру"</item>
+    <item msgid="2601700967903477651">"бір рет пайдаланылатын"</item>
+    <item msgid="1775341814323929840">"авторизациялау"</item>
+    <item msgid="4159587727958533896">"авторизация"</item>
+    <item msgid="7199374258785307822">"Жеке сәйкестендіру нөмірі"</item>
+    <item msgid="3860872742161492043">"PIN коды"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-km/strings.xml b/java/res/values-km/strings.xml
index 49649f9..eaf3957 100644
--- a/java/res/values-km/strings.xml
+++ b/java/res/values-km/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"ការជូនដំណឹង​ដែលមានភាពបត់បែន Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"កូដ pin"</item>
+    <item msgid="7174505163902448507">"ពាក្យសម្ងាត់"</item>
+    <item msgid="3917837442156595568">"លេខ​កូដ​សម្ងាត់"</item>
+    <item msgid="6971032950332150936">"ពីរកត្តា"</item>
+    <item msgid="826248726164877615">"ពីរកត្តា"</item>
+    <item msgid="2156400793251117724">"ការចូលគណនី"</item>
+    <item msgid="3621495493711216796">"ចូលគណនី"</item>
+    <item msgid="4652629344958695406">"ចូលគណនី"</item>
+    <item msgid="6021138326345874403">"ផ្ទៀងផ្ទាត់"</item>
+    <item msgid="301989899519648952">"ការផ្ទៀងផ្ទាត់"</item>
+    <item msgid="2409846400635400651">"កូដ"</item>
+    <item msgid="3362500960690003002">"សម្ងាត់"</item>
+    <item msgid="1542192064842556988">"ផ្ទៀងផ្ទាត់"</item>
+    <item msgid="2052362882225775298">"ការផ្ទៀងផ្ទាត់"</item>
+    <item msgid="4759495520595696444">"បញ្ជាក់"</item>
+    <item msgid="4360404417991731370">"ការបញ្ជាក់"</item>
+    <item msgid="5135302120938115660">"ម្តង"</item>
+    <item msgid="405482768547359066">"ការចូលប្រើ"</item>
+    <item msgid="7962233525908588330">"ការបញ្ជាក់សុពលភាព"</item>
+    <item msgid="9095545913763732113">"បញ្ជាក់​សុពលភាព"</item>
+    <item msgid="2601700967903477651">"ការប្រើប្រាស់តែមួយ"</item>
+    <item msgid="1775341814323929840">"អនុញ្ញាត"</item>
+    <item msgid="4159587727958533896">"ការ​អនុញ្ញាត"</item>
+    <item msgid="7199374258785307822">"លេខសម្គាល់​អត្តសញ្ញាណ​បុគ្គល"</item>
+    <item msgid="3860872742161492043">"កូដ PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-kn/strings.xml b/java/res/values-kn/strings.xml
index d03fa70..36d56da 100644
--- a/java/res/values-kn/strings.xml
+++ b/java/res/values-kn/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android ಅಡಾಪ್ಟಿವ್ ಅಧಿಸೂಚನೆಗಳು"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"ಪಿನ್"</item>
+    <item msgid="7174505163902448507">"ಪಾಸ್‌ವರ್ಡ್"</item>
+    <item msgid="3917837442156595568">"ಪಾಸ್‌ಕೋಡ್"</item>
+    <item msgid="6971032950332150936">"ಎರಡು ಅಂಶಗಳ"</item>
+    <item msgid="826248726164877615">"ಎರಡು-ಅಂಶಗಳ"</item>
+    <item msgid="2156400793251117724">"ಲಾಗಿನ್"</item>
+    <item msgid="3621495493711216796">"ಲಾಗ್‌ ಇನ್‌"</item>
+    <item msgid="4652629344958695406">"ಲಾಗ್‌ ಇನ್‌"</item>
+    <item msgid="6021138326345874403">"ದೃಢೀಕರಿಸಿ"</item>
+    <item msgid="301989899519648952">"ದೃಢೀಕರಣ"</item>
+    <item msgid="2409846400635400651">"ಕೋಡ್"</item>
+    <item msgid="3362500960690003002">"ರಹಸ್ಯ"</item>
+    <item msgid="1542192064842556988">"ಪರಿಶೀಲಿಸಿ"</item>
+    <item msgid="2052362882225775298">"ಪರಿಶೀಲನೆ"</item>
+    <item msgid="4759495520595696444">"ದೃಢೀಕರಿಸಿ"</item>
+    <item msgid="4360404417991731370">"ದೃಢೀಕರಣ"</item>
+    <item msgid="5135302120938115660">"ಒಂದು ಬಾರಿ"</item>
+    <item msgid="405482768547359066">"ಆ್ಯಕ್ಸೆಸ್"</item>
+    <item msgid="7962233525908588330">"ಮೌಲ್ಯೀಕರಣ"</item>
+    <item msgid="9095545913763732113">"ಮೌಲ್ಯೀಕರಿಸಿ"</item>
+    <item msgid="2601700967903477651">"ಏಕ-ಬಳಕೆ"</item>
+    <item msgid="1775341814323929840">"ದೃಢೀಕರಿಸಿ"</item>
+    <item msgid="4159587727958533896">"ದೃಢೀಕರಣ"</item>
+    <item msgid="7199374258785307822">"ವೈಯಕ್ತಿಕ ಗುರುತಿನ ಸಂಖ್ಯೆ"</item>
+    <item msgid="3860872742161492043">"ಪಿನ್"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ko/strings.xml b/java/res/values-ko/strings.xml
index 0755341..954d935 100644
--- a/java/res/values-ko/strings.xml
+++ b/java/res/values-ko/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android 적응형 알림"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"비밀번호"</item>
+    <item msgid="3917837442156595568">"비밀번호"</item>
+    <item msgid="6971032950332150936">"2단계 인증"</item>
+    <item msgid="826248726164877615">"2단계 인증"</item>
+    <item msgid="2156400793251117724">"로그인"</item>
+    <item msgid="3621495493711216796">"로그인"</item>
+    <item msgid="4652629344958695406">"로그인"</item>
+    <item msgid="6021138326345874403">"인증"</item>
+    <item msgid="301989899519648952">"인증"</item>
+    <item msgid="2409846400635400651">"코드"</item>
+    <item msgid="3362500960690003002">"비밀번호"</item>
+    <item msgid="1542192064842556988">"인증"</item>
+    <item msgid="2052362882225775298">"인증"</item>
+    <item msgid="4759495520595696444">"확인"</item>
+    <item msgid="4360404417991731370">"확인"</item>
+    <item msgid="5135302120938115660">"일회용"</item>
+    <item msgid="405482768547359066">"액세스"</item>
+    <item msgid="7962233525908588330">"유효성 검사"</item>
+    <item msgid="9095545913763732113">"유효성 검사"</item>
+    <item msgid="2601700967903477651">"일회용"</item>
+    <item msgid="1775341814323929840">"승인"</item>
+    <item msgid="4159587727958533896">"승인"</item>
+    <item msgid="7199374258785307822">"개인 식별 번호"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ky/strings.xml b/java/res/values-ky/strings.xml
index 22f0b13..17f5fe2 100644
--- a/java/res/values-ky/strings.xml
+++ b/java/res/values-ky/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android\'дин Ыңгайлаштырылуучу билдирмелери"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN код"</item>
+    <item msgid="7174505163902448507">"сырсөз"</item>
+    <item msgid="3917837442156595568">"өткөрүүчү код"</item>
+    <item msgid="6971032950332150936">"эки этап"</item>
+    <item msgid="826248726164877615">"эки этаптуу"</item>
+    <item msgid="2156400793251117724">"кирүү"</item>
+    <item msgid="3621495493711216796">"кирүү"</item>
+    <item msgid="4652629344958695406">"кирүү"</item>
+    <item msgid="6021138326345874403">"аныктыгын текшерүү"</item>
+    <item msgid="301989899519648952">"аутентификация"</item>
+    <item msgid="2409846400635400651">"код"</item>
+    <item msgid="3362500960690003002">"купуя"</item>
+    <item msgid="1542192064842556988">"текшерүү"</item>
+    <item msgid="2052362882225775298">"текшерүү"</item>
+    <item msgid="4759495520595696444">"ырастоо"</item>
+    <item msgid="4360404417991731370">"ырастоо"</item>
+    <item msgid="5135302120938115660">"бир жолку"</item>
+    <item msgid="405482768547359066">"мүмкүнчүлүк алуу"</item>
+    <item msgid="7962233525908588330">"тастыктоо"</item>
+    <item msgid="9095545913763732113">"тастыктоо"</item>
+    <item msgid="2601700967903477651">"бир жолу колдонуу"</item>
+    <item msgid="1775341814323929840">"уруксат алуу"</item>
+    <item msgid="4159587727958533896">"авторизация"</item>
+    <item msgid="7199374258785307822">"жеке идентификациялык номер"</item>
+    <item msgid="3860872742161492043">"PIN код"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-lo/strings.xml b/java/res/values-lo/strings.xml
index 972f147..fb3f4be 100644
--- a/java/res/values-lo/strings.xml
+++ b/java/res/values-lo/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"ການແຈ້ງເຕືອນແບບປັບຕົວໄດ້ຂອງ Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"ລະຫັດຜ່ານ"</item>
+    <item msgid="3917837442156595568">"ລະຫັດ"</item>
+    <item msgid="6971032950332150936">"ສອງຂັ້ນຕອນ"</item>
+    <item msgid="826248726164877615">"ສອງຂັ້ນຕອນ"</item>
+    <item msgid="2156400793251117724">"ເຂົ້າສູ່ລະບົບ"</item>
+    <item msgid="3621495493711216796">"ເຂົ້າສູ່ລະບົບ"</item>
+    <item msgid="4652629344958695406">"ເຂົ້າສູ່ລະບົບ"</item>
+    <item msgid="6021138326345874403">"ພິສູດຢືນຢັນ"</item>
+    <item msgid="301989899519648952">"ການພິສູດຢືນຢັນ"</item>
+    <item msgid="2409846400635400651">"ລະຫັດ"</item>
+    <item msgid="3362500960690003002">"ຂໍ້ມູນລັບ"</item>
+    <item msgid="1542192064842556988">"ຢັ້ງຢືນ"</item>
+    <item msgid="2052362882225775298">"ການຢັ້ງຢືນ"</item>
+    <item msgid="4759495520595696444">"ຢືນຢັນ"</item>
+    <item msgid="4360404417991731370">"ການຢືນຢັນ"</item>
+    <item msgid="5135302120938115660">"ເທື່ອດຽວ"</item>
+    <item msgid="405482768547359066">"ສິດເຂົ້າເຖິງ"</item>
+    <item msgid="7962233525908588330">"ການກວດສອບ"</item>
+    <item msgid="9095545913763732113">"ກວດສອບ"</item>
+    <item msgid="2601700967903477651">"ໃຊ້ເທື່ອດຽວ"</item>
+    <item msgid="1775341814323929840">"ອະນຸຍາດ"</item>
+    <item msgid="4159587727958533896">"ການອະນຸຍາດ"</item>
+    <item msgid="7199374258785307822">"ໝາຍເລກປະຈຳຕົວສ່ວນບຸກຄົນ"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-lt/strings.xml b/java/res/values-lt/strings.xml
index e731634..e325c40 100644
--- a/java/res/values-lt/strings.xml
+++ b/java/res/values-lt/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"„Android“ prisitaikantys pranešimai"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN kodas"</item>
+    <item msgid="7174505163902448507">"slaptažodis"</item>
+    <item msgid="3917837442156595568">"slaptažodis"</item>
+    <item msgid="6971032950332150936">"dviejų veiksmų"</item>
+    <item msgid="826248726164877615">"dviejų veiksmų"</item>
+    <item msgid="2156400793251117724">"prisijungimas"</item>
+    <item msgid="3621495493711216796">"prisijungti"</item>
+    <item msgid="4652629344958695406">"prisijungti"</item>
+    <item msgid="6021138326345874403">"autentifikuoti"</item>
+    <item msgid="301989899519648952">"autentifikavimas"</item>
+    <item msgid="2409846400635400651">"kodas"</item>
+    <item msgid="3362500960690003002">"slaptas"</item>
+    <item msgid="1542192064842556988">"patvirtinti"</item>
+    <item msgid="2052362882225775298">"patvirtinimas"</item>
+    <item msgid="4759495520595696444">"patvirtinti"</item>
+    <item msgid="4360404417991731370">"patvirtinimas"</item>
+    <item msgid="5135302120938115660">"vienkartinis"</item>
+    <item msgid="405482768547359066">"prieiga"</item>
+    <item msgid="7962233525908588330">"patvirtinimas"</item>
+    <item msgid="9095545913763732113">"patvirtinti"</item>
+    <item msgid="2601700967903477651">"vienkartinis"</item>
+    <item msgid="1775341814323929840">"suteikti prieigos teisę"</item>
+    <item msgid="4159587727958533896">"prieigos teisės suteikimas"</item>
+    <item msgid="7199374258785307822">"asmens identifikavimo numeris"</item>
+    <item msgid="3860872742161492043">"PIN kodas"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-lv/strings.xml b/java/res/values-lv/strings.xml
index 18388b2..f30a88e 100644
--- a/java/res/values-lv/strings.xml
+++ b/java/res/values-lv/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android adaptīvie paziņojumi"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"parole"</item>
+    <item msgid="3917837442156595568">"piekļuves kods"</item>
+    <item msgid="6971032950332150936">"divpakāpju"</item>
+    <item msgid="826248726164877615">"divpakāpju"</item>
+    <item msgid="2156400793251117724">"pieteikšanās"</item>
+    <item msgid="3621495493711216796">"pieteikties"</item>
+    <item msgid="4652629344958695406">"pieteikties"</item>
+    <item msgid="6021138326345874403">"autentificēt"</item>
+    <item msgid="301989899519648952">"autentificēšana"</item>
+    <item msgid="2409846400635400651">"kods"</item>
+    <item msgid="3362500960690003002">"slepenā atslēga"</item>
+    <item msgid="1542192064842556988">"verificēt"</item>
+    <item msgid="2052362882225775298">"verifikācija"</item>
+    <item msgid="4759495520595696444">"apstiprināt"</item>
+    <item msgid="4360404417991731370">"apstiprinājums"</item>
+    <item msgid="5135302120938115660">"vienreiz"</item>
+    <item msgid="405482768547359066">"piekļuve"</item>
+    <item msgid="7962233525908588330">"validācija"</item>
+    <item msgid="9095545913763732113">"validēt"</item>
+    <item msgid="2601700967903477651">"vienreizēja izmantošana"</item>
+    <item msgid="1775341814323929840">"autorizēt"</item>
+    <item msgid="4159587727958533896">"autorizācija"</item>
+    <item msgid="7199374258785307822">"personīgais identifikācijas numurs"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-mk/strings.xml b/java/res/values-mk/strings.xml
index 4643a92..b2e627c 100644
--- a/java/res/values-mk/strings.xml
+++ b/java/res/values-mk/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Адаптивни известувања на Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"лозинка"</item>
+    <item msgid="3917837442156595568">"лозинка"</item>
+    <item msgid="6971032950332150936">"два чекора"</item>
+    <item msgid="826248726164877615">"два чекора"</item>
+    <item msgid="2156400793251117724">"најавување"</item>
+    <item msgid="3621495493711216796">"најавување"</item>
+    <item msgid="4652629344958695406">"најави се"</item>
+    <item msgid="6021138326345874403">"автентицирај"</item>
+    <item msgid="301989899519648952">"автентикација"</item>
+    <item msgid="2409846400635400651">"код"</item>
+    <item msgid="3362500960690003002">"тајно"</item>
+    <item msgid="1542192064842556988">"потврди"</item>
+    <item msgid="2052362882225775298">"потврда"</item>
+    <item msgid="4759495520595696444">"потврди"</item>
+    <item msgid="4360404417991731370">"потврда"</item>
+    <item msgid="5135302120938115660">"еднаш"</item>
+    <item msgid="405482768547359066">"пристап"</item>
+    <item msgid="7962233525908588330">"потврда"</item>
+    <item msgid="9095545913763732113">"потврди"</item>
+    <item msgid="2601700967903477651">"еднократна употреба"</item>
+    <item msgid="1775341814323929840">"овласти"</item>
+    <item msgid="4159587727958533896">"овластување"</item>
+    <item msgid="7199374258785307822">"број за лична идентификација"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ml/strings.xml b/java/res/values-ml/strings.xml
index 960fb05..de92555 100644
--- a/java/res/values-ml/strings.xml
+++ b/java/res/values-ml/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android അഡാപ്റ്റീവ് അറിയിപ്പുകൾ"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"പിൻ"</item>
+    <item msgid="7174505163902448507">"പാസ്‌വേഡ്"</item>
+    <item msgid="3917837442156595568">"പാസ്‌കോഡ്"</item>
+    <item msgid="6971032950332150936">"ടൂ ഫാക്ടർ"</item>
+    <item msgid="826248726164877615">"ടൂ ഫാക്ടർ"</item>
+    <item msgid="2156400793251117724">"ലോഗിൻ ചെയ്യുക"</item>
+    <item msgid="3621495493711216796">"ലോഗിൻ ചെയ്യുക"</item>
+    <item msgid="4652629344958695406">"ലോഗിൻ ചെയ്യുക"</item>
+    <item msgid="6021138326345874403">"പരിശോധിച്ചുറപ്പിക്കുക"</item>
+    <item msgid="301989899519648952">"പരിശോധിച്ചുറപ്പിക്കൽ"</item>
+    <item msgid="2409846400635400651">"കോഡ്"</item>
+    <item msgid="3362500960690003002">"രഹസ്യം"</item>
+    <item msgid="1542192064842556988">"പരിശോധിച്ചുറപ്പിക്കുക"</item>
+    <item msgid="2052362882225775298">"പരിശോധിച്ചുറപ്പിക്കൽ"</item>
+    <item msgid="4759495520595696444">"സ്ഥിരീകരിക്കുക"</item>
+    <item msgid="4360404417991731370">"സ്ഥിരീകരണം"</item>
+    <item msgid="5135302120938115660">"ഒറ്റത്തവണ"</item>
+    <item msgid="405482768547359066">"ആക്‌സസ്"</item>
+    <item msgid="7962233525908588330">"സാധൂകരിക്കൽ"</item>
+    <item msgid="9095545913763732113">"സാധൂകരിക്കുക"</item>
+    <item msgid="2601700967903477651">"ഒറ്റത്തവണ ഉപയോഗം"</item>
+    <item msgid="1775341814323929840">"അംഗീകാരം നൽകുക"</item>
+    <item msgid="4159587727958533896">"അംഗീകരിക്കൽ"</item>
+    <item msgid="7199374258785307822">"പേഴ്‌സണൽ ഐഡന്റിഫിക്കേഷൻ നമ്പർ"</item>
+    <item msgid="3860872742161492043">"പിൻ"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-mn/strings.xml b/java/res/values-mn/strings.xml
index dde2265..3758982 100644
--- a/java/res/values-mn/strings.xml
+++ b/java/res/values-mn/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android-н тохируулсан мэдэгдэл"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"пин"</item>
+    <item msgid="7174505163902448507">"нууц үг"</item>
+    <item msgid="3917837442156595568">"нууц код"</item>
+    <item msgid="6971032950332150936">"хоёр хүчин зүйл"</item>
+    <item msgid="826248726164877615">"хоёр хүчин зүйл"</item>
+    <item msgid="2156400793251117724">"нэвтрэлт"</item>
+    <item msgid="3621495493711216796">"нэвтрэх"</item>
+    <item msgid="4652629344958695406">"нэвтрэх"</item>
+    <item msgid="6021138326345874403">"баталгаажуулах"</item>
+    <item msgid="301989899519648952">"баталгаажуулалт"</item>
+    <item msgid="2409846400635400651">"код"</item>
+    <item msgid="3362500960690003002">"нууц"</item>
+    <item msgid="1542192064842556988">"баталгаажуулах"</item>
+    <item msgid="2052362882225775298">"баталгаажуулалт"</item>
+    <item msgid="4759495520595696444">"баталгаажуулах"</item>
+    <item msgid="4360404417991731370">"баталгаажуулалт"</item>
+    <item msgid="5135302120938115660">"нэг удаагийн"</item>
+    <item msgid="405482768547359066">"хандалт"</item>
+    <item msgid="7962233525908588330">"баталгаажуулалт"</item>
+    <item msgid="9095545913763732113">"баталгаажуулах"</item>
+    <item msgid="2601700967903477651">"нэг удаа ашиглах"</item>
+    <item msgid="1775341814323929840">"зөвшөөрөх"</item>
+    <item msgid="4159587727958533896">"зөвшөөрөл"</item>
+    <item msgid="7199374258785307822">"хувийн таних дугаар"</item>
+    <item msgid="3860872742161492043">"ПИН"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-mr/strings.xml b/java/res/values-mr/strings.xml
index 8ab4b19..d5d421d 100644
--- a/java/res/values-mr/strings.xml
+++ b/java/res/values-mr/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android अ‍ॅडॅप्टिव्ह सूचना"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"पिन"</item>
+    <item msgid="7174505163902448507">"पासवर्ड"</item>
+    <item msgid="3917837442156595568">"पासकोड"</item>
+    <item msgid="6971032950332150936">"२ टप्पी"</item>
+    <item msgid="826248726164877615">"२ टप्पी"</item>
+    <item msgid="2156400793251117724">"लॉग इन"</item>
+    <item msgid="3621495493711216796">"लॉग इन करा"</item>
+    <item msgid="4652629344958695406">"लॉग इन करा"</item>
+    <item msgid="6021138326345874403">"ऑथेंटिकेट करा"</item>
+    <item msgid="301989899519648952">"ऑथेंटिकेशन"</item>
+    <item msgid="2409846400635400651">"कोड"</item>
+    <item msgid="3362500960690003002">"गुप्त"</item>
+    <item msgid="1542192064842556988">"पडताळणी करा"</item>
+    <item msgid="2052362882225775298">"पडताळणी"</item>
+    <item msgid="4759495520595696444">"कन्फर्म करा"</item>
+    <item msgid="4360404417991731370">"कन्फर्मेशन"</item>
+    <item msgid="5135302120938115660">"एक वेळ"</item>
+    <item msgid="405482768547359066">"अ‍ॅक्सेस करा"</item>
+    <item msgid="7962233525908588330">"व्हॅलिडेशन"</item>
+    <item msgid="9095545913763732113">"पडताळणी करा"</item>
+    <item msgid="2601700967903477651">"एकच वेळ वापरले"</item>
+    <item msgid="1775341814323929840">"ऑथोराइझ करा"</item>
+    <item msgid="4159587727958533896">"ऑथोरायझेशन"</item>
+    <item msgid="7199374258785307822">"वैयक्तिक ओळख क्रमांक"</item>
+    <item msgid="3860872742161492043">"पिन"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ms/strings.xml b/java/res/values-ms/strings.xml
index 71b68d7..b35a949 100644
--- a/java/res/values-ms/strings.xml
+++ b/java/res/values-ms/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Pemberitahuan Boleh Suai Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"kata laluan"</item>
+    <item msgid="3917837442156595568">"kod laluan"</item>
+    <item msgid="6971032950332150936">"dua faktor"</item>
+    <item msgid="826248726164877615">"dua faktor"</item>
+    <item msgid="2156400793251117724">"log masuk"</item>
+    <item msgid="3621495493711216796">"log masuk"</item>
+    <item msgid="4652629344958695406">"log masuk"</item>
+    <item msgid="6021138326345874403">"sahkan"</item>
+    <item msgid="301989899519648952">"pengesahan"</item>
+    <item msgid="2409846400635400651">"kod"</item>
+    <item msgid="3362500960690003002">"rahsia"</item>
+    <item msgid="1542192064842556988">"sahkan"</item>
+    <item msgid="2052362882225775298">"pengesahan"</item>
+    <item msgid="4759495520595696444">"sahkan"</item>
+    <item msgid="4360404417991731370">"pengesahan"</item>
+    <item msgid="5135302120938115660">"satu kali"</item>
+    <item msgid="405482768547359066">"akses"</item>
+    <item msgid="7962233525908588330">"pengesahan"</item>
+    <item msgid="9095545913763732113">"sahkan"</item>
+    <item msgid="2601700967903477651">"penggunaan satu kali"</item>
+    <item msgid="1775341814323929840">"izinkan"</item>
+    <item msgid="4159587727958533896">"keizinan"</item>
+    <item msgid="7199374258785307822">"nombor pengenalan peribadi"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-my/strings.xml b/java/res/values-my/strings.xml
index 9800595..2be5131 100644
--- a/java/res/values-my/strings.xml
+++ b/java/res/values-my/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android အလိုက်သင့် အကြောင်းကြားချက်များ"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"ပင်နံပါတ်"</item>
+    <item msgid="7174505163902448507">"စကားဝှက်"</item>
+    <item msgid="3917837442156595568">"လျှို့ဝှက်ကုဒ်"</item>
+    <item msgid="6971032950332150936">"နှစ်ဆင့်"</item>
+    <item msgid="826248726164877615">"နှစ်ဆင့်"</item>
+    <item msgid="2156400793251117724">"အကောင့်ဝင်ရန်"</item>
+    <item msgid="3621495493711216796">"အကောင့်ဝင်ရန်"</item>
+    <item msgid="4652629344958695406">"အကောင့်ဝင်ရန်"</item>
+    <item msgid="6021138326345874403">"အထောက်အထားစိစစ်ရန်"</item>
+    <item msgid="301989899519648952">"အထောက်အထားစိစစ်ခြင်း"</item>
+    <item msgid="2409846400635400651">"ကုဒ်"</item>
+    <item msgid="3362500960690003002">"လျှို့ဝှက်"</item>
+    <item msgid="1542192064842556988">"အတည်ပြုရန်"</item>
+    <item msgid="2052362882225775298">"အတည်ပြုခြင်း"</item>
+    <item msgid="4759495520595696444">"အတည်ပြုရန်"</item>
+    <item msgid="4360404417991731370">"အတည်ပြုခြင်း"</item>
+    <item msgid="5135302120938115660">"တစ်ကြိမ်"</item>
+    <item msgid="405482768547359066">"သုံးခွင့်"</item>
+    <item msgid="7962233525908588330">"အတည်ပြုခြင်း"</item>
+    <item msgid="9095545913763732113">"အတည်ပြုရန်"</item>
+    <item msgid="2601700967903477651">"တစ်ကြိမ်သုံး"</item>
+    <item msgid="1775341814323929840">"ခွင့်ပြုရန်"</item>
+    <item msgid="4159587727958533896">"ခွင့်ပြုခြင်း"</item>
+    <item msgid="7199374258785307822">"ကိုယ်ပိုင် သက်သေခံနံပါတ်"</item>
+    <item msgid="3860872742161492043">"ပင်နံပါတ်"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-nb/strings.xml b/java/res/values-nb/strings.xml
index f72cd99..1e61b9d 100644
--- a/java/res/values-nb/strings.xml
+++ b/java/res/values-nb/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Tilpassede Android-varsler"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"fest"</item>
+    <item msgid="7174505163902448507">"passord"</item>
+    <item msgid="3917837442156595568">"adgangskode"</item>
+    <item msgid="6971032950332150936">"totrinns"</item>
+    <item msgid="826248726164877615">"totrinns"</item>
+    <item msgid="2156400793251117724">"logg på"</item>
+    <item msgid="3621495493711216796">"pålogging"</item>
+    <item msgid="4652629344958695406">"logg på"</item>
+    <item msgid="6021138326345874403">"autentiser"</item>
+    <item msgid="301989899519648952">"autentisering"</item>
+    <item msgid="2409846400635400651">"kode"</item>
+    <item msgid="3362500960690003002">"hemmelighet"</item>
+    <item msgid="1542192064842556988">"verifiser"</item>
+    <item msgid="2052362882225775298">"verifisering"</item>
+    <item msgid="4759495520595696444">"bekreft"</item>
+    <item msgid="4360404417991731370">"bekreftelse"</item>
+    <item msgid="5135302120938115660">"én gang"</item>
+    <item msgid="405482768547359066">"tilgang"</item>
+    <item msgid="7962233525908588330">"validering"</item>
+    <item msgid="9095545913763732113">"valider"</item>
+    <item msgid="2601700967903477651">"engangsbruk"</item>
+    <item msgid="1775341814323929840">"autoriser"</item>
+    <item msgid="4159587727958533896">"autorisering"</item>
+    <item msgid="7199374258785307822">"personlig ID-nummer"</item>
+    <item msgid="3860872742161492043">"PIN-kode"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ne/strings.xml b/java/res/values-ne/strings.xml
index deeb0c4..9e63cbe 100644
--- a/java/res/values-ne/strings.xml
+++ b/java/res/values-ne/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android को अनुकूल पार्न मिल्ने सूचना"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"पासवर्ड"</item>
+    <item msgid="3917837442156595568">"पासकोड"</item>
+    <item msgid="6971032950332150936">"दुई चरण"</item>
+    <item msgid="826248726164877615">"दुई चरण"</item>
+    <item msgid="2156400793251117724">"लग इन"</item>
+    <item msgid="3621495493711216796">"लग इन गर्नुहोस्"</item>
+    <item msgid="4652629344958695406">"लग इन गर्नुहोस्"</item>
+    <item msgid="6021138326345874403">"प्रमाणित गर्नुहोस्"</item>
+    <item msgid="301989899519648952">"प्रमाणीकरण"</item>
+    <item msgid="2409846400635400651">"कोड"</item>
+    <item msgid="3362500960690003002">"गोप्य"</item>
+    <item msgid="1542192064842556988">"पुष्टि गर्नुहोस्"</item>
+    <item msgid="2052362882225775298">"पुष्टि गर्ने प्रक्रिया"</item>
+    <item msgid="4759495520595696444">"पुष्टि गर्नुहोस्"</item>
+    <item msgid="4360404417991731370">"पुष्टि गर्ने प्रक्रिया"</item>
+    <item msgid="5135302120938115660">"एक पटके"</item>
+    <item msgid="405482768547359066">"एक्सेस"</item>
+    <item msgid="7962233525908588330">"पुष्टि गर्ने प्रक्रिया"</item>
+    <item msgid="9095545913763732113">"पुष्टि गर्नुहोस्"</item>
+    <item msgid="2601700967903477651">"एक पटक मात्र प्रयोग गर्न मिल्ने"</item>
+    <item msgid="1775341814323929840">"अधिकार दिनुहोस्"</item>
+    <item msgid="4159587727958533896">"अधिकार दिने प्रक्रिया"</item>
+    <item msgid="7199374258785307822">"व्यक्तिगत पहिचान नम्बर"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-nl/strings.xml b/java/res/values-nl/strings.xml
index 9165a94..f23092c 100644
--- a/java/res/values-nl/strings.xml
+++ b/java/res/values-nl/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Aanpasbare Android-meldingen"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pincode"</item>
+    <item msgid="7174505163902448507">"wachtwoord"</item>
+    <item msgid="3917837442156595568">"toegangscode"</item>
+    <item msgid="6971032950332150936">"verificatie in 2 stappen"</item>
+    <item msgid="826248726164877615">"verificatie in 2 stappen"</item>
+    <item msgid="2156400793251117724">"inloggen"</item>
+    <item msgid="3621495493711216796">"login"</item>
+    <item msgid="4652629344958695406">"inloggen"</item>
+    <item msgid="6021138326345874403">"verifiëren"</item>
+    <item msgid="301989899519648952">"verificatie"</item>
+    <item msgid="2409846400635400651">"code"</item>
+    <item msgid="3362500960690003002">"geheim"</item>
+    <item msgid="1542192064842556988">"verifiëren"</item>
+    <item msgid="2052362882225775298">"verificatie"</item>
+    <item msgid="4759495520595696444">"bevestigen"</item>
+    <item msgid="4360404417991731370">"bevestiging"</item>
+    <item msgid="5135302120938115660">"één keer"</item>
+    <item msgid="405482768547359066">"toegang"</item>
+    <item msgid="7962233525908588330">"validatie"</item>
+    <item msgid="9095545913763732113">"valideren"</item>
+    <item msgid="2601700967903477651">"eenmalig gebruik"</item>
+    <item msgid="1775341814323929840">"autoriseren"</item>
+    <item msgid="4159587727958533896">"autorisatie"</item>
+    <item msgid="7199374258785307822">"persoonlijk identificatienummer"</item>
+    <item msgid="3860872742161492043">"Pincode"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-or/strings.xml b/java/res/values-or/strings.xml
index 75c4d51..bb8bd3f 100644
--- a/java/res/values-or/strings.xml
+++ b/java/res/values-or/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android ଆଡେପ୍ଟିଭ୍ ବିଜ୍ଞପ୍ତିଗୁଡ଼ିକ"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"ପାସୱାର୍ଡ"</item>
+    <item msgid="3917837442156595568">"ପାସକୋଡ"</item>
+    <item msgid="6971032950332150936">"ଦୁଇ ଫେକ୍ଟର"</item>
+    <item msgid="826248726164877615">"ଦୁଇ-ଫେକ୍ଟର"</item>
+    <item msgid="2156400793251117724">"ଲଗଇନ"</item>
+    <item msgid="3621495493711216796">"ଲଗ-ଇନ କରନ୍ତୁ"</item>
+    <item msgid="4652629344958695406">"ଲଗ ଇନ କରନ୍ତୁ"</item>
+    <item msgid="6021138326345874403">"ପ୍ରମାଣ କରନ୍ତୁ"</item>
+    <item msgid="301989899519648952">"ପ୍ରମାଣୀକରଣ"</item>
+    <item msgid="2409846400635400651">"କୋଡ"</item>
+    <item msgid="3362500960690003002">"ଗୁପ୍ତ"</item>
+    <item msgid="1542192064842556988">"ଯାଞ୍ଚ କରନ୍ତୁ"</item>
+    <item msgid="2052362882225775298">"ଯାଞ୍ଚକରଣ"</item>
+    <item msgid="4759495520595696444">"ସୁନିଶ୍ଚିତ କରନ୍ତୁ"</item>
+    <item msgid="4360404417991731370">"ସୁନିଶ୍ଚିତକରଣ"</item>
+    <item msgid="5135302120938115660">"ଗୋଟିଏ ଥର"</item>
+    <item msgid="405482768547359066">"ଆକ୍ସେସ କରନ୍ତୁ"</item>
+    <item msgid="7962233525908588330">"ବୈଧକରଣ"</item>
+    <item msgid="9095545913763732113">"ବୈଧତା ଯାଞ୍ଚ କରନ୍ତୁ"</item>
+    <item msgid="2601700967903477651">"ଗୋଟିଏ ଥର ବ୍ୟବହାର କରିବା ପାଇଁ"</item>
+    <item msgid="1775341814323929840">"ଅଧିକାର ଦିଅନ୍ତୁ"</item>
+    <item msgid="4159587727958533896">"ଅଥୋରାଇଜେସନ"</item>
+    <item msgid="7199374258785307822">"ବ୍ୟକ୍ତିଗତ ଚିହ୍ନଟକରଣ ନମ୍ବର"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-pa/strings.xml b/java/res/values-pa/strings.xml
index 260114d..ff9a505 100644
--- a/java/res/values-pa/strings.xml
+++ b/java/res/values-pa/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android ਅਡੈਪਟਿਵ ਸੂਚਨਾਵਾਂ"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"ਪਿੰਨ"</item>
+    <item msgid="7174505163902448507">"ਪਾਸਵਰਡ"</item>
+    <item msgid="3917837442156595568">"ਪਾਸਕੋਡ"</item>
+    <item msgid="6971032950332150936">"ਦੋ ਪੜਾਵੀ"</item>
+    <item msgid="826248726164877615">"ਦੋ-ਪੜਾਵੀ"</item>
+    <item msgid="2156400793251117724">"ਲੌਗ-ਇਨ"</item>
+    <item msgid="3621495493711216796">"ਲੌਗ-ਇਨ ਕਰੋ"</item>
+    <item msgid="4652629344958695406">"ਲੌਗ-ਇਨ ਕਰੋ"</item>
+    <item msgid="6021138326345874403">"ਪ੍ਰਮਾਣਿਤ ਕਰੋ"</item>
+    <item msgid="301989899519648952">"ਪ੍ਰਮਾਣੀਕਰਨ"</item>
+    <item msgid="2409846400635400651">"ਕੋਡ"</item>
+    <item msgid="3362500960690003002">"ਗੁਪਤ"</item>
+    <item msgid="1542192064842556988">"ਪੁਸ਼ਟੀ ਕਰੋ"</item>
+    <item msgid="2052362882225775298">"ਪੁਸ਼ਟੀਕਰਨ"</item>
+    <item msgid="4759495520595696444">"ਤਸਦੀਕ ਕਰੋ"</item>
+    <item msgid="4360404417991731370">"ਤਸਦੀਕ"</item>
+    <item msgid="5135302120938115660">"ਇੱਕ ਵਾਰ"</item>
+    <item msgid="405482768547359066">"ਪਹੁੰਚ"</item>
+    <item msgid="7962233525908588330">"ਪ੍ਰਮਾਣਿਕਤਾ"</item>
+    <item msgid="9095545913763732113">"ਪ੍ਰਮਾਣਿਤ ਕਰੋ"</item>
+    <item msgid="2601700967903477651">"ਸਿਰਫ਼ ਇੱਕ ਵਾਰ ਵਰਤਿਆ ਜਾ ਸਕਣ ਵਾਲਾ"</item>
+    <item msgid="1775341814323929840">"ਅਧਿਕਾਰਿਤ ਕਰੋ"</item>
+    <item msgid="4159587727958533896">"ਇਖਤਿਆਰੀਕਰਨ"</item>
+    <item msgid="7199374258785307822">"ਨਿੱਜੀ ਪਛਾਣ ਨੰਬਰ"</item>
+    <item msgid="3860872742161492043">"ਪਿੰਨ"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-pl/strings.xml b/java/res/values-pl/strings.xml
index 1bf207b..27f016a 100644
--- a/java/res/values-pl/strings.xml
+++ b/java/res/values-pl/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Powiadomienia adaptacyjne w Androidzie"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"przypiąć"</item>
+    <item msgid="7174505163902448507">"hasło"</item>
+    <item msgid="3917837442156595568">"hasło"</item>
+    <item msgid="6971032950332150936">"dwuskładnikowe"</item>
+    <item msgid="826248726164877615">"wielopoziomowe"</item>
+    <item msgid="2156400793251117724">"logowanie"</item>
+    <item msgid="3621495493711216796">"zaloguj się"</item>
+    <item msgid="4652629344958695406">"zalogować się"</item>
+    <item msgid="6021138326345874403">"uwierzytelnij"</item>
+    <item msgid="301989899519648952">"uwierzytelnianie"</item>
+    <item msgid="2409846400635400651">"kod"</item>
+    <item msgid="3362500960690003002">"tajne"</item>
+    <item msgid="1542192064842556988">"zweryfikuj"</item>
+    <item msgid="2052362882225775298">"weryfikacja"</item>
+    <item msgid="4759495520595696444">"potwierdź"</item>
+    <item msgid="4360404417991731370">"potwierdzenie"</item>
+    <item msgid="5135302120938115660">"jednorazowy"</item>
+    <item msgid="405482768547359066">"wejdź do"</item>
+    <item msgid="7962233525908588330">"walidacja"</item>
+    <item msgid="9095545913763732113">"weryfikuj"</item>
+    <item msgid="2601700967903477651">"pojedyncze użycie"</item>
+    <item msgid="1775341814323929840">"autoryzuj"</item>
+    <item msgid="4159587727958533896">"autoryzacja"</item>
+    <item msgid="7199374258785307822">"osobisty numer identyfikacyjny"</item>
+    <item msgid="3860872742161492043">"kod PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-pt-rBR/strings.xml b/java/res/values-pt-rBR/strings.xml
index 2d1d15c..58f06d6 100644
--- a/java/res/values-pt-rBR/strings.xml
+++ b/java/res/values-pt-rBR/strings.xml
@@ -16,5 +16,32 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="notification_assistant" msgid="9160940242838910547">"Notificações adaptáveis do Android"</string>
+    <string name="notification_assistant" msgid="9160940242838910547">"Notificações adaptativas do Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"senha"</item>
+    <item msgid="3917837442156595568">"senha"</item>
+    <item msgid="6971032950332150936">"dois fatores"</item>
+    <item msgid="826248726164877615">"dois fatores"</item>
+    <item msgid="2156400793251117724">"login"</item>
+    <item msgid="3621495493711216796">"fazer login"</item>
+    <item msgid="4652629344958695406">"login"</item>
+    <item msgid="6021138326345874403">"autenticar"</item>
+    <item msgid="301989899519648952">"autenticação"</item>
+    <item msgid="2409846400635400651">"código"</item>
+    <item msgid="3362500960690003002">"segredo"</item>
+    <item msgid="1542192064842556988">"verificar"</item>
+    <item msgid="2052362882225775298">"verificação"</item>
+    <item msgid="4759495520595696444">"confirmar"</item>
+    <item msgid="4360404417991731370">"confirmação"</item>
+    <item msgid="5135302120938115660">"de uso único"</item>
+    <item msgid="405482768547359066">"acesso"</item>
+    <item msgid="7962233525908588330">"validação"</item>
+    <item msgid="9095545913763732113">"validar"</item>
+    <item msgid="2601700967903477651">"uso único"</item>
+    <item msgid="1775341814323929840">"autorizar"</item>
+    <item msgid="4159587727958533896">"autorização"</item>
+    <item msgid="7199374258785307822">"número de identificação pessoal"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-pt-rPT/strings.xml b/java/res/values-pt-rPT/strings.xml
index 2d1d15c..2c5cc39 100644
--- a/java/res/values-pt-rPT/strings.xml
+++ b/java/res/values-pt-rPT/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Notificações adaptáveis do Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"palavra-passe"</item>
+    <item msgid="3917837442156595568">"código secreto"</item>
+    <item msgid="6971032950332150936">"dois fatores"</item>
+    <item msgid="826248726164877615">"dois fatores"</item>
+    <item msgid="2156400793251117724">"início de sessão"</item>
+    <item msgid="3621495493711216796">"início de sessão"</item>
+    <item msgid="4652629344958695406">"iniciar"</item>
+    <item msgid="6021138326345874403">"autenticar"</item>
+    <item msgid="301989899519648952">"autenticação"</item>
+    <item msgid="2409846400635400651">"código"</item>
+    <item msgid="3362500960690003002">"segredo"</item>
+    <item msgid="1542192064842556988">"validar"</item>
+    <item msgid="2052362882225775298">"validação"</item>
+    <item msgid="4759495520595696444">"confirmar"</item>
+    <item msgid="4360404417991731370">"confirmação"</item>
+    <item msgid="5135302120938115660">"uma vez"</item>
+    <item msgid="405482768547359066">"acesso"</item>
+    <item msgid="7962233525908588330">"validação"</item>
+    <item msgid="9095545913763732113">"validar"</item>
+    <item msgid="2601700967903477651">"utilização única"</item>
+    <item msgid="1775341814323929840">"autorizar"</item>
+    <item msgid="4159587727958533896">"autorização"</item>
+    <item msgid="7199374258785307822">"número de identificação pessoal"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-pt/strings.xml b/java/res/values-pt/strings.xml
index 2d1d15c..58f06d6 100644
--- a/java/res/values-pt/strings.xml
+++ b/java/res/values-pt/strings.xml
@@ -16,5 +16,32 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="notification_assistant" msgid="9160940242838910547">"Notificações adaptáveis do Android"</string>
+    <string name="notification_assistant" msgid="9160940242838910547">"Notificações adaptativas do Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"senha"</item>
+    <item msgid="3917837442156595568">"senha"</item>
+    <item msgid="6971032950332150936">"dois fatores"</item>
+    <item msgid="826248726164877615">"dois fatores"</item>
+    <item msgid="2156400793251117724">"login"</item>
+    <item msgid="3621495493711216796">"fazer login"</item>
+    <item msgid="4652629344958695406">"login"</item>
+    <item msgid="6021138326345874403">"autenticar"</item>
+    <item msgid="301989899519648952">"autenticação"</item>
+    <item msgid="2409846400635400651">"código"</item>
+    <item msgid="3362500960690003002">"segredo"</item>
+    <item msgid="1542192064842556988">"verificar"</item>
+    <item msgid="2052362882225775298">"verificação"</item>
+    <item msgid="4759495520595696444">"confirmar"</item>
+    <item msgid="4360404417991731370">"confirmação"</item>
+    <item msgid="5135302120938115660">"de uso único"</item>
+    <item msgid="405482768547359066">"acesso"</item>
+    <item msgid="7962233525908588330">"validação"</item>
+    <item msgid="9095545913763732113">"validar"</item>
+    <item msgid="2601700967903477651">"uso único"</item>
+    <item msgid="1775341814323929840">"autorizar"</item>
+    <item msgid="4159587727958533896">"autorização"</item>
+    <item msgid="7199374258785307822">"número de identificação pessoal"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ro/strings.xml b/java/res/values-ro/strings.xml
index 6985c29..148da15 100644
--- a/java/res/values-ro/strings.xml
+++ b/java/res/values-ro/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Notificări adaptive Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"parolă"</item>
+    <item msgid="3917837442156595568">"cod de acces"</item>
+    <item msgid="6971032950332150936">"doi factori"</item>
+    <item msgid="826248726164877615">"2 factori"</item>
+    <item msgid="2156400793251117724">"date de conectare"</item>
+    <item msgid="3621495493711216796">"conectează-te"</item>
+    <item msgid="4652629344958695406">"conectare"</item>
+    <item msgid="6021138326345874403">"autentifică-te"</item>
+    <item msgid="301989899519648952">"autentificare"</item>
+    <item msgid="2409846400635400651">"cod"</item>
+    <item msgid="3362500960690003002">"secret"</item>
+    <item msgid="1542192064842556988">"verifică"</item>
+    <item msgid="2052362882225775298">"verificare"</item>
+    <item msgid="4759495520595696444">"confirmă"</item>
+    <item msgid="4360404417991731370">"confirmare"</item>
+    <item msgid="5135302120938115660">"unic"</item>
+    <item msgid="405482768547359066">"acces"</item>
+    <item msgid="7962233525908588330">"validare"</item>
+    <item msgid="9095545913763732113">"validează"</item>
+    <item msgid="2601700967903477651">"o singură utilizare"</item>
+    <item msgid="1775341814323929840">"autorizează"</item>
+    <item msgid="4159587727958533896">"autorizare"</item>
+    <item msgid="7199374258785307822">"număr de identificare personală"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ru/strings.xml b/java/res/values-ru/strings.xml
index 6d4080b..fa9fe7a 100644
--- a/java/res/values-ru/strings.xml
+++ b/java/res/values-ru/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Адаптивные уведомления для Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN-код"</item>
+    <item msgid="7174505163902448507">"пароль"</item>
+    <item msgid="3917837442156595568">"код доступа"</item>
+    <item msgid="6971032950332150936">"двухэтапная"</item>
+    <item msgid="826248726164877615">"двухэтапная"</item>
+    <item msgid="2156400793251117724">"вход"</item>
+    <item msgid="3621495493711216796">"войти"</item>
+    <item msgid="4652629344958695406">"войти"</item>
+    <item msgid="6021138326345874403">"пройти аутентификацию"</item>
+    <item msgid="301989899519648952">"аутентификация"</item>
+    <item msgid="2409846400635400651">"код"</item>
+    <item msgid="3362500960690003002">"секрет"</item>
+    <item msgid="1542192064842556988">"подтвердить"</item>
+    <item msgid="2052362882225775298">"проверка"</item>
+    <item msgid="4759495520595696444">"подтвердить"</item>
+    <item msgid="4360404417991731370">"подтверждение"</item>
+    <item msgid="5135302120938115660">"один раз"</item>
+    <item msgid="405482768547359066">"доступ"</item>
+    <item msgid="7962233525908588330">"проверка"</item>
+    <item msgid="9095545913763732113">"проверить"</item>
+    <item msgid="2601700967903477651">"однократное использование"</item>
+    <item msgid="1775341814323929840">"пройти авторизацию"</item>
+    <item msgid="4159587727958533896">"авторизация"</item>
+    <item msgid="7199374258785307822">"персональный идентификационный номер"</item>
+    <item msgid="3860872742161492043">"PIN-код"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-si/strings.xml b/java/res/values-si/strings.xml
index d5a5c1a..e5b8b5c 100644
--- a/java/res/values-si/strings.xml
+++ b/java/res/values-si/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android අනුවර්තී දැනුම් දීම්"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"මුරපදය"</item>
+    <item msgid="3917837442156595568">"මුරකේතය"</item>
+    <item msgid="6971032950332150936">"සාධක දෙක"</item>
+    <item msgid="826248726164877615">"ද්වි-සාධක"</item>
+    <item msgid="2156400793251117724">"පුරන්න"</item>
+    <item msgid="3621495493711216796">"පුරනය වීම"</item>
+    <item msgid="4652629344958695406">"පුරනය වන්න"</item>
+    <item msgid="6021138326345874403">"සත්‍යවත් කරන්න"</item>
+    <item msgid="301989899519648952">"සත්‍යවත් කිරීම"</item>
+    <item msgid="2409846400635400651">"කේතය"</item>
+    <item msgid="3362500960690003002">"රහස"</item>
+    <item msgid="1542192064842556988">"සත්‍යාපනය කරන්න"</item>
+    <item msgid="2052362882225775298">"සත්‍යාපනය"</item>
+    <item msgid="4759495520595696444">"තහවුරු කරන්න"</item>
+    <item msgid="4360404417991731370">"තහවුරු කිරීම"</item>
+    <item msgid="5135302120938115660">"එක වරක්"</item>
+    <item msgid="405482768547359066">"ප්‍රවේශය"</item>
+    <item msgid="7962233525908588330">"වලංගුකරණය"</item>
+    <item msgid="9095545913763732113">"වලංගු කරන්න"</item>
+    <item msgid="2601700967903477651">"තනි භාවිතය"</item>
+    <item msgid="1775341814323929840">"අනුමැතිය දෙන්න"</item>
+    <item msgid="4159587727958533896">"අනුමැතිය"</item>
+    <item msgid="7199374258785307822">"පුද්ගලික හැඳුනුම් අංකය"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-sk/strings.xml b/java/res/values-sk/strings.xml
index b084233..0e5e10f 100644
--- a/java/res/values-sk/strings.xml
+++ b/java/res/values-sk/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Adaptívne upozornenia Androidu"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"heslo"</item>
+    <item msgid="3917837442156595568">"vstupný kód"</item>
+    <item msgid="6971032950332150936">"dvojstupňové"</item>
+    <item msgid="826248726164877615">"dvojstupňové"</item>
+    <item msgid="2156400793251117724">"prihlásenie"</item>
+    <item msgid="3621495493711216796">"prihláste sa"</item>
+    <item msgid="4652629344958695406">"prihláste sa"</item>
+    <item msgid="6021138326345874403">"overte"</item>
+    <item msgid="301989899519648952">"overenie"</item>
+    <item msgid="2409846400635400651">"kód"</item>
+    <item msgid="3362500960690003002">"tajné"</item>
+    <item msgid="1542192064842556988">"overte"</item>
+    <item msgid="2052362882225775298">"overenie"</item>
+    <item msgid="4759495520595696444">"potvrďte"</item>
+    <item msgid="4360404417991731370">"potvrdenie"</item>
+    <item msgid="5135302120938115660">"jednorazové"</item>
+    <item msgid="405482768547359066">"prístup"</item>
+    <item msgid="7962233525908588330">"overenie"</item>
+    <item msgid="9095545913763732113">"overte"</item>
+    <item msgid="2601700967903477651">"jednorazové použitie"</item>
+    <item msgid="1775341814323929840">"autorizujte"</item>
+    <item msgid="4159587727958533896">"autorizácia"</item>
+    <item msgid="7199374258785307822">"osobné identifikačné číslo"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-sl/strings.xml b/java/res/values-sl/strings.xml
index 9d2f0cf..68338e0 100644
--- a/java/res/values-sl/strings.xml
+++ b/java/res/values-sl/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Prilagodljiva obvestila Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"geslo"</item>
+    <item msgid="3917837442156595568">"koda za preverjanje"</item>
+    <item msgid="6971032950332150936">"dvojno"</item>
+    <item msgid="826248726164877615">"v dveh korakih"</item>
+    <item msgid="2156400793251117724">"prijava"</item>
+    <item msgid="3621495493711216796">"za prijavo"</item>
+    <item msgid="4652629344958695406">"prijavite se"</item>
+    <item msgid="6021138326345874403">"preveri pristnost"</item>
+    <item msgid="301989899519648952">"preverjanje pristnosti"</item>
+    <item msgid="2409846400635400651">"koda"</item>
+    <item msgid="3362500960690003002">"skrivnost"</item>
+    <item msgid="1542192064842556988">"potrdite"</item>
+    <item msgid="2052362882225775298">"potrjevanje"</item>
+    <item msgid="4759495520595696444">"potrdi"</item>
+    <item msgid="4360404417991731370">"potrditev"</item>
+    <item msgid="5135302120938115660">"enkratna"</item>
+    <item msgid="405482768547359066">"dostop"</item>
+    <item msgid="7962233525908588330">"preverjanje"</item>
+    <item msgid="9095545913763732113">"preveri"</item>
+    <item msgid="2601700967903477651">"za enkratno uporabo"</item>
+    <item msgid="1775341814323929840">"pooblasti"</item>
+    <item msgid="4159587727958533896">"pooblastitev"</item>
+    <item msgid="7199374258785307822">"številka za osebno identifikacijo"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-sq/strings.xml b/java/res/values-sq/strings.xml
index 270a97a..609d8a6 100644
--- a/java/res/values-sq/strings.xml
+++ b/java/res/values-sq/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Njoftimet me përshtatje të Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"gozhdo"</item>
+    <item msgid="7174505163902448507">"fjalëkalim"</item>
+    <item msgid="3917837442156595568">"kodi i kalimit"</item>
+    <item msgid="6971032950332150936">"me dy faktorë"</item>
+    <item msgid="826248726164877615">"me dy faktorë"</item>
+    <item msgid="2156400793251117724">"identifikohu"</item>
+    <item msgid="3621495493711216796">"identifikim"</item>
+    <item msgid="4652629344958695406">"identifikohu"</item>
+    <item msgid="6021138326345874403">"vërteto"</item>
+    <item msgid="301989899519648952">"vërtetim"</item>
+    <item msgid="2409846400635400651">"kod"</item>
+    <item msgid="3362500960690003002">"sekret"</item>
+    <item msgid="1542192064842556988">"verifiko"</item>
+    <item msgid="2052362882225775298">"verifikim"</item>
+    <item msgid="4759495520595696444">"konfirmo"</item>
+    <item msgid="4360404417991731370">"konfirmim"</item>
+    <item msgid="5135302120938115660">"për një herë"</item>
+    <item msgid="405482768547359066">"qasje"</item>
+    <item msgid="7962233525908588330">"verifikim"</item>
+    <item msgid="9095545913763732113">"verifiko"</item>
+    <item msgid="2601700967903477651">"njëpërdorimësh"</item>
+    <item msgid="1775341814323929840">"autorizo"</item>
+    <item msgid="4159587727958533896">"autorizim"</item>
+    <item msgid="7199374258785307822">"numri personal i identifikimit"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-sr/strings.xml b/java/res/values-sr/strings.xml
index f530b1c..1519f32 100644
--- a/java/res/values-sr/strings.xml
+++ b/java/res/values-sr/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Прилагодљива обавештења за Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"лозинка"</item>
+    <item msgid="3917837442156595568">"шифра"</item>
+    <item msgid="6971032950332150936">"у два корака"</item>
+    <item msgid="826248726164877615">"у два корака"</item>
+    <item msgid="2156400793251117724">"пријављивање"</item>
+    <item msgid="3621495493711216796">"пријави ме"</item>
+    <item msgid="4652629344958695406">"пријава"</item>
+    <item msgid="6021138326345874403">"потврдите идентитет"</item>
+    <item msgid="301989899519648952">"потврда аутентичности"</item>
+    <item msgid="2409846400635400651">"кôд"</item>
+    <item msgid="3362500960690003002">"тајна"</item>
+    <item msgid="1542192064842556988">"верификуј"</item>
+    <item msgid="2052362882225775298">"верификација"</item>
+    <item msgid="4759495520595696444">"потврди"</item>
+    <item msgid="4360404417991731370">"потврда"</item>
+    <item msgid="5135302120938115660">"једнократно"</item>
+    <item msgid="405482768547359066">"приступ"</item>
+    <item msgid="7962233525908588330">"валидација"</item>
+    <item msgid="9095545913763732113">"провери"</item>
+    <item msgid="2601700967903477651">"једно коришћење"</item>
+    <item msgid="1775341814323929840">"овласти"</item>
+    <item msgid="4159587727958533896">"овлашћење"</item>
+    <item msgid="7199374258785307822">"лични идентификациони број"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-sv/strings.xml b/java/res/values-sv/strings.xml
index c1ea373..4f666a5 100644
--- a/java/res/values-sv/strings.xml
+++ b/java/res/values-sv/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android anp. aviseringar"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pinkod"</item>
+    <item msgid="7174505163902448507">"lösenord"</item>
+    <item msgid="3917837442156595568">"lösenord"</item>
+    <item msgid="6971032950332150936">"tvåfaktorsautentisering"</item>
+    <item msgid="826248726164877615">"tvåfaktorsautentisering"</item>
+    <item msgid="2156400793251117724">"inloggning"</item>
+    <item msgid="3621495493711216796">"inloggning"</item>
+    <item msgid="4652629344958695406">"logga in"</item>
+    <item msgid="6021138326345874403">"autentisera"</item>
+    <item msgid="301989899519648952">"autentisering"</item>
+    <item msgid="2409846400635400651">"kod"</item>
+    <item msgid="3362500960690003002">"hemlighet"</item>
+    <item msgid="1542192064842556988">"verifiera"</item>
+    <item msgid="2052362882225775298">"verifiering"</item>
+    <item msgid="4759495520595696444">"bekräfta"</item>
+    <item msgid="4360404417991731370">"bekräftelse"</item>
+    <item msgid="5135302120938115660">"en gång"</item>
+    <item msgid="405482768547359066">"åtkomst"</item>
+    <item msgid="7962233525908588330">"validering"</item>
+    <item msgid="9095545913763732113">"validera"</item>
+    <item msgid="2601700967903477651">"engångsbruk"</item>
+    <item msgid="1775341814323929840">"auktorisera"</item>
+    <item msgid="4159587727958533896">"auktorisering"</item>
+    <item msgid="7199374258785307822">"personnummer"</item>
+    <item msgid="3860872742161492043">"pinkod"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-sw/strings.xml b/java/res/values-sw/strings.xml
index 4cea87c..f6dce44 100644
--- a/java/res/values-sw/strings.xml
+++ b/java/res/values-sw/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Arifa Zinazojirekebisha za Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"nenosiri"</item>
+    <item msgid="3917837442156595568">"namba ya siri"</item>
+    <item msgid="6971032950332150936">"hatua mbili"</item>
+    <item msgid="826248726164877615">"hatua mbili"</item>
+    <item msgid="2156400793251117724">"ingia katika akaunti"</item>
+    <item msgid="3621495493711216796">"ingia katika akaunti"</item>
+    <item msgid="4652629344958695406">"ingia katika akaunti"</item>
+    <item msgid="6021138326345874403">"thibitisha"</item>
+    <item msgid="301989899519648952">"uthibitishaji"</item>
+    <item msgid="2409846400635400651">"namba ya kuthibitisha"</item>
+    <item msgid="3362500960690003002">"siri"</item>
+    <item msgid="1542192064842556988">"thibitisha"</item>
+    <item msgid="2052362882225775298">"uthibitishaji"</item>
+    <item msgid="4759495520595696444">"thibitisha"</item>
+    <item msgid="4360404417991731370">"uthibitishaji"</item>
+    <item msgid="5135302120938115660">"mara moja"</item>
+    <item msgid="405482768547359066">"uwezo wa kufikia"</item>
+    <item msgid="7962233525908588330">"uthibitishaji"</item>
+    <item msgid="9095545913763732113">"thibitisha"</item>
+    <item msgid="2601700967903477651">"matumizi ya mara moja"</item>
+    <item msgid="1775341814323929840">"idhinisha"</item>
+    <item msgid="4159587727958533896">"uidhinishaji"</item>
+    <item msgid="7199374258785307822">"namba binafsi ya utambulisho"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ta/strings.xml b/java/res/values-ta/strings.xml
index 13fef9b..6c3e810 100644
--- a/java/res/values-ta/strings.xml
+++ b/java/res/values-ta/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android சூழலுக்கேற்ற அறிவிப்புகள்"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"பின்"</item>
+    <item msgid="7174505163902448507">"கடவுச்சொல்"</item>
+    <item msgid="3917837442156595568">"கடவுக்குறியீடு"</item>
+    <item msgid="6971032950332150936">"இருபடி"</item>
+    <item msgid="826248726164877615">"இரு-படி"</item>
+    <item msgid="2156400793251117724">"உள்நுழைவு"</item>
+    <item msgid="3621495493711216796">"உள்நுழை"</item>
+    <item msgid="4652629344958695406">"உள்நுழையுங்கள்"</item>
+    <item msgid="6021138326345874403">"அங்கீகரியுங்கள்"</item>
+    <item msgid="301989899519648952">"அங்கீகரிப்பு"</item>
+    <item msgid="2409846400635400651">"குறியீடு"</item>
+    <item msgid="3362500960690003002">"ரகசியம்"</item>
+    <item msgid="1542192064842556988">"சரிபாருங்கள்"</item>
+    <item msgid="2052362882225775298">"சரிபார்ப்பு"</item>
+    <item msgid="4759495520595696444">"உறுதிப்படுத்துங்கள்"</item>
+    <item msgid="4360404417991731370">"உறுதிப்படுத்துதல்"</item>
+    <item msgid="5135302120938115660">"ஒருமுறை"</item>
+    <item msgid="405482768547359066">"அணுகல்"</item>
+    <item msgid="7962233525908588330">"சரிபார்ப்பு"</item>
+    <item msgid="9095545913763732113">"சரிபாருங்கள்"</item>
+    <item msgid="2601700967903477651">"ஒற்றைப் பயன்பாடு"</item>
+    <item msgid="1775341814323929840">"அங்கீகரியுங்கள்"</item>
+    <item msgid="4159587727958533896">"அங்கீகாரம்"</item>
+    <item msgid="7199374258785307822">"தனிநபர் அடையாள எண்"</item>
+    <item msgid="3860872742161492043">"பின்"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-te/strings.xml b/java/res/values-te/strings.xml
index 5bacbc8..3b0d01a 100644
--- a/java/res/values-te/strings.xml
+++ b/java/res/values-te/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android అడాప్టివ్ నోటిఫికేషన్‌లు"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"పాస్‌వర్డ్"</item>
+    <item msgid="3917837442156595568">"పాస్‌కోడ్"</item>
+    <item msgid="6971032950332150936">"రెండు దశల"</item>
+    <item msgid="826248726164877615">"రెండు-దశల"</item>
+    <item msgid="2156400793251117724">"లాగిన్ అవ్వండి"</item>
+    <item msgid="3621495493711216796">"లాగిన్ అవ్వండి"</item>
+    <item msgid="4652629344958695406">"లాగిన్ అవ్వండి"</item>
+    <item msgid="6021138326345874403">"ప్రామాణీకరించండి"</item>
+    <item msgid="301989899519648952">"ప్రామాణీకరణ"</item>
+    <item msgid="2409846400635400651">"కోడ్"</item>
+    <item msgid="3362500960690003002">"రహస్యం"</item>
+    <item msgid="1542192064842556988">"వెరిఫై చేయండి"</item>
+    <item msgid="2052362882225775298">"వెరిఫికేషన్"</item>
+    <item msgid="4759495520595696444">"నిర్ధారించండి"</item>
+    <item msgid="4360404417991731370">"నిర్ధారణ"</item>
+    <item msgid="5135302120938115660">"ఒకసారి ఉపయోగించగలది"</item>
+    <item msgid="405482768547359066">"యాక్సెస్"</item>
+    <item msgid="7962233525908588330">"వ్యాలిడేషన్"</item>
+    <item msgid="9095545913763732113">"వ్యాలిడేట్ చేయండి"</item>
+    <item msgid="2601700967903477651">"ఒకసారి ఉపయోగించగలది"</item>
+    <item msgid="1775341814323929840">"ప్రామాణీకరించండి"</item>
+    <item msgid="4159587727958533896">"ప్రామాణీకరణ"</item>
+    <item msgid="7199374258785307822">"వ్యక్తిగత గుర్తింపు నంబర్"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-th/strings.xml b/java/res/values-th/strings.xml
index b17adbe..2df5da4 100644
--- a/java/res/values-th/strings.xml
+++ b/java/res/values-th/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"การแจ้งเตือนแบบปรับอัตโนมัติใน Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"รหัสผ่าน"</item>
+    <item msgid="3917837442156595568">"รหัสผ่าน"</item>
+    <item msgid="6971032950332150936">"การตรวจสอบสิทธิ์แบบ 2 ปัจจัย"</item>
+    <item msgid="826248726164877615">"การตรวจสอบสิทธิ์แบบ 2 ปัจจัย"</item>
+    <item msgid="2156400793251117724">"เข้าสู่ระบบ"</item>
+    <item msgid="3621495493711216796">"เข้าสู่ระบบ"</item>
+    <item msgid="4652629344958695406">"เข้าสู่ระบบ"</item>
+    <item msgid="6021138326345874403">"ตรวจสอบสิทธิ์"</item>
+    <item msgid="301989899519648952">"การตรวจสอบสิทธิ์"</item>
+    <item msgid="2409846400635400651">"รหัส"</item>
+    <item msgid="3362500960690003002">"ข้อมูลลับ"</item>
+    <item msgid="1542192064842556988">"ยืนยัน"</item>
+    <item msgid="2052362882225775298">"การยืนยัน"</item>
+    <item msgid="4759495520595696444">"ยืนยัน"</item>
+    <item msgid="4360404417991731370">"การยืนยัน"</item>
+    <item msgid="5135302120938115660">"ครั้งเดียว"</item>
+    <item msgid="405482768547359066">"การเข้าถึง"</item>
+    <item msgid="7962233525908588330">"การตรวจสอบความถูกต้อง"</item>
+    <item msgid="9095545913763732113">"สอบความถูกต้อง"</item>
+    <item msgid="2601700967903477651">"ใช้ครั้งเดียว"</item>
+    <item msgid="1775341814323929840">"ให้สิทธิ์"</item>
+    <item msgid="4159587727958533896">"การให้สิทธิ์"</item>
+    <item msgid="7199374258785307822">"หมายเลขประจำตัวส่วนบุคคล"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-tl/strings.xml b/java/res/values-tl/strings.xml
index 64a314d..61e4aa6 100644
--- a/java/res/values-tl/strings.xml
+++ b/java/res/values-tl/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Mga Adaptive na Notification ng Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"password"</item>
+    <item msgid="3917837442156595568">"passcode"</item>
+    <item msgid="6971032950332150936">"two factor"</item>
+    <item msgid="826248726164877615">"two-factor"</item>
+    <item msgid="2156400793251117724">"mag-log in"</item>
+    <item msgid="3621495493711216796">"mag-log in"</item>
+    <item msgid="4652629344958695406">"mag-log in"</item>
+    <item msgid="6021138326345874403">"i-authenticate"</item>
+    <item msgid="301989899519648952">"pag-authenticate"</item>
+    <item msgid="2409846400635400651">"code"</item>
+    <item msgid="3362500960690003002">"lihim"</item>
+    <item msgid="1542192064842556988">"i-verify"</item>
+    <item msgid="2052362882225775298">"pag-verify"</item>
+    <item msgid="4759495520595696444">"ikumpirma"</item>
+    <item msgid="4360404417991731370">"kumpirmasyon"</item>
+    <item msgid="5135302120938115660">"isang beses"</item>
+    <item msgid="405482768547359066">"i-access"</item>
+    <item msgid="7962233525908588330">"pag-validate"</item>
+    <item msgid="9095545913763732113">"i-validate"</item>
+    <item msgid="2601700967903477651">"pang-isang gamit"</item>
+    <item msgid="1775341814323929840">"pahintulutan"</item>
+    <item msgid="4159587727958533896">"pahintulot"</item>
+    <item msgid="7199374258785307822">"personal na numero ng pagkakakilanlan"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-tr/strings.xml b/java/res/values-tr/strings.xml
index 43d39a7..8d53081 100644
--- a/java/res/values-tr/strings.xml
+++ b/java/res/values-tr/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android Uyarlanabilir Bildirimler"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN"</item>
+    <item msgid="7174505163902448507">"şifre"</item>
+    <item msgid="3917837442156595568">"şifre kodu"</item>
+    <item msgid="6971032950332150936">"iki faktörlü"</item>
+    <item msgid="826248726164877615">"iki faktörlü"</item>
+    <item msgid="2156400793251117724">"giriş"</item>
+    <item msgid="3621495493711216796">"giriş"</item>
+    <item msgid="4652629344958695406">"giriş yapma"</item>
+    <item msgid="6021138326345874403">"kimlik doğrulaması yapma"</item>
+    <item msgid="301989899519648952">"kimlik doğrulama"</item>
+    <item msgid="2409846400635400651">"kod"</item>
+    <item msgid="3362500960690003002">"gizli anahtar"</item>
+    <item msgid="1542192064842556988">"doğrula"</item>
+    <item msgid="2052362882225775298">"doğrulama"</item>
+    <item msgid="4759495520595696444">"onayla"</item>
+    <item msgid="4360404417991731370">"onay"</item>
+    <item msgid="5135302120938115660">"bir kerelik"</item>
+    <item msgid="405482768547359066">"erişim"</item>
+    <item msgid="7962233525908588330">"doğrulama"</item>
+    <item msgid="9095545913763732113">"doğrula"</item>
+    <item msgid="2601700967903477651">"tek kullanımlık"</item>
+    <item msgid="1775341814323929840">"yetkilendir"</item>
+    <item msgid="4159587727958533896">"yetkilendirme"</item>
+    <item msgid="7199374258785307822">"kişisel kimlik numarası"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-uk/strings.xml b/java/res/values-uk/strings.xml
index 15f2860..b2be4d6 100644
--- a/java/res/values-uk/strings.xml
+++ b/java/res/values-uk/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Адаптивні сповіщення Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN-код"</item>
+    <item msgid="7174505163902448507">"пароль"</item>
+    <item msgid="3917837442156595568">"код доступу"</item>
+    <item msgid="6971032950332150936">"двохетапна"</item>
+    <item msgid="826248726164877615">"двохетапна"</item>
+    <item msgid="2156400793251117724">"вхід"</item>
+    <item msgid="3621495493711216796">"вхід"</item>
+    <item msgid="4652629344958695406">"увійти"</item>
+    <item msgid="6021138326345874403">"автентифікувати"</item>
+    <item msgid="301989899519648952">"автентифікація"</item>
+    <item msgid="2409846400635400651">"код"</item>
+    <item msgid="3362500960690003002">"секрет"</item>
+    <item msgid="1542192064842556988">"підтвердити"</item>
+    <item msgid="2052362882225775298">"підтвердження"</item>
+    <item msgid="4759495520595696444">"підтвердити"</item>
+    <item msgid="4360404417991731370">"підтвердження"</item>
+    <item msgid="5135302120938115660">"одноразовий"</item>
+    <item msgid="405482768547359066">"доступ"</item>
+    <item msgid="7962233525908588330">"перевірка"</item>
+    <item msgid="9095545913763732113">"перевірити"</item>
+    <item msgid="2601700967903477651">"одноразовий"</item>
+    <item msgid="1775341814323929840">"авторизувати"</item>
+    <item msgid="4159587727958533896">"авторизація"</item>
+    <item msgid="7199374258785307822">"персональний ідентифікаційний номер"</item>
+    <item msgid="3860872742161492043">"PIN-код"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-ur/strings.xml b/java/res/values-ur/strings.xml
index 24c8d3b..2f38c5a 100644
--- a/java/res/values-ur/strings.xml
+++ b/java/res/values-ur/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"‏Android اڈاپٹیو اطلاعات"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"پن کریں"</item>
+    <item msgid="7174505163902448507">"پاس ورڈ"</item>
+    <item msgid="3917837442156595568">"پاس کوڈ"</item>
+    <item msgid="6971032950332150936">"دو عنصری"</item>
+    <item msgid="826248726164877615">"دو عنصری"</item>
+    <item msgid="2156400793251117724">"لاگ ان کریں"</item>
+    <item msgid="3621495493711216796">"لاگ ان کریں"</item>
+    <item msgid="4652629344958695406">"لاگ ان کریں"</item>
+    <item msgid="6021138326345874403">"تصدیق کریں"</item>
+    <item msgid="301989899519648952">"تصدیق"</item>
+    <item msgid="2409846400635400651">"کوڈ"</item>
+    <item msgid="3362500960690003002">"راز"</item>
+    <item msgid="1542192064842556988">"توثیق کریں"</item>
+    <item msgid="2052362882225775298">"توثیق"</item>
+    <item msgid="4759495520595696444">"توثیق کریں"</item>
+    <item msgid="4360404417991731370">"توثیق"</item>
+    <item msgid="5135302120938115660">"یک وقتی"</item>
+    <item msgid="405482768547359066">"رسائی"</item>
+    <item msgid="7962233525908588330">"توثیق"</item>
+    <item msgid="9095545913763732113">"توثیق کریں"</item>
+    <item msgid="2601700967903477651">"واحد استعمال"</item>
+    <item msgid="1775341814323929840">"اجازت دیں"</item>
+    <item msgid="4159587727958533896">"منظوری"</item>
+    <item msgid="7199374258785307822">"ذاتی شناختی نمبر"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-uz/strings.xml b/java/res/values-uz/strings.xml
index 6bcdada..8e56e45 100644
--- a/java/res/values-uz/strings.xml
+++ b/java/res/values-uz/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android moslashuvchan bildirishnomalari"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"qadash"</item>
+    <item msgid="7174505163902448507">"parol"</item>
+    <item msgid="3917837442156595568">"kirish kodi"</item>
+    <item msgid="6971032950332150936">"ikki bosqichli"</item>
+    <item msgid="826248726164877615">"ikki bosqichli"</item>
+    <item msgid="2156400793251117724">"tizimga kirish"</item>
+    <item msgid="3621495493711216796">"tizimga kirish"</item>
+    <item msgid="4652629344958695406">"tizimga kirish"</item>
+    <item msgid="6021138326345874403">"autentifikatsiya"</item>
+    <item msgid="301989899519648952">"autentifikatsiya"</item>
+    <item msgid="2409846400635400651">"kod"</item>
+    <item msgid="3362500960690003002">"sir"</item>
+    <item msgid="1542192064842556988">"tekshirish"</item>
+    <item msgid="2052362882225775298">"tasdiqlash"</item>
+    <item msgid="4759495520595696444">"tasdiqlash"</item>
+    <item msgid="4360404417991731370">"tasdiq"</item>
+    <item msgid="5135302120938115660">"bir martalik"</item>
+    <item msgid="405482768547359066">"kirish"</item>
+    <item msgid="7962233525908588330">"tekshiruv"</item>
+    <item msgid="9095545913763732113">"tekshirish"</item>
+    <item msgid="2601700967903477651">"bir martalik"</item>
+    <item msgid="1775341814323929840">"ruxsat berish"</item>
+    <item msgid="4159587727958533896">"ruxsat berish"</item>
+    <item msgid="7199374258785307822">"shaxsiy identifikatsiya raqami"</item>
+    <item msgid="3860872742161492043">"PIN kod"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-vi/strings.xml b/java/res/values-vi/strings.xml
index 4afd38b..818980b 100644
--- a/java/res/values-vi/strings.xml
+++ b/java/res/values-vi/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Thông báo thích ứng trên Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"mã PIN"</item>
+    <item msgid="7174505163902448507">"mật khẩu"</item>
+    <item msgid="3917837442156595568">"mật mã"</item>
+    <item msgid="6971032950332150936">"hai yếu tố"</item>
+    <item msgid="826248726164877615">"hai yếu tố"</item>
+    <item msgid="2156400793251117724">"đăng nhập"</item>
+    <item msgid="3621495493711216796">"đăng nhập"</item>
+    <item msgid="4652629344958695406">"đăng nhập"</item>
+    <item msgid="6021138326345874403">"xác thực"</item>
+    <item msgid="301989899519648952">"xác thực"</item>
+    <item msgid="2409846400635400651">"mã"</item>
+    <item msgid="3362500960690003002">"bí mật"</item>
+    <item msgid="1542192064842556988">"xác minh"</item>
+    <item msgid="2052362882225775298">"xác minh"</item>
+    <item msgid="4759495520595696444">"xác nhận"</item>
+    <item msgid="4360404417991731370">"xác nhận"</item>
+    <item msgid="5135302120938115660">"một lần"</item>
+    <item msgid="405482768547359066">"truy cập"</item>
+    <item msgid="7962233525908588330">"xác thực"</item>
+    <item msgid="9095545913763732113">"xác thực"</item>
+    <item msgid="2601700967903477651">"một lần"</item>
+    <item msgid="1775341814323929840">"uỷ quyền"</item>
+    <item msgid="4159587727958533896">"uỷ quyền"</item>
+    <item msgid="7199374258785307822">"số định danh cá nhân"</item>
+    <item msgid="3860872742161492043">"mã PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-zh-rCN/strings.xml b/java/res/values-zh-rCN/strings.xml
index 6d6daa5..53fb4ea 100644
--- a/java/res/values-zh-rCN/strings.xml
+++ b/java/res/values-zh-rCN/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android 自适应通知功能"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN 码"</item>
+    <item msgid="7174505163902448507">"密码"</item>
+    <item msgid="3917837442156595568">"密码"</item>
+    <item msgid="6971032950332150936">"双重身份验证"</item>
+    <item msgid="826248726164877615">"双重身份验证"</item>
+    <item msgid="2156400793251117724">"登录"</item>
+    <item msgid="3621495493711216796">"登录"</item>
+    <item msgid="4652629344958695406">"登录"</item>
+    <item msgid="6021138326345874403">"身份验证"</item>
+    <item msgid="301989899519648952">"身份验证"</item>
+    <item msgid="2409846400635400651">"验证码"</item>
+    <item msgid="3362500960690003002">"密钥"</item>
+    <item msgid="1542192064842556988">"验证"</item>
+    <item msgid="2052362882225775298">"验证"</item>
+    <item msgid="4759495520595696444">"确认"</item>
+    <item msgid="4360404417991731370">"确认"</item>
+    <item msgid="5135302120938115660">"一次性"</item>
+    <item msgid="405482768547359066">"访问"</item>
+    <item msgid="7962233525908588330">"验证"</item>
+    <item msgid="9095545913763732113">"验证"</item>
+    <item msgid="2601700967903477651">"一次性"</item>
+    <item msgid="1775341814323929840">"授权"</item>
+    <item msgid="4159587727958533896">"授权"</item>
+    <item msgid="7199374258785307822">"个人识别码"</item>
+    <item msgid="3860872742161492043">"PIN 码"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-zh-rHK/strings.xml b/java/res/values-zh-rHK/strings.xml
index af88bf7..057cc53 100644
--- a/java/res/values-zh-rHK/strings.xml
+++ b/java/res/values-zh-rHK/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android 自動調節通知"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"pin"</item>
+    <item msgid="7174505163902448507">"密碼"</item>
+    <item msgid="3917837442156595568">"密碼"</item>
+    <item msgid="6971032950332150936">"雙重"</item>
+    <item msgid="826248726164877615">"雙重"</item>
+    <item msgid="2156400793251117724">"登入"</item>
+    <item msgid="3621495493711216796">"登入"</item>
+    <item msgid="4652629344958695406">"登入"</item>
+    <item msgid="6021138326345874403">"驗證"</item>
+    <item msgid="301989899519648952">"驗證"</item>
+    <item msgid="2409846400635400651">"代碼"</item>
+    <item msgid="3362500960690003002">"秘密"</item>
+    <item msgid="1542192064842556988">"驗證"</item>
+    <item msgid="2052362882225775298">"驗證"</item>
+    <item msgid="4759495520595696444">"確認"</item>
+    <item msgid="4360404417991731370">"確認"</item>
+    <item msgid="5135302120938115660">"一次性"</item>
+    <item msgid="405482768547359066">"存取權"</item>
+    <item msgid="7962233525908588330">"驗證"</item>
+    <item msgid="9095545913763732113">"驗證"</item>
+    <item msgid="2601700967903477651">"單次使用"</item>
+    <item msgid="1775341814323929840">"授權"</item>
+    <item msgid="4159587727958533896">"認證"</item>
+    <item msgid="7199374258785307822">"個人識別號碼"</item>
+    <item msgid="3860872742161492043">"PIN"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-zh-rTW/strings.xml b/java/res/values-zh-rTW/strings.xml
index dfd6624..985ff09 100644
--- a/java/res/values-zh-rTW/strings.xml
+++ b/java/res/values-zh-rTW/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Android 自動調整通知"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"PIN 碼"</item>
+    <item msgid="7174505163902448507">"密碼"</item>
+    <item msgid="3917837442156595568">"密碼"</item>
+    <item msgid="6971032950332150936">"雙重驗證"</item>
+    <item msgid="826248726164877615">"雙重驗證"</item>
+    <item msgid="2156400793251117724">"登入"</item>
+    <item msgid="3621495493711216796">"登入"</item>
+    <item msgid="4652629344958695406">"登入"</item>
+    <item msgid="6021138326345874403">"驗證"</item>
+    <item msgid="301989899519648952">"驗證"</item>
+    <item msgid="2409846400635400651">"碼"</item>
+    <item msgid="3362500960690003002">"Secret"</item>
+    <item msgid="1542192064842556988">"驗證"</item>
+    <item msgid="2052362882225775298">"驗證"</item>
+    <item msgid="4759495520595696444">"確認"</item>
+    <item msgid="4360404417991731370">"確認"</item>
+    <item msgid="5135302120938115660">"單次"</item>
+    <item msgid="405482768547359066">"存取"</item>
+    <item msgid="7962233525908588330">"驗證"</item>
+    <item msgid="9095545913763732113">"驗證"</item>
+    <item msgid="2601700967903477651">"單次使用"</item>
+    <item msgid="1775341814323929840">"授權"</item>
+    <item msgid="4159587727958533896">"授權"</item>
+    <item msgid="7199374258785307822">"個人識別號碼"</item>
+    <item msgid="3860872742161492043">"PIN 碼"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values-zu/strings.xml b/java/res/values-zu/strings.xml
index 4e0214d..b4b2786 100644
--- a/java/res/values-zu/strings.xml
+++ b/java/res/values-zu/strings.xml
@@ -17,4 +17,31 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="notification_assistant" msgid="9160940242838910547">"Izaziso Zokungaguqulwa kwe-Android"</string>
+  <string-array name="english_otp_context_words">
+    <item msgid="7615778208475066419">"iphinikhodi"</item>
+    <item msgid="7174505163902448507">"iphasiwedi"</item>
+    <item msgid="3917837442156595568">"ikhodi yokudlula"</item>
+    <item msgid="6971032950332150936">"izinyathelo ezimbili"</item>
+    <item msgid="826248726164877615">"izinyathelo ezimbili"</item>
+    <item msgid="2156400793251117724">"ngena ngemvume"</item>
+    <item msgid="3621495493711216796">"ngena ngemvume"</item>
+    <item msgid="4652629344958695406">"ngena ngemvume"</item>
+    <item msgid="6021138326345874403">"gunyaza"</item>
+    <item msgid="301989899519648952">"ukufakazela ubuqiniso"</item>
+    <item msgid="2409846400635400651">"ikhodi"</item>
+    <item msgid="3362500960690003002">"imfihlo"</item>
+    <item msgid="1542192064842556988">"qinisekisa"</item>
+    <item msgid="2052362882225775298">"ukuqinisekisa"</item>
+    <item msgid="4759495520595696444">"qinisekisa"</item>
+    <item msgid="4360404417991731370">"isiqinisekiso"</item>
+    <item msgid="5135302120938115660">"isikhathi esisodwa"</item>
+    <item msgid="405482768547359066">"ukufinyelela"</item>
+    <item msgid="7962233525908588330">"ukuqinisekisa"</item>
+    <item msgid="9095545913763732113">"qinisekisa"</item>
+    <item msgid="2601700967903477651">"ukusetshenziswa okukodwa"</item>
+    <item msgid="1775341814323929840">"gunyaza"</item>
+    <item msgid="4159587727958533896">"ukugunyazwa"</item>
+    <item msgid="7199374258785307822">"inombolo yokuhlonza yomuntu siqu"</item>
+    <item msgid="3860872742161492043">"Iphinikhodi"</item>
+  </string-array>
 </resources>
diff --git a/java/res/values/strings.xml b/java/res/values/strings.xml
index bd11c69..a17f198 100644
--- a/java/res/values/strings.xml
+++ b/java/res/values/strings.xml
@@ -25,4 +25,35 @@
         <item>EXACT_MATCH</item>
         <item>CREDIT_CARD</item>
     </string-array>
+
+    <!-- [CHAR LIMIT=none] An array of words and short phrases that might be used in a message
+    containing a one time password (also known as a single use pin, one time code,
+    or transaction authorization number) -->
+    <string-array name="english_otp_context_words">
+        <item>pin</item>
+        <item>password</item>
+        <item>passcode</item>
+        <item>two factor</item>
+        <item>two-factor</item>
+        <item>login</item>
+        <item>log-in</item>
+        <item>log in</item>
+        <item>authenticate</item>
+        <item>authentication</item>
+        <item>code</item>
+        <item>secret</item>
+        <item>verify</item>
+        <item>verification</item>
+        <item>confirm</item>
+        <item>confirmation</item>
+        <item>one time</item>
+        <item>access</item>
+        <item>validation</item>
+        <item>validate</item>
+        <item>single use</item>
+        <item>authorize</item>
+        <item>authorization</item>
+        <item>personal identification number</item>
+        <item>PIN</item>
+    </string-array>
 </resources>
diff --git a/java/src/android/ext/services/notification/Assistant.java b/java/src/android/ext/services/notification/Assistant.java
index e403634..335bfd6 100644
--- a/java/src/android/ext/services/notification/Assistant.java
+++ b/java/src/android/ext/services/notification/Assistant.java
@@ -27,6 +27,7 @@ import android.os.Bundle;
 import android.os.Trace;
 import android.os.UserHandle;
 import android.service.notification.Adjustment;
+import android.service.notification.Flags;
 import android.service.notification.NotificationAssistantService;
 import android.service.notification.NotificationStats;
 import android.service.notification.StatusBarNotification;
@@ -38,6 +39,7 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
 
+import com.android.modules.utils.build.SdkLevel;
 import com.android.textclassifier.notification.SmartSuggestions;
 import com.android.textclassifier.notification.SmartSuggestionsHelper;
 
@@ -132,8 +134,9 @@ public class Assistant extends NotificationAssistantService {
             return null;
         }
 
-        final boolean shouldCheckForOtp =
-                NotificationOtpDetectionHelper.shouldCheckForOtp(sbn.getNotification());
+        final boolean shouldCheckForOtp = SdkLevel.isAtLeastV()
+                && Flags.redactSensitiveNotificationsFromUntrustedListeners()
+                && NotificationOtpDetectionHelper.shouldCheckForOtp(sbn.getNotification());
         boolean foundOtpWithRegex = shouldCheckForOtp
                 && NotificationOtpDetectionHelper
                 .containsOtp(sbn.getNotification(), true, null);
diff --git a/java/src/android/ext/services/notification/NotificationOtpDetectionHelper.java b/java/src/android/ext/services/notification/NotificationOtpDetectionHelper.java
index 424c37e..d7006c3 100644
--- a/java/src/android/ext/services/notification/NotificationOtpDetectionHelper.java
+++ b/java/src/android/ext/services/notification/NotificationOtpDetectionHelper.java
@@ -27,40 +27,66 @@ import static android.app.Notification.EXTRA_TEXT;
 import static android.app.Notification.EXTRA_TEXT_LINES;
 import static android.app.Notification.EXTRA_TITLE;
 import static android.app.Notification.EXTRA_TITLE_BIG;
+import static android.os.Build.VERSION.SDK_INT;
 import static android.view.textclassifier.TextClassifier.TYPE_ADDRESS;
 import static android.view.textclassifier.TextClassifier.TYPE_FLIGHT_NUMBER;
 import static android.view.textclassifier.TextClassifier.TYPE_PHONE;
 
 import static java.lang.String.format;
 
+import android.annotation.SuppressLint;
 import android.app.Notification;
 import android.app.Notification.MessagingStyle;
 import android.app.Notification.MessagingStyle.Message;
 import android.icu.util.ULocale;
+import android.os.Build;
 import android.os.Bundle;
 import android.os.Parcelable;
-import android.service.notification.Flags;
 import android.util.ArrayMap;
 import android.view.textclassifier.TextClassifier;
 import android.view.textclassifier.TextLanguage;
 import android.view.textclassifier.TextLinks;
 
-import com.android.modules.utils.build.SdkLevel;
+import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
 
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.List;
 import java.util.Objects;
 import java.util.regex.Matcher;
 import java.util.regex.Pattern;
 
 /**
- * Class with helper methods related to detecting OTP codes in notifications
+ * Class with helper methods related to detecting OTP codes in notifications.
+ * This file needs to only use public android API methods, see b/361149088
  */
+@SuppressLint("ObsoleteSdkInt")
 public class NotificationOtpDetectionHelper {
 
     // Use an ArrayList because a List.of list will throw NPE when calling "contains(null)"
     private static final List<String> SENSITIVE_NOTIFICATION_CATEGORIES = new ArrayList<>(
-            List.of(CATEGORY_MESSAGE, CATEGORY_EMAIL, CATEGORY_SOCIAL));
+            Arrays.asList(CATEGORY_MESSAGE, CATEGORY_EMAIL, CATEGORY_SOCIAL));
+
+    private static final List<Class<? extends Notification.Style>> SENSITIVE_STYLES =
+            new ArrayList<>(Arrays.asList(Notification.MessagingStyle.class,
+                    Notification.InboxStyle.class, Notification.BigTextStyle.class));
+
+    private static final List<Class<? extends Notification.Style>> EXCLUDED_STYLES =
+            new ArrayList<>(Arrays.asList(Notification.MediaStyle.class,
+                    Notification.BigPictureStyle.class));
+    static {
+        if (SDK_INT >= Build.VERSION_CODES.S) {
+            EXCLUDED_STYLES.add(Notification.CallStyle.class);
+        }
+    }
+
+    private static final int PATTERN_FLAGS =
+            Pattern.DOTALL | Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;
+
+    private static ThreadLocal<Matcher> compileToRegex(String pattern) {
+        return ThreadLocal.withInitial(() -> Pattern.compile(pattern, PATTERN_FLAGS).matcher(""));
+    }
 
     private static final float TC_THRESHOLD = 0.6f;
 
@@ -69,34 +95,56 @@ public class NotificationOtpDetectionHelper {
 
     private static final int MAX_SENSITIVE_TEXT_LEN = 600;
 
-    // A regex matching a line start, space, open paren, arrow, colon (not proceeded by a digit),
-    // open square bracket, equals sign, double or single quote, or ideographic char. It will
-    // not consume the start char (meaning START won't be included in the matched string)
-    private static final String START = "(^|(?<=[>\\s(\"'=\\[\\p{IsIdeographic}]|[^0-9]:))";
+    /**
+     * A regex matching a line start, open paren, arrow, colon (not proceeded by a digit),
+     * open square bracket, equals sign, double or single quote, ideographic char, or a space that
+     * is not preceded by a number. It will not consume the start char (meaning START won't be
+     * included in the matched string)
+     */
+    private static final String START =
+            "(^|(?<=((^|[^0-9])\\s)|[>(\"'=\\[\\p{IsIdeographic}]|[^0-9]:))";
 
 
-    // One single OTP char. A number or alphabetical char (that isn't also ideographic), followed by
-    // an optional dash
-    private static final String OTP_CHAR = "([0-9\\p{IsAlphabetic}&&[^\\p{IsIdeographic}]]-?)";
+    /**
+     * One single OTP char. A number or alphabetical char (that isn't also ideographic)
+     */
+    private static final String OTP_CHAR = "([0-9\\p{IsAlphabetic}&&[^\\p{IsIdeographic}]])";
 
-    // Performs a lookahead to find a digit after 0 to 7 OTP_CHARs. This ensures that our potential
-    // OTP code contains at least one number
-    private static final String FIND_DIGIT = format("(?=%s{0,7}\\d)", OTP_CHAR);
+    /**
+     * One OTP char, followed by an optional dash
+     */
+    private static final String OTP_CHAR_WITH_DASH = format("(%s-?)", OTP_CHAR);
 
-    // Matches between 5 and 8 OTP_CHARs. Here, we are assuming an OTP code is 5-8 characters long
-    private static final String OTP_CHARS = format("(%s{5,8})", OTP_CHAR);
+    /**
+     * Performs a lookahead to find a digit after 0 to 7 OTP_CHARs. This ensures that our potential
+     * OTP code contains at least one number
+     */
+    private static final String FIND_DIGIT = format("(?=%s{0,7}\\d)", OTP_CHAR_WITH_DASH);
 
-    // A regex matching a line end, non-word char (except dash or underscore), or ideographic char.
-    // It will not consume the end char
-    private static final String END = "(?=\\W|$|\\p{IsIdeographic})";
+    /**
+     * Matches between 5 and 8 otp chars, with dashes in between. Here, we are assuming an OTP code
+     * is 5-8 characters long. The last char must not be followed by a dash
+     */
+    private static final String OTP_CHARS = format("(%s{4,7}%s)", OTP_CHAR_WITH_DASH, OTP_CHAR);
 
-    // A regex matching four digit numerical codes
+    /**
+     * A regex matching a line end, a space that is not followed by a number, an ideographic char,
+     * or a period, close paren, close square bracket, single or double quote, exclamation point,
+     * question mark, or comma. It will not consume the end char
+     */
+    private static final String END = "(?=\\s[^0-9]|$|\\p{IsIdeographic}|[.?!,)'\\]\"])";
+
+    /**
+     * A regex matching four digit numerical codes
+     */
     private static final String FOUR_DIGITS = "(\\d{4})";
 
     private static final String FIVE_TO_EIGHT_ALPHANUM_AT_LEAST_ONE_NUM =
             format("(%s%s)", FIND_DIGIT, OTP_CHARS);
 
-    // A regex matching two pairs of 3 digits (ex "123 456")
+    /**
+     * A regex matching two pairs of 3 digits (ex "123 456")
+     */
     private static final String SIX_DIGITS_WITH_SPACE = "(\\d{3}\\s\\d{3})";
 
     /**
@@ -117,32 +165,51 @@ public class NotificationOtpDetectionHelper {
 
 
 
-    private static final ThreadLocal<Matcher> OTP_REGEX = ThreadLocal.withInitial(() ->
-            Pattern.compile(ALL_OTP).matcher(""));
+    private static final ThreadLocal<Matcher> OTP_REGEX = compileToRegex(ALL_OTP);
     /**
      * A Date regular expression. Looks for dates with the month, day, and year separated by dashes.
      * Handles one and two digit months and days, and four or two-digit years. It makes the
      * following assumptions:
      * Dates and months will never be higher than 39
      * If a four digit year is used, the leading digit will be 1 or 2
-     * This regex is used to eliminate the most common false positive of the OTP regex, and is run
-     * on all messages, even before looking at language-specific regexs.
      */
-    private static final ThreadLocal<Matcher> DATE_WITH_DASHES_REGEX = ThreadLocal.withInitial(() ->
-            Pattern.compile(format("%s([0-3]?\\d-[0-3]?\\d-([12]\\d)?\\d\\d)%s", START, END))
-                    .matcher(""));
+    private static final String DATE_WITH_DASHES = "([0-3]?\\d-[0-3]?\\d-([12]\\d)?\\d\\d)";
+
+    /**
+     * matches a ten digit phone number, when the area code is separated by a space or dash.
+     * Supports optional parentheses around the area code, and an optional dash or space in between
+     * the rest of the numbers.
+     * This format registers as an otp match due to the space between the area code and the rest,
+     * but shouldn't.
+     */
+    private static final String PHONE_WITH_SPACE = "(\\(?\\d{3}\\)?(-|\\s)?\\d{3}(-|\\s)?\\d{4})";
 
-    // A regex matching the common years of 19xx and 20xx. Used for false positive reduction
+    /**
+     * A combination of common false positives. These matches are expected to be longer than (or
+     * equal in length to) otp matches, and are always run, even if we have a language specific
+     * regex
+     */
+    private static final ThreadLocal<Matcher> FALSE_POSITIVE_LONGER_REGEX =
+            compileToRegex(format("%s(%s|%s)%s", START, DATE_WITH_DASHES, PHONE_WITH_SPACE, END));
+
+    /**
+     * A regex matching the common years of 19xx and 20xx. Used for false positive reduction
+     */
     private static final String COMMON_YEARS = format("%s((19|20)\\d\\d)%s", START, END);
 
-    // A regex matching three lower case letters. Used for false positive reduction, as no known
-    // OTPs have 3 lowercase letters in sequence.
+    /**
+     * A regex matching three lower case letters. Used for false positive reduction, as no known
+     *  OTPs have 3 lowercase letters in sequence.
+     */
     private static final String THREE_LOWERCASE = "(\\p{Ll}{3})";
 
-    // A combination of common false positives. Run in cases where we don't have a language specific
-    // regular expression.
-    private static final ThreadLocal<Matcher> FALSE_POSITIVE_REGEX = ThreadLocal.withInitial(() ->
-            Pattern.compile(format("%s|%s", COMMON_YEARS, THREE_LOWERCASE)).matcher(""));
+    /**
+     * A combination of common false positives. Run in cases where we don't have a language specific
+     * regular expression. These matches are expect to be shorter than (or equal in length to) otp
+     * matches
+     */
+    private static final ThreadLocal<Matcher> FALSE_POSITIVE_SHORTER_REGEX =
+                    compileToRegex(format("%s|%s", COMMON_YEARS, THREE_LOWERCASE));
 
     /**
      * A list of regular expressions representing words found in an OTP context (non case sensitive)
@@ -151,32 +218,63 @@ public class NotificationOtpDetectionHelper {
     private static final String[] ENGLISH_CONTEXT_WORDS = new String[] {
             "pin", "pass[-\\s]?(code|word)", "TAN", "otp", "2fa", "(two|2)[-\\s]?factor",
             "log[-\\s]?in", "auth(enticat(e|ion))?", "code", "secret", "verif(y|ication)",
-            "confirm(ation)?"
+            "one(\\s|-)?time", "access", "validat(e|ion)"
     };
 
     /**
      * Creates a regular expression to match any of a series of individual words, case insensitive.
+     * It also verifies the position of the word, relative to the OTP match
      */
-    private static Matcher createDictionaryRegex(String[] words) {
-        StringBuilder regex = new StringBuilder("(?i)\\b(");
+    private static ThreadLocal<Matcher> createDictionaryRegex(String[] words) {
+        StringBuilder regex = new StringBuilder("(");
         for (int i = 0; i < words.length; i++) {
-            regex.append(words[i]);
+            regex.append(findContextWordWithCode(words[i]));
             if (i != words.length - 1) {
                 regex.append("|");
             }
         }
-        regex.append(")\\b");
-        return Pattern.compile(regex.toString()).matcher("");
+        regex.append(")");
+        return compileToRegex(regex.toString());
+    }
+
+    /**
+     * Creates a regular expression that will find a context word, if that word occurs in the
+     * sentence preceding an OTP, or in the same sentence as an OTP (before or after). In both
+     * cases, the context word must occur within 50 characters of the suspected OTP
+     * @param contextWord The context word we expect to find around the OTP match
+     * @return A string representing a regular expression that will determine if we found a context
+     * word occurring before an otp match, or after it, but in the same sentence.
+     */
+    private static String findContextWordWithCode(String contextWord) {
+        String boundedContext = "\\b" + contextWord + "\\b";
+        // Asserts that we find the OTP code within 50 characters after the context word, with at
+        // most one sentence punctuation between the OTP code and the context word (i.e. they are
+        // in the same sentence, or the context word is in the previous sentence)
+        String contextWordBeforeOtpInSameOrPreviousSentence =
+                String.format("(%s(?=.{1,50}%s)[^.?!]*[.?!]?[^.?!]*%s)",
+                        boundedContext, ALL_OTP, ALL_OTP);
+        // Asserts that we find the context word within 50 characters after the OTP code, with no
+        // sentence punctuation between the OTP code and the context word (i.e. they are in the same
+        // sentence)
+        String contextWordAfterOtpSameSentence =
+                String.format("(%s)[^.!?]{1,50}%s", ALL_OTP, boundedContext);
+        return String.format("(%s|%s)", contextWordBeforeOtpInSameOrPreviousSentence,
+                contextWordAfterOtpSameSentence);
     }
 
     static {
-        EXTRA_LANG_OTP_REGEX.put(ULocale.ENGLISH.toLanguageTag(), ThreadLocal.withInitial(() ->
-                createDictionaryRegex(ENGLISH_CONTEXT_WORDS)));
+        EXTRA_LANG_OTP_REGEX.put(ULocale.ENGLISH.toLanguageTag(),
+                createDictionaryRegex(ENGLISH_CONTEXT_WORDS));
+    }
+
+    private static boolean isPreV() {
+        return SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM;
     }
 
     /**
-     * Checks if the sensitive parts of a notification might contain an OTP, based on several
-     * regular expressions, and potentially using a textClassifier to eliminate false positives
+     * Checks if any text fields in a notification might contain an OTP, based on several
+     * regular expressions, and potentially using a textClassifier to eliminate false positives.
+     * Each text field will be examined individually.
      *
      * @param notification The notification whose content should be checked
      * @param checkForFalsePositives If true, will ensure the content does not match the date regex.
@@ -188,16 +286,53 @@ public class NotificationOtpDetectionHelper {
      * @param tc If non null, the provided TextClassifier will be used to find the language of the
      *           text, and look for a language-specific regex for it. If checkForFalsePositives is
      *           true will also use the classifier to find flight codes and addresses.
-     * @return True if the regex matches and ensureNotDate is false, or the date regex failed to
-     *     match, false otherwise.
+     * @return True if we believe an OTP is in the message, false otherwise.
      */
     public static boolean containsOtp(Notification notification,
-            boolean checkForFalsePositives, TextClassifier tc) {
-        if (notification == null || !SdkLevel.isAtLeastV()) {
+            boolean checkForFalsePositives, @Nullable TextClassifier tc) {
+        if (notification == null || notification.extras == null || isPreV()) {
+            return false;
+        }
+
+        // Get the language of the text once
+        ULocale textLocale = getLanguageWithRegex(getTextForDetection(notification), tc);
+        // Get all the individual fields
+        List<CharSequence> fields = getNotificationTextFields(notification);
+        for (CharSequence field : fields) {
+            if (field != null
+                    && containsOtp(field.toString(), checkForFalsePositives, tc, textLocale)) {
+                return true;
+            }
+        }
+
+        return false;
+    }
+
+    /**
+     * Checks if a string of text might contain an OTP, based on several
+     * regular expressions, and potentially using a textClassifier to eliminate false positives
+     *
+     * @param sensitiveText The text whose content should be checked
+     * @param checkForFalsePositives If true, will ensure the content does not match the date regex.
+     *                               If a TextClassifier is provided, it will then try to find a
+     *                               language specific regex. If it is successful, it will use that
+     *                               regex to check for false positives. If it is not, it will use
+     *                               the TextClassifier (if provided), plus the year and three
+     *                               lowercase regexes to remove possible false positives.
+     * @param tc If non null, the provided TextClassifier will be used to find the language of the
+     *           text, and look for a language-specific regex for it. If checkForFalsePositives is
+     *           true will also use the classifier to find flight codes and addresses.
+     * @param language If non null, then the TextClassifier (if provided), will not perform language
+     *                 id, and the system will assume the text is in the specified language
+     * @return True if we believe an OTP is in the message, false otherwise.
+     */
+    public static boolean containsOtp(String sensitiveText,
+            boolean checkForFalsePositives, @Nullable TextClassifier tc,
+            @Nullable ULocale language) {
+        if (sensitiveText == null || isPreV()) {
             return false;
         }
 
-        String sensitiveText = getTextForDetection(notification);
         Matcher otpMatcher = OTP_REGEX.get();
         otpMatcher.reset(sensitiveText);
         boolean otpMatch = otpMatcher.find();
@@ -205,12 +340,17 @@ public class NotificationOtpDetectionHelper {
             return otpMatch;
         }
 
-        if (allOtpMatchesAreFalsePositives(sensitiveText, DATE_WITH_DASHES_REGEX.get())) {
+        if (allOtpMatchesAreFalsePositives(
+                sensitiveText, FALSE_POSITIVE_LONGER_REGEX.get(), true)) {
             return false;
         }
 
-        if (tc != null) {
-            Matcher languageSpecificMatcher = getLanguageSpecificRegex(sensitiveText, tc);
+        if (tc != null || language != null) {
+            if (language == null) {
+                language = getLanguageWithRegex(sensitiveText, tc);
+            }
+            Matcher languageSpecificMatcher = language != null
+                    ? EXTRA_LANG_OTP_REGEX.get(language.toLanguageTag()).get() : null;
             if (languageSpecificMatcher != null) {
                 languageSpecificMatcher.reset(sensitiveText);
                 // Only use the language-specific regex for false positives
@@ -222,53 +362,97 @@ public class NotificationOtpDetectionHelper {
             }
         }
 
-        return !allOtpMatchesAreFalsePositives(sensitiveText, FALSE_POSITIVE_REGEX.get());
+        return !allOtpMatchesAreFalsePositives(sensitiveText, FALSE_POSITIVE_SHORTER_REGEX.get(),
+                false);
     }
 
     /**
      * Checks that a given text has at least one match for one regex, that doesn't match another
      * @param text The full text to check
      * @param falsePositiveRegex A regex that should not match the OTP regex (for at least one match
-     *                           found by the OTP regex
-     * @return true, if all matches found by OTP_REGEX are also found by "shouldNotMatch"
+     *                           found by the OTP regex). The false positive regex matches may be
+     *                           longer or shorter than the OTP matches.
+     * @param fpMatchesAreLongerThanOtp Whether the false positives are longer than the otp matches.
+     *                                  If true, this method will search the whole text for false
+     *                                  positives, and verify at least one OTP match is not
+     *                                  contained by any of the false positives. If false, then this
+     *                                  method will search individual OTP matches for false
+     *                                  positives, and will verify at least one OTP match doesn't
+     *                                  contain a false positive.
+     * @return true, if all matches found by OTP_REGEX are contained in, or themselves contain a
+     *         match to falsePositiveRegex, or there are no OTP matches, false otherwise.
      */
-    private static boolean allOtpMatchesAreFalsePositives(String text,
-            Matcher falsePositiveRegex) {
-        falsePositiveRegex = falsePositiveRegex.reset(text);
-        if (!falsePositiveRegex.find()) {
-            return false;
+    private static boolean allOtpMatchesAreFalsePositives(String text, Matcher falsePositiveRegex,
+            boolean fpMatchesAreLongerThanOtp) {
+        List<String> falsePositives = new ArrayList<>();
+        if (fpMatchesAreLongerThanOtp) {
+            // if the false positives are longer than the otp, search for them in the whole text
+            falsePositives = getAllMatches(text, falsePositiveRegex);
         }
-        Matcher otpMatcher = OTP_REGEX.get();
-        otpMatcher.reset(text);
-        while (otpMatcher.find()) {
-            falsePositiveRegex.reset(otpMatcher.group());
-            if (!falsePositiveRegex.find()) {
-                // A possible otp was not matched by the false positive regex
+        List<String> otpMatches = getAllMatches(text, OTP_REGEX.get());
+        for (String otpMatch: otpMatches) {
+            boolean otpMatchContainsNoFp = true;
+            boolean noFpContainsOtpMatch = true;
+            if (!fpMatchesAreLongerThanOtp) {
+                // if the false positives are shorter than the otp, search for them in the otp match
+                falsePositives = getAllMatches(otpMatch, falsePositiveRegex);
+            }
+            for (String falsePositive : falsePositives) {
+                otpMatchContainsNoFp = fpMatchesAreLongerThanOtp
+                        || (otpMatchContainsNoFp && !otpMatch.contains(falsePositive));
+                noFpContainsOtpMatch = !fpMatchesAreLongerThanOtp
+                        || (noFpContainsOtpMatch && !falsePositive.contains(otpMatch));
+            }
+            if (otpMatchContainsNoFp && noFpContainsOtpMatch) {
                 return false;
             }
         }
-        // All otp matches were matched by the false positive regex
         return true;
     }
 
-    private static Matcher getLanguageSpecificRegex(String text, TextClassifier tc) {
+    private static List<String> getAllMatches(String text, Matcher regex) {
+        ArrayList<String> matches = new ArrayList<>();
+        regex.reset(text);
+        while (regex.find()) {
+            matches.add(regex.group());
+        }
+        return matches;
+    }
+
+    // Tries to determine the language of the given text. Will return the language with the highest
+    // confidence score that meets the minimum threshold, and has a language-specific regex, null
+    // otherwise
+    @Nullable
+    private static ULocale getLanguageWithRegex(String text,
+            @Nullable TextClassifier tc) {
+        if (tc == null) {
+            return null;
+        }
+
+        float highestConfidence = 0;
+        ULocale highestConfidenceLocale = null;
         TextLanguage.Request langRequest = new TextLanguage.Request.Builder(text).build();
         TextLanguage lang = tc.detectLanguage(langRequest);
         for (int i = 0; i < lang.getLocaleHypothesisCount(); i++) {
             ULocale locale = lang.getLocale(i);
-            if (lang.getConfidenceScore(locale) >= TC_THRESHOLD
+            float confidence = lang.getConfidenceScore(locale);
+            if (confidence >= TC_THRESHOLD && confidence >= highestConfidence
                     && EXTRA_LANG_OTP_REGEX.containsKey(locale.toLanguageTag())) {
-                return EXTRA_LANG_OTP_REGEX.get(locale.toLanguageTag()).get();
+                highestConfidence = confidence;
+                highestConfidenceLocale = locale;
             }
         }
-        return null;
+        return highestConfidenceLocale;
     }
 
-    private static boolean hasFalsePositivesTcCheck(String text, TextClassifier tc) {
+    private static boolean hasFalsePositivesTcCheck(String text, @Nullable TextClassifier tc) {
+        if (tc == null) {
+            return false;
+        }
         // Use TC to eliminate false positives from a regex match, namely: flight codes, and
         // addresses
-        List<String> included = new ArrayList<>(List.of(TYPE_FLIGHT_NUMBER, TYPE_ADDRESS));
-        List<String> excluded = new ArrayList<>(List.of(TYPE_PHONE));
+        List<String> included = new ArrayList<>(Arrays.asList(TYPE_FLIGHT_NUMBER, TYPE_ADDRESS));
+        List<String> excluded = new ArrayList<>(Arrays.asList(TYPE_PHONE));
         TextClassifier.EntityConfig config =
                 new TextClassifier.EntityConfig.Builder().setIncludedTypes(
                         included).setExcludedTypes(excluded).build();
@@ -290,32 +474,34 @@ public class NotificationOtpDetectionHelper {
      * @param notification The notification whose content should be filtered
      * @return The extracted text fields
      */
-    public static String getTextForDetection(Notification notification) {
-        if (notification.extras == null || !SdkLevel.isAtLeastV()
-                || !Flags.redactSensitiveNotificationsFromUntrustedListeners()) {
+    @VisibleForTesting
+    protected static String getTextForDetection(Notification notification) {
+        if (notification == null || notification.extras == null || isPreV()) {
             return "";
         }
-        Bundle extras = notification.extras;
-        CharSequence title = extras.getCharSequence(EXTRA_TITLE);
-        CharSequence text = extras.getCharSequence(EXTRA_TEXT);
-        CharSequence subText = extras.getCharSequence(EXTRA_SUB_TEXT);
-        StringBuilder builder = new StringBuilder()
-                .append(title != null ? title : "").append(" ")
-                .append(text != null ? text : "").append(" ")
-                .append(subText != null ? subText : "").append(" ");
-        if (Flags.redactSensitiveNotificationsBigTextStyle()) {
-            CharSequence bigText = extras.getCharSequence(EXTRA_BIG_TEXT);
-            CharSequence bigTitleText = extras.getCharSequence(EXTRA_TITLE_BIG);
-            CharSequence summaryText = extras.getCharSequence(EXTRA_SUMMARY_TEXT);
-            builder.append(bigText != null ? bigText : "").append(" ")
-                    .append(bigTitleText != null ? bigTitleText : "").append(" ")
-                    .append(summaryText != null ? summaryText : "").append(" ");
+        StringBuilder builder = new StringBuilder();
+        for (CharSequence line : getNotificationTextFields(notification)) {
+            builder.append(line != null ? line : "").append(" ");
         }
+        return builder.length() <= MAX_SENSITIVE_TEXT_LEN ? builder.toString()
+                : builder.substring(0, MAX_SENSITIVE_TEXT_LEN);
+    }
+
+    protected static List<CharSequence> getNotificationTextFields(Notification notification) {
+        if (notification == null || notification.extras == null || isPreV()) {
+            return new ArrayList<>();
+        }
+        ArrayList<CharSequence> fields = new ArrayList<>();
+        Bundle extras = notification.extras;
+        fields.add(extras.getCharSequence(EXTRA_TITLE));
+        fields.add(extras.getCharSequence(EXTRA_TEXT));
+        fields.add(extras.getCharSequence(EXTRA_SUB_TEXT));
+        fields.add(extras.getCharSequence(EXTRA_BIG_TEXT));
+        fields.add(extras.getCharSequence(EXTRA_TITLE_BIG));
+        fields.add(extras.getCharSequence(EXTRA_SUMMARY_TEXT));
         CharSequence[] textLines = extras.getCharSequenceArray(EXTRA_TEXT_LINES);
         if (textLines != null) {
-            for (CharSequence line : textLines) {
-                builder.append(line).append(" ");
-            }
+            fields.addAll(Arrays.asList(textLines));
         }
         List<Message> messages = Message.getMessagesFromBundleArray(
                 extras.getParcelableArray(EXTRA_MESSAGES, Parcelable.class));
@@ -323,10 +509,9 @@ public class NotificationOtpDetectionHelper {
         messages.sort((MessagingStyle.Message lhs, MessagingStyle.Message rhs) ->
                 Long.compare(rhs.getTimestamp(), lhs.getTimestamp()));
         for (MessagingStyle.Message message : messages) {
-            builder.append(message.getText()).append(" ");
+            fields.add(message.getText());
         }
-        return builder.length() <= MAX_SENSITIVE_TEXT_LEN ? builder.toString()
-                : builder.substring(0, MAX_SENSITIVE_TEXT_LEN);
+        return fields;
     }
 
     /**
@@ -336,13 +521,12 @@ public class NotificationOtpDetectionHelper {
      * @return true, if further checks for OTP codes should be performed, false otherwise
      */
     public static boolean shouldCheckForOtp(Notification notification) {
-        if (notification == null || !SdkLevel.isAtLeastV()
-                || !Flags.redactSensitiveNotificationsFromUntrustedListeners()) {
+        if (notification == null || isPreV()
+                || EXCLUDED_STYLES.stream().anyMatch(s -> isStyle(notification, s))) {
             return false;
         }
         return SENSITIVE_NOTIFICATION_CATEGORIES.contains(notification.category)
-                || isStyle(notification, Notification.MessagingStyle.class)
-                || isStyle(notification, Notification.InboxStyle.class)
+                || SENSITIVE_STYLES.stream().anyMatch(s -> isStyle(notification, s))
                 || containsOtp(notification, false, null)
                 || shouldCheckForOtp(notification.publicVersion);
     }
diff --git a/java/src/android/ext/services/notification/OWNERS b/java/src/android/ext/services/notification/OWNERS
index 53f29fc..4ea9298 100644
--- a/java/src/android/ext/services/notification/OWNERS
+++ b/java/src/android/ext/services/notification/OWNERS
@@ -1 +1,4 @@
 include platform/frameworks/base:/core/java/android/service/notification/OWNERS
+
+# Owner of the OTP detection project
+per-file NotificationOtpDetectionHelper.java = ntmyren@google.com
diff --git a/java/tests/Android.bp b/java/tests/Android.bp
index 7a1d794..4193097 100644
--- a/java/tests/Android.bp
+++ b/java/tests/Android.bp
@@ -18,8 +18,8 @@ android_test {
     ],
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.test",
+        "android.test.base.stubs.test",
     ],
 
     static_libs: [
@@ -56,8 +56,8 @@ android_test {
     srcs: ["src/**/*.java"],
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.test",
+        "android.test.base.stubs.test",
     ],
 
     static_libs: [
diff --git a/java/tests/AndroidTest-tplus.xml b/java/tests/AndroidTest-tplus.xml
index a9dc50f..d17f789 100644
--- a/java/tests/AndroidTest-tplus.xml
+++ b/java/tests/AndroidTest-tplus.xml
@@ -35,4 +35,9 @@
     <object type="module_controller" class="com.android.tradefed.testtype.suite.module.MainlineTestModuleController">
         <option name="mainline-module-package-name" value="com.google.android.extservices" />
     </object>
+
+    <target_preparer class="com.android.tradefed.targetprep.DeviceSetup">
+        <option name="force-skip-system-props" value="true" />
+        <option name="set-global-setting" key="verifier_verify_adb_installs" value="0" />
+    </target_preparer>
 </configuration>
diff --git a/java/tests/hosttests/src/android/ext/services/hosttests/AdServicesFilesCleanupBootCompleteReceiverHostTest.java b/java/tests/hosttests/src/android/ext/services/hosttests/AdServicesFilesCleanupBootCompleteReceiverHostTest.java
index 3c835ea..b7dcc94 100644
--- a/java/tests/hosttests/src/android/ext/services/hosttests/AdServicesFilesCleanupBootCompleteReceiverHostTest.java
+++ b/java/tests/hosttests/src/android/ext/services/hosttests/AdServicesFilesCleanupBootCompleteReceiverHostTest.java
@@ -273,7 +273,8 @@ public final class AdServicesFilesCleanupBootCompleteReceiverHostTest
                 mExtServicesPackageName,
                 fileName);
 
-        runShellCommand("echo \"Hello\" > %s", fullPath);
+        runShellCommand("touch %s", fullPath);
+
         assertWithMessage("%s exists", fullPath)
                 .that(mDevice.doesFileExist(fullPath))
                 .isTrue();
diff --git a/java/tests/src/android/ext/services/common/AdServicesAppsearchDeleteJobTest.java b/java/tests/src/android/ext/services/common/AdServicesAppsearchDeleteJobTest.java
index de7a63f..d6be1c1 100644
--- a/java/tests/src/android/ext/services/common/AdServicesAppsearchDeleteJobTest.java
+++ b/java/tests/src/android/ext/services/common/AdServicesAppsearchDeleteJobTest.java
@@ -60,8 +60,6 @@ import org.mockito.MockitoSession;
 import org.mockito.Spy;
 import org.mockito.quality.Strictness;
 
-import java.util.ArrayList;
-import java.util.List;
 import java.util.concurrent.Executor;
 import java.util.concurrent.LinkedBlockingQueue;
 import java.util.concurrent.ThreadPoolExecutor;
@@ -134,15 +132,20 @@ public final class AdServicesAppsearchDeleteJobTest {
     @Test
     public void deleteAppsearchDb_onMigrationfailure_shouldBeFalse()
             throws Exception {
-        SetSchemaResponse mockResponse = Mockito.mock(SetSchemaResponse.class);
         SetSchemaResponse.MigrationFailure failure =
                 new SetSchemaResponse.MigrationFailure(
                         /* namespace= */ TEST,
                         /* id= */ TEST,
                         /* schemaType= */ TEST,
                         /* appSearchResult= */ AppSearchResult.newFailedResult(1, TEST));
-        when(mockResponse.getMigrationFailures()).thenReturn(List.of(failure));
-        doReturn(mockResponse).when(mAdServicesAppsearchDeleteJob).getDeleteSchemaResponse(
+        SetSchemaResponse setSchemaResponse =
+                new SetSchemaResponse.Builder()
+                        .addDeletedType("delete1")
+                        .addIncompatibleType("incompatible1")
+                        .addMigratedType("migrated1")
+                        .addMigrationFailure(failure)
+                        .build();
+        doReturn(setSchemaResponse).when(mAdServicesAppsearchDeleteJob).getDeleteSchemaResponse(
                 any(), any(), any());
         assertWithMessage("deleteAppsearchDb result should be false")
                 .that(mAdServicesAppsearchDeleteJob.deleteAppsearchDb(mContext, mExecutor, TEST))
@@ -162,9 +165,10 @@ public final class AdServicesAppsearchDeleteJobTest {
     @Test
     public void deleteAppsearchDb_onSuccess_shouldBeTrue()
             throws Exception {
-        SetSchemaResponse mockResponse = Mockito.mock(SetSchemaResponse.class);
-        when(mockResponse.getMigrationFailures()).thenReturn(new ArrayList<>());
-        doReturn(mockResponse).when(mAdServicesAppsearchDeleteJob).getDeleteSchemaResponse(
+        SetSchemaResponse setSchemaResponse =
+                new SetSchemaResponse.Builder()
+                        .build();
+        doReturn(setSchemaResponse).when(mAdServicesAppsearchDeleteJob).getDeleteSchemaResponse(
                 any(), any(), any());
         assertWithMessage("deleteAppsearchDb result should be true")
                 .that(mAdServicesAppsearchDeleteJob.deleteAppsearchDb(mContext, mExecutor, TEST))
diff --git a/java/tests/src/android/ext/services/notification/AssistantTest.kt b/java/tests/src/android/ext/services/notification/AssistantTest.kt
index 28027ca..fb3f62c 100644
--- a/java/tests/src/android/ext/services/notification/AssistantTest.kt
+++ b/java/tests/src/android/ext/services/notification/AssistantTest.kt
@@ -53,6 +53,7 @@ import org.mockito.ArgumentMatchers.any
 import org.mockito.ArgumentMatchers.eq
 import org.mockito.ArgumentMatchers.isNull
 import org.mockito.Mockito.atLeast
+import org.mockito.Mockito.atLeastOnce
 import org.mockito.Mockito.doAnswer
 import org.mockito.Mockito.doReturn
 import org.mockito.Mockito.mock
@@ -106,6 +107,17 @@ class AssistantTest {
         }
     }
 
+    @Test
+    fun onNotificationEnqueued_doesntCheckForOtpIfFlagDisabled() {
+        (setFlagsRule as SetFlagsRule)
+            .disableFlags(Flags.FLAG_REDACT_SENSITIVE_NOTIFICATIONS_FROM_UNTRUSTED_LISTENERS)
+        val sbn = createSbn(TEXT_WITH_OTP)
+        val directReturn =
+            assistant.onNotificationEnqueued(sbn, NotificationChannel("0", "", IMPORTANCE_DEFAULT))
+        // Expect no adjustment returned, despite the regex
+        assertThat(directReturn).isNull()
+    }
+
     @Test
     fun onNotificationEnqueued_callsTextClassifierForOtpAndSuggestions() {
         val sbn = createSbn(TEXT_WITH_OTP)
@@ -113,7 +125,7 @@ class AssistantTest {
             .whenKt(mockTc).detectLanguage(any())
         assistant.onNotificationEnqueued(sbn, NotificationChannel("0", "", IMPORTANCE_DEFAULT))
         Thread.sleep(EXECUTOR_AWAIT_TIME)
-        verify(mockTc).detectLanguage(any())
+        verify(mockTc, atLeastOnce()).detectLanguage(any())
         verify(assistant.mSmartSuggestionsHelper, times(1)).onNotificationEnqueued(eq(sbn))
         // A false result shouldn't result in an adjustment call for the otp
         verify(assistant).createNotificationAdjustment(any(), isNull(), isNull(), eq(true))
@@ -135,7 +147,7 @@ class AssistantTest {
         assertThat(directReturn.signals.getCharSequenceArrayList(KEY_TEXT_REPLIES)).isNull()
         Thread.sleep(EXECUTOR_AWAIT_TIME)
         // Expect a call to the TC, and a call to adjust the notification
-        verify(mockTc).detectLanguage(any())
+        verify(mockTc, atLeastOnce()).detectLanguage(any())
         verify(assistant).createNotificationAdjustment(any(), isNull(), isNull(), eq(true))
         // Expect adjustment for the suggestions and OTP together, with a true value
         verify(assistant).createNotificationAdjustment(any(),
@@ -189,7 +201,9 @@ class AssistantTest {
         var sensitiveString: String? = null
         doAnswer { invocation: InvocationOnMock ->
             val request = invocation.getArgument<TextLanguage.Request>(0)
-            sensitiveString = request.text.toString()
+            if (sensitiveString == null) {
+                sensitiveString = request.text.toString()
+            }
             return@doAnswer TextLanguage.Builder().putLocale(ULocale.ROOT, 0.9f).build()
 
         }.whenKt(mockTc).detectLanguage(any())
@@ -214,7 +228,7 @@ class AssistantTest {
             style = Notification.InboxStyle())
         assistant.onNotificationEnqueued(sbn, NotificationChannel("0", "", IMPORTANCE_DEFAULT))
         Thread.sleep(EXECUTOR_AWAIT_TIME)
-        verify(mockTc).detectLanguage(any())
+        verify(mockTc, atLeastOnce()).detectLanguage(any())
     }
 
     @Test
diff --git a/java/tests/src/android/ext/services/notification/NotificationOtpDetectionHelperTest.kt b/java/tests/src/android/ext/services/notification/NotificationOtpDetectionHelperTest.kt
index d90fd80..8dc7a38 100644
--- a/java/tests/src/android/ext/services/notification/NotificationOtpDetectionHelperTest.kt
+++ b/java/tests/src/android/ext/services/notification/NotificationOtpDetectionHelperTest.kt
@@ -23,41 +23,31 @@ import android.app.Notification.CATEGORY_SOCIAL
 import android.app.Notification.EXTRA_TEXT
 import android.app.PendingIntent
 import android.app.Person
+import android.content.Context
 import android.content.Intent
 import android.icu.util.ULocale
-import androidx.test.platform.app.InstrumentationRegistry
-import com.android.modules.utils.build.SdkLevel
-import android.platform.test.flag.junit.SetFlagsRule
-import android.service.notification.Flags.FLAG_REDACT_SENSITIVE_NOTIFICATIONS_BIG_TEXT_STYLE
-import android.service.notification.Flags.FLAG_REDACT_SENSITIVE_NOTIFICATIONS_FROM_UNTRUSTED_LISTENERS
+import android.os.Build
+import android.os.Build.VERSION.SDK_INT
+import android.view.textclassifier.TextClassificationManager
 import android.view.textclassifier.TextClassifier
 import android.view.textclassifier.TextLanguage
 import android.view.textclassifier.TextLinks
+import androidx.test.core.app.ApplicationProvider
+import androidx.test.ext.junit.runners.AndroidJUnit4
 import com.google.common.truth.Truth.assertWithMessage
 import org.junit.After
 import org.junit.Assume.assumeTrue
 import org.junit.Before
-import org.junit.Rule
 import org.junit.Test
-import org.junit.rules.TestRule
 import org.junit.runner.RunWith
-import org.junit.runners.JUnit4
 import org.mockito.ArgumentMatchers.any
 import org.mockito.Mockito
 
-@RunWith(JUnit4::class)
+@RunWith(AndroidJUnit4::class)
 class NotificationOtpDetectionHelperTest {
-    val context = InstrumentationRegistry.getInstrumentation().targetContext!!
-    val localeWithRegex = ULocale.ENGLISH
-    val invalidLocale = ULocale.ROOT
-
-    @get:Rule
-    val setFlagsRule = if (SdkLevel.isAtLeastV()) {
-        SetFlagsRule()
-    } else {
-        // On < V, have a test rule that does nothing
-        TestRule { statement, _ -> statement}
-    }
+    private val context = ApplicationProvider.getApplicationContext<Context>()
+    private val localeWithRegex = ULocale.ENGLISH
+    private val invalidLocale = ULocale.ROOT
 
     private data class TestResult(
         val expected: Boolean,
@@ -69,10 +59,7 @@ class NotificationOtpDetectionHelperTest {
 
     @Before
     fun enableFlag() {
-        assumeTrue(SdkLevel.isAtLeastV())
-        (setFlagsRule as SetFlagsRule).enableFlags(
-            FLAG_REDACT_SENSITIVE_NOTIFICATIONS_FROM_UNTRUSTED_LISTENERS,
-            FLAG_REDACT_SENSITIVE_NOTIFICATIONS_BIG_TEXT_STYLE)
+        assumeTrue(SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM)
         results.clear()
     }
 
@@ -80,7 +67,7 @@ class NotificationOtpDetectionHelperTest {
     fun verifyResults() {
         val allFailuresMessage = StringBuilder("")
         var numFailures = 0;
-        results.forEach { (expected, actual, failureMessage) ->
+        for ((expected, actual, failureMessage) in results) {
             if (expected != actual) {
                 numFailures += 1
                 allFailuresMessage.append("$failureMessage\n")
@@ -94,19 +81,6 @@ class NotificationOtpDetectionHelperTest {
         results.add(TestResult(expected, actual, failureMessage))
     }
 
-    @Test
-    fun testGetTextForDetection_emptyIfFlagDisabled() {
-        (setFlagsRule as SetFlagsRule)
-            .disableFlags(FLAG_REDACT_SENSITIVE_NOTIFICATIONS_FROM_UNTRUSTED_LISTENERS)
-        val text = "text"
-        val title = "title"
-        val subtext = "subtext"
-        val sensitive = NotificationOtpDetectionHelper.getTextForDetection(
-            createNotification(text = text, title = title, subtext = subtext))
-        assertWithMessage("expected sensitive text to be empty").that(sensitive).isEmpty()
-    }
-
-
     @Test
     fun testGetTextForDetection_textFieldsIncluded() {
         val text = "text"
@@ -227,16 +201,6 @@ class NotificationOtpDetectionHelperTest {
         addResult(expected = true, sensitive.length <= 600, "Expected to be 600 chars or fewer")
     }
 
-    @Test
-    fun testShouldCheckForOtp_falseIfFlagDisabled() {
-        (setFlagsRule as SetFlagsRule)
-            .disableFlags(FLAG_REDACT_SENSITIVE_NOTIFICATIONS_FROM_UNTRUSTED_LISTENERS)
-        val shouldCheck = NotificationOtpDetectionHelper
-            .shouldCheckForOtp(createNotification(category = CATEGORY_MESSAGE))
-        addResult(expected = false, shouldCheck, "$CATEGORY_MESSAGE should not be checked")
-    }
-
-
     @Test
     fun testShouldCheckForOtp_styles() {
         val style = Notification.InboxStyle()
@@ -246,6 +210,7 @@ class NotificationOtpDetectionHelperTest {
         val empty = Person.Builder().setName("test").build()
         val style2 = Notification.MessagingStyle(empty)
         val style3 = Notification.BigPictureStyle()
+        val rejectedStyle = Notification.MediaStyle()
         shouldCheck = NotificationOtpDetectionHelper
                 .shouldCheckForOtp(createNotification(style = style2))
         addResult(expected = true, shouldCheck, "MessagingStyle should be checked")
@@ -255,6 +220,10 @@ class NotificationOtpDetectionHelperTest {
         shouldCheck = NotificationOtpDetectionHelper
                 .shouldCheckForOtp(createNotification(style = style3))
         addResult(expected = false, shouldCheck, "Valid non-messaging non-inbox style should not be checked")
+        shouldCheck = NotificationOtpDetectionHelper
+            .shouldCheckForOtp(createNotification(text = "your one time code is 4343434",
+                style = rejectedStyle))
+        addResult(expected = false, shouldCheck, "MediaStyle should always be rejected")
     }
 
     @Test
@@ -275,7 +244,7 @@ class NotificationOtpDetectionHelperTest {
 
     @Test
     fun testShouldCheckForOtp_regex() {
-        var shouldCheck = NotificationOtpDetectionHelper
+        val shouldCheck = NotificationOtpDetectionHelper
                 .shouldCheckForOtp(createNotification(text = "45454", category = ""))
         assertWithMessage("Regex matches should be checked").that(shouldCheck).isTrue()
     }
@@ -343,14 +312,14 @@ class NotificationOtpDetectionHelperTest {
         val otpWithDashesButInvalidDate = "34-58-30"
         val otpWithDashesButInvalidYear = "12-1-3089"
 
-        addMatcherTestResult(expected =
-            true,
+        addMatcherTestResult(
+            expected = true,
             date,
             checkForFalsePositives = false,
             customFailureMessage = "should match if checkForFalsePositives is false"
         )
-        addMatcherTestResult(expected =
-            false,
+        addMatcherTestResult(
+            expected = false,
             date,
             customFailureMessage = "should not match if checkForFalsePositives is true"
         )
@@ -362,6 +331,26 @@ class NotificationOtpDetectionHelperTest {
         addMatcherTestResult(expected = true, otpWithDashesButInvalidYear)
     }
 
+    @Test
+    fun testContainsOtp_phoneExclusion() {
+        val parens = "(888) 8888888"
+        val allSpaces = "888 888 8888"
+        val withDash = "(888) 888-8888"
+        val allDashes = "888-888-8888"
+        val allDashesWithParen = "(888)-888-8888"
+        addMatcherTestResult(
+            expected = true,
+            parens,
+            checkForFalsePositives = false,
+            customFailureMessage = "should match if checkForFalsePositives is false"
+        )
+        addMatcherTestResult(expected = false, parens)
+        addMatcherTestResult(expected = false, allSpaces)
+        addMatcherTestResult(expected = false, withDash)
+        addMatcherTestResult(expected = false, allDashes)
+        addMatcherTestResult(expected = false, allDashesWithParen)
+    }
+
     @Test
     fun testContainsOtp_dashes() {
         val oneDash = "G-3d523"
@@ -378,31 +367,39 @@ class NotificationOtpDetectionHelperTest {
     fun testContainsOtp_startAndEnd() {
         val noSpaceStart = "your code isG-345821"
         val noSpaceEnd = "your code is G-345821for real"
+        val numberSpaceStart = "your code is 4 G-345821"
+        val numberSpaceEnd = "your code is G-345821 3"
         val colonStart = "your code is:G-345821"
-        val parenStart = "your code is (G-345821"
         val newLineStart = "your code is \nG-345821"
-        val quoteStart = "your code is 'G-345821"
-        val doubleQuoteStart = "your code is \"G-345821"
+        val quote = "your code is 'G-345821'"
+        val doubleQuote = "your code is \"G-345821\""
         val bracketStart = "your code is [G-345821"
         val ideographicStart = "your code is码G-345821"
         val colonStartNumberPreceding = "your code is4:G-345821"
         val periodEnd = "you code is G-345821."
-        val parenEnd = "you code is (G-345821)"
-        val quoteEnd = "you code is 'G-345821'"
+        val parens = "you code is (G-345821)"
+        val squareBrkt = "you code is [G-345821]"
+        val dashEnd = "you code is 'G-345821-'"
+        val randomSymbolEnd = "your code is G-345821$"
+        val underscoreEnd = "you code is 'G-345821_'"
         val ideographicEnd = "your code is码G-345821码"
         addMatcherTestResult(expected = false, noSpaceStart)
         addMatcherTestResult(expected = false, noSpaceEnd)
+        addMatcherTestResult(expected = false, numberSpaceStart)
+        addMatcherTestResult(expected = false, numberSpaceEnd)
         addMatcherTestResult(expected = false, colonStartNumberPreceding)
+        addMatcherTestResult(expected = false, dashEnd)
+        addMatcherTestResult(expected = false, underscoreEnd)
+        addMatcherTestResult(expected = false, randomSymbolEnd)
         addMatcherTestResult(expected = true, colonStart)
-        addMatcherTestResult(expected = true, parenStart)
         addMatcherTestResult(expected = true, newLineStart)
-        addMatcherTestResult(expected = true, quoteStart)
-        addMatcherTestResult(expected = true, doubleQuoteStart)
+        addMatcherTestResult(expected = true, quote)
+        addMatcherTestResult(expected = true, doubleQuote)
         addMatcherTestResult(expected = true, bracketStart)
         addMatcherTestResult(expected = true, ideographicStart)
         addMatcherTestResult(expected = true, periodEnd)
-        addMatcherTestResult(expected = true, parenEnd)
-        addMatcherTestResult(expected = true, quoteEnd)
+        addMatcherTestResult(expected = true, parens)
+        addMatcherTestResult(expected = true, squareBrkt)
         addMatcherTestResult(expected = true, ideographicEnd)
     }
 
@@ -429,6 +426,7 @@ class NotificationOtpDetectionHelperTest {
         val thirtyXX = "3035"
         val nineteenXX = "1945"
         val eighteenXX = "1899"
+        val yearSubstring = "20051"
         addMatcherTestResult(expected = false, twentyXX, textClassifier = tc)
         // Behavior should be the same for an invalid language, and null TextClassifier
         addMatcherTestResult(expected = false, twentyXX, textClassifier = null)
@@ -436,32 +434,81 @@ class NotificationOtpDetectionHelperTest {
         addMatcherTestResult(expected = true, thirtyXX, textClassifier = tc)
         addMatcherTestResult(expected = false, nineteenXX, textClassifier = tc)
         addMatcherTestResult(expected = true, eighteenXX, textClassifier = tc)
+        // A substring of a year should not trigger a false positive
+        addMatcherTestResult(expected = true, yearSubstring, textClassifier = tc)
     }
 
     @Test
-    fun testContainsOtp_engishSpecificRegex() {
+    fun testContainsOtp_englishSpecificRegex() {
         val tc = getTestTextClassifier(ULocale.ENGLISH)
         val englishFalsePositive = "This is a false positive 4543"
         val englishContextWords = listOf("login", "log in", "2fa", "authenticate", "auth",
             "authentication", "tan", "password", "passcode", "two factor", "two-factor", "2factor",
-            "2 factor", "pin")
+            "2 factor", "pin", "one time")
         val englishContextWordsCase = listOf("LOGIN", "logIn", "LoGiN")
         // Strings with a context word somewhere in the substring
         val englishContextSubstrings = listOf("pins", "gaping", "backspin")
+        val codeInNextSentence = "context word: code. This sentence has the actual value of 434343"
+        val codeInNextSentenceTooFar =
+            "context word: code. ${"f".repeat(60)} This sentence has the actual value of 434343"
+        val codeTwoSentencesAfterContext = "context word: code. One sentence. actual value 34343"
+        val codeInSentenceBeforeContext = "34343 is a number. This number is a code"
+        val codeInSentenceAfterNewline = "your code is \n 34343"
+        val codeTooFarBeforeContext = "34343 ${"f".repeat(60)} code"
 
         addMatcherTestResult(expected = false, englishFalsePositive, textClassifier = tc)
         for (context in englishContextWords) {
-            val englishTruePositive = "$englishFalsePositive $context"
+            val englishTruePositive = "$context $englishFalsePositive"
             addMatcherTestResult(expected = true, englishTruePositive, textClassifier = tc)
         }
         for (context in englishContextWordsCase) {
-            val englishTruePositive = "$englishFalsePositive $context"
+            val englishTruePositive = "$context $englishFalsePositive"
             addMatcherTestResult(expected = true, englishTruePositive, textClassifier = tc)
         }
         for (falseContext in englishContextSubstrings) {
-            val anotherFalsePositive = "$englishFalsePositive $falseContext"
+            val anotherFalsePositive = "$falseContext $englishFalsePositive"
             addMatcherTestResult(expected = false, anotherFalsePositive, textClassifier = tc)
         }
+        addMatcherTestResult(expected = true, codeInNextSentence, textClassifier = tc)
+        addMatcherTestResult(expected = true, codeInSentenceAfterNewline, textClassifier = tc)
+        addMatcherTestResult(expected = false, codeTwoSentencesAfterContext, textClassifier = tc)
+        addMatcherTestResult(expected = false, codeInSentenceBeforeContext, textClassifier = tc)
+        addMatcherTestResult(expected = false, codeInNextSentenceTooFar, textClassifier = tc)
+        addMatcherTestResult(expected = false, codeTooFarBeforeContext, textClassifier = tc)
+    }
+
+    @Test
+    fun testContainsOtp_notificationFieldsCheckedIndividually() {
+        val tc = getTestTextClassifier(ULocale.ENGLISH)
+        // Together, the title and text will match the language-specific regex and the main regex,
+        // but apart, neither are enough
+        val notification = createNotification(text = "code", title = "434343")
+        addMatcherTestResult(expected = true, "code 434343")
+        addResult(expected = false, NotificationOtpDetectionHelper.containsOtp(notification, true,
+            tc), "Expected text of 'code' and title of '434343' not to match")
+    }
+
+    @Test
+    fun testContainsOtp_multipleFalsePositives() {
+        val otp = "code 1543 code"
+        val longFp = "888-777-6666"
+        val shortFp = "34ess"
+        val multipleLongFp = "$longFp something something $longFp"
+        val multipleLongFpWithOtpBefore = "$otp $multipleLongFp"
+        val multipleLongFpWithOtpAfter = "$multipleLongFp $otp"
+        val multipleLongFpWithOtpBetween = "$longFp $otp $longFp"
+        val multipleShortFp = "$shortFp something something $shortFp"
+        val multipleShortFpWithOtpBefore = "$otp $multipleShortFp"
+        val multipleShortFpWithOtpAfter = "$otp $multipleShortFp"
+        val multipleShortFpWithOtpBetween = "$shortFp $otp $shortFp"
+        addMatcherTestResult(expected = false, multipleLongFp)
+        addMatcherTestResult(expected = false, multipleShortFp)
+        addMatcherTestResult(expected = true, multipleLongFpWithOtpBefore)
+        addMatcherTestResult(expected = true, multipleLongFpWithOtpAfter)
+        addMatcherTestResult(expected = true, multipleLongFpWithOtpBetween)
+        addMatcherTestResult(expected = true, multipleShortFpWithOtpBefore)
+        addMatcherTestResult(expected = true, multipleShortFpWithOtpAfter)
+        addMatcherTestResult(expected = true, multipleShortFpWithOtpBetween)
     }
 
     @Test
@@ -482,7 +529,7 @@ class NotificationOtpDetectionHelperTest {
         // Dates should still be checked
         addMatcherTestResult(expected = false, date, textClassifier = tc)
         // A string with a code with three lowercase letters, and an excluded year
-        val withOtherFalsePositives = "your login code is abd3 1985"
+        val withOtherFalsePositives = "your login code is abd4f 1985"
         // Other false positive regular expressions should not be checked
         addMatcherTestResult(expected = true, withOtherFalsePositives, textClassifier = tc)
     }
@@ -573,4 +620,4 @@ class NotificationOtpDetectionHelperTest {
         ).`when`(tc).generateLinks(any(TextLinks.Request::class.java))
         return tc
     }
-}
\ No newline at end of file
+}
diff --git a/java/tests/src/android/ext/services/notification/OWNERS b/java/tests/src/android/ext/services/notification/OWNERS
new file mode 100644
index 0000000..1a1fe22
--- /dev/null
+++ b/java/tests/src/android/ext/services/notification/OWNERS
@@ -0,0 +1,4 @@
+include platform/frameworks/base:/core/java/android/service/notification/OWNERS
+
+# Owner of the OTP detection project
+per-file NotificationOtpDetectionHelperTest.kt = ntmyren@google.com
diff --git a/native/tests/AndroidTest-sminus.xml b/native/tests/AndroidTest-sminus.xml
index 52e04f5..0955960 100644
--- a/native/tests/AndroidTest-sminus.xml
+++ b/native/tests/AndroidTest-sminus.xml
@@ -28,6 +28,7 @@
     <test class="com.android.tradefed.testtype.GTest" >
         <option name="native-test-device-path" value="/data/local/tmp" />
         <option name="module-name" value="libextservices_test-sminus" />
+        <option name="force-no-test-error" value="false" />
     </test>
 
     <!-- Prevent test from running on Android T+ -->
diff --git a/native/tests/AndroidTest-tplus.xml b/native/tests/AndroidTest-tplus.xml
index 179d511..ae2bf0b 100644
--- a/native/tests/AndroidTest-tplus.xml
+++ b/native/tests/AndroidTest-tplus.xml
@@ -28,6 +28,7 @@
     <test class="com.android.tradefed.testtype.GTest" >
         <option name="native-test-device-path" value="/data/local/tmp" />
         <option name="module-name" value="libextservices_test-tplus" />
+        <option name="force-no-test-error" value="false" />
     </test>
 
     <!-- Prevent tests from running on Android S- -->
```

