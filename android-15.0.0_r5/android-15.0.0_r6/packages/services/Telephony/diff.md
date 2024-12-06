```diff
diff --git a/Android.bp b/Android.bp
index 78e6afb4d..2c41fb91d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -29,7 +29,7 @@ android_app {
         "libprotobuf-java-lite",
         "app-compat-annotations",
         "unsupportedappusage",
-        "org.apache.http.legacy",
+        "org.apache.http.legacy.stubs.system",
     ],
 
     static_libs: [
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 09258a4e7..feb5a7870 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -181,6 +181,8 @@
 
     <!-- Needed because the DISPLAY_EMERGENCY_MESSAGE ConnectionEvent contains a PendingIntent to activate the satellite feature. -->
     <uses-permission android:name="com.google.android.apps.stargate.permission.SEND_EMERGENCY_INTENTS"/>
+    <!-- Needed to start demo session -->
+    <uses-permission android:name="com.google.android.apps.stargate.permission.SEND_NON_EMERGENCY_INTENTS"/>
 
     <application android:name="PhoneApp"
             android:persistent="true"
@@ -563,7 +565,7 @@
 
         <receiver
           android:name="com.android.phone.vvm.VvmSmsReceiver"
-            android:exported="false"
+            android:exported="true"
             androidprv:systemUserOnly="true">
             <intent-filter>
                 <action android:name="com.android.internal.provider.action.VOICEMAIL_SMS_RECEIVED"/>
@@ -572,7 +574,7 @@
 
         <receiver
             android:name="com.android.phone.vvm.VvmSimStateTracker"
-            android:exported="false"
+            android:exported="true"
             androidprv:systemUserOnly="true">
             <intent-filter>
                 <action android:name="android.intent.action.BOOT_COMPLETED"/>
@@ -597,7 +599,7 @@
 
         <receiver
             android:name=".security.SafetySourceReceiver"
-            android:exported="false"
+            android:exported="true"
             androidprv:systemUserOnly="true">
             <intent-filter>
                 <action android:name="android.safetycenter.action.REFRESH_SAFETY_SOURCES"/>
@@ -642,7 +644,7 @@
             android:name=".settings.RadioInfo"
             android:label="@string/phone_info_label"
             android:exported="true"
-            android:theme="@style/Theme.AppCompat.DayNight">
+            android:theme="@style/RadioInfoTheme">
             <intent-filter>
                 <action android:name="android.intent.action.MAIN" />
                 <category android:name="android.intent.category.DEVELOPMENT_PREFERENCE" />
diff --git a/ecc/input/eccdata.txt b/ecc/input/eccdata.txt
index c4edc9e58..f7c36e237 100644
--- a/ecc/input/eccdata.txt
+++ b/ecc/input/eccdata.txt
@@ -547,7 +547,8 @@ countries {
   }
   eccs {
     phone_number: "1414"
-    types: TYPE_UNSPECIFIED
+    types: MOUNTAIN_RESCUE
+    routing: NORMAL
   }
   eccs {
     phone_number: "0800117117"
@@ -836,11 +837,6 @@ countries {
     types: FIRE
     routing: EMERGENCY
   }
-  eccs {
-    phone_number: "088"
-    types: POLICE
-    routing: NORMAL
-  }
   eccs {
     phone_number: "085"
     types: FIRE
@@ -1019,6 +1015,7 @@ countries {
   eccs {
     phone_number: "114"
     types: TYPE_UNSPECIFIED
+    routing: NORMAL
   }
   eccs {
     phone_number: "191"
@@ -1382,6 +1379,11 @@ countries {
     types: AMBULANCE
     types: FIRE
   }
+  eccs {
+    phone_number: "108"
+    types: AMBULANCE
+    routing: NORMAL
+  }
   eccs {
     phone_number: "100"
     types: POLICE
diff --git a/ecc/output/eccdata b/ecc/output/eccdata
index 482ed79a3..697fd49d7 100644
Binary files a/ecc/output/eccdata and b/ecc/output/eccdata differ
diff --git a/res/layout/radio_info.xml b/res/layout/radio_info.xml
index f18eda007..ac1f3f335 100644
--- a/res/layout/radio_info.xml
+++ b/res/layout/radio_info.xml
@@ -20,7 +20,6 @@
 <ScrollView xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
-    android:paddingTop="40dp"
     android:layoutDirection="locale"
     android:textDirection="locale">
 
@@ -213,7 +212,9 @@
 
         <!-- Mock signal strength -->
         <LinearLayout style="@style/RadioInfo_entry_layout">
-            <TextView android:text="@string/radio_info_signal_strength_label" style="@style/info_label" />
+            <TextView android:id="@+id/signal_strength_label"
+                android:text="@string/radio_info_signal_strength_label"
+                style="@style/info_label" />
             <Spinner android:id="@+id/signalStrength"
                  android:layout_width="match_parent"
                  android:layout_height="wrap_content"/>
@@ -221,7 +222,9 @@
 
        <!-- Mock data network type -->
        <LinearLayout style="@style/RadioInfo_entry_layout">
-            <TextView android:text="@string/radio_info_data_network_type_label" style="@style/info_label" />
+            <TextView android:id="@+id/data_network_type_label"
+                android:text="@string/radio_info_data_network_type_label"
+                style="@style/info_label" />
             <Spinner android:id="@+id/dataNetworkType"
                  android:layout_width="match_parent"
                  android:layout_height="wrap_content"/>
@@ -249,6 +252,14 @@
                 android:layout_height="wrap_content"
                 android:text="@string/simulate_out_of_service_string"/>
 
+        <!-- Enforce camping on satellite channel -->
+        <Switch android:id="@+id/enforce_satellite_channel"
+            android:textSize="14sp"
+            android:layout_marginTop="8dip"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:text="@string/enforce_satellite_channel_string"/>
+
         <!-- Simulate this SIM to be satellite -->
         <Switch android:id="@+id/mock_carrier_roaming_satellite"
                 android:textSize="14sp"
@@ -267,6 +278,25 @@
                 android:text="@string/esos_satellite_string"
         />
 
+        <!-- Satellite enable non-emergency mode-->
+        <Button android:id="@+id/satellite_enable_non_emergency_mode"
+            android:textSize="14sp"
+            android:layout_marginTop="8dip"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textAllCaps="false"
+            android:text="@string/satellite_enable_non_emergency_mode_string" />
+
+        <!-- Demo ESOS -->
+        <Button android:id="@+id/demo_esos_questionnaire"
+                android:textSize="14sp"
+                android:layout_marginTop="8dip"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:textAllCaps="false"
+                android:text="@string/demo_esos_satellite_string"
+        />
+
         <!-- VoLTE provisioned -->
         <Switch android:id="@+id/volte_provisioned_switch"
                 android:textSize="14sp"
@@ -512,19 +542,5 @@
                       android:layout_toStartOf="@id/update_smsc"
                       android:layout_toEndOf="@id/smsc_label" />
         </RelativeLayout>
-
-        <!-- Test setting to ignore bad DNS, useful in lab environments -->
-        <LinearLayout style="@style/RadioInfo_entry_layout">
-            <Button android:id="@+id/dns_check_toggle"
-                    android:textSize="14sp"
-                    android:layout_marginTop="8dip"
-                    android:layout_width="wrap_content"
-                    android:layout_height="wrap_content"
-                    android:text="@string/radio_info_toggle_dns_check_label"
-                    />
-            <TextView android:id="@+id/dnsCheckState" style="@style/info_value" />
-        </LinearLayout>
-
-
     </LinearLayout>
 </ScrollView>
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 2827cf910..e4d1e2f34 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Stel Verwyderbare-e-SIM as Verstek"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobieleradiokrag"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simuleer is nie beskikbaar nie (Slegs ontfoutingbou)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE-kanaal (net ontfoutingsbou)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Satellietmodus van skyndiensverskaffer (net ontfoutingsbou)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Toets regte satelliet-eSOS-modus (net ontfoutingsbou)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Toets nie-eSOS-modus vir regte satelliet (net ontfoutingsbou)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Toets demonstrasiesatelliet-eSOS-modus (net ontfoutingsbou)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Bekyk SIM-adresboek"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Kyk na vaste skakelnommers"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Bekyk skakeldiensnommers"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Dateer op"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Herlaai"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Wissel DNS-kontrole"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-spesifieke inligting/instellings"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC-beskikbaar (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR-beperk (NSA):"</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index 96ef7accf..9c197dd72 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"የሚወገድን ኢሲም ነባሪ በሚል አቀናብር"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"የሞባይል ሬዲዮ ኃይል"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"ከአገልግሎት ውጭን አስመስል (የስህተት ማረሚያ ግንብ ብቻ)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE ሰርጥ (የስህተት አርም ግንባታ ብቻ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock Carrier Satellite Mode (የስህተት ማረሚያ ግንባታ ብቻ)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"የእውነተኛ ሳተላይት eSOS ሁነታን ይሞክሩ (የስህተት ማረሚያ ግንብ ብቻ)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"የእውነተኛ ሳተላይት eSOS ያልሆነ ሁነታን ይሞክሩ (የስህተት ማረሚያ ግንብ ብቻ)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"የቅንጭብ ማሳያ ሳተላይት eSOS ሁነታን ይሞክሩ (የስህተት ማረሚያ ግንብ ብቻ)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"የሲም አድራሻ ደብተር አሳይ"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"በቋሚነት የሚደወልባቸው ቁጥሮች"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"የአገልግሎት መደወያ ቁጥሮችን ተመልከት"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"አዘምን"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"አድስ"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"የDNS ፍተሻን ቀያይር"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-የተወሰነ መረጃ/ቅንብሮች"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC ይገኛል (NSA)፦"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR ተገድቧል (NSA)፦"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 97020a6fa..23916eb2c 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"‏ضبط شريحة eSIM القابلة للإزالة كشريحة تلقائية"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"طاقة اللاسلكي للجوّال"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"محاكاة الخطأ \"خارج الخدمة\" (الإصدار المخصص لتصحيح الأخطاء فقط)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"‏قناة LTE للقمر الصناعي Force Camp (إصدار مخصّص لتصحيح الأخطاء فقط)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"وضع القمر الصناعي التجريبي لمشغّل شبكة الجوّال (إصدار مخصّص لتصحيح الأخطاء فقط)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"‏اختبار وضع القمر الصناعي الحقيقي لنظام eSOS (إصدار مخصّص لتصحيح الأخطاء فقط)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"‏اختبار وضع القمر الصناعي الحقيقي غير تابع لنظام eSOS (إصدار مخصّص لتصحيح الأخطاء فقط)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"اختبار وضع \"اتصالات الطوارئ بالقمر الصناعي\" التجريبي (إصدار مخصّص لتصحيح الأخطاء فقط)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"‏عرض دفتر عناوين SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"عرض أرقام الطلب الثابت"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"عرض أرقام طلب الخدمة"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"تعديل"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"إعادة التحميل"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"تبديل فحص نظام أسماء النطاقات"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"المعلومات/الإعدادات المتعلّقة بالمصنّع الأصلي للجهاز"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"‏EN-DC متوفّر (في وضع NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"‏تم حظر DCNR ‏(في وضع NSA):"</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 987d5dde2..175d5bf0a 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"আঁতৰাব পৰা ই-ছিম ডিফ’ল্ট হিচাপে ছেট কৰক"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"ম’বাইলৰ ৰেডিঅ’ পাৱাৰ"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"সেৱাত নাই ছিমুলে’ট কৰক (কেৱল ডিবাগ বিল্ড)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp উপগ্ৰহ LTE চেনেল (কেৱল ডিবাগ বিল্ড)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"নকল বাহক উপগ্ৰহ ম’ড (কেৱল ডিবাগ বিল্ড)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"বাস্তৱিক উপগ্ৰহৰ eSOS ম’ড পৰীক্ষা কৰক (কেৱল ডিবাগ বিল্ড)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"বাস্তৱিক উপগ্ৰহৰ অনা eSOS ম’ড পৰীক্ষা কৰক (কেৱল ডিবাগ বিল্ড)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"উপগ্ৰহৰ eSOS ম’ডৰ ডেম’ পৰীক্ষা কৰক (কেৱল ডিবাগ বিল্ড)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"ছিম ঠিকনা সূচী চাওক"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"ফিক্সড্ ডায়েলিং নম্বৰসমূহ চাওক"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"সেৱা ডায়েলিং নম্বৰসমূহ চাওক"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"আপডে’ট কৰক"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"ৰিফ্ৰেশ্ব কৰক"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS পৰীক্ষা ট’গল কৰক"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM বিশেষক তথ্য/ছেটিংসমূহ"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC উপলব্ধ (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR সীমিত (NSA):"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 5e925a55d..e0f42b2eb 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Çıxarıla bilən eSIM\'i Defolt olaraq təyin edin"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobil Radio Enerjisi"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\"Xidmətdənkənar\" Simulyasiyası (yalnız Debaq Versiyası)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (yalnız sazlama versiyası)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Sınaq Daşıyıcı Peyk Rejimi (yalnız sazlama versiyası)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Real peyk eSOS rejimini sınaqdan keçirin (yalnız sazlama versiyası)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Real peyk qeyri-eSOS rejimini sınaqdan keçirin (yalnız sazlama versiyası)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Demo peyk eSOS rejimini sınaqdan keçirin (yalnız sazlama versiyası)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM Ünvan Kitabçasına Baxın"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Sabit Yığım Nömrələrinə Baxın"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Xidmət Yığım Nömrələrinə Baxın"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Güncəlləyin"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Yeniləyin"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS Yoxlanışına keçin"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Orijinal Avadanlıq İstehsalçısının Məlumatı/Ayarlar"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC Əlçatandır (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR Məhdudlaşdırıldı (NSA):"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index bd20dfa27..8d60adc45 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Podesi prenosivi eSIM kao podrazumevani"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Napajanje za radio na mobilnim uređajima"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulacija ne funkcioniše (samo verzija sa otklonjenim greškama)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Prinudno primeni satelit za kampovanje na LTE kanal (samo verzija za otklanjanje grešaka)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Lažni režim mobilnog operatera za slanje preko satelita (samo verzija za otklanjanje grešaka)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testirajte stvarni satelitski eSOS režim (samo verzija sa otklonjenim greškama)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testirajte stvarni satelitski režim koji nije eSOS (samo verzija sa otklonjenim greškama)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testirajte demo verziju satelitskog eSOS režima (samo verzija sa otklonjenim greškama)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Prikaži adresar SIM-a"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Prikaži brojeve za fiksno biranje"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Prikaži brojeve za servisno biranje"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Ažuriraj"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Osveži"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Uključi/isključi proveru DNS-a"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Informacije/podešavanja specifična za proizvođača originalne opreme"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC dostupno (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR ograničeno (NSA):"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index bc428923b..1306dbd72 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -377,9 +377,9 @@
     <item msgid="6685082338652847671">"7"</item>
   </string-array>
     <string name="list_language_dtitle" msgid="7457017255633587047">"Мовы"</string>
-    <string name="enable_disable_local_weather" msgid="7734933941872511543">"Мясцовае надвор\'е"</string>
-    <string name="local_weather_enable" msgid="2143929735295254729">"Мясцовае надвор\'е ўключана"</string>
-    <string name="local_weather_disable" msgid="4209936355998349647">"Мясцовае надвор\'е адключана"</string>
+    <string name="enable_disable_local_weather" msgid="7734933941872511543">"Мясцовае надвор’е"</string>
+    <string name="local_weather_enable" msgid="2143929735295254729">"Мясцовае надвор’е ўключана"</string>
+    <string name="local_weather_disable" msgid="4209936355998349647">"Мясцовае надвор’е адключана"</string>
     <string name="enable_disable_atr" msgid="821714821057385390">"Мясцовыя транспартныя паведамленні"</string>
     <string name="atr_enable" msgid="1799097759998768186">"Мясцовыя транспартныя паведамленні ўключаны"</string>
     <string name="atr_disable" msgid="6456758173289065766">"Мясцовыя транспартныя паведамленні адключаны"</string>
@@ -554,7 +554,7 @@
     <string name="incall_error_supp_service_resume" msgid="1276861499306817035">"Не ўдалося ўзнавіць выклік."</string>
     <string name="incall_error_supp_service_separate" msgid="8932660028965274353">"Немагчыма аддзяліць выклік."</string>
     <string name="incall_error_supp_service_transfer" msgid="8211925891867334323">"Немагчыма перадаць выклік."</string>
-    <string name="incall_error_supp_service_conference" msgid="27578082433544702">"Не ўдалося аб\'яднаць выклікі."</string>
+    <string name="incall_error_supp_service_conference" msgid="27578082433544702">"Не ўдалося аб’яднаць выклікі."</string>
     <string name="incall_error_supp_service_reject" msgid="3044363092441655912">"Немагчыма адхіліць выклік."</string>
     <string name="incall_error_supp_service_hangup" msgid="836524952243836735">"Немагчыма скончыць выклік(і)."</string>
     <string name="incall_error_supp_service_hold" msgid="8535056414643540997">"Немагчыма ўтрымліваць выклікі."</string>
@@ -572,7 +572,7 @@
     <string name="emergency_enable_radio_dialog_message" msgid="1695305158151408629">"Уключэнне радыё..."</string>
     <string name="emergency_enable_radio_dialog_retry" msgid="4329131876852608587">"Не абслугоўваецца. Паўтор спробы..."</string>
     <string name="radio_off_during_emergency_call" msgid="8011154134040481609">"Немагчыма ўвайсцi ў рэжым палёту падчас экстранага выклiку"</string>
-    <string name="dial_emergency_error" msgid="825822413209026039">"Выклік немагчымы. <xliff:g id="NON_EMERGENCY_NUMBER">%s</xliff:g> не з\'яўляецца нумарам экстраннай службы."</string>
+    <string name="dial_emergency_error" msgid="825822413209026039">"Выклік немагчымы. <xliff:g id="NON_EMERGENCY_NUMBER">%s</xliff:g> не з’яўляецца нумарам экстраннай службы."</string>
     <string name="dial_emergency_empty_error" msgid="2785803395047793634">"Выклік немагчымы. Набраць нумар экстраннай службы."</string>
     <string name="dial_emergency_calling_not_available" msgid="6485846193794727823">"Экстранныя выклікі недаступныя"</string>
     <string name="pin_puk_system_user_only" msgid="1045147220686867922">"Толькі ўладальнік прылады можа ўводзіць PIN-код ці PUK-код."</string>
@@ -586,7 +586,7 @@
     <string name="onscreenShowDialpadText" msgid="658465753816164079">"Кнопкі набору"</string>
     <string name="onscreenMuteText" msgid="5470306116733843621">"Выключыць гук"</string>
     <string name="onscreenAddCallText" msgid="9075675082903611677">"Дадаць выклік"</string>
-    <string name="onscreenMergeCallsText" msgid="3692389519611225407">"Аб\'яднаць выклікі"</string>
+    <string name="onscreenMergeCallsText" msgid="3692389519611225407">"Аб’яднаць выклікі"</string>
     <string name="onscreenSwapCallsText" msgid="2682542150803377991">"Пераключыць"</string>
     <string name="onscreenManageCallsText" msgid="1162047856081836469">"Кіраваць выклікамі"</string>
     <string name="onscreenManageConferenceText" msgid="4700574060601755137">"Кірав. канферэнцыяй"</string>
@@ -682,7 +682,7 @@
     <string name="status_hint_label_wifi_call" msgid="942993035689809853">"Выклік праз Wi-Fi"</string>
     <string name="message_decode_error" msgid="1061856591500290887">"Памылка расшыфравання паведамлення."</string>
     <string name="callFailed_cdma_activation" msgid="5392057031552253550">"SIM-карта актывавала вашу службу і абнавіла функцыі роўмінгу вашага тэлефона."</string>
-    <string name="callFailed_cdma_call_limit" msgid="1074219746093031412">"Занадта шмат актыўных выклікаў. Скончыце ці аб\'яднайце існуючыя выклікі, перш чым рабіць новы выклік."</string>
+    <string name="callFailed_cdma_call_limit" msgid="1074219746093031412">"Занадта шмат актыўных выклікаў. Скончыце ці аб’яднайце існуючыя выклікі, перш чым рабіць новы выклік."</string>
     <string name="callFailed_imei_not_accepted" msgid="7257903653685147251">"Немагчыма падключыцца, устаўце сапраўдную SIM-карту."</string>
     <string name="callFailed_wifi_lost" msgid="1788036730589163141">"Страчана падключэнне да Wi-Fi. Выклік завершаны."</string>
     <string name="dialFailed_low_battery" msgid="6857904237423407056">"Немагчыма наладзіць злучэнне для відэавыкліку: нізкі зарад акумулятара."</string>
@@ -824,7 +824,7 @@
     <string name="callFailed_already_dialing" msgid="7250591188960691086">"Немагчыма зрабіць выклік, паколькі зараз ідзе выходны выклік."</string>
     <string name="callFailed_already_ringing" msgid="2376603543544289303">"Нельга зрабіць выклік, паколькі ёсць уваходны выклік без адказу. Адкажыце на ўваходны выклік або адхіліце яго, каб зрабіць новы."</string>
     <string name="callFailed_calling_disabled" msgid="5010992739401206283">"Немагчыма зрабіць выклік, паколькі выклікі адключаны ў сістэмных наладах ro.telephony.disable-call."</string>
-    <string name="callFailed_too_many_calls" msgid="2761754044990799580">"Немагчыма зрабіць новы выклік, бо ўжо выконваюцца два іншыя. Каб зрабіць новы выклік, завяршыце адзін з бягучых ці аб\'яднайце іх у канферэнц-выклік."</string>
+    <string name="callFailed_too_many_calls" msgid="2761754044990799580">"Немагчыма зрабіць новы выклік, бо ўжо выконваюцца два іншыя. Каб зрабіць новы выклік, завяршыце адзін з бягучых ці аб’яднайце іх у канферэнц-выклік."</string>
     <string name="supp_service_over_ut_precautions" msgid="2145018231396701311">"Уключыце перадачу мабільных даных для выкарыстання сэрвісу <xliff:g id="SUPP_SERVICE">%s</xliff:g>. Гэта можна зрабіць у наладах мабільнай сеткі."</string>
     <string name="supp_service_over_ut_precautions_roaming" msgid="670342104569972327">"Уключыце перадачу мабільных даных і інтэрнэт-роўмінг для выкарыстання сэрвісу <xliff:g id="SUPP_SERVICE">%s</xliff:g>. Гэта можна зрабіць у наладах мабільнай сеткі."</string>
     <string name="supp_service_over_ut_precautions_dual_sim" msgid="5166866975550910474">"Уключыце перадачу мабільных даных на SIM-карце <xliff:g id="SIM_NUMBER">%2$d</xliff:g> для выкарыстання сэрвісу <xliff:g id="SUPP_SERVICE">%1$s</xliff:g>. Гэта можна зрабіць у наладах мабільнай сеткі."</string>
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Зрабіць здымную eSIM-карту стандартнай"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Магутнасць радыёсігналу"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Мадэляванне знаходжання па-за сеткай (толькі ў зборцы для адладкі)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Прымусова прымяняць спадарожнікавы канал LTE (толькі для адладачнай зборкі)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Імітацыя рэжыму спадарожніка з SIM-картай ад аператара (толькі ў зборцы для адладкі)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Тэсціраванне рэальнага рэжыму спадарожнікавага падключэння eSOS (толькі ў зборцы для адладкі)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Тэсціраванне рэальнага няэкстраннага (non-eSOS) рэжыму спадарожнікавага падключэння (толькі ў зборцы для адладкі)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Тэсціраванне дэманстрацыйнага рэжыму спадарожнікавага падключэння eSOS (толькі ў зборцы для адладкі)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Праглядзець адрасную кнігу на SIM-карце"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Прагляд фіксаваных нумароў"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Паглядзець сэрвісныя нумары"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Абнавіць"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Абнавіць"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Уключыць/выключыць праверку DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Інфармацыя/налады пастаўшчыка"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"Падключэнне EN-DC даступнае (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Падключэнне DCNR абмежавана (NSA):"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index fb7264e36..538027960 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Задаване на електронната SIM карта с изваждащ се чип като основна"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Мощност на мобилното радио"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Симулиране на липса на услуга (само в компилацията за отстраняване на грешки)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Принудително използване на сателитен LTE канал (само в компилацията за отстраняване на грешки)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Симулиран сателитен режим от оператора (само в компилацията за отстраняване на грешки)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Тестване на режим на истински сателитен eSOS (само в компилацията за отстраняване на грешки)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Тестване на режим на истинска сателитна неспешна комуникация (само в компилацията за отстраняване на грешки)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Тестване на режим на демонстрация на сателитен eSOS (само в компилацията за отстраняване на грешки)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Преглед на указателя на SIM картата"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Преглед на номера за фиксирано набиране"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Преглед на номера за набиране на услуги"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMS център:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Актуализиране"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Опресняване"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Превключване на проверката на DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Информация/настройки, специфични за ОЕМ"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC е налице (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR е ограничено (NSA):"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 8f4709440..e4a02b34d 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -534,7 +534,7 @@
     <string name="notification_voicemail_title_count" msgid="2806950319222327082">"নতুন ভয়েসমেল (<xliff:g id="COUNT">%d</xliff:g>)"</string>
     <string name="notification_voicemail_text_format" msgid="5720947141702312537">"<xliff:g id="VOICEMAIL_NUMBER">%s</xliff:g> এ ডায়াল করুন"</string>
     <string name="notification_voicemail_no_vm_number" msgid="3423686009815186750">"ভয়েসমেল নম্বর অজানা"</string>
-    <string name="notification_network_selection_title" msgid="255595526707809121">"কোনো পরিষেবা নেই"</string>
+    <string name="notification_network_selection_title" msgid="255595526707809121">"কোনও পরিষেবা নেই"</string>
     <string name="notification_network_selection_text" msgid="553288408722427659">"বেছে নেওয়া নেটওয়ার্ক (<xliff:g id="OPERATOR_NAME">%s</xliff:g>) নেই"</string>
     <string name="incall_error_power_off" product="watch" msgid="7191184639454113633">"কল করতে মোবাইল নেটওয়ার্ক চালু করুন, বিমান মোড বা ব্যাটারি সেভার বন্ধ করুন৷"</string>
     <string name="incall_error_power_off" product="default" msgid="8131672264311208673">"কল করতে বিমান মোড বন্ধ করুন৷"</string>
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"সরিয়ে দেওয়া যায় এমন eSIM ডিফল্ট হিসেবে সেট করুন"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"মোবাইল রেডিওর গুণমান"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"আউট-অফ-সার্ভিস সিমুলেট করা (শুধুমাত্র ডিবাগ বিল্ডের জন্য)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ফোর্স ক্যাম্প স্যাটেলাইট এলটিই চ্যানেল (শুধুমাত্র ডিবাগ বিল্ড)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"নকল পরিষেবা প্রদানকারী উপগ্রহ মোড (শুধুমাত্র ডিবাগ বিল্ড)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"রিয়েল স্যাটেলাইট eSOS মোড পরীক্ষা করুন (শুধুমাত্র ডিবাগ বিল্ড)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"রিয়েল স্যাটেলাইট নন-ইএসওএস মোড পরীক্ষা করুন (শুধুমাত্র ডিবাগ বিল্ড)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ডেমো স্যাটেলাইট eSOS মোড পরীক্ষা করুন (শুধুমাত্র ডিবাগ বিল্ড)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"সিম অ্যাড্রেস বুক দেখুন"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"স্থায়ী ডায়াল নম্বরগুলি দেখুন"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"সার্ভিস ডায়াল নম্বরগুলি দেখুন"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"আপডেট করুন"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"রিফ্রেশ"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS চেক টগল করুন"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-নির্দিষ্ট তথ্য/সেটিংস"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"এন-ডিসি (EN-DC) উপলভ্য (এনএসএ) (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"ডিসিএনআর (DCNR) সীমাবদ্ধ (এনএসএ) (NSA):"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 2fd44d8bf..226ab1845 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Postavljanje uklonjive eSim kartice kao zadane"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Snaga mobilnog radija"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulacija ne radi (samo verzija za otklanjanje grešaka)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Satelitski LTE kanala za Force Camp (samo verzija za otklanjanje grešaka)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Lažni način rada operatera za slanje putem satelita (samo verzija za otklanjanje grešaka)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testiraj stvarni način rada satelitskog eSOS-a (samo verzija za otklanjanje grešaka)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testiraj stvarni način rada satelita koji nije eSOS (samo verzija za otklanjanje grešaka)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testiraj demo način rada satelitskog eSOS-a (samo verzija za otklanjanje grešaka)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Prikaži SIM adresar"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Prikaži brojeve fiksnog biranja"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Prikaži brojeve biranja usluga"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Ažuriraj"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Osvježi"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Uključi/isključi provjeru DNS-a"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-specifične informacije/postavke"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC dostupno (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR ograničeno (NSA):"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index e351f02bc..f4c55930d 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Defineix l\'eSIM extraïble com a opció predeterminada"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Potència del senyal mòbil"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simula que està fora de servei (només per a la compilació de depuració)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Força el canal LTE del satèl·lit de camp (només per a la compilació de depuració)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mode de satèl·lit d\'un operador de telefonia mòbil simulat (només per a la compilació de depuració)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Provar el mode eSOS de satèl·lit real (només per a la compilació de depuració)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Prova el mode no eSOS de satèl·lit real (només per a la compilació de depuració)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Provar el mode de demostració d\'eSOS de satèl·lit (només per a la compilació de depuració)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Mostra la llibreta d\'adreces de la SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Mostra els números de marcatge fix"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Mostra els números de marcatge de serveis"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Actualitza"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Actualitza"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Activa o desactiva la comprovació de DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Informació/configuració específica d\'OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC disponible (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR amb restriccions (NSA):"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 5b76b8fbc..a6a6209c7 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Nastavit vyjímatelnou eSIM jako výchozí"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Výkon mobilního přijímače"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulovat provoz mimo službu (pouze ladicí sestavení)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Kanál LTE Force Camp Satellite (jen ladicí sestavení)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulace satelitního režimu operátora (pouze ladicí sestavení)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Otestovat reálný režim nouzových zpráv přes satelit (pouze ladicí sestavení)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Otestovat reálný režim jiných než nouzových zpráv přes satelit (pouze ladicí sestavení)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Otestovat ukázkový režim nouzových zpráv přes satelit (pouze ladicí sestavení)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Zobrazit adresář SIM karty"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Zobrazit povolená telefonní čísla"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Zobrazit čísla volání služeb"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Aktualizovat"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Obnovit"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Přepnout kontrolu DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Informace a nastavení specifické pro výrobce OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC k dispozici (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR – omezeno (NSA):"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index d73bc19a0..2f4ede6c7 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Konfigurer eSIM, der kan fjernes, som standard"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobilsendestyrke"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulering af enhed, der er ude af drift (kun i fejlretningsbuild)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Gennemtving Camp Satellite LTE-kanal (kun fejlretningsbuild)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Test af satellittilstand via mobilselskab (kun fejlretningsbuild)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test af virkelig eSOS-satellittilstand (kun fejlretningsbuild)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test af virkelig satellittilstand, der ikke er eSOS (kun fejlretningsbuild)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test af demo for eSOS-satellittilstand (kun fejlretningsbuild)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Vis adressebog på SIM-kortet"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Vis numre til begrænset opkald"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Vis tjenestens faste opkaldsnumre"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Opdater"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Opdater"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Skift DNS-kontrol"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-specifikke oplysninger/indstillinger"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"Tilgængelig for EN-DC (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Begrænset til DCNR (NSA):"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 9c50dd76d..24c72e3b1 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Wechsel-eSIM als Standard festlegen"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobilfunkstärke"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"„Außer Betrieb“ simulieren (nur Debug-Build)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"LTE-Kanal für Satelliten-Camp erzwingen (nur Debug-Build)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Vom Mobilfunkanbieter simulierter Satellitenmodus (nur Debug-Build)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"eSOS-Modus mit echtem Satelliten testen (nur Debug-Build)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"non-eSOS-Modus mit echtem Satelliten testen (nur Debug-Build)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"eSOS-Modus mit Demo-Satelliten testen (nur Debug-Build)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM-Adressbuch anzeigen"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Rufnummernbeschränkung ansehen"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Servicerufnummern anzeigen"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Update"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Aktualisieren"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS-Überprüfung ein-/ausschalten"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-spezifische Infos/Einstellungen"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC verfügbar (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR eingeschränkt (NSA):"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index cf3330680..75d47a9e2 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Ορισμός αφαιρούμενης eSIM ως προεπιλεγμένης"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Ισχύς πομπού κινητής τηλεφωνίας"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Η προσομοίωση δεν λειτουργεί (μόνο έκδοση εντοπισμού σφαλμάτων)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Επιβολή καναλιού Camp Satellite LTE (μόνο έκδοση εντοπισμού σφαλμάτων)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Εικονική λειτουργία δορυφόρου εταιρείας κινητής τηλεφωνίας (μόνο έκδοση εντοπισμού σφαλμάτων)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Δοκιμή πραγματικής δορυφορικής λειτουργίας eSOS (μόνο έκδοση εντοπισμού σφαλμάτων)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Δοκιμή πραγματικής δορυφορικής λειτουργίας εκτός eSOS (μόνο έκδοση εντοπισμού σφαλμάτων)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Έλεγχος δοκιμαστικής δορυφορικής λειτουργίας eSOS (μόνο έκδοση εντοπισμού σφαλμάτων)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Προβολή βιβλίου διευθύνσεων κάρτας SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Προβολή προκαθορισμένων αριθμών κλήσης"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Προβολή αριθμών κλήσης υπηρεσίας"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Ενημέρωση"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Ανανέωση"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Εναλλαγή ελέγχου DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Πληροφορίες/ρυθμίσεις για OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC διαθέσιμο (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR με περιορισμούς (NSA):"</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 13cd54b2c..75b50b117 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Set removable eSIM as default"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobile radio power"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulate out of service (debug build only)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (debug build only)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock operator satellite mode (debug build only)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test real satellite eSOS mode (debug build only)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test real satellite non-eSOS mode (debug build only)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test demo satellite eSOS mode (debug build only)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"View SIM address book"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"View fixed dialling numbers"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"View service dialling numbers"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Update"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Refresh"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Toggle DNS check"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-specific info/settings"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC available (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR restricted (NSA):"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 97417780e..d1edf820f 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Set Removable eSIM as Default"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobile Radio Power"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulate Out of Service (Debug Build only)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (Debug Build only)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock Carrier Satellite Mode (Debug Build only)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test real satellite eSOS mode (Debug Build only)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test real satellite non-eSOS mode (Debug Build only)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test demo satellite eSOS mode (Debug Build only)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"View SIM Address Book"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"View Fixed Dialing Numbers"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"View Service Dialing Numbers"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Update"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Refresh"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Toggle DNS Check"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-specific Info/Settings"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC Available (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR Restricted (NSA):"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 13cd54b2c..75b50b117 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Set removable eSIM as default"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobile radio power"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulate out of service (debug build only)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (debug build only)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock operator satellite mode (debug build only)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test real satellite eSOS mode (debug build only)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test real satellite non-eSOS mode (debug build only)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test demo satellite eSOS mode (debug build only)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"View SIM address book"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"View fixed dialling numbers"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"View service dialling numbers"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Update"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Refresh"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Toggle DNS check"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-specific info/settings"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC available (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR restricted (NSA):"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index 13cd54b2c..75b50b117 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Set removable eSIM as default"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobile radio power"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulate out of service (debug build only)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (debug build only)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock operator satellite mode (debug build only)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test real satellite eSOS mode (debug build only)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test real satellite non-eSOS mode (debug build only)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test demo satellite eSOS mode (debug build only)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"View SIM address book"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"View fixed dialling numbers"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"View service dialling numbers"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Update"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Refresh"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Toggle DNS check"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-specific info/settings"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC available (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR restricted (NSA):"</string>
diff --git a/res/values-en-rXC/strings.xml b/res/values-en-rXC/strings.xml
index f805a1e36..624727b7d 100644
--- a/res/values-en-rXC/strings.xml
+++ b/res/values-en-rXC/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‏‎‏‏‏‎‎‎‎‏‎‎‎‏‏‏‏‎‎‎‏‎‏‏‎‏‎‎‏‎‎‏‎‎‏‏‏‎‏‏‏‏‎‏‎‎‎‎‏‎‏‎‎‎‏‎‎‎‎‎‎‏‎Set Removable eSIM as Default‎‏‎‎‏‎"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‏‏‏‎‏‎‎‎‏‏‎‎‏‏‏‏‎‎‎‎‏‎‎‎‎‎‎‏‎‎‏‏‎‎‎‎‏‏‏‏‎‏‎‎‏‎‏‎‏‎‎‏‏‎‎‎‏‎‎‎‏‏‎Mobile Radio Power‎‏‎‎‏‎"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‏‎‏‏‎‎‎‎‎‏‎‏‎‎‎‏‎‎‎‏‎‏‎‎‎‏‎‏‎‎‏‏‏‎‏‎‎‎‎‎‏‏‎‎‎‎‏‎‏‎‏‏‏‎‏‎‎‎‏‎‎‏‎Simulate Out of Service (Debug Build only)‎‏‎‎‏‎"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‎‏‏‏‎‎‎‎‎‏‏‎‎‏‎‎‏‎‎‎‏‏‏‏‏‎‏‎‎‏‎‎‎‏‎‏‏‏‎‎‎‏‏‎‎‎‏‏‎‎‎‏‏‎‎‏‏‎‎‏‎‎‎Force Camp Satellite LTE Channel (Debug Build only)‎‏‎‎‏‎"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‎‎‎‎‏‎‏‎‎‎‏‏‏‏‏‏‏‎‎‎‎‏‏‎‏‎‏‎‏‏‎‎‎‎‎‏‏‏‏‎‏‏‏‏‎‎‎‎‎‏‏‎‎‏‎‏‏‏‎‎‎‏‎Mock Carrier Satellite Mode (Debug Build only)‎‏‎‎‏‎"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‏‎‎‏‎‎‏‏‏‏‎‏‎‏‎‏‎‎‎‎‏‎‏‏‎‎‏‏‏‎‎‎‎‏‏‏‏‎‎‏‎‎‏‏‎‏‎‎‎‏‎‏‎‏‎‎‎‏‎‎‎‏‎Test real satellite eSOS mode (Debug Build only)‎‏‎‎‏‎"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‎‎‏‏‏‏‏‎‎‏‎‏‎‏‏‏‏‎‎‏‎‏‎‏‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‎‏‏‏‎‏‏‏‎‎‏‎‏‏‎‏‏‎‎‎Test real satellite non-eSOS mode (Debug Build only)‎‏‎‎‏‎"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‎‏‎‏‎‎‎‏‏‎‏‎‎‏‏‎‏‏‎‏‎‎‏‏‏‏‏‎‏‎‎‏‏‏‎‎‏‏‎‏‏‎‏‎‏‎‎‏‏‎‏‎‎‏‎‎‏‏‎‎‎‏‎‎Test demo satellite eSOS mode (Debug Build only)‎‏‎‎‏‎"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‎‏‏‏‏‏‎‏‏‏‎‏‎‎‏‎‎‎‏‎‏‏‎‏‏‏‏‎‎‏‎‏‎‎‎‏‎‏‏‏‏‎‎‏‏‏‎‎‎‏‏‏‎‎‏‏‏‏‎‎‏‏‎‎View SIM Address Book‎‏‎‎‏‎"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‎‏‏‏‎‎‏‏‎‏‎‎‎‏‎‏‎‏‏‎‎‏‏‏‏‎‎‏‎‏‎‏‎‏‏‏‏‎‏‏‏‏‏‎‏‎‎‏‏‎‏‏‏‏‎‏‏‏‏‏‏‎‏‎View Fixed Dialing Numbers‎‏‎‎‏‎"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‎‏‎‎‏‎‎‎‏‎‎‎‏‎‎‏‏‎‎‎‏‏‎‎‎‏‎‏‏‎‏‏‏‏‏‏‎‎‎‎‎‏‏‏‏‏‎‎‏‎‏‎‏‎‏‎‎‎‎‏‎‏‎‎View Service Dialing Numbers‎‏‎‎‏‎"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‎‏‏‎‏‎‎‎‎‎‎‏‎‏‎‎‏‏‎‏‎‏‎‏‏‎‎‏‏‎‏‏‏‏‏‏‏‏‏‎‏‏‏‎‏‎‎‏‎‏‎‎‏‎‏‎‏‏‎‎‎‏‏‎SMSC:‎‏‎‎‏‎"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‎‎‎‏‏‏‎‏‎‏‏‏‎‎‎‎‎‎‏‎‏‎‎‏‎‏‏‎‎‏‏‏‏‏‏‎‎‏‎‎‎‎‏‏‏‎‏‎‎‏‏‏‏‎‎‏‏‎‏‎‎‏‎Update‎‏‎‎‏‎"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‏‏‎‏‎‎‏‎‏‏‎‏‏‎‎‎‎‎‏‏‎‏‎‎‎‏‎‎‎‏‎‎‏‎‎‏‎‏‎‏‎‎‎‎‎‏‎‎‎‎‏‎‏‎‎‏‎‏‎‎‎‎‎Refresh‎‏‎‎‏‎"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‎‏‏‎‎‏‏‎‏‎‏‏‎‎‎‏‏‎‎‎‎‏‏‎‎‎‎‏‏‏‏‎‎‏‏‏‏‏‏‎‏‏‏‎‏‎‏‏‏‏‎‏‏‎‏‎‏‎‏‎‏‏‎‎Toggle DNS Check‎‏‎‎‏‎"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‎‏‎‏‎‎‎‎‏‏‏‎‎‎‏‎‎‏‏‎‎‏‏‏‏‏‎‎‎‎‎‏‏‏‏‎‎‏‎‏‎‎‎‎‏‏‎‎‏‎‎‎‎‏‎‎‎‎‏‎‎‎‎‎OEM-specific Info/Settings‎‏‎‎‏‎"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‎‏‎‏‎‎‏‎‏‏‎‏‎‎‎‎‏‏‏‏‎‎‎‎‏‏‎‎‎‎‎‏‏‏‎‎‏‎‎‏‎‏‎‎‏‎‏‏‏‏‏‏‎‏‎‏‏‎‎‎‎‏‏‎EN-DC Available (NSA):‎‏‎‎‏‎"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‏‎‎‎‏‏‎‎‏‏‎‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‏‏‏‏‎‎‎‏‏‎‎‎‏‎‏‎‏‎‎‎‏‎‏‎‎‏‏‏‏‎‎‏‏‎‏‎DCNR Restricted (NSA):‎‏‎‎‏‎"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 27a41902e..4b06be3f3 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Establecer eSIM extraíble como predeterminada"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Potencia de la señal móvil"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simular fuera de servicio (solo para la compilación de depuración)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Canal LTE de satélite del campamento de la fuerza (solo compilación de depuración)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Modo Satélite del operador de prueba (solo en la compilación de depuración)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Prueba el modo eSOS de satélite real (solo en la compilación de depuración)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Prueba el modo que no es eSOS por satélite real (solo en la compilación de depuración)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Prueba el modo de demostración de eSOS de satélite (solo en la compilación de depuración)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Ver libreta de direcciones de SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Ver números de marcación fija"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Ver números de marcación de servicio"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Actualizar"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Actualizar"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Activar o desactivar la comprobación de DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Configuración/Datos específicos del OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC disponible (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR restringido (NSA):"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index b1f0611f3..bccc7cd19 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Establecer eSIM extraíble como predeterminada"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Potencia de la señal móvil"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simular fuera del servicio (solo versión de depuración)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forzar canal LTE de satélite de campamento (solo versión de depuración)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulación del modo Satélite de operador (solo versión de depuración)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Probar el modo eSOS por satélite real (solo versión de depuración)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Probar el modo no eSOS por satélite real (solo versión de depuración)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Probar el modo eSOS por satélite de demostración (solo versión de depuración)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Ver libreta de direcciones de tarjeta SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Ver números de marcación fija"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Ver números de marcación de servicio"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Actualizar"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Actualizar"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Activar o desactivar comprobación de DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Ajustes o información específica de OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC disponible (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR restringido (NSA):"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 1fc277f0d..56fc00a5d 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Eemaldatava eSIM-i määramine vaikevalikuks"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobiiliraadio toide"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simuleerimine ei tööta (ainult silumisjärgus)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Camp Satellite LTE kanali (ainult silumisjärgus) sundaktiveerimine"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simuleeritud operaatori satelliidirežiim (ainult silumisjärgus)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Režiimi eSOS katsetamine reaalse satelliitsidesüsteemi puhul (ainult silumisjärk)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Režiimi mitte-eSOS katsetamine reaalse satelliitsidesüsteemi puhul (ainult silumisjärk)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Režiimi eSOS katsetamine demo satelliitsidesüsteemi puhul (ainult silumisjärk)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Kuva SIM-i aadressiraamat"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Kuva fikseeritud valimisnumbrid"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Kuva teenuse valimise numbrid"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Värskendamine"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Värskendamine"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS-i kontrolli sisse- või väljalülitamine"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-i teave/seaded"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC on saadaval (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR on piiratud (NSA):"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 0f889d1eb..452df67ad 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Ezarri eSIM aldagarria lehenetsi gisa"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Sare mugikor bidezko irratiaren indarra"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulatu gailua ez dabilela (arazketa-konpilazioa soilik)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE kanala (arazte-konpilazioa bakarrik)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulatu operadorearen satelite modua (arazketa-konpilazioa soilik)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Probatu satelite bidezko SOS larrialdien modua (arazketa-konpilazioa soilik)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Probatu satelite bidezko SOS larrialdien modua ez dena (arazketa-konpilazioa soilik)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Probatu satelite bidezko SOS larrialdien moduaren demo-bertsioa (arazketa-konpilazioa soilik)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Ikusi SIMeko kontaktuak"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Ikusi markatze finkoko zenbakiak"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Ikusi zerbitzuaren markatze-zenbakiak"</string>
@@ -869,7 +872,7 @@
     <string name="radioInfo_data_disconnected" msgid="8085447971880814541">"Deskonektatuta"</string>
     <string name="radioInfo_data_connecting" msgid="925092271092152472">"Konektatzen"</string>
     <string name="radioInfo_data_connected" msgid="7637335645634239508">"Konektatuta"</string>
-    <string name="radioInfo_data_suspended" msgid="8695262782642002785">"Aldi baterako itxitakoak"</string>
+    <string name="radioInfo_data_suspended" msgid="8695262782642002785">"Aldi baterako etenda"</string>
     <string name="radioInfo_unknown" msgid="5401423738500672850">"Ezezaguna"</string>
     <string name="radioInfo_imei_primary" msgid="5948747378637224400">"Nagusia"</string>
     <string name="radioInfo_display_packets" msgid="6794302192441084157">"pkts"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Eguneratu"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Freskatu"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Aldatu DNS egiaztapenaren egoera"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Jatorrizko fabrikatzailearen berariazko informazioa edota ezarpenak"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC erabilgarri (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR murriztua (NSA):"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 60abd7f50..4aa57e894 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"تنظیم سیم‌کارت داخلی جداشدنی به‌عنوان پیش‌فرض"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"توان رادیوی تلفن همراه"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"شبیه‌سازی از کار افتادن (فقط ساخت اشکال‌زدایی)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"‏اجباری کردن کانال Camp Satellite LTE (فقط ساخت اشکال‌زدایی)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"حالت ماهواره‌ای شرکت مخابراتی ساختگی (فقط ساخت اشکال‌زدایی)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"آزمایش کردن حالت واقعی درخواست کمک اضطراری ماهواره‌ای (فقط ساخت اشکال‌زدایی)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"آزمایش کردن حالت واقعی درخواست کمک غیراضطراری ماهواره‌ای (فقط ساخت اشکال‌زدایی)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"آزمایش کردن نسخه نمایشی درخواست کمک اضطراری ماهواره‌ای (فقط ساخت اشکال‌زدایی)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"مشاهده دفترچه نشانی سیم‌کارت"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"مشاهده شماره‌های شماره‌گیری ثابت"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"مشاهده شماره‌های شماره‌گیری سرویس"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"به‌روزرسانی"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"بازآوری"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"‏تغییر وضعیت علامت DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"‏تنظیمات/اطلاعات خاص OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"‏EN-DC دردسترس است (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"‏DCNR محدود شده است (NSA):"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index d34748871..3a2dc6985 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Aseta poistettava eSIM oletukseksi"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobiiliradion voimakkuus"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Epäkunnossa-simulaatio (vain virheenkorjauksen koontiversio)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Pakota Camp Satellite LTE ‐kanava (vain virheenkorjauksen koontiversio)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Operaattorin satelliittitilaesimerkki (vain virheenkorjauksen koontiversio)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testaa oikeaa Satellite eSOS ‑tilaa (vain virheenkorjauksen koontiversio)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testaa oikeaa Satellite non-eSOS ‑tilaa (vain virheenkorjauksen koontiversio)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testaa Satellite eSOS ‑demotilaa (vain virheenkorjauksen koontiversio)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Näytä SIM-kortin osoitekirja"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Näytä sallitut numerot"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Näytä sallitut palvelunumerot"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Päivitä"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Päivitä"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Ota DNS-tarkistus käyttöön tai poista se käytöstä"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-kohtaiset tiedot/asetukset"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC saatavana (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR rajoitettu (NSA):"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 03c0e56c3..ff3247378 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -582,7 +582,7 @@
     <string name="description_concat_format" msgid="2014471565101724088">"%1$s, %2$s"</string>
     <string name="dialerKeyboardHintText" msgid="1115266533703764049">"Utilisez le clavier pour composer un numéro."</string>
     <string name="onscreenHoldText" msgid="4025348842151665191">"Attente"</string>
-    <string name="onscreenEndCallText" msgid="6138725377654842757">"Terminé"</string>
+    <string name="onscreenEndCallText" msgid="6138725377654842757">"Terminer"</string>
     <string name="onscreenShowDialpadText" msgid="658465753816164079">"Clavier numérique"</string>
     <string name="onscreenMuteText" msgid="5470306116733843621">"Couper le son"</string>
     <string name="onscreenAddCallText" msgid="9075675082903611677">"Autre appel"</string>
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Définir la carte eSIM amovible comme carte SIM par défaut"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Alimentation de radio cellulaire"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulation de l\'appareil hors service (version de débogage uniquement)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forcer le canal LTE satellite du camp (version de débogage uniquement)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mode Satellite de l\'opérateur simulé (version de débogage uniquement)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Tester le mode eSOS par satellite réel (version de débogage uniquement)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Tester le mode non-eSOS par satellite réel (version de débogage uniquement)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Tester eSOS par satellite en mode Démo (version de débogage uniquement)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Afficher le carnet d\'adresses de la carte SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Afficher les numéros d\'appel fixes"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Afficher les numéros de service"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC :"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Mettre à jour"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Actualiser"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Basculer la vérification DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Informations/paramètres OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"Disponibilité EN-DC (NSA) :"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Restriction DCNR (NSA) :"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 8fac28293..22a69bb62 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -582,7 +582,7 @@
     <string name="description_concat_format" msgid="2014471565101724088">"%1$s, %2$s"</string>
     <string name="dialerKeyboardHintText" msgid="1115266533703764049">"Utilisez le clavier pour composer un numéro."</string>
     <string name="onscreenHoldText" msgid="4025348842151665191">"En attente"</string>
-    <string name="onscreenEndCallText" msgid="6138725377654842757">"Raccrocher"</string>
+    <string name="onscreenEndCallText" msgid="6138725377654842757">"Terminer"</string>
     <string name="onscreenShowDialpadText" msgid="658465753816164079">"Clavier"</string>
     <string name="onscreenMuteText" msgid="5470306116733843621">"Silencieux"</string>
     <string name="onscreenAddCallText" msgid="9075675082903611677">"Autre appel"</string>
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Définir l\'eSIM amovible comme SIM par défaut"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Alimentation radio mobile"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simuler une panne (version de débogage uniquement)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forcer le canal LTE satellite du camp (version de débogage uniquement)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simuler le mode Satellite de l\'opérateur (version de débogage uniquement)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Tester le SOS par satellite en mode réel (version de débogage uniquement)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Tester le mode non-eSOS par satellite réel (version de débogage uniquement)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Tester eSOS par satellite en mode démo (version de débogage uniquement)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Afficher le carnet d\'adresses de la carte SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Afficher les numéros autorisés"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Afficher les numéros de service"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC :"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Mise à jour"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Actualiser"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Activer/Désactiver le contrôle DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Infos/paramètres OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"Accès EN-DC disponible (NSA) :"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Limitation DCNR (NSA) :"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 7d680f735..3d0bc84ae 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Establecer eSIM extraíble como predeterminada"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Alimentación da radio móbil"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simular Fóra de servizo (só compilación de depuración)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forzar o canal LTE do satélite do campamento (só compilación de depuración)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simular o modo Satélite do operador (só compilación de depuración)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Probar o modo real eSOS por satélite (só compilación de depuración)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Probar o modo real non eSOS por satélite (só compilación de depuración)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Probar o modo de demostración de eSOS por satélite (só compilación de depuración)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Ver axenda de enderezos da SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Ver números de marcación fixa"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Ver números de marcación de servizo"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Actualizar"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Actualizar"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Alternar comprobación de DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Información ou configuración específica de OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC dispoñible (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR restrinxido (NSA):"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 19d127d34..60b9b2432 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -25,13 +25,13 @@
     <string name="private_num" msgid="4487990167889159992">"ખાનગી નંબર"</string>
     <string name="payphone" msgid="7936735771836716941">"પેફોન"</string>
     <string name="onHold" msgid="6132725550015899006">"હોલ્ડ પર"</string>
-    <string name="carrier_mmi_msg_title" msgid="6050165242447507034">"<xliff:g id="MMICARRIER">%s</xliff:g> સંદેશ"</string>
-    <string name="default_carrier_mmi_msg_title" msgid="7754317179938537213">"કૅરિઅરનો સંદેશ"</string>
+    <string name="carrier_mmi_msg_title" msgid="6050165242447507034">"<xliff:g id="MMICARRIER">%s</xliff:g> મેસેજ"</string>
+    <string name="default_carrier_mmi_msg_title" msgid="7754317179938537213">"કૅરિઅર મેસેજ"</string>
     <string name="mmiStarted" msgid="9212975136944568623">"MMI કોડ પ્રારંભ કર્યો"</string>
     <string name="ussdRunning" msgid="1163586813106772717">"USSD કોડ ચાલે છે…"</string>
     <string name="mmiCancelled" msgid="5339191899200678272">"MMI કોડ રદ કર્યો"</string>
     <string name="cancel" msgid="8984206397635155197">"રદ કરો"</string>
-    <string name="enter_input" msgid="6193628663039958990">"USSD સંદેશ <xliff:g id="MIN_LEN">%1$d</xliff:g> અને <xliff:g id="MAX_LEN">%2$d</xliff:g> વર્ણ વચ્ચેનો હોવો આવશ્યક છે. કૃપા કરીને ફરી પ્રયાસ કરો."</string>
+    <string name="enter_input" msgid="6193628663039958990">"USSD મેસેજ <xliff:g id="MIN_LEN">%1$d</xliff:g> અને <xliff:g id="MAX_LEN">%2$d</xliff:g> અક્ષરો વચ્ચે હોવો આવશ્યક છે. કૃપા કરીને ફરી પ્રયાસ કરો."</string>
     <string name="manageConferenceLabel" msgid="8415044818156353233">"કોન્ફરન્સ કૉલ સંચાલિત કરો"</string>
     <string name="ok" msgid="7818974223666140165">"ઓકે"</string>
     <string name="audio_mode_speaker" msgid="243689733219312360">"સ્પીકર્સ"</string>
@@ -173,7 +173,7 @@
     <string name="vm_change_pin_error_mismatch" msgid="5364847280026257331">"જૂનો PIN મેળ ખાતો નથી."</string>
     <string name="vm_change_pin_error_invalid" msgid="5230002671175580674">"નવો PIN અમાન્ય અક્ષરો ધરાવે છે."</string>
     <string name="vm_change_pin_error_system_error" msgid="9116483527909681791">"PIN બદલવામાં અસમર્થ"</string>
-    <string name="vvm_unsupported_message_format" msgid="4206402558577739713">"અસમર્થિત સંદેશ પ્રકાર, સાંભળવા માટે <xliff:g id="NUMBER">%s</xliff:g> પર કૉલ કરો."</string>
+    <string name="vvm_unsupported_message_format" msgid="4206402558577739713">"અનસપોર્ટેડ મેસેજ પ્રકાર, સાંભળવા માટે <xliff:g id="NUMBER">%s</xliff:g> પર કૉલ કરો."</string>
     <string name="network_settings_title" msgid="7560807107123171541">"મોબાઇલ નેટવર્ક"</string>
     <string name="label_available" msgid="1316084116670821258">"ઉપલબ્ધ નેટવર્ક્સ"</string>
     <string name="load_networks_progress" msgid="4051433047717401683">"શોધી રહ્યું છે..."</string>
@@ -548,7 +548,7 @@
     <string name="incall_error_out_of_service_wfc_2g_user" msgid="8218768986365299663">"મોબાઇલ નેટવર્ક ઉપલબ્ધ નથી.\n\nકોઈ કૉલ કરવા માટે, વાયરલેસ નેટવર્કથી કનેક્ટ કરો.\n\nઆ ડિવાઇસ પર 2G સેવા બંધ છે, જે તમારી કનેક્ટિવિટીને અસર કરી શકે છે. સેટિંગમાં જાઓ અને આ સેવાને ચાલુ રાખવા માટે \'2Gને મંજૂરી આપો\' ચાલુ કરો."</string>
     <string name="incall_error_no_phone_number_supplied" msgid="8680831089508851894">"કૉલ કરવા માટે, માન્ય નંબર દાખલ કરો."</string>
     <string name="incall_error_call_failed" msgid="393508653582682539">"કૉલ નિષ્ફળ થયો."</string>
-    <string name="incall_error_cannot_add_call" msgid="5425764862628655443">"આ સમયે કૉલ ઉમેરી શકાતો નથી. તમે એક સંદેશ મોકલીને સંપર્ક કરવાનો પ્રયાસ કરી શકો છો."</string>
+    <string name="incall_error_cannot_add_call" msgid="5425764862628655443">"આ સમયે કૉલ ઉમેરી શકાતો નથી. તમે એક મેસેજ મોકલીને સંપર્ક કરવાનો પ્રયાસ કરી શકો છો."</string>
     <string name="incall_error_supp_service_unknown" msgid="8751177117194592623">"સેવા સમર્થિત નથી"</string>
     <string name="incall_error_supp_service_switch" msgid="5272822448189448479">"કૉલ્સ સ્વિચ કરી શકાતા નથી."</string>
     <string name="incall_error_supp_service_resume" msgid="1276861499306817035">"કૉલ ફરી શરૂ કરી શકતા નથી."</string>
@@ -601,8 +601,8 @@
     <string name="hac_mode_title" msgid="4127986689621125468">"સાંભળવામાં સહાયતા"</string>
     <string name="hac_mode_summary" msgid="7774989500136009881">"સાંભળવામાં સહાયતા સુસંગતતા ચાલુ કરો"</string>
     <string name="rtt_mode_title" msgid="3075948111362818043">"રિઅલ-ટાઇમ ટેક્સ્ટ(RTT) કૉલ"</string>
-    <string name="rtt_mode_summary" msgid="8631541375609989562">"વૉઇસ કૉલ અંતર્ગત સંદેશ મોકલવાની મંજૂરી આપો"</string>
-    <string name="rtt_mode_more_information" msgid="587500128658756318">"RTT બહેરા, સાંભળવા અને બોલવામાં મુશ્કેલી પડતી હોય અથવા વૉઇસ કરતાં પણ વધુ કંઈકની જરૂર હોય એવા કૉલરની સહાય કરે છે.&lt;br&gt; &lt;a href=<xliff:g id="URL">http://support.google.com/mobile?p=telephony_rtt</xliff:g>&gt;વધુ જાણો&lt;/a&gt;\n       &lt;br&gt;&lt;br&gt; - RTT કૉલને સંદેશ ટ્રાન્સક્રિપ્ટ તરીકે સાચવવામાં આવે છે\n       &lt;br&gt; - RTT વીડિઓ કૉલ માટે ઉપલબ્ધ નથી"</string>
+    <string name="rtt_mode_summary" msgid="8631541375609989562">"વૉઇસ કૉલ અંતર્ગત મેસેજ મોકલવાની મંજૂરી આપો"</string>
+    <string name="rtt_mode_more_information" msgid="587500128658756318">"RTT બહેરા, સાંભળવા અને બોલવામાં મુશ્કેલી પડતી હોય અથવા વૉઇસ કરતાં પણ વધુ કંઈકની જરૂર હોય એવા કૉલરની સહાય કરે છે.&lt;br&gt; &lt;a href=<xliff:g id="URL">http://support.google.com/mobile?p=telephony_rtt</xliff:g>&gt;વધુ જાણો&lt;/a&gt;\n       &lt;br&gt;&lt;br&gt; - RTT કૉલને મેસેજ ટ્રાન્સક્રિપ્ટ તરીકે સાચવવામાં આવે છે\n       &lt;br&gt; - RTT વીડિયો કૉલ માટે ઉપલબ્ધ નથી"</string>
     <string name="no_rtt_when_roaming" msgid="5268008247378355389">"નોંધ: રોમિંગ વખતે RTT ઉપલબ્ધ નથી"</string>
   <string-array name="tty_mode_entries">
     <item msgid="3238070884803849303">"TTY બંધ"</item>
@@ -616,8 +616,8 @@
     <item msgid="2271798469250155310">"સામાન્ય"</item>
     <item msgid="6044210222666533564">"લાંબુ"</item>
   </string-array>
-    <string name="network_info_message" msgid="7599413947016532355">"નેટવર્ક સંદેશ"</string>
-    <string name="network_error_message" msgid="4271579424089326618">"ભૂલ સંદેશ"</string>
+    <string name="network_info_message" msgid="7599413947016532355">"નેટવર્ક મેસેજ"</string>
+    <string name="network_error_message" msgid="4271579424089326618">"ભૂલ મેસેજ"</string>
     <string name="ota_title_activate" msgid="4049645324841263423">"તમારા ફોનને સક્રિય કરો"</string>
     <string name="ota_touch_activate" msgid="838764494319694754">"તમારી ફોન સેવાને સક્રિય કરવા માટે એક વિશિષ્ટ કૉલની જરૂર છે. \n\n\"સક્રિય કરો\" દબાવ્યાં પછી, તમારા ફોનને સક્રિય કરવા માટે પ્રદાન કરવામાં આવેલ સૂચનાઓને અનુસરો."</string>
     <string name="ota_hfa_activation_title" msgid="3300556778212729671">"સક્રિય કરી રહ્યું છે…"</string>
@@ -680,7 +680,7 @@
     <string name="accessibility_settings_activity_title" msgid="7883415189273700298">"ઍક્સેસિબિલિટી"</string>
     <string name="status_hint_label_incoming_wifi_call" msgid="2606052595898044071">"આમના તરફથી Wi-Fi કૉલ"</string>
     <string name="status_hint_label_wifi_call" msgid="942993035689809853">"Wi-Fi કૉલ"</string>
-    <string name="message_decode_error" msgid="1061856591500290887">"સંદેશ ડીકોડિંગ કરતી વખતે ભૂલ આવી હતી."</string>
+    <string name="message_decode_error" msgid="1061856591500290887">"મેસેજ ડિકોડિંગ કરતી વખતે ભૂલ આવી હતી."</string>
     <string name="callFailed_cdma_activation" msgid="5392057031552253550">"એક SIM કાર્ડ એ તમારી સેવા સક્રિય કરી છે અને તમારા ફોનની રોમિંગ ક્ષમતાઓને અપડેટ કરી છે."</string>
     <string name="callFailed_cdma_call_limit" msgid="1074219746093031412">"અહીં ઘણા બધા સક્રિય કૉલ્સ છે. કૃપા કરીને એક નવો કૉલ કરવા પહેલાં અસ્તિત્વમાંના કૉલ્સને સમાપ્ત કરો અથવા મર્જ કરો."</string>
     <string name="callFailed_imei_not_accepted" msgid="7257903653685147251">"કનેક્ટ કરવામાં અસમર્થ, કૃપા કરીને એક માન્ય SIM કાર્ડ દાખલ કરો."</string>
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"કાઢી નાખી શકાય એવા ઇ-સિમ કાર્ડને ડિફૉલ્ટ તરીકે સેટ કરો"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"મોબાઇલ રેડિયો પાવર"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\'સેવા ઉપલબ્ધ નથી\' મોડ સિમ્યુલેટ કરો (માત્ર ડિબગ બિલ્ડ માટે)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ફોર્સ કેમ્પ સૅટલાઇટ LTE ચૅનલ (માત્ર ડિબગ માટે બનાવવામાં આવેલી)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"મૉક કૅરિઅર સૅટલાઇટ મોડ (માત્ર ડિબગ બિલ્ડ માટે)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"રિઅલ સૅટલાઇટ eSOS મોડનું પરિક્ષણ કરો (માત્ર ડિબગ બિલ્ડ માટે)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"રિઅલ સૅટલાઇટ નૉન-eSOS મોડનું પરિક્ષણ કરો (માત્ર ડિબગ બિલ્ડ માટે)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ડેમો સૅટલાઇટ eSOS મોડનું પરીક્ષણ કરો (માત્ર ડિબગ બિલ્ડ માટે)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"સિમમાં સરનામા પુસ્તિકા જુઓ"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"ફિક્સ્ડ ડાયલિંગ નંબર જુઓ"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"સર્વિસ ડાયલિંગ નંબર જુઓ"</string>
@@ -896,7 +899,7 @@
     <string name="radio_info_signal_strength_label" msgid="5545444702102543260">"સિગ્નલની પ્રબળતા:"</string>
     <string name="radio_info_call_status_label" msgid="7693575431923095487">"વૉઇસ કૉલનું સ્ટેટસ:"</string>
     <string name="radio_info_ppp_sent_label" msgid="6542208429356199695">"ડેટા મોકલ્યો:"</string>
-    <string name="radio_info_message_waiting_label" msgid="1886549432566952078">"સંદેશ ઉપલબ્ધ છે:"</string>
+    <string name="radio_info_message_waiting_label" msgid="1886549432566952078">"મેસેજ ઉપલબ્ધ છે:"</string>
     <string name="radio_info_phone_number_label" msgid="2533852539562512203">"ફોન નંબર:"</string>
     <string name="radio_info_voice_network_type_label" msgid="2395347336419593265">"વૉઇસ નેટવર્ક પ્રકાર:"</string>
     <string name="radio_info_data_network_type_label" msgid="8886597029237501929">"ડેટા નેટવર્કનો પ્રકાર:"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"અપડેટ કરો"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"રિફ્રેશ કરો"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS તપાસ ટૉગલ કરો"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-વિશિષ્ટ માહિતી/સેટિંગ"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC ઉપલબ્ધ (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR પ્રતિબંધિત (NSA):"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 5e172b14e..68fca48eb 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"हटाए जा सकने वाले ई-सिम को डिफ़ॉल्ट के तौर पर सेट करें"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"मोबाइल रेडियो पावर"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"सिम्युलेट किया गया डिवाइस काम नहीं कर रहा है (सिर्फ़ डीबग के लिए बिल्ड)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"फ़ोर्स कैंप सैटलाइट एलटीई चैनल (सिर्फ़ डीबग के लिए बिल्ड)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"मोबाइल और इंटरनेट सेवा देने वाली कंपनी के सैटलाइट मोड की मॉक टेस्टिंग करें (सिर्फ़ डीबग के लिए बिल्ड)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"रीयल सैटलाइट इमरजेंसी एसओएस मोड को आज़माएं (सिर्फ़ डीबग के लिए बिल्ड)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"रीयल सैटलाइट नॉन इमरजेंसी एसओएस मोड को आज़माएं (सिर्फ़ डीबग के लिए बिल्ड)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"डेमो सैटलाइट इमरजेंसी एसओएस मोड को आज़माएं (सिर्फ़ डीबग के लिए बिल्ड)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"सिम में संपर्कों के पते की सूची देखें"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"फ़िक्स्ड डायलिंग नंबर देखें"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"सेवा के डायलिंग नंबर देखें"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"एसएमएससी:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"अपडेट करें"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"रीफ़्रेश करें"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"डीएनएस जांच टॉगल करें"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"ओईएम-खास जानकारी/सेटिंग"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC उपलब्ध है (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR प्रतिबंधित है (NSA):"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index e33b5028d..c397d8e9b 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Postavljanje uklonjivog eSIM-a kao zadanog"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Snaga mobilnog radija"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulacija stanja \"izvan upotrebe\" (samo međuverzija programa za otklanjanje pogrešaka)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Satelitski LTE kanal za Force Camp (samo međuverzija programa za otklanjanje pogrešaka)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Lažni način mobilnog operatera za slanje putem satelita (samo međuverzija programa za otklanjanje pogrešaka)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testiranje eSOS načina pravog satelita (samo međuverzija programa za otklanjanje pogrešaka)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testiranje načina pravog satelita bez eSOS-a (samo međuverzija programa za otklanjanje pogrešaka)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testiranje pokazne verzije eSOS načina satelita (samo međuverzija programa za otklanjanje pogrešaka)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Prikaži imenik SIM-a"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Prikaži brojeve za fiksno biranje"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Prikaži brojeve za servisno biranje"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Ažuriraj"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Osvježi"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Uključi/isključi provjeru DNS-a"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Informacije/postavke koje se posebno odnose na OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC dostupan (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Ograničeni DCNR (NSA):"</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 62c413a86..ea48ea669 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Cserélhető eSIM beállítása alapértelmezettként"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobil rádióadó teljesítménye"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Szolgáltatáskiesés szimulációja (csak hibaelhárító build)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Műholdas LTE-csatorna (csak hibaelhárító build)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Szimulált szolgáltató – Műholdas mód (csak hibaelhárító build)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"A valódi műholdas eSOS mód tesztelése (csak hibaelhárító build)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"A valódi műholdas, nem eSOS mód tesztelése (csak hibaelhárító build)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"A műholdas eSOS demó mód tesztelése (csak hibaelhárító build)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM-kártya telefonkönyvének megtekintése"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Fix hívószámok megtekintése"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Szolgáltatásszámok megtekintése"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Frissítés"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Frissítés"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS-ellenőrzés váltása"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-specifikus adatok és beállítások:"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC rendelkezésre áll (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR korlátozva (NSA):"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 731c6fb9b..576406527 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -561,7 +561,7 @@
     <string name="incall_error_wfc_only_no_wireless_network" msgid="5860742792811400109">"Զանգ կատարելու համար միացեք անլար ցանցին:"</string>
     <string name="incall_error_promote_wfc" msgid="9164896813931363415">"Զանգ կատարելու համար միացրեք «Զանգեր Wi-Fi ցանցի միջոցով» գործառույթը:"</string>
     <string name="incall_error_satellite_enabled" msgid="5247740814607087814">"Զանգ կատարելու համար նախ անջատեք արբանյակային կապը։"</string>
-    <string name="incall_error_carrier_roaming_satellite_mode" msgid="678603203562886361">"Դուք կարող եք ուղարկել և ստանալ հաղորդագրություններ՝ առանց բջջային կամ Wi-Fi կապի։"</string>
+    <string name="incall_error_carrier_roaming_satellite_mode" msgid="678603203562886361">"Դուք կարող եք հաղորդագրություններ ուղարկել և ստանալ առանց բջջային կամ Wi-Fi կապի։"</string>
     <string name="emergency_information_hint" msgid="9208897544917793012">"Անհետաձգելի բուժօգնության տվյալներ"</string>
     <string name="emergency_information_owner_hint" msgid="6256909888049185316">"Սեփականատեր"</string>
     <string name="emergency_information_confirm_hint" msgid="5109017615894918914">"Կրկին հպեք՝ տեղեկությունները դիտելու համար"</string>
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Սահմանել հեռացվելի eSIM քարտը որպես կանխադրված"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Բջջային ռադիոազդանշանի հզորությունը"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Սպասարկման գոտուց դուրս գտնվելու սիմուլյացիա (միայն վրիպազերծման կառուցում)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp արբանյակային LTE ալիք (միայն վրիպազերծման կառուցման մեջ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Օպերատորի արբանյակի ռեժիմի սիմուլյացիա (միայն վրիպազերծման կառուցում)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Փորձարկել իրական արբանյակային eSOS ռեժիմը (միայն վրիպազերծման կառուցման մեջ)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Փորձարկել իրական արբանյակային ոչ eSOS ռեժիմը (միայն վրիպազերծման կառուցման մեջ)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Փորձարկել արբանյակային eSOS ռեժիմը դեմո տարբերակով (միայն վրիպազերծման կառուցման մեջ)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Դիտել SIM քարտի հասցեագիրքը"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Տեսնել ամրակցված հեռախոսահամարները"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Տեսնել ծառայությունների հեռախոսահամարները"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC`"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Թարմացնել"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Թարմացնել"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Փոխարկել DNS ստուգումը"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-հատուկ տեղեկություններ/կարգավորումներ"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC հասանելի (NSA)՝"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR սահմանափակ (NSA)՝"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 1e9ca9af6..efb22b10a 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Tetapkan eSIM yang Dapat Dilepas sebagai Default"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Daya Radio Seluler"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulasi Tidak dapat Digunakan (Khusus Build Debug)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Terapkan Saluran Satelit LTE (khusus Build Debug)."</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mode Satelit Operator Tiruan (khusus Build Debug)."</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Uji mode eSOS satelit asli (khusus Build Debug)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Uji mode non-eSOS satelit asli (khusus Build Debug)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Uji mode eSOS satelit demo (khusus Build Debug)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Lihat Buku Alamat SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Lihat Panggilan Terbatas"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Lihat Nomor Panggilan Layanan"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Update"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Perbarui"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Aktifkan Pemeriksaan DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Info spesifik OEM/Setelan"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC Tersedia (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR Dibatasi (NSA):"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index a201c1e86..972481972 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Stilla laust eSIM sem sjálfgefið"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Loftnetsstyrkur farsíma"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Líkja eftir „Utan þjónustusvæðis“ (aðeins villuleitarsmíði)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Þvinga Camp Satellite LTE-rás (aðeins villuleitarsmíði)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Eftirlíking af gervihnattarstillingu símafyrirtækis (aðeins villuleitarsmíði)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Prófa eSOS-stillingu raunverulegs gervihnattar (eingöngu villuleitarsmíð)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Prófa af-eSOS-stillingu raunverulegs gervihnattar (eingöngu villuleitarsmíð)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Prófa prufuútgáfu af eSOS-stillingu gervihnattar (eingöngu villuleitarsmíð)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Skoða símaskrá SIM-korts"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Skoða læst númeraval"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Skoða þjónustunúmer"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Uppfæra"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Endurnýja"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Kveikja/slökkva á DNS-prófun"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Upplýsingar/stillingar framleiðanda"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC tiltækt (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR takmarkað (NSA):"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index cadede4df..9bbe00cb8 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Imposta la eSIM rimovibile come predefinita"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Potenza del segnale radio mobile"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulazione non disponibile (solo build di debug)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forza canale LTE satellitare del campo (solo build di debug)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Modalità satellite operatore fittizio (solo build di debug)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testa la modalità eSOS con satellite reale (solo build di debug)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testa la modalità non-eSOS con satellite reale (solo build di debug)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Prova la demo della modalità eSOS con satellite (solo build di debug)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Visualizza rubrica SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Visualizza numeri consentiti"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Visualizza numeri dell\'elenco dei numeri di servizio"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Aggiorna"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Aggiorna"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Attiva o disattiva verifica DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Info/impostazioni specifiche OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC disponibile (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR con limitazioni (NSA):"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index f93dc1d37..5e8999f2c 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -846,8 +846,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"‏הגדרת eSIM נשלף כברירת המחדל"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"הפעלה של רדיו סלולרי"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"‏סימולציה של המצב \'לא בשירות\' (גרסת build לניפוי באגים בלבד)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"‏ערוץ Force Camp Satellite LTE (רק גרסת build לניפוי באגים)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"‏מצב שמדמה תקשורת לוויינית דרך ספק הסלולר (גרסת build לניפוי באגים בלבד)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"‏מצב בדיקה שמדמה תקשורת לוויינית eSOS (גרסת build לניפוי באגים בלבד)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"‏מצב בדיקה שמדמה תקשורת לוויינית לא במצב eSOS (גרסת build לניפוי באגים בלבד)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"‏מצב בדיקה שמדמה תקשורת לוויינית eSOS (גרסת build לניפוי באגים בלבד)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"‏הצגת פנקס כתובות של SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"הצגת מספרי חיוג קבועים"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"מספרי חיוג לשירות"</string>
@@ -914,7 +917,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"עדכון"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"רענון"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"‏החלפת מצב של בדיקת DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"‏מידע/הגדרות ספציפיים ל-OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"‏זמין ל-EN-DC‏ (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"‏מוגבל על ידי DCNR‏ (NSA):"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 9642efc9f..ddbec3adf 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"リムーバブル eSIM をデフォルトに設定"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"モバイル無線電力"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"圏外状態のシミュレート（デバッグビルドのみ）"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE チャンネル（デバッグビルドのみ）"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"携帯通信会社の疑似航空写真モード（デバッグビルドのみ）"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"実際に衛星経由の緊急 SOS モードをテストする（デバッグビルドのみ）"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"実際に衛星経由の非緊急 SOS モードをテストする（デバッグビルドのみ）"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"デモ用の衛星による緊急 SOS モードをテストする（デバッグビルドのみ）"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM のアドレス帳を表示"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"発信番号制限を表示"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"サービス電話番号を表示"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"更新"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"更新"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS チェックを切り替え"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM 固有の情報 / 設定"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC 利用可能（NSA）:"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR 制限あり（NSA）:"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index 0d673a66e..31c7e0845 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"მოსახსნელი eSIM-ის ნაგულისხმევად დაყენება"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"მობილური რადიოკავშირის ელკვება"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"სიმულაცია სერვისის გარეშე (მხოლოდ გამართვის აგება)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Camp Satellite LTE არხის ფორსირება (მხოლოდ გამართვის მიზნით)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"სიმულაციური ოპერატორის სატელიტის რეჟიმი (მხოლოდ გამართვის აგება)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"სატელიტური eSOS-ის რეალური რეჟიმის ტესტირება (მხოლოდ გამართვის მიზნით)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"სატელიტური eSOS-ის რეალური რეჟიმის ტესტირება (მხოლოდ გამართვის მიზნით)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"სატელიტური eSOS-ის დემო-ვერსიის ტესტირება (მხოლოდ გამართვის მიზნით)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM-ის მისამართების წიგნის ნახვა"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"დაშვებული ნომრების ნახვა"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"სერვისის დარეკილი ნომრების ნახვა"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"განახლება"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"განახლება"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS შემოწმების გადართვა"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"ინფორმაცია/პარამეტრები სპეციალურად OEM-ისთვის"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC ხელმისაწვდომია (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR შეზღუდულია (NSA):"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 25ab94d49..6e51a49f7 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Алынбалы eSIM әдепкі етіп орнату"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Радиосигнал күші"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\"Істен шыққан\" қызметін симуляциялау (түзету құрамасы ғана)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Жерсеріктік LTE каналын мәжбүрлеп қолдану (тек түзету конструкциясы)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock Carrier жер серігі режимі (тек түзету құрамасы)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Шынайы жерсеріктегі құтқару қызметін шақыру режимін сынау (тек түзету құрамасы)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Шынайы жерсерікті құтқару қызметін шақыру режимінен басқа режимде сынау (тек түзету құрамасы)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Демо жерсеріктегі құтқару қызметін шақыру режимін сынау (тек түзету құрамасы)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM мекенжай кітапшасын көру"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Рұқсат нөмірлерді көру"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Қызметтік теру нөмірлерін көру"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Жаңарту"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Жаңарту"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS тексерісін қосу/өшіру"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Өндірушіге қатысты ақпарат/параметрлер"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC қолжетімді (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR шектеулі (NSA):"</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index e8084f91d..a6f712d4d 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"កំណត់ eSIM ដែល​អាចដកបាន​ជាលំនាំដើម"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"ថាមពល​វិទ្យុ​ទូរសព្ទ​ចល័ត"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"ត្រាប់តាម​ពេលគ្មានសេវា (កំណែបង្កើតសម្រាប់ជួសជុលតែប៉ុណ្ណោះ)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (តែកំណែបង្កើតសម្រាប់ជួសជុលប៉ុណ្ណោះ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"មុខងារ​ផ្កាយរណប​ក្រុមហ៊ុន​សេវាទូរសព្ទ​សាកល្បង (កំណែបង្កើត​សម្រាប់​ជួសជុល​តែប៉ុណ្ណោះ)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"មុខងារ​ធ្វើតេស្ត eSOS ផ្កាយរណប​ជាក់ស្ដែង (កំណែបង្កើត​សម្រាប់​ជួសជុល​តែប៉ុណ្ណោះ)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"មុខងារ​ធ្វើតេស្ត​ដែល​មិនមែនជា eSOS ផ្កាយរណប​ជាក់ស្ដែង (កំណែបង្កើត​សម្រាប់​ជួសជុល​តែប៉ុណ្ណោះ)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"មុខងារ​ធ្វើតេស្ត eSOS ផ្កាយរណប​សាកល្បង (កំណែបង្កើត​សម្រាប់​ជួសជុល​តែប៉ុណ្ណោះ)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"មើលសៀវភៅអាសយដ្ឋានក្នុងស៊ីមកាត"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"មើល​លេខ​ហៅ​ថេរ"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"មើល​លេខ​ហៅ​សេវាកម្ម"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC ៖"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"ធ្វើ​បច្ចុប្បន្នភាព"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"ផ្ទុកឡើងវិញ"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"បិទ/បើកការពិនិត្យ DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"ការ​កំណត់/ព័ត៌មាន​ជាក់លាក់ OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"អាច​ប្រើ EN-DC បាន (NSA)៖"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"បាន​ដាក់​កំហិត DCNR (NSA)៖"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 9feb53a76..9ef2be9d0 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"ತೆಗೆದುಹಾಕಬಹುದಾದ eSIM ಅನ್ನು ಡೀಫಾಲ್ಟ್ ಆಗಿ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"ಮೊಬೈಲ್ ರೇಡಿಯೋ ಪವರ್"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"ಸೇವೆಯಲ್ಲಿಲ್ಲದಿರುವುದನ್ನು ಸಿಮ್ಯುಲೇಟ್‌ ಮಾಡುವುದು (ಡೀಬಗ್ ಬಿಲ್ಡ್ ಮಾತ್ರ)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ಫೋರ್ಸ್ ಕ್ಯಾಂಪ್ ಸ್ಯಾಟಲೈಟ್ LTE ಚಾನಲ್ (ಡೀಬಗ್ ಬಿಲ್ಡ್ ಮಾತ್ರ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock Carrier ಉಪಗ್ರಹ ಮೋಡ್ (ಡೀಬಗ್ ಬಿಲ್ಡ್ ಮಾತ್ರ)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"ನೈಜ ಸ್ಯಾಟಲೈಟ್ eSOS ಮೋಡ್ ಅನ್ನು ಪರೀಕ್ಷಿಸಿ (ಡೀಬಗ್ ಬಿಲ್ಡ್ ಮಾತ್ರ)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"ರಿಯಲ್ ಸ್ಯಾಟಲೈಟ್ ನಾನ್-eSOS ಮೋಡ್ (ಡೀಬಗ್ ಬಿಲ್ಡ್ ಮಾತ್ರ) ಅನ್ನು ಟೆಸ್ಟ್ ಮಾಡಿ"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ಸ್ಯಾಟಲೈಟ್‌ eSOS ಮೋಡ್‌ ಅನ್ನು ಟೆಸ್ಟ್‌ ಡೆಮೋ ನೀಡಿ (ಡೀಬಗ್ ಬಿಲ್ಡ್ ಮಾತ್ರ)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"ಸಿಮ್ ವಿಳಾಸ ಪುಸ್ತಕವನ್ನು ವೀಕ್ಷಿಸಿ"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"ಸ್ಥಿರ ಡಯಲಿಂಗ್ ಸಂಖ್ಯೆಗಳನ್ನು ವೀಕ್ಷಿಸಿ"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"ಸೇವಾ ಡಯಲಿಂಗ್ ಸಂಖ್ಯೆಗಳನ್ನು ವೀಕ್ಷಿಸಿ"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"ಅಪ್‌ಡೇಟ್ ಮಾಡಿ"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"ರಿಫ್ರೆಶ್ ಮಾಡಿ"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS ಪರಿಶೀಲನೆ ಟಾಗಲ್ ಮಾಡಿ"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-ನಿರ್ದಿಷ್ಟ ಮಾಹಿತಿ/ಸೆಟ್ಟಿಂಗ್‌ಗಳು"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC ಲಭ್ಯವಿದೆ (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR ನಿರ್ಬಂಧಿತ (NSA):"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index c3b44253b..8e345f206 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -306,7 +306,7 @@
     <string name="keywords_carrier_settings_euicc" msgid="8540160967922063745">"이동통신사, esim, sim, euicc, 이동통신사 전환, 이동통신사 추가"</string>
     <string name="carrier_settings_euicc_summary" msgid="2027941166597330117">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> — <xliff:g id="PHONE_NUMBER">%2$s</xliff:g>"</string>
     <string name="mobile_data_settings_title" msgid="7228249980933944101">"모바일 데이터"</string>
-    <string name="mobile_data_settings_summary" msgid="5012570152029118471">"모바일 네트워크를 사용하여 데이터 액세스"</string>
+    <string name="mobile_data_settings_summary" msgid="5012570152029118471">"모바일 네트워크를 사용하여 데이터에 액세스합니다."</string>
     <string name="data_usage_disable_mobile" msgid="5669109209055988308">"모바일 데이터를 사용 중지하시겠습니까?"</string>
     <string name="sim_selection_required_pref" msgid="6985901872978341314">"선택 필요"</string>
     <string name="sim_change_data_title" msgid="9142726786345906606">"데이터 SIM을 변경하시겠습니까?"</string>
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"삭제 가능한 eSIM을 기본으로 설정"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"모바일 무선 전력"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\'서비스 지역 벗어남\' 시뮬레이션(디버그 빌드만 해당)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"캠프 위성 LTE 채널 강제(디버그 빌드만 해당)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"모의 이동통신사 위성 모드(디버그 빌드만 해당)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"실제 위성 eSOS 모드 테스트(디버그 빌드만 해당)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"실제 위성 비eSOS 모드 테스트(디버그 빌드만 해당)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"데모 위성 eSOS 모드 테스트(디버그 빌드만 해당)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM 주소록 보기"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"발신 허용 번호 보기"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"SDN(Service Dialing Numbers) 보기"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"업데이트"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"새로고침"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS 확인 전환"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM별 정보/설정"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC 사용 가능(NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR 제한됨(NSA):"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 3b086e9a2..a7054f93f 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -539,7 +539,7 @@
     <string name="incall_error_power_off" product="watch" msgid="7191184639454113633">"Мобилдик тармакты күйгүзүңүз, чалуу үчүн \"Учакта\" режимин же \"Батареяны үнөмдөө\" режимин өчүрүңүз."</string>
     <string name="incall_error_power_off" product="default" msgid="8131672264311208673">"Чалуу үчүн учак режимин өчүрүңүз."</string>
     <string name="incall_error_power_off_wfc" msgid="9125661184694727052">"Чалуу үчүн учак режимин өчүрүңүз же зымсыз тармакка туташыңыз."</string>
-    <string name="incall_error_power_off_thermal" product="default" msgid="8695809601655300168"><b>"Телефон ысып кетти"</b>\n\n"Бул чалуу аяктабай жатат. Телефон муздагандан кийин кайра аракет кылыңыз.\n\nШашылыш чалууларды аткара берсеңиз болот."</string>
+    <string name="incall_error_power_off_thermal" product="default" msgid="8695809601655300168"><b>"Телефон ысып кетти"</b>\n\n"Бул чалуу аяктабай жатат. Телефон муздагандан кийин кайталап көрүңүз.\n\nШашылыш чалууларды аткара берсеңиз болот."</string>
     <string name="incall_error_ecm_emergency_only" msgid="5622379058883722080">"Кадимки шартта чалуу үчүн шашылыш кайра чалуу режиминен чыгыңыз."</string>
     <string name="incall_error_emergency_only" msgid="8786127461027964653">"Тармакта катталган эмес."</string>
     <string name="incall_error_out_of_service" msgid="1927265196942672791">"Мобилдик тармак жок."</string>
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Чыгарылуучу eSIM-картаны демейки катары коюу"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Мобилдик радионун кубаты"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Тейлөө аймагынын сыртында режимин иштетүү (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Спутник LTE каналын иштетүү (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Симуляцияланган байланыш операторунун спутниги (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Чыныгы спутник eSOS режимин сыноо (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"eSOS болбогон чыныгы спутник режимин сыноо (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Демо спутник eSOS режимин сыноо (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM картадагы дарек китепчесин көрүү"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Туруктуу терүү номерлерин көрүү"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Кызматтык терүү номерлерин көрүү"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Жаңыртуу"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Жаңылоо"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS текшерүүнү которуштуруу"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM\'ге тиешелүү Маалымат/Параметрлер"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC жеткиликтүү (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR чектелген (NSA):"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index d771fe3b2..b823c549a 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"ຕັ້ງຄ່າ eSIM ແບບຖອດໄດ້ໃຫ້ເປັນຄ່າເລີ່ມຕົ້ນ"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"ພະລັງງານວິທະຍຸມືຖື"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"ຈໍາລອງເຫດການບໍ່ພ້ອມໃຫ້ບໍລິການ (ສໍາລັບ Build ດີບັກເທົ່ານັ້ນ)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ບັງຄັບໃຫ້ໃຊ້ຊ່ອງສັນຍານດາວທຽມ LTE ຂອງຄ້າຍ (ສຳລັບ Build ດີບັກເທົ່ານັ້ນ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"ຈຳລອງໂໝດດາວທຽມຂອງຜູ້ໃຫ້ບໍລິການ (ສຳລັບ Build ດີບັກເທົ່ານັ້ນ)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"ທົດສອບໂໝດ eSOS ດາວທຽມແທ້ (ສຳລັບ Build ດີບັກເທົ່ານັ້ນ)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"ທົດສອບໂໝດດາວທຽມແທ້ທີ່ບໍ່ແມ່ນ eSOS (ສຳລັບ Build ດີບັກເທົ່ານັ້ນ)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ທົດສອບໂໝດ eSOS ຂອງດາວທຽມເດໂມ (ສຳລັບ Build ດີບັກເທົ່ານັ້ນ)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"ເບິ່ງສະໝຸດທີ່ຢູ່ໃນຊິມ"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"ເບິ່ງໝາຍເລກໂທອອກທີ່ກຳນົດ"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"ເບິ່ງໝາຍເລກບໍລິການໂທອອກ"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"ອັບເດດ"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"ໂຫຼດຂໍ້ມູນໃໝ່"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"ເປີດ/ປິດ ການກວດ DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"ຂໍ້ມູນ/ການຕັ້ງຄ່າສະເພາະ OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"ສາມາດໃຊ້ EN-DC ໄດ້ (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"ຈຳກັດ DCNR (NSA):"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index 3034573f0..f2bc95b73 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Nustatyti pašalinimą „eSIM“ kaip numatytąją"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobiliojo ryšio radijo signalas"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Modeliavimas neteikiamas (tik derinimo versija)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Priverstinis stovyklos palydovinio ryšio LTE kanalo vykdymas (tik derinimo versija)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Netikras operatoriaus satelito režimas (tik derinimo versija)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Išbandykite tikrą Pagalbos iškvietimo kritiniu atveju naudojant palydovinį ryšį režimą (tik derinimo versija)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Išbandykite tikrą Pagalbos iškvietimo ne kritiniu atveju naudojant palydovinį ryšį režimą (tik derinimo versija)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Išbandykite demonstracinę Pagalbos iškvietimo kritiniu atveju naudojant palydovinį ryšį versiją (tik derinimo versija)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Žiūrėti SIM kortelės adresų knygą"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Žiūrėti fiksuotojo rinkimo numerius"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Žiūrėti paslaugos renkamus numerius"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Atnaujinti"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Atnaujinti"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Kaitalioti DNS tikrinimą"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM būdinga informacija / nustatymai"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"Pasiekiama EN-DC (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR apribota (NSA):"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 10a7a490f..339ea8254 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Iestatīt noņemamu eSIM kā noklusējumu"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobilā tālruņa radio signāla stiprums"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulācijas ierīce nedarbojas (tikai atkļūdošanas būvējums)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"LTE satelīta kanāla piespiedu izmantošana (tikai atkļūdošanas būvējums)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mobilo sakaru operatora satelīta režīma imitēšana (tikai atkļūdošanas būvējums)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Izmēģināt īsta satelīta eSOS režīmu (tikai atkļūdošanas būvējumā)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Izmēģināt īsta satelīta režīmu, kas nav eSOS režīms (tikai atkļūdošanas būvējumā)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Izmēģināt demonstrācijas satelīta eSOS režīmu (tikai atkļūdošanas būvējumā)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Skatīt SIM adrešu grāmatu"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Skatīt ierobežotā zvanu saraksta numurus"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Pakalpojuma iezvanes numuru skatīšana"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Atjaunināt"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Atsvaidzināt"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Pārslēgt DNS pārbaudi"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OAR raksturīga informācija/iestatījumi"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC pieejamība (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR ierobežojums (NSA):"</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 450fce03a..7eef5ee27 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Поставување eSIM што може да се отстрани како стандардна"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Радио-напојување на мобилен"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Симулирање „Надвор од употреба“ (само за верзиите за отстранување грешки)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (само верзија за отстранување грешки)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Симулација на режим на сателит за оператор (само за верзиите за отстранување грешки)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Тестирајте го реалниот режим на eSOS (само во верзијата за отстранување грешки)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Тестирајте го реалниот режим што не е на eSOS (само во верзијата за отстранување грешки)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Тестирајте го демо-режимот на eSOS (само во верзијата за отстранување грешки)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Прикажи именик на SIM-картичката"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Прикажи броеви со ограничено бирање"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Прикажи броеви за бирање служби"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Ажурирање"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Освежи"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Префрли на DNS-проверка"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Информации/Поставки карактеристични за ОЕМ"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"Достапно за EN-DC (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Ограничено на DCNR (NSA):"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 3f8935c14..8fd0e8ec8 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"നീക്കം ചെയ്യാവുന്ന ഇ-സിം ഡിഫോൾട്ടായി സജ്ജീകരിക്കുക"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"മൊബൈൽ റേഡിയോ പവർ"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"സേവനം ലഭ്യമല്ലെന്ന് അനുകരിക്കുക (ഡീബഗ് ബിൽഡ് മാത്രം)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ഫോഴ്‌സ് ക്യാമ്പ് സാറ്റലൈറ്റ് LTE ചാനൽ(ഡീബഗ് ബിൽഡ് മാത്രം)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock സേവനദാതാവ് ഉപഗ്രഹ മോഡ് (ഡീബഗ് ബിൽഡ് മാത്രം)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"യഥാർത്ഥ സാറ്റലൈറ്റ് eSOS മോഡ് പരീക്ഷിക്കുക (ഡീബഗ് ബിൽഡ് മാത്രം)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"യഥാർത്ഥ സാറ്റലൈറ്റ് eSOS ഇതര മോഡ് പരീക്ഷിക്കുക (ഡീബഗ് ബിൽഡ് മാത്രം)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ഡെമോ സാറ്റലൈറ്റ് eSOS മോഡ് പരീക്ഷിക്കുക (ഡീബഗ് ബിൽഡ് മാത്രം)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"സിം വിലാസ പുസ്‌തകം കാണുക"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"സ്ഥിര ഡയലിംഗ് നമ്പറുകൾ കാണുക"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"സർവീസ് ഡയലിംഗ് നമ്പറുകൾ കാണുക"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"അപ്ഡേറ്റ് ചെയ്യുക"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"റീഫ്രഷ് ചെയ്യുക"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS പരിശോധന മാറ്റുക"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-നിർദ്ദിഷ്‌ട വിവരം/ക്രമീകരണം"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC ലഭ്യമാണ് (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR നിയന്ത്രിച്ചിരിക്കുന്നു (NSA):"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index ea2421c1c..16f320798 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Салгах боломжтой eSIM-г өгөгдмөлөөр тохируулах"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Мобайл радио цахилгаан"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Үйлчилгээний хүрээнээс гарсан нөхцөл байдлыг загварчлах (зөвхөн дебагийн хийц)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Camp Satellite LTE сувгийг хүчлэх (зөвхөн дебаг хийсэн хийц)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Оператор компанийн хуурамч хиймэл дагуулын горим (зөвхөн дебаг хийсэн хийц)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Жинхэнэ хиймэл дагуул eSOS горимыг турших (зөвхөн дебаг хийсэн хийц)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Жинхэнэ хиймэл дагуул eSOS бус горимыг турших (зөвхөн дебаг хийсэн хийц)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Демо хиймэл дагуул eSOS горимыг турших (зөвхөн дебаг хийсэн хийц)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM хаягийн лавлахыг харах"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Залгахаар тохируулсан дугаарыг харах"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Үйлчилгээний залгах дугаарыг харах"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Шинэчлэх"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Сэргээх"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS шалгалтыг асаах/унтраах"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-тодорхой Мэдээлэл/Тохиргоо"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC боломжтой (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR хязгаарласан (NSA):"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 2975abdec..d3fe12d72 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"काढून टाकण्यायोग्य eSIM डीफॉल्ट म्हणून सेट करा"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"मोबाइल रेडिओ पॉवर"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"सेवा बंद आहे सिम्युलेट करा (फक्त डीबगचा बिल्‍ड)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"फोर्स कॅम्प सॅटेलाइट LTE चॅनल (फक्त डीबग बिल्ड)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"नमुना वाहकाचा उपग्रह मोड (फक्त डीबग बिल्ड)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"प्रत्यक्ष सॅटेलाइट eSOS मोडची चाचणी करा (फक्त डीबग बिल्ड)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"eSOS नसलेल्या वास्तविक सॅटेलाइट मोडची चाचणी करा (फक्त डीबग बिल्ड)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"डेमो सॅटेलाइट eSOS मोडची चाचणी करा (फक्त डीबग बिल्ड)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"सिम ॲड्रेस बुक पहा"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"निश्चित डायलिंग नंबर पहा"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"सर्व्हिस डायलिंग नंबर पहा"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"अपडेट करा"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"रिफ्रेश करा"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS तपासणी टॉगल करा"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-विशिष्ट माहिती/सेटिंग्ज"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC उपलब्ध (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR प्रतिबंधित (NSA):"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index b7e25caaf..fe16a4584 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Tetapkan eSIM Boleh Tanggal sebagai Lalai"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Kuasa Radio Mudah Alih"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulasi Rosak (Binaan Penyahpepijatan sahaja)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Paksa Saluran LTE Satelit Kem (Binaan Nyahpepijat sahaja)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Contoh Mod Satelit Pembawa (Binaan Penyahpepijatan sahaja)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Uji mod sSOS satelit sebenar (Binaan Penyahpepijatan sahaja)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Uji mod bukan eSOS satelit sebenar (Binaan Penyahpepijatan sahaja)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Uji mod eSOS satelit demo (Binaan Penyahpepijatan sahaja)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Lihat Buku Alamat SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Lihat Nombor Dailan Tetap"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Lihat Nombor Dailan Perkhidmatan"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Kemas kini"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Muat semula"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Togol Semakan DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Maklumat/Tetapan khusus OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC Tersedia (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR Terhad (NSA):"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 59182a338..90b1229df 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"ဖယ်ရှားနိုင်သော eSIM ကို မူရင်းအဖြစ် သတ်မှတ်ရန်"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"မိုဘိုင်း ရေဒီယိုစွမ်းအား"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"အသွင်တူပြုလုပ်သောစက် အလုပ်မလုပ်ပါ (အမှားရှာပြင်ခြင်းသာလျှင်)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE ချန်နယ် (အမှားရှာပြင်ခြင်းအတွက်သာ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock Carrier Satellite Mode (အမှားရှာပြင်ခြင်း အတွက်သာ)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"ဂြိုဟ်တုအစစ် eSOS မုဒ်ကို စမ်းသပ်ခြင်း (အမှားရှာပြင်ခြင်းအတွက်သာ)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"ဂြိုဟ်တုအစစ် eSOS မဟုတ်သော မုဒ်ကို စမ်းသပ်ခြင်း (အမှားရှာပြင်ခြင်းအတွက်သာ)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"သရုပ်ပြ ဂြိုဟ်တု eSOS မုဒ်ကို စမ်းသပ်ခြင်း (အမှားရှာပြင်ခြင်းအတွက်သာ)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM ထဲရှိ လိပ်စာ စာအုပ်ကိုကြည့်ပါ"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"ခေါ်ဆိုရန် ကန့်သတ် နံပါတ်ကို ကြည့်မည်"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"ခေါ်ဆိုသည့်ဝန်ဆောင်မှုနံပါတ်အားကြည့်မည်"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC -"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"အပ်ဒိတ်လုပ်ရန်"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"ပြန်စရန်"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS စစ်ဆေးမှုခလုတ်ကို နှိပ်ပါ"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"ထုတ်လုပ်သူနှင့် သက်ဆိုင်သော အချက်အလက်/ဆက်တင်များ"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC ရနိုင်သည် (NSA)-"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR ကန့်သတ်ထားသည် (NSA)-"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index b62d14ede..776a55d63 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Angi flyttbart eSIM-kort som standard"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Strømforsyning for mobilradio"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Ute av drift-simulering (bare for feilsøkingsversjoner)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE-kanal (bare feilsøkingsversjon)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Satelittmodus for fiktiv operatør (feilsøkingsversjon)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test ekte satellitt med eSOS-modus (kun for feilsøkingsversjoner)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test ekte satellitt med ikke-eSOS-modus (kun for feilsøkingsversjoner)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test demo av satellitt med eSOS-modus (kun for feilsøkingsversjoner)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Se adressebok for SIM-kort"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Vis forhåndsbestemte numre"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Vis tjenestenumre"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Oppdater"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Last inn på nytt"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Slå av/på DNS-sjekk"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Produsentspesfikk informasjon og innstillinger"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC tilgjengelig (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR begrenset (NSA):"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index f63b198bc..baa5aa790 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"हटाउन मिल्ने eSIM डिफल्ट रूपमा सेट गर्नुहोस्"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"मोबाइल रेडियोको पावर"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\"सेवा उपलब्ध छैन\" सिमुलेट गर्नुहोस् (डिबग बिल्डमा मात्र सिमुलेट गर्न मिल्छ)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE च्यानल (डिबग बिल्ड मात्र)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"सेवा प्रदायकको स्याटेलाइट मोडको परीक्षण गर्नुहोस् (डिबग बिल्ड मात्र)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"वास्तविक स्याटेलाइट eSOS मोड परीक्षण गर्नुहोस् (डिबग बिल्ड मात्र)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"वास्तविक स्याटेलाइट eSOS बाहेकका मोड (डिबग बिल्ड मात्र) परीक्षण गर्नुहोस्"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"डेमो स्याटेलाइट eSOS मोडको परीक्षण गर्नुहोस् (डिबग बिल्ड मात्र)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM को ठेगाना पुस्तिका हेर्नुहोस्"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"स्थिर डायल गर्ने नम्बरहरू हेर्नुहोस्"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"सेवामा डायल गर्ने नम्बरहरू हेर्नुहोस्"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"अपडेट गर्नुहोस्"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"पुनः ताजा गर्नुहोस्"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS को जाँचलाई टगल गर्नुहोस्"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-विशिष्ट जानकारी/सेटिङ"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC उपलब्ध छ (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR प्रतिबन्धित छ (NSA):"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index 7d92840e4..b859f88cd 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Verwisselbare e-simkaart instellen als standaard"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobiel radiovermogen"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\'Niet in gebruik\' simuleren (alleen in foutopsporingsbuild)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Camp Satellite LTE-kanaal afdwingen (alleen in foutopsporingsbuild)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Satellietmodus voor testprovider (alleen in foutopsporingsbuild)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Echte e-SOS via satellietmodus testen (alleen in foutopsporingsbuild)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Echte niet-noodoproep via satellietmodus testen (alleen in foutopsporingsbuild)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Demo e-SOS via satellietmodus testen (alleen in foutopsporingsbuild)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Adresboek op simkaart bekijken"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Vaste nummers bekijken"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Servicenummers bekijken"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Updaten"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Vernieuwen"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS-controle aan-/uitzetten"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-specifieke gegevens/instellingen"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC beschikbaar (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR beperkt (NSA):"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 8a0b029a6..3ec9fe797 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -624,7 +624,7 @@
     <string name="ota_hfa_activation_dialog_message" msgid="7921718445773342996">"ଏହି ଫୋନ୍‌ ଆପଣଙ୍କର ମୋବାଇଲ୍‌ ଡାଟା ସେବାକୁ ସକ୍ରିୟ କରୁଛି। \n\nଏଥି ପାଇଁ ପ୍ରାୟ 5 ମିନିଟ୍‌ ସମୟ ଲାଗିପାରେ।"</string>
     <string name="ota_skip_activation_dialog_title" msgid="7666611236789203797">"ସକ୍ରିୟ କରିବା ଛାଡ଼ିଯିବେ?"</string>
     <string name="ota_skip_activation_dialog_message" msgid="6691722887019708713">"ଯଦି ଆପଣ ସକ୍ରିୟ କରିବା କାର୍ଯ୍ୟକୁ ଛାଡ଼ିଯା’ନ୍ତି ତେବେ ଆପଣ କଲ୍ କରିପାରିବେ ନାହିଁ କିମ୍ବା ମୋବାଇଲ୍ ନେଟ୍‌ୱର୍କ (ଯଦିଓ ଆପଣ ୱାଇ-ଫାଇ ନେଟ୍‌ୱର୍କ ସହିତ ଯୋଡ଼ିହୋ‌ଇପାରିବେ) ସହିତ ଯୋଡ଼ିହୋ‌ଇପାରିବେ ନାହିଁ। ଆପଣ ନିଜର ଫୋନ୍‌କୁ ସକ୍ରିୟ ନକରିବା ପର୍ଯ୍ୟନ୍ତ ପ୍ରତ୍ୟେକଥର ଏହାକୁ ଚାଲୁ କରିବା ସମୟରେ ସକ୍ରିୟ କରିବା ପାଇଁ କୁହାଯିବ।"</string>
-    <string name="ota_skip_activation_dialog_skip_label" msgid="5908029466817825633">"ଛାଡ଼ିଦିଅନ୍ତୁ"</string>
+    <string name="ota_skip_activation_dialog_skip_label" msgid="5908029466817825633">"ବାଦ ଦିଅନ୍ତୁ"</string>
     <string name="ota_activate" msgid="7939695753665438357">"ସକ୍ରିୟ କରନ୍ତୁ"</string>
     <string name="ota_title_activate_success" msgid="1272135024761004889">"ଫୋନ୍ ସକ୍ରିୟ ହୋ‌ଇଯାଇଛି।"</string>
     <string name="ota_title_problem_with_activation" msgid="7019745985413368726">"ସକ୍ରିୟ ହେବାରେ ସମସ୍ୟା"</string>
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"କାଢ଼ି ହେଉଥିବା eSIMକୁ ଡିଫଲ୍ଟ ଭାବେ ସେଟ କରନ୍ତୁ"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"ମୋବାଇଲ୍ ରେଡିଓ ପାୱାର୍"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\"କାମ କରୁନାହିଁ\"ରେ ସିମୁଲେଟ କରନ୍ତୁ (କେବଳ ଡିବଗ ବିଲ୍ଡ)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ଫୋର୍ସ କେମ୍ପ ସେଟେଲାଇଟ LTE ଚେନେଲ (କେବଳ ଡିବଗ ବିଲ୍ଡ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"ମକ କେରିଅର ସେଟେଲାଇଟ ମୋଡ (କେବଳ ଡିବଗ ବିଲ୍ଡ)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"ପ୍ରକୃତ ସେଟେଲାଇଟର eSOS ମୋଡ ପରୀକ୍ଷା କରନ୍ତୁ (କେବଳ ଡିବଗ ବିଲ୍ଡ)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"ପ୍ରକୃତ ସେଟେଲାଇଟର ଅଣ-eSOS ମୋଡ ପରୀକ୍ଷା କରନ୍ତୁ (କେବଳ ଡିବଗ ବିଲ୍ଡ)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ଡେମୋ ସେଟେଲାଇଟର eSOS ମୋଡ ପରୀକ୍ଷା କରନ୍ତୁ (କେବଳ ଡିବଗ ବିଲ୍ଡ)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"ସିମ୍‌ରେ ଥିବା ଠିକଣା ପୁସ୍ତକ ଦେଖନ୍ତୁ"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"ସ୍ଥାୟୀ ଡାଏଲିଂ ନମ୍ୱରଗୁଡ଼ିକୁ ଦେଖନ୍ତୁ"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"ସର୍ଭିସ୍ ଡାଏଲିଂ ନମ୍ୱରଗୁଡ଼ିକ ଦେଖନ୍ତୁ"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"ଅପ୍‌ଡେଟ୍ କରନ୍ତୁ"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"ରିଫ୍ରେସ୍ କରନ୍ତୁ"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS ଯାଞ୍ଚ ଟୋଗଲ୍ କରନ୍ତୁ"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-ନିର୍ଦ୍ଦିଷ୍ଟ ସୂଚନା/ସେଟିଂସ୍"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC ଉପଲବ୍ଧ (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR ପ୍ରତିବନ୍ଧିତ (NSA):"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 585a53e21..cfe7dfb66 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"ਹਟਾਉਣਯੋਗ ਈ-ਸਿਮ ਨੂੰ ਪੂਰਵ-ਨਿਰਧਾਰਿਤ ਵਜੋਂ ਸੈੱਟ ਕਰੋ"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"ਮੋਬਾਈਲ ਰੇਡੀਓ ਪਾਵਰ"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\'ਸੇਵਾ ਵਿੱਚ ਨਹੀਂ\' ਨੂੰ ਸਿਮੂਲੇਟ ਕਰੋ (ਸਿਰਫ਼ ਡੀਬੱਗ ਬਿਲਡ)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ਫੋਰਸ ਕੈਂਪ ਸੈਟੇਲਾਈਟ LTE ਚੈਨਲ (ਸਿਰਫ਼ ਡੀਬੱਗ ਬਿਲਡ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"ਮੌਕ ਕੈਰੀਅਰ ਉਪਗ੍ਰਹਿ ਮੋਡ (ਸਿਰਫ਼ ਡੀਬੱਗ ਬਿਲਡ)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"ਰੀਅਲ ਸੈਟੇਲਾਈਟ eSOS ਮੋਡ ਅਜ਼ਮਾਓ (ਸਿਰਫ਼ ਡੀਬੱਗ ਬਿਲਡ)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"ਰੀਅਲ ਸੈਟੇਲਾਈਟ ਗੈਰ-eSOS ਮੋਡ ਅਜ਼ਮਾਓ (ਸਿਰਫ਼ ਡੀਬੱਗ ਬਿਲਡ)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ਡੈਮੋ ਸੈਟੇਲਾਈਟ eSOS ਮੋਡ ਅਜ਼ਮਾਓ (ਸਿਰਫ਼ ਡੀਬੱਗ ਬਿਲਡ)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"ਸਿਮ ਦੀ ਪਤਾ ਬੁੱਕ ਦੇਖੋ"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"ਫਿਕਸਡ ਡਾਇਲਿੰਗ ਨੰਬਰ ਦੇਖੋ"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"ਸੇਵਾ ਡਾਇਲਿੰਗ ਨੰਬਰ ਦੇਖੋ"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"ਅੱਪਡੇਟ"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"ਰਿਫ੍ਰੈਸ਼ ਕਰੋ"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS ਜਾਂਚ ਟੌਗਲ ਕਰੋ"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-ਵਿਸ਼ੇਸ਼ ਜਾਣਕਾਰੀ/ਸੈਟਿੰਗਾਂ"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC ਉਪਲਬਧ (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR ਪ੍ਰਤਿਬੰਧਿਤ (NSA):"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 7793f4972..c6de54721 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Ustaw wymienną kartę eSIM jako domyślną"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Moc sygnału komórkowego"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Symulowana przerwa w działaniu usługi (tylko w kompilacji do debugowania)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Wymuś kanał LTE satelitarny Force Camp (tylko kompilacja do debugowania)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Symulowany tryb satelitarny operatora (tylko kompilacja do debugowania)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testowanie rzeczywistego trybu satelitarnego eSOS (tylko kompilacja do debugowania)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testowanie rzeczywistego trybu satelitarnego innego niż eSOS (tylko kompilacja do debugowania)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testowanie wersji demonstracyjnej trybu satelitarnego eSOS (tylko kompilacja do debugowania)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Wyświetl książkę adresową z karty SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Wyświetl ustalone numery"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Wyświetl numery usług"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Aktualizacja"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Odśwież"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Przełącz sprawdzanie DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Informacje/ustawienia specyficzne dla producenta OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"Dostępne EN-DC (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Ograniczenie DCNR (NSA):"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 62c51e844..ddc06d482 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Predefinir eSIM removível"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Potência do rádio móvel"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simule o modo fora de serviço (apenas na versão de depuração)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Canal satélite LTE Force Camp (apenas na versão de depuração)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Modo satélite da operadora fictícia (apenas na versão de depuração)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testar modo eSOS de satélite real (apenas na versão de depuração)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Teste o modo não eSOS de satélite real (apenas na versão de depuração)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testar demonstração de modo eSOS de satélite (apenas na versão de depuração)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Ver livro de endereços do SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Ver números autorizados"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Ver números de marcação de serviços"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Atualizar"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Atualizar"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Ativar/desativar verificação de DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Informações/definições específicas de OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC disponível (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR restrito (NSA):"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index 6bd6988f2..966aa1555 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Definir eSIM removível como padrão"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Potência do rádio celular"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simular o modo fora de serviço (somente build de depuração)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forçar o canal LTE de satélite do grupo (somente build de depuração)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulação de modo satélite da operadora (somente build de depuração)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testar o modo eSOS por satélite (somente build de depuração)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testar o modo sem emergência de satélite real (somente build de depuração)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testar a demonstração do modo eSOS por satélite (somente build de depuração)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Ver o catálogo de endereços do chip"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Ver números de discagem fixa"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Ver números de discagem do serviço"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Atualizar"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Atualizar"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Ativar/desativar verificação do DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Informações/configurações específicas de OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC disponível (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR restrito (NSA):"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index dd8a13406..fd5cf374b 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Setează cartela eSIM portabilă drept prestabilită"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Alimentare radio celular"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulează modul în afara ariei de acoperire (numai în versiunea pentru remedierea erorilor)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forțează canalul Camp Satellite LTE (numai versiunea pentru remedierea erorilor)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mod Satelit al operatorului de testare (numai versiune pentru remedierea erorilor)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testează modul eSOS prin satelit real (numai versiunea pentru remedierea erorilor)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testează modul non-eSOS prin satelit real (numai versiunea pentru remedierea erorilor)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testează modul demonstrativ eSOS prin satelit (numai versiunea pentru remedierea erorilor)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Afișează agenda de pe SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Afișează numerele pentru apeluri restricționate"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Vezi numere de apelare de serviciu"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Actualizează"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Actualizează"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Activează/dezactivează verificarea DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Informații/Setări caracteristice OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"Disponibil EN-DC (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Restricționat DCNR (NSA):"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index c640ce35f..a5ceee8f4 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Установить съемную eSIM-карту в качестве используемой по умолчанию"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Мощность радиосигнала"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Моделирование нахождения вне зоны обслуживания (только отладочная сборка)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Принудительно использовать спутниковый канал LTE (только для отладочной сборки)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Режим спутниковой связи симуляции оператора (только отладочная сборка)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Проверка спутникового режима eSOS (только отладочная сборка)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Проверка спутниковой связи в режиме, отличном от eSOS (только отладочная сборка)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Проверка демоверсии спутникового режима eSOS (только отладочная сборка)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Посмотреть адресную книгу на SIM-карте"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Список разрешенных номеров"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Посмотреть номера служебного набора"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Обновить"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Обновить"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Включить/отключить проверку DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Информация/настройки OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC доступно (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR с ограничениями (NSA):"</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index c29bef180..8c90fde85 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"ඉවත් කළ හැකි eSIM පෙරනිමිය ලෙස සකසන්න"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"ජංගම රේඩියෝ බලය"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"සේවයෙන් බැහැරව අනුකරණය කරන්න (නිදොස් තැනුම පමණි)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE නාලිකාව (නිදොසීමේ තැනුම පමණි)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"ආදර්ශ වාහක චන්ද්‍රිකා ප්‍රකාරය (නිදොස් තැනීමට පමණි)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"සැබෑ චන්ද්‍රිකා eSOS ප්‍රකාරය පරීක්ෂා කරන්න (නිදොස් තැනීමට පමණි)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"සැබෑ චන්ද්‍රිකා eSOS නොවන ප්‍රකාරය පරීක්ෂා කරන්න (නිදොස් තැනීමට පමණි)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ආදර්ශන චන්ද්‍රිකා eSOS ප්‍රකාරය පරීක්ෂා කරන්න (නිදොස් තැනීමට පමණි)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM ලිපින පොත බලන්න"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"ස්ථාවර ඇමතුම් අංක පෙන්වන්න"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"සේවා ඩයල් කිරීමේ අංක පෙන්වන්න"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"යාවත්කාලීන කරන්න"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"නැවුම් කරන්න"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS පරීක්ෂාව ටොගල කරන්න"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-විශේෂිත තොරතුරු/සැකසීම්"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC තිබේ (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR සීමිතයි (NSA):"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index d540299a0..9c446a4e2 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Nastaviť odoberateľnú eSIM kartu ako predvolenú"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Sila signálu GSM"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulácia nefungujúceho zariadenia (možné iba v ladiacej zostave)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Vynútenie kanála Camp Satellite LTE (iba ladiaca zostava)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulácia satelitného režimu operátora (iba ladiaca zostava)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testovať režim pomoci v tiesni cez skutočné satelity (iba ladiaca zostava)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testovať štandardný režim cez skutočné satelity (iba ladiaca zostava)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testovať režim pomoci v tiesni cez demo satelity (iba ladiaca zostava)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Zobraziť adresár SIM karty"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Zobraziť povolené čísla"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Zobraziť čísla volaní služieb"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Aktualizovať"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Obnoviť"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Prepnúť kontrolu DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Informácie alebo nastavenia špecifické pre výrobcu OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"Dostupné EN-DC (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Obmedzené DCNR (NSA):"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index 214fcc435..46383b47b 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Nastavi izmenljivo kartico e-SIM kot privzeto"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Moč radia mobilne naprave"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulacija nedelovanja (samo za gradnjo za odpravljanje napak)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Satelitski kanal LTE za Force Camp (samo gradnja za odpravljanje napak)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Lažni satelitski način operaterja (samo gradnja za odpravljanje napak)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Preizkus pravega satelitskega načina eSOS (samo gradnja za odpravljanje napak)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Preizkus pravega satelitskega (nenujnega) načina eSOS (samo gradnja za odpravljanje napak)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Preizkus predstavitvenega satelitskega načina eSOS (samo gradnja za odpravljanje napak)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Prikaži imenik na kartici SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Prikaži številke za zaporo odhodnih klicev"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Prikaži številke za klicanje storitev"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Posodobi"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Osveži"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Preklop preverjanja DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Informacije/nastavitve za OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"Razpoložljivo za EN-DC (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Omejeno za DCNR (NSA):"</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index a9aad0dcf..5dc50c483 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Caktoje kartën e lëvizshme eSIM si të parazgjedhur"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Fuqia e radios së rrjetit celular"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulo gjendjen jashtë shërbimit (vetëm versioni i korrigjimit)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Detyro kanalin satelitor të LTE-së për kampin (vetëm versioni i korrigjimit)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulo modalitetin e satelitit të operatorit celular (vetëm versioni i korrigjimit)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testo modalitetin real të \"eSOS satelitor\" (vetëm versioni i korrigjimit)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testo modalitetin real satelitor jo për eSOS (vetëm versioni i korrigjimit)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testo modalitetin e demonstrimit të \"eSOS satelitor\" (vetëm versioni i korrigjimit)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Shiko librin e adresave të kartës SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Shiko numrat me telefonim të përzgjedhur"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Shiko numrat e telefonit të shërbimit"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Përditëso"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Rifresko"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Ndrysho kontrollin e DNS-së"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Informacion/cilësime specifike për OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC në dispozicion (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR me kufizime (NSA):"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 3c61e7202..7c70a74ca 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Подеси преносиви eSIM као подразумевани"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Напајање за радио на мобилним уређајима"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Симулација не функционише (само верзија са отклоњеним грешкама)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Принудно примени сателит за камповање на LTE канал (само верзија за отклањање грешака)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Лажни режим мобилног оператера за слање преко сателита (само верзија за отклањање грешака)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Тестирајте стварни сателитски eSOS режим (само верзија са отклоњеним грешкама)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Тестирајте стварни сателитски режим који није eSOS (само верзија са отклоњеним грешкама)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Тестирајте демо верзију сателитског eSOS режима (само верзија са отклоњеним грешкама)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Прикажи адресар SIM-а"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Прикажи бројеве за фиксно бирање"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Прикажи бројеве за сервисно бирање"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Ажурирај"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Освежи"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Укључи/искључи проверу DNS-а"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Информације/подешавања специфична за произвођача оригиналне опреме"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC доступно (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR ограничено (NSA):"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 65921b32f..a5c21a2a8 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Ställ in Flyttbart eSIM som standard"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Strömförsörjning för mobilradio"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulera ur funktion (endast felsökningsversion)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE-kanal (endast felsökningsversion)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulering av operatörssatellitläge (version endast för felsökning)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testa verkligt eSOS-satellitläge (endast felsökningsversion)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testa verkligt icke-eSOS-satellitläge (endast felsökningsversion)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testa demoläge för eSOS-satellit (endast felsökningsversion)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Visa SIM-adressbok"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Visa Fasta nummer"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Visa tjänstenummer"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Uppdatera"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Uppdatera"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Aktivera och inaktivera DNS-kontroll"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-specifik information/inställningar"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC tillgängligt (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR begränsat (NSA):"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 61ff509ee..2f3fdeb74 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -566,7 +566,7 @@
     <string name="emergency_information_owner_hint" msgid="6256909888049185316">"Mmiliki"</string>
     <string name="emergency_information_confirm_hint" msgid="5109017615894918914">"Gusa tena ili uangalie maelezo"</string>
     <string name="emergency_enable_radio_dialog_title" msgid="2667568200755388829">"Simu ya dharura"</string>
-    <string name="single_emergency_number_title" msgid="8413371079579067196">"Nambari ya dharura"</string>
+    <string name="single_emergency_number_title" msgid="8413371079579067196">"Namba ya dharura"</string>
     <string name="numerous_emergency_numbers_title" msgid="8972398932506755510">"Nambari za dharura"</string>
     <string name="emergency_call_shortcut_hint" msgid="1290485125107779500">"Gusa tena ili upige <xliff:g id="EMERGENCY_NUMBER">%s</xliff:g>"</string>
     <string name="emergency_enable_radio_dialog_message" msgid="1695305158151408629">"Inawasha redio..."</string>
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Weka eSIM Inayoweza Kuondolewa kama Chaguomsingi"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Nishati ya Redio ya Vifaa vya Mkononi"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Kifaa cha Kuiga Hakifanyi Kazi (Muundo wa Utatuzi pekee)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Chaneli ya Setilaiti ya LTE ya Force Camp (Muundo wa Utatuzi Pekee)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Hali ya Setilaiti ya Jaribio la Mtoa Huduma (Muundo wa Utatuzi pekee)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Kujaribu hali ya msaada halisi wa mtandaoni kupitia setilaiti (Muundo wa Utatuzi pekee)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Kujaribu hali ya non-eSOS kwenye setilaiti halisi (Muundo wa Utatuzi pekee)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Kujaribu hali ya eSOS kwenye setilaiti ya jaribio (Muundo wa Utatuzi pekee)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Angalia Kitabu cha Anwani katika SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Ona Nambari za Simu Zilizobainishwa"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Angalia Nambari Zilizowekwa na Mtoa Huduma"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Sasisha"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Onyesha upya"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Geuza Ukaguzi wa DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Maelezo/Mipangilio Mahususi kwa Kampuni Inayotengeneza Vifaa (OEM)"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC Inapatikana (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR Imedhibitiwa (NSA):"</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 24a1a8c11..68c9b31df 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"அகற்றக்கூடிய eSIMமை இயல்பாக அமை"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"மொபைல் ரேடியோ பவர்"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"சாதனம் \'வேலை செய்யவில்லை\' என்பதை சிமுலேட் செய்தல் (பிழைதிருத்தப் பதிப்பில் மட்டும்)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ஃபோர்ஸ் கேம்ப் சாட்டிலைட் LTE சேனல் (பிழைதிருத்தக் கட்டமைப்பு மட்டும்)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock மொபைல் நிறுவன சாட்டிலைட் பயன்முறை (பிழைதிருத்த பதிப்பு மட்டும்)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"அசல் சாட்டிலைட் eSOS பயன்முறை (பிழைதிருத்தப் பதிப்பு மட்டும்)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"அசல் சாட்டிலைட் eSOS அல்லாத பயன்முறையைப் பயன்படுத்திப் பாருங்கள் (பிழைதிருத்தப் பதிப்பு மட்டும்)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"டொமோ சாட்டிலைட் eSOS பயன்முறையைப் பரிசோதனை செய்தல் (பிழைதிருத்தப் பதிப்பு மட்டும்)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"சிம் முகவரிப் புத்தகத்தைக் காட்டு"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"நிலையான அழைப்பு எண்களைக் காட்டு"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"சேவை அழைப்பு எண்களைக் காட்டு"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"புதுப்பி"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"புதுப்பி"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS சரிபார்ப்பை நிலைமாற்று"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM சார்ந்த தகவல்/அமைப்புகள்"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC உள்ளது (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR கட்டுப்படுத்தப்பட்டது (NSA):"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index ba6a58139..1a7faf6f0 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"తీసివేయగలిగే eSIMని ఆటోమేటిక్ సెట్టింగ్‌గా సెట్ చేయండి"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"మొబైల్ రేడియో పవర్"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"పరికరాన్ని సిమ్యులేట్ చేయడం అందుబాటులో లేదు (డీబగ్ బిల్డ్ మోడ్‌లో మాత్రమే)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ఫోర్స్ క్యాంప్ శాటిలైట్ LTE ఛానెల్ (డీబగ్ బిల్డ్ మోడ్‌లో మాత్రమే)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"మాక్ క్యారియర్ శాటిలైట్ మోడ్ (డీబగ్ బిల్డ్ మోడ్‌లో మాత్రమే)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"రియల్ శాటిలైట్ eSOS మోడ్‌ను టెస్ట్ చేయండి (డీబగ్ బిల్డ్ మోడ్‌లో మాత్రమే)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"రియల్ శాటిలైట్ eSOS యేతర మోడ్‌ను టెస్ట్ చేయండి (డీబగ్ బిల్డ్ మోడ్‌లో మాత్రమే)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"డెమో శాటిలైట్ eSOS మోడ్‌ను టెస్ట్ చేయండి (డీబగ్ బిల్డ్ మోడ్‌లో మాత్రమే)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM అడ్రస్‌ పుస్తకాన్ని చూడండి"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"ఫిక్స్‌డ్ డయలింగ్ నంబర్‌లను చూడండి"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"సర్వీస్ డయలింగ్ నంబర్‌లను చూడండి"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"అప్‌డేట్ చేయండి"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"రిఫ్రెష్ చేయండి"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS తనిఖీని టోగుల్ చేయండి"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM-నిర్దిష్ట సమాచారం/సెట్టింగ్‌లు"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC అందుబాటులో ఉన్న (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR పరిమితం చేయబడిన (NSA):"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 1994bdf01..45b5bcf42 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"กำหนดให้ eSIM แบบนำออกได้เป็นค่าเริ่มต้น"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"กำลังส่งของวิทยุเครือข่ายมือถือ"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"จําลองความไม่พร้อมให้บริการ (บิลด์การแก้ไขข้อบกพร่องเท่านั้น)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"บังคับใช้แชนเนล LTE ของ Camp Satellite (บิลด์การแก้ไขข้อบกพร่องเท่านั้น)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"โหมดดาวเทียมของผู้ให้บริการจำลอง (บิลด์การแก้ไขข้อบกพร่องเท่านั้น)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"ทดสอบโหมด eSOS ของดาวเทียมจริง (บิลด์การแก้ไขข้อบกพร่องเท่านั้น)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"ทดสอบโหมด non-eSOS ของดาวเทียมจริง (บิลด์การแก้ไขข้อบกพร่องเท่านั้น)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ทดสอบโหมด eSOS ของดาวเทียมเดโม (บิลด์การแก้ไขข้อบกพร่องเท่านั้น)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"ดูสมุดที่อยู่ของซิม"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"ดูการจำกัดหมายเลขโทรออก"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"ดูหมายเลขรับบริการโทรออก"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"อัปเดต"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"รีเฟรช"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"สลับการตรวจสอบ DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"ข้อมูล/การตั้งค่าเฉพาะตาม OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC ที่พร้อมใช้งาน (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR ที่จำกัด (NSA):"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 7dd659f5a..d64fb8f5f 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Itakda na Default ang Naaalis na eSIM"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobile Radio Power"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Mag-simulate ng Hindi Gumagana (Build sa Pag-debug lang)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Ipilit ang Camp Satellite LTE Channel (Build sa Pag-debug lang)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Satellite Mode ng Mock Carrier (Debug Build lang)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test real satellite eSOS mode (Build sa Pag-debug lang)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test real satellite non-eSOS mode (Build sa Pag-debug lang)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test demo satellite eSOS mode (Build sa Pag-debug lang)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Tingnan ang Address Book ng SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Tingnan ang Mga Fixed Dialing Number"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Tingnan ang Mga Service Dialing Number"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"I-update"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"I-refresh"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"I-toggle ang DNS Check"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Impormasyon/Mga Setting na partikular sa OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"Available ang EN-DC (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Pinaghihigpitang DCNR (NSA):"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 3bb1dc597..c74263123 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Çıkarılabilir eSIM\'i Varsayılan Yap"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Mobil Radyo Gücü"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Hizmet Dışı Simülasyonu (Yalnızca Hata Ayıklama Derlemesi)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Kamp uydusu LTE kanalını zorunlu kılma (yalnızca hata ayıklama derlemesi)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Örnek operatör uydu modu (yalnızca hata ayıklama derlemesi)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Gerçek uydu eSOS modunu test et (yalnızca hata ayıklama derlemesi)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Gerçek uydu üzerinde eSOS olmayan modu test et (yalnızca hata ayıklama derlemesi)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Demo uydu üzerinde eSOS modunu test et (yalnızca hata ayıklama derlemesi)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM Adres Defterini Görüntüle"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Sabit Arama Numaralarını Görüntüle"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Hizmet Arama Numaralarını Görüntüle"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Güncelle"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Yenile"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS Denetimini Aç/Kapat"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM\'e Özgü Bilgiler/Ayarlar"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC Kullanılabilir (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR Kısıtlanmış (NSA):"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 0a994dca1..76b2a0478 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Установити знімну eSIM-карту як карту за умовчанням"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Потужність мобільного радіо"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Імітація знаходження поза зоною обслуговування (лише складання для налагодження)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Примусово застосувати супутниковий зв’язок із каналом LTE (лише для налагодження)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Режим супутника оператора Mock (лише складання для налагодження)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Тестувати реальний режим супутникового сигналу SOS (лише складання для налагодження)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Тестувати реальний режим супутникового сигналу, відмінного від SOS (лише складання для налагодження)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Тестування демоверсії супутникового сигналу SOS (складання лише для налагодження)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Переглянути адресну книгу SIM-карти"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Переглянути фіксовані номери"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Переглянути службові номери"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Оновити"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Оновити"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Увімк./вимк. перевірку DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Інформація/налаштування OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"З доступом EN-DC (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"З обмеженням DCNR (NSA):"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 840cc5655..cc704cbbf 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"‏ہٹانے لائق eSIM کو بطور ڈیفالٹ سیٹ کریں"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"موبائل ریڈیو پاور"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\'سروس دستیاب نہیں ہے\' موڈ کو سمیولیٹ کریں (صرف ڈیبگ بلڈ کیلئے)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"‏فورس کیمپ سیٹلائٹ LTE چینل (صرف ڈیبگ بلڈ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"موک کیریئر سیٹلائٹ موڈ (صرف ڈیبگ بلڈ)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"‏اصل سیٹلائٹ eSOS وضع کی جانچ کریں (صرف ڈیبگ بلڈ)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"‏اصل سیٹلائٹ غیر eSOS وضع کی جانچ کریں (صرف ڈیبگ بلڈ)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"‏ڈیمو سیٹلائٹ eSOS وضع کی جانچ کریں (صرف ڈیبگ بلڈ)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"‏SIM ایڈریس بک دیکھیں"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"فکسڈ ڈائلنگ نمبرز دیکھیں"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"سروس ڈائلنگ نمبرز دیکھیں"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"اپ ڈیٹ کریں"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"ریفریش کریں"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"‏DNS چیک ٹوگل کریں"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"‏OEM-کیلئے مخصوص معلومات/ترتیبات"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"‏EN-DC دستیاب (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"‏DCNR محدود (NSA):"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index 10b76671a..346373d96 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Olinadigan eSIM kartani birlamchi qilib belgilash"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Radio signal quvvati"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Xizmatdan tashqari simulyatsiya (faqat nosozliklarni aniqlash dasturi uchun)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Majburiy Camp sputnik LTE kanali (faqat debag nashrida)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Soxta operator sputnik rejimi (faqat debag nashrida)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Haqiqiy sputnik eSOS rejimini sinash (faqat debag nashrida)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Haqiqiy sputnik non-eSOS rejimini sinash (faqat debag nashrida)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Demo sputnik eSOS rejimini sinash (faqat debag nashrida)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"SIM kartadagi abonentlar ro‘yxatini ochish"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Ruxsat etilgan raqamlar ro‘yxatini ochish"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Xizmatlarni terish raqamlarini ochish"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Yangilash"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Yangilash"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"DNS tekshiruvini yoqish/o‘chirish"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM maxsus axboroti va sozlamalari"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC mavjud (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR: cheklovlar mavjud (NSA):"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 5935a58cf..ecf73bdb6 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Đặt eSIM có thể tháo rời là Mặc định"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Cường độ của sóng di động"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Mô phỏng thiết bị không hoạt động (chỉ dành cho bản gỡ lỗi)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Buộc sử dụng kênh LTE vệ tinh khi cắm trại (chỉ dành cho Bản gỡ lỗi)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mô phỏng chế độ vệ tinh của nhà mạng (chỉ dành cho Bản gỡ lỗi)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Thử nghiệm chế độ eSOS thực tế qua vệ tinh (chỉ bản gỡ lỗi)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Thử nghiệm chế độ không khẩn cấp thực tế qua vệ tinh (chỉ dành cho bản gỡ lỗi)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Thử nghiệm chế độ eSOS minh hoạ qua vệ tinh (chỉ dành cho bản gỡ lỗi)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Xem sổ địa chỉ trên SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Xem số gọi định sẵn"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Xem số quay số dịch vụ"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Cập nhật"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Làm mới"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Bật/tắt chế độ kiểm tra DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Thông tin/Cài đặt dành riêng cho OEM"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"Hỗ trợ EN-DC (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Hạn chế DCNR (NSA):"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index a53e592fd..fd6150721 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"将可卸载的 eSIM 卡设为默认 eSIM 卡"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"移动无线装置电源"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"模拟服务终止（仅限调试 build）"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"强制使用 Camp 卫星 LTE 信道（仅限调试 Build）"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"模拟运营商卫星模式（仅限调试 build）"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"测试真实的卫星 eSOS 模式（仅限调试 build）"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"测试真实的卫星非 eSOS 模式（仅限调试 build）"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"测试卫星 eSOS 演示模式（仅限调试 build）"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"查看 SIM 卡通讯录"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"查看固定拨号号码"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"查看服务拨号号码"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC："</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"更新"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"刷新"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"切换 DNS 检查"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"特定 OEM 的信息/设置"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC 可用 (NSA)："</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR 受限 (NSA)："</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index a338e3b75..30d09edc4 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"將可移除的 eSIM 卡設為預設值"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"流動無線電的電源"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"模擬沒有服務 (僅限偵錯版本)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp 衛星 LTE 頻道 (僅限偵錯版本)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"模擬流動網絡供應商衛星模式 (僅限偵錯版本)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"測試「緊急衛星連接」真實模式 (僅限偵錯版本)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"測試「非緊急衛星連接」真實模式 (僅限偵錯版本)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"測試「緊急衛星連接」試用模式 (僅限偵錯版本)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"查看 SIM 卡通訊錄"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"查看固定撥號"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"查看服務撥號"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC："</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"更新"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"重新整理"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"切換 DNS 檢查"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"OEM 專用資訊/設定"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC 可用 (NSA)："</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR 受限 (NSA)："</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 99e29123a..838cbe76f 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"將可移除的 eSIM 卡設為預設 eSIM 卡"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"行動無線電電源"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"模擬無法使用服務的情況 (僅限偵錯版本)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"強制執行 Camp 衛星 LTE 頻道 (僅限偵錯版本)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"模擬電信業者衛星模式 (僅限偵錯版本)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"實際測試衛星緊急求救模式 (僅限偵錯版本)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"實際測試衛星非緊急求救模式 (僅限偵錯版本)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"測試衛星緊急求救展示模式 (僅限偵錯版本)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"查看 SIM 通訊錄"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"查看固定撥號"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"查看服務撥號號碼"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC："</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"更新"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"重新整理"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"切換 DNS 檢查"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"原始設備製造商 (OEM) 專用資訊/設定"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"EN-DC 可使用 (NSA)："</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"DCNR 受限 (NSA)："</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 12ac0bc76..2ec8c18e2 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -845,8 +845,11 @@
     <string name="removable_esim_string" msgid="7931369811671787649">"Setha i-eSim Esusekayo Njengezenzakalelayo"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"Amandla erediyo yeselula"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Lingisa okuthi Ayikho Isevisi (Umakhiwo Wokususa Iphutha kuphela)"</string>
+    <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Isiteshi se-Force Camp Satellite LTE (Ukwakhiwa Kokususa Iphutha kuphela)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Imodi Yesethelayithi Yenkampani Yenethiwekhi ye-Mock (Susa Iphutha Esakhiweni kuphela)"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Hlola imodi yesathelayithi yangempela ye-eSOS (Ukwakhiwa Kokususa Iphutha kuphela)"</string>
+    <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Hlola imodi yesathelayithi yangempela ekungesiyo ye-eSOS (Ukwakhiwa Kokususa Iphutha kuphela)"</string>
+    <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Hlola imodi yesathelayithi yedemo ye-eSOS (Ukwakhiwa Kokususa Iphutha kuphela)"</string>
     <string name="radioInfo_menu_viewADN" msgid="4533179730908559846">"Buka incwadi yekheli le-SIM"</string>
     <string name="radioInfo_menu_viewFDN" msgid="1847236480527032061">"Buka Izinombolo Zokudayela Okungaguquki"</string>
     <string name="radioInfo_menu_viewSDN" msgid="2613431584522392842">"Buka Izinombolo Zokudayela Isevisi"</string>
@@ -913,7 +916,6 @@
     <string name="radio_info_smsc_label" msgid="3749927072726033763">"SMSC:"</string>
     <string name="radio_info_smsc_update_label" msgid="5141996256097115753">"Buyekeza"</string>
     <string name="radio_info_smsc_refresh_label" msgid="8409923721451604560">"Vuselela"</string>
-    <string name="radio_info_toggle_dns_check_label" msgid="1394078554927787350">"Guqula ukuhlola i-DNS"</string>
     <string name="oem_radio_info_label" msgid="2914167475119997456">"Ulwazi oucacile kwe-OEM/Izilungiselelo"</string>
     <string name="radio_info_endc_available" msgid="2983767110681230019">"I-EN-DC Iyatholakala (NSA):"</string>
     <string name="radio_info_dcnr_restricted" msgid="7147511536420148173">"Ikhawulewe nge-DCNR (NSA):"</string>
diff --git a/res/values/config.xml b/res/values/config.xml
index cdef37eb2..847c4c525 100644
--- a/res/values/config.xml
+++ b/res/values/config.xml
@@ -157,6 +157,8 @@
     <string name="mobile_network_settings_package" translatable="false">com.android.settings</string>
     <!-- Class name for the mobile network settings activity [DO NOT TRANSLATE] -->
     <string name="mobile_network_settings_class" translatable="false">com.android.settings.Settings$MobileNetworkActivity</string>
+    <!-- Class name for the SIMs settings activity [DO NOT TRANSLATE] -->
+    <string name="sims_settings_class" translatable="false">com.android.settings.Settings$MobileNetworkListActivity</string>
 
     <!-- CDMA activation goes through HFA -->
     <!-- DEPRECATED: Use CarrierConfigManager#KEY_USE_HFA_FOR_PROVISIONING_BOOL -->
@@ -347,6 +349,8 @@
         <!-- b/317945295 -->
         <item>in</item>
         <item>sg</item>
+        <!-- b/341611911 -->
+        <item>my</item>
     </string-array>
 
     <!-- Array of countries that a CS preferred scan is preferred after CSFB failure
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 87e7095f7..43fc09e5b 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -2028,10 +2028,17 @@
     <!-- Title for simulating device out of service. -->
     <string name="simulate_out_of_service_string">Simulate Out of Service (Debug Build only)</string>
 
+    <!-- Title for enforcing satellite channels. -->
+    <string name="enforce_satellite_channel_string">Force Camp Satellite LTE Channel (Debug Build only)</string>
+
     <!-- Title for simulating SIM capable of satellite. -->
     <string name="mock_carrier_roaming_satellite_string">Mock Carrier Satellite Mode (Debug Build only)</string>
     <!-- Title for trigger real satellite eSOS. -->
     <string name="esos_satellite_string">Test real satellite eSOS mode (Debug Build only)</string>
+    <!-- Title for enable real satellite non-emergency mode. -->
+    <string name="satellite_enable_non_emergency_mode_string">Test real satellite non-eSOS mode (Debug Build only)</string>
+    <!-- Title for trigger demo satellite eSOS. -->
+    <string name="demo_esos_satellite_string">Test demo satellite eSOS mode (Debug Build only)</string>
 
     <!-- Phone Info screen. Menu item label.  Used for diagnostic info screens, precise translation isn't needed -->
     <string name="radioInfo_menu_viewADN">View SIM Address Book</string>
@@ -2179,7 +2186,6 @@
     <!-- Radio Info screen. Label for a status item.  Used for diagnostic info screens, precise translation isn't needed -->
     <string name="radio_info_smsc_refresh_label">Refresh</string>
     <!-- Radio Info screen. Label for a status item.  Used for diagnostic info screens, precise translation isn't needed -->
-    <string name="radio_info_toggle_dns_check_label">Toggle DNS Check</string>
     <!-- Radio Info screen. Label for a status item.  Used for diagnostic info screens, precise translation isn't needed -->
     <string name="oem_radio_info_label">OEM-specific Info/Settings</string>
     <!-- Radio Info screen. Label for a status item.  Used for diagnostic info screens, precise translation isn't needed -->
diff --git a/res/values/styles.xml b/res/values/styles.xml
index 435e3a61a..088a5a7a1 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -369,4 +369,9 @@
         <item name="android:textColor">@android:color/white</item>
         <item name="android:textSize">@dimen/emergency_shortcut_tap_hint_text_size</item>
     </style>
+
+    <!--    <style name="RadioInfoTheme" parent="@android:style/Theme.DeviceDefault.DayNight">-->
+    <style name="RadioInfoTheme" parent="Theme.AppCompat.DayNight">
+        <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
+    </style>
 </resources>
diff --git a/src/com/android/phone/CallFeaturesSetting.java b/src/com/android/phone/CallFeaturesSetting.java
index 1dfcde7ef..1c5525689 100644
--- a/src/com/android/phone/CallFeaturesSetting.java
+++ b/src/com/android/phone/CallFeaturesSetting.java
@@ -35,6 +35,7 @@ import android.os.Handler;
 import android.os.HandlerExecutor;
 import android.os.Looper;
 import android.os.PersistableBundle;
+import android.os.UserHandle;
 import android.os.UserManager;
 import android.preference.Preference;
 import android.preference.PreferenceActivity;
@@ -233,7 +234,7 @@ public class CallFeaturesSetting extends PreferenceActivity
                                         getString(R.string.mobile_network_settings_package),
                                         getString(R.string.mobile_network_settings_class));
                                 intent.setComponent(mobileNetworkSettingsComponent);
-                                startActivity(intent);
+                                startActivityAsUser(intent, UserHandle.CURRENT);
                             }
                         };
                 builder.setMessage(getResourcesForSubId().getString(
@@ -622,7 +623,7 @@ public class CallFeaturesSetting extends PreferenceActivity
         Intent intent = subscriptionInfoHelper.getIntent(CallFeaturesSetting.class);
         intent.setAction(Intent.ACTION_MAIN);
         intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
-        activity.startActivity(intent);
+        activity.startActivityAsUser(intent, UserHandle.CURRENT);
         activity.finish();
     }
 
diff --git a/src/com/android/phone/CarrierConfigLoader.java b/src/com/android/phone/CarrierConfigLoader.java
index 47fd96e8e..c6c26b093 100644
--- a/src/com/android/phone/CarrierConfigLoader.java
+++ b/src/com/android/phone/CarrierConfigLoader.java
@@ -44,7 +44,6 @@ import android.os.Looper;
 import android.os.Message;
 import android.os.PermissionEnforcer;
 import android.os.PersistableBundle;
-import android.os.Process;
 import android.os.RemoteException;
 import android.os.ResultReceiver;
 import android.os.SystemProperties;
@@ -1345,7 +1344,10 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
             return new PersistableBundle();
         }
 
-        enforceTelephonyFeatureWithException(callingPackage, "getConfigForSubIdWithFeature");
+        if (!mContext.getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(callingPackage, "getConfigForSubIdWithFeature");
+        }
 
         int phoneId = SubscriptionManager.getPhoneId(subscriptionId);
         PersistableBundle retConfig = CarrierConfigManager.getDefaultConfig();
@@ -1495,10 +1497,8 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
         if (!SubscriptionManager.isValidPhoneId(phoneId)) {
             final String msg =
                     "Ignore invalid phoneId: " + phoneId + " for subId: " + subscriptionId;
-            if (mFeatureFlags.addAnomalyWhenNotifyConfigChangedWithInvalidPhone()) {
-                AnomalyReporter.reportAnomaly(
-                        UUID.fromString(UUID_NOTIFY_CONFIG_CHANGED_WITH_INVALID_PHONE), msg);
-            }
+            AnomalyReporter.reportAnomaly(
+                    UUID.fromString(UUID_NOTIFY_CONFIG_CHANGED_WITH_INVALID_PHONE), msg);
             logd(msg);
             throw new IllegalArgumentException(msg);
         }
@@ -1758,12 +1758,14 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
     private void enforceCallerIsSystemOrRequestingPackage(@NonNull String requestingPackage)
             throws SecurityException {
         final int callingUid = Binder.getCallingUid();
-        if (callingUid == Process.ROOT_UID || callingUid == Process.SYSTEM_UID
-                || callingUid == Process.SHELL_UID || callingUid == Process.PHONE_UID) {
-            // Bug reports (dumpstate.cpp) run as SHELL, and let some other privileged UIDs through
-            // as well.
+        if (TelephonyPermissions.isRootOrShell(callingUid)
+                || TelephonyPermissions.isSystemOrPhone(
+                callingUid)) {
+            // Bug reports (dumpstate.cpp) run as SHELL, and let some other privileged UIDs
+            // through as well.
             return;
         }
+
         // An app is trying to dump extra detail, block it if they aren't who they claim to be.
         AppOpsManager appOps = mContext.getSystemService(AppOpsManager.class);
         if (appOps == null) {
@@ -1870,9 +1872,16 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
      */
     @Nullable
     private String getCurrentPackageName() {
+        if (mFeatureFlags.hsumPackageManager()) {
+            PackageManager pm = mContext.createContextAsUser(Binder.getCallingUserHandle(), 0)
+                    .getPackageManager();
+            if (pm == null) return null;
+            String[] callingPackageNames = pm.getPackagesForUid(Binder.getCallingUid());
+            return (callingPackageNames == null) ? null : callingPackageNames[0];
+        }
         if (mPackageManager == null) return null;
-        String[] callingUids = mPackageManager.getPackagesForUid(Binder.getCallingUid());
-        return (callingUids == null) ? null : callingUids[0];
+        String[] callingPackageNames = mPackageManager.getPackagesForUid(Binder.getCallingUid());
+        return (callingPackageNames == null) ? null : callingPackageNames[0];
     }
 
     /**
diff --git a/src/com/android/phone/EmergencyCallbackModeService.java b/src/com/android/phone/EmergencyCallbackModeService.java
index 464db6f94..70eb017c5 100644
--- a/src/com/android/phone/EmergencyCallbackModeService.java
+++ b/src/com/android/phone/EmergencyCallbackModeService.java
@@ -129,9 +129,9 @@ public class EmergencyCallbackModeService extends Service {
             // Show dialog box
             else if (intent.getAction().equals(
                     TelephonyIntents.ACTION_SHOW_NOTICE_ECM_BLOCK_OTHERS)) {
-                    context.startActivity(
+                    context.startActivityAsUser(
                             new Intent(TelephonyIntents.ACTION_SHOW_NOTICE_ECM_BLOCK_OTHERS)
-                    .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
+                                    .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK), UserHandle.CURRENT);
             }
         }
     };
diff --git a/src/com/android/phone/EmergencyDialer.java b/src/com/android/phone/EmergencyDialer.java
index a608b1bd1..d4fdca6b2 100644
--- a/src/com/android/phone/EmergencyDialer.java
+++ b/src/com/android/phone/EmergencyDialer.java
@@ -40,6 +40,7 @@ import android.net.Uri;
 import android.os.AsyncTask;
 import android.os.Bundle;
 import android.os.PersistableBundle;
+import android.os.UserHandle;
 import android.provider.Settings;
 import android.telecom.PhoneAccount;
 import android.telecom.TelecomManager;
@@ -511,7 +512,7 @@ public class EmergencyDialer extends Activity implements View.OnClickListener,
 
         Intent intent = (Intent) button.getTag(R.id.tag_intent);
         if (intent != null) {
-            startActivity(intent);
+            startActivityAsUser(intent, UserHandle.CURRENT);
         }
     }
 
diff --git a/src/com/android/phone/ImsProvisioningController.java b/src/com/android/phone/ImsProvisioningController.java
index d2c720b40..ea6063314 100644
--- a/src/com/android/phone/ImsProvisioningController.java
+++ b/src/com/android/phone/ImsProvisioningController.java
@@ -49,9 +49,11 @@ import android.os.Message;
 import android.os.PersistableBundle;
 import android.os.RemoteCallbackList;
 import android.os.RemoteException;
+import android.telephony.AnomalyReporter;
 import android.telephony.CarrierConfigManager;
 import android.telephony.CarrierConfigManager.Ims;
 import android.telephony.SubscriptionManager;
+import android.telephony.TelephonyManager;
 import android.telephony.TelephonyRegistryManager;
 import android.telephony.ims.ProvisioningManager;
 import android.telephony.ims.aidl.IFeatureProvisioningCallback;
@@ -76,6 +78,7 @@ import com.android.telephony.Rlog;
 
 import java.util.Arrays;
 import java.util.Map;
+import java.util.UUID;
 import java.util.concurrent.Executor;
 
 /**
@@ -154,6 +157,10 @@ public class ImsProvisioningController {
             CAPABILITY_TYPE_PRESENCE_UCE, Ims.KEY_CAPABILITY_TYPE_PRESENCE_UCE_INT_ARRAY
     );
 
+    private static final UUID VOLTE_PROVISIONING_ANOMALY =
+            UUID.fromString("f5f90e4d-3d73-4f63-a0f9-cbe1941ca57c");
+    private static final String VOLTE_PROVISIONING_ANOMALY_DESC = "VoLTE is Not Provisioned";
+
     /**
      * Create a FeatureConnector for this class to use to connect to an ImsManager.
      */
@@ -249,7 +256,7 @@ public class ImsProvisioningController {
                                         (FeatureProvisioningData) msg.obj);
                     } catch (NullPointerException e) {
                         logw(LOG_PREFIX, msg.arg1,
-                                "can not find callback manager message" + msg.what);
+                                "can not find callback manager, message" + msg.what);
                     }
                     break;
                 case EVENT_MULTI_SIM_CONFIGURATION_CHANGE:
@@ -257,9 +264,11 @@ public class ImsProvisioningController {
                     onMultiSimConfigChanged(activeModemCount);
                     break;
                 case EVENT_PROVISIONING_VALUE_CHANGED:
-                    log("subId " + msg.arg1 + " changed provisioning value item : " + msg.arg2
+                    logAttr("ImsConfig", "EVENT_PROVISIONING_VALUE_CHANGED", msg.arg1,
+                            "changed provisioning value, item : " + msg.arg2
                             + " value : " + (int) msg.obj);
-                    updateCapabilityTechFromKey(msg.arg1, msg.arg2, (int) msg.obj);
+                    updateCapabilityTechFromKey("ImsConfig[" + msg.arg1 + "]",
+                            msg.arg1, msg.arg2, (int) msg.obj);
                     break;
                 case EVENT_NOTIFY_INIT_PROVISIONED_VALUE:
                     int slotId = msg.arg1;
@@ -419,7 +428,6 @@ public class ImsProvisioningController {
             }
 
             mSubId = subId;
-            mSlotId = getSlotId(subId);
             mConfigCallback.setSubId(subId);
         }
 
@@ -531,7 +539,9 @@ public class ImsProvisioningController {
 
                 if (mFeatureFlags.notifyInitialImsProvisioningStatus()) {
                     // Notify MmTel provisioning value based on capability and radio tech.
-                    if (mProvisioningCallbackManagersSlotMap.get(mSlotId).hasCallblacks()) {
+                    ProvisioningCallbackManager p =
+                            mProvisioningCallbackManagersSlotMap.get(mSlotId);
+                    if (p != null && p.hasCallblacks()) {
                         notifyMmTelProvisioningStatus(mSlotId, mSubId, null);
                     }
                 }
@@ -658,7 +668,6 @@ public class ImsProvisioningController {
             }
 
             mSubId = subId;
-            mSlotId = getSlotId(subId);
             mConfigCallback.setSubId(subId);
         }
 
@@ -769,7 +778,9 @@ public class ImsProvisioningController {
                 setInitialProvisioningKeys(mSubId);
 
                 if (mFeatureFlags.notifyInitialImsProvisioningStatus()) {
-                    if (mProvisioningCallbackManagersSlotMap.get(mSlotId).hasCallblacks()) {
+                    ProvisioningCallbackManager p =
+                            mProvisioningCallbackManagersSlotMap.get(mSlotId);
+                    if (p != null && p.hasCallblacks()) {
                         // Notify RCS provisioning value based on capability and radio tech.
                         notifyRcsProvisioningStatus(mSlotId, mSubId, null);
                     }
@@ -1134,11 +1145,12 @@ public class ImsProvisioningController {
      * return the provisioning status for MmTel capability in specific radio tech
      */
     @VisibleForTesting
-    public boolean getImsProvisioningStatusForCapability(int subId, int capability, int tech) {
+    public boolean getImsProvisioningStatusForCapability(String attributionPackage, int subId,
+            int capability, int tech) {
         boolean mmTelProvisioned = isImsProvisioningRequiredForCapability(subId, capability, tech);
         if (!mmTelProvisioned) { // provisioning not required
-            log("getImsProvisioningStatusForCapability : not required "
-                    + " capability " + capability + " tech " + tech);
+            logAttr(attributionPackage, "getImsProvisioningStatusForCapability", subId,
+                    " not required, capability " + capability + " tech " + tech);
             return true;
         }
 
@@ -1151,14 +1163,15 @@ public class ImsProvisioningController {
             result = getValueFromImsService(subId, capability, tech);
             mmTelProvisioned = getBoolValue(result);
             if (result != ProvisioningManager.PROVISIONING_RESULT_UNKNOWN) {
-                setAndNotifyMmTelProvisioningValue(subId, capability, tech, mmTelProvisioned);
+                setAndNotifyMmTelProvisioningValue(attributionPackage, subId, capability, tech,
+                        mmTelProvisioned);
             }
         } else {
             mmTelProvisioned = getBoolValue(result);
         }
 
-        log("getImsProvisioningStatusForCapability : "
-                + " capability " + capability
+        logAttr(attributionPackage, "getImsProvisioningStatusForCapability", subId,
+                " capability " + capability
                 + " tech " + tech
                 + " result " + mmTelProvisioned);
         return mmTelProvisioned;
@@ -1168,20 +1181,21 @@ public class ImsProvisioningController {
      * set MmTel provisioning status in specific tech
      */
     @VisibleForTesting
-    public void setImsProvisioningStatusForCapability(int subId, int capability, int tech,
-            boolean isProvisioned) {
+    public void setImsProvisioningStatusForCapability(String attributionPackage, int subId,
+            int capability, int tech, boolean isProvisioned) {
         boolean mmTelProvisioned = isImsProvisioningRequiredForCapability(subId, capability, tech);
         if (!mmTelProvisioned) { // provisioning not required
-            log("setImsProvisioningStatusForCapability : not required "
-                    + " capability " + capability + " tech " + tech);
+            logAttr(attributionPackage, "setImsProvisioningStatusForCapability", subId,
+                    "not required, capability " + capability + " tech " + tech);
             return;
         }
 
         // write value to ImsProvisioningLoader
-        boolean isChanged = setAndNotifyMmTelProvisioningValue(subId, capability, tech,
-                isProvisioned);
+        boolean isChanged = setAndNotifyMmTelProvisioningValue(attributionPackage, subId,
+                capability, tech, isProvisioned);
         if (!isChanged) {
-            log("status not changed mmtel capability " + capability + " tech " + tech);
+            logAttr(attributionPackage, "setImsProvisioningStatusForCapability", subId,
+                    "status not changed, capability " + capability + " tech " + tech);
             return;
         }
 
@@ -1190,7 +1204,8 @@ public class ImsProvisioningController {
         int value = getIntValue(isProvisioned);
         int key = getKeyFromCapability(capability, tech);
         if (key != INVALID_VALUE) {
-            log("setImsProvisioningStatusForCapability : matched key " + key);
+            logAttr(attributionPackage, "setImsProvisioningStatusForCapability", subId,
+                    "matched key " + key);
             try {
                 // set key and value to vendor ImsService for MmTel
                 mMmTelFeatureListenersSlotMap.get(slotId).setProvisioningValue(key, value);
@@ -1289,20 +1304,22 @@ public class ImsProvisioningController {
      * {@link ImsConfigImplBase#CONFIG_RESULT_SUCCESS} or
      */
     @VisibleForTesting
-    public int setProvisioningValue(int subId, int key, int value) {
-        log("setProvisioningValue");
+    public int setProvisioningValue(String attributionPackage, int subId, int key, int value) {
+        logAttr(attributionPackage, "setProvisioningValue", subId, key + ": " + value);
 
         int retVal = ImsConfigImplBase.CONFIG_RESULT_FAILED;
         // check key value
         if (!Arrays.stream(LOCAL_IMS_CONFIG_KEYS).anyMatch(keyValue -> keyValue == key)) {
-            log("not matched key " + key);
+            logAttr(attributionPackage, "setProvisioningValue", subId,
+                    "not matched key " + key);
             return ImsConfigImplBase.CONFIG_RESULT_UNKNOWN;
         }
 
         // check subId
         int slotId = getSlotId(subId);
         if (slotId <= SubscriptionManager.INVALID_SIM_SLOT_INDEX || slotId >= mNumSlot) {
-            loge("Fail to retrieve slotId from subId");
+            logAttrE(attributionPackage, "setProvisioningValue", subId,
+                    "Fail to retrieve slotId from subId");
             return ImsConfigImplBase.CONFIG_RESULT_FAILED;
         }
 
@@ -1324,12 +1341,13 @@ public class ImsProvisioningController {
                 retVal = mRcsFeatureListenersSlotMap.get(slotId).setProvisioningValue(key, value);
             }
         } catch (NullPointerException e) {
-            loge("can not access FeatureListener to set provisioning value");
+            logAttrE(attributionPackage, "setProvisioningValue", subId,
+                    "can not access FeatureListener to set provisioning value");
             return ImsConfigImplBase.CONFIG_RESULT_FAILED;
         }
 
         // update and notify provisioning status changed capability and tech from key
-        updateCapabilityTechFromKey(subId, key, value);
+        updateCapabilityTechFromKey(attributionPackage, subId, key, value);
 
         return retVal;
     }
@@ -1347,17 +1365,19 @@ public class ImsProvisioningController {
      * {@link ImsConfigImplBase#CONFIG_RESULT_UNKNOWN}
      */
     @VisibleForTesting
-    public int getProvisioningValue(int subId, int key) {
+    public int getProvisioningValue(String attributionPackage, int subId, int key) {
         // check key value
         if (!Arrays.stream(LOCAL_IMS_CONFIG_KEYS).anyMatch(keyValue -> keyValue == key)) {
-            log("not matched key " + key);
+            logAttr(attributionPackage, "getProvisioningValue", subId,
+                    "not matched key " + key);
             return ImsConfigImplBase.CONFIG_RESULT_UNKNOWN;
         }
 
         // check subId
         int slotId = getSlotId(subId);
         if (slotId <= SubscriptionManager.INVALID_SIM_SLOT_INDEX || slotId >= mNumSlot) {
-            loge("Fail to retrieve slotId from subId");
+            logAttrE(attributionPackage, "getProvisioningValue", subId,
+                    "Fail to retrieve slotId from subId");
             return ImsConfigImplBase.CONFIG_RESULT_UNKNOWN;
         }
 
@@ -1374,7 +1394,8 @@ public class ImsProvisioningController {
                         capability, tech);
             }
             if (result != ImsProvisioningLoader.STATUS_NOT_SET) {
-                log("getProvisioningValue from loader : key " + key + " result " + result);
+                logAttr(attributionPackage, "getProvisioningValue", subId,
+                        "cache hit : key=" + key + ": value=" + result);
                 return result;
             }
         }
@@ -1383,24 +1404,27 @@ public class ImsProvisioningController {
         if (key == KEY_EAB_PROVISIONING_STATUS) {
             result = getRcsValueFromImsService(subId, capability);
             if (result == ImsConfigImplBase.CONFIG_RESULT_UNKNOWN) {
-                logw("getProvisioningValue : fail to get data from ImsService capability"
-                        + capability);
+                logAttrW(attributionPackage, "getProvisioningValue", subId,
+                        "fail to get data from ImsService, capability=" + capability);
                 return result;
             }
-            log("getProvisioningValue from vendor : key " + key + " result " + result);
+            logAttr(attributionPackage, "getProvisioningValue", subId,
+                    "cache miss, get from RCS - key=" + key + ": value=" + result);
 
             setAndNotifyRcsProvisioningValueForAllTech(subId, capability, getBoolValue(result));
             return result;
         } else {
             result = getValueFromImsService(subId, capability, tech);
             if (result == ImsConfigImplBase.CONFIG_RESULT_UNKNOWN) {
-                logw("getProvisioningValue : fail to get data from ImsService capability"
-                        + capability);
+                logAttrW(attributionPackage, "getProvisioningValue", subId,
+                        "fail to get data from ImsService, capability=" + capability);
                 return result;
             }
-            log("getProvisioningValue from vendor : key " + key + " result " + result);
+            logAttr(attributionPackage, "getProvisioningValue", subId,
+                    "cache miss, get from MMTEL - key=" + key + ": value=" + result);
 
-            setAndNotifyMmTelProvisioningValue(subId, capability, tech, getBoolValue(result));
+            setAndNotifyMmTelProvisioningValue(attributionPackage, subId, capability, tech,
+                    getBoolValue(result));
             return result;
         }
     }
@@ -1529,20 +1553,23 @@ public class ImsProvisioningController {
         }
     }
 
-    private void  updateCapabilityTechFromKey(int subId, int key, int value) {
+    private void  updateCapabilityTechFromKey(String attributionPackage, int subId, int key,
+            int value) {
         boolean isProvisioned = getBoolValue(value);
         int capability = getCapabilityFromKey(key);
         int tech = getTechFromKey(key);
 
         if (capability == INVALID_VALUE || tech == INVALID_VALUE) {
-            logw("updateCapabilityTechFromKey : unknown key " + key);
+            logAttrW(attributionPackage, "updateCapabilityTechFromKey", subId,
+                    "unknown key " + key);
             return;
         }
 
         if (key == KEY_VOLTE_PROVISIONING_STATUS
                 || key == KEY_VT_PROVISIONING_STATUS
                 || key == KEY_VOICE_OVER_WIFI_ENABLED_OVERRIDE) {
-            setAndNotifyMmTelProvisioningValue(subId, capability, tech, isProvisioned);
+            setAndNotifyMmTelProvisioningValue(attributionPackage, subId, capability, tech,
+                    isProvisioned);
         }
         if (key == KEY_EAB_PROVISIONING_STATUS) {
             setAndNotifyRcsProvisioningValueForAllTech(subId, capability, isProvisioned);
@@ -1629,12 +1656,33 @@ public class ImsProvisioningController {
         return value == ProvisioningManager.PROVISIONING_VALUE_ENABLED ? true : false;
     }
 
-    private boolean setAndNotifyMmTelProvisioningValue(int subId, int capability, int tech,
+    // If VoLTE is not provisioned, generate an anomaly report as this is not expected.
+    private void checkProvisioningValueForAnomaly(String attributionPackage, int subId,
+            int capability, int tech, boolean isProvisioned) {
+        if (isProvisioned) return;
+        boolean isVolte = capability == CAPABILITY_TYPE_VOICE && tech == REGISTRATION_TECH_LTE;
+        if (!isVolte) return;
+        // We have hit the condition where VoLTE has been de-provisioned
+        int carrierId = TelephonyManager.UNKNOWN_CARRIER_ID;
+        TelephonyManager manager = mApp.getSystemService(TelephonyManager.class);
+        if (manager != null) {
+            carrierId = manager.createForSubscriptionId(subId).getSimCarrierId();
+        }
+        logAttrW(attributionPackage, "checkProvisioningValueForAnomaly", subId,
+                "VoLTE provisioning disabled");
+        AnomalyReporter.reportAnomaly(VOLTE_PROVISIONING_ANOMALY,
+                VOLTE_PROVISIONING_ANOMALY_DESC, carrierId);
+    }
+
+    private boolean setAndNotifyMmTelProvisioningValue(String attributionPackage, int subId,
+            int capability, int tech,
             boolean isProvisioned) {
         boolean changed = mImsProvisioningLoader.setProvisioningStatus(subId, FEATURE_MMTEL,
                 capability, tech, isProvisioned);
         // notify MmTel capability changed
         if (changed) {
+            checkProvisioningValueForAnomaly(attributionPackage, subId, capability, tech,
+                    isProvisioned);
             mHandler.sendMessage(mHandler.obtainMessage(EVENT_PROVISIONING_CAPABILITY_CHANGED,
                     getSlotId(subId), 0, (Object) new FeatureProvisioningData(
                             capability, tech, isProvisioned, /*isMmTel*/true)));
@@ -1764,6 +1812,18 @@ public class ImsProvisioningController {
         }
     }
 
+    private void logAttr(String attr, String prefix, int subId, String log) {
+        Rlog.d(TAG, prefix + "[" + subId + "]: " + log + ", attr = [" + attr + "]");
+    }
+
+    private void logAttrW(String attr, String prefix, int subId, String log) {
+        Rlog.w(TAG, prefix + "[" + subId + "]: " + log + ", attr = [" + attr + "]");
+    }
+
+    private void logAttrE(String attr, String prefix, int subId, String log) {
+        Rlog.e(TAG, prefix + "[" + subId + "]: " + log + ", attr = [" + attr + "]");
+    }
+
     private void log(String s) {
         Rlog.d(TAG, s);
     }
diff --git a/src/com/android/phone/ImsProvisioningLoader.java b/src/com/android/phone/ImsProvisioningLoader.java
index 1238b9a98..8d634637c 100644
--- a/src/com/android/phone/ImsProvisioningLoader.java
+++ b/src/com/android/phone/ImsProvisioningLoader.java
@@ -113,7 +113,7 @@ public class ImsProvisioningLoader {
                     logd("check UT provisioning status " + UtProvisioningStatus);
 
                     if (STATUS_PROVISIONED == UtProvisioningStatus) {
-                        setProvisioningStatusToSubIdBundle(ImsFeature.FEATURE_MMTEL, tech,
+                        setProvisioningStatusToSubIdBundle(subId, ImsFeature.FEATURE_MMTEL, tech,
                                 MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_UT, subIdBundle,
                                 UtProvisioningStatus);
                     }
@@ -130,7 +130,7 @@ public class ImsProvisioningLoader {
             subIdBundle = mSubIdBundleArray.get(subId, null);
         }
 
-        return getProvisioningStatusFromSubIdBundle(imsFeature, tech,
+        return getProvisioningStatusFromSubIdBundle(subId, imsFeature, tech,
                 capability, subIdBundle);
     }
 
@@ -146,42 +146,44 @@ public class ImsProvisioningLoader {
             }
 
             PersistableBundle subIdBundle = mSubIdBundleArray.get(subId, null);
-            setProvisioningStatusToSubIdBundle(imsFeature, tech, capability, subIdBundle,
+            setProvisioningStatusToSubIdBundle(subId, imsFeature, tech, capability, subIdBundle,
                     newValue);
             saveSubIdBundleToXml(subId, subIdBundle);
         }
         return true;
     }
 
-    private int getProvisioningStatusFromSubIdBundle(int imsFeature, int tech,
+    private int getProvisioningStatusFromSubIdBundle(int subId, int imsFeature, int tech,
             int capability, PersistableBundle subIdBundle) {
         // If it doesn't exist in xml, return STATUS_NOT_SET
         if (subIdBundle == null || subIdBundle.isEmpty()) {
-            logd("xml is empty");
+            logd("getProvisioningStatusFromSubIdBundle", subId, "xml is empty");
             return STATUS_NOT_SET;
         }
 
         PersistableBundle regTechBundle = subIdBundle.getPersistableBundle(
                 String.valueOf(imsFeature));
         if (regTechBundle == null) {
-            logd("ImsFeature " + imsFeature + " is not exist in xml");
+            logd("getProvisioningStatusFromSubIdBundle", subId,
+                    "ImsFeature " + imsFeature + " does not exist in xml");
             return STATUS_NOT_SET;
         }
 
         PersistableBundle capabilityBundle = regTechBundle.getPersistableBundle(
                 String.valueOf(tech));
         if (capabilityBundle == null) {
-            logd("RegistrationTech " + tech + " is not exist in xml");
+            logd("getProvisioningStatusFromSubIdBundle", subId,
+                    "RegistrationTech " + tech + " does not exist in xml");
             return STATUS_NOT_SET;
         }
 
-        return getIntValueFromBundle(String.valueOf(capability), capabilityBundle);
+        return getIntValueFromBundle(subId, tech, String.valueOf(capability), capabilityBundle);
     }
 
-    private void setProvisioningStatusToSubIdBundle(int imsFeature, int tech,
+    private void setProvisioningStatusToSubIdBundle(int subId, int imsFeature, int tech,
             int capability, PersistableBundle subIdBundle, int newStatus) {
-        logd("set provisioning status " + newStatus + " ImsFeature "
-                + imsFeature + " tech " + tech + " capa " + capability);
+        logd("setProvisioningStatusToSubIdBundle", subId, "set provisioning status " + newStatus
+                + " ImsFeature " + imsFeature + " tech " + tech + " capa " + capability);
 
         PersistableBundle regTechBundle = subIdBundle.getPersistableBundle(
                 String.valueOf(imsFeature));
@@ -201,9 +203,10 @@ public class ImsProvisioningLoader {
     }
 
     // Default value is STATUS_NOT_SET
-    private int getIntValueFromBundle(String key, PersistableBundle bundle) {
+    private int getIntValueFromBundle(int subId, int tech, String key, PersistableBundle bundle) {
         int value = bundle.getInt(key, STATUS_NOT_SET);
-        logd("get value " + value);
+        logd("getIntValueFromBundle", subId,
+                "Cache hit, tech=" + tech + " capability=" + key + ": returning " + value);
         return value;
     }
 
@@ -293,7 +296,7 @@ public class ImsProvisioningLoader {
             String[] infoArray) {
         for (String info : infoArray) {
             String[] paramArray = info.split(",");
-            setProvisioningStatusToSubIdBundle(Integer.valueOf(paramArray[0]),
+            setProvisioningStatusToSubIdBundle(subId, Integer.valueOf(paramArray[0]),
                     Integer.valueOf(paramArray[1]), Integer.valueOf(paramArray[2]),
                     subIdBundle, Integer.valueOf(paramArray[3]));
         }
@@ -304,6 +307,10 @@ public class ImsProvisioningLoader {
         Log.e(LOG_TAG, contents);
     }
 
+    private void logd(String prefix, int subId, String contents) {
+        Log.d(LOG_TAG, prefix + "[" + subId + "]: " + contents);
+    }
+
     private void logd(String contents) {
         Log.d(LOG_TAG, contents);
     }
diff --git a/src/com/android/phone/ImsRcsController.java b/src/com/android/phone/ImsRcsController.java
index 766d71949..e2ae34355 100644
--- a/src/com/android/phone/ImsRcsController.java
+++ b/src/com/android/phone/ImsRcsController.java
@@ -986,9 +986,16 @@ public class ImsRcsController extends IImsRcsController.Stub {
      */
     @Nullable
     private String getCurrentPackageName() {
+        if (mFeatureFlags.hsumPackageManager()) {
+            PackageManager pm = mApp.getBaseContext().createContextAsUser(
+                    Binder.getCallingUserHandle(), 0).getPackageManager();
+            if (pm == null) return null;
+            String[] callingPackageNames = pm.getPackagesForUid(Binder.getCallingUid());
+            return (callingPackageNames == null) ? null : callingPackageNames[0];
+        }
         if (mPackageManager == null) return null;
-        String[] callingUids = mPackageManager.getPackagesForUid(Binder.getCallingUid());
-        return (callingUids == null) ? null : callingUids[0];
+        String[] callingPackageNames = mPackageManager.getPackagesForUid(Binder.getCallingUid());
+        return (callingPackageNames == null) ? null : callingPackageNames[0];
     }
 
     /**
diff --git a/src/com/android/phone/ImsStateCallbackController.java b/src/com/android/phone/ImsStateCallbackController.java
index 019c1cab5..2dca102f8 100644
--- a/src/com/android/phone/ImsStateCallbackController.java
+++ b/src/com/android/phone/ImsStateCallbackController.java
@@ -59,6 +59,7 @@ import com.android.internal.telephony.IImsStateCallback;
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneConfigurationManager;
 import com.android.internal.telephony.PhoneFactory;
+import com.android.internal.telephony.flags.FeatureFlags;
 import com.android.internal.telephony.ims.ImsResolver;
 import com.android.internal.telephony.util.HandlerExecutor;
 import com.android.internal.util.IndentingPrintWriter;
@@ -159,6 +160,8 @@ public class ImsStateCallbackController {
 
     private int mNumSlots;
 
+    private final FeatureFlags mFeatureFlags;
+
     private BroadcastReceiver mReceiver = new BroadcastReceiver() {
         @Override
         public void onReceive(Context context, Intent intent) {
@@ -287,11 +290,13 @@ public class ImsStateCallbackController {
             if (mSubId == subId) return;
             logd(mLogPrefix + "setSubId changed subId=" + subId);
 
-            // subId changed from valid to invalid
-            if (subId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
-                if (VDBG) logv(mLogPrefix + "setSubId remove ImsManager " + mSubId);
-                // remove ImsManager reference associated with subId
-                mSubIdToImsManagerCache.remove(mSubId);
+            if (!mFeatureFlags.avoidDeletingImsObjectFromCache()) {
+                // subId changed from valid to invalid
+                if (subId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
+                    if (VDBG) logv(mLogPrefix + "setSubId remove ImsManager " + mSubId);
+                    // remove ImsManager reference associated with subId
+                    mSubIdToImsManagerCache.remove(mSubId);
+                }
             }
 
             mSubId = subId;
@@ -709,7 +714,8 @@ public class ImsStateCallbackController {
     /**
      * create an instance
      */
-    public static ImsStateCallbackController make(PhoneGlobals app, int numSlots) {
+    public static ImsStateCallbackController make(PhoneGlobals app, int numSlots,
+            FeatureFlags featureFlags) {
         synchronized (ImsStateCallbackController.class) {
             if (sInstance == null) {
                 logd("ImsStateCallbackController created");
@@ -718,7 +724,7 @@ public class ImsStateCallbackController {
                 handlerThread.start();
                 sInstance = new ImsStateCallbackController(app, handlerThread.getLooper(), numSlots,
                         ImsManager::getConnector, RcsFeatureManager::getConnector,
-                        ImsResolver.getInstance());
+                        ImsResolver.getInstance(), featureFlags);
             }
         }
         return sInstance;
@@ -727,7 +733,7 @@ public class ImsStateCallbackController {
     @VisibleForTesting
     public ImsStateCallbackController(PhoneGlobals app, Looper looper, int numSlots,
             MmTelFeatureConnectorFactory mmTelFactory, RcsFeatureConnectorFactory rcsFactory,
-            ImsResolver imsResolver) {
+            ImsResolver imsResolver, FeatureFlags featureFlags) {
         mApp = app;
         mHandler = new MyHandler(looper);
         mImsResolver = imsResolver;
@@ -735,6 +741,7 @@ public class ImsStateCallbackController {
         mTelephonyRegistryManager = mApp.getSystemService(TelephonyRegistryManager.class);
         mMmTelFeatureFactory = mmTelFactory;
         mRcsFeatureFactory = rcsFactory;
+        mFeatureFlags = featureFlags;
 
         updateFeatureControllerSize(numSlots);
 
diff --git a/src/com/android/phone/NotificationMgr.java b/src/com/android/phone/NotificationMgr.java
index 3cd9a8bf0..3c7b321c7 100644
--- a/src/com/android/phone/NotificationMgr.java
+++ b/src/com/android/phone/NotificationMgr.java
@@ -519,8 +519,14 @@ public class NotificationMgr {
             return false;
         }
 
-        List<ResolveInfo> receivers = mContext.getPackageManager()
-                .queryBroadcastReceivers(intent, 0);
+        List<ResolveInfo> receivers;
+        if (mFeatureFlags.hsumPackageManager()) {
+            receivers = mContext.createContextAsUser(userHandle, 0)
+                    .getPackageManager().queryBroadcastReceivers(intent, 0);
+        } else {
+            receivers = mContext.getPackageManager()
+                    .queryBroadcastReceivers(intent, 0);
+        }
         return receivers.size() > 0;
     }
 
diff --git a/src/com/android/phone/PhoneGlobals.java b/src/com/android/phone/PhoneGlobals.java
index d0d92c6b5..0433a3308 100644
--- a/src/com/android/phone/PhoneGlobals.java
+++ b/src/com/android/phone/PhoneGlobals.java
@@ -600,7 +600,7 @@ public class PhoneGlobals extends ContextWrapper {
                         }
                     }
                 }
-                RcsProvisioningMonitor.make(this);
+                RcsProvisioningMonitor.make(this, mFeatureFlags);
             }
 
             // Start TelephonyDebugService After the default phone is created.
@@ -638,7 +638,8 @@ public class PhoneGlobals extends ContextWrapper {
 
             if (getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY_IMS)) {
                 mImsStateCallbackController =
-                        ImsStateCallbackController.make(this, PhoneFactory.getPhones().length);
+                        ImsStateCallbackController.make(this, PhoneFactory.getPhones().length,
+                                mFeatureFlags);
                 mTelephonyRcsService = new TelephonyRcsService(this,
                         PhoneFactory.getPhones().length, mFeatureFlags);
                 mTelephonyRcsService.initialize();
diff --git a/src/com/android/phone/PhoneInterfaceManager.java b/src/com/android/phone/PhoneInterfaceManager.java
index dc4290d4a..4624884eb 100644
--- a/src/com/android/phone/PhoneInterfaceManager.java
+++ b/src/com/android/phone/PhoneInterfaceManager.java
@@ -25,7 +25,6 @@ import static android.telephony.TelephonyManager.HAL_SERVICE_NETWORK;
 import static android.telephony.TelephonyManager.HAL_SERVICE_RADIO;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_COMMUNICATION_ALLOWED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_ACCESS_BARRED;
-import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_SUCCESS;
 
 import static com.android.internal.telephony.PhoneConstants.PHONE_TYPE_CDMA;
@@ -170,6 +169,7 @@ import android.telephony.satellite.SatelliteDatagram;
 import android.telephony.satellite.SatelliteDatagramCallback;
 import android.telephony.satellite.SatelliteManager;
 import android.telephony.satellite.SatelliteProvisionStateCallback;
+import android.telephony.satellite.SatelliteSubscriberInfo;
 import android.text.TextUtils;
 import android.util.ArraySet;
 import android.util.EventLog;
@@ -479,6 +479,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
     private static final int MODEM_ACTIVITY_TIME_OFFSET_CORRECTION_MS = 50;
 
+    private static final int LINE1_NUMBER_MAX_LEN = 50;
+
     /**
      * With support for MEP(multiple enabled profile) in Android T, a SIM card can have more than
      * one ICCID active at the same time.
@@ -2611,7 +2613,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             if (state != PhoneConstants.State.OFFHOOK && state != PhoneConstants.State.RINGING) {
                 Intent intent = new Intent(Intent.ACTION_DIAL, Uri.parse(url));
                 intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-                mApp.startActivity(intent);
+                mApp.startActivityAsUser(intent, UserHandle.CURRENT);
             }
         } finally {
             Binder.restoreCallingIdentity(identity);
@@ -2626,7 +2628,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         if (DBG) log("call: " + number);
 
         // This is just a wrapper around the ACTION_CALL intent, but we still
-        // need to do a permission check since we're calling startActivity()
+        // need to do a permission check since we're calling startActivityAsUser()
         // from the context of the phone app.
         enforceCallPermission();
 
@@ -2662,7 +2664,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             Intent intent = new Intent(Intent.ACTION_CALL, Uri.parse(url));
             intent.putExtra(SUBSCRIPTION_KEY, subId);
             intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-            mApp.startActivity(intent);
+            mApp.startActivityAsUser(intent, UserHandle.CURRENT);
         } finally {
             Binder.restoreCallingIdentity(identity);
         }
@@ -2992,8 +2994,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public boolean needMobileRadioShutdown() {
         enforceReadPrivilegedPermission("needMobileRadioShutdown");
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "needMobileRadioShutdown");
+        if (!mApp.getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "needMobileRadioShutdown");
+        }
 
         /*
          * If any of the Radios are available, it will need to be
@@ -3198,7 +3203,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         try {
             int subId = SubscriptionManager.getDefaultDataSubscriptionId();
             final Phone phone = getPhone(subId);
-            if (phone != null) {
+            if (phone != null && phone.getDataSettingsManager() != null) {
                 phone.getDataSettingsManager().setDataEnabled(
                         TelephonyManager.DATA_ENABLED_REASON_USER, true, callingPackage);
                 return true;
@@ -3222,7 +3227,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         try {
             int subId = SubscriptionManager.getDefaultDataSubscriptionId();
             final Phone phone = getPhone(subId);
-            if (phone != null) {
+            if (phone != null && phone.getDataSettingsManager() != null) {
                 phone.getDataSettingsManager().setDataEnabled(
                         TelephonyManager.DATA_ENABLED_REASON_USER, false, callingPackage);
                 return true;
@@ -3428,8 +3433,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
     @Override
     public String getNetworkCountryIsoForPhone(int phoneId) {
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "getNetworkCountryIsoForPhone");
+        if (!mApp.getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "getNetworkCountryIsoForPhone");
+        }
 
         // Reporting the correct network country is ambiguous when IWLAN could conflict with
         // registered cell info, so return a NULL country instead.
@@ -3800,8 +3808,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
     @Override
     public int getSubscriptionCarrierId(int subId) {
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, "getSubscriptionCarrierId");
+        if (!mApp.getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, "getSubscriptionCarrierId");
+        }
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -3998,8 +4009,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
     @Override
     public int getActivePhoneTypeForSlot(int slotIndex) {
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY, "getActivePhoneTypeForSlot");
+        if (!mApp.getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY, "getActivePhoneTypeForSlot");
+        }
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -4276,10 +4290,9 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void enableVisualVoicemailSmsFilter(String callingPackage, int subId,
             VisualVoicemailSmsFilterSettings settings) {
         mAppOps.checkPackage(Binder.getCallingUid(), callingPackage);
-
+        enforceVisualVoicemailPackage(callingPackage, subId);
         enforceTelephonyFeatureWithException(callingPackage,
                 PackageManager.FEATURE_TELEPHONY_CALLING, "enableVisualVoicemailSmsFilter");
-
         final long identity = Binder.clearCallingIdentity();
         try {
             VisualVoicemailSmsFilterConfig.enableVisualVoicemailSmsFilter(
@@ -4292,7 +4305,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public void disableVisualVoicemailSmsFilter(String callingPackage, int subId) {
         mAppOps.checkPackage(Binder.getCallingUid(), callingPackage);
-
+        enforceVisualVoicemailPackage(callingPackage, subId);
         enforceTelephonyFeatureWithException(callingPackage,
                 PackageManager.FEATURE_TELEPHONY_CALLING, "disableVisualVoicemailSmsFilter");
 
@@ -4344,8 +4357,9 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                 PackageManager.FEATURE_TELEPHONY_CALLING, "sendVisualVoicemailSmsForSubscriber");
 
         SmsController smsController = PhoneFactory.getSmsController();
-        smsController.sendVisualVoicemailSmsForSubscriber(callingPackage, callingAttributionTag,
-                subId, number, port, text, sentIntent);
+        smsController.sendVisualVoicemailSmsForSubscriber(callingPackage,
+                Binder.getCallingUserHandle().getIdentifier(), callingAttributionTag, subId, number,
+                port, text, sentIntent);
     }
 
     /**
@@ -5458,6 +5472,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         enforceTelephonyFeatureWithException(getCurrentPackageName(),
                 FEATURE_TELEPHONY_IMS, "setImsProvisioningStatusForCapability");
 
+        String displayPackageName = getCurrentPackageNameOrPhone();
         final long identity = Binder.clearCallingIdentity();
         try {
             ImsProvisioningController controller = ImsProvisioningController.getInstance();
@@ -5465,7 +5480,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                 loge("setImsProvisioningStatusForCapability: Device does not support IMS");
                 return;
             }
-            controller.setImsProvisioningStatusForCapability(
+            controller.setImsProvisioningStatusForCapability(displayPackageName,
                     subId, capability, tech, isProvisioned);
         } finally {
             Binder.restoreCallingIdentity(identity);
@@ -5480,6 +5495,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         enforceTelephonyFeatureWithException(getCurrentPackageName(),
                 FEATURE_TELEPHONY_IMS, "getImsProvisioningStatusForCapability");
 
+        String displayPackageName = getCurrentPackageNameOrPhone();
         final long identity = Binder.clearCallingIdentity();
         try {
             ImsProvisioningController controller = ImsProvisioningController.getInstance();
@@ -5489,7 +5505,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                 // device does not support IMS, this method will return true always.
                 return true;
             }
-            return controller.getImsProvisioningStatusForCapability(subId, capability, tech);
+            return controller.getImsProvisioningStatusForCapability(displayPackageName,
+                    subId, capability, tech);
         } finally {
             Binder.restoreCallingIdentity(identity);
         }
@@ -5552,6 +5569,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         enforceTelephonyFeatureWithException(getCurrentPackageName(),
                 FEATURE_TELEPHONY_IMS, "getImsProvisioningInt");
 
+        String displayPackageName = getCurrentPackageNameOrPhone();
         final long identity = Binder.clearCallingIdentity();
         try {
             // TODO: Refactor to remove ImsManager dependence and query through ImsPhone directly.
@@ -5569,7 +5587,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                 // device does not support IMS, this method will return CONFIG_RESULT_UNKNOWN.
                 return ImsConfigImplBase.CONFIG_RESULT_UNKNOWN;
             }
-            int retVal = controller.getProvisioningValue(subId, key);
+            int retVal = controller.getProvisioningValue(displayPackageName, subId,
+                    key);
             if (retVal != ImsConfigImplBase.CONFIG_RESULT_UNKNOWN) {
                 return retVal;
             }
@@ -5625,6 +5644,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         enforceTelephonyFeatureWithException(getCurrentPackageName(),
                 FEATURE_TELEPHONY_IMS, "setImsProvisioningInt");
 
+        String displayPackageName = getCurrentPackageNameOrPhone();
         final long identity = Binder.clearCallingIdentity();
         try {
             // TODO: Refactor to remove ImsManager dependence and query through ImsPhone directly.
@@ -5642,7 +5662,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                 // device does not support IMS, this method will return CONFIG_RESULT_FAILED.
                 return ImsConfigImplBase.CONFIG_RESULT_FAILED;
             }
-            int retVal = controller.setProvisioningValue(subId, key, value);
+            int retVal = controller.setProvisioningValue(displayPackageName, subId, key,
+                    value);
             if (retVal != ImsConfigImplBase.CONFIG_RESULT_UNKNOWN) {
                 return retVal;
             }
@@ -5842,8 +5863,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public boolean hasIccCardUsingSlotIndex(int slotIndex) {
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, "hasIccCardUsingSlotIndex");
+        if (!mApp.getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, "hasIccCardUsingSlotIndex");
+        }
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -7256,8 +7280,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         TelephonyPermissions.enforceCallingOrSelfReadPrecisePhoneStatePermissionOrCarrierPrivilege(
                 mApp, subId, "getAllowedNetworkTypesForReason");
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "getAllowedNetworkTypesForReason");
+        if (!mApp.getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS,
+                            "getAllowedNetworkTypesForReason");
+        }
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -7402,8 +7430,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public boolean isTetheringApnRequiredForSubscriber(int subId) {
         enforceModifyPermission();
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_DATA, "isTetheringApnRequiredForSubscriber");
+        if (!mApp.getResources().getBoolean(
+                    com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_DATA, "isTetheringApnRequiredForSubscriber");
+        }
 
         final long identity = Binder.clearCallingIdentity();
         final Phone phone = getPhone(subId);
@@ -7514,12 +7545,15 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         try {
             int phoneId = SubscriptionManager.getPhoneId(subId);
             Phone phone = PhoneFactory.getPhone(phoneId);
-            if (phone != null) {
+            if (phone != null && phone.getDataSettingsManager() != null) {
                 boolean retVal = phone.getDataSettingsManager().isDataEnabled();
                 if (DBG) log("isDataEnabled: " + retVal + ", subId=" + subId);
                 return retVal;
             } else {
-                if (DBG) loge("isDataEnabled: no phone subId=" + subId + " retVal=false");
+                if (DBG) {
+                    loge("isDataEnabled: no phone or no DataSettingsManager subId="
+                            + subId + " retVal=false");
+                }
                 return false;
             }
         } finally {
@@ -7556,8 +7590,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             }
         }
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_DATA, "isDataEnabledForReason");
+        if (!mApp.getResources().getBoolean(
+                    com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_DATA, "isDataEnabledForReason");
+        }
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -7567,14 +7604,14 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                         + " reason=" + reason);
             }
             Phone phone = PhoneFactory.getPhone(phoneId);
-            if (phone != null) {
+            if (phone != null && phone.getDataSettingsManager() != null) {
                 boolean retVal;
                 retVal = phone.getDataSettingsManager().isDataEnabledForReason(reason);
                 if (DBG) log("isDataEnabledForReason: retVal=" + retVal);
                 return retVal;
             } else {
                 if (DBG) {
-                    loge("isDataEnabledForReason: no phone subId="
+                    loge("isDataEnabledForReason: no phone or no DataSettingsManager subId="
                             + subId + " retVal=false");
                 }
                 return false;
@@ -7597,8 +7634,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public int getCarrierPrivilegeStatusForUid(int subId, int uid) {
         enforceReadPrivilegedPermission("getCarrierPrivilegeStatusForUid");
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, "getCarrierPrivilegeStatusForUid");
+        if (!mApp.getResources().getBoolean(
+                    com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION,
+                    "getCarrierPrivilegeStatusForUid");
+        }
 
         return getCarrierPrivilegeStatusForUidWithPermission(subId, uid);
     }
@@ -7644,9 +7685,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public int checkCarrierPrivilegesForPackageAnyPhone(String pkgName) {
         enforceReadPrivilegedPermission("checkCarrierPrivilegesForPackageAnyPhone");
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION,
-                "checkCarrierPrivilegesForPackageAnyPhone");
+        if (!mApp.getResources().getBoolean(
+                    com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION,
+                    "checkCarrierPrivilegesForPackageAnyPhone");
+        }
 
         return checkCarrierPrivilegesForPackageAnyPhoneWithPermission(pkgName);
     }
@@ -7730,9 +7774,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public @Nullable String getCarrierServicePackageNameForLogicalSlot(int logicalSlotIndex) {
         enforceReadPrivilegedPermission("getCarrierServicePackageNameForLogicalSlot");
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION,
-                "getCarrierServicePackageNameForLogicalSlot");
+        if (!mApp.getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION,
+                    "getCarrierServicePackageNameForLogicalSlot");
+        }
 
         final Phone phone = PhoneFactory.getPhone(logicalSlotIndex);
         if (phone == null) {
@@ -7824,6 +7871,10 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             if (phone == null) {
                 return false;
             }
+            if (!TextUtils.isEmpty(number) && number.length() > LINE1_NUMBER_MAX_LEN) {
+                Rlog.e(LOG_TAG, "Number is too long");
+                return false;
+            }
             final String subscriberId = phone.getSubscriberId();
 
             if (DBG_MERGE) {
@@ -7873,8 +7924,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             return null;
         }
 
-        enforceTelephonyFeatureWithException(callingPackage,
-                PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, "getLine1NumberForDisplay");
+        if (!mApp.getResources().getBoolean(
+                    com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(callingPackage,
+                    PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, "getLine1NumberForDisplay");
+        }
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -8100,8 +8154,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             throw e;
         }
 
-        enforceTelephonyFeatureWithException(callingPackage,
-                PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "getRadioAccessFamily");
+        if (!mApp.getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(callingPackage,
+                    PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "getRadioAccessFamily");
+        }
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -8115,20 +8172,15 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public void uploadCallComposerPicture(int subscriptionId, String callingPackage,
             String contentType, ParcelFileDescriptor fd, ResultReceiver callback) {
-        try {
-            if (!Objects.equals(mApp.getPackageManager().getPackageUid(callingPackage, 0),
-                    Binder.getCallingUid())) {
-                throw new SecurityException("Invalid package:" + callingPackage);
-            }
-        } catch (PackageManager.NameNotFoundException e) {
-            throw new SecurityException("Invalid package:" + callingPackage);
-        }
-
+        enforceCallingPackage(callingPackage, Binder.getCallingUid(),
+                "Invalid package:" + callingPackage);
         enforceTelephonyFeatureWithException(callingPackage,
                 PackageManager.FEATURE_TELEPHONY_CALLING, "uploadCallComposerPicture");
 
         RoleManager rm = mApp.getSystemService(RoleManager.class);
-        List<String> dialerRoleHolders = rm.getRoleHolders(RoleManager.ROLE_DIALER);
+        List<String> dialerRoleHolders;
+        dialerRoleHolders = rm.getRoleHoldersAsUser(RoleManager.ROLE_DIALER,
+                UserHandle.of(ActivityManager.getCurrentUser()));
         if (!dialerRoleHolders.contains(callingPackage)) {
             throw new SecurityException("App must be the dialer role holder to"
                     + " upload a call composer pic");
@@ -8551,7 +8603,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             cleanUpSmsRawTable(getDefaultPhone().getContext());
             // Clean up IMS settings as well here.
             int slotId = getSlotIndex(subId);
-            if (slotId > SubscriptionManager.INVALID_SIM_SLOT_INDEX) {
+            if (isImsAvailableOnDevice() && slotId > SubscriptionManager.INVALID_SIM_SLOT_INDEX) {
                 ImsManager.getInstance(mApp, slotId).factoryReset();
             }
 
@@ -8682,8 +8734,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void requestModemActivityInfo(ResultReceiver result) {
         enforceModifyPermission();
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY, "requestModemActivityInfo");
+        if (!mApp.getResources().getBoolean(
+                    com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY, "requestModemActivityInfo");
+        }
 
         WorkSource workSource = getWorkSource(Binder.getCallingUid());
 
@@ -9267,11 +9322,17 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public void getCarrierRestrictionStatus(IIntegerConsumer callback, String packageName) {
-        enforceReadPermission("getCarrierRestrictionStatus");
-
+        String functionName = "getCarrierRestrictionStatus";
         enforceTelephonyFeatureWithException(packageName,
-                PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, "getCarrierRestrictionStatus");
-
+                PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, functionName);
+        try {
+            mApp.enforceCallingOrSelfPermission(
+                    android.Manifest.permission.READ_BASIC_PHONE_STATE,
+                    functionName);
+        } catch (SecurityException e) {
+            mApp.enforceCallingOrSelfPermission(permission.READ_PHONE_STATE,
+                    functionName);
+        }
         Set<Integer> carrierIds = validateCallerAndGetCarrierIds(packageName);
         if (carrierIds.contains(CarrierAllowListInfo.INVALID_CARRIER_ID)) {
             Rlog.e(LOG_TAG, "getCarrierRestrictionStatus: caller is not registered");
@@ -9508,7 +9569,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             if (phone != null) {
                 if (reason == TelephonyManager.DATA_ENABLED_REASON_CARRIER) {
                     phone.carrierActionSetMeteredApnsEnabled(enabled);
-                } else {
+                } else if (phone.getDataSettingsManager() != null) {
                     phone.getDataSettingsManager().setDataEnabled(
                             reason, enabled, callingPackage);
                 }
@@ -9545,8 +9606,16 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     }
 
     private WorkSource getWorkSource(int uid) {
-        String packageName = mApp.getPackageManager().getNameForUid(uid);
-        if (uid == Process.ROOT_UID && packageName == null) {
+        PackageManager pm;
+        if (mFeatureFlags.hsumPackageManager()) {
+            pm = mApp.getBaseContext().createContextAsUser(UserHandle.getUserHandleForUid(uid), 0)
+                    .getPackageManager();
+        } else {
+            pm = mApp.getPackageManager();
+        }
+
+        String packageName = pm.getNameForUid(uid);
+        if (UserHandle.isSameApp(uid, Process.ROOT_UID) && packageName == null) {
             // Downstream WorkSource attribution inside the RIL requires both a UID and package name
             // to be set for wakelock tracking, otherwise RIL requests fail with a runtime
             // exception. ROOT_UID seems not to have a valid package name returned by
@@ -10349,8 +10418,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                             mApp, defaultPhone.getSubId(), "isEmergencyNumber(Potential)");
         }
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_CALLING, "isEmergencyNumber");
+        if (!mApp.getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_CALLING, "isEmergencyNumber");
+        }
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -10812,9 +10884,35 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public @Nullable String getCurrentPackageName() {
-        PackageManager pm = mApp.getPackageManager();
-        String[] packageNames = pm == null ? null : pm.getPackagesForUid(Binder.getCallingUid());
-        return packageNames == null ? null : packageNames[0];
+        if (mFeatureFlags.hsumPackageManager()) {
+            PackageManager pm = mApp.getBaseContext().createContextAsUser(
+                    Binder.getCallingUserHandle(), 0).getPackageManager();
+            if (pm == null) return null;
+            String[] callingUids = pm.getPackagesForUid(Binder.getCallingUid());
+            return (callingUids == null) ? null : callingUids[0];
+        }
+        if (mPackageManager == null) return null;
+        String[] callingUids = mPackageManager.getPackagesForUid(Binder.getCallingUid());
+        return (callingUids == null) ? null : callingUids[0];
+    }
+
+    /**
+     * @return The calling package name or "phone" if the caller is the phone process. This is done
+     * because multiple Phone has multiple packages in it and the first element in the array is not
+     * actually always the caller.
+     * Note: This is for logging purposes only and should not be used for security checks.
+     */
+    private String getCurrentPackageNameOrPhone() {
+        PackageManager pm;
+        if (mFeatureFlags.hsumPackageManager()) {
+            pm = mApp.getBaseContext().createContextAsUser(
+                    Binder.getCallingUserHandle(), 0).getPackageManager();
+        } else {
+            pm = mApp.getPackageManager();
+        }
+        String uidName = pm == null ? null : pm.getNameForUid(Binder.getCallingUid());
+        if (uidName != null && !uidName.isEmpty()) return uidName;
+        return getCurrentPackageName();
     }
 
     /**
@@ -10850,7 +10948,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             isMetered = phone.getDataNetworkController().getDataConfigManager()
                     .isMeteredCapability(DataUtils.apnTypeToNetworkCapability(apnType),
                             phone.getServiceState().getDataRoaming());
-            isDataEnabled = phone.getDataSettingsManager().isDataEnabled(apnType);
+            isDataEnabled = (phone.getDataSettingsManager() != null)
+                    ?  phone.getDataSettingsManager().isDataEnabled(apnType) : false;
             return !isMetered || isDataEnabled;
         } finally {
             Binder.restoreCallingIdentity(identity);
@@ -10967,7 +11066,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         // Bring up choose default SMS subscription dialog right now
         intent.putExtra(PickSmsSubscriptionActivity.DIALOG_TYPE_KEY,
                 PickSmsSubscriptionActivity.SMS_PICK_FOR_MESSAGE);
-        mApp.startActivity(intent);
+        mApp.startActivityAsUser(intent, UserHandle.CURRENT);
     }
 
     @Override
@@ -10980,13 +11079,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             Intent intent = new Intent(Intent.ACTION_SENDTO);
             intent.setData(Uri.parse("smsto:"));
             intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-            mApp.startActivity(intent);
+            mApp.startActivityAsUser(intent, UserHandle.CURRENT);
         } catch (ActivityNotFoundException e) {
             Log.w(LOG_TAG, "Unable to show intent forwarder, try showing error dialog instead");
             Intent intent = new Intent();
             intent.setClass(mApp, ErrorDialogActivity.class);
             intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-            mApp.startActivity(intent);
+            mApp.startActivityAsUser(intent, UserHandle.CURRENT);
         }
     }
 
@@ -11040,7 +11139,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         final long identity = Binder.clearCallingIdentity();
         try {
             Phone phone = getPhone(subscriptionId);
-            if (phone == null) return false;
+            if (phone == null || phone.getDataSettingsManager() == null) return false;
 
             return phone.getDataSettingsManager().isMobileDataPolicyEnabled(policy);
         } finally {
@@ -11059,7 +11158,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         final long identity = Binder.clearCallingIdentity();
         try {
             Phone phone = getPhone(subscriptionId);
-            if (phone == null) return;
+            if (phone == null || phone.getDataSettingsManager() == null) return;
 
             phone.getDataSettingsManager().setMobileDataPolicy(policy, enabled);
         } finally {
@@ -11254,7 +11353,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         // In fact, the current code acquires way too many,
         // and probably has lurking deadlocks.
 
-        if (Binder.getCallingUid() != Process.SYSTEM_UID) {
+        if (!UserHandle.isSameApp(Binder.getCallingUid(), Process.SYSTEM_UID)) {
             throw new SecurityException("Only the OS may call notifyUserActivity()");
         }
 
@@ -11296,9 +11395,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public boolean isRadioInterfaceCapabilitySupported(
             final @NonNull @TelephonyManager.RadioInterfaceCapability String capability) {
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS,
-                "isRadioInterfaceCapabilitySupported");
+        if (!mApp.getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS,
+                    "isRadioInterfaceCapabilitySupported");
+        }
 
         Set<String> radioInterfaceCapabilities =
                 mRadioInterfaceCapabilities.getCapabilities();
@@ -12293,7 +12395,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
     private static void validateSignalStrengthUpdateRequest(Context context,
             SignalStrengthUpdateRequest request, int callingUid) {
-        if (callingUid == Process.PHONE_UID || callingUid == Process.SYSTEM_UID) {
+        if (TelephonyPermissions.isSystemOrPhone(callingUid)) {
             // phone/system process do not have further restriction on request
             return;
         }
@@ -12483,8 +12585,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
         String callingProcess;
         try {
-            callingProcess = mApp.getPackageManager().getApplicationInfo(
-                    getCurrentPackageName(), 0).processName;
+            if (mFeatureFlags.hsumPackageManager()) {
+                callingProcess = mApp.getPackageManager().getApplicationInfoAsUser(
+                        getCurrentPackageName(), 0, Binder.getCallingUserHandle()).processName;
+            } else {
+                callingProcess = mApp.getPackageManager().getApplicationInfo(
+                        getCurrentPackageName(), 0).processName;
+            }
         } catch (PackageManager.NameNotFoundException e) {
             callingProcess = getCurrentPackageName();
         }
@@ -12772,15 +12879,31 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
         Context context = getPhoneFromSubIdOrDefault(subId).getContext();
 
-        UserHandle userHandle = null;
-        final long identity = Binder.clearCallingIdentity();
-        try {
-            userHandle = TelephonyUtils.getSubscriptionUserHandle(context, subId);
-        } finally {
-            Binder.restoreCallingIdentity(identity);
+        if (mTelecomFeatureFlags.telecomMainUserInGetRespondMessageApp()){
+            UserHandle mainUser = null;
+            Context userContext = null;
+            final long identity = Binder.clearCallingIdentity();
+            try {
+                mainUser = mUserManager.getMainUser();
+                userContext = context.createContextAsUser(mainUser, 0);
+                Log.d(LOG_TAG, "getDefaultRespondViaMessageApplication: mainUser = " + mainUser);
+            } finally {
+                Binder.restoreCallingIdentity(identity);
+            }
+            return SmsApplication.getDefaultRespondViaMessageApplicationAsUser(userContext,
+                    updateIfNeeded, mainUser);
+        } else {
+            UserHandle userHandle = null;
+            final long identity = Binder.clearCallingIdentity();
+            try {
+                userHandle = TelephonyUtils.getSubscriptionUserHandle(context, subId);
+            } finally {
+                Binder.restoreCallingIdentity(identity);
+            }
+            return SmsApplication.getDefaultRespondViaMessageApplicationAsUser(context,
+                    updateIfNeeded, userHandle);
         }
-        return SmsApplication.getDefaultRespondViaMessageApplicationAsUser(context,
-                updateIfNeeded, userHandle);
+
     }
 
     /**
@@ -12870,8 +12993,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     @SimState
     public int getSimStateForSlotIndex(int slotIndex) {
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, "getSimStateForSlotIndex");
+        if (!mApp.getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
+            enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                    PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, "getSimStateForSlotIndex");
+        }
 
         IccCardConstants.State simState;
         if (slotIndex < 0) {
@@ -13058,7 +13184,6 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * enabled, this may also disable the cellular modem, and if the satellite modem is disabled,
      * this may also re-enable the cellular modem.
      *
-     * @param subId The subId of the subscription to set satellite enabled for.
      * @param enableSatellite {@code true} to enable the satellite modem and
      *                        {@code false} to disable.
      * @param enableDemoMode {@code true} to enable demo mode and {@code false} to disable.
@@ -13068,7 +13193,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    public void requestSatelliteEnabled(int subId, boolean enableSatellite, boolean enableDemoMode,
+    public void requestSatelliteEnabled(boolean enableSatellite, boolean enableDemoMode,
             boolean isEmergency, @NonNull IIntegerConsumer callback) {
         enforceSatelliteCommunicationPermission("requestSatelliteEnabled");
         if (enableSatellite) {
@@ -13093,93 +13218,86 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                     }
                     if (isAllowed) {
                         mSatelliteController.requestSatelliteEnabled(
-                                subId, enableSatellite, enableDemoMode, isEmergency, callback);
+                                enableSatellite, enableDemoMode, isEmergency, callback);
                     } else {
                         result.accept(SATELLITE_RESULT_ACCESS_BARRED);
                     }
                 }
             };
             mSatelliteAccessController.requestIsCommunicationAllowedForCurrentLocation(
-                    subId, resultReceiver);
+                    resultReceiver, true);
         } else {
             // No need to check if satellite is allowed at current location when disabling satellite
             mSatelliteController.requestSatelliteEnabled(
-                    subId, enableSatellite, enableDemoMode, isEmergency, callback);
+                    enableSatellite, enableDemoMode, isEmergency, callback);
         }
     }
 
     /**
      * Request to get whether the satellite modem is enabled.
      *
-     * @param subId The subId of the subscription to check whether satellite is enabled for.
      * @param result The result receiver that returns whether the satellite modem is enabled
      *               if the request is successful or an error code if the request failed.
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    public void requestIsSatelliteEnabled(int subId, @NonNull ResultReceiver result) {
+    public void requestIsSatelliteEnabled(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestIsSatelliteEnabled");
-        mSatelliteController.requestIsSatelliteEnabled(subId, result);
+        mSatelliteController.requestIsSatelliteEnabled(result);
     }
 
     /**
      * Request to get whether the satellite service demo mode is enabled.
      *
-     * @param subId The subId of the subscription to check whether the satellite demo mode
-     *              is enabled for.
      * @param result The result receiver that returns whether the satellite demo mode is enabled
      *               if the request is successful or an error code if the request failed.
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    public void requestIsDemoModeEnabled(int subId, @NonNull ResultReceiver result) {
+    public void requestIsDemoModeEnabled(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestIsDemoModeEnabled");
-        mSatelliteController.requestIsDemoModeEnabled(subId, result);
+        mSatelliteController.requestIsDemoModeEnabled(result);
     }
 
     /**
      * Request to get whether the satellite service is enabled with emergency mode.
      *
-     * @param subId The subId of the subscription to check whether the satellite demo mode
-     *              is enabled for.
      * @param result The result receiver that returns whether the satellite emergency mode is
      *               enabled if the request is successful or an error code if the request failed.
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    public void requestIsEmergencyModeEnabled(int subId, @NonNull ResultReceiver result) {
+    public void requestIsEmergencyModeEnabled(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestIsEmergencyModeEnabled");
-        result.send(SATELLITE_RESULT_REQUEST_NOT_SUPPORTED, null);
+        mSatelliteController.requestIsEmergencyModeEnabled(result);
     }
 
     /**
      * Request to get whether the satellite service is supported on the device.
      *
-     * @param subId The subId of the subscription to check satellite service support for.
      * @param result The result receiver that returns whether the satellite service is supported on
      *               the device if the request is successful or an error code if the request failed.
      */
     @Override
-    public void requestIsSatelliteSupported(int subId, @NonNull ResultReceiver result) {
-        mSatelliteController.requestIsSatelliteSupported(subId, result);
+    public void requestIsSatelliteSupported(@NonNull ResultReceiver result) {
+        mSatelliteController.requestIsSatelliteSupported(result);
     }
 
     /**
      * Request to get the {@link SatelliteCapabilities} of the satellite service.
      *
-     * @param subId The subId of the subscription to get the satellite capabilities for.
      * @param result The result receiver that returns the {@link SatelliteCapabilities}
      *               if the request is successful or an error code if the request failed.
      *
      * @throws SecurityException if the caller doesn't have required permission.
      */
     @Override
-    public void requestSatelliteCapabilities(int subId, @NonNull ResultReceiver result) {
+    public void requestSatelliteCapabilities(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestSatelliteCapabilities");
-        mSatelliteController.requestSatelliteCapabilities(subId, result);
+        mSatelliteController.requestSatelliteCapabilities(result);
     }
 
     /**
@@ -13187,44 +13305,41 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * This can be called by the pointing UI when the user starts pointing to the satellite.
      * Modem should continue to report the pointing input as the device or satellite moves.
      *
-     * @param subId The subId of the subscription to start satellite transmission updates for.
      * @param resultCallback The callback to get the result of the request.
      * @param callback The callback to notify of satellite transmission updates.
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    public void startSatelliteTransmissionUpdates(int subId,
+    public void startSatelliteTransmissionUpdates(
             @NonNull IIntegerConsumer resultCallback,
             @NonNull ISatelliteTransmissionUpdateCallback callback) {
         enforceSatelliteCommunicationPermission("startSatelliteTransmissionUpdates");
-        mSatelliteController.startSatelliteTransmissionUpdates(subId, resultCallback, callback);
+        mSatelliteController.startSatelliteTransmissionUpdates(resultCallback, callback);
     }
 
     /**
      * Stop receiving satellite transmission updates.
      * This can be called by the pointing UI when the user stops pointing to the satellite.
      *
-     * @param subId The subId of the subscription to stop satellite transmission updates for.
      * @param resultCallback The callback to get the result of the request.
      * @param callback The callback that was passed to {@link #startSatelliteTransmissionUpdates(
-     *                 int, IIntegerConsumer, ISatelliteTransmissionUpdateCallback)}.
+     *                 IIntegerConsumer, ISatelliteTransmissionUpdateCallback)}.
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    public void stopSatelliteTransmissionUpdates(int subId,
+    public void stopSatelliteTransmissionUpdates(
             @NonNull IIntegerConsumer resultCallback,
             @NonNull ISatelliteTransmissionUpdateCallback callback) {
         enforceSatelliteCommunicationPermission("stopSatelliteTransmissionUpdates");
-        mSatelliteController.stopSatelliteTransmissionUpdates(subId, resultCallback, callback);
+        mSatelliteController.stopSatelliteTransmissionUpdates(resultCallback, callback);
     }
 
     /**
      * Register the subscription with a satellite provider.
      * This is needed to register the subscription if the provider allows dynamic registration.
      *
-     * @param subId The subId of the subscription to be provisioned.
      * @param token The token to be used as a unique identifier for provisioning with satellite
      *              gateway.
      * @param provisionData Data from the provisioning app that can be used by provisioning server
@@ -13236,11 +13351,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    @Nullable public ICancellationSignal provisionSatelliteService(int subId,
+    @Nullable public ICancellationSignal provisionSatelliteService(
             @NonNull String token, @NonNull byte[] provisionData,
             @NonNull IIntegerConsumer callback) {
         enforceSatelliteCommunicationPermission("provisionSatelliteService");
-        return mSatelliteController.provisionSatelliteService(subId, token, provisionData,
+        return mSatelliteController.provisionSatelliteService(token, provisionData,
                 callback);
     }
 
@@ -13250,23 +13365,21 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * {@link SatelliteProvisionStateCallback#onSatelliteProvisionStateChanged(boolean)}
      * should report as deprovisioned.
      *
-     * @param subId The subId of the subscription to be deprovisioned.
      * @param token The token of the device/subscription to be deprovisioned.
      * @param callback The callback to get the result of the request.
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    public void deprovisionSatelliteService(int subId,
+    public void deprovisionSatelliteService(
             @NonNull String token, @NonNull IIntegerConsumer callback) {
         enforceSatelliteCommunicationPermission("deprovisionSatelliteService");
-        mSatelliteController.deprovisionSatelliteService(subId, token, callback);
+        mSatelliteController.deprovisionSatelliteService(token, callback);
     }
 
     /**
      * Registers for the satellite provision state changed.
      *
-     * @param subId The subId of the subscription to register for provision state changed.
      * @param callback The callback to handle the satellite provision state changed event.
      *
      * @return The {@link SatelliteManager.SatelliteResult} result of the operation.
@@ -13275,32 +13388,30 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     @SatelliteManager.SatelliteResult public int registerForSatelliteProvisionStateChanged(
-            int subId, @NonNull ISatelliteProvisionStateCallback callback) {
+            @NonNull ISatelliteProvisionStateCallback callback) {
         enforceSatelliteCommunicationPermission("registerForSatelliteProvisionStateChanged");
-        return mSatelliteController.registerForSatelliteProvisionStateChanged(subId, callback);
+        return mSatelliteController.registerForSatelliteProvisionStateChanged(callback);
     }
 
     /**
      * Unregisters for the satellite provision state changed.
      * If callback was not registered before, the request will be ignored.
      *
-     * @param subId The subId of the subscription to unregister for provision state changed.
      * @param callback The callback that was passed to
-     * {@link #registerForSatelliteProvisionStateChanged(int, ISatelliteProvisionStateCallback)}.
+     * {@link #registerForSatelliteProvisionStateChanged(ISatelliteProvisionStateCallback)}.
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
     public void unregisterForSatelliteProvisionStateChanged(
-            int subId, @NonNull ISatelliteProvisionStateCallback callback) {
+            @NonNull ISatelliteProvisionStateCallback callback) {
         enforceSatelliteCommunicationPermission("unregisterForSatelliteProvisionStateChanged");
-        mSatelliteController.unregisterForSatelliteProvisionStateChanged(subId, callback);
+        mSatelliteController.unregisterForSatelliteProvisionStateChanged(callback);
     }
 
     /**
      * Request to get whether the device is provisioned with a satellite provider.
      *
-     * @param subId The subId of the subscription to get whether the device is provisioned for.
      * @param result The result receiver that returns whether the device is provisioned with a
      *               satellite provider if the request is successful or an error code if the
      *               request failed.
@@ -13308,15 +13419,14 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    public void requestIsSatelliteProvisioned(int subId, @NonNull ResultReceiver result) {
+    public void requestIsSatelliteProvisioned(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestIsSatelliteProvisioned");
-        mSatelliteController.requestIsSatelliteProvisioned(subId, result);
+        mSatelliteController.requestIsSatelliteProvisioned(result);
     }
 
     /**
      * Registers for modem state changed from satellite modem.
      *
-     * @param subId The subId of the subscription to register for satellite modem state changed.
      * @param callback The callback to handle the satellite modem state changed event.
      *
      * @return The {@link SatelliteManager.SatelliteResult} result of the operation.
@@ -13324,33 +13434,30 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    @SatelliteManager.SatelliteResult public int registerForSatelliteModemStateChanged(int subId,
+    @SatelliteManager.SatelliteResult public int registerForSatelliteModemStateChanged(
             @NonNull ISatelliteModemStateCallback callback) {
         enforceSatelliteCommunicationPermission("registerForSatelliteModemStateChanged");
-        return mSatelliteController.registerForSatelliteModemStateChanged(subId, callback);
+        return mSatelliteController.registerForSatelliteModemStateChanged(callback);
     }
 
     /**
      * Unregisters for modem state changed from satellite modem.
      * If callback was not registered before, the request will be ignored.
      *
-     * @param subId The subId of the subscription to unregister for satellite modem state changed.
      * @param callback The callback that was passed to
      * {@link #registerForModemStateChanged(int, ISatelliteModemStateCallback)}.
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    public void unregisterForModemStateChanged(int subId,
-            @NonNull ISatelliteModemStateCallback callback) {
+    public void unregisterForModemStateChanged(@NonNull ISatelliteModemStateCallback callback) {
         enforceSatelliteCommunicationPermission("unregisterForModemStateChanged");
-        mSatelliteController.unregisterForModemStateChanged(subId, callback);
+        mSatelliteController.unregisterForModemStateChanged(callback);
     }
 
     /**
      * Register to receive incoming datagrams over satellite.
      *
-     * @param subId The subId of the subscription to register for incoming satellite datagrams.
      * @param callback The callback to handle incoming datagrams over satellite.
      *
      * @return The {@link SatelliteManager.SatelliteResult} result of the operation.
@@ -13358,27 +13465,25 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    @SatelliteManager.SatelliteResult public int registerForIncomingDatagram(int subId,
+    @SatelliteManager.SatelliteResult public int registerForIncomingDatagram(
             @NonNull ISatelliteDatagramCallback callback) {
         enforceSatelliteCommunicationPermission("registerForIncomingDatagram");
-        return mSatelliteController.registerForIncomingDatagram(subId, callback);
+        return mSatelliteController.registerForIncomingDatagram(callback);
     }
 
     /**
      * Unregister to stop receiving incoming datagrams over satellite.
      * If callback was not registered before, the request will be ignored.
      *
-     * @param subId The subId of the subscription to unregister for incoming satellite datagrams.
      * @param callback The callback that was passed to
-     *                 {@link #registerForIncomingDatagram(int, ISatelliteDatagramCallback)}.
+     *                 {@link #registerForIncomingDatagram(ISatelliteDatagramCallback)}.
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    public void unregisterForIncomingDatagram(int subId,
-            @NonNull ISatelliteDatagramCallback callback) {
+    public void unregisterForIncomingDatagram(@NonNull ISatelliteDatagramCallback callback) {
         enforceSatelliteCommunicationPermission("unregisterForIncomingDatagram");
-        mSatelliteController.unregisterForIncomingDatagram(subId, callback);
+        mSatelliteController.unregisterForIncomingDatagram(callback);
     }
 
     /**
@@ -13388,14 +13493,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * satellite. If there are any incoming datagrams, they will be received via
      * {@link SatelliteDatagramCallback#onSatelliteDatagramReceived(long, SatelliteDatagram, int, Consumer)})}
      *
-     * @param subId The subId of the subscription used for receiving datagrams.
      * @param callback The callback to get {@link SatelliteManager.SatelliteResult} of the request.
      *
      * @throws SecurityException if the caller doesn't have required permission.
      */
-    public void pollPendingDatagrams(int subId, IIntegerConsumer callback) {
+    public void pollPendingDatagrams(IIntegerConsumer callback) {
         enforceSatelliteCommunicationPermission("pollPendingDatagrams");
-        mSatelliteController.pollPendingDatagrams(subId, callback);
+        mSatelliteController.pollPendingDatagrams(callback);
     }
 
     /**
@@ -13405,7 +13509,6 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * input to this method. Datagram received here will be passed down to modem without any
      * encoding or encryption.
      *
-     * @param subId The subId of the subscription to send satellite datagrams for.
      * @param datagramType datagram type indicating whether the datagram is of type
      *                     SOS_SMS or LOCATION_SHARING.
      * @param datagram encoded gateway datagram which is encrypted by the caller.
@@ -13417,11 +13520,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * @throws SecurityException if the caller doesn't have required permission.
      */
     @Override
-    public void sendDatagram(int subId, @SatelliteManager.DatagramType int datagramType,
+    public void sendDatagram(@SatelliteManager.DatagramType int datagramType,
             @NonNull SatelliteDatagram datagram, boolean needFullScreenPointingUI,
             @NonNull IIntegerConsumer callback) {
         enforceSatelliteCommunicationPermission("sendDatagram");
-        mSatelliteController.sendDatagram(subId, datagramType, datagram, needFullScreenPointingUI,
+        mSatelliteController.sendDatagram(datagramType, datagram, needFullScreenPointingUI,
                 callback);
     }
 
@@ -13440,29 +13543,26 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void requestIsCommunicationAllowedForCurrentLocation(int subId,
             @NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestIsCommunicationAllowedForCurrentLocation");
-        mSatelliteAccessController.requestIsCommunicationAllowedForCurrentLocation(subId,
-                result);
+        mSatelliteAccessController.requestIsCommunicationAllowedForCurrentLocation(result, false);
     }
 
     /**
      * Request to get the time after which the satellite will be visible.
      *
-     * @param subId The subId to get the time after which the satellite will be visible for.
      * @param result The result receiver that returns the time after which the satellite will
      *               be visible if the request is successful or an error code if the request failed.
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    public void requestTimeForNextSatelliteVisibility(int subId, @NonNull ResultReceiver result) {
+    public void requestTimeForNextSatelliteVisibility(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestTimeForNextSatelliteVisibility");
-        mSatelliteController.requestTimeForNextSatelliteVisibility(subId, result);
+        mSatelliteController.requestTimeForNextSatelliteVisibility(result);
     }
 
     /**
      * Inform that Device is aligned to satellite for demo mode.
      *
-     * @param subId The subId to get the time after which the satellite will be visible for.
      * @param isAligned {@code true} Device is aligned with the satellite for demo mode
      *                  {@code false} Device fails to align with the satellite for demo mode.
      *
@@ -13470,9 +13570,9 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @RequiresPermission(Manifest.permission.SATELLITE_COMMUNICATION)
 
-    public void setDeviceAlignedWithSatellite(int subId, @NonNull boolean isAligned) {
+    public void setDeviceAlignedWithSatellite(@NonNull boolean isAligned) {
         enforceSatelliteCommunicationPermission("informDeviceAlignedToSatellite");
-        mSatelliteController.setDeviceAlignedWithSatellite(subId, isAligned);
+        mSatelliteController.setDeviceAlignedWithSatellite(isAligned);
     }
 
     /**
@@ -13547,18 +13647,17 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     /**
      * Request to get the signal strength of the satellite connection.
      *
-     * @param subId The subId of the subscription to request for.
      * @param result Result receiver to get the error code of the request and the current signal
      * strength of the satellite connection.
      *
      * @throws SecurityException if the caller doesn't have required permission.
      */
     @Override
-    public void requestNtnSignalStrength(int subId, @NonNull ResultReceiver result) {
+    public void requestNtnSignalStrength(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestNtnSignalStrength");
         final long identity = Binder.clearCallingIdentity();
         try {
-            mSatelliteController.requestNtnSignalStrength(subId, result);
+            mSatelliteController.requestNtnSignalStrength(result);
         } finally {
             Binder.restoreCallingIdentity(identity);
         }
@@ -13569,7 +13668,6 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * is not successful, a {@link ServiceSpecificException} that contains
      * {@link SatelliteManager.SatelliteResult} will be thrown.
      *
-     * @param subId The subId of the subscription to request for.
      * @param callback The callback to handle the NTN signal strength changed event. If the
      * operation is successful, {@link NtnSignalStrengthCallback#onNtnSignalStrengthChanged(
      * NtnSignalStrength)} will return an instance of {@link NtnSignalStrength} with a value of
@@ -13580,12 +13678,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * @throws ServiceSpecificException If the callback registration operation fails.
      */
     @Override
-    public void registerForNtnSignalStrengthChanged(int subId,
+    public void registerForNtnSignalStrengthChanged(
             @NonNull INtnSignalStrengthCallback callback) throws RemoteException {
         enforceSatelliteCommunicationPermission("registerForNtnSignalStrengthChanged");
         final long identity = Binder.clearCallingIdentity();
         try {
-            mSatelliteController.registerForNtnSignalStrengthChanged(subId, callback);
+            mSatelliteController.registerForNtnSignalStrengthChanged(callback);
         } finally {
             Binder.restoreCallingIdentity(identity);
         }
@@ -13595,20 +13693,19 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * Unregisters for NTN signal strength changed from satellite modem.
      * If callback was not registered before, the request will be ignored.
      *
-     * @param subId The subId of the subscription to unregister for listening NTN signal strength
      * changed event.
      * @param callback The callback that was passed to
-     * {@link #registerForNtnSignalStrengthChanged(int, INtnSignalStrengthCallback)}
+     * {@link #registerForNtnSignalStrengthChanged(INtnSignalStrengthCallback)}
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
     public void unregisterForNtnSignalStrengthChanged(
-            int subId, @NonNull INtnSignalStrengthCallback callback) {
+            @NonNull INtnSignalStrengthCallback callback) {
         enforceSatelliteCommunicationPermission("unregisterForNtnSignalStrengthChanged");
         final long identity = Binder.clearCallingIdentity();
         try {
-            mSatelliteController.unregisterForNtnSignalStrengthChanged(subId, callback);
+            mSatelliteController.unregisterForNtnSignalStrengthChanged(callback);
         } finally {
             Binder.restoreCallingIdentity(identity);
         }
@@ -13617,7 +13714,6 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     /**
      * Registers for satellite capabilities change event from the satellite service.
      *
-     * @param subId The subId of the subscription to request for.
      * @param callback The callback to handle the satellite capabilities changed event.
      *
      * @return The {@link SatelliteManager.SatelliteResult} result of the operation.
@@ -13626,11 +13722,11 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     @SatelliteManager.SatelliteResult public int registerForCapabilitiesChanged(
-            int subId, @NonNull ISatelliteCapabilitiesCallback callback) {
+            @NonNull ISatelliteCapabilitiesCallback callback) {
         enforceSatelliteCommunicationPermission("registerForCapabilitiesChanged");
         final long identity = Binder.clearCallingIdentity();
         try {
-            return mSatelliteController.registerForCapabilitiesChanged(subId, callback);
+            return mSatelliteController.registerForCapabilitiesChanged(callback);
         } finally {
             Binder.restoreCallingIdentity(identity);
         }
@@ -13640,19 +13736,18 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * Unregisters for satellite capabilities change event from the satellite service.
      * If callback was not registered before, the request will be ignored.
      *
-     * @param subId The subId of the subscription to unregister for satellite capabilities change.
      * @param callback The callback that was passed to.
-     * {@link #registerForCapabilitiesChanged(int, ISatelliteCapabilitiesCallback)}.
+     * {@link #registerForCapabilitiesChanged(ISatelliteCapabilitiesCallback)}.
      *
      * @throws SecurityException if the caller doesn't have required permission.
      */
     @Override
-    public void unregisterForCapabilitiesChanged(int subId,
+    public void unregisterForCapabilitiesChanged(
             @NonNull ISatelliteCapabilitiesCallback callback) {
         enforceSatelliteCommunicationPermission("unregisterForCapabilitiesChanged");
         final long identity = Binder.clearCallingIdentity();
         try {
-            mSatelliteController.unregisterForCapabilitiesChanged(subId, callback);
+            mSatelliteController.unregisterForCapabilitiesChanged(callback);
         } finally {
             Binder.restoreCallingIdentity(identity);
         }
@@ -13661,7 +13756,6 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     /**
      * Registers for the satellite supported state changed.
      *
-     * @param subId The subId of the subscription to register for supported state changed.
      * @param callback The callback to handle the satellite supported state changed event.
      *
      * @return The {@link SatelliteManager.SatelliteResult} result of the operation.
@@ -13670,43 +13764,47 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     @SatelliteManager.SatelliteResult public int registerForSatelliteSupportedStateChanged(
-            int subId, @NonNull ISatelliteSupportedStateCallback callback) {
+            @NonNull ISatelliteSupportedStateCallback callback) {
         enforceSatelliteCommunicationPermission("registerForSatelliteSupportedStateChanged");
-        return mSatelliteController.registerForSatelliteSupportedStateChanged(subId, callback);
+        return mSatelliteController.registerForSatelliteSupportedStateChanged(callback);
     }
 
     /**
      * Unregisters for the satellite supported state changed.
      * If callback was not registered before, the request will be ignored.
      *
-     * @param subId The subId of the subscription to unregister for supported state changed.
      * @param callback The callback that was passed to
-     * {@link #registerForSatelliteSupportedStateChanged(int, ISatelliteSupportedStateCallback)}.
+     * {@link #registerForSatelliteSupportedStateChanged(ISatelliteSupportedStateCallback)}.
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
     public void unregisterForSatelliteSupportedStateChanged(
-            int subId, @NonNull ISatelliteSupportedStateCallback callback) {
+            @NonNull ISatelliteSupportedStateCallback callback) {
         enforceSatelliteCommunicationPermission("unregisterForSatelliteSupportedStateChanged");
-        mSatelliteController.unregisterForSatelliteSupportedStateChanged(subId, callback);
+        mSatelliteController.unregisterForSatelliteSupportedStateChanged(callback);
     }
 
     /**
      * This API can be used by only CTS to update satellite vendor service package name.
      *
      * @param servicePackageName The package name of the satellite vendor service.
+     * @param provisioned Whether satellite should be provisioned or not.
+     *
      * @return {@code true} if the satellite vendor service is set successfully,
      * {@code false} otherwise.
      */
-    public boolean setSatelliteServicePackageName(String servicePackageName) {
-        Log.d(LOG_TAG, "setSatelliteServicePackageName - " + servicePackageName);
+    public boolean setSatelliteServicePackageName(String servicePackageName,
+            String provisioned) {
+        Log.d(LOG_TAG, "setSatelliteServicePackageName - " + servicePackageName
+                + ", provisioned=" + provisioned);
         TelephonyPermissions.enforceShellOnly(
                 Binder.getCallingUid(), "setSatelliteServicePackageName");
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "setSatelliteServicePackageName");
-        return mSatelliteController.setSatelliteServicePackageName(servicePackageName);
+        return mSatelliteController.setSatelliteServicePackageName(servicePackageName,
+                provisioned);
     }
 
     /**
@@ -13886,9 +13984,9 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "setCachedLocationCountryCode");
-        return TelephonyCountryDetector.getInstance(getDefaultPhone().getContext()).setCountryCodes(
-                reset, currentNetworkCountryCodes, cachedNetworkCountryCodes, locationCountryCode,
-                locationCountryCodeTimestampNanos);
+        return TelephonyCountryDetector.getInstance(getDefaultPhone().getContext(), mFeatureFlags)
+                .setCountryCodes(reset, currentNetworkCountryCodes, cachedNetworkCountryCodes,
+                        locationCountryCode, locationCountryCodeTimestampNanos);
     }
 
     /**
@@ -14232,8 +14330,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @SatelliteManager.SatelliteResult public int registerForCommunicationAllowedStateChanged(
             int subId, @NonNull ISatelliteCommunicationAllowedStateCallback callback) {
         enforceSatelliteCommunicationPermission("registerForCommunicationAllowedStateChanged");
-        return mSatelliteAccessController.registerForCommunicationAllowedStateChanged(
-                subId, callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteAccessController.registerForCommunicationAllowedStateChanged(
+                    subId, callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -14251,7 +14354,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void unregisterForCommunicationAllowedStateChanged(
             int subId, @NonNull ISatelliteCommunicationAllowedStateCallback callback) {
         enforceSatelliteCommunicationPermission("unregisterForCommunicationAllowedStateChanged");
-        mSatelliteAccessController.unregisterForCommunicationAllowedStateChanged(subId, callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteAccessController.unregisterForCommunicationAllowedStateChanged(subId,
+                    callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -14267,6 +14376,83 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void requestSatelliteSessionStats(int subId, @NonNull ResultReceiver result) {
         enforceModifyPermission();
         enforcePackageUsageStatsPermission("requestSatelliteSessionStats");
-        mSatelliteController.requestSatelliteSessionStats(subId, result);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.requestSatelliteSessionStats(subId, result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * Request to get list of prioritized satellite subscriber ids to be used for provision.
+     *
+     * @param result The result receiver, which returns the list of prioritized satellite tokens
+     * to be used for provision if the request is successful or an error code if the request failed.
+     *
+     * @throws SecurityException if the caller doesn't have the required permission.
+     */
+    @Override
+    public void requestSatelliteSubscriberProvisionStatus(@NonNull ResultReceiver result) {
+        enforceSatelliteCommunicationPermission("requestSatelliteSubscriberProvisionStatus");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.requestSatelliteSubscriberProvisionStatus(result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * Deliver the list of provisioned satellite subscriber ids.
+     *
+     * @param list List of provisioned satellite subscriber ids.
+     * @param result The result receiver that returns whether deliver success or fail.
+     *
+     * @throws SecurityException if the caller doesn't have the required permission.
+     */
+    @Override
+    public void provisionSatellite(@NonNull List<SatelliteSubscriberInfo> list,
+            @NonNull ResultReceiver result) {
+        enforceSatelliteCommunicationPermission("provisionSatellite");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.provisionSatellite(list, result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * This API can be used by only CTS to override the cached value for the device overlay config
+     * value :
+     * config_satellite_gateway_service_package and
+     * config_satellite_carrier_roaming_esos_provisioned_class.
+     * These values are set before sending an intent to broadcast there are any change to list of
+     * subscriber informations.
+     *
+     * @param name the name is one of the following that constitute an intent.
+     * Component package name, or component class name.
+     * @return {@code true} if the setting is successful, {@code false} otherwise.
+     */
+    @Override
+    public boolean setSatelliteSubscriberIdListChangedIntentComponent(String name) {
+        if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            Log.d(LOG_TAG, "setSatelliteSubscriberIdListChangedIntentComponent:"
+                    + " carrierRoamingNbIotNtn is disabled");
+            return false;
+        }
+        Log.d(LOG_TAG, "setSatelliteSubscriberIdListChangedIntentComponent");
+        TelephonyPermissions.enforceShellOnly(
+                Binder.getCallingUid(), "setSatelliteSubscriberIdListChangedIntentComponent");
+        TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
+                SubscriptionManager.INVALID_SUBSCRIPTION_ID,
+                "setSatelliteSubscriberIdListChangedIntentComponent");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setSatelliteSubscriberIdListChangedIntentComponent(name);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 }
diff --git a/src/com/android/phone/RcsProvisioningMonitor.java b/src/com/android/phone/RcsProvisioningMonitor.java
index 87a2869a7..eac80344b 100644
--- a/src/com/android/phone/RcsProvisioningMonitor.java
+++ b/src/com/android/phone/RcsProvisioningMonitor.java
@@ -21,6 +21,7 @@ import static com.android.internal.telephony.TelephonyStatsLog.RCS_CLIENT_PROVIS
 import static com.android.internal.telephony.TelephonyStatsLog.RCS_CLIENT_PROVISIONING_STATS__EVENT__TRIGGER_RCS_RECONFIGURATION;
 
 import android.Manifest;
+import android.annotation.NonNull;
 import android.app.role.OnRoleHoldersChangedListener;
 import android.app.role.RoleManager;
 import android.content.BroadcastReceiver;
@@ -51,6 +52,7 @@ import com.android.ims.FeatureConnector;
 import com.android.ims.FeatureUpdates;
 import com.android.ims.RcsFeatureManager;
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.internal.telephony.flags.FeatureFlags;
 import com.android.internal.telephony.metrics.RcsStats;
 import com.android.internal.telephony.metrics.RcsStats.RcsProvisioningCallback;
 import com.android.internal.telephony.util.HandlerExecutor;
@@ -110,6 +112,9 @@ public class RcsProvisioningMonitor {
 
     private static RcsProvisioningMonitor sInstance;
 
+    @NonNull
+    private final FeatureFlags mFeatureFlags;
+
     private final SubscriptionManager.OnSubscriptionsChangedListener mSubChangedListener =
             new SubscriptionManager.OnSubscriptionsChangedListener() {
         @Override
@@ -481,8 +486,10 @@ public class RcsProvisioningMonitor {
 
     @VisibleForTesting
     public RcsProvisioningMonitor(PhoneGlobals app, Looper looper, RoleManagerAdapter roleManager,
-            FeatureConnectorFactory<RcsFeatureManager> factory, RcsStats rcsStats) {
+            FeatureConnectorFactory<RcsFeatureManager> factory, RcsStats rcsStats,
+            @NonNull FeatureFlags flags) {
         mPhone = app;
+        mFeatureFlags = flags;
         mHandler = new MyHandler(looper);
         mCarrierConfigManager = mPhone.getSystemService(CarrierConfigManager.class);
         mSubscriptionManager = mPhone.getSystemService(SubscriptionManager.class);
@@ -499,14 +506,15 @@ public class RcsProvisioningMonitor {
     /**
      * create an instance
      */
-    public static RcsProvisioningMonitor make(PhoneGlobals app) {
+    public static RcsProvisioningMonitor make(@NonNull PhoneGlobals app,
+            @NonNull FeatureFlags flags) {
         if (sInstance == null) {
             logd("RcsProvisioningMonitor created.");
             HandlerThread handlerThread = new HandlerThread(TAG);
             handlerThread.start();
             sInstance = new RcsProvisioningMonitor(app, handlerThread.getLooper(),
                     new RoleManagerAdapterImpl(app), RcsFeatureManager::getConnector,
-                    RcsStats.getInstance());
+                    RcsStats.getInstance(), flags);
         }
         return sInstance;
     }
@@ -871,9 +879,18 @@ public class RcsProvisioningMonitor {
         // Only send permission to the default sms app if it has the correct permissions
         // except test mode enabled
         if (!mTestModeEnabled) {
-            mPhone.sendBroadcast(intent, Manifest.permission.PERFORM_IMS_SINGLE_REGISTRATION);
+            if (mFeatureFlags.hsumBroadcast()) {
+                mPhone.sendBroadcastAsUser(intent, UserHandle.ALL,
+                        Manifest.permission.PERFORM_IMS_SINGLE_REGISTRATION);
+            } else {
+                mPhone.sendBroadcast(intent, Manifest.permission.PERFORM_IMS_SINGLE_REGISTRATION);
+            }
         } else {
-            mPhone.sendBroadcast(intent);
+            if (mFeatureFlags.hsumBroadcast()) {
+                mPhone.sendBroadcastAsUser(intent, UserHandle.ALL);
+            } else {
+                mPhone.sendBroadcast(intent);
+            }
         }
     }
 
diff --git a/src/com/android/phone/SimContacts.java b/src/com/android/phone/SimContacts.java
index 4229482f2..d5f78403f 100644
--- a/src/com/android/phone/SimContacts.java
+++ b/src/com/android/phone/SimContacts.java
@@ -33,6 +33,7 @@ import android.database.Cursor;
 import android.net.Uri;
 import android.os.Bundle;
 import android.os.RemoteException;
+import android.os.UserHandle;
 import android.provider.ContactsContract;
 import android.provider.ContactsContract.CommonDataKinds.Email;
 import android.provider.ContactsContract.CommonDataKinds.GroupMembership;
@@ -372,7 +373,7 @@ public class SimContacts extends ADNList {
                             Uri.fromParts(PhoneAccount.SCHEME_TEL, phoneNumber, null));
                     intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                                           | Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS);
-                    startActivity(intent);
+                    startActivityAsUser(intent, UserHandle.CURRENT);
                     finish();
                     return true;
                 }
diff --git a/src/com/android/phone/SimPhonebookProvider.java b/src/com/android/phone/SimPhonebookProvider.java
index 3917d83c6..d912389a5 100644
--- a/src/com/android/phone/SimPhonebookProvider.java
+++ b/src/com/android/phone/SimPhonebookProvider.java
@@ -30,6 +30,7 @@ import android.database.ContentObserver;
 import android.database.Cursor;
 import android.database.MatrixCursor;
 import android.net.Uri;
+import android.os.Binder;
 import android.os.Bundle;
 import android.os.CancellationSignal;
 import android.os.RemoteException;
@@ -677,8 +678,14 @@ public class SimPhonebookProvider extends ContentProvider {
         String callingPackage = getCallingPackage();
         int granted = PackageManager.PERMISSION_DENIED;
         if (callingPackage != null) {
-            granted = getContext().getPackageManager().checkPermission(
-                    Manifest.permission.MODIFY_PHONE_STATE, callingPackage);
+            if (Flags.hsumPackageManager()) {
+                granted = getContext().createContextAsUser(Binder.getCallingUserHandle(), 0)
+                        .getPackageManager().checkPermission(
+                                Manifest.permission.MODIFY_PHONE_STATE, callingPackage);
+            } else {
+                granted = getContext().getPackageManager().checkPermission(
+                        Manifest.permission.MODIFY_PHONE_STATE, callingPackage);
+            }
         }
         return granted == PackageManager.PERMISSION_GRANTED
                 || telephonyManager.hasCarrierPrivileges(args.subscriptionId);
diff --git a/src/com/android/phone/SpecialCharSequenceMgr.java b/src/com/android/phone/SpecialCharSequenceMgr.java
index 8fe084b23..d0fe2c18a 100644
--- a/src/com/android/phone/SpecialCharSequenceMgr.java
+++ b/src/com/android/phone/SpecialCharSequenceMgr.java
@@ -21,6 +21,7 @@ import android.app.AlertDialog;
 import android.content.ActivityNotFoundException;
 import android.content.Context;
 import android.content.Intent;
+import android.os.UserHandle;
 import android.os.UserManager;
 import android.provider.Settings;
 import android.telephony.PhoneNumberUtils;
@@ -186,7 +187,7 @@ public class SpecialCharSequenceMgr {
                                     "com.android.phone.SimContacts");
                 intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                 intent.putExtra("index", index);
-                PhoneGlobals.getInstance().startActivity(intent);
+                PhoneGlobals.getInstance().startActivityAsUser(intent, UserHandle.CURRENT);
 
                 return true;
             } catch (NumberFormatException ex) {}
@@ -313,9 +314,9 @@ public class SpecialCharSequenceMgr {
             log("handleRegulatoryInfoDisplay() sending intent to settings app");
             Intent showRegInfoIntent = new Intent(Settings.ACTION_SHOW_REGULATORY_INFO);
             try {
-                context.startActivity(showRegInfoIntent);
+                context.startActivityAsUser(showRegInfoIntent, UserHandle.CURRENT);
             } catch (ActivityNotFoundException e) {
-                Log.e(TAG, "startActivity() failed: " + e);
+                Log.e(TAG, "startActivityAsUser() failed: " + e);
             }
             return true;
         }
diff --git a/src/com/android/phone/TelephonyShellCommand.java b/src/com/android/phone/TelephonyShellCommand.java
index 696927562..bfc93e0ed 100644
--- a/src/com/android/phone/TelephonyShellCommand.java
+++ b/src/com/android/phone/TelephonyShellCommand.java
@@ -34,6 +34,7 @@ import android.os.PersistableBundle;
 import android.os.Process;
 import android.os.RemoteException;
 import android.os.ServiceSpecificException;
+import android.os.UserHandle;
 import android.provider.BlockedNumberContract;
 import android.telephony.BarringInfo;
 import android.telephony.CarrierConfigManager;
@@ -209,6 +210,8 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
             "set-should-send-datagram-to-modem-in-demo-mode";
     private static final String SET_IS_SATELLITE_COMMUNICATION_ALLOWED_FOR_CURRENT_LOCATION_CACHE =
             "set-is-satellite-communication-allowed-for-current-location-cache";
+    private static final String SET_SATELLITE_SUBSCRIBERID_LIST_CHANGED_INTENT_COMPONENT =
+            "set-satellite-subscriberid-list-changed-intent-component";
 
     private static final String DOMAIN_SELECTION_SUBCOMMAND = "domainselection";
     private static final String DOMAIN_SELECTION_SET_SERVICE_OVERRIDE = "set-dss-override";
@@ -422,6 +425,8 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
                 return handleSetOemEnabledSatelliteProvisionStatus();
             case SET_IS_SATELLITE_COMMUNICATION_ALLOWED_FOR_CURRENT_LOCATION_CACHE:
                 return handleSetIsSatelliteCommunicationAllowedForCurrentLocationCache();
+            case SET_SATELLITE_SUBSCRIBERID_LIST_CHANGED_INTENT_COMPONENT:
+                return handleSetSatelliteSubscriberIdListChangedIntentComponent();
             default: {
                 return handleDefaultCommands(cmd);
             }
@@ -1115,7 +1120,8 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         }
         // Verify that the user is allowed to run the command. Only allowed in rooted device in a
         // non user build.
-        if (Binder.getCallingUid() != Process.ROOT_UID || TelephonyUtils.IS_USER) {
+        if (!UserHandle.isSameApp(Binder.getCallingUid(), Process.ROOT_UID)
+                || TelephonyUtils.IS_USER) {
             errPw.println("cc: Permission denied.");
             return -1;
         }
@@ -1681,14 +1687,15 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
 
     private boolean checkShellUid() {
         // adb can run as root or as shell, depending on whether the device is rooted.
-        return Binder.getCallingUid() == Process.SHELL_UID
-                || Binder.getCallingUid() == Process.ROOT_UID;
+        return UserHandle.isSameApp(Binder.getCallingUid(), Process.SHELL_UID)
+                || UserHandle.isSameApp(Binder.getCallingUid(), Process.ROOT_UID);
     }
 
     private int handleCcCommand() {
         // Verify that the user is allowed to run the command. Only allowed in rooted device in a
         // non user build.
-        if (Binder.getCallingUid() != Process.ROOT_UID || TelephonyUtils.IS_USER) {
+        if (!UserHandle.isSameApp(Binder.getCallingUid(), Process.ROOT_UID)
+                || TelephonyUtils.IS_USER) {
             getErrPrintWriter().println("cc: Permission denied.");
             return -1;
         }
@@ -2244,7 +2251,8 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
     private int handleRestartModemCommand() {
         // Verify that the user is allowed to run the command. Only allowed in rooted device in a
         // non user build.
-        if (Binder.getCallingUid() != Process.ROOT_UID || TelephonyUtils.IS_USER) {
+        if (!UserHandle.isSameApp(Binder.getCallingUid(), Process.ROOT_UID)
+                || TelephonyUtils.IS_USER) {
             getErrPrintWriter().println("RestartModem: Permission denied.");
             return -1;
         }
@@ -2258,7 +2266,8 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
     private int handleGetImei() {
         // Verify that the user is allowed to run the command. Only allowed in rooted device in a
         // non user build.
-        if (Binder.getCallingUid() != Process.ROOT_UID || TelephonyUtils.IS_USER) {
+        if (!UserHandle.isSameApp(Binder.getCallingUid(), Process.ROOT_UID)
+                || TelephonyUtils.IS_USER) {
             getErrPrintWriter().println("Device IMEI: Permission denied.");
             return -1;
         }
@@ -2289,7 +2298,8 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
     private int handleUnattendedReboot() {
         // Verify that the user is allowed to run the command. Only allowed in rooted device in a
         // non user build.
-        if (Binder.getCallingUid() != Process.ROOT_UID || TelephonyUtils.IS_USER) {
+        if (!UserHandle.isSameApp(Binder.getCallingUid(), Process.ROOT_UID)
+                || TelephonyUtils.IS_USER) {
             getErrPrintWriter().println("UnattendedReboot: Permission denied.");
             return -1;
         }
@@ -2303,7 +2313,8 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
     private int handleGetSimSlotsMapping() {
         // Verify that the user is allowed to run the command. Only allowed in rooted device in a
         // non user build.
-        if (Binder.getCallingUid() != Process.ROOT_UID || TelephonyUtils.IS_USER) {
+        if (!UserHandle.isSameApp(Binder.getCallingUid(), Process.ROOT_UID)
+                || TelephonyUtils.IS_USER) {
             getErrPrintWriter().println("GetSimSlotsMapping: Permission denied.");
             return -1;
         }
@@ -3203,6 +3214,7 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
     private int handleSetSatelliteServicePackageNameCommand() {
         PrintWriter errPw = getErrPrintWriter();
         String serviceName = null;
+        String provisioned = null;
 
         String opt;
         while ((opt = getNextOption()) != null) {
@@ -3211,24 +3223,31 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
                     serviceName = getNextArgRequired();
                     break;
                 }
+
+                case "-p": {
+                    provisioned = getNextArgRequired();
+                    break;
+                }
             }
         }
         Log.d(LOG_TAG, "handleSetSatelliteServicePackageNameCommand: serviceName="
-                + serviceName);
+                + serviceName + ", provisioned=" + provisioned);
 
         try {
-            boolean result = mInterface.setSatelliteServicePackageName(serviceName);
+            boolean result = mInterface.setSatelliteServicePackageName(serviceName, provisioned);
             if (VDBG) {
-                Log.v(LOG_TAG, "SetSatelliteServicePackageName " + serviceName
-                        + ", result = " + result);
+                Log.v(LOG_TAG,
+                        "SetSatelliteServicePackageName " + serviceName + ", provisioned="
+                                + provisioned + ", result = " + result);
             }
             getOutPrintWriter().println(result);
         } catch (RemoteException e) {
-            Log.w(LOG_TAG, "SetSatelliteServicePackageName: " + serviceName
-                    + ", error = " + e.getMessage());
+            Log.w(LOG_TAG, "SetSatelliteServicePackageName: " + serviceName + ", provisioned="
+                    + provisioned + ", error = " + e.getMessage());
             errPw.println("Exception: " + e.getMessage());
             return -1;
         }
+
         return 0;
     }
 
@@ -3758,6 +3777,54 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         return 0;
     }
 
+    private int handleSetSatelliteSubscriberIdListChangedIntentComponent() {
+        final String cmd = SET_SATELLITE_SUBSCRIBERID_LIST_CHANGED_INTENT_COMPONENT;
+        PrintWriter errPw = getErrPrintWriter();
+        String opt;
+        String name;
+
+        if ((opt = getNextArg()) == null) {
+            errPw.println("adb shell cmd phone " + cmd + ": Invalid Argument");
+            return -1;
+        } else {
+            switch (opt) {
+                case "-p": {
+                    name = opt + "/" + "android.telephony.cts";
+                    break;
+                }
+                case "-c": {
+                    name = opt + "/" + "android.telephony.cts.SatelliteReceiver";
+                    break;
+                }
+                case "-r": {
+                    name = "reset";
+                    break;
+                }
+                default:
+                    errPw.println("adb shell cmd phone " + cmd + ": Invalid Argument");
+                    return -1;
+            }
+        }
+
+        Log.d(LOG_TAG, "handleSetSatelliteSubscriberIdListChangedIntentComponent("
+                + name + ")");
+
+        try {
+            boolean result = mInterface.setSatelliteSubscriberIdListChangedIntentComponent(name);
+            if (VDBG) {
+                Log.v(LOG_TAG, "handleSetSatelliteSubscriberIdListChangedIntentComponent "
+                        + "returns: " + result);
+            }
+            getOutPrintWriter().println(result);
+        } catch (RemoteException e) {
+            Log.w(LOG_TAG, "handleSetSatelliteSubscriberIdListChangedIntentComponent("
+                    + name + "), error = " + e.getMessage());
+            errPw.println("Exception: " + e.getMessage());
+            return -1;
+        }
+        return 0;
+    }
+
     /**
      * Sample inputStr = "US,UK,CA;2,1,3"
      * Sample output: {[US,2], [UK,1], [CA,3]}
diff --git a/src/com/android/phone/euicc/EuiccUiDispatcherActivity.java b/src/com/android/phone/euicc/EuiccUiDispatcherActivity.java
index 3e4406286..a75f26f35 100644
--- a/src/com/android/phone/euicc/EuiccUiDispatcherActivity.java
+++ b/src/com/android/phone/euicc/EuiccUiDispatcherActivity.java
@@ -90,7 +90,7 @@ public class EuiccUiDispatcherActivity extends Activity {
             }
 
             euiccUiIntent.setFlags(Intent.FLAG_ACTIVITY_FORWARD_RESULT);
-            startActivity(euiccUiIntent);
+            startActivityAsUser(euiccUiIntent, UserHandle.CURRENT);
         } finally {
             // Since we're using Theme.NO_DISPLAY, we must always finish() at the end of onCreate().
             finish();
diff --git a/src/com/android/phone/satellite/accesscontrol/SatelliteAccessController.java b/src/com/android/phone/satellite/accesscontrol/SatelliteAccessController.java
index be7179ecb..7b244a1d9 100644
--- a/src/com/android/phone/satellite/accesscontrol/SatelliteAccessController.java
+++ b/src/com/android/phone/satellite/accesscontrol/SatelliteAccessController.java
@@ -19,16 +19,25 @@ package com.android.phone.satellite.accesscontrol;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_COMMUNICATION_ALLOWED;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_PROVISIONED;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_SUPPORTED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_LOCATION_DISABLED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_LOCATION_NOT_AVAILABLE;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_NOT_SUPPORTED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_SUCCESS;
 
+import static com.android.internal.telephony.satellite.SatelliteConstants.TRIGGERING_EVENT_EXTERNAL_REQUEST;
+import static com.android.internal.telephony.satellite.SatelliteConstants.TRIGGERING_EVENT_LOCATION_SETTINGS_ENABLED;
+import static com.android.internal.telephony.satellite.SatelliteConstants.TRIGGERING_EVENT_MCC_CHANGED;
+import static com.android.internal.telephony.satellite.SatelliteConstants.TRIGGERING_EVENT_UNKNOWN;
 import static com.android.internal.telephony.satellite.SatelliteController.SATELLITE_SHARED_PREF;
 
 import android.annotation.ArrayRes;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
+import android.content.BroadcastReceiver;
 import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
 import android.content.SharedPreferences;
 import android.content.res.Resources;
 import android.location.Location;
@@ -58,6 +67,7 @@ import android.telephony.satellite.ISatelliteCommunicationAllowedStateCallback;
 import android.telephony.satellite.ISatelliteProvisionStateCallback;
 import android.telephony.satellite.ISatelliteSupportedStateCallback;
 import android.telephony.satellite.SatelliteManager;
+import android.telephony.satellite.SatelliteSubscriberProvisionStatus;
 import android.text.TextUtils;
 import android.util.Pair;
 
@@ -84,7 +94,6 @@ import java.io.InputStream;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.StandardCopyOption;
-import java.time.Duration;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collection;
@@ -129,10 +138,12 @@ public class SatelliteAccessController extends Handler {
     private static final boolean DEBUG = !"user".equals(Build.TYPE);
     private static final int MAX_CACHE_SIZE = 50;
 
-    private static final int CMD_IS_SATELLITE_COMMUNICATION_ALLOWED = 1;
+    protected static final int CMD_IS_SATELLITE_COMMUNICATION_ALLOWED = 1;
     protected static final int EVENT_WAIT_FOR_CURRENT_LOCATION_TIMEOUT = 2;
     protected static final int EVENT_KEEP_ON_DEVICE_ACCESS_CONTROLLER_RESOURCES_TIMEOUT = 3;
     protected static final int EVENT_CONFIG_DATA_UPDATED = 4;
+    protected static final int EVENT_COUNTRY_CODE_CHANGED = 5;
+    protected static final int EVENT_LOCATION_SETTINGS_ENABLED = 6;
 
     private static SatelliteAccessController sInstance;
 
@@ -193,7 +204,7 @@ public class SatelliteAccessController extends Handler {
     };
     @GuardedBy("mLock")
     @Nullable
-    CancellationSignal mLocationRequestCancellationSignal = null;
+    protected CancellationSignal mLocationRequestCancellationSignal = null;
     private int mS2Level = DEFAULT_S2_LEVEL;
     @GuardedBy("mLock")
     @Nullable
@@ -223,6 +234,25 @@ public class SatelliteAccessController extends Handler {
     @Nullable
     private PersistentLogger mPersistentLogger = null;
 
+    private final Object mPossibleChangeInSatelliteAllowedRegionLock = new Object();
+    @GuardedBy("mPossibleChangeInSatelliteAllowedRegionLock")
+    private boolean mIsSatelliteAllowedRegionPossiblyChanged = false;
+    protected long mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos = 0;
+
+    protected int mRetryCountForValidatingPossibleChangeInAllowedRegion;
+    protected static final int
+            DEFAULT_DELAY_MINUTES_BEFORE_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION = 10;
+    protected static final int
+            DEFAULT_MAX_RETRY_COUNT_FOR_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION = 3;
+    protected static final int DEFAULT_THROTTLE_INTERVAL_FOR_LOCATION_QUERY_MINUTES = 10;
+
+    private long mRetryIntervalToEvaluateUserInSatelliteAllowedRegion = 0;
+    private int mMaxRetryCountForValidatingPossibleChangeInAllowedRegion = 0;
+    private long mLocationQueryThrottleIntervalNanos = 0;
+
+    @NonNull
+    protected ResultReceiver mHandlerForSatelliteAllowedResult;
+
     /**
      * Map key: binder of the callback, value: callback to receive the satellite communication
      * allowed state changed events.
@@ -233,25 +263,46 @@ public class SatelliteAccessController extends Handler {
     @GuardedBy("mSatelliteCommunicationAllowStateLock")
     private boolean mCurrentSatelliteAllowedState = false;
 
-    private static final long ALLOWED_STATE_CACHE_VALID_DURATION_HOURS =
-            Duration.ofHours(4).toNanos();
+    protected static final long ALLOWED_STATE_CACHE_VALID_DURATION_NANOS =
+            TimeUnit.HOURS.toNanos(4);
+
     private boolean mLatestSatelliteCommunicationAllowed;
-    private long mLatestSatelliteCommunicationAllowedSetTime;
+    protected long mLatestSatelliteCommunicationAllowedSetTime;
 
     private long mLocationQueryStartTimeMillis;
     private long mOnDeviceLookupStartTimeMillis;
     private long mTotalCheckingStartTimeMillis;
 
+    protected BroadcastReceiver mLocationModeChangedBroadcastReceiver = new BroadcastReceiver() {
+        @Override
+        public void onReceive(Context context, Intent intent) {
+            if (intent.getAction().equals(LocationManager.MODE_CHANGED_ACTION)) {
+                plogd("LocationManager mode is changed");
+                if (mLocationManager.isLocationEnabled()) {
+                    plogd("Location settings is just enabled");
+                    sendRequestAsync(EVENT_LOCATION_SETTINGS_ENABLED, null);
+                }
+            }
+        }
+    };
+
+    private final Object mIsAllowedCheckBeforeEnablingSatelliteLock = new Object();
+    @GuardedBy("mIsAllowedCheckBeforeEnablingSatelliteLock")
+    private boolean mIsAllowedCheckBeforeEnablingSatellite;
+
     /**
      * Create a SatelliteAccessController instance.
      *
      * @param context                           The context associated with the
      *                                          {@link SatelliteAccessController} instance.
      * @param featureFlags                      The FeatureFlags that are supported.
-     * @param locationManager                   The LocationManager for querying current location of
+     * @param locationManager                   The LocationManager for querying current
+     *                                          location of
      *                                          the device.
-     * @param looper                            The Looper to run the SatelliteAccessController on.
-     * @param satelliteOnDeviceAccessController The on-device satellite access controller instance.
+     * @param looper                            The Looper to run the SatelliteAccessController
+     *                                          on.
+     * @param satelliteOnDeviceAccessController The on-device satellite access controller
+     *                                          instance.
      */
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
     protected SatelliteAccessController(@NonNull Context context,
@@ -268,7 +319,13 @@ public class SatelliteAccessController extends Handler {
         mLocationManager = locationManager;
         mTelecomManager = telecomManager;
         mSatelliteOnDeviceAccessController = satelliteOnDeviceAccessController;
-        mCountryDetector = TelephonyCountryDetector.getInstance(context);
+
+        mCountryDetector = TelephonyCountryDetector.getInstance(context, mFeatureFlags);
+        mCountryDetector.registerForCountryCodeChanged(this,
+                EVENT_COUNTRY_CODE_CHANGED, null);
+        initializeHandlerForSatelliteAllowedResult();
+        setIsSatelliteAllowedRegionPossiblyChanged(false);
+
         mSatelliteController = SatelliteController.getInstance();
         mControllerMetricsStats = ControllerMetricsStats.getInstance();
         mAccessControllerMetricsStats = AccessControllerMetricsStats.getInstance();
@@ -303,17 +360,16 @@ public class SatelliteAccessController extends Handler {
                 logd("onSatelliteSupportedStateChanged: isSupported=" + isSupported);
                 if (isSupported) {
                     requestIsCommunicationAllowedForCurrentLocation(
-                            SubscriptionManager.DEFAULT_SUBSCRIPTION_ID, new ResultReceiver(null) {
+                            new ResultReceiver(null) {
                                 @Override
                                 protected void onReceiveResult(int resultCode, Bundle resultData) {
                                     // do nothing
                                 }
-                            });
+                            }, false);
                 }
             }
         };
         mSatelliteController.registerForSatelliteSupportedStateChanged(
-                SubscriptionManager.DEFAULT_SUBSCRIPTION_ID,
                 mInternalSatelliteSupportedStateCallback);
 
         mInternalSatelliteProvisionStateCallback = new ISatelliteProvisionStateCallback.Stub() {
@@ -322,21 +378,28 @@ public class SatelliteAccessController extends Handler {
                 logd("onSatelliteProvisionStateChanged: isProvisioned=" + isProvisioned);
                 if (isProvisioned) {
                     requestIsCommunicationAllowedForCurrentLocation(
-                            SubscriptionManager.DEFAULT_SUBSCRIPTION_ID, new ResultReceiver(null) {
+                            new ResultReceiver(null) {
                                 @Override
                                 protected void onReceiveResult(int resultCode, Bundle resultData) {
                                     // do nothing
                                 }
-                            });
+                            }, false);
                 }
             }
+
+            @Override
+            public void onSatelliteSubscriptionProvisionStateChanged(
+                    List<SatelliteSubscriberProvisionStatus> satelliteSubscriberProvisionStatus) {
+                logd("onSatelliteSubscriptionProvisionStateChanged: "
+                        + satelliteSubscriberProvisionStatus);
+            }
         };
         mSatelliteController.registerForSatelliteProvisionStateChanged(
-                SubscriptionManager.DEFAULT_SUBSCRIPTION_ID,
                 mInternalSatelliteProvisionStateCallback);
 
         // Init the SatelliteOnDeviceAccessController so that the S2 level can be cached
         initSatelliteOnDeviceAccessController();
+        registerLocationModeChangedBroadcastReceiver(context);
     }
 
     private void updateCurrentSatelliteAllowedState(boolean isAllowed) {
@@ -347,6 +410,7 @@ public class SatelliteAccessController extends Handler {
                         + mCurrentSatelliteAllowedState);
                 mCurrentSatelliteAllowedState = isAllowed;
                 notifySatelliteCommunicationAllowedStateChanged(isAllowed);
+                mControllerMetricsStats.reportAllowedStateChanged();
             }
         }
     }
@@ -383,6 +447,11 @@ public class SatelliteAccessController extends Handler {
                 AsyncResult ar = (AsyncResult) msg.obj;
                 updateSatelliteConfigData((Context) ar.userObj);
                 break;
+            case EVENT_LOCATION_SETTINGS_ENABLED:
+                // Fall through
+            case EVENT_COUNTRY_CODE_CHANGED:
+                handleSatelliteAllowedRegionPossiblyChanged(msg.what);
+                break;
             default:
                 plogw("SatelliteAccessControllerHandler: unexpected message code: " + msg.what);
                 break;
@@ -392,20 +461,25 @@ public class SatelliteAccessController extends Handler {
     /**
      * Request to get whether satellite communication is allowed for the current location.
      *
-     * @param subId  The subId of the subscription to check whether satellite communication is
-     *               allowed for the current location for.
      * @param result The result receiver that returns whether satellite communication is allowed
      *               for the current location if the request is successful or an error code
      *               if the request failed.
      */
-    public void requestIsCommunicationAllowedForCurrentLocation(int subId,
-            @NonNull ResultReceiver result) {
+    public void requestIsCommunicationAllowedForCurrentLocation(
+            @NonNull ResultReceiver result, boolean enablingSatellite) {
         if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
             plogd("oemEnabledSatelliteFlag is disabled");
             result.send(SATELLITE_RESULT_REQUEST_NOT_SUPPORTED, null);
             return;
         }
-        sendRequestAsync(CMD_IS_SATELLITE_COMMUNICATION_ALLOWED, new Pair<>(subId, result));
+        plogd("requestIsCommunicationAllowedForCurrentLocation : "
+                + "enablingSatellite is " + enablingSatellite);
+        synchronized (mIsAllowedCheckBeforeEnablingSatelliteLock) {
+            mIsAllowedCheckBeforeEnablingSatellite = enablingSatellite;
+        }
+        mAccessControllerMetricsStats.setTriggeringEvent(TRIGGERING_EVENT_EXTERNAL_REQUEST);
+        sendRequestAsync(CMD_IS_SATELLITE_COMMUNICATION_ALLOWED,
+                new Pair<>(mSatelliteController.getSatellitePhone().getSubId(), result));
     }
 
     /**
@@ -731,7 +805,8 @@ public class SatelliteAccessController extends Handler {
         mConfigUpdaterMetricsStats.reportConfigUpdateSuccess();
     }
 
-    private void loadOverlayConfigs(@NonNull Context context) {
+    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
+    protected void loadOverlayConfigs(@NonNull Context context) {
         mSatelliteCountryCodes = getSatelliteCountryCodesFromOverlayConfig(context);
         mIsSatelliteAllowAccessControl = getSatelliteAccessAllowFromOverlayConfig(context);
         String satelliteS2CellFileName = getSatelliteS2CellFileFromOverlayConfig(context);
@@ -744,6 +819,11 @@ public class SatelliteAccessController extends Handler {
         mLocationFreshDurationNanos = getSatelliteLocationFreshDurationFromOverlayConfig(context);
         mAccessControllerMetricsStats.setConfigDataSource(
                 SatelliteConstants.CONFIG_DATA_SOURCE_DEVICE_CONFIG);
+        mRetryIntervalToEvaluateUserInSatelliteAllowedRegion =
+                getDelayBeforeRetryValidatingPossibleChangeInSatelliteAllowedRegionMillis(context);
+        mMaxRetryCountForValidatingPossibleChangeInAllowedRegion =
+                getMaxRetryCountForValidatingPossibleChangeInAllowedRegion(context);
+        mLocationQueryThrottleIntervalNanos = getLocationQueryThrottleIntervalNanos(context);
     }
 
     private void loadConfigUpdaterConfigs() {
@@ -848,7 +928,7 @@ public class SatelliteAccessController extends Handler {
             }
             mTotalCheckingStartTimeMillis = System.currentTimeMillis();
             mSatelliteController.requestIsSatelliteSupported(
-                    requestArguments.first, mInternalSatelliteSupportedResultReceiver);
+                    mInternalSatelliteSupportedResultReceiver);
         }
     }
 
@@ -866,7 +946,43 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
-    private void handleIsSatelliteSupportedResult(int resultCode, Bundle resultData) {
+    private void registerLocationModeChangedBroadcastReceiver(Context context) {
+        if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
+            plogd("registerLocationModeChangedBroadcastReceiver: Flag "
+                    + "oemEnabledSatellite is disabled");
+            return;
+        }
+        IntentFilter intentFilter = new IntentFilter();
+        intentFilter.addAction(LocationManager.MODE_CHANGED_ACTION);
+        context.registerReceiver(mLocationModeChangedBroadcastReceiver, intentFilter);
+    }
+
+    /**
+     * At country borders, a multi-SIM device might connect to multiple cellular base
+     * stations and thus might have multiple different MCCs.
+     * In such cases, framework is not sure whether the region should be disallowed or not,
+     * and thus the geofence data will be used to decide whether to allow satellite.
+     */
+    private boolean isRegionDisallowed(List<String> networkCountryIsoList) {
+        if (networkCountryIsoList.isEmpty()) {
+            plogd("isRegionDisallowed : false : network country code is not available");
+            return false;
+        }
+
+        for (String countryCode : networkCountryIsoList) {
+            if (isSatelliteAccessAllowedForLocation(List.of(countryCode))) {
+                plogd("isRegionDisallowed : false : Country Code " + countryCode
+                        + " is allowed but not sure if current location should be allowed.");
+                return false;
+            }
+        }
+
+        plogd("isRegionDisallowed : true : " + networkCountryIsoList);
+        return true;
+    }
+
+    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
+    protected void handleIsSatelliteSupportedResult(int resultCode, Bundle resultData) {
         plogd("handleIsSatelliteSupportedResult: resultCode=" + resultCode);
         synchronized (mLock) {
             if (resultCode == SATELLITE_RESULT_SUCCESS) {
@@ -877,10 +993,23 @@ public class SatelliteAccessController extends Handler {
                         Bundle bundle = new Bundle();
                         bundle.putBoolean(SatelliteManager.KEY_SATELLITE_COMMUNICATION_ALLOWED,
                                 false);
-                        sendSatelliteAllowResultToReceivers(resultCode, bundle, false);
+                        sendSatelliteAllowResultToReceivers(SATELLITE_RESULT_NOT_SUPPORTED, bundle,
+                                false);
                     } else {
                         plogd("Satellite is supported");
-                        checkSatelliteAccessRestrictionUsingGPS();
+                        List<String> networkCountryIsoList =
+                                mCountryDetector.getCurrentNetworkCountryIso();
+                        if (isRegionDisallowed(networkCountryIsoList)) {
+                            Bundle bundle = new Bundle();
+                            bundle.putBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED, false);
+                            mAccessControllerMetricsStats.setAccessControlType(
+                                    SatelliteConstants.ACCESS_CONTROL_TYPE_NETWORK_COUNTRY_CODE)
+                                    .setCountryCodes(networkCountryIsoList);
+                            sendSatelliteAllowResultToReceivers(SATELLITE_RESULT_SUCCESS, bundle,
+                                    false);
+                        } else {
+                            checkSatelliteAccessRestrictionUsingGPS();
+                        }
                     }
                 } else {
                     ploge("KEY_SATELLITE_SUPPORTED does not exist.");
@@ -921,6 +1050,7 @@ public class SatelliteAccessController extends Handler {
 
     private void sendSatelliteAllowResultToReceivers(int resultCode, Bundle resultData,
             boolean allowed) {
+        plogd("sendSatelliteAllowResultToReceivers : resultCode is " + resultCode);
         if (resultCode == SATELLITE_RESULT_SUCCESS) {
             updateCurrentSatelliteAllowedState(allowed);
         }
@@ -930,11 +1060,18 @@ public class SatelliteAccessController extends Handler {
             }
             mSatelliteAllowResultReceivers.clear();
         }
+        if (!shouldRetryValidatingPossibleChangeInAllowedRegion(resultCode)) {
+            setIsSatelliteAllowedRegionPossiblyChanged(false);
+        }
+        synchronized (mIsAllowedCheckBeforeEnablingSatelliteLock) {
+            mIsAllowedCheckBeforeEnablingSatellite = false;
+        }
         reportMetrics(resultCode, allowed);
     }
 
     /**
-     * Telephony-internal logic to verify if satellite access is restricted at the current location.
+     * Telephony-internal logic to verify if satellite access is restricted at the current
+     * location.
      */
     private void checkSatelliteAccessRestrictionForCurrentLocation() {
         synchronized (mLock) {
@@ -964,30 +1101,124 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
+    private boolean shouldRetryValidatingPossibleChangeInAllowedRegion(int resultCode) {
+        return (resultCode == SATELLITE_RESULT_LOCATION_NOT_AVAILABLE);
+    }
+
+    private void initializeHandlerForSatelliteAllowedResult() {
+        mHandlerForSatelliteAllowedResult = new ResultReceiver(null) {
+            @Override
+            protected void onReceiveResult(int resultCode, Bundle resultData) {
+                plogd("query satellite allowed for current "
+                        + "location, resultCode=" + resultCode + ", resultData=" + resultData);
+                synchronized (mPossibleChangeInSatelliteAllowedRegionLock) {
+                    if (shouldRetryValidatingPossibleChangeInAllowedRegion(resultCode)
+                            && (mRetryCountForValidatingPossibleChangeInAllowedRegion
+                            < mMaxRetryCountForValidatingPossibleChangeInAllowedRegion)) {
+                        mRetryCountForValidatingPossibleChangeInAllowedRegion++;
+                        plogd("mRetryCountForValidatingPossibleChangeInAllowedRegion is "
+                                + mRetryCountForValidatingPossibleChangeInAllowedRegion);
+                        sendDelayedRequestAsync(CMD_IS_SATELLITE_COMMUNICATION_ALLOWED,
+                                new Pair<>(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID,
+                                        mHandlerForSatelliteAllowedResult),
+                                mRetryIntervalToEvaluateUserInSatelliteAllowedRegion);
+                    } else {
+                        mRetryCountForValidatingPossibleChangeInAllowedRegion = 0;
+                        plogd("Stop retry validating the possible change in satellite allowed "
+                                + "region");
+                    }
+                }
+            }
+        };
+    }
+
+    private void handleSatelliteAllowedRegionPossiblyChanged(int handleEvent) {
+        if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
+            ploge("handleSatelliteAllowedRegionPossiblyChanged: "
+                    + "The feature flag oemEnabledSatelliteFlag() is not enabled");
+            return;
+        }
+        synchronized (mPossibleChangeInSatelliteAllowedRegionLock) {
+            logd("handleSatelliteAllowedRegionPossiblyChanged");
+            setIsSatelliteAllowedRegionPossiblyChanged(true);
+            requestIsCommunicationAllowedForCurrentLocation(
+                    mHandlerForSatelliteAllowedResult, false);
+            int triggeringEvent = TRIGGERING_EVENT_UNKNOWN;
+            if (handleEvent == EVENT_LOCATION_SETTINGS_ENABLED) {
+                triggeringEvent = TRIGGERING_EVENT_LOCATION_SETTINGS_ENABLED;
+            } else if (handleEvent == EVENT_COUNTRY_CODE_CHANGED) {
+                triggeringEvent = TRIGGERING_EVENT_MCC_CHANGED;
+            }
+            mAccessControllerMetricsStats.setTriggeringEvent(triggeringEvent);
+        }
+    }
+
+    protected boolean allowLocationQueryForSatelliteAllowedCheck() {
+        synchronized (mPossibleChangeInSatelliteAllowedRegionLock) {
+            if (!isCommunicationAllowedCacheValid()) {
+                logd("allowLocationQueryForSatelliteAllowedCheck: cache is not valid");
+                return true;
+            }
+
+            if (isSatelliteAllowedRegionPossiblyChanged() && !isLocationQueryThrottled()) {
+                logd("allowLocationQueryForSatelliteAllowedCheck: location query is not throttled");
+                return true;
+            }
+        }
+        logd("allowLocationQueryForSatelliteAllowedCheck: false");
+        return false;
+    }
+
+    private boolean isLocationQueryThrottled() {
+        if (mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos == 0) {
+            plogv("isLocationQueryThrottled: "
+                    + "mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos is 0, return "
+                    + "false");
+            return false;
+        }
+
+        long currentTime = getElapsedRealtimeNanos();
+        if (currentTime - mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos
+                > mLocationQueryThrottleIntervalNanos) {
+            plogv("isLocationQueryThrottled: currentTime - "
+                    + "mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos is "
+                    + "bigger than " + mLocationQueryThrottleIntervalNanos + " so return false");
+            return false;
+        }
+
+        plogd("isLocationQueryThrottled : true");
+        return true;
+    }
+
     /**
      * Telephony-internal logic to verify if satellite access is restricted from the location query.
      */
-    private void checkSatelliteAccessRestrictionUsingGPS() {
+    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
+    public void checkSatelliteAccessRestrictionUsingGPS() {
         logv("checkSatelliteAccessRestrictionUsingGPS:");
-        if (isInEmergency()) {
-            executeLocationQuery();
-        } else {
-            if (mLocationManager.isLocationEnabled()) {
-                plogd("location query is allowed");
-                if (isCommunicationAllowedCacheValid()) {
-                    Bundle bundle = new Bundle();
-                    bundle.putBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED,
-                            mLatestSatelliteCommunicationAllowed);
-                    sendSatelliteAllowResultToReceivers(SATELLITE_RESULT_SUCCESS, bundle,
-                            mLatestSatelliteCommunicationAllowed);
+        synchronized (mIsAllowedCheckBeforeEnablingSatelliteLock) {
+            if (isInEmergency()) {
+                executeLocationQuery();
+            } else {
+                if (mLocationManager.isLocationEnabled()) {
+                    plogd("location query is allowed");
+                    if (allowLocationQueryForSatelliteAllowedCheck()
+                            || mIsAllowedCheckBeforeEnablingSatellite) {
+                        executeLocationQuery();
+                    } else {
+                        Bundle bundle = new Bundle();
+                        bundle.putBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED,
+                                mLatestSatelliteCommunicationAllowed);
+                        sendSatelliteAllowResultToReceivers(SATELLITE_RESULT_SUCCESS, bundle,
+                                mLatestSatelliteCommunicationAllowed);
+                    }
                 } else {
-                    executeLocationQuery();
+                    plogv("location query is not allowed");
+                    Bundle bundle = new Bundle();
+                    bundle.putBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED, false);
+                    sendSatelliteAllowResultToReceivers(
+                            SATELLITE_RESULT_LOCATION_DISABLED, bundle, false);
                 }
-            } else {
-                plogv("location query is not allowed");
-                Bundle bundle = new Bundle();
-                bundle.putBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED, false);
-                sendSatelliteAllowResultToReceivers(SATELLITE_RESULT_SUCCESS, bundle, false);
             }
         }
     }
@@ -998,9 +1229,9 @@ public class SatelliteAccessController extends Handler {
      */
     private boolean isCommunicationAllowedCacheValid() {
         if (mLatestSatelliteCommunicationAllowedSetTime > 0) {
-            long currentTime = SystemClock.elapsedRealtimeNanos();
+            long currentTime = getElapsedRealtimeNanos();
             if ((currentTime - mLatestSatelliteCommunicationAllowedSetTime)
-                    <= ALLOWED_STATE_CACHE_VALID_DURATION_HOURS) {
+                    <= ALLOWED_STATE_CACHE_VALID_DURATION_NANOS) {
                 logv("isCommunicationAllowedCacheValid: cache is valid");
                 return true;
             }
@@ -1010,7 +1241,15 @@ public class SatelliteAccessController extends Handler {
     }
 
     private void executeLocationQuery() {
-        plogv("executeLocationQuery");
+        plogd("executeLocationQuery");
+        synchronized (mPossibleChangeInSatelliteAllowedRegionLock) {
+            if (isSatelliteAllowedRegionPossiblyChanged()) {
+                mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos =
+                        getElapsedRealtimeNanos();
+                plogd("mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos is set "
+                        + mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos);
+            }
+        }
         synchronized (mLock) {
             mFreshLastKnownLocation = getFreshLastKnownLocation();
             checkSatelliteAccessRestrictionUsingOnDeviceData();
@@ -1078,15 +1317,16 @@ public class SatelliteAccessController extends Handler {
     private void queryCurrentLocation() {
         synchronized (mLock) {
             if (mLocationRequestCancellationSignal != null) {
-                plogd("Request for current location was already sent to LocationManager");
+                plogd("queryCurrentLocation : "
+                        + "Request for current location was already sent to LocationManager");
                 return;
             }
             mLocationRequestCancellationSignal = new CancellationSignal();
             mLocationQueryStartTimeMillis = System.currentTimeMillis();
-            mLocationManager.getCurrentLocation(LocationManager.GPS_PROVIDER,
+            mLocationManager.getCurrentLocation(LocationManager.FUSED_PROVIDER,
                     new LocationRequest.Builder(0)
                             .setQuality(LocationRequest.QUALITY_HIGH_ACCURACY)
-                            .setLocationSettingsIgnored(true)
+                            .setLocationSettingsIgnored(isInEmergency())
                             .build(),
                     mLocationRequestCancellationSignal, this::post,
                     this::onCurrentLocationAvailable);
@@ -1112,6 +1352,7 @@ public class SatelliteAccessController extends Handler {
                 }
                 mAccessControllerMetricsStats.setAccessControlType(
                         SatelliteConstants.ACCESS_CONTROL_TYPE_CURRENT_LOCATION);
+                mControllerMetricsStats.reportLocationQuerySuccessful(true);
                 checkSatelliteAccessRestrictionForLocation(location);
             } else {
                 plogd("current location is not available");
@@ -1126,6 +1367,7 @@ public class SatelliteAccessController extends Handler {
                     sendSatelliteAllowResultToReceivers(
                             SATELLITE_RESULT_LOCATION_NOT_AVAILABLE, bundle, false);
                 }
+                mControllerMetricsStats.reportLocationQuerySuccessful(false);
             }
         }
     }
@@ -1159,7 +1401,7 @@ public class SatelliteAccessController extends Handler {
                 sendSatelliteAllowResultToReceivers(SATELLITE_RESULT_SUCCESS, bundle,
                         satelliteAllowed);
                 mLatestSatelliteCommunicationAllowed = satelliteAllowed;
-                mLatestSatelliteCommunicationAllowedSetTime = SystemClock.elapsedRealtimeNanos();
+                mLatestSatelliteCommunicationAllowedSetTime = getElapsedRealtimeNanos();
                 persistLatestSatelliteCommunicationAllowedState();
             } catch (Exception ex) {
                 ploge("checkSatelliteAccessRestrictionForLocation: ex=" + ex);
@@ -1196,7 +1438,8 @@ public class SatelliteAccessController extends Handler {
         return true;
     }
 
-    private boolean isSatelliteAccessAllowedForLocation(
+    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
+    protected boolean isSatelliteAccessAllowedForLocation(
             @NonNull List<String> networkCountryIsoList) {
         if (isSatelliteAllowAccessControl()) {
             // The current country is unidentified, we're uncertain and thus returning false
@@ -1259,6 +1502,9 @@ public class SatelliteAccessController extends Handler {
             long lastKnownLocationAge =
                     getElapsedRealtimeNanos() - lastKnownLocation.getElapsedRealtimeNanos();
             if (lastKnownLocationAge <= getLocationFreshDurationNanos()) {
+                plogd("getFreshLastKnownLocation: lat=" + Rlog.pii(TAG,
+                        lastKnownLocation.getLatitude())
+                        + ", long=" + Rlog.pii(TAG, lastKnownLocation.getLongitude()));
                 return lastKnownLocation;
             }
         }
@@ -1427,6 +1673,63 @@ public class SatelliteAccessController extends Handler {
                 .collect(Collectors.toList());
     }
 
+    @NonNull
+    private static long getDelayBeforeRetryValidatingPossibleChangeInSatelliteAllowedRegionMillis(
+            @NonNull Context context) {
+        Integer retryDuration = null;
+        try {
+            retryDuration = context.getResources().getInteger(com.android.internal.R.integer
+                    .config_satellite_delay_minutes_before_retry_validating_possible_change_in_allowed_region);
+        } catch (Resources.NotFoundException ex) {
+            loge("getDelayBeforeRetryValidatingPossibleChangeInSatelliteAllowedRegionMillis: got "
+                    + "ex=" + ex);
+        }
+        if (retryDuration == null) {
+            logd("Use default retry duration for possible change satellite allowed region ="
+                    + DEFAULT_DELAY_MINUTES_BEFORE_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION);
+            retryDuration =
+                    DEFAULT_DELAY_MINUTES_BEFORE_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION;
+        }
+        return TimeUnit.MINUTES.toMillis(retryDuration);
+    }
+
+    @NonNull
+    private static int getMaxRetryCountForValidatingPossibleChangeInAllowedRegion(
+            @NonNull Context context) {
+        Integer maxRetrycount = null;
+        try {
+            maxRetrycount = context.getResources().getInteger(com.android.internal.R.integer
+                    .config_satellite_max_retry_count_for_validating_possible_change_in_allowed_region);
+        } catch (Resources.NotFoundException ex) {
+            loge("getMaxRetryCountForValidatingPossibleChangeInAllowedRegion: got ex= " + ex);
+        }
+        if (maxRetrycount == null) {
+            logd("Use default max retry count for possible change satellite allowed region ="
+                    + DEFAULT_MAX_RETRY_COUNT_FOR_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION);
+            maxRetrycount =
+                    DEFAULT_MAX_RETRY_COUNT_FOR_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION;
+        }
+        return maxRetrycount;
+    }
+
+    @NonNull
+    private static long getLocationQueryThrottleIntervalNanos(@NonNull Context context) {
+        Integer throttleInterval = null;
+        try {
+            throttleInterval = context.getResources().getInteger(com.android.internal.R.integer
+                    .config_satellite_location_query_throttle_interval_minutes);
+        } catch (Resources.NotFoundException ex) {
+            loge("getLocationQueryThrottleIntervalNanos: got ex=" + ex);
+        }
+        if (throttleInterval == null) {
+            logd("Use default location query throttle interval ="
+                    + DEFAULT_THROTTLE_INTERVAL_FOR_LOCATION_QUERY_MINUTES);
+            throttleInterval =
+                    DEFAULT_THROTTLE_INTERVAL_FOR_LOCATION_QUERY_MINUTES;
+        }
+        return TimeUnit.MINUTES.toNanos(throttleInterval);
+    }
+
     @NonNull
     private static String[] readStringArrayFromOverlayConfig(
             @NonNull Context context, @ArrayRes int id) {
@@ -1511,6 +1814,17 @@ public class SatelliteAccessController extends Handler {
                 || SystemProperties.getBoolean(BOOT_ALLOW_MOCK_MODEM_PROPERTY, false));
     }
 
+    /**
+     * Posts the specified command to be executed on the main thread and returns immediately.
+     *
+     * @param command  command to be executed on the main thread
+     * @param argument additional parameters required to perform of the operation
+     */
+    private void sendDelayedRequestAsync(int command, @NonNull Object argument, long dealyMillis) {
+        Message msg = this.obtainMessage(command, argument);
+        sendMessageDelayed(msg, dealyMillis);
+    }
+
     /**
      * Posts the specified command to be executed on the main thread and returns immediately.
      *
@@ -1541,6 +1855,20 @@ public class SatelliteAccessController extends Handler {
         }
 
         mSatelliteCommunicationAllowedStateChangedListeners.put(callback.asBinder(), callback);
+
+        this.post(() -> {
+            try {
+                synchronized (mSatelliteCommunicationAllowStateLock) {
+                    callback.onSatelliteCommunicationAllowedStateChanged(
+                            mCurrentSatelliteAllowedState);
+                    logd("registerForCommunicationAllowedStateChanged: "
+                            + "mCurrentSatelliteAllowedState " + mCurrentSatelliteAllowedState);
+                }
+            } catch (RemoteException ex) {
+                ploge("registerForCommunicationAllowedStateChanged: RemoteException ex=" + ex);
+            }
+        });
+
         return SATELLITE_RESULT_SUCCESS;
     }
 
@@ -1569,7 +1897,7 @@ public class SatelliteAccessController extends Handler {
      * This API can be used by only CTS to set the cache whether satellite communication is allowed.
      *
      * @param state a state indicates whether satellite access allowed state should be cached and
-     * the allowed state.
+     *              the allowed state.
      * @return {@code true} if the setting is successful, {@code false} otherwise.
      */
     public boolean setIsSatelliteCommunicationAllowedForCurrentLocationCache(String state) {
@@ -1589,7 +1917,7 @@ public class SatelliteAccessController extends Handler {
 
         synchronized (mSatelliteCommunicationAllowStateLock) {
             if ("cache_allowed".equalsIgnoreCase(state)) {
-                mLatestSatelliteCommunicationAllowedSetTime = SystemClock.elapsedRealtimeNanos();
+                mLatestSatelliteCommunicationAllowedSetTime = getElapsedRealtimeNanos();
                 mLatestSatelliteCommunicationAllowed = true;
                 mCurrentSatelliteAllowedState = true;
             } else if ("cache_clear_and_not_allowed".equalsIgnoreCase(state)) {
@@ -1646,6 +1974,19 @@ public class SatelliteAccessController extends Handler {
         mTotalCheckingStartTimeMillis = 0;
     }
 
+    protected boolean isSatelliteAllowedRegionPossiblyChanged() {
+        synchronized (mPossibleChangeInSatelliteAllowedRegionLock) {
+            return mIsSatelliteAllowedRegionPossiblyChanged;
+        }
+    }
+
+    protected void setIsSatelliteAllowedRegionPossiblyChanged(boolean changed) {
+        synchronized (mPossibleChangeInSatelliteAllowedRegionLock) {
+            plogd("setIsSatelliteAllowedRegionPossiblyChanged : " + changed);
+            mIsSatelliteAllowedRegionPossiblyChanged = changed;
+        }
+    }
+
     private static void logd(@NonNull String log) {
         Rlog.d(TAG, log);
     }
diff --git a/src/com/android/phone/satellite/entitlement/SatelliteEntitlementController.java b/src/com/android/phone/satellite/entitlement/SatelliteEntitlementController.java
index 307d1e6e6..8d9850d6c 100644
--- a/src/com/android/phone/satellite/entitlement/SatelliteEntitlementController.java
+++ b/src/com/android/phone/satellite/entitlement/SatelliteEntitlementController.java
@@ -145,8 +145,10 @@ public class SatelliteEntitlementController extends Handler {
         mCarrierConfigManager = context.getSystemService(CarrierConfigManager.class);
         mCarrierConfigChangeListener = (slotIndex, subId, carrierId, specificCarrierId) ->
                 handleCarrierConfigChanged(slotIndex, subId, carrierId, specificCarrierId);
-        mCarrierConfigManager.registerCarrierConfigChangeListener(this::post,
-                mCarrierConfigChangeListener);
+        if (mCarrierConfigManager != null) {
+            mCarrierConfigManager.registerCarrierConfigChangeListener(this::post,
+                    mCarrierConfigChangeListener);
+        }
         mConnectivityManager = context.getSystemService(ConnectivityManager.class);
         mNetworkCallback = new ConnectivityManager.NetworkCallback() {
             @Override
@@ -620,11 +622,14 @@ public class SatelliteEntitlementController extends Handler {
 
     @NonNull
     private PersistableBundle getConfigForSubId(int subId) {
-        PersistableBundle config = mCarrierConfigManager.getConfigForSubId(subId,
-                CarrierConfigManager.ImsServiceEntitlement.KEY_ENTITLEMENT_SERVER_URL_STRING,
-                CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_STATUS_REFRESH_DAYS_INT,
-                CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL,
-                CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_APP_NAME_STRING);
+        PersistableBundle config = null;
+        if (mCarrierConfigManager != null) {
+            config = mCarrierConfigManager.getConfigForSubId(subId,
+                    CarrierConfigManager.ImsServiceEntitlement.KEY_ENTITLEMENT_SERVER_URL_STRING,
+                    CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_STATUS_REFRESH_DAYS_INT,
+                    CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL,
+                    CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_APP_NAME_STRING);
+        }
         if (config == null || config.isEmpty()) {
             config = CarrierConfigManager.getDefaultConfig();
         }
diff --git a/src/com/android/phone/settings/RadioInfo.java b/src/com/android/phone/settings/RadioInfo.java
index c59f92ab4..24d680c19 100644
--- a/src/com/android/phone/settings/RadioInfo.java
+++ b/src/com/android/phone/settings/RadioInfo.java
@@ -20,8 +20,8 @@ import static android.net.ConnectivityManager.NetworkCallback;
 
 import static java.util.concurrent.TimeUnit.MILLISECONDS;
 
+import android.annotation.NonNull;
 import android.content.ComponentName;
-import android.content.Context;
 import android.content.DialogInterface;
 import android.content.Intent;
 import android.content.pm.ComponentInfo;
@@ -29,7 +29,6 @@ import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
 import android.content.res.Resources;
 import android.graphics.Typeface;
-import android.hardware.radio.modem.ImeiInfo;
 import android.net.ConnectivityManager;
 import android.net.Network;
 import android.net.NetworkCapabilities;
@@ -41,9 +40,11 @@ import android.os.Build;
 import android.os.Bundle;
 import android.os.Handler;
 import android.os.HandlerExecutor;
+import android.os.HandlerThread;
 import android.os.Message;
 import android.os.PersistableBundle;
 import android.os.SystemProperties;
+import android.os.UserHandle;
 import android.os.UserManager;
 import android.telephony.AccessNetworkConstants;
 import android.telephony.CarrierConfigManager;
@@ -68,6 +69,7 @@ import android.telephony.DataSpecificRegistrationInfo;
 import android.telephony.NetworkRegistrationInfo;
 import android.telephony.PhysicalChannelConfig;
 import android.telephony.RadioAccessFamily;
+import android.telephony.RadioAccessSpecifier;
 import android.telephony.ServiceState;
 import android.telephony.SignalStrength;
 import android.telephony.SubscriptionManager;
@@ -83,6 +85,8 @@ import android.telephony.ims.ImsRcsManager;
 import android.telephony.ims.ProvisioningManager;
 import android.telephony.ims.feature.MmTelFeature;
 import android.telephony.ims.stub.ImsRegistrationImplBase;
+import android.telephony.satellite.EnableRequestAttributes;
+import android.telephony.satellite.SatelliteManager;
 import android.text.TextUtils;
 import android.util.Log;
 import android.view.Menu;
@@ -105,21 +109,26 @@ import androidx.appcompat.app.AppCompatActivity;
 
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneFactory;
+import com.android.internal.telephony.RILConstants;
 import com.android.internal.telephony.euicc.EuiccConnector;
-import com.android.internal.telephony.util.TelephonyUtils;
 import com.android.phone.R;
 
 import java.io.IOException;
 import java.net.HttpURLConnection;
 import java.net.URL;
+import java.util.ArrayList;
 import java.util.Arrays;
+import java.util.Collections;
 import java.util.List;
+import java.util.Locale;
 import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.ExecutionException;
 import java.util.concurrent.LinkedBlockingDeque;
 import java.util.concurrent.ThreadPoolExecutor;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.TimeoutException;
+import java.util.concurrent.atomic.AtomicBoolean;
 
 /**
  * Radio Information Class
@@ -132,9 +141,6 @@ public class RadioInfo extends AppCompatActivity {
 
     private static final boolean IS_USER_BUILD = "user".equals(Build.TYPE);
 
-    private static final String ACTION_ESOS_TEST =
-            "com.google.android.apps.stargate.ACTION_ESOS_QUESTIONNAIRE";
-
     private static final String[] PREFERRED_NETWORK_LABELS = {
             "GSM/WCDMA preferred",
             "GSM only",
@@ -203,7 +209,7 @@ public class RadioInfo extends AppCompatActivity {
             ServiceState.RIL_RADIO_TECHNOLOGY_LTE_CA,
             ServiceState.RIL_RADIO_TECHNOLOGY_NR
     };
-    private static String[] sPhoneIndexLabels;
+    private static String[] sPhoneIndexLabels = new String[0];
 
     private static final int sCellInfoListRateDisabled = Integer.MAX_VALUE;
     private static final int sCellInfoListRateMax = 0;
@@ -247,7 +253,6 @@ public class RadioInfo extends AppCompatActivity {
 
     private static final int EVENT_QUERY_SMSC_DONE = 1005;
     private static final int EVENT_UPDATE_SMSC_DONE = 1006;
-    private static final int EVENT_PHYSICAL_CHANNEL_CONFIG_CHANGED = 1007;
     private static final int EVENT_UPDATE_NR_STATS = 1008;
 
     private static final int MENU_ITEM_VIEW_ADN            = 1;
@@ -290,7 +295,6 @@ public class RadioInfo extends AppCompatActivity {
     private TextView mPingHostnameV6;
     private TextView mHttpClientTest;
     private TextView mPhyChanConfig;
-    private TextView mDnsCheckState;
     private TextView mDownlinkKbps;
     private TextView mUplinkKbps;
     private TextView mEndcAvailable;
@@ -303,8 +307,8 @@ public class RadioInfo extends AppCompatActivity {
     private EditText mSmsc;
     private Switch mRadioPowerOnSwitch;
     private Switch mSimulateOutOfServiceSwitch;
+    private Switch mEnforceSatelliteChannel;
     private Switch mMockSatellite;
-    private Button mDnsCheckToggleButton;
     private Button mPingTestButton;
     private Button mUpdateSmscButton;
     private Button mRefreshSmscButton;
@@ -312,6 +316,8 @@ public class RadioInfo extends AppCompatActivity {
     private Button mCarrierProvisioningButton;
     private Button mTriggerCarrierProvisioningButton;
     private Button mEsosButton;
+    private Button mSatelliteEnableNonEmergencyModeButton;
+    private Button mEsosDemoButton;
     private Switch mImsVolteProvisionedSwitch;
     private Switch mImsVtProvisionedSwitch;
     private Switch mImsWfcProvisionedSwitch;
@@ -343,7 +349,10 @@ public class RadioInfo extends AppCompatActivity {
     private boolean mMwiValue = false;
     private boolean mCfiValue = false;
 
+    private boolean mSystemUser = true;
+
     private final PersistableBundle[] mCarrierSatelliteOriginalBundle = new PersistableBundle[2];
+    private final PersistableBundle[] mOriginalSystemChannels = new PersistableBundle[2];
     private List<CellInfo> mCellInfoResult = null;
     private final boolean[] mSimulateOos = new boolean[2];
     private int[] mSelectedSignalStrengthIndex = new int[2];
@@ -352,7 +361,17 @@ public class RadioInfo extends AppCompatActivity {
 
     private int mPreferredNetworkTypeResult;
     private int mCellInfoRefreshRateIndex;
-    private int mSelectedPhoneIndex;
+    private int mPhoneId = SubscriptionManager.INVALID_PHONE_INDEX;
+    private static final int DEFAULT_PHONE_ID = 0;
+
+    private int mSubId = SubscriptionManager.INVALID_SUBSCRIPTION_ID;
+
+    private String mActionEsos;
+    private String mActionEsosDemo;
+
+    private TelephonyDisplayInfo mDisplayInfo;
+
+    private List<PhysicalChannelConfig> mPhysicalChannelConfigs = new ArrayList<>();
 
     private final NetworkRequest mDefaultNetworkRequest = new NetworkRequest.Builder()
             .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
@@ -380,6 +399,7 @@ public class RadioInfo extends AppCompatActivity {
             TelephonyCallback.CellInfoListener,
             TelephonyCallback.SignalStrengthsListener,
             TelephonyCallback.ServiceStateListener,
+            TelephonyCallback.PhysicalChannelConfigListener,
             TelephonyCallback.DisplayInfoListener {
 
         @Override
@@ -444,16 +464,23 @@ public class RadioInfo extends AppCompatActivity {
 
         @Override
         public void onDisplayInfoChanged(TelephonyDisplayInfo displayInfo) {
+            mDisplayInfo = displayInfo;
             updateNetworkType();
         }
+
+        @Override
+        public void onPhysicalChannelConfigChanged(@NonNull List<PhysicalChannelConfig> configs) {
+            updatePhysicalChannelConfiguration(configs);
+        }
     }
 
     private void updatePhysicalChannelConfiguration(List<PhysicalChannelConfig> configs) {
+        mPhysicalChannelConfigs = configs;
         StringBuilder sb = new StringBuilder();
         String div = "";
         sb.append("{");
-        if (configs != null) {
-            for (PhysicalChannelConfig c : configs) {
+        if (mPhysicalChannelConfigs != null) {
+            for (PhysicalChannelConfig c : mPhysicalChannelConfigs) {
                 sb.append(div).append(c);
                 div = ",";
             }
@@ -472,24 +499,21 @@ public class RadioInfo extends AppCompatActivity {
         mPreferredNetworkType.setSelection(mPreferredNetworkTypeResult, true);
     }
 
-    private void updatePhoneIndex(int phoneIndex, int subId) {
+    private void updatePhoneIndex() {
         // unregister listeners on the old subId
         unregisterPhoneStateListener();
-        mTelephonyManager.setCellInfoListRate(sCellInfoListRateDisabled, mPhone.getSubId());
-
-        if (phoneIndex == SubscriptionManager.INVALID_PHONE_INDEX) {
-            log("Invalid phone index " + phoneIndex + ", subscription ID " + subId);
-            return;
-        }
+        mTelephonyManager.setCellInfoListRate(sCellInfoListRateDisabled, mSubId);
 
         // update the subId
-        mTelephonyManager = mTelephonyManager.createForSubscriptionId(subId);
+        mTelephonyManager = mTelephonyManager.createForSubscriptionId(mSubId);
 
         // update the phoneId
-        mPhone = PhoneFactory.getPhone(phoneIndex);
-        mImsManager = new ImsManager(mPhone.getContext());
+        if (mSystemUser) {
+            mPhone = PhoneFactory.getPhone(mPhoneId);
+        }
+        mImsManager = new ImsManager(this);
         try {
-            mProvisioningManager = ProvisioningManager.createForSubscriptionId(subId);
+            mProvisioningManager = ProvisioningManager.createForSubscriptionId(mSubId);
         } catch (IllegalArgumentException e) {
             log("updatePhoneIndex : IllegalArgumentException " + e.getMessage());
             mProvisioningManager = null;
@@ -518,13 +542,6 @@ public class RadioInfo extends AppCompatActivity {
                         mSmsc.setText("update error");
                     }
                     break;
-                case EVENT_PHYSICAL_CHANNEL_CONFIG_CHANGED:
-                    ar = (AsyncResult) msg.obj;
-                    if (ar.exception != null) {
-                        mPhyChanConfig.setText(("update error"));
-                    }
-                    updatePhysicalChannelConfiguration((List<PhysicalChannelConfig>) ar.result);
-                    break;
                 case EVENT_UPDATE_NR_STATS:
                     log("got EVENT_UPDATE_NR_STATS");
                     updateNrStats();
@@ -540,14 +557,9 @@ public class RadioInfo extends AppCompatActivity {
     @Override
     public void onCreate(Bundle icicle) {
         super.onCreate(icicle);
-        if (!android.os.Process.myUserHandle().isSystem()) {
-            Log.e(TAG, "Not run from system user, don't do anything.");
-            finish();
-            return;
-        }
-
-        UserManager userManager =
-                (UserManager) getApplicationContext().getSystemService(Context.USER_SERVICE);
+        mSystemUser = android.os.Process.myUserHandle().isSystem();
+        log("onCreate: mSystemUser=" + mSystemUser);
+        UserManager userManager = getSystemService(UserManager.class);
         if (userManager != null
                 && userManager.hasUserRestriction(UserManager.DISALLOW_CONFIG_MOBILE_NETWORKS)) {
             Log.w(TAG, "User is restricted from configuring mobile networks.");
@@ -556,20 +568,39 @@ public class RadioInfo extends AppCompatActivity {
         }
 
         setContentView(R.layout.radio_info);
+        Resources r = getResources();
+        mActionEsos =
+            r.getString(
+                    com.android.internal.R.string
+                            .config_satellite_test_with_esp_replies_intent_action);
 
-        log("Started onCreate");
+        mActionEsosDemo =
+            r.getString(
+                    com.android.internal.R.string.config_satellite_demo_mode_sos_intent_action);
 
         mQueuedWork = new ThreadPoolExecutor(1, 1, RUNNABLE_TIMEOUT_MS, TimeUnit.MICROSECONDS,
-                new LinkedBlockingDeque<Runnable>());
-        mConnectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
-        mPhone = getPhone(SubscriptionManager.getDefaultSubscriptionId());
-        mTelephonyManager = ((TelephonyManager) getSystemService(TELEPHONY_SERVICE))
-                .createForSubscriptionId(mPhone.getSubId());
+                new LinkedBlockingDeque<>());
+        mConnectivityManager = getSystemService(ConnectivityManager.class);
+        if (mSystemUser) {
+            mPhone = getPhone(SubscriptionManager.getDefaultSubscriptionId());
+        }
+        mSubId = SubscriptionManager.getDefaultSubscriptionId();
+        if (mPhone != null) {
+            mPhoneId = mPhone.getPhoneId();
+        } else {
+            mPhoneId = SubscriptionManager.getPhoneId(mSubId);
+        }
+        if (!SubscriptionManager.isValidPhoneId(mPhoneId)) {
+            mPhoneId = DEFAULT_PHONE_ID;
+        }
+
+        mTelephonyManager = getSystemService(TelephonyManager.class)
+                .createForSubscriptionId(mSubId);
         mEuiccManager = getSystemService(EuiccManager.class);
 
-        mImsManager = new ImsManager(mPhone.getContext());
+        mImsManager = new ImsManager(this);
         try {
-            mProvisioningManager = ProvisioningManager.createForSubscriptionId(mPhone.getSubId());
+            mProvisioningManager = ProvisioningManager.createForSubscriptionId(mSubId);
         } catch (IllegalArgumentException e) {
             log("onCreate : IllegalArgumentException " + e.getMessage());
             mProvisioningManager = null;
@@ -602,7 +633,6 @@ public class RadioInfo extends AppCompatActivity {
         mSent = (TextView) findViewById(R.id.sent);
         mReceived = (TextView) findViewById(R.id.received);
         mSmsc = (EditText) findViewById(R.id.smsc);
-        mDnsCheckState = (TextView) findViewById(R.id.dnsCheckState);
         mPingHostnameV4 = (TextView) findViewById(R.id.pingHostnameV4);
         mPingHostnameV6 = (TextView) findViewById(R.id.pingHostnameV6);
         mHttpClientTest = (TextView) findViewById(R.id.httpClientTest);
@@ -629,8 +659,10 @@ public class RadioInfo extends AppCompatActivity {
         mPreferredNetworkType.setAdapter(mPreferredNetworkTypeAdapter);
 
         mMockSignalStrength = (Spinner) findViewById(R.id.signalStrength);
-        if (!TelephonyUtils.IS_DEBUGGABLE) {
+        if (!Build.isDebuggable() || !mSystemUser) {
             mMockSignalStrength.setVisibility(View.GONE);
+            findViewById(R.id.signalStrength).setVisibility(View.GONE);
+            findViewById(R.id.signal_strength_label).setVisibility(View.GONE);
         } else {
             ArrayAdapter<Integer> mSignalStrengthAdapter = new ArrayAdapter<>(this,
                     android.R.layout.simple_spinner_item, SIGNAL_STRENGTH_LEVEL);
@@ -640,8 +672,10 @@ public class RadioInfo extends AppCompatActivity {
         }
 
         mMockDataNetworkType = (Spinner) findViewById(R.id.dataNetworkType);
-        if (!TelephonyUtils.IS_DEBUGGABLE) {
+        if (!Build.isDebuggable() || !mSystemUser) {
             mMockDataNetworkType.setVisibility(View.GONE);
+            findViewById(R.id.dataNetworkType).setVisibility(View.GONE);
+            findViewById(R.id.data_network_type_label).setVisibility(View.GONE);
         } else {
             ArrayAdapter<String> mNetworkTypeAdapter = new ArrayAdapter<>(this,
                     android.R.layout.simple_spinner_item, Arrays.stream(MOCK_DATA_NETWORK_TYPE)
@@ -668,7 +702,7 @@ public class RadioInfo extends AppCompatActivity {
         mImsWfcProvisionedSwitch = (Switch) findViewById(R.id.wfc_provisioned_switch);
         mEabProvisionedSwitch = (Switch) findViewById(R.id.eab_provisioned_switch);
 
-        if (!isImsSupportedOnDevice(mPhone.getContext())) {
+        if (!isImsSupportedOnDevice()) {
             mImsVolteProvisionedSwitch.setVisibility(View.GONE);
             mImsVtProvisionedSwitch.setVisibility(View.GONE);
             mImsWfcProvisionedSwitch.setVisibility(View.GONE);
@@ -705,13 +739,15 @@ public class RadioInfo extends AppCompatActivity {
         mRadioPowerOnSwitch = (Switch) findViewById(R.id.radio_power);
 
         mSimulateOutOfServiceSwitch = (Switch) findViewById(R.id.simulate_out_of_service);
-        if (!TelephonyUtils.IS_DEBUGGABLE) {
+        if (!Build.isDebuggable()) {
             mSimulateOutOfServiceSwitch.setVisibility(View.GONE);
         }
 
         mMockSatellite = (Switch) findViewById(R.id.mock_carrier_roaming_satellite);
-        if (!TelephonyUtils.IS_DEBUGGABLE) {
+        mEnforceSatelliteChannel = (Switch) findViewById(R.id.enforce_satellite_channel);
+        if (!Build.isDebuggable()) {
             mMockSatellite.setVisibility(View.GONE);
+            mEnforceSatelliteChannel.setVisibility(View.GONE);
         }
 
         mDownlinkKbps = (TextView) findViewById(R.id.dl_kbps);
@@ -724,8 +760,12 @@ public class RadioInfo extends AppCompatActivity {
         mUpdateSmscButton.setOnClickListener(mUpdateSmscButtonHandler);
         mRefreshSmscButton = (Button) findViewById(R.id.refresh_smsc);
         mRefreshSmscButton.setOnClickListener(mRefreshSmscButtonHandler);
-        mDnsCheckToggleButton = (Button) findViewById(R.id.dns_check_toggle);
-        mDnsCheckToggleButton.setOnClickListener(mDnsCheckButtonHandler);
+        if (!mSystemUser) {
+            mSmsc.setVisibility(View.GONE);
+            mUpdateSmscButton.setVisibility(View.GONE);
+            mRefreshSmscButton.setVisibility(View.GONE);
+            findViewById(R.id.smsc_label).setVisibility(View.GONE);
+        }
         mCarrierProvisioningButton = (Button) findViewById(R.id.carrier_provisioning);
         if (!TextUtils.isEmpty(getCarrierProvisioningAppString())) {
             mCarrierProvisioningButton.setOnClickListener(mCarrierProvisioningButtonHandler);
@@ -743,14 +783,36 @@ public class RadioInfo extends AppCompatActivity {
         }
 
         mEsosButton = (Button) findViewById(R.id.esos_questionnaire);
-        if (!TelephonyUtils.IS_DEBUGGABLE) {
-            mEsosButton.setVisibility(View.GONE);
+        mEsosDemoButton  = (Button) findViewById(R.id.demo_esos_questionnaire);
+        mSatelliteEnableNonEmergencyModeButton = (Button) findViewById(
+                R.id.satellite_enable_non_emergency_mode);
+        CarrierConfigManager cm = getSystemService(CarrierConfigManager.class);
+        if (!cm.getConfigForSubId(mSubId,
+                        CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL)
+                .getBoolean(CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL)) {
+            mSatelliteEnableNonEmergencyModeButton.setVisibility(View.GONE);
+        }
+        if (!Build.isDebuggable()) {
+            if (!TextUtils.isEmpty(mActionEsos)) {
+                mEsosButton.setVisibility(View.GONE);
+            }
+            if (!TextUtils.isEmpty(mActionEsosDemo)) {
+                mEsosDemoButton.setVisibility(View.GONE);
+            }
+            mSatelliteEnableNonEmergencyModeButton.setVisibility(View.GONE);
         } else {
-            mEsosButton.setOnClickListener(v ->
-                    mPhone.getContext().startActivity(
-                        new Intent(ACTION_ESOS_TEST)
-                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK))
+            mEsosButton.setOnClickListener(v -> startActivityAsUser(
+                    new Intent(mActionEsos).addFlags(
+                            Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK),
+                    UserHandle.CURRENT)
             );
+            mEsosDemoButton.setOnClickListener(v -> startActivityAsUser(
+                    new Intent(mActionEsosDemo).addFlags(
+                            Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK),
+                    UserHandle.CURRENT)
+            );
+            mSatelliteEnableNonEmergencyModeButton.setOnClickListener(v ->
+                    enableSatelliteNonEmergencyMode());
         }
 
         mOemInfoButton = (Button) findViewById(R.id.oem_info);
@@ -764,7 +826,6 @@ public class RadioInfo extends AppCompatActivity {
 
         mCellInfoRefreshRateIndex = 0; //disabled
         mPreferredNetworkTypeResult = PREFERRED_NETWORK_LABELS.length - 1; //Unknown
-        mSelectedPhoneIndex = mPhone.getPhoneId();
 
         new Thread(() -> {
             int networkType = (int) mTelephonyManager.getPreferredNetworkTypeBitmask();
@@ -802,7 +863,6 @@ public class RadioInfo extends AppCompatActivity {
         updateRadioPowerState();
         updateImsProvisionedState();
         updateProperties();
-        updateDnsCheckState();
         updateNetworkType();
         updateNrStats();
         updateEuiccInfo();
@@ -819,7 +879,7 @@ public class RadioInfo extends AppCompatActivity {
         mCellInfoRefreshRateSpinner.setSelection(mCellInfoRefreshRateIndex);
         // Request cell information update from RIL.
         mTelephonyManager.setCellInfoListRate(CELL_INFO_REFRESH_RATES[mCellInfoRefreshRateIndex],
-                mPhone.getSubId());
+                mSubId);
 
         //set selection before registering to prevent update
         mPreferredNetworkType.setSelection(mPreferredNetworkTypeResult, true);
@@ -832,22 +892,24 @@ public class RadioInfo extends AppCompatActivity {
         }).start();
 
         // mock signal strength
-        mMockSignalStrength.setSelection(mSelectedSignalStrengthIndex[mPhone.getPhoneId()]);
+        mMockSignalStrength.setSelection(mSelectedSignalStrengthIndex[mPhoneId]);
         mMockSignalStrength.setOnItemSelectedListener(mOnMockSignalStrengthSelectedListener);
 
         // mock data network type
-        mMockDataNetworkType.setSelection(mSelectedMockDataNetworkTypeIndex[mPhone.getPhoneId()]);
+        mMockDataNetworkType.setSelection(mSelectedMockDataNetworkTypeIndex[mPhoneId]);
         mMockDataNetworkType.setOnItemSelectedListener(mOnMockDataNetworkTypeSelectedListener);
 
         // set phone index
-        mSelectPhoneIndex.setSelection(mSelectedPhoneIndex, true);
+        mSelectPhoneIndex.setSelection(mPhoneId, true);
         mSelectPhoneIndex.setOnItemSelectedListener(mSelectPhoneIndexHandler);
 
         mRadioPowerOnSwitch.setOnCheckedChangeListener(mRadioPowerOnChangeListener);
-        mSimulateOutOfServiceSwitch.setChecked(mSimulateOos[mPhone.getPhoneId()]);
+        mSimulateOutOfServiceSwitch.setChecked(mSimulateOos[mPhoneId]);
         mSimulateOutOfServiceSwitch.setOnCheckedChangeListener(mSimulateOosOnChangeListener);
-        mMockSatellite.setChecked(mCarrierSatelliteOriginalBundle[mPhone.getPhoneId()] != null);
+        mMockSatellite.setChecked(mCarrierSatelliteOriginalBundle[mPhoneId] != null);
         mMockSatellite.setOnCheckedChangeListener(mMockSatelliteListener);
+        updateSatelliteChannelDisplay(mPhoneId);
+        mEnforceSatelliteChannel.setOnCheckedChangeListener(mForceSatelliteChannelOnChangeListener);
         mImsVolteProvisionedSwitch.setOnCheckedChangeListener(mImsVolteCheckedChangeListener);
         mImsVtProvisionedSwitch.setOnCheckedChangeListener(mImsVtCheckedChangeListener);
         mImsWfcProvisionedSwitch.setOnCheckedChangeListener(mImsWfcCheckedChangeListener);
@@ -860,9 +922,6 @@ public class RadioInfo extends AppCompatActivity {
 
         unregisterPhoneStateListener();
         registerPhoneStateListener();
-        mPhone.registerForPhysicalChannelConfig(mHandler,
-            EVENT_PHYSICAL_CHANNEL_CONFIG_CHANGED, null);
-
         mConnectivityManager.registerNetworkCallback(
                 mDefaultNetworkRequest, mNetworkCallback, mHandler);
 
@@ -876,7 +935,7 @@ public class RadioInfo extends AppCompatActivity {
         log("onPause: unregister phone & data intents");
 
         mTelephonyManager.unregisterTelephonyCallback(mTelephonyCallback);
-        mTelephonyManager.setCellInfoListRate(sCellInfoListRateDisabled, mPhone.getSubId());
+        mTelephonyManager.setCellInfoListRate(sCellInfoListRateDisabled, mSubId);
         mConnectivityManager.unregisterNetworkCallback(mNetworkCallback);
 
     }
@@ -897,7 +956,8 @@ public class RadioInfo extends AppCompatActivity {
         mPreferredNetworkTypeResult = b.getInt("mPreferredNetworkTypeResult",
                 PREFERRED_NETWORK_LABELS.length - 1);
 
-        mSelectedPhoneIndex = b.getInt("mSelectedPhoneIndex", 0);
+        mPhoneId = b.getInt("mSelectedPhoneIndex", 0);
+        mSubId = SubscriptionManager.getSubscriptionId(mPhoneId);
 
         mCellInfoRefreshRateIndex = b.getInt("mCellInfoRefreshRateIndex", 0);
     }
@@ -910,7 +970,7 @@ public class RadioInfo extends AppCompatActivity {
         outState.putString("mHttpClientTestResult", mHttpClientTestResult);
 
         outState.putInt("mPreferredNetworkTypeResult", mPreferredNetworkTypeResult);
-        outState.putInt("mSelectedPhoneIndex", mSelectedPhoneIndex);
+        outState.putInt("mSelectedPhoneIndex", mPhoneId);
         outState.putInt("mCellInfoRefreshRateIndex", mCellInfoRefreshRateIndex);
 
     }
@@ -924,7 +984,7 @@ public class RadioInfo extends AppCompatActivity {
                 R.string.radioInfo_menu_viewFDN).setOnMenuItemClickListener(mViewFDNCallback);
         menu.add(1, MENU_ITEM_VIEW_SDN, 0,
                 R.string.radioInfo_menu_viewSDN).setOnMenuItemClickListener(mViewSDNCallback);
-        if (isImsSupportedOnDevice(mPhone.getContext())) {
+        if (isImsSupportedOnDevice()) {
             menu.add(1, MENU_ITEM_GET_IMS_STATUS,
                     0, R.string.radioInfo_menu_getIMS).setOnMenuItemClickListener(mGetImsStatus);
         }
@@ -959,6 +1019,7 @@ public class RadioInfo extends AppCompatActivity {
 
     @Override
     protected void onDestroy() {
+        log("onDestroy");
         clearOverride();
         super.onDestroy();
         if (mQueuedWork != null) {
@@ -968,17 +1029,19 @@ public class RadioInfo extends AppCompatActivity {
 
     private void clearOverride() {
         for (int phoneId = 0; phoneId < sPhoneIndexLabels.length; phoneId++) {
-            mPhone = PhoneFactory.getPhone(phoneId);
-            if (mSimulateOos[mPhone.getPhoneId()])  {
+            if (mSystemUser) {
+                mPhone = PhoneFactory.getPhone(phoneId);
+            }
+            if (mSimulateOos[mPhoneId])  {
                 mSimulateOosOnChangeListener.onCheckedChanged(mSimulateOutOfServiceSwitch, false);
             }
-            if (mCarrierSatelliteOriginalBundle[mPhone.getPhoneId()] != null) {
+            if (mCarrierSatelliteOriginalBundle[mPhoneId] != null) {
                 mMockSatelliteListener.onCheckedChanged(mMockSatellite, false);
             }
-            if (mSelectedSignalStrengthIndex[mPhone.getPhoneId()] > 0) {
+            if (mSelectedSignalStrengthIndex[mPhoneId] > 0) {
                 mOnMockSignalStrengthSelectedListener.onItemSelected(null, null, 0/*pos*/, 0);
             }
-            if (mSelectedMockDataNetworkTypeIndex[mPhone.getPhoneId()] > 0) {
+            if (mSelectedMockDataNetworkTypeIndex[mPhoneId] > 0) {
                 mOnMockDataNetworkTypeSelectedListener.onItemSelected(null, null, 0/*pos*/, 0);
             }
         }
@@ -997,7 +1060,6 @@ public class RadioInfo extends AppCompatActivity {
 
     private void unregisterPhoneStateListener() {
         mTelephonyManager.unregisterTelephonyCallback(mTelephonyCallback);
-        mPhone.unregisterForPhysicalChannelConfig(mHandler);
 
         // clear all fields so they are blank until the next listener event occurs
         mOperatorName.setText("");
@@ -1020,6 +1082,8 @@ public class RadioInfo extends AppCompatActivity {
         mGsmState.setText("");
         mRoamingState.setText("");
         mPhyChanConfig.setText("");
+        mDownlinkKbps.setText("");
+        mUplinkKbps.setText("");
     }
 
     // register mTelephonyCallback for relevant fields using the current TelephonyManager
@@ -1044,12 +1108,6 @@ public class RadioInfo extends AppCompatActivity {
         mNetworkSlicingConfig.setVisibility(visibility);
     }
 
-    private void updateDnsCheckState() {
-        //FIXME: Replace with a TelephonyManager call
-        mDnsCheckState.setText(mPhone.isDnsCheckDisabled()
-                ? "0.0.0.0 allowed" : "0.0.0.0 not allowed");
-    }
-
     private void updateBandwidths(int dlbw, int ulbw) {
         dlbw = (dlbw < 0 || dlbw == Integer.MAX_VALUE) ? -1 : dlbw;
         ulbw = (ulbw < 0 || ulbw == Integer.MAX_VALUE) ? -1 : ulbw;
@@ -1256,7 +1314,7 @@ public class RadioInfo extends AppCompatActivity {
     }
 
     private void updateSubscriptionIds() {
-        mSubscriptionId.setText(Integer.toString(mPhone.getSubId()));
+        mSubscriptionId.setText(String.format(Locale.ROOT, "%d", mSubId));
         mDds.setText(Integer.toString(SubscriptionManager.getDefaultDataSubscriptionId()));
     }
 
@@ -1270,6 +1328,12 @@ public class RadioInfo extends AppCompatActivity {
 
 
     private void updateServiceState(ServiceState serviceState) {
+        if (!SubscriptionManager.isValidSubscriptionId(mSubId)) {
+            // When SIM is absent, we can't listen service state change from absent slot. Need
+            // explicitly get service state from the specific slot.
+            serviceState = mTelephonyManager.getServiceStateForSlot(mPhoneId);
+        }
+        log("Update service state " + serviceState);
         int state = serviceState.getState();
         Resources r = getResources();
         String display = r.getString(R.string.radioInfo_unknown);
@@ -1324,32 +1388,40 @@ public class RadioInfo extends AppCompatActivity {
         Resources r = getResources();
         String display = r.getString(R.string.radioInfo_unknown);
 
-        switch (state) {
-            case TelephonyManager.DATA_CONNECTED:
-                display = r.getString(R.string.radioInfo_data_connected);
-                break;
-            case TelephonyManager.DATA_CONNECTING:
-                display = r.getString(R.string.radioInfo_data_connecting);
-                break;
-            case TelephonyManager.DATA_DISCONNECTED:
-                display = r.getString(R.string.radioInfo_data_disconnected);
-                break;
-            case TelephonyManager.DATA_SUSPENDED:
-                display = r.getString(R.string.radioInfo_data_suspended);
-                break;
+        if (SubscriptionManager.isValidSubscriptionId(mSubId)) {
+            switch (state) {
+                case TelephonyManager.DATA_CONNECTED:
+                    display = r.getString(R.string.radioInfo_data_connected);
+                    break;
+                case TelephonyManager.DATA_CONNECTING:
+                    display = r.getString(R.string.radioInfo_data_connecting);
+                    break;
+                case TelephonyManager.DATA_DISCONNECTED:
+                    display = r.getString(R.string.radioInfo_data_disconnected);
+                    break;
+                case TelephonyManager.DATA_SUSPENDED:
+                    display = r.getString(R.string.radioInfo_data_suspended);
+                    break;
+            }
+        } else {
+            display = r.getString(R.string.radioInfo_data_disconnected);
         }
 
         mGprsState.setText(display);
     }
 
     private void updateNetworkType() {
-        if (mPhone != null) {
+        if (SubscriptionManager.isValidPhoneId(mPhoneId)) {
             mDataNetwork.setText(ServiceState.rilRadioTechnologyToString(
-                    mPhone.getServiceState().getRilDataRadioTechnology()));
+                    mTelephonyManager.getServiceStateForSlot(mPhoneId)
+                            .getRilDataRadioTechnology()));
             mVoiceNetwork.setText(ServiceState.rilRadioTechnologyToString(
-                    mPhone.getServiceState().getRilVoiceRadioTechnology()));
-            int overrideNetwork = mPhone.getDisplayInfoController().getTelephonyDisplayInfo()
-                    .getOverrideNetworkType();
+                    mTelephonyManager.getServiceStateForSlot(mPhoneId)
+                            .getRilVoiceRadioTechnology()));
+            int overrideNetwork = (mDisplayInfo != null
+                    && SubscriptionManager.isValidSubscriptionId(mSubId))
+                    ? mDisplayInfo.getOverrideNetworkType()
+                    : TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_NONE;
             mOverrideNetwork.setText(
                     TelephonyDisplayInfo.overrideNetworkTypeToString(overrideNetwork));
         }
@@ -1369,9 +1441,7 @@ public class RadioInfo extends AppCompatActivity {
 
     private void updateRawRegistrationState(ServiceState serviceState) {
         ServiceState ss = serviceState;
-        if (ss == null && mPhone != null) {
-            ss = mPhone.getServiceState();
-        }
+        ss = mTelephonyManager.getServiceStateForSlot(mPhoneId);
 
         mVoiceRawReg.setText(getRawRegistrationStateText(ss, NetworkRegistrationInfo.DOMAIN_CS,
                     AccessNetworkConstants.TRANSPORT_TYPE_WWAN));
@@ -1386,7 +1456,7 @@ public class RadioInfo extends AppCompatActivity {
                 & TelephonyManager.NETWORK_TYPE_BITMASK_NR) == 0) {
             return;
         }
-        ServiceState ss = (mPhone == null) ? null : mPhone.getServiceState();
+        ServiceState ss = mTelephonyManager.getServiceStateForSlot(mPhoneId);
         if (ss != null) {
             NetworkRegistrationInfo nri = ss.getNetworkRegistrationInfo(
                     NetworkRegistrationInfo.DOMAIN_PS, AccessNetworkConstants.TRANSPORT_TYPE_WWAN);
@@ -1426,21 +1496,18 @@ public class RadioInfo extends AppCompatActivity {
         String s;
         Resources r = getResources();
 
-        s = mPhone.getDeviceId();
-        if (s == null) {
-            s = r.getString(R.string.radioInfo_unknown);
-        }  else if (mPhone.getImeiType() == ImeiInfo.ImeiType.PRIMARY) {
-            s = s + " (" + r.getString(R.string.radioInfo_imei_primary) + ")";
-        }
+        s = mTelephonyManager.getImei(mPhoneId);
         mDeviceId.setText(s);
 
-        s = mPhone.getSubscriberId();
-        if (s == null) s = r.getString(R.string.radioInfo_unknown);
+        s = mTelephonyManager.getSubscriberId();
+        if (s == null || !SubscriptionManager.isValidSubscriptionId(mSubId)) {
+            s = r.getString(R.string.radioInfo_unknown);
+        }
 
         mSubscriberId.setText(s);
 
         SubscriptionManager subMgr = getSystemService(SubscriptionManager.class);
-        int subId = mPhone.getSubId();
+        int subId = mSubId;
         s = subMgr.getPhoneNumber(subId)
                 + " { CARRIER:"
                 + subMgr.getPhoneNumber(subId, SubscriptionManager.PHONE_NUMBER_SOURCE_CARRIER)
@@ -1551,9 +1618,8 @@ public class RadioInfo extends AppCompatActivity {
     }
 
     private void refreshSmsc() {
-        mQueuedWork.execute(new Runnable() {
-            public void run() {
-                //FIXME: Replace with a TelephonyManager call
+        mQueuedWork.execute(() -> {
+            if (mSystemUser) {
                 mPhone.getSmscAddress(mHandler.obtainMessage(EVENT_QUERY_SMSC_DONE));
             }
         });
@@ -1618,84 +1684,108 @@ public class RadioInfo extends AppCompatActivity {
 
     private MenuItem.OnMenuItemClickListener mViewADNCallback =
             new MenuItem.OnMenuItemClickListener() {
-        public boolean onMenuItemClick(MenuItem item) {
-            Intent intent = new Intent(Intent.ACTION_VIEW);
-            // XXX We need to specify the component here because if we don't
-            // the activity manager will try to resolve the type by calling
-            // the content provider, which causes it to be loaded in a process
-            // other than the Dialer process, which causes a lot of stuff to
-            // break.
-            intent.setClassName("com.android.phone", "com.android.phone.SimContacts");
-            startActivity(intent);
-            return true;
-        }
-    };
+                public boolean onMenuItemClick(MenuItem item) {
+                    Intent intent = new Intent(Intent.ACTION_VIEW);
+                    // XXX We need to specify the component here because if we don't
+                    // the activity manager will try to resolve the type by calling
+                    // the content provider, which causes it to be loaded in a process
+                    // other than the Dialer process, which causes a lot of stuff to
+                    // break.
+                    intent.setClassName("com.android.phone", "com.android.phone.SimContacts");
+                    startActivityAsUser(intent, UserHandle.CURRENT);
+                    return true;
+                }
+            };
 
     private MenuItem.OnMenuItemClickListener mViewFDNCallback =
             new MenuItem.OnMenuItemClickListener() {
-        public boolean onMenuItemClick(MenuItem item) {
-            Intent intent = new Intent(Intent.ACTION_VIEW);
-            // XXX We need to specify the component here because if we don't
-            // the activity manager will try to resolve the type by calling
-            // the content provider, which causes it to be loaded in a process
-            // other than the Dialer process, which causes a lot of stuff to
-            // break.
-            intent.setClassName("com.android.phone", "com.android.phone.settings.fdn.FdnList");
-            startActivity(intent);
-            return true;
-        }
-    };
+                public boolean onMenuItemClick(MenuItem item) {
+                    Intent intent = new Intent(Intent.ACTION_VIEW);
+                    // XXX We need to specify the component here because if we don't
+                    // the activity manager will try to resolve the type by calling
+                    // the content provider, which causes it to be loaded in a process
+                    // other than the Dialer process, which causes a lot of stuff to
+                    // break.
+                    intent.setClassName("com.android.phone",
+                            "com.android.phone.settings.fdn.FdnList");
+                    startActivityAsUser(intent, UserHandle.CURRENT);
+                    return true;
+                }
+            };
 
     private MenuItem.OnMenuItemClickListener mViewSDNCallback =
             new MenuItem.OnMenuItemClickListener() {
-        public boolean onMenuItemClick(MenuItem item) {
-            Intent intent = new Intent(
-                    Intent.ACTION_VIEW, Uri.parse("content://icc/sdn"));
-            // XXX We need to specify the component here because if we don't
-            // the activity manager will try to resolve the type by calling
-            // the content provider, which causes it to be loaded in a process
-            // other than the Dialer process, which causes a lot of stuff to
-            // break.
-            intent.setClassName("com.android.phone", "com.android.phone.ADNList");
-            startActivity(intent);
-            return true;
-        }
-    };
+                public boolean onMenuItemClick(MenuItem item) {
+                    Intent intent = new Intent(
+                            Intent.ACTION_VIEW, Uri.parse("content://icc/sdn"));
+                    // XXX We need to specify the component here because if we don't
+                    // the activity manager will try to resolve the type by calling
+                    // the content provider, which causes it to be loaded in a process
+                    // other than the Dialer process, which causes a lot of stuff to
+                    // break.
+                    intent.setClassName("com.android.phone", "com.android.phone.ADNList");
+                    startActivityAsUser(intent, UserHandle.CURRENT);
+                    return true;
+                }
+            };
 
     private MenuItem.OnMenuItemClickListener mGetImsStatus =
             new MenuItem.OnMenuItemClickListener() {
-        public boolean onMenuItemClick(MenuItem item) {
-            boolean isImsRegistered = mPhone.isImsRegistered();
-            boolean availableVolte = mPhone.isVoiceOverCellularImsEnabled();
-            boolean availableWfc = mPhone.isWifiCallingEnabled();
-            boolean availableVt = mPhone.isVideoEnabled();
-            boolean availableUt = mPhone.isUtEnabled();
-
-            final String imsRegString = isImsRegistered
-                    ? getString(R.string.radio_info_ims_reg_status_registered)
-                    : getString(R.string.radio_info_ims_reg_status_not_registered);
-
-            final String available = getString(R.string.radio_info_ims_feature_status_available);
-            final String unavailable = getString(
-                    R.string.radio_info_ims_feature_status_unavailable);
-
-            String imsStatus = getString(R.string.radio_info_ims_reg_status,
-                    imsRegString,
-                    availableVolte ? available : unavailable,
-                    availableWfc ? available : unavailable,
-                    availableVt ? available : unavailable,
-                    availableUt ? available : unavailable);
-
-            AlertDialog imsDialog = new AlertDialog.Builder(RadioInfo.this)
-                    .setMessage(imsStatus)
-                    .setTitle(getString(R.string.radio_info_ims_reg_status_title))
-                    .create();
-
-            imsDialog.show();
+                public boolean onMenuItemClick(MenuItem item) {
+                    boolean isSimValid = SubscriptionManager.isValidSubscriptionId(mSubId);
+                    boolean isImsRegistered = isSimValid && mTelephonyManager.isImsRegistered();
+                    boolean availableVolte = isSimValid && mTelephonyManager.isVolteAvailable();
+                    boolean availableWfc = isSimValid && mTelephonyManager.isWifiCallingAvailable();
+                    boolean availableVt =
+                            isSimValid && mTelephonyManager.isVideoTelephonyAvailable();
+                    AtomicBoolean availableUt = new AtomicBoolean(false);
+
+                    if (isSimValid) {
+                        ImsMmTelManager imsMmTelManager = mImsManager.getImsMmTelManager(mSubId);
+                        CountDownLatch latch = new CountDownLatch(1);
+                        try {
+                            HandlerThread handlerThread = new HandlerThread("RadioInfo");
+                            handlerThread.start();
+                            imsMmTelManager.isSupported(
+                                    MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_UT,
+                                    AccessNetworkConstants.TRANSPORT_TYPE_WWAN,
+                                    handlerThread.getThreadExecutor(), (result) -> {
+                                        latch.countDown();
+                                        availableUt.set(result);
+                                    });
+                            latch.await(2, TimeUnit.SECONDS);
+                            handlerThread.quit();
+                        } catch (Exception e) {
+                            loge("Failed to get UT state.");
+                        }
+                    }
 
-            return true;
-        }
-    };
+                    final String imsRegString = isImsRegistered
+                            ? getString(R.string.radio_info_ims_reg_status_registered)
+                            : getString(R.string.radio_info_ims_reg_status_not_registered);
+
+                    final String available = getString(
+                            R.string.radio_info_ims_feature_status_available);
+                    final String unavailable = getString(
+                            R.string.radio_info_ims_feature_status_unavailable);
+
+                    String imsStatus = getString(R.string.radio_info_ims_reg_status,
+                            imsRegString,
+                            availableVolte ? available : unavailable,
+                            availableWfc ? available : unavailable,
+                            availableVt ? available : unavailable,
+                            availableUt.get() ? available : unavailable);
+
+                    AlertDialog imsDialog = new AlertDialog.Builder(RadioInfo.this)
+                            .setMessage(imsStatus)
+                            .setTitle(getString(R.string.radio_info_ims_reg_status_title))
+                            .create();
+
+                    imsDialog.show();
+
+                    return true;
+                }
+            };
 
     private MenuItem.OnMenuItemClickListener mToggleData =
             new MenuItem.OnMenuItemClickListener() {
@@ -1850,42 +1940,159 @@ public class RadioInfo extends AppCompatActivity {
         }
     };
 
-    private final OnCheckedChangeListener mSimulateOosOnChangeListener =
-            (buttonView, isChecked) -> {
+    private final OnCheckedChangeListener mSimulateOosOnChangeListener = (bv, isChecked) -> {
         Intent intent = new Intent("com.android.internal.telephony.TestServiceState");
         if (isChecked) {
             log("Send OOS override broadcast intent.");
             intent.putExtra("data_reg_state", 1);
-            mSimulateOos[mPhone.getPhoneId()] = true;
+            mSimulateOos[mPhoneId] = true;
         } else {
             log("Remove OOS override.");
             intent.putExtra("action", "reset");
-            mSimulateOos[mPhone.getPhoneId()] = false;
+            mSimulateOos[mPhoneId] = false;
         }
-
         mPhone.getTelephonyTester().setServiceStateTestIntent(intent);
     };
 
+    private static final int SATELLITE_CHANNEL = 8665;
+    private final OnCheckedChangeListener mForceSatelliteChannelOnChangeListener =
+            (buttonView, isChecked) -> {
+                if (!SubscriptionManager.isValidSubscriptionId(mSubId)) {
+                    loge("Force satellite channel invalid subId " + mSubId);
+                    return;
+                }
+                CarrierConfigManager cm = getSystemService(CarrierConfigManager.class);
+                if (cm == null) {
+                    loge("Force satellite channel cm == null");
+                    return;
+                }
+                TelephonyManager tm = mTelephonyManager.createForSubscriptionId(mSubId);
+                // To be used in thread in case mPhone changes.
+                int subId = mSubId;
+                int phoneId = mPhoneId;
+                if (isChecked) {
+                    (new Thread(() -> {
+                        // Override carrier config
+                        PersistableBundle originalBundle = cm.getConfigForSubId(subId,
+                                CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL,
+                                CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL,
+                                CarrierConfigManager.KEY_EMERGENCY_MESSAGING_SUPPORTED_BOOL
+                        );
+                        PersistableBundle overrideBundle = new PersistableBundle();
+                        overrideBundle.putBoolean(
+                                CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL, true);
+                        overrideBundle.putBoolean(CarrierConfigManager
+                                .KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL, true);
+                        overrideBundle.putBoolean(CarrierConfigManager
+                                .KEY_EMERGENCY_MESSAGING_SUPPORTED_BOOL, true);
+
+                        // Set only allow LTE network type
+                        try {
+                            tm.setAllowedNetworkTypesForReason(
+                                    TelephonyManager.ALLOWED_NETWORK_TYPES_REASON_TEST,
+                                    RadioAccessFamily.getRafFromNetworkType(
+                                            RILConstants.NETWORK_MODE_LTE_ONLY));
+                            log("Force satellite channel set to LTE only");
+                        } catch (Exception e) {
+                            loge("Force satellite channel failed to set network type to LTE " + e);
+                            return;
+                        }
+
+                        // Set force channel selection
+                        List<RadioAccessSpecifier> mock = List.of(
+                                new RadioAccessSpecifier(
+                                        AccessNetworkConstants.AccessNetworkType.EUTRAN,
+                                        new int[]{AccessNetworkConstants.EutranBand.BAND_25},
+                                        new int[]{SATELLITE_CHANNEL}));
+                        try {
+                            log("Force satellite channel new channels " + mock);
+                            tm.setSystemSelectionChannels(mock);
+                        } catch (Exception e) {
+                            loge("Force satellite channel failed to set channels " + e);
+                            return;
+                        }
+                        log("Force satellite channel new config " + overrideBundle);
+                        cm.overrideConfig(subId, overrideBundle, false);
+
+                        mOriginalSystemChannels[phoneId] = originalBundle;
+                        log("Force satellite channel old " + mock  + originalBundle);
+                    })).start();
+                } else {
+                    (new Thread(() -> {
+                        try {
+                            tm.setSystemSelectionChannels(
+                                    Collections.emptyList() /* isSpecifyChannels false */);
+                            log("Force satellite channel successfully cleared channels ");
+                            tm.setAllowedNetworkTypesForReason(
+                                    TelephonyManager.ALLOWED_NETWORK_TYPES_REASON_TEST,
+                                    TelephonyManager.getAllNetworkTypesBitmask());
+                            log("Force satellite channel successfully reset network type to "
+                                    + TelephonyManager.getAllNetworkTypesBitmask());
+                            PersistableBundle original = mOriginalSystemChannels[phoneId];
+                            if (original != null) {
+                                cm.overrideConfig(subId, original, false);
+                                log("Force satellite channel successfully restored config to "
+                                        + original);
+                                mOriginalSystemChannels[phoneId] = null;
+                            }
+                        } catch (Exception e) {
+                            loge("Force satellite channel: Can't clear mock " + e);
+                        }
+                    })).start();
+                }
+    };
+
+    private void updateSatelliteChannelDisplay(int phoneId) {
+        if (mEnforceSatelliteChannel.isChecked()) return;
+        // Assume in testing mode
+        (new Thread(() -> {
+            TelephonyManager tm = mTelephonyManager.createForSubscriptionId(
+                    SubscriptionManager.getSubscriptionId(phoneId));
+            try {
+                List<RadioAccessSpecifier> channels = tm.getSystemSelectionChannels();
+                long networkTypeBitMask = tm.getAllowedNetworkTypesForReason(
+                        TelephonyManager.ALLOWED_NETWORK_TYPES_REASON_TEST);
+                long lteNetworkBitMask = RadioAccessFamily.getRafFromNetworkType(
+                        RILConstants.NETWORK_MODE_LTE_ONLY);
+                mHandler.post(() -> {
+                    log("Force satellite get channel " + channels
+                            + " get networkTypeBitMask " + networkTypeBitMask
+                            + " lte " + lteNetworkBitMask);
+                    // if SATELLITE_CHANNEL is the current channel
+                    mEnforceSatelliteChannel.setChecked(channels.stream().filter(specifier ->
+                                    specifier.getRadioAccessNetwork()
+                                            == AccessNetworkConstants.AccessNetworkType.EUTRAN)
+                            .flatMapToInt(specifier -> Arrays.stream(specifier.getChannels()))
+                            .anyMatch(channel -> channel == SATELLITE_CHANNEL)
+                            // OR ALLOWED_NETWORK_TYPES_REASON_TEST is LTE only.
+                            || (networkTypeBitMask & lteNetworkBitMask) == networkTypeBitMask);
+                });
+            } catch (Exception e) {
+                loge("updateSatelliteChannelDisplay " + e);
+            }
+        })).start();
+    }
+
     private final OnCheckedChangeListener mMockSatelliteListener =
             (buttonView, isChecked) -> {
-                if (mPhone != null) {
-                    CarrierConfigManager cm = mPhone.getContext()
-                            .getSystemService(CarrierConfigManager.class);
+                if (SubscriptionManager.isValidPhoneId(mPhoneId)) {
+                    CarrierConfigManager cm = getSystemService(CarrierConfigManager.class);
                     if (cm == null) return;
                     if (isChecked) {
-                        String operatorNumeric = mPhone.getOperatorNumeric();
+                        String operatorNumeric = mTelephonyManager
+                                .getNetworkOperatorForPhone(mPhoneId);
                         TelephonyManager tm;
-                        if (TextUtils.isEmpty(operatorNumeric) && (tm = mPhone.getContext()
-                                .getSystemService(TelephonyManager.class)) != null) {
-                            operatorNumeric = tm.getSimOperatorNumericForPhone(mPhone.getPhoneId());
+                        if (TextUtils.isEmpty(operatorNumeric)
+                                && (tm = getSystemService(TelephonyManager.class)) != null) {
+                            operatorNumeric = tm.getSimOperatorNumericForPhone(mPhoneId);
                         }
                         if (TextUtils.isEmpty(operatorNumeric)) {
                             loge("mMockSatelliteListener: Can't mock because no operator for phone "
-                                    + mPhone.getPhoneId());
+                                    + mPhoneId);
                             mMockSatellite.setChecked(false);
                             return;
                         }
-                        PersistableBundle originalBundle = cm.getConfigForSubId(mPhone.getSubId(),
+                        PersistableBundle originalBundle = cm.getConfigForSubId(mSubId,
                                 CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL,
                                 CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL,
                                 CarrierConfigManager
@@ -1897,28 +2104,30 @@ public class RadioInfo extends AppCompatActivity {
                         overrideBundle.putBoolean(CarrierConfigManager
                                 .KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL, false);
                         PersistableBundle capableProviderBundle = new PersistableBundle();
-                        capableProviderBundle.putIntArray(mPhone.getOperatorNumeric(), new int[]{
-                                // Currently satellite only supports below
-                                NetworkRegistrationInfo.SERVICE_TYPE_SMS,
-                                NetworkRegistrationInfo.SERVICE_TYPE_EMERGENCY
+                        capableProviderBundle.putIntArray(mTelephonyManager
+                                        .getNetworkOperatorForPhone(mPhoneId),
+                                new int[]{
+                                        // Currently satellite only supports below
+                                        NetworkRegistrationInfo.SERVICE_TYPE_SMS,
+                                        NetworkRegistrationInfo.SERVICE_TYPE_EMERGENCY
                         });
                         overrideBundle.putPersistableBundle(CarrierConfigManager
                                 .KEY_CARRIER_SUPPORTED_SATELLITE_SERVICES_PER_PROVIDER_BUNDLE,
                                 capableProviderBundle);
                         log("mMockSatelliteListener: new " + overrideBundle);
                         log("mMockSatelliteListener: old " + originalBundle);
-                        cm.overrideConfig(mPhone.getSubId(), overrideBundle, false);
-                        mCarrierSatelliteOriginalBundle[mPhone.getPhoneId()] = originalBundle;
+                        cm.overrideConfig(mSubId, overrideBundle, false);
+                        mCarrierSatelliteOriginalBundle[mPhoneId] = originalBundle;
                     } else {
                         try {
-                            cm.overrideConfig(mPhone.getSubId(),
-                                    mCarrierSatelliteOriginalBundle[mPhone.getPhoneId()], false);
-                            mCarrierSatelliteOriginalBundle[mPhone.getPhoneId()] = null;
+                            cm.overrideConfig(mSubId,
+                                    mCarrierSatelliteOriginalBundle[mPhoneId], false);
+                            mCarrierSatelliteOriginalBundle[mPhoneId] = null;
                             log("mMockSatelliteListener: Successfully cleared mock for phone "
-                                    + mPhone.getPhoneId());
+                                    + mPhoneId);
                         } catch (Exception e) {
                             loge("mMockSatelliteListener: Can't clear mock because invalid sub Id "
-                                    + mPhone.getSubId()
+                                    + mSubId
                                     + ", insert SIM and use adb shell cmd phone cc clear-values");
                             // Keep show toggle ON if the view is not destroyed. If destroyed, must
                             // use cmd to reset, because upon creation the view doesn't remember the
@@ -1929,6 +2138,29 @@ public class RadioInfo extends AppCompatActivity {
                 }
             };
 
+    /**
+     * Enable modem satellite for non-emergency mode.
+     */
+    private void enableSatelliteNonEmergencyMode() {
+        SatelliteManager sm = getSystemService(SatelliteManager.class);
+        CarrierConfigManager cm = getSystemService(CarrierConfigManager.class);
+        if (sm == null || cm == null) {
+            loge("enableSatelliteNonEmergencyMode: sm or cm is null");
+            return;
+        }
+        if (!cm.getConfigForSubId(mSubId,
+                CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL)
+                .getBoolean(CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL)) {
+            loge("enableSatelliteNonEmergencyMode: KEY_SATELLITE_ATTACH_SUPPORTED_BOOL is false");
+            return;
+        }
+        log("enableSatelliteNonEmergencyMode: requestEnabled");
+        sm.requestEnabled(new EnableRequestAttributes.Builder(true)
+                        .setDemoMode(false).setEmergencyMode(false).build(),
+                Runnable::run, res -> log("enableSatelliteNonEmergencyMode: " + res)
+        );
+    }
+
     private boolean isImsVolteProvisioned() {
         return getImsConfigProvisionedState(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VOICE,
                 ImsRegistrationImplBase.REGISTRATION_TECH_LTE);
@@ -2004,10 +2236,9 @@ public class RadioInfo extends AppCompatActivity {
     }
 
     private boolean isEabEnabledByPlatform() {
-        if (mPhone != null) {
-            CarrierConfigManager configManager = (CarrierConfigManager)
-                    mPhone.getContext().getSystemService(Context.CARRIER_CONFIG_SERVICE);
-            PersistableBundle b = configManager.getConfigForSubId(mPhone.getSubId());
+        if (SubscriptionManager.isValidPhoneId(mPhoneId)) {
+            CarrierConfigManager configManager = getSystemService(CarrierConfigManager.class);
+            PersistableBundle b = configManager.getConfigForSubId(mSubId);
             if (b != null) {
                 return b.getBoolean(
                         CarrierConfigManager.KEY_USE_RCS_PRESENCE_BOOL, false) || b.getBoolean(
@@ -2019,7 +2250,7 @@ public class RadioInfo extends AppCompatActivity {
     }
 
     private void updateImsProvisionedState() {
-        if (!isImsSupportedOnDevice(mPhone.getContext())) {
+        if (!isImsSupportedOnDevice()) {
             return;
         }
 
@@ -2071,19 +2302,11 @@ public class RadioInfo extends AppCompatActivity {
                 && isEnabledByPlatform && isEabProvisioningRequired());
     }
 
-    OnClickListener mDnsCheckButtonHandler = new OnClickListener() {
-        public void onClick(View v) {
-            //FIXME: Replace with a TelephonyManager call
-            mPhone.disableDnsCheck(!mPhone.isDnsCheckDisabled());
-            updateDnsCheckState();
-        }
-    };
-
     OnClickListener mOemInfoButtonHandler = new OnClickListener() {
         public void onClick(View v) {
             Intent intent = new Intent(OEM_RADIO_INFO_INTENT);
             try {
-                startActivity(intent);
+                startActivityAsUser(intent, UserHandle.CURRENT);
             } catch (android.content.ActivityNotFoundException ex) {
                 log("OEM-specific Info/Settings Activity Not Found : " + ex);
                 // If the activity does not exist, there are no OEM
@@ -2101,8 +2324,8 @@ public class RadioInfo extends AppCompatActivity {
     OnClickListener mUpdateSmscButtonHandler = new OnClickListener() {
         public void onClick(View v) {
             mUpdateSmscButton.setEnabled(false);
-            mQueuedWork.execute(new Runnable() {
-                public void run() {
+            mQueuedWork.execute(() -> {
+                if (mSystemUser) {
                     mPhone.setSmscAddress(mSmsc.getText().toString(),
                             mHandler.obtainMessage(EVENT_UPDATE_SMSC_DONE));
                 }
@@ -2110,11 +2333,7 @@ public class RadioInfo extends AppCompatActivity {
         }
     };
 
-    OnClickListener mRefreshSmscButtonHandler = new OnClickListener() {
-        public void onClick(View v) {
-            refreshSmsc();
-        }
-    };
+    OnClickListener mRefreshSmscButtonHandler = v -> refreshSmsc();
 
     OnClickListener mCarrierProvisioningButtonHandler = v -> {
         String carrierProvisioningApp = getCarrierProvisioningAppString();
@@ -2162,8 +2381,10 @@ public class RadioInfo extends AppCompatActivity {
 
                 public void onItemSelected(AdapterView<?> parent, View v, int pos, long id) {
                     log("mOnSignalStrengthSelectedListener: " + pos);
-                    mSelectedSignalStrengthIndex[mPhone.getPhoneId()] = pos;
-                    mPhone.getTelephonyTester().setSignalStrength(SIGNAL_STRENGTH_LEVEL[pos]);
+                    mSelectedSignalStrengthIndex[mPhoneId] = pos;
+                    if (mSystemUser) {
+                        mPhone.getTelephonyTester().setSignalStrength(SIGNAL_STRENGTH_LEVEL[pos]);
+                    }
                 }
 
                 public void onNothingSelected(AdapterView<?> parent) {}
@@ -2175,7 +2396,7 @@ public class RadioInfo extends AppCompatActivity {
 
                 public void onItemSelected(AdapterView<?> parent, View v, int pos, long id) {
                     log("mOnMockDataNetworkTypeSelectedListener: " + pos);
-                    mSelectedMockDataNetworkTypeIndex[mPhone.getPhoneId()] = pos;
+                    mSelectedMockDataNetworkTypeIndex[mPhoneId] = pos;
                     Intent intent = new Intent("com.android.internal.telephony.TestServiceState");
                     if (pos > 0) {
                         log("mOnMockDataNetworkTypeSelectedListener: Override RAT: "
@@ -2188,7 +2409,9 @@ public class RadioInfo extends AppCompatActivity {
                         intent.putExtra("action", "reset");
                     }
 
-                    mPhone.getTelephonyTester().setServiceStateTestIntent(intent);
+                    if (mSystemUser) {
+                        mPhone.getTelephonyTester().setServiceStateTestIntent(intent);
+                    }
                 }
 
                 public void onNothingSelected(AdapterView<?> parent) {}
@@ -2197,42 +2420,41 @@ public class RadioInfo extends AppCompatActivity {
     AdapterView.OnItemSelectedListener mSelectPhoneIndexHandler =
             new AdapterView.OnItemSelectedListener() {
 
-        public void onItemSelected(AdapterView parent, View v, int pos, long id) {
-            if (pos >= 0 && pos <= sPhoneIndexLabels.length - 1) {
-                // the array position is equal to the phone index
-                int phoneIndex = pos;
-                Phone[] phones = PhoneFactory.getPhones();
-                if (phones == null || phones.length <= phoneIndex) {
-                    return;
+                public void onItemSelected(AdapterView parent, View v, int pos, long id) {
+                    if (pos >= 0 && pos <= sPhoneIndexLabels.length - 1) {
+                        if (mTelephonyManager.getActiveModemCount() <= pos) {
+                            return;
+                        }
+
+                        mPhoneId = pos;
+                        mSubId = SubscriptionManager.getSubscriptionId(mPhoneId);
+                        log("Updated phone id to " + mPhoneId + ", sub id to " + mSubId);
+                        updatePhoneIndex();
+                    }
                 }
-                // getSubId says it takes a slotIndex, but it actually takes a phone index
-                mSelectedPhoneIndex = phoneIndex;
-                updatePhoneIndex(phoneIndex, SubscriptionManager.getSubscriptionId(phoneIndex));
-            }
-        }
 
-        public void onNothingSelected(AdapterView parent) {
-        }
-    };
+                public void onNothingSelected(AdapterView parent) {
+                }
+            };
 
-    AdapterView.OnItemSelectedListener mCellInfoRefreshRateHandler  =
+    AdapterView.OnItemSelectedListener mCellInfoRefreshRateHandler =
             new AdapterView.OnItemSelectedListener() {
 
-        public void onItemSelected(AdapterView parent, View v, int pos, long id) {
-            mCellInfoRefreshRateIndex = pos;
-            mTelephonyManager.setCellInfoListRate(CELL_INFO_REFRESH_RATES[pos], mPhone.getSubId());
-            updateAllCellInfo();
-        }
+                public void onItemSelected(AdapterView parent, View v, int pos, long id) {
+                    mCellInfoRefreshRateIndex = pos;
+                    mTelephonyManager.setCellInfoListRate(CELL_INFO_REFRESH_RATES[pos], mPhoneId);
+                    updateAllCellInfo();
+                }
 
-        public void onNothingSelected(AdapterView parent) {
-        }
-    };
+                public void onNothingSelected(AdapterView parent) {
+                }
+            };
 
     private String getCarrierProvisioningAppString() {
-        if (mPhone != null) {
+        if (SubscriptionManager.isValidPhoneId(mPhoneId)) {
             CarrierConfigManager configManager =
-                    mPhone.getContext().getSystemService(CarrierConfigManager.class);
-            PersistableBundle b = configManager.getConfigForSubId(mPhone.getSubId());
+                    getSystemService(CarrierConfigManager.class);
+            PersistableBundle b = configManager.getConfigForSubId(mSubId);
             if (b != null) {
                 return b.getString(
                         CarrierConfigManager.KEY_CARRIER_PROVISIONING_APP_STRING, "");
@@ -2339,18 +2561,17 @@ public class RadioInfo extends AppCompatActivity {
         sendBroadcast(intent);
     }
 
-    private boolean isImsSupportedOnDevice(Context context) {
-        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY_IMS);
+    private boolean isImsSupportedOnDevice() {
+        return getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY_IMS);
     }
 
     private void updateServiceEnabledByPlatform() {
-        int subId = mPhone.getSubId();
-        if (subId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
+        if (!SubscriptionManager.isValidSubscriptionId(mSubId)) {
             log("updateServiceEnabledByPlatform subscription ID is invalid");
             return;
         }
 
-        ImsMmTelManager imsMmTelManager = mImsManager.getImsMmTelManager(subId);
+        ImsMmTelManager imsMmTelManager = mImsManager.getImsMmTelManager(mSubId);
         try {
             imsMmTelManager.isSupported(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VOICE,
                     AccessNetworkConstants.TRANSPORT_TYPE_WWAN, getMainExecutor(), (result) -> {
diff --git a/src/com/android/phone/settings/SuppServicesUiUtil.java b/src/com/android/phone/settings/SuppServicesUiUtil.java
index 4f1a79fc9..bf4df6b89 100644
--- a/src/com/android/phone/settings/SuppServicesUiUtil.java
+++ b/src/com/android/phone/settings/SuppServicesUiUtil.java
@@ -22,6 +22,7 @@ import android.content.ComponentName;
 import android.content.Context;
 import android.content.DialogInterface;
 import android.content.Intent;
+import android.os.UserHandle;
 import android.telephony.TelephonyManager;
 import android.text.TextUtils;
 import android.util.Log;
@@ -70,9 +71,9 @@ public class SuppServicesUiUtil {
                         Intent intent = new Intent(Intent.ACTION_MAIN);
                         ComponentName mobileNetworkSettingsComponent = new ComponentName(
                                 context.getString(R.string.mobile_network_settings_package),
-                                context.getString(R.string.mobile_network_settings_class));
+                                context.getString(R.string.sims_settings_class));
                         intent.setComponent(mobileNetworkSettingsComponent);
-                        context.startActivity(intent);
+                        context.startActivityAsUser(intent, UserHandle.CURRENT);
                     }
                 };
         return builder.setMessage(message)
diff --git a/src/com/android/phone/settings/VoicemailSettingsActivity.java b/src/com/android/phone/settings/VoicemailSettingsActivity.java
index 817ca4cd9..909a3ada7 100644
--- a/src/com/android/phone/settings/VoicemailSettingsActivity.java
+++ b/src/com/android/phone/settings/VoicemailSettingsActivity.java
@@ -42,7 +42,6 @@ import android.text.TextDirectionHeuristics;
 import android.text.TextUtils;
 import android.util.Log;
 import android.view.MenuItem;
-import android.view.WindowManager;
 import android.widget.ListAdapter;
 import android.widget.Toast;
 
@@ -495,7 +494,7 @@ public class VoicemailSettingsActivity extends PreferenceActivity
                             Intent i = new Intent(ACTION_ADD_VOICEMAIL);
                             i.putExtra(IGNORE_PROVIDER_EXTRA, victim);
                             i.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
-                            this.startActivity(i);
+                            this.startActivityAsUser(i, UserHandle.CURRENT);
                         }
                         return;
                     }
diff --git a/src/com/android/phone/settings/fdn/EditFdnContactScreen.java b/src/com/android/phone/settings/fdn/EditFdnContactScreen.java
index 0884e1262..6bf41f363 100644
--- a/src/com/android/phone/settings/fdn/EditFdnContactScreen.java
+++ b/src/com/android/phone/settings/fdn/EditFdnContactScreen.java
@@ -346,7 +346,7 @@ public class EditFdnContactScreen extends BaseFdnContactScreen {
             Intent intent = mSubscriptionInfoHelper.getIntent(DeleteFdnContactScreen.class);
             intent.putExtra(INTENT_EXTRA_NAME, mName);
             intent.putExtra(INTENT_EXTRA_NUMBER, mNumber);
-            startActivity(intent);
+            startActivityAsUser(intent, UserHandle.CURRENT);
         }
         finish();
     }
diff --git a/src/com/android/phone/settings/fdn/FdnList.java b/src/com/android/phone/settings/fdn/FdnList.java
index c2ecbc670..1b5a7afa6 100644
--- a/src/com/android/phone/settings/fdn/FdnList.java
+++ b/src/com/android/phone/settings/fdn/FdnList.java
@@ -23,6 +23,7 @@ import android.content.res.Resources;
 import android.net.Uri;
 import android.os.Bundle;
 import android.os.PersistableBundle;
+import android.os.UserHandle;
 import android.telecom.PhoneAccount;
 import android.telephony.CarrierConfigManager;
 import android.telephony.SubscriptionManager;
@@ -167,7 +168,7 @@ public class FdnList extends ADNList {
                 Intent intent = mSubscriptionInfoHelper.getIntent(FdnSetting.class);
                 intent.setAction(Intent.ACTION_MAIN);
                 intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
-                startActivity(intent);
+                startActivityAsUser(intent, UserHandle.CURRENT);
                 finish();
                 return true;
 
@@ -200,7 +201,7 @@ public class FdnList extends ADNList {
     private void addContact() {
         //If there is no INTENT_EXTRA_NAME provided, EditFdnContactScreen treats it as an "add".
         Intent intent = mSubscriptionInfoHelper.getIntent(EditFdnContactScreen.class);
-        startActivity(intent);
+        startActivityAsUser(intent, UserHandle.CURRENT);
     }
 
     /**
@@ -224,7 +225,7 @@ public class FdnList extends ADNList {
             Intent intent = mSubscriptionInfoHelper.getIntent(EditFdnContactScreen.class);
             intent.putExtra(INTENT_EXTRA_NAME, name);
             intent.putExtra(INTENT_EXTRA_NUMBER, number);
-            startActivity(intent);
+            startActivityAsUser(intent, UserHandle.CURRENT);
         }
     }
 
@@ -240,7 +241,7 @@ public class FdnList extends ADNList {
             Intent intent = mSubscriptionInfoHelper.getIntent(DeleteFdnContactScreen.class);
             intent.putExtra(INTENT_EXTRA_NAME, name);
             intent.putExtra(INTENT_EXTRA_NUMBER, number);
-            startActivity(intent);
+            startActivityAsUser(intent, UserHandle.CURRENT);
         }
     }
 
@@ -254,7 +255,7 @@ public class FdnList extends ADNList {
             if (!TextUtils.isEmpty(number)) {
                 Uri uri = Uri.fromParts(PhoneAccount.SCHEME_TEL, number, null);
                 final Intent intent = new Intent(Intent.ACTION_CALL_PRIVILEGED, uri);
-                startActivity(intent);
+                startActivityAsUser(intent, UserHandle.CURRENT);
             }
         }
     }
diff --git a/src/com/android/phone/slice/SlicePurchaseController.java b/src/com/android/phone/slice/SlicePurchaseController.java
index 9a42e1670..51255ddd7 100644
--- a/src/com/android/phone/slice/SlicePurchaseController.java
+++ b/src/com/android/phone/slice/SlicePurchaseController.java
@@ -40,6 +40,7 @@ import android.os.HandlerThread;
 import android.os.Looper;
 import android.os.Message;
 import android.os.PersistableBundle;
+import android.os.UserHandle;
 import android.provider.DeviceConfig;
 import android.sysprop.TelephonyProperties;
 import android.telephony.AnomalyReporter;
@@ -832,7 +833,11 @@ public class SlicePurchaseController extends Handler {
         intent.putExtra(EXTRA_INTENT_NOTIFICATION_SHOWN, createPendingIntent(
                 ACTION_SLICE_PURCHASE_APP_RESPONSE_NOTIFICATION_SHOWN, capability, false));
         logd("Broadcasting start intent to SlicePurchaseBroadcastReceiver.");
-        mPhone.getContext().sendBroadcast(intent);
+        if (mFeatureFlags.hsumBroadcast()) {
+            mPhone.getContext().sendBroadcastAsUser(intent, UserHandle.ALL);
+        } else {
+            mPhone.getContext().sendBroadcast(intent);
+        }
 
         // Listen for responses from the slice purchase application
         mSlicePurchaseControllerBroadcastReceivers.put(capability,
@@ -913,7 +918,11 @@ public class SlicePurchaseController extends Handler {
         intent.putExtra(EXTRA_PHONE_ID, mPhone.getPhoneId());
         intent.putExtra(EXTRA_PREMIUM_CAPABILITY, capability);
         logd("Broadcasting timeout intent to SlicePurchaseBroadcastReceiver.");
-        mPhone.getContext().sendBroadcast(intent);
+        if (mFeatureFlags.hsumBroadcast()) {
+            mPhone.getContext().sendBroadcastAsUser(intent, UserHandle.ALL);
+        } else {
+            mPhone.getContext().sendBroadcast(intent);
+        }
 
         handlePurchaseResult(
                 capability, TelephonyManager.PURCHASE_PREMIUM_CAPABILITY_RESULT_TIMEOUT, true);
diff --git a/src/com/android/phone/utils/CarrierAllowListInfo.java b/src/com/android/phone/utils/CarrierAllowListInfo.java
index 3ab9733b5..b230a9e42 100644
--- a/src/com/android/phone/utils/CarrierAllowListInfo.java
+++ b/src/com/android/phone/utils/CarrierAllowListInfo.java
@@ -21,9 +21,11 @@ import android.content.Context;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.Signature;
+import android.os.Binder;
 import android.telephony.Rlog;
 import android.text.TextUtils;
 
+import com.android.internal.telephony.flags.Flags;
 import com.android.internal.telephony.uicc.IccUtils;
 
 import org.json.JSONArray;
@@ -155,7 +157,11 @@ public class CarrierAllowListInfo {
             // package name is mandatory
             return false;
         }
-        final PackageManager packageManager = context.getPackageManager();
+        PackageManager packageManager = context.getPackageManager();
+        if (Flags.hsumPackageManager()) {
+            packageManager = context.createContextAsUser(Binder.getCallingUserHandle(), 0)
+                    .getPackageManager();
+        }
         try {
             MessageDigest sha256MDigest = MessageDigest.getInstance(MESSAGE_DIGEST_256_ALGORITHM);
             final PackageInfo packageInfo = packageManager.getPackageInfo(packageName,
diff --git a/src/com/android/phone/vvm/CarrierVvmPackageInstalledReceiver.java b/src/com/android/phone/vvm/CarrierVvmPackageInstalledReceiver.java
index ec0d3f6b5..e866ce08a 100644
--- a/src/com/android/phone/vvm/CarrierVvmPackageInstalledReceiver.java
+++ b/src/com/android/phone/vvm/CarrierVvmPackageInstalledReceiver.java
@@ -21,6 +21,7 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
 import android.os.PersistableBundle;
+import android.os.UserHandle;
 import android.telecom.PhoneAccountHandle;
 import android.telecom.TelecomManager;
 import android.telephony.CarrierConfigManager;
@@ -29,6 +30,8 @@ import android.telephony.VisualVoicemailService;
 import android.text.TextUtils;
 import android.util.ArraySet;
 
+import com.android.internal.telephony.flags.Flags;
+
 import java.util.Collections;
 import java.util.Set;
 
@@ -80,28 +83,37 @@ public class CarrierVvmPackageInstalledReceiver extends BroadcastReceiver {
                     .createForPhoneAccountHandle(phoneAccountHandle);
 
             if (pinnedTelephonyManager == null) {
-                VvmLog.e(TAG, "cannot create TelephonyManager from " + phoneAccountHandle);
+                VvmLog.e(TAG, "carrierVvmPkgAdded: cannot create TelephonyManager from "
+                        + phoneAccountHandle);
                 continue;
             }
 
             if (!getCarrierVvmPackages(telephonyManager).contains(packageName)) {
+                VvmLog.w(TAG, "carrierVvmPkgAdded: carrier vvm packages doesn't contain "
+                        + packageName);
                 continue;
             }
 
-            VvmLog.i(TAG, "Carrier VVM app " + packageName + " installed");
+            VvmLog.i(TAG, "carrierVvmPkgAdded: Carrier VVM app " + packageName + " installed");
 
             String vvmPackage = pinnedTelephonyManager.getVisualVoicemailPackageName();
             if (!TextUtils.equals(vvmPackage, systemDialer)) {
                 // Non system dialer do not need to prioritize carrier vvm app.
-                VvmLog.i(TAG, "non system dialer " + vvmPackage + " ignored");
+                VvmLog.i(TAG, "carrierVvmPkgAdded: non system dialer "
+                        + vvmPackage + " ignored");
                 continue;
             }
 
-            VvmLog.i(TAG, "sending broadcast to " + vvmPackage);
+            VvmLog.i(TAG, "carrierVvmPkgAdded: sending vvm package installed broadcast to "
+                    + vvmPackage);
             Intent broadcast = new Intent(ACTION_CARRIER_VVM_PACKAGE_INSTALLED);
             broadcast.putExtra(Intent.EXTRA_PACKAGE_NAME, packageName);
             broadcast.setPackage(vvmPackage);
-            context.sendBroadcast(broadcast);
+            if (Flags.hsumBroadcast()) {
+                context.sendBroadcastAsUser(broadcast, UserHandle.ALL);
+            } else {
+                context.sendBroadcast(broadcast);
+            }
         }
     }
 
diff --git a/src/com/android/phone/vvm/RemoteVvmTaskManager.java b/src/com/android/phone/vvm/RemoteVvmTaskManager.java
index daa5d67ba..b7c34068c 100644
--- a/src/com/android/phone/vvm/RemoteVvmTaskManager.java
+++ b/src/com/android/phone/vvm/RemoteVvmTaskManager.java
@@ -170,22 +170,23 @@ public class RemoteVvmTaskManager extends Service {
             }
             if (info.serviceInfo == null) {
                 VvmLog.w(TAG,
-                        "Component " + TelephonyUtils.getComponentInfo(info)
+                        "getRemotePackage: Component " + TelephonyUtils.getComponentInfo(info)
                             + " is not a service, ignoring");
                 continue;
             }
             if (!android.Manifest.permission.BIND_VISUAL_VOICEMAIL_SERVICE
                     .equals(info.serviceInfo.permission)) {
-                VvmLog.w(TAG, "package " + info.serviceInfo.packageName
+                VvmLog.w(TAG, "getRemotePackage: package " + info.serviceInfo.packageName
                         + " does not enforce BIND_VISUAL_VOICEMAIL_SERVICE, ignoring");
                 continue;
             }
             if (targetPackage != null && !TextUtils.equals(packageName, targetPackage)) {
-                VvmLog.w(TAG, "target package " + targetPackage
+                VvmLog.w(TAG, "getRemotePackage: target package " + targetPackage
                         + " is no longer the active VisualVoicemailService, ignoring");
                 continue;
             }
             ComponentInfo componentInfo = TelephonyUtils.getComponentInfo(info);
+            VvmLog.i(TAG, "getRemotePackage: found package " + targetPackage);
             return new ComponentName(componentInfo.packageName, componentInfo.name);
 
         }
@@ -206,6 +207,7 @@ public class RemoteVvmTaskManager extends Service {
             return null;
         }
         ComponentInfo componentInfo = TelephonyUtils.getComponentInfo(info.get(0));
+        VvmLog.i(TAG, "getBroadcastPackage: found package " + componentInfo.packageName);
         return new ComponentName(componentInfo.packageName, componentInfo.name);
     }
 
@@ -234,7 +236,7 @@ public class RemoteVvmTaskManager extends Service {
         mTaskReferenceCount++;
 
         if (intent == null) {
-            VvmLog.i(TAG, "received intent is null");
+            VvmLog.i(TAG, "onStartCommand: received intent is null");
             checkReference();
             return START_NOT_STICKY;
         }
@@ -245,7 +247,8 @@ public class RemoteVvmTaskManager extends Service {
         ComponentName remotePackage = getRemotePackage(this, subId,
                 intent.getStringExtra(EXTRA_TARGET_PACKAGE));
         if (remotePackage == null) {
-            VvmLog.i(TAG, "No service to handle " + intent.getAction() + ", ignoring");
+            VvmLog.i(TAG, "onStartCommand: No service to handle "
+                    + intent.getAction() + ", ignoring");
             checkReference();
             return START_NOT_STICKY;
         }
@@ -309,6 +312,7 @@ public class RemoteVvmTaskManager extends Service {
 
         public void onServiceConnected(ComponentName className,
                 IBinder service) {
+            VvmLog.i(TAG, "onServiceConnected: " + className);
             mRemoteMessenger = new Messenger(service);
             mConnected = true;
             runQueue();
@@ -318,7 +322,8 @@ public class RemoteVvmTaskManager extends Service {
             mConnection = null;
             mConnected = false;
             mRemoteMessenger = null;
-            VvmLog.e(TAG, "Service disconnected, " + mTaskReferenceCount + " tasks dropped.");
+            VvmLog.e(TAG, "onServiceDisconnected: remoteService disconnected, "
+                    + mTaskReferenceCount + " tasks dropped.");
             mTaskReferenceCount = 0;
             checkReference();
         }
@@ -333,7 +338,7 @@ public class RemoteVvmTaskManager extends Service {
                 try {
                     mRemoteMessenger.send(message);
                 } catch (RemoteException e) {
-                    VvmLog.e(TAG, "Error sending message to remote service", e);
+                    VvmLog.e(TAG, "runQueue: Error sending message to remote service", e);
                 }
                 message = mTaskQueue.poll();
             }
@@ -351,7 +356,7 @@ public class RemoteVvmTaskManager extends Service {
              * a different repository so it can not be updated in sync with android SDK. It is also
              * hard to make a manifest service to work in the intermittent state.
              */
-            VvmLog.i(TAG, "sending broadcast " + what + " to " + remotePackage);
+            VvmLog.i(TAG, "send: sending broadcast " + what + " to " + remotePackage);
             Intent intent = new Intent(ACTION_VISUAL_VOICEMAIL_SERVICE_EVENT);
             intent.putExtras(extras);
             intent.putExtra(EXTRA_WHAT, what);
@@ -371,7 +376,7 @@ public class RemoteVvmTaskManager extends Service {
         if (!mConnection.isConnected()) {
             Intent intent = newBindIntent(this);
             intent.setComponent(remotePackage);
-            VvmLog.i(TAG, "Binding to " + intent.getComponent());
+            VvmLog.i(TAG, "send: Binding to " + intent.getComponent());
             bindServiceAsUser(intent, mConnection, Context.BIND_AUTO_CREATE, userHandle);
         }
     }
diff --git a/src/com/android/phone/vvm/VvmDumpHandler.java b/src/com/android/phone/vvm/VvmDumpHandler.java
index 82c5bb5da..bf09f3034 100644
--- a/src/com/android/phone/vvm/VvmDumpHandler.java
+++ b/src/com/android/phone/vvm/VvmDumpHandler.java
@@ -19,15 +19,20 @@ public class VvmDumpHandler {
         indentedWriter.println("******* OmtpVvm *******");
         indentedWriter.println("======= Configs =======");
         indentedWriter.increaseIndent();
-        for (PhoneAccountHandle handle : context.getSystemService(TelecomManager.class)
-                .getCallCapablePhoneAccounts()) {
-            int subId = PhoneAccountHandleConverter.toSubId(handle);
-            indentedWriter.println(
-                    "VisualVoicemailPackageName:" + telephonyManager.createForSubscriptionId(subId)
-                            .getVisualVoicemailPackageName());
-            indentedWriter.println(
-                    "VisualVoicemailSmsFilterSettings(" + subId + "):" + telephonyManager
-                            .getActiveVisualVoicemailSmsFilterSettings(subId));
+        try {
+            for (PhoneAccountHandle handle : context.getSystemService(TelecomManager.class)
+                    .getCallCapablePhoneAccounts()) {
+                int subId = PhoneAccountHandleConverter.toSubId(handle);
+                indentedWriter.println(
+                        "VisualVoicemailPackageName:" + telephonyManager.createForSubscriptionId(
+                                        subId)
+                                .getVisualVoicemailPackageName());
+                indentedWriter.println(
+                        "VisualVoicemailSmsFilterSettings(" + subId + "):" + telephonyManager
+                                .getActiveVisualVoicemailSmsFilterSettings(subId));
+            }
+        } catch (SecurityException se) {
+            indentedWriter.println("Could not get vvm config " + se);
         }
         indentedWriter.decreaseIndent();
         indentedWriter.println("======== Logs =========");
diff --git a/src/com/android/phone/vvm/VvmSimStateTracker.java b/src/com/android/phone/vvm/VvmSimStateTracker.java
index ab8329c89..0362d02fa 100644
--- a/src/com/android/phone/vvm/VvmSimStateTracker.java
+++ b/src/com/android/phone/vvm/VvmSimStateTracker.java
@@ -116,12 +116,13 @@ public class VvmSimStateTracker extends BroadcastReceiver {
 
         final String action = intent.getAction();
         if (action == null) {
-            VvmLog.w(TAG, "Null action for intent.");
+            VvmLog.w(TAG, "onReceive: Null action for intent.");
             return;
         }
         VvmLog.i(TAG, action);
         switch (action) {
             case Intent.ACTION_BOOT_COMPLETED:
+                VvmLog.i(TAG, "onReceive: ACTION_BOOT_COMPLETED");
                 onBootCompleted(context);
                 break;
             case TelephonyIntents.ACTION_SIM_STATE_CHANGED:
@@ -131,6 +132,7 @@ public class VvmSimStateTracker extends BroadcastReceiver {
                     // which SIM is removed.
                     // ACTION_SIM_STATE_CHANGED only provides subId which cannot be converted to a
                     // PhoneAccountHandle when the SIM is absent.
+                    VvmLog.i(TAG, "onReceive: ACTION_SIM_STATE_CHANGED");
                     checkRemovedSim(context);
                 }
                 break;
@@ -139,7 +141,7 @@ public class VvmSimStateTracker extends BroadcastReceiver {
                         SubscriptionManager.INVALID_SUBSCRIPTION_ID);
 
                 if (!SubscriptionManager.isValidSubscriptionId(subId)) {
-                    VvmLog.i(TAG, "Received SIM change for invalid subscription id.");
+                    VvmLog.i(TAG, "onReceive: Received carrier config for invalid sub id.");
                     checkRemovedSim(context);
                     return;
                 }
@@ -149,10 +151,11 @@ public class VvmSimStateTracker extends BroadcastReceiver {
 
                 if ("null".equals(phoneAccountHandle.getId())) {
                     VvmLog.e(TAG,
-                            "null phone account handle ID, possible modem crash."
+                            "onReceive: null phone account handle ID, possible modem crash."
                                     + " Ignoring carrier config changed event");
                     return;
                 }
+                VvmLog.i(TAG, "onReceive: ACTION_CARRIER_CONFIG_CHANGED; subId=" + subId);
                 onCarrierConfigChanged(context, phoneAccountHandle);
         }
     }
@@ -174,7 +177,7 @@ public class VvmSimStateTracker extends BroadcastReceiver {
     }
 
     private void sendConnected(Context context, PhoneAccountHandle phoneAccountHandle) {
-        VvmLog.i(TAG, "Service connected on " + phoneAccountHandle);
+        VvmLog.i(TAG, "sendConnected: Service connected on " + phoneAccountHandle);
         RemoteVvmTaskManager.startCellServiceConnected(context, phoneAccountHandle);
     }
 
@@ -210,7 +213,7 @@ public class VvmSimStateTracker extends BroadcastReceiver {
     }
 
     private void sendSimRemoved(Context context, PhoneAccountHandle phoneAccountHandle) {
-        VvmLog.i(TAG, "Sim removed on " + phoneAccountHandle);
+        VvmLog.i(TAG, "sendSimRemoved: Sim removed on " + phoneAccountHandle);
         RemoteVvmTaskManager.startSimRemoved(context, phoneAccountHandle);
     }
 
@@ -233,6 +236,8 @@ public class VvmSimStateTracker extends BroadcastReceiver {
         }
         if (telephonyManager.getServiceState().getState()
                 == ServiceState.STATE_IN_SERVICE) {
+            VvmLog.i(TAG, "onCarrierConfigChanged: in service; send connected "
+                    + phoneAccountHandle);
             sendConnected(context, phoneAccountHandle);
             sListeners.put(phoneAccountHandle, null);
         } else {
@@ -243,6 +248,7 @@ public class VvmSimStateTracker extends BroadcastReceiver {
     private void listenToAccount(Context context, PhoneAccountHandle phoneAccountHandle) {
         ServiceStateListener listener = new ServiceStateListener(context, phoneAccountHandle);
         listener.listen();
+        VvmLog.i(TAG, "listenToAccount: " + phoneAccountHandle);
         sListeners.put(phoneAccountHandle, listener);
     }
 
diff --git a/src/com/android/phone/vvm/VvmSmsReceiver.java b/src/com/android/phone/vvm/VvmSmsReceiver.java
index 8265e50c6..d4fa751e3 100644
--- a/src/com/android/phone/vvm/VvmSmsReceiver.java
+++ b/src/com/android/phone/vvm/VvmSmsReceiver.java
@@ -38,22 +38,22 @@ public class VvmSmsReceiver extends BroadcastReceiver {
                 .getParcelable(VoicemailContract.EXTRA_VOICEMAIL_SMS);
         if (sms.getPhoneAccountHandle() == null) {
             // This should never happen
-            VvmLog.e(TAG, "Received message for null phone account");
+            VvmLog.e(TAG, "onReceive: Received message for null phone account");
             return;
         }
 
         int subId = PhoneAccountHandleConverter.toSubId(sms.getPhoneAccountHandle());
         if (!SubscriptionManager.isValidSubscriptionId(subId)) {
-            VvmLog.e(TAG, "Received message for invalid subId");
+            VvmLog.e(TAG, "onReceive: Received message for invalid subId");
             return;
         }
 
         String targetPackage = intent.getExtras().getString(VoicemailContract.EXTRA_TARGET_PACKAGE);
         if (RemoteVvmTaskManager.hasRemoteService(context, subId, targetPackage)) {
-            VvmLog.i(TAG, "Sending SMS received event to remote service");
+            VvmLog.i(TAG, "onReceive: Sending SMS received event to remote service");
             RemoteVvmTaskManager.startSmsReceived(context, sms, targetPackage);
         } else {
-            VvmLog.w(TAG, "No remote service to handle SMS received event");
+            VvmLog.w(TAG, "onReceive: No remote service to handle SMS received event");
         }
     }
 }
diff --git a/src/com/android/services/telephony/PstnIncomingCallNotifier.java b/src/com/android/services/telephony/PstnIncomingCallNotifier.java
index d58c2110a..3b74c6f58 100644
--- a/src/com/android/services/telephony/PstnIncomingCallNotifier.java
+++ b/src/com/android/services/telephony/PstnIncomingCallNotifier.java
@@ -82,30 +82,7 @@ final class PstnIncomingCallNotifier {
     /**
      * Used to listen to events from {@link #mPhone}.
      */
-    private final Handler mHandler = new Handler() {
-        @Override
-        public void handleMessage(Message msg) {
-            switch(msg.what) {
-                case EVENT_NEW_RINGING_CONNECTION:
-                    handleNewRingingConnection((AsyncResult) msg.obj);
-                    break;
-                case EVENT_CDMA_CALL_WAITING:
-                    handleCdmaCallWaiting((AsyncResult) msg.obj);
-                    break;
-                case EVENT_UNKNOWN_CONNECTION:
-                    handleNewUnknownConnection((AsyncResult) msg.obj);
-                    break;
-                default:
-                    break;
-            }
-        }
-
-        @Override
-        public String toString() {
-            return String.format("[PstnIncomingCallNotifierHandler; phoneId=[%s]",
-                    getPhoneIdAsString());
-        }
-    };
+    private final Handler mHandler;
 
     /**
      * Persists the specified parameters and starts listening to phone events.
@@ -118,6 +95,30 @@ final class PstnIncomingCallNotifier {
         }
 
         mPhone = phone;
+        mHandler = new Handler(phone.getLooper()) {
+            @Override
+            public void handleMessage(Message msg) {
+                switch(msg.what) {
+                    case EVENT_NEW_RINGING_CONNECTION:
+                        handleNewRingingConnection((AsyncResult) msg.obj);
+                        break;
+                    case EVENT_CDMA_CALL_WAITING:
+                        handleCdmaCallWaiting((AsyncResult) msg.obj);
+                        break;
+                    case EVENT_UNKNOWN_CONNECTION:
+                        handleNewUnknownConnection((AsyncResult) msg.obj);
+                        break;
+                    default:
+                        break;
+                }
+            }
+
+            @Override
+            public String toString() {
+                return String.format("[PstnIncomingCallNotifierHandler; phoneId=[%s]",
+                        getPhoneIdAsString());
+            }
+        };
 
         registerForNotifications();
     }
diff --git a/src/com/android/services/telephony/PstnPhoneCapabilitiesNotifier.java b/src/com/android/services/telephony/PstnPhoneCapabilitiesNotifier.java
index 4038dd164..e91af8371 100644
--- a/src/com/android/services/telephony/PstnPhoneCapabilitiesNotifier.java
+++ b/src/com/android/services/telephony/PstnPhoneCapabilitiesNotifier.java
@@ -39,18 +39,7 @@ final class PstnPhoneCapabilitiesNotifier {
     private final Phone mPhone;
     private final Listener mListener;
 
-    private final Handler mHandler = new Handler() {
-        @Override
-        public void handleMessage(Message msg) {
-            switch (msg.what) {
-                case EVENT_VIDEO_CAPABILITIES_CHANGED:
-                    handleVideoCapabilitesChanged((AsyncResult) msg.obj);
-                    break;
-                default:
-                    break;
-            }
-        }
-    };
+    private final Handler mHandler;
 
     /*package*/
     PstnPhoneCapabilitiesNotifier(Phone phone, Listener listener) {
@@ -59,6 +48,18 @@ final class PstnPhoneCapabilitiesNotifier {
         }
 
         mPhone = phone;
+        mHandler = new Handler(phone.getLooper()) {
+            @Override
+            public void handleMessage(Message msg) {
+                switch (msg.what) {
+                    case EVENT_VIDEO_CAPABILITIES_CHANGED:
+                        handleVideoCapabilitesChanged((AsyncResult) msg.obj);
+                        break;
+                    default:
+                        break;
+                }
+            }
+        };
         mListener = listener;
 
         registerForNotifications();
diff --git a/src/com/android/services/telephony/TelecomAccountRegistry.java b/src/com/android/services/telephony/TelecomAccountRegistry.java
index da9cfdf9a..c39d121cf 100644
--- a/src/com/android/services/telephony/TelecomAccountRegistry.java
+++ b/src/com/android/services/telephony/TelecomAccountRegistry.java
@@ -101,6 +101,8 @@ public class TelecomAccountRegistry {
 
     private static final int REGISTER_START_DELAY_MS = 1 * 1000; // 1 second
     private static final int REGISTER_MAXIMUM_DELAY_MS = 60 * 1000; // 1 minute
+    private static final int TELECOM_CONNECT_START_DELAY_MS = 250; // 250 milliseconds
+    private static final int TELECOM_CONNECT_MAX_DELAY_MS = 4 * 1000; // 4 second
 
     /**
      * Indicates the {@link SubscriptionManager.OnSubscriptionsChangedListener} has not yet been
@@ -477,11 +479,13 @@ public class TelecomAccountRegistry {
                         isHandoverFromSupported);
             }
 
-            final boolean isTelephonyAudioDeviceSupported = mContext.getResources().getBoolean(
-                    R.bool.config_support_telephony_audio_device);
-            if (isTelephonyAudioDeviceSupported && !isEmergency
-                    && isCarrierUseCallRecordingTone()) {
-                extras.putBoolean(PhoneAccount.EXTRA_PLAY_CALL_RECORDING_TONE, true);
+            if (!com.android.server.telecom.flags.Flags.telecomResolveHiddenDependencies()) {
+                final boolean isTelephonyAudioDeviceSupported = mContext.getResources().getBoolean(
+                        R.bool.config_support_telephony_audio_device);
+                if (isTelephonyAudioDeviceSupported && !isEmergency
+                        && isCarrierUseCallRecordingTone()) {
+                    extras.putBoolean(PhoneAccount.EXTRA_PLAY_CALL_RECORDING_TONE, true);
+                }
             }
 
             extras.putBoolean(EXTRA_SUPPORTS_VIDEO_CALLING_FALLBACK,
@@ -504,14 +508,9 @@ public class TelecomAccountRegistry {
             // Set CAPABILITY_EMERGENCY_CALLS_ONLY flag if either
             // - Carrier config overrides subscription is not voice capable, or
             // - Resource config overrides it be emergency_calls_only
-            // TODO(b/316183370:): merge the two cases when clearing up flag
-            if (Flags.dataOnlyServiceAllowEmergencyCallOnly()) {
-                if (!isSubscriptionVoiceCapableByCarrierConfig()) {
-                    capabilities |= PhoneAccount.CAPABILITY_EMERGENCY_CALLS_ONLY;
-                }
-            }
-            if (isEmergency && mContext.getResources().getBoolean(
-                    R.bool.config_emergency_account_emergency_calls_only)) {
+            if (!isSubscriptionVoiceCapableByCarrierConfig()
+                    || (isEmergency && mContext.getResources().getBoolean(
+                    R.bool.config_emergency_account_emergency_calls_only))) {
                 capabilities |= PhoneAccount.CAPABILITY_EMERGENCY_CALLS_ONLY;
             }
 
@@ -1222,7 +1221,8 @@ public class TelecomAccountRegistry {
                 setupAccounts();
             } else if (CarrierConfigManager.ACTION_CARRIER_CONFIG_CHANGED.equals(
                     intent.getAction())) {
-                Log.i(this, "Carrier-config changed, checking for phone account updates.");
+                Log.i(this, "TelecomAccountRegistry: Carrier-config changed, "
+                        + "checking for phone account updates.");
                 int subId = intent.getIntExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX,
                         SubscriptionManager.INVALID_SUBSCRIPTION_ID);
                 handleCarrierConfigChange(subId);
@@ -1233,7 +1233,8 @@ public class TelecomAccountRegistry {
     private BroadcastReceiver mLocaleChangeReceiver = new BroadcastReceiver() {
         @Override
         public void onReceive(Context context, Intent intent) {
-            Log.i(this, "Locale change; re-registering phone accounts.");
+            Log.i(this, "TelecomAccountRegistry: Locale change; re-registering "
+                    + "phone accounts.");
             tearDownAccounts();
             setupAccounts();
         }
@@ -1247,10 +1248,11 @@ public class TelecomAccountRegistry {
         @Override
         public void onServiceStateChanged(ServiceState serviceState) {
             int newState = serviceState.getState();
-            Log.i(this, "onServiceStateChanged: newState=%d, mServiceState=%d",
-                    newState, mServiceState);
+            Log.i(this, "TelecomAccountRegistry: onServiceStateChanged: "
+                            + "newState=%d, mServiceState=%d", newState, mServiceState);
             if (newState == ServiceState.STATE_IN_SERVICE && mServiceState != newState) {
-                Log.i(this, "onServiceStateChanged: Tearing down and re-setting up accounts.");
+                Log.i(this, "TelecomAccountRegistry: onServiceStateChanged: "
+                        + "Tearing down and re-setting up accounts.");
                 tearDownAccounts();
                 setupAccounts();
             } else {
@@ -1287,6 +1289,7 @@ public class TelecomAccountRegistry {
     private int mActiveDataSubscriptionId = SubscriptionManager.INVALID_SUBSCRIPTION_ID;
     private boolean mIsPrimaryUser = UserHandle.of(ActivityManager.getCurrentUser()).isSystem();
     private ExponentialBackoff mRegisterSubscriptionListenerBackoff;
+    private ExponentialBackoff mTelecomReadyBackoff;
     private final HandlerThread mHandlerThread = new HandlerThread("TelecomAccountRegistry");
 
     // TODO: Remove back-pointer from app singleton to Service, since this is not a preferred
@@ -1305,6 +1308,53 @@ public class TelecomAccountRegistry {
         }
     };
 
+    /**
+     * When {@link #setupOnBoot()} is called, there is a chance that Telecom is not up yet. This
+     * runnable checks whether or not Telecom is up and if it isn't we wait until ready.
+     */
+    private final Runnable mCheckTelecomReadyRunnable = new Runnable() {
+        @Override
+        public void run() {
+            if (isTelecomReady()) {
+                setupOnBootInternal();
+            } else {
+                mTelecomReadyBackoff.notifyFailed();
+                Log.i(this, "TelecomAccountRegistry: telecom not ready, retrying in "
+                        + mTelecomReadyBackoff.getCurrentDelay() + " ms");
+            }
+        }
+    };
+
+    /**
+     * Test TelecomManager to determine if telecom is up yet.
+     * @return true if telecom is ready, false if it is not
+     */
+    private boolean isTelecomReady() {
+        if (mTelecomManager == null) {
+            Log.i(this, "TelecomAccountRegistry: isTelecomReady: "
+                    + "telecom null");
+            return true;
+        }
+        try {
+            // Assumption: this method should not return null unless Telecom is not ready yet
+            String result = mTelecomManager.getSystemDialerPackage();
+            if (result == null) {
+                Log.i(this, "TelecomAccountRegistry: isTelecomReady: "
+                        + "telecom not ready");
+                return false;
+            } else {
+                Log.i(this, "TelecomAccountRegistry: isTelecomReady: "
+                        + "telecom ready");
+                return true;
+            }
+        } catch (Exception e) {
+            Log.i(this, "TelecomAccountRegistry: isTelecomReady: "
+                    + "telecom exception");
+            // Any exception means that the service is at least up!
+            return true;
+        }
+    }
+
     TelecomAccountRegistry(Context context) {
         mContext = context;
         mTelecomManager = context.getSystemService(TelecomManager.class);
@@ -1319,6 +1369,12 @@ public class TelecomAccountRegistry {
                 2, /* multiplier */
                 mHandlerThread.getLooper(),
                 mRegisterOnSubscriptionsChangedListenerRunnable);
+        mTelecomReadyBackoff = new ExponentialBackoff(
+                TELECOM_CONNECT_START_DELAY_MS,
+                TELECOM_CONNECT_MAX_DELAY_MS,
+                2, /* multiplier */
+                mContext.getMainLooper(),
+                mCheckTelecomReadyRunnable);
     }
 
     /**
@@ -1546,9 +1602,21 @@ public class TelecomAccountRegistry {
     }
 
     /**
-     * Sets up all the phone accounts for SIMs on first boot.
+     * Waits for Telecom to come up first and then sets up.
      */
     public void setupOnBoot() {
+        if (Flags.delayPhoneAccountRegistration() && !isTelecomReady()) {
+            Log.i(this, "setupOnBoot: delaying start for Telecom...");
+            mTelecomReadyBackoff.start();
+        } else {
+            setupOnBootInternal();
+        }
+    }
+
+    /**
+     * Sets up all the phone accounts for SIMs on first boot.
+     */
+    private void setupOnBootInternal() {
         // TODO: When this object "finishes" we should unregister by invoking
         // SubscriptionManager.getInstance(mContext).unregister(mOnSubscriptionsChangedListener);
         // This is not strictly necessary because it will be unregistered if the
@@ -1556,7 +1624,8 @@ public class TelecomAccountRegistry {
 
         // Register for SubscriptionInfo list changes which is guaranteed
         // to invoke onSubscriptionsChanged the first time.
-        Log.i(this, "TelecomAccountRegistry: setupOnBoot - register subscription listener");
+        Log.i(this, "TelecomAccountRegistry: setupOnBootInternal - register "
+                + "subscription listener");
         SubscriptionManager.from(mContext).addOnSubscriptionsChangedListener(
                 mOnSubscriptionsChangedListener);
 
diff --git a/src/com/android/services/telephony/TelephonyConnectionService.java b/src/com/android/services/telephony/TelephonyConnectionService.java
index 148cff337..6a4ea3ede 100644
--- a/src/com/android/services/telephony/TelephonyConnectionService.java
+++ b/src/com/android/services/telephony/TelephonyConnectionService.java
@@ -18,6 +18,8 @@ package com.android.services.telephony;
 
 import static android.telephony.CarrierConfigManager.KEY_USE_ONLY_DIALED_SIM_ECC_LIST_BOOL;
 import static android.telephony.DomainSelectionService.SELECTOR_TYPE_CALLING;
+import static android.telephony.ServiceState.STATE_EMERGENCY_ONLY;
+import static android.telephony.ServiceState.STATE_IN_SERVICE;
 import static android.telephony.TelephonyManager.HAL_SERVICE_VOICE;
 
 import static com.android.internal.telephony.PhoneConstants.PHONE_TYPE_GSM;
@@ -39,6 +41,7 @@ import android.net.Uri;
 import android.os.Bundle;
 import android.os.ParcelUuid;
 import android.os.PersistableBundle;
+import android.os.UserHandle;
 import android.telecom.Conference;
 import android.telecom.Conferenceable;
 import android.telecom.Connection;
@@ -90,6 +93,8 @@ import com.android.internal.telephony.domainselection.NormalCallDomainSelectionC
 import com.android.internal.telephony.emergency.EmergencyStateTracker;
 import com.android.internal.telephony.emergency.RadioOnHelper;
 import com.android.internal.telephony.emergency.RadioOnStateListener;
+import com.android.internal.telephony.flags.FeatureFlags;
+import com.android.internal.telephony.flags.FeatureFlagsImpl;
 import com.android.internal.telephony.flags.Flags;
 import com.android.internal.telephony.imsphone.ImsExternalCallTracker;
 import com.android.internal.telephony.imsphone.ImsPhone;
@@ -214,6 +219,9 @@ public class TelephonyConnectionService extends ConnectionService {
             new TelephonyConferenceController(mTelephonyConnectionServiceProxy);
     private final CdmaConferenceController mCdmaConferenceController =
             new CdmaConferenceController(this);
+
+    private FeatureFlags mFeatureFlags = new FeatureFlagsImpl();
+
     private ImsConferenceController mImsConferenceController;
 
     private ComponentName mExpectedComponentName = null;
@@ -765,6 +773,15 @@ public class TelephonyConnectionService extends ConnectionService {
                 if (cause == android.telephony.DisconnectCause.EMERGENCY_TEMP_FAILURE
                         || cause == android.telephony.DisconnectCause.EMERGENCY_PERM_FAILURE) {
                     if (mEmergencyConnection != null) {
+                        if (Flags.hangupEmergencyCallForCrossSimRedialing()) {
+                            if (mEmergencyConnection.getOriginalConnection() != null) {
+                                if (mEmergencyConnection.getOriginalConnection()
+                                        .getState().isAlive()) {
+                                    mEmergencyConnection.hangup(cause);
+                                }
+                                return;
+                            }
+                        }
                         boolean isPermanentFailure =
                                 cause == android.telephony.DisconnectCause.EMERGENCY_PERM_FAILURE;
                         Log.i(this, "onSelectionTerminated permanent=" + isPermanentFailure);
@@ -1142,7 +1159,7 @@ public class TelephonyConnectionService extends ConnectionService {
             // so they will only need the special emergency call setup when the phone is out of
             // service.
             if (phone == null || phone.getServiceState().getState()
-                    != ServiceState.STATE_IN_SERVICE) {
+                    != STATE_IN_SERVICE) {
                 String convertedNumber = mPhoneNumberUtilsProxy.convertToEmergencyNumber(this,
                         number);
                 if (!TextUtils.equals(convertedNumber, number)) {
@@ -1156,14 +1173,14 @@ public class TelephonyConnectionService extends ConnectionService {
 
         final boolean isAirplaneModeOn = mDeviceState.isAirplaneModeOn(this);
 
-        boolean needToTurnOffSatellite = isSatelliteBlockingCall(isEmergencyNumber);
-
         // Get the right phone object from the account data passed in.
         final Phone phone = getPhoneForAccount(request.getAccountHandle(), isEmergencyNumber,
                 /* Note: when not an emergency, handle can be null for unknown callers */
                 handle == null ? null : handle.getSchemeSpecificPart());
         ImsPhone imsPhone = phone != null ? (ImsPhone) phone.getImsPhone() : null;
 
+        boolean needToTurnOffSatellite = shouldExitSatelliteModeForEmergencyCall(isEmergencyNumber);
+
         boolean isPhoneWifiCallingEnabled = phone != null && phone.isWifiCallingEnabled();
         boolean needToTurnOnRadio = (isEmergencyNumber && (!isRadioOn() || isAirplaneModeOn))
                 || (isRadioPowerDownOnBluetooth() && !isPhoneWifiCallingEnabled);
@@ -1186,17 +1203,20 @@ public class TelephonyConnectionService extends ConnectionService {
             }
         }
 
+        boolean forNormalRoutingEmergencyCall = false;
         if (mDomainSelectionResolver.isDomainSelectionSupported()) {
-            // Normal routing emergency number shall be handled by normal call domain selector.
-            int routing = (isEmergencyNumber)
-                    ? getEmergencyCallRouting(phone, number, needToTurnOnRadio)
-                    : EmergencyNumber.EMERGENCY_CALL_ROUTING_UNKNOWN;
-            if (isEmergencyNumber && routing != EmergencyNumber.EMERGENCY_CALL_ROUTING_NORMAL) {
-                final Connection resultConnection =
-                        placeEmergencyConnection(phone,
-                                request, numberToDial, isTestEmergencyNumber,
-                                handle, needToTurnOnRadio, routing);
-                if (resultConnection != null) return resultConnection;
+            if (isEmergencyNumber) {
+                // Normal routing emergency number shall be handled by normal call domain selector.
+                int routing = getEmergencyCallRouting(phone, number, needToTurnOnRadio);
+                if (routing != EmergencyNumber.EMERGENCY_CALL_ROUTING_NORMAL) {
+                    final Connection resultConnection =
+                            placeEmergencyConnection(phone,
+                                    request, numberToDial, isTestEmergencyNumber,
+                                    handle, needToTurnOnRadio, routing);
+                    if (resultConnection != null) return resultConnection;
+                }
+                forNormalRoutingEmergencyCall = true;
+                Log.d(this, "onCreateOutgoingConnection, forNormalRoutingEmergencyCall");
             }
         }
 
@@ -1280,12 +1300,12 @@ public class TelephonyConnectionService extends ConnectionService {
                         return phone.getState() == PhoneConstants.State.OFFHOOK
                                 // Do not wait for voice in service on opportunistic SIMs.
                                 || subInfo != null && subInfo.isOpportunistic()
-                                || (serviceState == ServiceState.STATE_IN_SERVICE
-                                && !isSatelliteBlockingCall(isEmergencyNumber));
+                                || (serviceState == STATE_IN_SERVICE
+                                && !needToTurnOffSatellite);
                     }
                 }
             }, isEmergencyNumber && !isTestEmergencyNumber, phone, isTestEmergencyNumber,
-                    timeoutToOnTimeoutCallback);
+                    timeoutToOnTimeoutCallback, forNormalRoutingEmergencyCall);
             // Return the still unconnected GsmConnection and wait for the Radios to boot before
             // connecting it to the underlying Phone.
             return resultConnection;
@@ -1480,7 +1500,7 @@ public class TelephonyConnectionService extends ConnectionService {
                 });
             }
         } else {
-            if (isSatelliteBlockingCall(isEmergencyNumber)) {
+            if (shouldExitSatelliteModeForEmergencyCall(isEmergencyNumber)) {
                 Log.w(LOG_TAG, "handleOnComplete, failed to turn off satellite modem");
                 closeOrDestroyConnection(originalConnection,
                         mDisconnectCauseFactory.toTelecomDisconnectCause(
@@ -1569,7 +1589,7 @@ public class TelephonyConnectionService extends ConnectionService {
                                 simUnlockUiPackage, simUnlockUiClass));
                         simUnlockIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                         try {
-                            context.startActivity(simUnlockIntent);
+                            context.startActivityAsUser(simUnlockIntent, UserHandle.CURRENT);
                         } catch (ActivityNotFoundException exception) {
                             Log.e(this, exception, "Unable to find SIM unlock UI activity.");
                         }
@@ -1621,8 +1641,8 @@ public class TelephonyConnectionService extends ConnectionService {
 
         if (!isEmergencyNumber) {
             switch (state) {
-                case ServiceState.STATE_IN_SERVICE:
-                case ServiceState.STATE_EMERGENCY_ONLY:
+                case STATE_IN_SERVICE:
+                case STATE_EMERGENCY_ONLY:
                     break;
                 case ServiceState.STATE_OUT_OF_SERVICE:
                     if (phone.isUtEnabled() && number.endsWith("#")) {
@@ -2120,7 +2140,7 @@ public class TelephonyConnectionService extends ConnectionService {
 
         return imsPhone != null
                 && (imsPhone.isVoiceOverCellularImsEnabled() || imsPhone.isWifiCallingEnabled())
-                && (imsPhone.getServiceState().getState() == ServiceState.STATE_IN_SERVICE);
+                && (imsPhone.getServiceState().getState() == STATE_IN_SERVICE);
     }
 
     private boolean isRadioOn() {
@@ -2131,7 +2151,7 @@ public class TelephonyConnectionService extends ConnectionService {
         return result;
     }
 
-    private boolean isSatelliteBlockingCall(boolean isEmergencyNumber) {
+    private boolean shouldExitSatelliteModeForEmergencyCall(boolean isEmergencyNumber) {
         if (!mSatelliteController.isSatelliteEnabled()
                 && !mSatelliteController.isSatelliteBeingEnabled()) {
             return false;
@@ -2141,8 +2161,35 @@ public class TelephonyConnectionService extends ConnectionService {
             if (mSatelliteController.isDemoModeEnabled()) {
                 // If user makes emergency call in demo mode, end the satellite session
                 return true;
-            } else {
-                return getTurnOffOemEnabledSatelliteDuringEmergencyCall();
+            } else if (mFeatureFlags.carrierRoamingNbIotNtn()
+                    && !mSatelliteController.getRequestIsEmergency()) {
+                // If satellite is not for emergency, end the satellite session
+                return true;
+            } else { // satellite is for emergency
+                if (mFeatureFlags.carrierRoamingNbIotNtn()) {
+                    Phone satellitePhone = mSatelliteController.getSatellitePhone();
+                    if (satellitePhone == null) {
+                        loge("satellite is/being enabled, but satellitePhone is null");
+                        return false;
+                    }
+                    SubscriptionInfoInternal info = SubscriptionManagerService.getInstance()
+                            .getSubscriptionInfoInternal(satellitePhone.getSubId());
+                    if (info == null) {
+                        loge("satellite is/being enabled, but satellite sub "
+                                + satellitePhone.getSubId() + " is null");
+                        return false;
+                    }
+
+                    if (info.getOnlyNonTerrestrialNetwork() == 1) {
+                        // OEM
+                        return getTurnOffOemEnabledSatelliteDuringEmergencyCall();
+                    } else {
+                        // Carrier
+                        return mSatelliteController.shouldTurnOffCarrierSatelliteForEmergencyCall();
+                    }
+                } else {
+                    return getTurnOffOemEnabledSatelliteDuringEmergencyCall();
+                }
             }
         }
 
@@ -2438,7 +2485,7 @@ public class TelephonyConnectionService extends ConnectionService {
             if (SubscriptionManager.isValidSubscriptionId(subId)) {
                 SubscriptionManager.putSubscriptionIdExtra(intent, subId);
             }
-            startActivity(intent);
+            startActivityAsUser(intent, UserHandle.CURRENT);
         }
         return disconnectCause;
     }
@@ -2869,9 +2916,19 @@ public class TelephonyConnectionService extends ConnectionService {
                 + "csCause=" +  callFailCause + ", psCause=" + reasonInfo
                 + ", showPreciseCause=" + showPreciseCause + ", overrideCause=" + overrideCause);
 
-        if (c.getOriginalConnection() != null
+        boolean isLocalHangup = c.getOriginalConnection() != null
                 && c.getOriginalConnection().getDisconnectCause()
-                        != android.telephony.DisconnectCause.LOCAL
+                        == android.telephony.DisconnectCause.LOCAL;
+
+        // Do not treat it as local hangup if it is a cross-sim redial.
+        if (Flags.hangupEmergencyCallForCrossSimRedialing()) {
+            isLocalHangup = isLocalHangup
+                    && overrideCause != android.telephony.DisconnectCause.EMERGENCY_TEMP_FAILURE
+                    && overrideCause != android.telephony.DisconnectCause.EMERGENCY_PERM_FAILURE;
+        }
+
+        // If it is neither a local hangup nor a power off hangup, then reselect domain.
+        if (c.getOriginalConnection() != null && (!isLocalHangup)
                 && c.getOriginalConnection().getDisconnectCause()
                         != android.telephony.DisconnectCause.POWER_OFF) {
 
@@ -3015,7 +3072,7 @@ public class TelephonyConnectionService extends ConnectionService {
         }
 
         ServiceState ss = phone.getServiceStateTracker().getServiceState();
-        if (ss.getState() != ServiceState.STATE_IN_SERVICE) return false;
+        if (ss.getState() != STATE_IN_SERVICE) return false;
 
         NetworkRegistrationInfo regState = ss.getNetworkRegistrationInfo(
                 NetworkRegistrationInfo.DOMAIN_PS, AccessNetworkConstants.TRANSPORT_TYPE_WWAN);
@@ -4089,7 +4146,7 @@ public class TelephonyConnectionService extends ConnectionService {
     @VisibleForTesting
     public boolean isAvailableForEmergencyCalls(Phone phone,
             @EmergencyNumber.EmergencyCallRouting int routing) {
-        if (isCallDisallowedDueToSatellite(phone)) {
+        if (isCallDisallowedDueToSatellite(phone) && isTerrestrialNetworkAvailable()) {
             // Phone is connected to satellite due to which it is not preferred for emergency call.
             return false;
         }
@@ -4103,7 +4160,7 @@ public class TelephonyConnectionService extends ConnectionService {
         }
 
         // In service phones are always appropriate for emergency calls.
-        if (ServiceState.STATE_IN_SERVICE == phone.getServiceState().getState()) {
+        if (STATE_IN_SERVICE == phone.getServiceState().getState()) {
             return true;
         }
 
@@ -4114,6 +4171,23 @@ public class TelephonyConnectionService extends ConnectionService {
                 && phone.getServiceState().isEmergencyOnly());
     }
 
+    private boolean isTerrestrialNetworkAvailable() {
+        for (Phone phone : mPhoneFactoryProxy.getPhones()) {
+            ServiceState serviceState = phone.getServiceState();
+            if (serviceState != null) {
+                int state = serviceState.getState();
+                if ((state == STATE_IN_SERVICE || state == STATE_EMERGENCY_ONLY
+                        || serviceState.isEmergencyOnly())
+                        && !serviceState.isUsingNonTerrestrialNetwork()) {
+                    Log.d(this, "isTerrestrialNetworkAvailable true");
+                    return true;
+                }
+            }
+        }
+        Log.d(this, "isTerrestrialNetworkAvailable false");
+        return false;
+    }
+
     /**
      * Determines if the connection should allow mute.
      *
@@ -4308,9 +4382,9 @@ public class TelephonyConnectionService extends ConnectionService {
                                                 context.getString(
                                                     R.string.mobile_network_settings_package),
                                                 context.getString(
-                                                    R.string.mobile_network_settings_class));
+                                                    R.string.sims_settings_class));
                                     intent.setComponent(mobileNetworkSettingsComponent);
-                                    context.startActivity(intent);
+                                    context.startActivityAsUser(intent, UserHandle.CURRENT);
                                 }
                             };
                     Dialog dialog = builder.setMessage(message)
@@ -4753,8 +4827,12 @@ public class TelephonyConnectionService extends ConnectionService {
             mSatelliteSOSMessageRecommender = new SatelliteSOSMessageRecommender(phone.getContext(),
                     phone.getContext().getMainLooper());
         }
+
+        String number = connection.getAddress().getSchemeSpecificPart();
+        final boolean isTestEmergencyNumber = isEmergencyNumberTestNumber(number);
+
         connection.addTelephonyConnectionListener(mEmergencyConnectionSatelliteListener);
-        mSatelliteSOSMessageRecommender.onEmergencyCallStarted(connection);
+        mSatelliteSOSMessageRecommender.onEmergencyCallStarted(connection, isTestEmergencyNumber);
         mSatelliteSOSMessageRecommender.onEmergencyCallConnectionStateChanged(
                 connection.getTelecomCallId(), connection.STATE_DIALING);
     }
@@ -4800,4 +4878,14 @@ public class TelephonyConnectionService extends ConnectionService {
         }
         return turnOffSatellite;
     }
+
+    /* Only for testing */
+    @VisibleForTesting
+    public void setFeatureFlags(FeatureFlags featureFlags) {
+        mFeatureFlags = featureFlags;
+    }
+
+    private void loge(String s) {
+        Log.d(this, s);
+    }
 }
diff --git a/src/com/android/services/telephony/domainselection/CrossSimRedialingController.java b/src/com/android/services/telephony/domainselection/CrossSimRedialingController.java
index d368d46e3..3a6945901 100644
--- a/src/com/android/services/telephony/domainselection/CrossSimRedialingController.java
+++ b/src/com/android/services/telephony/domainselection/CrossSimRedialingController.java
@@ -227,6 +227,8 @@ public class CrossSimRedialingController extends Handler {
 
         if (isThereOtherSlot()) {
             mSelector.notifyCrossStackTimerExpired();
+        } else if (!mPermanentRejectedSlots.isEmpty()) {
+            mSelector.maybeHangupOngoingDialing();
         }
     }
 
diff --git a/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelector.java b/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelector.java
index 9f2e0a965..0d373de24 100644
--- a/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelector.java
+++ b/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelector.java
@@ -101,6 +101,7 @@ import android.text.TextUtils;
 import android.util.LocalLog;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.internal.telephony.flags.Flags;
 import com.android.phone.R;
 
 import java.util.ArrayList;
@@ -270,6 +271,7 @@ public class EmergencyCallDomainSelector extends DomainSelectorBase
     private final CrossSimRedialingController mCrossSimRedialingController;
     private final DataConnectionStateHelper mEpdnHelper;
     private final List<Network> mWiFiNetworksAvailable = new ArrayList<>();
+    private final ImsEmergencyRegistrationStateHelper mImsEmergencyRegistrationHelper;
 
     /** Constructor. */
     public EmergencyCallDomainSelector(Context context, int slotId, int subId,
@@ -288,6 +290,8 @@ public class EmergencyCallDomainSelector extends DomainSelectorBase
         mCrossSimRedialingController = csrController;
         mEpdnHelper = epdnHelper;
         epdnHelper.setEmergencyCallDomainSelector(this);
+        mImsEmergencyRegistrationHelper = new ImsEmergencyRegistrationStateHelper(
+                mContext, getSlotId(), getSubId(), getLooper());
         acquireWakeLock();
     }
 
@@ -623,6 +627,9 @@ public class EmergencyCallDomainSelector extends DomainSelectorBase
         mDomainSelectionRequested = true;
         startCrossStackTimer();
         if (SubscriptionManager.isValidSubscriptionId(getSubId())) {
+            if (mCallSetupTimerOnCurrentRat > 0) {
+                mImsEmergencyRegistrationHelper.start();
+            }
             sendEmptyMessageDelayed(MSG_WAIT_FOR_IMS_STATE_TIMEOUT,
                     DEFAULT_WAIT_FOR_IMS_STATE_TIMEOUT_MS);
             selectDomain();
@@ -918,8 +925,7 @@ public class EmergencyCallDomainSelector extends DomainSelectorBase
                 requestScan(true);
                 return;
             }
-            // If NGRAN, request scan to trigger emergency registration.
-            if (mPsNetworkType == EUTRAN) {
+            if (mPsNetworkType != UNKNOWN) {
                 onWwanNetworkTypeSelected(mPsNetworkType);
             } else if (mCsNetworkType != UNKNOWN) {
                 checkAndSetTerminateAfterCsFailure(mLastRegResult);
@@ -1337,13 +1343,19 @@ public class EmergencyCallDomainSelector extends DomainSelectorBase
 
         int accessNetwork = regResult.getAccessNetwork();
         List<Integer> ratList = getImsNetworkTypeConfiguration();
+        if (!inService && !ratList.contains(NGRAN) && !isSimReady()
+                && !TextUtils.isEmpty(regResult.getCountryIso())) {
+            ratList.add(NGRAN);
+            logi("getSelectablePsNetworkType ratList=" + ratList);
+        }
         if (ratList.contains(accessNetwork)) {
             if (mIsEmergencyBarred) {
                 logi("getSelectablePsNetworkType barred");
                 return UNKNOWN;
             }
             if (accessNetwork == NGRAN) {
-                return (regResult.getNwProvidedEmc() > 0 && regResult.isVopsSupported())
+                return (regResult.getNwProvidedEmc() > 0
+                        && (regResult.isVopsSupported() || !inService))
                         ? NGRAN : UNKNOWN;
             } else if (accessNetwork == EUTRAN) {
                 return (regResult.isEmcBearerSupported()
@@ -1480,6 +1492,16 @@ public class EmergencyCallDomainSelector extends DomainSelectorBase
         for (int i = 0; i < rats.length; i++) {
             ratList.add(rats[i]);
         }
+
+        // Prefer LTE if UE is located in non-NR coverage.
+        if (ratList.contains(NGRAN) && mLastRegResult != null
+                && mLastRegResult.getAccessNetwork() != UNKNOWN
+                && mLastRegResult.getAccessNetwork() != NGRAN
+                && !TextUtils.isEmpty(mLastRegResult.getCountryIso())) {
+            ratList.remove(Integer.valueOf(NGRAN));
+            ratList.add(NGRAN);
+        }
+
         return ratList;
     }
 
@@ -1818,13 +1840,32 @@ public class EmergencyCallDomainSelector extends DomainSelectorBase
         logi("notifyCrossStackTimerExpired");
 
         mCrossStackTimerExpired = true;
-        if (mDomainSelected) {
+        boolean isHangupOngoingDialing = hangupOngoingDialing();
+        if (mDomainSelected && !isHangupOngoingDialing) {
             // When reselecting domain, terminateSelection will be called.
             return;
         }
         mIsWaitingForDataDisconnection = false;
         removeMessages(MSG_WAIT_DISCONNECTION_TIMEOUT);
-        terminateSelectionForCrossSimRedialing(false);
+        terminateSelectionForCrossSimRedialing(isHangupOngoingDialing);
+    }
+
+    /**
+     * If another slot has already permanently failed,
+     * and IMS REG is not completed in the current slot, hang up the ongoing call.
+     */
+    public void maybeHangupOngoingDialing() {
+        logi("maybeHangupOngoingDialing");
+
+        if (mDomainSelected && hangupOngoingDialing()) {
+            notifyCrossStackTimerExpired();
+        }
+    }
+
+    private boolean hangupOngoingDialing() {
+        return Flags.hangupEmergencyCallForCrossSimRedialing()
+                && (mCallSetupTimerOnCurrentRat > 0)
+                && (!mImsEmergencyRegistrationHelper.isImsEmergencyRegistered());
     }
 
     /** Notifies the ePDN connection state changes. */
@@ -1921,6 +1962,7 @@ public class EmergencyCallDomainSelector extends DomainSelectorBase
         if (DBG) logd("destroy");
 
         mEpdnHelper.setEmergencyCallDomainSelector(null);
+        mImsEmergencyRegistrationHelper.destroy();
         mCrossSimRedialingController.stopTimer();
         releaseWakeLock();
 
diff --git a/src/com/android/services/telephony/domainselection/ImsEmergencyRegistrationStateHelper.java b/src/com/android/services/telephony/domainselection/ImsEmergencyRegistrationStateHelper.java
new file mode 100644
index 000000000..a6ac9c4ff
--- /dev/null
+++ b/src/com/android/services/telephony/domainselection/ImsEmergencyRegistrationStateHelper.java
@@ -0,0 +1,212 @@
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
+package com.android.services.telephony.domainselection;
+
+import android.annotation.NonNull;
+import android.content.Context;
+import android.os.Handler;
+import android.os.Looper;
+import android.telephony.SubscriptionManager;
+import android.telephony.ims.ImsException;
+import android.telephony.ims.ImsManager;
+import android.telephony.ims.ImsMmTelManager;
+import android.telephony.ims.ImsReasonInfo;
+import android.telephony.ims.ImsRegistrationAttributes;
+import android.telephony.ims.ImsStateCallback;
+import android.telephony.ims.RegistrationManager;
+import android.util.Log;
+
+import com.android.internal.annotations.VisibleForTesting;
+
+/**
+ * A class to listen to the IMS emergency registration state.
+ */
+public class ImsEmergencyRegistrationStateHelper {
+    private static final String TAG = ImsEmergencyRegistrationStateHelper.class.getSimpleName();
+
+    protected static final long MMTEL_FEATURE_AVAILABLE_WAIT_TIME_MILLIS = 2 * 1000; // 2 seconds
+
+    private final Context mContext;
+    private final int mSlotId;
+    private final int mSubId;
+    private final Handler mHandler;
+
+    private ImsMmTelManager mMmTelManager;
+    private ImsStateCallback mImsStateCallback;
+    private RegistrationManager.RegistrationCallback mRegistrationCallback;
+    private boolean mImsEmergencyRegistered;
+
+    public ImsEmergencyRegistrationStateHelper(@NonNull Context context,
+            int slotId, int subId, @NonNull Looper looper) {
+        mContext = context;
+        mSlotId = slotId;
+        mSubId = subId;
+        mHandler = new Handler(looper);
+    }
+
+    /**
+     * Destroys this instance.
+     */
+    public void destroy() {
+        stopListeningForImsEmergencyRegistrationState();
+        mHandler.removeCallbacksAndMessages(null);
+    }
+
+    /**
+     * Returns the Handler instance.
+     */
+    @VisibleForTesting
+    public @NonNull Handler getHandler() {
+        return mHandler;
+    }
+
+    /**
+     * Returns {@code true} if IMS is registered, {@code false} otherwise.
+     */
+    public boolean isImsEmergencyRegistered() {
+        return mImsEmergencyRegistered;
+    }
+
+    /**
+     * Starts listening for IMS emergency registration state.
+     */
+    public void start() {
+        startListeningForImsEmergencyRegistrationState();
+    }
+
+    /**
+     * Starts listening to monitor the IMS states -
+     * connection state, IMS emergency registration state.
+     */
+    private void startListeningForImsEmergencyRegistrationState() {
+        if (!SubscriptionManager.isValidSubscriptionId(mSubId)) {
+            return;
+        }
+
+        ImsManager imsMngr = mContext.getSystemService(ImsManager.class);
+        mMmTelManager = imsMngr.getImsMmTelManager(mSubId);
+        mImsEmergencyRegistered = false;
+        registerImsStateCallback();
+    }
+
+    /**
+     * Stops listening to monitor the IMS states -
+     * connection state, IMS emergency registration state.
+     */
+    private void stopListeningForImsEmergencyRegistrationState() {
+        if (mMmTelManager != null) {
+            unregisterImsEmergencyRegistrationCallback();
+            unregisterImsStateCallback();
+            mMmTelManager = null;
+        }
+    }
+
+    private void registerImsStateCallback() {
+        if (mImsStateCallback != null) {
+            loge("ImsStateCallback is already registered for sub-" + mSubId);
+            return;
+        }
+
+        // Listens to the IMS connection state change.
+        mImsStateCallback = new ImsStateCallback() {
+            @Override
+            public void onUnavailable(@DisconnectedReason int reason) {
+                unregisterImsEmergencyRegistrationCallback();
+            }
+
+            @Override
+            public void onAvailable() {
+                registerImsEmergencyRegistrationCallback();
+            }
+
+            @Override
+            public void onError() {
+                mImsStateCallback = null;
+                mHandler.postDelayed(
+                        ImsEmergencyRegistrationStateHelper.this::registerImsStateCallback,
+                        MMTEL_FEATURE_AVAILABLE_WAIT_TIME_MILLIS);
+            }
+        };
+
+        try {
+            mMmTelManager.registerImsStateCallback(mHandler::post, mImsStateCallback);
+        } catch (ImsException e) {
+            loge("Exception when registering ImsStateCallback: " + e);
+            mImsStateCallback = null;
+        }
+    }
+
+    private void unregisterImsStateCallback() {
+        if (mImsStateCallback != null) {
+            try {
+                mMmTelManager.unregisterImsStateCallback(mImsStateCallback);
+            }  catch (Exception ignored) {
+                // Ignore the runtime exception while unregistering callback.
+                logd("Exception when unregistering ImsStateCallback: " + ignored);
+            }
+            mImsStateCallback = null;
+        }
+    }
+
+    private void registerImsEmergencyRegistrationCallback() {
+        if (mRegistrationCallback != null) {
+            logd("RegistrationCallback is already registered for sub-" + mSubId);
+            return;
+        }
+
+        // Listens to the IMS emergency registration state change.
+        mRegistrationCallback = new RegistrationManager.RegistrationCallback() {
+            @Override
+            public void onRegistered(@NonNull ImsRegistrationAttributes attributes) {
+                mImsEmergencyRegistered = true;
+            }
+
+            @Override
+            public void onUnregistered(@NonNull ImsReasonInfo info) {
+                mImsEmergencyRegistered = false;
+            }
+        };
+
+        try {
+            mMmTelManager.registerImsEmergencyRegistrationCallback(mHandler::post,
+                    mRegistrationCallback);
+        } catch (ImsException e) {
+            loge("Exception when registering RegistrationCallback: " + e);
+            mRegistrationCallback = null;
+        }
+    }
+
+    private void unregisterImsEmergencyRegistrationCallback() {
+        if (mRegistrationCallback != null) {
+            try {
+                mMmTelManager.unregisterImsEmergencyRegistrationCallback(mRegistrationCallback);
+            }  catch (Exception ignored) {
+                // Ignore the runtime exception while unregistering callback.
+                logd("Exception when unregistering RegistrationCallback: " + ignored);
+            }
+            mRegistrationCallback = null;
+        }
+    }
+
+    private void logd(String s) {
+        Log.d(TAG, "[" + mSlotId + "|" + mSubId + "] " + s);
+    }
+
+    private void loge(String s) {
+        Log.e(TAG, "[" + mSlotId + "|" + mSubId + "] " + s);
+    }
+}
diff --git a/src/com/android/services/telephony/domainselection/NormalCallDomainSelector.java b/src/com/android/services/telephony/domainselection/NormalCallDomainSelector.java
index a8ac04773..37813e3db 100644
--- a/src/com/android/services/telephony/domainselection/NormalCallDomainSelector.java
+++ b/src/com/android/services/telephony/domainselection/NormalCallDomainSelector.java
@@ -328,6 +328,42 @@ public class NormalCallDomainSelector extends DomainSelectorBase implements
         }
     }
 
+    private void handleReselectDomain(ImsReasonInfo imsReasonInfo) {
+        mReselectDomain = false;
+
+        // IMS -> CS
+        if (imsReasonInfo != null) {
+            logd("PsDisconnectCause:" + imsReasonInfo.getCode());
+            if (imsReasonInfo.getCode() == ImsReasonInfo.CODE_LOCAL_CALL_CS_RETRY_REQUIRED) {
+                logd("Redialing over CS");
+                notifyCsSelected();
+            } else {
+                // Not a valid redial
+                logd("Redialing cancelled.");
+                notifySelectionTerminated(DisconnectCause.NOT_VALID);
+            }
+            return;
+        }
+
+        // CS -> IMS
+        int csDisconnectCause = mSelectionAttributes.getCsDisconnectCause();
+        if (csDisconnectCause == CallFailCause.EMC_REDIAL_ON_IMS
+                || csDisconnectCause == CallFailCause.EMC_REDIAL_ON_VOWIFI) {
+            // Check IMS registration state.
+            if (mImsStateTracker.isImsRegistered()) {
+                logd("IMS is registered");
+                notifyPsSelected();
+                return;
+            }
+
+            logd("IMS is NOT registered");
+        }
+
+        // Not a valid redial
+        logd("Redialing cancelled.");
+        notifySelectionTerminated(DisconnectCause.NOT_VALID);
+    }
+
     private boolean isTtySupportedByIms() {
         CarrierConfigManager configManager = mContext.getSystemService(CarrierConfigManager.class);
 
@@ -364,42 +400,8 @@ public class NormalCallDomainSelector extends DomainSelectorBase implements
         }
 
         // Check if this is a re-dial scenario
-        ImsReasonInfo imsReasonInfo = mSelectionAttributes.getPsDisconnectCause();
         if (mReselectDomain) {
-            mReselectDomain = false;
-
-            // IMS -> CS
-            if (imsReasonInfo != null) {
-                logd("PsDisconnectCause:" + imsReasonInfo.getCode());
-                if (imsReasonInfo.getCode() == ImsReasonInfo.CODE_LOCAL_CALL_CS_RETRY_REQUIRED) {
-                    logd("Redialing over CS");
-                    notifyCsSelected();
-                } else {
-                    // Not a valid redial
-                    logd("Redialing cancelled.");
-                    notifySelectionTerminated(DisconnectCause.NOT_VALID);
-                }
-                return;
-            }
-
-            // CS -> IMS
-            int csDisconnectCause = mSelectionAttributes.getCsDisconnectCause();
-            switch (csDisconnectCause) {
-                case CallFailCause.EMC_REDIAL_ON_IMS:
-                case CallFailCause.EMC_REDIAL_ON_VOWIFI:
-                    // Check IMS registration state.
-                    if (mImsStateTracker.isImsRegistered()) {
-                        logd("IMS is registered");
-                        notifyPsSelected();
-                        return;
-                    } else {
-                        logd("IMS is NOT registered");
-                    }
-            }
-
-            // Not a valid redial
-            logd("Redialing cancelled.");
-            notifySelectionTerminated(DisconnectCause.NOT_VALID);
+            handleReselectDomain(mSelectionAttributes.getPsDisconnectCause());
             return;
         }
 
diff --git a/src/com/android/services/telephony/domainselection/OWNERS b/src/com/android/services/telephony/domainselection/OWNERS
index 2a7677001..5874c98d5 100644
--- a/src/com/android/services/telephony/domainselection/OWNERS
+++ b/src/com/android/services/telephony/domainselection/OWNERS
@@ -1,7 +1,7 @@
 # automatically inherit owners from fw/opt/telephony
 
 hwangoo@google.com
-forestchoi@google.com
+jaesikkong@google.com
 avinashmp@google.com
 mkoon@google.com
 seheele@google.com
diff --git a/testapps/SmsManagerTestApp/src/com/android/phone/testapps/smsmanagertestapp/SmsManagerTestApp.java b/testapps/SmsManagerTestApp/src/com/android/phone/testapps/smsmanagertestapp/SmsManagerTestApp.java
index cc3769ed0..d599a86be 100644
--- a/testapps/SmsManagerTestApp/src/com/android/phone/testapps/smsmanagertestapp/SmsManagerTestApp.java
+++ b/testapps/SmsManagerTestApp/src/com/android/phone/testapps/smsmanagertestapp/SmsManagerTestApp.java
@@ -184,7 +184,7 @@ public class SmsManagerTestApp extends Activity {
         intent.setComponent(SETTINGS_SUB_PICK_ACTIVITY);
         intent.putExtra(DIALOG_TYPE_KEY, SMS_PICK);
         try {
-            startActivity(intent, null);
+            startActivity(intent);
         } catch (ActivityNotFoundException anfe) {
             // If Settings is not installed, only log the error as we do not want to break
             // legacy applications.
diff --git a/testapps/TestRcsApp/TestApp/Android.bp b/testapps/TestRcsApp/TestApp/Android.bp
index 7654973e6..3bc31b1f3 100644
--- a/testapps/TestRcsApp/TestApp/Android.bp
+++ b/testapps/TestRcsApp/TestApp/Android.bp
@@ -17,7 +17,7 @@ android_app {
         "libphonenumber-platform",
     ],
 
-    libs: ["org.apache.http.legacy"],
+    libs: ["org.apache.http.legacy.stubs.system"],
 
     certificate: "platform",
     privileged: true,
diff --git a/testapps/TestRcsApp/aosp_test_rcsclient/Android.bp b/testapps/TestRcsApp/aosp_test_rcsclient/Android.bp
index fc4dc8b86..f6ed10f1f 100644
--- a/testapps/TestRcsApp/aosp_test_rcsclient/Android.bp
+++ b/testapps/TestRcsApp/aosp_test_rcsclient/Android.bp
@@ -17,7 +17,7 @@ android_library {
 
     libs: [
         "auto_value_annotations",
-        "org.apache.http.legacy",
+        "org.apache.http.legacy.stubs.system",
     ],
 
     plugins: [
diff --git a/testapps/TestSatelliteApp/res/layout/activity_SatelliteControl.xml b/testapps/TestSatelliteApp/res/layout/activity_SatelliteControl.xml
index 6aec1dab2..151f6cafe 100644
--- a/testapps/TestSatelliteApp/res/layout/activity_SatelliteControl.xml
+++ b/testapps/TestSatelliteApp/res/layout/activity_SatelliteControl.xml
@@ -21,6 +21,7 @@
     android:layout_height="wrap_content"
     android:orientation="vertical"
     android:gravity="center"
+    android:paddingTop="100dp"
     android:paddingLeft="4dp">
 
     <LinearLayout
@@ -125,6 +126,18 @@
             android:layout_height="wrap_content"
             android:paddingRight="4dp"
             android:text="@string/getIsEmergency"/>
+        <Button
+            android:id="@+id/requestSatelliteSubscriberProvisionStatus"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/requestSatelliteSubscriberProvisionStatus"/>
+        <Button
+            android:id="@+id/provisionSatellite"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/provisionSatellite"/>
          <Button
             android:id="@+id/Back"
             android:onClick="Back"
diff --git a/testapps/TestSatelliteApp/res/layout/activity_SatelliteTestApp.xml b/testapps/TestSatelliteApp/res/layout/activity_SatelliteTestApp.xml
index 5ba794660..8fdc01ff8 100644
--- a/testapps/TestSatelliteApp/res/layout/activity_SatelliteTestApp.xml
+++ b/testapps/TestSatelliteApp/res/layout/activity_SatelliteTestApp.xml
@@ -20,6 +20,7 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
+    android:paddingTop="100dp"
     android:paddingLeft="4dp">
 
     <LinearLayout
diff --git a/testapps/TestSatelliteApp/res/layout/activity_TestSatelliteWrapper.xml b/testapps/TestSatelliteApp/res/layout/activity_TestSatelliteWrapper.xml
index 43bb1c550..39a4bd690 100644
--- a/testapps/TestSatelliteApp/res/layout/activity_TestSatelliteWrapper.xml
+++ b/testapps/TestSatelliteApp/res/layout/activity_TestSatelliteWrapper.xml
@@ -25,7 +25,8 @@
         android:layout_height="wrap_content"
         android:orientation="vertical"
         android:gravity="center"
-        android:paddingStart="4dp">
+        android:paddingStart="4dp"
+        android:paddingTop="68dp">
 
         <TextView
             android:layout_width="wrap_content"
@@ -142,6 +143,30 @@
             android:layout_height="wrap_content"
             android:paddingRight="4dp"
             android:text="@string/unregisterForCarrierRoamingNtnModeChanged"/>
+        <Button
+            android:id="@+id/registerForCommunicationAllowedStateChanged"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/registerForCommunicationAllowedStateChanged"/>
+        <Button
+            android:id="@+id/unregisterForCommunicationAllowedStateChanged"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/unregisterForCommunicationAllowedStateChanged"/>
+        <Button
+            android:id="@+id/registerForModemStateChanged"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/registerForModemStateChanged"/>
+        <Button
+            android:id="@+id/unregisterForModemStateChanged"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/unregisterForModemStateChanged"/>
         <LinearLayout
             android:layout_width="match_parent"
             android:layout_height="wrap_content"
diff --git a/testapps/TestSatelliteApp/res/values/donottranslate_strings.xml b/testapps/TestSatelliteApp/res/values/donottranslate_strings.xml
index e7fbb970b..728576a10 100644
--- a/testapps/TestSatelliteApp/res/values/donottranslate_strings.xml
+++ b/testapps/TestSatelliteApp/res/values/donottranslate_strings.xml
@@ -44,6 +44,8 @@
     <string name="stopSatelliteTransmissionUpdates">stopSatelliteTransmissionUpdates</string>
     <string name="showDatagramSendStateTransition">showDatagramSendStateTransition</string>
     <string name="showDatagramReceiveStateTransition">showDatagramReceiveStateTransition</string>
+    <string name="registerForCommunicationAllowedStateChanged">registerForCommunicationAllowedStateChanged</string>
+    <string name="unregisterForCommunicationAllowedStateChanged">unregisterForCommunicationAllowedStateChanged</string>
 
     <string name="provisionSatelliteService">provisionSatelliteService</string>
     <string name="deprovisionSatelliteService">deprovisionSatelliteService</string>
@@ -91,9 +93,15 @@
     <string name="reportSatelliteNotSupportedFromModem">reportSatelliteNotSupportedFromModem</string>
     <string name="showCurrentSatelliteSupportedStated">showCurrentSatelliteSupportedStated</string>
 
+    <string name="requestSatelliteSubscriberProvisionStatus">requestSatelliteSubscriberProvisionStatus</string>
+    <string name="provisionSatellite">provisionSatellite</string>
+
     <string name="Back">Back</string>
     <string name="ClearLog">Clear Log</string>
 
     <string name="registerForCarrierRoamingNtnModeChanged">registerForCarrierRoamingNtnModeChanged</string>
     <string name="unregisterForCarrierRoamingNtnModeChanged">unregisterForCarrierRoamingNtnModeChanged</string>
+
+    <string name="registerForModemStateChanged">registerForModemStateChanged</string>
+    <string name="unregisterForModemStateChanged">unregisterForModemStateChanged</string>
 </resources>
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/Provisioning.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/Provisioning.java
index 20c5ef5b4..15c8fd830 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/Provisioning.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/Provisioning.java
@@ -39,7 +39,7 @@ import java.util.concurrent.atomic.AtomicReference;
  */
 public class Provisioning extends Activity {
 
-    private static final String TAG = "Provisioning";
+    private static final String TAG = "SatelliteProvisioning";
 
     private boolean mProvisioned = false;
 
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteControl.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteControl.java
index a03f04e19..379fc74d1 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteControl.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteControl.java
@@ -25,12 +25,15 @@ import android.telephony.SubscriptionManager;
 import android.telephony.satellite.EnableRequestAttributes;
 import android.telephony.satellite.SatelliteCapabilities;
 import android.telephony.satellite.SatelliteManager;
+import android.telephony.satellite.SatelliteSubscriberInfo;
+import android.telephony.satellite.SatelliteSubscriberProvisionStatus;
 import android.telephony.satellite.stub.SatelliteResult;
 import android.view.View;
 import android.view.View.OnClickListener;
 import android.widget.TextView;
 
 import java.time.Duration;
+import java.util.ArrayList;
 import java.util.List;
 import java.util.concurrent.LinkedBlockingQueue;
 import java.util.concurrent.TimeUnit;
@@ -45,6 +48,8 @@ public class SatelliteControl extends Activity {
 
     private SatelliteManager mSatelliteManager;
     private SubscriptionManager mSubscriptionManager;
+    private List<SatelliteSubscriberProvisionStatus> mSatelliteSubscriberProvisionStatuses =
+            new ArrayList<>();
 
     @Override
     public void onCreate(Bundle savedInstanceState) {
@@ -83,6 +88,10 @@ public class SatelliteControl extends Activity {
                 .setOnClickListener(this::isRequestIsSatelliteEnabledForCarrierApp);
         findViewById(R.id.getIsEmergency)
                 .setOnClickListener(this::getIsEmergencyApp);
+        findViewById(R.id.requestSatelliteSubscriberProvisionStatus)
+                .setOnClickListener(this::requestSatelliteSubscriberProvisionStatusApp);
+        findViewById(R.id.provisionSatellite)
+                .setOnClickListener(this::provisionSatelliteApp);
         findViewById(R.id.Back).setOnClickListener(new OnClickListener() {
             @Override
             public void onClick(View view) {
@@ -383,4 +392,68 @@ public class SatelliteControl extends Activity {
                 + SatelliteTestApp.getTestSatelliteService()
                 .getIsEmergency());
     }
+
+    private void requestSatelliteSubscriberProvisionStatusApp(View view) {
+        final AtomicReference<List<SatelliteSubscriberProvisionStatus>> list =
+                new AtomicReference<>();
+        final AtomicReference<Integer> errorCode = new AtomicReference<>();
+        OutcomeReceiver<List<SatelliteSubscriberProvisionStatus>,
+                SatelliteManager.SatelliteException>
+                receiver =
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(List<SatelliteSubscriberProvisionStatus> result) {
+                        mSatelliteSubscriberProvisionStatuses = result;
+                        list.set(result);
+                        TextView textView = findViewById(R.id.text_id);
+                        String text = "requestSatelliteSubscriberProvisionStatus: result=";
+                        for (SatelliteSubscriberProvisionStatus psi : result) {
+                            text += "" + psi + " , ";
+                        }
+                        textView.setText(text);
+                    }
+
+                    @Override
+                    public void onError(SatelliteManager.SatelliteException exception) {
+                        errorCode.set(exception.getErrorCode());
+                        TextView textView = findViewById(R.id.text_id);
+                        textView.setText(
+                                "Status for requestSatelliteSubscriberProvisionStatus error : "
+                                        + SatelliteErrorUtils.mapError(errorCode.get()));
+                    }
+                };
+        mSatelliteManager.requestSatelliteSubscriberProvisionStatus(Runnable::run, receiver);
+    }
+
+    private void provisionSatelliteApp(View view) {
+        final AtomicReference<Boolean> enabled = new AtomicReference<>();
+        final AtomicReference<Integer> errorCode = new AtomicReference<>();
+        OutcomeReceiver<Boolean, SatelliteManager.SatelliteException> receiver =
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(Boolean result) {
+                        enabled.set(result);
+                        TextView textView = findViewById(R.id.text_id);
+                        if (enabled.get()) {
+                            textView.setText("provisionSatellite is true");
+                        } else {
+                            textView.setText("Status for provisionSatellite result : "
+                                    + enabled.get());
+                        }
+                    }
+
+                    @Override
+                    public void onError(SatelliteManager.SatelliteException exception) {
+                        errorCode.set(exception.getErrorCode());
+                        TextView textView = findViewById(R.id.text_id);
+                        textView.setText("Status for provisionSatellite error : "
+                                + SatelliteErrorUtils.mapError(errorCode.get()));
+                    }
+                };
+        List<SatelliteSubscriberInfo> list = new ArrayList<>();
+        for (SatelliteSubscriberProvisionStatus status : mSatelliteSubscriberProvisionStatuses) {
+            list.add(status.getSatelliteSubscriberInfo());
+        }
+        mSatelliteManager.provisionSatellite(list, Runnable::run, receiver);
+    }
 }
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteService.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteService.java
index b5b781ced..9c75a8473 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteService.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteService.java
@@ -33,6 +33,7 @@ import android.telephony.satellite.stub.PointingInfo;
 import android.telephony.satellite.stub.SatelliteCapabilities;
 import android.telephony.satellite.stub.SatelliteDatagram;
 import android.telephony.satellite.stub.SatelliteImplBase;
+import android.telephony.satellite.stub.SatelliteModemEnableRequestAttributes;
 import android.telephony.satellite.stub.SatelliteModemState;
 import android.telephony.satellite.stub.SatelliteResult;
 import android.telephony.satellite.stub.SatelliteService;
@@ -93,7 +94,6 @@ public class TestSatelliteService extends SatelliteImplBase {
 
     private boolean mIsCommunicationAllowedInLocation;
     private boolean mIsEnabled;
-    private boolean mIsProvisioned;
     private boolean mIsSupported;
     private int mModemState;
     private boolean mIsCellularModemEnabledMode;
@@ -113,7 +113,6 @@ public class TestSatelliteService extends SatelliteImplBase {
         super(executor);
         mIsCommunicationAllowedInLocation = true;
         mIsEnabled = false;
-        mIsProvisioned = false;
         mIsSupported = true;
         mModemState = SatelliteModemState.SATELLITE_MODEM_STATE_OFF;
         mIsCellularModemEnabledMode = false;
@@ -186,21 +185,25 @@ public class TestSatelliteService extends SatelliteImplBase {
     }
 
     @Override
-    public void requestSatelliteEnabled(boolean enableSatellite, boolean enableDemoMode,
-            boolean isEmergency, @NonNull IIntegerConsumer errorCallback) {
-        logd("requestSatelliteEnabled: mErrorCode=" + mErrorCode + " enable = " + enableSatellite
-                + " isEmergency=" + isEmergency);
+    public void requestSatelliteEnabled(SatelliteModemEnableRequestAttributes enableAttributes,
+            @NonNull IIntegerConsumer errorCallback) {
+        logd("requestSatelliteEnabled: mErrorCode=" + mErrorCode
+                + ", isEnabled=" + enableAttributes.isEnabled
+                + ", isDemoMode=" + enableAttributes.isDemoMode
+                + ", isEmergency= " + enableAttributes.isEmergencyMode
+                + ", iccId=" + enableAttributes.satelliteSubscriptionInfo.iccId
+                + ", niddApn=" + enableAttributes.satelliteSubscriptionInfo.niddApn);
         if (mErrorCode != SatelliteResult.SATELLITE_RESULT_SUCCESS) {
             runWithExecutor(() -> errorCallback.accept(mErrorCode));
             return;
         }
 
-        if (enableSatellite) {
+        if (enableAttributes.isEnabled) {
             enableSatellite(errorCallback);
         } else {
             disableSatellite(errorCallback);
         }
-        mIsEmergnecy = isEmergency;
+        mIsEmergnecy = enableAttributes.isEmergencyMode;
     }
 
     private void enableSatellite(@NonNull IIntegerConsumer errorCallback) {
@@ -296,41 +299,6 @@ public class TestSatelliteService extends SatelliteImplBase {
         }
     }
 
-    @Override
-    public void provisionSatelliteService(@NonNull String token, @NonNull byte[] provisionData,
-            @NonNull IIntegerConsumer errorCallback) {
-        logd("provisionSatelliteService: mErrorCode=" + mErrorCode);
-        if (mErrorCode != SatelliteResult.SATELLITE_RESULT_SUCCESS) {
-            runWithExecutor(() -> errorCallback.accept(mErrorCode));
-            return;
-        }
-        runWithExecutor(() -> errorCallback.accept(SatelliteResult.SATELLITE_RESULT_SUCCESS));
-        updateSatelliteProvisionState(true);
-    }
-
-    @Override
-    public void deprovisionSatelliteService(@NonNull String token,
-            @NonNull IIntegerConsumer errorCallback) {
-        logd("deprovisionSatelliteService: mErrorCode=" + mErrorCode);
-        if (mErrorCode != SatelliteResult.SATELLITE_RESULT_SUCCESS) {
-            runWithExecutor(() -> errorCallback.accept(mErrorCode));
-            return;
-        }
-        runWithExecutor(() -> errorCallback.accept(SatelliteResult.SATELLITE_RESULT_SUCCESS));
-        updateSatelliteProvisionState(false);
-    }
-
-    @Override
-    public void requestIsSatelliteProvisioned(@NonNull IIntegerConsumer errorCallback,
-            @NonNull IBooleanConsumer callback) {
-        logd("requestIsSatelliteProvisioned: mErrorCode=" + mErrorCode);
-        if (mErrorCode != SatelliteResult.SATELLITE_RESULT_SUCCESS) {
-            runWithExecutor(() -> errorCallback.accept(mErrorCode));
-            return;
-        }
-        runWithExecutor(() -> callback.accept(mIsProvisioned));
-    }
-
     @Override
     public void pollPendingSatelliteDatagrams(@NonNull IIntegerConsumer errorCallback) {
         logd("pollPendingSatelliteDatagrams: mErrorCode=" + mErrorCode);
@@ -512,11 +480,6 @@ public class TestSatelliteService extends SatelliteImplBase {
                     SatelliteResult.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED));
             return false;
         }
-        if (!mIsProvisioned) {
-            runWithExecutor(() -> errorCallback.accept(
-                    SatelliteResult.SATELLITE_RESULT_SERVICE_NOT_PROVISIONED));
-            return false;
-        }
         if (!mIsEnabled) {
             runWithExecutor(() -> errorCallback.accept(
                     SatelliteResult.SATELLITE_RESULT_INVALID_MODEM_STATE));
@@ -544,24 +507,6 @@ public class TestSatelliteService extends SatelliteImplBase {
         mModemState = modemState;
     }
 
-    /**
-     * Update the satellite provision state and notify listeners if it changed.
-     *
-     * @param isProvisioned {@code true} if the satellite is currently provisioned and
-     *                      {@code false} if it is not.
-     */
-    private void updateSatelliteProvisionState(boolean isProvisioned) {
-        logd("updateSatelliteProvisionState: isProvisioned=" + isProvisioned
-                + ", mIsProvisioned=" + mIsProvisioned);
-        if (isProvisioned == mIsProvisioned) {
-            return;
-        }
-        mIsProvisioned = isProvisioned;
-        logd("updateSatelliteProvisionState: mRemoteListeners.size=" + mRemoteListeners.size());
-        mRemoteListeners.values().forEach(listener -> runWithExecutor(() ->
-                listener.onSatelliteProvisionStateChanged(mIsProvisioned)));
-    }
-
     /**
      * Execute the given runnable using the executor that this service was created with.
      *
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteWrapper.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteWrapper.java
index 93a8131a6..d8e6e7cfe 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteWrapper.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteWrapper.java
@@ -23,11 +23,13 @@ import android.os.Bundle;
 import android.os.OutcomeReceiver;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
-import android.telephony.satellite.wrapper.CarrierRoamingNtnModeListenerWrapper;
+import android.telephony.satellite.wrapper.CarrierRoamingNtnModeListenerWrapper2;
 import android.telephony.satellite.wrapper.NtnSignalStrengthCallbackWrapper;
 import android.telephony.satellite.wrapper.NtnSignalStrengthWrapper;
 import android.telephony.satellite.wrapper.SatelliteCapabilitiesCallbackWrapper;
+import android.telephony.satellite.wrapper.SatelliteCommunicationAllowedStateCallbackWrapper;
 import android.telephony.satellite.wrapper.SatelliteManagerWrapper;
+import android.telephony.satellite.wrapper.SatelliteModemStateCallbackWrapper2;
 import android.util.Log;
 import android.view.View;
 import android.view.View.OnClickListener;
@@ -54,7 +56,9 @@ public class TestSatelliteWrapper extends Activity {
     private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
     private SatelliteManagerWrapper mSatelliteManagerWrapper;
     private NtnSignalStrengthCallback mNtnSignalStrengthCallback = null;
+    private SatelliteModemStateCallback mModemStateCallback = null;
     private CarrierRoamingNtnModeListener mCarrierRoamingNtnModeListener = null;
+    private SatelliteCommunicationAllowedStateCallback mSatelliteCommunicationAllowedStateCallback;
     private SatelliteCapabilitiesCallbackWrapper mSatelliteCapabilitiesCallback;
     private SubscriptionManager mSubscriptionManager;
     private int mSubId;
@@ -105,6 +109,15 @@ public class TestSatelliteWrapper extends Activity {
                 .setOnClickListener(this::registerForCarrierRoamingNtnModeChanged);
         findViewById(R.id.unregisterForCarrierRoamingNtnModeChanged)
                 .setOnClickListener(this::unregisterForCarrierRoamingNtnModeChanged);
+        findViewById(R.id.registerForCommunicationAllowedStateChanged)
+                .setOnClickListener(this::registerForCommunicationAllowedStateChanged);
+        findViewById(R.id.unregisterForCommunicationAllowedStateChanged)
+                .setOnClickListener(this::unregisterForCommunicationAllowedStateChanged);
+        findViewById(R.id.registerForModemStateChanged)
+                .setOnClickListener(this::registerForModemStateChanged);
+        findViewById(R.id.unregisterForModemStateChanged)
+                .setOnClickListener(this::unregisterForModemStateChanged);
+
         findViewById(R.id.Back).setOnClickListener(new OnClickListener() {
             @Override
             public void onClick(View view) {
@@ -218,6 +231,38 @@ public class TestSatelliteWrapper extends Activity {
         }
     }
 
+    private void registerForCommunicationAllowedStateChanged(View view) {
+        addLogMessage("registerForCommunicationAllowedStateChanged");
+        logd("registerForCommunicationAllowedStateChanged()");
+        if (mSatelliteCommunicationAllowedStateCallback == null) {
+            logd("Creating new CarrierRoamingNtnModeListener instance.");
+            mSatelliteCommunicationAllowedStateCallback =
+                    new SatelliteCommunicationAllowedStateCallback();
+        }
+
+        try {
+            mSatelliteManagerWrapper.registerForCommunicationAllowedStateChanged(mExecutor,
+                    mSatelliteCommunicationAllowedStateCallback);
+        } catch (Exception ex) {
+            String errorMessage = "registerForCommunicationAllowedStateChanged: " + ex.getMessage();
+            logd(errorMessage);
+            addLogMessage(errorMessage);
+            mSatelliteCommunicationAllowedStateCallback = null;
+        }
+    }
+
+    private void unregisterForCommunicationAllowedStateChanged(View view) {
+        addLogMessage("unregisterForCommunicationAllowedStateChanged");
+        logd("unregisterForCommunicationAllowedStateChanged()");
+        if (mSatelliteCommunicationAllowedStateCallback != null) {
+            mSatelliteManagerWrapper.unregisterForCommunicationAllowedStateChanged(
+                    mSatelliteCommunicationAllowedStateCallback);
+            mSatelliteCommunicationAllowedStateCallback = null;
+            addLogMessage("mSatelliteCommunicationAllowedStateCallback was unregistered");
+        } else {
+            addLogMessage("mSatelliteCommunicationAllowedStateCallback is null, ignored.");
+        }
+    }
 
     private void registerForNtnSignalStrengthChanged(View view) {
         addLogMessage("registerForNtnSignalStrengthChanged");
@@ -314,6 +359,38 @@ public class TestSatelliteWrapper extends Activity {
         }
     }
 
+    private void registerForModemStateChanged(View view) {
+        addLogMessage("registerForModemStateChanged");
+        logd("registerForSatelliteModemStateChanged()");
+        if (mModemStateCallback == null) {
+            logd("create new ModemStateCallback instance.");
+            mModemStateCallback = new SatelliteModemStateCallback();
+        }
+
+        try {
+            mSatelliteManagerWrapper.registerForModemStateChanged(mExecutor, mModemStateCallback);
+        } catch (Exception ex) {
+            String errorMessage = "registerForModemStateChanged: " + ex.getMessage();
+            logd(errorMessage);
+            addLogMessage(errorMessage);
+            mModemStateCallback = null;
+        }
+    }
+
+    private void unregisterForModemStateChanged(View view) {
+        addLogMessage("unregisterForModemStateChanged");
+        logd("unregisterForModemStateChanged()");
+        if (mModemStateCallback != null) {
+            mSatelliteManagerWrapper.unregisterForModemStateChanged(mModemStateCallback);
+            mModemStateCallback = null;
+            addLogMessage("mModemStateCallback was unregistered");
+        } else {
+            addLogMessage("mModemStateCallback is null, ignored.");
+        }
+    }
+
+
+
     public class NtnSignalStrengthCallback implements NtnSignalStrengthCallbackWrapper {
         @Override
         public void onNtnSignalStrengthChanged(
@@ -324,7 +401,7 @@ public class TestSatelliteWrapper extends Activity {
         }
     }
 
-    private class CarrierRoamingNtnModeListener implements CarrierRoamingNtnModeListenerWrapper {
+    private class CarrierRoamingNtnModeListener implements CarrierRoamingNtnModeListenerWrapper2 {
 
         @Override
         public void onCarrierRoamingNtnModeChanged(boolean active) {
@@ -332,6 +409,42 @@ public class TestSatelliteWrapper extends Activity {
             logd(message);
             addLogMessage(message);
         }
+
+        @Override
+        public void onCarrierRoamingNtnEligibleStateChanged(boolean eligible) {
+            String message = "Received onCarrierRoamingNtnEligibleStateChanged "
+                    + "eligible: " + eligible;
+            logd(message);
+            addLogMessage(message);
+        }
+    }
+
+    private class SatelliteCommunicationAllowedStateCallback implements
+            SatelliteCommunicationAllowedStateCallbackWrapper {
+
+        @Override
+        public void onSatelliteCommunicationAllowedStateChanged(boolean isAllowed) {
+            String message =
+                    "Received onSatelliteCommunicationAllowedStateChanged isAllowed: " + isAllowed;
+            logd(message);
+            addLogMessage(message);
+        }
+    }
+
+    private class SatelliteModemStateCallback implements SatelliteModemStateCallbackWrapper2 {
+        @Override
+        public void onSatelliteModemStateChanged(int state) {
+            String message = "Received onSatelliteModemStateChanged state: " + state;
+            logd(message);
+            addLogMessage(message);
+        }
+
+        @Override
+        public void onEmergencyModeChanged(boolean isEmergency) {
+            String message = "Received onEmergencyModeChanged isEmergency: " + isEmergency;
+            logd(message);
+            addLogMessage(message);
+        }
     }
 
     private void isNonTerrestrialNetwork(View view) {
diff --git a/testapps/TestSliceApp/app/src/main/Android.bp b/testapps/TestSliceApp/app/src/main/Android.bp
index b02d5ff90..fa22c2b2d 100644
--- a/testapps/TestSliceApp/app/src/main/Android.bp
+++ b/testapps/TestSliceApp/app/src/main/Android.bp
@@ -12,7 +12,7 @@ android_app {
         "androidx-constraintlayout_constraintlayout",
         "androidx.appcompat_appcompat",
     ],
-    libs: ["org.apache.http.legacy"],
+    libs: ["org.apache.http.legacy.stubs.system"],
     certificate: "platform",
     privileged: true,
     product_specific: true,
diff --git a/tests/Android.bp b/tests/Android.bp
index 0fcd60e10..22b2f46e5 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -25,12 +25,12 @@ android_test {
     srcs: ["src/**/*.java"],
 
     libs: [
-        "android.test.mock",
-        "android.test.runner",
+        "android.test.mock.stubs.system",
+        "android.test.runner.stubs.system",
         "telephony-common",
-        "android.test.base",
+        "android.test.base.stubs.system",
         "ims-common",
-        "android.test.mock",
+        "android.test.mock.stubs.system",
     ],
     platform_apis: true,
     certificate: "platform",
diff --git a/tests/src/com/android/TestContext.java b/tests/src/com/android/TestContext.java
index a96ce2ef4..e464ad554 100644
--- a/tests/src/com/android/TestContext.java
+++ b/tests/src/com/android/TestContext.java
@@ -33,6 +33,7 @@ import android.os.Handler;
 import android.os.Looper;
 import android.os.PersistableBundle;
 import android.os.Process;
+import android.os.UserHandle;
 import android.os.UserManager;
 import android.telecom.TelecomManager;
 import android.telephony.CarrierConfigManager;
@@ -111,6 +112,11 @@ public class TestContext extends MockContext {
         return new AttributionSource(Process.myUid(), getPackageName(), "");
     }
 
+    @Override
+    public void startActivityAsUser(Intent intent, UserHandle user) {
+        throw new UnsupportedOperationException();
+    }
+
     @Override
     public void sendBroadcast(Intent intent) {
         mIntent = intent;
diff --git a/tests/src/com/android/phone/ImsProvisioningControllerTest.java b/tests/src/com/android/phone/ImsProvisioningControllerTest.java
index 6599f039c..c696151d9 100644
--- a/tests/src/com/android/phone/ImsProvisioningControllerTest.java
+++ b/tests/src/com/android/phone/ImsProvisioningControllerTest.java
@@ -112,6 +112,7 @@ public class ImsProvisioningControllerTest {
             REGISTRATION_TECH_NR
     };
     private static final int RADIO_TECH_INVALID = ImsRegistrationImplBase.REGISTRATION_TECH_NONE;
+    private static final String TEST_ATTR = "TEST";
 
     @Mock
     Context mContext;
@@ -636,7 +637,8 @@ public class ImsProvisioningControllerTest {
         for (int i = 0; i < RADIO_TECHS.length; i++) {
             // get provisioning status
             provisioned = mTestImsProvisioningController
-                    .getImsProvisioningStatusForCapability(mSubId0, capability, RADIO_TECHS[i]);
+                    .getImsProvisioningStatusForCapability(TEST_ATTR, mSubId0, capability,
+                            RADIO_TECHS[i]);
 
             // verify return value
             assertEquals(expectedVoiceProvisioningStatus[i], provisioned);
@@ -651,7 +653,8 @@ public class ImsProvisioningControllerTest {
         for (int i = 0; i < RADIO_TECHS.length; i++) {
             // get provisioning status
             provisioned = mTestImsProvisioningController
-                    .getImsProvisioningStatusForCapability(mSubId0, capability, RADIO_TECHS[i]);
+                    .getImsProvisioningStatusForCapability(TEST_ATTR, mSubId0, capability,
+                            RADIO_TECHS[i]);
 
             // verify return value
             assertEquals(expectedVideoProvisioningStatus[i], provisioned);
@@ -666,7 +669,8 @@ public class ImsProvisioningControllerTest {
         for (int i = 0; i < RADIO_TECHS.length; i++) {
             // get provisioning status
             provisioned = mTestImsProvisioningController
-                    .getImsProvisioningStatusForCapability(mSubId0, capability, RADIO_TECHS[i]);
+                    .getImsProvisioningStatusForCapability(TEST_ATTR, mSubId0, capability,
+                            RADIO_TECHS[i]);
 
             // verify return value
             assertEquals(expectedUtProvisioningStatus[i], provisioned);
@@ -718,7 +722,7 @@ public class ImsProvisioningControllerTest {
         int capability = CAPABILITY_TYPE_VOICE;
         int tech = REGISTRATION_TECH_LTE;
         provisioned = mTestImsProvisioningController
-                .getImsProvisioningStatusForCapability(mSubId0, capability, tech);
+                .getImsProvisioningStatusForCapability(TEST_ATTR, mSubId0, capability, tech);
 
         // verify return value default false - not provisioned
         assertEquals(true, provisioned);
@@ -741,7 +745,7 @@ public class ImsProvisioningControllerTest {
         capability = CAPABILITY_TYPE_VIDEO;
         tech = REGISTRATION_TECH_LTE;
         provisioned = mTestImsProvisioningController
-                .getImsProvisioningStatusForCapability(mSubId0, capability, tech);
+                .getImsProvisioningStatusForCapability(TEST_ATTR, mSubId0, capability, tech);
 
         // verify return value default false - not provisioned
         assertEquals(false, provisioned);
@@ -891,17 +895,19 @@ public class ImsProvisioningControllerTest {
         for (int i = 0; i < RADIO_TECHS.length; i++) {
             // get provisioning status
             provisionedFirst = mTestImsProvisioningController
-                    .getImsProvisioningStatusForCapability(mSubId0, capability, RADIO_TECHS[i]);
+                    .getImsProvisioningStatusForCapability(TEST_ATTR, mSubId0, capability,
+                            RADIO_TECHS[i]);
 
             // verify return value default false - not provisioned
             assertEquals(false, provisionedFirst);
 
             mTestImsProvisioningController.setImsProvisioningStatusForCapability(
-                    mSubId0, capability, RADIO_TECHS[i], !provisionedFirst);
+                    TEST_ATTR, mSubId0, capability, RADIO_TECHS[i], !provisionedFirst);
             processAllMessages();
 
             provisionedSecond = mTestImsProvisioningController
-                    .getImsProvisioningStatusForCapability(mSubId0, capability, RADIO_TECHS[i]);
+                    .getImsProvisioningStatusForCapability(TEST_ATTR, mSubId0, capability,
+                            RADIO_TECHS[i]);
 
             // verify return value default false - provisioned
             assertEquals(!provisionedFirst, provisionedSecond);
@@ -968,17 +974,19 @@ public class ImsProvisioningControllerTest {
         for (int i = 0; i < RADIO_TECHS.length; i++) {
             // get provisioning status
             provisionedFirst = mTestImsProvisioningController
-                    .getImsProvisioningStatusForCapability(mSubId0, capability, RADIO_TECHS[i]);
+                    .getImsProvisioningStatusForCapability(TEST_ATTR, mSubId0, capability,
+                            RADIO_TECHS[i]);
 
             // verify return value default false - not provisioned
             assertEquals(false, provisionedFirst);
 
             mTestImsProvisioningController.setImsProvisioningStatusForCapability(
-                    mSubId0, capability, RADIO_TECHS[i], !provisionedFirst);
+                    TEST_ATTR, mSubId0, capability, RADIO_TECHS[i], !provisionedFirst);
             processAllMessages();
 
             provisionedSecond = mTestImsProvisioningController
-                    .getImsProvisioningStatusForCapability(mSubId0, capability, RADIO_TECHS[i]);
+                    .getImsProvisioningStatusForCapability(TEST_ATTR, mSubId0, capability,
+                            RADIO_TECHS[i]);
 
             // verify return value default false - provisioned
             assertEquals(!provisionedFirst, provisionedSecond);
@@ -1161,7 +1169,7 @@ public class ImsProvisioningControllerTest {
         for (int i = 0; i < keys.length; i++) {
             clearInvocations(mIFeatureProvisioningCallback0);
             result = mTestImsProvisioningController.setProvisioningValue(
-                    mSubId0, keys[i], PROVISIONING_VALUE_ENABLED);
+                    TEST_ATTR, mSubId0, keys[i], PROVISIONING_VALUE_ENABLED);
             processAllMessages();
 
             // check return value
@@ -1220,7 +1228,7 @@ public class ImsProvisioningControllerTest {
         int capa = CAPABILITY_TYPE_PRESENCE_UCE;
 
         int result = mTestImsProvisioningController.setProvisioningValue(
-                    mSubId0, key, PROVISIONING_VALUE_ENABLED);
+                TEST_ATTR, mSubId0, key, PROVISIONING_VALUE_ENABLED);
         processAllMessages();
 
         // check return value
@@ -1271,7 +1279,7 @@ public class ImsProvisioningControllerTest {
         };
         for (int key : keys) {
             int result = mTestImsProvisioningController.setProvisioningValue(
-                    mSubId0, key, PROVISIONING_VALUE_ENABLED);
+                    TEST_ATTR, mSubId0, key, PROVISIONING_VALUE_ENABLED);
             processAllMessages();
 
             // check return value
@@ -1349,7 +1357,8 @@ public class ImsProvisioningControllerTest {
                 REGISTRATION_TECH_IWLAN
         };
         for (int i = 0; i < keys.length; i++) {
-            int result = mTestImsProvisioningController.getProvisioningValue(mSubId0, keys[i]);
+            int result = mTestImsProvisioningController.getProvisioningValue(TEST_ATTR, mSubId0,
+                    keys[i]);
             processAllMessages();
 
             // check return value
@@ -1365,7 +1374,7 @@ public class ImsProvisioningControllerTest {
         int key = KEY_EAB_PROVISIONING_STATUS;
         int capa = CAPABILITY_TYPE_PRESENCE_UCE;
 
-        int result = mTestImsProvisioningController.getProvisioningValue(mSubId0, key);
+        int result = mTestImsProvisioningController.getProvisioningValue(TEST_ATTR, mSubId0, key);
         processAllMessages();
 
         // check return value
@@ -1453,7 +1462,8 @@ public class ImsProvisioningControllerTest {
                 REGISTRATION_TECH_IWLAN
         };
         for (int i = 0; i < keys.length; i++) {
-            int result = mTestImsProvisioningController.getProvisioningValue(mSubId0, keys[i]);
+            int result = mTestImsProvisioningController.getProvisioningValue(TEST_ATTR, mSubId0,
+                    keys[i]);
             processAllMessages();
 
             // check return value
@@ -1481,7 +1491,7 @@ public class ImsProvisioningControllerTest {
         int key = KEY_EAB_PROVISIONING_STATUS;
         int capa = CAPABILITY_TYPE_PRESENCE_UCE;
 
-        int result = mTestImsProvisioningController.getProvisioningValue(mSubId0, key);
+        int result = mTestImsProvisioningController.getProvisioningValue(TEST_ATTR, mSubId0, key);
         processAllMessages();
 
         // check return value
@@ -1590,8 +1600,8 @@ public class ImsProvisioningControllerTest {
         int tech = REGISTRATION_TECH_LTE;
         boolean provisioned;
         provisioned = mTestImsProvisioningController.getImsProvisioningStatusForCapability(
-                mSubId1, capability, tech);
-        mTestImsProvisioningController.setImsProvisioningStatusForCapability(mSubId1,
+                TEST_ATTR, mSubId1, capability, tech);
+        mTestImsProvisioningController.setImsProvisioningStatusForCapability(TEST_ATTR, mSubId1,
                 capability, tech, !provisioned);
         processAllMessages();
 
@@ -1643,7 +1653,7 @@ public class ImsProvisioningControllerTest {
         int capa = CAPABILITY_TYPE_PRESENCE_UCE;
         int tech = REGISTRATION_TECH_LTE;
 
-        int result = mTestImsProvisioningController.getProvisioningValue(mSubId0, key);
+        int result = mTestImsProvisioningController.getProvisioningValue(TEST_ATTR, mSubId0, key);
         processAllMessages();
 
         // check return value
@@ -1668,7 +1678,7 @@ public class ImsProvisioningControllerTest {
         clearInvocations(mImsConfig);
         clearInvocations(mImsProvisioningLoader);
 
-        mTestImsProvisioningController.setProvisioningValue(mSubId0, key,
+        mTestImsProvisioningController.setProvisioningValue(TEST_ATTR, mSubId0, key,
                 PROVISIONING_VALUE_DISABLED);
         processAllMessages();
 
diff --git a/tests/src/com/android/phone/ImsStateCallbackControllerTest.java b/tests/src/com/android/phone/ImsStateCallbackControllerTest.java
index c86502b41..0e902a8ea 100644
--- a/tests/src/com/android/phone/ImsStateCallbackControllerTest.java
+++ b/tests/src/com/android/phone/ImsStateCallbackControllerTest.java
@@ -37,6 +37,7 @@ import static org.mockito.Matchers.anyInt;
 import static org.mockito.Matchers.eq;
 import static org.mockito.Mockito.atLeastOnce;
 import static org.mockito.Mockito.doAnswer;
+import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
@@ -60,6 +61,7 @@ import com.android.ims.RcsFeatureManager;
 import com.android.internal.telephony.IImsStateCallback;
 import com.android.internal.telephony.ITelephony;
 import com.android.internal.telephony.Phone;
+import com.android.internal.telephony.flags.FeatureFlags;
 import com.android.internal.telephony.ims.ImsResolver;
 
 import org.junit.After;
@@ -121,6 +123,7 @@ public class ImsStateCallbackControllerTest extends TelephonyTestBase {
     @Mock private IImsStateCallback mCallback2;
     @Mock private IImsStateCallback mCallback3;
     @Mock private ImsResolver mImsResolver;
+    @Mock private FeatureFlags mFeatureFlags;
 
     private Executor mExecutor = new Executor() {
         @Override
@@ -908,6 +911,31 @@ public class ImsStateCallbackControllerTest extends TelephonyTestBase {
         assertNull(imsManager);
     }
 
+    @Test
+    @SmallTest
+    public void testImsManagerInstanceWithInvalidSubId() throws Exception {
+        doReturn(true).when(mFeatureFlags).avoidDeletingImsObjectFromCache();
+
+        createController(1);
+
+        // MmTelConnection ready
+        mMmTelConnectorListenerSlot0.getValue()
+                .connectionReady(mMmTelFeatureManager, SLOT_0_SUB_ID);
+        processAllMessages();
+
+        // check ImsManager instance
+        ImsManager imsManager = mImsStateCallbackController.getImsManager(SLOT_0_SUB_ID);
+        assertNotNull(imsManager);
+
+        // SubId changed from SLOT_0_SUB_ID to INVALID_SUBSCRIPTION_ID
+        when(mPhoneSlot0.getSubId()).thenReturn(SubscriptionManager.INVALID_SUBSCRIPTION_ID);
+        mImsStateCallbackController.onSubChanged();
+
+        // ImsStateCallbackController should keep the ImsManager instance for SLOT_0_SUB_ID
+        imsManager = mImsStateCallbackController.getImsManager(SLOT_0_SUB_ID);
+        assertNotNull(imsManager);
+    }
+
     private void createController(int slotCount) throws Exception {
         if (Looper.myLooper() == null) {
             Looper.prepare();
@@ -929,7 +957,8 @@ public class ImsStateCallbackControllerTest extends TelephonyTestBase {
 
         mImsStateCallbackController =
                 new ImsStateCallbackController(mPhone, mHandlerThread.getLooper(),
-                        slotCount, mMmTelFeatureFactory, mRcsFeatureFactory, mImsResolver);
+                        slotCount, mMmTelFeatureFactory, mRcsFeatureFactory, mImsResolver,
+                        mFeatureFlags);
 
         replaceInstance(ImsStateCallbackController.class,
                 "mPhoneFactoryProxy", mImsStateCallbackController, mPhoneFactoryProxy);
diff --git a/tests/src/com/android/phone/PhoneInterfaceManagerTest.java b/tests/src/com/android/phone/PhoneInterfaceManagerTest.java
index 2d46c80f9..7464ba2fa 100644
--- a/tests/src/com/android/phone/PhoneInterfaceManagerTest.java
+++ b/tests/src/com/android/phone/PhoneInterfaceManagerTest.java
@@ -21,6 +21,7 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
@@ -41,6 +42,7 @@ import android.content.SharedPreferences;
 import android.content.pm.PackageManager;
 import android.content.res.Resources;
 import android.os.Build;
+import android.os.UserHandle;
 import android.permission.flags.Flags;
 import android.platform.test.flag.junit.SetFlagsRule;
 import android.telephony.RadioAccessFamily;
@@ -111,6 +113,9 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
         // alive on a test devices. You must use the spy to mock behavior. Mocks stemming from the
         // passed context will remain unused.
         mPhoneInterfaceManager = spy(PhoneInterfaceManager.init(mPhoneGlobals, mFeatureFlags));
+        doReturn(mPhoneGlobals).when(mPhoneGlobals).getBaseContext();
+        doReturn(mPhoneGlobals).when(mPhoneGlobals).createContextAsUser(
+                any(UserHandle.class), anyInt());
         doReturn(mSubscriptionManagerService).when(mPhoneInterfaceManager)
                 .getSubscriptionManagerService();
         TelephonyManager.setupISubForTest(mSubscriptionManagerService);
@@ -123,6 +128,7 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
         // and disabled enforce_telephony_feature_mapping_for_public_apis feature flag
         mPhoneInterfaceManager.setFeatureFlags(mFeatureFlags);
         doReturn(false).when(mFeatureFlags).enforceTelephonyFeatureMappingForPublicApis();
+        doReturn(true).when(mFeatureFlags).hsumPackageManager();
         mPhoneInterfaceManager.setPackageManager(mPackageManager);
         doReturn(true).when(mPackageManager).hasSystemFeature(anyString());
 
diff --git a/tests/src/com/android/phone/RcsProvisioningMonitorTest.java b/tests/src/com/android/phone/RcsProvisioningMonitorTest.java
index fe13d5667..26144607e 100644
--- a/tests/src/com/android/phone/RcsProvisioningMonitorTest.java
+++ b/tests/src/com/android/phone/RcsProvisioningMonitorTest.java
@@ -69,6 +69,7 @@ import androidx.test.filters.SmallTest;
 import com.android.ims.FeatureConnector;
 import com.android.ims.RcsFeatureManager;
 import com.android.internal.telephony.ITelephony;
+import com.android.internal.telephony.flags.FeatureFlags;
 import com.android.internal.telephony.metrics.RcsStats;
 
 import org.junit.After;
@@ -191,6 +192,9 @@ public class RcsProvisioningMonitorTest {
     @Mock
     private RcsStats.RcsProvisioningCallback mRcsProvisioningCallback;
 
+    @Mock
+    private FeatureFlags mFeatureFlags;
+
     private Executor mExecutor = new Executor() {
         @Override
         public void execute(Runnable r) {
@@ -251,6 +255,7 @@ public class RcsProvisioningMonitorTest {
                 .thenReturn(mSubscriptionManager);
         when(mPhone.getSystemService(eq(Context.TELEPHONY_REGISTRY_SERVICE)))
                 .thenReturn(mTelephonyRegistryManager);
+        when(mFeatureFlags.hsumBroadcast()).thenReturn(true);
 
         mBundle = new PersistableBundle();
         when(mCarrierConfigManager.getConfigForSubId(anyInt())).thenReturn(mBundle);
@@ -398,7 +403,7 @@ public class RcsProvisioningMonitorTest {
     public void testCarrierConfigChanged() throws Exception {
         createMonitor(1);
         // should not broadcast message if carrier config is not ready
-        verify(mPhone, never()).sendBroadcast(any(), any());
+        verify(mPhone, never()).sendBroadcastAsUser(any(), eq(UserHandle.ALL), any());
 
         when(mPackageManager.hasSystemFeature(
                 eq(PackageManager.FEATURE_TELEPHONY_IMS_SINGLE_REGISTRATION))).thenReturn(true);
@@ -410,7 +415,8 @@ public class RcsProvisioningMonitorTest {
         broadcastCarrierConfigChange(FAKE_SUB_ID_BASE);
         processAllMessages();
 
-        verify(mPhone, times(1)).sendBroadcast(captorIntent.capture(), any());
+        verify(mPhone, times(1)).sendBroadcastAsUser(captorIntent.capture(),
+                eq(UserHandle.ALL), any());
         Intent capturedIntent = captorIntent.getValue();
         assertEquals(capturedIntent.getAction(),
                 ProvisioningManager.ACTION_RCS_SINGLE_REGISTRATION_CAPABILITY_UPDATE);
@@ -424,7 +430,8 @@ public class RcsProvisioningMonitorTest {
         broadcastCarrierConfigChange(FAKE_SUB_ID_BASE);
         processAllMessages();
 
-        verify(mPhone, times(2)).sendBroadcast(captorIntent.capture(), any());
+        verify(mPhone, times(2)).sendBroadcastAsUser(captorIntent.capture(),
+                eq(UserHandle.ALL), any());
         capturedIntent = captorIntent.getValue();
         assertEquals(capturedIntent.getAction(),
                 ProvisioningManager.ACTION_RCS_SINGLE_REGISTRATION_CAPABILITY_UPDATE);
@@ -439,7 +446,8 @@ public class RcsProvisioningMonitorTest {
         broadcastCarrierConfigChange(FAKE_SUB_ID_BASE);
         processAllMessages();
 
-        verify(mPhone, times(3)).sendBroadcast(captorIntent.capture(), any());
+        verify(mPhone, times(3)).sendBroadcastAsUser(captorIntent.capture(),
+                eq(UserHandle.ALL), any());
         capturedIntent = captorIntent.getValue();
         assertEquals(capturedIntent.getAction(),
                 ProvisioningManager.ACTION_RCS_SINGLE_REGISTRATION_CAPABILITY_UPDATE);
@@ -592,7 +600,7 @@ public class RcsProvisioningMonitorTest {
         processAllMessages();
 
         // should not broadcast message as no carrier config change happens
-        verify(mPhone, never()).sendBroadcast(any(), any());
+        verify(mPhone, never()).sendBroadcastAsUser(any(), eq(UserHandle.ALL), any());
 
         when(mCarrierConfigManager.getConfigForSubId(anyInt())).thenReturn(mBundle);
         when(mPackageManager.hasSystemFeature(
@@ -604,7 +612,8 @@ public class RcsProvisioningMonitorTest {
         broadcastCarrierConfigChange(FAKE_SUB_ID_BASE);
         processAllMessages();
 
-        verify(mPhone, times(1)).sendBroadcast(captorIntent.capture(), any());
+        verify(mPhone, times(1)).sendBroadcastAsUser(captorIntent.capture(),
+                eq(UserHandle.ALL), any());
         Intent capturedIntent = captorIntent.getValue();
         assertEquals(capturedIntent.getAction(),
                 ProvisioningManager.ACTION_RCS_SINGLE_REGISTRATION_CAPABILITY_UPDATE);
@@ -614,7 +623,8 @@ public class RcsProvisioningMonitorTest {
 
         // should broadcast message when default messaging application changed if carrier config
         // has been loaded
-        verify(mPhone, times(2)).sendBroadcast(captorIntent.capture(), any());
+        verify(mPhone, times(2)).sendBroadcastAsUser(captorIntent.capture(),
+                eq(UserHandle.ALL), any());
         capturedIntent = captorIntent.getValue();
         assertEquals(capturedIntent.getAction(),
                 ProvisioningManager.ACTION_RCS_SINGLE_REGISTRATION_CAPABILITY_UPDATE);
@@ -848,7 +858,7 @@ public class RcsProvisioningMonitorTest {
                 .thenReturn(mFeatureConnector);
         when(mFeatureManager.getConfig()).thenReturn(mIImsConfig);
         mRcsProvisioningMonitor = new RcsProvisioningMonitor(mPhone, mHandlerThread.getLooper(),
-                mRoleManager, mFeatureFactory, mRcsStats);
+                mRoleManager, mFeatureFactory, mRcsStats, mFeatureFlags);
         mHandler = mRcsProvisioningMonitor.getHandler();
         try {
             mLooper = new TestableLooper(mHandler.getLooper());
diff --git a/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessControllerTest.java b/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessControllerTest.java
index 8eba53bfa..55f72fc1f 100644
--- a/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessControllerTest.java
+++ b/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessControllerTest.java
@@ -16,14 +16,26 @@
 
 package com.android.phone.satellite.accesscontrol;
 
+import static android.location.LocationManager.MODE_CHANGED_ACTION;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_COMMUNICATION_ALLOWED;
+import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_PROVISIONED;
+import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_SUPPORTED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_ERROR;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_LOCATION_DISABLED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_LOCATION_NOT_AVAILABLE;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_MODEM_ERROR;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_NOT_SUPPORTED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_SUCCESS;
 
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.ALLOWED_STATE_CACHE_VALID_DURATION_NANOS;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.EVENT_COUNTRY_CODE_CHANGED;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.CMD_IS_SATELLITE_COMMUNICATION_ALLOWED;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_DELAY_MINUTES_BEFORE_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_THROTTLE_INTERVAL_FOR_LOCATION_QUERY_MINUTES;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.EVENT_CONFIG_DATA_UPDATED;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.GOOGLE_US_SAN_SAT_S2_FILE_NAME;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_MAX_RETRY_COUNT_FOR_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
@@ -34,10 +46,12 @@ import static org.junit.Assert.fail;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.clearInvocations;
 import static org.mockito.Mockito.doAnswer;
+import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
@@ -47,7 +61,10 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.annotation.Nullable;
+import android.content.BroadcastReceiver;
 import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
 import android.content.SharedPreferences;
 import android.content.res.Resources;
 import android.location.Location;
@@ -63,6 +80,7 @@ import android.os.Looper;
 import android.os.Message;
 import android.os.ResultReceiver;
 import android.telecom.TelecomManager;
+import android.telephony.SubscriptionManager;
 import android.telephony.satellite.SatelliteManager;
 import android.testing.TestableLooper;
 import android.util.Log;
@@ -93,6 +111,7 @@ import java.lang.reflect.Field;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashMap;
+import java.util.Iterator;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
@@ -106,15 +125,23 @@ import java.util.function.Consumer;
 public class SatelliteAccessControllerTest {
     private static final String TAG = "SatelliteAccessControllerTest";
     private static final String[] TEST_SATELLITE_COUNTRY_CODES = {"US", "CA", "UK"};
+    private static final String[] TEST_SATELLITE_COUNTRY_CODES_EMPTY = {""};
+    private static final String TEST_SATELLITE_COUNTRY_CODE_US = "US";
+    private static final String TEST_SATELLITE_COUNTRY_CODE_KR = "KR";
+    private static final String TEST_SATELLITE_COUNTRY_CODE_JP = "JP";
+
     private static final String TEST_SATELLITE_S2_FILE = "sat_s2_file.dat";
     private static final boolean TEST_SATELLITE_ALLOW = true;
+    private static final boolean TEST_SATELLITE_NOT_ALLOW = false;
     private static final int TEST_LOCATION_FRESH_DURATION_SECONDS = 10;
     private static final long TEST_LOCATION_FRESH_DURATION_NANOS =
             TimeUnit.SECONDS.toNanos(TEST_LOCATION_FRESH_DURATION_SECONDS);
+    private static final long TEST_LOCATION_QUERY_THROTTLE_INTERVAL_NANOS =
+            TimeUnit.MINUTES.toNanos(10);  // DEFAULT_THROTTLE_INTERVAL_FOR_LOCATION_QUERY_MINUTES
     private static final long TIMEOUT = 500;
     private static final List<String> EMPTY_STRING_LIST = new ArrayList<>();
     private static final List<String> LOCATION_PROVIDERS =
-            listOf(LocationManager.NETWORK_PROVIDER, LocationManager.GPS_PROVIDER);
+            listOf(LocationManager.NETWORK_PROVIDER, LocationManager.FUSED_PROVIDER);
     private static final int SUB_ID = 0;
 
     @Mock
@@ -154,6 +181,12 @@ public class SatelliteAccessControllerTest {
     @Mock
     private Map<SatelliteOnDeviceAccessController.LocationToken, Boolean>
             mMockCachedAccessRestrictionMap;
+    @Mock
+    private Intent mMockLocationIntent;
+    @Mock
+    private Set<ResultReceiver> mMockSatelliteAllowResultReceivers;
+    @Mock
+    private ResultReceiver mMockSatelliteSupportedResultReceiver;
 
     private Looper mLooper;
     private TestableLooper mTestableLooper;
@@ -170,6 +203,25 @@ public class SatelliteAccessControllerTest {
     private ArgumentCaptor<Integer> mConfigUpdateIntCaptor;
     @Captor
     private ArgumentCaptor<Object> mConfigUpdateObjectCaptor;
+    @Captor
+    private ArgumentCaptor<Handler> mCountryDetectorHandlerCaptor;
+    @Captor
+    private ArgumentCaptor<Integer> mCountryDetectorIntCaptor;
+    @Captor
+    private ArgumentCaptor<Object> mCountryDetectorObjCaptor;
+    @Captor
+    private ArgumentCaptor<BroadcastReceiver> mLocationBroadcastReceiverCaptor;
+    @Captor
+    private ArgumentCaptor<IntentFilter> mIntentFilterCaptor;
+    @Captor
+    private ArgumentCaptor<LocationRequest> mLocationRequestCaptor;
+    @Captor
+    private ArgumentCaptor<String> mLocationProviderStringCaptor;
+    @Captor
+    private ArgumentCaptor<Integer> mResultCodeIntCaptor;
+    @Captor
+    private ArgumentCaptor<Bundle> mResultDataBundleCaptor;
+
     private boolean mQueriedSatelliteAllowed = false;
     private int mQueriedSatelliteAllowedResultCode = SATELLITE_RESULT_SUCCESS;
     private Semaphore mSatelliteAllowedSemaphore = new Semaphore(0);
@@ -230,6 +282,8 @@ public class SatelliteAccessControllerTest {
                 mMockSatelliteModemInterface);
         replaceInstance(TelephonyCountryDetector.class, "sInstance", null,
                 mMockCountryDetector);
+        when(mMockSatelliteController.getSatellitePhone()).thenReturn(mMockPhone);
+        when(mMockPhone.getSubId()).thenReturn(SubscriptionManager.getDefaultSubscriptionId());
         when(mMockContext.getResources()).thenReturn(mMockResources);
         when(mMockResources.getStringArray(
                 com.android.internal.R.array.config_oem_enabled_satellite_country_codes))
@@ -243,11 +297,22 @@ public class SatelliteAccessControllerTest {
         when(mMockResources.getInteger(com.android.internal.R.integer
                 .config_oem_enabled_satellite_location_fresh_duration))
                 .thenReturn(TEST_LOCATION_FRESH_DURATION_SECONDS);
+        when(mMockResources.getInteger(com.android.internal.R.integer
+                .config_satellite_delay_minutes_before_retry_validating_possible_change_in_allowed_region))
+                .thenReturn(
+                        DEFAULT_DELAY_MINUTES_BEFORE_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION);
+        when(mMockResources.getInteger(com.android.internal.R.integer
+                .config_satellite_max_retry_count_for_validating_possible_change_in_allowed_region))
+                .thenReturn(
+                        DEFAULT_MAX_RETRY_COUNT_FOR_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION);
+        when(mMockResources.getInteger(com.android.internal.R.integer
+                .config_satellite_location_query_throttle_interval_minutes))
+                .thenReturn(DEFAULT_THROTTLE_INTERVAL_FOR_LOCATION_QUERY_MINUTES);
 
         when(mMockLocationManager.getProviders(true)).thenReturn(LOCATION_PROVIDERS);
         when(mMockLocationManager.getLastKnownLocation(LocationManager.NETWORK_PROVIDER))
                 .thenReturn(mMockLocation0);
-        when(mMockLocationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER))
+        when(mMockLocationManager.getLastKnownLocation(LocationManager.FUSED_PROVIDER))
                 .thenReturn(mMockLocation1);
         when(mMockLocation0.getLatitude()).thenReturn(0.0);
         when(mMockLocation0.getLongitude()).thenReturn(0.0);
@@ -266,8 +331,13 @@ public class SatelliteAccessControllerTest {
                 .putBoolean(anyString(), anyBoolean());
         doReturn(mMockSharedPreferencesEditor).when(mMockSharedPreferencesEditor)
                 .putStringSet(anyString(), any());
+        doReturn(mMockSharedPreferencesEditor).when(mMockSharedPreferencesEditor)
+                .putLong(anyString(), anyLong());
+        doNothing().when(mMockSharedPreferencesEditor).apply();
 
         when(mMockFeatureFlags.satellitePersistentLogging()).thenReturn(true);
+        when(mMockFeatureFlags.geofenceEnhancementForBetterUx()).thenReturn(true);
+        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
 
         mSatelliteAccessControllerUT = new TestSatelliteAccessController(mMockContext,
                 mMockFeatureFlags, mLooper, mMockLocationManager, mMockTelecomManager,
@@ -298,12 +368,275 @@ public class SatelliteAccessControllerTest {
         assertEquals(inst1, inst2);
     }
 
+    @Test
+    public void testIsSatelliteAccessAllowedForLocation() {
+        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
+
+        // Test disallowList case
+        when(mMockResources.getBoolean(
+                com.android.internal.R.bool.config_oem_enabled_satellite_access_allow))
+                .thenReturn(TEST_SATELLITE_NOT_ALLOW);
+
+        // configuration is EMPTY then we return true with any network country code.
+        when(mMockResources.getStringArray(
+                com.android.internal.R.array.config_oem_enabled_satellite_country_codes))
+                .thenReturn(TEST_SATELLITE_COUNTRY_CODES_EMPTY);
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        assertTrue(mSatelliteAccessControllerUT
+                .isSatelliteAccessAllowedForLocation(List.of(TEST_SATELLITE_COUNTRY_CODE_US)));
+        assertTrue(mSatelliteAccessControllerUT
+                .isSatelliteAccessAllowedForLocation(List.of(TEST_SATELLITE_COUNTRY_CODE_JP)));
+
+        // configuration is ["US", "CA", "UK"]
+        // - if network country code is ["US"] or ["US","KR"] or [EMPTY] return false;
+        // - if network country code is ["KR"] return true;
+        when(mMockResources.getStringArray(
+                com.android.internal.R.array.config_oem_enabled_satellite_country_codes))
+                .thenReturn(TEST_SATELLITE_COUNTRY_CODES);
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        assertFalse(mSatelliteAccessControllerUT.isSatelliteAccessAllowedForLocation(List.of()));
+        assertFalse(mSatelliteAccessControllerUT
+                .isSatelliteAccessAllowedForLocation(List.of(TEST_SATELLITE_COUNTRY_CODE_US)));
+        assertFalse(mSatelliteAccessControllerUT.isSatelliteAccessAllowedForLocation(
+                        List.of(TEST_SATELLITE_COUNTRY_CODE_US, TEST_SATELLITE_COUNTRY_CODE_KR)));
+        assertTrue(mSatelliteAccessControllerUT
+                .isSatelliteAccessAllowedForLocation(List.of(TEST_SATELLITE_COUNTRY_CODE_KR)));
+
+        // Test allowList case
+        when(mMockResources.getBoolean(
+                com.android.internal.R.bool.config_oem_enabled_satellite_access_allow))
+                .thenReturn(TEST_SATELLITE_ALLOW);
+
+        // configuration is [EMPTY] then return false in case of any network country code
+        when(mMockResources.getStringArray(
+                com.android.internal.R.array.config_oem_enabled_satellite_country_codes))
+                .thenReturn(TEST_SATELLITE_COUNTRY_CODES_EMPTY);
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        assertFalse(mSatelliteAccessControllerUT
+                .isSatelliteAccessAllowedForLocation(List.of(TEST_SATELLITE_COUNTRY_CODE_US)));
+        assertFalse(mSatelliteAccessControllerUT
+                .isSatelliteAccessAllowedForLocation(List.of(TEST_SATELLITE_COUNTRY_CODE_JP)));
+
+        // configuration is ["US", "CA", "UK"]
+        // - if network country code is [EMPTY] or ["US","KR"] or [KR] return false;
+        // - if network country code is ["US"] return true;
+        when(mMockResources.getStringArray(
+                com.android.internal.R.array.config_oem_enabled_satellite_country_codes))
+                .thenReturn(TEST_SATELLITE_COUNTRY_CODES);
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        assertFalse(mSatelliteAccessControllerUT.isSatelliteAccessAllowedForLocation(List.of()));
+        assertFalse(mSatelliteAccessControllerUT
+                .isSatelliteAccessAllowedForLocation(List.of(TEST_SATELLITE_COUNTRY_CODE_KR)));
+        assertFalse(mSatelliteAccessControllerUT.isSatelliteAccessAllowedForLocation(
+                List.of(TEST_SATELLITE_COUNTRY_CODE_US, TEST_SATELLITE_COUNTRY_CODE_KR)));
+        assertTrue(mSatelliteAccessControllerUT
+                .isSatelliteAccessAllowedForLocation(List.of(TEST_SATELLITE_COUNTRY_CODE_US)));
+    }
+
+    @Test
+    public void testIsRegionDisallowed() throws Exception {
+        // setup to make the return value of mQueriedSatelliteAllowed 'true'
+        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
+        when(mMockContext.getResources()).thenReturn(mMockResources);
+        when(mMockResources.getBoolean(
+                com.android.internal.R.bool.config_oem_enabled_satellite_access_allow))
+                .thenReturn(TEST_SATELLITE_ALLOW);
+        setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
+        setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
+        doReturn(true).when(mMockLocationManager).isLocationEnabled();
+        when(mMockSatelliteOnDeviceAccessController.isSatCommunicationAllowedAtLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class))).thenReturn(true);
+        replaceInstance(SatelliteAccessController.class, "mCachedAccessRestrictionMap",
+                mSatelliteAccessControllerUT, mMockCachedAccessRestrictionMap);
+        doReturn(true).when(mMockCachedAccessRestrictionMap).containsKey(any());
+        doReturn(true).when(mMockCachedAccessRestrictionMap).get(any());
+
+        // get allowed country codes EMPTY from resources
+        when(mMockResources.getStringArray(
+                com.android.internal.R.array.config_oem_enabled_satellite_country_codes))
+                .thenReturn(TEST_SATELLITE_COUNTRY_CODES_EMPTY);
+
+        // allow case that network country codes [US] with [EMPTY] configuration
+        // location will not be compared and mQueriedSatelliteAllowed will be set false
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso())
+                .thenReturn(List.of(TEST_SATELLITE_COUNTRY_CODE_US));
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(0)).containsKey(any());
+        assertFalse(mQueriedSatelliteAllowed);
+
+        // allow case that network country codes [EMPTY] with [EMPTY] configuration
+        // location will be compared and mQueriedSatelliteAllowed will be set true
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso()).thenReturn(List.of());
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(1)).containsKey(any());
+        assertTrue(mQueriedSatelliteAllowed);
+
+        // get allowed country codes [US, CA, UK] from resources
+        when(mMockResources.getStringArray(
+                com.android.internal.R.array.config_oem_enabled_satellite_country_codes))
+                .thenReturn(TEST_SATELLITE_COUNTRY_CODES);
+
+        // allow case that network country codes [US, CA, UK] with [US, CA, UK] configuration
+        // location will be compared and mQueriedSatelliteAllowed will be set true
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso())
+                .thenReturn(List.of(TEST_SATELLITE_COUNTRY_CODES));
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(1)).containsKey(any());
+        assertTrue(mQueriedSatelliteAllowed);
+
+        // allow case that network country codes [US] with [US, CA, UK] configuration
+        // location will be compared and mQueriedSatelliteAllowed will be set true
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso())
+                .thenReturn(List.of(TEST_SATELLITE_COUNTRY_CODE_US));
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(1)).containsKey(any());
+        assertTrue(mQueriedSatelliteAllowed);
+
+        // allow case that network country codes [US, KR] with [US, CA, UK] configuration
+        // location will be compared and mQueriedSatelliteAllowed will be set true
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso()).thenReturn(
+                List.of(TEST_SATELLITE_COUNTRY_CODE_US, TEST_SATELLITE_COUNTRY_CODE_KR));
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(1)).containsKey(any());
+        assertTrue(mQueriedSatelliteAllowed);
+
+        // allow case that network country codes [US] with [EMPTY] configuration
+        // location will be compared and mQueriedSatelliteAllowed will be set true
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso()).thenReturn(List.of());
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(1)).containsKey(any());
+        assertTrue(mQueriedSatelliteAllowed);
+
+        // allow case that network country codes [KR, JP] with [US, CA, UK] configuration
+        // location will not be compared and mQueriedSatelliteAllowed will be set false
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso()).thenReturn(
+                List.of(TEST_SATELLITE_COUNTRY_CODE_KR, TEST_SATELLITE_COUNTRY_CODE_JP));
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(0)).containsKey(any());
+        assertFalse(mQueriedSatelliteAllowed);
+
+        // allow case that network country codes [KR] with [US, CA, UK] configuration
+        // location will not be compared and mQueriedSatelliteAllowed will be set false
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso())
+                .thenReturn(List.of(TEST_SATELLITE_COUNTRY_CODE_KR));
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(0)).containsKey(any());
+        assertFalse(mQueriedSatelliteAllowed);
+
+
+        // set disallowed list case
+        when(mMockResources.getBoolean(
+                com.android.internal.R.bool.config_oem_enabled_satellite_access_allow))
+                .thenReturn(TEST_SATELLITE_NOT_ALLOW);
+        // get disallowed country codes list [EMPTY] from resources
+        when(mMockResources.getStringArray(
+                com.android.internal.R.array.config_oem_enabled_satellite_country_codes))
+                .thenReturn(TEST_SATELLITE_COUNTRY_CODES_EMPTY);
+
+        // disallow case that network country codes [US] with [EMPTY] configuration
+        // location will be compared and mQueriedSatelliteAllowed will be set true
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso())
+                .thenReturn(List.of(TEST_SATELLITE_COUNTRY_CODE_US));
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(1)).containsKey(any());
+        assertTrue(mQueriedSatelliteAllowed);
+
+        // get disallowed country codes list ["US", "CA", "UK"] from resources
+        when(mMockResources.getStringArray(
+                com.android.internal.R.array.config_oem_enabled_satellite_country_codes))
+                .thenReturn(TEST_SATELLITE_COUNTRY_CODES);
+
+        // disallow case that network country codes [EMPTY] with [US, CA, UK] configuration
+        // location will be compared and mQueriedSatelliteAllowed will be set true
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso())
+                .thenReturn(List.of(TEST_SATELLITE_COUNTRY_CODES_EMPTY));
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(1)).containsKey(any());
+        assertTrue(mQueriedSatelliteAllowed);
+
+        // disallow case that network country codes [US, JP] with [US, CA, UK] configuration
+        // location will be compared and mQueriedSatelliteAllowed will be set true
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso()).thenReturn(
+                List.of(TEST_SATELLITE_COUNTRY_CODE_US, TEST_SATELLITE_COUNTRY_CODE_JP));
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(1)).containsKey(any());
+        assertTrue(mQueriedSatelliteAllowed);
+
+        // disallow case that network country codes [JP] with [US, CA, UK] configuration
+        // location will be compared and mQueriedSatelliteAllowed will be set true
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso())
+                .thenReturn(List.of(TEST_SATELLITE_COUNTRY_CODE_JP));
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(1)).containsKey(any());
+        assertTrue(mQueriedSatelliteAllowed);
+
+        // disallow case that network country codes [US] with [US, CA, UK] configuration
+        // location will not be compared and mQueriedSatelliteAllowed will be set false
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso())
+                .thenReturn(List.of(TEST_SATELLITE_COUNTRY_CODE_US));
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockCachedAccessRestrictionMap, times(0)).containsKey(any());
+        assertFalse(mQueriedSatelliteAllowed);
+    }
+
     @Test
     public void testRequestIsSatelliteCommunicationAllowedForCurrentLocation() throws Exception {
         // OEM-enabled satellite is not supported
         when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(false);
         mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
-                SUB_ID, mSatelliteAllowedReceiver);
+                mSatelliteAllowedReceiver, false);
         mTestableLooper.processAllMessages();
         assertTrue(waitForRequestIsSatelliteAllowedForCurrentLocationResult(
                 mSatelliteAllowedSemaphore, 1));
@@ -316,18 +649,18 @@ public class SatelliteAccessControllerTest {
         setUpResponseForRequestIsSatelliteSupported(false, SATELLITE_RESULT_SUCCESS);
         clearAllInvocations();
         mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
-                SUB_ID, mSatelliteAllowedReceiver);
+                mSatelliteAllowedReceiver, false);
         mTestableLooper.processAllMessages();
         assertTrue(waitForRequestIsSatelliteAllowedForCurrentLocationResult(
                 mSatelliteAllowedSemaphore, 1));
-        assertEquals(SATELLITE_RESULT_SUCCESS, mQueriedSatelliteAllowedResultCode);
+        assertEquals(SATELLITE_RESULT_NOT_SUPPORTED, mQueriedSatelliteAllowedResultCode);
         assertFalse(mQueriedSatelliteAllowed);
 
         // Failed to query whether satellite is supported or not
         setUpResponseForRequestIsSatelliteSupported(false, SATELLITE_RESULT_MODEM_ERROR);
         clearAllInvocations();
         mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
-                SUB_ID, mSatelliteAllowedReceiver);
+                mSatelliteAllowedReceiver, false);
         mTestableLooper.processAllMessages();
         assertTrue(waitForRequestIsSatelliteAllowedForCurrentLocationResult(
                 mSatelliteAllowedSemaphore, 1));
@@ -344,7 +677,7 @@ public class SatelliteAccessControllerTest {
         when(mMockLocation0.getElapsedRealtimeNanos()).thenReturn(2L);
         when(mMockLocation1.getElapsedRealtimeNanos()).thenReturn(0L);
         mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
-                SUB_ID, mSatelliteAllowedReceiver);
+                mSatelliteAllowedReceiver, false);
         mTestableLooper.processAllMessages();
         assertTrue(
                 mSatelliteAccessControllerUT.isKeepOnDeviceAccessControllerResourcesTimerStarted());
@@ -376,15 +709,17 @@ public class SatelliteAccessControllerTest {
         when(mMockCountryDetector.getCurrentNetworkCountryIso()).thenReturn(EMPTY_STRING_LIST);
         when(mMockTelecomManager.isInEmergencyCall()).thenReturn(false);
         when(mMockPhone.isInEcm()).thenReturn(true);
+        when(mMockPhone.getContext()).thenReturn(mMockContext);
+        when(mMockPhone2.getContext()).thenReturn(mMockContext);
         mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS + 1;
         when(mMockLocation0.getElapsedRealtimeNanos()).thenReturn(0L);
         when(mMockLocation1.getElapsedRealtimeNanos()).thenReturn(0L);
         mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
-                SUB_ID, mSatelliteAllowedReceiver);
+                mSatelliteAllowedReceiver, false);
         mTestableLooper.processAllMessages();
         assertFalse(
                 mSatelliteAccessControllerUT.isKeepOnDeviceAccessControllerResourcesTimerStarted());
-        verify(mMockLocationManager).getCurrentLocation(eq(LocationManager.GPS_PROVIDER),
+        verify(mMockLocationManager).getCurrentLocation(eq(LocationManager.FUSED_PROVIDER),
                 any(LocationRequest.class), mLocationRequestCancellationSignalCaptor.capture(),
                 any(Executor.class), mLocationRequestConsumerCaptor.capture());
         assertTrue(mSatelliteAccessControllerUT.isWaitForCurrentLocationTimerStarted());
@@ -411,7 +746,7 @@ public class SatelliteAccessControllerTest {
         when(mMockCountryDetector.getCachedLocationCountryIsoInfo()).thenReturn(new Pair<>("", 0L));
         when(mMockCountryDetector.getCachedNetworkCountryIsoInfo()).thenReturn(new HashMap<>());
         mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
-                SUB_ID, mSatelliteAllowedReceiver);
+                mSatelliteAllowedReceiver, false);
         mTestableLooper.processAllMessages();
         assertFalse(
                 mSatelliteAccessControllerUT.isKeepOnDeviceAccessControllerResourcesTimerStarted());
@@ -442,8 +777,9 @@ public class SatelliteAccessControllerTest {
         mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS + 1;
         when(mMockLocation0.getElapsedRealtimeNanos()).thenReturn(0L);
         when(mMockLocation1.getElapsedRealtimeNanos()).thenReturn(0L);
+        doReturn(false).when(mMockLocationManager).isLocationEnabled();
         mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
-                SUB_ID, mSatelliteAllowedReceiver);
+                mSatelliteAllowedReceiver, false);
         mTestableLooper.processAllMessages();
         verify(mMockLocationManager, never()).getCurrentLocation(anyString(),
                 any(LocationRequest.class), any(CancellationSignal.class), any(Executor.class),
@@ -452,10 +788,141 @@ public class SatelliteAccessControllerTest {
                 any(SatelliteOnDeviceAccessController.LocationToken.class));
         assertTrue(waitForRequestIsSatelliteAllowedForCurrentLocationResult(
                 mSatelliteAllowedSemaphore, 1));
-        assertEquals(SATELLITE_RESULT_SUCCESS, mQueriedSatelliteAllowedResultCode);
+        assertEquals(SATELLITE_RESULT_LOCATION_DISABLED, mQueriedSatelliteAllowedResultCode);
         assertFalse(mQueriedSatelliteAllowed);
     }
 
+    @Test
+    public void testAllowLocationQueryForSatelliteAllowedCheck() {
+        mSatelliteAccessControllerUT.mLatestSatelliteCommunicationAllowedSetTime = 1;
+
+        mSatelliteAccessControllerUT.setIsSatelliteAllowedRegionPossiblyChanged(false);
+        // cash is invalid
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos =
+                ALLOWED_STATE_CACHE_VALID_DURATION_NANOS + 10;
+        assertTrue(mSatelliteAccessControllerUT.allowLocationQueryForSatelliteAllowedCheck());
+
+        // cash is valid
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos =
+                ALLOWED_STATE_CACHE_VALID_DURATION_NANOS - 10;
+        assertFalse(mSatelliteAccessControllerUT.allowLocationQueryForSatelliteAllowedCheck());
+
+        mSatelliteAccessControllerUT.setIsSatelliteAllowedRegionPossiblyChanged(true);
+        // cash is invalid
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos =
+                ALLOWED_STATE_CACHE_VALID_DURATION_NANOS + 10;
+        assertTrue(mSatelliteAccessControllerUT.allowLocationQueryForSatelliteAllowedCheck());
+
+        // cash is valid and throttled
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos =
+                ALLOWED_STATE_CACHE_VALID_DURATION_NANOS - 10;
+
+        // cash is valid and never queried before
+        mSatelliteAccessControllerUT.mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos =
+                0;
+        assertTrue(mSatelliteAccessControllerUT.allowLocationQueryForSatelliteAllowedCheck());
+
+        // cash is valid and throttled
+        mSatelliteAccessControllerUT.mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos =
+                mSatelliteAccessControllerUT.elapsedRealtimeNanos
+                        - TEST_LOCATION_QUERY_THROTTLE_INTERVAL_NANOS + 100;
+        assertFalse(mSatelliteAccessControllerUT.allowLocationQueryForSatelliteAllowedCheck());
+
+        // cash is valid and not throttled
+        mSatelliteAccessControllerUT.mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos =
+                mSatelliteAccessControllerUT.elapsedRealtimeNanos
+                        - TEST_LOCATION_QUERY_THROTTLE_INTERVAL_NANOS - 100;
+        assertTrue(mSatelliteAccessControllerUT.allowLocationQueryForSatelliteAllowedCheck());
+    }
+
+    @Test
+    public void testValidatePossibleChangeInSatelliteAllowedRegion() throws Exception {
+        // OEM-enabled satellite is supported
+        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
+
+        verify(mMockCountryDetector).registerForCountryCodeChanged(
+                mCountryDetectorHandlerCaptor.capture(), mCountryDetectorIntCaptor.capture(),
+                mCountryDetectorObjCaptor.capture());
+
+        assertSame(mCountryDetectorHandlerCaptor.getValue(), mSatelliteAccessControllerUT);
+        assertSame(mCountryDetectorIntCaptor.getValue(), EVENT_COUNTRY_CODE_CHANGED);
+        assertNull(mCountryDetectorObjCaptor.getValue());
+
+        // Normal case that invokes
+        // mMockSatelliteOnDeviceAccessController.isSatCommunicationAllowedAtLocation
+        clearInvocations(mMockSatelliteOnDeviceAccessController);
+        setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
+        setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
+        doReturn(true).when(mMockLocationManager).isLocationEnabled();
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS;
+        sendCommandValidateCountryCodeChangeEvent(mMockContext);
+        verify(mMockSatelliteOnDeviceAccessController,
+                times(1)).isSatCommunicationAllowedAtLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class));
+
+        // Case that isCommunicationAllowedCacheValid is true
+        clearInvocations(mMockSatelliteOnDeviceAccessController);
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS + 1;
+        sendCommandValidateCountryCodeChangeEvent(mMockContext);
+        verify(mMockSatelliteOnDeviceAccessController, never()).isSatCommunicationAllowedAtLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class));
+
+        // Case that mLatestCacheEnforcedValidateTimeNanos is over
+        // ALLOWED_STATE_CACHE_VALIDATE_INTERVAL_NANOS (1hours)
+        clearInvocations(mMockSatelliteOnDeviceAccessController);
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos =
+                mSatelliteAccessControllerUT.elapsedRealtimeNanos
+                        + TEST_LOCATION_QUERY_THROTTLE_INTERVAL_NANOS + 1;
+        when(mMockLocation0.getElapsedRealtimeNanos())
+                .thenReturn(mSatelliteAccessControllerUT.elapsedRealtimeNanos + 1L);
+        when(mMockLocation1.getElapsedRealtimeNanos())
+                .thenReturn(mSatelliteAccessControllerUT.elapsedRealtimeNanos + 1L);
+        when(mMockLocation0.getLatitude()).thenReturn(2.0);
+        when(mMockLocation0.getLongitude()).thenReturn(2.0);
+        when(mMockLocation1.getLatitude()).thenReturn(3.0);
+        when(mMockLocation1.getLongitude()).thenReturn(3.0);
+        when(mMockSatelliteOnDeviceAccessController.isSatCommunicationAllowedAtLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class))).thenReturn(false);
+        sendCommandValidateCountryCodeChangeEvent(mMockContext);
+        verify(mMockSatelliteOnDeviceAccessController,
+                times(1)).isSatCommunicationAllowedAtLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class));
+    }
+
+    @Test
+    public void testRetryValidatePossibleChangeInSatelliteAllowedRegion() throws Exception {
+        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
+
+        verify(mMockCountryDetector).registerForCountryCodeChanged(
+                mCountryDetectorHandlerCaptor.capture(), mCountryDetectorIntCaptor.capture(),
+                mCountryDetectorObjCaptor.capture());
+
+        assertSame(mCountryDetectorHandlerCaptor.getValue(), mSatelliteAccessControllerUT);
+        assertSame(mCountryDetectorIntCaptor.getValue(), EVENT_COUNTRY_CODE_CHANGED);
+        assertNull(mCountryDetectorObjCaptor.getValue());
+
+        assertTrue(mSatelliteAccessControllerUT
+                .getRetryCountPossibleChangeInSatelliteAllowedRegion() == 0);
+
+        setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_LOCATION_NOT_AVAILABLE);
+        sendCommandValidateCountryCodeChangeEvent(mMockContext);
+
+        assertTrue(mSatelliteAccessControllerUT
+                .getRetryCountPossibleChangeInSatelliteAllowedRegion() == 1);
+
+        mSatelliteAccessControllerUT.setRetryCountPossibleChangeInSatelliteAllowedRegion(
+                DEFAULT_MAX_RETRY_COUNT_FOR_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION);
+        sendSatelliteCommunicationAllowedEvent();
+        assertTrue(mSatelliteAccessControllerUT
+                .getRetryCountPossibleChangeInSatelliteAllowedRegion() == 0);
+
+        mSatelliteAccessControllerUT.setRetryCountPossibleChangeInSatelliteAllowedRegion(2);
+        setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
+        sendSatelliteCommunicationAllowedEvent();
+        assertTrue(mSatelliteAccessControllerUT
+                .getRetryCountPossibleChangeInSatelliteAllowedRegion() == 0);
+    }
+
     @Test
     public void testUpdateSatelliteConfigData() throws Exception {
         verify(mMockSatelliteController).registerForConfigUpdateChanged(
@@ -528,6 +995,221 @@ public class SatelliteAccessControllerTest {
         verify(mMockCachedAccessRestrictionMap, times(1)).clear();
     }
 
+    @Test
+    public void testLocationModeChanged() throws Exception {
+        // setup for querying GPS not to reset mIsSatelliteAllowedRegionPossiblyChanged false.
+        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
+        when(mMockContext.getResources()).thenReturn(mMockResources);
+        when(mMockResources.getBoolean(
+                com.android.internal.R.bool.config_oem_enabled_satellite_access_allow))
+                .thenReturn(TEST_SATELLITE_ALLOW);
+        setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
+        setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
+        when(mMockSatelliteOnDeviceAccessController.isSatCommunicationAllowedAtLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class))).thenReturn(true);
+        replaceInstance(SatelliteAccessController.class, "mCachedAccessRestrictionMap",
+                mSatelliteAccessControllerUT, mMockCachedAccessRestrictionMap);
+        doReturn(false).when(mMockCachedAccessRestrictionMap).containsKey(any());
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS + 1;
+
+        // Captor and Verify if the mockReceiver and mocContext is registered well
+        verify(mMockContext).registerReceiver(mLocationBroadcastReceiverCaptor.capture(),
+                mIntentFilterCaptor.capture());
+        assertSame(mSatelliteAccessControllerUT.getLocationBroadcastReceiver(),
+                mLocationBroadcastReceiverCaptor.getValue());
+        assertSame(MODE_CHANGED_ACTION, mIntentFilterCaptor.getValue().getAction(0));
+
+        // When the intent action is not MODE_CHANGED_ACTION,
+        // verify if the location manager never invoke isLocationEnabled()
+        doReturn("").when(mMockLocationIntent).getAction();
+        mSatelliteAccessControllerUT.setIsSatelliteAllowedRegionPossiblyChanged(false);
+        mSatelliteAccessControllerUT.getLocationBroadcastReceiver()
+                .onReceive(mMockContext, mMockLocationIntent);
+        verify(mMockLocationManager, never()).isLocationEnabled();
+
+        // When the intent action is MODE_CHANGED_ACTION and isLocationEnabled() is true,
+        // verify if mIsSatelliteAllowedRegionPossiblyChanged is true
+        doReturn(MODE_CHANGED_ACTION).when(mMockLocationIntent).getAction();
+        doReturn(true).when(mMockLocationManager).isLocationEnabled();
+        clearInvocations(mMockLocationManager);
+        mSatelliteAccessControllerUT.setIsSatelliteAllowedRegionPossiblyChanged(false);
+        mSatelliteAccessControllerUT.getLocationBroadcastReceiver()
+                .onReceive(mMockContext, mMockLocationIntent);
+        verify(mMockLocationManager, times(1)).isLocationEnabled();
+        mTestableLooper.processAllMessages();
+        assertEquals(true, mSatelliteAccessControllerUT.isSatelliteAllowedRegionPossiblyChanged());
+
+        // When the intent action is MODE_CHANGED_ACTION and isLocationEnabled() is false,
+        // verify if mIsSatelliteAllowedRegionPossiblyChanged is false
+        doReturn(false).when(mMockLocationManager).isLocationEnabled();
+        clearInvocations(mMockLocationManager);
+        mSatelliteAccessControllerUT.setIsSatelliteAllowedRegionPossiblyChanged(false);
+        mSatelliteAccessControllerUT.getLocationBroadcastReceiver()
+                .onReceive(mMockContext, mMockLocationIntent);
+        verify(mMockLocationManager, times(1)).isLocationEnabled();
+        mTestableLooper.processAllMessages();
+        assertEquals(false, mSatelliteAccessControllerUT.isSatelliteAllowedRegionPossiblyChanged());
+    }
+
+    @Test
+    public void testCheckSatelliteAccessRestrictionUsingGPS() {
+        // In emergency case,
+        // verify if the location manager get FUSED provider and ignore location settings
+        doReturn(true).when(mMockTelecomManager).isInEmergencyCall();
+        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull();
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS + 1;
+        mSatelliteAccessControllerUT.checkSatelliteAccessRestrictionUsingGPS();
+
+        verify(mMockLocationManager, times(1))
+                .getCurrentLocation(mLocationProviderStringCaptor.capture(),
+                        mLocationRequestCaptor.capture(), any(), any(), any());
+        assertEquals(LocationManager.FUSED_PROVIDER, mLocationProviderStringCaptor.getValue());
+        assertTrue(mLocationRequestCaptor.getValue().isLocationSettingsIgnored());
+
+        // In non-emergency case,
+        // verify if the location manager get FUSED provider and not ignore location settings
+        clearInvocations(mMockLocationManager);
+        doReturn(false).when(mMockTelecomManager).isInEmergencyCall();
+        doReturn(false).when(mMockPhone).isInEcm();
+        doReturn(false).when(mMockPhone2).isInEcm();
+        doReturn(false).when(mMockSatelliteController).isInEmergencyMode();
+        doReturn(true).when(mMockLocationManager).isLocationEnabled();
+        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull();
+        mSatelliteAccessControllerUT.checkSatelliteAccessRestrictionUsingGPS();
+
+        verify(mMockLocationManager, times(1))
+                .getCurrentLocation(mLocationProviderStringCaptor.capture(),
+                        mLocationRequestCaptor.capture(), any(), any(), any());
+        assertEquals(LocationManager.FUSED_PROVIDER, mLocationProviderStringCaptor.getValue());
+        assertFalse(mLocationRequestCaptor.getValue().isLocationSettingsIgnored());
+    }
+
+    @Test
+    public void testHandleIsSatelliteSupportedResult() throws Exception {
+        // Setup for this test case
+        Iterator<ResultReceiver> mockIterator = mock(Iterator.class);
+        doReturn(mockIterator).when(mMockSatelliteAllowResultReceivers).iterator();
+        doReturn(true, false).when(mockIterator).hasNext();
+        doReturn(mMockSatelliteSupportedResultReceiver).when(mockIterator).next();
+
+        replaceInstance(SatelliteAccessController.class, "mSatelliteAllowResultReceivers",
+                mSatelliteAccessControllerUT, mMockSatelliteAllowResultReceivers);
+        doNothing().when(mMockSatelliteAllowResultReceivers).clear();
+
+        // case that resultCode is not SATELLITE_RESULT_SUCCESS
+        int resultCode = SATELLITE_RESULT_ERROR;
+        Bundle bundle = new Bundle();
+        doReturn(true, false).when(mockIterator).hasNext();
+        clearInvocations(mMockSatelliteSupportedResultReceiver);
+        mSatelliteAccessControllerUT.handleIsSatelliteSupportedResult(resultCode, bundle);
+        verify(mMockSatelliteSupportedResultReceiver)
+                .send(mResultCodeIntCaptor.capture(), any());
+        assertEquals(Integer.valueOf(SATELLITE_RESULT_ERROR), mResultCodeIntCaptor.getValue());
+
+        // case no KEY_SATELLITE_SUPPORTED in the bundle data.
+        // verify that the resultCode is delivered as it were
+        resultCode = SATELLITE_RESULT_SUCCESS;
+        bundle.putBoolean(KEY_SATELLITE_PROVISIONED, false);
+        doReturn(true, false).when(mockIterator).hasNext();
+        clearInvocations(mMockSatelliteSupportedResultReceiver);
+        mSatelliteAccessControllerUT.handleIsSatelliteSupportedResult(resultCode, bundle);
+        verify(mMockSatelliteSupportedResultReceiver)
+                .send(mResultCodeIntCaptor.capture(), any());
+        assertEquals(Integer.valueOf(SATELLITE_RESULT_SUCCESS), mResultCodeIntCaptor.getValue());
+
+        // case KEY_SATELLITE_SUPPORTED is false
+        // verify SATELLITE_RESULT_NOT_SUPPORTED is captured
+        bundle.putBoolean(KEY_SATELLITE_SUPPORTED, false);
+        doReturn(true, false).when(mockIterator).hasNext();
+        clearInvocations(mMockSatelliteSupportedResultReceiver);
+        mSatelliteAccessControllerUT.handleIsSatelliteSupportedResult(resultCode, bundle);
+        verify(mMockSatelliteSupportedResultReceiver)
+                .send(mResultCodeIntCaptor.capture(), mResultDataBundleCaptor.capture());
+        assertEquals(Integer.valueOf(SATELLITE_RESULT_NOT_SUPPORTED),
+                mResultCodeIntCaptor.getValue());
+        assertEquals(false,
+                mResultDataBundleCaptor.getValue().getBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED));
+
+        // case KEY_SATELLITE_SUPPORTED is success and region is not allowed
+        // verify SATELLITE_RESULT_SUCCESS is captured
+        bundle.putBoolean(KEY_SATELLITE_SUPPORTED, true);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso())
+                .thenReturn(List.of(TEST_SATELLITE_COUNTRY_CODE_KR));
+        doReturn(true, false).when(mockIterator).hasNext();
+        clearInvocations(mMockSatelliteSupportedResultReceiver);
+        mSatelliteAccessControllerUT.handleIsSatelliteSupportedResult(resultCode, bundle);
+        verify(mMockSatelliteSupportedResultReceiver)
+                .send(mResultCodeIntCaptor.capture(), mResultDataBundleCaptor.capture());
+        assertEquals(Integer.valueOf(SATELLITE_RESULT_SUCCESS),
+                mResultCodeIntCaptor.getValue());
+        assertEquals(false,
+                mResultDataBundleCaptor.getValue().getBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED));
+
+        // case KEY_SATELLITE_SUPPORTED is success and locationManager is disabled
+        // verify SATELLITE_RESULT_LOCATION_DISABLED is captured
+        when(mMockCountryDetector.getCurrentNetworkCountryIso())
+                .thenReturn(List.of(TEST_SATELLITE_COUNTRY_CODE_US));
+        doReturn(false).when(mMockLocationManager).isLocationEnabled();
+        doReturn(true, false).when(mockIterator).hasNext();
+        clearInvocations(mMockSatelliteSupportedResultReceiver);
+        mSatelliteAccessControllerUT.handleIsSatelliteSupportedResult(resultCode, bundle);
+        verify(mMockSatelliteSupportedResultReceiver)
+                .send(mResultCodeIntCaptor.capture(), mResultDataBundleCaptor.capture());
+        assertEquals(Integer.valueOf(SATELLITE_RESULT_LOCATION_DISABLED),
+                mResultCodeIntCaptor.getValue());
+        assertEquals(false,
+                mResultDataBundleCaptor.getValue().getBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED));
+    }
+
+    @Test
+    public void testRequestIsCommunicationAllowedForCurrentLocationWithEnablingSatellite() {
+        // Set non-emergency case
+        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
+        setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
+        setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso()).thenReturn(EMPTY_STRING_LIST);
+        doReturn(false).when(mMockTelecomManager).isInEmergencyCall();
+        doReturn(false).when(mMockPhone).isInEcm();
+        doReturn(false).when(mMockPhone2).isInEcm();
+        doReturn(false).when(mMockSatelliteController).isInEmergencyMode();
+        doReturn(true).when(mMockLocationManager).isLocationEnabled();
+        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull();
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS + 1;
+
+        // Invoking requestIsCommunicationAllowedForCurrentLocation(resultReceiver, "false");
+        // verify that mLocationManager.isLocationEnabled() is invoked
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, false);
+        mTestableLooper.processAllMessages();
+        verify(mMockLocationManager, times(1)).isLocationEnabled();
+        verify(mMockLocationManager, times(1)).getCurrentLocation(anyString(),
+                any(LocationRequest.class), any(CancellationSignal.class), any(Executor.class),
+                any(Consumer.class));
+
+        // Invoking requestIsCommunicationAllowedForCurrentLocation(resultReceiver, "true");
+        // verify that mLocationManager.isLocationEnabled() is not invoked
+        clearInvocations(mMockLocationManager);
+        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
+                mSatelliteAllowedReceiver, true);
+        mTestableLooper.processAllMessages();
+        verify(mMockLocationManager, times(1)).isLocationEnabled();
+        verify(mMockLocationManager, never()).getCurrentLocation(anyString(),
+                any(LocationRequest.class), any(CancellationSignal.class), any(Executor.class),
+                any(Consumer.class));
+    }
+
+    private void sendSatelliteCommunicationAllowedEvent() {
+        Pair<Integer, ResultReceiver> requestPair =
+                new Pair<>(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID,
+                        mSatelliteAccessControllerUT.getResultReceiverCurrentLocation());
+        Message msg = mSatelliteAccessControllerUT.obtainMessage(
+                CMD_IS_SATELLITE_COMMUNICATION_ALLOWED);
+        msg.obj = requestPair;
+        msg.sendToTarget();
+        mTestableLooper.processAllMessages();
+    }
+
+
     private void sendConfigUpdateChangedEvent(Context context) {
         Message msg = mSatelliteAccessControllerUT.obtainMessage(EVENT_CONFIG_DATA_UPDATED);
         msg.obj = new AsyncResult(context, SATELLITE_RESULT_SUCCESS, null);
@@ -535,6 +1217,13 @@ public class SatelliteAccessControllerTest {
         mTestableLooper.processAllMessages();
     }
 
+    private void sendCommandValidateCountryCodeChangeEvent(Context context) {
+        Message msg = mSatelliteAccessControllerUT.obtainMessage(EVENT_COUNTRY_CODE_CHANGED);
+        msg.obj = new AsyncResult(context, SATELLITE_RESULT_SUCCESS, null);
+        msg.sendToTarget();
+        mTestableLooper.processAllMessages();
+    }
+
     private void clearAllInvocations() {
         clearInvocations(mMockSatelliteController);
         clearInvocations(mMockSatelliteOnDeviceAccessController);
@@ -574,7 +1263,7 @@ public class SatelliteAccessControllerTest {
     private void setUpResponseForRequestIsSatelliteSupported(
             boolean isSatelliteSupported, @SatelliteManager.SatelliteResult int error) {
         doAnswer(invocation -> {
-            ResultReceiver resultReceiver = invocation.getArgument(1);
+            ResultReceiver resultReceiver = invocation.getArgument(0);
             if (error == SATELLITE_RESULT_SUCCESS) {
                 Bundle bundle = new Bundle();
                 bundle.putBoolean(SatelliteManager.KEY_SATELLITE_SUPPORTED, isSatelliteSupported);
@@ -583,25 +1272,23 @@ public class SatelliteAccessControllerTest {
                 resultReceiver.send(error, Bundle.EMPTY);
             }
             return null;
-        }).when(mMockSatelliteController).requestIsSatelliteSupported(anyInt(),
-                any(ResultReceiver.class));
+        }).when(mMockSatelliteController).requestIsSatelliteSupported(any(ResultReceiver.class));
     }
 
     private void setUpResponseForRequestIsSatelliteProvisioned(
             boolean isSatelliteProvisioned, @SatelliteManager.SatelliteResult int error) {
         doAnswer(invocation -> {
-            ResultReceiver resultReceiver = invocation.getArgument(1);
+            ResultReceiver resultReceiver = invocation.getArgument(0);
             if (error == SATELLITE_RESULT_SUCCESS) {
                 Bundle bundle = new Bundle();
-                bundle.putBoolean(SatelliteManager.KEY_SATELLITE_PROVISIONED,
+                bundle.putBoolean(KEY_SATELLITE_PROVISIONED,
                         isSatelliteProvisioned);
                 resultReceiver.send(error, bundle);
             } else {
                 resultReceiver.send(error, Bundle.EMPTY);
             }
             return null;
-        }).when(mMockSatelliteController).requestIsSatelliteProvisioned(anyInt(),
-                any(ResultReceiver.class));
+        }).when(mMockSatelliteController).requestIsSatelliteProvisioned(any(ResultReceiver.class));
     }
 
     @SafeVarargs
@@ -678,5 +1365,27 @@ public class SatelliteAccessControllerTest {
         public boolean isWaitForCurrentLocationTimerStarted() {
             return hasMessages(EVENT_WAIT_FOR_CURRENT_LOCATION_TIMEOUT);
         }
+
+        public int getRetryCountPossibleChangeInSatelliteAllowedRegion() {
+            return mRetryCountForValidatingPossibleChangeInAllowedRegion;
+        }
+
+        public void setRetryCountPossibleChangeInSatelliteAllowedRegion(int retryCount) {
+            mRetryCountForValidatingPossibleChangeInAllowedRegion = retryCount;
+        }
+
+        public ResultReceiver getResultReceiverCurrentLocation() {
+            return mHandlerForSatelliteAllowedResult;
+        }
+
+        public BroadcastReceiver getLocationBroadcastReceiver() {
+            return mLocationModeChangedBroadcastReceiver;
+        }
+
+        public void setLocationRequestCancellationSignalAsNull() {
+            synchronized (mLock) {
+                mLocationRequestCancellationSignal = null;
+            }
+        }
     }
 }
diff --git a/tests/src/com/android/phone/tests/CallDialTest.java b/tests/src/com/android/phone/tests/CallDialTest.java
index 6e78be095..cafa7f24d 100644
--- a/tests/src/com/android/phone/tests/CallDialTest.java
+++ b/tests/src/com/android/phone/tests/CallDialTest.java
@@ -22,6 +22,7 @@ import android.content.Intent;
 import android.net.Uri;
 import android.os.Bundle;
 import android.os.RemoteException;
+import android.os.UserHandle;
 import android.telecom.PhoneAccount;
 import android.telephony.PhoneNumberUtils;
 import android.telephony.TelephonyFrameworkInitializer;
@@ -136,13 +137,13 @@ public class CallDialTest extends Activity implements View.OnClickListener {
         log("==> intent: " + intent);
 
         try {
-            startActivity(intent);
+            startActivityAsUser(intent, UserHandle.CURRENT);
             Toast.makeText(this, "Starting activity...", Toast.LENGTH_SHORT).show();
         } catch (ActivityNotFoundException e) {
             Log.w(LOG_TAG, "testCall: ActivityNotFoundException for intent: " + intent);
             Toast.makeText(this, e.toString(), Toast.LENGTH_LONG).show();
         } catch (Exception e) {
-            Log.w(LOG_TAG, "testCall: Unexpected exception from startActivity(): " + e);
+            Log.w(LOG_TAG, "testCall: Unexpected exception from startActivityAsUser(): " + e);
             Toast.makeText(this, e.toString(), Toast.LENGTH_LONG).show();
         }
     }
diff --git a/tests/src/com/android/services/telephony/TelecomAccountRegistryTest.java b/tests/src/com/android/services/telephony/TelecomAccountRegistryTest.java
new file mode 100644
index 000000000..fc544b0e7
--- /dev/null
+++ b/tests/src/com/android/services/telephony/TelecomAccountRegistryTest.java
@@ -0,0 +1,314 @@
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
+package com.android.services.telephony;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.Mockito.atLeastOnce;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.content.BroadcastReceiver;
+import android.content.ContentProvider;
+import android.content.ContentResolver;
+import android.content.Context;
+import android.content.Intent;
+import android.content.res.Resources;
+import android.graphics.drawable.Drawable;
+import android.os.PersistableBundle;
+import android.os.UserHandle;
+import android.platform.test.flag.junit.SetFlagsRule;
+import android.telecom.PhoneAccount;
+import android.telecom.TelecomManager;
+import android.telephony.CarrierConfigManager;
+import android.telephony.ServiceState;
+import android.telephony.SubscriptionManager;
+import android.telephony.SubscriptionManager.OnSubscriptionsChangedListener;
+import android.telephony.TelephonyCallback;
+import android.telephony.TelephonyManager;
+import android.telephony.ims.ImsManager;
+import android.testing.AndroidTestingRunner;
+import android.testing.TestableLooper;
+
+import com.android.TelephonyTestBase;
+import com.android.internal.telephony.Phone;
+import com.android.internal.telephony.PhoneConstants;
+import com.android.internal.telephony.PhoneFactory;
+import com.android.internal.telephony.flags.Flags;
+import com.android.phone.PhoneGlobals;
+import com.android.phone.PhoneInterfaceManager;
+import com.android.phone.R;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+@RunWith(AndroidTestingRunner.class)
+@TestableLooper.RunWithLooper(setAsMainLooper = true)
+public class TelecomAccountRegistryTest extends TelephonyTestBase {
+
+    private static final String TAG = "TelecomAccountRegistryTest";
+    private static final int TEST_SUB_ID = 1;
+
+    @Rule
+    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
+
+    // We need more functions that what TelephonyTestBase.mContext supports.
+    // Use a local mocked Context to make life easier.
+    @Mock Context mMockedContext;
+    @Mock TelecomManager mTelecomManager;
+    @Mock TelephonyManager mTelephonyManager;
+    @Mock ImsManager mImsManager;
+    @Mock SubscriptionManager mSubscriptionManager;
+    @Mock ContentProvider mContentProvider;
+    @Mock PhoneGlobals mPhoneGlobals;
+    @Mock Phone mPhone;
+    @Mock Resources mResources;
+    @Mock Drawable mDrawable;
+    @Mock PhoneInterfaceManager mPhoneInterfaceManager;
+
+    private TelecomAccountRegistry mTelecomAccountRegistry;
+
+    private OnSubscriptionsChangedListener mOnSubscriptionsChangedListener;
+    private TelephonyCallback mTelephonyCallback;
+    private BroadcastReceiver mUserSwitchedAndConfigChangedReceiver;
+    private BroadcastReceiver mLocaleChangedBroadcastReceiver;
+    private ContentResolver mContentResolver;
+    private Phone[] mPhones;
+    private TestableLooper mTestableLooper;
+
+    @Before
+    public void setUp() throws Exception {
+        super.setUp();
+        mSetFlagsRule.disableFlags(Flags.FLAG_DELAY_PHONE_ACCOUNT_REGISTRATION);
+        MockitoAnnotations.initMocks(this);
+
+        mPhones = new Phone[]{mPhone};
+        replaceInstance(PhoneFactory.class, "sPhones", null, mPhones);
+        replaceInstance(PhoneGlobals.class, "sMe", null, mPhoneGlobals);
+        replaceInstance(PhoneInterfaceManager.class, "sInstance", null, mPhoneInterfaceManager);
+        when(mPhone.getPhoneType()).thenReturn(PhoneConstants.PHONE_TYPE_GSM);
+        when(mPhone.getContext()).thenReturn(mMockedContext);
+        when(mPhone.getSubId()).thenReturn(TEST_SUB_ID);
+        when(mPhoneInterfaceManager.isRttEnabled(anyInt())).thenReturn(false);
+
+        when(mMockedContext.getResources()).thenReturn(mResources);
+        // Enable PSTN PhoneAccount which can place emergency call by default
+        when(mResources.getBoolean(R.bool.config_pstn_phone_accounts_enabled)).thenReturn(true);
+        when(mResources.getBoolean(R.bool.config_pstnCanPlaceEmergencyCalls)).thenReturn(true);
+        when(mResources.getDrawable(anyInt(), any())).thenReturn(mDrawable);
+        when(mDrawable.getIntrinsicWidth()).thenReturn(5);
+        when(mDrawable.getIntrinsicHeight()).thenReturn(5);
+
+        PersistableBundle bundle = new PersistableBundle();
+        bundle.putBoolean(CarrierConfigManager.KEY_SUPPORT_IMS_CONFERENCE_CALL_BOOL, false);
+        bundle.putIntArray(CarrierConfigManager.KEY_CELLULAR_SERVICE_CAPABILITIES_INT_ARRAY,
+                new int[]{
+                        SubscriptionManager.SERVICE_CAPABILITY_VOICE,
+                        SubscriptionManager.SERVICE_CAPABILITY_SMS,
+                        SubscriptionManager.SERVICE_CAPABILITY_DATA
+                });
+        when(mPhoneGlobals.getCarrierConfigForSubId(anyInt())).thenReturn(bundle);
+
+        // Mock system services used by TelecomAccountRegistry
+        when(mMockedContext.getSystemServiceName(TelecomManager.class))
+                .thenReturn(Context.TELECOM_SERVICE);
+        when(mMockedContext.getSystemService(TelecomManager.class))
+                .thenReturn(mTelecomManager);
+        when(mMockedContext.getSystemServiceName(TelephonyManager.class))
+                .thenReturn(Context.TELEPHONY_SERVICE);
+        when(mMockedContext.getSystemService(TelephonyManager.class))
+                .thenReturn(mTelephonyManager);
+        when(mMockedContext.getSystemServiceName(ImsManager.class))
+                .thenReturn(Context.TELEPHONY_IMS_SERVICE);
+        when(mMockedContext.getSystemService(ImsManager.class))
+                .thenReturn(mImsManager);
+        when(mMockedContext.getSystemServiceName(SubscriptionManager.class))
+                .thenReturn(Context.TELEPHONY_SUBSCRIPTION_SERVICE);
+        when(mMockedContext.getSystemService(SubscriptionManager.class))
+                .thenReturn(mSubscriptionManager);
+
+        // Use mocked ContentProvider since we can't really mock ContentResolver
+        mContentResolver = ContentResolver.wrap(mContentProvider);
+        when(mMockedContext.getContentResolver()).thenReturn(mContentResolver);
+
+        mTestableLooper = TestableLooper.get(this);
+        when(mMockedContext.getMainLooper()).thenReturn(mTestableLooper.getLooper());
+        mTelecomAccountRegistry = new TelecomAccountRegistry(mMockedContext);
+        mTelecomAccountRegistry.setupOnBoot();
+
+        // Capture OnSubscriptionsChangedListener
+        ArgumentCaptor<OnSubscriptionsChangedListener> subChangeListenerCaptor =
+                ArgumentCaptor.forClass(OnSubscriptionsChangedListener.class);
+        verify(mSubscriptionManager).addOnSubscriptionsChangedListener(
+                subChangeListenerCaptor.capture());
+        mOnSubscriptionsChangedListener = subChangeListenerCaptor.getValue();
+
+        // Capture TelephonyCallback
+        ArgumentCaptor<TelephonyCallback> telephonyCallbackArgumentCaptor =
+                ArgumentCaptor.forClass(TelephonyCallback.class);
+        verify(mTelephonyManager).registerTelephonyCallback(anyInt(), any(),
+                telephonyCallbackArgumentCaptor.capture());
+        mTelephonyCallback = telephonyCallbackArgumentCaptor.getValue();
+
+        // Capture BroadcastReceivers
+        ArgumentCaptor<BroadcastReceiver> broadcastReceiverArgumentCaptor =
+                ArgumentCaptor.forClass(BroadcastReceiver.class);
+        verify(mMockedContext, times(2)).registerReceiver(broadcastReceiverArgumentCaptor.capture(),
+                any());
+        mUserSwitchedAndConfigChangedReceiver =
+                broadcastReceiverArgumentCaptor.getAllValues().get(0);
+        mLocaleChangedBroadcastReceiver = broadcastReceiverArgumentCaptor.getAllValues().get(1);
+
+        mTestableLooper.processAllMessages();
+    }
+
+    @After
+    public void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    @Test
+    public void userSwitched_withPSTNAccount_shouldRegisterPSTNAccount() {
+        onUserSwitched(UserHandle.CURRENT);
+
+        PhoneAccount phoneAccount = verifyAndCaptureRegisteredPhoneAccount();
+
+        assertThat(phoneAccount.hasCapabilities(
+                PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION)).isTrue();
+        assertThat(phoneAccount.hasCapabilities(
+                PhoneAccount.CAPABILITY_CALL_PROVIDER)).isTrue();
+        assertThat(phoneAccount.hasCapabilities(
+                PhoneAccount.CAPABILITY_PLACE_EMERGENCY_CALLS)).isTrue();
+    }
+
+    @Test
+    public void onLocaleChanged_withPSTNAccountDisabled_shouldRegisterEmergencyOnlyAccount() {
+        when(mResources.getBoolean(R.bool.config_pstn_phone_accounts_enabled)).thenReturn(false);
+        when(mResources.getBoolean(
+                R.bool.config_emergency_account_emergency_calls_only)).thenReturn(true);
+        onLocaleChanged();
+
+        PhoneAccount phoneAccount = verifyAndCaptureRegisteredPhoneAccount();
+
+        assertThat(phoneAccount.hasCapabilities(
+                PhoneAccount.CAPABILITY_EMERGENCY_CALLS_ONLY)).isTrue();
+    }
+
+    @Test
+    public void onLocaleChanged_withSubVoiceCapable_shouldNotRegisterEmergencyOnlyAccount() {
+        overrideSubscriptionServiceCapabilities(
+                new int[]{SubscriptionManager.SERVICE_CAPABILITY_VOICE});
+        onLocaleChanged();
+
+        PhoneAccount phoneAccount = verifyAndCaptureRegisteredPhoneAccount();
+
+        assertThat(phoneAccount.hasCapabilities(
+                PhoneAccount.CAPABILITY_EMERGENCY_CALLS_ONLY)).isFalse();
+    }
+
+    @Test
+    public void onLocaleChanged_withSubNotVoiceCapable_shouldRegisterEmergencyOnlyAccount() {
+        overrideSubscriptionServiceCapabilities(
+                new int[]{SubscriptionManager.SERVICE_CAPABILITY_DATA});
+        onLocaleChanged();
+
+        PhoneAccount phoneAccount = verifyAndCaptureRegisteredPhoneAccount();
+
+        assertThat(phoneAccount.hasCapabilities(
+                PhoneAccount.CAPABILITY_EMERGENCY_CALLS_ONLY)).isTrue();
+    }
+
+    private PhoneAccount verifyAndCaptureRegisteredPhoneAccount() {
+        ArgumentCaptor<PhoneAccount> phoneAccountArgumentCaptor =
+                ArgumentCaptor.forClass(PhoneAccount.class);
+        verify(mTelecomManager, atLeastOnce()).registerPhoneAccount(
+                phoneAccountArgumentCaptor.capture());
+        return phoneAccountArgumentCaptor.getValue();
+    }
+
+    private void onUserSwitched(UserHandle userHandle) {
+        Log.d(TAG, "Broadcast ACTION_USER_SWITCHED...");
+        Intent intent = new Intent(Intent.ACTION_USER_SWITCHED);
+        intent.putExtra(Intent.EXTRA_USER, userHandle);
+        mUserSwitchedAndConfigChangedReceiver.onReceive(mMockedContext, intent);
+        mTestableLooper.processAllMessages();
+    }
+
+    private void onCarrierConfigChanged(int subId) {
+        Log.d(TAG, "Broadcast ACTION_CARRIER_CONFIG_CHANGED...");
+        Intent intent = new Intent(CarrierConfigManager.ACTION_CARRIER_CONFIG_CHANGED);
+        intent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, subId);
+        mUserSwitchedAndConfigChangedReceiver.onReceive(mMockedContext, intent);
+        mTestableLooper.processAllMessages();
+    }
+
+    private void onSubscriptionsChanged() {
+        Log.d(TAG, "Change subscriptions...");
+        mOnSubscriptionsChangedListener.onSubscriptionsChanged();
+    }
+
+    private void onAddSubscriptionListenerFailed() {
+        Log.d(TAG, "Add subscription listener failed...");
+        mOnSubscriptionsChangedListener.onAddListenerFailed();
+    }
+
+    private void onServiceStateChanged(ServiceState serviceState) {
+        if (mTelephonyCallback instanceof TelephonyCallback.ServiceStateListener) {
+            TelephonyCallback.ServiceStateListener listener =
+                    (TelephonyCallback.ServiceStateListener) mTelephonyCallback;
+            listener.onServiceStateChanged(serviceState);
+        }
+    }
+
+    private void onActiveDataSubscriptionIdChanged(int subId) {
+        if (mTelephonyCallback instanceof TelephonyCallback.ActiveDataSubscriptionIdListener) {
+            TelephonyCallback.ActiveDataSubscriptionIdListener listener =
+                    (TelephonyCallback.ActiveDataSubscriptionIdListener) mTelephonyCallback;
+            listener.onActiveDataSubscriptionIdChanged(subId);
+        }
+    }
+
+    private void onLocaleChanged() {
+        Log.d(TAG, "Broadcast ACTION_LOCALE_CHANGED...");
+        Intent intent = new Intent(Intent.ACTION_LOCALE_CHANGED);
+        mLocaleChangedBroadcastReceiver.onReceive(mMockedContext, intent);
+    }
+
+    private void onNetworkCountryChanged() {
+        Log.d(TAG, "Broadcast ACTION_NETWORK_COUNTRY_CHANGED...");
+        Intent intent = new Intent(TelephonyManager.ACTION_NETWORK_COUNTRY_CHANGED);
+        mLocaleChangedBroadcastReceiver.onReceive(mMockedContext, intent);
+    }
+
+    private void overrideSubscriptionServiceCapabilities(int[] capabilities) {
+        PersistableBundle bundle = new PersistableBundle();
+        bundle.putIntArray(CarrierConfigManager.KEY_CELLULAR_SERVICE_CAPABILITIES_INT_ARRAY,
+                capabilities);
+
+        when(mPhoneGlobals.getCarrierConfigForSubId(anyInt())).thenReturn(bundle);
+        mTestableLooper.processAllMessages();
+    }
+}
diff --git a/tests/src/com/android/services/telephony/TelephonyConnectionServiceTest.java b/tests/src/com/android/services/telephony/TelephonyConnectionServiceTest.java
index 304cf2a0f..b6b1a36b4 100644
--- a/tests/src/com/android/services/telephony/TelephonyConnectionServiceTest.java
+++ b/tests/src/com/android/services/telephony/TelephonyConnectionServiceTest.java
@@ -106,11 +106,14 @@ import com.android.internal.telephony.emergency.EmergencyNumberTracker;
 import com.android.internal.telephony.emergency.EmergencyStateTracker;
 import com.android.internal.telephony.emergency.RadioOnHelper;
 import com.android.internal.telephony.emergency.RadioOnStateListener;
+import com.android.internal.telephony.flags.FeatureFlags;
 import com.android.internal.telephony.flags.Flags;
 import com.android.internal.telephony.gsm.SuppServiceNotification;
 import com.android.internal.telephony.imsphone.ImsPhone;
 import com.android.internal.telephony.satellite.SatelliteController;
 import com.android.internal.telephony.satellite.SatelliteSOSMessageRecommender;
+import com.android.internal.telephony.subscription.SubscriptionInfoInternal;
+import com.android.internal.telephony.subscription.SubscriptionManagerService;
 
 import org.junit.After;
 import org.junit.Before;
@@ -254,6 +257,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     @Mock private SatelliteSOSMessageRecommender mSatelliteSOSMessageRecommender;
     @Mock private EmergencyStateTracker mEmergencyStateTracker;
     @Mock private Resources mMockResources;
+    @Mock private FeatureFlags mFeatureFlags;
     private Phone mPhone0;
     private Phone mPhone1;
 
@@ -281,6 +285,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         super.setUp();
         doReturn(Looper.getMainLooper()).when(mContext).getMainLooper();
         mTestConnectionService = new TestTelephonyConnectionService(mContext);
+        mTestConnectionService.setFeatureFlags(mFeatureFlags);
         mTestConnectionService.setPhoneFactoryProxy(mPhoneFactoryProxy);
         mTestConnectionService.setSubscriptionManagerProxy(mSubscriptionManagerProxy);
         // Set configurations statically
@@ -309,7 +314,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 mTestConnectionService, mEmergencyStateTracker);
         replaceInstance(TelephonyConnectionService.class, "mSatelliteSOSMessageRecommender",
                 mTestConnectionService, mSatelliteSOSMessageRecommender);
-        doNothing().when(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any());
+        doNothing().when(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any(),
+                anyBoolean());
         doNothing().when(mSatelliteSOSMessageRecommender).onEmergencyCallConnectionStateChanged(
                 anyString(), anyInt());
         doReturn(CompletableFuture.completedFuture(NOT_DISCONNECTED))
@@ -1303,7 +1309,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(0));
+                eq(testPhone), eq(false), eq(0), eq(false));
 
         assertFalse(callback.getValue()
                 .isOkToCall(testPhone, ServiceState.STATE_OUT_OF_SERVICE, false));
@@ -1331,7 +1337,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(0));
+                eq(testPhone), eq(false), eq(0), eq(false));
 
         assertFalse(callback.getValue()
                 .isOkToCall(testPhone, ServiceState.STATE_OUT_OF_SERVICE, false));
@@ -1342,13 +1348,13 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         callback.getValue().onComplete(null, true);
 
         try {
-            doAnswer(invocation -> null).when(mContext).startActivity(any());
+            doAnswer(invocation -> null).when(mContext).startActivityAsUser(any(), any());
             verify(testPhone).dial(anyString(), any(), any());
         } catch (CallStateException e) {
             // This shouldn't happen
             fail();
         }
-        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any(), anyBoolean());
     }
 
     /**
@@ -1443,7 +1449,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(0));
+                eq(testPhone), eq(false), eq(0), eq(false));
 
         assertFalse(callback.getValue()
                 .isOkToCall(testPhone, ServiceState.STATE_OUT_OF_SERVICE, false));
@@ -1457,13 +1463,115 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         callback.getValue().onComplete(null, true);
 
         try {
-            doAnswer(invocation -> null).when(mContext).startActivity(any());
+            doAnswer(invocation -> null).when(mContext).startActivityAsUser(any(), any());
             verify(testPhone).dial(anyString(), any(), any());
         } catch (CallStateException e) {
             // This shouldn't happen
             fail();
         }
-        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any(), anyBoolean());
+    }
+
+    /**
+     * Test that the TelephonyConnectionService successfully placing the emergency call based on
+     * CarrierRoaming mode of Satellite.
+     */
+    @Test
+    @SmallTest
+    public void testCreateOutgoingEmergencyConnection_exitingSatellite_EmergencySatellite()
+            throws Exception {
+        doReturn(true).when(mFeatureFlags).carrierRoamingNbIotNtn();
+        doReturn(true).when(mSatelliteController).isSatelliteEnabled();
+
+        // Set config_turn_off_oem_enabled_satellite_during_emergency_call as false
+        doReturn(true).when(mTelephonyManagerProxy).isCurrentEmergencyNumber(anyString());
+        doReturn(false).when(mSatelliteController).isDemoModeEnabled();
+
+        // Satellite is not for emergency, allow EMC
+        doReturn(false).when(mSatelliteController).getRequestIsEmergency();
+        // Setup outgoing emergency call
+        setupConnectionServiceInApm();
+
+        // Verify emergency call go through
+        assertNull(mConnection.getDisconnectCause());
+    }
+
+    @Test
+    @SmallTest
+    public void testCreateOutgoingEmergencyConnection_exitingSatellite_OEM() throws Exception {
+        doReturn(true).when(mFeatureFlags).carrierRoamingNbIotNtn();
+        doReturn(true).when(mSatelliteController).isSatelliteEnabled();
+
+        // Set config_turn_off_oem_enabled_satellite_during_emergency_call as false
+        doReturn(false).when(mMockResources).getBoolean(anyInt());
+        doReturn(true).when(mTelephonyManagerProxy).isCurrentEmergencyNumber(anyString());
+        doReturn(false).when(mSatelliteController).isDemoModeEnabled();
+
+        // Satellite is for emergency
+        doReturn(true).when(mSatelliteController).getRequestIsEmergency();
+        Phone phone = mock(Phone.class);
+        doReturn(1).when(phone).getSubId();
+        doReturn(phone).when(mSatelliteController).getSatellitePhone();
+        SubscriptionManagerService isub = mock(SubscriptionManagerService.class);
+        replaceInstance(SubscriptionManagerService.class, "sInstance", null, isub);
+        SubscriptionInfoInternal info = mock(SubscriptionInfoInternal.class);
+        doReturn(info).when(isub).getSubscriptionInfoInternal(1);
+
+        // Setup outgoing emergency call
+        setupConnectionServiceInApm();
+
+        // Verify DisconnectCause which not allows emergency call
+        assertNotNull(mConnection.getDisconnectCause());
+        assertEquals(android.telephony.DisconnectCause.SATELLITE_ENABLED,
+                mConnection.getDisconnectCause().getTelephonyDisconnectCause());
+
+        // OEM: config_turn_off_oem_enabled_satellite_during_emergency_call = true
+        doReturn(1).when(info).getOnlyNonTerrestrialNetwork();
+        doReturn(true).when(mMockResources).getBoolean(anyInt());
+        // Setup outgoing emergency call
+        setupConnectionServiceInApm();
+
+        // Verify emergency call go through
+        assertNull(mConnection.getDisconnectCause());
+    }
+
+    @Test
+    @SmallTest
+    public void testCreateOutgoingEmergencyConnection_exitingSatellite_Carrier() throws Exception {
+        doReturn(true).when(mFeatureFlags).carrierRoamingNbIotNtn();
+        doReturn(true).when(mSatelliteController).isSatelliteEnabled();
+
+        // Set config_turn_off_oem_enabled_satellite_during_emergency_call as false
+        doReturn(false).when(mMockResources).getBoolean(anyInt());
+        doReturn(true).when(mTelephonyManagerProxy).isCurrentEmergencyNumber(anyString());
+        doReturn(false).when(mSatelliteController).isDemoModeEnabled();
+
+        // Satellite is for emergency
+        doReturn(true).when(mSatelliteController).getRequestIsEmergency();
+        Phone phone = mock(Phone.class);
+        doReturn(1).when(phone).getSubId();
+        doReturn(phone).when(mSatelliteController).getSatellitePhone();
+        SubscriptionManagerService isub = mock(SubscriptionManagerService.class);
+        replaceInstance(SubscriptionManagerService.class, "sInstance", null, isub);
+        SubscriptionInfoInternal info = mock(SubscriptionInfoInternal.class);
+        doReturn(info).when(isub).getSubscriptionInfoInternal(1);
+
+        // Carrier: shouldTurnOffCarrierSatelliteForEmergencyCall = false
+        doReturn(0).when(info).getOnlyNonTerrestrialNetwork();
+        doReturn(false).when(mSatelliteController).shouldTurnOffCarrierSatelliteForEmergencyCall();
+        setupConnectionServiceInApm();
+
+        // Verify DisconnectCause which not allows emergency call
+        assertNotNull(mConnection.getDisconnectCause());
+        assertEquals(android.telephony.DisconnectCause.SATELLITE_ENABLED,
+                mConnection.getDisconnectCause().getTelephonyDisconnectCause());
+
+        // Carrier: shouldTurnOffCarrierSatelliteForEmergencyCall = true
+        doReturn(true).when(mSatelliteController).shouldTurnOffCarrierSatelliteForEmergencyCall();
+        setupConnectionServiceInApm();
+
+        // Verify emergency call go through
+        assertNull(mConnection.getDisconnectCause());
     }
 
     /**
@@ -1496,7 +1604,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 PHONE_ACCOUNT_HANDLE_1, connectionRequest);
 
         verify(mRadioOnHelper).triggerRadioOnAndListen(any(), eq(false),
-                eq(testPhone0), eq(false), eq(0));
+                eq(testPhone0), eq(false), eq(0), eq(false));
     }
 
     /**
@@ -1530,7 +1638,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 PHONE_ACCOUNT_HANDLE_1, connectionRequest);
 
         verify(mRadioOnHelper).triggerRadioOnAndListen(any(), eq(false),
-                eq(testPhone0), eq(false), eq(0));
+                eq(testPhone0), eq(false), eq(0), eq(false));
     }
 
     /**
@@ -1563,7 +1671,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 PHONE_ACCOUNT_HANDLE_1, connectionRequest);
 
         verify(mRadioOnHelper, times(0)).triggerRadioOnAndListen(any(),
-                eq(true), eq(testPhone0), eq(false), eq(0));
+                eq(true), eq(testPhone0), eq(false), eq(0), eq(false));
     }
 
     /**
@@ -2051,7 +2159,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
             throws Exception {
         setupForCallTest();
         when(mTelephonyManagerProxy.isConcurrentCallsPossible()).thenReturn(true);
-        doNothing().when(mContext).startActivity(any());
+        doNothing().when(mContext).startActivityAsUser(any(), any());
 
         mBinderStub.createConnection(PHONE_ACCOUNT_HANDLE_1, "TC@1",
                 new ConnectionRequest(PHONE_ACCOUNT_HANDLE_1, Uri.parse("tel:16505551212"),
@@ -2084,7 +2192,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
             throws Exception {
         setupForCallTest();
         when(mTelephonyManagerProxy.isConcurrentCallsPossible()).thenReturn(true);
-        doNothing().when(mContext).startActivity(any());
+        doNothing().when(mContext).startActivityAsUser(any(), any());
 
         doReturn(true).when(mTelephonyManagerProxy).isCurrentEmergencyNumber(anyString());
         mBinderStub.createConnection(PHONE_ACCOUNT_HANDLE_1, "TC@1",
@@ -2120,7 +2228,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
             throws Exception {
         setupForCallTest();
         when(mTelephonyManagerProxy.isConcurrentCallsPossible()).thenReturn(true);
-        doNothing().when(mContext).startActivity(any());
+        doNothing().when(mContext).startActivityAsUser(any(), any());
 
         doReturn(true).when(mTelephonyManagerProxy).isCurrentEmergencyNumber(anyString());
         getTestContext().getCarrierConfig(0 /*subId*/).putBoolean(
@@ -2184,7 +2292,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(true));
         verify(mEmergencyStateTracker)
                 .startEmergencyCall(eq(mPhone0), connectionCaptor.capture(), eq(false));
-        verify(mSatelliteSOSMessageRecommender, times(2)).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender, times(2)).onEmergencyCallStarted(any(),
+                anyBoolean());
         verify(mEmergencyCallDomainSelectionConnection).createEmergencyConnection(any(), any());
 
         android.telecom.Connection tc = connectionCaptor.getValue();
@@ -2223,7 +2332,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(true));
         verify(mEmergencyStateTracker)
                 .startEmergencyCall(eq(mPhone0), connectionCaptor.capture(), eq(false));
-        verify(mSatelliteSOSMessageRecommender, times(2)).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender, times(2)).onEmergencyCallStarted(any(),
+                anyBoolean());
         verify(mEmergencyCallDomainSelectionConnection).createEmergencyConnection(any(), any());
 
         android.telecom.Connection tc = connectionCaptor.getValue();
@@ -2267,7 +2377,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(true));
         verify(mEmergencyStateTracker)
                 .startEmergencyCall(eq(mPhone0), connectionCaptor.capture(), eq(false));
-        verify(mSatelliteSOSMessageRecommender, times(2)).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender, times(2)).onEmergencyCallStarted(any(),
+                anyBoolean());
         verify(mEmergencyCallDomainSelectionConnection).createEmergencyConnection(any(), any());
 
         android.telecom.Connection tc = connectionCaptor.getValue();
@@ -2415,7 +2526,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
 
         listener.onDisconnect(0);
 
-        verify(mSatelliteSOSMessageRecommender, times(2)).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender, times(2)).onEmergencyCallStarted(any(),
+                anyBoolean());
 
         ArgumentCaptor<DialArgs> argsCaptor = ArgumentCaptor.forClass(DialArgs.class);
 
@@ -2521,7 +2633,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         verify(mDomainSelectionResolver)
                 .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(false));
         verify(mNormalCallDomainSelectionConnection).createNormalConnection(any(), any());
-        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any(), anyBoolean());
 
         ArgumentCaptor<DialArgs> argsCaptor = ArgumentCaptor.forClass(DialArgs.class);
 
@@ -2618,7 +2730,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(true));
         verify(mEmergencyStateTracker)
                 .startEmergencyCall(eq(mPhone0), connectionCaptor.capture(), eq(false));
-        verify(mSatelliteSOSMessageRecommender, times(2)).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender, times(2)).onEmergencyCallStarted(any(),
+                anyBoolean());
         verify(mEmergencyCallDomainSelectionConnection).createEmergencyConnection(any(), any());
 
         android.telecom.Connection tc = connectionCaptor.getValue();
@@ -2689,7 +2802,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         verify(mDomainSelectionResolver)
                 .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(false));
         verify(mNormalCallDomainSelectionConnection).createNormalConnection(any(), any());
-        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any(), anyBoolean());
 
         ArgumentCaptor<DialArgs> argsCaptor = ArgumentCaptor.forClass(DialArgs.class);
 
@@ -2711,7 +2824,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS));
+                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS), eq(true));
 
         ServiceState ss = new ServiceState();
         ss.setState(ServiceState.STATE_OUT_OF_SERVICE);
@@ -2750,7 +2863,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS));
+                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS), eq(true));
 
         ServiceState ss = new ServiceState();
         ss.setState(ServiceState.STATE_OUT_OF_SERVICE);
@@ -2775,7 +2888,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS));
+                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS), eq(true));
 
         ServiceState ss = new ServiceState();
         ss.setState(ServiceState.STATE_IN_SERVICE);
@@ -2811,7 +2924,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS));
+                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS), eq(true));
 
         ServiceState ss = new ServiceState();
         ss.setState(ServiceState.STATE_IN_SERVICE);
@@ -2848,7 +2961,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS));
+                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS), eq(true));
 
         ServiceState ss = new ServiceState();
         ss.setState(ServiceState.STATE_IN_SERVICE);
@@ -2885,7 +2998,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS));
+                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS), eq(true));
 
         mConnection.setDisconnected(null);
 
@@ -2922,7 +3035,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(true));
         verify(mEmergencyStateTracker)
                 .startEmergencyCall(eq(mPhone0), connectionCaptor.capture(), eq(false));
-        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any(), anyBoolean());
         verify(mEmergencyCallDomainSelectionConnection).createEmergencyConnection(any(), any());
 
         android.telecom.Connection tc = connectionCaptor.getValue();
@@ -2975,7 +3088,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(true));
         verify(mEmergencyStateTracker)
                 .startEmergencyCall(eq(mPhone0), connectionCaptor.capture(), eq(false));
-        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any(), anyBoolean());
         verify(mEmergencyCallDomainSelectionConnection).createEmergencyConnection(any(), any());
 
         android.telecom.Connection tc = connectionCaptor.getValue();
@@ -3310,7 +3423,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
 
         verify(mEmergencyStateTracker)
                 .startEmergencyCall(eq(mPhone0), connectionCaptor.capture(), eq(false));
-        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender).onEmergencyCallStarted(any(), anyBoolean());
 
         android.telecom.Connection tc = connectionCaptor.getValue();
 
@@ -3386,7 +3499,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(true));
         verify(mEmergencyStateTracker)
                 .startEmergencyCall(eq(mPhone0), connectionCaptor.capture(), eq(false));
-        verify(mSatelliteSOSMessageRecommender, times(2)).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender, times(2)).onEmergencyCallStarted(any(),
+                anyBoolean());
         verify(mEmergencyCallDomainSelectionConnection).createEmergencyConnection(any(), any());
         verify(mPhone0).dial(anyString(), any(), any());
 
@@ -3575,7 +3689,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     @Test
     public void testDomainSelectionWithMmiCode() {
         //UT domain selection should not be handled by new domain selector.
-        doNothing().when(mContext).startActivity(any());
+        doNothing().when(mContext).startActivityAsUser(any(), any());
         setupForCallTest();
         setupForDialForDomainSelection(mPhone0, 0, false);
         mTestConnectionService.onCreateOutgoingConnection(PHONE_ACCOUNT_HANDLE_1,
@@ -3596,7 +3710,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         verify(mDomainSelectionResolver)
                 .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(false));
         verify(mNormalCallDomainSelectionConnection).createNormalConnection(any(), any());
-        verify(mSatelliteSOSMessageRecommender, never()).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender, never()).onEmergencyCallStarted(any(),
+                anyBoolean());
 
         ArgumentCaptor<DialArgs> argsCaptor = ArgumentCaptor.forClass(DialArgs.class);
 
@@ -3621,7 +3736,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         verify(mDomainSelectionResolver)
                 .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(false));
         verify(mNormalCallDomainSelectionConnection).createNormalConnection(any(), any());
-        verify(mSatelliteSOSMessageRecommender, never()).onEmergencyCallStarted(any());
+        verify(mSatelliteSOSMessageRecommender, never()).onEmergencyCallStarted(any(),
+                anyBoolean());
 
         ArgumentCaptor<DialArgs> argsCaptor = ArgumentCaptor.forClass(DialArgs.class);
 
@@ -3781,6 +3897,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ss.setEmergencyOnly(true);
         ss.setState(ServiceState.STATE_EMERGENCY_ONLY);
         when(mockPhone.getServiceState()).thenReturn(ss);
+        when(mPhoneFactoryProxy.getPhones()).thenReturn(new Phone[] {mockPhone});
 
         assertFalse(mTestConnectionService.isAvailableForEmergencyCalls(mockPhone,
                 EmergencyNumber.EMERGENCY_CALL_ROUTING_EMERGENCY));
@@ -3804,6 +3921,79 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ss.setState(ServiceState.STATE_EMERGENCY_ONLY);
         when(mockPhone.getServiceState()).thenReturn(ss);
 
+        when(mPhoneFactoryProxy.getPhones()).thenReturn(new Phone[] {mockPhone});
+
+        assertTrue(mTestConnectionService.isAvailableForEmergencyCalls(mockPhone,
+                EmergencyNumber.EMERGENCY_CALL_ROUTING_EMERGENCY));
+        assertFalse(mTestConnectionService.isAvailableForEmergencyCalls(mockPhone,
+                EmergencyNumber.EMERGENCY_CALL_ROUTING_NORMAL));
+        assertTrue(mTestConnectionService.isAvailableForEmergencyCalls(mockPhone,
+                EmergencyNumber.EMERGENCY_CALL_ROUTING_UNKNOWN));
+    }
+
+    @Test
+    public void testIsAvailableForEmergencyCallsUsingNTN_CellularAvailable() {
+        mSetFlagsRule.enableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
+
+        // Call is not supported while using satellite
+        when(mSatelliteController.isInSatelliteModeForCarrierRoaming(any())).thenReturn(true);
+        when(mSatelliteController.getCapabilitiesForCarrierRoamingSatelliteMode(any()))
+                .thenReturn(List.of(NetworkRegistrationInfo.SERVICE_TYPE_DATA));
+
+        Phone mockPhone = Mockito.mock(Phone.class);
+        ServiceState ss = new ServiceState();
+        ss.setEmergencyOnly(true);
+        ss.setState(ServiceState.STATE_EMERGENCY_ONLY);
+        when(mockPhone.getServiceState()).thenReturn(ss);
+
+        // Phone2 is in limited service
+        Phone mockPhone2 = Mockito.mock(Phone.class);
+        ServiceState ss2 = new ServiceState();
+        ss2.setEmergencyOnly(true);
+        ss2.setState(ServiceState.STATE_EMERGENCY_ONLY);
+        when(mockPhone2.getServiceState()).thenReturn(ss2);
+
+        Phone[] phones = {mockPhone, mockPhone2};
+        when(mPhoneFactoryProxy.getPhones()).thenReturn(phones);
+
+        assertFalse(mTestConnectionService.isAvailableForEmergencyCalls(mockPhone,
+                EmergencyNumber.EMERGENCY_CALL_ROUTING_EMERGENCY));
+        assertFalse(mTestConnectionService.isAvailableForEmergencyCalls(mockPhone,
+                EmergencyNumber.EMERGENCY_CALL_ROUTING_NORMAL));
+        assertFalse(mTestConnectionService.isAvailableForEmergencyCalls(mockPhone,
+                EmergencyNumber.EMERGENCY_CALL_ROUTING_UNKNOWN));
+    }
+
+    @Test
+    public void testIsAvailableForEmergencyCallsUsingNTN_CellularNotAvailable() {
+        mSetFlagsRule.enableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
+
+        // Call is not supported while using satellite
+        when(mSatelliteController.isInSatelliteModeForCarrierRoaming(any())).thenReturn(true);
+        when(mSatelliteController.getCapabilitiesForCarrierRoamingSatelliteMode(any()))
+                .thenReturn(List.of(NetworkRegistrationInfo.SERVICE_TYPE_DATA));
+
+        NetworkRegistrationInfo nri = new NetworkRegistrationInfo.Builder()
+                .setIsNonTerrestrialNetwork(true)
+                .setAvailableServices(List.of(NetworkRegistrationInfo.SERVICE_TYPE_DATA))
+                .build();
+        Phone mockPhone = Mockito.mock(Phone.class);
+        ServiceState ss = new ServiceState();
+        ss.addNetworkRegistrationInfo(nri);
+        ss.setEmergencyOnly(true);
+        ss.setState(ServiceState.STATE_EMERGENCY_ONLY);
+        when(mockPhone.getServiceState()).thenReturn(ss);
+
+        // Phone2 is out of service
+        Phone mockPhone2 = Mockito.mock(Phone.class);
+        ServiceState ss2 = new ServiceState();
+        ss2.setEmergencyOnly(false);
+        ss2.setState(ServiceState.STATE_OUT_OF_SERVICE);
+        when(mockPhone2.getServiceState()).thenReturn(ss2);
+
+        Phone[] phones = {mockPhone, mockPhone2};
+        when(mPhoneFactoryProxy.getPhones()).thenReturn(phones);
+
         assertTrue(mTestConnectionService.isAvailableForEmergencyCalls(mockPhone,
                 EmergencyNumber.EMERGENCY_CALL_ROUTING_EMERGENCY));
         assertFalse(mTestConnectionService.isAvailableForEmergencyCalls(mockPhone,
diff --git a/tests/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelectorTest.java b/tests/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelectorTest.java
index d4ee9333b..8a83ab0e8 100644
--- a/tests/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelectorTest.java
+++ b/tests/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelectorTest.java
@@ -103,6 +103,7 @@ import android.os.IThermalService;
 import android.os.Looper;
 import android.os.PersistableBundle;
 import android.os.PowerManager;
+import android.platform.test.flag.junit.SetFlagsRule;
 import android.telecom.PhoneAccount;
 import android.telecom.TelecomManager;
 import android.telephony.AccessNetworkConstants;
@@ -130,10 +131,12 @@ import android.util.SparseArray;
 import androidx.test.filters.SmallTest;
 
 import com.android.TestContext;
+import com.android.internal.telephony.flags.Flags;
 import com.android.phone.R;
 
 import org.junit.After;
 import org.junit.Before;
+import org.junit.Rule;
 import org.junit.Test;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
@@ -147,10 +150,9 @@ import java.util.function.Consumer;
 
 /**
  * Unit tests for EmergencyCallDomainSelector
- */
+*/
 public class EmergencyCallDomainSelectorTest {
     private static final String TAG = "EmergencyCallDomainSelectorTest";
-
     private static final int SLOT_0 = 0;
     private static final int SLOT_0_SUB_ID = 1;
     private static final Uri TEST_URI = Uri.fromParts(PhoneAccount.SCHEME_TEL, "911", null);
@@ -167,6 +169,7 @@ public class EmergencyCallDomainSelectorTest {
     @Mock private CrossSimRedialingController mCsrdCtrl;
     @Mock private DataConnectionStateHelper mEpdnHelper;
     @Mock private Resources mResources;
+    @Mock private ImsEmergencyRegistrationStateHelper mImsEmergencyRegistrationHelper;
 
     private TelecomManager mTelecomManager;
 
@@ -181,6 +184,8 @@ public class EmergencyCallDomainSelectorTest {
     private ConnectivityManager.NetworkCallback mNetworkCallback;
     private Consumer<EmergencyRegistrationResult> mResultConsumer;
 
+    @Rule public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
+
     @Before
     public void setUp() throws Exception {
         MockitoAnnotations.initMocks(this);
@@ -471,7 +476,8 @@ public class EmergencyCallDomainSelectorTest {
         doReturn(TelephonyManager.SIM_STATE_PIN_REQUIRED)
                 .when(mTelephonyManager).getSimState(anyInt());
         doReturn(true).when(mCsrdCtrl).isThereOtherSlot();
-        doReturn(new String[] {"jp"}).when(mResources).getStringArray(anyInt());
+        doReturn(new String[] {"jp"}).when(mResources).getStringArray(
+                eq(R.array.config_countries_require_sim_for_emergency));
 
         EmergencyRegistrationResult regResult = getEmergencyRegResult(
                 UNKNOWN, REGISTRATION_STATE_UNKNOWN, 0, false, false, 0, 0, "", "", "jp");
@@ -586,7 +592,8 @@ public class EmergencyCallDomainSelectorTest {
     @Test
     public void testDefaultCombinedImsRegisteredSelectPsThenExtendedServiceRequestFailIsoMatch()
             throws Exception {
-        doReturn(new String[] {"us"}).when(mResources).getStringArray(anyInt());
+        doReturn(new String[] {"us"}).when(mResources).getStringArray(
+                eq(R.array.config_countries_prefer_cs_preferred_scan_after_csfb_failure));
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -625,7 +632,8 @@ public class EmergencyCallDomainSelectorTest {
     @Test
     public void testDefaultCombinedImsRegisteredSelectPsThenExtendedServiceRequestFailIsoNotMatch()
             throws Exception {
-        doReturn(new String[] {"us"}).when(mResources).getStringArray(anyInt());
+        doReturn(new String[] {"us"}).when(mResources).getStringArray(
+                eq(R.array.config_countries_prefer_cs_preferred_scan_after_csfb_failure));
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -1788,7 +1796,8 @@ public class EmergencyCallDomainSelectorTest {
         doReturn(TelephonyManager.SIM_STATE_PIN_REQUIRED)
                 .when(mTelephonyManager).getSimState(anyInt());
         doReturn(true).when(mCsrdCtrl).isThereOtherSlot();
-        doReturn(new String[] {"jp"}).when(mResources).getStringArray(anyInt());
+        doReturn(new String[] {"jp"}).when(mResources).getStringArray(
+                eq(R.array.config_countries_require_sim_for_emergency));
 
         EmergencyRegistrationResult regResult = getEmergencyRegResult(EUTRAN,
                 REGISTRATION_STATE_UNKNOWN,
@@ -1812,7 +1821,8 @@ public class EmergencyCallDomainSelectorTest {
         doReturn(TelephonyManager.SIM_STATE_PIN_REQUIRED)
                 .when(mTelephonyManager).getSimState(anyInt());
         doReturn(true).when(mCsrdCtrl).isThereOtherSlot();
-        doReturn(new String[] {"jp"}).when(mResources).getStringArray(anyInt());
+        doReturn(new String[] {"jp"}).when(mResources).getStringArray(
+                eq(R.array.config_countries_require_sim_for_emergency));
 
         EmergencyRegistrationResult regResult = getEmergencyRegResult(UNKNOWN,
                 REGISTRATION_STATE_UNKNOWN,
@@ -1843,7 +1853,8 @@ public class EmergencyCallDomainSelectorTest {
         doReturn(TelephonyManager.SIM_STATE_PIN_REQUIRED)
                 .when(mTelephonyManager).getSimState(anyInt());
         doReturn(false).when(mCsrdCtrl).isThereOtherSlot();
-        doReturn(new String[] {"jp"}).when(mResources).getStringArray(anyInt());
+        doReturn(new String[] {"jp"}).when(mResources).getStringArray(
+                eq(R.array.config_countries_require_sim_for_emergency));
 
         EmergencyRegistrationResult regResult = getEmergencyRegResult(EUTRAN,
                 REGISTRATION_STATE_UNKNOWN,
@@ -1865,7 +1876,8 @@ public class EmergencyCallDomainSelectorTest {
         unsolBarringInfoChanged(false);
         doReturn(2).when(mTelephonyManager).getActiveModemCount();
         doReturn(true).when(mCsrdCtrl).isThereOtherSlotInService();
-        doReturn(new String[] {"in"}).when(mResources).getStringArray(anyInt());
+        doReturn(new String[] {"in"}).when(mResources).getStringArray(
+                eq(R.array.config_countries_prefer_normal_service_capable_subscription));
 
         EmergencyRegistrationResult regResult = getEmergencyRegResult(EUTRAN,
                 REGISTRATION_STATE_UNKNOWN,
@@ -1889,7 +1901,8 @@ public class EmergencyCallDomainSelectorTest {
 
         doReturn(2).when(mTelephonyManager).getActiveModemCount();
         doReturn(true).when(mCsrdCtrl).isThereOtherSlotInService();
-        doReturn(new String[] {"in"}).when(mResources).getStringArray(anyInt());
+        doReturn(new String[] {"in"}).when(mResources).getStringArray(
+                eq(R.array.config_countries_prefer_normal_service_capable_subscription));
 
         EmergencyRegistrationResult regResult = getEmergencyRegResult(UNKNOWN,
                 REGISTRATION_STATE_UNKNOWN,
@@ -2343,6 +2356,152 @@ public class EmergencyCallDomainSelectorTest {
         assertTrue(networks.indexOf(GERAN) < networks.indexOf(NGRAN));
     }
 
+    @Test
+    public void testNotPreferLteThanNrInUnknownCoverage() throws Exception {
+        PersistableBundle bundle = getDefaultPersistableBundle();
+        bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
+                new int[] { NGRAN, EUTRAN });
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(
+                UNKNOWN, REGISTRATION_STATE_UNKNOWN, 0, false, false, 0, 0, "", "", "zz");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+        processAllMessages();
+
+        verify(mWwanSelectorCallback, times(1)).onRequestEmergencyNetworkScan(
+                any(), anyInt(), anyBoolean(), any(), any());
+        assertEquals(4, mAccessNetwork.size());
+        assertEquals(NGRAN, (int) mAccessNetwork.get(0));
+        assertEquals(EUTRAN, (int) mAccessNetwork.get(1));
+        assertEquals(UTRAN, (int) mAccessNetwork.get(2));
+        assertEquals(GERAN, (int) mAccessNetwork.get(3));
+    }
+
+    @Test
+    public void testNotPreferLteThanNrInNrCoverage() throws Exception {
+        PersistableBundle bundle = getDefaultPersistableBundle();
+        bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
+                new int[] { NGRAN, EUTRAN });
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(
+                NGRAN, REGISTRATION_STATE_UNKNOWN, 0, false, false, 0, 0, "", "", "zz");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+        processAllMessages();
+
+        verify(mWwanSelectorCallback, times(1)).onRequestEmergencyNetworkScan(
+                any(), anyInt(), anyBoolean(), any(), any());
+        assertEquals(4, mAccessNetwork.size());
+        assertEquals(NGRAN, (int) mAccessNetwork.get(0));
+        assertEquals(EUTRAN, (int) mAccessNetwork.get(1));
+        assertEquals(UTRAN, (int) mAccessNetwork.get(2));
+        assertEquals(GERAN, (int) mAccessNetwork.get(3));
+    }
+
+    @Test
+    public void testNotPreferLteThanNrInUnknownCountry() throws Exception {
+        PersistableBundle bundle = getDefaultPersistableBundle();
+        bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
+                new int[] { NGRAN, EUTRAN });
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(
+                EUTRAN, REGISTRATION_STATE_UNKNOWN, 0, false, false, 0, 0, "", "");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+        processAllMessages();
+
+        verify(mWwanSelectorCallback, times(1)).onRequestEmergencyNetworkScan(
+                any(), anyInt(), anyBoolean(), any(), any());
+        assertEquals(4, mAccessNetwork.size());
+        assertEquals(NGRAN, (int) mAccessNetwork.get(0));
+        assertEquals(EUTRAN, (int) mAccessNetwork.get(1));
+        assertEquals(UTRAN, (int) mAccessNetwork.get(2));
+        assertEquals(GERAN, (int) mAccessNetwork.get(3));
+    }
+
+    @Test
+    public void testPreferLteThanNrInLteCoverage() throws Exception {
+        PersistableBundle bundle = getDefaultPersistableBundle();
+        bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
+                new int[] { NGRAN, EUTRAN });
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(
+                EUTRAN, REGISTRATION_STATE_UNKNOWN, 0, false, false, 0, 0, "", "", "zz");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+        processAllMessages();
+
+        verify(mWwanSelectorCallback, times(1)).onRequestEmergencyNetworkScan(
+                any(), anyInt(), anyBoolean(), any(), any());
+        assertEquals(4, mAccessNetwork.size());
+        assertEquals(EUTRAN, (int) mAccessNetwork.get(0));
+        assertEquals(NGRAN, (int) mAccessNetwork.get(1));
+        assertEquals(UTRAN, (int) mAccessNetwork.get(2));
+        assertEquals(GERAN, (int) mAccessNetwork.get(3));
+    }
+
+    @Test
+    public void testPreferLteThanNrInCsCoverage() throws Exception {
+        PersistableBundle bundle = getDefaultPersistableBundle();
+        bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
+                new int[] { NGRAN, EUTRAN });
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(UTRAN,
+                REGISTRATION_STATE_HOME,
+                NetworkRegistrationInfo.DOMAIN_CS,
+                false, false, 0, 0, "", "", "zz");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+
+        verifyCsDialed();
+
+        mDomainSelector.reselectDomain(attr);
+        processAllMessages();
+
+        verify(mWwanSelectorCallback, times(1)).onRequestEmergencyNetworkScan(
+                any(), anyInt(), anyBoolean(), any(), any());
+        assertEquals(4, mAccessNetwork.size());
+        assertEquals(EUTRAN, (int) mAccessNetwork.get(0));
+        assertEquals(NGRAN, (int) mAccessNetwork.get(1));
+        assertEquals(UTRAN, (int) mAccessNetwork.get(2));
+        assertEquals(GERAN, (int) mAccessNetwork.get(3));
+    }
+
     @Test
     public void testScanLimitedOnlyAfterVoLteFailure() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
@@ -2389,6 +2548,8 @@ public class EmergencyCallDomainSelectorTest {
         bindImsServiceUnregistered();
 
         processAllMessages();
+
+        verify(mImsEmergencyRegistrationHelper, never()).start();
         verify(mCsrdCtrl).startTimer(any(), eq(mDomainSelector), any(),
                 any(), anyBoolean(), anyBoolean(), anyInt());
     }
@@ -2643,6 +2804,67 @@ public class EmergencyCallDomainSelectorTest {
         verify(mTransportSelectorCallback, times(1)).onWlanSelected(eq(true));
     }
 
+    @Test
+    public void testCrossStackTimerExpiredHangupOngoingDialing() throws Exception {
+        PersistableBundle bundle = getDefaultPersistableBundle();
+        bundle.putInt(KEY_EMERGENCY_CALL_SETUP_TIMER_ON_CURRENT_NETWORK_SEC_INT, 1);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+
+        mSetFlagsRule.enableFlags(Flags.FLAG_HANGUP_EMERGENCY_CALL_FOR_CROSS_SIM_REDIALING);
+
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(UTRAN,
+                REGISTRATION_STATE_HOME,
+                NetworkRegistrationInfo.DOMAIN_CS,
+                true, true, 0, 0, "", "");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+
+        verify(mImsEmergencyRegistrationHelper).start();
+        verifyCsDialed();
+
+        mDomainSelector.notifyCrossStackTimerExpired();
+
+        verify(mTransportSelectorCallback)
+                .onSelectionTerminated(eq(DisconnectCause.EMERGENCY_PERM_FAILURE));
+    }
+
+    @Test
+    public void testCrossStackTimerExpiredNotHangupOngoingDialing() throws Exception {
+        PersistableBundle bundle = getDefaultPersistableBundle();
+        bundle.putInt(KEY_EMERGENCY_CALL_SETUP_TIMER_ON_CURRENT_NETWORK_SEC_INT, 1);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        doReturn(true).when(mImsEmergencyRegistrationHelper).isImsEmergencyRegistered();
+
+        mSetFlagsRule.enableFlags(Flags.FLAG_HANGUP_EMERGENCY_CALL_FOR_CROSS_SIM_REDIALING);
+
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(UTRAN,
+                REGISTRATION_STATE_HOME,
+                NetworkRegistrationInfo.DOMAIN_CS,
+                true, true, 0, 0, "", "");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+
+        verify(mImsEmergencyRegistrationHelper).start();
+        verifyCsDialed();
+
+        mDomainSelector.notifyCrossStackTimerExpired();
+
+        verify(mTransportSelectorCallback, never())
+                .onSelectionTerminated(eq(DisconnectCause.EMERGENCY_TEMP_FAILURE));
+    }
+
     @Test
     public void testMaxCellularTimeout() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
@@ -3390,7 +3612,108 @@ public class EmergencyCallDomainSelectorTest {
 
         EmergencyRegistrationResult regResult = getEmergencyRegResult(NGRAN,
                 REGISTRATION_STATE_UNKNOWN,
-                0, false, true, 0, 0, "", "");
+                0, false, true, 1, 0, "", "", "us");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+
+        verifyScanPsPreferred();
+    }
+
+    @Test
+    public void testNrSaOnlyLimitedServiceNgranEmc() throws Exception {
+        PersistableBundle bundle = getDefaultPersistableBundle();
+        bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
+                new int[] { NGRAN, EUTRAN });
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(NGRAN,
+                REGISTRATION_STATE_UNKNOWN,
+                0, false, false, 1, 0, "", "", "us");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+
+        verifyPsDialed();
+    }
+
+    @Test
+    public void testNrSaOnlyLimitedServiceNgranNoEmc() throws Exception {
+        PersistableBundle bundle = getDefaultPersistableBundle();
+        bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
+                new int[] { NGRAN, EUTRAN });
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(NGRAN,
+                REGISTRATION_STATE_UNKNOWN,
+                0, false, false, 0, 0, "", "", "us");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+
+        verifyScanPreferred(DomainSelectionService.SCAN_TYPE_NO_PREFERENCE, NGRAN);
+    }
+
+    @Test
+    public void testDefaultLimitedServiceNgranEmcWhenSimNotReady() throws Exception {
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+        doReturn(TelephonyManager.SIM_STATE_PIN_REQUIRED)
+                .when(mTelephonyManager).getSimState(anyInt());
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(NGRAN,
+                REGISTRATION_STATE_UNKNOWN,
+                0, false, false, 1, 0, "", "", "us");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+
+        verifyPsDialed();
+    }
+
+    @Test
+    public void testDefaultLimitedServiceNgranNoEmcWhenSimNotReady() throws Exception {
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+        doReturn(TelephonyManager.SIM_STATE_PIN_REQUIRED)
+            .when(mTelephonyManager).getSimState(anyInt());
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(NGRAN,
+                REGISTRATION_STATE_UNKNOWN,
+                0, false, false, 0, 0, "", "", "us");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+
+        verifyScanPsPreferred();
+    }
+
+    @Test
+    public void testNrSaOnlyLimitedServiceNgranEmcNoCountryIsoWhenSimNotReady() throws Exception {
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+        doReturn(TelephonyManager.SIM_STATE_PIN_REQUIRED)
+                .when(mTelephonyManager).getSimState(anyInt());
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(NGRAN,
+                REGISTRATION_STATE_UNKNOWN,
+                0, false, false, 1, 0, "", "", "");
         SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
         mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
         processAllMessages();
@@ -4372,6 +4695,8 @@ public class EmergencyCallDomainSelectorTest {
         mDomainSelector.clearResourceConfiguration();
         replaceInstance(DomainSelectorBase.class,
                 "mWwanSelectorCallback", mDomainSelector, mWwanSelectorCallback);
+        replaceInstance(EmergencyCallDomainSelector.class, "mImsEmergencyRegistrationHelper",
+                mDomainSelector, mImsEmergencyRegistrationHelper);
     }
 
     private void verifyCsDialed() {
diff --git a/tests/src/com/android/services/telephony/domainselection/ImsEmergencyRegistrationStateHelperTest.java b/tests/src/com/android/services/telephony/domainselection/ImsEmergencyRegistrationStateHelperTest.java
new file mode 100644
index 000000000..41f174732
--- /dev/null
+++ b/tests/src/com/android/services/telephony/domainselection/ImsEmergencyRegistrationStateHelperTest.java
@@ -0,0 +1,212 @@
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
+package com.android.services.telephony.domainselection;
+
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+import android.os.HandlerThread;
+import android.telephony.ims.ImsException;
+import android.telephony.ims.ImsManager;
+import android.telephony.ims.ImsMmTelManager;
+import android.telephony.ims.ImsReasonInfo;
+import android.telephony.ims.ImsRegistrationAttributes;
+import android.telephony.ims.ImsStateCallback;
+import android.telephony.ims.RegistrationManager;
+import android.telephony.ims.stub.ImsRegistrationImplBase;
+import android.testing.TestableLooper;
+import android.util.Log;
+
+import androidx.test.filters.SmallTest;
+import androidx.test.runner.AndroidJUnit4;
+
+import com.android.TestContext;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import java.util.concurrent.Executor;
+
+/**
+ * Unit tests for ImsEmergencyRegistrationStateHelper.
+ */
+@RunWith(AndroidJUnit4.class)
+public class ImsEmergencyRegistrationStateHelperTest {
+    private static final String TAG = "ImsEmergencyRegistrationStateHelperTest";
+
+    private static final int SLOT_0 = 0;
+    private static final int SUB_1 = 1;
+
+    @Mock private ImsMmTelManager mMmTelManager;
+
+    private Context mContext;
+    private HandlerThread mHandlerThread;
+    private TestableLooper mLooper;
+    private ImsEmergencyRegistrationStateHelper mImsEmergencyRegistrationHelper;
+
+    @Before
+    public void setUp() throws Exception {
+        MockitoAnnotations.initMocks(this);
+        mContext = new TestContext() {
+            @Override
+            public String getSystemServiceName(Class<?> serviceClass) {
+                if (serviceClass == ImsManager.class) {
+                    return Context.TELEPHONY_IMS_SERVICE;
+                }
+                return super.getSystemServiceName(serviceClass);
+            }
+        };
+
+        mHandlerThread = new HandlerThread(
+                ImsEmergencyRegistrationStateHelperTest.class.getSimpleName());
+        mHandlerThread.start();
+        try {
+            mLooper = new TestableLooper(mHandlerThread.getLooper());
+        } catch (Exception e) {
+            loge("Unable to create looper from handler.");
+        }
+        mImsEmergencyRegistrationHelper = new ImsEmergencyRegistrationStateHelper(
+                mContext, SLOT_0, SUB_1, mHandlerThread.getLooper());
+
+        ImsManager imsManager = mContext.getSystemService(ImsManager.class);
+        when(imsManager.getImsMmTelManager(eq(SUB_1))).thenReturn(mMmTelManager);
+    }
+
+    @After
+    public void tearDown() throws Exception {
+        if (mImsEmergencyRegistrationHelper != null) {
+            mImsEmergencyRegistrationHelper.destroy();
+            mImsEmergencyRegistrationHelper = null;
+        }
+        mMmTelManager = null;
+
+        if (mLooper != null) {
+            mLooper.destroy();
+            mLooper = null;
+        }
+    }
+
+    @Test
+    @SmallTest
+    public void testStart() throws ImsException {
+        mImsEmergencyRegistrationHelper.start();
+
+        verify(mMmTelManager).registerImsStateCallback(
+                any(Executor.class), any(ImsStateCallback.class));
+        assertFalse(mImsEmergencyRegistrationHelper.isImsEmergencyRegistered());
+    }
+
+    @Test
+    @SmallTest
+    public void testNotifyImsStateCallbackOnAvailable() throws ImsException {
+        ImsStateCallback callback = setUpImsStateCallback();
+        callback.onAvailable();
+        processAllMessages();
+
+        verify(mMmTelManager).registerImsEmergencyRegistrationCallback(
+                any(Executor.class), any(RegistrationManager.RegistrationCallback.class));
+        assertFalse(mImsEmergencyRegistrationHelper.isImsEmergencyRegistered());
+    }
+
+    @Test
+    @SmallTest
+    public void testNotifyImsRegistrationCallbackOnRegistered() throws ImsException {
+        RegistrationManager.RegistrationCallback callback = setUpImsEmergencyRegistrationCallback();
+
+        assertFalse(mImsEmergencyRegistrationHelper.isImsEmergencyRegistered());
+
+        callback.onRegistered(getImsEmergencyRegistrationAttributes());
+        processAllMessages();
+
+        assertTrue(mImsEmergencyRegistrationHelper.isImsEmergencyRegistered());
+    }
+
+    @Test
+    @SmallTest
+    public void testNotifyImsRegistrationCallbackOnRegisteredUnregistered() throws ImsException {
+        RegistrationManager.RegistrationCallback callback = setUpImsEmergencyRegistrationCallback();
+
+        assertFalse(mImsEmergencyRegistrationHelper.isImsEmergencyRegistered());
+
+        callback.onRegistered(getImsEmergencyRegistrationAttributes());
+        processAllMessages();
+
+        callback.onUnregistered(
+                new ImsReasonInfo(ImsReasonInfo.CODE_LOCAL_CALL_CS_RETRY_REQUIRED, 0, null), 0, 0);
+        processAllMessages();
+
+        assertFalse(mImsEmergencyRegistrationHelper.isImsEmergencyRegistered());
+    }
+
+    private ImsStateCallback setUpImsStateCallback() throws ImsException {
+        mImsEmergencyRegistrationHelper.start();
+
+        ArgumentCaptor<ImsStateCallback> callbackCaptor =
+                ArgumentCaptor.forClass(ImsStateCallback.class);
+
+        verify(mMmTelManager).registerImsStateCallback(
+                any(Executor.class), callbackCaptor.capture());
+
+        ImsStateCallback imsStateCallback = callbackCaptor.getValue();
+        assertNotNull(imsStateCallback);
+        return imsStateCallback;
+    }
+
+    private RegistrationManager.RegistrationCallback setUpImsEmergencyRegistrationCallback()
+            throws ImsException {
+        ImsStateCallback imsStateCallback = setUpImsStateCallback();
+        imsStateCallback.onAvailable();
+        processAllMessages();
+
+        ArgumentCaptor<RegistrationManager.RegistrationCallback> callbackCaptor =
+                ArgumentCaptor.forClass(RegistrationManager.RegistrationCallback.class);
+
+        verify(mMmTelManager).registerImsEmergencyRegistrationCallback(
+                any(Executor.class), callbackCaptor.capture());
+
+        RegistrationManager.RegistrationCallback registrationCallback = callbackCaptor.getValue();
+        assertNotNull(registrationCallback);
+        return registrationCallback;
+    }
+
+    private static ImsRegistrationAttributes getImsEmergencyRegistrationAttributes() {
+        return new ImsRegistrationAttributes.Builder(ImsRegistrationImplBase.REGISTRATION_TECH_LTE)
+                .setFlagRegistrationTypeEmergency()
+                .build();
+    }
+
+    private void processAllMessages() {
+        while (!mLooper.getLooper().getQueue().isIdle()) {
+            mLooper.processAllMessages();
+        }
+    }
+
+    private static void loge(String str) {
+        Log.e(TAG, str);
+    }
+}
diff --git a/tests/src/com/android/services/telephony/domainselection/NormalCallDomainSelectorTest.java b/tests/src/com/android/services/telephony/domainselection/NormalCallDomainSelectorTest.java
index 9d5a017bc..49411bdb4 100644
--- a/tests/src/com/android/services/telephony/domainselection/NormalCallDomainSelectorTest.java
+++ b/tests/src/com/android/services/telephony/domainselection/NormalCallDomainSelectorTest.java
@@ -336,24 +336,23 @@ public class NormalCallDomainSelectorTest {
     public void testOutOfService() {
         final TestTransportSelectorCallback transportSelectorCallback =
                 new TestTransportSelectorCallback(mNormalCallDomainSelector);
-        mNormalCallDomainSelector.post(() -> {
-
-            DomainSelectionService.SelectionAttributes attributes =
-                    new DomainSelectionService.SelectionAttributes.Builder(
-                            SLOT_ID, SUB_ID_1, SELECTOR_TYPE_CALLING)
-                            .setAddress(TEST_URI)
-                            .setCallId(TEST_CALLID)
-                            .setEmergency(false)
-                            .setVideoCall(true)
-                            .setExitedFromAirplaneMode(false)
-                            .build();
-
-            ServiceState serviceState = new ServiceState();
-            serviceState.setStateOutOfService();
-            initialize(serviceState, false, false, false, false);
 
-            mNormalCallDomainSelector.selectDomain(attributes, transportSelectorCallback);
-        });
+        DomainSelectionService.SelectionAttributes attributes =
+                new DomainSelectionService.SelectionAttributes.Builder(
+                        SLOT_ID, SUB_ID_1, SELECTOR_TYPE_CALLING)
+                        .setAddress(TEST_URI)
+                        .setCallId(TEST_CALLID)
+                        .setEmergency(false)
+                        .setVideoCall(true)
+                        .setExitedFromAirplaneMode(false)
+                        .build();
+
+        ServiceState serviceState = new ServiceState();
+        serviceState.setStateOutOfService();
+        initialize(serviceState, false, false, false, false);
+
+        mNormalCallDomainSelector.selectDomain(attributes, transportSelectorCallback);
+
 
         processAllMessages();
         assertTrue(transportSelectorCallback.mSelectionTerminated);
diff --git a/tests/src/com/android/services/telephony/domainselection/OWNERS b/tests/src/com/android/services/telephony/domainselection/OWNERS
index 2a7677001..5874c98d5 100644
--- a/tests/src/com/android/services/telephony/domainselection/OWNERS
+++ b/tests/src/com/android/services/telephony/domainselection/OWNERS
@@ -1,7 +1,7 @@
 # automatically inherit owners from fw/opt/telephony
 
 hwangoo@google.com
-forestchoi@google.com
+jaesikkong@google.com
 avinashmp@google.com
 mkoon@google.com
 seheele@google.com
diff --git a/utils/satellite/README.md b/utils/satellite/README.md
index 77ee0fb3d..34a87948f 100644
--- a/utils/satellite/README.md
+++ b/utils/satellite/README.md
@@ -15,11 +15,15 @@ Directory structure
   for dumping the binary file into human-readable format.
 - `src/test` Contains the test code for the tools.
 
+`configdatagenerator`
+- `src/main` Contains the tool for generating satellite configdata protobuf file.
+- `src/test` Contains the test code for the configdatagenerator tool.
+
 Run unit tests
 =
 - Build the tools and test code: Go to the tool directory (`packages/services/Telephony/tools/
   satellite`) in the local workspace and run `mm`, e.g.,
-- Run unit tests: `$atest SatelliteToolsTests`
+- Run unit tests: `$atest SatelliteToolsTests`, `$atest SatelliteGenerateProtoTests`
 
 Data file generate tools
 =
@@ -43,6 +47,55 @@ Data file generate tools
 - Example run command: `$satellite_createsats2file --input-file s2cells.txt --s2-level 12
   --is-allowed-list true --output-file sats2.dat`
 
+`satellite_generateprotobuf`
+- Runs the `satellite_generateprotobuf` to create a binary file of TelephonyConfigProto whose format
+  is defined in telephony_config_update.proto
+- Command: `satellite_generateprotobuf --input-file <input.xml> --output-file <telephony_config.pb>`
+  - `--input-file` input XML file contains input information such as carrier id, carrier plmn,
+  allowed service list and country code list. This is example of input file.
+    ```xml
+    <satelliteconfig>
+      <!-- version -->
+       <version>14</version>
+
+      <!-- CarrierSupportedSatelliteServicesProto -->
+      <carriersupportedservices>
+        <carrier_id>1</carrier_id>
+          <providercapability>
+            <carrier_plmn>310160</carrier_plmn>
+            <service>1</service>
+          </providercapability>
+          <providercapability>
+            <carrier_plmn>310240</carrier_plmn>
+            <service>6</service>
+          </providercapability>
+      </carriersupportedservices>
+
+      <carriersupportedservices>
+        <carrier_id>1891</carrier_id>
+        <providercapability>
+          <carrier_plmn>45005</carrier_plmn>
+          <service>1</service>
+          <service>2</service>
+        </providercapability>
+      </carriersupportedservices>
+
+      <!-- SatelliteRegionProto -->
+      <satelliteregion>
+        <s2_cell_file>sats2.dat</s2_cell_file>
+        <country_code>US</country_code>
+        <country_code>KR</country_code>
+        <is_allowed>TRUE</is_allowed>
+      </satelliteregion>
+    </satelliteconfig>
+    ```
+  - `--output-file` The created binary TelephonyConfigProto file, which will be used by
+  the `ConfigUpdater` module for Satellite Project.
+- Build the tools: Go to the tool directory (`packages/services/Telephony/tools/satellite`)
+  in the local workspace and run `mm`.
+- Example run command: `satellite_generateprotobuf --input-file input.xml --output-file
+  telephony_config.pb`
+
 Debug tools
 =
 
@@ -64,4 +117,4 @@ Debug tools
 `satellite_location_lookup`
 - Check if a location is present in the input satellite S2 file.
 - Run the tool: `$satellite_location_lookup --input-file <...> --lat-degrees <...>
-  --lng-degrees <...>`
\ No newline at end of file
+  --lng-degrees <...>`
diff --git a/utils/satellite/configdatagenerator/Android.bp b/utils/satellite/configdatagenerator/Android.bp
new file mode 100644
index 000000000..b64b941fe
--- /dev/null
+++ b/utils/satellite/configdatagenerator/Android.bp
@@ -0,0 +1,49 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_team: "trendy_team_fwk_telephony",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_library_host {
+    name: "satellite-generateproto-lib",
+    srcs: [
+        "src/main/java/**/*.java",
+    ],
+    static_libs: [
+        "telephony-config-update-proto-lite",
+        "jcommander",
+    ],
+}
+
+// A tool to generate configdata protubuf file
+java_binary_host {
+    name: "satellite_generateprotobuf",
+    main_class: "com.android.telephony.tools.configdatagenerate.ConfigDataGenerator",
+    static_libs: [
+        "satellite-generateproto-lib",
+    ],
+}
+
+// Tests for ConfigDataGenerator.
+java_test_host {
+    name: "SatelliteGenerateProtoTests",
+    srcs: ["src/test/java/**/*.java"],
+    static_libs: [
+        "junit",
+        "satellite-generateproto-lib",
+    ],
+    test_suites: ["general-tests"],
+}
diff --git a/utils/satellite/configdatagenerator/TEST_MAPPING b/utils/satellite/configdatagenerator/TEST_MAPPING
new file mode 100644
index 000000000..13a3e1393
--- /dev/null
+++ b/utils/satellite/configdatagenerator/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+    "postsubmit": [
+        {
+            "name": "SatelliteGenerateProtoTests"
+        }
+    ]
+}
\ No newline at end of file
diff --git a/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ConfigDataGenerator.java b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ConfigDataGenerator.java
new file mode 100644
index 000000000..7e29e9ab1
--- /dev/null
+++ b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ConfigDataGenerator.java
@@ -0,0 +1,233 @@
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
+package com.android.telephony.tools.configdatagenerate;
+
+import com.beust.jcommander.JCommander;
+import com.beust.jcommander.Parameter;
+import com.beust.jcommander.ParameterException;
+
+import org.w3c.dom.Document;
+import org.w3c.dom.Element;
+import org.w3c.dom.Node;
+import org.w3c.dom.NodeList;
+import org.xml.sax.SAXException;
+
+import java.io.File;
+import java.io.IOException;
+import java.util.ArrayList;
+
+import javax.xml.parsers.DocumentBuilder;
+import javax.xml.parsers.DocumentBuilderFactory;
+import javax.xml.parsers.ParserConfigurationException;
+
+/** Creates a protubuf file **/
+public class ConfigDataGenerator {
+    public static final String TAG_SATELLITE_CONFIG = "satelliteconfig";
+    public static final String TAG_VERSION = "version";
+    public static final String TAG_SUPPORTED_SERVICES = "carriersupportedservices";
+    public static final String TAG_CARRIER_ID = "carrier_id";
+    public static final String TAG_PROVIDER_CAPABILITY = "providercapability";
+    public static final String TAG_CARRIER_PLMN = "carrier_plmn";
+    public static final String TAG_SERVICE = "service";
+    public static final String TAG_SATELLITE_REGION =  "satelliteregion";
+    public static final String TAG_S2_CELL_FILE = "s2_cell_file";
+    public static final String TAG_COUNTRY_CODE = "country_code";
+    public static final String TAG_IS_ALLOWED = "is_allowed";
+
+    /**
+     * Creates a protubuf file with user inputs
+     */
+    public static void main(String[] args) {
+        Arguments arguments = new Arguments();
+        JCommander.newBuilder()
+                .addObject(arguments)
+                .build()
+                .parse(args);
+        // Refer to the README file for an example of the input XML file
+        String inputFile = arguments.inputFile;
+        String outputFile = arguments.outputFile;
+        SatelliteConfigProtoGenerator.sProtoResultFile = outputFile;
+
+        Document doc = getDocumentFromInput(inputFile);
+
+        setSatelliteConfigVersion(doc);
+        createStarlinkConfigProto(doc);
+        createSkyloConfigProto(doc);
+
+        SatelliteConfigProtoGenerator.generateProto();
+
+        System.out.print("\n" + SatelliteConfigProtoGenerator.sProtoResultFile + " is generated\n");
+    }
+
+    private static class Arguments {
+        @Parameter(names = "--input-file",
+                description = "input xml file",
+                required = true)
+        public String inputFile;
+
+        @Parameter(names = "--output-file",
+                description = "out protobuf file",
+                required = false)
+        public String outputFile = SatelliteConfigProtoGenerator.sProtoResultFile;
+    }
+
+    private static Document getDocumentFromInput(String inputFile) {
+        File xmlFile = new File(inputFile);
+        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
+        DocumentBuilder dBuilder = null;
+        Document doc = null;
+        try {
+            dBuilder = dbFactory.newDocumentBuilder();
+            doc = dBuilder.parse(xmlFile);
+        } catch (ParserConfigurationException | SAXException | IOException e) {
+            throw new RuntimeException("getDocumentFromInput: e=" + e);
+        }
+        doc.getDocumentElement().normalize();
+        return doc;
+    }
+
+    /**
+     * Set version after getting version from the input document
+     *
+     * @param doc the input document. Format of document should be
+     * <pre>
+     * &lt;version&gt;value1&lt;/version&gt;
+     * </pre>
+     */
+    public static void setSatelliteConfigVersion(Document doc) {
+        NodeList versionList = doc.getElementsByTagName(TAG_VERSION);
+        Node versionNode = versionList.item(0);
+        System.out.println("Version: " + versionNode.getTextContent());
+        SatelliteConfigProtoGenerator.sVersion = Integer.parseInt(versionNode.getTextContent());
+    }
+
+
+    /**
+     * Creates a list of ServiceProto from the input document
+     *
+     * @param doc the input document. Format of document should be
+     * <pre>
+     * &lt;carriersupportedservices&gt;
+     *   &lt;carrier_id&gt;value1&lt;/carrier_id&gt;
+     *   &lt;providercapability&gt;
+     *     &lt;carrier_plmn&gt;value2&lt;/carrier_plmn&gt;
+     *     &lt;service&gt;value3&lt;/service&gt;
+     *   &lt;/providercapability&gt;
+     * &lt;/carriersupportedservices&gt;
+     * </pre>
+     */
+    public static void createStarlinkConfigProto(Document doc) {
+        NodeList carrierServicesList = doc.getElementsByTagName(TAG_SUPPORTED_SERVICES);
+        SatelliteConfigProtoGenerator.sServiceProtoList = new ArrayList<>();
+        for (int i = 0; i < carrierServicesList.getLength(); i++) {
+            Node carrierServiceNode = carrierServicesList.item(i);
+            if (carrierServiceNode.getNodeType() == Node.ELEMENT_NODE) {
+                Element carrierServiceElement = (Element) carrierServiceNode;
+                String carrierId = carrierServiceElement.getElementsByTagName(TAG_CARRIER_ID)
+                        .item(0).getTextContent();
+                System.out.println("\nCarrier ID: " + carrierId);
+
+                NodeList providerCapabilityList = carrierServiceElement.getElementsByTagName(
+                        TAG_PROVIDER_CAPABILITY);
+                ProviderCapabilityProto[] capabilityProtoList =
+                        new ProviderCapabilityProto[providerCapabilityList.getLength()];
+                for (int j = 0; j < providerCapabilityList.getLength(); j++) {
+                    Node providerCapabilityNode = providerCapabilityList.item(j);
+                    if (providerCapabilityNode.getNodeType() == Node.ELEMENT_NODE) {
+                        Element providerCapabilityElement = (Element) providerCapabilityNode;
+                        String carrierPlmn = providerCapabilityElement.getElementsByTagName(
+                                TAG_CARRIER_PLMN).item(0).getTextContent();
+                        System.out.println("  Carrier PLMN: " + carrierPlmn);
+                        if (!Util.isValidPlmn(carrierPlmn)) {
+                            throw new ParameterException("Invalid plmn:" + carrierPlmn);
+                        }
+
+                        NodeList allowedServicesList = providerCapabilityElement
+                                .getElementsByTagName(TAG_SERVICE);
+                        System.out.print("    Allowed services: ");
+                        int[] allowedServiceArray = new int[allowedServicesList.getLength()];
+                        for (int k = 0; k < allowedServicesList.getLength(); k++) {
+                            int service = Integer.parseInt(allowedServicesList.item(k)
+                                    .getTextContent());
+                            System.out.print(service + " ");
+                            if (!Util.isValidService(service)) {
+                                throw new ParameterException("Invalid service:" + service);
+                            }
+                            allowedServiceArray[k] = service;
+                        }
+                        System.out.println();
+                        ProviderCapabilityProto capabilityProto =
+                                new ProviderCapabilityProto(carrierPlmn, allowedServiceArray);
+                        capabilityProtoList[j] = capabilityProto;
+                    }
+                }
+                ServiceProto serviceProto = new ServiceProto(Integer.parseInt(carrierId),
+                        capabilityProtoList);
+                SatelliteConfigProtoGenerator.sServiceProtoList.add(serviceProto);
+            }
+        }
+    }
+
+    /**
+     * Creates a RegionProto from the input document
+     *
+     * @param doc the input document. Format of document should be
+     * <pre>
+     * &lt;satelliteregion&gt;
+     *   &lt;s2_cell_file&gt;value1&lt;/s2_cell_file&gt;
+     *   &lt;country_code&gt;value2&lt;/country_code&gt;
+     *   &lt;country_code&gt;value3&lt;/country_code&gt;
+     *   &lt;is_allowed&gt;value4&lt;/is_allowed&gt;
+     * &lt;/satelliteregion&gt;
+     * </pre>
+     */
+    public static void createSkyloConfigProto(Document doc) {
+        NodeList satelliteRegionList = doc.getElementsByTagName(TAG_SATELLITE_REGION);
+        Node satelliteRegionNode = satelliteRegionList.item(0);
+        if (satelliteRegionNode != null && satelliteRegionNode.getNodeType() == Node.ELEMENT_NODE) {
+            Element satelliteRegionElement = (Element) satelliteRegionNode;
+            String s2CellFileName = satelliteRegionElement.getElementsByTagName(TAG_S2_CELL_FILE)
+                    .item(0).getTextContent();
+            String isAllowedString = satelliteRegionElement.getElementsByTagName(TAG_IS_ALLOWED)
+                    .item(0).getTextContent();
+            boolean isAllowed = false;
+            if (isAllowedString.equals("TRUE")) {
+                isAllowed = true;
+            }
+            System.out.println("\nSatellite Region:");
+            System.out.println("  S2 Cell File: " + s2CellFileName);
+            System.out.println("  Is Allowed: " + isAllowed);
+
+            NodeList countryCodesList = satelliteRegionElement.getElementsByTagName(
+                    TAG_COUNTRY_CODE);
+            String[] listCountryCode = new String[countryCodesList.getLength()];
+            System.out.print("  Country Codes: ");
+            for (int k = 0; k < countryCodesList.getLength(); k++) {
+                String countryCode = countryCodesList.item(k).getTextContent();
+                System.out.print(countryCode + " ");
+                if (!Util.isValidCountryCode(countryCode)) {
+                    throw new ParameterException("Invalid countryCode:" + countryCode);
+                }
+                listCountryCode[k] = countryCode;
+            }
+            System.out.println();
+            SatelliteConfigProtoGenerator.sRegionProto =
+                    new RegionProto(s2CellFileName, listCountryCode, isAllowed);
+        }
+    }
+}
+
diff --git a/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ProviderCapabilityProto.java b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ProviderCapabilityProto.java
new file mode 100644
index 000000000..9fe692d6e
--- /dev/null
+++ b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ProviderCapabilityProto.java
@@ -0,0 +1,28 @@
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
+package com.android.telephony.tools.configdatagenerate;
+
+public class ProviderCapabilityProto {
+
+    public String mPlmn;
+    public int[] mAllowedServices;
+
+    public ProviderCapabilityProto(String plmn, int[] allowedServices) {
+        mPlmn = plmn;
+        mAllowedServices = allowedServices;
+    }
+}
diff --git a/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/RegionProto.java b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/RegionProto.java
new file mode 100644
index 000000000..be3b0cc5d
--- /dev/null
+++ b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/RegionProto.java
@@ -0,0 +1,30 @@
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
+package com.android.telephony.tools.configdatagenerate;
+
+public class RegionProto {
+
+    String mS2CellFileName;
+    String[] mCountryCodeList;
+    boolean mIsAllowed;
+
+    public RegionProto(String s2CellFileName, String[] countryCodeList, boolean isAllowed) {
+        mS2CellFileName = s2CellFileName;
+        mCountryCodeList = countryCodeList;
+        mIsAllowed = isAllowed;
+    }
+}
diff --git a/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/SatelliteConfigProtoGenerator.java b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/SatelliteConfigProtoGenerator.java
new file mode 100644
index 000000000..740e2ea94
--- /dev/null
+++ b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/SatelliteConfigProtoGenerator.java
@@ -0,0 +1,155 @@
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
+package com.android.telephony.tools.configdatagenerate;
+
+import com.android.internal.telephony.satellite.SatelliteConfigData;
+
+import com.google.protobuf.ByteString;
+
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.FileOutputStream;
+import java.io.IOException;
+import java.util.ArrayList;
+
+public class SatelliteConfigProtoGenerator {
+
+    private static final String TAG = "ProtoGenerator";
+    public static String sProtoResultFile = "telephony_config.pb";
+    public static int sVersion;
+    public static ArrayList<ServiceProto> sServiceProtoList;
+    public static RegionProto sRegionProto;
+
+    /**
+     * Generate Protobuf.
+     *
+     * The output file is a binary file of TelephonyConfigProto.
+     *
+     * The format of TelephonyConfigProto is defined in
+     * https://source.corp.google.com/android/frameworks/opt/telephony/proto/src/
+     * telephony_config_update.proto
+     */
+    public static void generateProto() {
+        SatelliteConfigData.TelephonyConfigProto.Builder telephonyConfigBuilder =
+                SatelliteConfigData.TelephonyConfigProto.newBuilder();
+        SatelliteConfigData.SatelliteConfigProto.Builder satelliteConfigBuilder =
+                SatelliteConfigData.SatelliteConfigProto.newBuilder();
+
+        satelliteConfigBuilder.setVersion(sVersion);    // Input version
+
+        if (sServiceProtoList != null) {
+            // carrierSupportedSatelliteServiceBuilder
+            SatelliteConfigData.CarrierSupportedSatelliteServicesProto.Builder
+                    carrierSupportedSatelliteServiceBuilder =
+                    SatelliteConfigData.CarrierSupportedSatelliteServicesProto.newBuilder();
+            for (int i = 0; i < sServiceProtoList.size(); i++) {
+                ServiceProto proto = sServiceProtoList.get(i);
+                carrierSupportedSatelliteServiceBuilder.setCarrierId(proto.mCarrierId);
+                SatelliteConfigData.SatelliteProviderCapabilityProto.Builder
+                        satelliteProviderCapabilityBuilder =
+                        SatelliteConfigData.SatelliteProviderCapabilityProto.newBuilder();
+                ProviderCapabilityProto[] capabilityProtoList = proto.mCapabilityProtoList;
+                for (int j = 0; j < capabilityProtoList.length; j++) {
+                    ProviderCapabilityProto capabilityProto = capabilityProtoList[j];
+                    satelliteProviderCapabilityBuilder.setCarrierPlmn(capabilityProto.mPlmn);
+                    int[] allowedServiceList = capabilityProto.mAllowedServices;
+                    for (int k = 0; k < allowedServiceList.length; k++) {
+                        satelliteProviderCapabilityBuilder
+                                .addAllowedServices(allowedServiceList[k]);
+                    }
+                    carrierSupportedSatelliteServiceBuilder
+                            .addSupportedSatelliteProviderCapabilities(
+                                    satelliteProviderCapabilityBuilder);
+                    satelliteProviderCapabilityBuilder.clear();
+                }
+                satelliteConfigBuilder.addCarrierSupportedSatelliteServices(
+                        carrierSupportedSatelliteServiceBuilder);
+                carrierSupportedSatelliteServiceBuilder.clear();
+            }
+        } else {
+            System.out.print("ServiceProtoList does not exist");
+        }
+
+        if (sRegionProto != null) {
+            // satelliteRegionBuilder
+            SatelliteConfigData.SatelliteRegionProto.Builder satelliteRegionBuilder =
+                    SatelliteConfigData.SatelliteRegionProto.newBuilder();
+            byte[] binaryData;
+            try {
+                binaryData = readFileToByteArray(sRegionProto.mS2CellFileName);
+            } catch (IOException e) {
+                throw new RuntimeException("Got exception in reading the file "
+                        + sRegionProto.mS2CellFileName + ", e=" + e);
+            }
+            if (binaryData != null) {
+                satelliteRegionBuilder.setS2CellFile(ByteString.copyFrom(binaryData));
+            }
+
+            String[] countryCodeList = sRegionProto.mCountryCodeList;
+            for (int i = 0; i < countryCodeList.length; i++) {
+                satelliteRegionBuilder.addCountryCodes(countryCodeList[i]);
+            }
+            satelliteRegionBuilder.setIsAllowed(sRegionProto.mIsAllowed);
+            satelliteConfigBuilder.setDeviceSatelliteRegion(satelliteRegionBuilder);
+        } else {
+            System.out.print("RegionProto does not exist");
+        }
+
+        telephonyConfigBuilder.setSatellite(satelliteConfigBuilder);
+
+        writeToResultFile(telephonyConfigBuilder);
+    }
+
+    private static void writeToResultFile(SatelliteConfigData
+            .TelephonyConfigProto.Builder telephonyConfigBuilder) {
+        try {
+            File file = new File(sProtoResultFile);
+            if (file.exists()) {
+                file.delete();
+            }
+            FileOutputStream fos = new FileOutputStream(file);
+            SatelliteConfigData.TelephonyConfigProto telephonyConfigData =
+                    telephonyConfigBuilder.build();
+            telephonyConfigData.writeTo(fos);
+
+            fos.close();
+        } catch (Exception e) {
+            throw new RuntimeException("Got exception in writing the file "
+                    + sProtoResultFile + ", e=" + e);
+        }
+    }
+
+    private static byte[] readFileToByteArray(String fileName) throws IOException {
+        File sat2File = new File(fileName);
+        if (!sat2File.exists()) {
+            throw new IOException("sat2File " + fileName + " does not exist");
+        }
+
+        if (sat2File.exists() && sat2File.canRead()) {
+            FileInputStream fileInputStream = new FileInputStream(sat2File);
+            long fileSize = fileInputStream.available();
+            byte[] bytes = new byte[(int) fileSize];
+            int bytesRead = fileInputStream.read(bytes);
+            fileInputStream.close();
+            if (bytesRead != fileSize) {
+                throw new IOException("file read fail: " + sat2File.getCanonicalPath());
+            }
+            return bytes;
+        }
+        return null;
+    }
+}
diff --git a/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ServiceProto.java b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ServiceProto.java
new file mode 100644
index 000000000..a17e1dd90
--- /dev/null
+++ b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ServiceProto.java
@@ -0,0 +1,28 @@
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
+package com.android.telephony.tools.configdatagenerate;
+
+public class ServiceProto {
+
+    public int mCarrierId;
+    public ProviderCapabilityProto[] mCapabilityProtoList;
+
+    public ServiceProto(int carrierId, ProviderCapabilityProto[] capabilityProtolist) {
+        mCarrierId = carrierId;
+        mCapabilityProtoList = capabilityProtolist;
+    }
+}
diff --git a/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/Util.java b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/Util.java
new file mode 100644
index 000000000..925e8287c
--- /dev/null
+++ b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/Util.java
@@ -0,0 +1,68 @@
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
+package com.android.telephony.tools.configdatagenerate;
+
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
+
+public class Util {
+
+    public static final int SERVICE_TYPE_VOICE = 1;
+    public static final int SERVICE_TYPE_MMS = 6;
+
+    private static final int FIRST_SERVICE_TYPE = SERVICE_TYPE_VOICE;
+    private static final int LAST_SERVICE_TYPE = SERVICE_TYPE_MMS;
+
+    private static boolean isValidPattern(String input, String regex) {
+        if ((input == null) || (regex == null)) {
+            return false;
+        }
+        Pattern pattern = Pattern.compile(regex);
+        Matcher matcher = pattern.matcher(input);
+        if (!matcher.matches()) {
+            return false;
+        }
+        return true;
+    }
+
+    /**
+     * @param countryCode two letters country code based on the ISO 3166-1.
+     * @return {@code true} if the countryCode is valid {@code false} otherwise.
+     */
+    public static boolean isValidCountryCode(String countryCode) {
+        return isValidPattern(countryCode, "^[A-Za-z]{2}$");
+    }
+
+    /**
+     * @param plmn target plmn for validation.
+     * @return {@code true} if the target plmn is valid {@code false} otherwise.
+     */
+    public static boolean isValidPlmn(String plmn) {
+        return isValidPattern(plmn, "^(?:[0-9]{3})(?:[0-9]{2}|[0-9]{3})$");
+    }
+
+    /**
+     * @param serviceType target serviceType for validation.
+     * @return {@code true} if the target serviceType is valid {@code false} otherwise.
+     */
+    public static boolean isValidService(int serviceType) {
+        if (serviceType < FIRST_SERVICE_TYPE || serviceType > LAST_SERVICE_TYPE) {
+            return false;
+        }
+        return true;
+    }
+}
diff --git a/utils/satellite/configdatagenerator/src/test/java/com/android/telephony/tools/configdatagenerate/ConfigDataGeneratorTest.java b/utils/satellite/configdatagenerator/src/test/java/com/android/telephony/tools/configdatagenerate/ConfigDataGeneratorTest.java
new file mode 100644
index 000000000..f588815fb
--- /dev/null
+++ b/utils/satellite/configdatagenerator/src/test/java/com/android/telephony/tools/configdatagenerate/ConfigDataGeneratorTest.java
@@ -0,0 +1,324 @@
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
+package com.android.telephony.tools.configdatagenerate;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.fail;
+
+import com.android.internal.telephony.satellite.SatelliteConfigData.CarrierSupportedSatelliteServicesProto;
+import com.android.internal.telephony.satellite.SatelliteConfigData.SatelliteConfigProto;
+import com.android.internal.telephony.satellite.SatelliteConfigData.SatelliteProviderCapabilityProto;
+import com.android.internal.telephony.satellite.SatelliteConfigData.SatelliteRegionProto;
+import com.android.internal.telephony.satellite.SatelliteConfigData.TelephonyConfigProto;
+
+import com.google.protobuf.ByteString;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.w3c.dom.Document;
+import org.w3c.dom.Element;
+
+import java.io.File;
+import java.io.FileOutputStream;
+import java.io.IOException;
+import java.nio.file.FileVisitResult;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.nio.file.Paths;
+import java.nio.file.SimpleFileVisitor;
+import java.nio.file.attribute.BasicFileAttributes;
+
+import javax.xml.parsers.DocumentBuilder;
+import javax.xml.parsers.DocumentBuilderFactory;
+import javax.xml.transform.Transformer;
+import javax.xml.transform.TransformerFactory;
+import javax.xml.transform.dom.DOMSource;
+import javax.xml.transform.stream.StreamResult;
+
+public class ConfigDataGeneratorTest {
+    private Path mTempDirPath;
+
+    @Before
+    public void setUp() throws IOException {
+        mTempDirPath = createTempDir(this.getClass());
+    }
+
+    @After
+    public void tearDown() throws IOException {
+        if (mTempDirPath != null) {
+            deleteDirectory(mTempDirPath);
+        }
+    }
+
+    @Test
+    public void testConfigDataGeneratorWithInvalidPlmn() throws Exception {
+        Path inputDirPath = mTempDirPath.resolve("input");
+        Files.createDirectory(inputDirPath);
+        Path inputFilePath = inputDirPath.resolve("test_input.xml");
+        Path inputS2CellFilePath = inputDirPath.resolve("sats2.dat");
+
+        Path outputDirPath = mTempDirPath.resolve("output");
+        Files.createDirectory(outputDirPath);
+        Path outputFilePath = outputDirPath.resolve("test_out.pb");
+        String inputfileName = inputFilePath.toAbsolutePath().toString();
+        String inputS2CellFileName = inputS2CellFilePath.toAbsolutePath().toString();
+        File inputFile = new File(inputfileName);
+        ByteString inputByteStringForS2Cell = ByteString.copyFromUtf8("Test ByteString!");
+        writeByteStringToFile(inputS2CellFileName, inputByteStringForS2Cell);
+
+        createInputXml(inputFile, 14, 1, "310062222", 1,
+                "US", true, inputS2CellFileName);
+        String[] args = {
+                "--input-file", inputFilePath.toAbsolutePath().toString(),
+                "--output-file", outputFilePath.toAbsolutePath().toString()
+        };
+        try {
+            ConfigDataGenerator.main(args);
+        } catch (Exception ex) {
+            // Expected exception because input plmn is invalid
+            return;
+        }
+        fail("Exception should have been caught");
+    }
+
+    @Test
+    public void testConfigDataGeneratorWithInvalidService() throws Exception {
+        Path inputDirPath = mTempDirPath.resolve("input");
+        Files.createDirectory(inputDirPath);
+        Path inputFilePath = inputDirPath.resolve("test_input.xml");
+        Path inputS2CellFilePath = inputDirPath.resolve("sats2.dat");
+
+        Path outputDirPath = mTempDirPath.resolve("output");
+        Files.createDirectory(outputDirPath);
+        Path outputFilePath = outputDirPath.resolve("test_out.pb");
+        String inputfileName = inputFilePath.toAbsolutePath().toString();
+        String inputS2CellFileName = inputS2CellFilePath.toAbsolutePath().toString();
+        File inputFile = new File(inputfileName);
+        ByteString inputByteStringForS2Cell = ByteString.copyFromUtf8("Test ByteString!");
+        writeByteStringToFile(inputS2CellFileName, inputByteStringForS2Cell);
+
+        createInputXml(inputFile, 14, 1, "31006", -1,
+                "US", true, inputS2CellFileName);
+        String[] args = {
+                "--input-file", inputFilePath.toAbsolutePath().toString(),
+                "--output-file", outputFilePath.toAbsolutePath().toString()
+        };
+        try {
+            ConfigDataGenerator.main(args);
+        } catch (Exception ex) {
+            // Expected exception because input allowed service is invalid
+            return;
+        }
+        fail("Exception should have been caught");
+    }
+
+    @Test
+    public void testConfigDataGeneratorWithInvalidCountryCode() throws Exception {
+        Path inputDirPath = mTempDirPath.resolve("input");
+        Files.createDirectory(inputDirPath);
+        Path inputFilePath = inputDirPath.resolve("test_input.xml");
+        Path inputS2CellFilePath = inputDirPath.resolve("sats2.dat");
+
+        Path outputDirPath = mTempDirPath.resolve("output");
+        Files.createDirectory(outputDirPath);
+        Path outputFilePath = outputDirPath.resolve("test_out.pb");
+        String inputfileName = inputFilePath.toAbsolutePath().toString();
+        String inputS2CellFileName = inputS2CellFilePath.toAbsolutePath().toString();
+        File inputFile = new File(inputfileName);
+        ByteString inputByteStringForS2Cell = ByteString.copyFromUtf8("Test ByteString!");
+        writeByteStringToFile(inputS2CellFileName, inputByteStringForS2Cell);
+
+        createInputXml(inputFile, 14, 1, "31006", 1,
+                "USSSS", true, inputS2CellFileName);
+        String[] args = {
+                "--input-file", inputFilePath.toAbsolutePath().toString(),
+                "--output-file", outputFilePath.toAbsolutePath().toString()
+        };
+        try {
+            ConfigDataGenerator.main(args);
+        } catch (Exception ex) {
+            // Expected exception because input country code is invalid
+            return;
+        }
+        fail("Exception should have been caught");
+    }
+
+    @Test
+    public void testConfigDataGeneratorWithValidInput() throws Exception {
+        Path inputDirPath = mTempDirPath.resolve("input");
+        Files.createDirectory(inputDirPath);
+        Path inputFilePath = inputDirPath.resolve("test_input.xml");
+        Path inputS2CellFilePath = inputDirPath.resolve("sats2.dat");
+
+        Path outputDirPath = mTempDirPath.resolve("output");
+        Files.createDirectory(outputDirPath);
+        Path outputFilePath = outputDirPath.resolve("test_out.pb");
+        String inputfileName = inputFilePath.toAbsolutePath().toString();
+        String inputS2CellFileName = inputS2CellFilePath.toAbsolutePath().toString();
+        File inputFile = new File(inputfileName);
+        String outputFileName = outputFilePath.toAbsolutePath().toString();
+
+
+        int inputVersion = 14;
+        int inputCarrierId = 1;
+        String inputPlmn = "31006";
+        int inputAllowedService = 1;
+        String inputCountryCode = "US";
+        boolean inputIsAllowed = true;
+        ByteString inputByteStringForS2Cell = ByteString.copyFromUtf8("Test ByteString!");
+        writeByteStringToFile(inputS2CellFileName, inputByteStringForS2Cell);
+        createInputXml(inputFile, inputVersion, inputCarrierId, inputPlmn, inputAllowedService,
+                inputCountryCode, inputIsAllowed, inputS2CellFileName);
+        String[] args = {
+                "--input-file", inputFilePath.toAbsolutePath().toString(),
+                "--output-file", outputFilePath.toAbsolutePath().toString()
+        };
+        try {
+            ConfigDataGenerator.main(args);
+        } catch (Exception ex) {
+            fail("Unexpected exception when executing the tool ex=" + ex);
+        }
+
+        Path filePath = Paths.get(outputFileName);
+        byte[] fileBytes = Files.readAllBytes(filePath);
+        TelephonyConfigProto telephonyConfigProto = TelephonyConfigProto.parseFrom(fileBytes);
+        SatelliteConfigProto satelliteConfigProto = telephonyConfigProto.getSatellite();
+        int version  = satelliteConfigProto.getVersion();
+        assertEquals(inputVersion, version);
+        CarrierSupportedSatelliteServicesProto serviceProto =
+                satelliteConfigProto.getCarrierSupportedSatelliteServices(0);
+        int carrierId = serviceProto.getCarrierId();
+        assertEquals(inputCarrierId, carrierId);
+        SatelliteProviderCapabilityProto providerCapabilityProto =
+                serviceProto.getSupportedSatelliteProviderCapabilities(0);
+        String plmn = providerCapabilityProto.getCarrierPlmn();
+        assertEquals(inputPlmn, plmn);
+        int allowedService = providerCapabilityProto.getAllowedServices(0);
+        assertEquals(inputAllowedService, allowedService);
+
+        SatelliteRegionProto regionProto = satelliteConfigProto.getDeviceSatelliteRegion();
+        String countryCode = regionProto.getCountryCodes(0);
+        assertEquals(inputCountryCode, countryCode);
+        ByteString s2cellfile = regionProto.getS2CellFile();
+        byte[] fileBytesForInputS2CellFile = Files.readAllBytes(Paths.get(inputS2CellFileName));
+        ByteString inputS2CellFile = ByteString.copyFrom(fileBytesForInputS2CellFile);
+        assertEquals(inputS2CellFile, s2cellfile);
+        boolean isAllowed = regionProto.getIsAllowed();
+        assertEquals(inputIsAllowed, isAllowed);
+    }
+
+    private void createInputXml(File outputFile, int version, int carrierId, String plmn,
+            int allowedService, String countryCode, boolean isAllowed, String inputS2CellFileName) {
+        try {
+            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
+            DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
+
+            // Create Document and Root Element
+            Document doc = docBuilder.newDocument();
+            Element rootElement = doc.createElement(ConfigDataGenerator.TAG_SATELLITE_CONFIG);
+            doc.appendChild(rootElement);
+
+            // Add <version>
+            Element versionElement = doc.createElement(ConfigDataGenerator.TAG_VERSION);
+            versionElement.appendChild(doc.createTextNode(String.valueOf(version)));
+            rootElement.appendChild(versionElement);
+
+            // Add <carriersupportedservices>
+            rootElement.appendChild(
+                    createCarrierSupportedServices(doc, carrierId, plmn, allowedService));
+
+            // Add <satelliteregion>
+            Element satelliteRegion = doc.createElement(ConfigDataGenerator.TAG_SATELLITE_REGION);
+            satelliteRegion.appendChild(
+                    createElementWithText(doc, ConfigDataGenerator.TAG_S2_CELL_FILE,
+                            inputS2CellFileName));
+            satelliteRegion.appendChild(
+                    createElementWithText(doc, ConfigDataGenerator.TAG_COUNTRY_CODE, countryCode));
+            satelliteRegion.appendChild(
+                    createElementWithText(doc, ConfigDataGenerator.TAG_IS_ALLOWED,
+                            isAllowed ? "TRUE" : "FALSE"));
+            rootElement.appendChild(satelliteRegion);
+
+            // Write XML to File
+            TransformerFactory transformerFactory = TransformerFactory.newInstance();
+            Transformer transformer = transformerFactory.newTransformer();
+            DOMSource source = new DOMSource(doc);
+            StreamResult result = new StreamResult(outputFile);
+            transformer.transform(source, result);
+
+        } catch (Exception e) {
+            throw new RuntimeException("Got exception in creating input file , e=" + e);
+        }
+    }
+
+    private static Element createCarrierSupportedServices(Document doc, int carrierId,
+            String carrierPlmn, int... services) {
+        Element carrierSupportedServices = doc.createElement(
+                ConfigDataGenerator.TAG_SUPPORTED_SERVICES);
+        carrierSupportedServices.appendChild(createElementWithText(doc,
+                ConfigDataGenerator.TAG_CARRIER_ID, String.valueOf(carrierId)));
+
+        Element providerCapability = doc.createElement(ConfigDataGenerator.TAG_PROVIDER_CAPABILITY);
+        providerCapability.appendChild(createElementWithText(doc,
+                ConfigDataGenerator.TAG_CARRIER_PLMN, carrierPlmn));
+        for (int service : services) {
+            providerCapability.appendChild(createElementWithText(doc,
+                    ConfigDataGenerator.TAG_SERVICE, String.valueOf(service)));
+        }
+        carrierSupportedServices.appendChild(providerCapability);
+
+        return carrierSupportedServices;
+    }
+
+    private static Element createElementWithText(Document doc, String tagName, String textContent) {
+        Element element = doc.createElement(tagName);
+        element.appendChild(doc.createTextNode(textContent));
+        return element;
+    }
+
+    private static Path createTempDir(Class<?> testClass) throws IOException {
+        return Files.createTempDirectory(testClass.getSimpleName());
+    }
+
+    private static void deleteDirectory(Path dir) throws IOException {
+        Files.walkFileTree(dir, new SimpleFileVisitor<>() {
+            @Override
+            public FileVisitResult visitFile(Path path, BasicFileAttributes basicFileAttributes)
+                    throws IOException {
+                Files.deleteIfExists(path);
+                return FileVisitResult.CONTINUE;
+            }
+
+            @Override
+            public FileVisitResult postVisitDirectory(Path path, IOException e) throws IOException {
+                Files.delete(path);
+                return FileVisitResult.CONTINUE;
+            }
+        });
+        assertFalse(Files.exists(dir));
+    }
+
+    private void writeByteStringToFile(String fileName, ByteString byteString) {
+        try (FileOutputStream fos = new FileOutputStream(fileName)) {
+            fos.write(byteString.toByteArray());
+        } catch (IOException e) {
+            System.err.println("Error writing to file: " + e.getMessage());
+        }
+    }
+}
diff --git a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2LocationLookup.java b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2LocationLookup.java
index 444ff8dff..713cca82b 100644
--- a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2LocationLookup.java
+++ b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2LocationLookup.java
@@ -41,7 +41,8 @@ public final class SatS2LocationLookup {
                      SatS2RangeFileReader.open(new File(arguments.inputFile))) {
             S2CellId s2CellId = getS2CellId(arguments.latDegrees, arguments.lngDegrees,
                     satS2RangeFileReader.getS2Level());
-            System.out.println("s2CellId=" + Long.toUnsignedString(s2CellId.id()));
+            System.out.println("s2CellId=" + Long.toUnsignedString(s2CellId.id())
+                    + ", token=" + s2CellId.toToken());
             if (satS2RangeFileReader.findEntryByCellId(s2CellId.id()) == null) {
                 System.out.println("The input file does not contain the input location");
             } else {
```

