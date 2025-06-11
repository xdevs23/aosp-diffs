```diff
diff --git a/Android.bp b/Android.bp
index 2c41fb91d..fb49da90a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_fwk_telephony",
     // See: http://go/android-license-faq
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
@@ -90,10 +91,10 @@ android_app {
 // Allow other applications to use public constants from SlicePurchaseController
 java_library {
     name: "SlicePurchaseController",
-    srcs: ["src/com/android/phone/slice/*.java",],
+    srcs: ["src/com/android/phone/slice/*.java"],
     libs: [
         "telephony-common",
-        "service-entitlement"
+        "service-entitlement",
     ],
 }
 
@@ -101,4 +102,3 @@ platform_compat_config {
     name: "TeleService-platform-compat-config",
     src: ":TeleService",
 }
-
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index feb5a7870..e8af01fa0 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -191,6 +191,7 @@
             android:allowBackup="false"
             android:supportsRtl="true"
             android:usesCleartextTraffic="true"
+            android:enableOnBackInvokedCallback="false"
             android:defaultToDeviceProtectedStorage="true"
             android:directBootAware="true">
 
@@ -280,6 +281,16 @@
             </intent-filter>
         </activity>
 
+        <activity android:name="com.android.phone.settings.SatelliteConfigViewer"
+            android:label="@string/satellite_config_viewer"
+            android:exported="true"
+            android:theme="@style/DialerSettingsLight">
+            <intent-filter>
+                <action android:name="android.intent.action.VIEW" />
+                <category android:name="android.intent.category.DEFAULT" />
+            </intent-filter>
+        </activity>
+
         <activity android:name="CdmaCallOptions"
                 android:label="@string/cdma_options"
                 android:exported="false"
@@ -586,6 +597,7 @@
         <!-- Update configuration data file -->
         <receiver android:name="com.android.internal.telephony.configupdate.TelephonyConfigUpdateInstallReceiver"
             android:exported="true"
+            androidprv:systemUserOnly="true"
             android:permission="android.permission.UPDATE_CONFIG">
             <intent-filter>
                 <action android:name="android.os.action.UPDATE_CONFIG" />
diff --git a/OWNERS b/OWNERS
index 96033ab86..dd12ee3b7 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,4 +2,4 @@ include platform/frameworks/opt/telephony:/OWNERS
 
 per-file *SimPhonebookProvider* = file:platform/packages/apps/Contacts:/OWNERS
 
-per-file config.xml=hwangoo@google.com,forestchoi@google.com,avinashmp@google.com,mkoon@google.com,seheele@google.com,radhikaagrawal@google.com,jdyou@google.com
+per-file config.xml=hwangoo@google.com,avinashmp@google.com,mkoon@google.com,seheele@google.com,radhikaagrawal@google.com,jdyou@google.com
diff --git a/res/layout/change_sim_pin_screen.xml b/res/layout/change_sim_pin_screen.xml
index 8c943e1b5..6653dc449 100644
--- a/res/layout/change_sim_pin_screen.xml
+++ b/res/layout/change_sim_pin_screen.xml
@@ -16,7 +16,8 @@
 
 <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
         android:layout_width="match_parent"
-        android:layout_height="match_parent">
+        android:layout_height="match_parent"
+        android:fitsSystemWindows="true">
         
     <ScrollView xmlns:android="http://schemas.android.com/apk/res/android" android:id="@+id/scroll"
             android:layout_width="match_parent"
diff --git a/res/layout/delete_fdn_contact_screen.xml b/res/layout/delete_fdn_contact_screen.xml
index ec8a2e014..5abad10c0 100644
--- a/res/layout/delete_fdn_contact_screen.xml
+++ b/res/layout/delete_fdn_contact_screen.xml
@@ -4,9 +4,9 @@
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
      You may obtain a copy of the License at
-  
+
           http://www.apache.org/licenses/LICENSE-2.0
-  
+
      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
@@ -16,8 +16,9 @@
 
 <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
-    android:layout_height="match_parent">
-    
+    android:layout_height="match_parent"
+    android:fitsSystemWindows="true">
+
     <!-- Modified to remove the status field in favor of a toast.-->
-    
+
 </RelativeLayout>
diff --git a/res/layout/edit_fdn_contact_screen.xml b/res/layout/edit_fdn_contact_screen.xml
index c7ba0d468..6635d4d79 100644
--- a/res/layout/edit_fdn_contact_screen.xml
+++ b/res/layout/edit_fdn_contact_screen.xml
@@ -19,6 +19,7 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:layout_margin="16dp"
+    android:fitsSystemWindows="true"
     android:orientation="vertical"
     android:gravity="center">
 
diff --git a/res/layout/enable_sim_pin_screen.xml b/res/layout/enable_sim_pin_screen.xml
index 417cbd9ef..fc2e4f268 100644
--- a/res/layout/enable_sim_pin_screen.xml
+++ b/res/layout/enable_sim_pin_screen.xml
@@ -16,7 +16,8 @@
 
 <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
-    android:layout_height="match_parent">
+    android:layout_height="match_parent"
+    android:fitsSystemWindows="true">
 
     <!-- Keyboard Version -->
     <LinearLayout android:id="@+id/pinc"
diff --git a/res/layout/get_pin2_screen.xml b/res/layout/get_pin2_screen.xml
index eecf73600..3f6787bb7 100644
--- a/res/layout/get_pin2_screen.xml
+++ b/res/layout/get_pin2_screen.xml
@@ -19,6 +19,7 @@
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:layout_margin="16dp"
+    android:fitsSystemWindows="true"
     android:orientation="vertical"
     android:gravity="center">
 
diff --git a/res/layout/radio_info.xml b/res/layout/radio_info.xml
index ac1f3f335..9084891f8 100644
--- a/res/layout/radio_info.xml
+++ b/res/layout/radio_info.xml
@@ -268,6 +268,42 @@
                 android:layout_height="wrap_content"
                 android:text="@string/mock_carrier_roaming_satellite_string"/>
 
+        <!-- Force to use SIM data in Mock satellite mode -->
+        <Switch android:id="@+id/satellite_data_controller_switch"
+            android:textSize="14sp"
+            android:layout_marginTop="8dip"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:text="@string/choose_satellite_data_mode"/>
+        <RadioGroup
+            android:id="@+id/satellite_data_controller"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginTop="8dip"
+            android:visibility="gone"
+            android:orientation="horizontal">
+
+            <RadioButton
+                android:id="@+id/satellite_data_restricted"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:layout_marginRight="4dip"
+                android:text="@string/satellite_data_restricted_string" />
+
+            <RadioButton
+                android:id="@+id/satellite_data_constrained"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:layout_marginRight="4dip"
+                android:text="@string/satellite_data_constrained_string" />
+
+            <RadioButton
+                android:id="@+id/satellite_data_unConstrained"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:text="@string/satellite_data_unConstrained_string" />
+        </RadioGroup>
+
         <!-- ESOS -->
         <Button android:id="@+id/esos_questionnaire"
                 android:textSize="14sp"
@@ -297,6 +333,16 @@
                 android:text="@string/demo_esos_satellite_string"
         />
 
+        <!-- Satellite Config Viewer -->
+        <Button android:id="@+id/satellite_config_viewer"
+            android:textSize="14sp"
+            android:layout_marginTop="8dip"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textAllCaps="false"
+            android:text="@string/satellite_config_viewer"
+            />
+
         <!-- VoLTE provisioned -->
         <Switch android:id="@+id/volte_provisioned_switch"
                 android:textSize="14sp"
diff --git a/res/layout/satellite_config_viewer.xml b/res/layout/satellite_config_viewer.xml
new file mode 100644
index 000000000..240e69742
--- /dev/null
+++ b/res/layout/satellite_config_viewer.xml
@@ -0,0 +1,96 @@
+<?xml version="1.0" encoding="utf-8"?><!-- Copyright (C) 2025 The Android Open Source Project
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
+<ScrollView xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:layout_marginTop="120dp"
+    android:layoutDirection="locale"
+    android:textDirection="locale">
+
+    <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:orientation="vertical"
+        android:padding="16dp">
+
+        <!-- VERSION -->
+        <LinearLayout style="@style/RadioInfo_entry_layout">
+            <TextView android:text="@string/satellite_config_version_label" style="@style/info_label" />
+            <TextView android:id="@+id/version" style="@style/info_value" />
+            <View
+                android:layout_width="fill_parent"
+                android:layout_height="1dip"
+                android:background="?android:attr/listDivider"/>
+        </LinearLayout>
+
+        <View
+            android:layout_width="fill_parent"
+            android:layout_height="2dip"
+            android:background="?android:attr/listDivider" />
+
+        <!-- cids, plmns, svcTypes -->
+        <LinearLayout style="@style/RadioInfo_entry_layout">
+            <TextView android:text="@string/satellite_config_service_type_label" style="@style/info_label" />
+            <TextView android:id="@+id/svc_type" style="@style/info_value" />
+        </LinearLayout>
+
+        <View
+            android:layout_width="fill_parent"
+            android:layout_height="3dip"
+            android:background="?android:attr/listDivider"/>
+
+        <!-- allow access -->
+        <LinearLayout style="@style/RadioInfo_entry_layout">
+            <TextView android:text="@string/satellite_config_allow_access_label" style="@style/info_label" />
+            <TextView android:id="@+id/allow_access" style="@style/info_value" />
+        </LinearLayout>
+
+        <View
+            android:layout_width="fill_parent"
+            android:layout_height="4dip"
+            android:background="?android:attr/listDivider"/>
+
+        <!-- country codes -->
+        <LinearLayout style="@style/RadioInfo_entry_layout">
+            <TextView android:text="@string/satellite_config_country_code_label" style="@style/info_label" />
+            <TextView android:id="@+id/country_codes" style="@style/info_value" />
+        </LinearLayout>
+
+        <View
+            android:layout_width="fill_parent"
+            android:layout_height="5dip"
+            android:background="?android:attr/listDivider"/>
+
+        <!-- size of sats2dat file -->
+        <LinearLayout style="@style/RadioInfo_entry_layout">
+            <TextView android:text="@string/satellite_config_size_of_sats2_dat_label" style="@style/info_label" />
+            <TextView android:id="@+id/size_of_sats2" style="@style/info_value" />
+        </LinearLayout>
+
+        <View
+            android:layout_width="fill_parent"
+            android:layout_height="1dip"
+            android:background="?android:attr/listDivider"/>
+
+        <!-- satellite access config json -->
+        <LinearLayout style="@style/entry_layout">
+            <TextView android:text="@string/satellite_config_json_label" style="@style/info_label" />
+            <TextView android:id="@+id/config_json" style="@style/info_value" />
+        </LinearLayout>
+
+    </LinearLayout>
+</ScrollView>
+
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index e4d1e2f34..f0aa25b79 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN is nie opgedateer nie, omdat die getal <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g>syfers oorskry."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN is nie bygewerk nie. Die PIN2 was verkeerd of die foonnommer is verwerp."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN-bewerking het misluk."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Kan nie MMI-kode bel nie omdat FDN geaktiveer is."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Lees tans van SIM-kaart af…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Geen kontakte op jou SIM-kaart nie."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Kies kontakte om in te voer"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simuleer is nie beskikbaar nie (Slegs ontfoutingbou)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE-kanaal (net ontfoutingsbou)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Satellietmodus van skyndiensverskaffer (net ontfoutingsbou)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Skynsatellietdatamodus (slegs ontfout)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Beperk"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Beperk"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Onbeperk"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Toets regte satelliet-eSOS-modus (net ontfoutingsbou)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Toets nie-eSOS-modus vir regte satelliet (net ontfoutingsbou)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Toets demonstrasiesatelliet-eSOS-modus (net ontfoutingsbou)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Kanselleer"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Skakel oor na werkprofiel"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Installeer ’n werkboodskapapp"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Wys satellietopstelling"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Satellietopstellingbekyker"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"weergawe:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/dienstipe:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"gee_toegang:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"landkodes:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"grootte van sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"satelliettoegangopstelling-json:"</string>
 </resources>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index 9c197dd72..509a08185 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN ቁጥሩ ከ<xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> አሃዞች ስለሚበልጥ አልዘመነም።"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN አልዘመነም። ፒን2 ትክክል አልነበረም፣ ወይም የስልክ ቁጥሩ ተቀባይነት አላገኘም።"</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN ክወና አልተሳካም!"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"ኤፍዲኤን ስለነቃ MMI ኮድ መደወል አይቻልም።"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"ከSIM ካርድ ላይ በማንበብ ላይ..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"በ SIM ካርድዎ ላይ ዕውቂያዎች የሉም።"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"ለማስገባት ዕውቂያዎች ምረጥ"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"ከአገልግሎት ውጭን አስመስል (የስህተት ማረሚያ ግንብ ብቻ)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE ሰርጥ (የስህተት አርም ግንባታ ብቻ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock Carrier Satellite Mode (የስህተት ማረሚያ ግንባታ ብቻ)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"የማስመሰያ ሳተላይት ውሂብ ሁነታ (የስሕተት አርም ግንባታ ብቻ)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"ተገድቧል"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"የተወሰነ"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"ያልተወሰነ"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"የእውነተኛ ሳተላይት eSOS ሁነታን ይሞክሩ (የስህተት ማረሚያ ግንብ ብቻ)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"የእውነተኛ ሳተላይት eSOS ያልሆነ ሁነታን ይሞክሩ (የስህተት ማረሚያ ግንብ ብቻ)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"የቅንጭብ ማሳያ ሳተላይት eSOS ሁነታን ይሞክሩ (የስህተት ማረሚያ ግንብ ብቻ)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"ይቅር"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"ወደ የሥራ መገለጫ ቀይር"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"የሥራ መልዕክቶች መተግበሪያ ይጫኑ"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"የሳተላይት ውቅረት አሳይ"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"የሳተላይት ውቅረት ተመልካች"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"ሥሪት፦"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype፦"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"መዳረሻ ፍቀድ፦"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"የአገር ኮዶች፦"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"size of sats2.dat፦"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"የሳተላይት መዳረሻ ውቅረት json፦"</string>
 </resources>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 23916eb2c..77aef2fc9 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"‏لم يتم تحديث FDN نظرًا لأن الرقم يتجاوز طوله <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> رقمًا."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"‏لم يتم تحديث FDN. رقم PIN2 غير صحيح، أو تم رفض رقم الهاتف."</string>
     <string name="fdn_failed" msgid="216592346853420250">"‏تعذّر إتمام عملية FDN!"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"‏لا يمكن الاتصال برمز MMI لأنّ ميزة FDN مفعَّلة."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"‏جارٍ القراءة من شريحة SIM..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"‏ليس هناك جهات اتصال على شريحة SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"حدد جهات اتصال لاستيرادها"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"محاكاة الخطأ \"خارج الخدمة\" (الإصدار المخصص لتصحيح الأخطاء فقط)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"‏قناة LTE للقمر الصناعي Force Camp (إصدار مخصّص لتصحيح الأخطاء فقط)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"وضع القمر الصناعي التجريبي لمشغّل شبكة الجوّال (إصدار مخصّص لتصحيح الأخطاء فقط)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"وضع بيانات القمر الصناعي التجريبي (إصدار مخصّص لتصحيح الأخطاء فقط)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"محظور"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"محدود"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"بدون حد أقصى"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"‏اختبار وضع القمر الصناعي الحقيقي لنظام eSOS (إصدار مخصّص لتصحيح الأخطاء فقط)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"‏اختبار وضع القمر الصناعي الحقيقي غير تابع لنظام eSOS (إصدار مخصّص لتصحيح الأخطاء فقط)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"اختبار وضع \"اتصالات الطوارئ بالقمر الصناعي\" التجريبي (إصدار مخصّص لتصحيح الأخطاء فقط)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"إلغاء"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"التبديل إلى ملف العمل"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"تثبيت تطبيق لرسائل العمل"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"عرض إعدادات القمر الصناعي"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"عارض إعدادات القمر الصناعي"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"الإصدار:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:‎"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"رموز البلدان:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"‏حجم ملف sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"‏ملف json لإعداد إمكانية الوصول إلى القمر الصناعي:"</string>
 </resources>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 175d5bf0a..c7a3d68ba 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -33,7 +33,7 @@
     <string name="cancel" msgid="8984206397635155197">"বাতিল কৰক"</string>
     <string name="enter_input" msgid="6193628663039958990">"USSD বাৰ্তাটো <xliff:g id="MIN_LEN">%1$d</xliff:g> আৰু <xliff:g id="MAX_LEN">%2$d</xliff:g> সংখ্যক বৰ্ণৰ ভিতৰত হ\'ব লাগিব। অনুগ্ৰহ কৰি আকৌ চেষ্টা কৰক।"</string>
     <string name="manageConferenceLabel" msgid="8415044818156353233">"কনফাৰেঞ্চ কল পৰিচালনা কৰক"</string>
-    <string name="ok" msgid="7818974223666140165">"ঠিক"</string>
+    <string name="ok" msgid="7818974223666140165">"ঠিক আছে"</string>
     <string name="audio_mode_speaker" msgid="243689733219312360">"স্পীকাৰ"</string>
     <string name="audio_mode_earpiece" msgid="2823700267171134282">"হেণ্ডছেট ইয়েৰপিচ"</string>
     <string name="audio_mode_wired_headset" msgid="5028010823105817443">"তাঁৰযুক্ত হেডছেট"</string>
@@ -148,7 +148,7 @@
     <string name="stk_cc_ss_to_dial_video_error" msgid="4255261231466032505">"SS অনুৰোধ ভিডিঅ\' কললৈ সলনি কৰা হ’ল"</string>
     <string name="fdn_check_failure" msgid="1833769746374185247">"আপোনাৰ ফ\'ন এপ্‌টোৰ ফিক্সড্ ডায়েলিং নম্বৰ ছেটিঙটো অন কৰি থোৱা আছে। ফলস্বৰূপে, কল সম্পৰ্কীয় কিছুমান সুবিধাই কাম কৰা নাই।"</string>
     <string name="radio_off_error" msgid="8321564164914232181">"এই ছেটিংসমূহ চোৱাৰ আগতে ৰেডিঅ\' অন কৰক।"</string>
-    <string name="close_dialog" msgid="1074977476136119408">"ঠিক"</string>
+    <string name="close_dialog" msgid="1074977476136119408">"ঠিক আছে"</string>
     <string name="enable" msgid="2636552299455477603">"অন কৰক"</string>
     <string name="disable" msgid="1122698860799462116">"অফ কৰক"</string>
     <string name="change_num" msgid="6982164494063109334">"আপডে’ট"</string>
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"নম্বৰটোত<xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g>টাতকৈ বেছি অংক আছে বাবে FDN আপডে\'ট নহ\'ল।"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN আপডে’ট কৰা নহ\'ল। PIN2টো ভুল আছিল বা ফ\'নটো নম্বৰটো নাকচ কৰা হৈছে।"</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN অপাৰেশ্বন বিফল হ’ল।"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN সক্ষম কৰি ৰখাৰ বাবে MMI ক\'ড ডায়েল কৰিব নোৱাৰি।"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"ছিম কাৰ্ডৰ পৰা পঢ়ি থকা হৈছে…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"আপোনাৰ ছিম কাৰ্ডত কোনো সম্পৰ্কসূচী নাই।"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"আমদানি কৰিবলৈ সম্পৰ্ক বাছনি কৰক"</string>
@@ -692,7 +693,7 @@
     <string name="change_pin_title" msgid="3564254326626797321">"ভইচমেইলৰ পিন সলনি কৰক"</string>
     <string name="change_pin_continue_label" msgid="5177011752453506371">"অব্যাহত ৰাখক"</string>
     <string name="change_pin_cancel_label" msgid="2301711566758827936">"বাতিল কৰক"</string>
-    <string name="change_pin_ok_label" msgid="6861082678817785330">"ঠিক"</string>
+    <string name="change_pin_ok_label" msgid="6861082678817785330">"ঠিক আছে"</string>
     <string name="change_pin_enter_old_pin_header" msgid="853151335217594829">"আপোনাৰ পুৰণি পিন নিশ্চিত কৰক"</string>
     <string name="change_pin_enter_old_pin_hint" msgid="8801292976275169367">"অব্যাহত ৰাখিবলৈ আপোনাৰ ভইচমেইল পিনটো দিয়ক।"</string>
     <string name="change_pin_enter_new_pin_header" msgid="4739465616733486118">"এটা নতুন পিন ছেট কৰক"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"সেৱাত নাই ছিমুলে’ট কৰক (কেৱল ডিবাগ বিল্ড)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp উপগ্ৰহ LTE চেনেল (কেৱল ডিবাগ বিল্ড)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"নকল বাহক উপগ্ৰহ ম’ড (কেৱল ডিবাগ বিল্ড)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"নকল উপগ্ৰহ ডেটা ম’ড (কেৱল ডিবাগ)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"প্ৰতিবন্ধিত"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"সীমিত"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"অসীমিত"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"বাস্তৱিক উপগ্ৰহৰ eSOS ম’ড পৰীক্ষা কৰক (কেৱল ডিবাগ বিল্ড)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"বাস্তৱিক উপগ্ৰহৰ অনা eSOS ম’ড পৰীক্ষা কৰক (কেৱল ডিবাগ বিল্ড)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"উপগ্ৰহৰ eSOS ম’ডৰ ডেম’ পৰীক্ষা কৰক (কেৱল ডিবাগ বিল্ড)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"বাতিল কৰক"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"কৰ্মস্থানৰ প্ৰ’ফাইললৈ সলনি কৰক"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"এটা কৰ্মস্থানৰ বাৰ্তা আদান-প্ৰদান কৰা এপ্‌ ইনষ্টল কৰক"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"উপগ্ৰহৰ কনফিগাৰেশ্বন দেখুৱাওক"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"উপগ্ৰহৰ কনফিগাৰেশ্বন ভিউৱাৰ"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"সংস্কৰণ:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"দেশৰ ক’ড:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.datৰ আকাৰ:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"উপগ্ৰহৰ এক্সেছৰ কনফিগাৰেশ্বন json:"</string>
 </resources>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index e0f42b2eb..87acbf2aa 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Nömrə <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> rəqəmi keçdiyindən FDN yenilənmədi."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN güncəlləşdirilmədi. PIN2 yanlış idi və ya telefon nömrəsi rədd edildi."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN əməliyyatı aılnmadı."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN deaktiv edildiyi üçün MMI kodunu yığmaq olmur."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM kart oxunur ..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"SIM kartınızda kontakt yoxdur."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"İmport üçün kontaktlar seçin"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\"Xidmətdənkənar\" Simulyasiyası (yalnız Debaq Versiyası)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (yalnız sazlama versiyası)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Sınaq Daşıyıcı Peyk Rejimi (yalnız sazlama versiyası)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Sınaq peyk datası rejimi (yalnız sazlama)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Məhdud"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limitli"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Limitsiz"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Real peyk eSOS rejimini sınaqdan keçirin (yalnız sazlama versiyası)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Real peyk qeyri-eSOS rejimini sınaqdan keçirin (yalnız sazlama versiyası)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Demo peyk eSOS rejimini sınaqdan keçirin (yalnız sazlama versiyası)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Ləğv edin"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"İş profilinə keçin"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"İş üçün mesajlaşma tətbiqi quraşdırın"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Peyk konfiqurasiyasını göstərin"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Peyk konfiqurasiyası görüntüləyicisi"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versiya:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"giriş icazəsi:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"ölkə kodları:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat faylının ölçüsü:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"peykə giriş üçün json konfiqurasiya faylı:"</string>
 </resources>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 8d60adc45..ab4057407 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Broj za fiksno biranje nije ažuriran jer ima previše cifara (više od <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g>)."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN nije ažuriran. PIN2 je netačan ili je broj telefona odbačen."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Radnja sa brojem za fiksno biranje nije uspela."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Nije moguće birati MMI kôd jer je broj za fiksno biranje omogućen."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Čita se sa SIM kartice…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Nema kontakata na SIM kartici."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Izbor kontakata za uvoz"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulacija ne funkcioniše (samo verzija sa otklonjenim greškama)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Prinudno primeni satelit za kampovanje na LTE kanal (samo verzija za otklanjanje grešaka)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Lažni režim mobilnog operatera za slanje preko satelita (samo verzija za otklanjanje grešaka)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Režim simulacije satelitskih podataka (samo verzija sa otklonjenim greškama)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Ograničeno"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Ograničeno"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Neograničeno"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testirajte stvarni satelitski eSOS režim (samo verzija sa otklonjenim greškama)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testirajte stvarni satelitski režim koji nije eSOS (samo verzija sa otklonjenim greškama)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testirajte demo verziju satelitskog eSOS režima (samo verzija sa otklonjenim greškama)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Otkaži"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Pređi na poslovni profil"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instalirajte poslovnu aplikaciju za razmenu poruka"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Prikaži satelitsku konfiguraciju"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Prikaz satelitske konfiguracije"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"verzija:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"dozvoli_pristup:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"kodovi zemalja:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"veličina fajla sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"pristup satelitskoj konfiguraciji u formatu json:"</string>
 </resources>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 1306dbd72..1df7ad1bf 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Дазволены нумар не абноўлены, бо не можа складацца больш чым з <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> лічбаў."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Cпiс дазволеных нумароў не адноўлены. PIN2 ўведзены няправiльна, або нумар быў адхiлены."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Аперацыя з дазволеным нумарам не ўдалася."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Не ўдаецца набраць код MMI, бо ўключана функцыя \"Дазволены нумар\"."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Чытанне з SIM-карты..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"На вашай SIM-карце няма кантактаў."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Выберыце кантакты для імпарту"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Мадэляванне знаходжання па-за сеткай (толькі ў зборцы для адладкі)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Прымусова прымяняць спадарожнікавы канал LTE (толькі для адладачнай зборкі)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Імітацыя рэжыму спадарожніка з SIM-картай ад аператара (толькі ў зборцы для адладкі)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Імітацыя рэжыму \"Спадарожнікавыя даныя\" (толькі ў зборцы для адладкі)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"З абмежаваннямі"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"З абмежаваннямі"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Без абмежаванняў"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Тэсціраванне рэальнага рэжыму спадарожнікавага падключэння eSOS (толькі ў зборцы для адладкі)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Тэсціраванне рэальнага няэкстраннага (non-eSOS) рэжыму спадарожнікавага падключэння (толькі ў зборцы для адладкі)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Тэсціраванне дэманстрацыйнага рэжыму спадарожнікавага падключэння eSOS (толькі ў зборцы для адладкі)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Скасаваць"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Пераключыцца на працоўны профіль"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Усталюйце працоўную праграму абмену паведамленнямі"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Паказаць канфігурацыю спадарожнікавага падключэння"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Сродак прагляду канфігурацыі спадарожнікавага падключэння"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"версія:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"дадатковы ідэнтыфікатар/сетка сувязі агульнага карыстання/тып сэрвісу:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"дазволіць доступ:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"коды краін:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"памер файла sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"файл JSON канфігурацыі доступу да спадарожнікавай сувязі:"</string>
 </resources>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 538027960..f10c4233b 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN не бе актуализиран, защото номерът надвишава <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> цифри."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN не е актуализирано. PIN2 бе неправилен или телефонният номер бе отхвърлен."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Операцията с фиксираните номера за набиране (FDN) не бе успешна."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Не може да се набере MMI код, защото функцията FDN е активирана."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Четене на данни от SIM картата…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Няма контакти в SIM картата ви."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Контакти за импортиране"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Симулиране на липса на услуга (само в компилацията за отстраняване на грешки)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Принудително използване на сателитен LTE канал (само в компилацията за отстраняване на грешки)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Симулиран сателитен режим от оператора (само в компилацията за отстраняване на грешки)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Режим на симулирани сателитни данни (само за отстраняване на грешки)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"С ограничения"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Ограничено"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Неограничено"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Тестване на режим на истински сателитен eSOS (само в компилацията за отстраняване на грешки)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Тестване на режим на истинска сателитна неспешна комуникация (само в компилацията за отстраняване на грешки)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Тестване на режим на демонстрация на сателитен eSOS (само в компилацията за отстраняване на грешки)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Отказ"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Превключване към служебния потребителски профил"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Инсталиране на служебно приложение за съобщения"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Показване на конфигурацията за сателитите"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Визуализатор на конфигурацията за сателитите"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"версия:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"разрешаване на достъп:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"кодове на държавите:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"размер на sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"JSON с конфигурация за достъп до сателитите:"</string>
 </resources>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index e4a02b34d..cfe64ab8c 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g>টি সংখ্যার সীমা ছাড়িয়ে যাওয়ায় তাকে আপডেট করা যায়নি।"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN আপডেট করা হয়নি৷ PIN2 ভুল ছিল, বা ফোন নম্বর বাতিল করা হয়েছে৷"</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN অপারেশন ব্যর্থ হয়েছে৷"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN চালু থাকায় MMI কোড ডায়াল করা যাচ্ছে না।"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"সিম কার্ড থেকে পড়া হচ্ছে…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"আপনার সিম কার্ডে কোনো পরিচিত নেই৷"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"পরিচিতগুলি আমদানি করুন"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"আউট-অফ-সার্ভিস সিমুলেট করা (শুধুমাত্র ডিবাগ বিল্ডের জন্য)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ফোর্স ক্যাম্প স্যাটেলাইট এলটিই চ্যানেল (শুধুমাত্র ডিবাগ বিল্ড)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"নকল পরিষেবা প্রদানকারী উপগ্রহ মোড (শুধুমাত্র ডিবাগ বিল্ড)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"স্যাটেলাইট ডেটা মোড মক করুন (শুধুমাত্র ডিবাগ)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"বিধিনিষেধযুক্ত"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"সীমিত"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"আনলিমিটেড"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"রিয়েল স্যাটেলাইট eSOS মোড পরীক্ষা করুন (শুধুমাত্র ডিবাগ বিল্ড)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"রিয়েল স্যাটেলাইট নন-ইএসওএস মোড পরীক্ষা করুন (শুধুমাত্র ডিবাগ বিল্ড)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ডেমো স্যাটেলাইট eSOS মোড পরীক্ষা করুন (শুধুমাত্র ডিবাগ বিল্ড)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"বাতিল করুন"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"অফিস প্রোফাইলে পাল্টে নিন"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"অফিসের জন্য একটি মেসেজিং অ্যাপ ইনস্টল করুন"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"স্যাটেলাইট কনফিগারেশন দেখুন"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"স্যাটেলাইট কনফিগারেশন ভিউয়ার"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"ভার্সন:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"দেশের কোড:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat-এর সাইজ:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"স্যাটেলাইট অ্যাক্সেস কনফিগারেশনের json ফাইল:"</string>
 </resources>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index f55369828..21cdf33bb 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="phoneAppLabel" product="tablet" msgid="1916019789885839910">"Prijenos podataka na mobilnoj mreži"</string>
+    <string name="phoneAppLabel" product="tablet" msgid="1916019789885839910">"Prenos podataka na mobilnoj mreži"</string>
     <string name="phoneAppLabel" product="default" msgid="130465039375347763">"Telefonske usluge"</string>
     <string name="emergencyDialerIconLabel" msgid="8668005772339436680">"Hitno biranje"</string>
     <string name="phoneIconLabel" msgid="3015941229249651419">"Telefon"</string>
@@ -305,7 +305,7 @@
     <string name="carrier_settings_euicc" msgid="1190237227261337749">"Operater"</string>
     <string name="keywords_carrier_settings_euicc" msgid="8540160967922063745">"mobilni operater, esim, sim, euicc, promijeni mobilnog operatera, dodaj mobilnog operatera"</string>
     <string name="carrier_settings_euicc_summary" msgid="2027941166597330117">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> — <xliff:g id="PHONE_NUMBER">%2$s</xliff:g>"</string>
-    <string name="mobile_data_settings_title" msgid="7228249980933944101">"Prijenos podataka na mobilnoj mreži"</string>
+    <string name="mobile_data_settings_title" msgid="7228249980933944101">"Prenos podataka na mobilnoj mreži"</string>
     <string name="mobile_data_settings_summary" msgid="5012570152029118471">"Pristup prenosu podataka mobilnom mrežom"</string>
     <string name="data_usage_disable_mobile" msgid="5669109209055988308">"Isključiti prijenos podataka na mobilnoj mreži?"</string>
     <string name="sim_selection_required_pref" msgid="6985901872978341314">"Potreban izbor"</string>
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN nije ažuriran jer broj ima više od <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> cifara."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN nije ažuriran. PIN2 je netačan ili je broj telefona odbijen."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN operacija nije uspjela."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Nije moguće birati MMI kôd jer je FDN omogućen."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Čitanje sa SIM kartice u toku…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Nema kontakata na SIM kartici."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Odaberite kontakte za uvoz"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulacija ne radi (samo verzija za otklanjanje grešaka)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Satelitski LTE kanala za Force Camp (samo verzija za otklanjanje grešaka)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Lažni način rada operatera za slanje putem satelita (samo verzija za otklanjanje grešaka)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Lažni način rada za satelitske podatke (samo verzija za otklanjanje grešaka)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Ograničeno"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Ograničeno"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Neograničeno"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testiraj stvarni način rada satelitskog eSOS-a (samo verzija za otklanjanje grešaka)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testiraj stvarni način rada satelita koji nije eSOS (samo verzija za otklanjanje grešaka)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testiraj demo način rada satelitskog eSOS-a (samo verzija za otklanjanje grešaka)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Otkaži"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Pređite na radni profil"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instalirajte poslovnu aplikaciju za razmjenu poruka"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Prikaži konfiguraciju satelita"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Prikazivač konfiguracije satelita"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"verzija:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"pozivni brojevi zemalja:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"veličina fajla sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"JSON konfiguracije za pristup satelitu:"</string>
 </resources>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index c6e47966e..32106800d 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN no s\'ha actualitzat perquè el número supera els <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> dígits."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"El número FDN no s\'ha actualitzat. El PIN2 no és correcte o bé s\'ha rebutjat el número de telèfon."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Hi ha hagut un problema en l\'operació FDN."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"No es pot marcar el codi MMI perquè l\'FDN està activat."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Lectura de la targeta SIM..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"No hi ha cap contacte a la targeta SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Selecciona contactes per importar-los"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simula que està fora de servei (només per a la compilació de depuració)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Força el canal LTE del satèl·lit de camp (només per a la compilació de depuració)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mode de satèl·lit d\'un operador de telefonia mòbil simulat (només per a la compilació de depuració)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Mode de dades de satèl·lit simulat (només per a la depuració)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restringit"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limitat"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Il·limitat"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Provar el mode eSOS de satèl·lit real (només per a la compilació de depuració)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Prova el mode no eSOS de satèl·lit real (només per a la compilació de depuració)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Provar el mode de demostració d\'eSOS de satèl·lit (només per a la compilació de depuració)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Cancel·la"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Canvia al perfil de treball"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instal·la una aplicació de missatgeria de treball"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Mostra la configuració del satèl·lit"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Visualitzador de configuració del satèl·lit"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versió:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"permet l\'accés:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"codis de país:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"mida de sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"fitxer JSON de configuració d\'accés per satèl·lit:"</string>
 </resources>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index a6a6209c7..c59737944 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Funkce Povolená telefonní čísla nebyla aktualizována, protože číslo má více než <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> číslic."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Povolená tel. čísla (FDN) nebyla aktualizována. Kód PIN2 byl nesprávný nebo bylo telefonní číslo odmítnuto."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Operace s čísly FDN se nezdařila."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Kód MMI nelze vytočit, protože jsou aktivována povolená telefonní čísla."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Čtení ze SIM karty..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Na SIM kartě nejsou žádné kontakty."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Kontakty pro import"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulovat provoz mimo službu (pouze ladicí sestavení)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Kanál LTE Force Camp Satellite (jen ladicí sestavení)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulace satelitního režimu operátora (pouze ladicí sestavení)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simulace režimu dat přes satelit (pouze ladicí sestavení)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Omezeno"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limitováno"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Neomezeno"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Otestovat reálný režim nouzových zpráv přes satelit (pouze ladicí sestavení)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Otestovat reálný režim jiných než nouzových zpráv přes satelit (pouze ladicí sestavení)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Otestovat ukázkový režim nouzových zpráv přes satelit (pouze ladicí sestavení)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Zrušit"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Přepnout na pracovní profil"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Nainstalovat pracovní aplikaci na odesílání zpráv"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Zobrazit konfiguraci satelitu"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Prohlížeč satelitní konfigurace"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"verze:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"kódy zemí:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"velikost souboru sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"konfigurační soubor json pro přístup přes satelit:"</string>
 </resources>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 2f4ede6c7..0ec557084 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Nummeret til begrænset opkald blev ikke opdateret, fordi nummeret er mere end <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> cifre."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Nummeret til begrænset opkald blev ikke opdateret. PIN2-koden var forkert, eller telefonnummeret blev afvist."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Handlingen mislykkedes."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"MMI-koden kan ikke ringes op, fordi FDN er aktiveret."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Læser fra SIM-kort ..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Der er ingen kontakter på dit SIM-kort."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Vælg kontakter, der skal importeres"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulering af enhed, der er ude af drift (kun i fejlretningsbuild)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Gennemtving Camp Satellite LTE-kanal (kun fejlretningsbuild)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Test af satellittilstand via mobilselskab (kun fejlretningsbuild)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Test af satellitdatatilstand (kun fejlretning)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Begrænset"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Begrænset"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Ubegrænset"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test af virkelig eSOS-satellittilstand (kun fejlretningsbuild)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test af virkelig satellittilstand, der ikke er eSOS (kun fejlretningsbuild)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test af demo for eSOS-satellittilstand (kun fejlretningsbuild)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Annuller"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Skift til arbejdsprofil"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Installer en app til arbejdsbeskeder"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Vis konfiguration af satellit"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Visning af satellitkonfiguration"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"version:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/tjenestetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"tillad_adgang:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"landekoder:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"størrelse på sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"JSON-fil til konfiguration af satellitadgang:"</string>
 </resources>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 24c72e3b1..103eb0335 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Die Rufnummernbeschränkung wurde nicht aktualisiert, da die Nummer länger als <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> Ziffern ist."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Die Liste der zugelassenen Rufnummern konnte nicht aktualisiert werden. Die eingegebene PIN2 ist ungültig oder die Rufnummer wurde abgelehnt."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Fehler bei der Rufnummernbeschränkung"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"MMI-Code kann nicht gewählt werden, da die Rufnummernbeschränkung aktiviert ist."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM-Karte wird ausgelesen..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Keine Kontakte auf SIM-Karte."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Kontakte für Import auswählen"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"„Außer Betrieb“ simulieren (nur Debug-Build)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"LTE-Kanal für Satelliten-Camp erzwingen (nur Debug-Build)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Vom Mobilfunkanbieter simulierter Satellitenmodus (nur Debug-Build)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simulierter Satellitendatenmodus (nur Debug)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Eingeschränkt"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Begrenzt"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Unbegrenzt"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"eSOS-Modus mit echtem Satelliten testen (nur Debug-Build)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"non-eSOS-Modus mit echtem Satelliten testen (nur Debug-Build)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"eSOS-Modus mit Demo-Satelliten testen (nur Debug-Build)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Abbrechen"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Zum Arbeitsprofil wechseln"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Geschäftliche Messaging-App installieren"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Satellitenkonfiguration anzeigen"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Satellite Config Viewer"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"Version:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"Ländercodes:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"Größe von sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"JSON-Konfiguration für Satellitenzugriff:"</string>
 </resources>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index 75d47a9e2..46c056068 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Το FDN δεν ενημερώθηκε, επειδή ο αριθμός υπερβαίνει τα <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> ψηφία."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Δεν έγινε ενημέρωση του FDN. Το PIN2 ήταν λανθασμένο ή ο αριθμός του τηλεφώνου απορρίφθηκε."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Αποτυχία λειτουργίας FDN."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Δεν είναι δυνατή η κλήση κωδικού MMI, επειδή το FDN είναι ενεργοποιημένο."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Ανάγνωση από κάρτα SIM…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Δεν υπάρχουν επαφές στην κάρτα SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Επιλέξτε επαφές για εισαγωγή"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Η προσομοίωση δεν λειτουργεί (μόνο έκδοση εντοπισμού σφαλμάτων)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Επιβολή καναλιού Camp Satellite LTE (μόνο έκδοση εντοπισμού σφαλμάτων)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Εικονική λειτουργία δορυφόρου εταιρείας κινητής τηλεφωνίας (μόνο έκδοση εντοπισμού σφαλμάτων)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Εικονική λειτουργία δεδομένων μέσω δορυφόρου (μόνο αποσφαλμάτωση)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Με περιορισμό"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Περιορισμένο"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Χωρίς περιορισμούς"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Δοκιμή πραγματικής δορυφορικής λειτουργίας eSOS (μόνο έκδοση εντοπισμού σφαλμάτων)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Δοκιμή πραγματικής δορυφορικής λειτουργίας εκτός eSOS (μόνο έκδοση εντοπισμού σφαλμάτων)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Έλεγχος δοκιμαστικής δορυφορικής λειτουργίας eSOS (μόνο έκδοση εντοπισμού σφαλμάτων)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Ακύρωση"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Εναλλαγή σε προφίλ εργασίας"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Εγκατάσταση εφαρμογής ανταλλαγής μηνυμάτων για την εργασία"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Εμφάνιση διαμόρφωσης δορυφόρου"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Πρόγραμμα προβολής διαμόρφωσης δορυφόρου"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"έκδοση:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"κωδικοί χωρών:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"μέγεθος του αρχείου sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"json ρύθμισης πρόσβασης δορυφόρου:"</string>
 </resources>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 75b50b117..74628111f 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN wasn\'t updated because the number exceeds <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> digits."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN wasn\'t updated. The PIN2 was incorrect or the phone number was rejected."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN operation failed."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Cannot dial MMI code because FDN is enabled."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Reading from SIM card…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"No contacts on your SIM card."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Select contacts to import"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulate out of service (debug build only)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (debug build only)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock operator satellite mode (debug build only)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Mock satellite data mode (debug only)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restricted"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limited"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Unlimited"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test real satellite eSOS mode (debug build only)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test real satellite non-eSOS mode (debug build only)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test demo satellite eSOS mode (debug build only)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Cancel"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Switch to work profile"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Install a work messages app"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Show satellite config"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Satellite config viewer"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"version:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"country codes:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"size of sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"satellite access config JSON:"</string>
 </resources>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index d1edf820f..8d392696d 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN wasn\'t updated because the number exceeds <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> digits."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN wasn\'t updated. The PIN2 was incorrect, or the phone number was rejected."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN operation failed."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Cannot dial MMI code because FDN is enabled."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Reading from SIM card…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"No contacts on your SIM card."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Select contacts to import"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulate Out of Service (Debug Build only)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (Debug Build only)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock Carrier Satellite Mode (Debug Build only)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Mock Satellite Data mode (Debug only)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restricted"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limited"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"UnLimited"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test real satellite eSOS mode (Debug Build only)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test real satellite non-eSOS mode (Debug Build only)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test demo satellite eSOS mode (Debug Build only)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Cancel"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Switch to work profile"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Install a work messages app"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Show Satellite Config"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Satellite Config Viewer"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"version:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"country codes:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"size of sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"satellite access config json:"</string>
 </resources>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 75b50b117..74628111f 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN wasn\'t updated because the number exceeds <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> digits."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN wasn\'t updated. The PIN2 was incorrect or the phone number was rejected."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN operation failed."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Cannot dial MMI code because FDN is enabled."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Reading from SIM card…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"No contacts on your SIM card."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Select contacts to import"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulate out of service (debug build only)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (debug build only)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock operator satellite mode (debug build only)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Mock satellite data mode (debug only)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restricted"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limited"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Unlimited"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test real satellite eSOS mode (debug build only)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test real satellite non-eSOS mode (debug build only)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test demo satellite eSOS mode (debug build only)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Cancel"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Switch to work profile"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Install a work messages app"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Show satellite config"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Satellite config viewer"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"version:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"country codes:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"size of sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"satellite access config JSON:"</string>
 </resources>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index 75b50b117..74628111f 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN wasn\'t updated because the number exceeds <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> digits."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN wasn\'t updated. The PIN2 was incorrect or the phone number was rejected."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN operation failed."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Cannot dial MMI code because FDN is enabled."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Reading from SIM card…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"No contacts on your SIM card."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Select contacts to import"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulate out of service (debug build only)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (debug build only)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock operator satellite mode (debug build only)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Mock satellite data mode (debug only)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restricted"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limited"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Unlimited"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test real satellite eSOS mode (debug build only)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test real satellite non-eSOS mode (debug build only)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test demo satellite eSOS mode (debug build only)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Cancel"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Switch to work profile"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Install a work messages app"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Show satellite config"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Satellite config viewer"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"version:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"country codes:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"size of sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"satellite access config JSON:"</string>
 </resources>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 4b06be3f3..2c8a43d00 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -481,10 +481,11 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"No se actualizó el NMF porque el número supera los <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> dígitos."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"No se actualizó el FDN. El PIN2 era incorrecto o se rechazó el número de teléfono."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Ocurrió un error de funcionamiento con el número de marcado fijo."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"No se puede marcar el código MMI porque el NMF está habilitado."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Leyendo la tarjeta SIM..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"No hay contactos en tu tarjeta SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Seleccionar contactos para importar"</string>
-    <string name="simContacts_airplaneMode" msgid="4654884030631503808">"Desactivar el modo de avión para importar contactos de la tarjeta SIM"</string>
+    <string name="simContacts_airplaneMode" msgid="4654884030631503808">"Desactivar el modo avión para importar contactos de la tarjeta SIM"</string>
     <string name="enable_pin" msgid="967674051730845376">"Activar/desactivar PIN de tarjeta SIM"</string>
     <string name="change_pin" msgid="3657869530942905790">"Cambiar PIN de tarjeta SIM"</string>
     <string name="enter_pin_text" msgid="3182311451978663356">"PIN de tarjeta SIM:"</string>
@@ -536,9 +537,9 @@
     <string name="notification_voicemail_no_vm_number" msgid="3423686009815186750">"Número de buzón de voz desconocido"</string>
     <string name="notification_network_selection_title" msgid="255595526707809121">"Sin servicio"</string>
     <string name="notification_network_selection_text" msgid="553288408722427659">"La red seleccionada (<xliff:g id="OPERATOR_NAME">%s</xliff:g>) no está disponible"</string>
-    <string name="incall_error_power_off" product="watch" msgid="7191184639454113633">"Activa la red móvil y desactiva el modo de avión o el modo de ahorro de batería para realizar una llamada."</string>
-    <string name="incall_error_power_off" product="default" msgid="8131672264311208673">"Desactivar modo de avión para hacer una llamada"</string>
-    <string name="incall_error_power_off_wfc" msgid="9125661184694727052">"Desactivar el modo de avión o conectarse a una red inalámbrica para hacer una llamada"</string>
+    <string name="incall_error_power_off" product="watch" msgid="7191184639454113633">"Activa la red móvil y desactiva el modo avión o el modo de ahorro de batería para realizar una llamada."</string>
+    <string name="incall_error_power_off" product="default" msgid="8131672264311208673">"Desactivar modo avión para hacer una llamada"</string>
+    <string name="incall_error_power_off_wfc" msgid="9125661184694727052">"Desactivar el modo avión o conectarse a una red inalámbrica para hacer una llamada"</string>
     <string name="incall_error_power_off_thermal" product="default" msgid="8695809601655300168"><b>"Se sobrecalentó el teléfono"</b>\n\n"No se puede completar esta llamada. Vuelve a intentar cuando se enfríe el teléfono.\n\nDe todos modos, puedes hacer llamadas de emergencia."</string>
     <string name="incall_error_ecm_emergency_only" msgid="5622379058883722080">"Para realizar una llamada que no sea de emergencia, sal del modo de devolución de llamada de emergencia."</string>
     <string name="incall_error_emergency_only" msgid="8786127461027964653">"No registrado en la red."</string>
@@ -571,7 +572,7 @@
     <string name="emergency_call_shortcut_hint" msgid="1290485125107779500">"Vuelve a presionar para llamar al <xliff:g id="EMERGENCY_NUMBER">%s</xliff:g>"</string>
     <string name="emergency_enable_radio_dialog_message" msgid="1695305158151408629">"Encendiendo radio..."</string>
     <string name="emergency_enable_radio_dialog_retry" msgid="4329131876852608587">"No hay servicio. Vuelve a intentarlo."</string>
-    <string name="radio_off_during_emergency_call" msgid="8011154134040481609">"No se puede entrar en modo de avión durante una llamada de emergencia."</string>
+    <string name="radio_off_during_emergency_call" msgid="8011154134040481609">"No se puede entrar en modo avión durante una llamada de emergencia."</string>
     <string name="dial_emergency_error" msgid="825822413209026039">"No se puede realizar la llamada. <xliff:g id="NON_EMERGENCY_NUMBER">%s</xliff:g> no es un número de emergencia."</string>
     <string name="dial_emergency_empty_error" msgid="2785803395047793634">"No se puede realizar la llamada. Marca un número de emergencia."</string>
     <string name="dial_emergency_calling_not_available" msgid="6485846193794727823">"Las llamadas de emergencia no están disponibles"</string>
@@ -716,7 +717,7 @@
     <string name="mobile_data_activate_button" msgid="1139792516354374612">"AGREGAR DATOS"</string>
     <string name="mobile_data_activate_cancel_button" msgid="3530174817572005860">"CANCELAR"</string>
     <string name="clh_card_title_call_ended_txt" msgid="5977978317527299698">"Llamada finalizada"</string>
-    <string name="clh_callFailed_powerOff_txt" msgid="8279934912560765361">"El modo de avión está activado"</string>
+    <string name="clh_callFailed_powerOff_txt" msgid="8279934912560765361">"El modo avión está activado"</string>
     <string name="clh_callFailed_simError_txt" msgid="5128538525762326413">"No se puede acceder a la tarjeta SIM"</string>
     <string name="clh_incall_error_out_of_service_txt" msgid="2736010617446749869">"Red móvil no disponible"</string>
     <string name="clh_callFailed_satelliteEnabled_txt" msgid="1675517238240377396">"El modo satelital está activado"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simular fuera de servicio (solo para la compilación de depuración)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Canal LTE de satélite del campamento de la fuerza (solo compilación de depuración)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Modo Satélite del operador de prueba (solo en la compilación de depuración)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simulación de modo de datos por satélite (solo depuración)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restringido"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limitado"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Ilimitado"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Prueba el modo eSOS de satélite real (solo en la compilación de depuración)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Prueba el modo que no es eSOS por satélite real (solo en la compilación de depuración)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Prueba el modo de demostración de eSOS de satélite (solo en la compilación de depuración)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Cancelar"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Cambiar al perfil de trabajo"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instalar una app de mensajes laboral"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Mostrar configuración del satélite"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Visualizador de configuración del satélite"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"Versión:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"ID de suscripción, PLMN y tipo de servicio:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"Parámetro allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"Códigos de país:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"Tamaño de sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"Archivo JSON de configuración del acceso al satélite:"</string>
 </resources>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index bccc7cd19..51832ac0c 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -85,7 +85,7 @@
     <string name="smart_forwarding_settings_menu_summary" msgid="5096947726032885325">"Cuando no se puede contactar con un número, las llamadas se desvían siempre a otro número"</string>
     <string name="voicemail_notifications_preference_title" msgid="7829238858063382977">"Notificaciones"</string>
     <string name="cell_broadcast_settings" msgid="8135324242541809924">"Difusiones de emergencia"</string>
-    <string name="call_settings" msgid="3677282690157603818">"Ajustes de llamadas"</string>
+    <string name="call_settings" msgid="3677282690157603818">"Ajustes de llamada"</string>
     <string name="additional_gsm_call_settings" msgid="1561980168685658846">"Ajustes adicionales"</string>
     <string name="additional_gsm_call_settings_with_label" msgid="7973920539979524908">"Ajustes adicionales (<xliff:g id="SUBSCRIPTIONLABEL">%s</xliff:g>)"</string>
     <string name="sum_gsm_call_settings" msgid="7964692601608878138">"Ajustes adicionales de llamadas solo GSM"</string>
@@ -131,7 +131,7 @@
     <string name="disable_cdma_cw" msgid="7119290446496301734">"Cancelar"</string>
     <string name="cdma_call_waiting_in_ims_on" msgid="6390979414188659218">"Llamada en espera de CDMA en IMS activada"</string>
     <string name="cdma_call_waiting_in_ims_off" msgid="1099246114368636334">"Llamada en espera de CDMA en IMS desactivada"</string>
-    <string name="updating_title" msgid="6130548922615719689">"Ajustes de llamadas"</string>
+    <string name="updating_title" msgid="6130548922615719689">"Ajustes de llamada"</string>
     <string name="call_settings_admin_user_only" msgid="7238947387649986286">"El administrador es el único usuario que puede cambiar los ajustes de llamada."</string>
     <string name="phone_account_settings_user_restriction" msgid="9142685151087208396">"Solo el administrador o el usuario de trabajo pueden cambiar la configuración de la cuenta del teléfono."</string>
     <string name="phone_account_no_config_mobile_networks" msgid="7351062247756521227">"El propietario del dispositivo ha restringido la posibilidad de cambiar la configuración de la red móvil."</string>
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"No se ha podido actualizar FDN porque el número tiene más de <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> dígitos."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN no actualizado. El código PIN2 era incorrecto o se ha rechazado el número de teléfono."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Error de funcionamiento de número de marcación fija."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"No se puede marcar el código MMI porque el FDN está habilitado."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Leyendo desde tarjeta SIM…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"No hay ningún contacto en la tarjeta SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Seleccionar contactos para importar"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simular fuera del servicio (solo versión de depuración)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forzar canal LTE de satélite de campamento (solo versión de depuración)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulación del modo Satélite de operador (solo versión de depuración)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simulación del modo de datos por satélite (solo depuración)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restringido"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limitado"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Ilimitado"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Probar el modo eSOS por satélite real (solo versión de depuración)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Probar el modo no eSOS por satélite real (solo versión de depuración)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Probar el modo eSOS por satélite de demostración (solo versión de depuración)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Cancelar"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Cambiar al perfil de trabajo"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instalar una aplicación de mensajería de trabajo"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Mostrar Satellite Config"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Lector de Satellite Config"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versión:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"códigos de país:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"tamaño de sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"json de configuración de acceso por satélite:"</string>
 </resources>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 56fc00a5d..3cbdf7963 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -166,7 +166,7 @@
     <string name="voicemail_default" msgid="6427575113775462077">"Teie operaator"</string>
     <string name="vm_change_pin_old_pin" msgid="7154951790929009241">"Vana PIN-kood"</string>
     <string name="vm_change_pin_new_pin" msgid="2656200418481288069">"Uus PIN-kood"</string>
-    <string name="vm_change_pin_progress_message" msgid="626015184502739044">"Oodake."</string>
+    <string name="vm_change_pin_progress_message" msgid="626015184502739044">"Palun oodake."</string>
     <string name="vm_change_pin_error_too_short" msgid="1789139338449945483">"Uus PIN-kood on liiga lühike."</string>
     <string name="vm_change_pin_error_too_long" msgid="3634907034310018954">"Uus PIN-kood on liiga pikk."</string>
     <string name="vm_change_pin_error_too_weak" msgid="8581892952627885719">"Uus PIN-kood on liiga nõrk. Tugevas paroolis ei tohi olla mitut järjestikust samasugust tähemärki ega korduvaid numbreid."</string>
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN-i ei värskendatud, sest number ületab <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> kohta."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN-i ei värskendatud. PIN2 oli vale või lükati telefoninumber tagasi."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN-i toiming ebaõnnestus."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"MMI-koodi ei saa valida, sest FDN on lubatud."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM-kaardilt lugemine ..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Teie SIM-kaardil pole ühtegi kontakti."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Valige imporditavad kontaktid"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simuleerimine ei tööta (ainult silumisjärgus)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Camp Satellite LTE kanali (ainult silumisjärgus) sundaktiveerimine"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simuleeritud operaatori satelliidirežiim (ainult silumisjärgus)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Näitlik satelliitside andmesiderežiim (ainult silumine)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Piirangutega"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Piiratud"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Piiramatu"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Režiimi eSOS katsetamine reaalse satelliitsidesüsteemi puhul (ainult silumisjärk)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Režiimi mitte-eSOS katsetamine reaalse satelliitsidesüsteemi puhul (ainult silumisjärk)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Režiimi eSOS katsetamine demo satelliitsidesüsteemi puhul (ainult silumisjärk)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Tühista"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Lülitu tööprofiilile"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Installi töökoha sõnumsiderakendus"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Kuva satelliidi seadistus"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Satelliidi seadistuse vaatur"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versioon:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"juurdepääsu lubamine:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"riigikoodid:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"üksuse sats2.dat suurus:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"satelliidi juurdepääsu seadistuse json-fail:"</string>
 </resources>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index cefda5a55..c5bebc285 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Ez da eguneratu markatze finkoko zenbakia, zenbakiak <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> digitu baino gehiago dituelako."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Ez da eguneratu markatze finkoko zenbakia. PIN2 kodea ez da zuzena edo telefono-zenbakia baztertu da."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Markatze finkoko zenbakiaren eragiketak huts egin du."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Ezin da markatu MMI kodea FDN gaituta dagoelako."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM txarteletik irakurtzen…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Ez duzu kontakturik SIM txartelean."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Aukeratu inportatu beharreko kontaktuak"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulatu gailua ez dabilela (arazketa-konpilazioa soilik)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE kanala (arazte-konpilazioa bakarrik)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulatu operadorearen satelite modua (arazketa-konpilazioa soilik)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simulatu sateliteko datuen modua (arazketa soilik)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Murriztua"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Mugatua"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Mugagabea"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Probatu satelite bidezko SOS larrialdien modua (arazketa-konpilazioa soilik)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Probatu satelite bidezko SOS larrialdien modua ez dena (arazketa-konpilazioa soilik)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Probatu satelite bidezko SOS larrialdien moduaren demo-bertsioa (arazketa-konpilazioa soilik)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Utzi"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Aldatu laneko profilera"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instalatu laneko mezularitza-aplikazio bat"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Erakutsi satelitearen konfigurazioa"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Satelitearen konfigurazioaren ikustailea"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"bertsioa:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"herrialde-kodeak:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"size of sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"satellite access config json:"</string>
 </resources>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 4aa57e894..5722035ee 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"‏FDN به‌روزرسانی نشد، زیرا شماره از <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> رقم بیشتر است."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"‏FDN به‌روز نشد. پین۲ اشتباه بود یا شماره تلفن رد شد."</string>
     <string name="fdn_failed" msgid="216592346853420250">"‏عملیات FDN ناموفق بود."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"‏نمی‌توان کد MMI را شماره‌گیری کرد زیرا FDN فعال شده است."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"در حال خواندن سیم کارت..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"مخاطبی در سیم‌کارت شما نیست."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"انتخاب مخاطبین برای وارد کردن"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"شبیه‌سازی از کار افتادن (فقط ساخت اشکال‌زدایی)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"‏اجباری کردن کانال Camp Satellite LTE (فقط ساخت اشکال‌زدایی)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"حالت ماهواره‌ای شرکت مخابراتی ساختگی (فقط ساخت اشکال‌زدایی)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"حالت «داده ماهواره‌ای ساختگی» (فقط برای اشکال‌زدایی)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"محدودشده"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"محدود"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"نامحدود"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"آزمایش کردن حالت واقعی درخواست کمک اضطراری ماهواره‌ای (فقط ساخت اشکال‌زدایی)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"آزمایش کردن حالت واقعی درخواست کمک غیراضطراری ماهواره‌ای (فقط ساخت اشکال‌زدایی)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"آزمایش کردن نسخه نمایشی درخواست کمک اضطراری ماهواره‌ای (فقط ساخت اشکال‌زدایی)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"لغو کردن"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"رفتن به نمایه کاری"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"نصب برنامه پیام‌رسانی کاری"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"نمایش دادن پیکربندی ماهواره"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"نمایشگر پیکربندی ماهواره"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"نسخه:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"اجازه دسترسی:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"کد کشورها:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"‏اندازه sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"‏‫‏JSON پیکربندی دسترسی ماهواره:"</string>
 </resources>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index ac8c6d9c5..dcd8232c6 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Sallittuja numeroita ei päivitetty, koska numerossa oli yli <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> merkkiä."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN-numeroa ei päivitetty. PIN2 on virheellinen tai puhelinnumero hylättiin."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN-toiminto epäonnistui."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"MMI-koodilla ei voi soittaa, koska Sallitut numerot ‑ominaisuus on käytössä."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Luetaan SIM-korttia…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"SIM-kortilla ei ole yhteystietoja."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Valitse yhteystiedot"</string>
@@ -716,7 +717,7 @@
     <string name="mobile_data_activate_button" msgid="1139792516354374612">"LISÄÄ DATAPAKETTI"</string>
     <string name="mobile_data_activate_cancel_button" msgid="3530174817572005860">"PERUUTA"</string>
     <string name="clh_card_title_call_ended_txt" msgid="5977978317527299698">"Puhelu lopetettu"</string>
-    <string name="clh_callFailed_powerOff_txt" msgid="8279934912560765361">"Lentokonetila on käytössä."</string>
+    <string name="clh_callFailed_powerOff_txt" msgid="8279934912560765361">"Lentokonetila on päällä"</string>
     <string name="clh_callFailed_simError_txt" msgid="5128538525762326413">"SIM-kortin käyttö epäonnistui."</string>
     <string name="clh_incall_error_out_of_service_txt" msgid="2736010617446749869">"Mobiiliverkko ei ole käytettävissä"</string>
     <string name="clh_callFailed_satelliteEnabled_txt" msgid="1675517238240377396">"Satelliittitila on päällä"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Epäkunnossa-simulaatio (vain virheenkorjauksen koontiversio)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Pakota Camp Satellite LTE ‐kanava (vain virheenkorjauksen koontiversio)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Operaattorin satelliittitilaesimerkki (vain virheenkorjauksen koontiversio)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Satelliittidatan esimerkkitila (vain virheenkorjaus)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Rajoitettu"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Rajoitettu"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Rajoittamaton"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testaa oikeaa Satellite eSOS ‑tilaa (vain virheenkorjauksen koontiversio)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testaa oikeaa Satellite non-eSOS ‑tilaa (vain virheenkorjauksen koontiversio)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testaa Satellite eSOS ‑demotilaa (vain virheenkorjauksen koontiversio)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Peru"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Vaihda työprofiiliin"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Asenna työviestisovellus"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Näytä satelliitin määritys"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Satelliitin määritysten katseluohjelma"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versio:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/palvelutyyppi:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"salli_pääsy:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"maatunnukset:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat-tiedoston koko:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"satelliittiyhteyden määrityksen json:"</string>
 </resources>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index ff3247378..5a1b3b617 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Le NAF n\'a pas été mis à jour, car le numéro comporte plus de <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> chiffres."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Le numéro autorisé n\'a pas été mis à jour. Soit le NIP2 est incorrect, soit le numéro de téléphone a été rejeté."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Échec de l\'opération FDN."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Impossible de composer le code IHM parce que le NAF est activé."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Lecture de la carte SIM…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Aucun contact n\'a été trouvé sur votre carte SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Sélection des contacts à importer"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulation de l\'appareil hors service (version de débogage uniquement)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forcer le canal LTE satellite du camp (version de débogage uniquement)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mode Satellite de l\'opérateur simulé (version de débogage uniquement)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simuler le mode de données satellites (débogage seulement)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restreint"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limité"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Illimité"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Tester le mode eSOS par satellite réel (version de débogage uniquement)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Tester le mode non-eSOS par satellite réel (version de débogage uniquement)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Tester eSOS par satellite en mode Démo (version de débogage uniquement)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Annuler"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Passer au profil professionnel"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Installer une appli de messagerie professionnelle"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Afficher la configuration du satellite"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Lecteur de la configuration du satellite"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"version :"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"sous-identifiant/plmn/type de service :"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"autoriser_accès :"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"codes de pays :"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"taille de sats2.dat :"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"configuration de l\'accès au satellite json :"</string>
 </resources>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 22a69bb62..291787ca4 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Le numéro autorisé n\'a pas été mis à jour, car il comporte plus de <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> chiffres."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Le numéro autorisé n\'a pas été mis à jour. Soit le code PIN2 est incorrect, soit le numéro de téléphone a été rejeté."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Échec de l\'opération liée aux numéros autorisés."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Impossible de composer le code IHM, car seuls les numéros autorisés peuvent être composés."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Lecture de la carte SIM…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Aucun contact n\'a été trouvé sur votre carte SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Sélection des contacts"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simuler une panne (version de débogage uniquement)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forcer le canal LTE satellite du camp (version de débogage uniquement)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simuler le mode Satellite de l\'opérateur (version de débogage uniquement)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simuler le mode de données par satellite (débogage uniquement)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restreint"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limité"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Illimité"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Tester le SOS par satellite en mode réel (version de débogage uniquement)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Tester le mode non-eSOS par satellite réel (version de débogage uniquement)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Tester eSOS par satellite en mode démo (version de débogage uniquement)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Annuler"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Passer au profil professionnel"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Installer une application de chat professionnelle"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Afficher la configuration satellite"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Lecteur de la configuration satellite"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"version :"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype :"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"autoriser l\'accès :"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"codes pays :"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"taille de sats2.dat :"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"configuration JSON de l\'accès par satellite:"</string>
 </resources>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 3d0bc84ae..29c4e60ac 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Non se puido actualizar o NMF porque o número supera os <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> díxitos."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Non se actualizaron os NMF. O PIN2 era incorrecto ou rexeitouse o número de teléfono."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Produciuse un fallo no funcionamento dos NMF."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Non se pode marcar o código MMI porque está activado o NMF."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Lendo da tarxeta SIM..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Non hai contactos na tarxeta SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Seleccionar contactos para importar"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simular Fóra de servizo (só compilación de depuración)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forzar o canal LTE do satélite do campamento (só compilación de depuración)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simular o modo Satélite do operador (só compilación de depuración)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simulación do modo de datos por satélite (só depuración)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restrinxido"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limitado"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Ilimitado"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Probar o modo real eSOS por satélite (só compilación de depuración)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Probar o modo real non eSOS por satélite (só compilación de depuración)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Probar o modo de demostración de eSOS por satélite (só compilación de depuración)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Cancelar"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Cambiar ao perfil de traballo"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instalar unha aplicación de mensaxaría para o traballo"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Mostrar a configuración do satélite"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Visualizador de configuración do satélite"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versión:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"códigos de país:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"tamaño de sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"configuración JSON de acesso ao satélite:"</string>
 </resources>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 60b9b2432..462678240 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -153,7 +153,7 @@
     <string name="disable" msgid="1122698860799462116">"બંધ કરો"</string>
     <string name="change_num" msgid="6982164494063109334">"અપડેટ"</string>
   <string-array name="clir_display_values">
-    <item msgid="8477364191403806960">"નેટવર્ક ડિફોલ્ટ"</item>
+    <item msgid="8477364191403806960">"નેટવર્ક ડિફૉલ્ટ"</item>
     <item msgid="6813323051965618926">"નંબર છુપાવો"</item>
     <item msgid="9150034130629852635">"નંબર બતાવો"</item>
   </string-array>
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDNમાં <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> કરતા વધુ અંક હોવાથી તેને અપડેટ કરી શકાયો ન હતો."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN અપડેટ થયો ન હતો. PIN2 ખોટો હતો અથવા ફોન નંબર નકારેલ હતો."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN ઓપરેશન નિષ્ફળ થયું."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN ચાલુ કરેલું હોવાથી MMI કોડ ડાયલ કરી શકતા નથી."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM કાર્ડમાંથી વાંચી રહ્યાં છે…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"તમારા SIM કાર્ડ પર કોઈ સંપર્કો નથી."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"આયાત કરવા માટે સંપર્કો પસંદ કરો"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\'સેવા ઉપલબ્ધ નથી\' મોડ સિમ્યુલેટ કરો (માત્ર ડિબગ બિલ્ડ માટે)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ફોર્સ કેમ્પ સૅટલાઇટ LTE ચૅનલ (માત્ર ડિબગ માટે બનાવવામાં આવેલી)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"મૉક કૅરિઅર સૅટલાઇટ મોડ (માત્ર ડિબગ બિલ્ડ માટે)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"સૅટલાઇટ ડેટા મૉડનું મૉક (ફક્ત ડિબગ)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"પ્રતિબંધિત"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"મર્યાદિત"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"અમર્યાદિત"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"રિઅલ સૅટલાઇટ eSOS મોડનું પરિક્ષણ કરો (માત્ર ડિબગ બિલ્ડ માટે)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"રિઅલ સૅટલાઇટ નૉન-eSOS મોડનું પરિક્ષણ કરો (માત્ર ડિબગ બિલ્ડ માટે)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ડેમો સૅટલાઇટ eSOS મોડનું પરીક્ષણ કરો (માત્ર ડિબગ બિલ્ડ માટે)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"રદ કરો"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"ઑફિસની પ્રોફાઇલ પર સ્વિચ કરો"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"ઑફિસ માટે કોઈ મેસેજિંગ ઍપ ઇન્સ્ટૉલ કરો"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"સૅટલાઇટ કન્ફિગ બતાવો"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"સૅટલાઇટ કન્ફિગ વ્યૂઅર"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"વર્ઝન:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"દેશના કોડ:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.datનું કદ:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"સૅટલાઇટ ઍક્સેસ કન્ફિગ json:"</string>
 </resources>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 68fca48eb..3af174eb7 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN अपडेट नहीं किया जा सका, क्योंकि नंबर में <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> से ज़्यादा अंक हैं."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN पे नई जानकारी नहीं है. PIN2 गलत था, या फ़ोन नंबर नामंजूर था."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN की कार्यवाही विफल रही."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"एफ़डीएन चालू होने की वजह से, MMI कोड डायल नहीं किया जा सकता."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"सिम कार्ड से पढ़ रहा है…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"आपके सिम कार्ड पर कोई संपर्क नहीं है."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"आयात करने के लिए संपर्कों को चुनें"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"सिम्युलेट किया गया डिवाइस काम नहीं कर रहा है (सिर्फ़ डीबग के लिए बिल्ड)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"फ़ोर्स कैंप सैटलाइट एलटीई चैनल (सिर्फ़ डीबग के लिए बिल्ड)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"मोबाइल और इंटरनेट सेवा देने वाली कंपनी के सैटलाइट मोड की मॉक टेस्टिंग करें (सिर्फ़ डीबग के लिए बिल्ड)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"सैटलाइट डेटा मोड की मॉक टेस्टिंग करें (सिर्फ़ डीबग के लिए उपलब्ध)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"प्रतिबंधित"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"सीमित"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"अनलिमिटेड"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"रीयल सैटलाइट इमरजेंसी एसओएस मोड को आज़माएं (सिर्फ़ डीबग के लिए बिल्ड)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"रीयल सैटलाइट नॉन इमरजेंसी एसओएस मोड को आज़माएं (सिर्फ़ डीबग के लिए बिल्ड)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"डेमो सैटलाइट इमरजेंसी एसओएस मोड को आज़माएं (सिर्फ़ डीबग के लिए बिल्ड)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"रद्द करें"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"वर्क प्रोफ़ाइल पर स्विच करें"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"वर्क मैसेज ऐप्लिकेशन इंस्टॉल करें"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"सैटलाइट कॉन्फ़िगरेशन दिखाएं"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"सैटलाइट कॉन्फ़िगरेशन व्यूअर"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"वर्शन:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"सदस्यता आईडी/पीएलएमएन/सेवा का टाइप:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"ऐक्सेस करने की अनुमति दें:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"देशों के कोड:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat का साइज़:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"सैटलाइट ऐक्सेस कॉन्फ़िगरेशन की JSON फ़ाइल:"</string>
 </resources>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index c397d8e9b..c7425ca7a 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN nije ažuriran jer broj premašuje sljedeći broj znamenki: <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g>."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN nije ažuriran. PIN2 nije točan ili je telefonski broj odbijen."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Operacija FDN nije uspjela."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"MMI kôd ne može se birati jer je omogućen FDN."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Čitanje sa SIM kartice…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Nema kontakata na vašoj SIM kartici."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Odabir kontakata za uvoz"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulacija stanja \"izvan upotrebe\" (samo međuverzija programa za otklanjanje pogrešaka)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Satelitski LTE kanal za Force Camp (samo međuverzija programa za otklanjanje pogrešaka)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Lažni način mobilnog operatera za slanje putem satelita (samo međuverzija programa za otklanjanje pogrešaka)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Lažni način rada sa satelitskim podacima (samo za otklanjanje pogrešaka)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Ograničeno"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Ograničeno"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Neograničeno"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testiranje eSOS načina pravog satelita (samo međuverzija programa za otklanjanje pogrešaka)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testiranje načina pravog satelita bez eSOS-a (samo međuverzija programa za otklanjanje pogrešaka)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testiranje pokazne verzije eSOS načina satelita (samo međuverzija programa za otklanjanje pogrešaka)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Odustani"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Prelazak na poslovni profil"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instalirajte poslovnu aplikaciju za slanje poruka"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Prikaži konfiguraciju satelita"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Preglednik konfiguracije satelita"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"verzija:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"šifre država:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"veličina datoteke sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"konfiguracija JSON-a za pristup satelitu:"</string>
 </resources>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index ea48ea669..45eee4792 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Az FDN nem frissült, mert az érték több mint <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> számjegyből áll."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"A fix hívószám nem lett frissítve. Hibás a PIN2 kód, vagy a telefonszámot elutasították."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Sikertelen a fix hívószámmal végzett művelet."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Nem lehet MMI-kódot tárcsázni, mert engedélyezve van az FDN."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Beolvasás a SIM kártyáról..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Nincsenek névjegyek a SIM-kártyán."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Válassza ki az importálni kívánt névjegyeket"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Szolgáltatáskiesés szimulációja (csak hibaelhárító build)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Műholdas LTE-csatorna (csak hibaelhárító build)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Szimulált szolgáltató – Műholdas mód (csak hibaelhárító build)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Szimulált műholdas adatforgalmi mód (csak hibaelhárítás)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Korlátozott"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Korlátozott"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Korlátlan"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"A valódi műholdas eSOS mód tesztelése (csak hibaelhárító build)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"A valódi műholdas, nem eSOS mód tesztelése (csak hibaelhárító build)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"A műholdas eSOS demó mód tesztelése (csak hibaelhárító build)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Mégse"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Váltás munkaprofilra"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Munkahelyi üzenetküldő alkalmazás telepítése"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Műholdas beállítások megjelenítése"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Műholdas beállítások képernyője"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"verzió:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"hozzáférés engedélyezése:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"országkódok:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"a sats2.dat mérete:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"műholdas hozzáférési beállítások JSON-fájlja:"</string>
 </resources>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 576406527..43ab24262 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN-ը չթարմացվեց, քանի որ համարը գերազանցում է <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> նիշը:"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN-ը չի թարմացվել: PIN2-ը սխալ է կամ հեռախոսահամարը մերժված է:"</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN գործողությունը ձախողվեց:"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Հնարավոր չէ հավաքել MMI կոդը, քանի որ FDN-ը միացված է։"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Ընթերցում է SIM քարտից..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Ձեր SIM քարտում կոնտակտներ չկան:"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Ընտրեք կոնտակտները ներմուծման համար"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Սպասարկման գոտուց դուրս գտնվելու սիմուլյացիա (միայն վրիպազերծման կառուցում)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp արբանյակային LTE ալիք (միայն վրիպազերծման կառուցման մեջ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Օպերատորի արբանյակի ռեժիմի սիմուլյացիա (միայն վրիպազերծման կառուցում)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Արբանյակային տվյալների սիմուլյացիայի ռեժիմ (միայն վրիպազերծում)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Հասանելիությունը սահմանափակված է"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Սահմանափակումներով"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Առանց սահմանափակումների"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Փորձարկել իրական արբանյակային eSOS ռեժիմը (միայն վրիպազերծման կառուցման մեջ)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Փորձարկել իրական արբանյակային ոչ eSOS ռեժիմը (միայն վրիպազերծման կառուցման մեջ)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Փորձարկել արբանյակային eSOS ռեժիմը դեմո տարբերակով (միայն վրիպազերծման կառուցման մեջ)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Չեղարկել"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Անցնել աշխատանքային պրոֆիլ"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Տեղադրել հաղորդագրման աշխատանքային հավելված"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Ցուցադրել արբանյակի կարգավորումները"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Արբանյակի կարգավորումների դիտող"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"տարբերակ՝"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access․"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"երկրի կոդը՝"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat չափը՝"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"արբանյակային մուտքի կարգավորման json՝"</string>
 </resources>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index af0b7f1c4..2f4985d8d 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN tidak diupdate karena nomor melebihi <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> digit."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN tidak diperbarui. PIN2 salah, atau nomor telepon ditolak."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Operasi FDN gagal."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Tidak dapat men-dial kode MMI karena FDN diaktifkan."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Membaca dari kartu SIM…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Tidak ada kontak pada kartu SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Pilih kontak untuk diimpor"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulasi Tidak dapat Digunakan (Khusus Build Debug)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Terapkan Saluran Satelit LTE (khusus Build Debug)."</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mode Satelit Operator Tiruan (khusus Build Debug)."</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Mode Data Satelit Tiruan (Khusus Debug)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Dibatasi"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Terbatas"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Tidak terbatas"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Uji mode eSOS satelit asli (khusus Build Debug)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Uji mode non-eSOS satelit asli (khusus Build Debug)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Uji mode eSOS satelit demo (khusus Build Debug)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Batal"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Beralih ke profil kerja"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instal aplikasi pesan untuk kerja"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Tampilkan Konfigurasi Satelit"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Penampil Konfigurasi Satelit"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versi:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"kode negara:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"ukuran sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"json konfigurasi akses satelit:"</string>
 </resources>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 972481972..1374ec27c 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Fast númeraval var ekki uppfært vegna þess að númerið er lengra en <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> tölustafir."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Fast númeraval var ekki uppfært. PIN2-númerið var rangt eða símanúmerinu var hafnað."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Aðgerð fasts númeravals mistókst."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Ekki er hægt að hringja í MMI-kóða vegna þess að kveikt er á föstu númeravali"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Les af SIM-korti…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Engir tengiliðir á SIM-kortinu."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Veldu tengiliði til að flytja inn"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Líkja eftir „Utan þjónustusvæðis“ (aðeins villuleitarsmíði)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Þvinga Camp Satellite LTE-rás (aðeins villuleitarsmíði)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Eftirlíking af gervihnattarstillingu símafyrirtækis (aðeins villuleitarsmíði)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Sýndar-gervihnattargagnastilling (aðeins kembing)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Háð skorðum"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Takmarkað"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Ótakmarkað"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Prófa eSOS-stillingu raunverulegs gervihnattar (eingöngu villuleitarsmíð)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Prófa af-eSOS-stillingu raunverulegs gervihnattar (eingöngu villuleitarsmíð)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Prófa prufuútgáfu af eSOS-stillingu gervihnattar (eingöngu villuleitarsmíð)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Hætta við"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Skipta yfir í vinnusnið"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Setja upp skilaboðaforrit fyrir vinnu"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Sýna stillingar gervihnattar"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Yfirlit yfir stillingar gervihnattar"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"útgáfa:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"landskóðar:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"size of sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"aðgangur að JSON-stillingaskrá gervihnattar:"</string>
 </resources>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 9bbe00cb8..292d71557 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"I numeri consentiti non sono stati aggiornati perché il numero supera le <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> cifre."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Numeri consentiti non aggiornati. Il codice PIN2 non era corretto o il numero di telefono è stato rifiutato."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Operazione numeri consentiti non riuscita."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Impossibile comporre il codice MMI perché i numeri consentiti sono abilitati."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Lettura da SIM..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Nessun contatto presente nella SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Seleziona contatti da importare"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulazione non disponibile (solo build di debug)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forza canale LTE satellitare del campo (solo build di debug)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Modalità satellite operatore fittizio (solo build di debug)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Modalità dati satellitari fittizia (solo debug)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Con restrizioni"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Con limitazioni"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Senza limitazioni"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testa la modalità eSOS con satellite reale (solo build di debug)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testa la modalità non-eSOS con satellite reale (solo build di debug)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Prova la demo della modalità eSOS con satellite (solo build di debug)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Annulla"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Passa al profilo di lavoro"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Installa un\'app di messaggistica di lavoro"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Mostra configurazione satellitare"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Visualizzatore configurazione satellitare"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versione:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"codici paese:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"dimensioni di sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"JSON di configurazione dell\'accesso satellitare:"</string>
 </resources>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index d13b2c04d..652a480b4 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"‏מספר ה-FDN לא עודכן כי הוא מכיל יותר מ-<xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> ספרות."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"רשימת מספרי החיוג הקבועים לא עודכנה. קוד הגישה היה שגוי או שמספר הטלפון נדחה."</string>
     <string name="fdn_failed" msgid="216592346853420250">"‏פעולת FDN נכשלה."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"‏אי אפשר להתקשר לקודי MMI כי FDN פועל."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"‏קריאה מכרטיס SIM מתבצעת…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"‏אין אנשי קשר בכרטיס ה-SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"בחירת אנשי קשר לייבוא"</string>
@@ -848,6 +849,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"‏סימולציה של המצב \'לא בשירות\' (גרסת build לניפוי באגים בלבד)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"‏ערוץ Force Camp Satellite LTE (רק גרסת build לניפוי באגים)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"‏מצב שמדמה תקשורת לוויינית דרך ספק הסלולר (גרסת build לניפוי באגים בלבד)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"מצב שמדמה חיבור לחבילת הגלישה באמצעות לוויין (רק לניפוי באגים)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"מוגבל"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"עם הגבלה"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"בלי הגבלה"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"‏מצב בדיקה שמדמה תקשורת לוויינית eSOS (גרסת build לניפוי באגים בלבד)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"‏מצב בדיקה שמדמה תקשורת לוויינית לא במצב eSOS (גרסת build לניפוי באגים בלבד)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"‏מצב בדיקה שמדמה תקשורת לוויינית eSOS (גרסת build לניפוי באגים בלבד)"</string>
@@ -940,4 +945,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"ביטול"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"החלפה לפרופיל עבודה"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"התקנה של אפליקציית הודעות לעבודה"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"הצגת מסך ההגדרה של התקשורת הלוויינית"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"צפייה בהגדרות התקשורת הלוויינית"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"גרסה:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"מתן גישה:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"קידומות חיוג:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"‏הגודל של sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"‏קובץ JSON של הגדרות הגישה לתקשורת הלוויינית:"</string>
 </resources>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 8cb4d1da5..2d65b3230 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"この電話番号の桁数が <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> 桁を超えているため、FDN を更新できませんでした。"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"発信番号制限は更新されませんでした。PIN2が正しくないか、電話番号が拒否されました。"</string>
     <string name="fdn_failed" msgid="216592346853420250">"発信番号制限操作に失敗しました。"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN が有効になっているため、MMI コードをダイヤルできません。"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIMカードから読み取り中..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"SIMカードに連絡先がありません。"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"インポートする連絡先の選択"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"圏外状態のシミュレート（デバッグビルドのみ）"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE チャンネル（デバッグビルドのみ）"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"携帯通信会社の疑似航空写真モード（デバッグビルドのみ）"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"モック衛星データモード（デバッグのみ）"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"制限付き"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"制限付き"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"無制限"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"実際に衛星経由の緊急 SOS モードをテストする（デバッグビルドのみ）"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"実際に衛星経由の非緊急 SOS モードをテストする（デバッグビルドのみ）"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"デモ用の衛星による緊急 SOS モードをテストする（デバッグビルドのみ）"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"キャンセル"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"仕事用プロファイルに切り替える"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"仕事用メッセージ アプリをインストール"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"衛星通信の設定を表示"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"衛星通信の設定の閲覧者"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"version:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"country codes:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"size of sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"satellite access config json:"</string>
 </resources>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index 31c7e0845..1a1608ee8 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN არ განახლებულა, რადგან ნომერი <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> ციფრზე მეტს შეიცავს."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN არ განახლდა. PIN2 არასწორია ან ტელეფონის ნომერი უარყოფილია."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN ოპერაცია ვერ განხორციელდა."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"MMI კოდის აკრეფა ვერ ხერხდება, რადგან ჩართულია დაშვებული ნომერი."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"მიმდინარეობს SIM ბარათიდან წაკითხვა…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"თქვენს SIM ბარათზე კონტაქტები არ არის."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"აირჩიეთ კონტაქტი იმპორტისათვის"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"სიმულაცია სერვისის გარეშე (მხოლოდ გამართვის აგება)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Camp Satellite LTE არხის ფორსირება (მხოლოდ გამართვის მიზნით)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"სიმულაციური ოპერატორის სატელიტის რეჟიმი (მხოლოდ გამართვის აგება)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"სიმულაციური სატელიტური მონაცემების რეჟიმი (მხოლოდ გამართვა)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"შეზღუდული"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"ლიმიტირებული"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"შეუზღუდავი"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"სატელიტური eSOS-ის რეალური რეჟიმის ტესტირება (მხოლოდ გამართვის მიზნით)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"სატელიტური eSOS-ის რეალური რეჟიმის ტესტირება (მხოლოდ გამართვის მიზნით)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"სატელიტური eSOS-ის დემო-ვერსიის ტესტირება (მხოლოდ გამართვის მიზნით)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"გაუქმება"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"სამსახურის პროფილზე გადართვა"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"დააინსტალირეთ აპი ბიზნეს-შეტყობინებების გასაცვლელად"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"სატელიტური კონფიგურაციის ჩვენება"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"სატელიტური კონფიგურაციის მნახველი"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"ვერსია:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"ქვეყნის კოდები:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"Sats2.dat ფაილის ზომა:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"სატელიტური წვდომის კონფიგურაციის JSON:"</string>
 </resources>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 6e51a49f7..9a3076189 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Рұқсат нөмірлер жаңартылмады, себебі нөмір <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> саннан аспауы тиіс."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"ТТН жаңартылмады. PIN2 қате болды немесе телефон нөмірі қабылданбады."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Тұрақты теру нөмірлерінің жұмысы орындалмады."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"MMI кодын теру мүмкін емес, себебі FDN функциясы қосылған."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM картасынан оқу…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"SIM картаңызда контактілер жоқ."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Импортталатын контактілерді таңдау"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\"Істен шыққан\" қызметін симуляциялау (түзету құрамасы ғана)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Жерсеріктік LTE каналын мәжбүрлеп қолдану (тек түзету конструкциясы)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock Carrier жер серігі режимі (тек түзету құрамасы)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Жалған жерсерік деректері режимі (тек түзету)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Шектелген"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Шектеулі"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Шектеусіз"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Шынайы жерсеріктегі құтқару қызметін шақыру режимін сынау (тек түзету құрамасы)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Шынайы жерсерікті құтқару қызметін шақыру режимінен басқа режимде сынау (тек түзету құрамасы)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Демо жерсеріктегі құтқару қызметін шақыру режимін сынау (тек түзету құрамасы)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Бас тарту"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Жұмыс профиліне ауысу"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Жұмысқа арналған хабар алмасу қолданбасын орнату"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Жерсерік конфигурациясын көрсету"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Жерсерік конфигурациясын көру құралы"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"нұсқасы:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"ел кодтары:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat файлының көлемі:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"жерсерікті пайдалану конфигурациясының JSON файлы:"</string>
 </resources>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index a6f712d4d..3d15df205 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN មិន​ត្រូវ​បាន​ធ្វើ​បច្ចុប្បន្នភាព​ទេ ដោយ​សារ​លេខ​លើស​ពី <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> ខ្ទង់។"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"មិន​បាន​ធ្វើ​បច្ចុប្បន្នភាព។ កូដ PIN2 មិន​ត្រឹមត្រូវ ឬ​លេខ​ទូរស័ព្ទ​ត្រូវ​បាន​ច្រានចោល។"</string>
     <string name="fdn_failed" msgid="216592346853420250">"បាន​បរាជ័យ​ក្នុង​ការ​ប្រតិបត្តិការ FDN ។"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"មិនអាចចុចលេខកូដ MMI បានទេ ដោយសារ FDN ត្រូវបានបើក។"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"កំពុង​អាន​ពី​ស៊ីមកាត…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"គ្មាន​ទំនាក់ទំនង​នៅ​ក្នុង​​ស៊ីមកាត​របស់​អ្នក​ទេ។"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"ជ្រើស​ទំនាក់​ទំនង​ដើម្បី​នាំចូល"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"ត្រាប់តាម​ពេលគ្មានសេវា (កំណែបង្កើតសម្រាប់ជួសជុលតែប៉ុណ្ណោះ)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (តែកំណែបង្កើតសម្រាប់ជួសជុលប៉ុណ្ណោះ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"មុខងារ​ផ្កាយរណប​ក្រុមហ៊ុន​សេវាទូរសព្ទ​សាកល្បង (កំណែបង្កើត​សម្រាប់​ជួសជុល​តែប៉ុណ្ណោះ)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"មុខងារ​ទិន្នន័យ​ផ្កាយរណបសាកល្បង (សម្រាប់ជួសជុលតែប៉ុណ្ណោះ)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"បានដាក់កំហិត"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"មាន​កំណត់"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"គ្មាន​ដែនកំណត់"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"មុខងារ​ធ្វើតេស្ត eSOS ផ្កាយរណប​ជាក់ស្ដែង (កំណែបង្កើត​សម្រាប់​ជួសជុល​តែប៉ុណ្ណោះ)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"មុខងារ​ធ្វើតេស្ត​ដែល​មិនមែនជា eSOS ផ្កាយរណប​ជាក់ស្ដែង (កំណែបង្កើត​សម្រាប់​ជួសជុល​តែប៉ុណ្ណោះ)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"មុខងារ​ធ្វើតេស្ត eSOS ផ្កាយរណប​សាកល្បង (កំណែបង្កើត​សម្រាប់​ជួសជុល​តែប៉ុណ្ណោះ)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"បោះបង់"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"ប្ដូរ​ទៅ​កម្រង​ព័ត៌មាន​ការងារ"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"ដំឡើង​កម្មវិធី messages សម្រាប់​ការងារ"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"បង្ហាញ​ការកំណត់​រចនាសម្ព័ន្ធ​ផ្កាយរណប"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"ឧបករណ៍មើល​ការកំណត់​រចនាសម្ព័ន្ធ​ផ្កាយរណប"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"កំណែ៖"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype៖"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"អនុញ្ញាត​ឱ្យចូលប្រើ៖"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"លេខកូដ​ប្រទេស៖"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"ទំហំ sats2.dat៖"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"json នៃការ​កំណត់​រចនាសម្ព័ន្ធ​សិទ្ធិចូលប្រើ​ផ្កាយរណប៖"</string>
 </resources>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 4b1c427e2..91487cc98 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"ಸಂಖ್ಯೆಯು <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> ಅಂಕಿಗಳನ್ನು ಮೀರುತ್ತಿರುವ ಕಾರಣ FDN ಅನ್ನು ಅಪ್‌ಡೇಟ್ ಮಾಡಲಾಗಲಿಲ್ಲ."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"ಎಫ್‌ಡಿಎನ್‌ ಅನ್ನು ನವೀಕರಿಸಲಾಗಲಿಲ್ಲ. PIN2 ತಪ್ಪಾಗಿದೆ ಅಥವಾ ಫೋನ್ ಸಂಖ್ಯೆಯನ್ನು ತಿರಸ್ಕರಿಸಲಾಗಿದೆ."</string>
     <string name="fdn_failed" msgid="216592346853420250">"ಎಫ್‌ಡಿಎನ್‌ ಕಾರ್ಯಾಚರಣೆ ವಿಫಲವಾಗಿದೆ."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN ಸಕ್ರಿಯಗೊಂಡಿರುವ ಕಾರಣ MMI ಕೋಡ್ ಅನ್ನು ಡಯಲ್ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"ಸಿಮ್‌ ಕಾರ್ಡ್‌ನಿಂದ ಓದಲಾಗುತ್ತಿದೆ…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"ನಿಮ್ಮ ಸಿಮ್‌ ಕಾರ್ಡ್‌ನಲ್ಲಿ ಯಾವುದೇ ಸಂಪರ್ಕಗಳಿಲ್ಲ."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"ಆಮದು ಮಾಡಲು ಸಂಪರ್ಕಗಳು"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"ಸೇವೆಯಲ್ಲಿಲ್ಲದಿರುವುದನ್ನು ಸಿಮ್ಯುಲೇಟ್‌ ಮಾಡುವುದು (ಡೀಬಗ್ ಬಿಲ್ಡ್ ಮಾತ್ರ)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ಫೋರ್ಸ್ ಕ್ಯಾಂಪ್ ಸ್ಯಾಟಲೈಟ್ LTE ಚಾನಲ್ (ಡೀಬಗ್ ಬಿಲ್ಡ್ ಮಾತ್ರ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock Carrier ಉಪಗ್ರಹ ಮೋಡ್ (ಡೀಬಗ್ ಬಿಲ್ಡ್ ಮಾತ್ರ)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"ಮಾಕ್ ಸ್ಯಾಟಲೈಟ್ ಡೇಟಾ ಮೋಡ್ (ಡೀಬಗ್ ಮಾತ್ರ)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"ಸೀಮಿತ"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"ಅನಿಯಮಿತ"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"ನೈಜ ಸ್ಯಾಟಲೈಟ್ eSOS ಮೋಡ್ ಅನ್ನು ಪರೀಕ್ಷಿಸಿ (ಡೀಬಗ್ ಬಿಲ್ಡ್ ಮಾತ್ರ)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"ರಿಯಲ್ ಸ್ಯಾಟಲೈಟ್ ನಾನ್-eSOS ಮೋಡ್ (ಡೀಬಗ್ ಬಿಲ್ಡ್ ಮಾತ್ರ) ಅನ್ನು ಟೆಸ್ಟ್ ಮಾಡಿ"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ಸ್ಯಾಟಲೈಟ್‌ eSOS ಮೋಡ್‌ ಅನ್ನು ಟೆಸ್ಟ್‌ ಡೆಮೋ ನೀಡಿ (ಡೀಬಗ್ ಬಿಲ್ಡ್ ಮಾತ್ರ)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"ರದ್ದುಮಾಡಿ"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"ಉದ್ಯೋಗ ಪ್ರೊಫೈಲ್‌ಗೆ ಬದಲಿಸಿ"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"ಕೆಲಸಕ್ಕೆ ಸಂಬಂಧಿಸಿದ ಸಂದೇಶಗಳನ್ನು ಕಳುಹಿಸುವ ಆ್ಯಪ್ ಅನ್ನು ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿ"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"ಸ್ಯಾಟಲೈಟ್ ಕಾನ್ಫಿಗರೇಶನ್ ಅನ್ನು ತೋರಿಸಿ"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"ಸ್ಯಾಟಲೈಟ್ ಕಾನ್ಫಿಗರೇಶನ್ ವೀಕ್ಷಕ"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"ಆವೃತ್ತಿ:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"ರಾಷ್ಟ್ರ ಕೋಡ್‌ಗಳು:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat ನ ಗಾತ್ರ:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"ಸ್ಯಾಟಲೈಟ್ ಆ್ಯಕ್ಸೆಸ್ ಕಾನ್ಫಿಗರೇಶನ್ json:"</string>
 </resources>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index 8e345f206..e8f223da5 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"숫자가 <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g>자리를 초과하여 FDN을 업데이트하지 못했습니다."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN이 업데이트되지 않았습니다. PIN2가 잘못되었거나 전화번호가 거부되었습니다."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN 작업이 실패했습니다."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN이 사용 설정되어 있으므로 MMI 코드를 다이얼할 수 없습니다."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM 카드에서 읽는 중..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"SIM 카드에 연락처가 없습니다."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"가져올 주소록 선택"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\'서비스 지역 벗어남\' 시뮬레이션(디버그 빌드만 해당)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"캠프 위성 LTE 채널 강제(디버그 빌드만 해당)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"모의 이동통신사 위성 모드(디버그 빌드만 해당)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"모의 위성 데이터 모드(디버그 전용)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"제한됨"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"한정됨"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"무제한"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"실제 위성 eSOS 모드 테스트(디버그 빌드만 해당)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"실제 위성 비eSOS 모드 테스트(디버그 빌드만 해당)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"데모 위성 eSOS 모드 테스트(디버그 빌드만 해당)"</string>
@@ -862,7 +867,7 @@
     <string name="radio_info_ims_reg_status" msgid="25582845222446390">"IMS 등록: <xliff:g id="STATUS">%1$s</xliff:g>\nVoLTE: <xliff:g id="AVAILABILITY_0">%2$s</xliff:g>\nVoWi-Fi: <xliff:g id="AVAILABILITY_1">%3$s</xliff:g>\n화상 통화: <xliff:g id="AVAILABILITY_2">%4$s</xliff:g>\nUT 인터페이스: <xliff:g id="AVAILABILITY_3">%5$s</xliff:g>"</string>
     <string name="radioInfo_service_in" msgid="45753418231446400">"서비스 중"</string>
     <string name="radioInfo_service_out" msgid="287972405416142312">"서비스 지역 벗어남"</string>
-    <string name="radioInfo_service_emergency" msgid="4763879891415016848">"긴급 통화만 허용"</string>
+    <string name="radioInfo_service_emergency" msgid="4763879891415016848">"긴급 전화만 허용"</string>
     <string name="radioInfo_service_off" msgid="3456583511226783064">"무선 연결 끊김"</string>
     <string name="radioInfo_roaming_in" msgid="3156335577793145965">"로밍"</string>
     <string name="radioInfo_roaming_not" msgid="1904547918725478110">"로밍 안함"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"취소"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"직장 프로필로 전환"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"직장 메시지 앱 설치"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"위성 구성 표시"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"위성 구성 뷰어"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"버전:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"국가 코드"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat 크기:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"위성 액세스 구성 JSON:"</string>
 </resources>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 60bbe0a28..288fbb4d5 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Уруксат берилген номер жаңырган жок, себеби жазылган номердин саны <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> ашпашы керек."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"БНТ жаңырган жок. PIN2 туура эмес, же телефон номуру жараксыз."</string>
     <string name="fdn_failed" msgid="216592346853420250">"БНТ иши кыйрады."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN (уруксат берилген номер) иштетилгендиктен, MMI кодун терүү мүмкүн болгон жок."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM-картадан окулууда…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"SIM картаңызда байланыштар жок."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Импорттоло турган байланыштарды тандаңыз"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Тейлөө аймагынын сыртында режимин иштетүү (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Спутник LTE каналын иштетүү (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Симуляцияланган байланыш операторунун спутниги (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Симуляцияланган спутник маалыматы режими (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Чектөө коюлган"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Чектелген"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Чектөөсүз"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Чыныгы спутник eSOS режимин сыноо (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"eSOS болбогон чыныгы спутник режимин сыноо (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Демо спутник eSOS режимин сыноо (Мүчүлүштүктөрдү оңдоо үчүн гана)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Жокко чыгаруу"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Жумуш профилине которулуу"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Жумушка арналган жазышуу колдонмосун орнотуу"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Спутниктин конфигурациясын көрсөтүү"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Спутниктин конфигурациясын көрсөткүч"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"версиясы:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"өлкөлөрдүн коддору:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat өлчөмү:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"спутникке мүмкүнчүлүк алуу конфигурациясынын json форматы:"</string>
 </resources>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index b823c549a..92bd3c1cd 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"ບໍ່ໄດ້ອັບເດດ FDN ເນື່ອງຈາກເບີໂທເກີນ <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> ຕົວເລກ."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN ບໍ່ໄດ້ອັບເດດເທື່ອ. ລະຫັດ PIN2 ບໍ່ຖືກຕ້ອງ ຫຼືເບີໂທລະສັບຖືກປະຕິເສດ."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN ເຮັດວຽກລົ້ມເຫຼວ!"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"ບໍ່ສາມາດໂທອອກດ້ວຍລະຫັດ MMI ໄດ້ເນື່ອງຈາກເປີດໃຊ້ FDN ຢູ່."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"ກຳລັງອ່ານຈາກ SIM card..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"ບໍ່ມີລາຍຊື່ຜູ້ຕິດຕໍ່ໃນຊິມກາດຂອງທ່ານ."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"ເລືອກລາຍຊື່ເພື່ອນຳເຂົ້າ"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"ຈໍາລອງເຫດການບໍ່ພ້ອມໃຫ້ບໍລິການ (ສໍາລັບ Build ດີບັກເທົ່ານັ້ນ)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ບັງຄັບໃຫ້ໃຊ້ຊ່ອງສັນຍານດາວທຽມ LTE ຂອງຄ້າຍ (ສຳລັບ Build ດີບັກເທົ່ານັ້ນ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"ຈຳລອງໂໝດດາວທຽມຂອງຜູ້ໃຫ້ບໍລິການ (ສຳລັບ Build ດີບັກເທົ່ານັ້ນ)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"ໂໝດຂໍ້ມູນດາວທຽມຈຳລອງ (ດີບັກເທົ່ານັ້ນ)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"ຈຳກັດ"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"ຖືກຈຳກັດ"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"ບໍ່ໄດ້ຈຳກັດ"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"ທົດສອບໂໝດ eSOS ດາວທຽມແທ້ (ສຳລັບ Build ດີບັກເທົ່ານັ້ນ)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"ທົດສອບໂໝດດາວທຽມແທ້ທີ່ບໍ່ແມ່ນ eSOS (ສຳລັບ Build ດີບັກເທົ່ານັ້ນ)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ທົດສອບໂໝດ eSOS ຂອງດາວທຽມເດໂມ (ສຳລັບ Build ດີບັກເທົ່ານັ້ນ)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"ຍົກເລີກ"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"ສະຫຼັບໄປໃຊ້ໂປຣໄຟລ໌ບ່ອນເຮັດວຽກ"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"ຕິດຕັ້ງແອັບ Messages ສຳລັບບ່ອນເຮັດວຽກ"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"ສະແດງການຕັ້ງຄ່າດາວທຽມ"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"ໂປຣແກຣມເບິ່ງການຕັ້ງຄ່າດາວທຽມ"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"ເວີຊັນ:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"ລະ​ຫັດ​ປະ​ເທດ:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"ຂະໜາດຂອງ sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"ການຕັ້ງຄ່າສິດເຂົ້າເຖິງດາວທຽມ json:"</string>
 </resources>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index f2bc95b73..2edd513d8 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FRN neatnaujintas, nes numeris viršija <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> skaitm. apribojimą."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN nebuvo atnaujintas. Įvestas PIN2 kodas buvo netinkamas arba telefono numeris buvo atmestas."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Nepavyko atlikti FDN operacijos."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Negalima surinkti MMI kodo, nes įgalintas FRN."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Skaitoma iš SIM kortelės..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"SIM kortelėje kontaktų nėra."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Pasirinkti importuojamus adresatus"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Modeliavimas neteikiamas (tik derinimo versija)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Priverstinis stovyklos palydovinio ryšio LTE kanalo vykdymas (tik derinimo versija)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Netikras operatoriaus satelito režimas (tik derinimo versija)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Netikras palydovinių duomenų režimas (tik derinimo versija)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Ribotoji prieiga"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Ribota"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Neribota"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Išbandykite tikrą Pagalbos iškvietimo kritiniu atveju naudojant palydovinį ryšį režimą (tik derinimo versija)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Išbandykite tikrą Pagalbos iškvietimo ne kritiniu atveju naudojant palydovinį ryšį režimą (tik derinimo versija)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Išbandykite demonstracinę Pagalbos iškvietimo kritiniu atveju naudojant palydovinį ryšį versiją (tik derinimo versija)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Atšaukti"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Perjungti į darbo profilį"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Įdiegti darbo pranešimų programą"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Rodyti palydovo konfigūraciją"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Palydovo konfigūracijos peržiūros priemonė"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versija:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"leisti pasiekti:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"šalių kodai:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat dydis:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"palydovo prieigos konfigūracijos JSON:"</string>
 </resources>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 339ea8254..e80e555ef 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"IZSN netika atjaunināts, jo numurā ir vairāk par <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> cipariem."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"IZSN netika atjaunināts. Ievadītais PIN2 nebija pareizs, vai tālruņa numurs tika noraidīts."</string>
     <string name="fdn_failed" msgid="216592346853420250">"IZSN ievadīšana neizdevās."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Nevar sastādīt MMI kodu, jo ir iespējots IZSN."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Notiek lasīšana no SIM kartes..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"SIM kartē nav nevienas kontaktpersonas."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Importējamo kontaktu atlase"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulācijas ierīce nedarbojas (tikai atkļūdošanas būvējums)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"LTE satelīta kanāla piespiedu izmantošana (tikai atkļūdošanas būvējums)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mobilo sakaru operatora satelīta režīma imitēšana (tikai atkļūdošanas būvējums)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Imitēts satelīta datu režīms (tikai atkļūdošana)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Ierobežots"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Ierobežots"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Neierobežots"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Izmēģināt īsta satelīta eSOS režīmu (tikai atkļūdošanas būvējumā)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Izmēģināt īsta satelīta režīmu, kas nav eSOS režīms (tikai atkļūdošanas būvējumā)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Izmēģināt demonstrācijas satelīta eSOS režīmu (tikai atkļūdošanas būvējumā)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Atcelt"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Pārslēgties uz darba profilu"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instalēt darba ziņojumapmaiņas lietotni"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Rādīt satelīta konfigurāciju"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Satelīta konfigurācijas skatītājs"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versija:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"atļaut piekļuvi:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"valstu kodi:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"faila sats2.dat lielums:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"satelīta piekļuves konfigurācijas JSON:"</string>
 </resources>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 7eef5ee27..caab1290e 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -284,8 +284,8 @@
     <string name="data_enable_summary" msgid="696860063456536557">"Дозволи користење интернет"</string>
     <string name="dialog_alert_title" msgid="5260471806940268478">"Внимание"</string>
     <string name="roaming" msgid="1576180772877858949">"Роаминг"</string>
-    <string name="roaming_enable" msgid="6853685214521494819">"Поврзи се со интернет услуги во роаминг"</string>
-    <string name="roaming_disable" msgid="8856224638624592681">"Поврзи се со интернет услуги во роаминг"</string>
+    <string name="roaming_enable" msgid="6853685214521494819">"Поврзувај се на мобилен интернет во роаминг"</string>
+    <string name="roaming_disable" msgid="8856224638624592681">"Поврзувај се на мобилен интернет во роаминг"</string>
     <string name="roaming_reenable_message" msgid="1951802463885727915">"Интернет-роамингот е исклучен. Допрете за да се вклучи."</string>
     <string name="roaming_enabled_message" msgid="9022249120750897">"Може да ви се наплати за роаминг. Допрете за да измените."</string>
     <string name="roaming_notification_title" msgid="3590348480688047320">"Мобилната интернет-врска се прекина"</string>
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN не е ажуриран затоа што бројот содржи повеќе од <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> цифри."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN не се ажурираше. PIN2 кодот е неточен или телефонскиот број е одбиен."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Операцијата со FDN не успеа."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Не може да се избере MMI-код бидејќи е овозможен FDN."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Се чита од SIM картичка..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Нема контакти на вашата SIM картичка."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Избери контакти за увоз"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Симулирање „Надвор од употреба“ (само за верзиите за отстранување грешки)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE Channel (само верзија за отстранување грешки)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Симулација на режим на сателит за оператор (само за верзиите за отстранување грешки)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Симулација на режим за сателитски интернет (само за отстранување грешки)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Ограничено"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Ограничено"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Неограничено"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Тестирајте го реалниот режим на eSOS (само во верзијата за отстранување грешки)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Тестирајте го реалниот режим што не е на eSOS (само во верзијата за отстранување грешки)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Тестирајте го демо-режимот на eSOS (само во верзијата за отстранување грешки)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Откажи"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Префрлете се на работен профил"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Инсталирајте работна апликација за разменување пораки"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Прикажи ја сателитската конфигурација"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Прикажувач за сателитска конфигурација"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"верзија:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"дозволи пристап:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"кодови на земји:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"големина на sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"json-датотека за конфигурирање сателитски пристап:"</string>
 </resources>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 8fd0e8ec8..6b9462200 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"<xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> അക്കങ്ങൾ കവിഞ്ഞതിനാൽ FDN അപ്‌ഡേറ്റ് ചെയ്‌തില്ല."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN അപ്‌ഡേറ്റുചെയ്‌തില്ല. PIN2 തെറ്റായിരുന്നു, അല്ലെങ്കിൽ ഫോൺ നമ്പർ നിരസിച്ചു."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN പ്രവർത്തനം പരാജയപ്പെട്ടു."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN പ്രവർത്തനക്ഷമമാക്കിയതിനാൽ MMI കോഡ് ഡയൽ ചെയ്യാനാകില്ല."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"സിം കാർഡിൽ നിന്നും റീഡുചെയ്യുന്നു…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"നിങ്ങളുടെ സിം കാർഡിൽ കോൺടാക്റ്റുകളൊന്നുമില്ല."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"ഇമ്പോർട്ടുചെയ്യാനുള്ളവ തിരഞ്ഞെടുക്കൂ"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"സേവനം ലഭ്യമല്ലെന്ന് അനുകരിക്കുക (ഡീബഗ് ബിൽഡ് മാത്രം)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ഫോഴ്‌സ് ക്യാമ്പ് സാറ്റലൈറ്റ് LTE ചാനൽ(ഡീബഗ് ബിൽഡ് മാത്രം)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock സേവനദാതാവ് ഉപഗ്രഹ മോഡ് (ഡീബഗ് ബിൽഡ് മാത്രം)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"സാറ്റലൈറ്റ് ഡാറ്റ മോഡ് അനുകരിക്കുക (ഡീബഗ് മാത്രം)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"നിയന്ത്രിതം"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"പരിമിതം"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"പരിധിയില്ലാത്തത്"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"യഥാർത്ഥ സാറ്റലൈറ്റ് eSOS മോഡ് പരീക്ഷിക്കുക (ഡീബഗ് ബിൽഡ് മാത്രം)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"യഥാർത്ഥ സാറ്റലൈറ്റ് eSOS ഇതര മോഡ് പരീക്ഷിക്കുക (ഡീബഗ് ബിൽഡ് മാത്രം)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ഡെമോ സാറ്റലൈറ്റ് eSOS മോഡ് പരീക്ഷിക്കുക (ഡീബഗ് ബിൽഡ് മാത്രം)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"റദ്ദാക്കുക"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"ഔദ്യോഗിക പ്രൊഫൈലിലേക്ക് മാറുക"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"ഒരു ഔദ്യോഗിക സന്ദേശമയയ്ക്കൽ ആപ്പ് ഇൻസ്റ്റാൾ ചെയ്യുക"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"സാറ്റലൈറ്റ് കോൺഫിഗറേഷൻ കാണിക്കുക"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"സാറ്റലൈറ്റ് കോൺഫിഗറേഷൻ വ്യൂവർ"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"പതിപ്പ്:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/സേവനതരം:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"രാജ്യങ്ങളുടെ കോഡുകൾ:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat എന്നതിന്റെ വലിപ്പം:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"സാറ്റലൈറ്റ് ആക്സസ് കോൺഫിഗറേഷൻ json:"</string>
 </resources>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 16f320798..4d78a90f7 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Дугаар <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> цифрээс хэтэрсэн тул FDN-г шинэчлээгүй."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN шинэчлэгдсэнгүй. PIN2 буруу байсан, эсхүл утасны дугаар зөвшөөрөгдсөнгүй."</string>
     <string name="fdn_failed" msgid="216592346853420250">"ФДН ажиллуулах амжилтгүй."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Залгахаар тохируулсан дугаарыг идэвхжүүлсэн тул MMI код руу залгах боломжгүй."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM картаас уншиж байна…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Таны SIM картанд харилцагчид байхгүй байна."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Оруулах харилцагчдыг сонгоно уу"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Үйлчилгээний хүрээнээс гарсан нөхцөл байдлыг загварчлах (зөвхөн дебагийн хийц)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Camp Satellite LTE сувгийг хүчлэх (зөвхөн дебаг хийсэн хийц)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Оператор компанийн хуурамч хиймэл дагуулын горим (зөвхөн дебаг хийсэн хийц)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Дуураймал хиймэл дагуулын горим (зөвхөн дебаг)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Хязгаарласан"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Хязгаарлагдсан"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Хязгааргүй"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Жинхэнэ хиймэл дагуул eSOS горимыг турших (зөвхөн дебаг хийсэн хийц)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Жинхэнэ хиймэл дагуул eSOS бус горимыг турших (зөвхөн дебаг хийсэн хийц)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Демо хиймэл дагуул eSOS горимыг турших (зөвхөн дебаг хийсэн хийц)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Цуцлах"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Ажлын профайл руу сэлгэх"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Ажлын мессеж аппыг суулгах"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Хиймэл дагуулын тохируулгыг харуулах"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Хиймэл дагуулын тохируулгын үзэгч"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"хувилбар:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"улсын код:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat-н хэмжээ:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"хиймэл дагуулын хандалтын тохируулгын json:"</string>
 </resources>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 36477c1e0..638741397 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN अपडेट केलेले नाही, कारण नंबर <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> अंकांपेक्षा जास्‍त आहेत."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN अपडेट केले नव्‍हते. PIN2 चुकीचा होता किंवा फोन नंबरला नकार दिला."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN कार्य अयशस्‍वी झाले."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN सुरू असल्यामुळे MMI कोड डायल करू शकत नाही."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"सिक कार्डमधून वाचत आहे..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"आपल्‍या सिम कार्डवर कोणतेही संपर्क नाहीत."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"इंपोर्ट करण्यासाठी संपर्क निवडा"</string>
@@ -823,7 +824,7 @@
     <string name="callFailed_otasp_provisioning_in_process" msgid="3345666183602879326">"सध्या डिव्हाइसची तरतूद केली जात असल्यामुळे कॉल करू शकत नाही."</string>
     <string name="callFailed_already_dialing" msgid="7250591188960691086">"दुसरा आउटगोइंग कॉल आधीच डायल होत असल्यामुळे कॉल करू शकत नाही."</string>
     <string name="callFailed_already_ringing" msgid="2376603543544289303">"अनुत्तरित इनकमिंग कॉल असल्यामुळे कॉल करू शकत नाही. नवीन कॉल करण्याआधी इनकमिंग कॉलला उत्तर द्या किंवा तो नाकारा."</string>
-    <string name="callFailed_calling_disabled" msgid="5010992739401206283">"ro.telephony.disable-call सिस्टम प्रॉपर्टी वापरून कॉल करणे बंद केले गेल्यामुळे कॉल करू शकत नाही."</string>
+    <string name="callFailed_calling_disabled" msgid="5010992739401206283">"ro.telephony.disable-call सिस्टीम प्रॉपर्टी वापरून कॉल करणे बंद केले गेल्यामुळे कॉल करू शकत नाही."</string>
     <string name="callFailed_too_many_calls" msgid="2761754044990799580">"दोन कॉल आधीच प्रगतीपथावर असल्यामुळे कॉल करू शकत नाही. नवीन कॉल करण्याआधी एक कॉल डिस्कनेक्ट करा किंवा त्यांना कॉंफरन्स कॉलमध्ये मर्ज करा."</string>
     <string name="supp_service_over_ut_precautions" msgid="2145018231396701311">"<xliff:g id="SUPP_SERVICE">%s</xliff:g> वापरण्यासाठी, मोबाइल डेटा सुरू केलेला आहे याची खात्री करा. तुम्ही हे मोबाइल नेटवर्क सेटिंग्जमध्ये बदलू शकता."</string>
     <string name="supp_service_over_ut_precautions_roaming" msgid="670342104569972327">"<xliff:g id="SUPP_SERVICE">%s</xliff:g> वापरण्यासाठी, मोबाइल डेटा आणि डेटा रोमिंग सुरू केलेले आहेत याची खात्री करा. तुम्ही हे मोबाइल नेटवर्क सेटिंग्जमध्ये बदलू शकता."</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"सेवा बंद आहे सिम्युलेट करा (फक्त डीबगचा बिल्‍ड)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"फोर्स कॅम्प सॅटेलाइट LTE चॅनल (फक्त डीबग बिल्ड)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"नमुना वाहकाचा उपग्रह मोड (फक्त डीबग बिल्ड)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"सॅटेलाइट डेटा मोडशी संबंधित नमुना (फक्त डीबग बिल्ड)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"प्रतिबंधित"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"मर्यादित"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"UnLimited"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"प्रत्यक्ष सॅटेलाइट eSOS मोडची चाचणी करा (फक्त डीबग बिल्ड)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"eSOS नसलेल्या वास्तविक सॅटेलाइट मोडची चाचणी करा (फक्त डीबग बिल्ड)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"डेमो सॅटेलाइट eSOS मोडची चाचणी करा (फक्त डीबग बिल्ड)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"रद्द करा"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"कार्य प्रोफाइलवर स्विच करा"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"ऑफिससाठीचे मेसेज ॲप इंस्टॉल करा"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"सॅटेलाइट कॉन्फिगरेशन दाखवा"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"सॅटेलाइट कॉन्फिगरेशन व्ह्यूअर"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"आवृत्ती:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"देशाचे कोड:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat चा आकार:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"सॅटेलाइट अ‍ॅक्सेस कॉन्फिगरेशन json:"</string>
 </resources>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index fe16a4584..579475d37 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN tidak dikemas kini kerana nombornya melebihi <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> digit."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN tidak dikemaskini. PIN2 salah atau nombor telefon telah ditolak."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Operasi FDN gagal."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Tidak dapat mendail kod MMI kerana FDN didayakan."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Membaca daripada kad SIM..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Tiada kenalan pada kad SIM anda."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Pilih kenalan untuk diimport"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulasi Rosak (Binaan Penyahpepijatan sahaja)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Paksa Saluran LTE Satelit Kem (Binaan Nyahpepijat sahaja)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Contoh Mod Satelit Pembawa (Binaan Penyahpepijatan sahaja)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Contoh mod Data Satelit (Penyahpepijatan sahaja)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Terhad"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Terhad"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Tidak Terhad"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Uji mod sSOS satelit sebenar (Binaan Penyahpepijatan sahaja)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Uji mod bukan eSOS satelit sebenar (Binaan Penyahpepijatan sahaja)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Uji mod eSOS satelit demo (Binaan Penyahpepijatan sahaja)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Batal"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Beralih kepada profil kerja"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Pasang apl mesej kerja"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Tunjukkan Konfigurasi Satelit"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Pemapar Konfigurasi Satelit"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versi:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"kod negara:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"saiz sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"konfigurasi akses satelit json:"</string>
 </resources>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 90b1229df..c24d6f307 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"နံပါတ်တွင် ဂဏန်းအလုံးရေ <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> ကျော်နေပါသဖြင့် FDN ကို အပ်ဒိတ်လုပ်၍ မရပါ။"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN ပြောင်းလဲမှု မဖြစ်ပါ။ ပင်နံပါတ် ၂ မှားယွင်းခြင်း သို့မဟုတ် ဖုန်းနံပါတ်ကို ငြင်းဖယ်ခံရခြင်း တစ်ခုခုဖြစ်ပါသည်"</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN လုပ်ဆောင်ချက် မအောင်မြင်ပါ"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN ဖွင့်ထားသောကြောင့် MMI ကုဒ်ကို ခေါ်ဆို၍မရပါ။"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"ဆင်းမ်ကတ်မှ ဖတ်နေပါသည်..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"ဆင်းမ်ကဒ်ထဲတွင် လိပ်စာများ မရှိပါ"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"ထည့်ယူရန် လိပ်စာများ ရွေးပါ"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"အသွင်တူပြုလုပ်သောစက် အလုပ်မလုပ်ပါ (အမှားရှာပြင်ခြင်းသာလျှင်)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE ချန်နယ် (အမှားရှာပြင်ခြင်းအတွက်သာ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock Carrier Satellite Mode (အမှားရှာပြင်ခြင်း အတွက်သာ)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"အသွင်တူ ဂြိုဟ်တုဒေတာမုဒ် (အမှားရှာပြင်ခြင်းအတွက် သီးသန့်)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"ကန့်သတ်ထားသည်"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"အကန့်အသတ်ဖြင့်သာ"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"အကန့်အသတ်မရှိ"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"ဂြိုဟ်တုအစစ် eSOS မုဒ်ကို စမ်းသပ်ခြင်း (အမှားရှာပြင်ခြင်းအတွက်သာ)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"ဂြိုဟ်တုအစစ် eSOS မဟုတ်သော မုဒ်ကို စမ်းသပ်ခြင်း (အမှားရှာပြင်ခြင်းအတွက်သာ)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"သရုပ်ပြ ဂြိုဟ်တု eSOS မုဒ်ကို စမ်းသပ်ခြင်း (အမှားရှာပြင်ခြင်းအတွက်သာ)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"မလုပ်တော့"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"အလုပ်ပရိုဖိုင်သို့ ပြောင်းရန်"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"အလုပ်သုံး မက်ဆေ့ဂျ်ပို့ရန်အက်ပ် ထည့်သွင်းရန်"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"ဂြိုဟ်တု စီစဉ်သတ်မှတ်ချက် ပြပါ"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"ဂြိုဟ်တု စီစဉ်သတ်မှတ်ချက် ကြည့်ရှုစနစ်"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"ဗားရှင်း-"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/ဝန်ဆောင်မှုအမျိုးအစား-"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"သုံးခွင့်ပြုရန်-"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"နိုင်ငံကုဒ်-"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat အရွယ်အစား-"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"ဂြိုဟ်တုသုံးခွင့် စီစဉ်သတ်မှတ်ချက် json-"</string>
 </resources>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index 776a55d63..512c1be29 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN ble ikke oppdatert fordi tallet er lengre enn <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> sifre."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Fast nummer ble ikke oppdatert. PIN2 var feil, eller telefonnummeret ble avvist."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN-handlingen mislyktes."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Kan ikke taste MMI-kode fordi FDN er aktivert."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Leser fra SIM-kort …"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Ingen kontakter på SIM-kortet."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Velg kontakter for import"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Ute av drift-simulering (bare for feilsøkingsversjoner)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE-kanal (bare feilsøkingsversjon)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Satelittmodus for fiktiv operatør (feilsøkingsversjon)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Fiktiv satellittdatamodus (bare feilsøking)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Tilgangsbegrenset"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Begrenset"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Ubegrenset"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test ekte satellitt med eSOS-modus (kun for feilsøkingsversjoner)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test ekte satellitt med ikke-eSOS-modus (kun for feilsøkingsversjoner)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test demo av satellitt med eSOS-modus (kun for feilsøkingsversjoner)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Avbryt"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Bytt til jobbprofilen"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Installer en jobbmeldingsapp"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Vis satellittkonfigurasjon"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Visning av satellittkonfigurasjon"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versjon:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"landskoder:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"størrelse på sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"JSON-konfigurasjon for satellittilgang:"</string>
 </resources>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index a5ccf9d8f..b9ed4e34b 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -83,7 +83,7 @@
     <string name="make_and_receive_calls" msgid="4868913166494621109">"कल गर्नुहोस् र प्राप्त गर्नुहोस्"</string>
     <string name="smart_forwarding_settings_menu" msgid="8850429887958938540">"स्मार्ट तरिकाले फर्वार्ड गर्ने सुविधा"</string>
     <string name="smart_forwarding_settings_menu_summary" msgid="5096947726032885325">"एउटा नम्बर सम्पर्क क्षेत्रबाहिर भएका बेला कल सधैँ आफ्नो अर्को नम्बरमा फर्वार्ड गर्नुहोस्"</string>
-    <string name="voicemail_notifications_preference_title" msgid="7829238858063382977">"सूचनाहरू"</string>
+    <string name="voicemail_notifications_preference_title" msgid="7829238858063382977">"नोटिफिकेसनहरू"</string>
     <string name="cell_broadcast_settings" msgid="8135324242541809924">"आपत्‌कालीन प्रसारणहरू"</string>
     <string name="call_settings" msgid="3677282690157603818">"कल सेटिङहरू"</string>
     <string name="additional_gsm_call_settings" msgid="1561980168685658846">"अतिरिक्त सेटिङहरू"</string>
@@ -271,7 +271,7 @@
     <string name="preferred_network_mode_nr_lte_tdscdma_wcdma_summary" msgid="5912457779733343522">"रुचाइएको नेटवर्क मोड: NR/LTE/TDSCDMA/WCDMA"</string>
     <string name="preferred_network_mode_nr_lte_tdscdma_gsm_wcdma_summary" msgid="6769797110309412576">"रुचाइएको नेटवर्क मोड: NR/LTE/TDSCDMA/GSM/WCDMA"</string>
     <string name="preferred_network_mode_nr_lte_tdscdma_cdma_evdo_gsm_wcdma_summary" msgid="4260661428277578573">"रुचाइएको नेटवर्क मोड: NR/LTE/TDSCDMA/CDMA/EvDo/GSM/WCDMA"</string>
-    <string name="call_category" msgid="4394703838833058138">"कल गर्दै"</string>
+    <string name="call_category" msgid="4394703838833058138">"कल गर्ने सुविधा"</string>
     <string name="network_operator_category" msgid="4992217193732304680">"नेटवर्क"</string>
     <string name="enhanced_4g_lte_mode_title" msgid="4213420368777080540">"Enhanced 4G LTE Mode"</string>
     <!-- no translation found for enhanced_4g_lte_mode_title_variant:0 (7240155150166394308) -->
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"उक्त सङ्ख्याले <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> अङ्कको अधिकतम सीमा नाघेकाले FDN अद्यावधिक गरिएन।"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN अद्यावधिक भएको थिएन। PIN2 गलत थियो वा फोन नम्बर अस्वीकार भएको थियो।"</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN कार्य बिफल भयो।"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN अन गरिएको हुनाले MMI कोड डायल गर्न सकिएन।"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM कार्ड पढ्दै..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"तपाईँको SIM कार्डमा कुनै पनि सम्पर्क छैन।"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"कन्ट्याक्टहरू इम्पोर्ट गर्न चयन गर्नुहोस्"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\"सेवा उपलब्ध छैन\" सिमुलेट गर्नुहोस् (डिबग बिल्डमा मात्र सिमुलेट गर्न मिल्छ)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE च्यानल (डिबग बिल्ड मात्र)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"सेवा प्रदायकको स्याटेलाइट मोडको परीक्षण गर्नुहोस् (डिबग बिल्ड मात्र)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"स्याटलाइट डेटा मोडको परीक्षण गर्नुहोस् (यो सुविधा डिबग बिल्डमा मात्र उपलब्ध छ)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"प्रतिबन्धित"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"सीमित"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"असीमित"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"वास्तविक स्याटेलाइट eSOS मोड परीक्षण गर्नुहोस् (डिबग बिल्ड मात्र)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"वास्तविक स्याटेलाइट eSOS बाहेकका मोड (डिबग बिल्ड मात्र) परीक्षण गर्नुहोस्"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"डेमो स्याटेलाइट eSOS मोडको परीक्षण गर्नुहोस् (डिबग बिल्ड मात्र)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"रद्द गर्नुहोस्"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"कार्य प्रोफाइल प्रयोग गर्नुहोस्"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"कामसम्बन्धी म्यासेजिङ एप इन्स्टल गर्नुहोस्"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"स्याटलाइट कन्फिगुरेसन देखाउनुहोस्"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"स्याटलाइट कन्फिगुरेसन भ्युअर"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"संस्करण:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"देशका कोडहरू:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat को आकार:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"स्याटलाइट एक्सेस कन्फिगुरेसनको json फाइल:"</string>
 </resources>
diff --git a/res/values-night/styles.xml b/res/values-night/styles.xml
index 977439689..f7d831b51 100644
--- a/res/values-night/styles.xml
+++ b/res/values-night/styles.xml
@@ -25,11 +25,6 @@
         <item name="android:navigationBarDividerColor">@color/dialer_divider_color</item>
         <item name="android:colorAccent">@color/dialer_theme_color</item>
         <item name="android:dialogTheme">@style/DialerAlertDialogTheme</item>
-
-        <!--
-            TODO(b/309578419): Make activities handle insets properly and then remove this.
-        -->
-        <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
     </style>
 
     <style name="EmergencyInfoNameTextAppearance"
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index b859f88cd..8d4c15718 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN is niet geüpdatet omdat het nummer langer is dan <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> tekens."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN is niet bijgewerkt. De PIN2 was onjuist of het telefoonnummer is geweigerd."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN-bewerking mislukt."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Kan geen MMI-code kiezen omdat FDN aanstaat."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Lezen vanaf simkaart..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Geen contacten op je simkaart."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Contacten selecteren om te importeren"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\'Niet in gebruik\' simuleren (alleen in foutopsporingsbuild)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Camp Satellite LTE-kanaal afdwingen (alleen in foutopsporingsbuild)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Satellietmodus voor testprovider (alleen in foutopsporingsbuild)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Satellietmodus om gegevens te simuleren (alleen foutopsporing)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Beperkt"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Beperkt"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Onbeperkt"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Echte e-SOS via satellietmodus testen (alleen in foutopsporingsbuild)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Echte niet-noodoproep via satellietmodus testen (alleen in foutopsporingsbuild)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Demo e-SOS via satellietmodus testen (alleen in foutopsporingsbuild)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Annuleren"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Overschakelen naar werkprofiel"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Werk-app voor berichten installeren"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Satellietconfiguratie tonen"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Weergave van satellietconfiguratie"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versie:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"landcodes:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"grootte van sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"Configuratie van json-bestand voor satelliettoegang:"</string>
 </resources>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 3ec9fe797..5db028c84 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"ନମ୍ବରରେ <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g>ଟିରୁ ଅଧିକ ଅଙ୍କ ଥିବା ଯୋଗୁଁ FDN ଅପ୍‌ଡେଟ୍ କରାଯାଇନଥିଲା।"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN ଅପଡେଟ୍ ହୋ‌ଇନଥିଲା। PIN2 ଭୁଲ୍ ଥିଲା କିମ୍ବା ଫୋନ୍ ନମ୍ବର୍‌କୁ ଗ୍ରହଣ କରାଗଲା ନାହିଁ।"</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN ଅପରେଶନ୍ ବିଫଳ ହେଲା।"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDNକୁ ସକ୍ଷମ କରାଯାଇଥିବା ଯୋଗୁଁ MMI କୋଡକୁ ଡାଏଲ କରାଯାଇପାରିବ ନାହିଁ।"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM କାର୍ଡରୁ ପଢ଼ାଯାଉଛି…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"ଆପଣଙ୍କ SIM କାର୍ଡରେ କୌଣସି ଯୋଗାଯୋଗ ନାହିଁ।"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"ଇମ୍ପୋର୍ଟ କରିବା ପାଇଁ ଯୋଗାଯୋଗକୁ ଚୟନ କରନ୍ତୁ"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\"କାମ କରୁନାହିଁ\"ରେ ସିମୁଲେଟ କରନ୍ତୁ (କେବଳ ଡିବଗ ବିଲ୍ଡ)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ଫୋର୍ସ କେମ୍ପ ସେଟେଲାଇଟ LTE ଚେନେଲ (କେବଳ ଡିବଗ ବିଲ୍ଡ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"ମକ କେରିଅର ସେଟେଲାଇଟ ମୋଡ (କେବଳ ଡିବଗ ବିଲ୍ଡ)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"ମୋକ ସେଟେଲାଇଟ ଡାଟା ମୋଡ (କେବଳ ଡିବଗ)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"ପ୍ରତିବନ୍ଧିତ"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"ସୀମିତ"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"ଅସୀମିତ"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"ପ୍ରକୃତ ସେଟେଲାଇଟର eSOS ମୋଡ ପରୀକ୍ଷା କରନ୍ତୁ (କେବଳ ଡିବଗ ବିଲ୍ଡ)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"ପ୍ରକୃତ ସେଟେଲାଇଟର ଅଣ-eSOS ମୋଡ ପରୀକ୍ଷା କରନ୍ତୁ (କେବଳ ଡିବଗ ବିଲ୍ଡ)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ଡେମୋ ସେଟେଲାଇଟର eSOS ମୋଡ ପରୀକ୍ଷା କରନ୍ତୁ (କେବଳ ଡିବଗ ବିଲ୍ଡ)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"ବାତିଲ କରନ୍ତୁ"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"ୱାର୍କ ପ୍ରୋଫାଇଲକୁ ସ୍ୱିଚ କରନ୍ତୁ"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"ଏକ ୱାର୍କ ମେସେଜ ଆପ ଇନଷ୍ଟଲ କରନ୍ତୁ"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"ସେଟେଲାଇଟ କନଫିଗରେସନ ଦେଖାନ୍ତୁ"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"ସେଟେଲାଇଟ କନଫିଗରେସନ ଭ୍ୟୁଅର"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"ଭର୍ସନ:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"ଦେଶ କୋଡ:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.datର ଆକାର:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"ସେଟେଲାଇଟ ଆକ୍ସେସ କନଫିଗରେସନ json:"</string>
 </resources>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index cfe7dfb66..f45c3f885 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN ਨੂੰ ਅੱਪਡੇਟ ਨਹੀਂ ਕੀਤਾ ਗਿਆ ਕਿਉਂਕਿ ਨੰਬਰ <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> ਅੰਕਾਂ ਤੋਂ ਵੱਧ ਹੈ।"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN ਅੱਪਡੇਟ ਨਹੀਂ ਕੀਤਾ ਗਿਆ ਸੀ। PIN2 ਗ਼ਲਤ ਸੀ ਜਾਂ ਫ਼ੋਨ ਨੰਬਰ ਅਸਵੀਕਾਰ ਕੀਤਾ ਗਿਆ ਸੀ।"</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN ਓਪਰੇਸ਼ਨ ਅਸਫਲ।"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN ਚਾਲੂ ਹੋਣ ਕਰਕੇ MMI ਕੋਡ ਡਾਇਲ ਨਹੀਂ ਕੀਤਾ ਜਾ ਸਕਦਾ।"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM ਕਾਰਡ ਤੋਂ ਪੜ੍ਹ ਰਿਹਾ ਹੈ…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"ਤੁਹਾਡੇ ਸਿਮ ਕਾਰਡ ’ਤੇ ਕੋਈ ਸੰਪਰਕ ਨਹੀਂ।"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"ਆਯਾਤ ਕਰਨ ਲਈ ਸੰਪਰਕ ਚੁਣੋ"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\'ਸੇਵਾ ਵਿੱਚ ਨਹੀਂ\' ਨੂੰ ਸਿਮੂਲੇਟ ਕਰੋ (ਸਿਰਫ਼ ਡੀਬੱਗ ਬਿਲਡ)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ਫੋਰਸ ਕੈਂਪ ਸੈਟੇਲਾਈਟ LTE ਚੈਨਲ (ਸਿਰਫ਼ ਡੀਬੱਗ ਬਿਲਡ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"ਮੌਕ ਕੈਰੀਅਰ ਉਪਗ੍ਰਹਿ ਮੋਡ (ਸਿਰਫ਼ ਡੀਬੱਗ ਬਿਲਡ)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"ਕਲਪਿਤ ਸੈਟੇਲਾਈਟ ਡਾਟਾ ਮੋਡ (ਸਿਰਫ਼ ਡੀਬੱਗ)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"ਪ੍ਰਤਿਬੰਧਿਤ"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"ਸੀਮਤ"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"ਅਸੀਮਤ"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"ਰੀਅਲ ਸੈਟੇਲਾਈਟ eSOS ਮੋਡ ਅਜ਼ਮਾਓ (ਸਿਰਫ਼ ਡੀਬੱਗ ਬਿਲਡ)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"ਰੀਅਲ ਸੈਟੇਲਾਈਟ ਗੈਰ-eSOS ਮੋਡ ਅਜ਼ਮਾਓ (ਸਿਰਫ਼ ਡੀਬੱਗ ਬਿਲਡ)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ਡੈਮੋ ਸੈਟੇਲਾਈਟ eSOS ਮੋਡ ਅਜ਼ਮਾਓ (ਸਿਰਫ਼ ਡੀਬੱਗ ਬਿਲਡ)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"ਰੱਦ ਕਰੋ"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"ਕਾਰਜ ਪ੍ਰੋਫਾਈਲ \'ਤੇ ਜਾਓ"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"ਕੰਮ ਸੰਬੰਧੀ ਸੁਨੇਹਾ ਐਪ ਸਥਾਪਤ ਕਰੋ"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"ਸੈਟੇਲਾਈਟ ਸੰਰੂਪਣ ਦਿਖਾਓ"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"ਸੈਟੇਲਾਈਟ ਸੰਰੂਪਣ ਦਰਸ਼ਕ"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"ਵਰਜਨ:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"ਦੇਸ਼ਾਂ ਦੇ ਕੋਡ:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat ਦਾ ਆਕਾਰ:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"ਸੈਟੇਲਾਈਟ ਪਹੁੰਚ ਸੰਰੂਪਣ json:"</string>
 </resources>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index c6de54721..b14adbbf6 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Nie zaktualizowano usługi FDN, ponieważ numer zawiera powyżej <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> cyfr."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Nie zaktualizowano FDN. PIN2 był niepoprawny lub numer telefonu został odrzucony."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Operacja FDN nie udała się."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Nie można wybrać kodu MMI, ponieważ funkcja FDN jest włączona."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Czytanie z karty SIM..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Brak kontaktów na karcie SIM"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Wybierz kontakty do importowania"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Symulowana przerwa w działaniu usługi (tylko w kompilacji do debugowania)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Wymuś kanał LTE satelitarny Force Camp (tylko kompilacja do debugowania)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Symulowany tryb satelitarny operatora (tylko kompilacja do debugowania)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Symulowany tryb danych satelitarnych (tylko debugowanie)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Z ograniczonym dostępem"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Z ograniczeniami"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Bez limitu"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testowanie rzeczywistego trybu satelitarnego eSOS (tylko kompilacja do debugowania)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testowanie rzeczywistego trybu satelitarnego innego niż eSOS (tylko kompilacja do debugowania)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testowanie wersji demonstracyjnej trybu satelitarnego eSOS (tylko kompilacja do debugowania)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Anuluj"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Przełącz na profil służbowy"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Zainstaluj służbową aplikację do obsługi wiadomości"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Pokaż konfigurację satelity"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Przeglądarka konfiguracji satelitów"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"wersja:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"zezwól_na_dostęp:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"kody krajów:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"rozmiar pliku sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"konfiguracja dostępu do satelity w formacie JSON:"</string>
 </resources>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index ddc06d482..0a7ca2077 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -467,7 +467,7 @@
     <string name="get_pin2" msgid="4221654606863196332">"Introduzir PIN2"</string>
     <string name="name" msgid="1347432469852527784">"Nome"</string>
     <string name="number" msgid="1564053487748491000">"Número"</string>
-    <string name="save" msgid="983805790346099749">"Guardar"</string>
+    <string name="save" msgid="983805790346099749">"Guard."</string>
     <string name="add_fdn_contact" msgid="1169713422306640887">"Adicionar números autorizados"</string>
     <string name="adding_fdn_contact" msgid="3112531600824361259">"A adicionar números autorizados..."</string>
     <string name="fdn_contact_added" msgid="2840016151693394596">"Números autorizados adicionados."</string>
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"O FDN não foi atualizado porque o número excede <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> dígitos."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Não foram atualizados os números autorizados. O PIN2 estava errado ou o número de telefone foi rejeitado."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Falha de FDN."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Não é possível marcar o código MMI porque o FDN está ativado."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"A ler a partir do cartão SIM..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Sem contactos no cartão SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Selecione os contactos a importar"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simule o modo fora de serviço (apenas na versão de depuração)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Canal satélite LTE Force Camp (apenas na versão de depuração)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Modo satélite da operadora fictícia (apenas na versão de depuração)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Modo de dados de satélite fictício (apenas na versão de depuração)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restrito"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limitado"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Ilimitado"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testar modo eSOS de satélite real (apenas na versão de depuração)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Teste o modo não eSOS de satélite real (apenas na versão de depuração)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testar demonstração de modo eSOS de satélite (apenas na versão de depuração)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Cancelar"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Mudar para perfil de trabalho"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instalar app de mensagens profissional"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Mostrar configuração de satélite"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Visualizador de configuração de satélite"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versão:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"permitir acesso:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"códigos dos países:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"tamanho de sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"ficheiro JSON de configuração de acesso a satélite:"</string>
 </resources>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index ecd6673f8..6f5adfaf1 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -75,7 +75,7 @@
     <string name="phone_accounts_configure_account_settings" msgid="6622119715253196586">"Configurar conta"</string>
     <string name="phone_accounts_all_calling_accounts" msgid="1609600743500618823">"Todas as contas de chamadas"</string>
     <string name="phone_accounts_all_calling_accounts_summary" msgid="2214134955430107240">"Selecione quais contas podem fazer chamadas"</string>
-    <string name="wifi_calling" msgid="3650509202851355742">"Chamadas por Wi-Fi"</string>
+    <string name="wifi_calling" msgid="3650509202851355742">"Ligação pelo Wi-Fi"</string>
     <string name="connection_service_default_label" msgid="7332739049855715584">"Serviço de conexão integrado"</string>
     <string name="voicemail" msgid="7697769412804195032">"Correio de voz"</string>
     <string name="voicemail_settings_with_label" msgid="4228431668214894138">"Correio de voz (<xliff:g id="SUBSCRIPTIONLABEL">%s</xliff:g>)"</string>
@@ -311,7 +311,7 @@
     <string name="sim_selection_required_pref" msgid="6985901872978341314">"É necessário selecionar uma opção"</string>
     <string name="sim_change_data_title" msgid="9142726786345906606">"Alterar SIM para dados móveis?"</string>
     <string name="sim_change_data_message" msgid="3567358694255933280">"Usar <xliff:g id="NEW_SIM">%1$s</xliff:g> em vez de <xliff:g id="OLD_SIM">%2$s</xliff:g> para dados móveis?"</string>
-    <string name="wifi_calling_settings_title" msgid="5800018845662016507">"Chamadas por Wi-Fi"</string>
+    <string name="wifi_calling_settings_title" msgid="5800018845662016507">"Ligação pelo Wi-Fi"</string>
     <string name="video_calling_settings_title" msgid="342829454913266078">"Videochamadas via operadora"</string>
     <string name="gsm_umts_options" msgid="4968446771519376808">"Opções GSM/UMTS"</string>
     <string name="cdma_options" msgid="3669592472226145665">"Opções CDMA"</string>
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"O FDN não foi atualizado porque o número excede <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> dígitos."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"O FDN não foi atualizado. O PIN2 estava incorreto, ou o número de telefone foi rejeitado."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Falha na operação de FDN."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Não é possível discar o código MMI porque o FDN está ativado."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Lendo a partir do chip…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Não há contatos no seu chip."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Selecione os contatos a serem importados"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simular o modo fora de serviço (somente build de depuração)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forçar o canal LTE de satélite do grupo (somente build de depuração)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulação de modo satélite da operadora (somente build de depuração)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simulação do modo de dados de satélite (somente depuração)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restrito"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limitado"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Ilimitado"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testar o modo eSOS por satélite (somente build de depuração)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testar o modo sem emergência de satélite real (somente build de depuração)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testar a demonstração do modo eSOS por satélite (somente build de depuração)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Cancelar"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Mudar para o perfil de trabalho"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instalar um app de mensagens de trabalho"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Ver configurações de satélite"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Leitor de configurações de satélite"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versão:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"códigos de países:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"tamanho do arquivo sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"arquivo JSON de configuração do acesso a satélite:"</string>
 </resources>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index fd5cf374b..560b941ef 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"NAR nu a fost actualizat deoarece numărul depășește <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> cifre."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"NAR nu a fost actualizat. Codul PIN2 a fost incorect sau numărul de telefon a fost respins."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Operațiunea NAR nu a reușit."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Nu se poate forma codul MMI deoarece NAR-ul este activat."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Se citește de pe cardul SIM..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Nicio persoană pe cardul SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Selectează pentru import"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulează modul în afara ariei de acoperire (numai în versiunea pentru remedierea erorilor)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Forțează canalul Camp Satellite LTE (numai versiunea pentru remedierea erorilor)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mod Satelit al operatorului de testare (numai versiune pentru remedierea erorilor)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Mod de date prin satelit pentru testare (numai pentru remedierea erorilor)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Restricționat"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limitat"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Nelimitat"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testează modul eSOS prin satelit real (numai versiunea pentru remedierea erorilor)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testează modul non-eSOS prin satelit real (numai versiunea pentru remedierea erorilor)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testează modul demonstrativ eSOS prin satelit (numai versiunea pentru remedierea erorilor)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Anulează"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Comută la profilul de serviciu"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instalează o aplicație pentru mesaje de serviciu"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Afișează configurația satelitului"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Vizualizator de configurații pentru satelit"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versiune:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"permite_accesul:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"coduri de țară:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"dimensiunea fișierului sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"fișierul json de configurare a accesului prin satelit:"</string>
 </resources>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index a5ceee8f4..ca227c541 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Разрешенный номер не обновлен, так как не может содержать более <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> цифр."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Список разрешенных номеров не обновлен. Указан неверный PIN2 или номер телефона."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Не удалось включить FDN"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Не удалось набрать код MMI, поскольку включена функция набора разрешенных номеров."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Считывание с SIM-карты…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"На SIM-карте нет контактов"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Выберите контакты для импорта"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Моделирование нахождения вне зоны обслуживания (только отладочная сборка)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Принудительно использовать спутниковый канал LTE (только для отладочной сборки)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Режим спутниковой связи симуляции оператора (только отладочная сборка)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Режим фиктивных спутниковых данных (только отладка)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Доступ ограничен"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"С ограничениями"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Без ограничений"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Проверка спутникового режима eSOS (только отладочная сборка)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Проверка спутниковой связи в режиме, отличном от eSOS (только отладочная сборка)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Проверка демоверсии спутникового режима eSOS (только отладочная сборка)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Отмена"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Перейти в рабочий профиль"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Установите приложение для обмена рабочими сообщениями"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Показать конфигурацию спутниковой связи"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Средство просмотра конфигурации спутниковой связи"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"версия:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"коды стран:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"размер sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"JSON-файл конфигурации спутниковой связи"</string>
 </resources>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 8c90fde85..5e9abc009 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"අංකය ඉලක්කම් <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> ඉක්මවන නිසා FDN යාවත්කාලීන නොකරන ලදී."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN යාවත්කාලින නොවුණි. PIN2 වැරදියි, නැති නම් දුරකථන අංකය ප්‍රතික්ෂේප විය."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN ක්‍රියාවලිය අසමත්."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN සබල කර ඇති නිසා MMI කේතය ඩයල් කළ නොහැක."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM කාඩ් පතෙන් කියවමින්…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"ඔබගේ SIM පතෙහි සම්බන්ධතා නොමැත."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"ආයාත කිරීමට සම්බන්ධතා තෝරන්න"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"සේවයෙන් බැහැරව අනුකරණය කරන්න (නිදොස් තැනුම පමණි)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE නාලිකාව (නිදොසීමේ තැනුම පමණි)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"ආදර්ශ වාහක චන්ද්‍රිකා ප්‍රකාරය (නිදොස් තැනීමට පමණි)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"අනුකරණ චන්ද්‍රිකා දත්ත ප්‍රකාරය (නිදොස්කරණය පමණි)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"සීමා කළ"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"සීමිතයි"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"අසීමිත"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"සැබෑ චන්ද්‍රිකා eSOS ප්‍රකාරය පරීක්ෂා කරන්න (නිදොස් තැනීමට පමණි)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"සැබෑ චන්ද්‍රිකා eSOS නොවන ප්‍රකාරය පරීක්ෂා කරන්න (නිදොස් තැනීමට පමණි)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ආදර්ශන චන්ද්‍රිකා eSOS ප්‍රකාරය පරීක්ෂා කරන්න (නිදොස් තැනීමට පමණි)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"අවලංගු කරන්න"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"කාර්යාල පැතිකඩ වෙත මාරු වන්න"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"කාර්යාල පණිවිඩ යැවීමේ යෙදුමක් ස්ථාපනය කරන්න"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"චන්ද්‍රිකා වින්‍යාසය පෙන්වන්න"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"චන්ද්‍රිකා වින්‍යාස දක්වනය"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"අනුවාදය:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/සේවාවර්ගය:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"රටේ කේත:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat ප්‍රමාණය:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"චන්ද්‍රිකා ප්‍රවේශ වින්‍යාස json:"</string>
 </resources>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 9c446a4e2..d28013539 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Režim povolených čísel nebol aktualizovaný, pretože číslo obsahuje viac než maximálny počet povolených číslic (<xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g>)."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Povolené čísla neboli aktualizované. Kód PIN2 je nesprávny alebo bolo telefónne číslo odmietnuté."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Operácia s povolenými číslami zlyhala."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Kód MMI nemožno vytočiť, pretože je zapnutý režim povolených čísel."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Prebieha čítanie zo SIM karty..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Na SIM karte nie sú žiadne kontakty."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Vybrať kontakty na import"</string>
@@ -664,7 +665,7 @@
     <string name="not_voice_capable" msgid="2819996734252084253">"Hlasové volanie nie je podporované"</string>
     <string name="description_dial_button" msgid="8614631902795087259">"vytáčanie"</string>
     <string name="description_dialpad_button" msgid="7395114120463883623">"zobraziť číselnú klávesnicu"</string>
-    <string name="pane_title_emergency_dialpad" msgid="3627372514638694401">"Číselná klávesnica na tiesňové volanie"</string>
+    <string name="pane_title_emergency_dialpad" msgid="3627372514638694401">"Tiesňové vytáčanie"</string>
     <string name="voicemail_visual_voicemail_switch_title" msgid="6610414098912832120">"Vizuálna hlasová schránka"</string>
     <string name="voicemail_set_pin_dialog_title" msgid="7005128605986960003">"Nastavenie kódu PIN"</string>
     <string name="voicemail_change_pin_dialog_title" msgid="4633077715231764435">"Zmena kódu PIN"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulácia nefungujúceho zariadenia (možné iba v ladiacej zostave)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Vynútenie kanála Camp Satellite LTE (iba ladiaca zostava)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulácia satelitného režimu operátora (iba ladiaca zostava)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simulácia režimu satelitných dát (iba ladenie)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Zakázané"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Obmedzené"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Neobmedzené"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testovať režim pomoci v tiesni cez skutočné satelity (iba ladiaca zostava)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testovať štandardný režim cez skutočné satelity (iba ladiaca zostava)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testovať režim pomoci v tiesni cez demo satelity (iba ladiaca zostava)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Zrušiť"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Prepnúť na pracovný profil"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Inštalovať aplikáciu na odosielanie pracovných správ"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Zobraziť konfiguráciu pre satelit"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Zobrazenie konfigurácie pre satelit"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"verzia:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"povoliť prístup:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"kódy krajín:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"veľkosť súboru sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"konfiguračný súbor JSON prístupu cez satelit:"</string>
 </resources>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index 46383b47b..eff5c0b78 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN ni bil posodobljen, ker število presega <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> mest."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN ni bil posodobljen. Koda PIN2 je bila napačna ali pa je bila telefonska številka zavrnjena."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Postopek za omejeno klicanje ni uspel."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Kode MMI ni mogoče vnesti, ker je omogočena funkcija FDN."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Branje kartice SIM ..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Na kartici SIM ni stikov."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Izberite stike za uvoz"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulacija nedelovanja (samo za gradnjo za odpravljanje napak)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Satelitski kanal LTE za Force Camp (samo gradnja za odpravljanje napak)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Lažni satelitski način operaterja (samo gradnja za odpravljanje napak)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simulirani način satelitskih podatkov (samo za odpravljanje napak)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Nedovoljeno"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Omejeno"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Neomejeno"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Preizkus pravega satelitskega načina eSOS (samo gradnja za odpravljanje napak)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Preizkus pravega satelitskega (nenujnega) načina eSOS (samo gradnja za odpravljanje napak)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Preizkus predstavitvenega satelitskega načina eSOS (samo gradnja za odpravljanje napak)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Prekliči"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Preklopi na delovni profil"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Namestite delovno aplikacijo za sporočanje"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Pokaži konfiguracijo satelita"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Pregledovalnik konfiguracije satelita"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"različica:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"omogoči_dostop:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"kode držav:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"velikost datoteke sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"datoteka json s konfiguracijo dostopa do satelita:"</string>
 </resources>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 5dc50c483..d565ede2f 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Veçoria FDN nuk u përditësua sepse numri i kalon <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> shifra."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN-ja nuk u përditësua. PIN2-shi ishte i pasaktë ose numri i telefonit u refuzua."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Operacioni FDN dështoi"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Kodi MMI nuk mund të formohet sepse FDN-ja është aktive."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Po lexon nga karta SIM..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"S\'ka kontakte në kartën SIM."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Zgjidh kontaktet për importim"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulo gjendjen jashtë shërbimit (vetëm versioni i korrigjimit)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Detyro kanalin satelitor të LTE-së për kampin (vetëm versioni i korrigjimit)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulo modalitetin e satelitit të operatorit celular (vetëm versioni i korrigjimit)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simulo modalitetin e të dhënave satelitore (vetëm versioni i korrigjimit)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Kufizuar"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Me kufi"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Pa kufi"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testo modalitetin real të \"eSOS satelitor\" (vetëm versioni i korrigjimit)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testo modalitetin real satelitor jo për eSOS (vetëm versioni i korrigjimit)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testo modalitetin e demonstrimit të \"eSOS satelitor\" (vetëm versioni i korrigjimit)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Anulo"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Kalo te profili i punës"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Instalo një aplikacion të mesazheve të punës"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Shfaq konfigurimin e satelitit"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Shikuesi i konfigurimit të satelitit"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versioni:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"prefikset e shtetit:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"madhësia e sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"json e konfigurimit të qasjes së satelitit:"</string>
 </resources>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 7c70a74ca..e942bd0c2 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Број за фиксно бирање није ажуриран јер има превише цифара (више од <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g>)."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN није ажуриран. PIN2 је нетачан или је број телефона одбачен."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Радња са бројем за фиксно бирање није успела."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Није могуће бирати MMI кôд јер је број за фиксно бирање омогућен."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Чита се са SIM картице…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Нема контаката на SIM картици."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Избор контаката за увоз"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Симулација не функционише (само верзија са отклоњеним грешкама)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Принудно примени сателит за камповање на LTE канал (само верзија за отклањање грешака)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Лажни режим мобилног оператера за слање преко сателита (само верзија за отклањање грешака)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Режим симулације сателитских података (само верзија са отклоњеним грешкама)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Ограничено"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Ограничено"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Неограничено"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Тестирајте стварни сателитски eSOS режим (само верзија са отклоњеним грешкама)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Тестирајте стварни сателитски режим који није eSOS (само верзија са отклоњеним грешкама)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Тестирајте демо верзију сателитског eSOS режима (само верзија са отклоњеним грешкама)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Откажи"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Пређи на пословни профил"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Инсталирајте пословну апликацију за размену порука"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Прикажи сателитску конфигурацију"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Приказ сателитске конфигурације"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"верзија:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"дозволи_приступ:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"кодови земаља:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"величина фајла sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"приступ сателитској конфигурацији у формату json:"</string>
 </resources>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 9e2e94379..ddc0d2160 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN uppdaterades inte eftersom numret översteg <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> siffror."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN uppdaterades inte. Antingen har du angivit fel PIN2, eller så avvisades telefonnumret."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Det gick inte att ringa till fast uppringningsnummer."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Det går inte att slå MMI-koden eftersom FDN har aktiverats."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Läser från SIM-kort…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Inga kontakter på SIM-kortet."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Välj vilka kontakter som ska importeras"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Simulera ur funktion (endast felsökningsversion)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp Satellite LTE-kanal (endast felsökningsversion)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Simulering av operatörssatellitläge (version endast för felsökning)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Simulering av satellitdataläge (endast felsökning)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Begränsat"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Begränsat"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Obegränsat"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Testa verkligt eSOS-satellitläge (endast felsökningsversion)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Testa verkligt icke-eSOS-satellitläge (endast felsökningsversion)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Testa demoläge för eSOS-satellit (endast felsökningsversion)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Avbryt"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Byt till jobbprofilen"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Installera jobbmeddelandeapp"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Visa satellitkonfiguration"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Visare av satellitkonfiguration"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"version:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetyp:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"tillåt åtkomst:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"landskoder:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"storlek på sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"json-fil för konfiguration av satellitåtkomst:"</string>
 </resources>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 2f3fdeb74..6c41cfc61 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"FDN haijasasishwa kwa sababu namba inazidi tarakimu <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g>."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN haikusasishwa. PIN2 haikuwa sahihi, au namba ya simu ilikataliwa."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Utendakazi wa FDN ulishindwa."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Haiwezi kupiga msimbo wa MMI kwa sababu namba mahususi za kupigia imewezeshwa."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Inasoma kutoka kwa SIM kadi…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Hakuna anwani kwenye SIM kadi yako."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Chagua anwani za kuingiza"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Kifaa cha Kuiga Hakifanyi Kazi (Muundo wa Utatuzi pekee)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Chaneli ya Setilaiti ya LTE ya Force Camp (Muundo wa Utatuzi Pekee)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Hali ya Setilaiti ya Jaribio la Mtoa Huduma (Muundo wa Utatuzi pekee)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Hali ya Data ya Setilaiti ya Majaribio (Muundo wa Utatuzi pekee)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Imezuiwa"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Ina kikomo"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Haina kikomo"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Kujaribu hali ya msaada halisi wa mtandaoni kupitia setilaiti (Muundo wa Utatuzi pekee)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Kujaribu hali ya non-eSOS kwenye setilaiti halisi (Muundo wa Utatuzi pekee)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Kujaribu hali ya eSOS kwenye setilaiti ya jaribio (Muundo wa Utatuzi pekee)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Ghairi"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Tumia wasifu wa kazini"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Sakinisha programu ya kazini ya kutuma ujumbe"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Onyesha Mipangilio ya Setilaiti"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Kitazamaji cha Mipangilio ya Setilaiti"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"toleo la:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"misimbo ya nchi:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"ukubwa wa faili ya sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"faili ya json ya mipangilio ya ufikiaji wa setilaiti:"</string>
 </resources>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 68c9b31df..400e50e90 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"உள்ளிட்ட எண் <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> இலக்கங்களுக்கும் அதிகமாக உள்ளதால் FDN புதுப்பிக்கப்படவில்லை."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN புதுப்பிக்கப்படவில்லை. PIN2 தவறானது அல்லது மொபைல் எண் நிராகரிக்கப்பட்டது."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN செயல்பாடு தோல்வி."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN இயக்கப்பட்டுள்ளதால் MMI குறியீட்டை டயல் செய்ய முடியவில்லை."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"சிம் கார்டில் இருப்பதைப் படிக்கிறது…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"சிம் கார்டில் தொடர்புகள் இல்லை."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"ஏற்ற தொடர்புகளைத் தேர்ந்தெடு"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"சாதனம் \'வேலை செய்யவில்லை\' என்பதை சிமுலேட் செய்தல் (பிழைதிருத்தப் பதிப்பில் மட்டும்)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ஃபோர்ஸ் கேம்ப் சாட்டிலைட் LTE சேனல் (பிழைதிருத்தக் கட்டமைப்பு மட்டும்)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mock மொபைல் நிறுவன சாட்டிலைட் பயன்முறை (பிழைதிருத்த பதிப்பு மட்டும்)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"செயற்கைக்கோள் தரவுப் பயன்முறை மாதிரி (பிழைதிருத்தம் மட்டும்)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"கட்டுப்படுத்தப்பட்டது"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"வரம்பிற்குட்பட்டது"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"வரம்பற்றது"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"அசல் சாட்டிலைட் eSOS பயன்முறை (பிழைதிருத்தப் பதிப்பு மட்டும்)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"அசல் சாட்டிலைட் eSOS அல்லாத பயன்முறையைப் பயன்படுத்திப் பாருங்கள் (பிழைதிருத்தப் பதிப்பு மட்டும்)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"டொமோ சாட்டிலைட் eSOS பயன்முறையைப் பரிசோதனை செய்தல் (பிழைதிருத்தப் பதிப்பு மட்டும்)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"ரத்துசெய்"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"பணிக் கணக்கிற்கு மாறு"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"பணி தொடர்பான மெசேஜ்களுக்கான ஆப்ஸை நிறுவு"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"சாட்டிலைட் உள்ளமைவைக் காட்டு"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"சாட்டிலைட் உள்ளமைவு வியூவர்"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"பதிப்பு:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"தேசக் குறியீடுகள்:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat ஃபைல் அளவு:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"சாட்டிலைட் அணுகலுக்கான உள்ளமைவு JSON ஃபைல்:"</string>
 </resources>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 1a7faf6f0..7d2e9312b 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"నంబర్ <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> అంకెలను మించినందున FDN అప్‌డేట్ చేయబడలేదు."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN అప్‌డేట్ చేయబడలేదు. PIN2 చెల్లదు లేదా ఫోన్ నంబర్ తిరస్కరించబడింది."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN చర్య విఫలమైంది."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDNను ఎనేబుల్ చేసిన కారణంగా MMI కోడ్‌ను డయల్ చేయలేరు."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM కార్డు నుండి చదువుతోంది…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"మీ SIM కార్డులో కాంటాక్ట్‌లు ఏవీ లేవు."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"దిగుమతి చేసుకోవాలనుకున్న కాంటాక్ట్‌లను ఎంచుకోండి"</string>
@@ -582,7 +583,7 @@
     <string name="description_concat_format" msgid="2014471565101724088">"%1$s, %2$s"</string>
     <string name="dialerKeyboardHintText" msgid="1115266533703764049">"డయల్ చేయడానికి కీబోర్డ్‌ను ఉపయోగించండి"</string>
     <string name="onscreenHoldText" msgid="4025348842151665191">"హోల్డ్ చేయి"</string>
-    <string name="onscreenEndCallText" msgid="6138725377654842757">"ముగించు"</string>
+    <string name="onscreenEndCallText" msgid="6138725377654842757">"ముగించండి"</string>
     <string name="onscreenShowDialpadText" msgid="658465753816164079">"డయల్‌ప్యాడ్"</string>
     <string name="onscreenMuteText" msgid="5470306116733843621">"మ్యూట్ చేయి"</string>
     <string name="onscreenAddCallText" msgid="9075675082903611677">"కాల్‌ను జోడించండి"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"పరికరాన్ని సిమ్యులేట్ చేయడం అందుబాటులో లేదు (డీబగ్ బిల్డ్ మోడ్‌లో మాత్రమే)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"ఫోర్స్ క్యాంప్ శాటిలైట్ LTE ఛానెల్ (డీబగ్ బిల్డ్ మోడ్‌లో మాత్రమే)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"మాక్ క్యారియర్ శాటిలైట్ మోడ్ (డీబగ్ బిల్డ్ మోడ్‌లో మాత్రమే)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"మాక్ శాటిలైట్ డేటా మోడ్ (డీబగ్ మాత్రమే)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"పరిమితం చేయబడింది"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"పరిమితం"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"అపరిమితం"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"రియల్ శాటిలైట్ eSOS మోడ్‌ను టెస్ట్ చేయండి (డీబగ్ బిల్డ్ మోడ్‌లో మాత్రమే)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"రియల్ శాటిలైట్ eSOS యేతర మోడ్‌ను టెస్ట్ చేయండి (డీబగ్ బిల్డ్ మోడ్‌లో మాత్రమే)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"డెమో శాటిలైట్ eSOS మోడ్‌ను టెస్ట్ చేయండి (డీబగ్ బిల్డ్ మోడ్‌లో మాత్రమే)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"రద్దు చేయండి"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"వర్క్ ప్రొఫైల్‌కు స్విచ్ అవ్వండి"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"వర్క్ మెసేజ్‌ల యాప్‌ను ఇన్‌స్టాల్ చేయండి"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"శాటిలైట్ కాన్ఫిగరేషన్‌ను చూడండి"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"శాటిలైట్ కాన్ఫిగరేషన్ వ్యూయర్"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"వెర్షన్:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"దేశం కోడ్:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat సైజు:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"శాటిలైట్ యాక్సెస్ కాన్ఫిగరేషన్ json:"</string>
 </resources>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 45b5bcf42..db78a1710 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"ระบบไม่ได้อัปเดต FDN เนื่องจากหมายเลขมีจำนวนเกิน <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> หลัก"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"ไม่ได้อัปเดต FDN เพราะ PIN2 ไม่ถูกต้องหรือหมายเลขโทรศัพท์ถูกปฏิเสธ"</string>
     <string name="fdn_failed" msgid="216592346853420250">"การปลดล็อกด้วย FDN ล้มเหลว"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"โทรออกด้วยรหัส MMI ไม่ได้เนื่องจากเปิดใช้ FDN อยู่"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"กำลังอ่านจากซิมการ์ด…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"ไม่มีรายชื่อติดต่อในซิมการ์ด"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"เลือกรายชื่อที่จะนำเข้า"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"จําลองความไม่พร้อมให้บริการ (บิลด์การแก้ไขข้อบกพร่องเท่านั้น)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"บังคับใช้แชนเนล LTE ของ Camp Satellite (บิลด์การแก้ไขข้อบกพร่องเท่านั้น)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"โหมดดาวเทียมของผู้ให้บริการจำลอง (บิลด์การแก้ไขข้อบกพร่องเท่านั้น)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"โหมดข้อมูลดาวเทียมจำลอง (เฉพาะการแก้ไขข้อบกพร่อง)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"จำกัด"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"จำกัด"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"ไม่จำกัด"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"ทดสอบโหมด eSOS ของดาวเทียมจริง (บิลด์การแก้ไขข้อบกพร่องเท่านั้น)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"ทดสอบโหมด non-eSOS ของดาวเทียมจริง (บิลด์การแก้ไขข้อบกพร่องเท่านั้น)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"ทดสอบโหมด eSOS ของดาวเทียมเดโม (บิลด์การแก้ไขข้อบกพร่องเท่านั้น)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"ยกเลิก"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"สลับไปใช้โปรไฟล์งาน"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"ติดตั้งแอปรับส่งข้อความสำหรับที่ทำงาน"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"แสดงการกำหนดค่าดาวเทียม"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"เครื่องมือดูการกำหนดค่าดาวเทียม"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"version:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"country codes:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"size of sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"satellite access config json:"</string>
 </resources>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index d64fb8f5f..9d1aa4349 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Hindi na-update ang FDN dahil ang bilang ay lampas sa <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> (na) digit."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Hindi na-update ang FDN. Hindi wasto ang PIN2, o tinanggihan ang numero ng telepono."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Nagbigo ang operasyon ng FDN."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Hindi ma-dial ang MMI code dahil naka-enable ang FDN."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Nagbabasa mula sa SIM card…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Walang contact sa iyong SIM card."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Piliin mga contact na i-import"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Mag-simulate ng Hindi Gumagana (Build sa Pag-debug lang)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Ipilit ang Camp Satellite LTE Channel (Build sa Pag-debug lang)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Satellite Mode ng Mock Carrier (Debug Build lang)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Mock Satellite Data mode (Pag-debug lang)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Pinaghihigpitan"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Limitado"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Unlimited"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Test real satellite eSOS mode (Build sa Pag-debug lang)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Test real satellite non-eSOS mode (Build sa Pag-debug lang)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Test demo satellite eSOS mode (Build sa Pag-debug lang)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Kanselahin"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Lumipat sa profile sa trabaho"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Mag-install ng app sa pagmemensahe para sa trabaho"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Ipakita ang Config ng Satellite"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Viewer ng Config ng Satellite"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"bersyon:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"mga country code:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"laki ng sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"json ng config ng access sa satellite:"</string>
 </resources>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index c74263123..a4650378d 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Numara <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> basamaktan uzun olduğu için SAN güncellenemedi."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN güncellenmedi. PIN2 doğru değildi veya telefon numarası reddedildi."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN işlemi başarısız oldu."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"SAN etkin olduğundan MMI kodu aranamıyor."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM karttan okunuyor..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"SIM kartınızda kişi yok."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"İçe aktarılacak kişileri seçin"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Hizmet Dışı Simülasyonu (Yalnızca Hata Ayıklama Derlemesi)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Kamp uydusu LTE kanalını zorunlu kılma (yalnızca hata ayıklama derlemesi)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Örnek operatör uydu modu (yalnızca hata ayıklama derlemesi)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Uydu verileri modunu taklit et (yalnızca hata ayıklama)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Kısıtlı"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Sınırlı"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Sınırsız"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Gerçek uydu eSOS modunu test et (yalnızca hata ayıklama derlemesi)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Gerçek uydu üzerinde eSOS olmayan modu test et (yalnızca hata ayıklama derlemesi)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Demo uydu üzerinde eSOS modunu test et (yalnızca hata ayıklama derlemesi)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"İptal"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"İş profiline geç"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"İş mesajları için uygulama yükle"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Uydu Yapılandırmasını Göster"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Uydu Yapılandırması Görüntüleyici"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"sürüm:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"erişime_izin_ver:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"ülke kodları:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat boyutu:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"uydu erişim yapılandırması JSON dosyası:"</string>
 </resources>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 76b2a0478..bf051c4aa 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Номер FDN не оновлено, оскільки кількість цифр не може перевищувати <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g>."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"Фіксований номер (FDN) не оновлено. PIN2-код неправильний або номер телефону відхилено."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Помилка набору фіксованого номера."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Не можна набрати код MMI, оскільки ввімкнено FDN."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Читання із SIM-карти…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"На SIM-карті немає контактів"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Виберіть контакти для імпорту"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Імітація знаходження поза зоною обслуговування (лише складання для налагодження)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Примусово застосувати супутниковий зв’язок із каналом LTE (лише для налагодження)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Режим супутника оператора Mock (лише складання для налагодження)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Режим імітації супутникового зв’язку (лише для налагодження)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Доступ обмежено"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"З обмеженнями"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Без обмежень"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Тестувати реальний режим супутникового сигналу SOS (лише складання для налагодження)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Тестувати реальний режим супутникового сигналу, відмінного від SOS (лише складання для налагодження)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Тестування демоверсії супутникового сигналу SOS (складання лише для налагодження)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Скасувати"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Перейти в робочий профіль"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Установіть робочий додаток для обміну повідомленнями"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Показати налаштування супутникового зв’язку"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Засіб перегляду налаштувань супутникового зв’язку"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"версія:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"коди країн:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"розмір файлу sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"налаштування доступу до супутникових даних (JSON):"</string>
 </resources>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index cc704cbbf..a93f83932 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"‏FDN اپ ڈیٹ نہیں ہوا کیونکہ <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> نمبر ہندسوں سے زائد ہے۔"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"‏FDN اپ ڈیٹ نہیں ہوا تھا کیونکہ PIN2 غلط تھا یا فون نمبر مسترد کر دیا گیا تھا۔"</string>
     <string name="fdn_failed" msgid="216592346853420250">"‏FDN کا عمل ناکام ہوگیا۔"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"‏‫MMI کوڈ ڈائل نہیں کیا جا سکتا کیونکہ FDN فعال ہے۔"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"‏SIM کارڈ سے پڑھ رہا ہے…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"‏آپ کے SIM کارڈ پر کوئی رابطے نہیں ہیں۔"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"درآمد کیلئے رابطے چنیں"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"\'سروس دستیاب نہیں ہے\' موڈ کو سمیولیٹ کریں (صرف ڈیبگ بلڈ کیلئے)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"‏فورس کیمپ سیٹلائٹ LTE چینل (صرف ڈیبگ بلڈ)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"موک کیریئر سیٹلائٹ موڈ (صرف ڈیبگ بلڈ)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"موک سیٹلائٹ ڈیٹا موڈ (صرف ڈیبگ کریں)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"ممنوع"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"محدود"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"لا محدود"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"‏اصل سیٹلائٹ eSOS وضع کی جانچ کریں (صرف ڈیبگ بلڈ)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"‏اصل سیٹلائٹ غیر eSOS وضع کی جانچ کریں (صرف ڈیبگ بلڈ)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"‏ڈیمو سیٹلائٹ eSOS وضع کی جانچ کریں (صرف ڈیبگ بلڈ)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"منسوخ کریں"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"دفتری پروفائل پر سوئچ کریں"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"دفتری پیغامات ایپ انسٹال کریں"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"سیٹلائٹ کی کنفیگریشن دکھائیں"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"سیٹلائٹ کنفیگریشن کا ملاحظہ کار"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"ورژن:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"ملک کے کوڈز:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"‏‫sats2.dat کا سائز:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"‏سیٹلائٹ رسائی کنفیگریشن کی json فائل:"</string>
 </resources>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index 346373d96..ea8f83474 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Ruxsat etilgan raqam <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> xonali raqam cheklovidan oshganligi uchun yangilanmadi."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN yangilanmadi. PIN2 kodi xato yoki telefon raqami rad qilingan."</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN jarayoni amalga oshmadi."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"FDN faolsizlantirilgani uchun MMI kodi terilmadi."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"SIM-kartadan o‘qilmoqda…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"SIM kartada hech qanday kontakt yo‘q."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Import u-n kontaktlarni tanlang"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Xizmatdan tashqari simulyatsiya (faqat nosozliklarni aniqlash dasturi uchun)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Majburiy Camp sputnik LTE kanali (faqat debag nashrida)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Soxta operator sputnik rejimi (faqat debag nashrida)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Sputnik internet rejimi simulyatsiyasi (faqat debaglash)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Cheklangan"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Cheklangan"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Cheksiz"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Haqiqiy sputnik eSOS rejimini sinash (faqat debag nashrida)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Haqiqiy sputnik non-eSOS rejimini sinash (faqat debag nashrida)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Demo sputnik eSOS rejimini sinash (faqat debag nashrida)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Bekor qilish"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Ish profiliga almashish"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Ishga oid xabar almashinuv ilovasini oʻrnating"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Sputnik sozlamasini chiqarish"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Sputnik sozlamasini koʻrish vositasi"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"versiyasi:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"mamlakat kodlari:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"size of sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"sputnik ruxsati sozlamasi json:"</string>
 </resources>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index ecf73bdb6..d3b30d0db 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"Số gọi định sẵn (FDN) chưa cập nhật do vượt quá <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> chữ số."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN không được cập nhật. Mã PIN2 không đúng hoặc số điện thoại đã bị từ chối."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Thao tác FDN không thành công."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Không thể gọi mã MMI vì tính năng số gọi định sẵn (FDN) đang bật."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Đang đọc từ thẻ SIM…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Không có liên hệ nào trên thẻ SIM của bạn."</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Chọn danh bạ để nhập"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Mô phỏng thiết bị không hoạt động (chỉ dành cho bản gỡ lỗi)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Buộc sử dụng kênh LTE vệ tinh khi cắm trại (chỉ dành cho Bản gỡ lỗi)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Mô phỏng chế độ vệ tinh của nhà mạng (chỉ dành cho Bản gỡ lỗi)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Mô phỏng dữ liệu ở chế độ vệ tinh (chỉ dành cho bản gỡ lỗi)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Bị hạn chế"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Giới hạn"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Không giới hạn"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Thử nghiệm chế độ eSOS thực tế qua vệ tinh (chỉ bản gỡ lỗi)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Thử nghiệm chế độ không khẩn cấp thực tế qua vệ tinh (chỉ dành cho bản gỡ lỗi)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Thử nghiệm chế độ eSOS minh hoạ qua vệ tinh (chỉ dành cho bản gỡ lỗi)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Huỷ"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Chuyển sang hồ sơ công việc"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Cài đặt một ứng dụng nhắn tin dùng trong công việc"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Hiển thị cấu hình vệ tinh"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Trình xem cấu hình vệ tinh"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"phiên bản:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"mã quốc gia:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"kích thước của tệp sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"json cấu hình truy cập vệ tinh:"</string>
 </resources>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index fd6150721..8eedd0ea3 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"未能更新 FDN，因为号码超过 <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> 位数。"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"固定拨号未更新。PIN2 码有误，或电话号码遭拒。"</string>
     <string name="fdn_failed" msgid="216592346853420250">"固定拨号操作失败。"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"由于已启用固定拨号，因此无法拨打 MMI 码。"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"正在从SIM卡读取..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"SIM卡上无联系人。"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"选择要导入的联系人"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"模拟服务终止（仅限调试 build）"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"强制使用 Camp 卫星 LTE 信道（仅限调试 Build）"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"模拟运营商卫星模式（仅限调试 build）"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"模拟卫星数据模式（仅限调试）"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"受限"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"有限"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"无限制"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"测试真实的卫星 eSOS 模式（仅限调试 build）"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"测试真实的卫星非 eSOS 模式（仅限调试 build）"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"测试卫星 eSOS 演示模式（仅限调试 build）"</string>
@@ -862,7 +867,7 @@
     <string name="radio_info_ims_reg_status" msgid="25582845222446390">"IMS 注册：<xliff:g id="STATUS">%1$s</xliff:g>\nLTE 语音通话：<xliff:g id="AVAILABILITY_0">%2$s</xliff:g>\nWLAN 语音通话：<xliff:g id="AVAILABILITY_1">%3$s</xliff:g>\n视频通话：<xliff:g id="AVAILABILITY_2">%4$s</xliff:g>\nUT 接口：<xliff:g id="AVAILABILITY_3">%5$s</xliff:g>"</string>
     <string name="radioInfo_service_in" msgid="45753418231446400">"服务中"</string>
     <string name="radioInfo_service_out" msgid="287972405416142312">"不在服务区"</string>
-    <string name="radioInfo_service_emergency" msgid="4763879891415016848">"只能拨打紧急呼叫电话"</string>
+    <string name="radioInfo_service_emergency" msgid="4763879891415016848">"只能拨打紧急求助电话"</string>
     <string name="radioInfo_service_off" msgid="3456583511226783064">"关闭无线装置"</string>
     <string name="radioInfo_roaming_in" msgid="3156335577793145965">"漫游"</string>
     <string name="radioInfo_roaming_not" msgid="1904547918725478110">"未使用漫游服务"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"取消"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"切换到工作资料"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"安装工作消息应用"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"显示卫星配置"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"卫星配置查看器"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"版本："</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/服务类型："</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"允许访问："</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"国家/地区代码："</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat 的大小："</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"卫星访问权限配置 JSON："</string>
 </resources>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 30d09edc4..236642bb8 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"號碼超過 <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> 位數，FDN 未更新。"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"FDN 無法更新。PIN2 碼不正確或電話號碼被拒。"</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN 操作失敗。"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"固定撥號已啟用，因此無法撥打 MMI 代碼。"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"正在從 SIM 卡讀取..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"SIM 卡中沒有聯絡人。"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"選取要匯入的聯絡人"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"模擬沒有服務 (僅限偵錯版本)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Force Camp 衛星 LTE 頻道 (僅限偵錯版本)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"模擬流動網絡供應商衛星模式 (僅限偵錯版本)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"模擬衛星數據模式 (僅限偵錯版本)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"受限制"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"有限制"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"無限制"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"測試「緊急衛星連接」真實模式 (僅限偵錯版本)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"測試「非緊急衛星連接」真實模式 (僅限偵錯版本)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"測試「緊急衛星連接」試用模式 (僅限偵錯版本)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"取消"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"切換至工作設定檔"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"安裝工作訊息應用程式"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"顯示衛星設定"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"衛星設定檢視器"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"版本："</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype："</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"允許存取："</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"國家/地區代碼："</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat 大小："</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"衛星存取設定 json："</string>
 </resources>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 838cbe76f..5f18e957d 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -303,7 +303,7 @@
     <string name="data_usage_template" msgid="6287906680674061783">"<xliff:g id="ID_2">%2$s</xliff:g>期間使用了 <xliff:g id="ID_1">%1$s</xliff:g> 的行動數據"</string>
     <string name="advanced_options_title" msgid="9208195294513520934">"進階"</string>
     <string name="carrier_settings_euicc" msgid="1190237227261337749">"電信業者"</string>
-    <string name="keywords_carrier_settings_euicc" msgid="8540160967922063745">"電信業者, eSIM 卡, SIM 卡, eUICC, 切換電信業者, 新增電信業者"</string>
+    <string name="keywords_carrier_settings_euicc" msgid="8540160967922063745">"電信業者, eSIM, SIM 卡, eUICC, 切換電信業者, 新增電信業者"</string>
     <string name="carrier_settings_euicc_summary" msgid="2027941166597330117">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> - <xliff:g id="PHONE_NUMBER">%2$s</xliff:g>"</string>
     <string name="mobile_data_settings_title" msgid="7228249980933944101">"行動數據"</string>
     <string name="mobile_data_settings_summary" msgid="5012570152029118471">"使用行動網路存取數據"</string>
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"固定撥號的號碼超過 <xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g> 位數，因此無法更新。"</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"未更新 FDN。可能是因為 PIN2 碼不正確或電話號碼遭拒。"</string>
     <string name="fdn_failed" msgid="216592346853420250">"FDN 操作失敗。"</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"固定撥號功能已啟用，因此無法撥打 MMI 碼。"</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"正在從 SIM 卡讀取…"</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"你的 SIM 卡上沒有聯絡人。"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"選取要匯入的聯絡人"</string>
@@ -842,11 +843,15 @@
     <string name="dsds_dialog_message" msgid="4047480385678538850">"你必須重新啟動裝置，才能變更這項設定。"</string>
     <string name="dsds_dialog_confirm" msgid="9032004888134129885">"重新啟動"</string>
     <string name="dsds_dialog_cancel" msgid="3245958947099586655">"取消"</string>
-    <string name="removable_esim_string" msgid="7931369811671787649">"將可移除的 eSIM 卡設為預設 eSIM 卡"</string>
+    <string name="removable_esim_string" msgid="7931369811671787649">"將可移除的 eSIM 設為預設 eSIM"</string>
     <string name="radio_info_radio_power" msgid="8805595022160471587">"行動無線電電源"</string>
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"模擬無法使用服務的情況 (僅限偵錯版本)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"強制執行 Camp 衛星 LTE 頻道 (僅限偵錯版本)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"模擬電信業者衛星模式 (僅限偵錯版本)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"模擬衛星資料模式 (僅限偵錯)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"受限制"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"有限"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"無限制"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"實際測試衛星緊急求救模式 (僅限偵錯版本)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"實際測試衛星非緊急求救模式 (僅限偵錯版本)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"測試衛星緊急求救展示模式 (僅限偵錯版本)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"取消"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"切換至工作資料夾"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"安裝工作訊息應用程式"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"顯示衛星設定"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"衛星設定檢視工具"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"版本："</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"子 ID/PLMN/服務類型："</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"允許存取："</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"國家/地區代碼："</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"sats2.dat 的大小："</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"衛星存取權設定 JSON："</string>
 </resources>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 2ec8c18e2..343126085 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -481,6 +481,7 @@
     <string name="fdn_invalid_number" msgid="9067189814657840439">"I-FDN ayizange ibuyekezwe ngoba inombolo idlula amadijithi angu-<xliff:g id="FDN_NUMBER_LIMIT_LENGTH">%d</xliff:g>."</string>
     <string name="pin2_or_fdn_invalid" msgid="7542639487955868181">"I-FDN ayibuyekeziwe. I-PIN2 kade ingalungile, noma inombolo yefoni yenqatshelwe."</string>
     <string name="fdn_failed" msgid="216592346853420250">"Umsebenzi we-FDN wehlulekile."</string>
+    <string name="fdn_blocked_mmi" msgid="3218296901316119797">"Ayikwazi ukudayela ikhodi ye-MMI ngoba i-FDN inikwe amandla."</string>
     <string name="simContacts_emptyLoading" msgid="4989040293858675483">"Ifunda ekhadini le-SIM..."</string>
     <string name="simContacts_empty" msgid="1135632055473689521">"Abekho othintana nabo ekhadini lakho le-SIM"</string>
     <string name="simContacts_title" msgid="2714029230160136647">"Khetha othintana nabo ozobangenisa"</string>
@@ -847,6 +848,10 @@
     <string name="simulate_out_of_service_string" msgid="7787925611727597193">"Lingisa okuthi Ayikho Isevisi (Umakhiwo Wokususa Iphutha kuphela)"</string>
     <string name="enforce_satellite_channel_string" msgid="295306734591329892">"Isiteshi se-Force Camp Satellite LTE (Ukwakhiwa Kokususa Iphutha kuphela)"</string>
     <string name="mock_carrier_roaming_satellite_string" msgid="4796300252858292593">"Imodi Yesethelayithi Yenkampani Yenethiwekhi ye-Mock (Susa Iphutha Esakhiweni kuphela)"</string>
+    <string name="choose_satellite_data_mode" msgid="7526640708482601423">"Imodi Yedatha Yesathelayithi Engasebenzi (Susa iphutha kuphela)"</string>
+    <string name="satellite_data_restricted_string" msgid="8729402021843670205">"Kuvinjelwe"</string>
+    <string name="satellite_data_constrained_string" msgid="4594481912792241881">"Ikhawulelwe"</string>
+    <string name="satellite_data_unConstrained_string" msgid="3957333012703408141">"Akukhawulelwe"</string>
     <string name="esos_satellite_string" msgid="7274794226125968657">"Hlola imodi yesathelayithi yangempela ye-eSOS (Ukwakhiwa Kokususa Iphutha kuphela)"</string>
     <string name="satellite_enable_non_emergency_mode_string" msgid="9005332650950637932">"Hlola imodi yesathelayithi yangempela ekungesiyo ye-eSOS (Ukwakhiwa Kokususa Iphutha kuphela)"</string>
     <string name="demo_esos_satellite_string" msgid="2941811482168709730">"Hlola imodi yesathelayithi yedemo ye-eSOS (Ukwakhiwa Kokususa Iphutha kuphela)"</string>
@@ -939,4 +944,12 @@
     <string name="send_from_work_profile_cancel" msgid="177746511030381711">"Khansela"</string>
     <string name="send_from_work_profile_action_str" msgid="6892775562934243337">"Shintshela kuphrofayela yomsebenzi"</string>
     <string name="install_messages_on_work_profile_action_str" msgid="3773440996395152903">"Faka i-app yemilayezo yomsebenzi"</string>
+    <string name="radio_info_data_view_satellite_config" msgid="343120041798242877">"Bonisa Ukulungiselela Isethelayithi"</string>
+    <string name="satellite_config_viewer" msgid="5128698910841573398">"Isibukeli Sokulungiselelwa Kwesethelayithi"</string>
+    <string name="satellite_config_version_label" msgid="1153447193166314791">"uhlobo:"</string>
+    <string name="satellite_config_service_type_label" msgid="21749170241956082">"subId/plmn/servicetype:"</string>
+    <string name="satellite_config_allow_access_label" msgid="3806779900418131140">"allow_access:"</string>
+    <string name="satellite_config_country_code_label" msgid="1389520866423113166">"amakhodi ezwe:"</string>
+    <string name="satellite_config_size_of_sats2_dat_label" msgid="671746449054349967">"usayizi we-sats2.dat:"</string>
+    <string name="satellite_config_json_label" msgid="4577292884014824105">"ukulungiselelwa kokufinyelela kwesethelayithi kwe-json:"</string>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 43fc09e5b..41c98e32e 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -1058,6 +1058,8 @@
     <string name="pin2_or_fdn_invalid">FDN wasn\'t updated. The PIN2 was incorrect, or the phone number was rejected.</string>
     <!-- FDN settings: error message displayed in a popup (toast) -->
     <string name="fdn_failed">FDN operation failed.</string>
+    <!-- FDN blocked MMI dialing: error message displayed in a popup (toast) -->
+    <string name="fdn_blocked_mmi">Cannot dial MMI code because FDN is enabled.</string>
 
     <!-- ADN related strings -->
     <!-- Placeholder text displayed while loading the list of SIM contacts -->
@@ -2033,6 +2035,11 @@
 
     <!-- Title for simulating SIM capable of satellite. -->
     <string name="mock_carrier_roaming_satellite_string">Mock Carrier Satellite Mode (Debug Build only)</string>
+    <!-- Title for simulating SIM Data in satellite Mode. -->
+    <string name="choose_satellite_data_mode">Mock Satellite Data mode (Debug only)</string>
+    <string name="satellite_data_restricted_string">Restricted</string>
+    <string name="satellite_data_constrained_string">Limited</string>
+    <string name="satellite_data_unConstrained_string">UnLimited</string>
     <!-- Title for trigger real satellite eSOS. -->
     <string name="esos_satellite_string">Test real satellite eSOS mode (Debug Build only)</string>
     <!-- Title for enable real satellite non-emergency mode. -->
@@ -2242,4 +2249,21 @@
     <string name="send_from_work_profile_action_str">Switch to work profile</string>
     <string name="install_messages_on_work_profile_action_str">Install a work messages app</string>
 
+    <!-- The title of option menu from phoneInfo test screen, to show satellite config -->
+    <string name="radio_info_data_view_satellite_config">Show Satellite Config</string>
+    <!-- Title of SatelliteConfigViewer screen -->
+    <string name="satellite_config_viewer">Satellite Config Viewer</string>
+    <!-- Satellite config viewer screen. Label for the config data version -->
+    <string name="satellite_config_version_label">version: </string>
+    <!-- Satellite config viewer screen. Label for the subId/plmn/servicetype -->
+    <string name="satellite_config_service_type_label">subId/plmn/servicetype: </string>
+    <!-- Satellite config viewer screen. Label for the allow access -->
+    <string name="satellite_config_allow_access_label">allow_access: </string>
+    <!-- Satellite config viewer screen. Label for the country codes -->
+    <string name="satellite_config_country_code_label">country codes: </string>
+    <!-- Satellite config viewer screen. Label for size of the s2sat.dat file -->
+    <string name="satellite_config_size_of_sats2_dat_label">size of sats2.dat: </string>
+    <!-- Satellite config viewer screen. satellite access config json file -->
+    <string name="satellite_config_json_label">satellite access config json: </string>
+
 </resources>
diff --git a/res/values/styles.xml b/res/values/styles.xml
index 088a5a7a1..584c3aa2e 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -202,11 +202,6 @@
         <item name="android:colorAccent">@color/dialer_theme_color</item>
         <item name="android:dialogTheme">@style/DialerAlertDialogTheme</item>
         <item name="android:homeAsUpIndicator">@drawable/ic_back_arrow</item>
-
-        <!--
-            TODO(b/309578419): Make activities handle insets properly and then remove this.
-        -->
-        <item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>
     </style>
 
     <style name="DialerAlertDialogTheme"
diff --git a/src/com/android/phone/CallFeaturesSetting.java b/src/com/android/phone/CallFeaturesSetting.java
index bec2a81a1..2ad8f901c 100644
--- a/src/com/android/phone/CallFeaturesSetting.java
+++ b/src/com/android/phone/CallFeaturesSetting.java
@@ -234,6 +234,9 @@ public class CallFeaturesSetting extends PreferenceActivity
                                         getString(R.string.mobile_network_settings_package),
                                         getString(R.string.mobile_network_settings_class));
                                 intent.setComponent(mobileNetworkSettingsComponent);
+                                if (mPhone != null) {
+                                    intent.putExtra(Settings.EXTRA_SUB_ID, mPhone.getSubId());
+                                }
                                 startActivityAsUser(intent, UserHandle.CURRENT);
                             }
                         };
@@ -416,7 +419,8 @@ public class CallFeaturesSetting extends PreferenceActivity
         Preference gsmOptions = prefSet.findPreference(BUTTON_GSM_UMTS_OPTIONS);
         Preference fdnButton = prefSet.findPreference(BUTTON_FDN_KEY);
         fdnButton.setIntent(mSubscriptionInfoHelper.getIntent(FdnSetting.class));
-        if (carrierConfig.getBoolean(CarrierConfigManager.KEY_WORLD_PHONE_BOOL)) {
+        if (!Flags.phoneTypeCleanup()
+                && carrierConfig.getBoolean(CarrierConfigManager.KEY_WORLD_PHONE_BOOL)) {
             cdmaOptions.setIntent(mSubscriptionInfoHelper.getIntent(CdmaCallOptions.class));
             gsmOptions.setIntent(mSubscriptionInfoHelper.getIntent(GsmUmtsCallOptions.class));
         } else {
@@ -425,7 +429,8 @@ public class CallFeaturesSetting extends PreferenceActivity
             prefSet.removePreference(gsmOptions);
 
             int phoneType = mPhone.getPhoneType();
-            if (carrierConfig.getBoolean(CarrierConfigManager.KEY_HIDE_CARRIER_NETWORK_SETTINGS_BOOL)) {
+            if (carrierConfig.getBoolean(
+                    CarrierConfigManager.KEY_HIDE_CARRIER_NETWORK_SETTINGS_BOOL)) {
                 prefSet.removePreference(fdnButton);
             } else {
                 if (phoneType == PhoneConstants.PHONE_TYPE_CDMA) {
diff --git a/src/com/android/phone/CallNotifier.java b/src/com/android/phone/CallNotifier.java
index daf3aa234..335bcba9d 100644
--- a/src/com/android/phone/CallNotifier.java
+++ b/src/com/android/phone/CallNotifier.java
@@ -34,6 +34,7 @@ import android.telephony.SubscriptionManager;
 import android.telephony.SubscriptionManager.OnSubscriptionsChangedListener;
 import android.telephony.TelephonyCallback;
 import android.telephony.TelephonyManager;
+import android.telephony.ims.feature.MmTelFeature;
 import android.util.ArrayMap;
 import android.util.Log;
 
@@ -43,6 +44,7 @@ import com.android.internal.telephony.PhoneConstants;
 import com.android.internal.telephony.cdma.CdmaInformationRecords.CdmaDisplayInfoRec;
 import com.android.internal.telephony.cdma.CdmaInformationRecords.CdmaSignalInfoRec;
 import com.android.internal.telephony.cdma.SignalToneUtil;
+import com.android.internal.telephony.imsphone.ImsPhoneCallTracker;
 import com.android.internal.telephony.subscription.SubscriptionManagerService;
 
 import java.util.ArrayList;
@@ -148,6 +150,7 @@ public class CallNotifier extends Handler {
                 new OnSubscriptionsChangedListener() {
                     @Override
                     public void onSubscriptionsChanged() {
+                        Log.i(LOG_TAG, "onSubscriptionsChanged");
                         updatePhoneStateListeners(true);
                     }
                 });
@@ -486,6 +489,22 @@ public class CallNotifier extends Handler {
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID);
     }
 
+    /**
+     * Update listeners of various "phone state" things; in particular message waiting indicators
+     * and call forwarding indicators.  The updates can either be due to network signals or due to
+     * "refreshes".  See below for more; I'm not saying this is a good design, I'm just helping set
+     * the context for how this works.
+     * @param isRefresh {@code true} if this is a refresh triggered by
+     * {@link OnSubscriptionsChangedListener}, which ultimately fires way more than it should, or
+     * {@code false} if this update is as a direct result of the network telling us something
+     * changed.
+     * @param updateType {@link #UPDATE_TYPE_MWI} for message waiting indication changes by the
+     * network, {@link #UPDATE_TYPE_CFI} for call forwarding changes by the network, or
+     * {@link #UPDATE_TYPE_MWI_CFI} when {@code isRefresh} is {@code true}.
+     * @param subIdToUpdate The sub ID the update applies to for updates from the network, or
+     * {@link SubscriptionManager#INVALID_SUBSCRIPTION_ID} refreshes due to
+     * {@link OnSubscriptionsChangedListener}.
+     */
     public void updatePhoneStateListeners(boolean isRefresh, int updateType, int subIdToUpdate) {
         List<SubscriptionInfo> subInfos = SubscriptionManagerService.getInstance()
                 .getActiveSubscriptionInfoList(mApplication.getOpPackageName(),
@@ -507,7 +526,7 @@ public class CallNotifier extends Handler {
         for (int subIdCounter = (subIdList.size() - 1); subIdCounter >= 0; subIdCounter--) {
             int subId = subIdList.get(subIdCounter);
             if (subInfos == null || !containsSubId(subInfos, subId)) {
-                Log.d(LOG_TAG, "updatePhoneStateListeners: Hide the outstanding notifications.");
+                Log.i(LOG_TAG, "updatePhoneStateListeners: Hide the outstanding notifications.");
                 // Hide the outstanding notifications.
                 mApplication.notificationMgr.updateMwi(subId, false);
                 mApplication.notificationMgr.updateCfi(subId, false);
@@ -516,7 +535,7 @@ public class CallNotifier extends Handler {
                 mTelephonyManager.unregisterTelephonyCallback(mTelephonyCallback.get(subId));
                 mTelephonyCallback.remove(subId);
             } else {
-                Log.d(LOG_TAG, "updatePhoneStateListeners: update CF notifications.");
+                Log.i(LOG_TAG, "updatePhoneStateListeners: update CF/MWI for subId=" + subId);
 
                 if (mCFIStatus.containsKey(subId)) {
                     if ((updateType == UPDATE_TYPE_CFI) && (subId == subIdToUpdate)) {
@@ -526,6 +545,16 @@ public class CallNotifier extends Handler {
                         mApplication.notificationMgr.updateCfi(subId, mCFIStatus.get(subId), true);
                     }
                 }
+                // Note: This logic is needlessly convoluted.  updatePhoneStateListeners is called
+                // with either:
+                // 1. isRefresh && updateType == UPDATE_TYPE_MWI_CFI
+                //      via updatePhoneStateListeners(bool)
+                //      (ie due to onSubscriptionsChanged)
+                //      This is the "refresh" case.
+                // 2. !isRefresh && updateType != UPDATE_TYPE_MWI_CFI
+                //      via TelephonyCallback MWI or CF changed event.
+                //      This is the "non-refresh" case.
+                // The same "logic" applies for call forwarding indications above.
                 if (mMWIStatus.containsKey(subId)) {
                     if ((updateType == UPDATE_TYPE_MWI) && (subId == subIdToUpdate)) {
                         mApplication.notificationMgr.updateMwi(subId, mMWIStatus.get(subId),
@@ -706,11 +735,20 @@ public class CallNotifier extends Handler {
             this.mSubId = subId;
         }
 
+        /**
+         * Handle changes to the message waiting indicator.
+         * This originates from {@link ImsPhoneCallTracker} via the
+         * {@link MmTelFeature.Listener#onVoiceMessageCountUpdate(int)} callback from the IMS
+         * implementation (there is something similar for GSM/CDMA, but that is old news).
+         * @param visible Whether the message waiting indicator has changed or not.
+         */
         @Override
         public void onMessageWaitingIndicatorChanged(boolean visible) {
-            if (VDBG) log("onMessageWaitingIndicatorChanged(): " + this.mSubId + " " + visible);
+            Log.i(LOG_TAG, "onMessageWaitingIndicatorChanged(): subId=" + this.mSubId
+                    + ", visible=" + (visible ? "Y" : "N"));
             mMWIStatus.put(this.mSubId, visible);
-            updatePhoneStateListeners(false, UPDATE_TYPE_MWI, this.mSubId);
+            // Trigger a "non-refresh" update to the MWI indicator.
+            updatePhoneStateListeners(false /* isRefresh */, UPDATE_TYPE_MWI, this.mSubId);
         }
 
         @Override
diff --git a/src/com/android/phone/CarrierConfigLoader.java b/src/com/android/phone/CarrierConfigLoader.java
index 3a908d23d..26ff9c744 100644
--- a/src/com/android/phone/CarrierConfigLoader.java
+++ b/src/com/android/phone/CarrierConfigLoader.java
@@ -141,6 +141,9 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
     @NonNull private boolean[] mHasSentConfigChange;
     // Whether the broadcast was sent from EVENT_SYSTEM_UNLOCKED, to track rebroadcasts
     @NonNull private boolean[] mFromSystemUnlocked;
+    // Whether this carrier config loading needs to trigger
+    // TelephonyRegistryManager.notifyCarrierConfigChanged
+    @NonNull private boolean[] mNeedNotifyCallback;
     // CarrierService change monitoring
     @NonNull private CarrierServiceChangeCallback[] mCarrierServiceChangeCallbacks;
 
@@ -257,6 +260,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
             }
             switch (msg.what) {
                 case EVENT_CLEAR_CONFIG: {
+                    mNeedNotifyCallback[phoneId] = true;
                     clearConfigForPhone(phoneId, true);
                     break;
                 }
@@ -268,8 +272,10 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
                         // trying to load the carrier config when the SIM is still loading when the
                         // unlock happens.
                         if (mHasSentConfigChange[i]) {
-                            logdWithLocalLog("System unlocked");
+                            logl("System unlocked");
                             mFromSystemUnlocked[i] = true;
+                            // Do not add mNeedNotifyCallback[phoneId] = true here. We intentionally
+                            // do not want to notify callback when system unlock happens.
                             updateConfigForPhoneId(i);
                         }
                     }
@@ -281,8 +287,9 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
                     // Always clear up the cache and re-load config from scratch since the carrier
                     // service change is reliable and specific to the phoneId now.
                     clearCachedConfigForPackage(carrierPackageName);
-                    logdWithLocalLog("Package changed: " + carrierPackageName
+                    logl("Package changed: " + carrierPackageName
                             + ", phone=" + phoneId);
+                    mNeedNotifyCallback[phoneId] = true;
                     updateConfigForPhoneId(phoneId);
                     break;
                 }
@@ -375,7 +382,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
                         ICarrierService carrierService =
                                 ICarrierService.Stub.asInterface(conn.service);
                         carrierService.getCarrierConfig(phoneId, carrierId, resultReceiver);
-                        logdWithLocalLog("Fetch config for default app: "
+                        logl("Fetch config for default app: "
                                 + mPlatformCarrierConfigPackage
                                 + ", carrierId=" + carrierId.getSpecificCarrierId());
                     } catch (RemoteException e) {
@@ -494,7 +501,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
                                     if (config != null) {
                                         mConfigFromCarrierApp[phoneId] = config;
                                     } else {
-                                        logdWithLocalLog("Config from carrier app is null "
+                                        logl("Config from carrier app is null "
                                                 + "for phoneId " + phoneId);
                                         // Put a stub bundle in place so that the rest of the logic
                                         // continues smoothly.
@@ -510,7 +517,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
                         ICarrierService carrierService =
                                 ICarrierService.Stub.asInterface(conn.service);
                         carrierService.getCarrierConfig(phoneId, carrierId, resultReceiver);
-                        logdWithLocalLog("Fetch config for carrier app: "
+                        logl("Fetch config for carrier app: "
                                 + getCarrierPackageForPhoneId(phoneId)
                                 + ", carrierId=" + carrierId.getSpecificCarrierId());
                     } catch (RemoteException e) {
@@ -676,7 +683,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
                         ICarrierService carrierService =
                                 ICarrierService.Stub.asInterface(conn.service);
                         carrierService.getCarrierConfig(phoneId, null, resultReceiver);
-                        logdWithLocalLog("Fetch no sim config from default app: "
+                        logl("Fetch no sim config from default app: "
                                 + mPlatformCarrierConfigPackage);
                     } catch (RemoteException e) {
                         loge("Failed to get no sim carrier config from default app: " +
@@ -728,6 +735,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
         mServiceBound = new boolean[mNumPhones];
         mHasSentConfigChange = new boolean[mNumPhones];
         mFromSystemUnlocked = new boolean[mNumPhones];
+        mNeedNotifyCallback = new boolean[mNumPhones];
         mServiceConnectionForNoSimConfig = new CarrierServiceConnection[mNumPhones];
         mServiceBoundForNoSimConfig = new boolean[mNumPhones];
         mCarrierServiceChangeCallbacks = new CarrierServiceChangeCallback[mNumPhones];
@@ -823,7 +831,12 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
             configToSend.putAll(config);
         }
 
-        SubscriptionManagerService.getInstance().updateSubscriptionByCarrierConfig(
+        SubscriptionManagerService sm = SubscriptionManagerService.getInstance();
+        if (sm == null) {
+            loge("SubscriptionManagerService missing");
+            return;
+        }
+        sm.updateSubscriptionByCarrierConfig(
                 phoneId, configPackageName, configToSend,
                 () -> mHandler.obtainMessage(EVENT_SUBSCRIPTION_INFO_UPDATED, phoneId, -1)
                         .sendToTarget());
@@ -861,35 +874,42 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
         TelephonyRegistryManager trm = mContext.getSystemService(TelephonyRegistryManager.class);
         // Unlike broadcast, we wouldn't notify registrants on carrier config change when device is
         // unlocked. Only real carrier config change will send the notification to registrants.
-        if (trm != null && !mFromSystemUnlocked[phoneId]) {
+        if (trm != null && (mFeatureFlags.carrierConfigChangedCallbackFix()
+                ? mNeedNotifyCallback[phoneId] : !mFromSystemUnlocked[phoneId])) {
+            logl("Notify carrier config changed callback for phone " + phoneId);
             trm.notifyCarrierConfigChanged(phoneId, subId, carrierId, specificCarrierId);
+            mNeedNotifyCallback[phoneId] = false;
+        } else {
+            logl("Skipped notifying carrier config changed callback for phone " + phoneId);
         }
 
         mContext.sendBroadcastAsUser(intent, UserHandle.ALL);
 
         if (SubscriptionManager.isValidSubscriptionId(subId)) {
-            logd("Broadcast CARRIER_CONFIG_CHANGED for phone " + phoneId + ", subId=" + subId);
+            logl("Broadcast CARRIER_CONFIG_CHANGED for phone " + phoneId + ", subId=" + subId);
         } else {
-            logd("Broadcast CARRIER_CONFIG_CHANGED for phone " + phoneId);
+            logl("Broadcast CARRIER_CONFIG_CHANGED for phone " + phoneId);
         }
         mHasSentConfigChange[phoneId] = true;
         mFromSystemUnlocked[phoneId] = false;
     }
 
     private int getSimApplicationStateForPhone(int phoneId) {
-        int simApplicationState = TelephonyManager.SIM_STATE_UNKNOWN;
         int subId = SubscriptionManager.getSubscriptionId(phoneId);
-        if (SubscriptionManager.isValidSubscriptionId(subId)) {
-            TelephonyManager telMgr = TelephonyManager.from(mContext)
-                    .createForSubscriptionId(subId);
-            simApplicationState = telMgr.getSimApplicationState();
+        if (!SubscriptionManager.isValidSubscriptionId(subId)) {
+            return TelephonyManager.SIM_STATE_UNKNOWN;
+        }
+        TelephonyManager telMgr = TelephonyManager.from(mContext)
+                .createForSubscriptionId(subId);
+        if (telMgr == null) {
+            return TelephonyManager.SIM_STATE_UNKNOWN;
         }
-        return simApplicationState;
+        return telMgr.getSimApplicationState();
     }
 
     /** Binds to the default or carrier config app. */
     private boolean bindToConfigPackage(@NonNull String pkgName, int phoneId, int eventId) {
-        logdWithLocalLog("Binding to " + pkgName + " for phone " + phoneId);
+        logl("Binding to " + pkgName + " for phone " + phoneId);
         Intent carrierService = new Intent(CarrierService.CARRIER_SERVICE_INTERFACE);
         carrierService.setPackage(pkgName);
         CarrierServiceConnection serviceConnection =  new CarrierServiceConnection(
@@ -1064,7 +1084,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
             return;
         }
 
-        logdWithLocalLog("Save carrier config to cache. phoneId=" + phoneId
+        logl("Save carrier config to cache. phoneId=" + phoneId
                         + ", xml=" + getFilePathForLogging(fileName) + ", version=" + version);
 
         FileOutputStream outFile = null;
@@ -1168,7 +1188,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
         }
 
         if (restoredBundle != null) {
-            logdWithLocalLog("Restored carrier config from cache. phoneId=" + phoneId + ", xml="
+            logl("Restored carrier config from cache. phoneId=" + phoneId + ", xml="
                     + getFilePathForLogging(fileName) + ", version=" + savedVersion
                     + ", modified time=" + getFileTime(filePath));
         }
@@ -1225,7 +1245,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
         });
         if (packageFiles == null || packageFiles.length < 1) return false;
         for (File f : packageFiles) {
-            logdWithLocalLog("Deleting " + getFilePathForLogging(f.getName()));
+            logl("Deleting " + getFilePathForLogging(f.getName()));
             f.delete();
         }
         return true;
@@ -1292,7 +1312,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
         if (mNumPhones == oldNumPhones) {
             return;
         }
-        logdWithLocalLog("mNumPhones change from " + oldNumPhones + " to " + mNumPhones);
+        logl("mNumPhones change from " + oldNumPhones + " to " + mNumPhones);
 
         // If DS -> SS switch, release the resources BEFORE truncating the arrays to avoid leaking
         for (int phoneId = mNumPhones; phoneId < oldNumPhones; phoneId++) {
@@ -1325,10 +1345,12 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
         mServiceBoundForNoSimConfig = Arrays.copyOf(mServiceBoundForNoSimConfig, mNumPhones);
         mHasSentConfigChange = Arrays.copyOf(mHasSentConfigChange, mNumPhones);
         mFromSystemUnlocked = Arrays.copyOf(mFromSystemUnlocked, mNumPhones);
+        mNeedNotifyCallback = Arrays.copyOf(mNeedNotifyCallback, mNumPhones);
         mCarrierServiceChangeCallbacks = Arrays.copyOf(mCarrierServiceChangeCallbacks, mNumPhones);
 
         // Load the config for all the phones and re-register callback AFTER padding the arrays.
         for (int phoneId = 0; phoneId < mNumPhones; phoneId++) {
+            mNeedNotifyCallback[phoneId] = true;
             updateConfigForPhoneId(phoneId);
             mCarrierServiceChangeCallbacks[phoneId] = new CarrierServiceChangeCallback(phoneId);
             TelephonyManager.from(mContext).registerCarrierPrivilegesCallback(phoneId,
@@ -1457,6 +1479,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
 
         // Post to run on handler thread on which all states should be confined.
         mHandler.post(() -> {
+            mNeedNotifyCallback[phoneId] = true;
             overrideConfig(mOverrideConfigs, phoneId, overrides);
 
             if (persistent) {
@@ -1476,7 +1499,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
                     fileToDelete.delete();
                 }
             }
-            logdWithLocalLog("overrideConfig: subId=" + subscriptionId + ", persistent="
+            logl("overrideConfig: subId=" + subscriptionId + ", persistent="
                     + persistent + ", overrides=" + overrides);
             updateSubscriptionDatabase(phoneId);
         });
@@ -1513,7 +1536,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
         enforceTelephonyFeatureWithException(getCurrentPackageName(),
                 "notifyConfigChangedForSubId");
 
-        logdWithLocalLog("Notified carrier config changed. phoneId=" + phoneId
+        logl("Notified carrier config changed. phoneId=" + phoneId
                 + ", subId=" + subscriptionId);
 
         // This method should block until deleting has completed, so that an error which prevents us
@@ -1522,6 +1545,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
         String callingPackageName = mContext.getPackageManager().getNameForUid(
                 Binder.getCallingUid());
         clearCachedConfigForPackage(callingPackageName);
+        mNeedNotifyCallback[phoneId] = true;
         updateConfigForPhoneId(phoneId);
     }
 
@@ -1529,7 +1553,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
     @Override
     public void updateConfigForPhoneId(int phoneId, @NonNull String simState) {
         updateConfigForPhoneId_enforcePermission();
-        logdWithLocalLog("Update config for phoneId=" + phoneId + " simState=" + simState);
+        logl("Update config for phoneId=" + phoneId + " simState=" + simState);
         if (!SubscriptionManager.isValidPhoneId(phoneId)) {
             throw new IllegalArgumentException("Invalid phoneId: " + phoneId);
         }
@@ -1547,6 +1571,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
                 break;
             case IccCardConstants.INTENT_VALUE_ICC_LOADED:
             case IccCardConstants.INTENT_VALUE_ICC_LOCKED:
+                mNeedNotifyCallback[phoneId] = true;
                 updateConfigForPhoneId(phoneId);
                 break;
         }
@@ -1696,6 +1721,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
                 + Arrays.toString(mServiceBoundForNoSimConfig));
         indentPW.println("mHasSentConfigChange=" + Arrays.toString(mHasSentConfigChange));
         indentPW.println("mFromSystemUnlocked=" + Arrays.toString(mFromSystemUnlocked));
+        indentPW.println("mNeedNotifyCallback=" + Arrays.toString(mNeedNotifyCallback));
         indentPW.println();
         indentPW.println("CarrierConfigLoader local log=");
         indentPW.increaseIndent();
@@ -1902,8 +1928,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
             return;
         }
 
-        if (!mFeatureFlags.enforceTelephonyFeatureMappingForPublicApis()
-                || !CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, callingPackage,
+        if (!CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, callingPackage,
                 Binder.getCallingUserHandle())
                 || mVendorApiLevel < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
             // Skip to check associated telephony feature,
@@ -2060,7 +2085,7 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
         Log.d(LOG_TAG, msg, tr);
     }
 
-    private void logdWithLocalLog(@NonNull String msg) {
+    private void logl(@NonNull String msg) {
         Log.d(LOG_TAG, msg);
         mCarrierConfigLoadingLog.log(msg);
     }
diff --git a/src/com/android/phone/ImsRcsController.java b/src/com/android/phone/ImsRcsController.java
index e2ae34355..65ca6f5d5 100644
--- a/src/com/android/phone/ImsRcsController.java
+++ b/src/com/android/phone/ImsRcsController.java
@@ -1009,8 +1009,7 @@ public class ImsRcsController extends IImsRcsController.Stub {
             return;
         }
 
-        if (!mFeatureFlags.enforceTelephonyFeatureMappingForPublicApis()
-                || !CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, callingPackage,
+        if (!CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, callingPackage,
                 Binder.getCallingUserHandle())
                 || mVendorApiLevel < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
             // Skip to check associated telephony feature,
diff --git a/src/com/android/phone/NotificationMgr.java b/src/com/android/phone/NotificationMgr.java
index 188baaad0..f67184579 100644
--- a/src/com/android/phone/NotificationMgr.java
+++ b/src/com/android/phone/NotificationMgr.java
@@ -73,6 +73,7 @@ import java.util.ArrayList;
 import java.util.HashSet;
 import java.util.Iterator;
 import java.util.List;
+import java.util.Objects;
 import java.util.Set;
 
 /**
@@ -140,6 +141,8 @@ public class NotificationMgr {
 
     // used to track whether the message waiting indicator is visible, per subscription id.
     private ArrayMap<Integer, Boolean> mMwiVisible = new ArrayMap<Integer, Boolean>();
+    // used to track the last broadcast sent to the dialer about the MWI, per sub id.
+    private ArrayMap<Integer, Integer> mLastMwiCountSent = new ArrayMap<Integer, Integer>();
 
     // those flags are used to track whether to show network selection notification or not.
     private SparseArray<Integer> mPreviousServiceState = new SparseArray<>();
@@ -271,11 +274,38 @@ public class NotificationMgr {
 
     /**
      * Updates the message waiting indicator (voicemail) notification.
-     *
-     * @param subId the subId to update.
-     * @param visible true if there are messages waiting
-     * @param isRefresh {@code true} if the notification is a refresh and the user should not be
-     * notified again.
+     * See also {@link CallNotifier#updatePhoneStateListeners(boolean)} for more background.
+     * Okay, lets get started; time for a code adventure.
+     * This method (unfortunately) serves double-duty for updating the message waiting indicator
+     * when either: the "subscription info" changes (could be due to the carrier name loading, the
+     * current phase of the moon, etc) -- this is considered a "refresh"; or due to a direct signal
+     * from the network that indeed the voicemail indicator has changed state.  Note that although
+     * {@link android.telephony.ims.feature.MmTelFeature.Listener#onVoiceMessageCountUpdate(int)}
+     * gives us an actual COUNT of the messages, that information is unfortunately lost in the
+     * current design -- that's a design issue left for another day.  Note; it is ALSO possible to
+     * get updates through SMS via {@code GsmInboundSmsHandler#updateMessageWaitingIndicator(int)},
+     * and that seems to generally not include a count.
+     * <p>
+     * There are two ways the message waiting indicator can be notified to the user; either directly
+     * here by posting a notification, or via the default dialer.
+     * <p>
+     * The {@code isRefresh} == false case is pretty intuitive.  The network told us something
+     * changed, so we should notify the user.
+     * <p>
+     * The {@code isRefresh} == true case is unfortunately not very intuitive.  While the device is
+     * booting up, we'll actually get a callback from the ImsService telling us the state of the
+     * MWI indication, BUT at that point in time it's possible the sim records won't have loaded so
+     * code below will return early -- the voicemail notification is supposed to include the user's
+     * voicemail number, so we have to defer posting the notification or notifying the dialer until
+     * later on.  That's where the refreshes are handy; once the voicemail number is known, we'll
+     * get a refresh and have an opportunity to notify the user at this point.
+     * @param subId the subId to update where {@code isRefresh} is false,
+     *              or {@link SubscriptionManager#INVALID_SUBSCRIPTION_ID} if {@code isRefresh} is
+     *              true.
+     * @param visible {@code true} if there are messages waiting, or {@code false} if there are not.
+     * @param isRefresh {@code true} if this is a refresh triggered by a subscription change,
+     *                              {@code false} if this is an update based on actual network
+     *                              signalling.
      */
     void updateMwi(int subId, boolean visible, boolean isRefresh) {
         if (!PhoneGlobals.sVoiceCapable) {
@@ -286,8 +316,19 @@ public class NotificationMgr {
         }
 
         Phone phone = PhoneGlobals.getPhone(subId);
-        Log.i(LOG_TAG, "updateMwi(): subId " + subId + " update to " + visible);
+        // --
+        // Note: This is all done just so that we can have a better log of what is going on here.
+        // The state changes are unfortunately not so intuitive.
+        boolean wasPrevStateKnown = mMwiVisible.containsKey(subId);
+        boolean wasVisible = wasPrevStateKnown && mMwiVisible.get(subId);
         mMwiVisible.put(subId, visible);
+        boolean mwiStateChanged = !wasPrevStateKnown || wasVisible != visible;
+        // --
+
+        Log.i(LOG_TAG, "updateMwi(): subId:" + subId + " isRefresh:" + isRefresh + " state:"
+                + (wasPrevStateKnown ? (wasVisible ? "Y" : "N") : "unset") + "->"
+                + (visible ? "Y" : "N")
+                + " (changed:" + (mwiStateChanged ? "Y" : "N") + ")");
 
         if (visible) {
             if (phone == null) {
@@ -328,12 +369,19 @@ public class NotificationMgr {
             //       register on the network before the SIM has loaded. In this case, the
             //       SubscriptionListener in CallNotifier will update this once the SIM is loaded.
             if ((vmNumber == null) && !phone.getIccRecordsLoaded()) {
-                if (DBG) log("- Null vm number: SIM records not loaded (yet)...");
+                Log.i(LOG_TAG, "updateMwi - Null vm number: SIM records not loaded (yet)...");
                 return;
             }
 
+            // Pay attention here; vmCount is an Integer, not an int.  This is because:
+            // vmCount == null - means there are voicemail messages waiting.
+            // vmCount == 0 - means there are no voicemail messages waiting.
+            // vmCount > 0 - means there are a specific number of voicemail messages waiting.
+            // Awesome.
             Integer vmCount = null;
 
+            // TODO: This should be revisited; in the IMS case, the network tells us a count, so
+            // it is strange to stash it and then retrieve it here instead of just passing it.
             if (TelephonyCapabilities.supportsVoiceMessageCount(phone)) {
                 vmCount = phone.getVoiceMessageCount();
                 String titleFormat = mContext.getString(R.string.notification_voicemail_title_count);
@@ -348,9 +396,6 @@ public class NotificationMgr {
             boolean isSettingsIntent = TextUtils.isEmpty(vmNumber);
 
             if (isSettingsIntent) {
-                notificationText = mContext.getString(
-                        R.string.notification_voicemail_no_vm_number);
-
                 // If the voicemail number if unknown, instead of calling voicemail, take the user
                 // to the voicemail settings.
                 notificationText = mContext.getString(
@@ -401,12 +446,13 @@ public class NotificationMgr {
             final Notification notification = builder.build();
             List<UserHandle> users = getUsersExcludeDying();
             for (UserHandle userHandle : users) {
-                boolean isManagedUser = mUserManager.isManagedProfile(userHandle.getIdentifier());
+                boolean isProfile = mUserManager.isProfile(userHandle.getIdentifier());
                 if (!hasUserRestriction(UserManager.DISALLOW_OUTGOING_CALLS, userHandle)
                         && (userHandle.equals(subAssociatedUserHandle)
-                            || (subAssociatedUserHandle == null && !isManagedUser))
+                            || (subAssociatedUserHandle == null && !isProfile))
                         && !maybeSendVoicemailNotificationUsingDefaultDialer(phone, vmCount,
                         vmNumber, pendingIntent, isSettingsIntent, userHandle, isRefresh)) {
+                    Log.i(LOG_TAG, "updateMwi: notify userHandle=" + userHandle);
                     notifyAsUser(
                             Integer.toString(subId) /* tag */,
                             VOICEMAIL_NOTIFICATION,
@@ -419,12 +465,13 @@ public class NotificationMgr {
                     mSubscriptionManager.getSubscriptionUserHandle(subId);
             List<UserHandle> users = getUsersExcludeDying();
             for (UserHandle userHandle : users) {
-                boolean isManagedUser = mUserManager.isManagedProfile(userHandle.getIdentifier());
+                boolean isProfile = mUserManager.isProfile(userHandle.getIdentifier());
                 if (!hasUserRestriction(UserManager.DISALLOW_OUTGOING_CALLS, userHandle)
                         && (userHandle.equals(subAssociatedUserHandle)
-                            || (subAssociatedUserHandle == null && !isManagedUser))
+                            || (subAssociatedUserHandle == null && !isProfile))
                         && !maybeSendVoicemailNotificationUsingDefaultDialer(phone, 0, null, null,
                         false, userHandle, isRefresh)) {
+                    Log.i(LOG_TAG, "notifyMwi: cancel userHandle=" + userHandle);
                     cancelAsUser(
                             Integer.toString(subId) /* tag */,
                             VOICEMAIL_NOTIFICATION,
@@ -474,7 +521,45 @@ public class NotificationMgr {
             UserHandle userHandle, boolean isRefresh) {
 
         if (shouldManageNotificationThroughDefaultDialer(userHandle)) {
+            int subId = phone.getSubId();
+            // We want to determine if the count of voicemails that we notified to the dialer app
+            // has changed or not.  mLastMwiCountSent will initially contain no entry for a subId
+            // meaning no count was ever sent to dialer.  The previous count is an Integer (not int)
+            // because the caller of maybeSendVoicemailNotificationUsingDefaultDialer will either
+            // send an instance of Integer with an actual number or "null" if the count isn't known.
+            // See the docs on updateMwi to get more flavor on this lovely logic.
+            // The end result here is we want to know if the "count" we last sent to the dialer for
+            // a sub has changed or not; this will play into whether we want to actually send the
+            // broadcast or not.
+            boolean wasCountSentYet = mLastMwiCountSent.containsKey(subId);
+            Integer previousCount = wasCountSentYet ? mLastMwiCountSent.get(subId) : null;
+            boolean didCountChange = !wasCountSentYet || !Objects.equals(previousCount, count);
+            mLastMwiCountSent.put(subId, count);
+
+            Log.i(LOG_TAG,
+                    "maybeSendVoicemailNotificationUsingDefaultDialer: count: " + (wasCountSentYet
+                            ? previousCount : "undef") + "->" + count + " (changed="
+                            + didCountChange + ")");
+
             Intent intent = getShowVoicemailIntentForDefaultDialer(userHandle);
+
+            /**
+             * isRefresh == true means that we're rebroadcasting because of an
+             * onSubscriptionsChanged callback -- that happens a LOT at boot up.  isRefresh == false
+             * happens when TelephonyCallback#onMessageWaitingIndicatorChanged is triggered in
+             * CallNotifier.  It's important to note that that count may either be an actual number,
+             * or "we don't know" because the modem doesn't know the actual count.  Hence anytime
+             * TelephonyCallback#onMessageWaitingIndicatorChanged occurs, we have to sent the
+             * broadcast even if the count didn't actually change.
+             */
+            if (!didCountChange && isRefresh) {
+                Log.i(LOG_TAG, "maybeSendVoicemailNotificationUsingDefaultDialer: skip bcast to:"
+                        + intent.getPackage() + ", user:" + userHandle);
+                // It's "technically" being sent through the dialer, but we just skipped that so
+                // still return true so we don't post a notification.
+                return true;
+            }
+
             intent.setFlags(Intent.FLAG_RECEIVER_FOREGROUND);
             intent.setAction(TelephonyManager.ACTION_SHOW_VOICEMAIL_NOTIFICATION);
             intent.putExtra(TelephonyManager.EXTRA_PHONE_ACCOUNT_HANDLE,
@@ -502,9 +587,15 @@ public class NotificationMgr {
 
             BroadcastOptions bopts = BroadcastOptions.makeBasic();
             bopts.setTemporaryAppWhitelistDuration(VOICEMAIL_ALLOW_LIST_DURATION_MILLIS);
-            mContext.sendBroadcastAsUser(intent, userHandle, READ_PHONE_STATE, bopts.toBundle());
+
+            Log.i(LOG_TAG, "maybeSendVoicemailNotificationUsingDefaultDialer: send via Dialer:"
+                    + intent.getPackage() + ", user:" + userHandle);
+            mContext.sendBroadcastAsUser(intent, userHandle, READ_PHONE_STATE,
+                    bopts.toBundle());
             return true;
         }
+        Log.i(LOG_TAG, "maybeSendVoicemailNotificationUsingDefaultDialer: not using dialer ; user:"
+                + userHandle);
 
         return false;
     }
@@ -817,7 +908,7 @@ public class NotificationMgr {
                 mContext.getString(R.string.mobile_network_settings_class)));
         intent.putExtra(Settings.EXTRA_SUB_ID, subId);
         builder.setContentIntent(
-                PendingIntent.getActivity(mContext, 0, intent, PendingIntent.FLAG_IMMUTABLE));
+                PendingIntent.getActivity(mContext, subId, intent, PendingIntent.FLAG_IMMUTABLE));
         notifyAsUser(
                 Integer.toString(subId) /* tag */,
                 SELECTED_OPERATOR_FAIL_NOTIFICATION,
@@ -843,11 +934,6 @@ public class NotificationMgr {
      * @param subId The subscription ID
      */
     void updateNetworkSelection(int serviceState, int subId) {
-        if (!mFeatureFlags.dismissNetworkSelectionNotificationOnSimDisable()) {
-            updateNetworkSelectionForFeatureDisabled(serviceState, subId);
-            return;
-        }
-
         // for dismissNetworkSelectionNotificationOnSimDisable feature enabled.
         int phoneId = SubscriptionManager.getPhoneId(subId);
         Phone phone = SubscriptionManager.isValidPhoneId(phoneId) ?
diff --git a/src/com/android/phone/NumberVerificationManager.java b/src/com/android/phone/NumberVerificationManager.java
index 2298d407f..5789fa0f9 100644
--- a/src/com/android/phone/NumberVerificationManager.java
+++ b/src/com/android/phone/NumberVerificationManager.java
@@ -22,6 +22,7 @@ import android.os.Looper;
 import android.os.RemoteException;
 import android.telephony.NumberVerificationCallback;
 import android.telephony.PhoneNumberRange;
+import android.telephony.PhoneNumberUtils;
 import android.telephony.ServiceState;
 import android.text.TextUtils;
 import android.util.Log;
@@ -30,11 +31,15 @@ import com.android.internal.telephony.Call;
 import com.android.internal.telephony.INumberVerificationCallback;
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneFactory;
+import com.android.internal.telephony.flags.Flags;
+import com.android.telephony.Rlog;
 
 /**
  * Singleton for managing the call based number verification requests.
  */
 public class NumberVerificationManager {
+    private static final String TAG = "NumberVerification";
+
     interface PhoneListSupplier {
         Phone[] getPhones();
     }
@@ -63,16 +68,40 @@ public class NumberVerificationManager {
      * Check whether the incoming call matches one of the active filters. If so, call the callback
      * that says that the number has been successfully verified.
      * @param number A phone number
+     * @param networkCountryISO the network country ISO for the number
      * @return true if the number matches, false otherwise
      */
-    public synchronized boolean checkIncomingCall(String number) {
+    public synchronized boolean checkIncomingCall(String number, String networkCountryISO) {
         if (mCurrentRange == null || mCallback == null) {
             return false;
         }
 
-        if (mCurrentRange.matches(number)) {
+        Log.i(TAG, "checkIncomingCall: number=" + Rlog.piiHandle(number) + ", country="
+                + networkCountryISO);
+
+        String numberInE164Format;
+        if (Flags.robustNumberVerification()) {
+            // Reformat the number in E.164 format prior to performing matching.
+            numberInE164Format = PhoneNumberUtils.formatNumberToE164(number,
+                    networkCountryISO);
+            if (TextUtils.isEmpty(numberInE164Format)) {
+                // Parsing failed, so we will fall back to just passing the number as-is and hope
+                // for the best.  Chances are this number is an unknown number (ie no caller id),
+                // so it is most likely empty.
+                numberInE164Format = number;
+            }
+        } else {
+            // Default behavior.
+            numberInE164Format = number;
+        }
+
+        if (mCurrentRange.matches(numberInE164Format)) {
             mCurrentRange = null;
             try {
+                // Pass back the network-matched number as-is to the caller of
+                // TelephonyManager#requestNumberVerification -- do not send them the E.164 format
+                // number as that changes the format of the number from what the API consumer may
+                // be expecting.
                 mCallback.onCallReceived(number);
                 return true;
             } catch (RemoteException e) {
@@ -187,6 +216,12 @@ public class NumberVerificationManager {
      * @param pkgName
      */
     static void overrideAuthorizedPackage(String pkgName) {
+        // Make sure we don't have any lingering callbacks kicking around as this could crash other
+        // test runs that follow; also old invocations from previous test invocations could also
+        // mess up things here too.
+        getInstance().mCallback = null;
+        getInstance().mCurrentRange = null;
+        getInstance().mHandler.removeMessages(0);
         sAuthorizedPackageOverride = pkgName;
     }
 }
diff --git a/src/com/android/phone/PhoneGlobals.java b/src/com/android/phone/PhoneGlobals.java
index bab260ce2..69ee88536 100644
--- a/src/com/android/phone/PhoneGlobals.java
+++ b/src/com/android/phone/PhoneGlobals.java
@@ -17,7 +17,6 @@
 package com.android.phone;
 
 import android.annotation.IntDef;
-import android.annotation.Nullable;
 import android.app.Activity;
 import android.app.KeyguardManager;
 import android.app.ProgressDialog;
@@ -443,19 +442,11 @@ public class PhoneGlobals extends ContextWrapper {
                     //TODO: handle message here;
                     break;
                 case EVENT_DATA_ROAMING_SETTINGS_CHANGED:
-                    if (mFeatureFlags.reorganizeRoamingNotification()) {
-                        updateDataRoamingStatus(
-                                ROAMING_NOTIFICATION_REASON_DATA_ROAMING_SETTING_CHANGED);
-                    } else {
-                        updateDataRoamingStatusForFeatureDisabled(null);
-                    }
+                    updateDataRoamingStatus(
+                            ROAMING_NOTIFICATION_REASON_DATA_ROAMING_SETTING_CHANGED);
                     break;
                 case EVENT_MOBILE_DATA_SETTINGS_CHANGED:
-                    if (mFeatureFlags.reorganizeRoamingNotification()) {
-                        updateDataRoamingStatus(ROAMING_NOTIFICATION_REASON_DATA_SETTING_CHANGED);
-                    } else {
-                        updateDataRoamingStatusForFeatureDisabled(null);
-                    }
+                    updateDataRoamingStatus(ROAMING_NOTIFICATION_REASON_DATA_SETTING_CHANGED);
                     break;
                 case EVENT_CARRIER_CONFIG_CHANGED:
                     int subId = (Integer) msg.obj;
@@ -510,11 +501,7 @@ public class PhoneGlobals extends ContextWrapper {
     public PhoneGlobals(Context context) {
         super(context);
         sMe = this;
-        if (mFeatureFlags.enforceTelephonyFeatureMappingForPublicApis()) {
-            if (getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY)) {
-                mSettingsObserver = new SettingsObserver(context, mHandler);
-            }
-        } else {
+        if (getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY)) {
             mSettingsObserver = new SettingsObserver(context, mHandler);
         }
     }
@@ -524,9 +511,8 @@ public class PhoneGlobals extends ContextWrapper {
 
         ContentResolver resolver = getContentResolver();
 
-        if (mFeatureFlags.enforceTelephonyFeatureMappingForPublicApis()
-                && !getResources().getBoolean(
-                    com.android.internal.R.bool.config_force_phone_globals_creation)) {
+        if (!getResources().getBoolean(
+                com.android.internal.R.bool.config_force_phone_globals_creation)) {
             if (!getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY)) {
                 Log.v(LOG_TAG, "onCreate()... but not defined FEATURE_TELEPHONY");
                 return;
@@ -573,8 +559,16 @@ public class PhoneGlobals extends ContextWrapper {
                         .getBoolean(R.bool.config_gnss_supl_requires_default_data_for_emergency);
                 int inServiceWaitTimeWhenDialEccInApm = getResources().getInteger(R.integer
                         .config_in_service_wait_timer_when_dialing_emergency_routing_ecc_in_apm);
+                boolean turnOffOemEnabledSatelliteDuringEmergencyCall = getResources().getBoolean(
+                        R.bool.config_turn_off_oem_enabled_satellite_during_emergency_call);
+                boolean turnOffNonEmergencyNbIotNtnSatelliteForEmergencyCall = getResources()
+                        .getBoolean(R.bool
+                            .config_turn_off_non_emergency_nb_iot_ntn_satellite_for_emergency_call);
                 EmergencyStateTracker.make(this, isSuplDdsSwitchRequiredForEmergencyCall,
-                        inServiceWaitTimeWhenDialEccInApm, mFeatureFlags);
+                        inServiceWaitTimeWhenDialEccInApm,
+                        turnOffOemEnabledSatelliteDuringEmergencyCall,
+                        turnOffNonEmergencyNbIotNtnSatelliteForEmergencyCall,
+                        mFeatureFlags);
                 DynamicRoutingController.getInstance().initialize(this);
             }
 
@@ -625,9 +619,11 @@ public class PhoneGlobals extends ContextWrapper {
             // {@link android.telephony.satellite.SatelliteManager}.
             SatelliteController.make(this, mFeatureFlags);
 
-            // Create an instance of CdmaPhoneCallState and initialize it to IDLE
-            cdmaPhoneCallState = new CdmaPhoneCallState();
-            cdmaPhoneCallState.CdmaPhoneCallStateInit();
+            if (!mFeatureFlags.phoneTypeCleanup()) {
+                // Create an instance of CdmaPhoneCallState and initialize it to IDLE
+                cdmaPhoneCallState = new CdmaPhoneCallState();
+                cdmaPhoneCallState.CdmaPhoneCallStateInit();
+            }
 
             // before registering for phone state changes
             mPowerManager = (PowerManager) getSystemService(Context.POWER_SERVICE);
@@ -896,11 +892,7 @@ public class PhoneGlobals extends ContextWrapper {
     /** Clear fields on power off radio **/
     private void clearCacheOnRadioOff() {
         // Re-show is-roaming notifications after APM mode
-        if (mFeatureFlags.reorganizeRoamingNotification()) {
-            mShownNotificationReasons.clear();
-        } else {
-            mPrevRoamingOperatorNumerics.clear();
-        }
+        mShownNotificationReasons.clear();
     }
 
     private void setRadioPowerOn() {
@@ -997,11 +989,7 @@ public class PhoneGlobals extends ContextWrapper {
             } else if (action.equals(CarrierConfigManager.ACTION_CARRIER_CONFIG_CHANGED)) {
                 // Roaming status could be overridden by carrier config, so we need to update it.
                 if (VDBG) Log.v(LOG_TAG, "carrier config changed.");
-                if (mFeatureFlags.reorganizeRoamingNotification()) {
-                    updateDataRoamingStatus(ROAMING_NOTIFICATION_REASON_CARRIER_CONFIG_CHANGED);
-                } else {
-                    updateDataRoamingStatusForFeatureDisabled(null);
-                }
+                updateDataRoamingStatus(ROAMING_NOTIFICATION_REASON_CARRIER_CONFIG_CHANGED);
                 updateLimitedSimFunctionForDualSim();
                 int subId = intent.getIntExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX,
                         SubscriptionManager.INVALID_SUBSCRIPTION_ID);
@@ -1016,12 +1004,8 @@ public class PhoneGlobals extends ContextWrapper {
                 registerSettingsObserver();
                 Phone phone = getPhone(mDefaultDataSubId);
                 if (phone != null) {
-                    if (mFeatureFlags.reorganizeRoamingNotification()) {
-                        updateDataRoamingStatus(
-                                ROAMING_NOTIFICATION_REASON_DEFAULT_DATA_SUBS_CHANGED);
-                    } else {
-                        updateDataRoamingStatusForFeatureDisabled(null);
-                    }
+                    updateDataRoamingStatus(
+                            ROAMING_NOTIFICATION_REASON_DEFAULT_DATA_SUBS_CHANGED);
                 }
             }
         }
@@ -1037,11 +1021,7 @@ public class PhoneGlobals extends ContextWrapper {
                     + mDefaultDataSubId + ", ss roaming=" + serviceState.getDataRoaming());
         }
         if (subId == mDefaultDataSubId) {
-            if (mFeatureFlags.reorganizeRoamingNotification()) {
-                updateDataRoamingStatus(ROAMING_NOTIFICATION_REASON_SERVICE_STATE_CHANGED);
-            } else {
-                updateDataRoamingStatusForFeatureDisabled(serviceState.getOperatorNumeric());
-            }
+            updateDataRoamingStatus(ROAMING_NOTIFICATION_REASON_SERVICE_STATE_CHANGED);
         }
     }
 
@@ -1067,26 +1047,24 @@ public class PhoneGlobals extends ContextWrapper {
         List<DataDisallowedReason> disallowReasons = phone.getDataNetworkController()
                 .getInternetDataDisallowedReasons();
 
-        if (mFeatureFlags.roamingNotificationForSingleDataNetwork()) {
-            if (disallowReasons.contains(DataDisallowedReason.ONLY_ALLOWED_SINGLE_NETWORK)
-                    && disallowReasons.contains(DataDisallowedReason.ROAMING_DISABLED)
-                    && (notificationReason == ROAMING_NOTIFICATION_REASON_DATA_SETTING_CHANGED
-                            || notificationReason
-                                    == ROAMING_NOTIFICATION_REASON_DATA_ROAMING_SETTING_CHANGED)) {
-                // If the ONLY_ALLOWED_SINGLE_NETWORK disallow reason has not yet been removed due
-                // to a change in mobile_data (including roaming_data) settings, update roaming
-                // notification again after the Internet is completely disconnected to check
-                // ONLY_ALLOWED_SINGLE_NETWORK disallow reason is removed.
-                mWaitForInternetDisconnection.set(true);
-                Log.d(LOG_TAG, "updateDataRoamingStatus,"
-                        + " wait for internet disconnection for single data network");
-            } else if (!disallowReasons.contains(DataDisallowedReason.ONLY_ALLOWED_SINGLE_NETWORK)
-                    && mWaitForInternetDisconnection.compareAndSet(true, false)) {
-                // If the ONLY_ALLOWED_SINGLE_NETWORK disallow reason has been removed,
-                // no longer wait for Internet disconnection.
-                Log.d(LOG_TAG, "updateDataRoamingStatus,"
-                        + " cancel to wait for internet disconnection for single data network");
-            }
+        if (disallowReasons.contains(DataDisallowedReason.ONLY_ALLOWED_SINGLE_NETWORK)
+                && disallowReasons.contains(DataDisallowedReason.ROAMING_DISABLED)
+                && (notificationReason == ROAMING_NOTIFICATION_REASON_DATA_SETTING_CHANGED
+                        || notificationReason
+                                == ROAMING_NOTIFICATION_REASON_DATA_ROAMING_SETTING_CHANGED)) {
+            // If the ONLY_ALLOWED_SINGLE_NETWORK disallow reason has not yet been removed due
+            // to a change in mobile_data (including roaming_data) settings, update roaming
+            // notification again after the Internet is completely disconnected to check
+            // ONLY_ALLOWED_SINGLE_NETWORK disallow reason is removed.
+            mWaitForInternetDisconnection.set(true);
+            Log.d(LOG_TAG, "updateDataRoamingStatus,"
+                    + " wait for internet disconnection for single data network");
+        } else if (!disallowReasons.contains(DataDisallowedReason.ONLY_ALLOWED_SINGLE_NETWORK)
+                && mWaitForInternetDisconnection.compareAndSet(true, false)) {
+            // If the ONLY_ALLOWED_SINGLE_NETWORK disallow reason has been removed,
+            // no longer wait for Internet disconnection.
+            Log.d(LOG_TAG, "updateDataRoamingStatus,"
+                    + " cancel to wait for internet disconnection for single data network");
         }
 
         updateDataRoamingStatus(notificationReason, disallowReasons, serviceState);
@@ -1229,88 +1207,6 @@ public class PhoneGlobals extends ContextWrapper {
         return mCurrentRoamingNotification;
     }
 
-    // For reorganize_roaming_notification feature disabled.
-    /**
-     * When roaming, if mobile data cannot be established due to data roaming not enabled, we need
-     * to notify the user so they can enable it through settings. Vise versa if the condition
-     * changes, we need to dismiss the notification.
-     * @param roamingOperatorNumeric The operator numeric for the current roaming. {@code null} if
-     *                               the current roaming operator numeric didn't change.
-     */
-    private void updateDataRoamingStatusForFeatureDisabled(
-            @Nullable String roamingOperatorNumeric) {
-        if (VDBG) Log.v(LOG_TAG, "updateDataRoamingStatusForFeatureDisabled");
-        Phone phone = getPhone(mDefaultDataSubId);
-        if (phone == null) {
-            Log.w(LOG_TAG, "Can't get phone with sub id = " + mDefaultDataSubId);
-            return;
-        }
-
-        boolean dataAllowed;
-        boolean notAllowedDueToRoamingOff;
-        List<DataDisallowedReason> reasons = phone.getDataNetworkController()
-                .getInternetDataDisallowedReasons();
-        dataAllowed = reasons.isEmpty();
-        notAllowedDueToRoamingOff = (reasons.size() == 1
-                && reasons.contains(DataDisallowedReason.ROAMING_DISABLED));
-        mDataRoamingNotifLog.log("dataAllowed=" + dataAllowed + ", reasons=" + reasons
-                + ", roamingOperatorNumeric=" + roamingOperatorNumeric);
-        if (VDBG) {
-            Log.v(LOG_TAG, "dataAllowed=" + dataAllowed + ", reasons=" + reasons
-                    + ", roamingOperatorNumeric=" + roamingOperatorNumeric);
-        }
-
-        if (!dataAllowed && notAllowedDueToRoamingOff) {
-            // Don't show roaming notification if we've already shown for this MccMnc
-            if (roamingOperatorNumeric != null
-                    && !mPrevRoamingOperatorNumerics.add(roamingOperatorNumeric)) {
-                Log.d(LOG_TAG, "Skip roaming disconnected notification since already shown in "
-                        + "MccMnc " + roamingOperatorNumeric);
-                return;
-            }
-            // No need to show it again if we never cancelled it explicitly.
-            if (mPrevRoamingNotification == ROAMING_NOTIFICATION_DISCONNECTED) return;
-            // If the only reason of no data is data roaming disabled, then we notify the user
-            // so the user can turn on data roaming.
-            mPrevRoamingNotification = ROAMING_NOTIFICATION_DISCONNECTED;
-            Log.d(LOG_TAG, "Show roaming disconnected notification");
-            mDataRoamingNotifLog.log("Show roaming off.");
-            Message msg = mHandler.obtainMessage(EVENT_DATA_ROAMING_DISCONNECTED);
-            msg.arg1 = mDefaultDataSubId;
-            msg.sendToTarget();
-        } else if (dataAllowed && dataIsNowRoaming(mDefaultDataSubId)) {
-            if (!shouldShowRoamingNotification(roamingOperatorNumeric != null
-                        ? roamingOperatorNumeric : phone.getServiceState().getOperatorNumeric())) {
-                Log.d(LOG_TAG, "Skip showing roaming connected notification.");
-                return;
-            }
-            // Don't show roaming notification if we've already shown for this MccMnc
-            if (roamingOperatorNumeric != null
-                    && !mPrevRoamingOperatorNumerics.add(roamingOperatorNumeric)) {
-                Log.d(LOG_TAG, "Skip roaming connected notification since already shown in "
-                        + "MccMnc " + roamingOperatorNumeric);
-                return;
-            }
-            // No need to show it again if we never cancelled it explicitly, or carrier config
-            // indicates this is not needed.
-            if (mPrevRoamingNotification == ROAMING_NOTIFICATION_CONNECTED) return;
-            mPrevRoamingNotification = ROAMING_NOTIFICATION_CONNECTED;
-            Log.d(LOG_TAG, "Show roaming connected notification");
-            mDataRoamingNotifLog.log("Show roaming on.");
-            Message msg = mHandler.obtainMessage(EVENT_DATA_ROAMING_CONNECTED);
-            msg.arg1 = mDefaultDataSubId;
-            msg.sendToTarget();
-        } else if (mPrevRoamingNotification != ROAMING_NOTIFICATION_NO_NOTIFICATION) {
-            // Otherwise we either 1) we are not roaming or 2) roaming is off but ROAMING_DISABLED
-            // is not the only data disable reason. In this case we dismiss the notification we
-            // showed earlier.
-            mPrevRoamingNotification = ROAMING_NOTIFICATION_NO_NOTIFICATION;
-            Log.d(LOG_TAG, "Dismiss roaming notification");
-            mDataRoamingNotifLog.log("Hide. data allowed=" + dataAllowed);
-            mHandler.sendEmptyMessage(EVENT_DATA_ROAMING_OK);
-        }
-    }
-
     /**
      *
      * @param subId to check roaming on
@@ -1325,9 +1221,8 @@ public class PhoneGlobals extends ContextWrapper {
         boolean showRoamingNotification = config.getBoolean(
                 CarrierConfigManager.KEY_SHOW_DATA_CONNECTED_ROAMING_NOTIFICATION_BOOL);
 
-        if (TextUtils.isEmpty(roamingNumeric) || !mFeatureFlags.hideRoamingIcon()) {
-            Log.d(LOG_TAG, "shouldShowRoamingNotification: roamingNumeric=" + roamingNumeric
-                    + ", hideRoaming=" + mFeatureFlags.hideRoamingIcon());
+        if (TextUtils.isEmpty(roamingNumeric)) {
+            Log.d(LOG_TAG, "shouldShowRoamingNotification: roamingNumeric=" + roamingNumeric);
             return showRoamingNotification;
         }
 
@@ -1449,16 +1344,8 @@ public class PhoneGlobals extends ContextWrapper {
         pw.increaseIndent();
         pw.println("FeatureFlags:");
         pw.increaseIndent();
-        pw.println("reorganizeRoamingNotification="
-                + mFeatureFlags.reorganizeRoamingNotification());
-        pw.println("dismissNetworkSelectionNotificationOnSimDisable="
-                + mFeatureFlags.dismissNetworkSelectionNotificationOnSimDisable());
         pw.decreaseIndent();
-        if (mFeatureFlags.reorganizeRoamingNotification()) {
-            pw.println("mCurrentRoamingNotification=" + mCurrentRoamingNotification);
-        } else {
-            pw.println("mPrevRoamingNotification=" + mPrevRoamingNotification);
-        }
+        pw.println("mCurrentRoamingNotification=" + mCurrentRoamingNotification);
         pw.println("mDefaultDataSubId=" + mDefaultDataSubId);
         pw.println("isSmsCapable=" + TelephonyManager.from(this).isSmsCapable());
         pw.println("mDataRoamingNotifLog:");
@@ -1496,11 +1383,7 @@ public class PhoneGlobals extends ContextWrapper {
         }
         pw.decreaseIndent();
         pw.decreaseIndent();
-        if (mFeatureFlags.reorganizeRoamingNotification()) {
-            pw.println("mShownNotificationReasons=" + mShownNotificationReasons);
-        } else {
-            pw.println("mPrevRoamingOperatorNumerics:" + mPrevRoamingOperatorNumerics);
-        }
+        pw.println("mShownNotificationReasons=" + mShownNotificationReasons);
         pw.println("------- End PhoneGlobals -------");
     }
 
diff --git a/src/com/android/phone/PhoneInterfaceManager.java b/src/com/android/phone/PhoneInterfaceManager.java
index bafcc6f76..9789165e0 100644
--- a/src/com/android/phone/PhoneInterfaceManager.java
+++ b/src/com/android/phone/PhoneInterfaceManager.java
@@ -24,11 +24,11 @@ import static android.telephony.TelephonyManager.ENABLE_FEATURE_MAPPING;
 import static android.telephony.TelephonyManager.HAL_SERVICE_NETWORK;
 import static android.telephony.TelephonyManager.HAL_SERVICE_RADIO;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_COMMUNICATION_ALLOWED;
-import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_ACCESS_BARRED;
-import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_SUCCESS;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_ACCESS_BARRED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_SUCCESS;
 
 import static com.android.internal.telephony.PhoneConstants.PHONE_TYPE_CDMA;
 import static com.android.internal.telephony.PhoneConstants.PHONE_TYPE_GSM;
@@ -159,12 +159,11 @@ import android.telephony.ims.stub.ImsConfigImplBase;
 import android.telephony.ims.stub.ImsRegistrationImplBase;
 import android.telephony.satellite.INtnSignalStrengthCallback;
 import android.telephony.satellite.ISatelliteCapabilitiesCallback;
-import android.telephony.satellite.ISatelliteCommunicationAllowedStateCallback;
+import android.telephony.satellite.ISatelliteCommunicationAccessStateCallback;
 import android.telephony.satellite.ISatelliteDatagramCallback;
 import android.telephony.satellite.ISatelliteDisallowedReasonsCallback;
 import android.telephony.satellite.ISatelliteModemStateCallback;
 import android.telephony.satellite.ISatelliteProvisionStateCallback;
-import android.telephony.satellite.ISatelliteSupportedStateCallback;
 import android.telephony.satellite.ISatelliteTransmissionUpdateCallback;
 import android.telephony.satellite.ISelectedNbIotSatelliteSubscriptionCallback;
 import android.telephony.satellite.NtnSignalStrength;
@@ -225,6 +224,7 @@ import com.android.internal.telephony.SmsPermissions;
 import com.android.internal.telephony.TelephonyCountryDetector;
 import com.android.internal.telephony.TelephonyIntents;
 import com.android.internal.telephony.TelephonyPermissions;
+import com.android.internal.telephony.configupdate.TelephonyConfigUpdateInstallReceiver;
 import com.android.internal.telephony.data.DataUtils;
 import com.android.internal.telephony.domainselection.DomainSelectionResolver;
 import com.android.internal.telephony.emergency.EmergencyNumberTracker;
@@ -2587,8 +2587,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     }
 
     private void sendEraseModemConfig(@NonNull Phone phone) {
-        if (mFeatureFlags.cleanupCdma()) return;
-        Boolean success = (Boolean) sendRequest(CMD_ERASE_MODEM_CONFIG, null);
+        int cmd = mFeatureFlags.cleanupCdma() ? CMD_MODEM_REBOOT : CMD_ERASE_MODEM_CONFIG;
+        Boolean success = (Boolean) sendRequest(cmd, null);
         if (DBG) log("eraseModemConfig:" + ' ' + (success ? "ok" : "fail"));
     }
 
@@ -5829,6 +5829,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                 mApp, functionName)) {
             if (!TelephonyPermissions.checkCallingOrSelfReadPhoneState(
                     mApp, subId, callingPackage, callingFeatureId, functionName)) {
+                loge("getDataNetworkTypeForSubscriber: missing permission " + callingPackage);
                 return TelephonyManager.NETWORK_TYPE_UNKNOWN;
             }
         }
@@ -5842,6 +5843,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             if (phone != null) {
                 return phone.getServiceState().getDataNetworkType();
             } else {
+                loge("getDataNetworkTypeForSubscriber: phone is null for sub " + subId);
                 return TelephonyManager.NETWORK_TYPE_UNKNOWN;
             }
         } finally {
@@ -6164,8 +6166,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             int command, int p1, int p2, int p3, String data) {
         final long identity = Binder.clearCallingIdentity();
         try {
-            if (channel <= 0) {
-                return "";
+            if (channel <= 0 || channel >= 256) {
+                return "6881";  // STATUS_CHANNEL_NOT_SUPPORTED
             }
 
             IccIoResult response = (IccIoResult) sendRequest(CMD_TRANSMIT_APDU_LOGICAL_CHANNEL,
@@ -6503,7 +6505,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
             final long identity = Binder.clearCallingIdentity();
             try {
-                Boolean success = (Boolean) sendRequest(CMD_RESET_MODEM_CONFIG, null);
+                int cmd = mFeatureFlags.cleanupCdma() ? CMD_MODEM_REBOOT : CMD_RESET_MODEM_CONFIG;
+                Boolean success = (Boolean) sendRequest(cmd, null);
                 if (DBG) log("resetModemConfig:" + ' ' + (success ? "ok" : "fail"));
                 return success;
             } finally {
@@ -8446,10 +8449,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public boolean isRttEnabled(int subscriptionId) {
         final long identity = Binder.clearCallingIdentity();
         try {
-            if (mFeatureFlags.enforceTelephonyFeatureMappingForPublicApis()) {
-                if (!mPackageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_IMS)) {
-                    return false;
-                }
+            if (!mPackageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_IMS)) {
+                return false;
             }
 
             boolean isRttSupported = isRttSupported(subscriptionId);
@@ -10444,8 +10445,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             throw new SecurityException("Requires READ_PHONE_STATE permission.");
         }
 
-        enforceTelephonyFeatureWithException(callingPackage,
-                PackageManager.FEATURE_TELEPHONY_CALLING, "getEmergencyNumberList");
+        enforceTelephonyFeatureWithException(
+                callingPackage,
+                Arrays.asList(
+                        PackageManager.FEATURE_TELEPHONY_CALLING,
+                        PackageManager.FEATURE_TELEPHONY_MESSAGING),
+                "getEmergencyNumberList");
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -10475,8 +10480,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
         if (!mApp.getResources().getBoolean(
                 com.android.internal.R.bool.config_force_phone_globals_creation)) {
-            enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                    PackageManager.FEATURE_TELEPHONY_CALLING, "isEmergencyNumber");
+            enforceTelephonyFeatureWithException(
+                    getCurrentPackageName(),
+                    Arrays.asList(
+                            PackageManager.FEATURE_TELEPHONY_CALLING,
+                            PackageManager.FEATURE_TELEPHONY_MESSAGING),
+                    "isEmergencyNumber");
         }
 
         final long identity = Binder.clearCallingIdentity();
@@ -10571,8 +10580,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public int getEmergencyNumberDbVersion(int subId) {
         enforceReadPrivilegedPermission("getEmergencyNumberDbVersion");
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_CALLING, "getEmergencyNumberDbVersion");
+        enforceTelephonyFeatureWithException(
+                getCurrentPackageName(),
+                Arrays.asList(
+                        PackageManager.FEATURE_TELEPHONY_CALLING,
+                        PackageManager.FEATURE_TELEPHONY_MESSAGING),
+                "getEmergencyNumberDbVersion");
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -10591,8 +10604,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void notifyOtaEmergencyNumberDbInstalled() {
         enforceModifyPermission();
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_CALLING, "notifyOtaEmergencyNumberDbInstalled");
+        enforceTelephonyFeatureWithException(
+                getCurrentPackageName(),
+                Arrays.asList(
+                        PackageManager.FEATURE_TELEPHONY_CALLING,
+                        PackageManager.FEATURE_TELEPHONY_MESSAGING),
+                "notifyOtaEmergencyNumberDbInstalled");
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -10611,8 +10628,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void updateOtaEmergencyNumberDbFilePath(ParcelFileDescriptor otaParcelFileDescriptor) {
         enforceActiveEmergencySessionPermission();
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_CALLING, "updateOtaEmergencyNumberDbFilePath");
+        enforceTelephonyFeatureWithException(
+                getCurrentPackageName(),
+                Arrays.asList(
+                        PackageManager.FEATURE_TELEPHONY_CALLING,
+                        PackageManager.FEATURE_TELEPHONY_MESSAGING),
+                "updateOtaEmergencyNumberDbFilePath");
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -10631,8 +10652,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void resetOtaEmergencyNumberDbFilePath() {
         enforceActiveEmergencySessionPermission();
 
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_CALLING, "resetOtaEmergencyNumberDbFilePath");
+        enforceTelephonyFeatureWithException(
+                getCurrentPackageName(),
+                Arrays.asList(
+                        PackageManager.FEATURE_TELEPHONY_CALLING,
+                        PackageManager.FEATURE_TELEPHONY_MESSAGING),
+                "resetOtaEmergencyNumberDbFilePath");
 
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -11265,8 +11290,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             throw new IllegalArgumentException("Invalid Subscription ID: " + subId);
         }
 
-        if (!mFeatureFlags.enforceTelephonyFeatureMappingForPublicApis()
-                || !CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, getCurrentPackageName(),
+        if (!CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, getCurrentPackageName(),
                 Binder.getCallingUserHandle())) {
             if (!isImsAvailableOnDevice()) {
                 // ProvisioningManager can not handle ServiceSpecificException.
@@ -11820,7 +11844,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         if (instance == null) {
             String packageName = mApp.getResources().getString(R.string.config_gba_package);
             int releaseTime = mApp.getResources().getInteger(R.integer.config_gba_release_time);
-            instance = GbaManager.make(mApp, subId, packageName, releaseTime);
+            instance = GbaManager.make(mApp, subId, packageName, releaseTime, mFeatureFlags);
         }
         return instance;
     }
@@ -11870,8 +11894,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         if (!SubscriptionManager.isValidSubscriptionId(subId)) {
             throw new IllegalArgumentException("Invalid Subscription ID: " + subId);
         }
-        if (!mFeatureFlags.enforceTelephonyFeatureMappingForPublicApis()
-                || !CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, getCurrentPackageName(),
+        if (!CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, getCurrentPackageName(),
                 Binder.getCallingUserHandle())) {
             if (!isImsAvailableOnDevice()) {
                 throw new ServiceSpecificException(ImsException.CODE_ERROR_UNSUPPORTED_OPERATION,
@@ -11909,8 +11932,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             throw new IllegalArgumentException("Invalid Subscription ID: " + subId);
         }
 
-        if (!mFeatureFlags.enforceTelephonyFeatureMappingForPublicApis()
-                || !CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, getCurrentPackageName(),
+        if (!CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, getCurrentPackageName(),
                 Binder.getCallingUserHandle())) {
             if (!isImsAvailableOnDevice()) {
                 // operation failed silently
@@ -11943,8 +11965,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         if (!SubscriptionManager.isValidSubscriptionId(subId)) {
             throw new IllegalArgumentException("Invalid Subscription ID: " + subId);
         }
-        if (!mFeatureFlags.enforceTelephonyFeatureMappingForPublicApis()
-                || !CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, getCurrentPackageName(),
+        if (!CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, getCurrentPackageName(),
                 Binder.getCallingUserHandle())) {
             if (!isImsAvailableOnDevice()) {
                 // ProvisioningManager can not handle ServiceSpecificException.
@@ -11975,8 +11996,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         if (!SubscriptionManager.isValidSubscriptionId(subId)) {
             throw new IllegalArgumentException("Invalid Subscription ID: " + subId);
         }
-        if (!mFeatureFlags.enforceTelephonyFeatureMappingForPublicApis()
-                || !CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, getCurrentPackageName(),
+        if (!CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, getCurrentPackageName(),
                 Binder.getCallingUserHandle())) {
             if (!isImsAvailableOnDevice()) {
                 throw new ServiceSpecificException(ImsException.CODE_ERROR_UNSUPPORTED_OPERATION,
@@ -12936,12 +12956,18 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
         if (mTelecomFeatureFlags.telecomMainUserInGetRespondMessageApp()){
             UserHandle mainUser = null;
-            Context userContext = null;
+            Context userContext = context;
             final long identity = Binder.clearCallingIdentity();
             try {
                 mainUser = mUserManager.getMainUser();
-                userContext = context.createContextAsUser(mainUser, 0);
-                Log.d(LOG_TAG, "getDefaultRespondViaMessageApplication: mainUser = " + mainUser);
+                if (mainUser != null) {
+                    userContext = context.createContextAsUser(mainUser, 0);
+                } else {
+                    // If getting the main user is null, then fall back to legacy behavior:
+                    mainUser = TelephonyUtils.getSubscriptionUserHandle(context, subId);
+                }
+                Log.d(LOG_TAG, "getDefaultRespondViaMessageApplication: mainUser = "
+                        + mainUser);
             } finally {
                 Binder.restoreCallingIdentity(identity);
             }
@@ -13284,6 +13310,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                                 (r == SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP
                                         || r == SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED
                                         || r == SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED))) {
+                            Log.d(LOG_TAG, "Satellite access is disallowed for current location.");
                             result.accept(SATELLITE_RESULT_ACCESS_BARRED);
                             return;
                         }
@@ -14123,7 +14150,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     @SatelliteManager.SatelliteResult public int registerForSatelliteSupportedStateChanged(
-            @NonNull ISatelliteSupportedStateCallback callback) {
+            @NonNull IBooleanConsumer callback) {
         enforceSatelliteCommunicationPermission("registerForSatelliteSupportedStateChanged");
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -14138,13 +14165,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * If callback was not registered before, the request will be ignored.
      *
      * @param callback The callback that was passed to
-     * {@link #registerForSatelliteSupportedStateChanged(ISatelliteSupportedStateCallback)}.
+     *                 {@link #registerForSatelliteSupportedStateChanged(IBooleanConsumer)}
      *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
     public void unregisterForSatelliteSupportedStateChanged(
-            @NonNull ISatelliteSupportedStateCallback callback) {
+            @NonNull IBooleanConsumer callback) {
         enforceSatelliteCommunicationPermission("unregisterForSatelliteSupportedStateChanged");
         final long identity = Binder.clearCallingIdentity();
         try {
@@ -14181,6 +14208,30 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         }
     }
 
+    /**
+     * This API can be used by only CTS to override the satellite access allowed state for
+     * a list of subscription IDs.
+     *
+     * @param subIdListStr The string representation of the list of subscription IDs,
+     *                     which are numbers separated by comma.
+     * @return {@code true} if the satellite access allowed state is set successfully,
+     * {@code false} otherwise.
+     */
+    public boolean setSatelliteAccessAllowedForSubscriptions(@Nullable String subIdListStr) {
+        Log.d(LOG_TAG, "setSatelliteAccessAllowedForSubscriptions - " + subIdListStr);
+        TelephonyPermissions.enforceShellOnly(
+                Binder.getCallingUid(), "setSatelliteAccessAllowedForSubscriptions");
+        TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
+                SubscriptionManager.INVALID_SUBSCRIPTION_ID,
+                "setSatelliteAccessAllowedForSubscriptions");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setSatelliteAccessAllowedForSubscriptions(subIdListStr);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
     /**
      * This API can be used by only CTS to update satellite gateway service package name.
      *
@@ -14251,6 +14302,37 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         }
     }
 
+    /**
+     * This API can be used by only CTS to override TN scanning support.
+     *
+     * @param reset {@code true} mean the overridden configs should not be used, {@code false}
+     *              otherwise.
+     * @param concurrentTnScanningSupported Whether concurrent TN scanning is supported.
+     * @param tnScanningDuringSatelliteSessionAllowed Whether TN scanning is allowed during
+     * a satellite session.
+     * @return {@code true} if the TN scanning support is set successfully,
+     * {@code false} otherwise.
+     */
+    public boolean setTnScanningSupport(boolean reset, boolean concurrentTnScanningSupported,
+        boolean tnScanningDuringSatelliteSessionAllowed) {
+        Log.d(LOG_TAG, "setTnScanningSupport: reset= " + reset
+            + ", concurrentTnScanningSupported=" + concurrentTnScanningSupported
+            + ", tnScanningDuringSatelliteSessionAllowed="
+            + tnScanningDuringSatelliteSessionAllowed);
+        TelephonyPermissions.enforceShellOnly(
+                Binder.getCallingUid(), "setTnScanningSupport");
+        TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
+                SubscriptionManager.INVALID_SUBSCRIPTION_ID,
+                "setTnScanningSupport");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setTnScanningSupport(reset,
+                concurrentTnScanningSupported, tnScanningDuringSatelliteSessionAllowed);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
     /**
      * This API can be used by only CTS to control ingoring cellular service state event.
      *
@@ -14272,6 +14354,32 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         }
     }
 
+    /**
+     * This API can be used by only CTS to control the feature
+     * {@code config_support_disable_satellite_while_enable_in_progress}.
+     *
+     * @param reset Whether to reset the override.
+     * @param supported Whether to support the feature.
+     * @return {@code true} if the value is set successfully, {@code false} otherwise.
+     */
+    public boolean setSupportDisableSatelliteWhileEnableInProgress(
+        boolean reset, boolean supported) {
+        Log.d(LOG_TAG, "setSupportDisableSatelliteWhileEnableInProgress - reset=" + reset
+                  + ", supported=" + supported);
+        TelephonyPermissions.enforceShellOnly(
+                Binder.getCallingUid(), "setSupportDisableSatelliteWhileEnableInProgress");
+        TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
+                SubscriptionManager.INVALID_SUBSCRIPTION_ID,
+                "setSupportDisableSatelliteWhileEnableInProgress");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setSupportDisableSatelliteWhileEnableInProgress(
+                reset, supported);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
     /**
      * This API can be used by only CTS to override the timeout durations used by the
      * DatagramController module.
@@ -14429,6 +14537,22 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         }
     }
 
+    /**
+     * This API is used by CTS to override the version of the config data
+     *
+     * @param reset Whether to restore the original version
+     * @param version The overriding version
+     * @return {@code true} if successful, {@code false} otherwise
+     */
+    public boolean overrideConfigDataVersion(boolean reset, int version) {
+        Log.d(LOG_TAG, "overrideVersion - reset=" + reset + ", version=" + version);
+        TelephonyPermissions.enforceShellOnly(
+                Binder.getCallingUid(), "overrideConfigDataVersion");
+        TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
+                SubscriptionManager.INVALID_SUBSCRIPTION_ID, "overrideVersion");
+        return TelephonyConfigUpdateInstallReceiver.getInstance().overrideVersion(reset, version);
+    }
+
     /**
      * This API should be used by only CTS tests to override the overlay configs of satellite
      * access controller.
@@ -14472,11 +14596,6 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * @return {@code true} if the operation is successful, {@code false} otherwise.
      */
     public boolean setShouldSendDatagramToModemInDemoMode(boolean shouldSendToModemInDemoMode) {
-        if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
-            Log.d(LOG_TAG, "shouldSendDatagramToModemInDemoMode: oemEnabledSatelliteFlag is "
-                    + "disabled");
-            return false;
-        }
         Log.d(LOG_TAG, "setShouldSendDatagramToModemInDemoMode");
         TelephonyPermissions.enforceShellOnly(
                 Binder.getCallingUid(), "setShouldSendDatagramToModemInDemoMode");
@@ -14500,12 +14619,6 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * @return {@code true} if the setting is successful, {@code false} otherwise.
      */
     public boolean setIsSatelliteCommunicationAllowedForCurrentLocationCache(String state) {
-        if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
-            Log.d(LOG_TAG, "setIsSatelliteCommunicationAllowedForCurrentLocationCache: "
-                    + "oemEnabledSatelliteFlag is disabled");
-            return false;
-        }
-
         Log.d(LOG_TAG, "setIsSatelliteCommunicationAllowedForCurrentLocationCache: "
                 + "state=" + state);
         TelephonyPermissions.enforceShellOnly(
@@ -14755,8 +14868,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             return;
         }
 
-        if (!mFeatureFlags.enforceTelephonyFeatureMappingForPublicApis()
-                || !CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, callingPackage,
+        if (!CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, callingPackage,
                 Binder.getCallingUserHandle())
                 || mVendorApiLevel < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
             // Skip to check associated telephony feature,
@@ -14771,6 +14883,40 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         }
     }
 
+    /**
+     * Make sure the device has at least one of the required telephony feature
+     *
+     * @throws UnsupportedOperationException if the device does not have any of the required
+     *     telephony feature
+     */
+    private void enforceTelephonyFeatureWithException(
+            @Nullable String callingPackage,
+            @NonNull List<String> anyOfTelephonyFeatures,
+            @NonNull String methodName) {
+        if (callingPackage == null || mPackageManager == null) {
+            return;
+        }
+
+        if (!CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, callingPackage,
+                Binder.getCallingUserHandle())
+                || mVendorApiLevel < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+            // Skip to check associated telephony feature,
+            // if compatibility change is not enabled for the current process or
+            // the SDK version of vendor partition is less than Android V.
+            return;
+        }
+        for (String feature : anyOfTelephonyFeatures) {
+            if (mPackageManager.hasSystemFeature(feature)) {
+                // At least one feature is present, so the requirement is satisfied.
+                return;
+            }
+        }
+
+        // No features were found.
+        throw new UnsupportedOperationException(
+                methodName + " is unsupported without any of " + anyOfTelephonyFeatures);
+    }
+
     /**
      * Registers for the satellite communication allowed state changed.
      *
@@ -14784,12 +14930,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    @SatelliteManager.SatelliteResult public int registerForCommunicationAllowedStateChanged(
-            int subId, @NonNull ISatelliteCommunicationAllowedStateCallback callback) {
-        enforceSatelliteCommunicationPermission("registerForCommunicationAllowedStateChanged");
+    @SatelliteManager.SatelliteResult public int registerForCommunicationAccessStateChanged(
+            int subId, @NonNull ISatelliteCommunicationAccessStateCallback callback) {
+        enforceSatelliteCommunicationPermission("registerForCommunicationAccessStateChanged");
         final long identity = Binder.clearCallingIdentity();
         try {
-            return mSatelliteAccessController.registerForCommunicationAllowedStateChanged(
+            return mSatelliteAccessController.registerForCommunicationAccessStateChanged(
                     subId, callback);
         } finally {
             Binder.restoreCallingIdentity(identity);
@@ -14803,17 +14949,17 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * @param subId    The subId of the subscription to unregister for the satellite communication
      *                 allowed state changed.
      * @param callback The callback that was passed to
-     *                 {@link #registerForCommunicationAllowedStateChanged(int,
-     *                 ISatelliteCommunicationAllowedStateCallback)}.     *
+     *                 {@link #registerForCommunicationAccessStateChanged(int,
+     *                 ISatelliteCommunicationAccessStateCallback)}.     *
      * @throws SecurityException if the caller doesn't have the required permission.
      */
     @Override
-    public void unregisterForCommunicationAllowedStateChanged(
-            int subId, @NonNull ISatelliteCommunicationAllowedStateCallback callback) {
-        enforceSatelliteCommunicationPermission("unregisterForCommunicationAllowedStateChanged");
+    public void unregisterForCommunicationAccessStateChanged(
+            int subId, @NonNull ISatelliteCommunicationAccessStateCallback callback) {
+        enforceSatelliteCommunicationPermission("unregisterForCommunicationAccessStateChanged");
         final long identity = Binder.clearCallingIdentity();
         try {
-            mSatelliteAccessController.unregisterForCommunicationAllowedStateChanged(subId,
+            mSatelliteAccessController.unregisterForCommunicationAccessStateChanged(subId,
                     callback);
         } finally {
             Binder.restoreCallingIdentity(identity);
@@ -15022,4 +15168,72 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             Binder.restoreCallingIdentity(identity);
         }
     }
+
+    /**
+     * Get list of applications that are optimized for low bandwidth satellite data.
+     *
+     * @return List of Application Name with data optimized network property.
+     * {@link #PROPERTY_SATELLITE_DATA_OPTIMIZED}
+     */
+    @Override
+    public List<String> getSatelliteDataOptimizedApps() {
+        enforceSatelliteCommunicationPermission("getSatelliteDataOptimizedApps");
+        List<String> appNames = new ArrayList<>();
+        int userId = Binder.getCallingUserHandle().getIdentifier();
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            appNames = mSatelliteController.getSatelliteDataOptimizedApps(userId);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+
+        return appNames;
+    }
+
+    /**
+     * Method to return the current satellite data service policy supported mode for the
+     * subscriptionId based on carrier config.
+     *
+     * @param subId current subscription id.
+     *
+     * @return Supported modes {@link SatelliteManager#SatelliteDataSupportMode}
+     * @throws IllegalArgumentException if the subscription is invalid.
+     *
+     * @hide
+     */
+    @Override
+    @SatelliteManager.SatelliteDataSupportMode
+    public int getSatelliteDataSupportMode(int subId) {
+        enforceSatelliteCommunicationPermission("getSatelliteDataSupportMode");
+        int satelliteMode = SatelliteManager.SATELLITE_DATA_SUPPORT_UNKNOWN;
+
+        if (!SubscriptionManager.isValidSubscriptionId(subId)) {
+            throw new IllegalArgumentException("Invalid Subscription ID: " + subId);
+        }
+
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            satelliteMode = mSatelliteController.getSatelliteDataSupportMode(subId);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+
+        return satelliteMode;
+    }
+
+    /**
+     * This API can be used by only CTS to ignore plmn list from storage.
+     *
+     * @param enabled Whether to enable boolean config.
+     * @return {@code true} if the value is set successfully, {@code false} otherwise.
+     */
+    public boolean setSatelliteIgnorePlmnListFromStorage(boolean enabled) {
+        Log.d(LOG_TAG, "setSatelliteIgnorePlmnListFromStorage - " + enabled);
+        TelephonyPermissions.enforceShellOnly(
+                Binder.getCallingUid(), "setSatelliteIgnorePlmnListFromStorage");
+        TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
+                SubscriptionManager.INVALID_SUBSCRIPTION_ID,
+                "setSatelliteIgnorePlmnListFromStorage");
+        return mSatelliteController.setSatelliteIgnorePlmnListFromStorage(enabled);
+    }
 }
diff --git a/src/com/android/phone/SimContacts.java b/src/com/android/phone/SimContacts.java
index fcbe4a09a..f3911348a 100644
--- a/src/com/android/phone/SimContacts.java
+++ b/src/com/android/phone/SimContacts.java
@@ -177,7 +177,7 @@ public class SimContacts extends ADNList {
         builder.withValue(Data.IS_PRIMARY, 1);
         operationList.add(builder.build());
 
-        if (emailAddresses != null) {
+        if (emailAddressArray != null) {
             for (String emailAddress : emailAddressArray) {
                 builder = ContentProviderOperation.newInsert(Data.CONTENT_URI);
                 builder.withValueBackReference(Email.RAW_CONTACT_ID, 0);
diff --git a/src/com/android/phone/TelephonyShellCommand.java b/src/com/android/phone/TelephonyShellCommand.java
index cd6a369cf..ba1caa120 100644
--- a/src/com/android/phone/TelephonyShellCommand.java
+++ b/src/com/android/phone/TelephonyShellCommand.java
@@ -53,6 +53,7 @@ import android.util.Log;
 import android.util.SparseArray;
 
 import com.android.ims.rcs.uce.util.FeatureTags;
+import com.android.internal.telephony.IIntegerConsumer;
 import com.android.internal.telephony.ITelephony;
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneFactory;
@@ -189,6 +190,10 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
             "set-satellite-listening-timeout-duration";
     private static final String SET_SATELLITE_IGNORE_CELLULAR_SERVICE_STATE =
             "set-satellite-ignore-cellular-service-state";
+    private static final String SET_SUPPORT_DISABLE_SATELLITE_WHILE_ENABLE_IN_PROGRESS =
+            "set-support-disable-satellite-while-enable-in-progress";
+    private static final String SET_SATELLITE_TN_SCANNING_SUPPORT =
+            "set-satellite-tn-scanning-support";
     private static final String SET_SATELLITE_POINTING_UI_CLASS_NAME =
             "set-satellite-pointing-ui-class-name";
     private static final String SET_DATAGRAM_CONTROLLER_TIMEOUT_DURATION =
@@ -200,6 +205,7 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
             "set-satellite-controller-timeout-duration";
     private static final String SET_EMERGENCY_CALL_TO_SATELLITE_HANDOVER_TYPE =
             "set-emergency-call-to-satellite-handover-type";
+    private static final String OVERRIDE_CONFIG_DATA_VERSION = "override-config-data-version";
     private static final String SET_COUNTRY_CODES = "set-country-codes";
     private static final String SET_SATELLITE_ACCESS_CONTROL_OVERLAY_CONFIGS =
             "set-satellite-access-control-overlay-configs";
@@ -212,8 +218,15 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
     private static final String SET_SATELLITE_SUBSCRIBERID_LIST_CHANGED_INTENT_COMPONENT =
             "set-satellite-subscriberid-list-changed-intent-component";
 
+    private static final String  ADD_ATTACH_RESTRICTION_FOR_CARRIER =
+            "add-attach-restriction-for-carrier";
+    private static final String  REMOVE_ATTACH_RESTRICTION_FOR_CARRIER =
+            "remove-attach-restriction-for-carrier";
+
     private static final String SET_SATELLITE_ACCESS_RESTRICTION_CHECKING_RESULT =
             "set-satellite-access-restriction-checking-result";
+    private static final String SET_SATELLITE_ACCESS_ALLOWED_FOR_SUBSCRIPTIONS =
+            "set-satellite-access-allowed-for-subscriptions";
 
     private static final String DOMAIN_SELECTION_SUBCOMMAND = "domainselection";
     private static final String DOMAIN_SELECTION_SET_SERVICE_OVERRIDE = "set-dss-override";
@@ -233,6 +246,9 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
     private static final String GET_IMEI = "get-imei";
     private static final String GET_SIM_SLOTS_MAPPING = "get-sim-slots-mapping";
     private static final String COMMAND_DELETE_IMSI_KEY = "delete_imsi_key";
+    private static final String SET_SATELLITE_IGNORE_PLMN_LIST_FROM_STORAGE =
+            "set-satellite-ignore-plmn-list-from-storage";
+
     // Take advantage of existing methods that already contain permissions checks when possible.
     private final ITelephony mInterface;
 
@@ -408,6 +424,8 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
                 return handleSetSatelliteListeningTimeoutDuration();
             case SET_SATELLITE_IGNORE_CELLULAR_SERVICE_STATE:
                 return handleSetSatelliteIgnoreCellularServiceState();
+            case SET_SUPPORT_DISABLE_SATELLITE_WHILE_ENABLE_IN_PROGRESS:
+                return handleSetSupportDisableSatelliteWhileEnableInProgress();
             case SET_SATELLITE_POINTING_UI_CLASS_NAME:
                 return handleSetSatellitePointingUiClassNameCommand();
             case SET_DATAGRAM_CONTROLLER_TIMEOUT_DURATION:
@@ -422,6 +440,8 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
                 return handleSetShouldSendDatagramToModemInDemoMode();
             case SET_SATELLITE_ACCESS_CONTROL_OVERLAY_CONFIGS:
                 return handleSetSatelliteAccessControlOverlayConfigs();
+            case OVERRIDE_CONFIG_DATA_VERSION:
+                return handleOverrideConfigDataVersion();
             case SET_COUNTRY_CODES:
                 return handleSetCountryCodes();
             case SET_OEM_ENABLED_SATELLITE_PROVISION_STATUS:
@@ -432,8 +452,18 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
                 return handleSetSatelliteSubscriberIdListChangedIntentComponent();
             case SET_SATELLITE_ACCESS_RESTRICTION_CHECKING_RESULT:
                 return handleOverrideCarrierRoamingNtnEligibilityChanged();
+            case ADD_ATTACH_RESTRICTION_FOR_CARRIER:
+                return handleAddAttachRestrictionForCarrier(cmd);
+            case REMOVE_ATTACH_RESTRICTION_FOR_CARRIER:
+                return handleRemoveAttachRestrictionForCarrier(cmd);
+            case SET_SATELLITE_ACCESS_ALLOWED_FOR_SUBSCRIPTIONS:
+                return handleSetSatelliteAccessAllowedForSubscriptions();
+            case SET_SATELLITE_TN_SCANNING_SUPPORT:
+                return handleSetSatelliteTnScanningSupport();
             case COMMAND_DELETE_IMSI_KEY:
                 return handleDeleteTestImsiKey();
+            case SET_SATELLITE_IGNORE_PLMN_LIST_FROM_STORAGE:
+                return handleSetSatelliteIgnorePlmnListFromStorage();
             default: {
                 return handleDefaultCommands(cmd);
             }
@@ -613,7 +643,7 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         pw.println("  numverify override-package PACKAGE_NAME;");
         pw.println("    Set the authorized package for number verification.");
         pw.println("    Leave the package name blank to reset.");
-        pw.println("  numverify fake-call NUMBER;");
+        pw.println("  numverify fake-call NUMBER <NETWORK_COUNTRY_ISO>");
         pw.println("    Fake an incoming call from NUMBER. This is for testing. Output will be");
         pw.println("    1 if the call would have been intercepted, 0 otherwise.");
     }
@@ -859,6 +889,26 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         pw.println("    Sets the OEM-enabled satellite provision status. Options are:");
         pw.println("      -p: the overriding satellite provision status. If no option is ");
         pw.println("          specified, reset the overridden provision status.");
+        pw.println("  add-attach-restriction-for-carrier [-s SLOT_ID ");
+        pw.println("    -r SATELLITE_COMMUNICATION_RESTRICTION_REASON] Add a restriction reason ");
+        pw.println("     for disallowing carrier supported satellite plmn scan ");
+        pw.println("     and attach by modem. ");
+        pw.println("    Options are:");
+        pw.println("      -s: The SIM slot ID to add a restriction reason. If no option ");
+        pw.println("          is specified, it will choose the default voice SIM slot.");
+        pw.println("      -r: restriction reason ");
+        pw.println("          If no option is specified, it will use ");
+        pw.println("          the default value SATELLITE_COMMUNICATION_RESTRICTION_REASON_USER.");
+        pw.println("  remove-attach-restriction-for-carrier [-s SLOT_ID ");
+        pw.println("    -r SATELLITE_COMMUNICATION_RESTRICTION_REASON] Add a restriction reason ");
+        pw.println("     for disallowing carrier supported satellite plmn scan ");
+        pw.println("     and attach by modem. ");
+        pw.println("    Options are:");
+        pw.println("      -s: The SIM slot ID to add a restriction reason. If no option ");
+        pw.println("          is specified, it will choose the default voice SIM slot.");
+        pw.println("      -r: restriction reason ");
+        pw.println("          If no option is specified, it will use ");
+        pw.println("          the default value SATELLITE_COMMUNICATION_RESTRICTION_REASON_USER.");
     }
 
     private void onHelpImei() {
@@ -1091,8 +1141,16 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
                 return 0;
             }
             case NUMBER_VERIFICATION_FAKE_CALL: {
+                String number = getNextArg();
+                String country = getNextArg();
+                if (country == null) {
+                    // No locale provided, default to current locale.
+                    Locale currentLocale = Locale.getDefault();
+                    country = currentLocale.getCountry();
+                }
+                Log.i(TAG, "numberVerificationFakeCall: " + number + " Locale: " + country);
                 boolean val = NumberVerificationManager.getInstance()
-                        .checkIncomingCall(getNextArg());
+                        .checkIncomingCall(number, country);
                 getOutPrintWriter().println(val ? "1" : "0");
                 return 0;
             }
@@ -3231,6 +3289,38 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         return 0;
     }
 
+    private int handleSetSatelliteAccessAllowedForSubscriptions() {
+        PrintWriter errPw = getErrPrintWriter();
+        String subIdListStr = null;
+
+        String opt;
+        while ((opt = getNextOption()) != null) {
+            switch (opt) {
+                case "-s": {
+                    subIdListStr = getNextArgRequired();
+                    break;
+                }
+            }
+        }
+        Log.d(LOG_TAG, "handleSetSatelliteAccessAllowedForSubscriptions: subIdListStr="
+            + subIdListStr);
+
+        try {
+            boolean result = mInterface.setSatelliteAccessAllowedForSubscriptions(subIdListStr);
+            if (VDBG) {
+                Log.v(LOG_TAG, "SetSatelliteAccessAllowedForSubscriptions " + subIdListStr
+                    + ", result = " + result);
+            }
+            getOutPrintWriter().println(result);
+        } catch (RemoteException e) {
+            Log.w(LOG_TAG, "SetSatelliteAccessAllowedForSubscriptions: error = " + e.getMessage());
+            errPw.println("Exception: " + e.getMessage());
+            return -1;
+        }
+
+        return 0;
+    }
+
     private int handleSetSatelliteGatewayServicePackageNameCommand() {
         PrintWriter errPw = getErrPrintWriter();
         String serviceName = null;
@@ -3411,6 +3501,88 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         return 0;
     }
 
+    private int handleSetSupportDisableSatelliteWhileEnableInProgress() {
+        PrintWriter errPw = getErrPrintWriter();
+        boolean reset = false;
+        boolean supported = false;
+
+        String opt;
+        while ((opt = getNextOption()) != null) {
+            switch (opt) {
+                case "-r": {
+                    reset = true;
+                    break;
+                }
+                case "-s": {
+                    supported = Boolean.parseBoolean(getNextArgRequired());
+                    break;
+                }
+            }
+        }
+        Log.d(LOG_TAG, "handleSetSupportDisableSatelliteWhileEnableInProgress: reset=" + reset
+            + ", supported=" + supported);
+
+        try {
+            boolean result = mInterface.setSupportDisableSatelliteWhileEnableInProgress(
+                reset, supported);
+            if (VDBG) {
+                Log.v(LOG_TAG, "handleSetSupportDisableSatelliteWhileEnableInProgress: result = "
+                    + result);
+            }
+            getOutPrintWriter().println(result);
+        } catch (RemoteException e) {
+            Log.w(LOG_TAG, "handleSetSupportDisableSatelliteWhileEnableInProgress: error = "
+                + e.getMessage());
+            errPw.println("Exception: " + e.getMessage());
+            return -1;
+        }
+        return 0;
+    }
+
+    private int handleSetSatelliteTnScanningSupport() {
+        PrintWriter errPw = getErrPrintWriter();
+        boolean reset = false;
+        boolean concurrentTnScanningSupported = false;
+        boolean tnScanningDuringSatelliteSessionAllowed = false;
+
+        String opt;
+        while ((opt = getNextOption()) != null) {
+            switch (opt) {
+                case "-r": {
+                    reset = true;
+                    break;
+                }
+                case "-s": {
+                    concurrentTnScanningSupported = Boolean.parseBoolean(getNextArgRequired());
+                    break;
+                }
+                case "-a": {
+                    tnScanningDuringSatelliteSessionAllowed =
+                            Boolean.parseBoolean(getNextArgRequired());
+                    break;
+                }
+            }
+        }
+        Log.d(LOG_TAG, "handleSetSatelliteTnScanningSupport: reset=" + reset
+            + ", concurrentTnScanningSupported =" + concurrentTnScanningSupported
+            + ", tnScanningDuringSatelliteSessionAllowed="
+            + tnScanningDuringSatelliteSessionAllowed);
+
+        try {
+            boolean result = mInterface.setTnScanningSupport(reset,
+                concurrentTnScanningSupported, tnScanningDuringSatelliteSessionAllowed);
+            if (VDBG) {
+                Log.v(LOG_TAG, "handleSetSatelliteTnScanningSupport: result = " + result);
+            }
+            getOutPrintWriter().println(result);
+        } catch (RemoteException e) {
+            Log.w(LOG_TAG, "handleSetSatelliteTnScanningSupport: error = " + e.getMessage());
+            errPw.println("Exception: " + e.getMessage());
+            return -1;
+        }
+        return 0;
+    }
+
     private int handleSetDatagramControllerTimeoutDuration() {
         PrintWriter errPw = getErrPrintWriter();
         boolean reset = false;
@@ -3704,6 +3876,40 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         return 0;
     }
 
+    private int handleOverrideConfigDataVersion() {
+        PrintWriter errPw = getErrPrintWriter();
+        boolean reset = false;
+        int version = 0;
+
+        String opt;
+        while ((opt = getNextOption()) != null) {
+            switch (opt) {
+                case "-r": {
+                    reset = true;
+                    break;
+                }
+                case "-v": {
+                    version = Integer.parseInt(getNextArgRequired());
+                    break;
+                }
+            }
+        }
+        Log.d(LOG_TAG, "overrideConfigDataVersion: reset=" + reset + ", version=" + version);
+
+        try {
+            boolean result = mInterface.overrideConfigDataVersion(reset, version);
+            if (VDBG) {
+                Log.v(LOG_TAG, "overrideConfigDataVersion result =" + result);
+            }
+            getOutPrintWriter().println(result);
+        } catch (RemoteException e) {
+            Log.e(LOG_TAG, "overrideConfigDataVersion: ex=" + e.getMessage());
+            errPw.println("Exception: " + e.getMessage());
+            return -1;
+        }
+        return 0;
+    }
+
     private int handleSetOemEnabledSatelliteProvisionStatus() {
         PrintWriter errPw = getErrPrintWriter();
         boolean isProvisioned = false;
@@ -3847,6 +4053,118 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         return 0;
     }
 
+    private int handleAddAttachRestrictionForCarrier(String command) {
+        PrintWriter errPw = getErrPrintWriter();
+        String tag = command + ": ";
+        int subId = SubscriptionManager.getDefaultSubscriptionId();
+        int reason = 0;
+
+        String opt;
+        while ((opt = getNextOption()) != null) {
+            switch (opt) {
+                case "-s": {
+                    try {
+                        subId = slotStringToSubId(tag, getNextArgRequired());
+                    } catch (NumberFormatException e) {
+                        errPw.println("handleAddAttachRestrictionForCarrier:"
+                                + " require an integer for subId");
+                        return -1;
+                    }
+                    break;
+                }
+                case "-r": {
+                    try {
+                        reason = Integer.parseInt(getNextArgRequired());
+                    } catch (NumberFormatException e) {
+                        errPw.println("handleAddAttachRestrictionForCarrier:"
+                                + " require an integer for reason");
+                        return -1;
+                    }
+                    break;
+                }
+            }
+        }
+
+        Log.d(LOG_TAG, "handleAddAttachRestrictionForCarrier: subId= "
+                + subId + ", reason= " + reason);
+
+        try {
+            IIntegerConsumer errorCallback = new IIntegerConsumer.Stub() {
+                @Override
+                public void accept(int result) {
+                    if (VDBG) {
+                        Log.v(LOG_TAG, "addAttachRestrictionForCarrier result = " + result);
+                    }
+                    getOutPrintWriter().println(result);
+                }
+            };
+
+            mInterface.addAttachRestrictionForCarrier(subId, reason, errorCallback);
+        } catch (RemoteException e) {
+            Log.e(LOG_TAG, "addAttachRestrictionForCarrier:"
+                    + " error = " + e.getMessage());
+            errPw.println("Exception: " + e.getMessage());
+            return -1;
+        }
+        return 0;
+    }
+
+    private int handleRemoveAttachRestrictionForCarrier(String command) {
+        PrintWriter errPw = getErrPrintWriter();
+        String tag = command + ": ";
+        int subId = SubscriptionManager.getDefaultSubscriptionId();
+        int reason = 0;
+
+        String opt;
+        while ((opt = getNextOption()) != null) {
+            switch (opt) {
+                case "-s": {
+                    try {
+                        subId = slotStringToSubId(tag, getNextArgRequired());
+                    } catch (NumberFormatException e) {
+                        errPw.println("handleRemoveAttachRestrictionForCarrier:"
+                                + " require an integer for subId");
+                        return -1;
+                    }
+                    break;
+                }
+                case "-r": {
+                    try {
+                        reason = Integer.parseInt(getNextArgRequired());
+                    } catch (NumberFormatException e) {
+                        errPw.println("handleRemoveAttachRestrictionForCarrier:"
+                                + " require an integer for reason");
+                        return -1;
+                    }
+                    break;
+                }
+            }
+        }
+
+        Log.d(LOG_TAG, "handleRemoveAttachRestrictionForCarrier: subId= "
+                + subId + ", reason= " + reason);
+
+        try {
+            IIntegerConsumer errorCallback = new IIntegerConsumer.Stub() {
+                @Override
+                public void accept(int result) {
+                    if (VDBG) {
+                        Log.v(LOG_TAG, "removeAttachRestrictionForCarrier result = " + result);
+                    }
+                    getOutPrintWriter().println(result);
+                }
+            };
+
+            mInterface.removeAttachRestrictionForCarrier(subId, reason, errorCallback);
+        } catch (RemoteException e) {
+            Log.e(LOG_TAG, "removeAttachRestrictionForCarrier:"
+                    + " error = " + e.getMessage());
+            errPw.println("Exception: " + e.getMessage());
+            return -1;
+        }
+        return 0;
+    }
+
     /**
      * Sample inputStr = "US,UK,CA;2,1,3"
      * Sample output: {[US,2], [UK,1], [CA,3]}
@@ -4161,4 +4479,36 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         phone.resetCarrierKeysForImsiEncryption(true);
         return 1;
     }
+
+    private int handleSetSatelliteIgnorePlmnListFromStorage() {
+        PrintWriter errPw = getErrPrintWriter();
+        boolean enabled = false;
+
+        String opt;
+        while ((opt = getNextOption()) != null) {
+            switch (opt) {
+                case "-d": {
+                    enabled = Boolean.parseBoolean(getNextArgRequired());
+                    break;
+                }
+            }
+        }
+        Log.d(LOG_TAG, "handleSetSatelliteIgnorePlmnListFromStorage: enabled ="
+                + enabled);
+
+        try {
+            boolean result = mInterface.setSatelliteIgnorePlmnListFromStorage(enabled);
+            if (VDBG) {
+                Log.v(LOG_TAG, "handleSetAllPlmnListFromStorageEmpty " + enabled
+                        + ", result = " + result);
+            }
+            getOutPrintWriter().println(result);
+        } catch (RemoteException e) {
+            Log.w(LOG_TAG, "handleSetAllPlmnListFromStorageEmpty: " + enabled
+                    + ", error = " + e.getMessage());
+            errPw.println("Exception: " + e.getMessage());
+            return -1;
+        }
+        return 0;
+    }
 }
diff --git a/src/com/android/phone/otasp/OtaspActivationService.java b/src/com/android/phone/otasp/OtaspActivationService.java
index 72bf249f4..b4f540df5 100644
--- a/src/com/android/phone/otasp/OtaspActivationService.java
+++ b/src/com/android/phone/otasp/OtaspActivationService.java
@@ -32,6 +32,7 @@ import com.android.internal.telephony.GsmCdmaConnection;
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneConstants;
 import com.android.internal.telephony.ServiceStateTracker;
+import com.android.internal.telephony.flags.Flags;
 import com.android.phone.PhoneGlobals;
 import com.android.phone.PhoneUtils;
 
@@ -77,6 +78,7 @@ public class OtaspActivationService extends Service {
     @Override
     public void onCreate() {
         logd("otasp service onCreate");
+        if (Flags.phoneTypeCleanup()) return;
         mPhone = PhoneGlobals.getPhone();
         ServiceStateTracker sst = mPhone.getServiceStateTracker();
         if (sst != null && sst.getOtasp() != TelephonyManager.OTASP_NEEDED) {
diff --git a/src/com/android/phone/otasp/OtaspSimStateReceiver.java b/src/com/android/phone/otasp/OtaspSimStateReceiver.java
index a47ab6705..324a13b4c 100644
--- a/src/com/android/phone/otasp/OtaspSimStateReceiver.java
+++ b/src/com/android/phone/otasp/OtaspSimStateReceiver.java
@@ -27,6 +27,7 @@ import android.telephony.TelephonyManager;
 import android.util.Log;
 
 import com.android.internal.telephony.Phone;
+import com.android.internal.telephony.flags.Flags;
 import com.android.phone.PhoneGlobals;
 
 public class OtaspSimStateReceiver extends BroadcastReceiver {
@@ -89,6 +90,7 @@ public class OtaspSimStateReceiver extends BroadcastReceiver {
 
     @Override
     public void onReceive(Context context, Intent intent) {
+        if (Flags.phoneTypeCleanup()) return;
         mContext = context;
         if(CarrierConfigManager.ACTION_CARRIER_CONFIG_CHANGED.equals(intent.getAction())) {
             if (DBG) logd("Received intent: " + intent.getAction());
diff --git a/src/com/android/phone/satellite/accesscontrol/SatelliteAccessConfigurationParser.java b/src/com/android/phone/satellite/accesscontrol/SatelliteAccessConfigurationParser.java
index ad0926b65..b22fb644d 100644
--- a/src/com/android/phone/satellite/accesscontrol/SatelliteAccessConfigurationParser.java
+++ b/src/com/android/phone/satellite/accesscontrol/SatelliteAccessConfigurationParser.java
@@ -26,8 +26,6 @@ import android.telephony.satellite.SatelliteInfo;
 import android.telephony.satellite.SatellitePosition;
 import android.util.Log;
 
-import com.android.internal.annotations.VisibleForTesting;
-
 import org.json.JSONArray;
 import org.json.JSONException;
 import org.json.JSONObject;
@@ -302,7 +300,6 @@ public class SatelliteAccessConfigurationParser {
      * @return json string type json contents
      */
     @Nullable
-    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
     public static String readJsonStringFromFile(@NonNull String jsonFilePath) {
         logd("jsonFilePath is " + jsonFilePath);
         String json = null;
diff --git a/src/com/android/phone/satellite/accesscontrol/SatelliteAccessController.java b/src/com/android/phone/satellite/accesscontrol/SatelliteAccessController.java
index 291780cfb..50730a991 100644
--- a/src/com/android/phone/satellite/accesscontrol/SatelliteAccessController.java
+++ b/src/com/android/phone/satellite/accesscontrol/SatelliteAccessController.java
@@ -34,7 +34,9 @@ import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_NO_R
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_SUCCESS;
 
+import static com.android.internal.telephony.satellite.SatelliteConstants.TRIGGERING_EVENT_CONFIG_DATA_UPDATED;
 import static com.android.internal.telephony.satellite.SatelliteConstants.TRIGGERING_EVENT_EXTERNAL_REQUEST;
+import static com.android.internal.telephony.satellite.SatelliteConstants.TRIGGERING_EVENT_LOCATION_SETTINGS_DISABLED;
 import static com.android.internal.telephony.satellite.SatelliteConstants.TRIGGERING_EVENT_LOCATION_SETTINGS_ENABLED;
 import static com.android.internal.telephony.satellite.SatelliteConstants.TRIGGERING_EVENT_MCC_CHANGED;
 import static com.android.internal.telephony.satellite.SatelliteConstants.TRIGGERING_EVENT_UNKNOWN;
@@ -60,6 +62,7 @@ import android.os.AsyncResult;
 import android.os.Build;
 import android.os.Bundle;
 import android.os.CancellationSignal;
+import android.os.FileUtils;
 import android.os.Handler;
 import android.os.HandlerExecutor;
 import android.os.HandlerThread;
@@ -75,17 +78,15 @@ import android.provider.DeviceConfig;
 import android.telecom.TelecomManager;
 import android.telephony.AnomalyReporter;
 import android.telephony.CarrierConfigManager;
-import android.telephony.DropBoxManagerLoggerBackend;
 import android.telephony.NetworkRegistrationInfo;
 import android.telephony.PersistentLogger;
 import android.telephony.Rlog;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
 import android.telephony.satellite.EarfcnRange;
-import android.telephony.satellite.ISatelliteCommunicationAllowedStateCallback;
+import android.telephony.satellite.ISatelliteCommunicationAccessStateCallback;
 import android.telephony.satellite.ISatelliteDisallowedReasonsCallback;
 import android.telephony.satellite.ISatelliteProvisionStateCallback;
-import android.telephony.satellite.ISatelliteSupportedStateCallback;
 import android.telephony.satellite.SatelliteAccessConfiguration;
 import android.telephony.satellite.SatelliteInfo;
 import android.telephony.satellite.SatelliteManager;
@@ -93,11 +94,13 @@ import android.telephony.satellite.SatelliteSubscriberProvisionStatus;
 import android.telephony.satellite.SystemSelectionSpecifier;
 import android.text.TextUtils;
 import android.util.IntArray;
+import android.util.Log;
 import android.util.Pair;
 
 import com.android.internal.R;
 import com.android.internal.annotations.GuardedBy;
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.internal.telephony.IBooleanConsumer;
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneFactory;
 import com.android.internal.telephony.SmsApplication;
@@ -106,6 +109,7 @@ import com.android.internal.telephony.flags.FeatureFlags;
 import com.android.internal.telephony.satellite.SatelliteConfig;
 import com.android.internal.telephony.satellite.SatelliteConstants;
 import com.android.internal.telephony.satellite.SatelliteController;
+import com.android.internal.telephony.satellite.SatelliteServiceUtils;
 import com.android.internal.telephony.satellite.metrics.AccessControllerMetricsStats;
 import com.android.internal.telephony.satellite.metrics.ConfigUpdaterMetricsStats;
 import com.android.internal.telephony.satellite.metrics.ControllerMetricsStats;
@@ -158,6 +162,8 @@ public class SatelliteAccessController extends Handler {
             "3ac767d8-2867-4d60-97c2-ae9d378a5521";
     protected static final long WAIT_FOR_CURRENT_LOCATION_TIMEOUT_MILLIS =
             TimeUnit.SECONDS.toMillis(180);
+    protected static final long WAIT_UNTIL_CURRENT_LOCATION_QUERY_IS_DONE_MILLIS =
+            TimeUnit.SECONDS.toMillis(90);
     protected static final long KEEP_ON_DEVICE_ACCESS_CONTROLLER_RESOURCES_TIMEOUT_MILLIS =
             TimeUnit.MINUTES.toMillis(30);
     protected static final int DEFAULT_S2_LEVEL = 12;
@@ -171,11 +177,13 @@ public class SatelliteAccessController extends Handler {
     protected static final int CMD_IS_SATELLITE_COMMUNICATION_ALLOWED = 1;
     protected static final int EVENT_WAIT_FOR_CURRENT_LOCATION_TIMEOUT = 2;
     protected static final int EVENT_KEEP_ON_DEVICE_ACCESS_CONTROLLER_RESOURCES_TIMEOUT = 3;
-    protected static final int EVENT_CONFIG_DATA_UPDATED = 4;
+    protected static final int CMD_UPDATE_CONFIG_DATA = 4;
     protected static final int EVENT_COUNTRY_CODE_CHANGED = 5;
     protected static final int EVENT_LOCATION_SETTINGS_ENABLED = 6;
     protected static final int CMD_UPDATE_SYSTEM_SELECTION_CHANNELS = 7;
     protected static final int EVENT_LOCATION_SETTINGS_DISABLED = 8;
+    protected static final int EVENT_SATELLITE_SUBSCRIPTION_CHANGED = 9;
+    protected static final int EVENT_CONFIG_DATA_UPDATED = 10;
 
     public static final int DEFAULT_REGIONAL_SATELLITE_CONFIG_ID = 0;
     public static final int UNKNOWN_REGIONAL_SATELLITE_CONFIG_ID = -1;
@@ -259,7 +267,7 @@ public class SatelliteAccessController extends Handler {
     @NonNull
     private final ResultReceiver mInternalSatelliteProvisionedResultReceiver;
     @NonNull
-    private final ISatelliteSupportedStateCallback mInternalSatelliteSupportedStateCallback;
+    private final IBooleanConsumer mInternalSatelliteSupportedStateCallback;
     @NonNull
     private final ISatelliteProvisionStateCallback mInternalSatelliteProvisionStateCallback;
     @NonNull
@@ -275,8 +283,11 @@ public class SatelliteAccessController extends Handler {
     @NonNull
     private List<String> mSatelliteCountryCodes;
     private boolean mIsSatelliteAllowAccessControl;
+    protected int mSatelliteAccessConfigVersion;
     @Nullable
     private File mSatelliteS2CellFile;
+    @Nullable
+    private File mSatelliteAccessConfigFile;
     private long mLocationFreshDurationNanos;
     @GuardedBy("mLock")
     private boolean mIsOverlayConfigOverridden = false;
@@ -286,6 +297,8 @@ public class SatelliteAccessController extends Handler {
     @Nullable
     private File mOverriddenSatelliteS2CellFile;
     @Nullable
+    private File mOverriddenSatelliteAccessConfigFile;
+    @Nullable
     private String mOverriddenSatelliteConfigurationFileName;
     private long mOverriddenLocationFreshDurationNanos;
 
@@ -343,12 +356,16 @@ public class SatelliteAccessController extends Handler {
     /** These are for config updater config data */
     private static final String SATELLITE_ACCESS_CONTROL_DATA_DIR = "satellite_access_control";
     private static final String CONFIG_UPDATER_S2_CELL_FILE_NAME = "config_updater_sat_s2.dat";
+    private static final String CONFIG_UPDATER_SATELLITE_ACCESS_CONFIG_FILE_NAME =
+            "config_updater_satellite_access_config.json";
     private static final int MIN_S2_LEVEL = 0;
     private static final int MAX_S2_LEVEL = 30;
     private static final String CONFIG_UPDATER_SATELLITE_COUNTRY_CODES_KEY =
             "config_updater_satellite_country_codes";
     private static final String CONFIG_UPDATER_SATELLITE_IS_ALLOW_ACCESS_CONTROL_KEY =
             "config_updater_satellite_is_allow_access_control";
+    protected static final String CONFIG_UPDATER_SATELLITE_VERSION_KEY =
+            "config_updater_satellite_version";
 
     private static final String LATEST_SATELLITE_COMMUNICATION_ALLOWED_SET_TIME_KEY =
             "latest_satellite_communication_allowed_set_time";
@@ -384,8 +401,8 @@ public class SatelliteAccessController extends Handler {
      * Map key: binder of the callback, value: callback to receive the satellite communication
      * allowed state changed events.
      */
-    private final ConcurrentHashMap<IBinder, ISatelliteCommunicationAllowedStateCallback>
-            mSatelliteCommunicationAllowedStateChangedListeners = new ConcurrentHashMap<>();
+    private final ConcurrentHashMap<IBinder, ISatelliteCommunicationAccessStateCallback>
+            mSatelliteCommunicationAccessStateChangedListeners = new ConcurrentHashMap<>();
     protected final Object mSatelliteCommunicationAllowStateLock = new Object();
     @GuardedBy("mSatelliteCommunicationAllowStateLock")
     protected boolean mCurrentSatelliteAllowedState = false;
@@ -404,32 +421,64 @@ public class SatelliteAccessController extends Handler {
     private long mOnDeviceLookupStartTimeMillis;
     private long mTotalCheckingStartTimeMillis;
 
-    private final boolean mNotifySatelliteAvailabilityEnabled;
     private Notification mSatelliteAvailableNotification;
     // Key: SatelliteManager#SatelliteDisallowedReason; Value: Notification
     private final Map<Integer, Notification> mSatelliteUnAvailableNotifications = new HashMap<>();
     private NotificationManager mNotificationManager;
+    @GuardedBy("mSatelliteDisallowedReasonsLock")
     private final List<Integer> mSatelliteDisallowedReasons = new ArrayList<>();
 
+    private boolean mIsLocationManagerEnabled = false;
+
     protected BroadcastReceiver mLocationModeChangedBroadcastReceiver = new BroadcastReceiver() {
         @Override
         public void onReceive(Context context, Intent intent) {
+            // Check whether user has turned on/off location manager from settings menu
             if (intent.getAction().equals(LocationManager.MODE_CHANGED_ACTION)) {
                 plogd("LocationManager mode is changed");
                 if (mLocationManager.isLocationEnabled()) {
                     plogd("Location settings is just enabled");
                     sendRequestAsync(EVENT_LOCATION_SETTINGS_ENABLED, null);
                 } else {
-                    plogd("Location settings is just enabled");
+                    plogd("Location settings is just disabled");
                     sendRequestAsync(EVENT_LOCATION_SETTINGS_DISABLED, null);
                 }
             }
+
+            // Check whether location manager has been enabled when boot up
+            if (intent.getAction().equals(LocationManager.PROVIDERS_CHANGED_ACTION)) {
+                plogd("mLocationModeChangedBroadcastReceiver: " + intent.getAction()
+                        + ", mIsLocationManagerEnabled= " + mIsLocationManagerEnabled);
+                if (!mIsLocationManagerEnabled) {
+                    if (mLocationManager.isLocationEnabled()) {
+                        plogd("Location manager is enabled");
+                        mIsLocationManagerEnabled = true;
+                        boolean isResultReceiverEmpty;
+                        synchronized (mLock) {
+                            isResultReceiverEmpty = mSatelliteAllowResultReceivers.isEmpty();
+                        }
+                        if (isResultReceiverEmpty) {
+                            sendRequestAsync(EVENT_LOCATION_SETTINGS_ENABLED, null);
+                        } else {
+                            plogd("delayed EVENT_LOCATION_SETTINGS_ENABLED due to "
+                                    + "requestIsCommunicationAllowedForCurrentLocation is "
+                                    + "already being processed");
+                            sendDelayedRequestAsync(EVENT_LOCATION_SETTINGS_ENABLED, null,
+                                    WAIT_UNTIL_CURRENT_LOCATION_QUERY_IS_DONE_MILLIS);
+                        }
+                    } else {
+                        plogd("Location manager is still disabled, wait until next enabled event");
+                    }
+                }
+            }
         }
     };
 
     private final Object mIsAllowedCheckBeforeEnablingSatelliteLock = new Object();
     @GuardedBy("mIsAllowedCheckBeforeEnablingSatelliteLock")
     private boolean mIsAllowedCheckBeforeEnablingSatellite;
+    private boolean mIsCurrentLocationEligibleForNotification = false;
+    private boolean mIsProvisionEligibleForNotification = false;
 
     /**
      * Create a SatelliteAccessController instance.
@@ -453,10 +502,7 @@ public class SatelliteAccessController extends Handler {
             @Nullable File s2CellFile) {
         super(looper);
         mContext = context;
-        if (isSatellitePersistentLoggingEnabled(context, featureFlags)) {
-            mPersistentLogger = new PersistentLogger(
-                    DropBoxManagerLoggerBackend.getInstance(context));
-        }
+        mPersistentLogger = SatelliteServiceUtils.getPersistentLogger(context);
         mFeatureFlags = featureFlags;
         mLocationManager = locationManager;
         mTelecomManager = telecomManager;
@@ -473,12 +519,15 @@ public class SatelliteAccessController extends Handler {
         mAccessControllerMetricsStats = AccessControllerMetricsStats.getInstance();
         initSharedPreferences(context);
         checkSharedPreference();
+
         loadOverlayConfigs(context);
         // loadConfigUpdaterConfigs has to be called after loadOverlayConfigs
         // since config updater config has higher priority and thus can override overlay config
         loadConfigUpdaterConfigs();
-        mSatelliteController.registerForConfigUpdateChanged(this, EVENT_CONFIG_DATA_UPDATED,
+        mSatelliteController.registerForConfigUpdateChanged(this, CMD_UPDATE_CONFIG_DATA,
                 context);
+        mSatelliteController.registerForSatelliteSubIdChanged(this,
+                EVENT_SATELLITE_SUBSCRIPTION_CHANGED, context);
         if (s2CellFile != null) {
             mSatelliteS2CellFile = s2CellFile;
         }
@@ -499,15 +548,12 @@ public class SatelliteAccessController extends Handler {
         };
 
         mConfigUpdaterMetricsStats = ConfigUpdaterMetricsStats.getOrCreateInstance();
-        mNotifySatelliteAvailabilityEnabled =
-                context.getResources().getBoolean(
-                        R.bool.config_satellite_should_notify_availability);
         initializeSatelliteSystemNotification(context);
         registerDefaultSmsAppChangedBroadcastReceiver(context);
 
-        mInternalSatelliteSupportedStateCallback = new ISatelliteSupportedStateCallback.Stub() {
+        mInternalSatelliteSupportedStateCallback = new IBooleanConsumer.Stub() {
             @Override
-            public void onSatelliteSupportedStateChanged(boolean isSupported) {
+            public void accept(boolean isSupported) {
                 logd("onSatelliteSupportedStateChanged: isSupported=" + isSupported);
                 if (isSupported) {
                     final String caller = "SAC:onSatelliteSupportedStateChanged";
@@ -520,17 +566,17 @@ public class SatelliteAccessController extends Handler {
                                 }
                             }, false);
                     mSatelliteController.incrementResultReceiverCount(caller);
-                    if (mSatelliteDisallowedReasons.contains(
-                            Integer.valueOf(SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED))) {
-                        mSatelliteDisallowedReasons.remove(
-                                Integer.valueOf(SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED));
+                    if (isReasonPresentInSatelliteDisallowedReasons(
+                            SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED)) {
+                        removeReasonFromSatelliteDisallowedReasons(
+                                SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED);
                         handleEventDisallowedReasonsChanged();
                     }
                 } else {
-                    if (!mSatelliteDisallowedReasons.contains(
-                            Integer.valueOf(SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED))) {
-                        mSatelliteDisallowedReasons.add(
-                                Integer.valueOf(SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED));
+                    if (!isReasonPresentInSatelliteDisallowedReasons(
+                            SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED)) {
+                        addReasonToSatelliteDisallowedReasons(
+                                SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED);
                         handleEventDisallowedReasonsChanged();
                     }
                 }
@@ -545,6 +591,7 @@ public class SatelliteAccessController extends Handler {
             public void onSatelliteProvisionStateChanged(boolean isProvisioned) {
                 logd("onSatelliteProvisionStateChanged: isProvisioned=" + isProvisioned);
                 if (isProvisioned) {
+                    mIsProvisionEligibleForNotification = true;
                     final String caller = "SAC:onSatelliteProvisionStateChanged";
                     requestIsCommunicationAllowedForCurrentLocation(
                             new ResultReceiver(null) {
@@ -555,16 +602,16 @@ public class SatelliteAccessController extends Handler {
                                 }
                             }, false);
                     mSatelliteController.incrementResultReceiverCount(caller);
-                    if (mSatelliteDisallowedReasons.contains(
+                    if (isReasonPresentInSatelliteDisallowedReasons(
                             SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED)) {
-                        mSatelliteDisallowedReasons.remove(
-                                Integer.valueOf(SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED));
+                        removeReasonFromSatelliteDisallowedReasons(
+                                SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED);
                         handleEventDisallowedReasonsChanged();
                     }
                 } else {
-                    if (!mSatelliteDisallowedReasons.contains(
+                    if (!isReasonPresentInSatelliteDisallowedReasons(
                             SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED)) {
-                        mSatelliteDisallowedReasons.add(
+                        addReasonToSatelliteDisallowedReasons(
                                 SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED);
                         handleEventDisallowedReasonsChanged();
                     }
@@ -578,7 +625,6 @@ public class SatelliteAccessController extends Handler {
                         + satelliteSubscriberProvisionStatus);
             }
         };
-        initializeSatelliteSystemNotification(context);
         result = mSatelliteController.registerForSatelliteProvisionStateChanged(
                 mInternalSatelliteProvisionStateCallback);
         plogd("registerForSatelliteProvisionStateChanged result: " + result);
@@ -655,19 +701,29 @@ public class SatelliteAccessController extends Handler {
             case EVENT_KEEP_ON_DEVICE_ACCESS_CONTROLLER_RESOURCES_TIMEOUT:
                 cleanupOnDeviceAccessControllerResources();
                 break;
-            case EVENT_CONFIG_DATA_UPDATED:
+            case CMD_UPDATE_CONFIG_DATA:
                 AsyncResult ar = (AsyncResult) msg.obj;
-                updateSatelliteConfigData((Context) ar.userObj);
+                updateSatelliteAccessDataWithConfigUpdaterData((Context) ar.userObj);
                 break;
+
+            case EVENT_CONFIG_DATA_UPDATED:
+                plogd("EVENT_CONFIG_DATA_UPDATED");      // Fall through
             case EVENT_LOCATION_SETTINGS_ENABLED:
+                plogd("EVENT_LOCATION_SETTINGS_ENABLED");        // Fall through
             case EVENT_LOCATION_SETTINGS_DISABLED:
-                // Fall through
+                plogd("EVENT_LOCATION_SETTINGS_DISABLED");       // Fall through
             case EVENT_COUNTRY_CODE_CHANGED:
+                plogd("EVENT_COUNTRY_CODE_CHANGED");
                 handleSatelliteAllowedRegionPossiblyChanged(msg.what);
                 break;
             case CMD_UPDATE_SYSTEM_SELECTION_CHANNELS:
                 handleCmdUpdateSystemSelectionChannels((ResultReceiver) msg.obj);
                 break;
+            case EVENT_SATELLITE_SUBSCRIPTION_CHANGED:
+                plogd("Event: EVENT_SATELLITE_SUBSCRIPTION_CHANGED");
+                initializeSatelliteSystemNotification(mContext);
+                handleEventDisallowedReasonsChanged();
+                break;
             default:
                 plogw("SatelliteAccessControllerHandler: unexpected message code: " + msg.what);
                 break;
@@ -683,11 +739,6 @@ public class SatelliteAccessController extends Handler {
      */
     public void requestIsCommunicationAllowedForCurrentLocation(
             @NonNull ResultReceiver result, boolean enablingSatellite) {
-        if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
-            plogd("oemEnabledSatelliteFlag is disabled");
-            result.send(SATELLITE_RESULT_REQUEST_NOT_SUPPORTED, null);
-            return;
-        }
         plogd("requestIsCommunicationAllowedForCurrentLocation : "
                 + "enablingSatellite is " + enablingSatellite);
         synchronized (mIsAllowedCheckBeforeEnablingSatelliteLock) {
@@ -783,6 +834,9 @@ public class SatelliteAccessController extends Handler {
             if (reset) {
                 mIsOverlayConfigOverridden = false;
                 cleanUpCtsResources();
+                cleanUpTelephonyConfigs();
+                cleanUpSatelliteAccessConfigOtaResources();
+                cleanupSatelliteConfigOtaResources();
             } else {
                 mIsOverlayConfigOverridden = true;
                 mOverriddenIsSatelliteAllowAccessControl = isAllowed;
@@ -799,19 +853,16 @@ public class SatelliteAccessController extends Handler {
                     mOverriddenSatelliteS2CellFile = null;
                 }
                 if (!TextUtils.isEmpty(satelliteConfigurationFile)) {
-                    File overriddenSatelliteConfigurationFile = getTestSatelliteConfiguration(
+                    mOverriddenSatelliteAccessConfigFile = getTestSatelliteConfiguration(
                             satelliteConfigurationFile);
-                    if (overriddenSatelliteConfigurationFile.exists()) {
-                        mOverriddenSatelliteConfigurationFileName =
-                                overriddenSatelliteConfigurationFile.getAbsolutePath();
-                    } else {
+                    if (!mOverriddenSatelliteAccessConfigFile.exists()) {
                         plogd("The overriding file "
-                                + overriddenSatelliteConfigurationFile.getAbsolutePath()
+                                + mOverriddenSatelliteAccessConfigFile.getAbsolutePath()
                                 + " does not exist");
-                        mOverriddenSatelliteConfigurationFileName = null;
+                        mOverriddenSatelliteAccessConfigFile = null;
                     }
                 } else {
-                    mOverriddenSatelliteConfigurationFileName = null;
+                    mOverriddenSatelliteAccessConfigFile = null;
                 }
                 mOverriddenLocationFreshDurationNanos = locationFreshDurationNanos;
                 if (satelliteCountryCodes != null) {
@@ -907,45 +958,75 @@ public class SatelliteAccessController extends Handler {
     }
 
     @Nullable
-    private static File copySatS2FileToLocalDirectory(@NonNull File sourceFile) {
+    private static File copyFileToLocalDirectory(@NonNull File sourceFile,
+            @NonNull String targetFileName) {
+        logd(
+                "copyFileToLocalDirectory: Copying sourceFile:"
+                        + sourceFile.getAbsolutePath()
+                        + " to targetFileName:"
+                        + targetFileName);
         PhoneGlobals phoneGlobals = PhoneGlobals.getInstance();
-        File satelliteAccessControlFile = phoneGlobals.getDir(
+        File satelliteAccessControlDir = phoneGlobals.getDir(
                 SATELLITE_ACCESS_CONTROL_DATA_DIR, Context.MODE_PRIVATE);
-        if (!satelliteAccessControlFile.exists()) {
-            satelliteAccessControlFile.mkdirs();
+        if (!satelliteAccessControlDir.exists()) {
+            satelliteAccessControlDir.mkdirs();
         }
 
-        Path targetDir = satelliteAccessControlFile.toPath();
-        Path targetSatS2FilePath = targetDir.resolve(CONFIG_UPDATER_S2_CELL_FILE_NAME);
+        Path targetDir = satelliteAccessControlDir.toPath();
+        Path targetFilePath = targetDir.resolve(targetFileName);
+        logd(
+                "copyFileToLocalDirectory: Copying from sourceFile="
+                        + sourceFile.getAbsolutePath()
+                        + " to targetFilePath="
+                        + targetFilePath);
         try {
             InputStream inputStream = new FileInputStream(sourceFile);
             if (inputStream == null) {
-                loge("copySatS2FileToPhoneDirectory: Resource=" + sourceFile.getAbsolutePath()
+                loge("copyFileToLocalDirectory: Resource=" + sourceFile.getAbsolutePath()
                         + " not found");
                 return null;
             } else {
-                Files.copy(inputStream, targetSatS2FilePath, StandardCopyOption.REPLACE_EXISTING);
+                Files.copy(inputStream, targetFilePath, StandardCopyOption.REPLACE_EXISTING);
             }
         } catch (IOException ex) {
-            loge("copySatS2FileToPhoneDirectory: ex=" + ex);
+            loge("copyFileToLocalDirectory: ex=" + ex);
             return null;
         }
-        return targetSatS2FilePath.toFile();
+
+        File targetFile = targetFilePath.toFile();
+        if (targetFile == null || !targetFile.exists()) {
+            loge("copyFileToLocalDirectory: targetFile is null or not exist");
+            return null;
+        }
+        logd(
+                "copyFileToLocalDirectory: Copied from sourceFile="
+                        + sourceFile.getAbsolutePath()
+                        + " to targetFilePath="
+                        + targetFilePath);
+        return targetFile;
     }
 
     @Nullable
-    private File getConfigUpdaterSatS2CellFileFromLocalDirectory() {
+    private File getConfigUpdaterSatelliteConfigFileFromLocalDirectory(@NonNull String fileName) {
         PhoneGlobals phoneGlobals = PhoneGlobals.getInstance();
-        File satelliteAccessControlFile = phoneGlobals.getDir(
+        File satelliteAccessControlDataDir = phoneGlobals.getDir(
                 SATELLITE_ACCESS_CONTROL_DATA_DIR, Context.MODE_PRIVATE);
-        if (!satelliteAccessControlFile.exists()) {
+        if (!satelliteAccessControlDataDir.exists()) {
+            ploge("getConfigUpdaterSatelliteConfigFileFromLocalDirectory: "
+                    + "Directory: " + satelliteAccessControlDataDir.getAbsoluteFile()
+                    + " is not exist");
             return null;
         }
 
-        Path satelliteAccessControlFileDir = satelliteAccessControlFile.toPath();
-        Path configUpdaterSatS2FilePath = satelliteAccessControlFileDir.resolve(
-                CONFIG_UPDATER_S2_CELL_FILE_NAME);
-        return configUpdaterSatS2FilePath.toFile();
+        Path satelliteAccessControlFileDir = satelliteAccessControlDataDir.toPath();
+        Path configUpdaterSatelliteConfigFilePath = satelliteAccessControlFileDir.resolve(fileName);
+        File configUpdaterSatelliteConfigFile = configUpdaterSatelliteConfigFilePath.toFile();
+        if (!configUpdaterSatelliteConfigFile.exists()) {
+            ploge("getConfigUpdaterSatelliteConfigFileFromLocalDirectory: "
+                    + "File: " + fileName + " is not exist");
+            return null;
+        }
+        return configUpdaterSatelliteConfigFile;
     }
 
     private boolean isS2CellFileValid(@NonNull File s2CellFile) {
@@ -976,6 +1057,39 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
+    private void cleanUpTelephonyConfigs() {
+        mSatelliteController.cleanUpTelephonyConfigs();
+    }
+
+    private void cleanUpSatelliteAccessConfigOtaResources() {
+        PhoneGlobals phoneGlobals = PhoneGlobals.getInstance();
+        File satelliteAccessControlDir =
+                phoneGlobals.getDir(SATELLITE_ACCESS_CONTROL_DATA_DIR, Context.MODE_PRIVATE);
+        if (satelliteAccessControlDir == null || !satelliteAccessControlDir.exists()) {
+            plogd(
+                    "cleanUpSatelliteAccessConfigOtaResources: "
+                            + SATELLITE_ACCESS_CONTROL_DATA_DIR
+                            + " does not exist");
+            return;
+        }
+        plogd(
+                "cleanUpSatelliteAccessConfigOtaResources: Deleting contents under "
+                        + SATELLITE_ACCESS_CONTROL_DATA_DIR);
+        FileUtils.deleteContents(satelliteAccessControlDir);
+    }
+
+    private void cleanupSatelliteConfigOtaResources() {
+        SatelliteConfig satelliteConfig = mSatelliteController.getSatelliteConfig();
+        if (satelliteConfig == null) {
+            plogd(
+                    "cleanupSatelliteConfigOtaResources: satelliteConfig is null. Cannot or Not"
+                        + " needed to delete satellite config OTA files");
+            return;
+        }
+        plogd("cleanupSatelliteConfigOtaResources: Deleting satellite config OTA files");
+        satelliteConfig.cleanOtaResources(mContext);
+    }
+
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
     protected long getElapsedRealtimeNanos() {
         return SystemClock.elapsedRealtimeNanos();
@@ -1005,7 +1119,7 @@ public class SatelliteAccessController extends Handler {
             initSharedPreferences(context);
         }
         if (mSharedPreferences == null) {
-            ploge("updateSharedPreferencesCountryCodes: mSharedPreferences is null");
+            ploge("updateSharedPreferencesCountryCodes: mSharedPreferences is still null");
             return false;
         }
         try {
@@ -1018,6 +1132,24 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
+    private void deleteSharedPreferencesbyKey(
+            @NonNull Context context, @NonNull String key) {
+        plogd("deletedeleteSharedPreferencesbyKey: " + key);
+        if (mSharedPreferences == null) {
+            plogd("deleteSharedPreferencesbyKey: mSharedPreferences is null");
+            initSharedPreferences(context);
+        }
+        if (mSharedPreferences == null) {
+            plogd("deleteSharedPreferencesbyKey: mSharedPreferences is still null");
+            return;
+        }
+        try {
+            mSharedPreferences.edit().remove(key).apply();
+        } catch (Exception ex) {
+            ploge("deleteSharedPreferencesbyKey error : " + ex);
+        }
+    }
+
     private boolean updateSharedPreferencesIsAllowAccessControl(
             @NonNull Context context, boolean value) {
         if (mSharedPreferences == null) {
@@ -1039,6 +1171,27 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
+    private boolean updateSharedPreferencesSatelliteAccessConfigVersion(
+            @NonNull Context context, int version) {
+        if (mSharedPreferences == null) {
+            plogd("updateSharedPreferencesSatelliteAccessConfigVersion: "
+                    + "mSharedPreferences is null");
+            initSharedPreferences(context);
+        }
+        if (mSharedPreferences == null) {
+            ploge("updateSharedPreferencesSatelliteAccessConfigVersion: "
+                    + "mSharedPreferences is null");
+            return false;
+        }
+        try {
+            mSharedPreferences.edit().putInt(CONFIG_UPDATER_SATELLITE_VERSION_KEY, version).apply();
+            return true;
+        } catch (Exception ex) {
+            ploge("updateSharedPreferencesSatelliteAccessConfigVersion error: " + ex);
+            return false;
+        }
+    }
+
     private void persistLatestSatelliteCommunicationAllowedState() {
         if (mSharedPreferences == null) {
             ploge("persistLatestSatelliteCommunicationAllowedState: mSharedPreferences is null");
@@ -1056,80 +1209,167 @@ public class SatelliteAccessController extends Handler {
     }
 
     /**
-     * Update country codes and S2CellFile with the new data from ConfigUpdater
+     * Update satellite access config data when ConfigUpdater updates with the new config data.
+     * - country codes, satellite allow access, sats2.dat, satellite_access_config.json
      */
-    private void updateSatelliteConfigData(Context context) {
-        plogd("updateSatelliteConfigData");
-
+    private void updateSatelliteAccessDataWithConfigUpdaterData(Context context) {
+        plogd("updateSatelliteAccessDataWithConfigUpdaterData");
         SatelliteConfig satelliteConfig = mSatelliteController.getSatelliteConfig();
         if (satelliteConfig == null) {
-            ploge("satelliteConfig is null");
+            ploge("updateSatelliteAccessDataWithConfigUpdaterData: satelliteConfig is null");
             mConfigUpdaterMetricsStats.reportOemAndCarrierConfigError(
                     SatelliteConstants.CONFIG_UPDATE_RESULT_NO_SATELLITE_DATA);
             return;
         }
 
+        // satellite access config version
+        int satelliteAccessConfigVersion = satelliteConfig.getSatelliteConfigDataVersion();
+        if (satelliteAccessConfigVersion <= 0) {
+            plogd("updateSatelliteAccessDataWithConfigUpdaterData: version is invalid: "
+                    + satelliteAccessConfigVersion);
+            return;
+        }
+
+        // validation check country code
         List<String> satelliteCountryCodes = satelliteConfig.getDeviceSatelliteCountryCodes();
         if (!isValidCountryCodes(satelliteCountryCodes)) {
-            plogd("country codes is invalid");
+            plogd("updateSatelliteAccessDataWithConfigUpdaterData: country codes is invalid");
             mConfigUpdaterMetricsStats.reportOemConfigError(
                     SatelliteConstants.CONFIG_UPDATE_RESULT_DEVICE_DATA_INVALID_COUNTRY_CODE);
             return;
         }
 
+        // validation check allow region
         Boolean isSatelliteDataForAllowedRegion = satelliteConfig.isSatelliteDataForAllowedRegion();
         if (isSatelliteDataForAllowedRegion == null) {
-            ploge("Satellite allowed is not configured with country codes");
+            ploge("updateSatelliteAccessDataWithConfigUpdaterData: "
+                    + "Satellite isSatelliteDataForAllowedRegion is null ");
             mConfigUpdaterMetricsStats.reportOemConfigError(
                     SatelliteConstants.CONFIG_UPDATE_RESULT_DEVICE_DATA_INVALID_S2_CELL_FILE);
             return;
         }
 
+        // validation check s2 cell file
         File configUpdaterS2CellFile = satelliteConfig.getSatelliteS2CellFile(context);
         if (configUpdaterS2CellFile == null || !configUpdaterS2CellFile.exists()) {
-            plogd("No S2 cell file configured or the file does not exist");
+            plogd("updateSatelliteAccessDataWithConfigUpdaterData: "
+                    + "configUpdaterS2CellFile is not exist");
             mConfigUpdaterMetricsStats.reportOemConfigError(
                     SatelliteConstants.CONFIG_UPDATE_RESULT_DEVICE_DATA_INVALID_S2_CELL_FILE);
             return;
         }
 
         if (!isS2CellFileValid(configUpdaterS2CellFile)) {
-            ploge("The configured S2 cell file is not valid");
+            ploge("updateSatelliteAccessDataWithConfigUpdaterData: "
+                    + "the configUpdaterS2CellFile is not valid");
             mConfigUpdaterMetricsStats.reportOemConfigError(
                     SatelliteConstants.CONFIG_UPDATE_RESULT_DEVICE_DATA_INVALID_S2_CELL_FILE);
             return;
         }
 
-        File localS2CellFile = copySatS2FileToLocalDirectory(configUpdaterS2CellFile);
-        if (localS2CellFile == null || !localS2CellFile.exists()) {
-            ploge("Fail to copy S2 cell file to local directory");
+        // validation check satellite_access_config file
+        File configUpdaterSatelliteAccessConfigJsonFile =
+                satelliteConfig.getSatelliteAccessConfigJsonFile(context);
+        if (configUpdaterSatelliteAccessConfigJsonFile == null
+                || !configUpdaterSatelliteAccessConfigJsonFile.exists()) {
+            plogd("updateSatelliteAccessDataWithConfigUpdaterData: "
+                    + "satellite_access_config.json does not exist");
+            mConfigUpdaterMetricsStats.reportOemConfigError(SatelliteConstants
+                            .CONFIG_UPDATE_RESULT_INVALID_SATELLITE_ACCESS_CONFIG_FILE);
+            return;
+        }
+
+        try {
+            if (SatelliteAccessConfigurationParser.parse(
+                    configUpdaterSatelliteAccessConfigJsonFile.getAbsolutePath()) == null) {
+                ploge("updateSatelliteAccessDataWithConfigUpdaterData: "
+                        + "the satellite_access_config.json is not valid");
+                mConfigUpdaterMetricsStats.reportOemConfigError(SatelliteConstants
+                        .CONFIG_UPDATE_RESULT_INVALID_SATELLITE_ACCESS_CONFIG_FILE);
+                return;
+            }
+        } catch (Exception e) {
+            loge("updateSatelliteAccessDataWithConfigUpdaterData: "
+                    + "the satellite_access_config.json parse error " + e);
+        }
+
+        // copy s2 cell data into the phone internal directory
+        File localS2CellFile = copyFileToLocalDirectory(
+                configUpdaterS2CellFile, CONFIG_UPDATER_S2_CELL_FILE_NAME);
+        if (localS2CellFile == null) {
+            ploge("updateSatelliteAccessDataWithConfigUpdaterData: "
+                    + "fail to copy localS2CellFile");
             mConfigUpdaterMetricsStats.reportOemConfigError(
                     SatelliteConstants.CONFIG_UPDATE_RESULT_IO_ERROR);
             return;
         }
 
+        // copy satellite_access_config file into the phone internal directory
+        File localSatelliteAccessConfigFile = copyFileToLocalDirectory(
+                configUpdaterSatelliteAccessConfigJsonFile,
+                CONFIG_UPDATER_SATELLITE_ACCESS_CONFIG_FILE_NAME);
+
+        if (localSatelliteAccessConfigFile == null) {
+            ploge("updateSatelliteAccessDataWithConfigUpdaterData: "
+                    + "fail to copy localSatelliteAccessConfigFile");
+            mConfigUpdaterMetricsStats.reportOemConfigError(
+                    SatelliteConstants.CONFIG_UPDATE_RESULT_IO_ERROR);
+            localS2CellFile.delete();
+            return;
+        }
+
+        // copy country codes into the shared preferences of phoen
         if (!updateSharedPreferencesCountryCodes(context, satelliteCountryCodes)) {
-            ploge("Fail to copy country coeds into shared preferences");
+            ploge("updateSatelliteAccessDataWithConfigUpdaterData: "
+                    + "fail to copy country coeds into shared preferences");
             localS2CellFile.delete();
+            localSatelliteAccessConfigFile.delete();
             mConfigUpdaterMetricsStats.reportOemConfigError(
                     SatelliteConstants.CONFIG_UPDATE_RESULT_IO_ERROR);
             return;
         }
 
+        // copy allow access into the shared preferences of phone
         if (!updateSharedPreferencesIsAllowAccessControl(
                 context, isSatelliteDataForAllowedRegion.booleanValue())) {
-            ploge("Fail to copy allow access control into shared preferences");
+            ploge("updateSatelliteAccessDataWithConfigUpdaterData: "
+                    + "fail to copy isSatelliteDataForAllowedRegion"
+                    + " into shared preferences");
+            localS2CellFile.delete();
+            localSatelliteAccessConfigFile.delete();
+            deleteSharedPreferencesbyKey(
+                    context, CONFIG_UPDATER_SATELLITE_COUNTRY_CODES_KEY);
+            mConfigUpdaterMetricsStats.reportOemConfigError(
+                    SatelliteConstants.CONFIG_UPDATE_RESULT_IO_ERROR);
+            return;
+        }
+
+        // copy version of satellite access config into the shared preferences of phone
+        if (!updateSharedPreferencesSatelliteAccessConfigVersion(
+                context, satelliteAccessConfigVersion)) {
+            ploge("updateSatelliteAccessDataWithConfigUpdaterData: "
+                    + "fail to copy satelliteAccessConfigVersion"
+                    + " into shared preferences");
             localS2CellFile.delete();
+            localSatelliteAccessConfigFile.delete();
+            deleteSharedPreferencesbyKey(
+                    context, CONFIG_UPDATER_SATELLITE_COUNTRY_CODES_KEY);
+            deleteSharedPreferencesbyKey(
+                    context, CONFIG_UPDATER_SATELLITE_IS_ALLOW_ACCESS_CONTROL_KEY);
             mConfigUpdaterMetricsStats.reportOemConfigError(
                     SatelliteConstants.CONFIG_UPDATE_RESULT_IO_ERROR);
             return;
         }
 
+        mSatelliteAccessConfigVersion = satelliteAccessConfigVersion;
         mSatelliteS2CellFile = localS2CellFile;
+        mSatelliteAccessConfigFile = localSatelliteAccessConfigFile;
         mSatelliteCountryCodes = satelliteCountryCodes;
         mIsSatelliteAllowAccessControl = satelliteConfig.isSatelliteDataForAllowedRegion();
-        plogd("Use s2 cell file=" + mSatelliteS2CellFile.getAbsolutePath() + ", country codes="
-                + String.join(",", mSatelliteCountryCodes)
+        plogd("mSatelliteAccessConfigVersion=" + mSatelliteAccessConfigVersion
+                + ", Use s2 cell file=" + mSatelliteS2CellFile.getAbsolutePath()
+                + ", mSatelliteAccessConfigFile=" + mSatelliteAccessConfigFile.getAbsolutePath()
+                + ", country codes=" + String.join(",", mSatelliteCountryCodes)
                 + ", mIsSatelliteAllowAccessControl=" + mIsSatelliteAllowAccessControl
                 + " from ConfigUpdater");
 
@@ -1143,10 +1383,15 @@ public class SatelliteAccessController extends Handler {
         }
 
         mConfigUpdaterMetricsStats.reportConfigUpdateSuccess();
+        // We need to re-evaluate if satellite is allowed at the current location and if
+        // satellite access configuration has changed with the config data received from config
+        // server, and then notify listeners accordingly.
+        sendRequestAsync(EVENT_CONFIG_DATA_UPDATED, null);
     }
 
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
     protected void loadOverlayConfigs(@NonNull Context context) {
+        plogd("loadOverlayConfigs");
         mSatelliteCountryCodes = getSatelliteCountryCodesFromOverlayConfig(context);
         mIsSatelliteAllowAccessControl = getSatelliteAccessAllowFromOverlayConfig(context);
         String satelliteS2CellFileName = getSatelliteS2CellFileFromOverlayConfig(context);
@@ -1157,6 +1402,16 @@ public class SatelliteAccessController extends Handler {
             mSatelliteS2CellFile = null;
         }
 
+        String satelliteAccessConfigFileName =
+                getSatelliteConfigurationFileNameFromOverlayConfig(context);
+        mSatelliteAccessConfigFile = TextUtils.isEmpty(satelliteAccessConfigFileName)
+                ? null : new File(satelliteAccessConfigFileName);
+        if (mSatelliteAccessConfigFile != null && !mSatelliteAccessConfigFile.exists()) {
+            ploge("The satellite access config file " + satelliteAccessConfigFileName
+                    + " does not exist");
+            mSatelliteAccessConfigFile = null;
+        }
+
         mLocationFreshDurationNanos = getSatelliteLocationFreshDurationFromOverlayConfig(context);
         mAccessControllerMetricsStats.setConfigDataSource(
                 SatelliteConstants.CONFIG_DATA_SOURCE_DEVICE_CONFIG);
@@ -1167,22 +1422,25 @@ public class SatelliteAccessController extends Handler {
         mLocationQueryThrottleIntervalNanos = getLocationQueryThrottleIntervalNanos(context);
     }
 
-    protected void loadSatelliteAccessConfigurationFromDeviceConfig() {
-        logd("loadSatelliteAccessConfigurationFromDeviceConfig:");
+    protected void loadSatelliteAccessConfiguration() {
+        logd("loadSatelliteAccessConfiguration");
         String satelliteConfigurationFileName;
+        File satelliteAccessConfigFile = getSatelliteAccessConfigFile();
         synchronized (mLock) {
-            if (mIsOverlayConfigOverridden && mOverriddenSatelliteConfigurationFileName != null) {
-                satelliteConfigurationFileName = mOverriddenSatelliteConfigurationFileName;
+            if (satelliteAccessConfigFile != null) {
+                satelliteConfigurationFileName = satelliteAccessConfigFile.getAbsolutePath();
             } else {
+                logd("loadSatelliteAccessConfiguration:");
                 satelliteConfigurationFileName = getSatelliteConfigurationFileNameFromOverlayConfig(
                         mContext);
             }
         }
-        loadSatelliteAccessConfigurationFromFile(satelliteConfigurationFileName);
+
+        loadSatelliteAccessConfigurationFileToMap(satelliteConfigurationFileName);
     }
 
-    protected void loadSatelliteAccessConfigurationFromFile(String fileName) {
-        logd("loadSatelliteAccessConfigurationFromFile: " + fileName);
+    protected void loadSatelliteAccessConfigurationFileToMap(String fileName) {
+        logd("loadSatelliteAccessConfigurationFileToMap: " + fileName);
         if (!TextUtils.isEmpty(fileName)) {
             try {
                 synchronized (mLock) {
@@ -1190,24 +1448,33 @@ public class SatelliteAccessController extends Handler {
                             SatelliteAccessConfigurationParser.parse(fileName);
                 }
             } catch (Exception e) {
-                loge("loadSatelliteAccessConfigurationFromFile: failed load json file: " + e);
+                loge("loadSatelliteAccessConfigurationFileToMap: failed load json file: " + e);
             }
         } else {
-            loge("loadSatelliteAccessConfigurationFromFile: fileName is empty");
+            loge("loadSatelliteAccessConfigurationFileToMap: fileName is empty");
         }
     }
 
     private void loadConfigUpdaterConfigs() {
+        plogd("loadConfigUpdaterConfigs");
         if (mSharedPreferences == null) {
             ploge("loadConfigUpdaterConfigs : mSharedPreferences is null");
             return;
         }
 
+        int satelliteConfigVersion = mSharedPreferences.getInt(
+                CONFIG_UPDATER_SATELLITE_VERSION_KEY, 0);
+        if (satelliteConfigVersion <= 0) {
+            ploge("loadConfigUpdaterConfigs: satelliteConfigVersion is invalid: "
+                    + satelliteConfigVersion);
+            return;
+        }
+
         Set<String> countryCodes =
                 mSharedPreferences.getStringSet(CONFIG_UPDATER_SATELLITE_COUNTRY_CODES_KEY, null);
 
         if (countryCodes == null || countryCodes.isEmpty()) {
-            ploge("config updater country codes are either null or empty");
+            ploge("loadConfigUpdaterConfigs: configupdater country codes are either null or empty");
             return;
         }
 
@@ -1215,16 +1482,32 @@ public class SatelliteAccessController extends Handler {
                 mSharedPreferences.getBoolean(
                         CONFIG_UPDATER_SATELLITE_IS_ALLOW_ACCESS_CONTROL_KEY, true);
 
-        File s2CellFile = getConfigUpdaterSatS2CellFileFromLocalDirectory();
+        File s2CellFile = getConfigUpdaterSatelliteConfigFileFromLocalDirectory(
+                CONFIG_UPDATER_S2_CELL_FILE_NAME);
         if (s2CellFile == null) {
-            ploge("s2CellFile is null");
+            ploge("loadConfigUpdaterConfigs: s2CellFile is null");
+            return;
+        }
+
+        File satelliteAccessConfigJsonFile = getConfigUpdaterSatelliteConfigFileFromLocalDirectory(
+                CONFIG_UPDATER_SATELLITE_ACCESS_CONFIG_FILE_NAME);
+        if (satelliteAccessConfigJsonFile == null) {
+            ploge("satelliteAccessConfigJsonFile is null");
             return;
         }
 
-        plogd("use config updater config data");
+        mSatelliteAccessConfigVersion = satelliteConfigVersion;
         mSatelliteS2CellFile = s2CellFile;
+        mSatelliteAccessConfigFile = satelliteAccessConfigJsonFile;
         mSatelliteCountryCodes = countryCodes.stream().collect(Collectors.toList());
         mIsSatelliteAllowAccessControl = isSatelliteAllowAccessControl;
+        plogd("loadConfigUpdaterConfigs: use satellite config data from configupdater: "
+                + " mSatelliteAccessConfigVersion=" + mSatelliteAccessConfigVersion
+                + ", Use s2 cell file=" + mSatelliteS2CellFile.getAbsolutePath()
+                + ", mSatelliteAccessConfigFile=" + mSatelliteAccessConfigFile.getAbsolutePath()
+                + ", country codes=" + String.join(",", mSatelliteCountryCodes)
+                + ", mIsSatelliteAllowAccessControl=" + mIsSatelliteAllowAccessControl
+                + " from ConfigUpdater");
         mAccessControllerMetricsStats.setConfigDataSource(
                 SatelliteConstants.CONFIG_DATA_SOURCE_CONFIG_UPDATER);
     }
@@ -1259,8 +1542,13 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
+    /**
+     * Returns a list of satellite country codes.
+     *
+     * @return The list of satellite country codes.
+     */
     @NonNull
-    private List<String> getSatelliteCountryCodes() {
+    public List<String> getSatelliteCountryCodes() {
         synchronized (mLock) {
             if (mIsOverlayConfigOverridden) {
                 return mOverriddenSatelliteCountryCodes;
@@ -1269,8 +1557,13 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
+    /**
+     * Returns a satellite s2 cell file
+     *
+     * @return The file of satellite s2 cell
+     */
     @Nullable
-    private File getSatelliteS2CellFile() {
+    public File getSatelliteS2CellFile() {
         synchronized (mLock) {
             if (mIsOverlayConfigOverridden) {
                 return mOverriddenSatelliteS2CellFile;
@@ -1279,7 +1572,32 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
-    private boolean isSatelliteAllowAccessControl() {
+    /**
+     * Returns a satellite access config file
+     *
+     * @return The file of satellite access config
+     */
+    @Nullable
+    public File getSatelliteAccessConfigFile() {
+        synchronized (mLock) {
+            if (mIsOverlayConfigOverridden) {
+                logd("mIsOverlayConfigOverridden: " + mIsOverlayConfigOverridden);
+                return mOverriddenSatelliteAccessConfigFile;
+            }
+            if (mSatelliteAccessConfigFile != null) {
+                logd("getSatelliteAccessConfigFile path: "
+                        + mSatelliteAccessConfigFile.getAbsoluteFile());
+            }
+            return mSatelliteAccessConfigFile;
+        }
+    }
+
+    /**
+     * Checks if satellite access control is allowed.
+     *
+     * @return {@code true} if satellite access control is allowed, {@code false} otherwise.
+     */
+    public boolean isSatelliteAllowAccessControl() {
         synchronized (mLock) {
             if (mIsOverlayConfigOverridden) {
                 return mOverriddenIsSatelliteAllowAccessControl;
@@ -1330,13 +1648,9 @@ public class SatelliteAccessController extends Handler {
     }
 
     private void registerLocationModeChangedBroadcastReceiver(Context context) {
-        if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
-            plogd("registerLocationModeChangedBroadcastReceiver: Flag "
-                    + "oemEnabledSatellite is disabled");
-            return;
-        }
         IntentFilter intentFilter = new IntentFilter();
         intentFilter.addAction(LocationManager.MODE_CHANGED_ACTION);
+        intentFilter.addAction(LocationManager.PROVIDERS_CHANGED_ACTION);
         context.registerReceiver(mLocationModeChangedBroadcastReceiver, intentFilter);
     }
 
@@ -1434,9 +1748,19 @@ public class SatelliteAccessController extends Handler {
     private void sendSatelliteAllowResultToReceivers(int resultCode, Bundle resultData,
             boolean allowed) {
         plogd("sendSatelliteAllowResultToReceivers : resultCode is " + resultCode);
-        if (resultCode == SATELLITE_RESULT_SUCCESS) {
-            updateCurrentSatelliteAllowedState(allowed);
+        switch(resultCode) {
+            case SATELLITE_RESULT_SUCCESS:
+                updateCurrentSatelliteAllowedState(allowed);
+                mIsCurrentLocationEligibleForNotification = true;
+                break;
+
+            case SATELLITE_RESULT_LOCATION_DISABLED:
+                updateCurrentSatelliteAllowedState(allowed);
+                break;
+            default:
+                break;
         }
+
         synchronized (mLock) {
             for (ResultReceiver resultReceiver : mSatelliteAllowResultReceivers) {
                 resultReceiver.send(resultCode, resultData);
@@ -1451,20 +1775,25 @@ public class SatelliteAccessController extends Handler {
         Integer disallowedReason = getDisallowedReason(resultCode, allowed);
         boolean isChanged = false;
         if (disallowedReason != SATELLITE_DISALLOWED_REASON_NONE) {
-            if (!mSatelliteDisallowedReasons.contains(disallowedReason)) {
+            if (!isReasonPresentInSatelliteDisallowedReasons(disallowedReason)) {
                 isChanged = true;
             }
         } else {
-            if (mSatelliteDisallowedReasons.contains(
+            if (isSatelliteDisallowedReasonsEmpty()) {
+                if (!hasAlreadyNotified(KEY_AVAILABLE_NOTIFICATION_SHOWN)) {
+                    isChanged = true;
+                }
+            }
+            if (isReasonPresentInSatelliteDisallowedReasons(
                     SATELLITE_DISALLOWED_REASON_NOT_IN_ALLOWED_REGION)
-                    || mSatelliteDisallowedReasons.contains(
+                    || isReasonPresentInSatelliteDisallowedReasons(
                     SATELLITE_DISALLOWED_REASON_LOCATION_DISABLED)) {
                 isChanged = true;
             }
         }
-        mSatelliteDisallowedReasons.removeAll(DISALLOWED_REASONS_TO_BE_RESET);
+        removeAllReasonsFromSatelliteDisallowedReasons(DISALLOWED_REASONS_TO_BE_RESET);
         if (disallowedReason != SATELLITE_DISALLOWED_REASON_NONE) {
-            mSatelliteDisallowedReasons.add(disallowedReason);
+            addReasonToSatelliteDisallowedReasons(disallowedReason);
         }
         if (isChanged) {
             handleEventDisallowedReasonsChanged();
@@ -1487,13 +1816,32 @@ public class SatelliteAccessController extends Handler {
     }
 
     private void handleEventDisallowedReasonsChanged() {
-        logd("mSatelliteDisallowedReasons:"
-                + String.join(", ", mSatelliteDisallowedReasons.toString()));
+        if (mNotificationManager == null) {
+            logd("showSatelliteSystemNotification: NotificationManager is null");
+            return;
+        }
+
+        List<Integer> satelliteDisallowedReasons = getSatelliteDisallowedReasonsCopy();
+        plogd("getSatelliteDisallowedReasons: satelliteDisallowedReasons:"
+                + String.join(", ", satelliteDisallowedReasons.toString()));
+
         notifySatelliteDisallowedReasonsChanged();
-        int subId = mSatelliteController.getSelectedSatelliteSubId();
         if (mSatelliteController.isSatelliteSystemNotificationsEnabled(
-                CarrierConfigManager.CARRIER_ROAMING_NTN_CONNECT_MANUAL)) {
+                CarrierConfigManager.CARRIER_ROAMING_NTN_CONNECT_MANUAL)
+                && mIsCurrentLocationEligibleForNotification
+                && mIsProvisionEligibleForNotification) {
             showSatelliteSystemNotification();
+        } else {
+            logd("mSatelliteDisallowedReasons:"
+                    + " CurrentLocationAvailable: " + mIsCurrentLocationEligibleForNotification
+                    + " SatelliteProvision: " + mIsProvisionEligibleForNotification);
+            // If subId does not support satellite, remove the notification currently shown.
+            if (hasAlreadyNotified(KEY_UNAVAILABLE_NOTIFICATION_SHOWN)) {
+                mNotificationManager.cancel(UNAVAILABLE_NOTIFICATION_TAG, NOTIFICATION_ID);
+            }
+            if (hasAlreadyNotified(KEY_AVAILABLE_NOTIFICATION_SHOWN)) {
+                mNotificationManager.cancel(AVAILABLE_NOTIFICATION_TAG, NOTIFICATION_ID);
+            }
         }
     }
 
@@ -1503,7 +1851,7 @@ public class SatelliteAccessController extends Handler {
             return;
         }
 
-        if (mSatelliteDisallowedReasons.isEmpty()) {
+        if (isSatelliteDisallowedReasonsEmpty()) {
             mNotificationManager.cancel(UNAVAILABLE_NOTIFICATION_TAG, NOTIFICATION_ID);
             if (!hasAlreadyNotified(KEY_AVAILABLE_NOTIFICATION_SHOWN)) {
                 mNotificationManager.notifyAsUser(
@@ -1514,6 +1862,12 @@ public class SatelliteAccessController extends Handler {
                 );
                 markAsNotified(KEY_AVAILABLE_NOTIFICATION_SHOWN, true);
                 markAsNotified(KEY_UNAVAILABLE_NOTIFICATION_SHOWN, false);
+                logd("showSatelliteSystemNotification: Notification is shown "
+                        + KEY_AVAILABLE_NOTIFICATION_SHOWN);
+            } else {
+                logd("showSatelliteSystemNotification: Notification is not shown "
+                        + KEY_AVAILABLE_NOTIFICATION_SHOWN + " = "
+                        + hasAlreadyNotified(KEY_AVAILABLE_NOTIFICATION_SHOWN));
             }
         } else {
             mNotificationManager.cancel(AVAILABLE_NOTIFICATION_TAG, NOTIFICATION_ID);
@@ -1527,7 +1881,12 @@ public class SatelliteAccessController extends Handler {
                     );
                     markAsNotified(KEY_UNAVAILABLE_NOTIFICATION_SHOWN, true);
                     markAsNotified(KEY_AVAILABLE_NOTIFICATION_SHOWN, false);
+                    logd("showSatelliteSystemNotification: Notification is shown "
+                            + KEY_UNAVAILABLE_NOTIFICATION_SHOWN);
                     break;
+                } else {
+                    logd("showSatelliteSystemNotification: Notification is not shown "
+                            + KEY_UNAVAILABLE_NOTIFICATION_SHOWN);
                 }
             }
         }
@@ -1650,7 +2009,8 @@ public class SatelliteAccessController extends Handler {
                 .setAutoCancel(true)
                 .setColor(context.getColor(
                         com.android.internal.R.color.system_notification_accent_color))
-                .setVisibility(Notification.VISIBILITY_PUBLIC);
+                .setVisibility(Notification.VISIBILITY_PUBLIC)
+                .setLocalOnly(true);
 
         return notificationBuilder.build();
     }
@@ -1735,28 +2095,23 @@ public class SatelliteAccessController extends Handler {
         }
 
         if (isDefaultMsgAppSupported) {
-            if (mSatelliteDisallowedReasons.contains(Integer.valueOf(
-                    SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP))) {
-                mSatelliteDisallowedReasons.remove(Integer.valueOf(
-                        SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP));
+            if (isReasonPresentInSatelliteDisallowedReasons(
+                    SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP)) {
+                removeReasonFromSatelliteDisallowedReasons(
+                        SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP);
                 handleEventDisallowedReasonsChanged();
             }
         } else {
-            if (!mSatelliteDisallowedReasons.contains(Integer.valueOf(
-                    SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP))) {
-                mSatelliteDisallowedReasons.add(Integer.valueOf(
-                        SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP));
+            if (!isReasonPresentInSatelliteDisallowedReasons(
+                    SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP)) {
+                addReasonToSatelliteDisallowedReasons(
+                        SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP);
                 handleEventDisallowedReasonsChanged();
             }
         }
     }
 
     private void handleSatelliteAllowedRegionPossiblyChanged(int handleEvent) {
-        if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
-            ploge("handleSatelliteAllowedRegionPossiblyChanged: "
-                    + "The feature flag oemEnabledSatelliteFlag() is not enabled");
-            return;
-        }
         synchronized (mPossibleChangeInSatelliteAllowedRegionLock) {
             logd("handleSatelliteAllowedRegionPossiblyChanged");
             setIsSatelliteAllowedRegionPossiblyChanged(true);
@@ -1767,6 +2122,10 @@ public class SatelliteAccessController extends Handler {
                 triggeringEvent = TRIGGERING_EVENT_LOCATION_SETTINGS_ENABLED;
             } else if (handleEvent == EVENT_COUNTRY_CODE_CHANGED) {
                 triggeringEvent = TRIGGERING_EVENT_MCC_CHANGED;
+            } else if (handleEvent == EVENT_LOCATION_SETTINGS_DISABLED) {
+                triggeringEvent = TRIGGERING_EVENT_LOCATION_SETTINGS_DISABLED;
+            } else if (handleEvent == EVENT_CONFIG_DATA_UPDATED) {
+                triggeringEvent = TRIGGERING_EVENT_CONFIG_DATA_UPDATED;
             }
             mAccessControllerMetricsStats.setTriggeringEvent(triggeringEvent);
         }
@@ -1975,6 +2334,7 @@ public class SatelliteAccessController extends Handler {
                         SatelliteConstants.ACCESS_CONTROL_TYPE_CURRENT_LOCATION);
                 mControllerMetricsStats.reportLocationQuerySuccessful(true);
                 checkSatelliteAccessRestrictionForLocation(location);
+                mIsCurrentLocationEligibleForNotification = true;
             } else {
                 plogd("current location is not available");
                 if (isCommunicationAllowedCacheValid()) {
@@ -1983,6 +2343,7 @@ public class SatelliteAccessController extends Handler {
                             mLatestSatelliteCommunicationAllowed);
                     sendSatelliteAllowResultToReceivers(SATELLITE_RESULT_SUCCESS, bundle,
                             mLatestSatelliteCommunicationAllowed);
+                    mIsCurrentLocationEligibleForNotification = true;
                 } else {
                     bundle.putBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED, false);
                     sendSatelliteAllowResultToReceivers(
@@ -1996,6 +2357,14 @@ public class SatelliteAccessController extends Handler {
     protected void checkSatelliteAccessRestrictionForLocation(@NonNull Location location) {
         synchronized (mLock) {
             try {
+                plogd(
+                        "checkSatelliteAccessRestrictionForLocation: "
+                                + "checking satellite access restriction for location: lat - "
+                                + Rlog.pii(TAG, location.getLatitude())
+                                + ", long - "
+                                + Rlog.pii(TAG, location.getLongitude())
+                                + ", mS2Level - "
+                                + mS2Level);
                 SatelliteOnDeviceAccessController.LocationToken locationToken =
                         SatelliteOnDeviceAccessController.createLocationTokenForLatLng(
                                 location.getLatitude(),
@@ -2005,7 +2374,8 @@ public class SatelliteAccessController extends Handler {
                 if (mCachedAccessRestrictionMap.containsKey(locationToken)) {
                     mNewRegionalConfigId = mCachedAccessRestrictionMap.get(locationToken);
                     satelliteAllowed = (mNewRegionalConfigId != null);
-                    plogd("mNewRegionalConfigId is " + mNewRegionalConfigId);
+                    plogd("mNewRegionalConfigId from mCachedAccessRestrictionMap is "
+                            + mNewRegionalConfigId);
                 } else {
                     if (!initSatelliteOnDeviceAccessController()) {
                         ploge("Failed to init SatelliteOnDeviceAccessController");
@@ -2020,7 +2390,9 @@ public class SatelliteAccessController extends Handler {
                         synchronized (mLock) {
                             mNewRegionalConfigId = mSatelliteOnDeviceAccessController
                                     .getRegionalConfigIdForLocation(locationToken);
-                            plogd("mNewRegionalConfigId is " + mNewRegionalConfigId);
+                            plogd(
+                                    "mNewRegionalConfigId from geofence file lookup is "
+                                            + mNewRegionalConfigId);
                             satelliteAllowed = (mNewRegionalConfigId != null);
                         }
                     } else {
@@ -2028,12 +2400,25 @@ public class SatelliteAccessController extends Handler {
                                 + "carrierRoamingNbIotNtn is disabled");
                         satelliteAllowed = mSatelliteOnDeviceAccessController
                                 .isSatCommunicationAllowedAtLocation(locationToken);
+                        plogd(
+                                "checkSatelliteAccessRestrictionForLocation: satelliteAllowed from "
+                                        + "geofence file lookup: "
+                                        + satelliteAllowed);
                         mNewRegionalConfigId =
                                 satelliteAllowed ? UNKNOWN_REGIONAL_SATELLITE_CONFIG_ID : null;
                     }
                     updateCachedAccessRestrictionMap(locationToken, mNewRegionalConfigId);
                 }
                 mAccessControllerMetricsStats.setOnDeviceLookupTime(mOnDeviceLookupStartTimeMillis);
+                plogd(
+                        "checkSatelliteAccessRestrictionForLocation: "
+                                + (satelliteAllowed ? "Satellite Allowed" : "Satellite NOT Allowed")
+                                + " for location: lat - "
+                                + Rlog.pii(TAG, location.getLatitude())
+                                + ", long - "
+                                + Rlog.pii(TAG, location.getLongitude())
+                                + ", mS2Level - "
+                                + mS2Level);
                 Bundle bundle = new Bundle();
                 bundle.putBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED, satelliteAllowed);
                 sendSatelliteAllowResultToReceivers(SATELLITE_RESULT_SUCCESS, bundle,
@@ -2049,10 +2434,12 @@ public class SatelliteAccessController extends Handler {
                 if (isCommunicationAllowedCacheValid()) {
                     bundle.putBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED,
                             mLatestSatelliteCommunicationAllowed);
-                    plogd("checkSatelliteAccessRestrictionForLocation: cache is still valid, "
-                            + "using it");
+                    plogd(
+                            "checkSatelliteAccessRestrictionForLocation: cache is still valid, "
+                                    + "allowing satellite communication");
                 } else {
                     bundle.putBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED, false);
+                    plogd("satellite communication not allowed");
                 }
                 sendSatelliteAllowResultToReceivers(SATELLITE_RESULT_SUCCESS, bundle,
                         mLatestSatelliteCommunicationAllowed);
@@ -2222,6 +2609,8 @@ public class SatelliteAccessController extends Handler {
      */
     private boolean initSatelliteOnDeviceAccessController()
             throws IllegalStateException {
+        plogd("initSatelliteOnDeviceAccessController");
+
         synchronized (mLock) {
             if (getSatelliteS2CellFile() == null) return false;
 
@@ -2235,10 +2624,14 @@ public class SatelliteAccessController extends Handler {
                 mSatelliteOnDeviceAccessController =
                         SatelliteOnDeviceAccessController.create(
                                 getSatelliteS2CellFile(), mFeatureFlags);
+
+                plogd(
+                        "initSatelliteOnDeviceAccessController: initialized"
+                            + " SatelliteOnDeviceAccessController");
                 restartKeepOnDeviceAccessControllerResourcesTimer();
                 mS2Level = mSatelliteOnDeviceAccessController.getS2Level();
                 plogd("mS2Level=" + mS2Level);
-                loadSatelliteAccessConfigurationFromDeviceConfig();
+                loadSatelliteAccessConfiguration();
             } catch (Exception ex) {
                 ploge("Got exception in creating an instance of SatelliteOnDeviceAccessController,"
                         + " ex=" + ex + ", sat s2 file="
@@ -2390,7 +2783,6 @@ public class SatelliteAccessController extends Handler {
         return accessAllowed;
     }
 
-
     @Nullable
     protected String getSatelliteConfigurationFileNameFromOverlayConfig(
             @NonNull Context context) {
@@ -2595,9 +2987,9 @@ public class SatelliteAccessController extends Handler {
      * @param command  command to be executed on the main thread
      * @param argument additional parameters required to perform of the operation
      */
-    private void sendDelayedRequestAsync(int command, @NonNull Object argument, long dealyMillis) {
+    private void sendDelayedRequestAsync(int command, @Nullable Object argument, long delayMillis) {
         Message msg = this.obtainMessage(command, argument);
-        sendMessageDelayed(msg, dealyMillis);
+        sendMessageDelayed(msg, delayMillis);
     }
 
     /**
@@ -2606,7 +2998,7 @@ public class SatelliteAccessController extends Handler {
      * @param command  command to be executed on the main thread
      * @param argument additional parameters required to perform of the operation
      */
-    private void sendRequestAsync(int command, @NonNull Object argument) {
+    private void sendRequestAsync(int command, @Nullable Object argument) {
         Message msg = this.obtainMessage(command, argument);
         msg.sendToTarget();
     }
@@ -2621,22 +3013,15 @@ public class SatelliteAccessController extends Handler {
      * @return The {@link SatelliteManager.SatelliteResult} result of the operation.
      */
     @SatelliteManager.SatelliteResult
-    public int registerForCommunicationAllowedStateChanged(int subId,
-            @NonNull ISatelliteCommunicationAllowedStateCallback callback) {
-        if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
-            plogd("registerForCommunicationAllowedStateChanged: oemEnabledSatelliteFlag is "
-                    + "disabled");
-            return SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
-        }
-
-        mSatelliteCommunicationAllowedStateChangedListeners.put(callback.asBinder(), callback);
+    public int registerForCommunicationAccessStateChanged(int subId,
+            @NonNull ISatelliteCommunicationAccessStateCallback callback) {
+        mSatelliteCommunicationAccessStateChangedListeners.put(callback.asBinder(), callback);
 
         this.post(() -> {
             try {
                 synchronized (mSatelliteCommunicationAllowStateLock) {
-                    callback.onSatelliteCommunicationAllowedStateChanged(
-                            mCurrentSatelliteAllowedState);
-                    logd("registerForCommunicationAllowedStateChanged: "
+                    callback.onAccessAllowedStateChanged(mCurrentSatelliteAllowedState);
+                    logd("registerForCommunicationAccessStateChanged: "
                             + "mCurrentSatelliteAllowedState " + mCurrentSatelliteAllowedState);
                 }
                 synchronized (mLock) {
@@ -2644,13 +3029,13 @@ public class SatelliteAccessController extends Handler {
                             Optional.ofNullable(mSatelliteAccessConfigMap)
                                     .map(map -> map.get(mRegionalConfigId))
                                     .orElse(null);
-                    callback.onSatelliteAccessConfigurationChanged(satelliteAccessConfig);
-                    logd("registerForCommunicationAllowedStateChanged: satelliteAccessConfig: "
+                    callback.onAccessConfigurationChanged(satelliteAccessConfig);
+                    logd("registerForCommunicationAccessStateChanged: satelliteAccessConfig: "
                             + satelliteAccessConfig + " of mRegionalConfigId: "
                             + mRegionalConfigId);
                 }
             } catch (RemoteException ex) {
-                ploge("registerForCommunicationAllowedStateChanged: RemoteException ex=" + ex);
+                ploge("registerForCommunicationAccessStateChanged: RemoteException ex=" + ex);
             }
         });
 
@@ -2664,18 +3049,12 @@ public class SatelliteAccessController extends Handler {
      * @param subId    The subId of the subscription to unregister for the satellite communication
      *                 allowed state changed.
      * @param callback The callback that was passed to
-     *                 {@link #registerForCommunicationAllowedStateChanged(int,
-     *                 ISatelliteCommunicationAllowedStateCallback)}.
+     *                 {@link #registerForCommunicationAccessStateChanged(int,
+     *                 ISatelliteCommunicationAccessStateCallback)}.
      */
-    public void unregisterForCommunicationAllowedStateChanged(
-            int subId, @NonNull ISatelliteCommunicationAllowedStateCallback callback) {
-        if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
-            plogd("unregisterForCommunicationAllowedStateChanged: "
-                    + "oemEnabledSatelliteFlag is disabled");
-            return;
-        }
-
-        mSatelliteCommunicationAllowedStateChangedListeners.remove(callback.asBinder());
+    public void unregisterForCommunicationAccessStateChanged(
+            int subId, @NonNull ISatelliteCommunicationAccessStateCallback callback) {
+        mSatelliteCommunicationAccessStateChangedListeners.remove(callback.asBinder());
     }
 
     /**
@@ -2690,11 +3069,10 @@ public class SatelliteAccessController extends Handler {
             return new ArrayList<>();
         }
 
-        synchronized (mSatelliteDisallowedReasonsLock) {
-            logd("mSatelliteDisallowedReasons:"
-                    + String.join(", ", mSatelliteDisallowedReasons.toString()));
-            return mSatelliteDisallowedReasons;
-        }
+        List<Integer> satelliteDisallowedReasons = getSatelliteDisallowedReasonsCopy();
+        plogd("getSatelliteDisallowedReasons: satelliteDisallowedReasons:"
+                + String.join(", ", satelliteDisallowedReasons.toString()));
+        return satelliteDisallowedReasons;
     }
 
     /**
@@ -2714,14 +3092,13 @@ public class SatelliteAccessController extends Handler {
 
         this.post(() -> {
             try {
-                synchronized (mSatelliteDisallowedReasonsLock) {
-                    callback.onSatelliteDisallowedReasonsChanged(
-                            mSatelliteDisallowedReasons.stream()
-                                    .mapToInt(Integer::intValue)
-                                    .toArray());
-                    logd("registerForSatelliteDisallowedReasonsChanged: "
-                            + "mSatelliteDisallowedReasons " + mSatelliteDisallowedReasons.size());
-                }
+                List<Integer> satelliteDisallowedReasons = getSatelliteDisallowedReasonsCopy();
+                callback.onSatelliteDisallowedReasonsChanged(
+                        satelliteDisallowedReasons.stream()
+                                .mapToInt(Integer::intValue)
+                                .toArray());
+                logd("registerForSatelliteDisallowedReasonsChanged: "
+                        + "satelliteDisallowedReasons " + satelliteDisallowedReasons.size());
             } catch (RemoteException ex) {
                 ploge("registerForSatelliteDisallowedReasonsChanged: RemoteException ex=" + ex);
             }
@@ -2755,12 +3132,6 @@ public class SatelliteAccessController extends Handler {
      * @return {@code true} if the setting is successful, {@code false} otherwise.
      */
     public boolean setIsSatelliteCommunicationAllowedForCurrentLocationCache(String state) {
-        if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
-            logd("setIsSatelliteCommunicationAllowedForCurrentLocationCache: "
-                    + "oemEnabledSatelliteFlag is disabled");
-            return false;
-        }
-
         if (!isMockModemAllowed()) {
             logd("setIsSatelliteCommunicationAllowedForCurrentLocationCache: "
                     + "mock modem not allowed.");
@@ -2773,15 +3144,15 @@ public class SatelliteAccessController extends Handler {
             if ("cache_allowed".equalsIgnoreCase(state)) {
                 mLatestSatelliteCommunicationAllowedSetTime = getElapsedRealtimeNanos();
                 mLatestSatelliteCommunicationAllowed = true;
-                mCurrentSatelliteAllowedState = true;
+                updateCurrentSatelliteAllowedState(true);
             } else if ("cache_not_allowed".equalsIgnoreCase(state)) {
                 mLatestSatelliteCommunicationAllowedSetTime = getElapsedRealtimeNanos();
                 mLatestSatelliteCommunicationAllowed = false;
-                mCurrentSatelliteAllowedState = false;
+                updateCurrentSatelliteAllowedState(false);
             } else if ("cache_clear_and_not_allowed".equalsIgnoreCase(state)) {
                 mLatestSatelliteCommunicationAllowedSetTime = 0;
                 mLatestSatelliteCommunicationAllowed = false;
-                mCurrentSatelliteAllowedState = false;
+                updateCurrentSatelliteAllowedState(false);
                 persistLatestSatelliteCommunicationAllowedState();
             } else if ("clear_cache_only".equalsIgnoreCase(state)) {
                 mLatestSatelliteCommunicationAllowedSetTime = 0;
@@ -2799,28 +3170,29 @@ public class SatelliteAccessController extends Handler {
     private void notifySatelliteCommunicationAllowedStateChanged(boolean allowState) {
         plogd("notifySatelliteCommunicationAllowedStateChanged: allowState=" + allowState);
 
-        List<ISatelliteCommunicationAllowedStateCallback> deadCallersList = new ArrayList<>();
-        mSatelliteCommunicationAllowedStateChangedListeners.values().forEach(listener -> {
+        List<ISatelliteCommunicationAccessStateCallback> deadCallersList = new ArrayList<>();
+        mSatelliteCommunicationAccessStateChangedListeners.values().forEach(listener -> {
             try {
-                listener.onSatelliteCommunicationAllowedStateChanged(allowState);
+                listener.onAccessAllowedStateChanged(allowState);
             } catch (RemoteException e) {
                 plogd("handleEventNtnSignalStrengthChanged RemoteException: " + e);
                 deadCallersList.add(listener);
             }
         });
         deadCallersList.forEach(listener -> {
-            mSatelliteCommunicationAllowedStateChangedListeners.remove(listener.asBinder());
+            mSatelliteCommunicationAccessStateChangedListeners.remove(listener.asBinder());
         });
     }
 
     private void notifySatelliteDisallowedReasonsChanged() {
         plogd("notifySatelliteDisallowedReasonsChanged");
 
+        List<Integer> satelliteDisallowedReasons = getSatelliteDisallowedReasonsCopy();
         List<ISatelliteDisallowedReasonsCallback> deadCallersList = new ArrayList<>();
         mSatelliteDisallowedReasonsChangedListeners.values().forEach(listener -> {
             try {
                 listener.onSatelliteDisallowedReasonsChanged(
-                        mSatelliteDisallowedReasons.stream()
+                        satelliteDisallowedReasons.stream()
                                 .mapToInt(Integer::intValue)
                                 .toArray());
             } catch (RemoteException e) {
@@ -2838,17 +3210,17 @@ public class SatelliteAccessController extends Handler {
         plogd("notifyRegionalSatelliteConfigurationChanged : satelliteAccessConfig is "
                 + satelliteAccessConfig);
 
-        List<ISatelliteCommunicationAllowedStateCallback> deadCallersList = new ArrayList<>();
-        mSatelliteCommunicationAllowedStateChangedListeners.values().forEach(listener -> {
+        List<ISatelliteCommunicationAccessStateCallback> deadCallersList = new ArrayList<>();
+        mSatelliteCommunicationAccessStateChangedListeners.values().forEach(listener -> {
             try {
-                listener.onSatelliteAccessConfigurationChanged(satelliteAccessConfig);
+                listener.onAccessConfigurationChanged(satelliteAccessConfig);
             } catch (RemoteException e) {
                 plogd("handleEventNtnSignalStrengthChanged RemoteException: " + e);
                 deadCallersList.add(listener);
             }
         });
         deadCallersList.forEach(listener -> {
-            mSatelliteCommunicationAllowedStateChangedListeners.remove(listener.asBinder());
+            mSatelliteCommunicationAccessStateChangedListeners.remove(listener.asBinder());
         });
     }
 
@@ -2859,6 +3231,9 @@ public class SatelliteAccessController extends Handler {
             mControllerMetricsStats.reportFailedSatelliteAccessCheckCount();
         }
 
+        mControllerMetricsStats.reportCurrentVersionOfSatelliteAccessConfig(
+                mSatelliteAccessConfigVersion);
+
         mAccessControllerMetricsStats
                 .setLocationQueryTime(mLocationQueryStartTimeMillis)
                 .setTotalCheckingTime(mTotalCheckingStartTimeMillis)
@@ -2887,32 +3262,19 @@ public class SatelliteAccessController extends Handler {
     }
 
     private static void logd(@NonNull String log) {
-        Rlog.d(TAG, log);
+        Log.d(TAG, log);
     }
 
     private static void logw(@NonNull String log) {
-        Rlog.w(TAG, log);
+        Log.w(TAG, log);
     }
 
     protected static void loge(@NonNull String log) {
-        Rlog.e(TAG, log);
+        Log.e(TAG, log);
     }
 
     private static void logv(@NonNull String log) {
-        Rlog.v(TAG, log);
-    }
-
-    private boolean isSatellitePersistentLoggingEnabled(
-            @NonNull Context context, @NonNull FeatureFlags featureFlags) {
-        if (featureFlags.satellitePersistentLogging()) {
-            return true;
-        }
-        try {
-            return context.getResources().getBoolean(
-                    R.bool.config_dropboxmanager_persistent_logging_enabled);
-        } catch (RuntimeException e) {
-            return false;
-        }
+        Log.v(TAG, log);
     }
 
     /**
@@ -3014,29 +3376,79 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
+    private boolean isReasonPresentInSatelliteDisallowedReasons(int disallowedReason) {
+        synchronized (mSatelliteDisallowedReasonsLock) {
+            return mSatelliteDisallowedReasons.contains(Integer.valueOf(disallowedReason));
+        }
+    }
+
+    private void addReasonToSatelliteDisallowedReasons(int disallowedReason) {
+        synchronized (mSatelliteDisallowedReasonsLock) {
+            mSatelliteDisallowedReasons.add(Integer.valueOf(disallowedReason));
+        }
+    }
+
+    private void removeReasonFromSatelliteDisallowedReasons(int disallowedReason) {
+        synchronized (mSatelliteDisallowedReasonsLock) {
+            mSatelliteDisallowedReasons.remove(Integer.valueOf(disallowedReason));
+        }
+    }
+
+    private boolean isSatelliteDisallowedReasonsEmpty() {
+        synchronized (mSatelliteDisallowedReasonsLock) {
+            return mSatelliteDisallowedReasons.isEmpty();
+        }
+    }
+
+    private void removeAllReasonsFromSatelliteDisallowedReasons(
+            List<Integer> disallowedReasonsList) {
+        synchronized (mSatelliteDisallowedReasonsLock) {
+            mSatelliteDisallowedReasons.removeAll(disallowedReasonsList);
+        }
+    }
+
+    private List<Integer> getSatelliteDisallowedReasonsCopy() {
+        List<Integer> satelliteDisallowedReasons;
+        synchronized (mSatelliteDisallowedReasonsLock) {
+            satelliteDisallowedReasons = new ArrayList<>(mSatelliteDisallowedReasons);
+        }
+        return satelliteDisallowedReasons;
+    }
+
+    /**
+     * Returns the satellite access configuration version.
+     *
+     * If the satellite config data hasn't been updated by configUpdater,
+     * it returns 0. If it has been updated, it returns the updated version information.
+     */
+    @NonNull
+    public int getSatelliteAccessConfigVersion() {
+        return mSatelliteAccessConfigVersion;
+    }
+
     private void plogv(@NonNull String log) {
-        Rlog.v(TAG, log);
+        Log.v(TAG, log);
         if (mPersistentLogger != null) {
             mPersistentLogger.debug(TAG, log);
         }
     }
 
     private void plogd(@NonNull String log) {
-        Rlog.d(TAG, log);
+        Log.d(TAG, log);
         if (mPersistentLogger != null) {
             mPersistentLogger.debug(TAG, log);
         }
     }
 
     private void plogw(@NonNull String log) {
-        Rlog.w(TAG, log);
+        Log.w(TAG, log);
         if (mPersistentLogger != null) {
             mPersistentLogger.warn(TAG, log);
         }
     }
 
     private void ploge(@NonNull String log) {
-        Rlog.e(TAG, log);
+        Log.e(TAG, log);
         if (mPersistentLogger != null) {
             mPersistentLogger.error(TAG, log);
         }
diff --git a/src/com/android/phone/satellite/entitlement/SatelliteEntitlementController.java b/src/com/android/phone/satellite/entitlement/SatelliteEntitlementController.java
index 1f46ff64f..60b57c392 100644
--- a/src/com/android/phone/satellite/entitlement/SatelliteEntitlementController.java
+++ b/src/com/android/phone/satellite/entitlement/SatelliteEntitlementController.java
@@ -37,7 +37,6 @@ import android.telephony.CarrierConfigManager;
 import android.telephony.Rlog;
 import android.telephony.SubscriptionManager;
 
-
 import com.android.internal.annotations.GuardedBy;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telephony.ExponentialBackoff;
@@ -118,10 +117,6 @@ public class SatelliteEntitlementController extends Handler {
      * @param featureFlags The feature flag.
      */
     public static void make(@NonNull Context context, @NonNull FeatureFlags featureFlags) {
-        if (!featureFlags.carrierEnabledSatelliteFlag()) {
-            logd("carrierEnabledSatelliteFlag is disabled. don't created this.");
-            return;
-        }
         if (sInstance == null) {
             HandlerThread handlerThread = new HandlerThread(TAG);
             handlerThread.start();
@@ -253,6 +248,51 @@ public class SatelliteEntitlementController extends Handler {
         sendEmptyMessage(CMD_START_QUERY_ENTITLEMENT);
     }
 
+    private int[] getServiceTypeForEntitlementMetrics(Map<String, List<Integer>> map) {
+        if (map == null || map.isEmpty()) {
+            return new int[]{};
+        }
+
+        return map.entrySet().stream()
+                .findFirst()
+                .map(entry -> {
+                    List<Integer> list = entry.getValue();
+                    if (list == null) {
+                        return new int[]{}; // Return empty array if the list is null
+                    }
+                    return list.stream().mapToInt(Integer::intValue).toArray();
+                })
+                .orElse(new int[]{}); // Return empty array if no entry is found
+    }
+
+    private int getDataPolicyForEntitlementMetrics(Map<String, Integer> dataPolicyMap) {
+        if (dataPolicyMap != null && !dataPolicyMap.isEmpty()) {
+            return dataPolicyMap.values().stream().findFirst()
+                    .orElse(-1);
+        }
+        return -1;
+    }
+
+    private void reportSuccessForEntitlement(int subId, SatelliteEntitlementResult
+            entitlementResult) {
+        // allowed service info entitlement status
+        boolean isAllowedServiceInfo = !entitlementResult
+                .getAvailableServiceTypeInfoForPlmnList().isEmpty();
+
+        int[] serviceType = new int[0];
+        int dataPolicy = 0;
+        if (isAllowedServiceInfo) {
+            serviceType = getServiceTypeForEntitlementMetrics(
+                    entitlementResult.getAvailableServiceTypeInfoForPlmnList());
+            dataPolicy = SatelliteController.getInstance().mapDataPolicyForMetrics(
+                    getDataPolicyForEntitlementMetrics(
+                    entitlementResult.getDataServicePolicyInfoForPlmnList()));
+        }
+        mEntitlementMetricsStats.reportSuccess(subId,
+                getEntitlementStatus(entitlementResult), true, isAllowedServiceInfo,
+                serviceType, dataPolicy);
+    }
+
     /**
      * Check if the device can request to entitlement server (if there is an internet connection and
      * if the throttle time has passed since the last request), and then pass the response to
@@ -273,8 +313,7 @@ public class SatelliteEntitlementController extends Handler {
                     SatelliteEntitlementResult entitlementResult =  getSatelliteEntitlementApi(
                             subId).checkEntitlementStatus();
                     mSatelliteEntitlementResultPerSub.put(subId, entitlementResult);
-                    mEntitlementMetricsStats.reportSuccess(subId,
-                            getEntitlementStatus(entitlementResult), false);
+                    reportSuccessForEntitlement(subId, entitlementResult);
                 }
             } catch (ServiceEntitlementException e) {
                 loge(e.toString());
@@ -341,8 +380,8 @@ public class SatelliteEntitlementController extends Handler {
                 SatelliteEntitlementResult entitlementResult =  getSatelliteEntitlementApi(
                         subId).checkEntitlementStatus();
                 mSatelliteEntitlementResultPerSub.put(subId, entitlementResult);
-                mEntitlementMetricsStats.reportSuccess(subId,
-                        getEntitlementStatus(entitlementResult), true);
+                reportSuccessForEntitlement(subId, entitlementResult);
+
             }
         } catch (ServiceEntitlementException e) {
             loge(e.toString());
diff --git a/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResponse.java b/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResponse.java
index 7d6b5ba50..a9e2f3978 100644
--- a/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResponse.java
+++ b/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResponse.java
@@ -21,7 +21,6 @@ import static com.android.phone.satellite.entitlement.SatelliteEntitlementResult
 import android.text.TextUtils;
 import android.util.Log;
 
-import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telephony.satellite.SatelliteNetworkInfo;
 import com.android.libraries.entitlement.ServiceEntitlement;
 
@@ -135,7 +134,7 @@ public class SatelliteEntitlementResponse {
                 for (int i = 0; i < jsonArray.length(); i++) {
                     String dataPlanType = jsonArray.getJSONObject(i).has(DATA_PLAN_TYPE_KEY)
                             ? jsonArray.getJSONObject(i).getString(DATA_PLAN_TYPE_KEY) : "";
-                    Map<String, String> allowedServicesInfo = new HashMap<>();
+                    Map<String, String> allowedServicesInfo = null;
                     if (jsonArray.getJSONObject(i).has(ALLOWED_SERVICES_INFO_TYPE_KEY)) {
                         allowedServicesInfo = new HashMap<>();
                         JSONArray jsonArray1 = jsonArray.getJSONObject(i)
diff --git a/src/com/android/phone/security/SafetySourceReceiver.java b/src/com/android/phone/security/SafetySourceReceiver.java
index 76f8e72de..835c79b7d 100644
--- a/src/com/android/phone/security/SafetySourceReceiver.java
+++ b/src/com/android/phone/security/SafetySourceReceiver.java
@@ -26,7 +26,6 @@ import android.content.pm.PackageManager;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telephony.Phone;
-import com.android.internal.telephony.flags.Flags;
 import com.android.phone.PhoneGlobals;
 import com.android.telephony.Rlog;
 
@@ -34,14 +33,6 @@ public class SafetySourceReceiver extends BroadcastReceiver {
     private static final String TAG = "TelephonySafetySourceReceiver";
     @Override
     public void onReceive(Context context, Intent intent) {
-
-        // If none of the features that depend on this receiver are enabled, there's no reason
-        // to progress.
-        if (!Flags.enableIdentifierDisclosureTransparencyUnsolEvents()
-                || !Flags.enableModemCipherTransparencyUnsolEvents()) {
-            return;
-        }
-
         String action = intent.getAction();
         if (!ACTION_REFRESH_SAFETY_SOURCES.equals(action)) {
             return;
@@ -53,11 +44,7 @@ public class SafetySourceReceiver extends BroadcastReceiver {
             return;
         }
 
-        if (Flags.enforceTelephonyFeatureMappingForPublicApis()) {
-            if (context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY)) {
-                refreshSafetySources(refreshBroadcastId);
-            }
-        } else {
+        if (context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY)) {
             refreshSafetySources(refreshBroadcastId);
         }
     }
diff --git a/src/com/android/phone/settings/AccessibilitySettingsActivity.java b/src/com/android/phone/settings/AccessibilitySettingsActivity.java
index 7cc18f6be..7d193afe6 100644
--- a/src/com/android/phone/settings/AccessibilitySettingsActivity.java
+++ b/src/com/android/phone/settings/AccessibilitySettingsActivity.java
@@ -36,6 +36,8 @@ public class AccessibilitySettingsActivity extends PreferenceActivity {
         if (actionBar != null) {
             actionBar.setTitle(R.string.accessibility_settings_activity_title);
         }
+        SettingsConstants.setupEdgeToEdge(this);
+
         getFragmentManager().beginTransaction().replace(
                 android.R.id.content, new AccessibilitySettingsFragment()).commit();
     }
diff --git a/src/com/android/phone/settings/PhoneAccountSettingsActivity.java b/src/com/android/phone/settings/PhoneAccountSettingsActivity.java
index 5617a0bf1..c753fe188 100644
--- a/src/com/android/phone/settings/PhoneAccountSettingsActivity.java
+++ b/src/com/android/phone/settings/PhoneAccountSettingsActivity.java
@@ -63,6 +63,8 @@ public class PhoneAccountSettingsActivity extends PreferenceActivity {
         }
         getFragmentManager().beginTransaction().replace(
                 android.R.id.content, new PhoneAccountSettingsFragment()).commit();
+
+        SettingsConstants.setupEdgeToEdge(this);
     }
 
     @Override
diff --git a/src/com/android/phone/settings/PhoneAccountSettingsFragment.java b/src/com/android/phone/settings/PhoneAccountSettingsFragment.java
index 976afd4df..a9161a5d0 100644
--- a/src/com/android/phone/settings/PhoneAccountSettingsFragment.java
+++ b/src/com/android/phone/settings/PhoneAccountSettingsFragment.java
@@ -109,6 +109,7 @@ public class PhoneAccountSettingsFragment extends PreferenceFragment
         }
 
         addPreferencesFromResource(R.xml.phone_account_settings);
+        getView().setFitsSystemWindows(true);
 
         /**
          * Here we make decisions about what we will and will not display with regards to phone-
diff --git a/src/com/android/phone/settings/RadioInfo.java b/src/com/android/phone/settings/RadioInfo.java
index 4a5029613..65de1bccc 100644
--- a/src/com/android/phone/settings/RadioInfo.java
+++ b/src/com/android/phone/settings/RadioInfo.java
@@ -17,10 +17,23 @@
 package com.android.phone.settings;
 
 import static android.net.ConnectivityManager.NetworkCallback;
+import static android.telephony.CarrierConfigManager.KEY_CARRIER_ROAMING_SATELLITE_DEFAULT_SERVICES_INT_ARRAY;
+import static android.telephony.CarrierConfigManager.KEY_CARRIER_SUPPORTED_SATELLITE_SERVICES_PER_PROVIDER_BUNDLE;
+import static android.telephony.CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL;
+import static android.telephony.CarrierConfigManager.KEY_SATELLITE_DATA_SUPPORT_MODE_INT;
+import static android.telephony.CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL;
+import static android.telephony.ims.feature.MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VIDEO;
+import static android.telephony.ims.feature.MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VOICE;
+import static android.telephony.ims.stub.ImsRegistrationImplBase.REGISTRATION_TECH_3G;
+import static android.telephony.ims.stub.ImsRegistrationImplBase.REGISTRATION_TECH_CROSS_SIM;
+import static android.telephony.ims.stub.ImsRegistrationImplBase.REGISTRATION_TECH_IWLAN;
+import static android.telephony.ims.stub.ImsRegistrationImplBase.REGISTRATION_TECH_LTE;
+import static android.telephony.ims.stub.ImsRegistrationImplBase.REGISTRATION_TECH_NR;
 
 import static java.util.concurrent.TimeUnit.MILLISECONDS;
 
 import android.annotation.NonNull;
+import android.content.ActivityNotFoundException;
 import android.content.ComponentName;
 import android.content.DialogInterface;
 import android.content.Intent;
@@ -84,7 +97,6 @@ import android.telephony.ims.ImsMmTelManager;
 import android.telephony.ims.ImsRcsManager;
 import android.telephony.ims.ProvisioningManager;
 import android.telephony.ims.feature.MmTelFeature;
-import android.telephony.ims.stub.ImsRegistrationImplBase;
 import android.telephony.satellite.SatelliteManager;
 import android.text.TextUtils;
 import android.util.Log;
@@ -98,6 +110,7 @@ import android.widget.Button;
 import android.widget.CompoundButton;
 import android.widget.CompoundButton.OnCheckedChangeListener;
 import android.widget.EditText;
+import android.widget.RadioGroup;
 import android.widget.Spinner;
 import android.widget.Switch;
 import android.widget.TextView;
@@ -110,6 +123,7 @@ import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneFactory;
 import com.android.internal.telephony.RILConstants;
 import com.android.internal.telephony.euicc.EuiccConnector;
+import com.android.internal.telephony.satellite.SatelliteServiceUtils;
 import com.android.phone.R;
 
 import java.io.IOException;
@@ -120,6 +134,8 @@ import java.util.Arrays;
 import java.util.Collections;
 import java.util.List;
 import java.util.Locale;
+import java.util.Map;
+import java.util.Set;
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.ExecutionException;
@@ -206,8 +222,7 @@ public class RadioInfo extends AppCompatActivity {
             ServiceState.RIL_RADIO_TECHNOLOGY_GSM,
             ServiceState.RIL_RADIO_TECHNOLOGY_TD_SCDMA,
             ServiceState.RIL_RADIO_TECHNOLOGY_LTE_CA,
-            ServiceState.RIL_RADIO_TECHNOLOGY_NR,
-            ServiceState.RIL_RADIO_TECHNOLOGY_NB_IOT_NTN
+            ServiceState.RIL_RADIO_TECHNOLOGY_NR
     };
     private static String[] sPhoneIndexLabels = new String[0];
 
@@ -309,6 +324,8 @@ public class RadioInfo extends AppCompatActivity {
     private Switch mSimulateOutOfServiceSwitch;
     private Switch mEnforceSatelliteChannel;
     private Switch mMockSatellite;
+    private Switch mMockSatelliteDataSwitch;
+    private RadioGroup mMockSatelliteData;
     private Button mPingTestButton;
     private Button mUpdateSmscButton;
     private Button mRefreshSmscButton;
@@ -318,6 +335,7 @@ public class RadioInfo extends AppCompatActivity {
     private Button mEsosButton;
     private Button mSatelliteEnableNonEmergencyModeButton;
     private Button mEsosDemoButton;
+    private Button mSatelliteConfigViewerButton;
     private Switch mImsVolteProvisionedSwitch;
     private Switch mImsVtProvisionedSwitch;
     private Switch mImsWfcProvisionedSwitch;
@@ -352,6 +370,7 @@ public class RadioInfo extends AppCompatActivity {
     private boolean mSystemUser = true;
 
     private final PersistableBundle[] mCarrierSatelliteOriginalBundle = new PersistableBundle[2];
+    private final PersistableBundle[] mSatelliteDataOriginalBundle = new PersistableBundle[2];
     private final PersistableBundle[] mOriginalSystemChannels = new PersistableBundle[2];
     private List<CellInfo> mCellInfoResult = null;
     private final boolean[] mSimulateOos = new boolean[2];
@@ -370,6 +389,7 @@ public class RadioInfo extends AppCompatActivity {
     private String mActionEsosDemo;
     private Intent mNonEsosIntent;
     private TelephonyDisplayInfo mDisplayInfo;
+    private CarrierConfigManager mCarrierConfigManager;
 
     private List<PhysicalChannelConfig> mPhysicalChannelConfigs = new ArrayList<>();
 
@@ -557,6 +577,7 @@ public class RadioInfo extends AppCompatActivity {
     @Override
     public void onCreate(Bundle icicle) {
         super.onCreate(icicle);
+        SettingsConstants.setupEdgeToEdge(this);
         mSystemUser = android.os.Process.myUserHandle().isSystem();
         log("onCreate: mSystemUser=" + mSystemUser);
         UserManager userManager = getSystemService(UserManager.class);
@@ -742,11 +763,14 @@ public class RadioInfo extends AppCompatActivity {
         if (!Build.isDebuggable()) {
             mSimulateOutOfServiceSwitch.setVisibility(View.GONE);
         }
-
         mMockSatellite = (Switch) findViewById(R.id.mock_carrier_roaming_satellite);
+        mMockSatelliteDataSwitch = (Switch) findViewById(R.id.satellite_data_controller_switch);
+        mMockSatelliteData = findViewById(R.id.satellite_data_controller);
         mEnforceSatelliteChannel = (Switch) findViewById(R.id.enforce_satellite_channel);
         if (!Build.isDebuggable()) {
             mMockSatellite.setVisibility(View.GONE);
+            mMockSatelliteDataSwitch.setVisibility(View.GONE);
+            mMockSatelliteData.setVisibility(View.GONE);
             mEnforceSatelliteChannel.setVisibility(View.GONE);
         }
 
@@ -786,6 +810,7 @@ public class RadioInfo extends AppCompatActivity {
         mEsosDemoButton  = (Button) findViewById(R.id.demo_esos_questionnaire);
         mSatelliteEnableNonEmergencyModeButton = (Button) findViewById(
                 R.id.satellite_enable_non_emergency_mode);
+        mSatelliteConfigViewerButton = (Button) findViewById(R.id.satellite_config_viewer);
 
         if (shouldHideButton(mActionEsos)) {
             mEsosButton.setVisibility(View.GONE);
@@ -815,6 +840,14 @@ public class RadioInfo extends AppCompatActivity {
             });
         }
 
+        mSatelliteConfigViewerButton.setOnClickListener(v -> {
+            Intent intent = new Intent(Intent.ACTION_VIEW);
+            intent.putExtra("mSubId", mSubId);
+            intent.setClassName("com.android.phone",
+                    "com.android.phone.settings.SatelliteConfigViewer");
+            startActivityAsUser(intent, UserHandle.CURRENT);
+        });
+
         mOemInfoButton = (Button) findViewById(R.id.oem_info);
         mOemInfoButton.setOnClickListener(mOemInfoButtonHandler);
         PackageManager pm = getPackageManager();
@@ -832,7 +865,6 @@ public class RadioInfo extends AppCompatActivity {
             runOnUiThread(() -> updatePreferredNetworkType(
                     RadioAccessFamily.getNetworkTypeFromRaf(networkType)));
         }).start();
-
         restoreFromBundle(icicle);
     }
 
@@ -923,6 +955,10 @@ public class RadioInfo extends AppCompatActivity {
         mSimulateOutOfServiceSwitch.setOnCheckedChangeListener(mSimulateOosOnChangeListener);
         mMockSatellite.setChecked(mCarrierSatelliteOriginalBundle[mPhoneId] != null);
         mMockSatellite.setOnCheckedChangeListener(mMockSatelliteListener);
+        mMockSatelliteDataSwitch.setChecked(mSatelliteDataOriginalBundle[mPhoneId] != null);
+        mMockSatelliteDataSwitch.setOnCheckedChangeListener(mMockSatelliteDataSwitchListener);
+        mMockSatelliteData.setOnCheckedChangeListener(mMockSatelliteDataListener);
+
         updateSatelliteChannelDisplay(mPhoneId);
         mEnforceSatelliteChannel.setOnCheckedChangeListener(mForceSatelliteChannelOnChangeListener);
         mImsVolteProvisionedSwitch.setOnCheckedChangeListener(mImsVolteCheckedChangeListener);
@@ -939,7 +975,6 @@ public class RadioInfo extends AppCompatActivity {
         registerPhoneStateListener();
         mConnectivityManager.registerNetworkCallback(
                 mDefaultNetworkRequest, mNetworkCallback, mHandler);
-
         mSmsc.clearFocus();
     }
 
@@ -1053,6 +1088,10 @@ public class RadioInfo extends AppCompatActivity {
             if (mCarrierSatelliteOriginalBundle[mPhoneId] != null) {
                 mMockSatelliteListener.onCheckedChanged(mMockSatellite, false);
             }
+            if (mSatelliteDataOriginalBundle[mPhoneId] != null) {
+                mMockSatelliteDataSwitchListener.onCheckedChanged(mMockSatelliteDataSwitch, false);
+                mSatelliteDataOriginalBundle[mPhoneId] = null;
+            }
             if (mSelectedSignalStrengthIndex[mPhoneId] > 0) {
                 mOnMockSignalStrengthSelectedListener.onItemSelected(null, null, 0/*pos*/, 0);
             }
@@ -1751,14 +1790,16 @@ public class RadioInfo extends AppCompatActivity {
                 public boolean onMenuItemClick(MenuItem item) {
                     boolean isSimValid = SubscriptionManager.isValidSubscriptionId(mSubId);
                     boolean isImsRegistered = isSimValid && mTelephonyManager.isImsRegistered();
-                    boolean availableVolte = isSimValid && mTelephonyManager.isVolteAvailable();
-                    boolean availableWfc = isSimValid && mTelephonyManager.isWifiCallingAvailable();
-                    boolean availableVt =
-                            isSimValid && mTelephonyManager.isVideoTelephonyAvailable();
+                    boolean availableVolte = false;
+                    boolean availableWfc = false;
+                    boolean availableVt = false;
                     AtomicBoolean availableUt = new AtomicBoolean(false);
 
                     if (isSimValid) {
                         ImsMmTelManager imsMmTelManager = mImsManager.getImsMmTelManager(mSubId);
+                        availableVolte = isVoiceServiceAvailable(imsMmTelManager);
+                        availableVt = isVideoServiceAvailable(imsMmTelManager);
+                        availableWfc = isWfcServiceAvailable(imsMmTelManager);
                         CountDownLatch latch = new CountDownLatch(1);
                         try {
                             HandlerThread handlerThread = new HandlerThread("RadioInfo");
@@ -1793,7 +1834,7 @@ public class RadioInfo extends AppCompatActivity {
                             availableVt ? available : unavailable,
                             availableUt.get() ? available : unavailable);
 
-                    AlertDialog imsDialog = new AlertDialog.Builder(RadioInfo.this)
+                    AlertDialog imsDialog = new  AlertDialog.Builder(RadioInfo.this)
                             .setMessage(imsStatus)
                             .setTitle(getString(R.string.radio_info_ims_reg_status_title))
                             .create();
@@ -1837,26 +1878,26 @@ public class RadioInfo extends AppCompatActivity {
 
     private void setImsVolteProvisionedState(boolean state) {
         Log.d(TAG, "setImsVolteProvisioned state: " + ((state) ? "on" : "off"));
-        setImsConfigProvisionedState(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VOICE,
-                ImsRegistrationImplBase.REGISTRATION_TECH_LTE, state);
+        setImsConfigProvisionedState(CAPABILITY_TYPE_VOICE,
+                REGISTRATION_TECH_LTE, state);
     }
 
     private void setImsVtProvisionedState(boolean state) {
         Log.d(TAG, "setImsVtProvisioned() state: " + ((state) ? "on" : "off"));
-        setImsConfigProvisionedState(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VIDEO,
-                ImsRegistrationImplBase.REGISTRATION_TECH_LTE, state);
+        setImsConfigProvisionedState(CAPABILITY_TYPE_VIDEO,
+                REGISTRATION_TECH_LTE, state);
     }
 
     private void setImsWfcProvisionedState(boolean state) {
         Log.d(TAG, "setImsWfcProvisioned() state: " + ((state) ? "on" : "off"));
-        setImsConfigProvisionedState(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VOICE,
-                ImsRegistrationImplBase.REGISTRATION_TECH_IWLAN, state);
+        setImsConfigProvisionedState(CAPABILITY_TYPE_VOICE,
+                REGISTRATION_TECH_IWLAN, state);
     }
 
     private void setEabProvisionedState(boolean state) {
         Log.d(TAG, "setEabProvisioned() state: " + ((state) ? "on" : "off"));
         setRcsConfigProvisionedState(ImsRcsManager.CAPABILITY_TYPE_PRESENCE_UCE,
-                ImsRegistrationImplBase.REGISTRATION_TECH_LTE, state);
+                REGISTRATION_TECH_LTE, state);
     }
 
     private void setImsConfigProvisionedState(int capability, int tech, boolean state) {
@@ -1891,26 +1932,26 @@ public class RadioInfo extends AppCompatActivity {
 
     private boolean isImsVolteProvisioningRequired() {
         return isImsConfigProvisioningRequired(
-                MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VOICE,
-                ImsRegistrationImplBase.REGISTRATION_TECH_LTE);
+                CAPABILITY_TYPE_VOICE,
+                REGISTRATION_TECH_LTE);
     }
 
     private boolean isImsVtProvisioningRequired() {
         return isImsConfigProvisioningRequired(
-                MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VIDEO,
-                ImsRegistrationImplBase.REGISTRATION_TECH_LTE);
+                CAPABILITY_TYPE_VIDEO,
+                REGISTRATION_TECH_LTE);
     }
 
     private boolean isImsWfcProvisioningRequired() {
         return isImsConfigProvisioningRequired(
-                MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VOICE,
-                ImsRegistrationImplBase.REGISTRATION_TECH_IWLAN);
+                CAPABILITY_TYPE_VOICE,
+                REGISTRATION_TECH_IWLAN);
     }
 
     private boolean isEabProvisioningRequired() {
         return isRcsConfigProvisioningRequired(
                 ImsRcsManager.CAPABILITY_TYPE_PRESENCE_UCE,
-                ImsRegistrationImplBase.REGISTRATION_TECH_LTE);
+                REGISTRATION_TECH_LTE);
     }
 
     private boolean isImsConfigProvisioningRequired(int capability, int tech) {
@@ -1974,12 +2015,12 @@ public class RadioInfo extends AppCompatActivity {
     private static final int SATELLITE_CHANNEL = 8665;
     private final OnCheckedChangeListener mForceSatelliteChannelOnChangeListener =
             (buttonView, isChecked) -> {
-                if (!SubscriptionManager.isValidSubscriptionId(mSubId)) {
+
+                if (!isValidSubscription(mSubId)) {
                     loge("Force satellite channel invalid subId " + mSubId);
                     return;
                 }
-                CarrierConfigManager cm = getSystemService(CarrierConfigManager.class);
-                if (cm == null) {
+                if (getCarrierConfig() == null) {
                     loge("Force satellite channel cm == null");
                     return;
                 }
@@ -1990,16 +2031,16 @@ public class RadioInfo extends AppCompatActivity {
                 if (isChecked) {
                     (new Thread(() -> {
                         // Override carrier config
-                        PersistableBundle originalBundle = cm.getConfigForSubId(subId,
-                                CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL,
-                                CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL,
+                        PersistableBundle originalBundle = getCarrierConfig().getConfigForSubId(
+                                subId,
+                                KEY_SATELLITE_ATTACH_SUPPORTED_BOOL,
+                                KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL,
                                 CarrierConfigManager.KEY_EMERGENCY_MESSAGING_SUPPORTED_BOOL
                         );
                         PersistableBundle overrideBundle = new PersistableBundle();
                         overrideBundle.putBoolean(
-                                CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL, true);
-                        overrideBundle.putBoolean(CarrierConfigManager
-                                .KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL, true);
+                                KEY_SATELLITE_ATTACH_SUPPORTED_BOOL, true);
+                        overrideBundle.putBoolean(KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL, true);
                         overrideBundle.putBoolean(CarrierConfigManager
                                 .KEY_EMERGENCY_MESSAGING_SUPPORTED_BOOL, true);
 
@@ -2029,7 +2070,7 @@ public class RadioInfo extends AppCompatActivity {
                             return;
                         }
                         log("Force satellite channel new config " + overrideBundle);
-                        cm.overrideConfig(subId, overrideBundle, false);
+                        getCarrierConfig().overrideConfig(subId, overrideBundle, false);
 
                         mOriginalSystemChannels[phoneId] = originalBundle;
                         log("Force satellite channel old " + mock  + originalBundle);
@@ -2047,7 +2088,7 @@ public class RadioInfo extends AppCompatActivity {
                                     + TelephonyManager.getAllNetworkTypesBitmask());
                             PersistableBundle original = mOriginalSystemChannels[phoneId];
                             if (original != null) {
-                                cm.overrideConfig(subId, original, false);
+                                getCarrierConfig().overrideConfig(subId, original, false);
                                 log("Force satellite channel successfully restored config to "
                                         + original);
                                 mOriginalSystemChannels[phoneId] = null;
@@ -2090,61 +2131,254 @@ public class RadioInfo extends AppCompatActivity {
         })).start();
     }
 
+    /**
+     * Method will create the PersistableBundle and pack the satellite services like
+     * SMS, MMS, EMERGENCY CALL, DATA in it.
+     *
+     * @return PersistableBundle
+     */
+    public PersistableBundle getSatelliteServicesBundleForOperatorPlmn(
+            PersistableBundle originalBundle) {
+        String plmn = mTelephonyManager.getNetworkOperatorForPhone(mPhoneId);
+        if (TextUtils.isEmpty(plmn)) {
+            loge("satData: NetworkOperator PLMN is empty");
+            plmn = mTelephonyManager.getSimOperatorNumeric(mSubId);
+            loge("satData: SimOperator PLMN = " + plmn);
+        }
+        int[] supportedServicesArray = {NetworkRegistrationInfo.SERVICE_TYPE_DATA,
+                NetworkRegistrationInfo.SERVICE_TYPE_SMS,
+                NetworkRegistrationInfo.SERVICE_TYPE_EMERGENCY,
+                NetworkRegistrationInfo.SERVICE_TYPE_MMS};
+
+        PersistableBundle satServicesPerBundle = originalBundle.getPersistableBundle(
+                KEY_CARRIER_SUPPORTED_SATELLITE_SERVICES_PER_PROVIDER_BUNDLE);
+        // New bundle is required, as existed one will throw `ArrayMap is immutable` when we try
+        // to modify.
+        PersistableBundle newSatServicesPerBundle = new PersistableBundle();
+        //Copy the values from the old bundle into the new bundle.
+        boolean hasPlmnKey = false;
+        if (satServicesPerBundle != null) {
+            for (String key : satServicesPerBundle.keySet()) {
+                if (!TextUtils.isEmpty(key) && key.equalsIgnoreCase(plmn)) {
+                    newSatServicesPerBundle.putIntArray(plmn, supportedServicesArray);
+                    hasPlmnKey = true;
+                } else {
+                    newSatServicesPerBundle.putIntArray(key, satServicesPerBundle.getIntArray(key));
+                }
+            }
+        }
+        if (!hasPlmnKey) {
+            newSatServicesPerBundle.putIntArray(plmn, supportedServicesArray);
+        }
+        log("satData: New SatelliteServicesBundle = " + newSatServicesPerBundle);
+        return newSatServicesPerBundle;
+    }
+
+    /**
+     * This method will check the required carrier config keys which plays role in enabling /
+     * supporting satellite data and update the keys accordingly.
+     * @param bundleToModify : PersistableBundle
+     */
+    private void updateCarrierConfigToSupportData(PersistableBundle bundleToModify) {
+        // KEY_CARRIER_ROAMING_SATELLITE_DEFAULT_SERVICES_INT_ARRAY key info update
+        int[] availableServices = bundleToModify.getIntArray(
+                KEY_CARRIER_ROAMING_SATELLITE_DEFAULT_SERVICES_INT_ARRAY);
+        int[] newServices;
+        if (availableServices != null && availableServices.length > 0) {
+            if (Arrays.stream(availableServices).anyMatch(
+                    element -> element == NetworkRegistrationInfo.SERVICE_TYPE_DATA)) {
+                newServices = new int[availableServices.length];
+                System.arraycopy(availableServices, 0, newServices, 0, availableServices.length);
+            } else {
+                newServices = new int[availableServices.length + 1];
+                System.arraycopy(availableServices, 0, newServices, 0, availableServices.length);
+                newServices[newServices.length - 1] = NetworkRegistrationInfo.SERVICE_TYPE_DATA;
+            }
+        } else {
+            newServices = new int[1];
+            newServices[0] = NetworkRegistrationInfo.SERVICE_TYPE_DATA;
+        }
+        bundleToModify.putIntArray(KEY_CARRIER_ROAMING_SATELLITE_DEFAULT_SERVICES_INT_ARRAY,
+                newServices);
+        // KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL setting to false.
+        bundleToModify.putBoolean(KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL, false);
+        // Below one not required to update as we are not changing this value.
+        bundleToModify.remove(KEY_SATELLITE_DATA_SUPPORT_MODE_INT);
+        log("satData: changing carrierConfig to : " + bundleToModify);
+        getCarrierConfig().overrideConfig(mSubId, bundleToModify, false);
+    }
+
+    /**
+     * Method that restore the previous satellite data mode selection.
+     */
+    private void updateSatelliteDataButton() {
+        if (mSatelliteDataOriginalBundle[mPhoneId] == null) {
+            // It executes only at first time
+            PersistableBundle originalBundle = getCarrierConfig().getConfigForSubId(mSubId,
+                    KEY_SATELLITE_DATA_SUPPORT_MODE_INT,
+                    KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL,
+                    KEY_CARRIER_ROAMING_SATELLITE_DEFAULT_SERVICES_INT_ARRAY,
+                    KEY_CARRIER_SUPPORTED_SATELLITE_SERVICES_PER_PROVIDER_BUNDLE);
+            mSatelliteDataOriginalBundle[mPhoneId] = originalBundle;
+            log("satData: OriginalConfig = " + originalBundle);
+        }
+        PersistableBundle currentBundle = getCarrierConfig().getConfigForSubId(mSubId,
+                KEY_SATELLITE_DATA_SUPPORT_MODE_INT,
+                KEY_CARRIER_ROAMING_SATELLITE_DEFAULT_SERVICES_INT_ARRAY,
+                KEY_CARRIER_SUPPORTED_SATELLITE_SERVICES_PER_PROVIDER_BUNDLE);
+        int dataMode = currentBundle.getInt(
+                KEY_SATELLITE_DATA_SUPPORT_MODE_INT, -1);
+        log("satData: present dataMode = " + dataMode);
+        if (dataMode != -1) {
+            int checkedId = 0;
+            switch (dataMode) {
+                case CarrierConfigManager.SATELLITE_DATA_SUPPORT_ONLY_RESTRICTED:
+                    checkedId = R.id.satellite_data_restricted;
+                    break;
+                case CarrierConfigManager.SATELLITE_DATA_SUPPORT_BANDWIDTH_CONSTRAINED:
+                    checkedId = R.id.satellite_data_constrained;
+                    break;
+                case CarrierConfigManager.SATELLITE_DATA_SUPPORT_ALL:
+                    checkedId = R.id.satellite_data_unConstrained;
+                    break;
+            }
+            mMockSatelliteData.check(checkedId);
+        }
+        updateCarrierConfigToSupportData(currentBundle);
+    }
+
+    private final RadioGroup.OnCheckedChangeListener mMockSatelliteDataListener =
+            (group, checkedId) -> {
+                int dataMode = CarrierConfigManager.SATELLITE_DATA_SUPPORT_ONLY_RESTRICTED;
+                switch (checkedId) {
+                    case R.id.satellite_data_restricted:
+                        dataMode = CarrierConfigManager.SATELLITE_DATA_SUPPORT_ONLY_RESTRICTED;
+                        break;
+                    case R.id.satellite_data_constrained:
+                        dataMode =
+                                CarrierConfigManager.SATELLITE_DATA_SUPPORT_BANDWIDTH_CONSTRAINED;
+                        break;
+                    case R.id.satellite_data_unConstrained:
+                        dataMode = CarrierConfigManager.SATELLITE_DATA_SUPPORT_ALL;
+                        break;
+                }
+                log("satData: OnCheckedChangeListener setting dataMode = " + dataMode);
+                if (getCarrierConfig() == null) return;
+                PersistableBundle overrideBundle = new PersistableBundle();
+                overrideBundle.putInt(KEY_SATELLITE_DATA_SUPPORT_MODE_INT, dataMode);
+                overrideBundle.putBoolean(KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL, false);
+                if (isValidSubscription(mSubId)) {
+                    getCarrierConfig().overrideConfig(mSubId, overrideBundle, false);
+                    log("satData: mMockSatelliteDataListener: Updated new config" + overrideBundle);
+                }
+            };
+
+    private final OnCheckedChangeListener mMockSatelliteDataSwitchListener =
+            (buttonView, isChecked) -> {
+        log("satData: ServiceData enabling = " + isChecked);
+        if (isChecked) {
+            if (isValidOperator(mSubId)) {
+                updateSatelliteDataButton();
+            } else {
+                log("satData: Not a valid Operator");
+                mMockSatelliteDataSwitch.setChecked(false);
+                return;
+            }
+        } else {
+            reloadCarrierConfigDefaults();
+        }
+        setDataModeChangeVisibility(isChecked);
+    };
+
+    private void setDataModeChangeVisibility(boolean isChecked) {
+        if (isChecked) {
+            mMockSatelliteData.setVisibility(View.VISIBLE);
+        } else {
+            mMockSatelliteData.setVisibility(View.GONE);
+        }
+    }
+
+    private void reloadCarrierConfigDefaults() {
+        if (mSatelliteDataOriginalBundle[mPhoneId] != null) {
+            log("satData: Setting originalCarrierConfig = "
+                    + mSatelliteDataOriginalBundle[mPhoneId]);
+            getCarrierConfig().overrideConfig(mSubId, mSatelliteDataOriginalBundle[mPhoneId],
+                    false);
+            mSatelliteDataOriginalBundle[mPhoneId] = null;
+        }
+    }
+
+    private boolean isValidOperator(int subId) {
+        String operatorNumeric = null;
+        if (isValidSubscription(subId)) {
+            operatorNumeric = mTelephonyManager.getNetworkOperatorForPhone(mPhoneId);
+            TelephonyManager tm;
+            if (TextUtils.isEmpty(operatorNumeric) && (tm = getSystemService(
+                    TelephonyManager.class)) != null) {
+                operatorNumeric = tm.getSimOperatorNumericForPhone(mPhoneId);
+            }
+        }
+        return !TextUtils.isEmpty(operatorNumeric);
+    }
+
+    /**
+     * This method will do extra check to validate the subId.
+     * <p>
+     * In case user opens the radioInfo when sim is active and enable some checks and go to the
+     * SIM settings screen and disabled the screen. Upon return to radioInfo screen subId is still
+     * valid but not in active state any more.
+     */
+    private boolean isValidSubscription(int subId) {
+        boolean isValidSubId = false;
+        if (SubscriptionManager.isValidSubscriptionId(subId)) {
+            SubscriptionManager mSm = getSystemService(SubscriptionManager.class);
+            isValidSubId = mSm.isActiveSubscriptionId(subId);
+        }
+        log("isValidSubscription, subId [ " + subId + " ] = " + isValidSubId);
+        return isValidSubId;
+    }
+
     private final OnCheckedChangeListener mMockSatelliteListener =
             (buttonView, isChecked) -> {
-                if (SubscriptionManager.isValidPhoneId(mPhoneId)) {
-                    CarrierConfigManager cm = getSystemService(CarrierConfigManager.class);
-                    if (cm == null) return;
+                int subId = mSubId;
+                int phoneId = mPhoneId;
+                if (SubscriptionManager.isValidPhoneId(phoneId) && isValidSubscription(subId)) {
+                    if (getCarrierConfig() == null) return;
                     if (isChecked) {
-                        String operatorNumeric = mTelephonyManager
-                                .getNetworkOperatorForPhone(mPhoneId);
-                        TelephonyManager tm;
-                        if (TextUtils.isEmpty(operatorNumeric)
-                                && (tm = getSystemService(TelephonyManager.class)) != null) {
-                            operatorNumeric = tm.getSimOperatorNumericForPhone(mPhoneId);
-                        }
-                        if (TextUtils.isEmpty(operatorNumeric)) {
-                            loge("mMockSatelliteListener: Can't mock because no operator for phone "
-                                    + mPhoneId);
+                        if (!isValidOperator(subId)) {
                             mMockSatellite.setChecked(false);
+                            loge("mMockSatelliteListener: Can't mock because no operator for phone "
+                                    + phoneId);
                             return;
                         }
-                        PersistableBundle originalBundle = cm.getConfigForSubId(mSubId,
-                                CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL,
-                                CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL,
-                                CarrierConfigManager
-                                        .KEY_CARRIER_SUPPORTED_SATELLITE_SERVICES_PER_PROVIDER_BUNDLE
-                        );
+                        PersistableBundle originalBundle = getCarrierConfig().getConfigForSubId(
+                                subId, KEY_SATELLITE_ATTACH_SUPPORTED_BOOL,
+                                KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL,
+                                KEY_CARRIER_SUPPORTED_SATELLITE_SERVICES_PER_PROVIDER_BUNDLE);
+                        mCarrierSatelliteOriginalBundle[phoneId] = originalBundle;
+
                         PersistableBundle overrideBundle = new PersistableBundle();
-                        overrideBundle.putBoolean(
-                                CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL, true);
-                        overrideBundle.putBoolean(CarrierConfigManager
-                                .KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL, false);
-                        PersistableBundle capableProviderBundle = new PersistableBundle();
-                        capableProviderBundle.putIntArray(mTelephonyManager
-                                        .getNetworkOperatorForPhone(mPhoneId),
-                                new int[]{
-                                        // Currently satellite only supports below
-                                        NetworkRegistrationInfo.SERVICE_TYPE_SMS,
-                                        NetworkRegistrationInfo.SERVICE_TYPE_EMERGENCY
-                        });
-                        overrideBundle.putPersistableBundle(CarrierConfigManager
-                                .KEY_CARRIER_SUPPORTED_SATELLITE_SERVICES_PER_PROVIDER_BUNDLE,
-                                capableProviderBundle);
-                        log("mMockSatelliteListener: new " + overrideBundle);
+                        overrideBundle.putBoolean(KEY_SATELLITE_ATTACH_SUPPORTED_BOOL, true);
+                        // NOTE: In case of TMO setting KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL
+                        // to false will result in SIM Settings not to show few items, which is
+                        // expected.
+                        overrideBundle.putBoolean(KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL, false);
+                        overrideBundle.putPersistableBundle(
+                                KEY_CARRIER_SUPPORTED_SATELLITE_SERVICES_PER_PROVIDER_BUNDLE,
+                                getSatelliteServicesBundleForOperatorPlmn(originalBundle));
                         log("mMockSatelliteListener: old " + originalBundle);
-                        cm.overrideConfig(mSubId, overrideBundle, false);
-                        mCarrierSatelliteOriginalBundle[mPhoneId] = originalBundle;
+                        log("mMockSatelliteListener: new " + overrideBundle);
+                        getCarrierConfig().overrideConfig(subId, overrideBundle, false);
                     } else {
                         try {
-                            cm.overrideConfig(mSubId,
-                                    mCarrierSatelliteOriginalBundle[mPhoneId], false);
-                            mCarrierSatelliteOriginalBundle[mPhoneId] = null;
+                            getCarrierConfig().overrideConfig(subId,
+                                    mCarrierSatelliteOriginalBundle[phoneId], false);
+                            mCarrierSatelliteOriginalBundle[phoneId] = null;
                             log("mMockSatelliteListener: Successfully cleared mock for phone "
-                                    + mPhoneId);
+                                    + phoneId);
                         } catch (Exception e) {
                             loge("mMockSatelliteListener: Can't clear mock because invalid sub Id "
-                                    + mSubId
+                                    + subId
                                     + ", insert SIM and use adb shell cmd phone cc clear-values");
                             // Keep show toggle ON if the view is not destroyed. If destroyed, must
                             // use cmd to reset, because upon creation the view doesn't remember the
@@ -2166,13 +2400,12 @@ public class RadioInfo extends AppCompatActivity {
         if (mNonEsosIntent != null) {
             mNonEsosIntent = null;
         }
-        CarrierConfigManager cm = getSystemService(CarrierConfigManager.class);
-        if (cm == null) {
+        if (getCarrierConfig() == null) {
             loge("shouldHideNonEmergencyMode: cm is null");
             return true;
         }
-        PersistableBundle bundle = cm.getConfigForSubId(mSubId,
-                CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL,
+        PersistableBundle bundle = getCarrierConfig().getConfigForSubId(mSubId,
+                KEY_SATELLITE_ATTACH_SUPPORTED_BOOL,
                 CarrierConfigManager.KEY_SATELLITE_ESOS_SUPPORTED_BOOL);
         if (!bundle.getBoolean(
                 CarrierConfigManager.KEY_SATELLITE_ESOS_SUPPORTED_BOOL, false)) {
@@ -2180,7 +2413,7 @@ public class RadioInfo extends AppCompatActivity {
             return true;
         }
         if (!bundle.getBoolean(
-                CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL, false)) {
+                KEY_SATELLITE_ATTACH_SUPPORTED_BOOL, false)) {
             log("shouldHideNonEmergencyMode: attach_supported false");
             return true;
         }
@@ -2220,8 +2453,8 @@ public class RadioInfo extends AppCompatActivity {
     }
 
     private boolean isImsVolteProvisioned() {
-        return getImsConfigProvisionedState(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VOICE,
-                ImsRegistrationImplBase.REGISTRATION_TECH_LTE);
+        return getImsConfigProvisionedState(CAPABILITY_TYPE_VOICE,
+                REGISTRATION_TECH_LTE);
     }
 
     OnCheckedChangeListener mImsVolteCheckedChangeListener = new OnCheckedChangeListener() {
@@ -2232,8 +2465,8 @@ public class RadioInfo extends AppCompatActivity {
     };
 
     private boolean isImsVtProvisioned() {
-        return getImsConfigProvisionedState(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VIDEO,
-                ImsRegistrationImplBase.REGISTRATION_TECH_LTE);
+        return getImsConfigProvisionedState(CAPABILITY_TYPE_VIDEO,
+                REGISTRATION_TECH_LTE);
     }
 
     OnCheckedChangeListener mImsVtCheckedChangeListener = new OnCheckedChangeListener() {
@@ -2244,8 +2477,8 @@ public class RadioInfo extends AppCompatActivity {
     };
 
     private boolean isImsWfcProvisioned() {
-        return getImsConfigProvisionedState(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VOICE,
-                ImsRegistrationImplBase.REGISTRATION_TECH_IWLAN);
+        return getImsConfigProvisionedState(CAPABILITY_TYPE_VOICE,
+                REGISTRATION_TECH_IWLAN);
     }
 
     OnCheckedChangeListener mImsWfcCheckedChangeListener = new OnCheckedChangeListener() {
@@ -2257,7 +2490,7 @@ public class RadioInfo extends AppCompatActivity {
 
     private boolean isEabProvisioned() {
         return getRcsConfigProvisionedState(ImsRcsManager.CAPABILITY_TYPE_PRESENCE_UCE,
-                ImsRegistrationImplBase.REGISTRATION_TECH_LTE);
+                REGISTRATION_TECH_LTE);
     }
 
     OnCheckedChangeListener mEabCheckedChangeListener = new OnCheckedChangeListener() {
@@ -2295,8 +2528,7 @@ public class RadioInfo extends AppCompatActivity {
 
     private boolean isEabEnabledByPlatform() {
         if (SubscriptionManager.isValidPhoneId(mPhoneId)) {
-            CarrierConfigManager configManager = getSystemService(CarrierConfigManager.class);
-            PersistableBundle b = configManager.getConfigForSubId(mSubId);
+            PersistableBundle b = getCarrierConfig().getConfigForSubId(mSubId);
             if (b != null) {
                 return b.getBoolean(
                         CarrierConfigManager.KEY_USE_RCS_PRESENCE_BOOL, false) || b.getBoolean(
@@ -2365,7 +2597,7 @@ public class RadioInfo extends AppCompatActivity {
             Intent intent = new Intent(OEM_RADIO_INFO_INTENT);
             try {
                 startActivityAsUser(intent, UserHandle.CURRENT);
-            } catch (android.content.ActivityNotFoundException ex) {
+            } catch (ActivityNotFoundException ex) {
                 log("OEM-specific Info/Settings Activity Not Found : " + ex);
                 // If the activity does not exist, there are no OEM
                 // settings, and so we can just do nothing...
@@ -2510,9 +2742,7 @@ public class RadioInfo extends AppCompatActivity {
 
     private String getCarrierProvisioningAppString() {
         if (SubscriptionManager.isValidPhoneId(mPhoneId)) {
-            CarrierConfigManager configManager =
-                    getSystemService(CarrierConfigManager.class);
-            PersistableBundle b = configManager.getConfigForSubId(mSubId);
+            PersistableBundle b = getCarrierConfig().getConfigForSubId(mSubId);
             if (b != null) {
                 return b.getString(
                         CarrierConfigManager.KEY_CARRIER_PROVISIONING_APP_STRING, "");
@@ -2631,15 +2861,15 @@ public class RadioInfo extends AppCompatActivity {
 
         ImsMmTelManager imsMmTelManager = mImsManager.getImsMmTelManager(mSubId);
         try {
-            imsMmTelManager.isSupported(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VOICE,
+            imsMmTelManager.isSupported(CAPABILITY_TYPE_VOICE,
                     AccessNetworkConstants.TRANSPORT_TYPE_WWAN, getMainExecutor(), (result) -> {
                         updateVolteProvisionedSwitch(result);
                     });
-            imsMmTelManager.isSupported(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VIDEO,
+            imsMmTelManager.isSupported(CAPABILITY_TYPE_VIDEO,
                     AccessNetworkConstants.TRANSPORT_TYPE_WWAN, getMainExecutor(), (result) -> {
                         updateVtProvisionedSwitch(result);
                     });
-            imsMmTelManager.isSupported(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VOICE,
+            imsMmTelManager.isSupported(CAPABILITY_TYPE_VOICE,
                     AccessNetworkConstants.TRANSPORT_TYPE_WLAN, getMainExecutor(), (result) -> {
                         updateWfcProvisionedSwitch(result);
                     });
@@ -2658,4 +2888,88 @@ public class RadioInfo extends AppCompatActivity {
 
         return phone;
     }
+
+    private boolean isVoiceServiceAvailable(ImsMmTelManager imsMmTelManager) {
+        if (imsMmTelManager == null) {
+            log("isVoiceServiceAvailable: ImsMmTelManager is null");
+            return false;
+        }
+
+        final int[] radioTechs = {
+            REGISTRATION_TECH_LTE,
+            REGISTRATION_TECH_CROSS_SIM,
+            REGISTRATION_TECH_NR,
+            REGISTRATION_TECH_3G
+        };
+
+        boolean isAvailable = false;
+        for (int tech : radioTechs) {
+            try {
+                isAvailable |= imsMmTelManager.isAvailable(CAPABILITY_TYPE_VOICE, tech);
+                if (isAvailable) {
+                    break;
+                }
+            } catch (Exception e) {
+                log("isVoiceServiceAvailable: exception " + e.getMessage());
+            }
+        }
+
+        log("isVoiceServiceAvailable: " + isAvailable);
+        return isAvailable;
+    }
+
+    private boolean isVideoServiceAvailable(ImsMmTelManager imsMmTelManager) {
+        if (imsMmTelManager == null) {
+            log("isVideoServiceAvailable: ImsMmTelManager is null");
+            return false;
+        }
+
+        final int[] radioTechs = {
+            REGISTRATION_TECH_LTE,
+            REGISTRATION_TECH_IWLAN,
+            REGISTRATION_TECH_CROSS_SIM,
+            REGISTRATION_TECH_NR,
+            REGISTRATION_TECH_3G
+        };
+
+        boolean isAvailable = false;
+        for (int tech : radioTechs) {
+            try {
+                isAvailable |= imsMmTelManager.isAvailable(CAPABILITY_TYPE_VIDEO, tech);
+                if (isAvailable) {
+                    break;
+                }
+            } catch (Exception e) {
+                log("isVideoServiceAvailable: exception " + e.getMessage());
+            }
+        }
+
+        log("isVideoServiceAvailable: " + isAvailable);
+        return isAvailable;
+    }
+
+    private boolean isWfcServiceAvailable(ImsMmTelManager imsMmTelManager) {
+        if (imsMmTelManager == null) {
+            log("isWfcServiceAvailable: ImsMmTelManager is null");
+            return false;
+        }
+
+        boolean isAvailable = false;
+        try {
+            isAvailable = imsMmTelManager.isAvailable(CAPABILITY_TYPE_VOICE,
+                    REGISTRATION_TECH_IWLAN);
+        } catch (Exception e) {
+            log("isWfcServiceAvailable: exception " + e.getMessage());
+        }
+
+        log("isWfcServiceAvailable: " + isAvailable);
+        return isAvailable;
+    }
+
+    private CarrierConfigManager getCarrierConfig() {
+        if (mCarrierConfigManager == null) {
+            mCarrierConfigManager = getSystemService(CarrierConfigManager.class);
+        }
+        return mCarrierConfigManager;
+    }
 }
diff --git a/src/com/android/phone/settings/SatelliteConfigViewer.java b/src/com/android/phone/settings/SatelliteConfigViewer.java
new file mode 100644
index 000000000..4d7309faa
--- /dev/null
+++ b/src/com/android/phone/settings/SatelliteConfigViewer.java
@@ -0,0 +1,177 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.phone.settings;
+
+import static android.telephony.SubscriptionManager.INVALID_SUBSCRIPTION_ID;
+import static android.telephony.SubscriptionManager.getDefaultSubscriptionId;
+
+import android.annotation.ArrayRes;
+import android.annotation.NonNull;
+import android.app.ActionBar;
+import android.app.Activity;
+import android.content.Context;
+import android.content.Intent;
+import android.content.res.Resources;
+import android.os.Bundle;
+import android.util.Log;
+import android.view.MenuItem;
+import android.widget.TextView;
+
+import com.android.internal.telephony.flags.FeatureFlagsImpl;
+import com.android.internal.telephony.satellite.SatelliteController;
+import com.android.phone.R;
+import com.android.phone.satellite.accesscontrol.SatelliteAccessConfigurationParser;
+import com.android.phone.satellite.accesscontrol.SatelliteAccessController;
+
+import java.io.File;
+import java.util.HashMap;
+import java.util.List;
+
+public class SatelliteConfigViewer extends Activity {
+    private static final String TAG = SatelliteConfigViewer.class.getSimpleName();
+
+    private TextView mVersion;
+    private TextView mServiceType;
+    private TextView mAllowAccess;
+    private TextView mCountryCodes;
+    private TextView mSizeOfSats2;
+    private TextView mConfigAccessJson;
+
+    private SatelliteController mSatelliteController;
+    private SatelliteAccessController mSatelliteAccessController;
+
+    private int mSubId = INVALID_SUBSCRIPTION_ID;
+
+    @Override
+    protected void onCreate(Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
+        setContentView(R.layout.satellite_config_viewer);
+        Log.d(TAG, "SatelliteConfigViewer: onCreate");
+
+        ActionBar actionBar = getActionBar();
+        if (actionBar != null) {
+            actionBar.setDisplayHomeAsUpEnabled(true);
+        }
+
+        Intent intentRadioInfo = getIntent();
+        mSubId = intentRadioInfo.getIntExtra("mSubId", getDefaultSubscriptionId());
+        Log.d(TAG, "SatelliteConfigViewer: mSubId: " + mSubId);
+
+        mVersion = (TextView) findViewById(R.id.version);
+        mServiceType = (TextView) findViewById(R.id.svc_type);
+        mAllowAccess = (TextView) findViewById(R.id.allow_access);
+        mCountryCodes = (TextView) findViewById(R.id.country_codes);
+        mSizeOfSats2 = (TextView) findViewById(R.id.size_of_sats2);
+        mConfigAccessJson = (TextView) findViewById(R.id.config_json);
+
+        mSatelliteController = SatelliteController.getInstance();
+        mSatelliteAccessController = SatelliteAccessController.getOrCreateInstance(
+                getApplicationContext(), new FeatureFlagsImpl());
+
+        mVersion.setText(getSatelliteConfigVersion());
+        mServiceType.setText(getSatelliteCarrierConfigUpdateData());
+        mAllowAccess.setText(getSatelliteAllowAccess());
+        mCountryCodes.setText(getSatelliteConfigCountryCodes());
+        mSizeOfSats2.setText(getSatelliteS2SatFileSize(getApplicationContext()));
+        mConfigAccessJson.setText(getSatelliteConfigJsonFile(getApplicationContext()));
+    }
+
+    private String getSatelliteConfigVersion() {
+        logd("getSatelliteConfigVersion");
+        return Integer.toString(mSatelliteAccessController.getSatelliteAccessConfigVersion());
+    }
+
+    private String getSatelliteCarrierConfigUpdateData() {
+        logd("getSatelliteCarrierConfigUpdateData");
+        HashMap<String, List<Integer>> mapPlmnServiceType = new HashMap<>();
+        List<String> plmnList = mSatelliteController.getSatellitePlmnsForCarrier(mSubId);
+        for (String plmn : plmnList) {
+            List<Integer> listServiceType =
+                    mSatelliteController.getSupportedSatelliteServicesForPlmn(mSubId, plmn);
+            mapPlmnServiceType.put(plmn, listServiceType);
+        }
+        logd("getSatelliteCarrierConfigUpdateData: " + "subId: " + mSubId + ": "
+                + mapPlmnServiceType);
+        return "subId: " + mSubId + ": " + mapPlmnServiceType;
+    }
+
+    private String getSatelliteAllowAccess() {
+        logd("getSatelliteAllowAccess");
+        return Boolean.toString(mSatelliteAccessController.isSatelliteAllowAccessControl());
+    }
+
+    private String getSatelliteConfigCountryCodes() {
+        logd("getSatelliteConfigCountryCodes");
+        return String.join(",", mSatelliteAccessController.getSatelliteCountryCodes());
+    }
+
+    private String getSatelliteConfigJsonFile(Context context) {
+        logd("getSatelliteConfigJsonFile");
+
+        File jsonFile = mSatelliteAccessController.getSatelliteAccessConfigFile();
+        if (jsonFile == null) {
+            loge("getSatelliteConfigJsonFile: satellite access config json file is null");
+            return "satellite access config json file is not ready";
+        }
+        return SatelliteAccessConfigurationParser
+                .readJsonStringFromFile(jsonFile.getAbsolutePath());
+    }
+
+    private String getSatelliteS2SatFileSize(Context context) {
+        logd("getSatelliteS2SatFileSize");
+        File s2CellFile = mSatelliteAccessController.getSatelliteS2CellFile();
+        if (s2CellFile == null) {
+            loge("getSatelliteS2SatFileSize: s2satFile is null");
+            return "s2satFile is null";
+        }
+        return Long.toString(s2CellFile.length());
+    }
+
+    @NonNull
+    private static String[] readStringArrayFromOverlayConfig(
+            @NonNull Context context, @ArrayRes int id) {
+        String[] strArray = null;
+        try {
+            strArray = context.getResources().getStringArray(id);
+        } catch (Resources.NotFoundException ex) {
+            loge("readStringArrayFromOverlayConfig: id= " + id + ", ex=" + ex);
+        }
+        if (strArray == null) {
+            strArray = new String[0];
+        }
+        return strArray;
+    }
+
+    @Override
+    public boolean onOptionsItemSelected(@androidx.annotation.NonNull MenuItem item) {
+        switch (item.getItemId()) {
+            case android.R.id.home:
+                finish();
+                return true;
+            default:
+                return super.onOptionsItemSelected(item);
+        }
+    }
+
+    private static void logd(@NonNull String log) {
+        Log.d(TAG, log);
+    }
+
+    private static void loge(@NonNull String log) {
+        Log.e(TAG, log);
+    }
+}
diff --git a/src/com/android/phone/settings/SettingsConstants.java b/src/com/android/phone/settings/SettingsConstants.java
index c17e6df4f..6ffef06a5 100644
--- a/src/com/android/phone/settings/SettingsConstants.java
+++ b/src/com/android/phone/settings/SettingsConstants.java
@@ -16,6 +16,12 @@
 
 package com.android.phone.settings;
 
+import android.app.Activity;
+
+import androidx.core.graphics.Insets;
+import androidx.core.view.ViewCompat;
+import androidx.core.view.WindowInsetsCompat;
+
 /**
  * Constants related to settings which are shared by two or more classes.
  */
@@ -30,4 +36,23 @@ public class SettingsConstants {
     public static final int HAC_ENABLED = 1;
     public static final String HAC_VAL_ON = "ON";
     public static final String HAC_VAL_OFF = "OFF";
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
diff --git a/src/com/android/phone/settings/VoicemailSettingsActivity.java b/src/com/android/phone/settings/VoicemailSettingsActivity.java
index 909a3ada7..baae26b24 100644
--- a/src/com/android/phone/settings/VoicemailSettingsActivity.java
+++ b/src/com/android/phone/settings/VoicemailSettingsActivity.java
@@ -264,6 +264,8 @@ public class VoicemailSettingsActivity extends PreferenceActivity
                 NotificationChannelController.CHANNEL_ID_VOICE_MAIL);
         intent.putExtra(Settings.EXTRA_APP_PACKAGE, mPhone.getContext().getPackageName());
         mVoicemailNotificationPreference.setIntent(intent);
+
+        SettingsConstants.setupEdgeToEdge(this);
     }
 
     @Override
@@ -289,6 +291,10 @@ public class VoicemailSettingsActivity extends PreferenceActivity
         mPreviousVMProviderKey = mVoicemailProviders.getValue();
 
         mVoicemailSettings = (PreferenceScreen) findPreference(BUTTON_VOICEMAIL_SETTING_KEY);
+        // 😮‍💨 the legacy PreferenceScreen displays a dialog in its onClick.  Set a property on the
+        // PreferenceScreen to ensure that it will fit system windows to accommodate for edge to
+        // edge.
+        mVoicemailSettings.setDialogFitsSystemWindows(true);
 
         maybeHidePublicSettings();
 
diff --git a/src/com/android/phone/settings/fdn/FdnList.java b/src/com/android/phone/settings/fdn/FdnList.java
index e50fc60e9..ca9806163 100644
--- a/src/com/android/phone/settings/fdn/FdnList.java
+++ b/src/com/android/phone/settings/fdn/FdnList.java
@@ -39,6 +39,7 @@ import com.android.phone.ADNList;
 import com.android.phone.PhoneGlobals;
 import com.android.phone.R;
 import com.android.phone.SubscriptionInfoHelper;
+import com.android.phone.settings.SettingsConstants;
 
 /**
  * Fixed Dialing Number (FDN) List UI for the Phone app. FDN is a feature of the service provider
@@ -112,6 +113,8 @@ public class FdnList extends ADNList {
         mSubscriptionInfoHelper = new SubscriptionInfoHelper(this, getIntent());
         mSubscriptionInfoHelper.setActionBarTitle(
                 getActionBar(), getResources(), R.string.fdn_list_with_label);
+
+        SettingsConstants.setupEdgeToEdge(this);
     }
 
     @Override
diff --git a/src/com/android/phone/vvm/RemoteVvmTaskManager.java b/src/com/android/phone/vvm/RemoteVvmTaskManager.java
index b7c34068c..9fa821b8a 100644
--- a/src/com/android/phone/vvm/RemoteVvmTaskManager.java
+++ b/src/com/android/phone/vvm/RemoteVvmTaskManager.java
@@ -157,7 +157,6 @@ public class RemoteVvmTaskManager extends Service {
             }
         }
         packages.add(context.getResources().getString(R.string.system_visual_voicemail_client));
-        packages.add(telecomManager.getSystemDialerPackage());
 
         for (String packageName : packages) {
             if (TextUtils.isEmpty(packageName)) {
diff --git a/src/com/android/phone/vvm/VvmSimStateTracker.java b/src/com/android/phone/vvm/VvmSimStateTracker.java
index 0362d02fa..4f3328fcc 100644
--- a/src/com/android/phone/vvm/VvmSimStateTracker.java
+++ b/src/com/android/phone/vvm/VvmSimStateTracker.java
@@ -234,7 +234,8 @@ public class VvmSimStateTracker extends BroadcastReceiver {
             // return null.
             return;
         }
-        if (telephonyManager.getServiceState().getState()
+        ServiceState currentServiceState = telephonyManager.getServiceState();
+        if (currentServiceState != null && currentServiceState.getState()
                 == ServiceState.STATE_IN_SERVICE) {
             VvmLog.i(TAG, "onCarrierConfigChanged: in service; send connected "
                     + phoneAccountHandle);
diff --git a/src/com/android/services/telephony/ConferenceParticipantConnection.java b/src/com/android/services/telephony/ConferenceParticipantConnection.java
index 81798173e..d01bc04e6 100644
--- a/src/com/android/services/telephony/ConferenceParticipantConnection.java
+++ b/src/com/android/services/telephony/ConferenceParticipantConnection.java
@@ -200,8 +200,9 @@ public class ConferenceParticipantConnection extends Connection {
 
         int subId = phone.getSubId();
 
-        SubscriptionInfo subInfo = TelecomAccountRegistry.getInstance(null).
-                getSubscriptionManager().getActiveSubscriptionInfo(subId);
+        var subscriptionManager = TelecomAccountRegistry.getInstance(null).getSubscriptionManager();
+        if (subscriptionManager == null) return null;
+        SubscriptionInfo subInfo = subscriptionManager.getActiveSubscriptionInfo(subId);
 
         if (subInfo == null || TextUtils.isEmpty(subInfo.getCountryIso())) {
             return null;
diff --git a/src/com/android/services/telephony/PstnIncomingCallNotifier.java b/src/com/android/services/telephony/PstnIncomingCallNotifier.java
index 3b74c6f58..fce3d9155 100644
--- a/src/com/android/services/telephony/PstnIncomingCallNotifier.java
+++ b/src/com/android/services/telephony/PstnIncomingCallNotifier.java
@@ -33,8 +33,10 @@ import com.android.internal.telephony.Call;
 import com.android.internal.telephony.CallStateException;
 import com.android.internal.telephony.Connection;
 import com.android.internal.telephony.GsmCdmaPhone;
+import com.android.internal.telephony.LocaleTracker;
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneConstants;
+import com.android.internal.telephony.ServiceStateTracker;
 import com.android.internal.telephony.cdma.CdmaCallWaitingNotification;
 import com.android.internal.telephony.imsphone.ImsExternalCallTracker;
 import com.android.internal.telephony.imsphone.ImsExternalConnection;
@@ -148,6 +150,19 @@ final class PstnIncomingCallNotifier {
         }
     }
 
+    /**
+     * Note: Same logic as
+     * {@link com.android.phone.PhoneInterfaceManager#getNetworkCountryIsoForPhone(int)}.
+     * @return the network country ISO for the current phone, or {@code null} if not known.
+     */
+    private String getNetworkCountryIso() {
+        ServiceStateTracker sst = mPhone.getServiceStateTracker();
+        if (sst == null) return null;
+        LocaleTracker lt = sst.getLocaleTracker();
+        if (lt == null) return null;
+        return lt.getCurrentCountry();
+    }
+
     /**
      * Verifies the incoming call and triggers sending the incoming-call intent to Telecom.
      *
@@ -161,7 +176,7 @@ final class PstnIncomingCallNotifier {
             // Check if we have a pending number verification request.
             if (connection.getAddress() != null) {
                 if (NumberVerificationManager.getInstance()
-                        .checkIncomingCall(connection.getAddress())) {
+                        .checkIncomingCall(connection.getAddress(), getNetworkCountryIso())) {
                     // Disconnect the call if it matches, after a delay
                     mHandler.postDelayed(() -> {
                         try {
diff --git a/src/com/android/services/telephony/TelecomAccountRegistry.java b/src/com/android/services/telephony/TelecomAccountRegistry.java
index 895626695..2222fb873 100644
--- a/src/com/android/services/telephony/TelecomAccountRegistry.java
+++ b/src/com/android/services/telephony/TelecomAccountRegistry.java
@@ -1398,8 +1398,7 @@ public class TelecomAccountRegistry {
                     Build.VERSION.DEVICE_INITIAL_SDK_INT);
             PackageManager pm = context.getPackageManager();
 
-            if (Flags.enforceTelephonyFeatureMappingForPublicApis()
-                    && vendorApiLevel >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+            if (vendorApiLevel >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
                 if (pm != null && pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)
                         && pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_CALLING)) {
                     sInstance = new TelecomAccountRegistry(context);
@@ -1790,7 +1789,7 @@ public class TelecomAccountRegistry {
                         }
 
                         // Skip the sim for satellite as it does not support call for now
-                        if (Flags.oemEnabledSatelliteFlag() && info.isOnlyNonTerrestrialNetwork()) {
+                        if (info.isOnlyNonTerrestrialNetwork()) {
                             Log.d(this, "setupAccounts: skipping satellite sub id "
                                     + subscriptionId);
                             continue;
diff --git a/src/com/android/services/telephony/TelephonyConnection.java b/src/com/android/services/telephony/TelephonyConnection.java
index 3dbae8e3b..457dec6fe 100644
--- a/src/com/android/services/telephony/TelephonyConnection.java
+++ b/src/com/android/services/telephony/TelephonyConnection.java
@@ -1338,8 +1338,10 @@ abstract class TelephonyConnection extends Connection implements Holdable, Commu
                     if (phone.getPhoneType() == PhoneConstants.PHONE_TYPE_IMS) {
                         ImsPhone imsPhone = (ImsPhone) phone;
                         imsPhone.holdActiveCall();
-                        mTelephonyConnectionService.maybeUnholdCallsOnOtherSubs(
-                                getPhoneAccountHandle());
+                        if (!com.android.server.telecom.flags.Flags.enableCallSequencing()) {
+                            mTelephonyConnectionService.maybeUnholdCallsOnOtherSubs(
+                                    getPhoneAccountHandle());
+                        }
                         return;
                     }
                     phone.switchHoldingAndActive();
diff --git a/src/com/android/services/telephony/TelephonyConnectionService.java b/src/com/android/services/telephony/TelephonyConnectionService.java
index 6f8e83804..abf725fde 100644
--- a/src/com/android/services/telephony/TelephonyConnectionService.java
+++ b/src/com/android/services/telephony/TelephonyConnectionService.java
@@ -23,7 +23,6 @@ import static android.telephony.ServiceState.STATE_IN_SERVICE;
 import static android.telephony.TelephonyManager.HAL_SERVICE_VOICE;
 
 import static com.android.internal.telephony.PhoneConstants.PHONE_TYPE_GSM;
-import static com.android.internal.telephony.flags.Flags.carrierEnabledSatelliteFlag;
 
 import android.annotation.NonNull;
 import android.app.AlertDialog;
@@ -71,6 +70,7 @@ import android.telephony.ims.stub.ImsRegistrationImplBase;
 import android.text.TextUtils;
 import android.util.Pair;
 import android.view.WindowManager;
+import android.widget.Toast;
 
 import com.android.ims.ImsManager;
 import com.android.internal.annotations.VisibleForTesting;
@@ -126,6 +126,7 @@ import java.util.Queue;
 import java.util.Set;
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.Executor;
+import java.util.concurrent.TimeUnit;
 import java.util.function.Consumer;
 import java.util.regex.Pattern;
 import java.util.stream.Stream;
@@ -147,11 +148,15 @@ public class TelephonyConnectionService extends ConnectionService {
 
     // Timeout before we terminate the outgoing DSDA call if HOLD did not complete in time on the
     // existing call.
-    private static final int DEFAULT_DSDA_OUTGOING_CALL_HOLD_TIMEOUT_MS = 2000;
+    private static final int DEFAULT_DSDA_CALL_STATE_CHANGE_TIMEOUT_MS = 5000;
 
     // Timeout to wait for the termination of incoming call before continue with the emergency call.
     private static final int DEFAULT_REJECT_INCOMING_CALL_TIMEOUT_MS = 10 * 1000; // 10 seconds.
 
+    // Timeout to wait for ending active call on other domain before continuing with
+    // the emergency call.
+    private static final int DEFAULT_DISCONNECT_CALL_ON_OTHER_DOMAIN_TIMEOUT_MS = 2 * 1000;
+
     // If configured, reject attempts to dial numbers matching this pattern.
     private static final Pattern CDMA_ACTIVATION_CODE_REGEX_PATTERN =
             Pattern.compile("\\*228[0-9]{0,2}");
@@ -220,6 +225,8 @@ public class TelephonyConnectionService extends ConnectionService {
     private final CdmaConferenceController mCdmaConferenceController =
             new CdmaConferenceController(this);
 
+    private com.android.server.telecom.flags.FeatureFlags mTelecomFlags =
+            new com.android.server.telecom.flags.FeatureFlagsImpl();
     private FeatureFlags mFeatureFlags = new FeatureFlagsImpl();
 
     private ImsConferenceController mImsConferenceController;
@@ -743,6 +750,32 @@ public class TelephonyConnectionService extends ConnectionService {
         }
     }
 
+    private static class StateDisconnectListener extends
+            TelephonyConnection.TelephonyConnectionListener {
+        private final CompletableFuture<Boolean> mDisconnectFuture;
+
+        StateDisconnectListener(CompletableFuture<Boolean> future) {
+            mDisconnectFuture = future;
+        }
+
+        @Override
+        public void onStateChanged(
+                Connection connection, @Connection.ConnectionState int state) {
+            TelephonyConnection c = (TelephonyConnection) connection;
+            if (c != null) {
+                switch (c.getState()) {
+                    case Connection.STATE_DISCONNECTED: {
+                        Log.d(LOG_TAG, "Connection " + connection.getTelecomCallId()
+                                + " changed to STATE_DISCONNECTED!");
+                        mDisconnectFuture.complete(true);
+                        c.removeTelephonyConnectionListener(this);
+                    }
+                    break;
+                }
+            }
+        }
+    }
+
     private static class OnDisconnectListener extends
             com.android.internal.telephony.Connection.ListenerBase {
         private final CompletableFuture<Boolean> mFuture;
@@ -1317,7 +1350,8 @@ public class TelephonyConnectionService extends ConnectionService {
             }
 
             if (!isEmergencyNumber) {
-                if (isCallDisallowedDueToSatellite(phone)
+                if ((isCallDisallowedDueToSatellite(phone)
+                        || isCallDisallowedDueToNtnEligibility(phone))
                         && (imsPhone == null || !imsPhone.canMakeWifiCall())) {
                     Log.d(this, "onCreateOutgoingConnection, cannot make call "
                             + "when device is connected to carrier roaming satellite network");
@@ -1336,7 +1370,11 @@ public class TelephonyConnectionService extends ConnectionService {
                     }
                     return resultConnection;
                 } else {
-                    if (mTelephonyManagerProxy.isConcurrentCallsPossible()) {
+                    // If call sequencing is enabled, Telecom will take care of holding calls across
+                    // subscriptions if needed before delegating the connection creation over to
+                    // Telephony.
+                    if (mTelephonyManagerProxy.isConcurrentCallsPossible()
+                            && !mTelecomFlags.enableCallSequencing()) {
                         Conferenceable c = maybeHoldCallsOnOtherSubs(request.getAccountHandle());
                         if (c != null) {
                             delayDialForOtherSubHold(phone, c, (success) -> {
@@ -1366,44 +1404,61 @@ public class TelephonyConnectionService extends ConnectionService {
                     }
                 }
 
-                CompletableFuture<Void> maybeHoldFuture =
-                        checkAndHoldCallsOnOtherSubsForEmergencyCall(request,
+                CompletableFuture<Void> maybeHoldOrDisconnectOnOtherSubsFuture =
+                        checkAndHoldOrDisconnectCallsOnOtherSubsForEmergencyCall(request,
                                 resultConnection, phone);
                 Consumer<Boolean> ddsSwitchConsumer = (result) -> {
                     Log.i(this, "onCreateOutgoingConn emergency-"
                             + " delayDialForDdsSwitch result = " + result);
                     placeOutgoingConnection(request, resultConnection, phone);
                 };
-                maybeHoldFuture.thenRun(() -> delayDialForDdsSwitch(phone, ddsSwitchConsumer));
+                maybeHoldOrDisconnectOnOtherSubsFuture.thenRun(() -> delayDialForDdsSwitch(phone,
+                        ddsSwitchConsumer));
                 return resultConnection;
             }
         }
     }
 
-    private CompletableFuture<Void> checkAndHoldCallsOnOtherSubsForEmergencyCall(
+    private CompletableFuture<Void> checkAndHoldOrDisconnectCallsOnOtherSubsForEmergencyCall(
             ConnectionRequest request, Connection resultConnection, Phone phone) {
-        CompletableFuture<Void> maybeHoldFuture = CompletableFuture.completedFuture(null);
-        if (mTelephonyManagerProxy.isConcurrentCallsPossible()
-                && shouldHoldForEmergencyCall(phone)) {
+        CompletableFuture<Void> future = CompletableFuture.completedFuture(null);
+        if (mTelephonyManagerProxy.isConcurrentCallsPossible()) {
             // If the PhoneAccountHandle was adjusted on building the TelephonyConnection,
             // the relevant PhoneAccountHandle will be updated in resultConnection.
             PhoneAccountHandle phoneAccountHandle =
                     resultConnection.getPhoneAccountHandle() == null
-                    ? request.getAccountHandle() : resultConnection.getPhoneAccountHandle();
-            Conferenceable c = maybeHoldCallsOnOtherSubs(phoneAccountHandle);
-            if (c != null) {
-                maybeHoldFuture = delayDialForOtherSubHold(phone, c, (success) -> {
-                    Log.i(this, "checkAndHoldCallsOnOtherSubsForEmergencyCall"
-                            + " delayDialForOtherSubHold success = " + success);
-                    if (!success) {
-                        // Terminates the existing call to make way for the emergency call.
-                        hangup(c, android.telephony.DisconnectCause
-                                .OUTGOING_EMERGENCY_CALL_PLACED);
-                    }
-                });
+                            ? request.getAccountHandle()
+                            : resultConnection.getPhoneAccountHandle();
+            if (shouldHoldForEmergencyCall(phone) && !mTelecomFlags.enableCallSequencing()) {
+                Conferenceable c = maybeHoldCallsOnOtherSubs(phoneAccountHandle);
+                if (c != null) {
+                    future = delayDialForOtherSubHold(phone, c, (success) -> {
+                        Log.i(this, "checkAndHoldOrDisconnectCallsOnOtherSubsForEmergencyCall"
+                                + " delayDialForOtherSubHold success = " + success);
+                        if (!success) {
+                            // Terminates the existing call to make way for the emergency call.
+                            hangup(c, android.telephony.DisconnectCause
+                                    .OUTGOING_EMERGENCY_CALL_PLACED);
+                        }
+                    });
+                }
+            } else {
+                Log.i(this, "checkAndHoldOrDisconnectCallsOnOtherSubsForEmergencyCall"
+                        + " disconnectAllCallsOnOtherSubs, phoneAccountExcluded: "
+                        + phoneAccountHandle);
+                // Disconnect any calls on other subscription as part of call sequencing. This will
+                // cover the shared data call case too when we have a call on the shared data sim
+                // as the call will always try to be placed on the sim in service. Refer to
+                // #isAvailableForEmergencyCalls.
+                List<Conferenceable> disconnectedConferenceables =
+                        disconnectAllConferenceablesOnOtherSubs(phoneAccountHandle);
+                future = delayDialForOtherSubDisconnects(phone, disconnectedConferenceables,
+                        (success) -> Log.i(this,
+                                "checkAndHoldOrDisconnectCallsOnOtherSubsForEmergencyCall"
+                                        + " delayDialForOtherSubDisconnects success = " + success));
             }
         }
-        return maybeHoldFuture;
+        return future;
     }
 
     private Connection placeOutgoingConnection(ConnectionRequest request,
@@ -1854,6 +1909,12 @@ public class TelephonyConnectionService extends ConnectionService {
     public void onCreateIncomingConnectionFailed(PhoneAccountHandle connectionManagerPhoneAccount,
             ConnectionRequest request) {
         Log.i(this, "onCreateIncomingConnectionFailed, request: " + request);
+        // for auto disconnect cases, the request will contain this message, so we can ignore
+        if (request.getExtras().containsKey(TelecomManager.EXTRA_CALL_DISCONNECT_MESSAGE)) {
+            Log.i(this, "onCreateIncomingConnectionFailed: auto-disconnected,"
+                    + "ignoring.");
+            return;
+        }
         // If there is an incoming emergency CDMA Call (while the phone is in ECBM w/ No SIM),
         // make sure the PhoneAccount lookup retrieves the default Emergency Phone.
         PhoneAccountHandle accountHandle = request.getAccountHandle();
@@ -2339,9 +2400,8 @@ public class TelephonyConnectionService extends ConnectionService {
                                 }
                             }
                             for (Conference c : getAllConferences()) {
-                                if (c.getState() != Connection.STATE_DISCONNECTED
-                                        && c instanceof Conference) {
-                                    ((Conference) c).onDisconnect();
+                                if (c.getState() != Connection.STATE_DISCONNECTED) {
+                                    c.onDisconnect();
                                 }
                             }
                         } else if (!isVideoCallHoldAllowed(phone)) {
@@ -2562,6 +2622,10 @@ public class TelephonyConnectionService extends ConnectionService {
             }
         } catch (CallStateException e) {
             Log.e(this, e, "Call placeOutgoingCallConnection, phone.dial exception: " + e);
+            if (e.getError() == CallStateException.ERROR_FDN_BLOCKED) {
+                Toast.makeText(getApplicationContext(), R.string.fdn_blocked_mmi,
+                        Toast.LENGTH_SHORT).show();
+            }
             mNormalCallConnection.unregisterForCallEvents();
             handleCallStateException(e, mNormalCallConnection, phone);
         } catch (Exception e) {
@@ -2673,10 +2737,12 @@ public class TelephonyConnectionService extends ConnectionService {
                     phone);
         }
 
-        CompletableFuture<Void> maybeHoldFuture =
-                checkAndHoldCallsOnOtherSubsForEmergencyCall(request, resultConnection, phone);
-        maybeHoldFuture.thenRun(() -> placeEmergencyConnectionInternal(resultConnection,
-                phone, request, numberToDial, isTestEmergencyNumber, needToTurnOnRadio));
+        CompletableFuture<Void> maybeHoldOrDisconnectOnOtherSubFuture =
+                checkAndHoldOrDisconnectCallsOnOtherSubsForEmergencyCall(request,
+                        resultConnection, phone);
+        maybeHoldOrDisconnectOnOtherSubFuture.thenRun(() -> placeEmergencyConnectionInternal(
+                resultConnection, phone, request, numberToDial, isTestEmergencyNumber,
+                needToTurnOnRadio));
 
         // Non TelephonyConnection type instance means dialing failure.
         return resultConnection;
@@ -2799,11 +2865,147 @@ public class TelephonyConnectionService extends ConnectionService {
                             + "reject incoming, dialing canceled");
                     return;
                 }
-                placeEmergencyConnectionOnSelectedDomain(request, resultConnection, phone);
+                // Hang up the active calls if the domain of currently active call is different
+                // from the domain selected by domain selector.
+                if (Flags.hangupActiveCallBasedOnEmergencyCallDomain()) {
+                    CompletableFuture<Void> disconnectCall = maybeDisconnectCallsOnOtherDomain(
+                            phone, resultConnection, result,
+                            getAllConnections(), getAllConferences(), (ret) -> {
+                                if (!ret) {
+                                    Log.i(this, "createEmergencyConnection: "
+                                            + "disconnecting call on other domain failed");
+                                }
+                            });
+
+                    CompletableFuture<Void> unused = disconnectCall.thenRun(() -> {
+                        if (resultConnection.getState() == Connection.STATE_DISCONNECTED) {
+                            Log.i(this, "createEmergencyConnection: "
+                                    + "disconnect call on other domain, dialing canceled");
+                            return;
+                        }
+                        placeEmergencyConnectionOnSelectedDomain(request, resultConnection, phone);
+                    });
+                } else {
+                    placeEmergencyConnectionOnSelectedDomain(request, resultConnection, phone);
+                }
             });
         }, mDomainSelectionMainExecutor);
     }
 
+    /**
+     * Disconnect the active calls on the other domain for an emergency call.
+     * For example,
+     *  - Active IMS normal call and CS emergency call
+     *  - Active CS normal call and IMS emergency call
+     *
+     * @param phone The Phone to be used for an emergency call.
+     * @param emergencyConnection The connection created for an emergency call.
+     * @param emergencyDomain The selected domain for an emergency call.
+     * @param connections All individual connections, including conference participants.
+     * @param conferences All conferences.
+     * @param completeConsumer The consumer to call once the call hangup has been completed.
+     *        {@code true} if the operation commpletes successfully, or
+     *        {@code false} if the operation timed out/failed.
+     */
+    @VisibleForTesting
+    public static CompletableFuture<Void> maybeDisconnectCallsOnOtherDomain(Phone phone,
+            Connection emergencyConnection,
+            @NetworkRegistrationInfo.Domain int emergencyDomain,
+            @NonNull Collection<Connection> connections,
+            @NonNull Collection<Conference> conferences,
+            Consumer<Boolean> completeConsumer) {
+        List<Connection> activeConnections = connections.stream()
+                .filter(c -> {
+                    return !c.equals(emergencyConnection)
+                            && isConnectionOnOtherDomain(c, phone, emergencyDomain);
+                }).toList();
+        List<Conference> activeConferences = conferences.stream()
+                .filter(c -> {
+                    Connection pc = c.getPrimaryConnection();
+                    return isConnectionOnOtherDomain(pc, phone, emergencyDomain);
+                }).toList();
+
+        if (activeConnections.isEmpty() && activeConferences.isEmpty()) {
+            // There are no active calls.
+            completeConsumer.accept(true);
+            return CompletableFuture.completedFuture(null);
+        }
+
+        Log.i(LOG_TAG, "maybeDisconnectCallsOnOtherDomain: "
+                + "connections=" + activeConnections.size()
+                + ", conferences=" + activeConferences.size());
+
+        try {
+            CompletableFuture<Boolean> future = null;
+
+            for (Connection c : activeConnections) {
+                TelephonyConnection tc = (TelephonyConnection) c;
+                if (tc.getState() != Connection.STATE_DISCONNECTED) {
+                    if (future == null) {
+                        future = new CompletableFuture<>();
+                        tc.getOriginalConnection().addListener(new OnDisconnectListener(future));
+                    }
+                    tc.hangup(android.telephony.DisconnectCause.OUTGOING_EMERGENCY_CALL_PLACED);
+                }
+            }
+
+            for (Conference c : activeConferences) {
+                if (c.getState() != Connection.STATE_DISCONNECTED) {
+                    c.onDisconnect();
+                }
+            }
+
+            if (future != null) {
+                // A timeout that will complete the future to not block the outgoing call
+                // indefinitely.
+                CompletableFuture<Boolean> timeout = new CompletableFuture<>();
+                phone.getContext().getMainThreadHandler().postDelayed(
+                        () -> timeout.complete(false),
+                        DEFAULT_DISCONNECT_CALL_ON_OTHER_DOMAIN_TIMEOUT_MS);
+                // Ensure that the Consumer is completed on the main thread.
+                return future.acceptEitherAsync(timeout, completeConsumer,
+                        phone.getContext().getMainExecutor()).exceptionally((ex) -> {
+                            Log.w(LOG_TAG, "maybeDisconnectCallsOnOtherDomain: exceptionally="
+                                    + ex);
+                            return null;
+                        });
+            } else {
+                completeConsumer.accept(true);
+                return CompletableFuture.completedFuture(null);
+            }
+        } catch (Exception e) {
+            Log.w(LOG_TAG, "maybeDisconnectCallsOnOtherDomain: exception=" + e.getMessage());
+            completeConsumer.accept(false);
+            return CompletableFuture.completedFuture(null);
+        }
+    }
+
+    private static boolean isConnectionOnOtherDomain(Connection c, Phone phone,
+            @NetworkRegistrationInfo.Domain int domain) {
+        if (c instanceof TelephonyConnection) {
+            TelephonyConnection tc = (TelephonyConnection) c;
+            Phone callPhone = tc.getPhone();
+            int callDomain = NetworkRegistrationInfo.DOMAIN_UNKNOWN;
+
+            // Treat Wi-Fi calling same as PS domain.
+            if (domain == PhoneConstants.DOMAIN_NON_3GPP_PS) {
+                domain = NetworkRegistrationInfo.DOMAIN_PS;
+            }
+
+            if (callPhone != null && callPhone.getSubId() == phone.getSubId()) {
+                if (tc.isGsmCdmaConnection()) {
+                    callDomain = NetworkRegistrationInfo.DOMAIN_CS;
+                } else if (tc.isImsConnection()) {
+                    callDomain = NetworkRegistrationInfo.DOMAIN_PS;
+                }
+            }
+
+            return callDomain != NetworkRegistrationInfo.DOMAIN_UNKNOWN
+                    && callDomain != domain;
+        }
+        return false;
+    }
+
     private void dialCsEmergencyCall(final Phone phone,
             final TelephonyConnection resultConnection, final ConnectionRequest request) {
         Log.d(this, "dialCsEmergencyCall");
@@ -3827,7 +4029,7 @@ public class TelephonyConnectionService extends ConnectionService {
             // a timeout that will complete the future to not block the outgoing call indefinitely.
             CompletableFuture<Boolean> timeout = new CompletableFuture<>();
             phone.getContext().getMainThreadHandler().postDelayed(
-                    () -> timeout.complete(false), DEFAULT_DSDA_OUTGOING_CALL_HOLD_TIMEOUT_MS);
+                    () -> timeout.complete(false), DEFAULT_DSDA_CALL_STATE_CHANGE_TIMEOUT_MS);
             // Ensure that the Consumer is completed on the main thread.
             return stateHoldingFuture.acceptEitherAsync(timeout, completeConsumer,
                     phone.getContext().getMainExecutor());
@@ -3839,6 +4041,60 @@ public class TelephonyConnectionService extends ConnectionService {
         }
     }
 
+    /**
+     * For DSDA devices, block until the connections passed in are disconnected (STATE_DISCONNECTED)
+     * or time out.
+     * @return {@link CompletableFuture} indicating the completion result after performing
+     * the bulk disconnect
+     */
+    private CompletableFuture<Void> delayDialForOtherSubDisconnects(Phone phone,
+            List<Conferenceable> conferenceables, Consumer<Boolean> completeConsumer) {
+        if (conferenceables.isEmpty()) {
+            completeConsumer.accept(true);
+            return CompletableFuture.completedFuture(null);
+        }
+        if (phone == null) {
+            // Unexpected inputs
+            completeConsumer.accept(false);
+            return CompletableFuture.completedFuture(null);
+        }
+        List<CompletableFuture<Boolean>> disconnectFutures = new ArrayList<>();
+        for (Conferenceable conferenceable : conferenceables) {
+            CompletableFuture<Boolean> disconnectFuture = CompletableFuture.completedFuture(null);
+            try {
+                if (conferenceable == null) {
+                    disconnectFuture = CompletableFuture.completedFuture(null);
+                } else {
+                    // Listen for each disconnect as part of an individual future.
+                    disconnectFuture = listenForDisconnectStateChanged(conferenceable)
+                            .completeOnTimeout(false, DEFAULT_DSDA_CALL_STATE_CHANGE_TIMEOUT_MS,
+                                    TimeUnit.MILLISECONDS);
+                }
+            } catch (Exception e) {
+                Log.w(this, "delayDialForOtherSubDisconnects - exception= " + e.getMessage());
+                disconnectFuture = CompletableFuture.completedFuture(null);
+            } finally {
+                disconnectFutures.add(disconnectFuture);
+            }
+        }
+        // Return a future that waits for all the disconnect futures to complete.
+        return CompletableFuture.allOf(disconnectFutures.toArray(CompletableFuture[]::new));
+    }
+
+    /**
+     * Listen for the disconnect state change from the passed in {@link Conferenceable}.
+     * @param conferenceable
+     * @return {@link CompletableFuture} that provides the result of waiting on the
+     * disconnect state change.
+     */
+    private CompletableFuture<Boolean> listenForDisconnectStateChanged(
+            @NonNull Conferenceable conferenceable) {
+        CompletableFuture<Boolean> future = new CompletableFuture<>();
+        final StateDisconnectListener disconnectListener = new StateDisconnectListener(future);
+        addTelephonyConnectionListener(conferenceable, disconnectListener);
+        return future;
+    }
+
     /**
      * If needed, block until an incoming call is disconnected for outgoing emergency call,
      * or timeout expires.
@@ -4508,6 +4764,8 @@ public class TelephonyConnectionService extends ConnectionService {
      */
     public void maybeIndicateAnsweringWillDisconnect(@NonNull TelephonyConnection connection,
             @NonNull PhoneAccountHandle phoneAccountHandle) {
+        // With sequencing, Telecom handles setting the extra.
+        if (mTelecomFlags.enableCallSequencing()) return;
         if (isCallPresentOnOtherSub(phoneAccountHandle)) {
             if (mTelephonyManagerProxy.isConcurrentCallsPossible()
                     && allCallsSupportHold(connection)) {
@@ -4771,8 +5029,47 @@ public class TelephonyConnectionService extends ConnectionService {
         return null;
     }
 
-    private void disconnectAllCallsOnOtherSubs (@NonNull PhoneAccountHandle handle) {
-        Collection<Connection>connections = getAllConnections();
+    /**
+     * For DSDA devices, disconnects all calls (and conferences) on other subs when placing an
+     * emergency call.
+     * @param handle The {@link PhoneAccountHandle} to exclude when disconnecting calls
+     * @return {@link List} compromised of the conferenceables that have been disconnected.
+     */
+    @VisibleForTesting
+    protected List<Conferenceable> disconnectAllConferenceablesOnOtherSubs(
+            @NonNull PhoneAccountHandle handle) {
+        List<Conferenceable> conferenceables = new ArrayList<>();
+        Collection<Conference> conferences = getAllConferences();
+        // Add the conferences
+        conferences.stream()
+                .filter(c ->
+                        (c.getState() == Connection.STATE_ACTIVE
+                                || c.getState() == Connection.STATE_HOLDING)
+                                // Include any calls not on same sub as current connection.
+                                && !Objects.equals(c.getPhoneAccountHandle(), handle))
+                .forEach(c -> {
+                    if (c instanceof TelephonyConference) {
+                        TelephonyConference tc = (TelephonyConference) c;
+                        Log.i(LOG_TAG, "disconnectAllConferenceablesOnOtherSubs: disconnect"
+                                        + " %s due to redial happened on other sub.",
+                                tc.getTelecomCallId());
+                        tc.onDisconnect();
+                        conferenceables.add(c);
+                    }
+                });
+        // Add the connections.
+        conferenceables.addAll(disconnectAllCallsOnOtherSubs(handle));
+        return conferenceables;
+    }
+
+    /**
+     * For DSDA devices, disconnects all calls on other subs when placing an emergency call.
+     * @param handle The {@link PhoneAccountHandle} to exclude when disconnecting calls
+     * @return {@link List} including compromised of the connections that have been disconnected.
+     */
+    private List<Connection> disconnectAllCallsOnOtherSubs(@NonNull PhoneAccountHandle handle) {
+        Collection<Connection> connections = getAllConnections();
+        List<Connection> disconnectedConnections = new ArrayList<>();
         connections.stream()
                 .filter(c ->
                         (c.getState() == Connection.STATE_ACTIVE
@@ -4786,8 +5083,10 @@ public class TelephonyConnectionService extends ConnectionService {
                                 " %s due to redial happened on other sub.",
                                 tc.getTelecomCallId());
                         tc.hangup(android.telephony.DisconnectCause.LOCAL);
+                        disconnectedConnections.add(c);
                     }
                 });
+        return disconnectedConnections;
     }
 
     private @NetworkRegistrationInfo.Domain int getActiveCallDomain(int subId) {
@@ -4839,28 +5138,58 @@ public class TelephonyConnectionService extends ConnectionService {
      * else {@code false}.
      */
     private boolean isCallDisallowedDueToSatellite(Phone phone) {
-        if (!carrierEnabledSatelliteFlag()) {
+        if (phone == null) {
             return false;
         }
 
+        if (!mSatelliteController.isInSatelliteModeForCarrierRoaming(phone)) {
+            // Phone is not connected to carrier roaming ntn
+            return false;
+        }
+
+        if (isVoiceSupportedInSatelliteMode(phone)) {
+            // Call is supported in satellite mode
+            return false;
+        }
+
+        // Call is disallowed while using satellite
+        return true;
+    }
+
+    private boolean isCallDisallowedDueToNtnEligibility(@Nullable Phone phone) {
         if (phone == null) {
+            Log.d(this, "isCallDisallowedDueToNtnEligibility: phone is null");
             return false;
         }
 
-        if (!mSatelliteController.isInSatelliteModeForCarrierRoaming(phone)) {
-            // Device is not connected to satellite
+        if (!mSatelliteController.getLastNotifiedNtnEligibility(phone)) {
+            // Phone is not carrier roaming ntn eligible
+            Log.d(this, "isCallDisallowedDueToNtnEligibility: eligibility is false");
+            return false;
+        }
+
+        if (isVoiceSupportedInSatelliteMode(phone)) {
+            // Call is supported in satellite mode
+            Log.d(this, "isCallDisallowedDueToNtnEligibility: voice is supported");
             return false;
         }
 
+        // Call is disallowed while eligibility is true
+        Log.d(this, "isCallDisallowedDueToNtnEligibility: return true");
+        return true;
+    }
+
+    private boolean isVoiceSupportedInSatelliteMode(@NonNull Phone phone) {
         List<Integer> capabilities =
                 mSatelliteController.getCapabilitiesForCarrierRoamingSatelliteMode(phone);
         if (capabilities.contains(NetworkRegistrationInfo.SERVICE_TYPE_VOICE)) {
-            // Call is supported while using satellite
-            return false;
+            // Call is supported in satellite mode
+            Log.d(this, "isVoiceSupportedInSatelliteMode: voice is supported");
+            return true;
         }
 
-        // Call is disallowed while using satellite
-        return true;
+        Log.d(this, "isVoiceSupportedInSatelliteMode: voice is not supported");
+        return false;
     }
 
     private boolean getTurnOffOemEnabledSatelliteDuringEmergencyCall() {
@@ -4888,8 +5217,10 @@ public class TelephonyConnectionService extends ConnectionService {
 
     /* Only for testing */
     @VisibleForTesting
-    public void setFeatureFlags(FeatureFlags featureFlags) {
+    public void setFeatureFlags(FeatureFlags featureFlags,
+            com.android.server.telecom.flags.FeatureFlags telecomFlags) {
         mFeatureFlags = featureFlags;
+        mTelecomFlags = telecomFlags;
     }
 
     private void loge(String s) {
diff --git a/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelector.java b/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelector.java
index 0d373de24..2b4f2b9f0 100644
--- a/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelector.java
+++ b/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelector.java
@@ -55,6 +55,8 @@ import static android.telephony.CarrierConfigManager.ImsEmergency.VOWIFI_REQUIRE
 import static android.telephony.CarrierConfigManager.ImsWfc.KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL;
 import static android.telephony.NetworkRegistrationInfo.REGISTRATION_STATE_HOME;
 import static android.telephony.NetworkRegistrationInfo.REGISTRATION_STATE_ROAMING;
+import static android.telephony.NrVopsSupportInfo.NR_STATUS_EMC_5GCN_ONLY;
+import static android.telephony.NrVopsSupportInfo.NR_STATUS_EMC_NR_EUTRA_5GCN;
 import static android.telephony.PreciseDisconnectCause.EMERGENCY_PERM_FAILURE;
 import static android.telephony.PreciseDisconnectCause.EMERGENCY_TEMP_FAILURE;
 import static android.telephony.PreciseDisconnectCause.NO_VALID_SIM;
@@ -1354,7 +1356,8 @@ public class EmergencyCallDomainSelector extends DomainSelectorBase
                 return UNKNOWN;
             }
             if (accessNetwork == NGRAN) {
-                return (regResult.getNwProvidedEmc() > 0
+                return ((regResult.getNwProvidedEmc() == NR_STATUS_EMC_5GCN_ONLY
+                        || regResult.getNwProvidedEmc() == NR_STATUS_EMC_NR_EUTRA_5GCN)
                         && (regResult.isVopsSupported() || !inService))
                         ? NGRAN : UNKNOWN;
             } else if (accessNetwork == EUTRAN) {
diff --git a/src/com/android/services/telephony/domainselection/NormalCallDomainSelector.java b/src/com/android/services/telephony/domainselection/NormalCallDomainSelector.java
index a7ed708dc..1bce40521 100644
--- a/src/com/android/services/telephony/domainselection/NormalCallDomainSelector.java
+++ b/src/com/android/services/telephony/domainselection/NormalCallDomainSelector.java
@@ -232,7 +232,7 @@ public class NormalCallDomainSelector extends DomainSelectorBase implements
 
     @Override
     public void onServiceStateUpdated(ServiceState serviceState) {
-        logd("onServiceStateUpdated");
+        logd("onServiceStateUpdated:" + serviceState.getState());
         mServiceState = serviceState;
         selectDomain();
     }
@@ -265,8 +265,8 @@ public class NormalCallDomainSelector extends DomainSelectorBase implements
         }
     }
 
-    private void notifyCsSelected() {
-        if (isOutOfService()) {
+    private void notifyCsSelected(boolean checkServiceState) {
+        if (checkServiceState && isOutOfService()) {
             loge("Cannot place call in current ServiceState: " + mServiceState.getState());
             notifySelectionTerminated(DisconnectCause.OUT_OF_SERVICE);
             return;
@@ -327,7 +327,7 @@ public class NormalCallDomainSelector extends DomainSelectorBase implements
             notifyPsSelected();
         } else {
             logd("WPS call placed over CS");
-            notifyCsSelected();
+            notifyCsSelected(true);
         }
     }
 
@@ -339,7 +339,9 @@ public class NormalCallDomainSelector extends DomainSelectorBase implements
             logd("PsDisconnectCause:" + imsReasonInfo.getCode());
             if (imsReasonInfo.getCode() == ImsReasonInfo.CODE_LOCAL_CALL_CS_RETRY_REQUIRED) {
                 logd("Redialing over CS");
-                notifyCsSelected();
+                // Don't check for ServiceState when CODE_LOCAL_CALL_CS_RETRY_REQUIRED is received
+                // as requested here b/380412925.
+                notifyCsSelected(false);
             } else {
                 // Not a valid redial
                 logd("Redialing cancelled.");
@@ -410,7 +412,7 @@ public class NormalCallDomainSelector extends DomainSelectorBase implements
 
         if (!mImsStateTracker.isMmTelFeatureAvailable()) {
             logd("MmTelFeatureAvailable unavailable");
-            notifyCsSelected();
+            notifyCsSelected(true);
             return;
         }
 
@@ -426,13 +428,13 @@ public class NormalCallDomainSelector extends DomainSelectorBase implements
         // Check IMS registration state.
         if (!mImsStateTracker.isImsRegistered()) {
             logd("IMS is NOT registered");
-            notifyCsSelected();
+            notifyCsSelected(true);
             return;
         }
 
         // Check TTY
         if (isTtyModeEnabled() && !isTtySupportedByIms()) {
-            notifyCsSelected();
+            notifyCsSelected(true);
             return;
         }
 
@@ -461,7 +463,7 @@ public class NormalCallDomainSelector extends DomainSelectorBase implements
         } else {
             logd("IMS is not voice capable");
             // Voice call CS fallback
-            notifyCsSelected();
+            notifyCsSelected(true);
         }
     }
 
diff --git a/src/com/android/services/telephony/rcs/SipTransportController.java b/src/com/android/services/telephony/rcs/SipTransportController.java
index 2f090d564..efd3e8399 100644
--- a/src/com/android/services/telephony/rcs/SipTransportController.java
+++ b/src/com/android/services/telephony/rcs/SipTransportController.java
@@ -823,7 +823,7 @@ public class SipTransportController implements RcsFeatureController.Feature,
         mEvaluateCompleteFuture = pendingChange
                 .whenComplete((f, ex) -> {
                     if (ex != null) {
-                        logw("reevaluateDelegates: Exception caught: " + ex);
+                        logw("reevaluateDelegates: Exception caught", ex);
                     }
                 }).thenAccept((associatedFeatures) -> {
                     logi("reevaluateDelegates: reevaluate complete, feature tags associated: "
@@ -977,8 +977,9 @@ public class SipTransportController implements RcsFeatureController.Feature,
      */
     private Set<FeatureTagState> updateSupportedTags(Set<String> candidateFeatureTags,
             Set<String> previouslyGrantedTags) {
-        Boolean overrideRes = RcsProvisioningMonitor.getInstance()
-                .getImsFeatureValidationOverride(mSubId);
+        RcsProvisioningMonitor monitor = RcsProvisioningMonitor.getInstance();
+        Boolean overrideRes = monitor == null ? null :
+                monitor.getImsFeatureValidationOverride(mSubId);
         // deny tags already used by other delegates
         Set<FeatureTagState> deniedTags = new ArraySet<>();
 
@@ -1212,4 +1213,9 @@ public class SipTransportController implements RcsFeatureController.Feature,
         Log.w(LOG_TAG, "[" + mSlotId  + "->" + mSubId + "] " + log);
         mLocalLog.log("[W] " + log);
     }
+
+    private void logw(String log, Throwable ex) {
+        Log.w(LOG_TAG, "[" + mSlotId  + "->" + mSubId + "] " + log, ex);
+        mLocalLog.log("[W] " + log + ": " + ex);
+    }
 }
diff --git a/testapps/TelephonyManagerTestApp/Android.bp b/testapps/TelephonyManagerTestApp/Android.bp
index 0ff917e83..28cad7635 100644
--- a/testapps/TelephonyManagerTestApp/Android.bp
+++ b/testapps/TelephonyManagerTestApp/Android.bp
@@ -9,4 +9,7 @@ android_test {
     javacflags: ["-parameters"],
     platform_apis: true,
     certificate: "platform",
+    static_libs: [
+        "androidx.appcompat_appcompat",
+    ],
 }
diff --git a/testapps/TelephonyManagerTestApp/AndroidManifest.xml b/testapps/TelephonyManagerTestApp/AndroidManifest.xml
index 6392c26b6..dd1d624f4 100644
--- a/testapps/TelephonyManagerTestApp/AndroidManifest.xml
+++ b/testapps/TelephonyManagerTestApp/AndroidManifest.xml
@@ -41,6 +41,20 @@
             </meta-data>
         </activity>
 
+        <activity android:name=".NumberVerificationActivity"
+            android:label="Number Verification"
+            android:exported="true">
+            <intent-filter>
+                <action android:name="android.intent.action.MAIN"/>
+                <action android:name="android.intent.action.SEARCH"/>
+                <category android:name="android.intent.category.DEFAULT"/>
+                <category android:name="android.intent.category.LAUNCHER"/>
+            </intent-filter>
+            <meta-data android:name="android.app.searchable"
+                android:resource="@xml/searchable">
+            </meta-data>
+        </activity>
+
         <activity android:name=".CallingMethodActivity"
              android:label="CallingMethodActivity"
              android:exported="true">
diff --git a/testapps/TelephonyManagerTestApp/res/layout/number_verification.xml b/testapps/TelephonyManagerTestApp/res/layout/number_verification.xml
new file mode 100644
index 000000000..a82e54e0d
--- /dev/null
+++ b/testapps/TelephonyManagerTestApp/res/layout/number_verification.xml
@@ -0,0 +1,99 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:orientation="vertical" >
+    <LinearLayout
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:orientation="horizontal" >
+        <TextView
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textSize="15dp"
+            android:text="Country Code:" />
+        <EditText
+            android:id="@+id/countryCode"
+            android:inputType="text"
+            android:text="100"
+            android:layout_width="50dp"
+            android:layout_height="wrap_content" />
+    </LinearLayout>
+    <LinearLayout
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:orientation="horizontal" >
+        <TextView
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textSize="15dp"
+            android:text="Prefix:" />
+        <EditText
+            android:id="@+id/prefix"
+            android:inputType="text"
+            android:text="100"
+            android:layout_width="50dp"
+            android:layout_height="wrap_content" />
+    </LinearLayout>
+    <LinearLayout
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:orientation="horizontal" >
+        <TextView
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textSize="15dp"
+            android:text="Lower Bound:" />
+        <EditText
+            android:id="@+id/lowerBound"
+            android:inputType="text"
+            android:text="100"
+            android:layout_width="50dp"
+            android:layout_height="wrap_content" />
+    </LinearLayout>
+    <LinearLayout
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:orientation="horizontal" >
+        <TextView
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:textSize="15dp"
+            android:text="Upper Bound:" />
+        <EditText
+            android:id="@+id/upperBound"
+            android:inputType="text"
+            android:text="100"
+            android:layout_width="50dp"
+            android:layout_height="wrap_content" />
+    </LinearLayout>
+
+    <Button
+        android:id="@+id/request_verification_button"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:text="Request Verification" />
+
+    <TextView
+        android:id="@+id/verificationResult"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:textSize="15dp"
+        android:text="result" />
+</LinearLayout>
diff --git a/testapps/TelephonyManagerTestApp/src/com/android/phone/testapps/telephonymanagertestapp/NumberVerificationActivity.java b/testapps/TelephonyManagerTestApp/src/com/android/phone/testapps/telephonymanagertestapp/NumberVerificationActivity.java
new file mode 100644
index 000000000..81ffe3686
--- /dev/null
+++ b/testapps/TelephonyManagerTestApp/src/com/android/phone/testapps/telephonymanagertestapp/NumberVerificationActivity.java
@@ -0,0 +1,97 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.phone.testapps.telephonymanagertestapp;
+
+import android.app.Activity;
+import android.os.Bundle;
+import android.telephony.NumberVerificationCallback;
+import android.telephony.PhoneNumberRange;
+import android.telephony.TelephonyManager;
+import android.widget.Button;
+import android.widget.EditText;
+import android.widget.TextView;
+
+import androidx.annotation.NonNull;
+import androidx.core.graphics.Insets;
+import androidx.core.view.ViewCompat;
+import androidx.core.view.WindowInsetsCompat;
+
+public class NumberVerificationActivity extends Activity {
+    private EditText mCountryCode;
+    private EditText mPrefix;
+    private EditText mLowerBound;
+    private EditText mUpperBound;
+    private Button mRequestVerificationButton;
+    private TextView mResultField;
+    private TelephonyManager mTelephonyManager;
+
+    private NumberVerificationCallback mCallback = new NumberVerificationCallback() {
+        @Override
+        public void onCallReceived(@NonNull String phoneNumber) {
+            mResultField.setText("Received call from " + phoneNumber);
+        }
+
+        @Override
+        public void onVerificationFailed(int reason) {
+            mResultField.setText("Verification failed " + reason);
+        }
+    };
+
+    @Override
+    protected void onCreate(Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
+        setContentView(R.layout.number_verification);
+        setupEdgeToEdge(this);
+        mTelephonyManager = getSystemService(TelephonyManager.class);
+        mCountryCode = findViewById(R.id.countryCode);
+        mPrefix = findViewById(R.id.prefix);
+        mLowerBound = findViewById(R.id.lowerBound);
+        mUpperBound = findViewById(R.id.upperBound);
+        mRequestVerificationButton = findViewById(R.id.request_verification_button);
+        mRequestVerificationButton.setOnClickListener(v -> {
+            mTelephonyManager.requestNumberVerification(
+                    new PhoneNumberRange(mCountryCode.getText().toString(),
+                            mPrefix.getText().toString(), mLowerBound.getText().toString(),
+                            mUpperBound.getText().toString()),
+                    60000,
+                    getMainExecutor(),
+                    mCallback
+            );
+        });
+        mResultField = findViewById(R.id.verificationResult);
+    }
+
+    /**
+     * Given an activity, configure the activity to adjust for edge to edge restrictions.
+     *
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
+}
diff --git a/testapps/TestSatelliteApp/Android.bp b/testapps/TestSatelliteApp/Android.bp
index 78d125db2..a48c60b6f 100644
--- a/testapps/TestSatelliteApp/Android.bp
+++ b/testapps/TestSatelliteApp/Android.bp
@@ -14,6 +14,8 @@ android_app {
     static_libs: [
         "SatelliteClient",
     ],
+    min_sdk_version: "35",
+    target_sdk_version: "35",
     owner: "google",
     privileged: true,
     certificate: "platform",
diff --git a/testapps/TestSatelliteApp/AndroidManifest.xml b/testapps/TestSatelliteApp/AndroidManifest.xml
index a1f22fa4b..de455f21f 100644
--- a/testapps/TestSatelliteApp/AndroidManifest.xml
+++ b/testapps/TestSatelliteApp/AndroidManifest.xml
@@ -1,5 +1,4 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
+<?xml version="1.0" encoding="utf-8"?><!--
   ~ Copyright (C) 2024 The Android Open Source Project
   ~
   ~ Licensed under the Apache License, Version 2.0 (the "License");
@@ -17,31 +16,21 @@
 
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.android.phone.testapps.satellitetestapp">
-    <uses-permission android:name="android.permission.BIND_SATELLITE_SERVICE"/>
-    <uses-permission android:name="android.permission.SATELLITE_COMMUNICATION"/>
-    <uses-permission android:name="android.permission.READ_PRIVILEGED_PHONE_STATE"/>
-    <uses-permission android:name="android.permission.SEND_SMS"/>
-    <application android:label="SatelliteTestApp">
-        <activity android:name=".SatelliteTestApp"
-             android:label="SatelliteTestApp"
-             android:exported="true">
-            <intent-filter>
-                <action android:name="android.intent.action.MAIN"/>
-                <category android:name="android.intent.category.DEFAULT"/>
-                <category android:name="android.intent.category.LAUNCHER"/>
-            </intent-filter>
-        </activity>
 
-        <service android:name=".TestSatelliteService"
-             android:directBootAware="true"
-             android:persistent="true"
-             android:permission="android.permission.BIND_SATELLITE_SERVICE"
-             android:exported="true">
+    <application
+        android:networkSecurityConfig="@xml/network_security_config"
+        android:label="SatelliteTestApp">
+        <activity
+            android:name=".SatelliteTestApp"
+            android:exported="true"
+            android:label="SatelliteTestApp">
             <intent-filter>
-                <action android:name="android.telephony.satellite.SatelliteService"/>
-            </intent-filter>
-        </service>
+                <action android:name="android.intent.action.MAIN" />
 
+                <category android:name="android.intent.category.DEFAULT" />
+                <category android:name="android.intent.category.LAUNCHER" />
+            </intent-filter>
+        </activity>
         <activity android:name=".SatelliteControl" />
         <activity android:name=".Datagram" />
         <activity android:name=".Provisioning" />
@@ -49,5 +38,36 @@
         <activity android:name=".SendReceive" />
         <activity android:name=".NbIotSatellite" />
         <activity android:name=".TestSatelliteWrapper" />
+
+        <receiver
+            android:name=".SatelliteTestAppReceiver"
+            android:exported="true">
+            <intent-filter>
+                <action android:name="com.android.phone.testapps.satellitetestapp.RECEIVER" />
+            </intent-filter>
+        </receiver>
+
+        <service
+            android:name=".TestSatelliteService"
+            android:directBootAware="true"
+            android:exported="true"
+            android:permission="android.permission.BIND_SATELLITE_SERVICE"
+            android:persistent="true">
+            <intent-filter>
+                <action android:name="android.telephony.satellite.SatelliteService" />
+            </intent-filter>
+        </service>
+
+        <meta-data
+            android:name="android.telephony.PROPERTY_SATELLITE_DATA_OPTIMIZED"
+            android:value="true"/>
     </application>
+
+    <uses-permission android:name="android.permission.SATELLITE_COMMUNICATION" />
+    <uses-permission android:name="android.permission.READ_PRIVILEGED_PHONE_STATE" />
+    <uses-permission android:name="android.permission.SEND_SMS" />
+    <uses-permission android:name="android.permission.BIND_SATELLITE_SERVICE" />
+    <uses-permission android:name="android.permission.CHANGE_NETWORK_STATE" />
+    <uses-permission android:name="android.permission.WRITE_SETTINGS" />
+    <uses-permission android:name="android.permission.INTERNET" />
 </manifest>
diff --git a/testapps/TestSatelliteApp/res/layout/activity_SatelliteTestApp.xml b/testapps/TestSatelliteApp/res/layout/activity_SatelliteTestApp.xml
index 26b45e309..43cce9b27 100644
--- a/testapps/TestSatelliteApp/res/layout/activity_SatelliteTestApp.xml
+++ b/testapps/TestSatelliteApp/res/layout/activity_SatelliteTestApp.xml
@@ -81,5 +81,12 @@
             android:paddingStart="4dp"
             android:paddingEnd="4dp"
             android:text="@string/TestSatelliteWrapper"/>
+        <Button
+            android:id="@+id/TestSatelliteConstrainConnection"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingStart="4dp"
+            android:paddingEnd="4dp"
+            android:text="@string/TestSatelliteConstrainConnection"/>
     </LinearLayout>
 </ScrollView>
diff --git a/testapps/TestSatelliteApp/res/values/donottranslate_strings.xml b/testapps/TestSatelliteApp/res/values/donottranslate_strings.xml
index 5c3a72d82..f48c022d2 100644
--- a/testapps/TestSatelliteApp/res/values/donottranslate_strings.xml
+++ b/testapps/TestSatelliteApp/res/values/donottranslate_strings.xml
@@ -62,6 +62,8 @@
     <string name="sendMessage">sendMessage</string>
     <string name="receiveMessage">receiveMessage</string>
 
+    <string name="TestSatelliteConstrainConnection">Test Satellite Constrain Connection</string>
+
     <string name="TestSatelliteWrapper">Test Satellite Wrapper</string>
     <string name="requestNtnSignalStrength">requestNtnSignalStrength</string>
     <string name="registerForNtnSignalStrengthChanged">registerForNtnSignalStrengthChanged</string>
diff --git a/testapps/TestSatelliteApp/res/xml/network_security_config.xml b/testapps/TestSatelliteApp/res/xml/network_security_config.xml
new file mode 100644
index 000000000..463e65a2e
--- /dev/null
+++ b/testapps/TestSatelliteApp/res/xml/network_security_config.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
+<network-security-config>
+  <domain-config cleartextTrafficPermitted="true">
+    <domain includeSubdomains="true">www.google.com</domain>
+  </domain-config>
+</network-security-config>
\ No newline at end of file
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/NbIotSatellite.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/NbIotSatellite.java
index 17646f0ee..86713200c 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/NbIotSatellite.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/NbIotSatellite.java
@@ -25,13 +25,13 @@ import android.content.SharedPreferences;
 import android.os.Bundle;
 import android.os.OutcomeReceiver;
 import android.telephony.satellite.SatelliteManager;
-import android.telephony.satellite.SatelliteSupportedStateCallback;
 import android.util.Log;
 import android.view.View;
 import android.view.View.OnClickListener;
 import android.widget.TextView;
 
 import java.util.concurrent.atomic.AtomicReference;
+import java.util.function.Consumer;
 
 /**
  * Activity related to NB IoT satellite APIs.
@@ -76,9 +76,9 @@ public class NbIotSatellite extends Activity {
         mTextView = findViewById(R.id.text_id);
     }
 
-    protected class TestSatelliteSupportedStateCallback implements SatelliteSupportedStateCallback {
+    protected class TestSatelliteSupportedStateCallback implements Consumer<Boolean> {
         @Override
-        public void onSatelliteSupportedStateChanged(boolean supported) {
+        public void accept(Boolean supported) {
             mSatelliteSupported = supported;
             updateLogMessage("onSatelliteSupportedStateChanged: "
                     + (mSatelliteSupported ? "Satellite is supported"
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/PingTask.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/PingTask.java
new file mode 100644
index 000000000..fe86c2109
--- /dev/null
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/PingTask.java
@@ -0,0 +1,69 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.phone.testapps.satellitetestapp;
+
+import android.net.Network;
+import android.os.AsyncTask;
+import android.util.Log;
+
+import java.io.IOException;
+import java.io.InputStream;
+import java.net.HttpURLConnection;
+import java.net.URL;
+import java.util.Scanner;
+
+class PingTask extends AsyncTask<Network, Integer, Integer> {
+  protected Integer doInBackground(Network... network) {
+    ping(network[0]);
+    return 0;
+  }
+  String ping(Network network) {
+    URL url = null;
+    try {
+      url = new URL("http://www.google.com");
+    } catch (Exception e) {
+      Log.d("SatelliteDataConstrained", "exception: " + e);
+    }
+    if (url != null) {
+      try {
+        Log.d("SatelliteDataConstrained", "ping " + url);
+        String result = httpGet(network, url);
+        Log.d("SatelliteDataConstrained", "Ping Success");
+        return result;
+      } catch (Exception e) {
+        Log.d("SatelliteDataConstrained", "exception: " + e);
+      }
+    }
+    return null;
+  }
+
+  /**
+   * Performs a HTTP GET to the specified URL on the specified Network, and returns
+   * the response body decoded as UTF-8.
+   */
+  private static String httpGet(Network network, URL httpUrl) throws IOException {
+    HttpURLConnection connection = (HttpURLConnection) network.openConnection(httpUrl);
+    try {
+      InputStream inputStream = connection.getInputStream();
+      Log.d("httpGet", "httpUrl + " + httpUrl);
+      Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
+      return scanner.hasNext() ? scanner.next() : "";
+    } finally {
+      connection.disconnect();
+    }
+  }
+}
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteControl.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteControl.java
index 484a6d15f..831c7b2aa 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteControl.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteControl.java
@@ -441,11 +441,11 @@ public class SatelliteControl extends Activity {
     private void provisionSatelliteApp(View view) {
         final AtomicReference<Boolean> enabled = new AtomicReference<>();
         final AtomicReference<Integer> errorCode = new AtomicReference<>();
-        OutcomeReceiver<Boolean, SatelliteManager.SatelliteException> receiver =
+        OutcomeReceiver<Void, SatelliteManager.SatelliteException> receiver =
                 new OutcomeReceiver<>() {
                     @Override
-                    public void onResult(Boolean result) {
-                        enabled.set(result);
+                    public void onResult(Void result) {
+                        enabled.set(true);
                         TextView textView = findViewById(R.id.text_id);
                         if (enabled.get()) {
                             textView.setText("provisionSatellite is true");
@@ -473,11 +473,11 @@ public class SatelliteControl extends Activity {
     private void deprovisionSatelliteApp(View view) {
         final AtomicReference<Boolean> enabled = new AtomicReference<>();
         final AtomicReference<Integer> errorCode = new AtomicReference<>();
-        OutcomeReceiver<Boolean, SatelliteManager.SatelliteException> receiver =
+        OutcomeReceiver<Void, SatelliteManager.SatelliteException> receiver =
                 new OutcomeReceiver<>() {
                     @Override
-                    public void onResult(Boolean result) {
-                        enabled.set(result);
+                    public void onResult(Void result) {
+                        enabled.set(true);
                         TextView textView = findViewById(R.id.text_id);
                         if (enabled.get()) {
                             textView.setText("deprovisionSatellite is true");
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteTestApp.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteTestApp.java
index cb56e87a8..911e179af 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteTestApp.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteTestApp.java
@@ -23,15 +23,24 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.ServiceConnection;
 import android.content.pm.PackageManager;
+import android.net.ConnectivityManager;
+import android.net.ConnectivityManager.NetworkCallback;
+import android.net.Network;
+import android.net.NetworkCapabilities;
+import android.net.NetworkRequest;
 import android.os.Bundle;
+import android.os.Looper;
 import android.os.IBinder;
 import android.telephony.satellite.stub.SatelliteDatagram;
 import android.util.Log;
 import android.view.View;
 import android.view.View.OnClickListener;
+import android.widget.Toast;
 
 import java.util.ArrayList;
 import java.util.List;
+import java.util.concurrent.ExecutorService;
+import java.util.concurrent.Executors;
 
 /**
  * SatelliteTestApp main activity to navigate to other APIs related to satellite.
@@ -41,14 +50,23 @@ public class SatelliteTestApp extends Activity {
     private static final String TAG = "SatelliteTestApp";
     public static TestSatelliteService sSatelliteService;
     private final Object mSendDatagramLock = new Object();
-
+    Network mNetwork = null;
+    Context mContext;
+    ConnectivityManager mConnectivityManager;
+    NetworkCallback mSatelliteConstrainNetworkCallback;
+    private final ExecutorService executor = Executors.newSingleThreadExecutor();
     private TestSatelliteServiceConnection mSatelliteServiceConn;
     private List<SatelliteDatagram> mSentSatelliteDatagrams = new ArrayList<>();
     private static final int REQUEST_CODE_SEND_SMS = 1;
+    private final int NET_CAPABILITY_NOT_BANDWIDTH_CONSTRAINED = 37;
+    private boolean isNetworkRequested = false;
 
     @Override
     public void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
+        mContext = getApplicationContext();
+
+        mConnectivityManager = getSystemService(ConnectivityManager.class);
 
         if (mSatelliteServiceConn == null) {
             mSatelliteServiceConn = new TestSatelliteServiceConnection();
@@ -106,6 +124,21 @@ public class SatelliteTestApp extends Activity {
                 startActivity(intent);
             }
         });
+
+      findViewById(R.id.TestSatelliteConstrainConnection).setOnClickListener(view -> {
+        executor.execute(() -> {
+          Log.e(TAG, "onClick");
+          mSatelliteConstrainNetworkCallback = new NetworkCallback() {
+            @Override
+            public void onAvailable(final Network network) {
+              makeSatelliteDataConstrainedPing(network);
+            }
+          };
+          if(isNetworkRequested == false) {
+            requestingNetwork();
+          }
+        });
+      });
     }
 
     @Override
@@ -117,6 +150,61 @@ public class SatelliteTestApp extends Activity {
         }
     }
 
+    @Override
+    protected void onDestroy() {
+      super.onDestroy();
+      if(isNetworkRequested == true) {
+        releasingNetwork();
+      }
+    }
+
+    private void requestingNetwork() {
+      Log.e(TAG, "Requesting Network");
+      isNetworkRequested = true;
+      NetworkRequest request = new NetworkRequest.Builder()
+          .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
+          .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VCN_MANAGED)
+          .removeCapability(NET_CAPABILITY_NOT_BANDWIDTH_CONSTRAINED)
+          .addTransportType(NetworkCapabilities.TRANSPORT_SATELLITE)
+          .build();
+
+      // Requesting for Network
+      mConnectivityManager.requestNetwork(request, mSatelliteConstrainNetworkCallback);
+      Log.e(TAG, "onClick + " + request);
+    }
+
+
+    private void makeSatelliteDataConstrainedPing(final Network network) {
+      Log.e(TAG, "onAvailable + " + network);
+      mNetwork = network;
+
+      try {
+        PingTask pingTask = new PingTask();
+        Log.d(TAG, "Connecting Satellite for ping");
+        String pingResult = pingTask.ping(mNetwork);
+        if(pingResult != null) {
+          Toast.makeText(mContext, "Ping Passed!", Toast.LENGTH_SHORT).show();
+        } else {
+          Toast.makeText(mContext, "Ping Failed!", Toast.LENGTH_SHORT).show();
+        }
+      } catch (Exception e) {
+        Log.d(TAG, "Exception at ping: " + e);
+      } finally {
+        // Releasing the callback in the background thread
+        releasingNetwork();
+      }
+    }
+
+    private void releasingNetwork() {
+      Log.e(TAG, "Realsing Network");
+      try {
+        mConnectivityManager
+            .unregisterNetworkCallback(mSatelliteConstrainNetworkCallback);
+      } catch (Exception e) {
+        Log.d("SatelliteDataConstrined", "Exception: " + e);
+      }
+      isNetworkRequested = false;
+    }
 
     private final ILocalSatelliteListener mSatelliteListener =
             new ILocalSatelliteListener.Stub() {
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteTestAppReceiver.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteTestAppReceiver.java
new file mode 100644
index 000000000..693ac7a2b
--- /dev/null
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteTestAppReceiver.java
@@ -0,0 +1,167 @@
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
+package com.android.phone.testapps.satellitetestapp;
+
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.os.CancellationSignal;
+import android.telephony.satellite.EnableRequestAttributes;
+import android.telephony.satellite.SatelliteManager;
+import android.telephony.satellite.stub.SatelliteResult;
+import android.util.Log;
+
+import java.util.Objects;
+import java.util.concurrent.LinkedBlockingQueue;
+import java.util.concurrent.TimeUnit;
+
+public class SatelliteTestAppReceiver extends BroadcastReceiver {
+    private static final String TAG = "SatelliteTestAppRcvr";
+
+    private static final long TEST_REQUEST_TIMEOUT = TimeUnit.SECONDS.toMillis(3);
+    private static final String TEST_SATELLITE_TOKEN = "SATELLITE_TOKEN";
+    private static final String ACTION = "com.android.phone.testapps.satellitetestapp.RECEIVER";
+    private static final String ACTION_PROVISION = "provision";
+    private static final String ACTION_DEPROVISION = "deprovision";
+    private static final String ACTION_ENABLE = "enable";
+    private static final String ACTION_DISABLE = "disable";
+    private static final String PARAM_ACTION_KEY = "action_key";
+    private static final String PARAM_DEMO_MODE = "demo_mode";
+
+    private static SatelliteManager mSatelliteManager;
+
+
+    @Override
+    public void onReceive(Context context, Intent intent) {
+        Log.d(TAG, "onReceive: intent: " + intent.toString());
+
+        String action = intent.getAction();
+        if (!Objects.equals(action, ACTION)) {
+            Log.d(TAG, "Unsupported action: " + action + ", exiting.");
+            return;
+        }
+
+        String param = intent.getStringExtra(PARAM_ACTION_KEY);
+        if (param == null) {
+            Log.d(TAG, "No param provided, exiting");
+            return;
+        }
+
+        if (mSatelliteManager == null) {
+            mSatelliteManager = context.getSystemService(SatelliteManager.class);
+        }
+
+        if (mSatelliteManager == null) {
+            Log.d(TAG, "Satellite Manager is not available, exiting.");
+            return;
+        }
+
+        switch (param) {
+            case ACTION_PROVISION -> provisionSatellite();
+            case ACTION_DEPROVISION -> deprovisionSatellite();
+            case ACTION_ENABLE -> {
+                boolean demoMode = intent.getBooleanExtra(PARAM_DEMO_MODE, true);
+                enableSatellite(demoMode);
+            }
+            case ACTION_DISABLE -> disableSatellite();
+            default -> Log.d(TAG, "Unsupported param:" + param);
+        }
+    }
+
+    private void provisionSatellite() {
+        CancellationSignal cancellationSignal = new CancellationSignal();
+        LinkedBlockingQueue<Integer> error = new LinkedBlockingQueue<>(1);
+        String mText = "This is test provision data.";
+        byte[] testProvisionData = mText.getBytes();
+        mSatelliteManager.provisionService(TEST_SATELLITE_TOKEN, testProvisionData,
+                cancellationSignal, Runnable::run, error::offer);
+        try {
+            Integer value = error.poll(TEST_REQUEST_TIMEOUT, TimeUnit.MILLISECONDS);
+            if (value == null) {
+                Log.d(TAG, "Timed out to provision the satellite");
+            } else if (value != SatelliteResult.SATELLITE_RESULT_SUCCESS) {
+                Log.d(TAG, "Failed to provision the satellite, error ="
+                        + SatelliteErrorUtils.mapError(value));
+            } else {
+                Log.d(TAG, "Successfully provisioned the satellite");
+            }
+        } catch (InterruptedException e) {
+            Log.d(TAG, "Provision SatelliteService exception caught =" + e);
+        }
+    }
+
+    private void deprovisionSatellite() {
+        LinkedBlockingQueue<Integer> error = new LinkedBlockingQueue<>(1);
+        mSatelliteManager.deprovisionService(TEST_SATELLITE_TOKEN, Runnable::run,
+                error::offer);
+        try {
+            Integer value = error.poll(TEST_REQUEST_TIMEOUT, TimeUnit.MILLISECONDS);
+            if (value == null) {
+                Log.d(TAG, "Timed out to deprovision the satellite");
+            } else if (value != SatelliteResult.SATELLITE_RESULT_SUCCESS) {
+                Log.d(TAG, "Failed to deprovision the satellite, error ="
+                        + SatelliteErrorUtils.mapError(value));
+            } else {
+                Log.d(TAG, "Successfully deprovisioned the satellite");
+            }
+        } catch (InterruptedException e) {
+            Log.d(TAG, "Deprovision SatelliteService exception caught =" + e);
+        }
+    }
+
+    private void enableSatellite(boolean isDemoMode) {
+        LinkedBlockingQueue<Integer> error = new LinkedBlockingQueue<>(1);
+        mSatelliteManager.requestEnabled(
+                new EnableRequestAttributes.Builder(true)
+                        .setDemoMode(isDemoMode)
+                        .setEmergencyMode(true)
+                        .build(), Runnable::run, error::offer);
+        Log.d(TAG, "enableSatelliteApp: isDemoMode=" + isDemoMode);
+        try {
+            Integer value = error.poll(TEST_REQUEST_TIMEOUT, TimeUnit.MILLISECONDS);
+            if (value == null) {
+                Log.d(TAG, "Timed out to enable the satellite");
+            } else if (value != SatelliteResult.SATELLITE_RESULT_SUCCESS) {
+                Log.d(TAG, "Failed to enable the satellite, error ="
+                        + SatelliteErrorUtils.mapError(value));
+            } else {
+                Log.d(TAG, "Successfully enabled the satellite");
+            }
+        } catch (InterruptedException e) {
+            Log.d(TAG, "Enable SatelliteService exception caught =" + e);
+        }
+    }
+
+    private void disableSatellite() {
+        LinkedBlockingQueue<Integer> error = new LinkedBlockingQueue<>(1);
+        mSatelliteManager.requestEnabled(new EnableRequestAttributes.Builder(false).build(),
+                Runnable::run, error::offer);
+        try {
+            Integer value = error.poll(TEST_REQUEST_TIMEOUT, TimeUnit.MILLISECONDS);
+            if (value == null) {
+                Log.d(TAG, "Timed out to enable the satellite");
+            } else if (value != SatelliteResult.SATELLITE_RESULT_SUCCESS) {
+                Log.d(TAG, "Failed to enable the satellite, error ="
+                        + SatelliteErrorUtils.mapError(value));
+            } else {
+                Log.d(TAG, "Successfully disabled the satellite");
+            }
+        } catch (InterruptedException e) {
+            Log.d(TAG, "Disable SatelliteService exception caught =" + e);
+        }
+    }
+}
diff --git a/tests/Android.bp b/tests/Android.bp
index 22b2f46e5..bc66408b5 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -60,4 +60,6 @@ android_test {
         "mts",
     ],
 
+    resource_dirs: ["res"],
+
 }
diff --git a/tests/res/raw/v15_satellite_access_config.json b/tests/res/raw/v15_satellite_access_config.json
new file mode 100644
index 000000000..fd5257ebd
--- /dev/null
+++ b/tests/res/raw/v15_satellite_access_config.json
@@ -0,0 +1,195 @@
+{
+  "access_control_configs": [
+    {
+      "config_id": 0,
+      "satellite_infos": [
+        {
+          "satellite_id": "967f8e86-fc27-4673-9343-a820280a14dd",
+          "satellite_position": {
+            "longitude": 10.25,
+            "altitude": 35793.1
+          },
+          "bands": [
+            256
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229360,
+              "end_earfcn": 229360
+            },
+            {
+              "start_earfcn": 229362,
+              "end_earfcn": 229362
+            },
+            {
+              "start_earfcn": 229364,
+              "end_earfcn": 229364
+            },
+            {
+              "start_earfcn": 229366,
+              "end_earfcn": 229366
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        101
+      ]
+    },
+    {
+      "config_id": 1,
+      "satellite_infos": [
+        {
+          "satellite_id": "c9d78ffa-ffa5-4d41-a81b-34693b33b496",
+          "satellite_position": {
+            "longitude": -101.3,
+            "altitude": 35786.0
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229011,
+              "end_earfcn": 229011
+            },
+            {
+              "start_earfcn": 229013,
+              "end_earfcn": 229013
+            },
+            {
+              "start_earfcn": 229015,
+              "end_earfcn": 229015
+            },
+            {
+              "start_earfcn": 229017,
+              "end_earfcn": 229017
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11,
+        1001
+      ]
+    },
+    {
+      "config_id": 2,
+      "satellite_infos": [
+        {
+          "satellite_id": "62de127d-ead1-481f-8524-b58e2664103a",
+          "satellite_position": {
+            "longitude": -98.0,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 228837,
+              "end_earfcn": 228837
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11,
+        1001
+      ]
+    },
+    {
+      "config_id": 3,
+      "satellite_infos": [
+        {
+          "satellite_id": "62de127d-ead1-481f-8524-b58e2664103a",
+          "satellite_position": {
+            "longitude": -98.0,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 228909,
+              "end_earfcn": 228909
+            },
+            {
+              "start_earfcn": 228919,
+              "end_earfcn": 228919
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11
+      ]
+    },
+    {
+      "config_id": 4,
+      "satellite_infos": [
+        {
+          "satellite_id": "c9d78ffa-ffa5-4d41-a81b-34693b33b496",
+          "satellite_position": {
+            "longitude": -101.3,
+            "altitude": 35786.0
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229011,
+              "end_earfcn": 229011
+            },
+            {
+              "start_earfcn": 229013,
+              "end_earfcn": 229013
+            },
+            {
+              "start_earfcn": 229015,
+              "end_earfcn": 229015
+            },
+            {
+              "start_earfcn": 229017,
+              "end_earfcn": 229017
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        12
+      ]
+    },
+    {
+      "config_id": 5,
+      "satellite_infos": [
+        {
+          "satellite_id": "62de127d-ead1-481f-8524-b58e2664103a",
+          "satellite_position": {
+            "longitude": -98.0,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 228919,
+              "end_earfcn": 228919
+            },
+            {
+              "start_earfcn": 228909,
+              "end_earfcn": 228909
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11,
+        1001
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/tests/res/raw/v15_sats2.dat b/tests/res/raw/v15_sats2.dat
new file mode 100644
index 000000000..b06872f9c
Binary files /dev/null and b/tests/res/raw/v15_sats2.dat differ
diff --git a/tests/res/raw/v16_satellite_access_config.json b/tests/res/raw/v16_satellite_access_config.json
new file mode 100644
index 000000000..48cc6429b
--- /dev/null
+++ b/tests/res/raw/v16_satellite_access_config.json
@@ -0,0 +1,267 @@
+{
+  "access_control_configs": [
+    {
+      "config_id": 0,
+      "satellite_infos": [
+        {
+          "satellite_id": "64998d22-17ce-47d2-bba9-1a2c72296e83",
+          "satellite_position": {
+            "longitude": 143.5,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229001,
+              "end_earfcn": 229001
+            },
+            {
+              "start_earfcn": 229003,
+              "end_earfcn": 229003
+            },
+            {
+              "start_earfcn": 229005,
+              "end_earfcn": 229005
+            },
+            {
+              "start_earfcn": 229007,
+              "end_earfcn": 229007
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        886
+      ]
+    },
+    {
+      "config_id": 1,
+      "satellite_infos": [
+        {
+          "satellite_id": "967f8e86-fc27-4673-9343-a820280a14dd",
+          "satellite_position": {
+            "longitude": 10.25,
+            "altitude": 35793.1
+          },
+          "bands": [
+            256
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229360,
+              "end_earfcn": 229360
+            },
+            {
+              "start_earfcn": 229362,
+              "end_earfcn": 229362
+            },
+            {
+              "start_earfcn": 229364,
+              "end_earfcn": 229364
+            },
+            {
+              "start_earfcn": 229366,
+              "end_earfcn": 229366
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        101
+      ]
+    },
+    {
+      "config_id": 2,
+      "satellite_infos": [
+        {
+          "satellite_id": "c9d78ffa-ffa5-4d41-a81b-34693b33b496",
+          "satellite_position": {
+            "longitude": -101.3,
+            "altitude": 35786.0
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229011,
+              "end_earfcn": 229011
+            },
+            {
+              "start_earfcn": 229013,
+              "end_earfcn": 229013
+            },
+            {
+              "start_earfcn": 229015,
+              "end_earfcn": 229015
+            },
+            {
+              "start_earfcn": 229017,
+              "end_earfcn": 229017
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11,
+        1001
+      ]
+    },
+    {
+      "config_id": 3,
+      "satellite_infos": [
+        {
+          "satellite_id": "795bfab9-2851-438e-8861-79e8c82acc5e",
+          "satellite_position": {
+            "longitude": 143.5,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229001,
+              "end_earfcn": 229001
+            },
+            {
+              "start_earfcn": 229003,
+              "end_earfcn": 229003
+            },
+            {
+              "start_earfcn": 229005,
+              "end_earfcn": 229005
+            },
+            {
+              "start_earfcn": 229007,
+              "end_earfcn": 229007
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        886
+      ]
+    },
+    {
+      "config_id": 4,
+      "satellite_infos": [
+        {
+          "satellite_id": "62de127d-ead1-481f-8524-b58e2664103a",
+          "satellite_position": {
+            "longitude": -98.0,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 228837,
+              "end_earfcn": 228837
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11,
+        1001
+      ]
+    },
+    {
+      "config_id": 5,
+      "satellite_infos": [
+        {
+          "satellite_id": "62de127d-ead1-481f-8524-b58e2664103a",
+          "satellite_position": {
+            "longitude": -98.0,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 228909,
+              "end_earfcn": 228909
+            },
+            {
+              "start_earfcn": 228919,
+              "end_earfcn": 228919
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11
+      ]
+    },
+    {
+      "config_id": 6,
+      "satellite_infos": [
+        {
+          "satellite_id": "c9d78ffa-ffa5-4d41-a81b-34693b33b496",
+          "satellite_position": {
+            "longitude": -101.3,
+            "altitude": 35786.0
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229011,
+              "end_earfcn": 229011
+            },
+            {
+              "start_earfcn": 229013,
+              "end_earfcn": 229013
+            },
+            {
+              "start_earfcn": 229015,
+              "end_earfcn": 229015
+            },
+            {
+              "start_earfcn": 229017,
+              "end_earfcn": 229017
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        12
+      ]
+    },
+    {
+      "config_id": 7,
+      "satellite_infos": [
+        {
+          "satellite_id": "62de127d-ead1-481f-8524-b58e2664103a",
+          "satellite_position": {
+            "longitude": -98.0,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 228919,
+              "end_earfcn": 228919
+            },
+            {
+              "start_earfcn": 228909,
+              "end_earfcn": 228909
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11,
+        1001
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/tests/res/raw/v16_sats2.dat b/tests/res/raw/v16_sats2.dat
new file mode 100644
index 000000000..d8ec4152f
Binary files /dev/null and b/tests/res/raw/v16_sats2.dat differ
diff --git a/tests/res/raw/v17_satellite_access_config.json b/tests/res/raw/v17_satellite_access_config.json
new file mode 100644
index 000000000..fd5257ebd
--- /dev/null
+++ b/tests/res/raw/v17_satellite_access_config.json
@@ -0,0 +1,195 @@
+{
+  "access_control_configs": [
+    {
+      "config_id": 0,
+      "satellite_infos": [
+        {
+          "satellite_id": "967f8e86-fc27-4673-9343-a820280a14dd",
+          "satellite_position": {
+            "longitude": 10.25,
+            "altitude": 35793.1
+          },
+          "bands": [
+            256
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229360,
+              "end_earfcn": 229360
+            },
+            {
+              "start_earfcn": 229362,
+              "end_earfcn": 229362
+            },
+            {
+              "start_earfcn": 229364,
+              "end_earfcn": 229364
+            },
+            {
+              "start_earfcn": 229366,
+              "end_earfcn": 229366
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        101
+      ]
+    },
+    {
+      "config_id": 1,
+      "satellite_infos": [
+        {
+          "satellite_id": "c9d78ffa-ffa5-4d41-a81b-34693b33b496",
+          "satellite_position": {
+            "longitude": -101.3,
+            "altitude": 35786.0
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229011,
+              "end_earfcn": 229011
+            },
+            {
+              "start_earfcn": 229013,
+              "end_earfcn": 229013
+            },
+            {
+              "start_earfcn": 229015,
+              "end_earfcn": 229015
+            },
+            {
+              "start_earfcn": 229017,
+              "end_earfcn": 229017
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11,
+        1001
+      ]
+    },
+    {
+      "config_id": 2,
+      "satellite_infos": [
+        {
+          "satellite_id": "62de127d-ead1-481f-8524-b58e2664103a",
+          "satellite_position": {
+            "longitude": -98.0,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 228837,
+              "end_earfcn": 228837
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11,
+        1001
+      ]
+    },
+    {
+      "config_id": 3,
+      "satellite_infos": [
+        {
+          "satellite_id": "62de127d-ead1-481f-8524-b58e2664103a",
+          "satellite_position": {
+            "longitude": -98.0,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 228909,
+              "end_earfcn": 228909
+            },
+            {
+              "start_earfcn": 228919,
+              "end_earfcn": 228919
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11
+      ]
+    },
+    {
+      "config_id": 4,
+      "satellite_infos": [
+        {
+          "satellite_id": "c9d78ffa-ffa5-4d41-a81b-34693b33b496",
+          "satellite_position": {
+            "longitude": -101.3,
+            "altitude": 35786.0
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 229011,
+              "end_earfcn": 229011
+            },
+            {
+              "start_earfcn": 229013,
+              "end_earfcn": 229013
+            },
+            {
+              "start_earfcn": 229015,
+              "end_earfcn": 229015
+            },
+            {
+              "start_earfcn": 229017,
+              "end_earfcn": 229017
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        12
+      ]
+    },
+    {
+      "config_id": 5,
+      "satellite_infos": [
+        {
+          "satellite_id": "62de127d-ead1-481f-8524-b58e2664103a",
+          "satellite_position": {
+            "longitude": -98.0,
+            "altitude": 35775.1
+          },
+          "bands": [
+            255
+          ],
+          "earfcn_ranges": [
+            {
+              "start_earfcn": 228919,
+              "end_earfcn": 228919
+            },
+            {
+              "start_earfcn": 228909,
+              "end_earfcn": 228909
+            }
+          ]
+        }
+      ],
+      "tag_ids": [
+        11,
+        1001
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/tests/res/raw/v17_sats2.dat b/tests/res/raw/v17_sats2.dat
new file mode 100644
index 000000000..b06872f9c
Binary files /dev/null and b/tests/res/raw/v17_sats2.dat differ
diff --git a/tests/src/com/android/TelephonyTestBase.java b/tests/src/com/android/TelephonyTestBase.java
index 94e91d331..d8c3727a3 100644
--- a/tests/src/com/android/TelephonyTestBase.java
+++ b/tests/src/com/android/TelephonyTestBase.java
@@ -24,7 +24,9 @@ import static org.mockito.Mockito.doReturn;
 import android.content.ContextWrapper;
 import android.content.res.Resources;
 import android.os.Handler;
+import android.os.HandlerThread;
 import android.os.Looper;
+import android.os.TestLooperManager;
 import android.util.Log;
 
 import androidx.test.InstrumentationRegistry;
@@ -37,6 +39,7 @@ import com.android.internal.telephony.data.DataConfigManager;
 import com.android.internal.telephony.data.DataNetworkController;
 import com.android.internal.telephony.metrics.MetricsCollector;
 import com.android.internal.telephony.metrics.PersistAtomsStorage;
+import com.android.internal.telephony.satellite.SatelliteController;
 import com.android.phone.PhoneGlobals;
 import com.android.phone.PhoneInterfaceManager;
 
@@ -69,6 +72,10 @@ public class TelephonyTestBase {
     @Mock protected DataNetworkController mDataNetworkController;
     @Mock private MetricsCollector mMetricsCollector;
 
+    private HandlerThread mTestHandlerThread;
+    protected Looper mTestLooper;
+    protected TestLooperManager mLooperManager;
+
     private final HashMap<InstanceKey, Object> mOldInstances = new HashMap<>();
     private final LinkedList<InstanceKey> mInstanceKeys = new LinkedList<>();
 
@@ -80,6 +87,9 @@ public class TelephonyTestBase {
 
         doCallRealMethod().when(mPhoneGlobals).getBaseContext();
         doCallRealMethod().when(mPhoneGlobals).getResources();
+        doCallRealMethod().when(mPhoneGlobals).getSystemService(Mockito.anyString());
+        doCallRealMethod().when(mPhoneGlobals).getSystemService(Mockito.any(Class.class));
+        doCallRealMethod().when(mPhoneGlobals).getSystemServiceName(Mockito.any(Class.class));
         doCallRealMethod().when(mPhone).getServiceState();
 
         mContext = spy(new TestContext());
@@ -96,6 +106,8 @@ public class TelephonyTestBase {
         replaceInstance(PhoneFactory.class, "sPhones", null, new Phone[] {mPhone});
         replaceInstance(PhoneGlobals.class, "sMe", null, mPhoneGlobals);
         replaceInstance(PhoneFactory.class, "sMetricsCollector", null, mMetricsCollector);
+        replaceInstance(SatelliteController.class, "sInstance", null,
+                Mockito.mock(SatelliteController.class));
 
         doReturn(Mockito.mock(PersistAtomsStorage.class)).when(mMetricsCollector).getAtomsStorage();
 
@@ -112,9 +124,47 @@ public class TelephonyTestBase {
     public void tearDown() throws Exception {
         // Ensure there are no static references to handlers after test completes.
         PhoneConfigurationManager.unregisterAllMultiSimConfigChangeRegistrants();
+        cleanupTestLooper();
         restoreInstances();
     }
 
+    protected void setupTestLooper() {
+        mTestHandlerThread = new HandlerThread("TestHandlerThread");
+        mTestHandlerThread.start();
+        mTestLooper = mTestHandlerThread.getLooper();
+        mLooperManager = new TestLooperManager(mTestLooper);
+    }
+
+    private void cleanupTestLooper() {
+        mTestLooper = null;
+        if (mLooperManager != null) {
+            mLooperManager.release();
+            mLooperManager = null;
+        }
+        if (mTestHandlerThread != null) {
+            mTestHandlerThread.quit();
+            try {
+                mTestHandlerThread.join();
+            } catch (InterruptedException ex) {
+                Log.w("TelephonyTestBase", "HandlerThread join interrupted", ex);
+            }
+            mTestHandlerThread = null;
+        }
+    }
+
+    protected void processOneMessage() {
+        var msg = mLooperManager.next();
+        mLooperManager.execute(msg);
+        mLooperManager.recycle(msg);
+    }
+
+    protected void processAllMessages() {
+        for (var msg = mLooperManager.poll(); msg != null && msg.getTarget() != null;) {
+            mLooperManager.execute(msg);
+            mLooperManager.recycle(msg);
+        }
+    }
+
     protected final boolean waitForExecutorAction(Executor executor, long timeoutMillis) {
         final CountDownLatch lock = new CountDownLatch(1);
         executor.execute(() -> {
diff --git a/tests/src/com/android/TestContext.java b/tests/src/com/android/TestContext.java
index bf7832abc..54ee6e025 100644
--- a/tests/src/com/android/TestContext.java
+++ b/tests/src/com/android/TestContext.java
@@ -33,6 +33,7 @@ import android.content.ServiceConnection;
 import android.content.pm.PackageManager;
 import android.content.res.AssetManager;
 import android.content.res.Resources;
+import android.net.ConnectivityManager;
 import android.os.Binder;
 import android.os.Handler;
 import android.os.Looper;
@@ -72,6 +73,7 @@ public class TestContext extends MockContext {
     @Mock ImsManager mMockImsManager;
     @Mock UserManager mMockUserManager;
     @Mock PackageManager mPackageManager;
+    @Mock ConnectivityManager mMockConnectivityManager;
 
     private final SparseArray<PersistableBundle> mCarrierConfigs = new SparseArray<>();
 
@@ -192,6 +194,9 @@ public class TestContext extends MockContext {
             case Context.CARRIER_CONFIG_SERVICE: {
                 return mMockCarrierConfigManager;
             }
+            case Context.CONNECTIVITY_SERVICE: {
+                return mMockConnectivityManager;
+            }
             case Context.TELECOM_SERVICE: {
                 return mMockTelecomManager;
             }
@@ -216,6 +221,9 @@ public class TestContext extends MockContext {
         if (serviceClass == CarrierConfigManager.class) {
             return Context.CARRIER_CONFIG_SERVICE;
         }
+        if (serviceClass == ConnectivityManager.class) {
+            return Context.CONNECTIVITY_SERVICE;
+        }
         if (serviceClass == TelecomManager.class) {
             return Context.TELECOM_SERVICE;
         }
diff --git a/tests/src/com/android/phone/CarrierConfigLoaderTest.java b/tests/src/com/android/phone/CarrierConfigLoaderTest.java
index 5190b2150..5b306e6a6 100644
--- a/tests/src/com/android/phone/CarrierConfigLoaderTest.java
+++ b/tests/src/com/android/phone/CarrierConfigLoaderTest.java
@@ -28,6 +28,7 @@ import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
@@ -51,7 +52,6 @@ import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
 import android.telephony.TelephonyRegistryManager;
 import android.testing.AndroidTestingRunner;
-import android.testing.TestableLooper;
 
 import androidx.test.InstrumentationRegistry;
 
@@ -69,6 +69,7 @@ import org.junit.Rule;
 import org.junit.Test;
 import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
 import org.mockito.Mockito;
 
@@ -80,7 +81,6 @@ import java.io.StringWriter;
  * Unit Test for CarrierConfigLoader.
  */
 @RunWith(AndroidTestingRunner.class)
-@TestableLooper.RunWithLooper(setAsMainLooper = true)
 public class CarrierConfigLoaderTest extends TelephonyTestBase {
     @Rule
     public TestRule compatChangeRule = new PlatformCompatChangeRule();
@@ -107,7 +107,6 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
     private TelephonyManager mTelephonyManager;
     private CarrierConfigLoader mCarrierConfigLoader;
     private Handler mHandler;
-    private TestableLooper mTestableLooper;
 
     // The AIDL stub will use PermissionEnforcer to check permission from the caller.
     private FakePermissionEnforcer mFakePermissionEnforcer = new FakePermissionEnforcer();
@@ -115,6 +114,9 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
     @Before
     public void setUp() throws Exception {
         super.setUp();
+        setupTestLooper();
+        doReturn(true).when(mPackageManager).hasSystemFeature(
+                eq(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION));
         doReturn(Context.PERMISSION_ENFORCER_SERVICE).when(mContext).getSystemServiceName(
                 eq(PermissionEnforcer.class));
         doReturn(mFakePermissionEnforcer).when(mContext).getSystemService(
@@ -148,8 +150,7 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
         when(mContext.getSystemService(TelephonyRegistryManager.class)).thenReturn(
                 mTelephonyRegistryManager);
 
-        mTestableLooper = TestableLooper.get(this);
-        mCarrierConfigLoader = new CarrierConfigLoader(mContext, mTestableLooper.getLooper(),
+        mCarrierConfigLoader = new CarrierConfigLoader(mContext, mTestLooper,
                 mFeatureFlags);
         mHandler = mCarrierConfigLoader.getHandler();
 
@@ -209,7 +210,10 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
         mCarrierConfigLoader.saveNoSimConfigToXml(PLATFORM_CARRIER_CONFIG_PACKAGE, config);
         mCarrierConfigLoader.updateConfigForPhoneId(DEFAULT_PHONE_ID,
                 IccCardConstants.INTENT_VALUE_ICC_ABSENT);
-        mTestableLooper.processAllMessages();
+        processOneMessage();
+        processOneMessage();
+        processOneMessage();
+        processOneMessage();
 
         assertThat(mCarrierConfigLoader.getConfigFromDefaultApp(DEFAULT_PHONE_ID)).isNull();
         assertThat(mCarrierConfigLoader.getConfigFromCarrierApp(DEFAULT_PHONE_ID)).isNull();
@@ -248,7 +252,7 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
                 DEFAULT_PHONE_ID, carrierId, config);
         mCarrierConfigLoader.updateConfigForPhoneId(DEFAULT_PHONE_ID,
                 IccCardConstants.INTENT_VALUE_ICC_LOADED);
-        mTestableLooper.processAllMessages();
+        processAllMessages();
 
         assertThat(mCarrierConfigLoader.getConfigFromDefaultApp(DEFAULT_PHONE_ID).getInt(
                 CARRIER_CONFIG_EXAMPLE_KEY)).isEqualTo(CARRIER_CONFIG_EXAMPLE_VALUE);
@@ -290,7 +294,8 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
 
         mCarrierConfigLoader.overrideConfig(DEFAULT_SUB_ID, null /*overrides*/,
                 false/*persistent*/);
-        mTestableLooper.processAllMessages();
+        processOneMessage();
+        processOneMessage();
 
         assertThat(mCarrierConfigLoader.getOverrideConfig(DEFAULT_PHONE_ID).isEmpty()).isTrue();
         verify(mSubscriptionManagerService).updateSubscriptionByCarrierConfig(
@@ -312,7 +317,8 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
         PersistableBundle config = getTestConfig();
         mCarrierConfigLoader.overrideConfig(DEFAULT_SUB_ID, config /*overrides*/,
                 false/*persistent*/);
-        mTestableLooper.processAllMessages();
+        processOneMessage();
+        processOneMessage();
 
         assertThat(mCarrierConfigLoader.getOverrideConfig(DEFAULT_PHONE_ID).getInt(
                 CARRIER_CONFIG_EXAMPLE_KEY)).isEqualTo(CARRIER_CONFIG_EXAMPLE_VALUE);
@@ -431,7 +437,6 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
         replaceInstance(CarrierConfigLoader.class, "mVendorApiLevel", mCarrierConfigLoader,
                 vendorApiLevel);
 
-        doReturn(true).when(mFeatureFlags).enforceTelephonyFeatureMappingForPublicApis();
         doReturn(false).when(mPackageManager).hasSystemFeature(
                 eq(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION));
 
@@ -477,9 +482,48 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
                 any(Intent.class), any(ServiceConnection.class), anyInt());
         doNothing().when(mContext).sendBroadcastAsUser(any(Intent.class), any(UserHandle.class));
         mHandler.sendMessage(mHandler.obtainMessage(17 /* EVENT_MULTI_SIM_CONFIG_CHANGED */));
-        mTestableLooper.processAllMessages();
+        processAllMessages();
 
         mCarrierConfigLoader.updateConfigForPhoneId(1, IccCardConstants.INTENT_VALUE_ICC_ABSENT);
-        mTestableLooper.processAllMessages();
+        processAllMessages();
+    }
+
+    @Test
+    public void testSystemUnlocked_noCallback() throws Exception {
+        replaceInstance(TelephonyManager.class, "sInstance", null, mTelephonyManager);
+        replaceInstance(CarrierConfigLoader.class, "mHasSentConfigChange",
+                mCarrierConfigLoader, new boolean[]{true});
+        doNothing().when(mContext).sendBroadcastAsUser(any(Intent.class), any(UserHandle.class));
+
+        mFakePermissionEnforcer.grant(android.Manifest.permission.MODIFY_PHONE_STATE);
+        // Prepare to make sure we can save the config into the XML file which used as cache
+        doReturn(PLATFORM_CARRIER_CONFIG_PACKAGE).when(mTelephonyManager)
+                .getCarrierServicePackageNameForLogicalSlot(anyInt());
+
+        doReturn(true).when(mContext).bindService(
+                any(Intent.class), any(ServiceConnection.class), anyInt());
+        Mockito.clearInvocations(mTelephonyRegistryManager);
+        Mockito.clearInvocations(mContext);
+        mHandler.sendMessage(mHandler.obtainMessage(13 /* EVENT_SYSTEM_UNLOCKED */));
+        processOneMessage();
+        mHandler.sendMessage(mHandler.obtainMessage(5 /* EVENT_FETCH_DEFAULT_DONE */));
+        processOneMessage();
+        processOneMessage();
+        mHandler.sendMessage(mHandler.obtainMessage(6 /* EVENT_FETCH_CARRIER_DONE */));
+        processOneMessage();
+        processOneMessage();
+
+        ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
+        verify(mSubscriptionManagerService).updateSubscriptionByCarrierConfig(eq(0), anyString(),
+                any(PersistableBundle.class), runnableCaptor.capture());
+
+        runnableCaptor.getValue().run();
+        processAllMessages();
+
+        // Broadcast should be sent for backwards compatibility.
+        verify(mContext).sendBroadcastAsUser(any(Intent.class), any(UserHandle.class));
+        // But callback should not be sent.
+        verify(mTelephonyRegistryManager, never()).notifyCarrierConfigChanged(
+                anyInt(), anyInt(), anyInt(), anyInt());
     }
 }
diff --git a/tests/src/com/android/phone/ImsStateCallbackControllerTest.java b/tests/src/com/android/phone/ImsStateCallbackControllerTest.java
index 5521ac0b1..4e85bd09a 100644
--- a/tests/src/com/android/phone/ImsStateCallbackControllerTest.java
+++ b/tests/src/com/android/phone/ImsStateCallbackControllerTest.java
@@ -32,9 +32,9 @@ import static junit.framework.Assert.assertNotNull;
 import static junit.framework.Assert.assertNull;
 import static junit.framework.Assert.assertTrue;
 
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.atLeastOnce;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
@@ -985,7 +985,9 @@ public class ImsStateCallbackControllerTest extends TelephonyTestBase {
         when(mSubscriptionManager.getActiveSubscriptionIdList()).thenReturn(subIds);
     }
 
-    private void processAllMessages() {
+    // Override - not using mTestLooper from the base class
+    @Override
+    protected void processAllMessages() {
         while (!mLooper.getLooper().getQueue().isIdle()) {
             mLooper.processAllMessages();
         }
diff --git a/tests/src/com/android/phone/LocationAccessPolicyTest.java b/tests/src/com/android/phone/LocationAccessPolicyTest.java
index 551c2cbc8..7acdb777e 100644
--- a/tests/src/com/android/phone/LocationAccessPolicyTest.java
+++ b/tests/src/com/android/phone/LocationAccessPolicyTest.java
@@ -148,7 +148,7 @@ public class LocationAccessPolicyTest {
         }
     }
 
-    private static final int TESTING_UID = 10001;
+    private static final int TESTING_UID = UserHandle.getUid(UserHandle.myUserId(), 10001);
     private static final int TESTING_PID = 8009;
     private static final String TESTING_CALLING_PACKAGE = "com.android.phone";
 
diff --git a/tests/src/com/android/phone/NumberVerificationManagerTest.java b/tests/src/com/android/phone/NumberVerificationManagerTest.java
index f7914ab23..56df13984 100644
--- a/tests/src/com/android/phone/NumberVerificationManagerTest.java
+++ b/tests/src/com/android/phone/NumberVerificationManagerTest.java
@@ -26,6 +26,9 @@ import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
 import android.telephony.NumberVerificationCallback;
 import android.telephony.PhoneNumberRange;
 import android.telephony.ServiceState;
@@ -33,8 +36,10 @@ import android.telephony.ServiceState;
 import com.android.internal.telephony.Call;
 import com.android.internal.telephony.INumberVerificationCallback;
 import com.android.internal.telephony.Phone;
+import com.android.internal.telephony.flags.Flags;
 
 import org.junit.Before;
+import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
@@ -43,6 +48,10 @@ import org.mockito.MockitoAnnotations;
 
 @RunWith(JUnit4.class)
 public class NumberVerificationManagerTest {
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule =
+            DeviceFlagsValueProvider.createCheckFlagsRule();
+
     private static final PhoneNumberRange SAMPLE_RANGE =
             new PhoneNumberRange("1", "650555", "0000", "8999");
     private static final long DEFAULT_VERIFICATION_TIMEOUT = 100;
@@ -131,7 +140,7 @@ public class NumberVerificationManagerTest {
 
     private void verifyDefaultRangeMatching(NumberVerificationManager manager) throws Exception {
         String testNumber = "6505550000";
-        assertTrue(manager.checkIncomingCall(testNumber));
+        assertTrue(manager.checkIncomingCall(testNumber, "US"));
         verify(mCallback).onCallReceived(testNumber);
     }
 
@@ -148,6 +157,45 @@ public class NumberVerificationManagerTest {
         verifyDefaultRangeMatching(manager);
     }
 
+    /**
+     * Verifies that numbers starting with '0' prefix from the network and lacking the country code
+     * will be correctly compared to a range with the `44` country code.
+     * @throws Exception
+     */
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_ROBUST_NUMBER_VERIFICATION)
+    public void testVerificationOfUkNumbersWithZeroPrefix() throws Exception {
+        NumberVerificationManager manager =
+                new NumberVerificationManager(() -> new Phone[]{mPhone1});
+
+        manager.requestVerification(new PhoneNumberRange("44", "7445", "000000", "999999"),
+                mCallback, DEFAULT_VERIFICATION_TIMEOUT);
+        verify(mCallback, never()).onVerificationFailed(anyInt());
+        String testNumber = "0 7445 032046";
+        assertTrue(manager.checkIncomingCall(testNumber, "GB"));
+        verify(mCallback).onCallReceived(testNumber);
+    }
+
+    /**
+     * Similar to {@link #testVerificationOfUkNumbersWithZeroPrefix()}, except verifies that if the
+     * network sent a full qualified UK phone number with the `+44` country code that it would
+     * match the range.
+     * @throws Exception
+     */
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_ROBUST_NUMBER_VERIFICATION)
+    public void testVerificationOfUkNumbersWithCountryPrefix() throws Exception {
+        NumberVerificationManager manager =
+                new NumberVerificationManager(() -> new Phone[]{mPhone1});
+
+        manager.requestVerification(new PhoneNumberRange("44", "7445", "000000", "999999"),
+                mCallback, DEFAULT_VERIFICATION_TIMEOUT);
+        verify(mCallback, never()).onVerificationFailed(anyInt());
+        String testNumber = "+447445032046";
+        assertTrue(manager.checkIncomingCall(testNumber, "GB"));
+        verify(mCallback).onCallReceived(testNumber);
+    }
+
     @Test
     public void testVerificationWorksWithOnePhoneFull() throws Exception {
         Call fakeCall = mock(Call.class);
@@ -169,6 +217,6 @@ public class NumberVerificationManagerTest {
                 new NumberVerificationManager(() -> new Phone[]{mPhone1, mPhone2});
         manager.requestVerification(SAMPLE_RANGE, mCallback, DEFAULT_VERIFICATION_TIMEOUT);
         verifyDefaultRangeMatching(manager);
-        assertFalse(manager.checkIncomingCall("this doesn't even matter"));
+        assertFalse(manager.checkIncomingCall("this doesn't even matter", "US"));
     }
 }
diff --git a/tests/src/com/android/phone/PhoneInterfaceManagerTest.java b/tests/src/com/android/phone/PhoneInterfaceManagerTest.java
index ef6a02a72..266481e56 100644
--- a/tests/src/com/android/phone/PhoneInterfaceManagerTest.java
+++ b/tests/src/com/android/phone/PhoneInterfaceManagerTest.java
@@ -46,6 +46,7 @@ import android.permission.flags.Flags;
 import android.platform.test.flag.junit.SetFlagsRule;
 import android.preference.PreferenceManager;
 import android.telephony.RadioAccessFamily;
+import android.telephony.Rlog;
 import android.telephony.TelephonyManager;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
@@ -58,6 +59,7 @@ import com.android.internal.telephony.IIntegerConsumer;
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.RILConstants;
 import com.android.internal.telephony.flags.FeatureFlags;
+import com.android.internal.telephony.satellite.SatelliteController;
 import com.android.internal.telephony.subscription.SubscriptionManagerService;
 import com.android.phone.satellite.accesscontrol.SatelliteAccessController;
 
@@ -74,6 +76,7 @@ import org.mockito.Mockito;
 import java.lang.reflect.Field;
 import java.lang.reflect.Modifier;
 import java.util.Collections;
+import java.util.List;
 import java.util.Locale;
 
 /**
@@ -85,6 +88,8 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
     @Rule
     public TestRule compatChangeRule = new PlatformCompatChangeRule();
 
+    private static final String TAG = "PhoneInterfaceManagerTest";
+
     private PhoneInterfaceManager mPhoneInterfaceManager;
     private SharedPreferences mSharedPreferences;
     @Mock private IIntegerConsumer mIIntegerConsumer;
@@ -114,6 +119,9 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
         replaceInstance(SatelliteAccessController.class, "sInstance", null,
                 Mockito.mock(SatelliteAccessController.class));
 
+        replaceInstance(SatelliteController.class, "sInstance", null,
+                Mockito.mock(SatelliteController.class));
+
         mSharedPreferences = PreferenceManager.getDefaultSharedPreferences(
                 InstrumentationRegistry.getInstrumentation().getTargetContext());
         doReturn(mSharedPreferences).when(mPhoneGlobals)
@@ -138,7 +146,6 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
         // In order not to affect the existing implementation, define a telephony features
         // and disabled enforce_telephony_feature_mapping_for_public_apis feature flag
         mPhoneInterfaceManager.setFeatureFlags(mFeatureFlags);
-        doReturn(false).when(mFeatureFlags).enforceTelephonyFeatureMappingForPublicApis();
         doReturn(true).when(mFeatureFlags).hsumPackageManager();
         mPhoneInterfaceManager.setPackageManager(mPackageManager);
         doReturn(mPackageManager).when(mPhoneGlobals).getPackageManager();
@@ -322,6 +329,10 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
                 mPhoneInterfaceManager).getDefaultPhone();
     }
 
+    private static void loge(String message) {
+        Rlog.e(TAG, message);
+    }
+
     @Test
     public void setNullCipherNotificationsEnabled_allReqsMet_successfullyEnabled() {
         setModemSupportsNullCipherNotification(true);
@@ -500,7 +511,6 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
     @Test
     @EnableCompatChanges({TelephonyManager.ENABLE_FEATURE_MAPPING})
     public void testWithTelephonyFeatureAndCompatChanges() throws Exception {
-        doReturn(true).when(mFeatureFlags).enforceTelephonyFeatureMappingForPublicApis();
         mPhoneInterfaceManager.setFeatureFlags(mFeatureFlags);
         doNothing().when(mPhoneInterfaceManager).enforceModifyPermission();
 
@@ -525,7 +535,6 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
         doReturn(false).when(mPackageManager).hasSystemFeature(
                 PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS);
         mPhoneInterfaceManager.setPackageManager(mPackageManager);
-        doReturn(true).when(mFeatureFlags).enforceTelephonyFeatureMappingForPublicApis();
         mPhoneInterfaceManager.setFeatureFlags(mFeatureFlags);
         doNothing().when(mPhoneInterfaceManager).enforceModifyPermission();
 
@@ -550,4 +559,25 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
         String packageName = mPhoneInterfaceManager.getCurrentPackageName();
         assertEquals(null, packageName);
     }
+
+    @Test
+    public void testGetSatelliteDataOptimizedApps() throws Exception {
+        doReturn(true).when(mFeatureFlags).carrierRoamingNbIotNtn();
+        mPhoneInterfaceManager.setFeatureFlags(mFeatureFlags);
+        loge("FeatureFlagApi is set to return true");
+
+        boolean containsCtsApp = false;
+        String ctsPackageName = "android.telephony.cts";
+        List<String> listSatelliteApplications =
+                mPhoneInterfaceManager.getSatelliteDataOptimizedApps();
+
+        for (String packageName : listSatelliteApplications) {
+            if (ctsPackageName.equals(packageName)) {
+                containsCtsApp = true;
+            }
+        }
+
+        assertFalse(containsCtsApp);
+    }
+
 }
diff --git a/tests/src/com/android/phone/RcsProvisioningMonitorTest.java b/tests/src/com/android/phone/RcsProvisioningMonitorTest.java
index 26144607e..2783f0724 100644
--- a/tests/src/com/android/phone/RcsProvisioningMonitorTest.java
+++ b/tests/src/com/android/phone/RcsProvisioningMonitorTest.java
@@ -25,10 +25,10 @@ import static junit.framework.Assert.assertFalse;
 import static junit.framework.Assert.assertNull;
 import static junit.framework.Assert.assertTrue;
 
-import static org.mockito.Matchers.any;
-import static org.mockito.Matchers.anyBoolean;
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.atLeastOnce;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.never;
diff --git a/tests/src/com/android/phone/SimPhonebookProviderTest.java b/tests/src/com/android/phone/SimPhonebookProviderTest.java
index d8518f85d..817c53ecf 100644
--- a/tests/src/com/android/phone/SimPhonebookProviderTest.java
+++ b/tests/src/com/android/phone/SimPhonebookProviderTest.java
@@ -29,11 +29,11 @@ import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doNothing;
+import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
-import static org.mockito.Mockito.when;
 
 import android.content.ContentResolver;
 import android.content.ContentValues;
@@ -169,8 +169,7 @@ public final class SimPhonebookProviderTest {
 
     @Test
     public void query_entityFiles_noSim_returnsEmptyCursor() {
-        when(mMockSubscriptionManager.getActiveSubscriptionInfoList()).thenReturn(
-                ImmutableList.of());
+        doReturn(ImmutableList.of()).when(mMockSubscriptionManager).getActiveSubscriptionInfoList();
 
         try (Cursor cursor = mResolver.query(ElementaryFiles.CONTENT_URI, null, null, null)) {
             assertThat(cursor).hasCount(0);
@@ -363,7 +362,7 @@ public final class SimPhonebookProviderTest {
         // Use a mock so that a null list can be returned
         IIccPhoneBook mockIccPhoneBook = mock(
                 IIccPhoneBook.class, AdditionalAnswers.delegatesTo(mIccPhoneBook));
-        when(mockIccPhoneBook.getAdnRecordsInEfForSubscriber(anyInt(), anyInt())).thenReturn(null);
+        doReturn(null).when(mockIccPhoneBook).getAdnRecordsInEfForSubscriber(anyInt(), anyInt());
         TestableSimPhonebookProvider.setup(mResolver, mMockSubscriptionManager, mockIccPhoneBook);
 
         try (Cursor adnCursor = mResolver.query(SimRecords.getContentUri(1, EF_ADN), null, null,
@@ -1334,14 +1333,14 @@ public final class SimPhonebookProviderTest {
     }
 
     private void setupSimsWithSubscriptionIds(int... subscriptionIds) {
-        when(mMockSubscriptionManager.getActiveSubscriptionIdList()).thenReturn(subscriptionIds);
-        when(mMockSubscriptionManager.getActiveSubscriptionInfoCount())
-                .thenReturn(subscriptionIds.length);
+        doReturn(subscriptionIds).when(mMockSubscriptionManager).getActiveSubscriptionIdList();
+        doReturn(subscriptionIds.length).when(mMockSubscriptionManager)
+                .getActiveSubscriptionInfoCount();
         List<SubscriptionInfo> subscriptions = createSubscriptionsWithIds(subscriptionIds);
-        when(mMockSubscriptionManager.getActiveSubscriptionInfoList()).thenReturn(subscriptions);
+        doReturn(subscriptions).when(mMockSubscriptionManager).getActiveSubscriptionInfoList();
         for (SubscriptionInfo info : subscriptions) {
-            when(mMockSubscriptionManager.getActiveSubscriptionInfo(info.getSubscriptionId()))
-                    .thenReturn(info);
+            doReturn(info).when(mMockSubscriptionManager)
+                    .getActiveSubscriptionInfo(info.getSubscriptionId());
         }
     }
 
diff --git a/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessControllerTest.java b/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessControllerTest.java
index 3750dd18a..8c8e39373 100644
--- a/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessControllerTest.java
+++ b/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessControllerTest.java
@@ -34,16 +34,18 @@ import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_SUCC
 
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.ALLOWED_STATE_CACHE_VALID_DURATION_NANOS;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.CMD_IS_SATELLITE_COMMUNICATION_ALLOWED;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.CONFIG_UPDATER_SATELLITE_VERSION_KEY;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_DELAY_MINUTES_BEFORE_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_MAX_RETRY_COUNT_FOR_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_REGIONAL_SATELLITE_CONFIG_ID;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_S2_LEVEL;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_THROTTLE_INTERVAL_FOR_LOCATION_QUERY_MINUTES;
-import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.EVENT_CONFIG_DATA_UPDATED;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.CMD_UPDATE_CONFIG_DATA;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.EVENT_COUNTRY_CODE_CHANGED;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.EVENT_KEEP_ON_DEVICE_ACCESS_CONTROLLER_RESOURCES_TIMEOUT;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.EVENT_WAIT_FOR_CURRENT_LOCATION_TIMEOUT;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.GOOGLE_US_SAN_SAT_S2_FILE_NAME;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.SATELLITE_ACCESS_CONFIG_FILE_NAME;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.UNKNOWN_REGIONAL_SATELLITE_CONFIG_ID;
 
 import static org.junit.Assert.assertArrayEquals;
@@ -53,7 +55,6 @@ import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertSame;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
-import static org.junit.Assume.assumeTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
@@ -103,7 +104,7 @@ import android.telecom.TelecomManager;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
 import android.telephony.satellite.EarfcnRange;
-import android.telephony.satellite.ISatelliteCommunicationAllowedStateCallback;
+import android.telephony.satellite.ISatelliteCommunicationAccessStateCallback;
 import android.telephony.satellite.SatelliteAccessConfiguration;
 import android.telephony.satellite.SatelliteInfo;
 import android.telephony.satellite.SatelliteManager;
@@ -125,7 +126,9 @@ import com.android.internal.telephony.satellite.SatelliteConfig;
 import com.android.internal.telephony.satellite.SatelliteConfigParser;
 import com.android.internal.telephony.satellite.SatelliteController;
 import com.android.internal.telephony.satellite.SatelliteModemInterface;
+import com.android.internal.telephony.satellite.metrics.CarrierRoamingSatelliteControllerStats;
 import com.android.internal.telephony.satellite.metrics.ControllerMetricsStats;
+import com.android.internal.telephony.subscription.SubscriptionManagerService;
 
 import org.junit.After;
 import org.junit.Before;
@@ -136,6 +139,9 @@ import org.mockito.Captor;
 import org.mockito.Mock;
 
 import java.io.File;
+import java.io.FileOutputStream;
+import java.io.IOException;
+import java.io.InputStream;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashMap;
@@ -233,8 +239,14 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
     @Mock
     private ResultReceiver mMockResultReceiver;
     @Mock
-    private ConcurrentHashMap<IBinder, ISatelliteCommunicationAllowedStateCallback>
+    private ConcurrentHashMap<IBinder, ISatelliteCommunicationAccessStateCallback>
             mSatelliteCommunicationAllowedStateCallbackMap;
+    @Mock
+    private ConcurrentHashMap<IBinder, ISatelliteCommunicationAccessStateCallback>
+            mMockSatelliteCommunicationAccessStateChangedListeners;
+    @Mock
+    private CarrierRoamingSatelliteControllerStats mCarrierRoamingSatelliteControllerStats;
+
     private SatelliteInfo mSatelliteInfo;
 
     private TestableLooper mTestableLooper;
@@ -270,7 +282,7 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
     @Captor
     private ArgumentCaptor<Bundle> mResultDataBundleCaptor;
     @Captor
-    private ArgumentCaptor<ISatelliteCommunicationAllowedStateCallback> mAllowedStateCallbackCaptor;
+    private ArgumentCaptor<ISatelliteCommunicationAccessStateCallback> mAllowedStateCallbackCaptor;
 
     private boolean mQueriedSatelliteAllowed = false;
     private int mQueriedSatelliteAllowedResultCode = SATELLITE_RESULT_SUCCESS;
@@ -317,6 +329,7 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
 
     @Before
     public void setUp() throws Exception {
+        logd("SatelliteAccessControllerTest setUp");
         super.setUp();
 
         mMockContext = mContext;
@@ -338,16 +351,26 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
             return InstrumentationRegistry.getTargetContext()
                     .getDir((String) args[0], (Integer) args[1]);
         }).when(mPhoneGlobals).getDir(anyString(), anyInt());
+        doAnswer(
+                        inv -> {
+                            return InstrumentationRegistry.getTargetContext().getAssets();
+                        })
+                .when(mPhoneGlobals)
+                .getAssets();
         mPhones = new Phone[]{mMockPhone, mMockPhone2};
         replaceInstance(PhoneFactory.class, "sPhones", null, mPhones);
         replaceInstance(SatelliteController.class, "sInstance", null,
                 mMockSatelliteController);
         replaceInstance(SatelliteModemInterface.class, "sInstance", null,
                 mMockSatelliteModemInterface);
+        replaceInstance(SubscriptionManagerService.class, "sInstance", null,
+                mock(SubscriptionManagerService.class));
         replaceInstance(TelephonyCountryDetector.class, "sInstance", null,
                 mMockCountryDetector);
         replaceInstance(ControllerMetricsStats.class, "sInstance", null,
                 mock(ControllerMetricsStats.class));
+        replaceInstance(CarrierRoamingSatelliteControllerStats.class, "sInstance", null,
+                mCarrierRoamingSatelliteControllerStats);
         when(mMockSatelliteController.getSatellitePhone()).thenReturn(mMockPhone);
         when(mMockPhone.getSubId()).thenReturn(SubscriptionManager.getDefaultSubscriptionId());
 
@@ -394,6 +417,8 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
         when(mMockSharedPreferences.getBoolean(anyString(), anyBoolean())).thenReturn(true);
         when(mMockSharedPreferences.getStringSet(anyString(), any()))
                 .thenReturn(Set.of(TEST_SATELLITE_COUNTRY_CODES));
+        when(mMockSharedPreferences.getInt(
+                eq(CONFIG_UPDATER_SATELLITE_VERSION_KEY), anyInt())).thenReturn(0);
         doReturn(mMockSharedPreferencesEditor).when(mMockSharedPreferences).edit();
         doReturn(mMockSharedPreferencesEditor).when(mMockSharedPreferencesEditor)
                 .putBoolean(anyString(), anyBoolean());
@@ -401,11 +426,11 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
                 .putStringSet(anyString(), any());
         doReturn(mMockSharedPreferencesEditor).when(mMockSharedPreferencesEditor)
                 .putLong(anyString(), anyLong());
+        doReturn(mMockSharedPreferencesEditor).when(mMockSharedPreferencesEditor)
+                .putInt(anyString(), anyInt());
         doNothing().when(mMockSharedPreferencesEditor).apply();
 
-        when(mMockFeatureFlags.satellitePersistentLogging()).thenReturn(true);
         when(mMockFeatureFlags.geofenceEnhancementForBetterUx()).thenReturn(true);
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
         when(mMockFeatureFlags.carrierRoamingNbIotNtn()).thenReturn(true);
 
         when(mMockContext.getSystemService(Context.TELEPHONY_SERVICE))
@@ -424,6 +449,7 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
         mMockApplicationInfo.targetSdkVersion = Build.VERSION_CODES.UPSIDE_DOWN_CAKE;
         when(mMockPackageManager.getApplicationInfo(anyString(), anyInt()))
                 .thenReturn(mMockApplicationInfo);
+        when(mCarrierRoamingSatelliteControllerStats.isMultiSim()).thenReturn(false);
 
         mSatelliteInfo = new SatelliteInfo(
                 UUID.randomUUID(),
@@ -431,6 +457,7 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
                 new ArrayList<>(Arrays.asList(5, 30)),
                 new ArrayList<>(Arrays.asList(new EarfcnRange(0, 250))));
 
+        logd("setUp: Initializing mSatelliteAccessControllerUT:TestSatelliteAccessController");
         mSatelliteAccessControllerUT = new TestSatelliteAccessController(mMockContext,
                 mMockFeatureFlags, mTestableLooper.getLooper(), mMockLocationManager,
                 mMockTelecomManager, mMockSatelliteOnDeviceAccessController, mMockSatS2File);
@@ -496,8 +523,6 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
 
     @Test
     public void testIsSatelliteAccessAllowedForLocation() {
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
-
         // Test disallowList case
         when(mMockResources.getBoolean(
                 com.android.internal.R.bool.config_oem_enabled_satellite_access_allow))
@@ -598,15 +623,15 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
                 .get(eq(UNKNOWN_REGIONAL_SATELLITE_CONFIG_ID));
 
         // setup callback
-        ISatelliteCommunicationAllowedStateCallback mockSatelliteAllowedStateCallback = mock(
-                ISatelliteCommunicationAllowedStateCallback.class);
+        ISatelliteCommunicationAccessStateCallback mockSatelliteAllowedStateCallback = mock(
+                ISatelliteCommunicationAccessStateCallback.class);
         ArgumentCaptor<SatelliteAccessConfiguration> satelliteAccessConfigurationCaptor =
                 ArgumentCaptor.forClass(SatelliteAccessConfiguration.class);
 
         when(mSatelliteCommunicationAllowedStateCallbackMap.values())
                 .thenReturn(List.of(mockSatelliteAllowedStateCallback));
         replaceInstance(SatelliteAccessController.class,
-                "mSatelliteCommunicationAllowedStateChangedListeners", mSatelliteAccessControllerUT,
+                "mSatelliteCommunicationAccessStateChangedListeners", mSatelliteAccessControllerUT,
                 mSatelliteCommunicationAllowedStateCallbackMap);
 
         // Test when the featureFlags.carrierRoamingNbIotNtn() is false
@@ -621,7 +646,7 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
         assertEquals(SATELLITE_RESULT_REQUEST_NOT_SUPPORTED, (int) resultCodeCaptor.getValue());
         assertNull(bundleCaptor.getValue());
         verify(mockSatelliteAllowedStateCallback, never())
-                .onSatelliteAccessConfigurationChanged(any());
+                .onAccessConfigurationChanged(any());
 
         doReturn(true).when(mMockFeatureFlags).carrierRoamingNbIotNtn();
 
@@ -642,7 +667,7 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
         assertSame(bundleCaptor.getValue().getParcelable(KEY_SATELLITE_ACCESS_CONFIGURATION,
                 SatelliteAccessConfiguration.class), satelliteAccessConfig);
         verify(mockSatelliteAllowedStateCallback, times(1))
-                .onSatelliteAccessConfigurationChanged(
+                .onAccessConfigurationChanged(
                         satelliteAccessConfigurationCaptor.capture());
         assertEquals(satelliteAccessConfigurationCaptor.getValue(), satelliteAccessConfig);
 
@@ -661,7 +686,7 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
         assertNull(bundleCaptor.getValue());
 
         verify(mockSatelliteAllowedStateCallback, times(1))
-                .onSatelliteAccessConfigurationChanged(
+                .onAccessConfigurationChanged(
                         satelliteAccessConfigurationCaptor.capture());
         assertNull(satelliteAccessConfigurationCaptor.getValue());
     }
@@ -675,52 +700,41 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
 
     @Test
     public void testRegisterForCommunicationAllowedStateChanged() throws Exception {
-        ISatelliteCommunicationAllowedStateCallback mockSatelliteAllowedStateCallback = mock(
-                ISatelliteCommunicationAllowedStateCallback.class);
+        ISatelliteCommunicationAccessStateCallback mockSatelliteAllowedStateCallback = mock(
+                ISatelliteCommunicationAccessStateCallback.class);
         doReturn(true).when(mSatelliteCommunicationAllowedStateCallbackMap)
-                .put(any(IBinder.class), any(ISatelliteCommunicationAllowedStateCallback.class));
+                .put(any(IBinder.class), any(ISatelliteCommunicationAccessStateCallback.class));
         replaceInstance(SatelliteAccessController.class,
-                "mSatelliteCommunicationAllowedStateChangedListeners", mSatelliteAccessControllerUT,
+                "mSatelliteCommunicationAccessStateChangedListeners", mSatelliteAccessControllerUT,
                 mSatelliteCommunicationAllowedStateCallbackMap);
 
-        doReturn(false).when(mMockFeatureFlags).oemEnabledSatelliteFlag();
-        int result = mSatelliteAccessControllerUT.registerForCommunicationAllowedStateChanged(
-                DEFAULT_SUBSCRIPTION_ID, mockSatelliteAllowedStateCallback);
-        mTestableLooper.processAllMessages();
-        assertEquals(SATELLITE_RESULT_REQUEST_NOT_SUPPORTED, result);
-        verify(mockSatelliteAllowedStateCallback, never())
-                .onSatelliteCommunicationAllowedStateChanged(anyBoolean());
-        verify(mockSatelliteAllowedStateCallback, never())
-                .onSatelliteAccessConfigurationChanged(any(SatelliteAccessConfiguration.class));
-
-        doReturn(true).when(mMockFeatureFlags).oemEnabledSatelliteFlag();
-        result = mSatelliteAccessControllerUT.registerForCommunicationAllowedStateChanged(
+        int result = mSatelliteAccessControllerUT.registerForCommunicationAccessStateChanged(
                 DEFAULT_SUBSCRIPTION_ID, mockSatelliteAllowedStateCallback);
         mTestableLooper.processAllMessages();
         assertEquals(SATELLITE_RESULT_SUCCESS, result);
         verify(mockSatelliteAllowedStateCallback, times(1))
-                .onSatelliteCommunicationAllowedStateChanged(anyBoolean());
+                .onAccessAllowedStateChanged(anyBoolean());
         verify(mockSatelliteAllowedStateCallback, times(1))
-                .onSatelliteAccessConfigurationChanged(
+                .onAccessConfigurationChanged(
                         nullable(SatelliteAccessConfiguration.class));
     }
 
     @Test
     public void testNotifyRegionalSatelliteConfigurationChanged() throws Exception {
         // setup test
-        ISatelliteCommunicationAllowedStateCallback mockSatelliteAllowedStateCallback = mock(
-                ISatelliteCommunicationAllowedStateCallback.class);
+        ISatelliteCommunicationAccessStateCallback mockSatelliteAllowedStateCallback = mock(
+                ISatelliteCommunicationAccessStateCallback.class);
         ArgumentCaptor<SatelliteAccessConfiguration> satelliteAccessConfigurationCaptor =
                 ArgumentCaptor.forClass(SatelliteAccessConfiguration.class);
 
         when(mSatelliteCommunicationAllowedStateCallbackMap.values())
                 .thenReturn(List.of(mockSatelliteAllowedStateCallback));
         replaceInstance(SatelliteAccessController.class,
-                "mSatelliteCommunicationAllowedStateChangedListeners", mSatelliteAccessControllerUT,
+                "mSatelliteCommunicationAccessStateChangedListeners", mSatelliteAccessControllerUT,
                 mSatelliteCommunicationAllowedStateCallbackMap);
 
         // register callback
-        mSatelliteAccessControllerUT.registerForCommunicationAllowedStateChanged(
+        mSatelliteAccessControllerUT.registerForCommunicationAccessStateChanged(
                 DEFAULT_SUBSCRIPTION_ID, mockSatelliteAllowedStateCallback);
 
         // verify if the callback is
@@ -737,7 +751,7 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
                 .notifyRegionalSatelliteConfigurationChanged(satelliteAccessConfig);
 
         // verify if the satelliteAccessConfig is the same instance with the captured one.
-        verify(mockSatelliteAllowedStateCallback).onSatelliteAccessConfigurationChanged(
+        verify(mockSatelliteAllowedStateCallback).onAccessConfigurationChanged(
                 satelliteAccessConfigurationCaptor.capture());
         assertSame(satelliteAccessConfig, satelliteAccessConfigurationCaptor.getValue());
     }
@@ -865,8 +879,6 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
 
     @Test
     public void testIsRegionDisallowed() throws Exception {
-        // setup to make the return value of mQueriedSatelliteAllowed 'true'
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
         when(mMockContext.getResources()).thenReturn(mMockResources);
         when(mMockResources.getBoolean(
                 com.android.internal.R.bool.config_oem_enabled_satellite_access_allow))
@@ -1065,18 +1077,6 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
 
     @Test
     public void testRequestIsSatelliteCommunicationAllowedForCurrentLocation() throws Exception {
-        // OEM-enabled satellite is not supported
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(false);
-        mSatelliteAccessControllerUT.requestIsCommunicationAllowedForCurrentLocation(
-                mSatelliteAllowedReceiver, false);
-        mTestableLooper.processAllMessages();
-        assertTrue(waitForRequestIsSatelliteAllowedForCurrentLocationResult(
-                mSatelliteAllowedSemaphore, 1));
-        assertEquals(SATELLITE_RESULT_REQUEST_NOT_SUPPORTED, mQueriedSatelliteAllowedResultCode);
-
-        // OEM-enabled satellite is supported
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
-
         // Satellite is not supported
         setUpResponseForRequestIsSatelliteSupported(false, SATELLITE_RESULT_SUCCESS);
         clearAllInvocations();
@@ -1230,15 +1230,12 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
         long lastKnownLocationElapsedRealtime =
                 firstMccChangedTime + TEST_LOCATION_QUERY_THROTTLE_INTERVAL_NANOS;
 
-        // OEM-enabled satellite is supported
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
-
         verify(mMockCountryDetector).registerForCountryCodeChanged(
                 mCountryDetectorHandlerCaptor.capture(), mCountryDetectorIntCaptor.capture(),
                 mCountryDetectorObjCaptor.capture());
 
         assertSame(mCountryDetectorHandlerCaptor.getValue(), mSatelliteAccessControllerUT);
-        assertSame(mCountryDetectorIntCaptor.getValue(), EVENT_COUNTRY_CODE_CHANGED);
+        assertSame(EVENT_COUNTRY_CODE_CHANGED, mCountryDetectorIntCaptor.getValue());
         assertNull(mCountryDetectorObjCaptor.getValue());
 
         // Setup to invoke GPS query
@@ -1354,9 +1351,6 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
 
     @Test
     public void testValidatePossibleChangeInSatelliteAllowedRegion() throws Exception {
-        // OEM-enabled satellite is supported
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
-
         verify(mMockCountryDetector).registerForCountryCodeChanged(
                 mCountryDetectorHandlerCaptor.capture(), mCountryDetectorIntCaptor.capture(),
                 mCountryDetectorObjCaptor.capture());
@@ -1408,8 +1402,6 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
 
     @Test
     public void testRetryValidatePossibleChangeInSatelliteAllowedRegion() throws Exception {
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
-
         verify(mMockCountryDetector).registerForCountryCodeChanged(
                 mCountryDetectorHandlerCaptor.capture(), mCountryDetectorIntCaptor.capture(),
                 mCountryDetectorObjCaptor.capture());
@@ -1442,11 +1434,6 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
 
     @Test
     public void testLoadSatelliteAccessConfigurationFromDeviceConfig() {
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(false);
-        assertNull(mSatelliteAccessControllerUT
-                .getSatelliteConfigurationFileNameFromOverlayConfig(mMockContext));
-
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
         when(mMockContext.getResources()).thenReturn(mMockResources);
         when(mMockResources
                 .getString(eq(com.android.internal.R.string.satellite_access_config_file)))
@@ -1460,7 +1447,7 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
         assertNull(mSatelliteAccessControllerUT
                 .getSatelliteConfigurationFileNameFromOverlayConfig(mMockContext));
         try {
-            mSatelliteAccessControllerUT.loadSatelliteAccessConfigurationFromDeviceConfig();
+            mSatelliteAccessControllerUT.loadSatelliteAccessConfiguration();
         } catch (Exception e) {
             fail("Unexpected exception thrown: " + e.getMessage());
         }
@@ -1468,23 +1455,28 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
 
 
     @Test
-    public void testUpdateSatelliteConfigData() throws Exception {
+    public void testUpdateSatelliteAccessDataWithConfigUpdaterData() throws Exception {
+        logd("registering for config update changed");
         verify(mMockSatelliteController).registerForConfigUpdateChanged(
                 mConfigUpdateHandlerCaptor.capture(), mConfigUpdateIntCaptor.capture(),
                 mConfigUpdateObjectCaptor.capture());
 
         assertSame(mConfigUpdateHandlerCaptor.getValue(), mSatelliteAccessControllerUT);
-        assertSame(mConfigUpdateIntCaptor.getValue(), EVENT_CONFIG_DATA_UPDATED);
+        assertSame(mConfigUpdateIntCaptor.getValue(), CMD_UPDATE_CONFIG_DATA);
         assertSame(mConfigUpdateObjectCaptor.getValue(), mMockContext);
 
+        logd("replacing instance for mCachedAccessRestrictionMap");
         replaceInstance(SatelliteAccessController.class, "mCachedAccessRestrictionMap",
                 mSatelliteAccessControllerUT, mMockCachedAccessRestrictionMap);
 
         // These APIs are executed during loadRemoteConfigs
-        verify(mMockSharedPreferences, times(1)).getStringSet(anyString(), any());
-        verify(mMockSharedPreferences, times(5)).getBoolean(anyString(), anyBoolean());
+        logd("verify load remote configs shared preferences method calls");
+        verify(mMockSharedPreferences, times(1)).getInt(anyString(), anyInt());
+        verify(mMockSharedPreferences, times(0)).getStringSet(anyString(), any());
+        verify(mMockSharedPreferences, times(4)).getBoolean(anyString(), anyBoolean());
 
         // satelliteConfig is null
+        logd("test for satelliteConfig is null");
         SatelliteConfigParser spyConfigParser =
                 spy(new SatelliteConfigParser("test".getBytes()));
         doReturn(spyConfigParser).when(mMockSatelliteController).getSatelliteConfigParser();
@@ -1493,9 +1485,28 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
         sendConfigUpdateChangedEvent(mMockContext);
         verify(mMockSharedPreferences, never()).edit();
         verify(mMockCachedAccessRestrictionMap, never()).clear();
+        verify(mMockSatelliteController, times(1)).getSatelliteConfig();
 
-        // satelliteConfig has invalid country codes
+        // satelliteConfig has satellite config data version(0) which is from device config.
+        logd("test for satelliteConfig from device config version 0");
         SatelliteConfig mockConfig = mock(SatelliteConfig.class);
+        doReturn(0).when(mockConfig).getSatelliteConfigDataVersion();
+        doReturn(mockConfig).when(mMockSatelliteController).getSatelliteConfig();
+        doReturn(false).when(mockConfig).isSatelliteDataForAllowedRegion();
+
+        sendConfigUpdateChangedEvent(mMockContext);
+        verify(mMockSharedPreferences, never()).edit();
+        verify(mMockCachedAccessRestrictionMap, never()).clear();
+        verify(mMockSatelliteController, times(2)).getSatelliteConfig();
+        verify(mockConfig, times(1)).getSatelliteConfigDataVersion();
+        verify(mockConfig, times(0)).getDeviceSatelliteCountryCodes();
+        verify(mockConfig, times(0)).isSatelliteDataForAllowedRegion();
+        verify(mockConfig, times(0)).getSatelliteS2CellFile(mMockContext);
+        verify(mockConfig, times(0)).getSatelliteAccessConfigJsonFile(mMockContext);
+
+        // satelliteConfig has invalid country codes
+        logd("test for satelliteConfig with invalid country codes");
+        doReturn(1).when(mockConfig).getSatelliteConfigDataVersion();
         doReturn(List.of("USA", "JAP")).when(mockConfig).getDeviceSatelliteCountryCodes();
         doReturn(mockConfig).when(mMockSatelliteController).getSatelliteConfig();
         doReturn(false).when(mockConfig).isSatelliteDataForAllowedRegion();
@@ -1503,8 +1514,15 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
         sendConfigUpdateChangedEvent(mMockContext);
         verify(mMockSharedPreferences, never()).edit();
         verify(mMockCachedAccessRestrictionMap, never()).clear();
+        verify(mMockSatelliteController, times(3)).getSatelliteConfig();
+        verify(mockConfig, times(2)).getSatelliteConfigDataVersion();
+        verify(mockConfig, times(1)).getDeviceSatelliteCountryCodes();
+        verify(mockConfig, times(0)).isSatelliteDataForAllowedRegion();
+        verify(mockConfig, times(0)).getSatelliteS2CellFile(mMockContext);
+        verify(mockConfig, times(0)).getSatelliteAccessConfigJsonFile(mMockContext);
 
         // satelliteConfig does not have is_allow_access_control data
+        logd("test for satelliteConfig does not have is_allow_access_control data");
         doReturn(List.of(TEST_SATELLITE_COUNTRY_CODES))
                 .when(mockConfig).getDeviceSatelliteCountryCodes();
         doReturn(null).when(mockConfig).isSatelliteDataForAllowedRegion();
@@ -1512,37 +1530,478 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
         sendConfigUpdateChangedEvent(mMockContext);
         verify(mMockSharedPreferences, never()).edit();
         verify(mMockCachedAccessRestrictionMap, never()).clear();
-
-        // satelliteConfig doesn't have S2CellFile
-        File mockFile = mock(File.class);
-        doReturn(false).when(mockFile).exists();
+        verify(mMockSatelliteController, times(4)).getSatelliteConfig();
+        verify(mockConfig, times(3)).getSatelliteConfigDataVersion();
+        verify(mockConfig, times(2)).getDeviceSatelliteCountryCodes();
+        verify(mockConfig, times(1)).isSatelliteDataForAllowedRegion();
+        verify(mockConfig, times(0)).getSatelliteS2CellFile(mMockContext);
+        verify(mockConfig, times(0)).getSatelliteAccessConfigJsonFile(mMockContext);
+
+        // satelliteConfig doesn't have both S2CellFile and satellite access config json file
+        logd(
+                "test for satelliteConfig doesn't have both S2CellFile and satellite access config"
+                        + " json file");
+        File mockS2File = mock(File.class);
+        doReturn(false).when(mockS2File).exists();
+        File mockSatelliteAccessConfigJsonFile = mock(File.class);
+        doReturn(false).when(mockSatelliteAccessConfigJsonFile).exists();
         doReturn(List.of(TEST_SATELLITE_COUNTRY_CODES))
                 .when(mockConfig).getDeviceSatelliteCountryCodes();
         doReturn(true).when(mockConfig).isSatelliteDataForAllowedRegion();
-        doReturn(mockFile).when(mockConfig).getSatelliteS2CellFile(mMockContext);
+        doReturn(mockS2File).when(mockConfig).getSatelliteS2CellFile(mMockContext);
+        doReturn(mockSatelliteAccessConfigJsonFile)
+                .when(mockConfig)
+                .getSatelliteAccessConfigJsonFile(mMockContext);
 
         sendConfigUpdateChangedEvent(mMockContext);
         verify(mMockSharedPreferences, never()).edit();
         verify(mMockCachedAccessRestrictionMap, never()).clear();
-
-        // satelliteConfig has valid data
+        verify(mMockSatelliteController, times(5)).getSatelliteConfig();
+        verify(mockConfig, times(4)).getSatelliteConfigDataVersion();
+        verify(mockConfig, times(3)).getDeviceSatelliteCountryCodes();
+        verify(mockConfig, times(2)).isSatelliteDataForAllowedRegion();
+        verify(mockConfig, times(1)).getSatelliteS2CellFile(mMockContext);
+        verify(mockConfig, times(0)).getSatelliteAccessConfigJsonFile(mMockContext);
+
+        // satelliteConfig has s2CellFill, but doesn't have satellite access config json file
+        logd(
+                "test for satelliteConfig having s2CellFill, but doesn't have satellite access"
+                        + " config json file");
         doReturn(mockConfig).when(mMockSatelliteController).getSatelliteConfig();
         File testS2File = mSatelliteAccessControllerUT
                 .getTestSatelliteS2File(GOOGLE_US_SAN_SAT_S2_FILE_NAME);
-        assumeTrue("Satellite not supported", testS2File != null && testS2File.exists());
+        assertTrue("Test S2 file not created", testS2File != null && testS2File.exists());
+        mockSatelliteAccessConfigJsonFile = mock(File.class);
+        doReturn(false).when(mockSatelliteAccessConfigJsonFile).exists();
         doReturn(List.of(TEST_SATELLITE_COUNTRY_CODES))
                 .when(mockConfig).getDeviceSatelliteCountryCodes();
         doReturn(true).when(mockConfig).isSatelliteDataForAllowedRegion();
         doReturn(testS2File).when(mockConfig).getSatelliteS2CellFile(mMockContext);
+        doReturn(mockSatelliteAccessConfigJsonFile)
+                .when(mockConfig)
+                .getSatelliteAccessConfigJsonFile(mMockContext);
 
         sendConfigUpdateChangedEvent(mMockContext);
-        verify(mMockSharedPreferences, times(2)).edit();
+        verify(mMockSharedPreferences, never()).edit();
+        verify(mMockCachedAccessRestrictionMap, never()).clear();
+        verify(mMockSatelliteController, times(6)).getSatelliteConfig();
+        verify(mockConfig, times(5)).getSatelliteConfigDataVersion();
+        verify(mockConfig, times(4)).getDeviceSatelliteCountryCodes();
+        verify(mockConfig, times(3)).isSatelliteDataForAllowedRegion();
+        verify(mockConfig, times(2)).getSatelliteS2CellFile(mMockContext);
+        verify(mockConfig, times(1)).getSatelliteAccessConfigJsonFile(mMockContext);
+
+        // satelliteConfig has valid data
+        logd("test for satelliteConfig having valid data");
+        doReturn(true).when(mockConfig).isSatelliteDataForAllowedRegion();
+        doReturn(List.of(TEST_SATELLITE_COUNTRY_CODES))
+                .when(mockConfig)
+                .getDeviceSatelliteCountryCodes();
+        testS2File =
+                mSatelliteAccessControllerUT.getTestSatelliteS2File(GOOGLE_US_SAN_SAT_S2_FILE_NAME);
+        assertTrue("Test S2 file not created", testS2File != null && testS2File.exists());
+        doReturn(testS2File).when(mockConfig).getSatelliteS2CellFile(mMockContext);
+        File testSatelliteAccessConfigFile =
+                mSatelliteAccessControllerUT.getTestSatelliteConfiguration(
+                        SATELLITE_ACCESS_CONFIG_FILE_NAME);
+        assertTrue(
+                "Test satellite access config file not created",
+                testSatelliteAccessConfigFile != null && testSatelliteAccessConfigFile.exists());
+        doReturn(testSatelliteAccessConfigFile)
+                .when(mockConfig)
+                .getSatelliteAccessConfigJsonFile(mMockContext);
+
+        sendConfigUpdateChangedEvent(mMockContext);
+        verify(mMockSharedPreferences, times(3)).edit();
         verify(mMockCachedAccessRestrictionMap, times(1)).clear();
+        verify(mMockSatelliteController, times(7)).getSatelliteConfig();
+        verify(mockConfig, times(6)).getSatelliteConfigDataVersion();
+        verify(mockConfig, times(5)).getDeviceSatelliteCountryCodes();
+        verify(mockConfig, times(5)).isSatelliteDataForAllowedRegion();
+        verify(mockConfig, times(3)).getSatelliteS2CellFile(mMockContext);
+        verify(mockConfig, times(2)).getSatelliteAccessConfigJsonFile(mMockContext);
+    }
+
+    private String setupTestFileFromRawResource(int resId, String targetFileName)
+            throws IOException {
+        logd("setting up rest file for resId: " + resId + ", targetFileName: " + targetFileName);
+        Context context = InstrumentationRegistry.getInstrumentation().getContext();
+        InputStream is = context.getResources().openRawResource(resId);
+        logd("Copying test file to temp_satellite_config_update");
+        File tempDir =
+                InstrumentationRegistry.getInstrumentation()
+                        .getTargetContext()
+                        .getDir("temp_satellite_config_update", Context.MODE_PRIVATE);
+        File tempFile = new File(tempDir, targetFileName);
+        FileOutputStream fos = new FileOutputStream(tempFile);
+        byte[] buffer = new byte[1024];
+        int length;
+        while ((length = is.read(buffer)) > 0) {
+            fos.write(buffer, 0, length);
+        }
+        is.close();
+        fos.close();
+        return tempFile.getAbsolutePath();
+    }
+
+    private boolean isLocationAllowed(
+            ArgumentCaptor<Bundle> bundleCaptor,
+            Iterator<ResultReceiver> mockResultReceiverIterator,
+            Location location)
+            throws Exception {
+        clearInvocations(mMockResultReceiver);
+        when(mMockLocationManager.getLastKnownLocation(LocationManager.NETWORK_PROVIDER))
+                .thenReturn(location);
+        when(mMockLocationManager.getLastKnownLocation(LocationManager.FUSED_PROVIDER))
+                .thenReturn(location);
+        doReturn(true, false).when(mockResultReceiverIterator).hasNext();
+        mSatelliteAccessControllerUT.checkSatelliteAccessRestrictionForLocation(location);
+        verify(mMockResultReceiver, times(1))
+                .send(mResultCodeIntCaptor.capture(), bundleCaptor.capture());
+        if (mResultCodeIntCaptor.getValue() != SATELLITE_RESULT_SUCCESS) return false;
+        return bundleCaptor.getValue().getBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED);
+    }
+
+    private void setupOnDeviceGeofenceData(
+            int sats2ResId,
+            String targetSats2FileName,
+            int satelliteAccessConfigResId,
+            String targetSatelliteAccessConfigFileName)
+            throws Exception {
+        logd("setting up on device geofence data");
+
+        logd("Clearing on device geofence data");
+        sendSatelliteDeviceAccessControllerResourcesTimeOutEvent();
+
+        logd("Creating sats2.dat and satellite_access_config.json files");
+        // set given sats2.dat and satellite_access_config.json as device geofence files
+        doReturn(0).when(mMockSharedPreferences)
+                .getInt(eq(CONFIG_UPDATER_SATELLITE_VERSION_KEY), anyInt());
+        String sats2FilePath = setupTestFileFromRawResource(sats2ResId, targetSats2FileName);
+        when(mMockResources.getString(
+                        com.android.internal.R.string.config_oem_enabled_satellite_s2cell_file))
+                .thenReturn(sats2FilePath);
+        String satelliteAccessConfigFilePath =
+                setupTestFileFromRawResource(
+                        satelliteAccessConfigResId, targetSatelliteAccessConfigFileName);
+        when(mMockResources.getString(com.android.internal.R.string.satellite_access_config_file))
+                .thenReturn(satelliteAccessConfigFilePath);
+        mSatelliteAccessControllerUT.loadOverlayConfigs(mMockContext);
+    }
+
+    private void setupOtaGeofenceData(
+            int version,
+            SatelliteConfig mockConfig,
+            int sats2ResId,
+            String targetSats2FileName,
+            int satelliteAccessConfigResId,
+            String targetSatelliteAccessConfigFileName,
+            String[] countryCodes)
+            throws Exception {
+        String sats2FilePath = setupTestFileFromRawResource(sats2ResId, targetSats2FileName);
+        String satelliteAccessConfigFilePath =
+                setupTestFileFromRawResource(
+                        satelliteAccessConfigResId, targetSatelliteAccessConfigFileName);
+
+        File sats2File = new File(sats2FilePath);
+        assertTrue("OTA geofence S2 file not created", sats2File != null && sats2File.exists());
+        doReturn(sats2File).when(mockConfig).getSatelliteS2CellFile(mMockContext);
+
+        File satelliteAccessConfigFile = new File(satelliteAccessConfigFilePath);
+        assertTrue(
+                "OTA geofence satellite access config file not created",
+                satelliteAccessConfigFile != null && satelliteAccessConfigFile.exists());
+        doReturn(satelliteAccessConfigFile)
+                .when(mockConfig)
+                .getSatelliteAccessConfigJsonFile(mMockContext);
+
+        doReturn(true).when(mockConfig).isSatelliteDataForAllowedRegion();
+        doReturn(List.of(TEST_SATELLITE_COUNTRY_CODES))
+                .when(mockConfig)
+                .getDeviceSatelliteCountryCodes();
+        doReturn(version).when(mockConfig).getSatelliteConfigDataVersion();
+        doReturn(version).when(mMockSharedPreferences)
+                .getInt(eq(CONFIG_UPDATER_SATELLITE_VERSION_KEY), anyInt());
+    }
+
+    private boolean areOnDeviceAndOtaFilesValidAndDifferent(
+            File onDeviceSats2File,
+            File onDeviceSatelliteAccessConfigFile,
+            File otaSats2File,
+            File otaSatelliteAccessConfigFile) {
+        if (onDeviceSats2File == null
+                || onDeviceSatelliteAccessConfigFile == null
+                || otaSats2File == null
+                || otaSatelliteAccessConfigFile == null) {
+            throw new AssertionError("Both on device and OTA files should NOT be null");
+        }
+        String onDeviceSats2FileAbsPath = onDeviceSats2File.getAbsolutePath();
+        String onDeviceSatelliteAccessConfigFileAbsPath =
+                onDeviceSatelliteAccessConfigFile.getAbsolutePath();
+        String otaSats2FileAbsPath = otaSats2File.getAbsolutePath();
+        String otaSatelliteAccessConfigFileAbsPath = otaSatelliteAccessConfigFile.getAbsolutePath();
+
+        logd("onDeviceSats2FileAbsPath: " + onDeviceSats2FileAbsPath);
+        logd(
+                "onDeviceSatelliteAccessConfigFileAbsPath: "
+                        + onDeviceSatelliteAccessConfigFileAbsPath);
+        logd("otaSats2FileAbsPath: " + otaSats2FileAbsPath);
+        logd("otaSatelliteAccessConfigFileAbsPath: " + otaSatelliteAccessConfigFileAbsPath);
+
+        if (onDeviceSats2FileAbsPath.equals(otaSats2FileAbsPath)
+                || onDeviceSatelliteAccessConfigFileAbsPath.equals(
+                        otaSatelliteAccessConfigFileAbsPath)) {
+            return false;
+        }
+
+        logd("areOnDeviceAndOtaFilesValidAndDifferent: true");
+        return true;
+    }
+
+    @Test
+    public void testConfigUpdateAndCorrespondingSatelliteAllowedAtLocationChecks()
+            throws Exception {
+        replaceInstance(
+                SatelliteAccessController.class,
+                "mS2Level",
+                mSatelliteAccessControllerUT,
+                DEFAULT_S2_LEVEL);
+        when(mMockFeatureFlags.carrierRoamingNbIotNtn()).thenReturn(true);
+        when(mMockContext.getResources()).thenReturn(mMockResources);
+        when(mMockResources.getBoolean(
+                        com.android.internal.R.bool.config_oem_enabled_satellite_access_allow))
+                .thenReturn(TEST_SATELLITE_ALLOW);
+        setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
+        setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
+        doReturn(true).when(mMockLocationManager).isLocationEnabled();
+
+        ArgumentCaptor<Bundle> bundleCaptor = ArgumentCaptor.forClass(Bundle.class);
+        Iterator<ResultReceiver> mockResultReceiverIterator = mock(Iterator.class);
+        doReturn(mockResultReceiverIterator).when(mMockSatelliteAllowResultReceivers).iterator();
+        doNothing().when(mMockSatelliteAllowResultReceivers).clear();
+        doReturn(mMockResultReceiver).when(mockResultReceiverIterator).next();
+        replaceInstance(
+                SatelliteAccessController.class,
+                "mSatelliteAllowResultReceivers",
+                mSatelliteAccessControllerUT,
+                mMockSatelliteAllowResultReceivers);
+        replaceInstance(
+                SatelliteAccessController.class,
+                "mCachedAccessRestrictionMap",
+                mSatelliteAccessControllerUT,
+                mMockCachedAccessRestrictionMap);
+
+        ISatelliteCommunicationAccessStateCallback mockSatelliteAllowedStateCallback = mock(
+                ISatelliteCommunicationAccessStateCallback.class);
+
+        when(mSatelliteCommunicationAllowedStateCallbackMap.values())
+                .thenReturn(List.of(mockSatelliteAllowedStateCallback));
+        replaceInstance(SatelliteAccessController.class,
+                "mSatelliteCommunicationAccessStateChangedListeners", mSatelliteAccessControllerUT,
+                mSatelliteCommunicationAllowedStateCallbackMap);
+
+        SatelliteConfig mockConfig = mock(SatelliteConfig.class);
+        doReturn(mockConfig).when(mMockSatelliteController).getSatelliteConfig();
+
+        Location locationUS = mock(Location.class);
+        when(locationUS.getLatitude()).thenReturn(37.7749);
+        when(locationUS.getLongitude()).thenReturn(-122.4194);
+        Location locationKR = mock(Location.class);
+        when(locationKR.getLatitude()).thenReturn(37.5665);
+        when(locationKR.getLongitude()).thenReturn(126.9780);
+        Location locationTW = mock(Location.class);
+        when(locationTW.getLatitude()).thenReturn(25.034);
+        when(locationTW.getLongitude()).thenReturn(121.565);
+
+        // Test v15 geofence data - supports US location
+        // set v15's sats2.dat and satellite_access_config.json as device geofence files and
+        // verify for below locations are allowed or not for satellite commiunication as expected.
+        // location1 - US - allowed; location2 - KR - not allowed; location3 - TW - not allowed;
+        logd(
+                "Step 1: Testing v15 (US) satellite config files. Expectation: locationUS -"
+                        + " allowed; locationKR - not allowed; locationTW - not allowed");
+        setupOnDeviceGeofenceData(
+                com.android.phone.tests.R.raw.v15_sats2,
+                "v15_sats2.dat",
+                com.android.phone.tests.R.raw.v15_satellite_access_config,
+                "v15_satellite_access_config.json");
+        assertEquals(0, mSatelliteAccessControllerUT.getSatelliteAccessConfigVersion());
+        assertTrue(isLocationAllowed(bundleCaptor, mockResultReceiverIterator, locationUS));
+        assertFalse(isLocationAllowed(bundleCaptor, mockResultReceiverIterator, locationKR));
+        assertFalse(isLocationAllowed(bundleCaptor, mockResultReceiverIterator, locationTW));
+        Map<Integer, SatelliteAccessConfiguration> satelliteAccessConfigurationMap =
+                mSatelliteAccessControllerUT.getSatelliteAccessConfigMap();
+        logd("Obatined satelliteAccessConfigurationMap: " + satelliteAccessConfigurationMap);
+        assertEquals(6, satelliteAccessConfigurationMap.size());
+        assertEquals(
+                "62de127d-ead1-481f-8524-b58e2664103a",
+                satelliteAccessConfigurationMap
+                        .get(5)
+                        .getSatelliteInfos()
+                        .get(0)
+                        .getSatelliteId()
+                        .toString());
+        assertEquals(
+                -98.0,
+                satelliteAccessConfigurationMap
+                        .get(5)
+                        .getSatelliteInfos()
+                        .get(0)
+                        .getSatellitePosition()
+                        .getLongitudeDegrees(),
+                0.001);
+        assertEquals(
+                35775.1,
+                satelliteAccessConfigurationMap
+                        .get(5)
+                        .getSatelliteInfos()
+                        .get(0)
+                        .getSatellitePosition()
+                        .getAltitudeKm(),
+                0.001);
+        File onDeviceSats2File = mSatelliteAccessControllerUT.getSatelliteS2CellFile();
+        File onDeviceSatelliteAccessConfigFile =
+                mSatelliteAccessControllerUT.getSatelliteAccessConfigFile();
+
+        // Test v16 geofence data - supports US, KR, TW locations
+        // Simulate config update to override v16's sats2.dat and satellite_access_config.json
+        // as the geofence files.
+        // And verify for below locations are allowed or not for satellite commiunication as
+        // expected.
+        // location1 - US - allowed; location2 - KR - allowed; location3 - TW - allowed;
+        logd(
+                "Step 2: Testing v16 (US, KR, TW) satellite config files."
+                        + " Simulate config update for v16 files. Expectation: locationUS -"
+                        + " allowed; locationKR - allowed; locationTW - allowed");
+        clearInvocations(mockSatelliteAllowedStateCallback);
+        setupOtaGeofenceData(
+                16,
+                mockConfig,
+                com.android.phone.tests.R.raw.v16_sats2,
+                "v16_sats2.dat",
+                com.android.phone.tests.R.raw.v16_satellite_access_config,
+                "v16_satellite_access_config.json",
+                new String[] {"US", "CA", "UK", "KR", "TW"});
+        sendConfigUpdateChangedEvent(mMockContext);
+        verify(mockSatelliteAllowedStateCallback, times(1))
+                .onAccessConfigurationChanged(any());
+        verify(mockSatelliteAllowedStateCallback, times(1))
+                .onAccessAllowedStateChanged(anyBoolean());
+        assertEquals(16, mSatelliteAccessControllerUT.getSatelliteAccessConfigVersion());
+        assertTrue(isLocationAllowed(bundleCaptor, mockResultReceiverIterator, locationUS));
+        assertTrue(isLocationAllowed(bundleCaptor, mockResultReceiverIterator, locationKR));
+        assertTrue(isLocationAllowed(bundleCaptor, mockResultReceiverIterator, locationTW));
+        satelliteAccessConfigurationMap =
+                mSatelliteAccessControllerUT.getSatelliteAccessConfigMap();
+        logd("Obatined satelliteAccessConfigurationMap: " + satelliteAccessConfigurationMap);
+        assertEquals(8, satelliteAccessConfigurationMap.size());
+        assertEquals(
+                "c9d78ffa-ffa5-4d41-a81b-34693b33b496",
+                satelliteAccessConfigurationMap
+                        .get(6)
+                        .getSatelliteInfos()
+                        .get(0)
+                        .getSatelliteId()
+                        .toString());
+        assertEquals(
+                -101.3,
+                satelliteAccessConfigurationMap
+                        .get(6)
+                        .getSatelliteInfos()
+                        .get(0)
+                        .getSatellitePosition()
+                        .getLongitudeDegrees(),
+                0.001);
+        assertEquals(
+                35786.0,
+                satelliteAccessConfigurationMap
+                        .get(6)
+                        .getSatelliteInfos()
+                        .get(0)
+                        .getSatellitePosition()
+                        .getAltitudeKm(),
+                0.001);
+        File otaSats2File = mSatelliteAccessControllerUT.getSatelliteS2CellFile();
+        File otaSatelliteAccessConfigFile =
+                mSatelliteAccessControllerUT.getSatelliteAccessConfigFile();
+        assertTrue(
+                areOnDeviceAndOtaFilesValidAndDifferent(
+                        onDeviceSats2File,
+                        onDeviceSatelliteAccessConfigFile,
+                        otaSats2File,
+                        otaSatelliteAccessConfigFile));
+
+        // Test v17 geofence data - supports US location
+        // Simulate config update to override v17's sats2.dat and satellite_access_config.json
+        // as the geofence files.
+        // And verify for below locations are allowed or not for satellite commiunication as
+        // expected.
+        // location1 - US - allowed; location2 - KR - not allowed; location3 - TW - not allowed;
+        logd(
+                "Step 3: Testing v17 (US) satellite config files."
+                        + " Simulate config update for v17 files. Expectation: locationUS -"
+                        + " allowed; locationKR - not allowed; locationTW - not allowed");
+        clearInvocations(mockSatelliteAllowedStateCallback);
+        setupOtaGeofenceData(
+                17,
+                mockConfig,
+                com.android.phone.tests.R.raw.v17_sats2,
+                "v17_sats2.dat",
+                com.android.phone.tests.R.raw.v17_satellite_access_config,
+                "v17_satellite_access_config.json",
+                new String[] {"US", "CA", "UK", "KR", "TW"});
+        sendConfigUpdateChangedEvent(mMockContext);
+        verify(mockSatelliteAllowedStateCallback, times(1))
+                .onAccessConfigurationChanged(any());
+        verify(mockSatelliteAllowedStateCallback, times(1))
+                .onAccessAllowedStateChanged(anyBoolean());
+        assertEquals(17, mSatelliteAccessControllerUT.getSatelliteAccessConfigVersion());
+        assertTrue(isLocationAllowed(bundleCaptor, mockResultReceiverIterator, locationUS));
+        assertFalse(isLocationAllowed(bundleCaptor, mockResultReceiverIterator, locationKR));
+        assertFalse(isLocationAllowed(bundleCaptor, mockResultReceiverIterator, locationTW));
+        satelliteAccessConfigurationMap =
+                mSatelliteAccessControllerUT.getSatelliteAccessConfigMap();
+        logd("Obatined satelliteAccessConfigurationMap: " + satelliteAccessConfigurationMap);
+        assertEquals(6, satelliteAccessConfigurationMap.size());
+        assertEquals(
+                "62de127d-ead1-481f-8524-b58e2664103a",
+                satelliteAccessConfigurationMap
+                        .get(5)
+                        .getSatelliteInfos()
+                        .get(0)
+                        .getSatelliteId()
+                        .toString());
+        assertEquals(
+                -98.0,
+                satelliteAccessConfigurationMap
+                        .get(5)
+                        .getSatelliteInfos()
+                        .get(0)
+                        .getSatellitePosition()
+                        .getLongitudeDegrees(),
+                0.001);
+        assertEquals(
+                35775.1,
+                satelliteAccessConfigurationMap
+                        .get(5)
+                        .getSatelliteInfos()
+                        .get(0)
+                        .getSatellitePosition()
+                        .getAltitudeKm(),
+                0.001);
+        otaSats2File = mSatelliteAccessControllerUT.getSatelliteS2CellFile();
+        otaSatelliteAccessConfigFile = mSatelliteAccessControllerUT.getSatelliteAccessConfigFile();
+        assertTrue(
+                areOnDeviceAndOtaFilesValidAndDifferent(
+                        onDeviceSats2File,
+                        onDeviceSatelliteAccessConfigFile,
+                        otaSats2File,
+                        otaSatelliteAccessConfigFile));
     }
 
     @Test
     public void testLocationModeChanged() throws Exception {
-        // setup for querying GPS not to reset mIsSatelliteAllowedRegionPossiblyChanged false.
+        logd("testLocationModeChanged: setup to query the current location");
         when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
         when(mMockContext.getResources()).thenReturn(mMockResources);
         when(mMockResources.getBoolean(
@@ -1558,13 +2017,13 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
         doReturn(false).when(mMockCachedAccessRestrictionMap).containsKey(any());
         mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS + 1;
 
-        // Captor and Verify if the mockReceiver and mocContext is registered well
-        verify(mMockContext, times(2))
-                .registerReceiver(mLocationBroadcastReceiverCaptor.capture(),
-                        mIntentFilterCaptor.capture());
+        logd("testLocationModeChanged: "
+                + "captor and verify if the mockReceiver and mockContext is registered well");
+        verify(mMockContext, times(2)).registerReceiver(
+                mLocationBroadcastReceiverCaptor.capture(), mIntentFilterCaptor.capture());
 
-        // When the intent action is not MODE_CHANGED_ACTION,
-        // verify if the location manager never invoke isLocationEnabled()
+        logd("testLocationModeChanged: verify if the location manager doesn't invoke "
+                + "isLocationEnabled(), when the intent action is not MODE_CHANGED_ACTION");
         doReturn("").when(mMockLocationIntent).getAction();
         mSatelliteAccessControllerUT.setIsSatelliteAllowedRegionPossiblyChanged(false);
         mSatelliteAccessControllerUT.getLocationBroadcastReceiver()
@@ -1573,6 +2032,8 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
 
         // When the intent action is MODE_CHANGED_ACTION and isLocationEnabled() is true,
         // verify if mIsSatelliteAllowedRegionPossiblyChanged is true
+        logd("testLocationModeChanged: verify if mIsSatelliteAllowedRegionPossiblyChanged is true, "
+                + "when the intent action is MODE_CHANGED_ACTION and isLocationEnabled() is true");
         doReturn(MODE_CHANGED_ACTION).when(mMockLocationIntent).getAction();
         doReturn(true).when(mMockLocationManager).isLocationEnabled();
         clearInvocations(mMockLocationManager);
@@ -1583,8 +2044,15 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
         mTestableLooper.processAllMessages();
         assertEquals(true, mSatelliteAccessControllerUT.isSatelliteAllowedRegionPossiblyChanged());
 
-        // When the intent action is MODE_CHANGED_ACTION and isLocationEnabled() is false,
-        // verify if mIsSatelliteAllowedRegionPossiblyChanged is false
+        logd("testLocationModeChanged: "
+                + "verify if mIsSatelliteAllowedRegionPossiblyChanged is false, "
+                + "when the intent action is MODE_CHANGED_ACTION and isLocationEnabled() is false");
+        mSatelliteAccessControllerUT
+                .setIsSatelliteCommunicationAllowedForCurrentLocationCache("cache_allowed");
+        replaceInstance(SatelliteAccessController.class,
+                "mSatelliteCommunicationAccessStateChangedListeners",
+                mSatelliteAccessControllerUT,
+                mMockSatelliteCommunicationAccessStateChangedListeners);
         doReturn(false).when(mMockLocationManager).isLocationEnabled();
         clearInvocations(mMockLocationManager);
         mSatelliteAccessControllerUT.setIsSatelliteAllowedRegionPossiblyChanged(false);
@@ -1592,7 +2060,9 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
                 .onReceive(mMockContext, mMockLocationIntent);
         verify(mMockLocationManager, times(1)).isLocationEnabled();
         mTestableLooper.processAllMessages();
-        assertEquals(false, mSatelliteAccessControllerUT.isSatelliteAllowedRegionPossiblyChanged());
+        assertEquals(false,
+                mSatelliteAccessControllerUT.isSatelliteAllowedRegionPossiblyChanged());
+        verify(mMockSatelliteCommunicationAccessStateChangedListeners, times(1)).values();
     }
 
     @Test
@@ -1707,7 +2177,6 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
     @Test
     public void testRequestIsCommunicationAllowedForCurrentLocationWithEnablingSatellite() {
         // Set non-emergency case
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
         setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
         setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
         when(mMockCountryDetector.getCurrentNetworkCountryIso()).thenReturn(EMPTY_STRING_LIST);
@@ -1744,7 +2213,6 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
     @Test
     public void testUpdateSystemSelectionChannels() {
         // Set non-emergency case
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
         when(mMockFeatureFlags.carrierRoamingNbIotNtn()).thenReturn(true);
 
         setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
@@ -1904,7 +2372,6 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
     @Test
     public void testUpdateSystemSelectionChannels_HandleInvalidInput() {
         // Set non-emergency case
-        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
         when(mMockFeatureFlags.carrierRoamingNbIotNtn()).thenReturn(true);
 
         setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
@@ -2061,6 +2528,7 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
     }
 
     private void sendSatelliteDeviceAccessControllerResourcesTimeOutEvent() {
+        logd("sendSatelliteDeviceAccessControllerResourcesTimeOutEvent");
         Message msg = mSatelliteAccessControllerUT
                 .obtainMessage(EVENT_KEEP_ON_DEVICE_ACCESS_CONTROLLER_RESOURCES_TIMEOUT);
         msg.sendToTarget();
@@ -2068,7 +2536,7 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
     }
 
     private void sendConfigUpdateChangedEvent(Context context) {
-        Message msg = mSatelliteAccessControllerUT.obtainMessage(EVENT_CONFIG_DATA_UPDATED);
+        Message msg = mSatelliteAccessControllerUT.obtainMessage(CMD_UPDATE_CONFIG_DATA);
         msg.obj = new AsyncResult(context, SATELLITE_RESULT_SUCCESS, null);
         msg.sendToTarget();
         mTestableLooper.processAllMessages();
@@ -2318,5 +2786,17 @@ public class SatelliteAccessControllerTest extends TelephonyTestBase {
                 }
             }
         }
+
+        public Map<Integer, SatelliteAccessConfiguration> getSatelliteAccessConfigMap() {
+            synchronized (mLock) {
+                return mSatelliteAccessConfigMap;
+            }
+        }
+
+        public int getSatelliteAccessConfigVersion() {
+            synchronized (mLock) {
+                return mSatelliteAccessConfigVersion;
+            }
+        }
     }
 }
diff --git a/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementApiTest.java b/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementApiTest.java
index f7cbc55fa..866b7ec5c 100644
--- a/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementApiTest.java
+++ b/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementApiTest.java
@@ -26,7 +26,6 @@ import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
-import static org.mockito.ArgumentMatchers.anyVararg;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.verify;
@@ -78,7 +77,7 @@ public class SatelliteEntitlementApiTest {
                 Context.CARRIER_CONFIG_SERVICE);
         mCarrierConfigBundle = new PersistableBundle();
         doReturn(mCarrierConfigBundle)
-                .when(mCarrierConfigManager).getConfigForSubId(anyInt(), anyVararg());
+                .when(mCarrierConfigManager).getConfigForSubId(anyInt(), any());
         doReturn(Context.TELEPHONY_SERVICE).when(mContext).getSystemServiceName(
                 TelephonyManager.class);
         doReturn(mTelephonyManager).when(mContext).getSystemService(Context.TELEPHONY_SERVICE);
diff --git a/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementControllerTest.java b/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementControllerTest.java
index a3b38df7c..37c7efd37 100644
--- a/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementControllerTest.java
+++ b/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementControllerTest.java
@@ -36,7 +36,6 @@ import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyList;
 import static org.mockito.ArgumentMatchers.anyMap;
-import static org.mockito.ArgumentMatchers.anyVararg;
 import static org.mockito.Mockito.clearInvocations;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
@@ -173,7 +172,7 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         mCarrierConfigBundle.putBoolean(
                 CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL, true);
         doReturn(mCarrierConfigBundle)
-                .when(mCarrierConfigManager).getConfigForSubId(anyInt(), anyVararg());
+                .when(mCarrierConfigManager).getConfigForSubId(anyInt(), any());
         doReturn(Context.CONNECTIVITY_SERVICE).when(mContext).getSystemServiceName(
                 ConnectivityManager.class);
         doReturn(mConnectivityManager).when(mContext).getSystemService(
diff --git a/tests/src/com/android/phone/security/SafetySourceReceiverTest.java b/tests/src/com/android/phone/security/SafetySourceReceiverTest.java
index 305e698f1..72687714f 100644
--- a/tests/src/com/android/phone/security/SafetySourceReceiverTest.java
+++ b/tests/src/com/android/phone/security/SafetySourceReceiverTest.java
@@ -35,7 +35,6 @@ import android.platform.test.flag.junit.SetFlagsRule;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
 import com.android.internal.telephony.Phone;
-import com.android.internal.telephony.flags.Flags;
 
 import org.junit.Before;
 import org.junit.Rule;
@@ -67,9 +66,6 @@ public class SafetySourceReceiverTest {
 
     @Test
     public void testOnReceive() {
-        mSetFlagsRule.enableFlags(Flags.FLAG_ENABLE_IDENTIFIER_DISCLOSURE_TRANSPARENCY_UNSOL_EVENTS,
-                Flags.FLAG_ENABLE_MODEM_CIPHER_TRANSPARENCY_UNSOL_EVENTS,
-                Flags.FLAG_ENFORCE_TELEPHONY_FEATURE_MAPPING_FOR_PUBLIC_APIS);
         Phone mockPhone = mock(Phone.class);
         when(mSafetySourceReceiver.getDefaultPhone()).thenReturn(mockPhone);
 
@@ -80,25 +76,8 @@ public class SafetySourceReceiverTest {
         verify(mockPhone, times(1)).refreshSafetySources("aBroadcastId");
     }
 
-    @Test
-    public void testOnReceive_featureFlagsOff() {
-        mSetFlagsRule.disableFlags(
-                Flags.FLAG_ENABLE_IDENTIFIER_DISCLOSURE_TRANSPARENCY_UNSOL_EVENTS,
-                Flags.FLAG_ENABLE_MODEM_CIPHER_TRANSPARENCY_UNSOL_EVENTS,
-                Flags.FLAG_ENFORCE_TELEPHONY_FEATURE_MAPPING_FOR_PUBLIC_APIS);
-
-        Intent intent = new Intent(ACTION_REFRESH_SAFETY_SOURCES);
-        intent.putExtra(EXTRA_REFRESH_SAFETY_SOURCES_BROADCAST_ID, "aBroadcastId");
-        mSafetySourceReceiver.onReceive(mContext, intent);
-
-        verify(mSafetySourceReceiver, never()).getDefaultPhone();
-    }
-
     @Test
     public void testOnReceive_phoneNotReadyYet() {
-        mSetFlagsRule.enableFlags(Flags.FLAG_ENABLE_IDENTIFIER_DISCLOSURE_TRANSPARENCY_UNSOL_EVENTS,
-                Flags.FLAG_ENABLE_MODEM_CIPHER_TRANSPARENCY_UNSOL_EVENTS,
-                Flags.FLAG_ENFORCE_TELEPHONY_FEATURE_MAPPING_FOR_PUBLIC_APIS);
         when(mSafetySourceReceiver.getDefaultPhone()).thenReturn(null);
 
         Intent intent = new Intent(ACTION_REFRESH_SAFETY_SOURCES);
@@ -111,10 +90,6 @@ public class SafetySourceReceiverTest {
 
     @Test
     public void testOnReceive_noTelephonyFeature() {
-        mSetFlagsRule.enableFlags(Flags.FLAG_ENABLE_IDENTIFIER_DISCLOSURE_TRANSPARENCY_UNSOL_EVENTS,
-                Flags.FLAG_ENABLE_MODEM_CIPHER_TRANSPARENCY_UNSOL_EVENTS,
-                Flags.FLAG_ENFORCE_TELEPHONY_FEATURE_MAPPING_FOR_PUBLIC_APIS);
-
         when(mContext.getPackageManager().hasSystemFeature(
                 PackageManager.FEATURE_TELEPHONY)).thenReturn(false);
 
diff --git a/tests/src/com/android/phone/slice/SlicePurchaseControllerTest.java b/tests/src/com/android/phone/slice/SlicePurchaseControllerTest.java
index 5637c3a85..a7927804d 100644
--- a/tests/src/com/android/phone/slice/SlicePurchaseControllerTest.java
+++ b/tests/src/com/android/phone/slice/SlicePurchaseControllerTest.java
@@ -21,6 +21,7 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeTrue;
 import static org.mockito.Mockito.any;
 import static org.mockito.Mockito.anyBoolean;
 import static org.mockito.Mockito.anyInt;
@@ -40,6 +41,7 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
 import android.content.SharedPreferences;
+import android.content.pm.PackageManager;
 import android.os.AsyncResult;
 import android.os.Handler;
 import android.os.HandlerThread;
@@ -56,6 +58,7 @@ import android.telephony.data.TrafficDescriptor;
 import android.telephony.data.UrspRule;
 import android.testing.TestableLooper;
 
+import androidx.test.InstrumentationRegistry;
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
 import com.android.TelephonyTestBase;
@@ -335,6 +338,12 @@ public class SlicePurchaseControllerTest extends TelephonyTestBase {
         mSlicePurchaseController.purchasePremiumCapability(
                 TelephonyManager.PREMIUM_CAPABILITY_PRIORITIZE_LATENCY, mHandler.obtainMessage());
         mTestableLooper.processAllMessages();
+        if (isAutomotive()) {
+            // TODO(b/401032628): this test is flaky here
+            assumeTrue(
+                    TelephonyManager.PURCHASE_PREMIUM_CAPABILITY_RESULT_NETWORK_NOT_AVAILABLE
+                    != mResult);
+        }
         assertEquals(
                 TelephonyManager.PURCHASE_PREMIUM_CAPABILITY_RESULT_NOT_DEFAULT_DATA_SUBSCRIPTION,
                 mResult);
@@ -350,6 +359,11 @@ public class SlicePurchaseControllerTest extends TelephonyTestBase {
                 mResult);
     }
 
+    private boolean isAutomotive() {
+        return InstrumentationRegistry.getTargetContext().getPackageManager()
+                .hasSystemFeature(PackageManager.FEATURE_AUTOMOTIVE);
+    }
+
     @Test
     public void testPurchasePremiumCapabilityResultNetworkNotAvailable() {
         doReturn((int) TelephonyManager.NETWORK_TYPE_BITMASK_NR).when(mPhone)
diff --git a/tests/src/com/android/services/telephony/ImsConferenceTest.java b/tests/src/com/android/services/telephony/ImsConferenceTest.java
index b6cb11a7e..9403c70de 100644
--- a/tests/src/com/android/services/telephony/ImsConferenceTest.java
+++ b/tests/src/com/android/services/telephony/ImsConferenceTest.java
@@ -21,7 +21,7 @@ import static junit.framework.Assert.assertTrue;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.any;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
@@ -32,7 +32,6 @@ import static org.mockito.Mockito.when;
 
 import android.net.Uri;
 import android.os.Bundle;
-import android.os.Looper;
 import android.telecom.Call;
 import android.telecom.Conference;
 import android.telecom.Connection;
@@ -40,22 +39,26 @@ import android.telecom.PhoneAccountHandle;
 import android.telecom.StatusHints;
 import android.telecom.TelecomManager;
 import android.telephony.TelephonyManager;
+import android.testing.AndroidTestingRunner;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.TelephonyTestBase;
 import com.android.ims.internal.ConferenceParticipant;
 
+import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
+import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
 
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.List;
 
-public class ImsConferenceTest {
+@RunWith(AndroidTestingRunner.class)
+public class ImsConferenceTest extends TelephonyTestBase {
     @Mock
     private TelephonyConnectionServiceProxy mMockTelephonyConnectionServiceProxy;
 
@@ -66,15 +69,20 @@ public class ImsConferenceTest {
 
     @Before
     public void setUp() throws Exception {
-        MockitoAnnotations.initMocks(this);
-        if (Looper.myLooper() == null) {
-            Looper.prepare();
-        }
+        super.setUp();
+        replaceInstance(TelecomAccountRegistry.class, "sInstance", null,
+                mMockTelecomAccountRegistry);
         mConferenceHost = new TestTelephonyConnection();
         mConferenceHost.setManageImsConferenceCallSupported(true);
         when(mMockTelecomAccountRegistry.getAddress(any(PhoneAccountHandle.class)))
                 .thenReturn(null);
     }
+
+    @After
+    public void tearDown() throws Exception {
+        super.tearDown();
+    }
+
     @Test
     @SmallTest
     public void testPropertyPropagation() {
diff --git a/tests/src/com/android/services/telephony/TelephonyConnectionServiceTest.java b/tests/src/com/android/services/telephony/TelephonyConnectionServiceTest.java
index 349716710..b2a8991cd 100644
--- a/tests/src/com/android/services/telephony/TelephonyConnectionServiceTest.java
+++ b/tests/src/com/android/services/telephony/TelephonyConnectionServiceTest.java
@@ -42,7 +42,7 @@ import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
@@ -51,7 +51,7 @@ import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
-import static org.mockito.Mockito.verifyZeroInteractions;
+import static org.mockito.Mockito.verifyNoMoreInteractions;
 import static org.mockito.Mockito.when;
 
 import android.content.ComponentName;
@@ -109,6 +109,8 @@ import com.android.internal.telephony.flags.FeatureFlags;
 import com.android.internal.telephony.flags.Flags;
 import com.android.internal.telephony.gsm.SuppServiceNotification;
 import com.android.internal.telephony.imsphone.ImsPhone;
+import com.android.internal.telephony.imsphone.ImsPhoneCall;
+import com.android.internal.telephony.imsphone.ImsPhoneConnection;
 import com.android.internal.telephony.satellite.SatelliteController;
 import com.android.internal.telephony.satellite.SatelliteSOSMessageRecommender;
 import com.android.internal.telephony.subscription.SubscriptionInfoInternal;
@@ -197,15 +199,26 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         public void onHold() {
             wasHeld = true;
         }
+
+        @Override
+        void setOriginalConnection(com.android.internal.telephony.Connection connection) {
+            mOriginalConnection = connection;
+        }
     }
 
     public static class SimpleConference extends Conference {
+        public boolean wasDisconnected = false;
         public boolean wasUnheld = false;
 
         public SimpleConference(PhoneAccountHandle phoneAccountHandle) {
             super(phoneAccountHandle);
         }
 
+        @Override
+        public void onDisconnect() {
+            wasDisconnected = true;
+        }
+
         @Override
         public void onUnhold() {
             wasUnheld = true;
@@ -253,10 +266,12 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     @Mock EmergencyCallDomainSelectionConnection mEmergencyCallDomainSelectionConnection;
     @Mock NormalCallDomainSelectionConnection mNormalCallDomainSelectionConnection;
     @Mock ImsPhone mImsPhone;
+    @Mock SubscriptionManagerService mSubscriptionManagerService;
     @Mock private SatelliteSOSMessageRecommender mSatelliteSOSMessageRecommender;
     @Mock private EmergencyStateTracker mEmergencyStateTracker;
     @Mock private Resources mMockResources;
     @Mock private FeatureFlags mFeatureFlags;
+    @Mock private com.android.server.telecom.flags.FeatureFlags mTelecomFlags;
     private Phone mPhone0;
     private Phone mPhone1;
 
@@ -284,7 +299,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         super.setUp();
 
         mTestConnectionService = new TestTelephonyConnectionService(mContext);
-        mTestConnectionService.setFeatureFlags(mFeatureFlags);
+        mTestConnectionService.setFeatureFlags(mFeatureFlags, mTelecomFlags);
         mTestConnectionService.setPhoneFactoryProxy(mPhoneFactoryProxy);
         mTestConnectionService.setSubscriptionManagerProxy(mSubscriptionManagerProxy);
         // Set configurations statically
@@ -305,8 +320,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 (int) invocation.getArgument(2)))
                 .when(mDisconnectCauseFactory).toTelecomDisconnectCause(anyInt(), any(), anyInt());
         mTestConnectionService.setDisconnectCauseFactory(mDisconnectCauseFactory);
-        mTestConnectionService.onCreate();
-        mTestConnectionService.setTelephonyManagerProxy(mTelephonyManagerProxy);
+        replaceInstance(DomainSelectionResolver.class, "sInstance", null,
+                mDomainSelectionResolver);
         replaceInstance(TelephonyConnectionService.class, "mDomainSelectionResolver",
                 mTestConnectionService, mDomainSelectionResolver);
         replaceInstance(TelephonyConnectionService.class, "mEmergencyStateTracker",
@@ -325,14 +340,20 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         doReturn(false).when(mDomainSelectionResolver).isDomainSelectionSupported();
         doReturn(null).when(mDomainSelectionResolver).getDomainSelectionConnection(
                 any(), anyInt(), anyBoolean());
+        replaceInstance(SatelliteController.class, "sInstance", null, mSatelliteController);
         replaceInstance(TelephonyConnectionService.class,
                 "mSatelliteController", mTestConnectionService, mSatelliteController);
         doReturn(mMockResources).when(mContext).getResources();
+        replaceInstance(SubscriptionManagerService.class, "sInstance", null,
+                mSubscriptionManagerService);
+
+        mTestConnectionService.onCreate();
+        mTestConnectionService.setTelephonyManagerProxy(mTelephonyManagerProxy);
 
         mBinderStub = (IConnectionService.Stub) mTestConnectionService.onBind(null);
-        mSetFlagsRule.disableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
         mSetFlagsRule.enableFlags(Flags.FLAG_DO_NOT_OVERRIDE_PRECISE_LABEL);
         mSetFlagsRule.enableFlags(Flags.FLAG_CALL_EXTRA_FOR_NON_HOLD_SUPPORTED_CARRIERS);
+        mSetFlagsRule.disableFlags(Flags.FLAG_HANGUP_ACTIVE_CALL_BASED_ON_EMERGENCY_CALL_DOMAIN);
     }
 
     @After
@@ -1510,10 +1531,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         // Satellite is for emergency
         doReturn(true).when(mSatelliteController).getRequestIsEmergency();
         doReturn(1).when(mSatelliteController).getSelectedSatelliteSubId();
-        SubscriptionManagerService isub = mock(SubscriptionManagerService.class);
-        replaceInstance(SubscriptionManagerService.class, "sInstance", null, isub);
         SubscriptionInfoInternal info = mock(SubscriptionInfoInternal.class);
-        doReturn(info).when(isub).getSubscriptionInfoInternal(1);
+        doReturn(info).when(mSubscriptionManagerService).getSubscriptionInfoInternal(1);
 
         // Setup outgoing emergency call
         setupConnectionServiceInApm();
@@ -1547,10 +1566,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         // Satellite is for emergency
         doReturn(true).when(mSatelliteController).getRequestIsEmergency();
         doReturn(1).when(mSatelliteController).getSelectedSatelliteSubId();
-        SubscriptionManagerService isub = mock(SubscriptionManagerService.class);
-        replaceInstance(SubscriptionManagerService.class, "sInstance", null, isub);
         SubscriptionInfoInternal info = mock(SubscriptionInfoInternal.class);
-        doReturn(info).when(isub).getSubscriptionInfoInternal(1);
+        doReturn(info).when(mSubscriptionManagerService).getSubscriptionInfoInternal(1);
 
         // Carrier: shouldTurnOffCarrierSatelliteForEmergencyCall = false
         doReturn(0).when(info).getOnlyNonTerrestrialNetwork();
@@ -1859,6 +1876,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     @Test
     @SmallTest
     public void testSecondCallSameSubWontDisconnect() throws Exception {
+        doReturn(false).when(mTelecomFlags).enableCallSequencing();
         // Previous test gets us into a good enough state
         testIncomingDoesntRequestDisconnect();
 
@@ -2274,6 +2292,35 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         assertEquals(connection1.getState(), android.telecom.Connection.STATE_DISCONNECTED);
     }
 
+    /**
+     * For DSDA devices, verifies that calls on other subs are disconnected based on the passed in
+     * phone account
+     */
+    @Test
+    @SmallTest
+    public void testDisconnectCallsOnOtherSubs() throws Exception {
+        setupForCallTest();
+        when(mTelephonyManagerProxy.isConcurrentCallsPossible()).thenReturn(true);
+        doNothing().when(mContext).startActivityAsUser(any(), any());
+
+        mBinderStub.createConnection(PHONE_ACCOUNT_HANDLE_1, "TC@1",
+                new ConnectionRequest(PHONE_ACCOUNT_HANDLE_1, Uri.parse("tel:16505551212"),
+                        new Bundle()),
+                true, false, null);
+        waitForHandlerAction(mTestConnectionService.getHandler(), TIMEOUT_MS);
+        assertEquals(1, mTestConnectionService.getAllConnections().size());
+
+        TelephonyConnection cn = (TelephonyConnection)
+                mTestConnectionService.getAllConnections().toArray()[0];
+        cn.setActive();
+
+        List<Conferenceable> conferenceables = mTestConnectionService
+                .disconnectAllConferenceablesOnOtherSubs(PHONE_ACCOUNT_HANDLE_2);
+        assertFalse(conferenceables.isEmpty());
+        assertEquals(conferenceables.getFirst(), cn);
+        assertEquals(cn.getState(), android.telecom.Connection.STATE_DISCONNECTED);
+    }
+
     /**
      * Verifies that TelephonyManager is used to determine whether a connection is Emergency when
      * creating an outgoing connection.
@@ -3705,6 +3752,294 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         verify(mEmergencyCallDomainSelectionConnection).reselectDomain(any());
     }
 
+    @Test
+    public void testDomainSelectionAddCsEmergencyCallWhenImsCallActive() throws Exception {
+        mSetFlagsRule.enableFlags(Flags.FLAG_HANGUP_ACTIVE_CALL_BASED_ON_EMERGENCY_CALL_DOMAIN);
+
+        setupForCallTest();
+        doReturn(1).when(mPhone0).getSubId();
+        doReturn(1).when(mImsPhone).getSubId();
+        ImsPhoneCall imsPhoneCall = Mockito.mock(ImsPhoneCall.class);
+        ImsPhoneConnection imsPhoneConnection = Mockito.mock(ImsPhoneConnection.class);
+        when(imsPhoneCall.getPhone()).thenReturn(mImsPhone);
+        when(imsPhoneConnection.getCall()).thenReturn(imsPhoneCall);
+        when(imsPhoneConnection.getPhoneType()).thenReturn(PhoneConstants.PHONE_TYPE_IMS);
+
+        // PROPERTY_IS_EXTERNAL_CALL: to avoid extra processing that is not related to this test.
+        SimpleTelephonyConnection tc1 = createTestConnection(PHONE_ACCOUNT_HANDLE_1,
+                android.telecom.Connection.PROPERTY_IS_EXTERNAL_CALL, false);
+        // IMS connection is set.
+        tc1.setOriginalConnection(imsPhoneConnection);
+        mTestConnectionService.addExistingConnection(PHONE_ACCOUNT_HANDLE_1, tc1);
+
+        assertEquals(1, mTestConnectionService.getAllConnections().size());
+        TelephonyConnection connection1 = (TelephonyConnection)
+                mTestConnectionService.getAllConnections().toArray()[0];
+        assertEquals(tc1, connection1);
+
+        // Add a CS emergency call.
+        String telecomCallId2 = "TC2";
+        int selectedDomain = DOMAIN_CS;
+        setupForDialForDomainSelection(mPhone0, selectedDomain, true);
+        getTestContext().getCarrierConfig(0 /*subId*/).putBoolean(
+                CarrierConfigManager.KEY_ALLOW_HOLD_CALL_DURING_EMERGENCY_BOOL, true);
+
+        mTestConnectionService.onCreateOutgoingConnection(PHONE_ACCOUNT_HANDLE_1,
+                createConnectionRequest(PHONE_ACCOUNT_HANDLE_1,
+                        TEST_EMERGENCY_NUMBER, telecomCallId2));
+
+        // Hang up the active IMS call due to CS emergency call.
+        ArgumentCaptor<Connection.Listener> listenerCaptor =
+                ArgumentCaptor.forClass(Connection.Listener.class);
+        verify(imsPhoneConnection).addListener(listenerCaptor.capture());
+        assertTrue(tc1.wasDisconnected);
+
+        // Call disconnection completed.
+        Connection.Listener listener = listenerCaptor.getValue();
+        assertNotNull(listener);
+        listener.onDisconnect(0);
+
+        // Continue to proceed the outgoing emergency call after active call is disconnected.
+        ArgumentCaptor<android.telecom.Connection> connectionCaptor =
+                ArgumentCaptor.forClass(android.telecom.Connection.class);
+        verify(mDomainSelectionResolver)
+                .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(true));
+        verify(mEmergencyStateTracker)
+                .startEmergencyCall(eq(mPhone0), connectionCaptor.capture(), eq(false));
+        verify(mSatelliteSOSMessageRecommender, times(2))
+                .onEmergencyCallStarted(any(), anyBoolean());
+        verify(mEmergencyCallDomainSelectionConnection).createEmergencyConnection(any(), any());
+        verify(mPhone0).dial(anyString(), any(), any());
+
+        android.telecom.Connection tc = connectionCaptor.getValue();
+        assertNotNull(tc);
+        assertEquals(telecomCallId2, tc.getTelecomCallId());
+        assertEquals(mTestConnectionService.getEmergencyConnection(), tc);
+    }
+
+    @Test
+    public void testDomainSelectionAddImsEmergencyCallWhenCsCallActive() throws Exception {
+        mSetFlagsRule.enableFlags(Flags.FLAG_HANGUP_ACTIVE_CALL_BASED_ON_EMERGENCY_CALL_DOMAIN);
+
+        setupForCallTest();
+
+        // PROPERTY_IS_EXTERNAL_CALL: to avoid extra processing that is not related to this test.
+        SimpleTelephonyConnection tc1 = createTestConnection(PHONE_ACCOUNT_HANDLE_1,
+                android.telecom.Connection.PROPERTY_IS_EXTERNAL_CALL, false);
+        // CS connection is set.
+        tc1.setOriginalConnection(mInternalConnection);
+        mTestConnectionService.addExistingConnection(PHONE_ACCOUNT_HANDLE_1, tc1);
+
+        assertEquals(1, mTestConnectionService.getAllConnections().size());
+        TelephonyConnection connection1 = (TelephonyConnection)
+                mTestConnectionService.getAllConnections().toArray()[0];
+        assertEquals(tc1, connection1);
+
+        // Add an IMS emergency call.
+        String telecomCallId2 = "TC2";
+        int selectedDomain = DOMAIN_PS;
+        setupForDialForDomainSelection(mPhone0, selectedDomain, true);
+        getTestContext().getCarrierConfig(0 /*subId*/).putBoolean(
+                CarrierConfigManager.KEY_ALLOW_HOLD_CALL_DURING_EMERGENCY_BOOL, true);
+
+        mTestConnectionService.onCreateOutgoingConnection(PHONE_ACCOUNT_HANDLE_1,
+                createConnectionRequest(PHONE_ACCOUNT_HANDLE_1,
+                        TEST_EMERGENCY_NUMBER, telecomCallId2));
+
+        // Hang up the active CS call due to IMS emergency call.
+        ArgumentCaptor<Connection.Listener> listenerCaptor =
+                ArgumentCaptor.forClass(Connection.Listener.class);
+        verify(mInternalConnection).addListener(listenerCaptor.capture());
+        assertTrue(tc1.wasDisconnected);
+
+        // Call disconnection completed.
+        Connection.Listener listener = listenerCaptor.getValue();
+        assertNotNull(listener);
+        listener.onDisconnect(0);
+
+        // Continue to proceed the outgoing emergency call after active call is disconnected.
+        ArgumentCaptor<android.telecom.Connection> connectionCaptor =
+                ArgumentCaptor.forClass(android.telecom.Connection.class);
+        verify(mDomainSelectionResolver)
+                .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(true));
+        verify(mEmergencyStateTracker)
+                .startEmergencyCall(eq(mPhone0), connectionCaptor.capture(), eq(false));
+        verify(mSatelliteSOSMessageRecommender, times(2))
+                .onEmergencyCallStarted(any(), anyBoolean());
+        verify(mEmergencyCallDomainSelectionConnection).createEmergencyConnection(any(), any());
+        verify(mPhone0).dial(anyString(), any(), any());
+
+        android.telecom.Connection tc = connectionCaptor.getValue();
+        assertNotNull(tc);
+        assertEquals(telecomCallId2, tc.getTelecomCallId());
+        assertEquals(mTestConnectionService.getEmergencyConnection(), tc);
+    }
+
+    @Test
+    public void testDomainSelectionAddVoWifiEmergencyCallWhenImsCallActive() throws Exception {
+        mSetFlagsRule.enableFlags(Flags.FLAG_HANGUP_ACTIVE_CALL_BASED_ON_EMERGENCY_CALL_DOMAIN);
+
+        setupForCallTest();
+        doReturn(1).when(mPhone0).getSubId();
+        doReturn(1).when(mImsPhone).getSubId();
+        ImsPhoneCall imsPhoneCall = Mockito.mock(ImsPhoneCall.class);
+        ImsPhoneConnection imsPhoneConnection = Mockito.mock(ImsPhoneConnection.class);
+        when(imsPhoneCall.getPhone()).thenReturn(mImsPhone);
+        when(imsPhoneConnection.getCall()).thenReturn(imsPhoneCall);
+        when(imsPhoneConnection.getPhoneType()).thenReturn(PhoneConstants.PHONE_TYPE_IMS);
+
+        // PROPERTY_IS_EXTERNAL_CALL: to avoid extra processing that is not related to this test.
+        SimpleTelephonyConnection tc1 = createTestConnection(PHONE_ACCOUNT_HANDLE_1,
+                android.telecom.Connection.PROPERTY_IS_EXTERNAL_CALL, false);
+        // IMS connection is set.
+        tc1.setOriginalConnection(imsPhoneConnection);
+        mTestConnectionService.addExistingConnection(PHONE_ACCOUNT_HANDLE_1, tc1);
+
+        assertEquals(1, mTestConnectionService.getAllConnections().size());
+        TelephonyConnection connection1 = (TelephonyConnection)
+                mTestConnectionService.getAllConnections().toArray()[0];
+        assertEquals(tc1, connection1);
+
+        // Add VoWifi emergency call.
+        String telecomCallId2 = "TC2";
+        int selectedDomain = PhoneConstants.DOMAIN_NON_3GPP_PS;
+        setupForDialForDomainSelection(mPhone0, selectedDomain, true);
+        getTestContext().getCarrierConfig(0 /*subId*/).putBoolean(
+                CarrierConfigManager.KEY_ALLOW_HOLD_CALL_DURING_EMERGENCY_BOOL, true);
+
+        mTestConnectionService.onCreateOutgoingConnection(PHONE_ACCOUNT_HANDLE_1,
+                createConnectionRequest(PHONE_ACCOUNT_HANDLE_1,
+                        TEST_EMERGENCY_NUMBER, telecomCallId2));
+
+        // Maintain the active IMS call because VoWifi emergency call is made.
+        ArgumentCaptor<Connection.Listener> listenerCaptor =
+                ArgumentCaptor.forClass(Connection.Listener.class);
+        verify(imsPhoneConnection, never()).addListener(listenerCaptor.capture());
+        assertFalse(tc1.wasDisconnected);
+
+        // Continue to proceed the outgoing emergency call without active call disconnection.
+        ArgumentCaptor<android.telecom.Connection> connectionCaptor =
+                ArgumentCaptor.forClass(android.telecom.Connection.class);
+        verify(mDomainSelectionResolver)
+                .getDomainSelectionConnection(eq(mPhone0), eq(SELECTOR_TYPE_CALLING), eq(true));
+        verify(mEmergencyStateTracker)
+                .startEmergencyCall(eq(mPhone0), connectionCaptor.capture(), eq(false));
+        verify(mSatelliteSOSMessageRecommender, times(2))
+                .onEmergencyCallStarted(any(), anyBoolean());
+        verify(mEmergencyCallDomainSelectionConnection).createEmergencyConnection(any(), any());
+        verify(mPhone0).dial(anyString(), any(), any());
+
+        android.telecom.Connection tc = connectionCaptor.getValue();
+        assertNotNull(tc);
+        assertEquals(telecomCallId2, tc.getTelecomCallId());
+        assertEquals(mTestConnectionService.getEmergencyConnection(), tc);
+    }
+
+    @Test
+    @SmallTest
+    public void testDomainSelectionMaybeDisconnectCallsOnOtherDomainWhenNoActiveCalls() {
+        SimpleTelephonyConnection ec = createTestConnection(PHONE_ACCOUNT_HANDLE_1, 0, true);
+        Consumer<Boolean> consumer = (result) -> {
+            if (!result) {
+                fail("Unexpected result=" + result);
+            }
+        };
+        CompletableFuture<Void> unused =
+                TelephonyConnectionService.maybeDisconnectCallsOnOtherDomain(mPhone0,
+                        ec, DOMAIN_PS, Collections.emptyList(), Collections.emptyList(), consumer);
+
+        assertTrue(unused.isDone());
+    }
+
+    @Test
+    @SmallTest
+    public void testDomainSelectionMaybeDisconnectCallsOnOtherDomainWhenConferenceOnly() {
+        setupForCallTest();
+        ArrayList<android.telecom.Conference> conferences = new ArrayList<>();
+        SimpleTelephonyConnection tc1 = createTestConnection(PHONE_ACCOUNT_HANDLE_1, 0, false);
+        SimpleConference conference = createTestConference(PHONE_ACCOUNT_HANDLE_1, 0);
+        tc1.setOriginalConnection(mInternalConnection);
+        conference.addConnection(tc1);
+        conferences.add(conference);
+
+        SimpleTelephonyConnection ec = createTestConnection(PHONE_ACCOUNT_HANDLE_1, 0, true);
+        Consumer<Boolean> consumer = (result) -> {
+            if (!result) {
+                fail("Unexpected result=" + result);
+            }
+        };
+        CompletableFuture<Void> unused =
+                TelephonyConnectionService.maybeDisconnectCallsOnOtherDomain(
+                        mPhone0, ec, DOMAIN_PS, Collections.emptyList(), conferences, consumer);
+
+        assertTrue(unused.isDone());
+        assertTrue(conference.wasDisconnected);
+    }
+
+    @Test
+    @SmallTest
+    public void testDomainSelectionMaybeDisconnectCallsOnOtherDomainWhenActiveCall() {
+        setupForCallTest();
+        ArrayList<android.telecom.Connection> connections = new ArrayList<>();
+        ArrayList<android.telecom.Conference> conferences = new ArrayList<>();
+        SimpleTelephonyConnection tc1 = createTestConnection(PHONE_ACCOUNT_HANDLE_1, 0, false);
+        SimpleConference conference = createTestConference(PHONE_ACCOUNT_HANDLE_1, 0);
+        tc1.setOriginalConnection(mInternalConnection);
+        connections.add(tc1);
+        conference.addConnection(tc1);
+        conferences.add(conference);
+
+        SimpleTelephonyConnection ec = createTestConnection(PHONE_ACCOUNT_HANDLE_1, 0, true);
+        Consumer<Boolean> consumer = (result) -> {
+            if (!result) {
+                fail("Unexpected result=" + result);
+            }
+        };
+        CompletableFuture<Void> unused =
+                TelephonyConnectionService.maybeDisconnectCallsOnOtherDomain(
+                        mPhone0, ec, DOMAIN_PS, connections, conferences, consumer);
+
+        assertFalse(unused.isDone());
+        assertTrue(tc1.wasDisconnected);
+        assertTrue(conference.wasDisconnected);
+
+        ArgumentCaptor<Connection.Listener> listenerCaptor =
+                ArgumentCaptor.forClass(Connection.Listener.class);
+        verify(mInternalConnection).addListener(listenerCaptor.capture());
+
+        // Call disconnection completed.
+        Connection.Listener listener = listenerCaptor.getValue();
+        assertNotNull(listener);
+        listener.onDisconnect(0);
+
+        assertTrue(unused.isDone());
+    }
+
+    @Test
+    @SmallTest
+    public void testDomainSelectionMaybeDisconnectCallsOnOtherDomainWhenExceptionOccurs() {
+        setupForCallTest();
+        ArrayList<android.telecom.Connection> connections = new ArrayList<>();
+        SimpleTelephonyConnection tc1 = createTestConnection(PHONE_ACCOUNT_HANDLE_1, 0, false);
+        tc1.setOriginalConnection(mInternalConnection);
+        connections.add(tc1);
+        doThrow(new NullPointerException("Intended: Connection is null"))
+                .when(mInternalConnection).addListener(any());
+
+        SimpleTelephonyConnection ec = createTestConnection(PHONE_ACCOUNT_HANDLE_1, 0, true);
+        Consumer<Boolean> consumer = (result) -> {
+            if (result) {
+                fail("Unexpected result=" + result);
+            }
+        };
+        CompletableFuture<Void> unused =
+                TelephonyConnectionService.maybeDisconnectCallsOnOtherDomain(
+                        mPhone0, ec, DOMAIN_PS, connections, Collections.emptyList(), consumer);
+
+        assertTrue(unused.isDone());
+        assertFalse(tc1.wasDisconnected);
+    }
+
     @Test
     public void testDomainSelectionWithMmiCode() {
         //UT domain selection should not be handled by new domain selector.
@@ -3714,7 +4049,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         mTestConnectionService.onCreateOutgoingConnection(PHONE_ACCOUNT_HANDLE_1,
                 createConnectionRequest(PHONE_ACCOUNT_HANDLE_1, "*%2321%23", TELECOM_CALL_ID1));
 
-        verifyZeroInteractions(mNormalCallDomainSelectionConnection);
+        verifyNoMoreInteractions(mNormalCallDomainSelectionConnection);
     }
 
     @Test
@@ -3802,8 +4137,6 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
 
     @Test
     public void testNormalCallUsingNonTerrestrialNetwork_enableFlag() throws Exception {
-        mSetFlagsRule.enableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
-
         setupForCallTest();
         // Call is not supported while using satellite
         when(mSatelliteController.isInSatelliteModeForCarrierRoaming(any())).thenReturn(true);
@@ -3829,8 +4162,6 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
 
     @Test
     public void testNormalCallUsingSatelliteConnectedWithinHysteresisTime() throws Exception {
-        mSetFlagsRule.enableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
-
         // Call is not supported when device is connected to satellite within hysteresis time
         setupForCallTest();
         when(mSatelliteController.isInSatelliteModeForCarrierRoaming(any())).thenReturn(true);
@@ -3856,14 +4187,15 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     }
 
     @Test
-    public void testNormalCallUsingNonTerrestrialNetwork_disableFlag() throws Exception {
-        mSetFlagsRule.disableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
-
+    public void testNormalCallUsingNonTerrestrialNetwork_canMakeWifiCall() throws Exception {
         setupForCallTest();
-        // Flag is disabled, so call is supported while using satellite
+        // Call is not supported while using satellite
         when(mSatelliteController.isInSatelliteModeForCarrierRoaming(any())).thenReturn(true);
-        when(mSatelliteController.getCapabilitiesForCarrierRoamingSatelliteMode(any())).thenReturn(
-                List.of(NetworkRegistrationInfo.SERVICE_TYPE_VOICE));
+        when(mSatelliteController.getCapabilitiesForCarrierRoamingSatelliteMode(any()))
+                .thenReturn(List.of(NetworkRegistrationInfo.SERVICE_TYPE_DATA));
+        // Wi-Fi call is possible
+        doReturn(true).when(mImsPhone).canMakeWifiCall();
+        when(mPhone0.getImsPhone()).thenReturn(mImsPhone);
 
         // UnsupportedOperationException is thrown as we cannot perform actual call
         assertThrows(UnsupportedOperationException.class, () -> mTestConnectionService
@@ -3872,22 +4204,32 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     }
 
     @Test
-    public void testNormalCallUsingNonTerrestrialNetwork_canMakeWifiCall() throws Exception {
-        mSetFlagsRule.enableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
+    public void testNormalCallWhenEligibilityIsTrue() throws Exception {
+        mSetFlagsRule.enableFlags(Flags.FLAG_CARRIER_ROAMING_NB_IOT_NTN);
 
         setupForCallTest();
-        // Call is not supported while using satellite
-        when(mSatelliteController.isInSatelliteModeForCarrierRoaming(any())).thenReturn(true);
+
+        // Carrier roaming ntn eligibility is true and call is not supported
+        when(mSatelliteController.getLastNotifiedNtnEligibility(any())).thenReturn(true);
         when(mSatelliteController.getCapabilitiesForCarrierRoamingSatelliteMode(any()))
                 .thenReturn(List.of(NetworkRegistrationInfo.SERVICE_TYPE_DATA));
-        // Wi-Fi call is possible
-        doReturn(true).when(mImsPhone).canMakeWifiCall();
-        when(mPhone0.getImsPhone()).thenReturn(mImsPhone);
+
+        mConnection = mTestConnectionService.onCreateOutgoingConnection(PHONE_ACCOUNT_HANDLE_1,
+                createConnectionRequest(PHONE_ACCOUNT_HANDLE_1, "1234", TELECOM_CALL_ID1));
+        DisconnectCause disconnectCause = mConnection.getDisconnectCause();
+        assertEquals(android.telephony.DisconnectCause.SATELLITE_ENABLED,
+                disconnectCause.getTelephonyDisconnectCause());
+        assertEquals(DISCONNECT_REASON_CARRIER_ROAMING_SATELLITE_MODE, disconnectCause.getReason());
+
+        // Carrier roaming ntn eligibility is true and call is supported
+        setupForCallTest();
+        when(mSatelliteController.getCapabilitiesForCarrierRoamingSatelliteMode(any())).thenReturn(
+                List.of(NetworkRegistrationInfo.SERVICE_TYPE_VOICE));
 
         // UnsupportedOperationException is thrown as we cannot perform actual call
         assertThrows(UnsupportedOperationException.class, () -> mTestConnectionService
                 .onCreateOutgoingConnection(PHONE_ACCOUNT_HANDLE_1,
-                createConnectionRequest(PHONE_ACCOUNT_HANDLE_1, "1234", TELECOM_CALL_ID1)));
+                        createConnectionRequest(PHONE_ACCOUNT_HANDLE_1, "1234", "TC@2")));
     }
 
     @Test
@@ -3905,8 +4247,6 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
 
     @Test
     public void testIsAvailableForEmergencyCallsUsingNonTerrestrialNetwork_enableFlag() {
-        mSetFlagsRule.enableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
-
         // Call is not supported while using satellite
         when(mSatelliteController.isInSatelliteModeForCarrierRoaming(any())).thenReturn(true);
         when(mSatelliteController.getCapabilitiesForCarrierRoamingSatelliteMode(any()))
@@ -3926,34 +4266,8 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 EmergencyNumber.EMERGENCY_CALL_ROUTING_UNKNOWN));
     }
 
-    @Test
-    public void testIsAvailableForEmergencyCallsUsingNonTerrestrialNetwork_disableFlag() {
-        mSetFlagsRule.disableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
-
-        // Call is supported while using satellite
-        when(mSatelliteController.isInSatelliteModeForCarrierRoaming(any())).thenReturn(true);
-        when(mSatelliteController.getCapabilitiesForCarrierRoamingSatelliteMode(any()))
-                .thenReturn(List.of(NetworkRegistrationInfo.SERVICE_TYPE_VOICE));
-        Phone mockPhone = Mockito.mock(Phone.class);
-        ServiceState ss = new ServiceState();
-        ss.setEmergencyOnly(true);
-        ss.setState(ServiceState.STATE_EMERGENCY_ONLY);
-        when(mockPhone.getServiceState()).thenReturn(ss);
-
-        when(mPhoneFactoryProxy.getPhones()).thenReturn(new Phone[] {mockPhone});
-
-        assertTrue(mTestConnectionService.isAvailableForEmergencyCalls(mockPhone,
-                EmergencyNumber.EMERGENCY_CALL_ROUTING_EMERGENCY));
-        assertFalse(mTestConnectionService.isAvailableForEmergencyCalls(mockPhone,
-                EmergencyNumber.EMERGENCY_CALL_ROUTING_NORMAL));
-        assertTrue(mTestConnectionService.isAvailableForEmergencyCalls(mockPhone,
-                EmergencyNumber.EMERGENCY_CALL_ROUTING_UNKNOWN));
-    }
-
     @Test
     public void testIsAvailableForEmergencyCallsUsingNTN_CellularAvailable() {
-        mSetFlagsRule.enableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
-
         // Call is not supported while using satellite
         when(mSatelliteController.isInSatelliteModeForCarrierRoaming(any())).thenReturn(true);
         when(mSatelliteController.getCapabilitiesForCarrierRoamingSatelliteMode(any()))
@@ -3985,8 +4299,6 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
 
     @Test
     public void testIsAvailableForEmergencyCallsUsingNTN_CellularNotAvailable() {
-        mSetFlagsRule.enableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
-
         // Call is not supported while using satellite
         when(mSatelliteController.isInSatelliteModeForCarrierRoaming(any())).thenReturn(true);
         when(mSatelliteController.getCapabilitiesForCarrierRoamingSatelliteMode(any()))
diff --git a/tests/src/com/android/services/telephony/TelephonyConnectionTest.java b/tests/src/com/android/services/telephony/TelephonyConnectionTest.java
index c659d5efa..c6953748d 100644
--- a/tests/src/com/android/services/telephony/TelephonyConnectionTest.java
+++ b/tests/src/com/android/services/telephony/TelephonyConnectionTest.java
@@ -32,6 +32,7 @@ import android.telephony.ims.ImsReasonInfo;
 
 import androidx.test.runner.AndroidJUnit4;
 
+import com.android.TelephonyTestBase;
 import com.android.internal.telephony.Call;
 import com.android.internal.telephony.PhoneConstants;
 import com.android.internal.telephony.d2d.DtmfTransport;
@@ -43,12 +44,11 @@ import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
 
 import java.util.ArrayList;
 
 @RunWith(AndroidJUnit4.class)
-public class TelephonyConnectionTest {
+public class TelephonyConnectionTest extends TelephonyTestBase {
     @Mock
     private ImsPhoneConnection mImsPhoneConnection;
     @Mock
@@ -56,7 +56,8 @@ public class TelephonyConnectionTest {
 
     @Before
     public void setUp() throws Exception {
-        MockitoAnnotations.initMocks(this);
+        super.setUp();
+
         when(mImsPhoneConnection.getState()).thenReturn(Call.State.ACTIVE);
         when(mImsPhoneConnection.getPhoneType()).thenReturn(PhoneConstants.PHONE_TYPE_IMS);
     }
diff --git a/tests/src/com/android/services/telephony/TelephonyManagerTest.java b/tests/src/com/android/services/telephony/TelephonyManagerTest.java
index efb737524..8b4e0fe95 100644
--- a/tests/src/com/android/services/telephony/TelephonyManagerTest.java
+++ b/tests/src/com/android/services/telephony/TelephonyManagerTest.java
@@ -24,8 +24,8 @@ import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.anyInt;
-import static org.mockito.Matchers.anyString;
-import static org.mockito.Matchers.eq;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.times;
diff --git a/tests/src/com/android/services/telephony/TestTelephonyConnection.java b/tests/src/com/android/services/telephony/TestTelephonyConnection.java
index 9f1a0ec21..08bc2eb0c 100644
--- a/tests/src/com/android/services/telephony/TestTelephonyConnection.java
+++ b/tests/src/com/android/services/telephony/TestTelephonyConnection.java
@@ -177,14 +177,14 @@ public class TestTelephonyConnection extends TelephonyConnection {
         when(mMockCall.getPhone()).thenReturn(mMockPhone);
         when(mMockPhone.getDefaultPhone()).thenReturn(mMockPhone);
         when(mImsPhoneConnection.getImsCall()).thenReturn(mImsCall);
-        when(mTelecomAccountRegistry.isMergeCallSupported(notNull(PhoneAccountHandle.class)))
+        when(mTelecomAccountRegistry.isMergeCallSupported(notNull()))
                 .thenReturn(mIsConferenceSupported);
-        when(mTelecomAccountRegistry.isMergeImsCallSupported(notNull(PhoneAccountHandle.class)))
+        when(mTelecomAccountRegistry.isMergeImsCallSupported(notNull()))
                 .thenReturn(mIsImsConnection);
         when(mTelecomAccountRegistry
-                .isVideoConferencingSupported(notNull(PhoneAccountHandle.class))).thenReturn(false);
+                .isVideoConferencingSupported(notNull())).thenReturn(false);
         when(mTelecomAccountRegistry
-                .isMergeOfWifiCallsAllowedWhenVoWifiOff(notNull(PhoneAccountHandle.class)))
+                .isMergeOfWifiCallsAllowedWhenVoWifiOff(notNull()))
                 .thenReturn(false);
         try {
             doNothing().when(mMockCall).hangup();
@@ -301,7 +301,7 @@ public class TestTelephonyConnection extends TelephonyConnection {
 
     public void setIsImsConnection(boolean isImsConnection) {
         mIsImsConnection = isImsConnection;
-        when(mTelecomAccountRegistry.isMergeImsCallSupported(notNull(PhoneAccountHandle.class)))
+        when(mTelecomAccountRegistry.isMergeImsCallSupported(notNull()))
                 .thenReturn(isImsConnection && mIsConferenceSupported);
     }
 
diff --git a/tests/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelectorTest.java b/tests/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelectorTest.java
index 51493d393..e2f503eb5 100644
--- a/tests/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelectorTest.java
+++ b/tests/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelectorTest.java
@@ -77,7 +77,6 @@ import static junit.framework.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
-import static org.mockito.ArgumentMatchers.anyVararg;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doReturn;
@@ -262,7 +261,7 @@ public class EmergencyCallDomainSelectorTest {
         when(mTelecomManager.getCurrentTtyMode()).thenReturn(TelecomManager.TTY_MODE_OFF);
 
         mCarrierConfigManager = mContext.getSystemService(CarrierConfigManager.class);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg()))
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any()))
             .thenReturn(getDefaultPersistableBundle());
 
         mConnectivityManager = mContext.getSystemService(ConnectivityManager.class);
@@ -365,7 +364,7 @@ public class EmergencyCallDomainSelectorTest {
                 CarrierConfigManager.ImsEmergency.DOMAIN_PS_NON_3GPP,
                 };
         bundle.putIntArray(KEY_EMERGENCY_DOMAIN_PREFERENCE_INT_ARRAY, domainPreference);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -431,7 +430,7 @@ public class EmergencyCallDomainSelectorTest {
                 CarrierConfigManager.ImsEmergency.DOMAIN_CS
                 };
         bundle.putIntArray(KEY_EMERGENCY_DOMAIN_PREFERENCE_INT_ARRAY, domainPreference);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(true);
@@ -774,7 +773,7 @@ public class EmergencyCallDomainSelectorTest {
     public void testAirplaneRequiresRegCombinedImsNotRegisteredSelectPs() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_REQUIRES_IMS_REGISTRATION_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -803,7 +802,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putIntArray(KEY_EMERGENCY_OVER_CS_SUPPORTED_ACCESS_NETWORK_TYPES_INT_ARRAY,
                 new int[0]);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -1080,7 +1079,7 @@ public class EmergencyCallDomainSelectorTest {
                 CarrierConfigManager.ImsEmergency.DOMAIN_CS
                 };
         bundle.putIntArray(KEY_EMERGENCY_DOMAIN_PREFERENCE_INT_ARRAY, domainPreference);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -1114,7 +1113,7 @@ public class EmergencyCallDomainSelectorTest {
                 CarrierConfigManager.ImsEmergency.DOMAIN_CS
                 };
         bundle.putIntArray(KEY_EMERGENCY_DOMAIN_PREFERENCE_INT_ARRAY, domainPreference);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -1139,7 +1138,7 @@ public class EmergencyCallDomainSelectorTest {
                 CarrierConfigManager.ImsEmergency.DOMAIN_PS_3GPP
                 };
         bundle.putIntArray(KEY_EMERGENCY_DOMAIN_PREFERENCE_INT_ARRAY, domainPreference);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -1465,7 +1464,7 @@ public class EmergencyCallDomainSelectorTest {
     public void testVoLteOnEpsImsNotRegisteredSelectPs() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_REQUIRES_VOLTE_ENABLED_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -1488,7 +1487,7 @@ public class EmergencyCallDomainSelectorTest {
     public void testVoLteOffEpsImsNotRegisteredScanCsPreferred() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_REQUIRES_VOLTE_ENABLED_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         // Disable VoLTE.
         when(mMmTelManager.isAdvancedCallingSettingEnabled()).thenReturn(false);
@@ -1514,7 +1513,7 @@ public class EmergencyCallDomainSelectorTest {
     public void testRequiresRegEpsImsNotRegisteredScanCsPreferred() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_REQUIRES_IMS_REGISTRATION_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -1538,7 +1537,7 @@ public class EmergencyCallDomainSelectorTest {
 
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_REQUIRES_IMS_REGISTRATION_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -1561,7 +1560,7 @@ public class EmergencyCallDomainSelectorTest {
             throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_REQUIRES_IMS_REGISTRATION_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -1583,7 +1582,7 @@ public class EmergencyCallDomainSelectorTest {
     public void testDefaultEpsImsRegisteredBarredScanTimeoutWifi() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         mResultConsumer = null;
         createSelector(SLOT_0_SUB_ID);
@@ -1627,7 +1626,7 @@ public class EmergencyCallDomainSelectorTest {
                 TelephonyManager.SIM_STATE_PIN_REQUIRED);
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(true);
@@ -1652,7 +1651,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
         bundle.putInt(KEY_EMERGENCY_VOWIFI_REQUIRES_CONDITION_INT, VOWIFI_REQUIRES_SETTING_ENABLED);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(true);
@@ -1692,7 +1691,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
         bundle.putInt(KEY_EMERGENCY_VOWIFI_REQUIRES_CONDITION_INT, VOWIFI_REQUIRES_VALID_EID);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(true);
@@ -2002,7 +2001,7 @@ public class EmergencyCallDomainSelectorTest {
     public void testFullService() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putInt(KEY_EMERGENCY_NETWORK_SCAN_TYPE_INT, SCAN_TYPE_FULL_SERVICE);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         mResultConsumer = null;
         createSelector(SLOT_0_SUB_ID);
@@ -2035,7 +2034,7 @@ public class EmergencyCallDomainSelectorTest {
     public void testFullServiceInDomesticRoaming() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putInt(KEY_EMERGENCY_NETWORK_SCAN_TYPE_INT, SCAN_TYPE_FULL_SERVICE);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
         doReturn("us").when(mTelephonyManager).getSimCountryIso();
 
         createSelector(SLOT_0_SUB_ID);
@@ -2060,7 +2059,7 @@ public class EmergencyCallDomainSelectorTest {
     public void testFullServiceInInterNationalRoaming() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putInt(KEY_EMERGENCY_NETWORK_SCAN_TYPE_INT, SCAN_TYPE_FULL_SERVICE);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
         doReturn("us").when(mTelephonyManager).getSimCountryIso();
 
         createSelector(SLOT_0_SUB_ID);
@@ -2086,7 +2085,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putInt(KEY_EMERGENCY_NETWORK_SCAN_TYPE_INT,
                 SCAN_TYPE_FULL_SERVICE_FOLLOWED_BY_LIMITED_SERVICE);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         mResultConsumer = null;
         createSelector(SLOT_0_SUB_ID);
@@ -2367,7 +2366,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -2395,7 +2394,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -2423,7 +2422,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -2451,7 +2450,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -2479,7 +2478,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -2513,7 +2512,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_SCAN_LIMITED_SERVICE_AFTER_VOLTE_FAILURE_BOOL,
                 true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -2767,7 +2766,7 @@ public class EmergencyCallDomainSelectorTest {
     public void testScanTimeoutWifiNotAvailable() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -2814,7 +2813,7 @@ public class EmergencyCallDomainSelectorTest {
     public void testCrossStackTimerExpiredHangupOngoingDialing() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putInt(KEY_EMERGENCY_CALL_SETUP_TIMER_ON_CURRENT_NETWORK_SEC_INT, 1);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         mSetFlagsRule.enableFlags(Flags.FLAG_HANGUP_EMERGENCY_CALL_FOR_CROSS_SIM_REDIALING);
 
@@ -2844,7 +2843,7 @@ public class EmergencyCallDomainSelectorTest {
     public void testCrossStackTimerExpiredNotHangupOngoingDialing() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putInt(KEY_EMERGENCY_CALL_SETUP_TIMER_ON_CURRENT_NETWORK_SEC_INT, 1);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
         doReturn(true).when(mImsEmergencyRegistrationHelper).isImsEmergencyRegistered();
 
         mSetFlagsRule.enableFlags(Flags.FLAG_HANGUP_EMERGENCY_CALL_FOR_CROSS_SIM_REDIALING);
@@ -2876,7 +2875,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
         bundle.putInt(KEY_MAXIMUM_CELLULAR_SEARCH_TIMER_SEC_INT, 20);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         setupForHandleScanResult();
 
@@ -2901,7 +2900,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
         bundle.putInt(KEY_MAXIMUM_CELLULAR_SEARCH_TIMER_SEC_INT, 20);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         setupForHandleScanResult();
 
@@ -2932,7 +2931,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
         bundle.putInt(KEY_MAXIMUM_CELLULAR_SEARCH_TIMER_SEC_INT, 20);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         setupForHandleScanResult();
 
@@ -2945,7 +2944,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
         bundle.putInt(KEY_MAXIMUM_CELLULAR_SEARCH_TIMER_SEC_INT, 20);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         setupForHandleScanResult();
 
@@ -2970,7 +2969,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
         bundle.putInt(KEY_MAXIMUM_CELLULAR_SEARCH_TIMER_SEC_INT, 5);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -3024,7 +3023,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
         bundle.putInt(KEY_MAXIMUM_CELLULAR_SEARCH_TIMER_SEC_INT, 5);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -3103,7 +3102,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
         bundle.putInt(KEY_MAXIMUM_CELLULAR_SEARCH_TIMER_SEC_INT, 20);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         setupForHandleScanResult();
 
@@ -3129,7 +3128,7 @@ public class EmergencyCallDomainSelectorTest {
         bundle.putBoolean(KEY_EMERGENCY_CALL_OVER_EMERGENCY_PDN_BOOL, true);
         bundle.putInt(KEY_MAXIMUM_CELLULAR_SEARCH_TIMER_SEC_INT, 20);
         bundle.putInt(KEY_MAXIMUM_NUMBER_OF_EMERGENCY_TRIES_OVER_VOWIFI_INT, 2);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         setupForHandleScanResult();
 
@@ -3290,7 +3289,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_SCAN_LIMITED_SERVICE_AFTER_VOLTE_FAILURE_BOOL,
                 true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -3351,7 +3350,7 @@ public class EmergencyCallDomainSelectorTest {
     public void testDefaultLimitedServiceScanTypeFullService() throws Exception {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putInt(KEY_EMERGENCY_NETWORK_SCAN_TYPE_INT, SCAN_TYPE_FULL_SERVICE);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -3374,7 +3373,7 @@ public class EmergencyCallDomainSelectorTest {
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
         bundle.putBoolean(KEY_EMERGENCY_LTE_PREFERRED_AFTER_NR_FAILED_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
         doReturn(DATA_CONNECTED).when(mEpdnHelper).getDataConnectionState(anyInt());
 
         createSelector(SLOT_0_SUB_ID);
@@ -3412,7 +3411,7 @@ public class EmergencyCallDomainSelectorTest {
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
         bundle.putBoolean(KEY_EMERGENCY_LTE_PREFERRED_AFTER_NR_FAILED_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
         doReturn(DATA_CONNECTED).when(mEpdnHelper).getDataConnectionState(anyInt());
 
         createSelector(SLOT_0_SUB_ID);
@@ -3459,7 +3458,7 @@ public class EmergencyCallDomainSelectorTest {
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
         bundle.putBoolean(KEY_EMERGENCY_LTE_PREFERRED_AFTER_NR_FAILED_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
         doReturn(DATA_CONNECTED).when(mEpdnHelper).getDataConnectionState(anyInt());
 
         createSelector(SLOT_0_SUB_ID);
@@ -3496,7 +3495,7 @@ public class EmergencyCallDomainSelectorTest {
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
         bundle.putBoolean(KEY_EMERGENCY_LTE_PREFERRED_AFTER_NR_FAILED_BOOL, true);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
         doReturn(DATA_CONNECTED).when(mEpdnHelper).getDataConnectionState(anyInt());
 
         createSelector(SLOT_0_SUB_ID);
@@ -3540,7 +3539,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
         doReturn(DATA_CONNECTED).when(mEpdnHelper).getDataConnectionState(anyInt());
 
         createSelector(SLOT_0_SUB_ID);
@@ -3578,7 +3577,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
         doReturn(DATA_CONNECTED).when(mEpdnHelper).getDataConnectionState(anyInt());
 
         createSelector(SLOT_0_SUB_ID);
@@ -3633,7 +3632,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -3655,7 +3654,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
                 new int[] { NGRAN, EUTRAN });
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -3729,6 +3728,29 @@ public class EmergencyCallDomainSelectorTest {
         verifyScanPsPreferred();
     }
 
+    @Test
+    public void testNgranNotSupportEmcSupportEmf() throws Exception {
+        PersistableBundle bundle = getDefaultPersistableBundle();
+        bundle.putIntArray(KEY_EMERGENCY_OVER_IMS_SUPPORTED_3GPP_NETWORK_TYPES_INT_ARRAY,
+                new int[] { NGRAN, EUTRAN });
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
+        doReturn(DATA_CONNECTED).when(mEpdnHelper).getDataConnectionState(anyInt());
+
+        createSelector(SLOT_0_SUB_ID);
+        unsolBarringInfoChanged(false);
+
+        EmergencyRegistrationResult regResult = getEmergencyRegResult(NGRAN,
+                REGISTRATION_STATE_HOME,
+                NetworkRegistrationInfo.DOMAIN_PS, true, false, 2, 1, "", "");
+        SelectionAttributes attr = getSelectionAttributes(SLOT_0, SLOT_0_SUB_ID, regResult);
+        mDomainSelector.selectDomain(attr, mTransportSelectorCallback);
+        processAllMessages();
+
+        bindImsServiceUnregistered();
+
+        verifyScanPsPreferred();
+    }
+
     @Test
     public void testTestEmergencyNumberOverCs() throws Exception {
         createSelector(SLOT_0_SUB_ID);
@@ -3951,7 +3973,7 @@ public class EmergencyCallDomainSelectorTest {
                 CarrierConfigManager.ImsEmergency.DOMAIN_CS,
                 };
         bundle.putIntArray(KEY_EMERGENCY_DOMAIN_PREFERENCE_ROAMING_INT_ARRAY, domainPreferenceRoam);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
         doReturn("").when(mTelephonyManager).getNetworkCountryIso();
         doReturn("us").when(mTelephonyManager).getSimCountryIso();
 
@@ -4055,7 +4077,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putIntArray(KEY_IMS_REASONINFO_CODE_TO_RETRY_EMERGENCY_INT_ARRAY,
                 new int[] { ImsReasonInfo.CODE_SIP_FORBIDDEN });
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -4232,7 +4254,7 @@ public class EmergencyCallDomainSelectorTest {
         PersistableBundle bundle = getDefaultPersistableBundle();
         bundle.putBoolean(KEY_CARRIER_VOLTE_TTY_SUPPORTED_BOOL, true);
         bundle.putInt(KEY_MAXIMUM_CELLULAR_SEARCH_TIMER_SEC_INT, 20);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
@@ -4270,7 +4292,7 @@ public class EmergencyCallDomainSelectorTest {
                     new int[] { NGRAN, EUTRAN });
         bundle.putBoolean(KEY_CARRIER_VOLTE_TTY_SUPPORTED_BOOL, false);
         bundle.putInt(KEY_MAXIMUM_CELLULAR_SEARCH_TIMER_SEC_INT, 20);
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         when(mTelecomManager.getCurrentTtyMode()).thenReturn(TelecomManager.TTY_MODE_FULL);
 
@@ -4627,7 +4649,7 @@ public class EmergencyCallDomainSelectorTest {
     }
 
     private void setupForScanListTest(PersistableBundle bundle, boolean psFailed) throws Exception {
-        when(mCarrierConfigManager.getConfigForSubId(anyInt(), anyVararg())).thenReturn(bundle);
+        when(mCarrierConfigManager.getConfigForSubId(anyInt(), any())).thenReturn(bundle);
 
         createSelector(SLOT_0_SUB_ID);
         unsolBarringInfoChanged(false);
diff --git a/tests/src/com/android/services/telephony/domainselection/NormalCallDomainSelectorTest.java b/tests/src/com/android/services/telephony/domainselection/NormalCallDomainSelectorTest.java
index 7acc7d6b3..854016ec3 100644
--- a/tests/src/com/android/services/telephony/domainselection/NormalCallDomainSelectorTest.java
+++ b/tests/src/com/android/services/telephony/domainselection/NormalCallDomainSelectorTest.java
@@ -667,6 +667,56 @@ public class NormalCallDomainSelectorTest {
                 mNormalCallDomainSelector.getSelectorState());
     }
 
+    @Test
+    public void testEmcPsFailureAndCsRedial() {
+        final TestTransportSelectorCallback transportSelectorCallback =
+                new TestTransportSelectorCallback(mNormalCallDomainSelector);
+
+        final ServiceState serviceState = new ServiceState();
+
+        // dial PS call with APN-ON
+        serviceState.setStateOutOfService();
+        initialize(serviceState, true, true, true, false);
+        DomainSelectionService.SelectionAttributes attributes =
+                new DomainSelectionService.SelectionAttributes.Builder(
+                        SLOT_ID, SUB_ID_1, SELECTOR_TYPE_CALLING)
+                        .setAddress(TEST_URI)
+                        .setCallId(TEST_CALLID)
+                        .setEmergency(false)
+                        .setVideoCall(false)
+                        .setExitedFromAirplaneMode(true)
+                        .build();
+
+        mNormalCallDomainSelector.selectDomain(attributes, transportSelectorCallback);
+
+        processAllMessages();
+        assertTrue(transportSelectorCallback.mWlanSelected);
+        assertEquals(NormalCallDomainSelector.SelectorState.INACTIVE,
+                mNormalCallDomainSelector.getSelectorState());
+
+        // CODE_LOCAL_CALL_CS_RETRY_REQUIRED when ServiceState is OOS
+        final ImsReasonInfo imsReasonInfoCsRetry = new ImsReasonInfo(
+                ImsReasonInfo.CODE_LOCAL_CALL_CS_RETRY_REQUIRED, 0, null);
+        transportSelectorCallback.reset();
+
+        attributes = new DomainSelectionService.SelectionAttributes.Builder(
+                SLOT_ID, SUB_ID_1, SELECTOR_TYPE_CALLING)
+                .setAddress(TEST_URI)
+                .setCallId(TEST_CALLID)
+                .setEmergency(false)
+                .setVideoCall(false)
+                .setExitedFromAirplaneMode(true)
+                .setPsDisconnectCause(imsReasonInfoCsRetry)
+                .build();
+
+        mNormalCallDomainSelector.reselectDomain(attributes);
+
+        processAllMessages();
+        assertEquals(NetworkRegistrationInfo.DOMAIN_CS, transportSelectorCallback.mSelectedDomain);
+        assertEquals(NormalCallDomainSelector.SelectorState.INACTIVE,
+                mNormalCallDomainSelector.getSelectorState());
+    }
+
     @Test
     public void testImsRegistrationStateTimeoutMessage() {
         final TestTransportSelectorCallback transportSelectorCallback =
diff --git a/tests/src/com/android/services/telephony/rcs/SipSessionTrackerTest.java b/tests/src/com/android/services/telephony/rcs/SipSessionTrackerTest.java
index 387432165..dfe96ef04 100644
--- a/tests/src/com/android/services/telephony/rcs/SipSessionTrackerTest.java
+++ b/tests/src/com/android/services/telephony/rcs/SipSessionTrackerTest.java
@@ -43,6 +43,7 @@ import android.util.Base64;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
+import com.android.TelephonyTestBase;
 import com.android.internal.telephony.ISipDialogStateCallback;
 import com.android.internal.telephony.ITelephony;
 import com.android.internal.telephony.PhoneFactory;
@@ -64,7 +65,7 @@ import java.util.Set;
 import java.util.stream.Collectors;
 
 @RunWith(AndroidJUnit4.class)
-public class SipSessionTrackerTest {
+public class SipSessionTrackerTest extends TelephonyTestBase {
 
     private class DialogAttributes {
         public final String branchId;
@@ -133,6 +134,8 @@ public class SipSessionTrackerTest {
 
     @Before
     public void setUp() throws Exception {
+        super.setUp();
+
         mStringEntryCounter = 0;
         MockitoAnnotations.initMocks(this);
         mTrackerUT = new SipSessionTracker(TEST_SUB_ID, mRcsStats);
diff --git a/tests/src/com/android/services/telephony/rcs/SipTransportControllerTest.java b/tests/src/com/android/services/telephony/rcs/SipTransportControllerTest.java
index df7a37ebe..4ec5e6291 100644
--- a/tests/src/com/android/services/telephony/rcs/SipTransportControllerTest.java
+++ b/tests/src/com/android/services/telephony/rcs/SipTransportControllerTest.java
@@ -21,6 +21,7 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeNotNull;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
@@ -717,7 +718,9 @@ public class SipTransportControllerTest extends TelephonyTestBase {
     @SmallTest
     @Test
     public void testFeatureTagsDeniedByOverride() throws Exception {
-        RcsProvisioningMonitor.getInstance().overrideImsFeatureValidation(TEST_SUB_ID, false);
+        RcsProvisioningMonitor monitor = RcsProvisioningMonitor.getInstance();
+        assumeNotNull(monitor);
+        monitor.overrideImsFeatureValidation(TEST_SUB_ID, false);
         SipTransportController controller = setupLiveTransportController(THROTTLE_MS, 0);
 
         ArraySet<String> requestTags = new ArraySet<>(getBaseDelegateRequest().getFeatureTags());
@@ -737,8 +740,10 @@ public class SipTransportControllerTest extends TelephonyTestBase {
     @SmallTest
     @Test
     public void testFeatureTagsDeniedByConfigAllowedByOverride() throws Exception {
+        RcsProvisioningMonitor monitor = RcsProvisioningMonitor.getInstance();
+        assumeNotNull(monitor);
         setFeatureAllowedConfig(TEST_SUB_ID, new String[]{});
-        RcsProvisioningMonitor.getInstance().overrideImsFeatureValidation(TEST_SUB_ID, true);
+        monitor.overrideImsFeatureValidation(TEST_SUB_ID, true);
         SipTransportController controller = setupLiveTransportController(THROTTLE_MS, 0);
 
         ArraySet<String> requestTags = new ArraySet<>(getBaseDelegateRequest().getFeatureTags());
diff --git a/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ConfigDataGenerator.java b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ConfigDataGenerator.java
index 7e29e9ab1..974d0b479 100644
--- a/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ConfigDataGenerator.java
+++ b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/ConfigDataGenerator.java
@@ -47,6 +47,7 @@ public class ConfigDataGenerator {
     public static final String TAG_S2_CELL_FILE = "s2_cell_file";
     public static final String TAG_COUNTRY_CODE = "country_code";
     public static final String TAG_IS_ALLOWED = "is_allowed";
+    public static final String TAG_SATELLITE_ACCESS_CONFIG_FILE = "satellite_access_config_file";
 
     /**
      * Creates a protubuf file with user inputs
@@ -192,6 +193,7 @@ public class ConfigDataGenerator {
      *   &lt;country_code&gt;value2&lt;/country_code&gt;
      *   &lt;country_code&gt;value3&lt;/country_code&gt;
      *   &lt;is_allowed&gt;value4&lt;/is_allowed&gt;
+     *   &lt;satellite_access_config_file&gt;value5lt;/satellite_access_config_file&gt;
      * &lt;/satelliteregion&gt;
      * </pre>
      */
@@ -208,9 +210,22 @@ public class ConfigDataGenerator {
             if (isAllowedString.equals("TRUE")) {
                 isAllowed = true;
             }
+            String satelliteAccessConfigFileName = "";
+            if (satelliteRegionElement
+                            .getElementsByTagName(TAG_SATELLITE_ACCESS_CONFIG_FILE)
+                            .getLength()
+                    > 0) {
+                satelliteAccessConfigFileName =
+                        satelliteRegionElement
+                                .getElementsByTagName(TAG_SATELLITE_ACCESS_CONFIG_FILE)
+                                .item(0)
+                                .getTextContent();
+            }
             System.out.println("\nSatellite Region:");
             System.out.println("  S2 Cell File: " + s2CellFileName);
             System.out.println("  Is Allowed: " + isAllowed);
+            System.out.println(
+                    "  Satellite Access Config File Name: " + satelliteAccessConfigFileName);
 
             NodeList countryCodesList = satelliteRegionElement.getElementsByTagName(
                     TAG_COUNTRY_CODE);
@@ -226,8 +241,11 @@ public class ConfigDataGenerator {
             }
             System.out.println();
             SatelliteConfigProtoGenerator.sRegionProto =
-                    new RegionProto(s2CellFileName, listCountryCode, isAllowed);
+                    new RegionProto(
+                            s2CellFileName,
+                            listCountryCode,
+                            isAllowed,
+                            satelliteAccessConfigFileName);
         }
     }
 }
-
diff --git a/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/RegionProto.java b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/RegionProto.java
index be3b0cc5d..9dd724721 100644
--- a/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/RegionProto.java
+++ b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/RegionProto.java
@@ -21,10 +21,16 @@ public class RegionProto {
     String mS2CellFileName;
     String[] mCountryCodeList;
     boolean mIsAllowed;
+    String mSatelliteAccessConfigFileName;
 
-    public RegionProto(String s2CellFileName, String[] countryCodeList, boolean isAllowed) {
+    public RegionProto(
+            String s2CellFileName,
+            String[] countryCodeList,
+            boolean isAllowed,
+            String satelliteAccessConfigFileName) {
         mS2CellFileName = s2CellFileName;
         mCountryCodeList = countryCodeList;
         mIsAllowed = isAllowed;
+        mSatelliteAccessConfigFileName = satelliteAccessConfigFileName;
     }
 }
diff --git a/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/SatelliteConfigProtoGenerator.java b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/SatelliteConfigProtoGenerator.java
index 740e2ea94..c4610c71a 100644
--- a/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/SatelliteConfigProtoGenerator.java
+++ b/utils/satellite/configdatagenerator/src/main/java/com/android/telephony/tools/configdatagenerate/SatelliteConfigProtoGenerator.java
@@ -88,6 +88,8 @@ public class SatelliteConfigProtoGenerator {
             // satelliteRegionBuilder
             SatelliteConfigData.SatelliteRegionProto.Builder satelliteRegionBuilder =
                     SatelliteConfigData.SatelliteRegionProto.newBuilder();
+
+            // mS2CellFileName
             byte[] binaryData;
             try {
                 binaryData = readFileToByteArray(sRegionProto.mS2CellFileName);
@@ -99,11 +101,38 @@ public class SatelliteConfigProtoGenerator {
                 satelliteRegionBuilder.setS2CellFile(ByteString.copyFrom(binaryData));
             }
 
+            // mCountryCodeList
             String[] countryCodeList = sRegionProto.mCountryCodeList;
             for (int i = 0; i < countryCodeList.length; i++) {
                 satelliteRegionBuilder.addCountryCodes(countryCodeList[i]);
             }
+
+            // mIsAllowed
             satelliteRegionBuilder.setIsAllowed(sRegionProto.mIsAllowed);
+
+            // mSatelliteAccessConfigFileName
+            if (sRegionProto.mSatelliteAccessConfigFileName != null
+                    && sRegionProto.mSatelliteAccessConfigFileName.length() > 0) {
+                byte[] satelliteAccessBinaryData;
+                try {
+                    System.out.println(
+                            "ConfigDataGenerator: mSatelliteAccessConfigFileName: "
+                                    + sRegionProto.mSatelliteAccessConfigFileName);
+                    satelliteAccessBinaryData =
+                            readFileToByteArray(sRegionProto.mSatelliteAccessConfigFileName);
+                } catch (IOException e) {
+                    throw new RuntimeException(
+                            "Got exception in reading the mSatelliteAccessConfigFileName "
+                                    + sRegionProto.mSatelliteAccessConfigFileName
+                                    + ", e="
+                                    + e);
+                }
+                if (satelliteAccessBinaryData != null) {
+                    satelliteRegionBuilder.setSatelliteAccessConfigFile(
+                            ByteString.copyFrom(satelliteAccessBinaryData));
+                }
+            }
+
             satelliteConfigBuilder.setDeviceSatelliteRegion(satelliteRegionBuilder);
         } else {
             System.out.print("RegionProto does not exist");
@@ -134,19 +163,19 @@ public class SatelliteConfigProtoGenerator {
     }
 
     private static byte[] readFileToByteArray(String fileName) throws IOException {
-        File sat2File = new File(fileName);
-        if (!sat2File.exists()) {
-            throw new IOException("sat2File " + fileName + " does not exist");
+        File file = new File(fileName);
+        if (!file.exists()) {
+            throw new IOException("File: " + fileName + " does not exist");
         }
 
-        if (sat2File.exists() && sat2File.canRead()) {
-            FileInputStream fileInputStream = new FileInputStream(sat2File);
+        if (file.exists() && file.canRead()) {
+            FileInputStream fileInputStream = new FileInputStream(file);
             long fileSize = fileInputStream.available();
             byte[] bytes = new byte[(int) fileSize];
             int bytesRead = fileInputStream.read(bytes);
             fileInputStream.close();
             if (bytesRead != fileSize) {
-                throw new IOException("file read fail: " + sat2File.getCanonicalPath());
+                throw new IOException("file read fail: " + file.getCanonicalPath());
             }
             return bytes;
         }
diff --git a/utils/satellite/configdatagenerator/src/test/java/com/android/telephony/tools/configdatagenerate/ConfigDataGeneratorTest.java b/utils/satellite/configdatagenerator/src/test/java/com/android/telephony/tools/configdatagenerate/ConfigDataGeneratorTest.java
index f588815fb..baf8f9f59 100644
--- a/utils/satellite/configdatagenerator/src/test/java/com/android/telephony/tools/configdatagenerate/ConfigDataGeneratorTest.java
+++ b/utils/satellite/configdatagenerator/src/test/java/com/android/telephony/tools/configdatagenerate/ConfigDataGeneratorTest.java
@@ -82,8 +82,25 @@ public class ConfigDataGeneratorTest {
         ByteString inputByteStringForS2Cell = ByteString.copyFromUtf8("Test ByteString!");
         writeByteStringToFile(inputS2CellFileName, inputByteStringForS2Cell);
 
-        createInputXml(inputFile, 14, 1, "310062222", 1,
-                "US", true, inputS2CellFileName);
+        Path inputSatelliteAccessConfigFilePath =
+                inputDirPath.resolve("satellite_access_config.json");
+        String inputSatelliteAccessConfigFileAbsolutePath =
+                inputSatelliteAccessConfigFilePath.toAbsolutePath().toString();
+        ByteString inputSatelliteAccessConfigContent =
+                ByteString.copyFromUtf8("Test ByteString for satellite access config!");
+        writeByteStringToFile(
+                inputSatelliteAccessConfigFileAbsolutePath, inputSatelliteAccessConfigContent);
+
+        createInputXml(
+                inputFile,
+                14,
+                1,
+                "310062222",
+                1,
+                "US",
+                true,
+                inputS2CellFileName,
+                inputSatelliteAccessConfigFileAbsolutePath);
         String[] args = {
                 "--input-file", inputFilePath.toAbsolutePath().toString(),
                 "--output-file", outputFilePath.toAbsolutePath().toString()
@@ -113,8 +130,25 @@ public class ConfigDataGeneratorTest {
         ByteString inputByteStringForS2Cell = ByteString.copyFromUtf8("Test ByteString!");
         writeByteStringToFile(inputS2CellFileName, inputByteStringForS2Cell);
 
-        createInputXml(inputFile, 14, 1, "31006", -1,
-                "US", true, inputS2CellFileName);
+        Path inputSatelliteAccessConfigFilePath =
+                inputDirPath.resolve("satellite_access_config.json");
+        String inputSatelliteAccessConfigFileAbsolutePath =
+                inputSatelliteAccessConfigFilePath.toAbsolutePath().toString();
+        ByteString inputSatelliteAccessConfigContent =
+                ByteString.copyFromUtf8("Test ByteString for satellite access config!");
+        writeByteStringToFile(
+                inputSatelliteAccessConfigFileAbsolutePath, inputSatelliteAccessConfigContent);
+
+        createInputXml(
+                inputFile,
+                14,
+                1,
+                "31006",
+                -1,
+                "US",
+                true,
+                inputS2CellFileName,
+                inputSatelliteAccessConfigFileAbsolutePath);
         String[] args = {
                 "--input-file", inputFilePath.toAbsolutePath().toString(),
                 "--output-file", outputFilePath.toAbsolutePath().toString()
@@ -144,8 +178,25 @@ public class ConfigDataGeneratorTest {
         ByteString inputByteStringForS2Cell = ByteString.copyFromUtf8("Test ByteString!");
         writeByteStringToFile(inputS2CellFileName, inputByteStringForS2Cell);
 
-        createInputXml(inputFile, 14, 1, "31006", 1,
-                "USSSS", true, inputS2CellFileName);
+        Path inputSatelliteAccessConfigFilePath =
+                inputDirPath.resolve("satellite_access_config.json");
+        String inputSatelliteAccessConfigFileAbsolutePath =
+                inputSatelliteAccessConfigFilePath.toAbsolutePath().toString();
+        ByteString inputSatelliteAccessConfigContent =
+                ByteString.copyFromUtf8("Test ByteString for satellite access config!");
+        writeByteStringToFile(
+                inputSatelliteAccessConfigFileAbsolutePath, inputSatelliteAccessConfigContent);
+
+        createInputXml(
+                inputFile,
+                14,
+                1,
+                "31006",
+                1,
+                "USSSS",
+                true,
+                inputS2CellFileName,
+                inputSatelliteAccessConfigFileAbsolutePath);
         String[] args = {
                 "--input-file", inputFilePath.toAbsolutePath().toString(),
                 "--output-file", outputFilePath.toAbsolutePath().toString()
@@ -183,8 +234,26 @@ public class ConfigDataGeneratorTest {
         boolean inputIsAllowed = true;
         ByteString inputByteStringForS2Cell = ByteString.copyFromUtf8("Test ByteString!");
         writeByteStringToFile(inputS2CellFileName, inputByteStringForS2Cell);
-        createInputXml(inputFile, inputVersion, inputCarrierId, inputPlmn, inputAllowedService,
-                inputCountryCode, inputIsAllowed, inputS2CellFileName);
+
+        Path inputSatelliteAccessConfigFilePath =
+                inputDirPath.resolve("satellite_access_config.json");
+        String inputSatelliteAccessConfigFileAbsolutePath =
+                inputSatelliteAccessConfigFilePath.toAbsolutePath().toString();
+        ByteString inputSatelliteAccessConfigContent =
+                ByteString.copyFromUtf8("Test ByteString for satellite access config!");
+        writeByteStringToFile(
+                inputSatelliteAccessConfigFileAbsolutePath, inputSatelliteAccessConfigContent);
+
+        createInputXml(
+                inputFile,
+                inputVersion,
+                inputCarrierId,
+                inputPlmn,
+                inputAllowedService,
+                inputCountryCode,
+                inputIsAllowed,
+                inputS2CellFileName,
+                inputSatelliteAccessConfigFileAbsolutePath);
         String[] args = {
                 "--input-file", inputFilePath.toAbsolutePath().toString(),
                 "--output-file", outputFilePath.toAbsolutePath().toString()
@@ -221,10 +290,62 @@ public class ConfigDataGeneratorTest {
         assertEquals(inputS2CellFile, s2cellfile);
         boolean isAllowed = regionProto.getIsAllowed();
         assertEquals(inputIsAllowed, isAllowed);
+
+        ByteString outputSatelliteAccessConfigFileContent =
+                regionProto.getSatelliteAccessConfigFile();
+        byte[] inputSatelliteAccessConfigFileContentAsBytes =
+                Files.readAllBytes(Paths.get(inputSatelliteAccessConfigFileAbsolutePath));
+        ByteString inputSatelliteAccessConfigFileContent =
+                ByteString.copyFrom(inputSatelliteAccessConfigFileContentAsBytes);
+        assertEquals(inputSatelliteAccessConfigContent, outputSatelliteAccessConfigFileContent);
+    }
+
+    @Test
+    public void testSatelliteAccessConfigFileNotPresent() throws Exception {
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
+        createInputXml(inputFile, 14, 1, "31006", 1, "US", true, inputS2CellFileName, null);
+        String[] args = {
+            "--input-file", inputFilePath.toAbsolutePath().toString(),
+            "--output-file", outputFilePath.toAbsolutePath().toString()
+        };
+        try {
+            ConfigDataGenerator.main(args);
+        } catch (Exception ex) {
+            fail("Unexpected exception when executing the tool ex=" + ex);
+        }
+
+        Path filePath = Paths.get(outputFilePath.toAbsolutePath().toString());
+        byte[] fileBytes = Files.readAllBytes(filePath);
+        TelephonyConfigProto telephonyConfigProto = TelephonyConfigProto.parseFrom(fileBytes);
+        SatelliteConfigProto satelliteConfigProto = telephonyConfigProto.getSatellite();
+        SatelliteRegionProto regionProto = satelliteConfigProto.getDeviceSatelliteRegion();
+        ByteString outputSatelliteAccessConfigFile = regionProto.getSatelliteAccessConfigFile();
+        assertEquals(ByteString.EMPTY, outputSatelliteAccessConfigFile);
     }
 
-    private void createInputXml(File outputFile, int version, int carrierId, String plmn,
-            int allowedService, String countryCode, boolean isAllowed, String inputS2CellFileName) {
+    private void createInputXml(
+            File outputFile,
+            int version,
+            int carrierId,
+            String plmn,
+            int allowedService,
+            String countryCode,
+            boolean isAllowed,
+            String inputS2CellFileName,
+            String inputSatelliteAccessConfigFileName) {
         try {
             DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
             DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
@@ -253,6 +374,11 @@ public class ConfigDataGeneratorTest {
             satelliteRegion.appendChild(
                     createElementWithText(doc, ConfigDataGenerator.TAG_IS_ALLOWED,
                             isAllowed ? "TRUE" : "FALSE"));
+            satelliteRegion.appendChild(
+                    createElementWithText(
+                            doc,
+                            ConfigDataGenerator.TAG_SATELLITE_ACCESS_CONFIG_FILE,
+                            inputSatelliteAccessConfigFileName));
             rootElement.appendChild(satelliteRegion);
 
             // Write XML to File
diff --git a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2LocationLookup.java b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2LocationLookup.java
index 9a03d7c69..3a0dfd2cb 100644
--- a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2LocationLookup.java
+++ b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2LocationLookup.java
@@ -24,10 +24,21 @@ import com.beust.jcommander.Parameter;
 import com.google.common.geometry.S2CellId;
 import com.google.common.geometry.S2LatLng;
 
+import java.io.BufferedReader;
 import java.io.File;
+import java.io.FileReader;
+import java.io.FileWriter;
+import java.io.IOException;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
 
 /** A util class for checking if a location is in the input satellite S2 file. */
 public final class SatS2LocationLookup {
+
+    private static final Pattern DMS_PATTERN =
+            Pattern.compile(
+                    "^\"?(\\d+)°(\\d+)'(\\d+)\"+\\s*(N|S)\\s+(\\d+)°(\\d+)'(\\d+)\"+\\s*(E|W)\"?$");
+
     /**
      *  A util method for checking if a location is in the input satellite S2 file.
      */
@@ -38,10 +49,39 @@ public final class SatS2LocationLookup {
                 .build()
                 .parse(args);
 
+        if (arguments.csvFile != null) {
+            processLocationLookupFromCSV(arguments);
+            return;
+        }
+
+        // Make sure either DMS or DD format location is passed
+        if (arguments.dms == null && arguments.latDegrees == null && arguments.lngDegrees == null) {
+            throw new IllegalArgumentException(
+                    "Either --lat-degrees and --lng-degrees or --dms must be specified");
+        }
+
+        double latDegrees, lngDegrees;
+
+        if (arguments.dms != null) {
+            double[] dmsCoords = parseDMS(arguments.dms);
+            latDegrees = dmsCoords[0];
+            lngDegrees = dmsCoords[1];
+        } else {
+            latDegrees = arguments.latDegrees;
+            lngDegrees = arguments.lngDegrees;
+        }
+
         try (SatS2RangeFileReader satS2RangeFileReader =
                      SatS2RangeFileReader.open(new File(arguments.inputFile))) {
-            S2CellId s2CellId = getS2CellId(arguments.latDegrees, arguments.lngDegrees,
-                    satS2RangeFileReader.getS2Level());
+            System.out.println(
+                    "lat - "
+                            + latDegrees
+                            + ", long - "
+                            + lngDegrees
+                            + ", s2Level - "
+                            + satS2RangeFileReader.getS2Level());
+            S2CellId s2CellId =
+                    getS2CellId(latDegrees, lngDegrees, satS2RangeFileReader.getS2Level());
             System.out.println("s2CellId=" + Long.toUnsignedString(s2CellId.id())
                     + ", token=" + s2CellId.toToken());
             SuffixTableRange entry = satS2RangeFileReader.findEntryByCellId(s2CellId.id());
@@ -54,6 +94,84 @@ public final class SatS2LocationLookup {
         }
     }
 
+    private static void processLocationLookupFromCSV(Arguments arguments) throws Exception {
+        File inputFile = new File(arguments.inputFile);
+        File csvFile = new File(arguments.csvFile);
+        File outputFile = new File(arguments.outputFile);
+
+        try (SatS2RangeFileReader satS2RangeFileReader =
+                        SatS2RangeFileReader.open(new File(arguments.inputFile));
+                BufferedReader csvReader = new BufferedReader(new FileReader(arguments.csvFile));
+                FileWriter csvWriter = new FileWriter(arguments.outputFile)) {
+
+            // Write header to output CSV
+            csvWriter.append("Place,Distance,DMS coordinates,Satellite supported\n");
+
+            String row = csvReader.readLine(); // skip first row
+            while ((row = csvReader.readLine()) != null) {
+                String[] data = row.split(",");
+                if (data.length != 3) { // Handle invalid CSV rows
+                    System.err.println("Skipping invalid CSV row: " + row);
+                    continue;
+                }
+
+                String place = data[0].trim();
+                String distance = data[1].trim();
+                String dms = data[2].trim();
+
+                // Remove the outer double quotes if present, but keep inner quotes:
+                String cleanedDMS = dms.replaceAll("^\"", "").replaceAll("\"$", "").trim();
+
+                double[] dmsCoords = parseDMS(cleanedDMS);
+                double latDegrees = dmsCoords[0];
+                double lngDegrees = dmsCoords[1];
+
+                S2CellId s2CellId =
+                        getS2CellId(latDegrees, lngDegrees, satS2RangeFileReader.getS2Level());
+                SuffixTableRange entry = satS2RangeFileReader.findEntryByCellId(s2CellId.id());
+
+                String supported = (entry != null) ? "Yes" : "No";
+
+                // Write data to the output file
+                csvWriter.append(String.format("%s,%s,%s,%s\n", place, distance, dms, supported));
+
+                System.out.println(String.format("%s,%s,%s,%s\n", place, distance, dms, supported));
+            }
+
+        } catch (IOException e) {
+            System.err.println("Error processing CSV file: " + e.getMessage());
+            throw e;
+        }
+
+        System.out.println("Geofence lookup results are at: " + outputFile.getAbsolutePath());
+    }
+
+    private static double[] parseDMS(String dmsString) {
+        Matcher matcher = DMS_PATTERN.matcher(dmsString);
+        if (!matcher.matches()) {
+            System.err.println("Invalid DMS format: " + dmsString);
+            throw new IllegalArgumentException("Invalid DMS format: " + dmsString);
+        }
+
+        double latDegrees =
+                Integer.parseInt(matcher.group(1))
+                        + Integer.parseInt(matcher.group(2)) / 60.0
+                        + Integer.parseInt(matcher.group(3)) / 3600.0;
+        if (matcher.group(4).equals("S")) {
+            latDegrees = -latDegrees;
+        }
+
+        double lngDegrees =
+                Integer.parseInt(matcher.group(5))
+                        + Integer.parseInt(matcher.group(6)) / 60.0
+                        + Integer.parseInt(matcher.group(7)) / 3600.0;
+        if (matcher.group(8).equals("W")) {
+            lngDegrees = -lngDegrees;
+        }
+
+        return new double[] {latDegrees, lngDegrees};
+    }
+
     private static S2CellId getS2CellId(double latDegrees, double lngDegrees, int s2Level) {
         // Create the leaf S2 cell containing the given S2LatLng
         S2CellId cellId = S2CellId.fromLatLng(S2LatLng.fromDegrees(latDegrees, lngDegrees));
@@ -68,14 +186,21 @@ public final class SatS2LocationLookup {
                 required = true)
         public String inputFile;
 
-        @Parameter(names = "--lat-degrees",
-                description = "lat degress of the location",
-                required = true)
-        public double latDegrees;
+        @Parameter(names = "--lat-degrees", description = "latitude in degrees")
+        public Double latDegrees;
 
-        @Parameter(names = "--lng-degrees",
-                description = "lng degress of the location",
-                required = true)
-        public double lngDegrees;
+        @Parameter(names = "--lng-degrees", description = "longitude in degrees")
+        public Double lngDegrees;
+
+        @Parameter(
+                names = "--dms",
+                description = "coordinates in DMS format (e.g., 32°43'19\"N 117°23'40\"W)")
+        public String dms;
+
+        @Parameter(names = "--csv-file", description = "Input CSV file")
+        public String csvFile;
+
+        @Parameter(names = "--output-file", description = "Output CSV file")
+        public String outputFile;
     }
 }
```

