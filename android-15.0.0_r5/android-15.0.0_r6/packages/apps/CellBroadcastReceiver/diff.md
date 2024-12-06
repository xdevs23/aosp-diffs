```diff
diff --git a/Android.bp b/Android.bp
index 9a148fb30..4954e3b88 100644
--- a/Android.bp
+++ b/Android.bp
@@ -25,8 +25,8 @@ android_library {
     ],
     libs: [
         "framework-annotations-lib",
-        "framework-statsd",
-        "framework-bluetooth",
+        "framework-statsd.stubs.module_lib",
+        "framework-bluetooth.stubs.module_lib",
     ],
     static_libs: [
         "androidx.legacy_legacy-support-v4",
@@ -41,6 +41,7 @@ android_library {
         "SettingsLibTopIntroPreference",
         "modules-utils-build_system",
         "cellbroadcast-java-proto-lite",
+        "cellbroadcastreceiver_flags_lib",
     ],
     resource_dirs: ["res"],
     manifest: "AndroidManifest_Lib.xml",
diff --git a/flags/Android.bp b/flags/Android.bp
new file mode 100644
index 000000000..e85f29182
--- /dev/null
+++ b/flags/Android.bp
@@ -0,0 +1,58 @@
+//
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
+//
+
+package {
+    default_team: "trendy_team_fwk_telephony",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+aconfig_declarations {
+    name: "cellbroadcastreceiver_aconfig_flags",
+    package: "com.android.cellbroadcastreceiver.flags",
+    container: "com.android.cellbroadcast",
+    srcs: ["cellbroadcastreceiver_flags.aconfig"],
+}
+
+java_aconfig_library {
+    name: "cellbroadcastreceiver_aconfig_flags_lib",
+    aconfig_declarations: "cellbroadcastreceiver_aconfig_flags",
+    min_sdk_version: "30",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.cellbroadcast",
+    ],
+}
+
+java_library {
+    name: "cellbroadcastreceiver_flags_lib",
+    sdk_version: "system_current",
+    min_sdk_version: "30",
+    srcs: [
+        "lib/**/*.java",
+    ],
+    static_libs: [
+        "cellbroadcastreceiver_aconfig_flags_lib",
+    ],
+    installable: false,
+    visibility: [
+        "//packages/apps/CellBroadcastReceiver:__subpackages__",
+        "//vendor:__subpackages__",
+    ],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.cellbroadcast",
+    ],
+}
diff --git a/flags/cellbroadcastreceiver_flags.aconfig b/flags/cellbroadcastreceiver_flags.aconfig
new file mode 100644
index 000000000..41b03c566
--- /dev/null
+++ b/flags/cellbroadcastreceiver_flags.aconfig
@@ -0,0 +1,9 @@
+package: "com.android.cellbroadcastreceiver.flags"
+container: "com.android.cellbroadcast"
+
+flag {
+    name: "test_flag"
+    namespace: "cellbroadcast"
+    description: "Test flag for cellbroadcastreceiver"
+    bug: "343345283"
+}
\ No newline at end of file
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 2b7a378a7..1c526a50a 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Draadlose noodwaarskuwings"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Draadlose noodwaarskuwings"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Inligtingkennisgewing"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Draadlose noodwaarskuwing-instellings is nie vir hierdie gebruiker beskikbaar nie"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Geen vorige waarskuwings nie"</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index 5d63544d6..ea846edd1 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"ገመድ-አልባ የድንገተኛ አደጋ ማንቂያዎች"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"ገመድ-አልባ የድንገተኛ አደጋ ማንቂያዎች"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"የመረጃ ማሳወቂያ"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"የገመድ-አልባ ድንገተኛ አደጋ ማንቂያ ቅንብሮች ለዚህ ተጠቃሚ አይገኙም"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"እሺ"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"ምንም ቀዳሚ ማንቂያዎች የሉም"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index b22232c51..e7cc20519 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"تنبيهات الطوارئ اللاسلكية"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"تنبيهات الطوارئ اللاسلكية"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"إشعار معلوماتي"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"لا تتوفَّر إعدادات إنذارات الطوارئ اللاسلكية لهذا المستخدم,"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"حسنًا"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"ليست هناك تنبيهات سابقة."</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index ffab3b3ed..0eac39fdc 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"অনাতাঁৰ জৰুৰীকালীন সতৰ্কবাৰ্তাসমূহ"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"অনাতাঁৰ জৰুৰীকালীন সতৰ্কবাৰ্তাসমূহ"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"তথ্যসমৃদ্ধ জাননী"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"এই ব্যৱহাৰকাৰীৰ বাবে অনাতাঁৰ জৰুৰীকালীন সতৰ্কবাৰ্তাৰ ছেটিং উপলব্ধ নহয়"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ঠিক আছে"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"পূৰ্বৰ কোনো সতৰ্কবাণী নাই"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index bf202c339..d1ac93c03 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Fövqəladə hal xəbərdarlıqları"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Fövqəladə hal xəbərdarlıqları"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Məlumat bildirişi"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Simsiz həyəcan siqnalı ayarları bu istifadəçi üçün əlçatan deyil"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Keçmiş siqnal yoxdur"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index b3cc21c35..27e5323e4 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Bežična upozorenja o hitnim slučajevima"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Bežična upozorenja o hitnim slučajevima"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informativno obaveštenje"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Podešavanja bežičnih obaveštenja o hitnim slučajevima nisu dostupna za ovog korisnika"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Potvrdi"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Nema prethodnih obaveštenja"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 3e792bad1..1ba87eebb 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Аварыйныя абвесткі па бесправадных сетках"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Аварыйныя абвесткі па бесправадных сетках"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Інфармацыйнае апавяшчэнне"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Налады абвестак па бесправадных сетках пра надзвычайныя сітуацыі недаступныя для гэтага карыстальніка"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ОК"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Папярэднія абвесткі адсутнічаюць"</string>
@@ -45,7 +47,7 @@
     <string name="cmas_extreme_alert" msgid="2588720613319969289">"Аварыйная абвестка: надзвычайная сітуацыя"</string>
     <string name="cmas_extreme_immediate_observed_alert" msgid="2328845915287460780">"Аварыйная абвестка: надзвычайная сітуацыя"</string>
     <string name="cmas_extreme_immediate_likely_alert" msgid="1859702950323471778">"Аварыйная абвестка: надзвычайная сітуацыя"</string>
-    <string name="cmas_severe_alert" msgid="4135809475315826913">"Аварыйная абвестка: сур\'ёзная сітуацыя"</string>
+    <string name="cmas_severe_alert" msgid="4135809475315826913">"Аварыйная абвестка: сур’ёзная сітуацыя"</string>
     <string name="cmas_amber_alert" msgid="6154867710264778887">"Выкраданне дзіцяці (абвестка AMBER)"</string>
     <string name="cmas_required_monthly_test" msgid="1890205712251132193">"Абавязковы штомесячны тэст"</string>
     <string name="cmas_exercise_alert" msgid="2892255514938370321">"Аварыйная абвестка (вучэбная трывога)"</string>
@@ -72,8 +74,8 @@
     <string name="enable_etws_test_alerts_summary" msgid="8746155402612927306">"Тэставыя рассылкі сістэмы папярэджання аб землятрусах і цунамі"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="5416260219062637770">"Надзвычайныя пагрозы"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="5832146246627518123">"Надзвычайныя пагрозы для жыцця і маёмасці"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"Сур\'ёзныя пагрозы"</string>
-    <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"Сур\'ёзныя пагрозы для жыцця і маёмасці"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="1066172973703410042">"Сур’ёзныя пагрозы"</string>
+    <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"Сур’ёзныя пагрозы для жыцця і маёмасці"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"Абвесткі сістэмы AMBER"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"Апавяшчэнні пра выкраданне дзяцей"</string>
     <string name="enable_alert_message_title" msgid="2939830587633599352">"Папярэджанні"</string>
@@ -124,7 +126,7 @@
     <string name="cmas_response_none" msgid="5149009359674452959">"Няма"</string>
     <string name="cmas_severity_heading" msgid="8437057117822305243">"Цяжкасць:"</string>
     <string name="cmas_severity_extreme" msgid="1312013282860183082">"Крайнія"</string>
-    <string name="cmas_severity_severe" msgid="7504359209737074524">"Сур\'ёзныя"</string>
+    <string name="cmas_severity_severe" msgid="7504359209737074524">"Сур’ёзныя"</string>
     <string name="cmas_urgency_heading" msgid="8218282767913431492">"Тэрміновасць:"</string>
     <string name="cmas_urgency_immediate" msgid="1577485208196449288">"Неадкладна"</string>
     <string name="cmas_urgency_expected" msgid="6830831119872375936">"Чаканае"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 7dea5b644..d983afa30 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Безжични сигнали при спешни случаи"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Безжични сигнали при спешни случаи"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Информационно известие"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Настройките за безжичните сигнали при спешни случаи не са налице за този потребител"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Няма предишни сигнали"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 4f766c3f1..7dfcc03d7 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"ওয়্যারলেস জরুরি সতর্কতা"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"ওয়্যারলেস জরুরি সতর্কতা"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"তথ্য সংক্রান্ত বিজ্ঞপ্তি"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"এই ব্যবহারকারীর জন্য ওয়্যারলেস সতর্কতার সেটিংস উপলভ্য নয়"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ঠিক আছে"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"পূর্বের কোনও সতর্কতা নেই"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index ff5a37e33..7a8193762 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Hitna upozorenja putem bežične mreže"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Hitna upozorenja putem bežične mreže"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informativno obavještenje"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Postavke hitnih upozorenja putem bežične mreže nisu dostupna za ovog korisnika"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Uredu"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Nema prethodnih upozorenja"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index e7f72d117..a2d520ab0 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Alertes d\'emergència sense fil"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Alertes d\'emergència sense fil"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notificació informativa"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"La configuració de les alertes d\'emergència sense fil no estan disponibles per a aquest usuari"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"D\'acord"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"No hi ha cap alerta anterior"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index a1b955217..70ccf6604 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Bezdrátové výstražné zprávy"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Bezdrátové výstražné zprávy"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informační oznámení"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Nastavení bezdrátových výstražných zpráv nejsou pro tohoto uživatele dostupná"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Žádná předchozí upozornění"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 572f3c4fc..358d0479f 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Mobilbaseret varsling"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Mobilbaseret varsling"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notifikation med oplysninger"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Denne bruger har ikke adgang til indstillingerne for mobilbaseret varsling"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Ingen tidligere nødalarmer"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 7b4fefb31..e2f469ee5 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Notfallbenachrichtigungen an Mobilgeräte"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Notfallbenachrichtigungen an Mobilgeräte"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Benachrichtigung zur Information"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Die Einstellungen für Notfallbenachrichtigungen für Mobilgeräte sind für diesen Nutzer nicht verfügbar"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Ok"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Bisher noch keine Benachrichtigungen"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index c6726dbe4..3b51de7bf 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Ασύρματες ειδοποιήσεις έκτακτης ανάγκης"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Ασύρματες ειδοποιήσεις έκτακτης ανάγκης"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Ενημερωτική ειδοποίηση"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Οι ρυθμίσεις για τις ειδοποιήσεις έκτακτης ανάγκης μέσω ασύρματου δικτύου δεν είναι διαθέσιμες για αυτόν τον χρήστη"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Δεν υπάρχουν προηγούμενες ειδοποιήσεις"</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index c98300dda..383975b5d 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Wireless emergency alerts"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Wireless emergency alerts"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informational notification"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Wireless emergency alert settings are not available for this user"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"No previous alerts"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 93942f0c9..d2d329aa4 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Wireless emergency alerts"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Wireless emergency alerts"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informational notification"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Wireless emergency alert settings are not available for this user"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"No previous alerts"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index c98300dda..383975b5d 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Wireless emergency alerts"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Wireless emergency alerts"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informational notification"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Wireless emergency alert settings are not available for this user"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"No previous alerts"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index c98300dda..383975b5d 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Wireless emergency alerts"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Wireless emergency alerts"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informational notification"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Wireless emergency alert settings are not available for this user"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"No previous alerts"</string>
diff --git a/res/values-en-rXC/strings.xml b/res/values-en-rXC/strings.xml
index 05a3a9778..6f035c8ad 100644
--- a/res/values-en-rXC/strings.xml
+++ b/res/values-en-rXC/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‎‏‎‎‏‏‎‎‏‎‏‏‏‎‎‏‎‏‎‏‎‏‎‏‎‎‏‏‎‎‎‏‏‏‎‏‏‏‏‏‏‏‎‏‏‎‏‏‎‏‏‎‏‎‏‎‏‎‏‎‎‎Wireless emergency alerts‎‏‎‎‏‎"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‎‏‎‏‎‎‎‏‏‎‎‎‎‏‎‏‎‎‎‏‏‏‏‏‎‏‎‎‏‎‎‎‏‎‏‎‏‏‏‎‎‎‏‎‏‏‎‎‏‏‎‎‏‏‎‎‎‏‏‎‏‎‏‎Wireless emergency alerts‎‏‎‎‏‎"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‎‏‎‎‎‏‎‎‏‎‏‎‎‏‏‎‎‏‏‏‏‏‎‏‎‎‏‏‏‏‏‏‏‏‏‎‏‏‏‎‏‎‎‏‎‏‎‎‎‎‎‎‏‏‎‎‏‎‎‏‎‎Informational notification‎‏‎‎‏‎"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‎‏‏‎‏‏‎‎‎‏‏‏‏‎‎‏‎‎‎‎‎‏‏‎‏‎‏‎‎‎‏‎‏‎‏‏‏‏‏‎‎‏‎‎‎‎‏‏‎‎‏‏‎‏‎‎‎‏‏‎‏‎‏‎Wireless emergency alert settings are not available for this user‎‏‎‎‏‎"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‎‏‏‎‎‎‏‎‎‏‎‎‎‎‎‏‏‎‏‎‏‏‎‎‎‎‎‏‏‏‏‎‎‎‎‎‏‏‏‎‎‎‎‏‎‏‎‏‏‎‎‎‏‏‏‎‎‏‏‏‏‏‏‎OK‎‏‎‎‏‎"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‏‎‏‎‎‎‏‏‎‏‎‏‏‏‏‏‏‏‏‎‎‎‎‎‏‎‎‎‏‏‎‎‏‏‏‎‎‏‎‏‎‏‏‏‏‏‏‏‎‏‎‏‎‎‎‏‎‎‏‎‎‏‎No previous alerts‎‏‎‎‏‎"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 69ef2323d..f80698ed4 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Alertas de emergencia inalámbricas"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Alertas de emergencia inalámbricas"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notificación informativa"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"La configuración de alertas de emergencia inalámbricas no está disponible para este usuario"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Aceptar"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Sin alertas anteriores"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 472b467bd..fe1d1f5fd 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Alertas de emergencia inalámbricas"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Alertas de emergencia inalámbricas"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notificación informativa"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Este usuario no puede modificar la configuración de las alertas de emergencia inalámbricas"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Aceptar"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"No hay alertas anteriores"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index a246364ae..1d760f552 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Eriolukorra raadiosideteatised"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Eriolukorra raadiosideteatised"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informatiivne märguanne"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Juhtmevabade hädaolukorra teatiste seaded pole selle kasutaja puhul saadaval"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Varasemaid teatisi ei ole"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 4f77347ed..a13796166 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Hari gabeko larrialdi-alertak"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Hari gabeko larrialdi-alertak"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informazioa emateko jakinarazpena"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Erabiltzaile honek ez ditu erabilgarri hari gabeko larrialdi-alerten ezarpenak"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Ados"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Ez dago aurreko alertarik"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 59c74e326..5c50d8923 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"هشدارهای اضطراری بی‌سیم"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"هشدارهای اضطراری بی‌سیم"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"اعلان اطلاعاتی"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"تنظیمات مربوط به هشدارهای اضطراری بی‌سیم برای این کاربر در دسترس نیست"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"تأیید"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"هشداری ازقبل وجود ندارد"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 3538b18ee..5a738fbca 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Langattomat vaaratiedotteet"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Langattomat vaaratiedotteet"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Ilmoitus"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Tällä käyttäjällä ei ole pääsyä langattomien vaaratiedotteiden asetuksiin"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Ei aiempia hälytyksiä"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 7aca121c4..5c6e787e3 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Alertes d\'urgence sans fil"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Alertes d\'urgence sans fil"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notification informative"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Les paramètres des alertes d\'urgence sans fil ne sont pas accessibles pour cet utilisateur"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Aucune alerte précédente"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 3d40aa640..4d9803d4b 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Alertes d\'urgence sans fil"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Alertes d\'urgence sans fil"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notification d\'information"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Cet utilisateur n\'a pas accès aux paramètres d\'alertes d\'urgence sans fil"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Aucune alerte"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index bef31a5bc..1ba664921 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Alertas de emerxencia sen fíos"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Alertas de emerxencia sen fíos"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notificación informativa"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"A configuración das alertas de emerxencia sen fíos non está dispoñible para este usuario"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Aceptar"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Non hai alertas anteriores"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index e08e5a6c8..789662f05 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -22,24 +22,26 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"વાયરલેસ ઇમર્જન્સી અલર્ટ"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"વાયરલેસ ઇમર્જન્સી અલર્ટ"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"માહિતી આપતું નોટિફિકેશન"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"આ વપરાશકર્તા માટે વાયરલેસ ઇમર્જન્સી અલર્ટના સેટિંગ ઉપલબ્ધ નથી"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ઓકે"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"કોઈ પાછલી અલર્ટ નથી"</string>
     <string name="menu_preferences" msgid="3596514894131599202">"સેટિંગ"</string>
     <string name="menu_delete_all" msgid="3940997343921149800">"બ્રોડકાસ્ટ્સ કાઢી નાખો"</string>
-    <string name="message_options" msgid="3178489901903589574">"સંદેશ વિકલ્પો"</string>
+    <string name="message_options" msgid="3178489901903589574">"મેસેજના વિકલ્પો"</string>
     <string name="menu_view_details" msgid="1040989019045280975">"વિગતો જુઓ"</string>
     <string name="menu_delete" msgid="128380070910799366">"બ્રોડકાસ્ટ કાઢી નાખો"</string>
     <string name="view_details_title" msgid="1780427629491781473">"ચેતવણી વિગતો"</string>
     <string name="view_details_debugging_title" msgid="5699927030805114173">"ડિબગિંગ માટે અલર્ટની વિગતો"</string>
     <string name="confirm_delete_broadcast" msgid="2540199303730232322">"આ બ્રોડકાસ્ટ કાઢી નાખીએ?"</string>
-    <string name="confirm_delete_all_broadcasts" msgid="2924444089047280871">"તમામ પ્રાપ્ત બ્રોડકાસ્ટ સંદેશા કાઢી નાખીએ?"</string>
+    <string name="confirm_delete_all_broadcasts" msgid="2924444089047280871">"તમામ પ્રાપ્ત બ્રોડકાસ્ટ મેસેજ ડિલીટ કરીએ?"</string>
     <string name="button_delete" msgid="4672451757925194350">"કાઢી નાખો"</string>
     <string name="button_cancel" msgid="7479958360523246140">"રદ કરો"</string>
     <string name="etws_earthquake_warning" msgid="6428741104423152511">"ભૂકંપની ચેતવણી"</string>
     <string name="etws_tsunami_warning" msgid="6173964105145900312">"સુનામીની ચેતવણી"</string>
     <string name="etws_earthquake_and_tsunami_warning" msgid="662449983177407681">"ભૂકંપ અને સુનામી ચેતવણી"</string>
-    <string name="etws_test_message" msgid="8447820262584381894">"ETWS પરીક્ષણ સંદેશ"</string>
+    <string name="etws_test_message" msgid="8447820262584381894">"ETWS પરીક્ષણ મેસેજ"</string>
     <string name="etws_other_emergency_type" msgid="5233080551309721499">"કટોકટીની ચેતવણી"</string>
     <string name="cmas_presidential_level_alert" msgid="1209234030582361001">"પ્રમુખપદની ચેતવણી"</string>
     <string name="cmas_extreme_alert" msgid="2588720613319969289">"કટોકટીની ચેતવણી: અત્યંત"</string>
@@ -50,12 +52,12 @@
     <string name="cmas_required_monthly_test" msgid="1890205712251132193">"આવશ્યક માસિક પરીક્ષણ"</string>
     <string name="cmas_exercise_alert" msgid="2892255514938370321">"કટોકટીની ચેતવણી (અભ્યાસ)"</string>
     <string name="cmas_operator_defined_alert" msgid="8755372450810011476">"કટોકટીની ચેતવણી (ઓપરેટર)"</string>
-    <string name="cb_other_message_identifiers" msgid="5790068194529377210">"બ્રોડકાસ્ટના સંદેશા"</string>
-    <string name="public_safety_message" msgid="9119928798786998252">"સાર્વજનિક સુરક્ષા સંદેશ"</string>
+    <string name="cb_other_message_identifiers" msgid="5790068194529377210">"બ્રોડકાસ્ટના મેસેજ"</string>
+    <string name="public_safety_message" msgid="9119928798786998252">"સાર્વજનિક સુરક્ષા મેસેજ"</string>
     <string name="state_local_test_alert" msgid="8003145745857480200">"રાજ્ય/સ્થાનિક પરીક્ષણ"</string>
     <string name="emergency_alert" msgid="624783871477634263">"કટોકટીની ચેતવણી"</string>
     <string name="emergency_alerts_title" msgid="6605036374197485429">"અલર્ટ"</string>
-    <string name="notification_channel_broadcast_messages" msgid="880704362482824524">"બ્રોડકાસ્ટના સંદેશા"</string>
+    <string name="notification_channel_broadcast_messages" msgid="880704362482824524">"બ્રોડકાસ્ટના મેસેજ"</string>
     <string name="notification_channel_emergency_alerts" msgid="5008287980979183617">"કટોકટીની ચેતવણીઓ"</string>
     <string name="notification_channel_emergency_alerts_high_priority" msgid="3937475297436439073">"અસ્વીકૃત ઇમર્જન્સી અલર્ટ"</string>
     <string name="notification_channel_broadcast_messages_in_voicecall" msgid="3291001780110813190">"વૉઇસ કૉલ દરમ્યાન ઇમર્જન્સી અલર્ટ"</string>
@@ -63,8 +65,8 @@
     <string name="enable_alerts_master_toggle_title" msgid="1457904343636699446">"અલર્ટને મંજૂરી આપો"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="5583168548073938617">"વાયરલેસ ઇમર્જન્સી અલર્ટના નોટિફિકેશન પ્રાપ્ત કરો"</string>
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"અલર્ટ રિમાઇન્ડર"</string>
-    <string name="enable_alert_speech_title" msgid="8052104771053526941">"ચેતવણી સંદેશ બોલો"</string>
-    <string name="enable_alert_speech_summary" msgid="2855629032890937297">"વાયરલેસ ઇમર્જન્સી અલર્ટ સંદેશા બોલવા માટે ટેક્સ્ટ ટૂ સ્પીચનો ઉપયોગ કરો"</string>
+    <string name="enable_alert_speech_title" msgid="8052104771053526941">"ચેતવણી મેસેજ બોલો"</string>
+    <string name="enable_alert_speech_summary" msgid="2855629032890937297">"વાયરલેસ ઇમર્જન્સી અલર્ટ મેસેજ બોલવા માટે ટેક્સ્ટ ટૂ સ્પીચનો ઉપયોગ કરો"</string>
     <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"રિમાઇન્ડરનો સાઉન્ડ સામાન્ય વૉલ્યૂમ પર વાગશે"</string>
     <string name="emergency_alert_history_title" msgid="8310173569237268431">"ઇમર્જન્સી અલર્ટનો ઇતિહાસ"</string>
     <string name="alert_preferences_title" msgid="6001469026393248468">"અલર્ટની પસંદગીઓ"</string>
@@ -76,21 +78,21 @@
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="5292443310309039223">"જીવન અને સંપત્તિના ગંભીર જોખમો"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="1475030503498979651">"AMBER અલર્ટ"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="4495233280416889667">"બાળ અપહરણની કટોકટીના બુલેટિન"</string>
-    <string name="enable_alert_message_title" msgid="2939830587633599352">"અલર્ટ સંદેશા"</string>
+    <string name="enable_alert_message_title" msgid="2939830587633599352">"અલર્ટ મેસેજ"</string>
     <string name="enable_alert_message_summary" msgid="6525664541696985610">"નિકટવર્તી સલામતી જોખમો વિશે ચેતવો"</string>
     <string name="enable_public_safety_messages_title" msgid="5576770949182656524">"સાર્વજનિક સુરક્ષા મેસેજ"</string>
     <string name="enable_public_safety_messages_summary" msgid="7868069748857851521">"સુઝાવ આપેલ ક્રિયાઓ જે જીંદગીઓ અથવા મિલ્કતને બચાવી શકે"</string>
-    <string name="enable_full_screen_public_safety_messages_title" msgid="1790574642368284876">"સંદેશા પૂર્ણ સ્ક્રીનમાં બતાવો"</string>
-    <string name="enable_full_screen_public_safety_messages_summary" msgid="194171850169012897">"જ્યારે એ બંધ હોય, ત્યારે પણ સાર્વજનિક સુરક્ષાના સંદેશા નોટિફિકેશન તરીકે મોકલવામાં આવે છે"</string>
+    <string name="enable_full_screen_public_safety_messages_title" msgid="1790574642368284876">"મેસેજ પૂર્ણ સ્ક્રીનમાં બતાવો"</string>
+    <string name="enable_full_screen_public_safety_messages_summary" msgid="194171850169012897">"જ્યારે એ બંધ હોય, ત્યારે પણ સાર્વજનિક સુરક્ષાના મેસેજ નોટિફિકેશન તરીકે મોકલવામાં આવે છે"</string>
     <string name="enable_state_local_test_alerts_title" msgid="1012930918171302720">"રાજ્ય અને સ્થાનિક પરીક્ષણો"</string>
-    <string name="enable_state_local_test_alerts_summary" msgid="780298327377950187">"રાજ્ય અને સ્થાનિક સત્તાવાળાઓ પાસેથી પરીક્ષણ સંદેશા પ્રાપ્ત કરો"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="780298327377950187">"રાજ્ય અને સ્થાનિક અધિકારીઓ પાસેથી પરીક્ષણ મેસેજ મેળવો"</string>
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"કટોકટીની ચેતવણીઓ"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"જીવલેણ ઘટનાઓ વિશે ચેતવો"</string>
     <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"પરીક્ષણના અલર્ટ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"સલામતી અલર્ટ સિસ્ટમમાંથી કૅરિઅરના પરીક્ષણો અને માસિક પરીક્ષણો મેળવો"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
-    <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"ઇમર્જન્સી માટે અલર્ટ મેળવો: અભ્યાસ/તાલીમ સંબંધિત સંદેશ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"ઇમર્જન્સી માટે અલર્ટ મેળવો: અભ્યાસ/તાલીમ સંબંધિત મેસેજ"</string>
     <!-- no translation found for enable_operator_defined_test_alerts_title (7459219458579095832) -->
     <skip />
     <string name="enable_operator_defined_test_alerts_summary" msgid="7856514354348843433">"ઇમર્જન્સી અલર્ટ મેળવો: ઑપરેટર દ્વારા નિર્ધારિત"</string>
@@ -151,24 +153,24 @@
   </string-array>
     <string name="emergency_alert_settings_title_watches" msgid="4477073412799894883">"કટોકટી માટેની વાયરલેસ ચેતવણીઓ"</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="7293800023375154256">"રાષ્ટ્રપતિ દ્વારા અલર્ટ"</string>
-    <string name="enable_cmas_presidential_alerts_summary" msgid="7900094335808247024">"રાષ્ટ્રપતિ દ્વારા જારી કરાયેલા રાષ્ટ્રીય ચેતવણી સંદેશા. બંધ કરી શકાતા નથી."</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="7900094335808247024">"રાષ્ટ્રપતિ દ્વારા જારી કરાયેલા રાષ્ટ્રીય ચેતવણી માટેના મેસેજ બંધ કરી શકાતા નથી."</string>
     <string name="receive_cmas_in_second_language_title" msgid="1223260365527361964"></string>
     <string name="receive_cmas_in_second_language_summary" msgid="7704105502782770718"></string>
     <string name="alerts_header_summary" msgid="4700985191868591788"></string>
     <string name="testing_mode_enabled" msgid="8296556666392297467">"સેલ બ્રોડકાસ્ટ પરીક્ષણ મોડ ચાલુ કરેલો છે."</string>
     <string name="testing_mode_disabled" msgid="8381408377958182661">"સેલ બ્રોડકાસ્ટ પરીક્ષણ મોડ બંધ કરેલો છે."</string>
-    <string name="show_all_messages" msgid="3780970968167139836">"બધા સંદેશા બતાવો"</string>
-    <string name="show_regular_messages" msgid="7376885150513522515">"નિયમિત સંદેશા બતાવો"</string>
+    <string name="show_all_messages" msgid="3780970968167139836">"બધા મેસેજ બતાવો"</string>
+    <string name="show_regular_messages" msgid="7376885150513522515">"નિયમિત મેસેજ બતાવો"</string>
     <string name="message_identifier" msgid="5558338496219327850">"ઓળખકર્તા:"</string>
     <string name="message_serial_number" msgid="3386553658712978964">"અનુક્રમ નંબર:"</string>
     <string name="data_coding_scheme" msgid="4628901196730870577">"ડેટા કોડિંગ સ્કીમ:"</string>
     <string name="message_content" msgid="6204502929879474632">"સંદેશનું કન્ટેન્ટ:"</string>
     <string name="location_check_time" msgid="4105326161240531207">"સ્થાન ચેક કરવાનો સમય:"</string>
-    <string name="message_displayed" msgid="5091678195925617971">"સંદેશ બતાવાયો:"</string>
+    <string name="message_displayed" msgid="5091678195925617971">"મેસેજ બતાવાયો:"</string>
     <string name="message_coordinates" msgid="356333576818059052">"કોઑર્ડિનેટ:"</string>
     <string name="maximum_waiting_time" msgid="3504809124079381356">"પ્રતીક્ષાનો મહત્તમ સમયગાળો:"</string>
     <string name="seconds" msgid="141450721520515025">"સેકન્ડ"</string>
-    <string name="message_copied" msgid="6922953753733166675">"સંદેશ કૉપિ કર્યો"</string>
+    <string name="message_copied" msgid="6922953753733166675">"મેસેજ કૉપિ કર્યો"</string>
     <string name="top_intro_default_text" msgid="1922926733152511202"></string>
     <string name="top_intro_roaming_text" msgid="5250650823028195358">"જ્યારે તમે રોમિંગમાં હો અથવા તમારી પાસે કોઈ સક્રિય સિમ કાર્ડ ન હોય, ત્યારે તમને આ સેટિંગમાં સમાવેશ ન થયો હોય તેવા કેટલાક અલર્ટ મળે તેમ બની શકે"</string>
     <string name="notification_cb_settings_changed_title" msgid="8404224790323899805">"તમારા સેટિંગ બદલાઈ ગયા છે"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 50e8e468f..449d46997 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"खतरे की चेतावनी"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"वायरलेस इमरजेंसी अलर्ट"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"जानकारी देने वाली सूचना"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"यह उपयोगकर्ता, वायरलेस इमरजेंसी अलर्ट की सूचनाओं की सेटिंग में बदलाव नहीं कर सकता"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ठीक है"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"पहले की कोई चेतावनी मौजूद नहीं है"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index aa0fadc1a..ae771e870 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Hitna upozorenja putem bežične mreže"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Hitna upozorenja putem bežične mreže"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informativna obavijest"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Postavke hitnih upozorenja putem bežične mreže nisu dostupne za ovog korisnika"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"U redu"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Nema prethodnih upozorenja"</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index baa2b1675..d67c6a2be 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Vezeték nélküli riasztások"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Vezeték nélküli riasztások"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Tájékoztató értesítés"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"A vezeték nélküli vészjelzések beállításai nem állnak rendelkezésre ennél a felhasználónál"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Nincs korábbi értesítés"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 916168a26..b60518e2c 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Արտակարգ իրավիճակների մասին ծանուցումներ անլար կապով"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Արտակարգ իրավիճակների մասին ծանուցումներ անլար կապով"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Տեղեկատվական ծանուցում"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Արտակարգ իրավիճակների անլար ծանուցումների կարգավորումներն անհասանելի են այս օգտատիրոջը"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Եղավ"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Ծանուցումներ չեն եղել"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 6cacd8e18..5db5d681c 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Peringatan darurat nirkabel"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Peringatan darurat nirkabel"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notifikasi informasi"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Setelan notifikasi darurat nirkabel tidak tersedia untuk pengguna ini"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Oke"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Tidak ada peringatan sebelumnya"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 7ef13bdbb..f645bbf47 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Þráðlausar neyðartilkynningar"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Þráðlausar neyðartilkynningar"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Upplýsingatilkynning"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Stillingar fyrir þráðlausar neyðartilkynningar eru ekki í boði fyrir þennan notanda"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Í lagi"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Engar fyrri viðvaranir"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 5fb91d89f..04aeb31fb 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Avvisi di emergenza wireless"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Avvisi di emergenza wireless"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notifica informativa"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Le impostazioni per gli avvisi di emergenza wireless non sono disponibili per questo utente"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Nessuna allerta precedente"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 3cd8a1f4e..8aaa6b5bf 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"התרעות אלחוטיות על מקרי חירום"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"התרעות אלחוטיות על מקרי חירום"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"הודעה אינפורמטיבית"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"הגדרות של התרעות אלחוטיות על מקרי חירום לא זמינות למשתמש זה"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"אישור"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"אין התרעות קודמות"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index d1dfdef15..81be82427 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"緊急速報メール"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"緊急速報メール"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"情報の通知"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"このユーザーは緊急速報メール設定を利用できません"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"以前の通知はありません"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index 63c89222c..340fbe65b 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"უსადენო საგანგებო გაფრთხილებები"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"უსადენო საგანგებო გაფრთხილებები"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"საინფორმაციო შეტყობინება"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"უსადენო საგანგებო გაფრთხილებების პარამეტრები არ არის ხელმისაწვდომი ამ მომხმარებლისთვის"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"კარგი"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"წინა გაფრთხილებები არ არის"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index fb60eb670..e981e0263 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Сымсыз шұғыл хабарландырулар"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Төтенше жағдай туралы сымсыз хабарландырулар"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Ақпараттық хабарландыру"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Төтенше жағдай туралы сымсыз хабарландыру параметрлері бұл пайдаланушы үшін қолжетімді емес."</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Жарайды"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Бұрын хабарландыру берілмеген."</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index d10181bc6..b61887fc7 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"ការប្រកាសអាសន្ន​តាមប្រព័ន្ធឥតខ្សែ"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"ការប្រកាសអាសន្ន​តាមប្រព័ន្ធឥតខ្សែ"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"ការជូនដំណឹង​សម្រាប់ជាព័ត៌មាន"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"មិនអាចប្រើ​ការកំណត់ការជូនដំណឹងពេលមាន​អាសន្នដោយឥតប្រើខ្សែ​សម្រាប់អ្នកប្រើប្រាស់នេះ​បានទេ"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"យល់​ព្រម​"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"មិន​មាន​ការប្រកាសអាសន្ន​ពីមុន​ទេ"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 34df743d3..a1842dabd 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"ವೈರ್‌ಲೆಸ್ ತುರ್ತು ಅಲರ್ಟ್‌ಗಳು"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"ವೈರ್‌ಲೆಸ್ ತುರ್ತು ಅಲರ್ಟ್‌ಗಳು"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"ಮಾಹಿತಿಯ ನೋಟಿಫಿಕೇಶನ್"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"ಈ ಬಳಕೆದಾರರಿಗೆ ವೈರ್‌ಲೆಸ್ ತುರ್ತು ಅಲರ್ಟ್ ಸೆಟ್ಟಿಂಗ್‌ಗಳು ಲಭ್ಯವಿಲ್ಲ"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ಸರಿ"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"ಹಿಂದಿನ ಯಾವುದೇ ಎಚ್ಚರಿಕೆಗಳಿಲ್ಲ"</string>
@@ -65,7 +67,7 @@
     <string name="alert_reminder_interval_title" msgid="3283595202268218149">"ಎಚ್ಚರಿಕೆ ಜ್ಞಾಪನೆ"</string>
     <string name="enable_alert_speech_title" msgid="8052104771053526941">"ಎಚ್ಚರಿಕೆ ಸಂದೇಶವನ್ನು ಹೇಳಿ"</string>
     <string name="enable_alert_speech_summary" msgid="2855629032890937297">"ವೈರ್‌ಲೆಸ್ ತುರ್ತು ಅಲರ್ಟ್ ಸಂದೇಶಗಳನ್ನು ತಿಳಿಸಲು ಪಠ್ಯದಿಂದ ಧ್ವನಿಯನ್ನು ಬಳಸಿ"</string>
-    <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"ಜ್ಞಾಪನೆ ಧ್ವನಿಯು ಸಾಮಾನ್ಯ ವಾಲ್ಯೂಮ್‌ನಲ್ಲಿ ಪ್ಲೇ ಆಗುತ್ತದೆ"</string>
+    <string name="alert_reminder_dialog_title" msgid="2299010977651377315">"ರಿಮೈಂಡರ್ ಧ್ವನಿಯು ಸಾಮಾನ್ಯ ವಾಲ್ಯೂಮ್‌ನಲ್ಲಿ ಪ್ಲೇ ಆಗುತ್ತದೆ"</string>
     <string name="emergency_alert_history_title" msgid="8310173569237268431">"ತುರ್ತು ಎಚ್ಚರಿಕೆ ಇತಿಹಾಸ"</string>
     <string name="alert_preferences_title" msgid="6001469026393248468">"ಎಚ್ಚರಿಕೆ ಪ್ರಾಶಸ್ತ್ಯಗಳು"</string>
     <string name="enable_etws_test_alerts_title" msgid="3593533226735441539">"ETWS ಪರೀಕ್ಷಾ ಪ್ರಸಾರಗಳು"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index 4db77bb01..18981e5ab 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"위급 재난 문자"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"긴급 재난 문자"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"안전 안내 문자"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"이 사용자는 무선 긴급 경보 알림 설정을 사용할 수 없습니다."</string>
     <string name="button_dismiss" msgid="1234221657930516287">"확인"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"이전 경보 없음"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 025a1355f..67f304637 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Зымсыз тармактардан келген шашылыш билдирүүлөр"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Зымсыз тармактардан келген шашылыш билдирүүлөр"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Маалыматтык билдирме"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Бул колдонуучу үчүн зымсыз шашылыш билдирүүлөрдүн параметрлери жеткиликсиз"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Азырынча эч нерсе жок"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 67f550e67..e3d049bf7 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"ການເຕືອນສຸກເສີນໄຮ້ສາຍ"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"ການເຕືອນສຸກເສີນໄຮ້ສາຍ"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"ການແຈ້ງເຕືອນດ້ານຂໍ້ມູນ"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"ຜູ້ໃຊ້ນີ້ບໍ່ສາມາດໃຊ້ການຕັ້ງຄ່າການເຕືອນສຸກເສີນໄຮ້ສາຍໄດ້"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ຕົກລົງ"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"ບໍ່ມີການເຕືອນກ່ອນໜ້າ"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index d9b0635af..7a512534d 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Belaidžiu ryšiu siunčiami kritinės padėties įspėjimai"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Belaidžiu ryšiu siunčiami kritinės padėties įspėjimai"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informacinis pranešimas"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Šis naudotojas negali pasiekti belaidžiu ryšiu siunčiamų įspėjimų nustatymų"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Gerai"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Nėra ankstesnių įspėjimų"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 568192821..ef6d0906c 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Bezvadu ārkārtas brīdinājumi"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Bezvadu ārkārtas brīdinājumi"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informatīvs paziņojums"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Bezvadu ārkārtas brīdinājumu iestatījumi nav pieejami šim lietotājam."</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Labi"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Nav bijis neviena brīdinājuma"</string>
diff --git a/res/values-mcc001/config.xml b/res/values-mcc001/config.xml
index 42ce6c7c7..3a03c8ff8 100644
--- a/res/values-mcc001/config.xml
+++ b/res/values-mcc001/config.xml
@@ -102,6 +102,8 @@
         <!-- Channel 50 and 60 for area update info -->
         <item>0x32:type=area, emergency=false</item>
         <item>0x3C:type=area, emergency=false</item>
+        <!-- Channel 999 -->
+        <item>0x3E7:rat=gsm, emergency=true</item>
     </string-array>
     <!-- Show area update info settings in CellBroadcastReceiver and information in SIM status in Settings app -->
     <bool name="config_showAreaUpdateInfoSettings">true</bool>
diff --git a/res/values-mcc202-be/strings.xml b/res/values-mcc202-be/strings.xml
index 95cad49f9..d039d7188 100644
--- a/res/values-mcc202-be/strings.xml
+++ b/res/values-mcc202-be/strings.xml
@@ -21,5 +21,5 @@
     <string name="cmas_extreme_alert" msgid="7989498696890004631">"Абвестка GR: экстранная абвестка"</string>
     <string name="cmas_extreme_immediate_observed_alert" msgid="3810446910355766140">"Абвестка GR: экстранная абвестка"</string>
     <string name="cmas_extreme_immediate_likely_alert" msgid="4723844134984591798">"Абвестка GR: экстранная абвестка"</string>
-    <string name="cmas_severe_alert" msgid="3002006180717551407">"Абвестка GR: абвестка аб сур\'ёзнай пагрозе"</string>
+    <string name="cmas_severe_alert" msgid="3002006180717551407">"Абвестка GR: абвестка аб сур’ёзнай пагрозе"</string>
 </resources>
diff --git a/res/values-mcc208-be/strings.xml b/res/values-mcc208-be/strings.xml
index 09f381874..cfce420a9 100644
--- a/res/values-mcc208-be/strings.xml
+++ b/res/values-mcc208-be/strings.xml
@@ -18,15 +18,15 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_presidential_level_alert" msgid="7877341103742233094">"FR-ALERT : Урадавая абвестка"</string>
     <string name="cmas_extreme_alert" msgid="2584151399464241888">"FR-ALERT : Экстранная абвестка"</string>
-    <string name="cmas_severe_alert" msgid="9149520947951402872">"FR-ALERT : Абвестка пра сур\'ёзную пагрозу"</string>
+    <string name="cmas_severe_alert" msgid="9149520947951402872">"FR-ALERT : Абвестка пра сур’ёзную пагрозу"</string>
     <string name="public_safety_message" msgid="5860178069821018697">"FR-ALERT : Папярэджанне"</string>
     <string name="cmas_amber_alert" msgid="6428083238223852662">"FR-ALERT : Абвестка пра выкраданне чалавека"</string>
     <string name="cmas_required_monthly_test" msgid="3216225136685938963">"FR-ALERT: тэставая абвестка"</string>
     <string name="cmas_exercise_alert" msgid="6540820517122545556">"FR-ALERT: Вучэбная трывога"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="1268433786689479357">"Абвесткі пра экстрэмальныя пагрозы (узровень 2)"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6125474083043183037">"Паказваць абвесткі пра экстрэмальныя пагрозы"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="6185770513604614548">"Абвесткі пра сур\'ёзныя пагрозы (узровень 3)"</string>
-    <string name="enable_cmas_severe_threat_alerts_summary" msgid="3073259381449390054">"Паказваць папярэджанні пра сур\'ёзныя пагрозы"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="6185770513604614548">"Абвесткі пра сур’ёзныя пагрозы (узровень 3)"</string>
+    <string name="enable_cmas_severe_threat_alerts_summary" msgid="3073259381449390054">"Паказваць папярэджанні пра сур’ёзныя пагрозы"</string>
     <string name="enable_public_safety_messages_title" msgid="4231398452970069457">"Папярэджанні (узровень 4)"</string>
     <string name="enable_public_safety_messages_summary" msgid="1691623841627340948">"Паказваць папярэджанні"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="4087727029650572978">"Абвестка пра выкраданне чалавека"</string>
diff --git a/res/values-mcc208/config.xml b/res/values-mcc208/config.xml
index 84954ee5b..7f97464de 100644
--- a/res/values-mcc208/config.xml
+++ b/res/values-mcc208/config.xml
@@ -69,4 +69,7 @@
     <string-array name="operator_defined_alert_range_strings" translatable="false" />
     <string-array name="etws_alerts_range_strings" translatable="false" />
     <string-array name="etws_test_alerts_range_strings" translatable="false" />
+
+    <!-- Whether to restore the sub-toggle setting to carrier default -->
+    <bool name="restore_sub_toggle_to_carrier_default">true</bool>
 </resources>
diff --git a/res/values-mcc222-gu/strings.xml b/res/values-mcc222-gu/strings.xml
index 9770eedbd..f971b1fa3 100644
--- a/res/values-mcc222-gu/strings.xml
+++ b/res/values-mcc222-gu/strings.xml
@@ -27,6 +27,6 @@
     <skip />
     <!-- no translation found for enable_cmas_extreme_threat_alerts_title (4190349287603327927) -->
     <skip />
-    <string name="alerts_header_summary" msgid="5963536832729208581">"મહત્ત્વપૂર્ણ સંદેશા સ્ક્રીન પર દેખાઈ શકે છે પછી ભલેને વપરાશકર્તાએ કોઈપણ સેટિંગ પસંદ કર્યા હોય"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="7658007515811137035">"પરીક્ષણ સંદેશા"</string>
+    <string name="alerts_header_summary" msgid="5963536832729208581">"મહત્ત્વપૂર્ણ મેસેજ સ્ક્રીન પર દેખાઈ શકે છે પછી ભલેને વપરાશકર્તાએ કોઈપણ સેટિંગ પસંદ કર્યા હોય"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="7658007515811137035">"પરીક્ષણ મેસેજ"</string>
 </resources>
diff --git a/res/values-mcc226-be/strings.xml b/res/values-mcc226-be/strings.xml
index d080cba69..701b6d7aa 100644
--- a/res/values-mcc226-be/strings.xml
+++ b/res/values-mcc226-be/strings.xml
@@ -22,6 +22,6 @@
     <string name="cmas_extreme_alert" msgid="1713701020039340032">"Абвестка RO: экстранная абвестка"</string>
     <string name="cmas_extreme_immediate_observed_alert" msgid="9008972835754333116">"Абвестка RO: экстранная абвестка"</string>
     <string name="cmas_extreme_immediate_likely_alert" msgid="4535498659302678812">"Абвестка RO: экстранная абвестка"</string>
-    <string name="cmas_severe_alert" msgid="9170931869067635495">"Абвестка RO: абвестка аб сур\'ёзнай пагрозе"</string>
+    <string name="cmas_severe_alert" msgid="9170931869067635495">"Абвестка RO: абвестка аб сур’ёзнай пагрозе"</string>
     <string name="cmas_exercise_alert" msgid="5696553249081579138">"Абвестка RO: вучэбная абвестка"</string>
 </resources>
diff --git a/res/values-mcc232-af/strings.xml b/res/values-mcc232-af/strings.xml
index a2e155d31..769714d88 100644
--- a/res/values-mcc232-af/strings.xml
+++ b/res/values-mcc232-af/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Noodalarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Noodwaarskuwing"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Uiterse gevaar"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Ernstige gevaar"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Inligting oor gevaar"</string>
diff --git a/res/values-mcc232-am/strings.xml b/res/values-mcc232-am/strings.xml
index d9ea2e4c0..80beff771 100644
--- a/res/values-mcc232-am/strings.xml
+++ b/res/values-mcc232-am/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"የድንገተኛ አደጋ ማንቂያ"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"የአደጋ ጊዜ ማንቂያ"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"እጅግ በጣም ከባድ ስጋት"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"ከባድ ስጋት"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"የስጋት መረጃ"</string>
diff --git a/res/values-mcc232-ar/strings.xml b/res/values-mcc232-ar/strings.xml
index f3a2941e6..4763155ab 100644
--- a/res/values-mcc232-ar/strings.xml
+++ b/res/values-mcc232-ar/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"إنذار طوارئ"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"تنبيه طوارئ"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"تهديد بالغ الخطورة"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"تهديد خطير"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"معلومات عن التهديد"</string>
diff --git a/res/values-mcc232-as/strings.xml b/res/values-mcc232-as/strings.xml
index d16786235..311aac25a 100644
--- a/res/values-mcc232-as/strings.xml
+++ b/res/values-mcc232-as/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"জৰুৰীকালীন এলাৰ্ম"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"জৰুৰীকালীন সতৰ্কবাৰ্তা"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"চৰম ভাবুকি"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"গুৰুতৰ ভাবুকি"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"ভাবুকি সম্পৰ্কীয় তথ্য"</string>
diff --git a/res/values-mcc232-az/strings.xml b/res/values-mcc232-az/strings.xml
index 19f41307e..d4365889d 100644
--- a/res/values-mcc232-az/strings.xml
+++ b/res/values-mcc232-az/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Fövqəladə hal siqnalı"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Fövqəladə hal siqnalı"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Yüksək təhlükə"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Ciddi təhlükə"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Təhlükə məlumatı"</string>
diff --git a/res/values-mcc232-b+sr+Latn/strings.xml b/res/values-mcc232-b+sr+Latn/strings.xml
index 74c1ad029..c23720081 100644
--- a/res/values-mcc232-b+sr+Latn/strings.xml
+++ b/res/values-mcc232-b+sr+Latn/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Uzbuna"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Upozorenje o hitnom slučaju"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ekstremna pretnja"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Ozbiljna pretnja"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informacije o pretnji"</string>
diff --git a/res/values-mcc232-be/strings.xml b/res/values-mcc232-be/strings.xml
index 8bb4fb7aa..91f4a3cdb 100644
--- a/res/values-mcc232-be/strings.xml
+++ b/res/values-mcc232-be/strings.xml
@@ -16,16 +16,16 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Экстранны сігнал"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Экстранная абвестка"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Экстрэмальная пагроза"</string>
-    <string name="cmas_severe_alert" msgid="628940584325136759">"Сур\'ёзная пагроза"</string>
+    <string name="cmas_severe_alert" msgid="628940584325136759">"Сур’ёзная пагроза"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Інфармацыя пра пагрозу"</string>
     <string name="cmas_amber_alert" msgid="404589837946037736">"Пошук прапаўшага чалавека"</string>
     <string name="state_local_test_alert" msgid="3774161961273584245">"Тэставая абвестка"</string>
     <string name="cmas_exercise_alert" msgid="4845005677469935113">"Тэставы сігнал"</string>
     <string name="cmas_required_monthly_test" msgid="8386390153236774475">"Праверка сотавай трансляцыі"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2361635321508611596">"Экстрэмальная пагроза"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="1718166777595485623">"Сур\'ёзная пагроза"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="1718166777595485623">"Сур’ёзная пагроза"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="3125202178531035580">"Прапаўшыя людзі"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5252326889751639729">"Пошук прапаўшых людзей"</string>
     <string name="enable_public_safety_messages_title" msgid="3974955568145658404">"Інфармацыя пра пагрозу"</string>
diff --git a/res/values-mcc232-bg/strings.xml b/res/values-mcc232-bg/strings.xml
index 00ac2dedd..05e1f1fa3 100644
--- a/res/values-mcc232-bg/strings.xml
+++ b/res/values-mcc232-bg/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Аларма за спешен случай"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Сигнал при спешен случай"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Екстремна заплаха"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Сериозна заплаха"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Информация за заплахата"</string>
diff --git a/res/values-mcc232-bn/strings.xml b/res/values-mcc232-bn/strings.xml
index 67708b4e6..abb74f17e 100644
--- a/res/values-mcc232-bn/strings.xml
+++ b/res/values-mcc232-bn/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"ইমার্জেন্সি অ্যালার্ম"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"জরুরি সতর্কতা"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"চরম ঝুঁকি"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"গুরুতর ঝুঁকি"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"ঝুঁকি সম্পর্কিত তথ্য"</string>
diff --git a/res/values-mcc232-bs/strings.xml b/res/values-mcc232-bs/strings.xml
index 1ad4f4ef6..0884260b0 100644
--- a/res/values-mcc232-bs/strings.xml
+++ b/res/values-mcc232-bs/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarm za hitne slučajeve"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Upozorenje na hitan slučaj"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ekstremna prijetnja"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Ozbiljna prijetnja"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informacije o prijetnji"</string>
diff --git a/res/values-mcc232-ca/strings.xml b/res/values-mcc232-ca/strings.xml
index 2ad8cd3ee..58959fe60 100644
--- a/res/values-mcc232-ca/strings.xml
+++ b/res/values-mcc232-ca/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarma d\'emergència"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Alerta d\'emergència"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Amenaça extrema"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Amenaça greu"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informació sobre les amenaces"</string>
diff --git a/res/values-mcc232-cs/strings.xml b/res/values-mcc232-cs/strings.xml
index e8c224b6c..f4a1e117a 100644
--- a/res/values-mcc232-cs/strings.xml
+++ b/res/values-mcc232-cs/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Poplach"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Výstražná zpráva"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Extrémní hrozba"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Vážná hrozba"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informace o hrozbě"</string>
diff --git a/res/values-mcc232-da/strings.xml b/res/values-mcc232-da/strings.xml
index 002040df7..acc3eb128 100644
--- a/res/values-mcc232-da/strings.xml
+++ b/res/values-mcc232-da/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Nødalarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Varsling"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ekstrem fare"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Alvorlig fare"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Oplysninger om fare"</string>
diff --git a/res/values-mcc232-de/strings.xml b/res/values-mcc232-de/strings.xml
index 528c3538f..9b09202cd 100644
--- a/res/values-mcc232-de/strings.xml
+++ b/res/values-mcc232-de/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Notfallalarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Notfallalarm"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Extreme Gefahr"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Erhebliche Gefahr"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Gefahreninformation"</string>
diff --git a/res/values-mcc232-el/strings.xml b/res/values-mcc232-el/strings.xml
index 95f417dda..5df4c10d4 100644
--- a/res/values-mcc232-el/strings.xml
+++ b/res/values-mcc232-el/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Συναγερμός έκτακτης ανάγκης"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Ειδοποίηση έκτακτης ανάγκης"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ακραία απειλή"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Σοβαρή απειλή"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Πληροφορίες απειλής"</string>
diff --git a/res/values-mcc232-en-rAU/strings.xml b/res/values-mcc232-en-rAU/strings.xml
index 33a60aae4..8f718b25e 100644
--- a/res/values-mcc232-en-rAU/strings.xml
+++ b/res/values-mcc232-en-rAU/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Emergency alarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Emergency alert"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Extreme threat"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Severe threat"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Threat information"</string>
diff --git a/res/values-mcc232-en-rCA/strings.xml b/res/values-mcc232-en-rCA/strings.xml
index 11507e456..463e6c25c 100644
--- a/res/values-mcc232-en-rCA/strings.xml
+++ b/res/values-mcc232-en-rCA/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Emergency alarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Emergency alert"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Extreme threat"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Severe threat"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Threat information"</string>
diff --git a/res/values-mcc232-en-rGB/strings.xml b/res/values-mcc232-en-rGB/strings.xml
index 33a60aae4..8f718b25e 100644
--- a/res/values-mcc232-en-rGB/strings.xml
+++ b/res/values-mcc232-en-rGB/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Emergency alarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Emergency alert"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Extreme threat"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Severe threat"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Threat information"</string>
diff --git a/res/values-mcc232-en-rIN/strings.xml b/res/values-mcc232-en-rIN/strings.xml
index 33a60aae4..8f718b25e 100644
--- a/res/values-mcc232-en-rIN/strings.xml
+++ b/res/values-mcc232-en-rIN/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Emergency alarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Emergency alert"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Extreme threat"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Severe threat"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Threat information"</string>
diff --git a/res/values-mcc232-en-rXC/strings.xml b/res/values-mcc232-en-rXC/strings.xml
index c3facf44f..24848f422 100644
--- a/res/values-mcc232-en-rXC/strings.xml
+++ b/res/values-mcc232-en-rXC/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‎‏‏‏‏‏‎‎‏‎‎‎‏‏‏‏‎‎‏‎‎‎‎‎‏‎‏‎‏‏‎‎‏‏‎‏‎‎‎‏‏‏‎‏‎‏‏‏‏‏‎‎‎‎‎‎‎‏‎‎Emergency alarm‎‏‎‎‏‎"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‎‏‏‎‏‏‎‏‎‏‏‎‎‏‏‏‏‎‏‏‏‏‎‏‎‏‏‎‏‎‏‏‎‏‏‏‏‎‏‎‏‎‏‏‏‎‏‏‎‏‎‏‏‎‎‎‎‏‎‏‎‏‎‎Emergency alert‎‏‎‎‏‎"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‎‏‎‎‏‏‎‏‎‏‎‏‎‏‎‏‏‏‎‏‎‏‎‏‏‎‎‏‏‎‎‎‏‏‏‏‎‏‏‏‏‏‏‏‎‏‎‎‎‎‏‏‎‏‎‎‎‎Extreme threat‎‏‎‎‏‎"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‎‎‏‎‎‎‏‎‏‏‏‎‏‎‎‏‏‏‎‎‏‎‎‎‏‎‎‎‎‏‎‎‎‏‎‎‎‏‏‎‎‎‎‏‏‎‏‏‎‎‎‎‎‏‎‏‏‏‎‏‏‏‎Severe threat‎‏‎‎‏‎"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‏‏‎‎‎‎‎‎‏‏‎‎‏‎‏‎‎‏‎‏‏‎‏‏‏‏‏‎‏‏‎‏‏‏‏‏‏‏‏‏‏‏‎‏‏‎‏‏‏‏‎‎‎‎‏‏‏‎‎‎‎‎‎Threat information‎‏‎‎‏‎"</string>
diff --git a/res/values-mcc232-es-rUS/strings.xml b/res/values-mcc232-es-rUS/strings.xml
index 151de5271..729f810b6 100644
--- a/res/values-mcc232-es-rUS/strings.xml
+++ b/res/values-mcc232-es-rUS/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarma de emergencia"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Alerta de emergencia"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Amenaza extrema"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Amenaza grave"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Información sobre la amenaza"</string>
diff --git a/res/values-mcc232-es/strings.xml b/res/values-mcc232-es/strings.xml
index c9d99fd66..49e56e585 100644
--- a/res/values-mcc232-es/strings.xml
+++ b/res/values-mcc232-es/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarma de emergencia"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Alerta de emergencia"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Amenaza extrema"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Amenaza grave"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Información sobre la amenaza"</string>
diff --git a/res/values-mcc232-et/strings.xml b/res/values-mcc232-et/strings.xml
index 0ae7378e0..543acf18e 100644
--- a/res/values-mcc232-et/strings.xml
+++ b/res/values-mcc232-et/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Hädaolukorra alarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Hädaolukorra hoiatus"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ekstreemne oht"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Tõsine oht"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Teave ohu kohta"</string>
diff --git a/res/values-mcc232-eu/strings.xml b/res/values-mcc232-eu/strings.xml
index b961840ba..6754ad184 100644
--- a/res/values-mcc232-eu/strings.xml
+++ b/res/values-mcc232-eu/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Larrialdi-alarma"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Larrialdi-alerta"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Muturreko beroa"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Arrisku larria"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Arriskuari buruzko informazioa"</string>
diff --git a/res/values-mcc232-fa/strings.xml b/res/values-mcc232-fa/strings.xml
index 6fd47a781..03817aa95 100644
--- a/res/values-mcc232-fa/strings.xml
+++ b/res/values-mcc232-fa/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"هشدار اضطراری"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"هشدار اضطراری"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"تهدید بسیار شدید"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"تهدید شدید"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"اطلاعات مربوط به تهدید"</string>
diff --git a/res/values-mcc232-fi/strings.xml b/res/values-mcc232-fi/strings.xml
index cc5cc67df..200d4ac07 100644
--- a/res/values-mcc232-fi/strings.xml
+++ b/res/values-mcc232-fi/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Hätätilahälytys"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Hätävaroitus"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Äärimmäinen uhka"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Vakava uhka"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Uhan tiedot"</string>
diff --git a/res/values-mcc232-fr-rCA/strings.xml b/res/values-mcc232-fr-rCA/strings.xml
index 1a013ec01..6a02995a3 100644
--- a/res/values-mcc232-fr-rCA/strings.xml
+++ b/res/values-mcc232-fr-rCA/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarme d\'urgence"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Alerte d\'urgence"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Menace extrême"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Menace grave"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Renseignements sur les menaces"</string>
diff --git a/res/values-mcc232-fr/strings.xml b/res/values-mcc232-fr/strings.xml
index c426c7229..96e4c9516 100644
--- a/res/values-mcc232-fr/strings.xml
+++ b/res/values-mcc232-fr/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alerte d\'urgence"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Alerte d\'urgence"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Menace extrême"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Menace grave"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informations sur la menace"</string>
diff --git a/res/values-mcc232-gl/strings.xml b/res/values-mcc232-gl/strings.xml
index 9655e6e18..ec3255173 100644
--- a/res/values-mcc232-gl/strings.xml
+++ b/res/values-mcc232-gl/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarma de emerxencia"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Alerta de emerxencia"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ameaza extrema"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Ameaza grave"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Información sobre ameazas"</string>
diff --git a/res/values-mcc232-gu/strings.xml b/res/values-mcc232-gu/strings.xml
index 049678f1b..b394167e9 100644
--- a/res/values-mcc232-gu/strings.xml
+++ b/res/values-mcc232-gu/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"ઇમર્જન્સી અલાર્મ"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"ઇમર્જન્સી અલર્ટ"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"ભારે જોખમ"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"ગંભીર જોખમ"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"જોખમની માહિતી"</string>
diff --git a/res/values-mcc232-hi/strings.xml b/res/values-mcc232-hi/strings.xml
index 4c8665f14..6dfc200c2 100644
--- a/res/values-mcc232-hi/strings.xml
+++ b/res/values-mcc232-hi/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"आपातकालीन अलार्म"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"आपातकालीन स्थिति के बारे में चेतावनी"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"बेहद गंभीर खतरा"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"गंभीर खतरा"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"खतरे की जानकारी"</string>
diff --git a/res/values-mcc232-hr/strings.xml b/res/values-mcc232-hr/strings.xml
index b5d4bab7b..4f3a7d386 100644
--- a/res/values-mcc232-hr/strings.xml
+++ b/res/values-mcc232-hr/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarm za hitne slučajeve"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Hitno upozorenje"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ekstremna prijetnja"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Snažna prijetnja"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informacije o prijetnji"</string>
diff --git a/res/values-mcc232-hu/strings.xml b/res/values-mcc232-hu/strings.xml
index d55bce8dc..ca31ae4c2 100644
--- a/res/values-mcc232-hu/strings.xml
+++ b/res/values-mcc232-hu/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Sürgősségi riasztás"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Vészjelzés"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Rendkívüli veszély"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Súlyos veszély"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Veszélyinformációk"</string>
diff --git a/res/values-mcc232-hy/strings.xml b/res/values-mcc232-hy/strings.xml
index 16b45b249..d5790e126 100644
--- a/res/values-mcc232-hy/strings.xml
+++ b/res/values-mcc232-hy/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Վթարային ազդանշան"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Արտակարգ իրավիճակի մասին ծանուցում"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ծայրահեղ լուրջ վտանգ"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Շատ լուրջ վտանգ"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Տեղեկություններ վտանգի մասին"</string>
diff --git a/res/values-mcc232-in/strings.xml b/res/values-mcc232-in/strings.xml
index 53a501159..29794a34d 100644
--- a/res/values-mcc232-in/strings.xml
+++ b/res/values-mcc232-in/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarm darurat"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Peringatan darurat"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ancaman ekstrem"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Ancaman serius"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informasi ancaman"</string>
diff --git a/res/values-mcc232-is/strings.xml b/res/values-mcc232-is/strings.xml
index 76319319f..43accdb20 100644
--- a/res/values-mcc232-is/strings.xml
+++ b/res/values-mcc232-is/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Neyðarviðvörun"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Neyðartilkynning"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Alvarleg ógn"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Mikil ógn"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Upplýsingar um ógn"</string>
diff --git a/res/values-mcc232-it/strings.xml b/res/values-mcc232-it/strings.xml
index 4156943e9..de6634e31 100644
--- a/res/values-mcc232-it/strings.xml
+++ b/res/values-mcc232-it/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Allarme d\'emergenza"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Avviso di emergenza"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Pericolo estremo"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Serio pericolo"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informazioni sul pericolo"</string>
diff --git a/res/values-mcc232-iw/strings.xml b/res/values-mcc232-iw/strings.xml
index 5ef33e2b7..3dfc77ea6 100644
--- a/res/values-mcc232-iw/strings.xml
+++ b/res/values-mcc232-iw/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"התראה על מקרה חירום"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"התראה על מקרה חירום"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"איום קיצוני"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"איום חמור"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"פרטים על האיום"</string>
diff --git a/res/values-mcc232-ja/strings.xml b/res/values-mcc232-ja/strings.xml
index ac2387280..f0c7a5c0d 100644
--- a/res/values-mcc232-ja/strings.xml
+++ b/res/values-mcc232-ja/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"緊急警報"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"緊急速報メール"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"差し迫った脅威"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"深刻な脅威"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"脅威に関する情報"</string>
diff --git a/res/values-mcc232-ka/strings.xml b/res/values-mcc232-ka/strings.xml
index b90b80633..0b464e8c3 100644
--- a/res/values-mcc232-ka/strings.xml
+++ b/res/values-mcc232-ka/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"ავარიული სიგნალიზაცია"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"საგანგებო ვითარების გაფრთხილება"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"უკიდურესი საფრთხე"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"სერიოზული საფრთხე"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"ინფორმაცია საფრთხის შესახებ"</string>
diff --git a/res/values-mcc232-kk/strings.xml b/res/values-mcc232-kk/strings.xml
index eea06fad2..86d525199 100644
--- a/res/values-mcc232-kk/strings.xml
+++ b/res/values-mcc232-kk/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Төтенше жағдай дабылы"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Шұғыл хабарландыру"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Шектен тыс қауіп"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Елеулі қауіп"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Қауіп туралы ақпарат"</string>
diff --git a/res/values-mcc232-km/strings.xml b/res/values-mcc232-km/strings.xml
index a400f5cea..b862b4847 100644
--- a/res/values-mcc232-km/strings.xml
+++ b/res/values-mcc232-km/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"សំឡេងប្រកាសអាសន្ន"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"ការប្រកាសអាសន្ន"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"ការគំរាមកំហែងធ្ងន់ធ្ងរខ្លាំង"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"ការគំរាមកំហែងធ្ងន់ធ្ងរ"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"ព័ត៌មានអំពីការគំរាមកំហែង"</string>
diff --git a/res/values-mcc232-kn/strings.xml b/res/values-mcc232-kn/strings.xml
index 0631228b6..0f5494040 100644
--- a/res/values-mcc232-kn/strings.xml
+++ b/res/values-mcc232-kn/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"ಎಮರ್ಜೆನ್ಸಿ ಅಲಾರಂ"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"ತುರ್ತು ಅಲರ್ಟ್"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"ತೀವ್ರ ಅಪಾಯ"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"ಗಂಭೀರ ಅಪಾಯ"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"ಅಪಾಯದ ಕುರಿತ ಮಾಹಿತಿ"</string>
diff --git a/res/values-mcc232-ko/strings.xml b/res/values-mcc232-ko/strings.xml
index 550211877..271d99a4e 100644
--- a/res/values-mcc232-ko/strings.xml
+++ b/res/values-mcc232-ko/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"응급 상황 알림"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"긴급 재난 문자"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"긴급 위험 알림"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"중대 위험 알림"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"안전 안내"</string>
diff --git a/res/values-mcc232-ky/strings.xml b/res/values-mcc232-ky/strings.xml
index feee719ad..b0c6ec8e5 100644
--- a/res/values-mcc232-ky/strings.xml
+++ b/res/values-mcc232-ky/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Өзгөчө кырдаал сигнализациясы"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Шашылыш билдирүү"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Өтө коркунучтуу абал"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Олуттуу кырдаал"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Коркунуч тууралуу маалымат"</string>
diff --git a/res/values-mcc232-lo/strings.xml b/res/values-mcc232-lo/strings.xml
index 977159257..9923ec78b 100644
--- a/res/values-mcc232-lo/strings.xml
+++ b/res/values-mcc232-lo/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"ສັນຍານເຕືອນສຸກເສີນ"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"ແຈ້ງເຕືອນເຫດສຸກເສີນ"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"ໄພຄຸກຄາມທີ່ສຸດຂີດ"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"ໄພຄຸກຄາມທີ່ຮຸນແຮງ"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"ຂໍ້ມູນໄພຄຸກຄາມ"</string>
diff --git a/res/values-mcc232-lt/strings.xml b/res/values-mcc232-lt/strings.xml
index b4a9dcd27..4d1ed4ef9 100644
--- a/res/values-mcc232-lt/strings.xml
+++ b/res/values-mcc232-lt/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Įspėjimas apie kritinę padėtį"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Įspėjimas apie kritinę padėtį"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Labai didelis pavojus"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Rimtas pavojus"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Pavojaus informacija"</string>
diff --git a/res/values-mcc232-lv/strings.xml b/res/values-mcc232-lv/strings.xml
index f88659a73..359d8f703 100644
--- a/res/values-mcc232-lv/strings.xml
+++ b/res/values-mcc232-lv/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Ārkārtas brīdinājums"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Ārkārtas brīdinājums"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ārkārtējs apdraudējums"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Nopietns apdraudējums"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informācija par apdraudējumu"</string>
diff --git a/res/values-mcc232-mk/strings.xml b/res/values-mcc232-mk/strings.xml
index 33abf9226..d1f85d891 100644
--- a/res/values-mcc232-mk/strings.xml
+++ b/res/values-mcc232-mk/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Аларм за итни случаи"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Предупредување за итни случаи"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Екстремна закана"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Сериозна закана"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Информации за заканата"</string>
diff --git a/res/values-mcc232-ml/strings.xml b/res/values-mcc232-ml/strings.xml
index 54edd18fc..9612d8a60 100644
--- a/res/values-mcc232-ml/strings.xml
+++ b/res/values-mcc232-ml/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"എമർജൻസി അലാറം"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"അടിയന്തര മുന്നറിയിപ്പ്"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"അതീവ ഗുരുതരമായ ഭീഷണി"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"ഗുരുതരമായ ഭീഷണി"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"ഭീഷണിയുടെ വിവരങ്ങൾ"</string>
diff --git a/res/values-mcc232-mn/strings.xml b/res/values-mcc232-mn/strings.xml
index 7545c66e4..0d22d5924 100644
--- a/res/values-mcc232-mn/strings.xml
+++ b/res/values-mcc232-mn/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Яаралтай тусламжийн дохиолол"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Утасгүй яаралтай тусламжийн сэрэмжлүүлэг"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Гамшгийн аюул"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Ноцтой аюул"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Аюулын мэдээлэл"</string>
diff --git a/res/values-mcc232-mr/strings.xml b/res/values-mcc232-mr/strings.xml
index 5dd4851ef..0f680c557 100644
--- a/res/values-mcc232-mr/strings.xml
+++ b/res/values-mcc232-mr/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"आणीबाणी अलार्म"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"आणीबाणी सूचना"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"अत्याधिक धोका"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"गंभीर धोका"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"धोक्याविषयी माहिती"</string>
diff --git a/res/values-mcc232-ms/strings.xml b/res/values-mcc232-ms/strings.xml
index c24e06a70..68f8226be 100644
--- a/res/values-mcc232-ms/strings.xml
+++ b/res/values-mcc232-ms/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Penggera kecemasan"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Amaran kecemasan"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ancaman melampau"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Ancaman serius"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Maklumat ancaman"</string>
diff --git a/res/values-mcc232-my/strings.xml b/res/values-mcc232-my/strings.xml
index 4f27169bc..4cbe12a68 100644
--- a/res/values-mcc232-my/strings.xml
+++ b/res/values-mcc232-my/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"အရေးပေါ် သတိပေးချက်"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"အရေးပေါ် သတိပေးချက်"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"ဆိုးရွားပြင်းထန်သည့် ခြိမ်းခြောက်မှု"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"အလွန်ဆိုးရွားသည့် ခြိမ်းခြောက်မှု"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"ခြိမ်းခြောက်မှု အချက်အလက်"</string>
diff --git a/res/values-mcc232-nb/strings.xml b/res/values-mcc232-nb/strings.xml
index ea830a453..f97c9edd0 100644
--- a/res/values-mcc232-nb/strings.xml
+++ b/res/values-mcc232-nb/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Nødalarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Nødvarsel"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ekstrem trussel"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Alvorlig trussel"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Trusselinformasjon"</string>
diff --git a/res/values-mcc232-ne/strings.xml b/res/values-mcc232-ne/strings.xml
index 1ecdf38c0..78190caaa 100644
--- a/res/values-mcc232-ne/strings.xml
+++ b/res/values-mcc232-ne/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"आपत्‌कालीन अलार्म"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"आपत्‌कालीन अलर्ट"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"अत्यधिक जोखिम"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"गम्भीर जोखिम"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"जोखिमसम्बन्धी जानकारी"</string>
diff --git a/res/values-mcc232-nl/strings.xml b/res/values-mcc232-nl/strings.xml
index 9609313be..deec40305 100644
--- a/res/values-mcc232-nl/strings.xml
+++ b/res/values-mcc232-nl/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Noodalarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Noodmelding"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Extreme dreiging"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Ernstige dreiging"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informatie over dreiging"</string>
diff --git a/res/values-mcc232-or/strings.xml b/res/values-mcc232-or/strings.xml
index de33f7b59..cfa18dff1 100644
--- a/res/values-mcc232-or/strings.xml
+++ b/res/values-mcc232-or/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"ଜରୁରୀକାଳୀନ ଆଲାରାମ"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"ଜରୁରୀକାଳୀନ ଆଲର୍ଟ"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"ଅତ୍ୟନ୍ତ ଗୁରୁତର ବିପଦ"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"ଗୁରୁତର ବିପଦ"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"ବିପଦ ସୂଚନା"</string>
diff --git a/res/values-mcc232-pa/strings.xml b/res/values-mcc232-pa/strings.xml
index 59e273c6e..f42db6fc6 100644
--- a/res/values-mcc232-pa/strings.xml
+++ b/res/values-mcc232-pa/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"ਐਮਰਜੈਂਸੀ ਅਲਾਰਮ"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"ਐਮਰਜੈਂਸੀ ਅਲਰਟ"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"ਬਹੁਤ ਜ਼ਿਆਦਾ ਖਤਰਾ"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"ਗੰਭੀਰ ਖਤਰਾ"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"ਖਤਰੇ ਸੰਬੰਧੀ ਜਾਣਕਾਰੀ"</string>
diff --git a/res/values-mcc232-pl/strings.xml b/res/values-mcc232-pl/strings.xml
index 88f5bcbd9..dd92d6177 100644
--- a/res/values-mcc232-pl/strings.xml
+++ b/res/values-mcc232-pl/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarm o zagrożeniu"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Alert o zagrożeniu"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ekstremalne zagrożenie"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Poważne zagrożenie"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informacje o zagrożeniu"</string>
diff --git a/res/values-mcc232-pt-rPT/strings.xml b/res/values-mcc232-pt-rPT/strings.xml
index 402a213df..ff40df3c5 100644
--- a/res/values-mcc232-pt-rPT/strings.xml
+++ b/res/values-mcc232-pt-rPT/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarme de emergência"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Alerta de emergência"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ameaça extrema"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Ameaça grave"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informações sobre a ameaça"</string>
diff --git a/res/values-mcc232-pt/strings.xml b/res/values-mcc232-pt/strings.xml
index 7252f826a..419d2dd9e 100644
--- a/res/values-mcc232-pt/strings.xml
+++ b/res/values-mcc232-pt/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarme de emergência"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Alerta de emergência"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Ameaça extrema"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Ameaça grave"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informações sobre a ameaça"</string>
diff --git a/res/values-mcc232-ro/strings.xml b/res/values-mcc232-ro/strings.xml
index 7d2145b88..6d84bf205 100644
--- a/res/values-mcc232-ro/strings.xml
+++ b/res/values-mcc232-ro/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarmă de urgență"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Alertă de urgență"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Pericol extrem"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Pericol grav"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informații despre pericol"</string>
diff --git a/res/values-mcc232-ru/strings.xml b/res/values-mcc232-ru/strings.xml
index ec7ffe957..45f324485 100644
--- a/res/values-mcc232-ru/strings.xml
+++ b/res/values-mcc232-ru/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Предупреждение об экстренной ситуации"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Экстренное оповещение"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Чрезвычайная угроза"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Очень серьезная угроза"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Сведения об угрозе"</string>
diff --git a/res/values-mcc232-si/strings.xml b/res/values-mcc232-si/strings.xml
index b7b0cfcb5..d6061f0fa 100644
--- a/res/values-mcc232-si/strings.xml
+++ b/res/values-mcc232-si/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"හදිසි එලාමය"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"හදිසි අවස්ථා ඇඟවීම"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"බරපතළ තර්ජනය"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"දරුණු තර්ජනය"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"තර්ජන තොරතුරු"</string>
diff --git a/res/values-mcc232-sk/strings.xml b/res/values-mcc232-sk/strings.xml
index 1cdfb8b91..ee8301930 100644
--- a/res/values-mcc232-sk/strings.xml
+++ b/res/values-mcc232-sk/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Núdzový alarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Tiesňové varovanie"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Extrémna hrozba"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Závažná hrozba"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informácie o hrozbe"</string>
diff --git a/res/values-mcc232-sl/strings.xml b/res/values-mcc232-sl/strings.xml
index 493472b09..74c550bee 100644
--- a/res/values-mcc232-sl/strings.xml
+++ b/res/values-mcc232-sl/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarm v sili"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Nujno opozorilo"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Skrajna grožnja"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Resna grožnja"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informacije o grožnji"</string>
diff --git a/res/values-mcc232-sq/strings.xml b/res/values-mcc232-sq/strings.xml
index 37a25eb6f..2d9ca2f7d 100644
--- a/res/values-mcc232-sq/strings.xml
+++ b/res/values-mcc232-sq/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Alarm urgjence"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Sinjalizimi i urgjencës"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Rrezik ekstrem"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Rrezik serioz"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Informacione për rrezikun"</string>
diff --git a/res/values-mcc232-sr/strings.xml b/res/values-mcc232-sr/strings.xml
index 47a7681f6..9b553298b 100644
--- a/res/values-mcc232-sr/strings.xml
+++ b/res/values-mcc232-sr/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Узбуна"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Упозорење о хитном случају"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Екстремна претња"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Озбиљна претња"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Информације о претњи"</string>
diff --git a/res/values-mcc232-sv/strings.xml b/res/values-mcc232-sv/strings.xml
index cc2310bfc..f6f6dad32 100644
--- a/res/values-mcc232-sv/strings.xml
+++ b/res/values-mcc232-sv/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Nödlarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Varning om nödsituation"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Extrem fara"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Allvarlig fara"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Information om fara"</string>
diff --git a/res/values-mcc232-sw/strings.xml b/res/values-mcc232-sw/strings.xml
index 0f7f5fde1..e1f4f514f 100644
--- a/res/values-mcc232-sw/strings.xml
+++ b/res/values-mcc232-sw/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"King\'ora cha dharura"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Tahadhari ya dharura"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Tishio lililokithiri"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Tishio kali"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Maelezo ya tishio"</string>
diff --git a/res/values-mcc232-ta/strings.xml b/res/values-mcc232-ta/strings.xml
index 58db1cea1..463aa19e0 100644
--- a/res/values-mcc232-ta/strings.xml
+++ b/res/values-mcc232-ta/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"அவசரகால அலாரம்"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"அவசரகால எச்சரிக்கை"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"தீவிர அச்சுறுத்தல்"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"கடுமையான அச்சுறுத்தல்"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"அச்சுறுத்தல் தொடர்பான தகவல்கள்"</string>
diff --git a/res/values-mcc232-te/strings.xml b/res/values-mcc232-te/strings.xml
index 526a7df5b..263f3a565 100644
--- a/res/values-mcc232-te/strings.xml
+++ b/res/values-mcc232-te/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"ఎమర్జెన్సీ అలారం"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"ఎమర్జెన్సీ అలర్ట్"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"విపరీతమైన ముప్పు"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"తీవ్రమైన ముప్పు"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"ముప్పు సమాచారం"</string>
diff --git a/res/values-mcc232-th/strings.xml b/res/values-mcc232-th/strings.xml
index 09af99cd8..417071b46 100644
--- a/res/values-mcc232-th/strings.xml
+++ b/res/values-mcc232-th/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"สัญญาณเตือนฉุกเฉิน"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"การแจ้งเตือนเหตุฉุกเฉิน"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"ภัยคุกคามระดับสูงสุด"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"ภัยคุกคามระดับร้ายแรง"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"ข้อมูลภัยคุกคาม"</string>
diff --git a/res/values-mcc232-tl/strings.xml b/res/values-mcc232-tl/strings.xml
index 66a561807..a871703cf 100644
--- a/res/values-mcc232-tl/strings.xml
+++ b/res/values-mcc232-tl/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Emergency alarm"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Alertong pang-emergency"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Napakatinding banta"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Matinding banta"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Impormasyon tungkol sa banta"</string>
diff --git a/res/values-mcc232-tr/strings.xml b/res/values-mcc232-tr/strings.xml
index f484bf28d..ed9759231 100644
--- a/res/values-mcc232-tr/strings.xml
+++ b/res/values-mcc232-tr/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Acil durum alarmı"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Acil durum uyarısı"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Olağanüstü tehlike"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Ciddi tehlike"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Tehlike bilgileri"</string>
diff --git a/res/values-mcc232-uk/strings.xml b/res/values-mcc232-uk/strings.xml
index 29b0130ad..ca98c2f28 100644
--- a/res/values-mcc232-uk/strings.xml
+++ b/res/values-mcc232-uk/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Аварійне сповіщення"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Екстрене сповіщення"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Надзвичайна загроза"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Серйозна загроза"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Інформація про загрозу"</string>
diff --git a/res/values-mcc232-ur/strings.xml b/res/values-mcc232-ur/strings.xml
index e9fb272c2..1aa5370e0 100644
--- a/res/values-mcc232-ur/strings.xml
+++ b/res/values-mcc232-ur/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"ایمرجنسی الارم"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"ایمرجنسی الرٹ"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"انتہائی دھمکی"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"شدید دھمکی"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"دھمکی سے متعلق معلومات"</string>
diff --git a/res/values-mcc232-uz/strings.xml b/res/values-mcc232-uz/strings.xml
index dc7109f91..0648d7229 100644
--- a/res/values-mcc232-uz/strings.xml
+++ b/res/values-mcc232-uz/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Favqulodda holat signalizatsiyasi"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Favqulodda ogohlantirish"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Favqulodda tahdid"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Juda jiddiy tahdid"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Tahdid haqida maʼlumot"</string>
diff --git a/res/values-mcc232-vi/strings.xml b/res/values-mcc232-vi/strings.xml
index 61a71f5e0..3332bd5dd 100644
--- a/res/values-mcc232-vi/strings.xml
+++ b/res/values-mcc232-vi/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"Chuông báo khẩn cấp"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Cảnh báo khẩn cấp"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Mối đe doạ vô cùng nghiêm trọng"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Mối đe doạ nghiêm trọng"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Thông tin về mối đe doạ"</string>
diff --git a/res/values-mcc232-zh-rCN/strings.xml b/res/values-mcc232-zh-rCN/strings.xml
index a791bb5b5..123758fb6 100644
--- a/res/values-mcc232-zh-rCN/strings.xml
+++ b/res/values-mcc232-zh-rCN/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"紧急警报"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"紧急警报"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"极端威胁"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"严重威胁"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"威胁信息"</string>
diff --git a/res/values-mcc232-zh-rHK/strings.xml b/res/values-mcc232-zh-rHK/strings.xml
index f678f8a5a..95d1cfdcb 100644
--- a/res/values-mcc232-zh-rHK/strings.xml
+++ b/res/values-mcc232-zh-rHK/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"緊急警報"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"緊急警示"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"極嚴重威脅"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"嚴重威脅"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"威脅資料"</string>
diff --git a/res/values-mcc232-zh-rTW/strings.xml b/res/values-mcc232-zh-rTW/strings.xml
index c02608a10..38ab7fe66 100644
--- a/res/values-mcc232-zh-rTW/strings.xml
+++ b/res/values-mcc232-zh-rTW/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"緊急警報"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"緊急警報"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"極嚴重威脅"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"嚴重威脅"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"威脅資訊"</string>
diff --git a/res/values-mcc232-zu/strings.xml b/res/values-mcc232-zu/strings.xml
index c59f65870..ea917f520 100644
--- a/res/values-mcc232-zu/strings.xml
+++ b/res/values-mcc232-zu/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_presidential_level_alert" msgid="28280561773493762">"I-Alamu yesimo esiphuthumayo"</string>
+    <string name="cmas_presidential_level_alert" msgid="1635895961813101610">"Isexwayiso esiphuthumayo"</string>
     <string name="cmas_extreme_alert" msgid="9122792746957924456">"Usongo oludlulele"</string>
     <string name="cmas_severe_alert" msgid="628940584325136759">"Usongo olunzima"</string>
     <string name="public_safety_message" msgid="8084690288011309280">"Ulwazi lokusongela"</string>
diff --git a/res/values-mcc232/strings.xml b/res/values-mcc232/strings.xml
index 144af927a..ec2ef4970 100644
--- a/res/values-mcc232/strings.xml
+++ b/res/values-mcc232/strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <!-- CMAS dialog title for presidential level alert. [CHAR LIMIT=50] -->
     <!-- Required Germany(de) translation for this message: Notfallalarm -->
-    <string name="cmas_presidential_level_alert">Emergency alarm</string>
+    <string name="cmas_presidential_level_alert">Emergency alert</string>
     <!-- CMAS dialog title for extreme alert. [CHAR LIMIT=50] -->
     <!-- Required Germany(de) translation for this message: Extreme Gefahr -->
     <string name="cmas_extreme_alert">Extreme threat</string>
diff --git a/res/values-mcc234-be/strings.xml b/res/values-mcc234-be/strings.xml
index 4fd049424..042b3b443 100644
--- a/res/values-mcc234-be/strings.xml
+++ b/res/values-mcc234-be/strings.xml
@@ -17,7 +17,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="8511466399220042295">"Экстранныя абвесткі"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="2271741871998936543">"Абвесткі пра сур\'ёзныя пагрозы"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="2271741871998936543">"Абвесткі пра сур’ёзныя пагрозы"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6022925848643811044">"Тэставыя абвесткі"</string>
     <string name="enable_exercise_test_alerts_title" msgid="411880452689537935">"Трэніровачныя абвесткі"</string>
     <string name="cmas_presidential_level_alert" msgid="3429191761649839884">"Абвестка ад дзяржаўнай установы"</string>
@@ -26,7 +26,7 @@
     <skip />
     <!-- no translation found for cmas_extreme_immediate_likely_alert (1667218798350595295) -->
     <skip />
-    <string name="cmas_severe_alert" msgid="6989950459525380066">"Абвестка пра сур\'ёзную пагрозу"</string>
+    <string name="cmas_severe_alert" msgid="6989950459525380066">"Абвестка пра сур’ёзную пагрозу"</string>
     <string name="cmas_required_monthly_test" msgid="1226904101913162471">"Тэставая абвестка"</string>
     <string name="cmas_exercise_alert" msgid="4540370572086918020">"Трэніровачная абвестка"</string>
     <string name="app_label" msgid="3863159788297913185">"Абвесткі аб надзвычайных сітуацыях"</string>
diff --git a/res/values-mcc234-gu/strings.xml b/res/values-mcc234-gu/strings.xml
index 103658a52..3a7fc26b2 100644
--- a/res/values-mcc234-gu/strings.xml
+++ b/res/values-mcc234-gu/strings.xml
@@ -32,7 +32,7 @@
     <string name="app_label" msgid="3863159788297913185">"ઇમર્જન્સી અલર્ટ"</string>
     <string name="sms_cb_settings" msgid="4187131985831792308">"ઇમર્જન્સી અલર્ટ"</string>
     <string name="enable_alerts_master_toggle_summary" msgid="805446672915814777">"ઇમર્જન્સી અલર્ટના નોટિફિકેશન પ્રાપ્ત કરો"</string>
-    <string name="enable_alert_speech_summary" msgid="5021926525240750702">"ઇમર્જન્સી અલર્ટ સંદેશા બોલવા માટે ટેક્સ્ટ ટૂ સ્પીચનો ઉપયોગ કરો"</string>
+    <string name="enable_alert_speech_summary" msgid="5021926525240750702">"ઇમર્જન્સી અલર્ટ મેસેજ બોલવા માટે ટેક્સ્ટ ટૂ સ્પીચનો ઉપયોગ કરો"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="2931455154355509465">"ઇમર્જન્સી અલર્ટ સિસ્ટમમાંથી પરીક્ષણો મેળવો"</string>
     <string name="cmas_opt_out_dialog_text" msgid="1972978578760513449">"તમે હાલમાં ઇમર્જન્સી અલર્ટ પ્રાપ્ત કરી રહ્યાં છો. શું તમે ઇમર્જન્સી અલર્ટ પ્રાપ્ત કરવાનું ચાલુ રાખવા માગો છો?"</string>
     <string name="emergency_alert_settings_title_watches" msgid="5299419351642118203">"ઇમર્જન્સી અલર્ટ"</string>
diff --git a/res/values-mcc238-be/strings.xml b/res/values-mcc238-be/strings.xml
index 41a38813a..61ff0f7e8 100644
--- a/res/values-mcc238-be/strings.xml
+++ b/res/values-mcc238-be/strings.xml
@@ -19,15 +19,15 @@
     <string name="sms_cb_settings" msgid="2385801397334582049">"Экстранныя абвесткі"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="7171885969406895532">"Экстрэмальная пагроза"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="289758466218591800">"Экстрэмальнае здарэнне"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="2574445861711004849">"Сур\'ёзная пагроза"</string>
-    <string name="enable_cmas_severe_threat_alerts_summary" msgid="7614150249934894203">"Сур\'ёзнае здарэнне"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="2574445861711004849">"Сур’ёзная пагроза"</string>
+    <string name="enable_cmas_severe_threat_alerts_summary" msgid="7614150249934894203">"Сур’ёзнае здарэнне"</string>
     <string name="enable_cmas_test_alerts_title" msgid="2201656327607526283">"Тэсціраванне"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="9167491531803427454">"Тэставыя папярэджанні"</string>
     <string name="enable_exercise_test_alerts_title" msgid="1899116047320259060">"Трэніроўка"</string>
     <string name="enable_exercise_test_alerts_summary" msgid="8874462134900526256">"Трэніровачныя папярэджанні"</string>
     <string name="cmas_presidential_level_alert" msgid="1021328259636041398">"Папярэджанне насельніцтва"</string>
     <string name="cmas_extreme_alert" msgid="8549790257394972582">"Экстрэмальная пагроза"</string>
-    <string name="cmas_severe_alert" msgid="9168154995381314879">"Сур\'ёзная пагроза"</string>
+    <string name="cmas_severe_alert" msgid="9168154995381314879">"Сур’ёзная пагроза"</string>
     <string name="cmas_required_monthly_test" msgid="3066529282314710473">"Тэсціраванне"</string>
     <string name="cmas_exercise_alert" msgid="4686404814038501898">"Трэніроўка"</string>
 </resources>
diff --git a/res/values-mcc238-de/strings.xml b/res/values-mcc238-de/strings.xml
index 3bc65dcf8..d8e714d79 100644
--- a/res/values-mcc238-de/strings.xml
+++ b/res/values-mcc238-de/strings.xml
@@ -24,10 +24,10 @@
     <string name="enable_cmas_test_alerts_title" msgid="2201656327607526283">"Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="9167491531803427454">"Testwarnungen"</string>
     <string name="enable_exercise_test_alerts_title" msgid="1899116047320259060">"Probe"</string>
-    <string name="enable_exercise_test_alerts_summary" msgid="8874462134900526256">"Probewarnungen"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="8874462134900526256">"Übungswarnungen"</string>
     <string name="cmas_presidential_level_alert" msgid="1021328259636041398">"Öffentliche Warnung"</string>
     <string name="cmas_extreme_alert" msgid="8549790257394972582">"Extrem"</string>
     <string name="cmas_severe_alert" msgid="9168154995381314879">"Schwerwiegend"</string>
     <string name="cmas_required_monthly_test" msgid="3066529282314710473">"Test"</string>
-    <string name="cmas_exercise_alert" msgid="4686404814038501898">"Probe"</string>
+    <string name="cmas_exercise_alert" msgid="4686404814038501898">"Übung"</string>
 </resources>
diff --git a/res/values-mcc242/config.xml b/res/values-mcc242/config.xml
index 9ebf790e2..54662561f 100644
--- a/res/values-mcc242/config.xml
+++ b/res/values-mcc242/config.xml
@@ -45,6 +45,11 @@
     <!-- additional language -->
     <item>0x112A:rat=gsm, emergency=true, override_dnd=true</item>
   </string-array>
+  <!-- Channels to receive geo-fencing trigger messages -->
+  <string-array name="geo_fencing_trigger_messages_range_strings" translatable="false">
+    <!-- geo-fencing trigger messages -->
+    <item>0x1130:rat=gsm, emergency=true</item>
+  </string-array>
 
   <string-array name="cmas_amber_alerts_channels_range_strings" translatable="false"/>
   <string-array name="operator_defined_alert_range_strings" translatable="false"/>
diff --git a/res/values-mcc262-be/strings.xml b/res/values-mcc262-be/strings.xml
index 74adc17fd..7301f84aa 100644
--- a/res/values-mcc262-be/strings.xml
+++ b/res/values-mcc262-be/strings.xml
@@ -18,14 +18,14 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_presidential_level_alert" msgid="2107659575955828996">"Экстранны сігнал"</string>
     <string name="cmas_extreme_alert" msgid="3655071721612807998">"Экстрэмальная пагроза"</string>
-    <string name="cmas_severe_alert" msgid="8204679766209106041">"Сур\'ёзная пагроза"</string>
+    <string name="cmas_severe_alert" msgid="8204679766209106041">"Сур’ёзная пагроза"</string>
     <string name="public_safety_message" msgid="8870933058203924990">"Інфармацыя пра пагрозу"</string>
     <string name="state_local_test_alert" msgid="4208083984152605275">"Тэставая абвестка"</string>
     <string name="cmas_operator_defined_alert" msgid="7554916428554204737">"Зарэзервавана ЕС"</string>
     <string name="cmas_exercise_alert" msgid="9166953612111508567">"Тэставы сігнал"</string>
     <string name="cmas_required_monthly_test" msgid="5030077310729851915">"Праверка сотавай трансляцыі"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="140477407513377226">"Экстрэмальная пагроза"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="2244702687286589592">"Сур\'ёзная пагроза"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="2244702687286589592">"Сур’ёзная пагроза"</string>
     <string name="enable_public_safety_messages_title" msgid="9081684819449444846">"Інфармацыя пра пагрозу"</string>
     <string name="enable_state_local_test_alerts_title" msgid="2160210558920782153">"Тэставая абвестка"</string>
     <string name="enable_operator_defined_test_alerts_title" msgid="6867927342721101561">"Зарэзервавана ЕС"</string>
diff --git a/res/values-mcc270-af/strings.xml b/res/values-mcc270-af/strings.xml
index 60fa8b151..28a9f84bb 100644
--- a/res/values-mcc270-af/strings.xml
+++ b/res/values-mcc270-af/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-waarskuwing : Ontvoeringwaarskuwing"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-waarskuwingtoets"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-waarskuwingoefening"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Ontvoeringwaarskuwing"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Ontvoering-veiligheidsberig"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Wys waarskuwingboodskappe oor kinderontvoerings"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-waarskuwingtoets"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Wys toetsboodskappe"</string>
diff --git a/res/values-mcc270-am/strings.xml b/res/values-mcc270-am/strings.xml
index 0634a7b0c..206acaf9d 100644
--- a/res/values-mcc270-am/strings.xml
+++ b/res/values-mcc270-am/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"የልጅ ጠለፋ-ማንቂያ ፦ የጠለፋ ማንቂያ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"የልጅ ጠለፋ-ማንቂያ ሙከራ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"የልጅ ጠለፋ-ማንቂያ ልምምድ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"የጠለፋ ማንቂያ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"የጠለፋ ማንቂያ"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"የልጅ ጠለፋዎች የማንቂያ መልዕክቶችን አሳይ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"የልጅ ጠለፋ-ማንቂያ ሙከራ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"የሙከራ መልዕክቶችን አሳይ"</string>
diff --git a/res/values-mcc270-ar/strings.xml b/res/values-mcc270-ar/strings.xml
index 13d6edd11..b2984bc2f 100644
--- a/res/values-mcc270-ar/strings.xml
+++ b/res/values-mcc270-ar/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"‏‫LU-Alert : تنبيه الاختطاف"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"‏اختبار تنبيه LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"‏تجربة تنبيه LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"تنبيه بشأن الاختطاف"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"تنبيه بشأن الاختطاف"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"إظهار رسائل تنبيه حول اختطاف الأطفال"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"‏اختبار تنبيه LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"عرض رسائل الاختبار"</string>
diff --git a/res/values-mcc270-as/strings.xml b/res/values-mcc270-as/strings.xml
index fbf1cb032..4456156f7 100644
--- a/res/values-mcc270-as/strings.xml
+++ b/res/values-mcc270-as/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-সতৰ্কবাৰ্তা : অপহৰণৰ সতৰ্কবাৰ্তা"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-সতৰ্কবাৰ্তা পৰীক্ষণ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-সতৰ্কবাৰ্তা অনুশীলন"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"অপহৰণৰ সতৰ্কবাৰ্তা"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"অপহৰণৰ সতৰ্কবাৰ্তা"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"শিশু অপহৰণৰ সতৰ্কবাৰ্তা দেখুৱাওক"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-সতৰ্কবাৰ্তা পৰীক্ষণ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"পৰীক্ষণ বাৰ্তা দেখুৱাওক"</string>
diff --git a/res/values-mcc270-az/strings.xml b/res/values-mcc270-az/strings.xml
index 8b95a3362..21d463c6e 100644
--- a/res/values-mcc270-az/strings.xml
+++ b/res/values-mcc270-az/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Adam oğurluğu xəbərdarlığı"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert testi"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert məşqi"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Adam oğurluğu xəbərdarlığı"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Adam oğurluğu xəbərdarlığı"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Uşaq oğurluğu ilə bağlı xəbərdarlıq mesajlarını göstərin"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert testi"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Test mesajlarını göstərin"</string>
diff --git a/res/values-mcc270-b+sr+Latn/strings.xml b/res/values-mcc270-b+sr+Latn/strings.xml
index 657760c61..a42bc1f19 100644
--- a/res/values-mcc270-b+sr+Latn/strings.xml
+++ b/res/values-mcc270-b+sr+Latn/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Upozorenje o otmici"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert vežbanje"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Upozorenje o otmici"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Upozorenje o otmici"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Prikazuj poruke upozorenja za otmice dece"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Prikazuj probne poruke"</string>
diff --git a/res/values-mcc270-be/strings.xml b/res/values-mcc270-be/strings.xml
index 3ca7fd487..bfa8156fe 100644
--- a/res/values-mcc270-be/strings.xml
+++ b/res/values-mcc270-be/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Абвестка пра выкраданне чалавека"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert : Тэсціраванне"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert : Вучэбная трывога"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Абвестка пра выкраданне чалавека"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Абвестка пра выкраданне чалавека"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Паказваць абвесткі пра выкраданні дзяцей"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert : Тэсціраванне"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Паказваць тэставыя абвесткі"</string>
diff --git a/res/values-mcc270-bg/strings.xml b/res/values-mcc270-bg/strings.xml
index 0de0dfae5..50348021f 100644
--- a/res/values-mcc270-bg/strings.xml
+++ b/res/values-mcc270-bg/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Сигнал за отвличане на човек"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: Тестване"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: Обучение"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Сигнал за отвличане на човек"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Сигнал за отвличане"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Показване на съобщения за сигнали за отвличания на деца"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: Тестване"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Показване на тестови съобщения"</string>
diff --git a/res/values-mcc270-bn/strings.xml b/res/values-mcc270-bn/strings.xml
index 914bd8a49..deff3f39b 100644
--- a/res/values-mcc270-bn/strings.xml
+++ b/res/values-mcc270-bn/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : অপহরণ সংক্রান্ত সতর্কতা"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert টেস্ট"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert এক্সারসাইজ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"অপহরণ সংক্রান্ত সতর্কতা"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"অপহরণ সংক্রান্ত সতর্কতা"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"শিশু অপহরণ সংক্রান্ত সতর্কতা মেসেজ দেখুন"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert টেস্ট"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"টেস্ট মেসেজ দেখুন"</string>
diff --git a/res/values-mcc270-bs/strings.xml b/res/values-mcc270-bs/strings.xml
index 9a7fc7005..34702ebfe 100644
--- a/res/values-mcc270-bs/strings.xml
+++ b/res/values-mcc270-bs/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: upozorenje o otmici"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: vježba"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Upozorenje o otmici"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Upozorenje o otmici"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Prikaz poruka upozorenja za otmice djece"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Prikaz testnih poruka"</string>
diff --git a/res/values-mcc270-ca/strings.xml b/res/values-mcc270-ca/strings.xml
index 0d8ad6f40..722dd7e66 100644
--- a/res/values-mcc270-ca/strings.xml
+++ b/res/values-mcc270-ca/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: alerta de segrest"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Prova de LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Simulacre de LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Alerta de segrest"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerta de segrest"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Mostra els missatges d\'alerta de segrestos de menors"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Prova de LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Mostra els missatges de prova"</string>
diff --git a/res/values-mcc270-cs/strings.xml b/res/values-mcc270-cs/strings.xml
index f3c05c134..20a372dcc 100644
--- a/res/values-mcc270-cs/strings.xml
+++ b/res/values-mcc270-cs/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Upozornění na únos"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: Cvičení"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Upozornění na únos"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Upozornění na únos"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Zobrazovat upozornění na únosy dětí"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Zobrazit testovací zprávy"</string>
diff --git a/res/values-mcc270-da/strings.xml b/res/values-mcc270-da/strings.xml
index a2dcead5a..7591fbfc3 100644
--- a/res/values-mcc270-da/strings.xml
+++ b/res/values-mcc270-da/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Underretning om kidnapning"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert (test)"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert (øvelse)"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Underretning om kidnapning"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Underretning om bortførelse"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Vis underretninger om bortførelse af børn"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert (test)"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Vis underretninger om tests"</string>
diff --git a/res/values-mcc270-de/strings.xml b/res/values-mcc270-de/strings.xml
index bd6a9923b..e5645cbf2 100644
--- a/res/values-mcc270-de/strings.xml
+++ b/res/values-mcc270-de/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Entführungswarnung"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Übung"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Entführungswarnung"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Entführungswarnung"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Warnmeldungen bei Kindesentführungen anzeigen"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Testmeldungen anzeigen"</string>
diff --git a/res/values-mcc270-el/strings.xml b/res/values-mcc270-el/strings.xml
index 78d2b682c..b2d95ce5a 100644
--- a/res/values-mcc270-el/strings.xml
+++ b/res/values-mcc270-el/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Συναγερμός απαγωγής"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Δοκιμή LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Άσκηση LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Συναγερμός απαγωγής"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Ειδοποίηση απαγωγής"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Εμφάνιση μηνυμάτων συναγερμού για απαγωγές παιδιών"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Δοκιμή LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Εμφάνιση δοκιμαστικών μηνυμάτων"</string>
diff --git a/res/values-mcc270-en-rAU/strings.xml b/res/values-mcc270-en-rAU/strings.xml
index 5f02a7037..bc799db82 100644
--- a/res/values-mcc270-en-rAU/strings.xml
+++ b/res/values-mcc270-en-rAU/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-alert: Kidnapping alert"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-alert test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-alert exercise"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Kidnapping alert"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnapping alert"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Show alert messages for child abductions"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-alert test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Show test messages"</string>
diff --git a/res/values-mcc270-en-rCA/strings.xml b/res/values-mcc270-en-rCA/strings.xml
index e8b30e818..084fbc719 100644
--- a/res/values-mcc270-en-rCA/strings.xml
+++ b/res/values-mcc270-en-rCA/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Kidnapping alert"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Exercise"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Kidnapping Alert"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnapping alert"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Show alert messages for child abductions"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Show test messages"</string>
diff --git a/res/values-mcc270-en-rGB/strings.xml b/res/values-mcc270-en-rGB/strings.xml
index 5f02a7037..bc799db82 100644
--- a/res/values-mcc270-en-rGB/strings.xml
+++ b/res/values-mcc270-en-rGB/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-alert: Kidnapping alert"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-alert test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-alert exercise"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Kidnapping alert"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnapping alert"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Show alert messages for child abductions"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-alert test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Show test messages"</string>
diff --git a/res/values-mcc270-en-rIN/strings.xml b/res/values-mcc270-en-rIN/strings.xml
index 5f02a7037..bc799db82 100644
--- a/res/values-mcc270-en-rIN/strings.xml
+++ b/res/values-mcc270-en-rIN/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-alert: Kidnapping alert"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-alert test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-alert exercise"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Kidnapping alert"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnapping alert"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Show alert messages for child abductions"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-alert test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Show test messages"</string>
diff --git a/res/values-mcc270-en-rXC/strings.xml b/res/values-mcc270-en-rXC/strings.xml
index ed85e7053..7b00a8d39 100644
--- a/res/values-mcc270-en-rXC/strings.xml
+++ b/res/values-mcc270-en-rXC/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‎‏‏‏‎‏‎‏‏‎‏‏‎‎‏‎‏‎‏‎‎‏‎‏‎‏‎‏‏‏‏‎‏‏‎‏‏‏‏‏‏‎‏‎‏‎‏‏‏‏‎‎‎‎‎‏‏‎‏‏‎‏‏‎LU-Alert : Kidnapping alert‎‏‎‎‏‎"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‏‎‎‏‏‎‎‎‏‏‎‎‏‎‎‏‏‏‎‏‎‏‏‎‎‎‏‏‎‏‏‎‏‏‏‏‏‎‎‎‏‏‎‎‎‎‏‎‏‏‏‏‏‏‎‎‎‏‎‎‏‏‎LU-Alert Test‎‏‎‎‏‎"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‏‏‏‎‎‎‎‎‎‎‏‏‏‎‏‏‏‏‎‎‎‎‏‎‏‏‎‏‎‎‏‎‏‎‏‏‏‏‏‏‏‏‎‎‏‎‏‎‎‏‎‎‎‎‏‎‏‏‎‏‏‎‎LU-Alert Exercise‎‏‎‎‏‎"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‏‏‎‏‏‏‎‎‏‎‎‎‎‏‏‎‏‎‏‏‏‎‏‏‏‏‏‎‎‏‏‎‏‏‏‏‏‎‏‎‏‏‎‏‎‏‎‎‎‎‏‎‎‏‎‏‏‎‎‎‎‏‎Kidnapping Alert‎‏‎‎‏‎"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‎‏‎‏‏‏‏‏‎‎‎‏‏‏‏‎‎‏‎‎‏‎‎‏‎‏‏‏‎‏‎‏‏‏‎‎‏‏‏‏‎‎‎‏‎‎‏‏‎‏‏‏‎‏‎‎‎‏‏‏‎‎‎‎Kidnapping alert‎‏‎‎‏‎"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‎‏‏‎‎‏‏‎‎‎‏‏‏‎‎‏‏‏‎‎‏‏‎‎‏‎‏‎‏‎‏‏‎‏‏‏‏‏‎‎‏‏‎‎‏‏‎‎‎‏‎‎‏‏‏‎‏‎‎‏‎‎Show alert messages for child abductions‎‏‎‎‏‎"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‏‏‎‏‎‎‏‎‎‎‎‎‏‎‏‎‏‏‎‎‏‏‏‏‏‎‏‎‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‏‎‎‏‎‏‏‏‏‏‎‏‏‎‎‎‎‏‎LU-Alert Test‎‏‎‎‏‎"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‎‏‏‏‏‎‎‏‏‏‏‏‎‎‏‎‏‏‎‏‎‎‏‏‎‎‎‏‏‎‏‎‏‎‎‏‎‏‎‏‏‎‎‎‎‎‏‎‏‎‏‎‏‏‎‎‏‎‏‏‏‎‏‎Show test messages‎‏‎‎‏‎"</string>
diff --git a/res/values-mcc270-es-rUS/strings.xml b/res/values-mcc270-es-rUS/strings.xml
index de013a5ca..388346455 100644
--- a/res/values-mcc270-es-rUS/strings.xml
+++ b/res/values-mcc270-es-rUS/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Alerta de secuestro"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Prueba de LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Ejercicio de LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Alerta de secuestro"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerta de secuestro"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Mostrar mensajes de alerta sobre secuestros de menores"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Prueba de LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Mostrar mensajes de prueba"</string>
diff --git a/res/values-mcc270-es/strings.xml b/res/values-mcc270-es/strings.xml
index c25778a5e..85ee27bc4 100644
--- a/res/values-mcc270-es/strings.xml
+++ b/res/values-mcc270-es/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Alerta de secuestro"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Prueba"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Simulacro"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Alerta de secuestro"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerta de secuestro"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Muestra mensajes de alerta sobre secuestros de niños"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Prueba"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Muestra mensajes de prueba"</string>
diff --git a/res/values-mcc270-et/strings.xml b/res/values-mcc270-et/strings.xml
index 3f9be7213..fa515257f 100644
--- a/res/values-mcc270-et/strings.xml
+++ b/res/values-mcc270-et/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: lapseröövi hoiatus"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alerti test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alerti harjutus"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Lapseröövi hoiatus"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Lapseröövi hoiatus"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Lapseröövi hoiatussõnumite kuvamine"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alerti test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Testsõnumite kuvamine"</string>
diff --git a/res/values-mcc270-eu/strings.xml b/res/values-mcc270-eu/strings.xml
index 338e0bd94..b1d23ee99 100644
--- a/res/values-mcc270-eu/strings.xml
+++ b/res/values-mcc270-eu/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: bahiketa-alerta"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: proba"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: simulazioa"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Bahiketa-alerta"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Bahiketa-alerta"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Erakutsi bahitutako haurrei buruzko alertak"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: proba"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Erakutsi probako mezuak"</string>
diff --git a/res/values-mcc270-fa/strings.xml b/res/values-mcc270-fa/strings.xml
index 2194ac45e..5b544710c 100644
--- a/res/values-mcc270-fa/strings.xml
+++ b/res/values-mcc270-fa/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"‏هشدار LU : هشدار آدم‌ربایی"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"‏آزمایش هشدار LU"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"‏تمرین هشدار LU"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"هشدار آدم‌ربایی"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"هشدار آدم‌ربایی"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"نمایش پیام‌های هشدار برای کودک‌ربایی"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"‏آزمایش هشدار LU"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"نمایش پیام‌های آزمایشی"</string>
diff --git a/res/values-mcc270-fi/strings.xml b/res/values-mcc270-fi/strings.xml
index 0425c9a3b..4721172c8 100644
--- a/res/values-mcc270-fi/strings.xml
+++ b/res/values-mcc270-fi/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : hälytys sieppauksesta"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert-testi"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert-harjoitus"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Hälytys sieppauksesta"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Hälytys sieppauksesta"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Näytä hälytysviestit lapsikaappauksista"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert-testi"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Näytä testiviestit"</string>
diff --git a/res/values-mcc270-fr-rCA/strings.xml b/res/values-mcc270-fr-rCA/strings.xml
index ea9fb32cb..7c077ce27 100644
--- a/res/values-mcc270-fr-rCA/strings.xml
+++ b/res/values-mcc270-fr-rCA/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Alerte enlèvement"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Exercice"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Alerte enlèvement"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerte enlèvement"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Afficher les messages d\'alerte pour les enlèvements d\'enfant"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Afficher les messages de test"</string>
diff --git a/res/values-mcc270-fr/strings.xml b/res/values-mcc270-fr/strings.xml
index bd094feb5..88d054419 100644
--- a/res/values-mcc270-fr/strings.xml
+++ b/res/values-mcc270-fr/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Alerte enlèvement"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Exercice"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Alerte enlèvement"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerte enlèvement"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Afficher les messages d\'alerte pour les enlèvements d\'enfants"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Afficher les messages de test"</string>
diff --git a/res/values-mcc270-gl/strings.xml b/res/values-mcc270-gl/strings.xml
index db71bdeed..5c5ae0074 100644
--- a/res/values-mcc270-gl/strings.xml
+++ b/res/values-mcc270-gl/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Alerta de secuestro"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Proba de LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Simulacro de LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Alerta de secuestro"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerta de secuestro"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Mostra mensaxes de alerta relacionadas con secuestros infantís"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Proba de LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Mostra mensaxes de proba"</string>
diff --git a/res/values-mcc270-gu/strings.xml b/res/values-mcc270-gu/strings.xml
index 29853c010..aafd4e29c 100644
--- a/res/values-mcc270-gu/strings.xml
+++ b/res/values-mcc270-gu/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : અપહરણ માટેનું અલર્ટ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alertનું પરીક્ષણ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alertનો અભ્યાસ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"અપહરણ માટેનું અલર્ટ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"અપહરણ માટેનું અલર્ટ"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"બાળકના અપહરણ માટેના અલર્ટ મેસેજ બતાવો"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alertનું પરીક્ષણ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"પરીક્ષણ માટેના મેસેજ બતાવો"</string>
diff --git a/res/values-mcc270-hi/strings.xml b/res/values-mcc270-hi/strings.xml
index aaef2f787..dfbc5c142 100644
--- a/res/values-mcc270-hi/strings.xml
+++ b/res/values-mcc270-hi/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"एलयू-चेतावनी : अपहरण की चेतावनी"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"एलयू-चेतावनी की जांच"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"एलयू-चेतावनी की ड्रिल"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"अपहरण की चेतावनी"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"अपहरण की चेतावनी"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"बच्चों के अपहरण से जुड़ी चेतावनी वाले मैसेज दिखाएं"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"एलयू-चेतावनी की जांच"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"टेस्ट मैसेज दिखाएं"</string>
diff --git a/res/values-mcc270-hr/strings.xml b/res/values-mcc270-hr/strings.xml
index 7a2e1cf50..ed25fc4bc 100644
--- a/res/values-mcc270-hr/strings.xml
+++ b/res/values-mcc270-hr/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : upozorenje o otmici"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert – testiranje"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert – vježba"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Upozorenje o otmici"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Upozorenje o otmici"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Prikazivanje poruka upozorenja za otmice djece"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert – testiranje"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Prikazivanje testnih poruka"</string>
diff --git a/res/values-mcc270-hu/strings.xml b/res/values-mcc270-hu/strings.xml
index 825614ea6..83ae12f7e 100644
--- a/res/values-mcc270-hu/strings.xml
+++ b/res/values-mcc270-hu/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-riasztás: Emberrablási riasztás"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-riasztási teszt"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-riasztási gyakorlat"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Emberrablásról szóló riasztás"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Emberrablásról szóló riasztás"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Gyermekrablás esetén kiadott riasztási üzenetek megjelenítése"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-riasztási teszt"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Tesztüzenetek megjelenítése"</string>
diff --git a/res/values-mcc270-hy/strings.xml b/res/values-mcc270-hy/strings.xml
index 360487b3a..ceea6f819 100644
--- a/res/values-mcc270-hy/strings.xml
+++ b/res/values-mcc270-hy/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert․ առևանգման մասին զգուշացում"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert․ փորձարկում"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert․ վարժանք"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Առևանգման մասին զգուշացում"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Առևանգման մասին զգուշացում"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Ցուցադրել զգուշացումներ երեխաների առևանգման մասին"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert․ փորձարկում"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Ցուցադրել փորձնական հաղորդագրություններ"</string>
diff --git a/res/values-mcc270-in/strings.xml b/res/values-mcc270-in/strings.xml
index a935d3f5d..c5bd20200 100644
--- a/res/values-mcc270-in/strings.xml
+++ b/res/values-mcc270-in/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Peringatan penculikan"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Pengujian LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Latihan LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Peringatan Penculikan"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Peringatan penculikan"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Tampilkan pesan peringatan untuk penculikan anak"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Pengujian LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Tampilkan pesan pengujian"</string>
diff --git a/res/values-mcc270-is/strings.xml b/res/values-mcc270-is/strings.xml
index 6c844348f..5e0ef39ef 100644
--- a/res/values-mcc270-is/strings.xml
+++ b/res/values-mcc270-is/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-viðvörun : Viðvörun um mannrán"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-viðvörunarprófun"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-viðvörunaræfing"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Viðvörun um mannrán"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Viðvörun um mannrán"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Sýna viðvaranir varðandi mannrán á börnum"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-viðvörunarprófun"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Sýna prófskilaboð"</string>
diff --git a/res/values-mcc270-it/strings.xml b/res/values-mcc270-it/strings.xml
index 8842ba91a..d1d2543ca 100644
--- a/res/values-mcc270-it/strings.xml
+++ b/res/values-mcc270-it/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Allerta per rapimento"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Test LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Esercitazione LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Allerta per rapimento"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Allerta rapimento"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Mostra messaggi di allerta relativi a rapimenti di bambini"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Test LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Mostra messaggi relativi a test"</string>
diff --git a/res/values-mcc270-iw/strings.xml b/res/values-mcc270-iw/strings.xml
index 9dc8a68a9..50014c014 100644
--- a/res/values-mcc270-iw/strings.xml
+++ b/res/values-mcc270-iw/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"התרעה בלוקסמבורג: התרעה על חטיפה"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"בדיקה של התרעה בלוקסמבורג"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"תרגיל התרעה בלוקסמבורג"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"התרעת חטיפה"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"התרעה על חטיפה"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"הצגת הודעות התרעה על חטיפות של ילדים"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"בדיקה של התרעה בלוקסמבורג"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"הצגת הודעות בדיקה"</string>
diff --git a/res/values-mcc270-ja/strings.xml b/res/values-mcc270-ja/strings.xml
index 15d89b4f8..56798a926 100644
--- a/res/values-mcc270-ja/strings.xml
+++ b/res/values-mcc270-ja/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: 誘拐に関するアラート"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert テスト"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert 訓練"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"誘拐に関するアラート"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"誘拐に関するアラート"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"児童誘拐についてのアラート メッセージを表示する"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert テスト"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"テスト メッセージを表示する"</string>
diff --git a/res/values-mcc270-ka/strings.xml b/res/values-mcc270-ka/strings.xml
index 23024d237..932995496 100644
--- a/res/values-mcc270-ka/strings.xml
+++ b/res/values-mcc270-ka/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-გაფრთხილება : გატაცების გაფრთხილება"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"სატესტო LU-გაფრთხილება"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"საცდელი LU-გაფრთხილება"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"გატაცების გაფრთხილება"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"გატაცების გაფრთხილება"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ბავშვის გატაცების შესახებ გაფრთხილებების ჩვენება"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"სატესტო LU-გაფრთხილება"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"სატესტო შეტყობინებების ჩვენება"</string>
diff --git a/res/values-mcc270-kk/strings.xml b/res/values-mcc270-kk/strings.xml
index c51c35a35..cfa95af48 100644
--- a/res/values-mcc270-kk/strings.xml
+++ b/res/values-mcc270-kk/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : адам ұрлау туралы хабарландыру"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert сынағы"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert жаттығуы"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Адам ұрлау туралы хабарландыру"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Адам ұрлау туралы хабарландыру"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Жоғалған балалар туралы хабарландыруларды көрсету"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert сынағы"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Сынақ хабарларын көрсету"</string>
diff --git a/res/values-mcc270-km/strings.xml b/res/values-mcc270-km/strings.xml
index 0c92f9c66..e2f360eda 100644
--- a/res/values-mcc270-km/strings.xml
+++ b/res/values-mcc270-km/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert៖ ការ​ជូនដំណឹង​អំពី​ការ​ចាប់​ជំរិត"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"ការធ្វើតេស្ដ LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"ការសាកល្បង LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"ការ​ជូនដំណឹង​អំពី​ការ​ចាប់​ជំរិត"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"ការជូនដំណឹង​អំពី​ការចាប់​ជំរិត"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"បង្ហាញ​សារ​ជូនដំណឹង​សម្រាប់ការ​ចាប់​ជំរិត​កុមារ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"ការធ្វើតេស្ដ LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"បង្ហាញ​សារ​សាកល្បង"</string>
diff --git a/res/values-mcc270-kn/strings.xml b/res/values-mcc270-kn/strings.xml
index 5832f8b3d..790e19417 100644
--- a/res/values-mcc270-kn/strings.xml
+++ b/res/values-mcc270-kn/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-ಅಲರ್ಟ್ : ಅಪಹರಣದ ಎಚ್ಚರಿಕೆ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-ಅಲರ್ಟ್ ಪರೀಕ್ಷೆ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-ಅಲರ್ಟ್ ಅಭ್ಯಾಸ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"ಅಪಹರಣದ ಎಚ್ಚರಿಕೆ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"ಅಪಹರಣದ ಅಲರ್ಟ್"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ಮಕ್ಕಳ ಅಪಹರಣದ ಎಚ್ಚರಿಕೆ ಸಂದೇಶವನ್ನು ತೋರಿಸಿ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-ಅಲರ್ಟ್ ಪರೀಕ್ಷೆ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"ಪರೀಕ್ಷಾ ಸಂದೇಶಗಳನ್ನು ತೋರಿಸಿ"</string>
diff --git a/res/values-mcc270-ko/strings.xml b/res/values-mcc270-ko/strings.xml
index 6872e6515..2723f6dd2 100644
--- a/res/values-mcc270-ko/strings.xml
+++ b/res/values-mcc270-ko/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: 유괴 경보"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert 테스트"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert 안전 훈련"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"유괴 경보"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"유괴 경보"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"아동 유괴 관련 경보 메시지 표시"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert 테스트"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"테스트 메시지 표시"</string>
diff --git a/res/values-mcc270-ky/strings.xml b/res/values-mcc270-ky/strings.xml
index 02a94f2ba..e175f4f3f 100644
--- a/res/values-mcc270-ky/strings.xml
+++ b/res/values-mcc270-ky/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Уурдалгандыгы тууралуу шашылыш билдирүү"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: Сыноо"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: Көнүгүү"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Уурдалгандыгы тууралуу шашылыш билдирүү"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Уурдалгандыгы тууралуу шашылыш билдирүү"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Балдардын уурдалгандыгы жөнүндө шашылыш билдирүүлөрдү көрсөтүү"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: Сыноо"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Сынамык билдирүүлөрдү көрсөтүү"</string>
diff --git a/res/values-mcc270-lo/strings.xml b/res/values-mcc270-lo/strings.xml
index 32c7e8b3a..cba7d107e 100644
--- a/res/values-mcc270-lo/strings.xml
+++ b/res/values-mcc270-lo/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : ການແຈ້ງເຕືອນການລັກພາຕົວ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"ການທົດສອບ LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"ການຝຶກຊ້ອມ LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"ການແຈ້ງເຕືອນການລັກພາຕົວ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"ການແຈ້ງເຕືອນການລັກພາຕົວ"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ສະແດງຂໍ້ຄວາມແຈ້ງເຕືອນເລື່ອງການລັກພາຕົວເດັກນ້ອຍ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"ການທົດສອບ LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"ສະແດງຂໍ້ຄວາມທົດສອບ"</string>
diff --git a/res/values-mcc270-lt/strings.xml b/res/values-mcc270-lt/strings.xml
index e0b2fcdb3..eec58beae 100644
--- a/res/values-mcc270-lt/strings.xml
+++ b/res/values-mcc270-lt/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"„LU-Alert“: įspėjimas apie pagrobimą"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"„LU-Alert“ bandymas"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"„LU-Alert“ pratybos"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Įspėjimas apie pagrobimą"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Įspėjimas apie pagrobimą"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Rodyti įspėjimų pranešimus apie vaikų pagrobimą"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"„LU-Alert“ bandymas"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Rodyti bandomuosius pranešimus"</string>
diff --git a/res/values-mcc270-lv/strings.xml b/res/values-mcc270-lv/strings.xml
index c7c327601..252d2dd4c 100644
--- a/res/values-mcc270-lv/strings.xml
+++ b/res/values-mcc270-lv/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: trauksme nolaupīšanas dēļ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert pārbaude"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert mācību ziņojums"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Trauksme nolaupīšanas dēļ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Trauksme nolaupīšanas dēļ"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Rādīt trauksmes ziņojumus par bērnu nolaupīšanu"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert pārbaude"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Rādīt pārbaudes ziņojumus"</string>
diff --git a/res/values-mcc270-mk/strings.xml b/res/values-mcc270-mk/strings.xml
index fe40a0831..dc8a9c2d9 100644
--- a/res/values-mcc270-mk/strings.xml
+++ b/res/values-mcc270-mk/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: предупредување за киднапирање"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: пробно"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: вежби"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Предупредување за киднапирање"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Предупредување за киднапирање"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Прикажувај пораки за предупредување за киднапирање деца"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: пробно"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Прикажувај пробни пораки"</string>
diff --git a/res/values-mcc270-ml/strings.xml b/res/values-mcc270-ml/strings.xml
index a7cff39b8..c545b90dd 100644
--- a/res/values-mcc270-ml/strings.xml
+++ b/res/values-mcc270-ml/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : തട്ടിക്കൊണ്ടുപോകൽ മുന്നറിയിപ്പ്"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert പരിശീലനം"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"തട്ടികൊണ്ടുപോകൽ മുന്നറിയിപ്പ്"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"തട്ടിക്കൊണ്ടുപോകൽ മുന്നറിയിപ്പ്"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"കുട്ടികളെ തട്ടിക്കൊണ്ടുപോകൽ സംബന്ധിച്ച മുന്നറിയിപ്പ് സന്ദേശങ്ങൾ കാണിക്കുക"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"ടെസ്റ്റ് സന്ദേശങ്ങൾ കാണിക്കുക"</string>
diff --git a/res/values-mcc270-mn/strings.xml b/res/values-mcc270-mn/strings.xml
index adbee28de..7d4af9a3c 100644
--- a/res/values-mcc270-mn/strings.xml
+++ b/res/values-mcc270-mn/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-сэрэмжлүүлэг : Хүн хулгайлсан тухай сэрэмжлүүлэг"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-сэрэмжлүүлгийн туршилт"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-сэрэмжлүүлгийн сургуулилалт"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Хүн хулгайлсан тухай сэрэмжлүүлэг"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Хүн хулгайлсан тухай сэрэмжлүүлэг"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Хүүхэд хулгайлсан тухай сэрэмжлүүлгийн мессежийг харуулах"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-сэрэмжлүүлгийн туршилт"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Туршилтын мессежийг харуулах"</string>
diff --git a/res/values-mcc270-mr/strings.xml b/res/values-mcc270-mr/strings.xml
index 1e5c69dcd..ef5b07c2c 100644
--- a/res/values-mcc270-mr/strings.xml
+++ b/res/values-mcc270-mr/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU सूचना : अपहरणासंबंधित सूचना"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU सूचना चाचणी"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU सूचना व्यायाम"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"अपहरणासंबंधित सूचना"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"अपहरणासंबंधित इशारा"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"लहान मुलांच्या अपहरणांसंबंधित सूचना मेसेज दाखवा"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU सूचना चाचणी"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"चाचणी मेसेज दाखवा"</string>
diff --git a/res/values-mcc270-ms/strings.xml b/res/values-mcc270-ms/strings.xml
index 3ef8bca94..66e52fc34 100644
--- a/res/values-mcc270-ms/strings.xml
+++ b/res/values-mcc270-ms/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"Makluman-LU : Makluman penculikan"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Ujian Makluman-LU"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Latihan Makluman-LU"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Makluman Penculikan"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Makluman penculikan"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Tunjukkan mesej makluman untuk penculikan kanak-kanak"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Ujian Makluman-LU"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Tunjukkan mesej ujian"</string>
diff --git a/res/values-mcc270-my/strings.xml b/res/values-mcc270-my/strings.xml
index b39510212..45ba5166d 100644
--- a/res/values-mcc270-my/strings.xml
+++ b/res/values-mcc270-my/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-သတိပေးချက်- ပြန်ပေးဆွဲမှု သတိပေးချက်"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-သတိပေးချက် စမ်းသပ်မှု"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-သတိပေးချက် လုပ်ထုံးလုပ်နည်း"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"ပြန်ပေးဆွဲမှု သတိပေးချက်"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"ပြန်ပေးဆွဲမှု သတိပေးချက်"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ကလေးခိုးယူခံရမှုများအတွက် သတိပေးမက်ဆေ့ဂျ်များ ပြပါ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-သတိပေးချက် စမ်းသပ်မှု"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"စမ်းသပ်မက်ဆေ့ဂျ်များ ပြပါ"</string>
diff --git a/res/values-mcc270-nb/strings.xml b/res/values-mcc270-nb/strings.xml
index 89a31c2e6..8949c34f9 100644
--- a/res/values-mcc270-nb/strings.xml
+++ b/res/values-mcc270-nb/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: varsel om kidnapping"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: øvelse"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Kidnappingsvarsel"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kidnappingsvarsel"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Vis varselsmeldinger om bortføring av barn"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Vis testmeldinger"</string>
diff --git a/res/values-mcc270-ne/strings.xml b/res/values-mcc270-ne/strings.xml
index db0bd0264..87e167748 100644
--- a/res/values-mcc270-ne/strings.xml
+++ b/res/values-mcc270-ne/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-सतर्कता : अपहरणसम्बन्धी सूचना"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-सतर्कतासम्बन्धी परीक्षण"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-सतर्कतासम्बन्धी अभ्यास"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"अपहरणसम्बन्धी सूचना"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"अपहरणसम्बन्धी सूचना"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"बालबालिकाको अपहरणसँग सम्बन्धित सतर्कताका म्यासेजहरू देखाउनुहोस्"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-सतर्कतासम्बन्धी परीक्षण"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"परीक्षणसम्बन्धी म्यासेजहरू देखाउनुहोस्"</string>
diff --git a/res/values-mcc270-nl/strings.xml b/res/values-mcc270-nl/strings.xml
index 5e05e4ec6..298e71753 100644
--- a/res/values-mcc270-nl/strings.xml
+++ b/res/values-mcc270-nl/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: kidnappingswaarschuwing"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: oefening"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Waarschuwing voor gekidnapt kind"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Vermist Kind Alert"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Waarschuwingen voor gekidnapte kinderen tonen"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Testberichten tonen"</string>
diff --git a/res/values-mcc270-or/strings.xml b/res/values-mcc270-or/strings.xml
index 020ccc7e3..ccf553060 100644
--- a/res/values-mcc270-or/strings.xml
+++ b/res/values-mcc270-or/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-ଆଲର୍ଟ : ଅପହରଣର ଆଲର୍ଟ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-ଆଲର୍ଟ ଟେଷ୍ଟ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-ଆଲର୍ଟ ବ୍ୟାୟାମ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"ଅପହରଣର ଆଲର୍ଟ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"ଅପହରଣର ଆଲର୍ଟ"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ଶିଶୁ ଅପହରଣ ପାଇଁ ଆଲର୍ଟ ମେସେଜଗୁଡ଼ିକ ଦେଖାନ୍ତୁ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-ଆଲର୍ଟ ଟେଷ୍ଟ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"ପରୀକ୍ଷା ବିଷୟରେ ମେସେଜଗୁଡ଼ିକ ଦେଖାନ୍ତୁ"</string>
diff --git a/res/values-mcc270-pa/strings.xml b/res/values-mcc270-pa/strings.xml
index 52c47c2ce..eb066e43b 100644
--- a/res/values-mcc270-pa/strings.xml
+++ b/res/values-mcc270-pa/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-ਅਲਰਟ : ਅਪਹਰਨ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-ਅਲਰਟ ਸੰਬੰਧੀ ਜਾਂਚ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-ਅਲਰਟ ਸੰਬੰਧੀ ਅਭਿਆਸ"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"ਅਪਹਰਨ ਹੋ ਜਾਣ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"ਅਪਹਰਨ ਹੋ ਜਾਣ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ਅਪਹਰਨ ਹੋਏ ਬੱਚੇ ਲਈ ਅਲਰਟ ਸੁਨੇਹੇ ਦਿਖਾਓ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-ਅਲਰਟ ਸੰਬੰਧੀ ਜਾਂਚ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"ਜਾਂਚ ਸੁਨੇਹੇ ਦਿਖਾਓ"</string>
diff --git a/res/values-mcc270-pl/strings.xml b/res/values-mcc270-pl/strings.xml
index 4c6c9c29d..fbd6ef4dd 100644
--- a/res/values-mcc270-pl/strings.xml
+++ b/res/values-mcc270-pl/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Alert dotyczący porwania"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: Ćwiczenie"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Alert o porwaniu"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alert o porwaniu"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Pokazuj alerty o uprowadzeniu dziecka"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Pokazuj komunikaty testowe"</string>
diff --git a/res/values-mcc270-pt-rPT/strings.xml b/res/values-mcc270-pt-rPT/strings.xml
index ce8a88f57..08f2a97b7 100644
--- a/res/values-mcc270-pt-rPT/strings.xml
+++ b/res/values-mcc270-pt-rPT/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: alerta de rapto"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Teste de LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Exercício de LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Alerta de rapto"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerta de rapto"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Mostrar mensagens de alerta para raptos de crianças"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Teste de LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Mostrar mensagens de teste"</string>
diff --git a/res/values-mcc270-pt/strings.xml b/res/values-mcc270-pt/strings.xml
index 7678d376f..1b5e24158 100644
--- a/res/values-mcc270-pt/strings.xml
+++ b/res/values-mcc270-pt/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: alerta de sequestro"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Teste de LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Simulação de LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Alerta de sequestro"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerta de sequestro"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Mostrar mensagens de alerta para sequestro de crianças"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Teste de LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Mostrar mensagens de teste"</string>
diff --git a/res/values-mcc270-ro/strings.xml b/res/values-mcc270-ro/strings.xml
index 7b82bc2c1..4a701f27b 100644
--- a/res/values-mcc270-ro/strings.xml
+++ b/res/values-mcc270-ro/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: alertă de răpire"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Test LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Simulare LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Alertă de răpire"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alertă de răpire"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Afișează mesaje de alertă pentru răpirile de copii"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Test LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Afișează mesaje de test"</string>
diff --git a/res/values-mcc270-ru/strings.xml b/res/values-mcc270-ru/strings.xml
index 0a3c45de6..64917b441 100644
--- a/res/values-mcc270-ru/strings.xml
+++ b/res/values-mcc270-ru/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: оповещение о похищении"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: тестовые оповещения"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: учебная тревога"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Оповещения о похищениях"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Оповещения о похищениях"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Показывать сообщения о пропавших детях"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: тестовые оповещения"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Показывать тестовые сообщения"</string>
diff --git a/res/values-mcc270-si/strings.xml b/res/values-mcc270-si/strings.xml
index e4e0fdba8..0e3025856 100644
--- a/res/values-mcc270-si/strings.xml
+++ b/res/values-mcc270-si/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-ඇඟවීම: පැහැරගැනීම් ඇඟවීම"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-ඇඟවීම පරීක්ෂණය"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-ඇඟවීම අභ්‍යාසය"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"පහර ගැනීමේ ඇඟවීම"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"පහර ගැනීමේ ඇඟවීම"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"ළමයින් පැහැර ගැනීම් සඳහා ඇඟවීම් පණිවිඩ පෙන්වන්න"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-ඇඟවීම පරීක්ෂණය"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"පරීක්ෂණ පණිවිඩ පෙන්වන්න"</string>
diff --git a/res/values-mcc270-sk/strings.xml b/res/values-mcc270-sk/strings.xml
index 5f179880b..c045a42ad 100644
--- a/res/values-mcc270-sk/strings.xml
+++ b/res/values-mcc270-sk/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: upozornenie na únos"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Test"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Cvičenie"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Upozornenie na únos"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Upozornenie na únos"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Zobrazovať upozornenia na únosy detí"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Zobrazovať testovacie správy"</string>
diff --git a/res/values-mcc270-sl/strings.xml b/res/values-mcc270-sl/strings.xml
index 38fa36f14..5882c8d43 100644
--- a/res/values-mcc270-sl/strings.xml
+++ b/res/values-mcc270-sl/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"Opozorilo za LU: Opozorilo o ugrabitvi"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Preizkus opozorila za LU"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Vaja za opozorilo za LU"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Opozorilo o ugrabitvi"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Opozorilo o ugrabitvi"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Prikaz opozorilnih sporočil o ugrabitvah otrok"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Preizkus opozorila za LU"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Prikaz preizkusnih sporočil"</string>
diff --git a/res/values-mcc270-sq/strings.xml b/res/values-mcc270-sq/strings.xml
index 56cf097d9..05885b396 100644
--- a/res/values-mcc270-sq/strings.xml
+++ b/res/values-mcc270-sq/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Sinjalizim për rrëmbim"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: Testim"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: Ushtrim"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Sinjalizim rrëmbimi"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Sinjalizim rrëmbimi"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Shfaq mesazhe sinjalizuese për rrëmbimet e fëmijëve"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: Testim"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Shfaq mesazhet e testimit"</string>
diff --git a/res/values-mcc270-sr/strings.xml b/res/values-mcc270-sr/strings.xml
index 714658234..265808851 100644
--- a/res/values-mcc270-sr/strings.xml
+++ b/res/values-mcc270-sr/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: Упозорење о отмици"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert тест"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert вежбање"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Упозорење о отмици"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Упозорење о отмици"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Приказуј поруке упозорења за отмице деце"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert тест"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Приказуј пробне поруке"</string>
diff --git a/res/values-mcc270-sv/strings.xml b/res/values-mcc270-sv/strings.xml
index 250933e52..2d1bdd331 100644
--- a/res/values-mcc270-sv/strings.xml
+++ b/res/values-mcc270-sv/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-varning : Varning om kidnappning"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-varningstest"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-varningsövning"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Varning om kidnappning"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Varning om kidnappning"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Visa varningsmeddelanden om kidnappade barn"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-varningstest"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Visa testmeddelanden"</string>
diff --git a/res/values-mcc270-sw/strings.xml b/res/values-mcc270-sw/strings.xml
index f0960e2da..fc016f8f4 100644
--- a/res/values-mcc270-sw/strings.xml
+++ b/res/values-mcc270-sw/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Arifa kuhusu utekaji nyara"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Jaribio la LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Majaribio ya LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Arifa kuhusu Utekaji Nyara"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Arifa kuhusu utekaji nyara"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Onyesha ujumbe wa arifa kuhusu matukio ya watoto kutekwa nyara"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Jaribio la LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Onyesha ujumbe wa jaribio"</string>
diff --git a/res/values-mcc270-ta/strings.xml b/res/values-mcc270-ta/strings.xml
index eb687aa25..02eae5d17 100644
--- a/res/values-mcc270-ta/strings.xml
+++ b/res/values-mcc270-ta/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : கடத்தல் குறித்த எச்சரிக்கை"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert பரிசோதனை"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert பயிற்சி"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"கடத்தல் குறித்த எச்சரிக்கை"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"கடத்தல் குறித்த எச்சரிக்கை"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"குழந்தை கடத்தல்கள் குறித்த எச்சரிக்கை மெசேஜ்களைக் காட்டும்"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert பரிசோதனை"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"பரிசோதனை மெசேஜ்களைக் காட்டும்"</string>
diff --git a/res/values-mcc270-te/strings.xml b/res/values-mcc270-te/strings.xml
index 5443f3eb9..539251f46 100644
--- a/res/values-mcc270-te/strings.xml
+++ b/res/values-mcc270-te/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-అలర్ట్ : కిడ్నాపింగ్ అలర్ట్"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-అలర్ట్ టెస్ట్"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-అలర్ట్ డ్రిల్"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"కిడ్నాపింగ్ అలర్ట్"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"కిడ్నాపింగ్ అలర్ట్"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"పిల్లల కిడ్నాప్‌లకు సంబంధించిన అలర్ట్ మెసేజ్‌లను చూడండి"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-అలర్ట్ టెస్ట్"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"టెస్ట్ మెసేజ్‌లను చూడండి"</string>
diff --git a/res/values-mcc270-th/strings.xml b/res/values-mcc270-th/strings.xml
index 3108507da..7b62aebc2 100644
--- a/res/values-mcc270-th/strings.xml
+++ b/res/values-mcc270-th/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : การแจ้งเตือนการลักพาตัวเด็ก"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"การทดสอบ LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"การฝึกซ้อม LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"การแจ้งเตือนการลักพาตัวเด็ก"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"การแจ้งเตือนการลักพาตัวเด็ก"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"แสดงข้อความแจ้งเตือนเรื่องการลักพาตัวเด็ก"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"การทดสอบ LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"แสดงข้อความทดสอบ"</string>
diff --git a/res/values-mcc270-tl/strings.xml b/res/values-mcc270-tl/strings.xml
index a835ef2ba..33410c69e 100644
--- a/res/values-mcc270-tl/strings.xml
+++ b/res/values-mcc270-tl/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Alerto sa pag-kidnap"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Pagsubok sa LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Pagsasanay sa LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Alerto sa Pag-kidnap"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Alerto sa pag-kidnap"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Magpakita ng mga mensahe ng alerto para sa mga pagdukot ng bata"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Pagsubok sa LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Magpakita ng mga mensahe ng pagsubok"</string>
diff --git a/res/values-mcc270-tr/strings.xml b/res/values-mcc270-tr/strings.xml
index 4e5a96516..0db79c931 100644
--- a/res/values-mcc270-tr/strings.xml
+++ b/res/values-mcc270-tr/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Kaçırılma uyarısı"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Testi"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Tatbikatı"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Kaçırılma Uyarısı"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Kaçırılma uyarısı"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Çocuk kaçırma olaylarıyla ilgili uyarı mesajlarını göster"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Testi"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Test mesajlarını göster"</string>
diff --git a/res/values-mcc270-uk/strings.xml b/res/values-mcc270-uk/strings.xml
index 25179b479..412f74c3f 100644
--- a/res/values-mcc270-uk/strings.xml
+++ b/res/values-mcc270-uk/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert: сповіщення про викрадення"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert: тестове сповіщення"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert: тренувальне сповіщення"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Сповіщення про викрадення"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Сповіщення про викрадення дитини"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Показувати сповіщення про викрадених дітей"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert: тестові сповіщення"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Показувати тестові повідомлення"</string>
diff --git a/res/values-mcc270-ur/strings.xml b/res/values-mcc270-ur/strings.xml
index c614f8a9b..ddd15ef46 100644
--- a/res/values-mcc270-ur/strings.xml
+++ b/res/values-mcc270-ur/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"‏‫Alert-LU: اغوا سے متعلق الرٹ"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"‏‫LU-Alert ٹيسٹ"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"‏‫LU-Alert ورزش"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"اغوا سے متعلق الرٹ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"اغوا سے متعلق الرٹ"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"بچوں کے اغوا کے لیے الرٹ پیغامات دکھائیں"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"‏‫LU-Alert ٹيسٹ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"ٹیسٹ پیغامات دکھائیں"</string>
diff --git a/res/values-mcc270-uz/strings.xml b/res/values-mcc270-uz/strings.xml
index 87d6c7dd0..5ddab3f6b 100644
--- a/res/values-mcc270-uz/strings.xml
+++ b/res/values-mcc270-uz/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Bola oʻgʻirlanishi haqida ogohlantirish"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert sinovi"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert simulyatsiyasi"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Oʻgʻrilik ogohlantiruvi"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Bola oʻgʻirlanishi haqida ogohlantirish"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Bola oʻgʻrilanishi haqida ogohlantirishlarini koʻrsatish"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert sinovi"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Sinov xabarlarini koʻrsatish"</string>
diff --git a/res/values-mcc270-vi/strings.xml b/res/values-mcc270-vi/strings.xml
index d5d28b3df..17df1fc72 100644
--- a/res/values-mcc270-vi/strings.xml
+++ b/res/values-mcc270-vi/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert : Cảnh báo bắt cóc"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert Kiểm thử"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert Diễn tập"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Cảnh báo bắt cóc"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Cảnh báo bắt cóc trẻ em"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Hiện cảnh báo bắt cóc trẻ em"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert Kiểm thử"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Hiện thông báo kiểm thử"</string>
diff --git a/res/values-mcc270-zh-rCN/strings.xml b/res/values-mcc270-zh-rCN/strings.xml
index bb7020710..09152261b 100644
--- a/res/values-mcc270-zh-rCN/strings.xml
+++ b/res/values-mcc270-zh-rCN/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert：绑架警报"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert 测试"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert 演习"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"绑架警报"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"绑架警报"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"显示有关儿童被诱拐的警报消息"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert 测试"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"显示测试消息"</string>
diff --git a/res/values-mcc270-zh-rHK/strings.xml b/res/values-mcc270-zh-rHK/strings.xml
index 283778f11..5066b70a7 100644
--- a/res/values-mcc270-zh-rHK/strings.xml
+++ b/res/values-mcc270-zh-rHK/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert：綁架警示"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert 測試"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert 演習"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"綁架警示"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"綁架警示"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"顯示兒童誘帶案件的警示訊息"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert 測試"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"顯示測試訊息"</string>
diff --git a/res/values-mcc270-zh-rTW/strings.xml b/res/values-mcc270-zh-rTW/strings.xml
index b4298044a..eda696b6c 100644
--- a/res/values-mcc270-zh-rTW/strings.xml
+++ b/res/values-mcc270-zh-rTW/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"LU-Alert：綁架警報"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"LU-Alert 測試"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"LU-Alert 演習"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"綁架警報"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"綁架警報"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"顯示兒童誘拐案件的警報訊息"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"LU-Alert 測試"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"顯示測試訊息"</string>
diff --git a/res/values-mcc270-zu/strings.xml b/res/values-mcc270-zu/strings.xml
index 90915ecee..ff52ae253 100644
--- a/res/values-mcc270-zu/strings.xml
+++ b/res/values-mcc270-zu/strings.xml
@@ -23,7 +23,7 @@
     <string name="cmas_amber_alert" msgid="1934668428381380827">"I-LU-Alert : Isexwayiso sokuthumba"</string>
     <string name="cmas_required_monthly_test" msgid="7364077592345886483">"Ukuhlolwa kwe-LU-Alert"</string>
     <string name="cmas_exercise_alert" msgid="8651116593061990582">"Isivivinyo Se-LU-Alert"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="8584334752414501217">"Isexwayiso Sokuthunjwa"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3426998226619316792">"Isexwayiso sokuthunjwa"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="5532453981233187282">"Bonisa imiyalezo yesixwayiso yokuthunjwa kwezingane"</string>
     <string name="enable_cmas_test_alerts_title" msgid="6503578245169569633">"Ukuhlolwa kwe-LU-Alert"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="4393658967042119261">"Bonisa imiyalezo yokuhlola"</string>
diff --git a/res/values-mcc270/strings.xml b/res/values-mcc270/strings.xml
index 7ac1628ea..208c60149 100644
--- a/res/values-mcc270/strings.xml
+++ b/res/values-mcc270/strings.xml
@@ -55,7 +55,7 @@
     <!-- Preference title for enable 'EU-Amber / Child Abdunction Alert' checkbox. [CHAR LIMIT=50] -->
     <!-- Required German (de) translation for this message: "Entführungswarnung" -->
     <!-- Required French (fr) translation for this message: "Alerte enlèvement" -->
-    <string name="enable_cmas_amber_alerts_title">Kidnapping Alert</string>
+    <string name="enable_cmas_amber_alerts_title">Kidnapping alert</string>
     <!-- Preference summary for enable 'EU-Amber / Child Abdunction Alert' checkbox. [CHAR LIMIT=100] -->
     <!-- Required German (de) translation for this message: "Warnmeldungen bei Kindesentführungen anzeigen" -->
     <!-- Required French (fr) translation for this message: "Afficher les messages d’alerte pour les enlèvements d'enfant" -->
@@ -71,7 +71,7 @@
     <string name="enable_cmas_test_alerts_summary">Show test messages</string>
 
     <!-- Preference title for 'EU-Exercise / Exercise Alert' checkbox. [CHAR LIMIT=50] -->
-    <!-- Required German (de) translation for this message: "LU-Alert-Übung" -->
+    <!-- Required German (de) translation for this message: "LU-Alert Übung" -->
     <!-- Required French (fr) translation for this message: "LU-Alert Exercice" -->
     <string name="enable_exercise_test_alerts_title">LU-Alert Exercise</string>
     <!-- Preference summary for 'EU-Exercise / Exercise Alert' checkbox. [CHAR LIMIT=125] -->
diff --git a/res/values-mcc284-af/strings.xml b/res/values-mcc284-af/strings.xml
index fba142116..c3b322a8e 100644
--- a/res/values-mcc284-af/strings.xml
+++ b/res/values-mcc284-af/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-WAARSKUWING: Inligting"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-WAARSKUWING: Waarskuwing oor vermiste persone"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-WAARSKUWING: Toetswaarskuwing"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-WAARSKUWING: Oefening"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-WAARSKUWING: Gereserveer"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-WAARSKUWING: Tegniese toets"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Uiterste en ernstige bedreigings"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Uiterste en ernstige bedreigings vir lewe en eiendom"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Inligting"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Boodskappe vir vermiste persone"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Toetswaarskuwings"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Ontvang toetsboodskappe"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Oefenwaarskuwings"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Ontvang oefeningwaarskuwing"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-gereserveerd"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Ontvang EU-gereserveerde boodskappe"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Tegniesetoetswaarskuwings"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Ontvang tegniesetoetsboodskappe"</string>
 </resources>
diff --git a/res/values-mcc284-am/strings.xml b/res/values-mcc284-am/strings.xml
index 9da212eeb..05258a9c0 100644
--- a/res/values-mcc284-am/strings.xml
+++ b/res/values-mcc284-am/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT፦ መረጃ"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT፦ የጠፋ ሰው ማንቂያ"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT፦ የሙከራ ማንቂያ"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: ልምምድ"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: ቦታ ተይዟል"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: የቴክኒክ ሙከራ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"ከፍተኛ እና የከፉ አደጋዎች"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"በሕይወት እና ንብረት ላይ የተጋረጡ ከፍተኛ እና የከፉ አደጋዎች"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"መረጃ"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"ለጠፉ ሰዎች መልዕክቶች"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"የሙከራ ማንቂያዎች"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"የሙከራ መልዕክቶችን ይቀበሉ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"የአካል ብቃት እንቅስቃሴ ማንቂያዎች"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"መልመጃ መልዕክቶችን ተቀበል"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"በአውሮፓ ህብረት የተያዘ"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"በአውሮፓ ህብረት የተያዙ ኤምሴዎችን ተቀበል"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"የቴክኒክ ሙከራ ማንቂያዎች"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"የቴክኒካዊ ሙከራ መልዕክቶችን ይቀበሉ"</string>
 </resources>
diff --git a/res/values-mcc284-ar/strings.xml b/res/values-mcc284-ar/strings.xml
index 605d937eb..b56966a52 100644
--- a/res/values-mcc284-ar/strings.xml
+++ b/res/values-mcc284-ar/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"‏BG-ALERT: معلومات"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"‏BG-ALERT: تنبيه بشأن الأشخاص المفقودين"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"‏BG-ALERT: تنبيه تجريبي"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"‏‫BG-ALERT: تنبيه تجريبي"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"‏‫BG-ALERT: تنبيه محجوز"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"‏‫BG-ALERT: الاختبار الفني"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"التهديدات الشديدة والقصوى"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"التهديدات الشديدة والقصوى للأرواح والممتلكات"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"معلومات"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"رسائل بشأن الأشخاص المفقودين"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"تنبيهات تجريبية"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"تلقّي رسائل تجريبية"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"تنبيهات تجريبية"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"تلقّي رسائل تجريبية"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"‏تلقّي رسائل EU-Reserved"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"تنبيهات الاختبار الفني"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"تلقّي رسائل الاختبار الفني"</string>
 </resources>
diff --git a/res/values-mcc284-as/strings.xml b/res/values-mcc284-as/strings.xml
index dd3e6ecf0..79a8860ad 100644
--- a/res/values-mcc284-as/strings.xml
+++ b/res/values-mcc284-as/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: তথ্য"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: ব্যক্তি নিৰুদ্দেশ সম্পৰ্কীয় সতৰ্কবাৰ্তা"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: পৰীক্ষামূলক সতৰ্কবাৰ্তা"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: অনুশীলন"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: সংৰক্ষিত"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: কাৰিকৰী পৰীক্ষণ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"চৰম আৰু ভয়াৱহ ভাবুকি"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"জীৱন আৰু সম্পত্তিৰ প্ৰতি চৰম আৰু ভয়াৱহ ভাবুকি"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"তথ্য"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"নিৰুদ্দেশ হোৱা ব্যক্তিৰ বাবে বাৰ্তা"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"পৰীক্ষামূলক সতৰ্কবাৰ্তাসমূহ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"পৰীক্ষামূলক বাৰ্তা লাভ কৰক"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"অনুশীলন সতৰ্কবাৰ্তা"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"অনুশীলনৰ বাৰ্তা পাওক"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-সংৰক্ষিত"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-সংৰক্ষিত বাৰ্তা পাওক"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"কাৰিকৰী পৰীক্ষণৰ সতৰ্কবাৰ্তা"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"কাৰিকৰী পৰীক্ষণৰ বাৰ্তা পাওক"</string>
 </resources>
diff --git a/res/values-mcc284-az/strings.xml b/res/values-mcc284-az/strings.xml
index 7feef5038..964baef0a 100644
--- a/res/values-mcc284-az/strings.xml
+++ b/res/values-mcc284-az/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Məlumat"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: İtmiş şəxs siqnalı"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Test siqnalı"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Sınaq"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Rezerv"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Texniki test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ekstremal və ciddi təhdidlər"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Həyat və mülkiyyət üçün ekstremal və ciddi təhdidlər"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Məlumat"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"İtmiş şəxslər haqqında mesajlar"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Test siqnalları"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Test mesajları qəbul edin"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Sınaq xəbərdarlıqları"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Sınaq mesajları qəbul edin"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Rezerv"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-Rezerv mesajları qəbul edin"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Texniki test xəbərdarlıqları"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Texniki test mesajları qəbul edin"</string>
 </resources>
diff --git a/res/values-mcc284-b+sr+Latn/strings.xml b/res/values-mcc284-b+sr+Latn/strings.xml
index b8c492226..f65711d90 100644
--- a/res/values-mcc284-b+sr+Latn/strings.xml
+++ b/res/values-mcc284-b+sr+Latn/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: informacije"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: upozorenje o nestaloj osobi"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: probno upozorenje"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Vežbanje"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Rezervisano"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Tehnički test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ekstremne i ozbiljne opasnosti"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ekstremne i ozbiljne opasnosti po život i imovinu"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informacije"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Poruke za nestale osobe"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Probna obaveštenja"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Prijem probnih poruka"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Obaveštenja o vežbanju"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Primaj poruke o vežbanju"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Samo za EU"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Primaj poruke samo za EU"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Upozorenja o tehničkim testovima"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Primaj poruke o tehničkim testovima"</string>
 </resources>
diff --git a/res/values-mcc284-be/strings.xml b/res/values-mcc284-be/strings.xml
index 6167618d2..1274534ae 100644
--- a/res/values-mcc284-be/strings.xml
+++ b/res/values-mcc284-be/strings.xml
@@ -21,12 +21,21 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Інфармацыя"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Абвестка аб знікненні чалавека"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Тэставая абвестка"</string>
-    <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Надзвычайныя і сур\'ёзныя пагрозы"</string>
-    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Надзвычайныя і сур\'ёзныя пагрозы для жыцця і маёмасці"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: практыкаванне"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: зарэзервавана"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: тэхнічныя выпрабаванні"</string>
+    <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Надзвычайныя і сур’ёзныя пагрозы"</string>
+    <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Надзвычайныя і сур’ёзныя пагрозы для жыцця і маёмасці"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Інфармацыя"</string>
     <string name="enable_cmas_severe_threat_alerts_summary" msgid="4573406416500374588">"Інфармацыйныя паведамленні"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="7180345818103607889">"Абвесткі пра зніклых людзей"</string>
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Паведамленні для зніклых людзей"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Тэставыя абвесткі"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Атрымліваць тэставыя паведамленні"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Трэніровачныя абвесткі"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Атрымліваць трэніровачныя паведамленні"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Зарэзервавана ЕС"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Атрымліваць паведамленні \"Зарэзервавана ЕС\""</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Абвесткі ў рамках тэхнічных выпрабаванняў"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Атрымліваць паведамленні ў рамках тэхнічных выпрабаванняў"</string>
 </resources>
diff --git a/res/values-mcc284-bg/strings.xml b/res/values-mcc284-bg/strings.xml
index b4e81583c..7a69a0e39 100644
--- a/res/values-mcc284-bg/strings.xml
+++ b/res/values-mcc284-bg/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Информация"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Човек в неизвестност"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Тестово съобщение"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Упражнение"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Резервиран"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Технически тест"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Сериозни опасности"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Съобщения за сериозни опасности"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Информация"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Съобщения за хора в неизвестност"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Тестови сигнали"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Получаване на тестови съобщения"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Сигнали за упражнения"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Получаване на съобщения за упражнения"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Получаване на EU-Reserved съобщения"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Технически тестови сигнали"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Получаване на технически тестови съобщения"</string>
 </resources>
diff --git a/res/values-mcc284-bn/strings.xml b/res/values-mcc284-bn/strings.xml
index 65588f674..bd1449c5d 100644
--- a/res/values-mcc284-bn/strings.xml
+++ b/res/values-mcc284-bn/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: তথ্য"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: নিখোঁজ ব্যক্তি সংক্রান্ত সতর্কতা"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: পরীক্ষা সংক্রান্ত সতর্কতা"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: এক্সারসাইজ"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: সংরক্ষিত"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: টেকনিক্যাল টেস্ট"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"চরম এবং গুরুতর হুমকি"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"জীবন ও সম্পত্তি নিয়ে চরম এবং গুরুতর হুমকি"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"তথ্য"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"নিখোঁজ ব্যক্তি সংক্রান্ত মেসেজ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"পরীক্ষা সংক্রান্ত সতর্কতা"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"পরীক্ষা সম্পর্কে মেসেজ পান"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"এক্সারসাইজ সংক্রান্ত সতর্কতা"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"এক্সারসাইজ সংক্রান্ত মেসেজ পান"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"ইউরোপীয় ইউনিয়নের মাধ্যমে সংরক্ষিত"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"ইউরোপীয় ইউনিয়নের মাধ্যমে সংরক্ষিত মেসেজ পান"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"টেকনিক্যাল টেস্ট সংক্রান্ত সতর্কতা"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"টেকনিক্যাল টেস্ট সংক্রান্ত মেসেজ পান"</string>
 </resources>
diff --git a/res/values-mcc284-bs/strings.xml b/res/values-mcc284-bs/strings.xml
index 0bd7829b8..1a4012cb8 100644
--- a/res/values-mcc284-bs/strings.xml
+++ b/res/values-mcc284-bs/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"UPOZORENJE ZA BUGARSKU: informacije"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"UPOZORENJE ZA BUGARSKU: upozorenje o nestaloj osobi"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"UPOZORENJE ZA BUGARSKU: testno upozorenje"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: vježbanje"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: rezervirano"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: tehnički test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ekstremne i ozbiljne prijetnje"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ekstremne i ozbiljne prijetnje po život i imovinu"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informacije"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Poruke za nestale osobe"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testna upozorenja"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Primi tekstualne poruke"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Obavještenja o vježbanju"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Primajte poruke o vježbanju"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Rezervirano za EU"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Primajte poruke rezervirane za EU"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Obavještenja o tehničkim testovima"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Primajte poruke o tehničkim testovima"</string>
 </resources>
diff --git a/res/values-mcc284-ca/strings.xml b/res/values-mcc284-ca/strings.xml
index 714eee67d..f5bec0c8d 100644
--- a/res/values-mcc284-ca/strings.xml
+++ b/res/values-mcc284-ca/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: informació"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: alerta de persona desapareguda"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: alerta de prova"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: simulacre"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: reservat"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: prova tècnica"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Amenaces extremes i greus"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Amenaces extremes i greus per a la vida i la propietat"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informació"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Missatges de persones desaparegudes"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Alertes de prova"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Rep missatges de prova"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Alertes de simulacre"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Rep missatges de simulacre"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Reservat per a la UE"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Rep missatges de Reservat per a la UE"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Alertes de proves tècniques"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Rep missatges de proves tècniques"</string>
 </resources>
diff --git a/res/values-mcc284-cs/strings.xml b/res/values-mcc284-cs/strings.xml
index b5e400e01..211d9087e 100644
--- a/res/values-mcc284-cs/strings.xml
+++ b/res/values-mcc284-cs/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Informace"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Upozornění na pohřešovanou osobu"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Testovací upozornění"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Cvičení"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Vyhrazeno"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Technický test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Extrémní ohrožení"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Extrémní ohrožení zdraví a majetku"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informace"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Oznámení o pohřešovaných osobách"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testovací upozornění"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Dostávat testovací upozornění"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Cvičné výstrahy"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Přijímat cvičné zprávy"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Vyhrazeno pro EU"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Přijímat zprávy vyhrazené pro EU"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Technické testovací výstrahy"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Přijímat technické testovací zprávy"</string>
 </resources>
diff --git a/res/values-mcc284-da/strings.xml b/res/values-mcc284-da/strings.xml
index 82cd98ea4..bd0b9fc4c 100644
--- a/res/values-mcc284-da/strings.xml
+++ b/res/values-mcc284-da/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Oplysninger"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Underretning om forsvundet person"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Testunderretning"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Øvelse"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Reserveret"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Teknisk test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ekstreme og alvorlige trusler"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ekstreme og alvorlige trusler mod liv og ejendom"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Oplysninger"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Meddelelser om forsvundne personer"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testunderretninger"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Modtag meddelelser om tests"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Øvelsesunderretninger"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Modtag meddelelser om øvelser"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Reserveret til EU"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Modtag meddelelser, der er reserveret til EU"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Underretninger om tekniske tests"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Modtag meddelelser om tekniske tests"</string>
 </resources>
diff --git a/res/values-mcc284-de/strings.xml b/res/values-mcc284-de/strings.xml
index fd0bbea02..f5b419366 100644
--- a/res/values-mcc284-de/strings.xml
+++ b/res/values-mcc284-de/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Information"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Meldung über eine vermisste Person"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Testwarnung"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Übung"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Reserviert"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Technischer Test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Schwerwiegende Gefahren"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Schwerwiegende Gefahren für Leben und Eigentum"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Information"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Benachrichtigungen über vermisste Personen"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testwarnungen"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Testnachrichten erhalten"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Warnungen der Kategorie „Übung“"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Meldungen der Kategorie „Übung“ empfangen"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Reserviert für die EU"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Meldungen der Kategorie „Reserviert für die EU“ empfangen"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Warnungen der Kategorie „Technischer Test“"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Meldungen der Kategorie „Technischer Test“ empfangen"</string>
 </resources>
diff --git a/res/values-mcc284-el/strings.xml b/res/values-mcc284-el/strings.xml
index 328b5a9b2..f4a4c4f53 100644
--- a/res/values-mcc284-el/strings.xml
+++ b/res/values-mcc284-el/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Πληροφορίες"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Ειδοποίηση για άτομο που αγνοείται"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Δοκιμαστική ειδοποίηση"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Άσκηση"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Με δέσμευση"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Τεχνική δοκιμή"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ακραίες και σοβαρές απειλές"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ακραίες και σοβαρές απειλές κατά της ζωής και της ιδιοκτησίας"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Πληροφορίες"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Μηνύματα σχετικά με άτομα που αγνοούνται"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Δοκιμαστικές ειδοποιήσεις"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Λήψη δοκιμαστικών μηνυμάτων"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Ειδοποιήσεις άσκησης"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Λήψη μηνυμάτων άσκησης"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Λήψη μηνυμάτων με δέσμευση για ΕΕ"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Ειδοποιήσεις τεχνικών δοκιμών"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Λήψη μηνυμάτων τεχνικών δοκιμών"</string>
 </resources>
diff --git a/res/values-mcc284-en-rAU/strings.xml b/res/values-mcc284-en-rAU/strings.xml
index 8935e808c..c4bc34bd9 100644
--- a/res/values-mcc284-en-rAU/strings.xml
+++ b/res/values-mcc284-en-rAU/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Information"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Missing person alert"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Test alert"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Exercise"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Reserved"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Technical test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Extreme and severe threats"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Extreme and severe threats to life and property"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Information"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Messages for missing persons"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Test alerts"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Receive test messages"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Exercise alerts"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Receive exercise messages"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Receive EU-reserved messages"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Technical test alerts"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Receive technical test messages"</string>
 </resources>
diff --git a/res/values-mcc284-en-rCA/strings.xml b/res/values-mcc284-en-rCA/strings.xml
index 1153eab7b..d001bc89a 100644
--- a/res/values-mcc284-en-rCA/strings.xml
+++ b/res/values-mcc284-en-rCA/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Information"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Missing Person Alert"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Test alert"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Exercise"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Reserved"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Technical test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Extreme and Severe Threats"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Extreme and Severe Threats to Life and Property"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Information"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Messages for Missing Persons"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Test Alerts"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Receive Тest Мessages"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Exercise Alerts"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Receive Exercise Мessages"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Receive EU-Reserved Мessages"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Technical Test Alerts"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Receive Technical Test Мessages"</string>
 </resources>
diff --git a/res/values-mcc284-en-rGB/strings.xml b/res/values-mcc284-en-rGB/strings.xml
index 8935e808c..c4bc34bd9 100644
--- a/res/values-mcc284-en-rGB/strings.xml
+++ b/res/values-mcc284-en-rGB/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Information"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Missing person alert"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Test alert"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Exercise"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Reserved"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Technical test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Extreme and severe threats"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Extreme and severe threats to life and property"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Information"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Messages for missing persons"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Test alerts"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Receive test messages"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Exercise alerts"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Receive exercise messages"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Receive EU-reserved messages"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Technical test alerts"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Receive technical test messages"</string>
 </resources>
diff --git a/res/values-mcc284-en-rIN/strings.xml b/res/values-mcc284-en-rIN/strings.xml
index 8935e808c..c4bc34bd9 100644
--- a/res/values-mcc284-en-rIN/strings.xml
+++ b/res/values-mcc284-en-rIN/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Information"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Missing person alert"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Test alert"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Exercise"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Reserved"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Technical test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Extreme and severe threats"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Extreme and severe threats to life and property"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Information"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Messages for missing persons"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Test alerts"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Receive test messages"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Exercise alerts"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Receive exercise messages"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Receive EU-reserved messages"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Technical test alerts"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Receive technical test messages"</string>
 </resources>
diff --git a/res/values-mcc284-en-rXC/strings.xml b/res/values-mcc284-en-rXC/strings.xml
index 82277791c..ab3d6c80c 100644
--- a/res/values-mcc284-en-rXC/strings.xml
+++ b/res/values-mcc284-en-rXC/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‎‏‏‎‎‏‏‎‏‎‏‏‎‏‎‎‎‏‎‎‎‎‏‏‎‎‎‎‎‎‎‎‎‏‎‏‏‏‏‏‎‎‎‏‎‎‏‎‏‎‏‎‏‏‎‏‏‎‎‎‎‏‎‎BG-ALERT: Information‎‏‎‎‏‎"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‏‎‎‏‏‏‏‎‏‏‏‎‎‏‎‏‎‏‎‏‏‎‏‏‏‎‎‏‎‏‏‎‏‎‏‎‏‎‏‏‎‎‎‎‏‎‎‎‏‎‎‏‏‏‎‏‎‏‏‎‏‎BG-ALERT: Missing Person Alert‎‏‎‎‏‎"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‎‏‎‏‏‎‎‏‏‏‏‏‎‏‏‎‎‎‎‏‏‏‎‎‏‎‎‎‏‎‎‏‏‎‏‏‎‎‏‎‏‏‏‏‎‏‏‎‎‏‎‏‎‎‏‎‏‎‏‏‏‏‎‎BG-ALERT: Test alert‎‏‎‎‏‎"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‎‏‏‎‏‏‏‏‏‏‏‏‎‎‎‏‏‏‏‏‎‏‎‏‎‏‏‎‎‏‎‏‏‎‎‎‎‎‎‎‏‏‏‎‏‎‏‎‎‎‎‏‎‎‎‎‎‏‏‎‎‏‎‎BG-ALERT: Exercise‎‏‎‎‏‎"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‎‏‏‏‎‏‏‎‎‏‎‏‏‏‎‏‏‎‏‏‎‎‎‎‎‏‏‏‏‎‎‎‎‏‎‎‎‎‎‏‏‎‏‏‏‏‎‎‏‏‎‎‏‏‎‎‎‏‎‎‏‏‏‎BG-ALERT: Reserved‎‏‎‎‏‎"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‎‏‏‎‎‎‎‎‏‎‎‎‎‎‎‏‎‎‏‏‏‏‎‏‎‎‏‎‏‏‏‏‎‏‎‎‏‎‏‎‏‏‎‎‎‎‎‏‎‏‎‎‎‏‏‏‏‏‏‏‎‏‎‎BG-ALERT: Technical test‎‏‎‎‏‎"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‎‏‎‎‏‏‏‏‎‏‎‎‎‏‏‎‏‏‎‎‎‎‎‏‏‏‎‏‏‎‏‏‎‎‏‎‏‎‎‎‎‏‎‏‎‎‎‏‏‏‏‏‎‏‏‎‏‎‎‏‏‎‏‎Extreme and Severe Threats‎‏‎‎‏‎"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‎‏‏‏‏‎‏‎‎‎‎‏‏‎‎‏‏‎‏‎‏‏‎‎‏‎‏‏‏‎‏‎‎‎‏‏‎‏‎‎‏‎‏‎‏‎‎‏‏‏‏‎‏‏‏‎‏‎‏‏‎‎‏‎Extreme and Severe Threats to Life and Property‎‏‎‎‏‎"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‏‎‎‏‎‏‎‏‎‏‏‏‏‎‏‏‎‏‎‏‏‎‎‎‏‎‎‏‎‎‏‎‏‏‎‎‎‏‎‎‎‏‏‏‎‎‏‎‏‏‏‎‎‏‎‏‎‎‏‏‏‎‎Information‎‏‎‎‏‎"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‎‏‎‎‏‎‏‏‏‏‏‏‏‎‎‎‎‎‏‎‎‎‏‎‎‎‎‏‏‏‎‎‏‎‎‏‎‏‎‎‎‏‎‏‏‏‎‏‎‏‎‎‎‎‎‎‏‎‏‏‎‏‏‎Messages for Missing Persons‎‏‎‎‏‎"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‎‏‏‎‎‎‏‎‏‏‎‏‎‏‎‏‏‏‏‏‏‏‎‏‏‎‎‎‎‏‎‏‏‏‏‏‎‏‏‏‏‎‏‎‎‏‏‎‎‎‏‏‎‎‎‏‏‏‏‎‎‎Test Alerts‎‏‎‎‏‎"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‏‎‎‏‎‏‏‏‏‏‎‏‎‏‏‏‎‏‎‎‎‎‏‎‎‎‏‎‎‏‎‎‏‏‎‏‎‎‎‏‏‎‏‎‏‎‎‎‏‎‎‎‎‏‎‎‏‎‏‏‎‎Receive Тest Мessages‎‏‎‎‏‎"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‏‎‏‎‏‏‏‎‏‏‎‏‏‎‏‏‏‎‏‎‏‎‎‎‎‎‏‏‎‎‏‏‎‎‏‎‏‎‎‎‎‏‏‎‏‏‏‏‎‏‏‏‎‏‎‎‎‎‎‎‏‎Exercise Alerts‎‏‎‎‏‎"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‎‏‎‏‏‎‎‎‎‎‏‏‎‏‏‎‏‎‎‏‎‎‏‎‏‏‎‎‏‏‏‏‎‏‏‏‎‎‎‎‏‏‎‎‏‎‎‏‎‏‏‎‏‎‏‎‏‏‎‏‎‎Receive Exercise Мessages‎‏‎‎‏‎"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‏‎‏‎‏‎‎‏‏‏‏‎‎‎‏‏‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‎‎‎‎‎‏‎‏‎‎‎‎‎‏‎‏‎‎‎‏‏‏‎‎‏‎‏‏‏‏‏‎EU-Reserved‎‏‎‎‏‎"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‏‎‎‎‏‏‏‎‎‎‏‏‎‏‎‏‎‎‏‎‏‏‏‎‏‏‏‎‎‏‎‏‏‏‎‎‏‎‎‏‎‏‎‏‏‏‎Receive EU-Reserved Мessages‎‏‎‎‏‎"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‎‏‏‏‎‎‎‎‎‏‎‎‎‎‏‏‏‎‏‏‏‎‎‏‎‎‎‏‎‎‏‏‏‏‎‎‏‎‎‎‏‎‎‏‎‎‎‎‎‎‎‎‎‏‎‎‏‎‎‏‎‎Technical Test Alerts‎‏‎‎‏‎"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‎‏‏‎‎‎‎‏‏‏‏‎‎‎‏‎‏‏‏‏‎‎‏‎‎‎‎‎‎‏‎‎‎‎‏‎‎‏‏‎‎‎‎‏‎‎‏‏‎‏‎‏‏‏‎‏‎‏‎Receive Technical Test Мessages‎‏‎‎‏‎"</string>
 </resources>
diff --git a/res/values-mcc284-es-rUS/strings.xml b/res/values-mcc284-es-rUS/strings.xml
index b6cf630c9..a47d78bb5 100644
--- a/res/values-mcc284-es-rUS/strings.xml
+++ b/res/values-mcc284-es-rUS/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Información"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Alerta de persona desaparecida"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Alerta de prueba"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Ejercicio"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Reservado"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Prueba técnica"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Amenazas graves y extremas"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Amenazas graves y extremas contra la vida y la propiedad"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Información"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Mensajes sobre persona desaparecida"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Alertas de prueba"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Recibir mensajes de prueba"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Alertas de ejercicio"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Recibir mensajes de ejercicio"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Reservado para la UE"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Recibir mensajes reservados para la UE"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Alertas de prueba técnica"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Recibir mensajes de prueba técnica"</string>
 </resources>
diff --git a/res/values-mcc284-es/strings.xml b/res/values-mcc284-es/strings.xml
index a771e9595..9e5a0d459 100644
--- a/res/values-mcc284-es/strings.xml
+++ b/res/values-mcc284-es/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Información"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Alerta de persona desaparecida"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Alerta de prueba"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: simulacro"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: reservado"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: prueba técnica"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Amenazas graves y extremas"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Amenazas graves y extremas contra la vida y la propiedad"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Información"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Mensajes sobre personas desaparecidas"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Alertas de prueba"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Recibir mensajes de prueba"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Alertas de simulacro"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Recibir mensajes de simulacro"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Reservado para la UE"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Recibir mensajes reservados para la UE"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Alertas de pruebas técnicas"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Recibir mensajes de pruebas técnicas"</string>
 </resources>
diff --git a/res/values-mcc284-et/strings.xml b/res/values-mcc284-et/strings.xml
index e4158414a..72cc42401 100644
--- a/res/values-mcc284-et/strings.xml
+++ b/res/values-mcc284-et/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: teave"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: kadunud inimese hoiatus"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: testhoiatus"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: harjutus"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: reserveeritud"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: tehniline test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ekstreemsed ja tõsised ohud"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ekstreemsed ja tõsised ohud elule ja varale"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Teave"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Kadunud inimeste sõnumid"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testhoiatused"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Testsõnumite vastuvõtmine"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Harjutuse hoiatused"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Saate harjutuse kohta sõnumeid"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EL-i reserveeritud"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Saate EL-i hoiatussüsteemi (EU-Reserved) sõnumeid"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Tehnilise testi hoiatused"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Saate tehnilise testi kohta sõnumeid"</string>
 </resources>
diff --git a/res/values-mcc284-eu/strings.xml b/res/values-mcc284-eu/strings.xml
index 71cd6e49f..ae5394e74 100644
--- a/res/values-mcc284-eu/strings.xml
+++ b/res/values-mcc284-eu/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BULGARIAKO ALERTA: informazioa"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BULGARIAKO ALERTA: pertsona bat galdu da"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BULGARIAKO ALERTA: probako alerta"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: simulazioa"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: mugatuta"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: proba teknikoa"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Muturreko mehatxuak eta mehatxu larriak"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Bizitzaren eta jabetzen aurkako muturreko mehatxuen eta mehatxu larrien alertak"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informazioa"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Galdu diren pertsonei buruzko mezuak"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Probako alertak"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Jaso probako mezuak"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Simulazio-alertak"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Jaso simulazioei buruzko mezuak"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Europar Batasunera mugatua"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Jaso Europar Batasunera mugatutako mezuak"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Proba teknikoen alertak"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Jaso proba teknikoei buruzko mezuak"</string>
 </resources>
diff --git a/res/values-mcc284-fa/strings.xml b/res/values-mcc284-fa/strings.xml
index c36b7cf84..8810d5129 100644
--- a/res/values-mcc284-fa/strings.xml
+++ b/res/values-mcc284-fa/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"‏BG-ALERT: اطلاع‌رسانی"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"‏BG-ALERT: هشدار شخص گم‌شده"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"‏BG-ALERT: هشدار آزمایشی"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"‏BG-ALERT: تمرینی"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"‏BG-ALERT: رزروشده"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"‏BG-ALERT: آزمایش فنی"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"تهدیدهای شدید و جدی"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"تهدیدهای شدید و جدی جانی و مالی"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"اطلاع‌رسانی"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"پیام‌های مربوط به اشخاص گم‌شده"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"هشدارهای آزمایشی"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"دریافت پیام‌های آزمایشی"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"هشدارهای تمرینی"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"دریافت پیام‌های تمرینی"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"ویژه اتحادیه اروپا"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"دریافت پیام‌های ویژه اتحادیه اروپا"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"هشدارهای آزمایش فنی"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"دریافت پیام‌های آزمایش فنی"</string>
 </resources>
diff --git a/res/values-mcc284-fi/strings.xml b/res/values-mcc284-fi/strings.xml
index d64995338..9cae0668d 100644
--- a/res/values-mcc284-fi/strings.xml
+++ b/res/values-mcc284-fi/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Ilmoitus"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Hälytys kadonneesta henkilöstä"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Testihälytys"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Harjoitus"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Varattu"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Tekninen testi"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Äärimmäiset ja vakavat uhat"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ihmishenkiä ja omaisuutta koskevat äärimmäiset ja vakavat uhat"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Ilmoitukset"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Viestit kadonneista henkilöistä"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testihälytykset"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Vastaanota testiviestejä"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Harjoitushälytykset"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Vastaanota harjoitusviestejä"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-varattu"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Vastaanota EU-varattu -viestejä"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Teknisiä testejä koskevat hälytykset"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Vastaanota teknisiä testejä koskevia viestejä"</string>
 </resources>
diff --git a/res/values-mcc284-fr-rCA/strings.xml b/res/values-mcc284-fr-rCA/strings.xml
index f833b5899..f2d20ae7e 100644
--- a/res/values-mcc284-fr-rCA/strings.xml
+++ b/res/values-mcc284-fr-rCA/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Renseignements"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Alerte de personne disparue"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Alerte d\'essai"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT : Exercice"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT : Réservé"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT : Test technique"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Menaces extrêmes et graves"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Menaces extrêmes et graves à la vie et aux biens"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Renseignements"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Messages relatifs à des personnes disparues"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Alertes d\'essai"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Recevoir des messages d\'essai"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Alertes d\'exercice"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Recevoir les messages d\'exercice"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Réservé à l\'UE"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Recevoir les messages réservés à l\'UE"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Alertes de test technique"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Recevoir les messages de test technique"</string>
 </resources>
diff --git a/res/values-mcc284-fr/strings.xml b/res/values-mcc284-fr/strings.xml
index 6e27321c6..4257dbf59 100644
--- a/res/values-mcc284-fr/strings.xml
+++ b/res/values-mcc284-fr/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT : Information"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT : Alerte de personne disparue"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT : Alerte de test"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT : Exercice"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT : Réservé"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT : Test technique"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Menaces graves et extrêmes"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Menaces graves et extrêmes pour les biens et personnes"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informations"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Messages concernant les personnes disparues"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Alertes de test"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Recevoir les messages de test"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Alertes d\'exercice"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Recevoir les messages d\'exercice"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Réservé"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Recevoir les messages EU-Réservé"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Alertes de test technique"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Recevoir les messages de test technique"</string>
 </resources>
diff --git a/res/values-mcc284-gl/strings.xml b/res/values-mcc284-gl/strings.xml
index 7b1742de7..e4057c16b 100644
--- a/res/values-mcc284-gl/strings.xml
+++ b/res/values-mcc284-gl/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Información"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Alerta de persoa desaparecida"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Alerta de proba"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Simulacro"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Reservado"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Proba técnica"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ameazas graves e extremas"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ameazas graves e extremas para a vida e a propiedade"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Información"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Mensaxes sobre persoas desaparecidas"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Alertas de proba"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Recibe mensaxes de proba"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Alertas de simulacro"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Recibir mensaxes de simulacro"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Reservadas para a UE"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Recibir mensaxes reservadas para a UE"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Alertas de probas técnicas"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Recibir mensaxes de probas técnicas"</string>
 </resources>
diff --git a/res/values-mcc284-gu/strings.xml b/res/values-mcc284-gu/strings.xml
index a9ddec543..081007dd7 100644
--- a/res/values-mcc284-gu/strings.xml
+++ b/res/values-mcc284-gu/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: માહિતી"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: ગુમ થયેલી વ્યક્તિ સંબંધિત અલર્ટ"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: પરીક્ષણનું અલર્ટ"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: ડ્રિલ"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: આરક્ષિત"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: ટેક્નિકલ પરીક્ષણ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"આત્યંતિક અને ગંભીર જોખમો"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"જીવન અને સંપત્તિના આત્યંતિક અને ગંભીર જોખમો"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"માહિતી"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"ગુમ થયેલી વ્યક્તિ માટે મેસેજ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"પરીક્ષણ માટે અલર્ટ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"પરીક્ષણ માટે મેસેજ મેળવો"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"સુરક્ષા ડ્રિલનાં અલર્ટ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"ડ્રિલને લગતા મેસેજ મેળવો"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU માટે આરક્ષિત"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU માટે આરક્ષિત મેસેજ મેળવો"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"ટેક્નિકલ પરીક્ષણ સંબંધિત અલર્ટ"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"ટેક્નિકલ પરીક્ષણ સંબંધિત મેસેજ મેળવો"</string>
 </resources>
diff --git a/res/values-mcc284-hi/strings.xml b/res/values-mcc284-hi/strings.xml
index 860bda8b2..92b06a97f 100644
--- a/res/values-mcc284-hi/strings.xml
+++ b/res/values-mcc284-hi/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: जानकारी"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: व्यक्ति के लापता होने की सूचना"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: जांच के बारे में चेतावनी"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: ड्रिल"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: रिज़र्व"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: टेक्निकल टेस्ट"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"गंभीर खतरों की चेतावनियां"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"ज़िंदगी और प्रॉपर्टी को होने वाले गंभीर खतरों की चेतावनियां"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"जानकारी"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"व्यक्ति के लापता होने के बारे में मैसेज"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"जांच के बारे में चेतावनियां"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"जांच के बारे में मैसेज पाएं"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"सुरक्षा ड्रिल की जानकारी"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"ड्रिल से जुड़े मैसेज पाएं"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"ईयू-रिज़र्व"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"ईयू के रिज़र्व मैसेज पाएं"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"टेक्निकल टेस्ट से जुड़ी चेतावनियां"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"टेक्निकल टेस्ट से जुड़े मैसेज पाएं"</string>
 </resources>
diff --git a/res/values-mcc284-hr/strings.xml b/res/values-mcc284-hr/strings.xml
index 6ba9ef65c..811e26f59 100644
--- a/res/values-mcc284-hr/strings.xml
+++ b/res/values-mcc284-hr/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: informacije"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: upozorenje o nestaloj osobi"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: testno upozorenje"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: vježba"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: ograničeno"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: tehnički test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ekstremne i ozbiljne prijetnje"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ekstremne i ozbiljne prijetnje po život i imovinu"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informacije"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Poruke za nestale osobe"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testna upozorenja"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Primanje testnih poruka"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Upozorenja u vezi s vježbama"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Primajte poruke o vježbama"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Ograničeno na EU"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Primajte poruke o stavkama ograničenim na EU"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Upozorenja u vezi s tehničkim testovima"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Primajte poruke o tehničkim testovima"</string>
 </resources>
diff --git a/res/values-mcc284-hu/strings.xml b/res/values-mcc284-hu/strings.xml
index 42854e606..c40541771 100644
--- a/res/values-mcc284-hu/strings.xml
+++ b/res/values-mcc284-hu/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Információ"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Eltűnt személy miatti riasztás"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Próbariasztás"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Gyakorlat"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Fenntartva"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Műszaki teszt"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Szélsőséges és súlyos veszélyek"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Az életet és a vagyontárgyakat fenyegető szélsőséges és súlyos veszélyek"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Információ"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Eltűnt személyekkel kapcsolatos üzenetek"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Próbariasztások"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Próbaüzenetek fogadása"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Gyakorlati riasztások"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Gyakorlattal kapcsolatos üzenetek fogadása"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU számára fenntartott"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU számára fenntartott üzenetek fogadása"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Műszaki próbariasztások"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Műszaki tesztüzenetek fogadása"</string>
 </resources>
diff --git a/res/values-mcc284-hy/strings.xml b/res/values-mcc284-hy/strings.xml
index a2df908eb..1df60b881 100644
--- a/res/values-mcc284-hy/strings.xml
+++ b/res/values-mcc284-hy/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT․ տեղեկություններ"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT․ անհայտ կորած անձի մասին ծանուցում"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT․ փորձնական ծանուցում"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT. ուսումնական տագնապ"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT․ ամրագրված"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT․ տեխնիկական փորձարկում"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ծայրահեղ կամ լուրջ վտանգներ"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Կյանքին և գույքին սպառնացող ծայրահեղ կամ լուրջ վտանգներ"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Տեղեկություններ"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Հաղորդագրություններ անհայտ կորած մարդկանց մասին"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Փորձնական ծանուցումներ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Ստանալ փորձնական հաղորդագրություններ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Ուսումնական տագնապների մասին ծանուցումներ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Ստանալ ուսումնական տագնապների մասին ծանուցումներ"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Ստանալ EU-Reserved հաղորդագրություններ"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Տեխնիկական փորձարկումների մասին ծանուցումներ"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Ստանալ տեխնիկական փորձարկումների մասին ծանուցումներ"</string>
 </resources>
diff --git a/res/values-mcc284-in/strings.xml b/res/values-mcc284-in/strings.xml
index 9c563c657..a4f92d2fc 100644
--- a/res/values-mcc284-in/strings.xml
+++ b/res/values-mcc284-in/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Informasi"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Peringatan Orang Hilang"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Peringatan pengujian"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Latihan"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Khusus"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Pengujian teknis"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ancaman Ekstrem dan Serius"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ancaman Ekstrem dan Serius terhadap Nyawa dan Properti"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informasi"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Pesan untuk Orang Hilang"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Peringatan Pengujian"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Terima Pesan Pengujian"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Peringatan Latihan"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Terima Pesan Latihan"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Khusus Uni Eropa"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Terima Pesan Khusus Uni Eropa"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Peringatan Pengujian Teknis"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Terima Pesan Pengujian Teknis"</string>
 </resources>
diff --git a/res/values-mcc284-is/strings.xml b/res/values-mcc284-is/strings.xml
index fac71666d..304cfb398 100644
--- a/res/values-mcc284-is/strings.xml
+++ b/res/values-mcc284-is/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Upplýsingar"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Viðvörun um týndan einstakling"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Prufuviðvörun"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Æfing"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Afmörkuð"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Tæknileg prófun"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Mikil eða mjög mikil hætta"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Líf og eignir í mikilli eða mjög mikilli hættu"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Upplýsingar"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Skilaboð um týnda einstaklinga"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Prufuviðvaranir"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Móttaka prufuskilaboð"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Æfingaviðvaranir"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Fá skilaboð vegna æfinga"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Aðeins ESB"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Fá skilaboð sem eru afmörkuð við ESB"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Viðvaranir um tæknilegar prófanir"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Fá skilaboð vegna tæknilegra prófana"</string>
 </resources>
diff --git a/res/values-mcc284-it/strings.xml b/res/values-mcc284-it/strings.xml
index ada61f306..6a834a713 100644
--- a/res/values-mcc284-it/strings.xml
+++ b/res/values-mcc284-it/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: informazioni"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: allerta persona scomparsa"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: allerta di prova"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: simulazione"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: riservato"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: prova tecnica"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Minacce estreme e gravi"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Minacce estreme e gravi alla vita e alle proprietà"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informazioni"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Messaggi relativi a persone scomparse"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Allerte di prova"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Ricevi messaggi di prova"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Avvisi di simulazioni"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Ricevi messaggi per le simulazioni"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Solo per l\'UE"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Ricevi messaggi riservati all\'UE"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Avvisi di prove tecniche"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Ricevi messaggi per le prove tecniche"</string>
 </resources>
diff --git a/res/values-mcc284-iw/strings.xml b/res/values-mcc284-iw/strings.xml
index faf89f84d..641c18fcc 100644
--- a/res/values-mcc284-iw/strings.xml
+++ b/res/values-mcc284-iw/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"התראה בבולגריה: מידע"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"התראה בבולגריה: התראה על אדם נעדר"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"התראה בבולגריה: התראת בדיקה"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"‏BG-ALERT: תרגיל"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"התרעה בבולגריה: נשמר"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"‏BG-ALERT: בדיקה טכנית"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"איומים קיצוניים וחמורים"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"איומים קיצוניים וחמורים לנפש ולרכוש"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"מידע"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"הודעות על אנשים נעדרים"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"התראות בדיקה"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"קבלת הודעות בדיקה"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"התרעות על תרגילים"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"קבלת הודעות על תרגילים"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"שמור לאיחוד האירופי"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"קבלת הודעות שמורות לאיחוד האירופי"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"התרעות לגבי בדיקות טכניות"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"קבלת הודעות לגבי בדיקות טכניות"</string>
 </resources>
diff --git a/res/values-mcc284-ja/strings.xml b/res/values-mcc284-ja/strings.xml
index 2a8bc6f32..b5f0de97a 100644
--- a/res/values-mcc284-ja/strings.xml
+++ b/res/values-mcc284-ja/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: 情報"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: 行方不明者に関するアラート"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: テストアラート"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: 訓練"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: 予約済み"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: 技術テスト"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"極めて重大な脅威"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"命や財産に関わる極めて重大な脅威"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"情報"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"行方不明者に関するメッセージ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"テストアラート"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"テスト メッセージを受信する"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"訓練用速報メール"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"訓練用メッセージを受信する"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU 専用"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU 専用メッセージを受信する"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"技術テスト速報メール"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"技術テストのメッセージを受信する"</string>
 </resources>
diff --git a/res/values-mcc284-ka/strings.xml b/res/values-mcc284-ka/strings.xml
index 1e163cd46..32214eeba 100644
--- a/res/values-mcc284-ka/strings.xml
+++ b/res/values-mcc284-ka/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: ინფორმაცია"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: გაფრთხილება დაკარგული ადამიანის შესახებ"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: სატესტო გაფრთხილება"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: სავარჯიშო"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: რეზერვირებული"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: ტექნიკური ტესტი"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"უკიდურესი და სერიოზული საფრთხეები"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"სიცოცხლისა და საკუთრებისადმი უკიდურესი და სერიოზული საფრთხეები"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"ინფორმაცია"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"შეტყობინებები დაკარგული ადამიანებისთვის"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"სატესტო გაფრთხილებები"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"სატესტო შეტყობინებების მიღება"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"სავარჯიშო გაფრთხილებები"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"სავარჯიშო შეტყობინებების მიღება"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"ევროკავშირის მიერ რეზერვირებული"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"ევროკავშირის მიერ რეზერვირებული შეტყობინებების მიღება"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"ტექნიკური სატესტო გაფრთხილებები"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"ტექნიკური სატესტო შეტყობინებების მიღება"</string>
 </resources>
diff --git a/res/values-mcc284-kk/strings.xml b/res/values-mcc284-kk/strings.xml
index f4b10392e..71557ebe6 100644
--- a/res/values-mcc284-kk/strings.xml
+++ b/res/values-mcc284-kk/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: ақпарат"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: жоғалған адам туралы хабарландыру"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: сынақ хабарландыру"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Жаттығу"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Резервтелді"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Техникалық сынақ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Үлкен қауіптер"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Өмірге және мүлікке төнген үлкен қауіптер"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Ақпарат"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Жоғалған адамдарға қатысты хабарлар"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Сынақ хабарландырулар"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Сынақ хабарландырулар алу"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Жаттығу хабарландырулары"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Жаттығу хабарларын алу"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-Reserved хабарларын алу"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Техникалық сынақ хабарландырулары"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Техникалық сынақ хабарларын алу"</string>
 </resources>
diff --git a/res/values-mcc284-km/strings.xml b/res/values-mcc284-km/strings.xml
index 2911fea5e..7ebe2f1b5 100644
--- a/res/values-mcc284-km/strings.xml
+++ b/res/values-mcc284-km/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT៖ ព័ត៌មាន"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT៖ ការជូនដំណឹងអំពីការបាត់មនុស្ស"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT៖ ការជូនដំណឹងសាកល្បង"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT៖ អនុវត្តសាកល្បង"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT៖ បម្រុង"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT៖ ការធ្វើតេស្តបច្ចេកទេស"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"ការគំរាមកំហែងខ្លាំងក្លា និងធ្ងន់ធ្ងរ"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"ការគំរាមកំហែងខ្លាំងក្លា និងធ្ងន់ធ្ងរដល់អាយុជីវិត និងទ្រព្យសម្បត្តិ"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"ព័ត៌មាន"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"សារសម្រាប់ការបាត់មនុស្ស"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"ការជូនដំណឹង​សាកល្បង"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"ទទួលបានសារសាកល្បង"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"ការជូនដំណឹង​អំពី​ការអនុវត្តសាកល្បង"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"ទទួលសារអំពីការអនុវត្តសាកល្បង"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"ទទួលសារ EU-Reserved"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"ការជូនដំណឹងអំពីការធ្វើតេស្តបច្ចេកទេស"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"ទទួលបានសារអំពីការធ្វើតេស្តបច្ចេកទេស"</string>
 </resources>
diff --git a/res/values-mcc284-kn/strings.xml b/res/values-mcc284-kn/strings.xml
index f7f164606..4e0cb1aae 100644
--- a/res/values-mcc284-kn/strings.xml
+++ b/res/values-mcc284-kn/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ಅಲರ್ಟ್: ಮಾಹಿತಿ"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ಅಲರ್ಟ್: ಕಾಣೆಯಾದ ವ್ಯಕ್ತಿಯ ಕುರಿತ ಅಲರ್ಟ್"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ಅಲರ್ಟ್: ಪರೀಕ್ಷಾ ಅಲರ್ಟ್"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ಅಲರ್ಟ್: ಅಭ್ಯಾಸ"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ಅಲರ್ಟ್: ಕಾಯ್ದಿರಿಸಲಾಗಿದೆ"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ಅಲರ್ಟ್: ತಾಂತ್ರಿಕ ಪರೀಕ್ಷೆ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"ತೀವ್ರ ಮತ್ತು ಗಂಭೀರ ಬೆದರಿಕೆಗಳು"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"ಜೀವ ಮತ್ತು ಆಸ್ತಿಪಾಸ್ತಿಗೆ ತೀವ್ರ ಮತ್ತು ಗಂಭೀರ ಬೆದರಿಕೆಗಳು"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"ಮಾಹಿತಿ"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"ಕಾಣೆಯಾದ ವ್ಯಕ್ತಿಗಳಿಗೆ ಸಂದೇಶಗಳು"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"ಪರೀಕ್ಷೆ ಅಲರ್ಟ್‌ಗಳು"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"ಪರೀಕ್ಷಾ ಸಂದೇಶಗಳನ್ನು ಸ್ವೀಕರಿಸಿ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"ಅಭ್ಯಾಸದ ಅಲರ್ಟ್‌ಗಳು"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"ಅಭ್ಯಾಸದ ಸಂದೇಶಗಳನ್ನು ಪಡೆಯಿರಿ"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-ಕಾಯ್ದಿರಿಸಲಾಗಿದೆ"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-ಕಾಯ್ದಿರಿಸಿದ ಸಂದೇಶಗಳನ್ನು ಸ್ವೀಕರಿಸಿ"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"ತಾಂತ್ರಿಕ ಪರೀಕ್ಷಾರ್ಥ ಅಲರ್ಟ್‌ಗಳು"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"ತಾಂತ್ರಿಕ ಪರೀಕ್ಷಾರ್ಥ ಸಂದೇಶಗಳನ್ನು ಸ್ವೀಕರಿಸಿ"</string>
 </resources>
diff --git a/res/values-mcc284-ko/strings.xml b/res/values-mcc284-ko/strings.xml
index bf1545117..b20aaa818 100644
--- a/res/values-mcc284-ko/strings.xml
+++ b/res/values-mcc284-ko/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: 정보"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: 실종자 경보"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: 시험 알림"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: 안전 훈련"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: 전용"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: 기술 테스트"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"심각한 위협"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"생명 및 재산에 대한 심각한 위협"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"정보"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"실종자 메시지"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"테스트 경보"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"시험 메시지 받기"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"안전 훈련 알림"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"안전 훈련 메시지 받기"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU 전용"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU 전용 메시지 받기"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"기술 테스트 알림"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"기술 테스트 메시지 받기"</string>
 </resources>
diff --git a/res/values-mcc284-ky/strings.xml b/res/values-mcc284-ky/strings.xml
index c3c743f36..83014533b 100644
--- a/res/values-mcc284-ky/strings.xml
+++ b/res/values-mcc284-ky/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Маалымат"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Жоголгон адам тууралуу билдирүү"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Сынамык эскертүү"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Көнүгүү"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Ээленген"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Техникалык сыноо"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Олуттуу коркунуч"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Өмүргө жана мүлккө келтирилгөн олуттуу коркунуч"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Маалымат"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Жоголгон адам тууралуу билдирүүлөр"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Сынамык шашылыш билдирүүлөр"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Сынамык билдирүүлөрдү алуу"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Көнүгүү билдирүүлөрү"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Көнүгүү билдирүүлөрүн алуу"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-Reserved билдирүүлөрүн алуу"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Техникалык cыноо билдирүүлөрү"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Техникалык сыноо билдирүүлөрүн алуу"</string>
 </resources>
diff --git a/res/values-mcc284-lo/strings.xml b/res/values-mcc284-lo/strings.xml
index 2bd1a4c6a..b7ba35ea2 100644
--- a/res/values-mcc284-lo/strings.xml
+++ b/res/values-mcc284-lo/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: ຂໍ້ມູນ"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: ການແຈ້ງເຕືອນຄົນເສຍ"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: ທົດສອບການແຈ້ງເຕືອນ"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: ອອກກຳລັງກາຍ"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: ສະຫງວນໄວ້"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: ການທົດສອບທາງເທັກນິກ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"ໄພຂົ່ມຂູ່ຮ້າຍແຮງ ແລະ ຮຸນແຮງ"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"ໄພຂົ່ມຂູ່ຮ້າຍແຮງ ແລະ ຮຸນແຮງຕໍ່ຊີວິດ ແລະ ຊັບສິນ"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"ຂໍ້ມູນ"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"ຂໍ້ຄວາມສຳລັບຄົນເສຍ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"ທົດສອດແຈ້ງເຕືອນ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"ຮັບຂໍ້ຄວາມທົດສອບ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"ແຈ້ງເຕືອນອອກກຳລັງກາຍ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"ຮັບຂໍ້ຄວາມອອກກຳລັງກາຍ"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"ສະຫງວນໄວ້ສຳລັບ EU"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"ຮັບຂໍ້ຄວາມທີ່ສະຫງວນໄວ້ສຳລັບ EU"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"ແຈ້ງເຕືອນການທົດສອບທາງເທັກນິກ"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"ຮັບຂໍ້ຄວາມການທົດສອບທາງເທັກນິກ"</string>
 </resources>
diff --git a/res/values-mcc284-lt/strings.xml b/res/values-mcc284-lt/strings.xml
index 425f451a0..488a1f099 100644
--- a/res/values-mcc284-lt/strings.xml
+++ b/res/values-mcc284-lt/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: informacija"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: įspėjimas apie dingusį asmenį"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: bandomasis įspėjimas"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: testinis bandymas"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: rezervuota"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: techninis bandymas"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Didelė ir rimta grėsmė"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Didelė ir rimta grėsmė gyvybei ir nuosavybei"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informacija"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Pranešimai apie dingusius asmenis"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Bandomieji įspėjimai"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Gauti bandomuosius pranešimus"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Testinių bandymų įspėjimai"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Gauti testinių bandymų pranešimus"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"ES rezervuota"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Gauti ES rezervuotus pranešimus"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Įspėjimai apie techninius bandymus"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Gauti techninių bandymų pranešimus"</string>
 </resources>
diff --git a/res/values-mcc284-lv/strings.xml b/res/values-mcc284-lv/strings.xml
index cc247a542..3b70022aa 100644
--- a/res/values-mcc284-lv/strings.xml
+++ b/res/values-mcc284-lv/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: informācija"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: brīdinājums par pazudušu personu"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: testa brīdinājums"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: vingrinājums"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: rezervēts"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: tehniskais izmēģinājums"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ārkārtējs un nopietns apdraudējums"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ārkārtējs un nopietns apdraudējums dzīvībai un īpašumam"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informācija"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Ziņojumi par pazudušām personām"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testa brīdinājumi"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Saņemt testa ziņojumus"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Vingrošanas brīdinājums"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Saņemt paziņojumus par vingrošanu"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"ES rezervēts"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Saņemt ES rezervētus paziņojumus"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Brīdinājums par tehniskajiem izmēģinājumiem"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Saņemt paziņojumus par tehniskajiem izmēģinājumiem"</string>
 </resources>
diff --git a/res/values-mcc284-mk/strings.xml b/res/values-mcc284-mk/strings.xml
index 96f1ee7d8..077496c67 100644
--- a/res/values-mcc284-mk/strings.xml
+++ b/res/values-mcc284-mk/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: информации"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: предупредувањe за исчезнато лице"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: пробно предупредувањe"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: вежба"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: резервирано"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: технички тест"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Екстремни и сериозни закани"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Екстремни и сериозни закани за животот и имотот"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Информации"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Пораки за исчезнати лица"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Пробни предупредувања"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Примање пробни пораки"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Предупредувања за вежби"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Примајте пораки за вежби"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Резервирано за ЕУ"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Примајте пораки резервирани за ЕУ"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Предупредувања за технички тестови"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Примајте пораки за технички тестови"</string>
 </resources>
diff --git a/res/values-mcc284-ml/strings.xml b/res/values-mcc284-ml/strings.xml
index 3b7c593ec..ae6ab5c35 100644
--- a/res/values-mcc284-ml/strings.xml
+++ b/res/values-mcc284-ml/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-മുന്നറിയിപ്പ്: വിവരങ്ങൾ"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-അലേർട്ട്: വ്യക്തിയെ കാണാനില്ലെന്ന മുന്നറിയിപ്പ്"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-മുന്നറിയിപ്പ്: പരീക്ഷണ മുന്നറിയിപ്പ്"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: പരിശീലനം"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: റിസർവ് ചെയ്തവ"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: സാങ്കേതിക പരീക്ഷണം"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"ഗുരുതരവും അപകടകരവുമായ ഭീഷണികൾ"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"ജീവനും സ്വത്തിനും നേരെയുള്ള ഗുരുതരവും അപകടകരവുമായ ഭീഷണികൾ"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"വിവരങ്ങൾ"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"വ്യക്തികളെ കാണാതാകുന്നതുമായി ബന്ധപ്പെട്ട സന്ദേശങ്ങൾ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"പരീക്ഷണ മുന്നറിയിപ്പുകൾ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"പരീക്ഷണ സന്ദേശങ്ങൾ സ്വീകരിക്കുക"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"പരിശീലന അറിയിപ്പുകൾ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"പരിശീലന സന്ദേശങ്ങൾ സ്വീകരിക്കുക"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-വിന് റിസർവ് ചെയ്തവ"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-വിന് റിസർവ് ചെയ്ത സന്ദേശങ്ങൾ സ്വീകരിക്കുക"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"സാങ്കേതിക പരീക്ഷണ അറിയിപ്പുകൾ"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"സാങ്കേതിക പരീക്ഷണ സന്ദേശങ്ങൾ സ്വീകരിക്കുക"</string>
 </resources>
diff --git a/res/values-mcc284-mn/strings.xml b/res/values-mcc284-mn/strings.xml
index ceb3cac6a..4e9857e51 100644
--- a/res/values-mcc284-mn/strings.xml
+++ b/res/values-mcc284-mn/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Мэдээлэл"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Алга болсон хүний сэрэмжлүүлэг"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Туршилтын сэрэмжлүүлэг"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Сургуулилт"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Тусгайлан хадгалсан"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Техникийн туршилт"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Онц бөгөөд ноцтой заналхийлэл"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Амь нас болон өмч хөрөнгийн онц бөгөөд ноцтой заналхийлэл"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Мэдээлэл"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Алга болсон хүний мессеж"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Туршилтын сэрэмжлүүлэг"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Туршилтын мессеж хүлээн авах"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Сургуулилтын сэрэмжлүүлэг"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Сургуулилтын зурвас хүлээн авах"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"ЕХ-нд тусгайлан хадгалсан"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"ЕХ-нд тусгайлан хадгалсан зурвас хүлээн авах"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Техникийн туршилтын сэрэмжлүүлэг"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Техникийн туршилтын зурвас хүлээн авах"</string>
 </resources>
diff --git a/res/values-mcc284-mr/strings.xml b/res/values-mcc284-mr/strings.xml
index 89f6f72d4..91a0f5baa 100644
--- a/res/values-mcc284-mr/strings.xml
+++ b/res/values-mcc284-mr/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG इशारा: माहिती"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG इशारा: व्यक्ती सूचना दिलेली नाही"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG इशारा: चाचणी सूचना"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: सराव"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: राखीव"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: तांत्रिक चाचणी"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"अत्यधिक आणि गंभीर धोके"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"जीवन आणि मालमत्तेशी संबंधित अत्यधिक व गंभीर धोके"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"माहिती"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"नसलेल्या लोकांविषयी मेसेज"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"चाचणी अलर्ट"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"चाचणी मेसेज मिळवा"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"सरावासंबंधित सूचना"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"सरावासंबंधित मेसेज मिळवा"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"ईयूसाठी राखीव"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"ईयूसाठी राखीव मेसेज मिळवा"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"तांत्रिक चाचणीशी संबंधित सूचना"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"तांत्रिक चाचणीशी संबंधित मेसेज मिळवा"</string>
 </resources>
diff --git a/res/values-mcc284-ms/strings.xml b/res/values-mcc284-ms/strings.xml
index 9e5aba836..efe0a212e 100644
--- a/res/values-mcc284-ms/strings.xml
+++ b/res/values-mcc284-ms/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Maklumat"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Makluman Orang Hilang"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Makluman ujian"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"MAKLUMAN-BG: Latihan"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"MAKLUMAN-BG: Khas"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"MAKLUMAN-BG: Ujian teknikal"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ancaman Ekstrem dan Melampau"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ancaman Ekstrem dan Melampau kepada Nyawa dan Harta Benda"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Maklumat"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Mesej untuk Orang Hilang"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Makluman Ujian"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Terima Mesej Ujian"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Makluman Latihan"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Terima Mesej Latihan"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Khas EU"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Terima Mesej Khas EU"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Makluman Ujian Teknikal"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Terima Mesej Ujian Teknikal"</string>
 </resources>
diff --git a/res/values-mcc284-my/strings.xml b/res/values-mcc284-my/strings.xml
index 4b3937bdc..34fd477f3 100644
--- a/res/values-mcc284-my/strings.xml
+++ b/res/values-mcc284-my/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-သတိပေးချက်- အချက်အလက်"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-သတိပေးချက်- လူပျောက်ကြောင်း သတိပေးချက်"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-သတိပေးချက်- စမ်းသပ် သတိပေးချက်"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT- လေ့ကျင့်မှု"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT- သီးသန့်"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT- နည်းပညာဆိုင်ရာ စမ်းသပ်မှု"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"အလွန်ကြီးမားပြင်းထန်သော အန္တရာယ်များ"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"အသက်အိုးအိမ်အတွက် အလွန်ကြီးမားပြင်းထန်သော အန္တရာယ်များ"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"အချက်အလက်"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"လူပျောက်ခြင်းအတွက် မက်ဆေ့ဂျ်များ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"စမ်းသပ် သတိပေးချက်များ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"စမ်းသပ် မက်ဆေ့ဂျ်များ လက်ခံသည်"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"လေ့ကျင့်မှု သတိပေးချက်များ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"လေ့ကျင့်မှု မက်ဆေ့ဂျ်များ လက်ခံရန်"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-Reserved မက်ဆေ့ဂျ်များ လက်ခံရန်"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"နည်းပညာဆိုင်ရာ စမ်းသပ်မှု သတိပေးချက်များ"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"နည်းပညာဆိုင်ရာ စမ်းသပ်မှု မက်ဆေ့ဂျ်များ လက်ခံရန်"</string>
 </resources>
diff --git a/res/values-mcc284-nb/strings.xml b/res/values-mcc284-nb/strings.xml
index 8191d5c82..d3b55a8ad 100644
--- a/res/values-mcc284-nb/strings.xml
+++ b/res/values-mcc284-nb/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Informasjon"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Varsel om forsvunne personer"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Testvarsel"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: øvelse"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: reservert"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: teknisk test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ekstreme og alvorlige trusler"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ekstreme og alvorlige trusler mot liv og eiendom"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informasjon"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Meldinger om forsvunne personer"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testvarsler"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Motta testmeldinger"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Øvelsesvarsler"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Motta øvelsesmeldinger"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-reservert"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Motta EU-reserverte meldinger"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Tekniske testvarsler"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Motta tekniske testmeldinger"</string>
 </resources>
diff --git a/res/values-mcc284-ne/strings.xml b/res/values-mcc284-ne/strings.xml
index 2ad354c81..899eef0cf 100644
--- a/res/values-mcc284-ne/strings.xml
+++ b/res/values-mcc284-ne/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: जानकारी"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: मान्छे हराएको सूचना"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: परीक्षणसम्बन्धी अलर्ट"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: अभ्यास"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: रिजर्भ गरिएको छ"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: प्राविधिक परीक्षण"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"चरम र गम्भीर जोखिमहरू"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"जीवन र सम्पत्तिमा हुने चरम र गम्भीर जोखिमहरू"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"जानकारी"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"मान्छे हराएकोसम्बन्धी म्यासेज"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"परीक्षणसम्बन्धी अलर्टहरू"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"परीक्षणका म्यासेजहरू प्राप्त गर्नुहोस्"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"अभ्याससम्बन्धी अलर्टहरू"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"अभ्याससम्बन्धी म्यासेजहरू प्राप्त गर्नुहोस्"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU का लागि रिजर्भ गरिएको"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU का लागि रिजर्भ गरिएका म्यासेजहरू प्राप्त गर्नुहोस्"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"प्राविधिक परीक्षणसम्बन्धी अलर्टहरू"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"प्राविधिक परीक्षणसम्बन्धी म्यासेजहरू प्राप्त गर्नुहोस्"</string>
 </resources>
diff --git a/res/values-mcc284-nl/strings.xml b/res/values-mcc284-nl/strings.xml
index d75bb9560..4f21206d0 100644
--- a/res/values-mcc284-nl/strings.xml
+++ b/res/values-mcc284-nl/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: informatie"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: melding voor vermiste personen"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: testmelding"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: oefening"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: gereserveerd"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: technische test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Extreem en ernstig gevaar"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Extreem en ernstig gevaar voor levens en eigendommen"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informatie"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Berichten voor vermiste personen"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testmeldingen"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Testberichten krijgen"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Oefeningsmeldingen"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Oefeningsberichten ontvangen"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Gereserveerd voor de EU"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Berichten gereserveerd voor de EU ontvangen"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Meldingen voor technische tests"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Berichten voor technische tests ontvangen"</string>
 </resources>
diff --git a/res/values-mcc284-or/strings.xml b/res/values-mcc284-or/strings.xml
index 3d98183c4..2a10803fb 100644
--- a/res/values-mcc284-or/strings.xml
+++ b/res/values-mcc284-or/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: ସୂଚନା"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: ହଜିଯାଇଥିବା ବ୍ୟକ୍ତିଙ୍କ ବିଷୟରେ ଆଲର୍ଟ"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: ଟେଷ୍ଟ ଆଲର୍ଟ"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: ବ୍ୟାୟାମ"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: ସଂରକ୍ଷିତ"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: ଟେକ୍ନିକାଲ ଟେଷ୍ଟ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"ଅତ୍ୟନ୍ତ ଗୁରୁତର ଏବଂ ଗମ୍ଭୀର ବିପଦଗୁଡ଼ିକ"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"ଜୀବନ ଓ ସମ୍ପତ୍ତି ପ୍ରତି ଅତ୍ୟନ୍ତ ଗୁରୁତର ଏବଂ ଗମ୍ଭୀର ବିପଦଗୁଡ଼ିକ"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"ସୂଚନା"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"ହଜିଯାଇଥିବା ବ୍ୟକ୍ତିଙ୍କ ପାଇଁ ମେସେଜଗୁଡ଼ିକ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"ଟେଷ୍ଟ ଆଲର୍ଟ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"ଟେଷ୍ଟ ମେସେଜଗୁଡ଼ିକ ପାଆନ୍ତୁ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"ବ୍ୟାୟାମ ଆଲର୍ଟଗୁଡ଼ିକ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"ବ୍ୟାୟାମ ମେସେଜଗୁଡ଼ିକ ପାଆନ୍ତୁ"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-ସଂରକ୍ଷିତ"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-ସଂରକ୍ଷିତ ମେସେଜଗୁଡ଼ିକ ପାଆନ୍ତୁ"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"ଟେକ୍ନିକାଲ ଟେଷ୍ଟ ଆଲର୍ଟଗୁଡ଼ିକ"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"ଟେକ୍ନିକାଲ ଟେଷ୍ଟ ମେସେଜଗୁଡ଼ିକ ପାଆନ୍ତୁ"</string>
 </resources>
diff --git a/res/values-mcc284-pa/strings.xml b/res/values-mcc284-pa/strings.xml
index b8f642e34..c85a556ef 100644
--- a/res/values-mcc284-pa/strings.xml
+++ b/res/values-mcc284-pa/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: ਜਾਣਕਾਰੀ"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: ਗੁੰਮਸ਼ੁਦਾ ਵਿਅਕਤੀ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: ਜਾਂਚ ਅਲਰਟ"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: ਅਭਿਆਸ"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: ਰਾਖਵਾਂ"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: ਤਕਨੀਕੀ ਜਾਂਚ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"ਬਹੁਤ ਜ਼ਿਆਦਾ ਅਤੇ ਗੰਭੀਰ ਧਮਕੀਆਂ"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"ਜਾਨ-ਮਾਲ ਦੀਆਂ ਬਹੁਤ ਜ਼ਿਆਦਾ ਅਤੇ ਗੰਭੀਰ ਧਮਕੀਆਂ"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"ਜਾਣਕਾਰੀ"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"ਗੁੰਮਸ਼ੁਦਾ ਵਿਅਕਤੀ ਲਈ ਸੁਨੇਹੇ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"ਜਾਂਚ ਅਲਰਟ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"ਲਿਖਤ ਸੁਨੇਹੇ ਪ੍ਰਾਪਤ ਕਰੋ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"ਅਭਿਆਸ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"ਅਭਿਆਸ ਸੁਨੇਹੇ ਪ੍ਰਾਪਤ ਕਰੋ"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-Reserved ਸੁਨੇਹੇ ਪ੍ਰਾਪਤ ਕਰੋ"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"ਤਕਨੀਕੀ ਜਾਂਚ ਸੰਬੰਧੀ ਅਲਰਟ"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"ਤਕਨੀਕੀ ਜਾਂਚ ਸੁਨੇਹੇ ਪ੍ਰਾਪਤ ਕਰੋ"</string>
 </resources>
diff --git a/res/values-mcc284-pl/strings.xml b/res/values-mcc284-pl/strings.xml
index 646ab9438..0a783e0db 100644
--- a/res/values-mcc284-pl/strings.xml
+++ b/res/values-mcc284-pl/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: informacja"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: alert dotyczący osoby zaginionej"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: alert testowy"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Ćwiczenia"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Zastrzeżone"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Testy techniczne"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Poważne zagrożenia"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Poważne zagrożenia dla życia i mienia"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informacje"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Komunikaty dotyczące zaginionych osób"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Alerty testowe"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Otrzymuj wiadomości testowe"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Alerty ćwiczeniowe"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Odbieraj komunikaty ćwiczeniowe"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Zastrzeżone dla UE"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Odbieraj komunikaty zastrzeżone dla UE"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Techniczne alerty testowe"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Odbieraj techniczne komunikaty testowe"</string>
 </resources>
diff --git a/res/values-mcc284-pt-rPT/strings.xml b/res/values-mcc284-pt-rPT/strings.xml
index 04ab450f1..3fd355abd 100644
--- a/res/values-mcc284-pt-rPT/strings.xml
+++ b/res/values-mcc284-pt-rPT/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Informações"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Alerta de pessoa desaparecida"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Alerta de teste"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: exercício"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: reservado"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: teste técnico"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ameaças extremas e graves"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ameaças extremas e graves à vida e propriedade"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informações"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Mensagens relativamente a pessoas desaparecidas"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Alertas de teste"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Receber mensagens de teste"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Alertas de exercício"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Receber mensagens de exercício"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Reservado à UE"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Receber mensagens reservadas à UE"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Alertas de teste técnico"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Receber mensagens de teste técnico"</string>
 </resources>
diff --git a/res/values-mcc284-pt/strings.xml b/res/values-mcc284-pt/strings.xml
index 365e05c28..0438d474d 100644
--- a/res/values-mcc284-pt/strings.xml
+++ b/res/values-mcc284-pt/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: informação"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: alerta de pessoa desaparecida"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: alerta de teste"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: exercício"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: reservado"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: teste técnico"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Ameaças graves e extremas"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Ameaças graves e extremas à vida e propriedade"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informações"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Mensagens sobre pessoas desaparecidas"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Alertas de teste"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Receber mensagens de teste"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Alertas de exercício"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Receber mensagens de exercício"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Reservados à UE"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Receber mensagens reservadas à UE"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Alertas de teste técnico"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Receber mensagens de teste técnico"</string>
 </resources>
diff --git a/res/values-mcc284-ro/strings.xml b/res/values-mcc284-ro/strings.xml
index cf30bf8e4..9e95da1d9 100644
--- a/res/values-mcc284-ro/strings.xml
+++ b/res/values-mcc284-ro/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Informare"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Alertă de persoană dispărută"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Alertă de testare"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Simulare"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Rezervate"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Testare tehnică"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Amenințări extreme și severe"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Amenințări extreme și severe la adresa vieții și a proprietăților"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informații"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Mesaje pentru persoane dispărute"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Alerte de testare"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Primește mesaje de testare"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Simulări de alertă"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Primește mesaje privind simulările"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Primește mesaje EU-Reserved"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Alerte pentru testări tehnice"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Primește mesaje privind testările tehnice"</string>
 </resources>
diff --git a/res/values-mcc284-ru/strings.xml b/res/values-mcc284-ru/strings.xml
index fd54b2dd3..a08a09b32 100644
--- a/res/values-mcc284-ru/strings.xml
+++ b/res/values-mcc284-ru/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: информация"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: оповещение о пропавшем человеке"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: тестовое оповещение"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: учебная тревога"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: зарезервировано"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: техническое испытание"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Серьезные угрозы"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Оповещения о серьезных угрозах жизни и имуществу"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Информация"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Сообщения о пропавших людях"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Тестовые оповещения"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Получать тестовые сообщения"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Оповещения об учебных тревогах"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Получать сообщения об учебных тревогах"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Получать сообщения EU-Reserved"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Оповещения о технических испытаниях"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Получать сообщения о технических испытаниях"</string>
 </resources>
diff --git a/res/values-mcc284-si/strings.xml b/res/values-mcc284-si/strings.xml
index d17f21594..e725f3e0c 100644
--- a/res/values-mcc284-si/strings.xml
+++ b/res/values-mcc284-si/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ඇඟවීම: තොරතුරු"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ඇඟවීම: අතුරුදහන් වූ පුද්ගල ඇඟවීම"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ඇඟවීම: පරීක්ෂණ ඇඟවීම"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: ව්‍යායාම"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: වෙන් කර ඇත"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: තාක්ෂණික පරීක්ෂණ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"දැඩි සහ දරුණු තර්ජන"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"ජීවිතයට සහ දේපළවලට අතිශයින් සහ දරුණු තර්ජන"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"තොරතුරු"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"අතුරුදහන් වූවන් සඳහා පණිවිඩ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"පරීක්ෂණ ඇඟවීම්"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"පරීක්ෂණ පණිවිඩ ලබන්න"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"ව්‍යායාම ඇඟවීම්"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"ව්‍යායාම පණිවිඩ ලබන්න"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-Reserved කර ඇති පණිවිඩ ලබන්න"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"තාක්ෂණික පරීක්ෂණ ඇඟවීම්"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"තාක්ෂණික පරීක්ෂණ පණිවිඩ ලබන්න"</string>
 </resources>
diff --git a/res/values-mcc284-sk/strings.xml b/res/values-mcc284-sk/strings.xml
index 55fdb3777..1d526614b 100644
--- a/res/values-mcc284-sk/strings.xml
+++ b/res/values-mcc284-sk/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"UPOZORNENIE BG: Informácia"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"UPOZORNENIE BG: Upozornenie na nezvestnú osobu"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"UPOZORNENIE BG: Testovacie varovanie"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Cvičenie"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Vyhradené"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Technický test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Kritické a závažné ohrozenie"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Kritické a závažné ohrozenie života a majetku"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informácia"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Správy o nezvestných osobách"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testovacie varovania"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Dostávať testovacie správy"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Cvičné výstrahy"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Prijímať cvičné správy"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Vyhradené pre EÚ"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Prijímať správy vyhradené pre EÚ"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Technické testovacie výstrahy"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Prijímať technické testovacie správy"</string>
 </resources>
diff --git a/res/values-mcc284-sl/strings.xml b/res/values-mcc284-sl/strings.xml
index 8fefea0ba..c27a8ba57 100644
--- a/res/values-mcc284-sl/strings.xml
+++ b/res/values-mcc284-sl/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"OPOZORILO ZA BG: Informacije"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"OPOZORILO ZA BG: Opozorilo o pogrešani osebi"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"OPOZORILO ZA BG: Preizkusno opozorilo"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Vaja"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Rezervirano"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Tehnični preizkus"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Izredno hude in hude nevarnosti"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Izredno hude in hude nevarnosti za življenje in premoženje"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informacije"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Sporočila za pogrešane osebe"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Preizkusna opozorila"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Prejemanje preizkusnih sporočil"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Opozorila o vajah"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Prejemanje sporočil o vajah"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Prejemanje sporočil EU-Reserved"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Opozorila o tehničnih preizkusih"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Prejemanje sporočil o tehničnih preizkusih"</string>
 </resources>
diff --git a/res/values-mcc284-sq/strings.xml b/res/values-mcc284-sq/strings.xml
index 264691e1c..4b422b1a0 100644
--- a/res/values-mcc284-sq/strings.xml
+++ b/res/values-mcc284-sq/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Informacione"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Sinjalizim për person të zhdukur"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Sinjalizim testimi"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Ushtrim"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Rezervuar"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Testim teknik"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Kërcënime ekstreme dhe të rënda"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Kërcënime ekstreme dhe të rënda për jetën dhe pronën"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Informacione"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Mesazhe për persona të zhdukur"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Sinjalizime testimi"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Merr mesazhe me tekst"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Sinjalizimet për ushtrime"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Merr mesazhe për ushtrime"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Rezervuar për BE-në"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Merr mesazhe të rezervuara për BE-në"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Sinjalizimet e testimeve teknike"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Merr mesazhe testimesh teknike"</string>
 </resources>
diff --git a/res/values-mcc284-sr/strings.xml b/res/values-mcc284-sr/strings.xml
index 74b04f09c..d94fbb9f6 100644
--- a/res/values-mcc284-sr/strings.xml
+++ b/res/values-mcc284-sr/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: информације"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: упозорење о несталој особи"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: пробно упозорење"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Вежбање"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Резервисано"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Технички тест"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Екстремне и озбиљне опасности"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Екстремне и озбиљне опасности по живот и имовину"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Информације"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Поруке за нестале особе"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Пробна обавештења"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Пријем пробних порука"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Обавештења о вежбању"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Примај поруке о вежбању"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Само за ЕУ"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Примај поруке само за ЕУ"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Упозорења о техничким тестовима"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Примај поруке о техничким тестовима"</string>
 </resources>
diff --git a/res/values-mcc284-sv/strings.xml b/res/values-mcc284-sv/strings.xml
index b007111b3..c9b680e4a 100644
--- a/res/values-mcc284-sv/strings.xml
+++ b/res/values-mcc284-sv/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Information"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Varning om försvunnen person"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Testvarning"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Övning"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Reserverad"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Tekniskt test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Extrema och allvarliga hot"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Extrema och allvarliga hot mot liv och egendom"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Information"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Meddelanden om försvunna personer"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Testvarningar"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Ta emot testmeddelanden"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Varningar om övningar"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Ta emot övningsmeddelanden"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Reserverat för EU"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Ta emot meddelanden som reserverats för EU"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Varningar om tekniska tester"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Ta emot meddelanden om tekniska tester"</string>
 </resources>
diff --git a/res/values-mcc284-sw/strings.xml b/res/values-mcc284-sw/strings.xml
index f5471c895..5c54458cc 100644
--- a/res/values-mcc284-sw/strings.xml
+++ b/res/values-mcc284-sw/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Maelezo"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Arifa kuhusu Mtu Aliyepotea"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Arifa kuhusu jaribio"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Majaribio"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Imeshikiwa nafasi"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Majaribio ya Kiufundi"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Vitisho Vikali"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Vitisho Vikali Dhidi ya Maisha na Mali"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Maelezo"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Ujumbe kuhusu Watu Waliopotea"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Tahadhari za Majaribio"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Pokea Ujumbe kuhusu Jaribio"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Arifa za Majaribio"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Pokea Ujumbe wa Majaribio"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Mahususi kwa Umoja wa Ulaya"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Pokea Ujumbe Mahususi kwa Umoja wa Ulaya"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Arifa Kuhusu Majaribio ya Kiufundi"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Pokea Ujumbe wa Majaribio ya Kiufundi"</string>
 </resources>
diff --git a/res/values-mcc284-ta/strings.xml b/res/values-mcc284-ta/strings.xml
index 26c70c7d3..7ba77ca12 100644
--- a/res/values-mcc284-ta/strings.xml
+++ b/res/values-mcc284-ta/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: தகவல்கள்"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: காணாமல் போனவர் குறித்த எச்சரிக்கை"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: பரிசோதனை எச்சரிக்கை"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: பயிற்சி"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: ஒதுக்கப்பட்டது"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: தொழில்நுட்பப் பரிசோதனை"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"தீவிரமான மற்றும் கடுமையான அச்சுறுத்தல்கள்"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"உயிருக்கும் உடைமைக்கும் தீவிரமான மற்றும் கடுமையான அச்சுறுத்தல்கள்"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"தகவல்கள்"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"காணாமல் போனவர்கள் குறித்த அறிவிப்புகள்"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"பரிசோதனை எச்சரிக்கைகள்"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"பரிசோதனை அறிவிப்புகளைப் பெறலாம்"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"பயிற்சி விழிப்பூட்டல்கள்"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"பயிற்சி மெசேஜ்களைப் பெறுக"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"ஐரோப்பிய ஒன்றியத்துக்கு ஒதுக்கப்பட்டது"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"ஐரோப்பிய ஒன்றியத்துக்கு ஒதுக்கப்பட்ட மெசேஜ்களைப் பெறுக"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"தொழில்நுட்பப் பரிசோதனை விழிப்பூட்டல்கள்"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"தொழில்நுட்பப் பரிசோதனை மெசேஜ்களைப் பெறுக"</string>
 </resources>
diff --git a/res/values-mcc284-te/strings.xml b/res/values-mcc284-te/strings.xml
index 00be22e28..ddee21d03 100644
--- a/res/values-mcc284-te/strings.xml
+++ b/res/values-mcc284-te/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-అలర్ట్: సమాచారం"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-అలర్ట్: మిస్ అయిన వ్యక్తి గుర్తింపు అలర్ట్"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-అలర్ట్: టెస్ట్ అలర్ట్"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: వ్యాయామం"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: రిజర్వ్ చేసినవి"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: టెక్నికల్ టెస్ట్"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"విపరీతమైన, తీవ్రమైన ప్రమాద బెదిరింపులు"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"ప్రాణం, ఆస్తికి విపరీతమైన, తీవ్రమైన ప్రమాద బెదిరింపులు"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"సమాచారం"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"మిస్ అయిన వ్యక్తుల కోసం మెసేజ్‌లు"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"టెస్ట్ అలర్ట్‌లు"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"టెస్ట్ మెసేజ్‌లను స్వీకరించండి"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"వ్యాయామ అలర్ట్‌లు"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"వ్యాయామ మెసేజ్‌లను అందుకోండి"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-రిజర్వ్ చేసినవి"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-రిజర్వ్ చేసిన మెసేజ్‌లను అందుకోండి"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"టెక్నికల్ టెస్ట్ అలర్ట్‌లు"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"టెక్నికల్ టెస్ట్ మెసేజ్‌లను అందుకోండి"</string>
 </resources>
diff --git a/res/values-mcc284-th/strings.xml b/res/values-mcc284-th/strings.xml
index 60ae0c669..ff2866d06 100644
--- a/res/values-mcc284-th/strings.xml
+++ b/res/values-mcc284-th/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"การแจ้งเตือน BG: ข้อมูล"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"การแจ้งเตือน BG: การแจ้งเตือนคนหาย"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"การแจ้งเตือน BG: การแจ้งเตือนทดสอบ"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: การฝึกซ้อม"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Reserved"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: การทดสอบทางเทคนิค"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"ภัยคุกคามที่รุนแรงและร้ายแรง"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"ภัยคุกคามที่รุนแรงและร้ายแรงต่อชีวิตและทรัพย์สิน"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"ข้อมูล"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"ข้อความสำหรับคนหาย"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"การแจ้งเตือนทดสอบ"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"รับข้อความทดสอบ"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"การแจ้งเตือนของการฝึกซ้อม"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"รับข้อความของการฝึกซ้อม"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"รับข้อความ EU-Reserved"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"การแจ้งเตือนการทดสอบทางเทคนิค"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"รับข้อความทดสอบทางเทคนิค"</string>
 </resources>
diff --git a/res/values-mcc284-tl/strings.xml b/res/values-mcc284-tl/strings.xml
index 5c37b3cc0..9fc02dd6a 100644
--- a/res/values-mcc284-tl/strings.xml
+++ b/res/values-mcc284-tl/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Impormasyon"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Alerto sa Nawawalang Tao"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Pansubok na alerto"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Pagsasanay"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Nakareserba"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Teknikal na test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Mga Matindi at Malalang Banta"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Mga Matindi at Malalang Banta sa Buhay at Ari-arian"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Impormasyon"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Mga Mensahe para sa Mga Nawawalang Tao"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Mga Pansubok na Alerto"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Tumanggap ng Mga Pansubok na Mensahe"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Mga Alerto para sa Pagsasanay"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Makatanggap ng Mga Mensahe para sa Pagsasanay"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Nakareserba sa EU"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Makatanggap ng Mga Mensaheng Nakareserba sa EU"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Mga Alerto sa Teknikal na Test"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Makatanggap ng Mga Mensahe ng Teknikal na Test"</string>
 </resources>
diff --git a/res/values-mcc284-tr/strings.xml b/res/values-mcc284-tr/strings.xml
index 43aa7cc1b..b1c1dd20e 100644
--- a/res/values-mcc284-tr/strings.xml
+++ b/res/values-mcc284-tr/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Bilgi"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Kayıp İnsan Uyarısı"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Test Amaçlı Uyarı"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Tatbikat"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Ayrılmış"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Teknik test"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Olağanüstü ve Ciddi Tehditler"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Cana ve Mala Karşı Olağanüstü ve Ciddi Tehditler"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Bilgi"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Kayıp İnsan Mesajları"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Test Amaçlı Uyarılar"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Test Mesajlarını Al"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Tatbikat Uyarıları"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Tatbikat Mesajlarını Al"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-Reserved Мesajları Al"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Teknik Test Uyarıları"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Teknik Test Mesajlarını Al"</string>
 </resources>
diff --git a/res/values-mcc284-uk/strings.xml b/res/values-mcc284-uk/strings.xml
index 753f6f144..ead3a475c 100644
--- a/res/values-mcc284-uk/strings.xml
+++ b/res/values-mcc284-uk/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: інформація"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: сповіщення про зниклу особу"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: тестове сповіщення"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Навчання"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Зарезервовано"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Технічний тест"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Надзвичайні й серйозні загрози"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Надзвичайні й серйозні загрози для життя та майна"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Інформація"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Повідомлення щодо зниклих осіб"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Тестові сповіщення"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Отримувати тестові повідомлення"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Навчальні сповіщення"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Отримувати навчальні сповіщення"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Отримувати повідомлення EU-Reserved"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Сповіщення технічних випробувань"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Отримувати сповіщення технічних випробувань"</string>
 </resources>
diff --git a/res/values-mcc284-ur/strings.xml b/res/values-mcc284-ur/strings.xml
index fb7ca2653..d22383f85 100644
--- a/res/values-mcc284-ur/strings.xml
+++ b/res/values-mcc284-ur/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"‏BG-الرٹ: معلومات"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"‏BG-الرٹ: گمشدہ فرد کا الرٹ"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"‏BG-الرٹ: ٹیسٹ الرٹ"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"‏‫BG-ALERT: مشق"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"‏‫BG-ALERT: ریزرو کردہ"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"‏‫BG-ALERT: ٹیکنیکل ٹیسٹ"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"انتہائی اور شدید خطرات"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"زندگی اور پراپرٹی کو انتہائی اور شدید خطرات"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"معلومات"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"گمشدہ افراد کے لیے پیغامات"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"ٹیسٹ الرٹس"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"ٹیسٹ پیغامات موصول کریں"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"مشق کے الرٹس"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"مشق کے پیغامات موصول کریں"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"‏EU-Reserved پیغامات موصول کریں"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"ٹیکنیکل ٹیسٹ سے متعلق الرٹس"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"ٹیکنیکل ٹیسٹ پیغامات وصول کریں"</string>
 </resources>
diff --git a/res/values-mcc284-uz/strings.xml b/res/values-mcc284-uz/strings.xml
index 230e29a01..5297ea2db 100644
--- a/res/values-mcc284-uz/strings.xml
+++ b/res/values-mcc284-uz/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Axborot"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Yoʻqolgan odam haqida ogohlantirish"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Sinov ogohlantirishi"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Oʻquv mashqi"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Band qilingan"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Texnik sinov"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Oʻta va jiddiy tahdidlar"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Hayot va mulkka oʻta va jiddiy tahdidlar"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Maʼlumot"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Yoʻqolgan odamlar uchun xabarlar"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Sinov ogohlantirishlari"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Sinov xabarlarini olish"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Oʻquv mashqi ogohlantirishlari"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Oʻquv mashqi xabarlarini qabul qilish"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"EU-Reserved"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"EU-Reserved xabarlarini qabul qilish"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Texnik sinov ogohlantirishlari"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Texnik sinov xabarlarni qabul qilish"</string>
 </resources>
diff --git a/res/values-mcc284-vi/strings.xml b/res/values-mcc284-vi/strings.xml
index 8775ed4dc..a11289d3e 100644
--- a/res/values-mcc284-vi/strings.xml
+++ b/res/values-mcc284-vi/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT: Thông tin"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT: Cảnh báo có người mất tích"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT: Cảnh báo thử nghiệm"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Diễn tập"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Dành riêng"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Kiểm tra kỹ thuật"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Mối nguy hiểm cực kỳ nghiêm trọng"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Mối nguy hiểm cực kỳ nghiêm trọng đe doạ tính mạng và tài sản"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Thông tin"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Thông báo có người mất tích"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Cảnh báo thử nghiệm"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Nhận thông báo thử nghiệm"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Cảnh báo diễn tập"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Nhận thông báo diễn tập"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Dành riêng cho Liên minh Châu Âu"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Nhận thông báo dành riêng cho Liên minh Châu Âu"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Cảnh báo kiểm tra kỹ thuật"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Nhận thông báo kiểm tra kỹ thuật"</string>
 </resources>
diff --git a/res/values-mcc284-zh-rCN/strings.xml b/res/values-mcc284-zh-rCN/strings.xml
index b969503d5..3e861d31f 100644
--- a/res/values-mcc284-zh-rCN/strings.xml
+++ b/res/values-mcc284-zh-rCN/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT：信息"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT：人员失踪警报"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT：测试警报"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT：演习"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT：预留"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT：技术测试"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"极端和严重威胁"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"生命财产遭受极端和严重威胁"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"信息"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"人员失踪消息"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"测试警报"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"接收测试消息"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"演习警报"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"接收演习消息"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"欧盟预留"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"接收欧盟预留消息"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"技术测试警报"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"接收技术测试消息"</string>
 </resources>
diff --git a/res/values-mcc284-zh-rHK/strings.xml b/res/values-mcc284-zh-rHK/strings.xml
index dd4dd27fe..2808ff96e 100644
--- a/res/values-mcc284-zh-rHK/strings.xml
+++ b/res/values-mcc284-zh-rHK/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"保加利亞警示：資訊"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"保加利亞警示：失蹤人口警示"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"保加利亞警示：測試警示"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT：演習"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT：保留"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT：技術測試"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"重大威脅"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"生命財產重大威脅"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"資訊"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"失蹤人口訊息"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"測試警示"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"接收測試訊息"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"演習警報"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"接收演習消息"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"歐盟專用"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"接收歐盟專用訊息"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"技術測試警報"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"接收技術測試訊息"</string>
 </resources>
diff --git a/res/values-mcc284-zh-rTW/strings.xml b/res/values-mcc284-zh-rTW/strings.xml
index fe4e6daed..63549d681 100644
--- a/res/values-mcc284-zh-rTW/strings.xml
+++ b/res/values-mcc284-zh-rTW/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"BG-ALERT：資訊"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"BG-ALERT：失蹤人口警報"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"BG-ALERT：測試警報"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT：演習"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT：保留"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT：技術測試"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"重大威脅"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"生命財產重大威脅"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"資訊"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"失蹤人口的訊息"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"測試警報"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"接收測試訊息"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"演習警報"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"接收演習訊息"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"歐盟預留"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"接收歐盟保留訊息"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"技術測試警報"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"接收技術測試訊息"</string>
 </resources>
diff --git a/res/values-mcc284-zu/strings.xml b/res/values-mcc284-zu/strings.xml
index a49f98a10..c2131f627 100644
--- a/res/values-mcc284-zu/strings.xml
+++ b/res/values-mcc284-zu/strings.xml
@@ -21,6 +21,9 @@
     <string name="cmas_severe_alert" msgid="1394463869061650114">"I-BG-ALERT: Ulwazi"</string>
     <string name="cmas_amber_alert" msgid="6042893309718893485">"I-BG-ALERT: Isexwayiso Somuntu Olahlekile"</string>
     <string name="cmas_required_monthly_test" msgid="3241200045692496222">"I-BG-ALERT: Isexwayiso sokuhlola"</string>
+    <string name="cmas_exercise_alert" msgid="1727406102736603186">"BG-ALERT: Ukuzivocavoca"</string>
+    <string name="cmas_operator_defined_alert" msgid="4264583649927521831">"BG-ALERT: Kubhukhiwe"</string>
+    <string name="state_local_test_alert" msgid="3476953286481847290">"BG-ALERT: Ukuhlola ubuchwepheshe"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="2856233162192255821">"Izinsongo Ezidlulele Nezinzima"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="4399126631396210521">"Izinsongo Ezinkulu Nezinzima Empilweni Nempahla"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="7304511098720139598">"Ulwazi"</string>
@@ -29,4 +32,10 @@
     <string name="enable_cmas_amber_alerts_summary" msgid="2737081426606202971">"Imilayezo Yabantu Abalahlekile"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5501920660625344060">"Izexwayiso Zokuhlola"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5979346836630343830">"Thola Imilayeza Yokuhlola"</string>
+    <string name="enable_exercise_test_alerts_title" msgid="6186667183449173633">"Izexwayiso Zokuzivocavoca"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="5406239686393408858">"Thola Imiyalezo Yokuzivocavoca"</string>
+    <string name="enable_operator_defined_test_alerts_title" msgid="7672118368857656927">"Kubhukhwe Yi-EU"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="6269683089765134935">"Thola Imiyalezo Ebhukhwe Yi-EU"</string>
+    <string name="enable_state_local_test_alerts_title" msgid="5622875124715880594">"Izexwayiso Zokuhlola Ubuchwepheshe"</string>
+    <string name="enable_state_local_test_alerts_summary" msgid="9045352067985067381">"Thola Imiyalezo Yokuhlola Ubuchwepheshe"</string>
 </resources>
diff --git a/res/values-mcc284/config.xml b/res/values-mcc284/config.xml
index d02288075..780daa83d 100644
--- a/res/values-mcc284/config.xml
+++ b/res/values-mcc284/config.xml
@@ -15,42 +15,63 @@
 -->
 
 <resources>
-    <!-- 4370, 4383 -->
+    <!-- 4370, 4383 to receive BG-ALERT: Emergency Alert -->
     <string-array name="cmas_presidential_alerts_channels_range_strings" translatable="false">
         <item>0x1112:rat=gsm, emergency=true, alert_duration=31500, override_dnd=true, always_on=true</item>
         <!-- additional language -->
         <item>0x111F:rat=gsm, emergency=true, alert_duration=31500, override_dnd=true, always_on=true</item>
     </string-array>
-    <!-- 4371~4372, 4384~4385 -->
+    <!-- 4371~4372, 4384~4385 BG-ALERT: Warning -->
     <string-array name="cmas_alert_extreme_channels_range_strings" translatable="false">
         <item>0x1113-0x1114:rat=gsm, emergency=true, alert_duration=31500, override_dnd=true</item>
         <!-- additional language -->
         <item>0x1120-0x1121:rat=gsm, emergency=true, alert_duration=31500, override_dnd=true</item>
     </string-array>
-    <!-- 4373~4378, 4386~4391 -->
+    <!-- 4373~4378, 4386~4391 to receive BG-ALERT: Information -->
     <string-array name="cmas_alerts_severe_range_strings" translatable="false">
         <item>0x1115-0x111A:rat=gsm, emergency=true, alert_duration=31500, override_dnd=true</item>
         <!-- additional language -->
         <item>0x1122-0x1127:rat=gsm, emergency=true, alert_duration=31500, override_dnd=true</item>
     </string-array>
-    <!-- 4379, 4392 loss / hijack alert notification for Bulgaria -->
+    <!-- 4379, 4392 to receive BG-ALERT: Missing Person Alert -->
     <string-array name="cmas_amber_alerts_channels_range_strings" translatable="false">
         <item>0x111B:rat=gsm, emergency=true, alert_duration=31500, override_dnd=true</item>
         <!-- additional language -->
         <item>0x1128:rat=gsm, emergency=true, alert_duration=31500, override_dnd=true</item>
     </string-array>
-    <!-- Channel 4380, 4393 test notification for Bulgaria -->
+    <!-- Channel 4380, 4393 to receive BG-ALERT: Test alert -->
     <string-array name="required_monthly_test_range_strings" translatable="false">
-        <item>0x111C:rat=gsm, emergency=false, save=false</item>
+        <item>0x111C:rat=gsm, emergency=true</item>
         <!-- additional language -->
-        <item>0x1129:rat=gsm, emergency=false, save=false</item>
+        <item>0x1129:rat=gsm, emergency=true</item>
+    </string-array>
+    <!-- Channel 4381, 4394 to receive BG-ALERT: Exercise -->
+    <string-array name="exercise_alert_range_strings" translatable="false">
+        <item>0x111D:rat=gsm, emergency=true, testing_mode=true</item>
+        <!-- additional language -->
+        <item>0x112A:rat=gsm, emergency=true, testing_mode=true</item>
+    </string-array>
+    <!-- Channel 4382, 4395 to receive BG-ALERT: Reserved -->
+    <string-array name="operator_defined_alert_range_strings" translatable="false">
+        <item>0x111E:rat=gsm, emergency=true, testing_mode=true</item>
+        <!-- additional language -->
+        <item>0x112B:rat=gsm, emergency=true, testing_mode=true</item>
+    </string-array>
+    <!-- Channel 4398, 4399 to receive BG-ALERT: Technical test -->
+    <string-array name="state_local_test_alert_range_strings" translatable="false">
+        <item>0x112E:rat=gsm, emergency=true</item>
+        <!-- additional language -->
+        <item>0x112F:rat=gsm, emergency=true</item>
     </string-array>
 
-    <string-array name="exercise_alert_range_strings" translatable="false" />
-    <string-array name="operator_defined_alert_range_strings" translatable="false" />
     <string-array name="etws_alerts_range_strings" translatable="false"/>
     <string-array name="etws_test_alerts_range_strings" translatable="false"/>
 
+    <!-- whether to display a separate operator defined test settings. today, most of time, operator defined channels was controlled by the main test toggle. -->
+    <bool name="show_separate_operator_defined_settings">true</bool>
+    <!-- whether to display a separate exercise test settings. today, most of time, exercise channels was controlled by the main test toggle. -->
+    <bool name="show_separate_exercise_settings">true</bool>
+
     <!-- Default value that in the ListPreference.
          These must be a subset of the alert_reminder_interval_values list above. -->
     <string name="alert_reminder_interval_in_min_default" translatable="false">15</string>
@@ -58,5 +79,5 @@
     <!-- Allow user to enable/disable audio speech alert (text-to-speech for received messages)-->
     <bool name="show_alert_speech_setting">true</bool>
     <!-- Default value which determines whether spoken alerts enabled -->
-    <bool name="enable_alert_speech_default">true</bool>
+    <bool name="enable_alert_speech_default">false</bool>
 </resources>
diff --git a/res/values-mcc284/strings.xml b/res/values-mcc284/strings.xml
index e04fcac57..4bd55dfec 100644
--- a/res/values-mcc284/strings.xml
+++ b/res/values-mcc284/strings.xml
@@ -35,6 +35,17 @@
   <!-- Required Bulgarian (bg) translation for this message: "BG-ALERT: Тестово съобщение" -->
   <string name="cmas_required_monthly_test">BG-ALERT: Test alert</string>
 
+  <!-- CMAS dialog title for CMAS Exercise. [CHAR LIMIT=50] -->
+  <!-- Required Bulgarian (bg) translation for this message: "BG-ALERT: Упражнение" -->
+  <string name="cmas_exercise_alert">BG-ALERT: Exercise</string>
+  <!-- CMAS dialog title for operator defined use. [CHAR LIMIT=50] -->
+  <!-- Required Bulgarian (bg) translation for this message: "BG-ALERT: Резервиран" -->
+  <string name="cmas_operator_defined_alert">BG-ALERT: Reserved</string>
+  <!-- Dialog title for all state/local test alerts. [CHAR LIMIT=50] -->
+  <!-- Required Bulgarian (bg) translation for this message: "BG-ALERT: Технически тест" -->
+  <string name="state_local_test_alert">BG-ALERT: Technical test</string>
+
+
   <!-- Preference title for enable CMAS extreme threat alerts checkbox. [CHAR LIMIT=50] -->
   <!-- Required Bulgarian (bg) translation for this message: "Сериозни опасности" -->
   <string name="enable_cmas_extreme_threat_alerts_title">Extreme and Severe Threats</string>
@@ -62,5 +73,25 @@
   <!-- Preference summary for other test alerts checkbox. [CHAR LIMIT=125] -->
   <!-- Required Bulgarian (bg) translation for this message: "Получаване на тестови съобщения" -->
   <string name="enable_cmas_test_alerts_summary">Receive Тest Мessages</string>
+  <!-- Preference title for exercise test alerts checkbox. [CHAR LIMIT=50] -->
+  <!-- Required Bulgarian (bg) translation for this message: "Сигнали за упражнения" -->
+  <string name="enable_exercise_test_alerts_title">Exercise Alerts</string>
+  <!-- Preference summary for exercise test alerts checkbox. [CHAR LIMIT=125] -->
+  <!-- Required Bulgarian (bg) translation for this message: "Получаване на съобщения за упражнения" -->
+  <string name="enable_exercise_test_alerts_summary">Receive Exercise Мessages</string>
+
+  <!-- Preference title for operator defined test alerts checkbox. [CHAR LIMIT=50] -->
+  <!-- Required Bulgarian (bg) translation for this message: "EU-Reserved" -->
+  <string name="enable_operator_defined_test_alerts_title">EU-Reserved</string>
+  <!-- Preference summary for operator defined test alerts checkbox. [CHAR LIMIT=125] -->
+  <!-- Required Bulgarian (bg) translation for this message: "Получаване на EU-Reserved съобщения" -->
+  <string name="enable_operator_defined_test_alerts_summary">Receive EU-Reserved Мessages</string>
+
+  <!-- Preference title for enable state/local test alerts checkbox. [CHAR LIMIT=50] -->
+  <!-- Required Bulgarian (bg) translation for this message: "Технически тестови сигнали" -->
+  <string name="enable_state_local_test_alerts_title">Technical Test Alerts</string>
+  <!-- Preference summary for enable state/local test alerts checkbox. [CHAR LIMIT=125] -->
+  <!-- Required Bulgarian (bg) translation for this message: "Получаване на технически тестови съобщения" -->
+  <string name="enable_state_local_test_alerts_summary">Receive Technical Test Мessages</string>
 
 </resources>
\ No newline at end of file
diff --git a/res/values-mcc310-gu/strings.xml b/res/values-mcc310-gu/strings.xml
index da8037d40..d71d3572a 100644
--- a/res/values-mcc310-gu/strings.xml
+++ b/res/values-mcc310-gu/strings.xml
@@ -31,5 +31,5 @@
     <string name="cmas_presidential_level_alert" msgid="5810314558991898384">"રાષ્ટ્રીય અલર્ટ"</string>
     <string name="show_cmas_opt_out_summary" msgid="5612381687166765604">"પ્રથમ અલર્ટ બતાવ્યા પછી નાપસંદ કરવા માટેનો સંવાદ બતાવો (રાષ્ટ્રીય અલર્ટ સિવાય અન્ય)."</string>
     <string name="enable_cmas_presidential_alerts_title" msgid="3871388542233245120">"રાષ્ટ્ર સંબંધિત જોખમની અલર્ટ"</string>
-    <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"રાષ્ટ્ર સંબંધિત જોખમની ચેતવણીના સંદેશા. બંધ કરી શકાતા નથી."</string>
+    <string name="enable_cmas_presidential_alerts_summary" msgid="1292969668875568075">"રાષ્ટ્ર સંબંધિત જોખમની ચેતવણીના મેસેજ. બંધ કરી શકાતા નથી."</string>
 </resources>
diff --git a/res/values-mcc334-mnc03/config.xml b/res/values-mcc334-mnc03/config.xml
index d769091e5..d329a05a9 100644
--- a/res/values-mcc334-mnc03/config.xml
+++ b/res/values-mcc334-mnc03/config.xml
@@ -17,7 +17,7 @@
 <resources>
     <!-- 50 -->
     <string-array name="operator_defined_alert_range_strings" translatable="false">
-        <item>0x0032:rat=gsm, emergency=true, dialog_with_notification=true</item>
+        <item>0x0032:rat=gsm, type=mute, emergency=true, dialog_with_notification=true</item>
     </string-array>
     <!-- This is read only when show_separate_exercise_settings is on -->
     <bool name="show_operator_defined_settings">true</bool>
diff --git a/res/values-mcc404-be/strings.xml b/res/values-mcc404-be/strings.xml
index fc6828459..8a13c747f 100644
--- a/res/values-mcc404-be/strings.xml
+++ b/res/values-mcc404-be/strings.xml
@@ -14,6 +14,6 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_presidential_level_alert" msgid="1792032344095168538">"Абвестка пра крытычную пагрозу"</string>
-    <string name="cmas_extreme_alert" msgid="3131679659546331921">"Абвестка пра сур\'ёзную пагрозу"</string>
+    <string name="cmas_extreme_alert" msgid="3131679659546331921">"Абвестка пра сур’ёзную пагрозу"</string>
     <string name="cmas_required_monthly_test" msgid="4474361767637803948">"Тэставае паведамленне"</string>
 </resources>
diff --git a/res/values-mcc420/config.xml b/res/values-mcc420/config.xml
index 7639507ae..f0aa8beef 100644
--- a/res/values-mcc420/config.xml
+++ b/res/values-mcc420/config.xml
@@ -66,6 +66,13 @@
     <string-array name="cmas_amber_alerts_channels_range_strings" translatable="false">
     </string-array>
 
+    <!-- 4352~4354, 4356 -->
+    <string-array name="etws_alerts_range_strings" translatable="false"/>
+    <!-- 4355-->
+    <string-array name="etws_test_alerts_range_strings" translatable="false">
+        <item>0x1103:rat=gsm, emergency=true, test_mode=true</item>
+    </string-array>
+
     <!-- Whether to override the language of the alert dialog's title to match the message locale -->
     <bool name="override_alert_title_language_to_match_message_locale">true</bool>
     <!-- Whether enabling copy message text into clipboard by long press -->
diff --git a/res/values-mcc420/strings.xml b/res/values-mcc420/strings.xml
index 26ea9ba67..8980c9377 100644
--- a/res/values-mcc420/strings.xml
+++ b/res/values-mcc420/strings.xml
@@ -13,21 +13,34 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <!-- Dialog title for presidential level alert. [CHAR LIMIT=50] -->
+    <!-- Required arabic (ar) translation for this message: الرسائل التحذيرية الوطنية -->
     <string name="cmas_presidential_level_alert">National Warning Alerts</string>
+
     <!-- CMAS dialog title for extreme alert. [CHAR LIMIT=50] -->
+    <!-- Required arabic (ar) translation for this message: الرسائل التحذيرية الطارئة جداً -->
     <string name="cmas_extreme_alert">Extreme Emergency Warning Alerts</string>
+
     <!-- CMAS dialog title for extreme alert with extreme severity, immediate urgency, and observed certainty. [CHAR LIMIT=50] -->
     <string name="cmas_extreme_immediate_observed_alert">@string/cmas_extreme_alert</string>
     <!-- CMAS dialog title for extreme alert with extreme severity, immediate urgency,  and likely certainty. [CHAR LIMIT=50] -->
     <string name="cmas_extreme_immediate_likely_alert">@string/cmas_extreme_alert</string>
+
     <!-- CMAS dialog title for severe alert. [CHAR LIMIT=50] -->
+    <!-- Required arabic (ar) translation for this message: الرسائل التحذيرية الطارئة -->
     <string name="cmas_severe_alert">Emergency Warning Alerts</string>
+
     <!-- Dialog title for emergency alert for Saudi users. -->
+    <!-- Required arabic (ar) translation for this message: الرسائل التحذيرية -->
     <string name="pws_other_message_identifiers">Alerts</string>
+
     <string name="enable_emergency_alerts_message_title">Alerts</string>
     <string name="enable_emergency_alerts_message_summary">Recommended actions that can save lives or property</string>
+
     <!-- Dialog title for test alert. [CHAR LIMIT=50] -->
+    <!-- Required arabic (ar) translation for this message: الرسائل التجريبية -->
     <string name="cmas_required_monthly_test">Testing Alerts</string>
+
     <!-- Dialog title for exercise level alert. [CHAR LIMIT=50] -->
+    <!-- Required arabic (ar) translation for this message: تمارين -->
     <string name="cmas_exercise_alert">Exercises</string>
 </resources>
\ No newline at end of file
diff --git a/res/values-mcc425-gu/strings.xml b/res/values-mcc425-gu/strings.xml
index d64671924..7887fde91 100644
--- a/res/values-mcc425-gu/strings.xml
+++ b/res/values-mcc425-gu/strings.xml
@@ -17,9 +17,9 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_severe_alert" msgid="4470698515511189493">"ચેતવણી અલર્ટ"</string>
-    <string name="public_safety_message" msgid="7373019453807671797">"માહિતીપ્રદ સંદેશ"</string>
-    <string name="cmas_amber_alert" msgid="740474290634511931">"લોકોથી સહાયતાની વિનંતી કરતો સંદેશ"</string>
+    <string name="public_safety_message" msgid="7373019453807671797">"માહિતીપ્રદ મેસેજ"</string>
+    <string name="cmas_amber_alert" msgid="740474290634511931">"લોકોને સહાયતાની વિનંતી કરતો મેસેજ"</string>
     <string name="enable_cmas_severe_threat_alerts_title" msgid="4570611095431464471">"ચેતવણીના અલર્ટ"</string>
-    <string name="enable_public_safety_messages_title" msgid="6173886162636474286">"માહિતીપ્રદ સંદેશા"</string>
-    <string name="enable_cmas_amber_alerts_title" msgid="3896845887375326185">"લોકોથી સહાયતાની વિનંતી કરતા સંદેશા"</string>
+    <string name="enable_public_safety_messages_title" msgid="6173886162636474286">"માહિતીપ્રદ મેસેજ"</string>
+    <string name="enable_cmas_amber_alerts_title" msgid="3896845887375326185">"લોકોથી સહાયતાની વિનંતી કરતા મેસેજ"</string>
 </resources>
diff --git a/res/values-mcc440-mnc50/config.xml b/res/values-mcc440-mnc50/config.xml
index 922092d3c..ba237e220 100644
--- a/res/values-mcc440-mnc50/config.xml
+++ b/res/values-mcc440-mnc50/config.xml
@@ -20,7 +20,7 @@
         <item>0x1100:rat=gsm, type=etws_earthquake, emergency=true</item>
         <!-- 0x1101 for tsunami -->
         <item>0x1101:rat=gsm, type=etws_tsunami, emergency=true</item>
-        <!-- 0xA808 for other purposes -->
-        <item>0xA808:rat=gsm, type=other, emergency=true, scope=carrier</item>
+        <!-- 0x1104 for other purposes -->
+        <item>0x1104:rat=gsm, type=other, emergency=true, scope=carrier</item>
     </string-array>
 </resources>
diff --git a/res/values-mcc440-mnc54 b/res/values-mcc440-mnc54
new file mode 120000
index 000000000..afae1afc3
--- /dev/null
+++ b/res/values-mcc440-mnc54
@@ -0,0 +1 @@
+values-mcc440-mnc50/
\ No newline at end of file
diff --git a/res/values-mcc440-mnc54/config.xml b/res/values-mcc440-mnc54/config.xml
deleted file mode 100644
index cc9d7e924..000000000
--- a/res/values-mcc440-mnc54/config.xml
+++ /dev/null
@@ -1,26 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2021 The Android Open Source Project
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
-    <string-array name="etws_alerts_range_strings" translatable="false">
-        <!-- 0x1100 for earthquake -->
-        <item>0x1100:rat=gsm, type=etws_earthquake, emergency=true</item>
-        <!-- 0x1101 for tsunami -->
-        <item>0x1101:rat=gsm, type=etws_tsunami, emergency=true</item>
-        <!-- 0x1104 for other purposes -->
-        <item>0x1104:rat=gsm, type=other, emergency=true, scope=carrier</item>
-    </string-array>
-</resources>
diff --git a/res/values-mcc450-af/strings.xml b/res/values-mcc450-af/strings.xml
index e10e4f089..55b8ee81c 100644
--- a/res/values-mcc450-af/strings.xml
+++ b/res/values-mcc450-af/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Noodwaarskuwing"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Publiekeveiligheidwaarskuwing"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER-veiligheidsberig"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Jou foon kan vir jou waarskuwings, soos ontruiminginstruksies, gedurende rampe stuur. Hierdie diens is ’n samewerking tussen die Koreaanse regering, netwerkverskaffers en toestelvervaardigers.\n\nJy sal dalk nie waarskuwings ontvang as daar ’n probleem met jou toestel is of as netwerktoestande swak is nie."</string>
 </resources>
diff --git a/res/values-mcc450-am/strings.xml b/res/values-mcc450-am/strings.xml
index da5fbddb1..0df7ddf16 100644
--- a/res/values-mcc450-am/strings.xml
+++ b/res/values-mcc450-am/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"የአደጋ ጊዜ ማንቂያ"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"የሕዝባዊ ደህንነት ማንቂያ"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"የልጅ ስርቆት ማንቂያ"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"በአደጋዎች ወቅት እንደ መውጫ መመሪያዎች ያሉ ማንቂያዎች ስልክዎ ሊልክልዎ ይችላል። ይህ አገልግሎት በኮሪያ መንግስት፣ በአውታረ መረብ አቅራቢዎች እና በመሣሪያ አምራቾች መካከል የሚደረግ ትብብር ነው።\n\nበመሣሪያዎ ላይ ችግር ካለ ወይም የአውታረ መረብ ሁኔታዎች ደካማ ከሆኑ ማንቂያዎችን ላያገኙ ይችላሉ።"</string>
 </resources>
diff --git a/res/values-mcc450-ar/strings.xml b/res/values-mcc450-ar/strings.xml
index a66d0252f..625434325 100644
--- a/res/values-mcc450-ar/strings.xml
+++ b/res/values-mcc450-ar/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"تنبيه طوارئ"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"تنبيه بشأن السلامة العامة"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"إنذار آمبر"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"يمكن لهاتفك أن يرسل لك تنبيهات أثناء الكوارث، مثلاً تعليمات الإخلاء. نقدم لك هذه الخدمة بالتعاون مع الحكومة الكورية وموفري الشبكات والشركات المصنّعة للأجهزة.\n\nقد لا تتلقّى تنبيهات إذا حدثت مشكلة في جهازك أو إذا كانت حالة الشبكة سيئة."</string>
 </resources>
diff --git a/res/values-mcc450-as/strings.xml b/res/values-mcc450-as/strings.xml
index 52efbeed3..377dd2898 100644
--- a/res/values-mcc450-as/strings.xml
+++ b/res/values-mcc450-as/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"জৰুৰীকালীন সতৰ্কবাৰ্তা"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"ৰাজহুৱা সুৰক্ষা বিষয়ক সতৰ্কবাৰ্তা"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"এম্বাৰ সতৰ্কবাৰ্তা"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"আপোনাৰ ফ’নটোৱে আপোনালৈ দুৰ্যোগৰ সময়ত অপসাৰণৰ নিৰ্দেশাৱলীৰ দৰে সতৰ্কবাণীসমূহ পঠিয়াব পাৰে। কোৰিয়ান চৰকাৰ, নেটৱৰ্ক প্ৰদানকাৰী আৰু ডিভাইচ নিৰ্মাতাসকলৰ সহযোগত এই সেৱা আগবঢ়োৱা হৈছে।\n\nআপোনাৰ ডিভাইচত কিবা সমস্যা থাকিলে অথবা নেটৱৰ্কৰ স্থিতি দুৰ্বল হ’লে আপুনি সতৰ্কবাণী লাভ নকৰিবও পাৰে।"</string>
 </resources>
diff --git a/res/values-mcc450-az/strings.xml b/res/values-mcc450-az/strings.xml
index f40dfe67c..bb19354a4 100644
--- a/res/values-mcc450-az/strings.xml
+++ b/res/values-mcc450-az/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Fövqəladə hal siqnalı"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"İctimai güvənlik siqnalı"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Kəhrəba siqnalı"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefon fəlakətlər zamanı evakuasiya təlimatları kimi xəbərdarlıqlar göndərə bilər. Bu xidmət Koreya hökuməti, şəbəkə provayderləri və cihaz istehsalçıları arasında əməkdaşlıqdır.\n\nCihazda problem olarsa və ya şəbəkə zəif olarsa, xəbərdarlıq almaya bilərsiniz."</string>
 </resources>
diff --git a/res/values-mcc450-b+sr+Latn/strings.xml b/res/values-mcc450-b+sr+Latn/strings.xml
index a9bcd6825..39037841b 100644
--- a/res/values-mcc450-b+sr+Latn/strings.xml
+++ b/res/values-mcc450-b+sr+Latn/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Upozorenje o hitnom slučaju"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Obaveštenje o javnoj bezbednosti"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Amber upozorenje"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefon može da vam šalje upozorenja tokom katastrofa, npr. uputstva za evakuaciju. Ova usluga predstavlja saradnju između Vlade Koreje, provajdera i proizvođača uređaja.\n\nMožda nećete dobijati upozorenja ako postoji problem sa uređajem ili ako signal mreže nije dovoljno jak."</string>
 </resources>
diff --git a/res/values-mcc450-be/strings.xml b/res/values-mcc450-be/strings.xml
index aa9d4c16f..32e2ee7bf 100644
--- a/res/values-mcc450-be/strings.xml
+++ b/res/values-mcc450-be/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Экстранная абвестка"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Абвестка пра пагрозу грамадскай бяспецы"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Абвестка AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Ваш тэлефон падчас катастроф можа паказваць вам абвесткі, напрыклад інструкцыі па эвакуацыі. Гэты сэрвіс працуе пры падтрымцы ўрада Паўднёвай Карэі, аператараў сетак і вытворцаў прылад.\n\nВы можаце не атрымаць абвестак у тых выпадках, калі ўзнікне праблема з вашай прыладай ці з падключэннем да сеткі."</string>
 </resources>
diff --git a/res/values-mcc450-bg/strings.xml b/res/values-mcc450-bg/strings.xml
index 617587592..5a5e3942a 100644
--- a/res/values-mcc450-bg/strings.xml
+++ b/res/values-mcc450-bg/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Сигнал при спешен случай"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Сигнал за обществена безопасност"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Сигнал за изчезнало дете"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Телефонът ви може да ви изпраща сигнали, като например инструкции за евакуация, по време на бедствия. Тази услуга се предоставя съвместно от корейското правителство, мобилни оператори и производители на устройства.\n\nВъзможно е да не получавате сигнали, ако има проблем с устройството ви или мрежовите условия са лоши."</string>
 </resources>
diff --git a/res/values-mcc450-bn/strings.xml b/res/values-mcc450-bn/strings.xml
index 60b59ee41..1c05dcf12 100644
--- a/res/values-mcc450-bn/strings.xml
+++ b/res/values-mcc450-bn/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"জরুরি সতর্কতা"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"সর্বজনীন নিরাপত্তা সতর্কতা"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER সতর্কতা"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"আপনার ফোন সতর্কতা পাঠাতে পারে, যেমন দুর্যোগের সময় নিরাপদ স্থানে যাওয়ার ব্যাপারে নির্দেশ। কোরিয়ান সরকার, নেটওয়ার্ক পরিষেবা প্রদানকারী ও ডিভাইস প্রস্তুতকারকদের সহযোগিতায় এই পরিষেবার ব্যবস্থা করা হয়েছে।\n\nআপনার ডিভাইসে কোনও সমস্যা থাকলে বা নেটওয়ার্ক দুর্বল হলে, আপনি সতর্কতা নাও পেতে পারেন।"</string>
 </resources>
diff --git a/res/values-mcc450-bs/strings.xml b/res/values-mcc450-bs/strings.xml
index 3a3f48088..4f8e42227 100644
--- a/res/values-mcc450-bs/strings.xml
+++ b/res/values-mcc450-bs/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Upozorenje na hitan slučaj"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Upozorenje o javnoj sigurnosti"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER upozorenje"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefon vam može slati upozorenja, kao što su uputstva za evakuaciju, tokom katastrofa. Ova usluga predstavlja saradnju između vlade Koreje, mrežnih operatera i proizvođača uređaja.\n\nMožda nećete primati obavještenja ako postoji problem s uređajem ili ako je stanje mreže loše."</string>
 </resources>
diff --git a/res/values-mcc450-ca/strings.xml b/res/values-mcc450-ca/strings.xml
index b663bf8ac..f0d1383ed 100644
--- a/res/values-mcc450-ca/strings.xml
+++ b/res/values-mcc450-ca/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Alerta d\'emergència"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Alerta de seguretat pública"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Alerta AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"El telèfon et pot enviar alertes, com ara instruccions d\'evacuació, durant els desastres. Aquest servei és una col·laboració entre el govern de Corea, els proveïdors de xarxa i els fabricants de dispositius.\n\nÉs possible que no rebis alertes si hi ha un problema al teu dispositiu o si l\'estat de la xarxa és deficient."</string>
 </resources>
diff --git a/res/values-mcc450-cs/strings.xml b/res/values-mcc450-cs/strings.xml
index 9ccf3b873..92f4052eb 100644
--- a/res/values-mcc450-cs/strings.xml
+++ b/res/values-mcc450-cs/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Výstražná zpráva"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Upozornění ohledně veřejné bezpečnosti"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Varování AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefon vám bude při katastrofách odesílat upozornění, např. pokyny k evakuaci. Tato služba je výsledkem spolupráce mezi korejskou vládou, poskytovateli sítí a výrobci zařízení.\n\nPokud dojde k problému se zařízením nebo bude špatné připojení, upozornění nemusíte dostat."</string>
 </resources>
diff --git a/res/values-mcc450-da/strings.xml b/res/values-mcc450-da/strings.xml
index e6a7bb562..152a87ef8 100644
--- a/res/values-mcc450-da/strings.xml
+++ b/res/values-mcc450-da/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Varsling"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Offentlig sikkerhedsvarsling"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Underretning om barnebortførelse"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Din telefon kan sende dig varsler, f.eks. om, hvordan du skal søge i ly, ved katastrofer. Denne tjeneste er et samarbejde mellem de sydkoreanske myndigheder, netværksudbydere og enhedsproducenter.\n\nDu modtager muligvis ikke varsler, hvis der er et problem med din enhed, eller hvis dine netværksforhold er dårlige."</string>
 </resources>
diff --git a/res/values-mcc450-de/strings.xml b/res/values-mcc450-de/strings.xml
index 40b2b6135..cf44f1300 100644
--- a/res/values-mcc450-de/strings.xml
+++ b/res/values-mcc450-de/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Notfallbenachrichtigung"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Warnung zur öffentlichen Sicherheit"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER Alert"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Dein Smartphone kann dir bei Katastrophen Warnungen anzeigen, z. B. Evakuierungsanweisungen. Dieser Dienst ist ein gemeinsames Angebot der südkoreanischen Regierung mit Netzanbietern und Geräteherstellern.\n\nBei einem Problem mit deinem Gerät oder schlechtem Empfang kannst du eventuell keine Warnungen empfangen."</string>
 </resources>
diff --git a/res/values-mcc450-el/strings.xml b/res/values-mcc450-el/strings.xml
index 414987b6f..d02456c47 100644
--- a/res/values-mcc450-el/strings.xml
+++ b/res/values-mcc450-el/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Ειδοποίηση έκτακτης ανάγκης"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Ειδοποίηση δημόσιας ασφάλειας"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Ειδοποίηση Amber"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Το τηλέφωνό σας μπορεί να σας στείλει ειδοποιήσεις, όπως οδηγίες εκκένωσης κατά τη διάρκεια καταστροφών. Αυτή η υπηρεσία είναι μια συνεργασία μεταξύ της κυβέρνησης της Κορέας, παρόχων υπηρεσιών δικτύου και κατασκευαστών συσκευών.\n\nΕνδέχεται να μην λάβετε ειδοποιήσεις εάν υπάρχει πρόβλημα με τη συσκευή σας ή αν δεν είναι καλές οι συνθήκες του δικτύου."</string>
 </resources>
diff --git a/res/values-mcc450-en-rAU/strings.xml b/res/values-mcc450-en-rAU/strings.xml
index 84f9ab120..3a13090e3 100644
--- a/res/values-mcc450-en-rAU/strings.xml
+++ b/res/values-mcc450-en-rAU/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Emergency alert"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Public safety alert"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Amber alert"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Your phone can send you alerts during disasters, such as evacuation instructions. This service is a collaboration between the Korean government, network providers and device manufacturers.\n\nYou may not receive alerts if there\'s a problem with your device or if network conditions are poor."</string>
 </resources>
diff --git a/res/values-mcc450-en-rCA/strings.xml b/res/values-mcc450-en-rCA/strings.xml
index 74fef097b..9cb080b75 100644
--- a/res/values-mcc450-en-rCA/strings.xml
+++ b/res/values-mcc450-en-rCA/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Emergency Alert"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Public Safety Alert"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Amber Alert"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Your phone can send you alerts, like evacuation instructions, during disasters. This service is a collaboration between the Korean government, network providers, and device manufacturers.\n\nYou may not get alerts if there’s a problem with your device or if network conditions are poor."</string>
 </resources>
diff --git a/res/values-mcc450-en-rGB/strings.xml b/res/values-mcc450-en-rGB/strings.xml
index 84f9ab120..3a13090e3 100644
--- a/res/values-mcc450-en-rGB/strings.xml
+++ b/res/values-mcc450-en-rGB/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Emergency alert"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Public safety alert"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Amber alert"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Your phone can send you alerts during disasters, such as evacuation instructions. This service is a collaboration between the Korean government, network providers and device manufacturers.\n\nYou may not receive alerts if there\'s a problem with your device or if network conditions are poor."</string>
 </resources>
diff --git a/res/values-mcc450-en-rIN/strings.xml b/res/values-mcc450-en-rIN/strings.xml
index 84f9ab120..3a13090e3 100644
--- a/res/values-mcc450-en-rIN/strings.xml
+++ b/res/values-mcc450-en-rIN/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Emergency alert"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Public safety alert"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Amber alert"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Your phone can send you alerts during disasters, such as evacuation instructions. This service is a collaboration between the Korean government, network providers and device manufacturers.\n\nYou may not receive alerts if there\'s a problem with your device or if network conditions are poor."</string>
 </resources>
diff --git a/res/values-mcc450-en-rXC/strings.xml b/res/values-mcc450-en-rXC/strings.xml
index fdc0a313f..9640892f1 100644
--- a/res/values-mcc450-en-rXC/strings.xml
+++ b/res/values-mcc450-en-rXC/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‎‎‎‏‏‏‏‏‏‏‎‏‎‎‎‎‏‎‎‏‏‏‎‏‏‏‎‎‏‏‏‎‎‏‎‏‏‎‏‏‎‏‎‎‏‎‎‎‎‎‎‎‎‏‏‏‎‏‎‏‏‎Emergency Alert‎‏‎‎‏‎"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‎‎‏‏‎‎‎‏‏‏‏‏‎‎‎‎‏‏‎‎‏‎‎‏‎‎‏‏‎‎‎‏‏‎‎‏‎‏‎‎‎‏‏‎‏‏‎‎‏‏‏‏‎‏‎‏‎‏‎‏‎Public Safety Alert‎‏‎‎‏‎"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‎‏‎‏‎‏‎‎‎‏‏‏‏‏‏‎‎‎‏‎‏‏‏‏‎‏‏‏‎‏‏‏‎‏‏‎‏‎‏‏‎‎‎‏‏‎‏‎‏‏‏‎‎‏‏‏‎‎‎‏‎‎‎Amber Alert‎‏‎‎‏‎"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‏‏‏‎‎‏‎‏‏‎‏‎‏‎‏‏‎‎‎‏‎‏‎‏‏‎‎‎‎‏‏‎‏‏‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‎‏‎‏‎‎‏‎‎‎‎‏‏‎Your phone can send you alerts, like evacuation instructions, during disasters. This service is a collaboration between the Korean government, network providers, and device manufacturers.‎‏‎‎‏‏‎\n‎‏‎‎‏‏‏‎‎‏‎‎‏‏‎\n‎‏‎‎‏‏‏‎You may not get alerts if there’s a problem with your device or if network conditions are poor.‎‏‎‎‏‎"</string>
 </resources>
diff --git a/res/values-mcc450-es-rUS/strings.xml b/res/values-mcc450-es-rUS/strings.xml
index a22251550..4b431195a 100644
--- a/res/values-mcc450-es-rUS/strings.xml
+++ b/res/values-mcc450-es-rUS/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Alerta de emergencia"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Alerta de seguridad pública"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Alerta AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"El teléfono puede enviarte alertas, como instrucciones de evacuación, durante catástrofes. Este servicio es una colaboración entre el Gobierno coreano, los proveedores de red y los fabricantes de dispositivos.\n\nEs posible que no recibas alertas si hay un problema con el dispositivo o si la conexión de red no es buena."</string>
 </resources>
diff --git a/res/values-mcc450-es/strings.xml b/res/values-mcc450-es/strings.xml
index ac99305e7..be21303b4 100644
--- a/res/values-mcc450-es/strings.xml
+++ b/res/values-mcc450-es/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Alerta de emergencia"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Alerta de seguridad pública"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Alerta AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Tu teléfono puede enviarte alertas, como instrucciones de evacuación, durante catástrofes naturales. Este servicio es una colaboración entre el Gobierno de Corea, proveedores de red y fabricantes de dispositivos.\n\nEs posible que no recibas alertas si hay un problema con tu dispositivo o si las condiciones de la red son deficientes."</string>
 </resources>
diff --git a/res/values-mcc450-et/strings.xml b/res/values-mcc450-et/strings.xml
index c9dfd22c1..ffba8692c 100644
--- a/res/values-mcc450-et/strings.xml
+++ b/res/values-mcc450-et/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Hädaolukorra hoiatus"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Avalik ohutusmärguanne"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER-märguanne"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefon võib looduskatastroofi korral teid hoiatada, näiteks evakueerumisjuhiseid anda. Seda teenust pakutakse Korea valitsuse, võrguteenuse pakkujate ja seadmetootjate koostöös.\n\nKui teie seadmega on probleeme või võrgutingimused on kehvad, siis ei pruugi te hoiatusi saada."</string>
 </resources>
diff --git a/res/values-mcc450-eu/strings.xml b/res/values-mcc450-eu/strings.xml
index 6e617b5a1..bdc89643c 100644
--- a/res/values-mcc450-eu/strings.xml
+++ b/res/values-mcc450-eu/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Larrialdi-alerta"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Segurtasun publikoari buruzko alerta"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Alerta anbara"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefonoak alertak bidal diezazkizuke (adibidez, ebakuatzeko argibideak) hondamendietan. Koreako gobernuaren, sare-hornitzaileen eta gailu-fabrikatzaileen arteko elkarlana da zerbitzua.\n\nAgian ez duzu jasoko alertarik gailuak arazoren bat badu edo sarearen egoera txarra bada."</string>
 </resources>
diff --git a/res/values-mcc450-fa/strings.xml b/res/values-mcc450-fa/strings.xml
index 161b407b4..7a80e2789 100644
--- a/res/values-mcc450-fa/strings.xml
+++ b/res/values-mcc450-fa/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"هشدار وضعیت اضطراری"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"هشدار ایمنی عمومی"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"هشدار امبر"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"تلفنتان می‌تواند هنگام بروز بلایای طبیعی هشدارهایی مثل دستورالعمل‌های تخلیه برایتان ارسال کند. این سرویس حاصل همکاری میان دولت کره، ارائه‌دهندگان شبکه، و سازندگان دستگاه است.\n\nاگر دستگاهتان مشکلی داشته باشد یا آنتن‌دهی شبکه ضعیف باشد، ممکن است هشدارها را دریافت نکنید."</string>
 </resources>
diff --git a/res/values-mcc450-fi/strings.xml b/res/values-mcc450-fi/strings.xml
index 54221545e..d502e0b2b 100644
--- a/res/values-mcc450-fi/strings.xml
+++ b/res/values-mcc450-fi/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Hätävaroitus"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Yleistä turvallisuutta koskeva varoitus"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER-hälytys"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Puhelimesi voi lähettää sinulle katastrofien aikana ilmoituksia, esim. evakuointiohjeita. Palvelun tarjoavat yhteistyössä Korean valtio, verkko-operaattorit ja laitevalmistajat.\n\nEt välttämättä saa ilmoituksia, jos laitteessa on ongelma tai verkkoyhteys on heikko."</string>
 </resources>
diff --git a/res/values-mcc450-fr-rCA/strings.xml b/res/values-mcc450-fr-rCA/strings.xml
index dc9281863..112557c36 100644
--- a/res/values-mcc450-fr-rCA/strings.xml
+++ b/res/values-mcc450-fr-rCA/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Alerte d\'urgence"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Alerte relative à la sécurité publique"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Alerte AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Votre téléphone peut vous envoyer des alertes, comme des instructions d\'évacuation, lors de catastrophes. Ce service est le résultat d\'une collaboration entre le gouvernement coréen, les fournisseurs de réseau et les fabricants d\'appareils.\n\nVous pourriez ne pas recevoir d\'alertes en cas de problème avec votre appareil ou si les conditions du réseau ne sont pas optimales."</string>
 </resources>
diff --git a/res/values-mcc450-fr/strings.xml b/res/values-mcc450-fr/strings.xml
index 8eae0758a..a1ecc05c9 100644
--- a/res/values-mcc450-fr/strings.xml
+++ b/res/values-mcc450-fr/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Alerte d\'urgence"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Alerte de sécurité publique"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Alerte enlèvement"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"En cas de catastrophe, votre téléphone peut vous envoyer des alertes, comme des instructions d\'évacuation. Ce service est proposé par le biais d\'une collaboration entre le gouvernement coréen, les fournisseurs de réseau et les fabricants de l\'appareil.\n\nIl se peut que vous ne receviez pas les alertes si votre appareil est défectueux ou si les conditions de réseau sont mauvaises."</string>
 </resources>
diff --git a/res/values-mcc450-gl/strings.xml b/res/values-mcc450-gl/strings.xml
index 24756e5f4..f62d93b35 100644
--- a/res/values-mcc450-gl/strings.xml
+++ b/res/values-mcc450-gl/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Alerta de emerxencia"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Alerta de seguranza pública"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Alerta AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"O teléfono pode enviarche alertas, como instrucións de evacuación, en caso de que se produza un desastre. Este servizo é unha colaboración entre o Goberno de Corea do Sur, os provedores de rede e os fabricantes de dispositivos.\n\nÉ posible que non recibas ningunha alerta se o teu dispositivo ten algún problema ou se a conexión á rede é deficiente."</string>
 </resources>
diff --git a/res/values-mcc450-gu/strings.xml b/res/values-mcc450-gu/strings.xml
index 9e147cf23..eb5b2a583 100644
--- a/res/values-mcc450-gu/strings.xml
+++ b/res/values-mcc450-gu/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"ઇમર્જન્સી અલર્ટ"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"સાર્વજનિક સલામતી માટે અલર્ટ"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER અલર્ટ"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"તમારો ફોન તમને આફતો દરમિયાન સ્થળાંતરની સૂચનાઓ જેવા અલર્ટ મોકલી શકે છે. આ સેવા કોરિયન સરકાર, નેટવર્ક પ્રદાતાઓ અને ડિવાઇસના નિર્માતાઓ વચ્ચેનો સહયોગ છે.\n\nતમારા ડિવાઇસમાં કોઈ સમસ્યા હોય અથવા નેટવર્ક ખરાબ હોય તો તમને કદાચ અલર્ટ ન પણ મળે."</string>
 </resources>
diff --git a/res/values-mcc450-hi/strings.xml b/res/values-mcc450-hi/strings.xml
index e73ffcd70..f2151c47c 100644
--- a/res/values-mcc450-hi/strings.xml
+++ b/res/values-mcc450-hi/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"खतरे की चेतावनी"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"लोगों की सुरक्षा से जुड़ी चेतावनी"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"ऐंबर अलर्ट (अगवा बच्चों से जुड़ी जानकारी)"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"आपको फ़ोन पर चेतावनियां मिल सकती हैं. जैसे, आपदाओं के दौरान, खतरे वाली जगहों से सुरक्षित बाहर निकलने के निर्देश. कोरिया की सरकार, नेटवर्क सेवा देने वाली कंपनियों, और डिवाइस बनाने वाली कंपनियों के साथ मिलकर काम करने की वजह से, यह सेवा शुरू की गई है.\n\nअगर आपके डिवाइस में कोई समस्या है या नेटवर्क ठीक से नहीं आ रहा है, तो शायद आपको चेतावनियां न मिलें."</string>
 </resources>
diff --git a/res/values-mcc450-hr/strings.xml b/res/values-mcc450-hr/strings.xml
index 6bf9e0ca3..11e8ef0ab 100644
--- a/res/values-mcc450-hr/strings.xml
+++ b/res/values-mcc450-hr/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Hitno upozorenje"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Upozorenje o javnoj sigurnosti"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER upozorenje"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefon vam može slati upozorenja tijekom katastrofa, kao što su upute za evakuaciju. Ta je usluga rezultat suradnje korejske vlade, mrežnih operatera i proizvođača uređaja.\n\nAko postoji problem s vašim uređajem ili su mrežni uvjeti loši, možda nećete primiti obavijesti."</string>
 </resources>
diff --git a/res/values-mcc450-hu/strings.xml b/res/values-mcc450-hu/strings.xml
index 7843efff8..32efa2e5f 100644
--- a/res/values-mcc450-hu/strings.xml
+++ b/res/values-mcc450-hu/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Vészjelzés"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Közbiztonsággal kapcsolatos riasztás"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER riasztás"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Az esetleges katasztrófák során telefonja fontos értesítéseket, például evakuációs utasításokat küldhet Önnek. Ez a szolgáltatás a koreai kormány, a mobilhálózati szolgáltatók és az eszközgyártók összefogásával működik.\n\nAz eszközzel kapcsolatos problémák és a gyenge hálózati viszonyok megakadályozhatják az értesítések fogadását."</string>
 </resources>
diff --git a/res/values-mcc450-hy/strings.xml b/res/values-mcc450-hy/strings.xml
index ae6769aed..6725b44d3 100644
--- a/res/values-mcc450-hy/strings.xml
+++ b/res/values-mcc450-hy/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Արտակարգ իրավիճակի մասին ծանուցում"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Հանրային անվտանգության սպառնալիքի մասին զգուշացում"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER ծանուցում"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Աղետների ժամանակ հեռախոսը կարող է ձեզ ուղարկել ծանուցումներ, օրինակ՝ տարհանման հրահանգներով։ Այս ծառայությունը տրամադրվում է Կորեայի կառավարության, ցանցային օպերատորների և սարքերի արտադրողների համագործակցությամբ։\n\nԴուք կարող եք չստանալ ծանուցումներ, եթե ձեր հեռախոսի հետ խնդիր կա, կամ եթե կապի որակը թույլ է։"</string>
 </resources>
diff --git a/res/values-mcc450-in/strings.xml b/res/values-mcc450-in/strings.xml
index 3fd206f0e..6a5020167 100644
--- a/res/values-mcc450-in/strings.xml
+++ b/res/values-mcc450-in/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Peringatan Darurat"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Peringatan Keselamatan Publik"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER Alert"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Ponsel dapat menerima peringatan, seperti petunjuk evakuasi, selama bencana. Layanan ini adalah kolaborasi antara pemerintah Korea, penyedia jaringan, dan produsen perangkat.\n\nAnda mungkin tidak akan menerima peringatan jika perangkat bermasalah atau kondisi jaringan buruk."</string>
 </resources>
diff --git a/res/values-mcc450-is/strings.xml b/res/values-mcc450-is/strings.xml
index 71d30dc99..317bdc043 100644
--- a/res/values-mcc450-is/strings.xml
+++ b/res/values-mcc450-is/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Neyðartilkynning"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Almannavarnatilkynning"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Tilkynning um týnt barn"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Síminn þinn getur sent þér viðvaranir á borð við leiðbeiningar þegar rýma þarf stað vegna hamfara. Þjónustan er samstarfsverkefni kóreskra stjórnvalda, símafyrirtækja og tækjaframleiðenda.\n\nEkki er víst að þú fáir viðvaranir ef það er vandamál með tækið eða ef tengingar eru slæmar."</string>
 </resources>
diff --git a/res/values-mcc450-it/strings.xml b/res/values-mcc450-it/strings.xml
index 00168ea3b..930078494 100644
--- a/res/values-mcc450-it/strings.xml
+++ b/res/values-mcc450-it/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Avviso di emergenza"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Allerta sicurezza pubblica"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Allerta AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Lo smartphone può inviarti avvisi, ad esempio indicazioni per l\'evacuazione, durante i disastri. Questo servizio è nato dalla collaborazione tra il governo coreano, network provider e produttori di dispositivi.\n\nPotresti non ricevere avvisi in caso di problemi con il tuo dispositivo o condizioni non ottimali della rete."</string>
 </resources>
diff --git a/res/values-mcc450-iw/strings.xml b/res/values-mcc450-iw/strings.xml
index 9f18fed97..d68953902 100644
--- a/res/values-mcc450-iw/strings.xml
+++ b/res/values-mcc450-iw/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"התראה על מקרה חירום"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"התראה בנוגע לביטחון הציבור"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"‏התרעת AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"במהלך אסונות, הטלפון יכול לשלוח התראות כמו הוראות לפינוי. השירות נוצר מתוך שיתוף פעולה בין ממשלת קוריאה, ספקי תקשורת ויצרני מכשירים.\n\nיכול להיות שלא יתקבלו התראות אם יש בעיה במכשיר או אם איכות הרשת נמוכה."</string>
 </resources>
diff --git a/res/values-mcc450-ja/strings.xml b/res/values-mcc450-ja/strings.xml
index 2300c7742..b5f4ae485 100644
--- a/res/values-mcc450-ja/strings.xml
+++ b/res/values-mcc450-ja/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"緊急速報メール"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"災害情報アラート"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"アンバー アラート"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"災害が発生した際に、スマートフォンで避難手順などの通知を受け取ることができます。これは、韓国政府、ネットワーク プロバイダ、デバイス メーカー間の連携サービスです。\n\nデバイスに問題がある場合やネットワーク状況が不安定の場合は通知が届かないことがあります。"</string>
 </resources>
diff --git a/res/values-mcc450-ka/strings.xml b/res/values-mcc450-ka/strings.xml
index 044b4c5fa..43ec73590 100644
--- a/res/values-mcc450-ka/strings.xml
+++ b/res/values-mcc450-ka/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"საგანგებო ვითარების გაფრთხილება"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"საჯარო უსაფრთხოების გაფრთხილება"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Amber-ის გაფრთხილება"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"თქვენს ტელეფონს შეუძლია გამოგიგზავნოთ გაფრთხილებები, მაგალითად, ევაკუაციის ინსტრუქცია ბუნებრივი კატასტროფების დროს. ეს სერვისი შემუშავებულია კორეის მთავრობის, ქსელის პროვაიდერებისა და მოწყობილობის მწარმოებლების თანამშრომლობით.\n\nგაფრთხილებები შეიძლება ვერ მიიღოთ, თუ მოწყობილობას პრობლემა აქვს ან ქსელი ცუდად მუშაობს."</string>
 </resources>
diff --git a/res/values-mcc450-kk/strings.xml b/res/values-mcc450-kk/strings.xml
index 570584778..fe989bc9f 100644
--- a/res/values-mcc450-kk/strings.xml
+++ b/res/values-mcc450-kk/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Шұғыл хабарландыру"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Қоғамдық қауіпсіздік хабарландыруы"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER дабылы"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Табиғи апаттар кезінде телефоныңызға хабарландырулар (мысалы, эвакуация туралы нұсқаулар) келеді. Бұл қызмет – Корея үкіметі, желі провайдерлері және құрылғы өндірушілері бірлесіп жасаған жоба.\n\nҚұрылғыңызға қатысты мәселе туындаса немесе желі байланысы нашар болса, мұндай хабарландырулар алмауыңыз мүмкін."</string>
 </resources>
diff --git a/res/values-mcc450-km/strings.xml b/res/values-mcc450-km/strings.xml
index 52bce50ec..2dfd5a699 100644
--- a/res/values-mcc450-km/strings.xml
+++ b/res/values-mcc450-km/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"ការប្រកាសអាសន្ន"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"ការជូនដំណឹង​អំពីសុវត្ថិភាព​សាធារណៈ"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"ការជូនដំណឹងអំពីការចាប់ជំរិតក្មេង"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"ទូរសព្ទរបស់អ្នក​អាចផ្ញើការជូនដំណឹងទៅអ្នកដូចជា ការណែនាំអំពីការជម្លៀស អំឡុងពេល​មានគ្រោះមហន្តរាយជាដើម។ សេវាកម្មនេះគឺជាការសហការរវាងរដ្ឋាភិបាលកូរ៉េ ក្រុមហ៊ុនផ្ដល់សេវាបណ្ដាញ និងក្រុមហ៊ុនផលិតឧបករណ៍។\n\nអ្នកអាចនឹងមិនទទួលបានការជូនដំណឹងទេ ប្រសិនបើមានបញ្ហាជាមួយឧបករណ៍របស់អ្នក ឬប្រសិនបើស្ថានភាពបណ្ដាញខ្សោយ។"</string>
 </resources>
diff --git a/res/values-mcc450-kn/strings.xml b/res/values-mcc450-kn/strings.xml
index 06abd71e3..541dacca2 100644
--- a/res/values-mcc450-kn/strings.xml
+++ b/res/values-mcc450-kn/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"ತುರ್ತು ಅಲರ್ಟ್"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"ಸಾರ್ವಜನಿಕ ಸುರಕ್ಷತೆಯ ಎಚ್ಚರಿಕೆ"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER ಎಚ್ಚರಿಕೆ"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"ನಿಮ್ಮ ಫೋನ್, ವಿಪತ್ತುಗಳ ಸಂದರ್ಭದಲ್ಲಿ ಸ್ಥಳಾಂತರದ ಸೂಚನೆಗಳಂತಹ ಎಚ್ಚರಿಕೆಗಳನ್ನು ನಿಮಗೆ ಕಳುಹಿಸಬಹುದು. ಈ ಸೇವೆಯು ಕೊರಿಯನ್ ಸರ್ಕಾರ, ನೆಟ್‌ವರ್ಕ್ ಒದಗಿಸುವವರು ಮತ್ತು ಸಾಧನದ ಉತ್ಪಾದಕರ ನಡುವಿನ ಸಹಯೋಗವಾಗಿದೆ.\n\nನಿಮ್ಮ ಸಾಧನದಲ್ಲಿ ಸಮಸ್ಯೆ ಇದ್ದರೆ ಅಥವಾ ನೆಟ್‌ವರ್ಕ್ ಸ್ಥಿತಿಗಳು ದುರ್ಬಲವಾಗಿದ್ದರೆ ನೀವು ಎಚ್ಚರಿಕೆಗಳನ್ನು ಪಡೆಯದೇ ಇರಬಹುದು."</string>
 </resources>
diff --git a/res/values-mcc450-ko/strings.xml b/res/values-mcc450-ko/strings.xml
index d29d1f1d6..bb987e56f 100644
--- a/res/values-mcc450-ko/strings.xml
+++ b/res/values-mcc450-ko/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"긴급 재난문자"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"안전 안내문자"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"실종 경보문자"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"재난 발생 시 휴대전화에서 대피 안내와 같은 경고 알림을 받아볼 수 있습니다. 이 서비스는 정부, 네트워크 공급자, 기기 제조업체와의 공조로 제공됩니다.\n\n기기에 문제가 있거나 네트워크 상태가 좋지 않을 경우 알림을 받지 못할 수 있습니다."</string>
 </resources>
diff --git a/res/values-mcc450-ky/strings.xml b/res/values-mcc450-ky/strings.xml
index f985a2400..d0c59a96a 100644
--- a/res/values-mcc450-ky/strings.xml
+++ b/res/values-mcc450-ky/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Шашылыш билдирүү"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Коомдук коопсуздукка жаралган коркунуч билдирүүсү"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Amber билдирүүсү"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Телефонуңуз эвакуация боюнча нускамалар сыяктуу шашылыш билдирүүлөрдү кырсыктар учурунда жөнөтө алат. Бул кызмат Корея өкмөтү, тармак кызматтарын көрсөтүүчүлөрү жана түзмөк өндүрүүчүлөрдүн ортосундагы кызматташуу болуп саналат.\n\nТүзмөгүңүздө көйгөй келип чыкса же тармак шарттары начар болсо, эскертүүлөрдү ала албай каласыз."</string>
 </resources>
diff --git a/res/values-mcc450-lo/strings.xml b/res/values-mcc450-lo/strings.xml
index c382dcbc3..6ac57090a 100644
--- a/res/values-mcc450-lo/strings.xml
+++ b/res/values-mcc450-lo/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"ການແຈ້ງເຕືອນເຫດສຸກເສີນ"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"ການແຈ້ງເຕືອນດ້ານຄວາມປອດໄພສາທາລະນະ"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"ການແຈ້ງເຕືອນ AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"ໂທລະສັບຂອງທ່ານສາມາດສົ່ງການແຈ້ງເຕືອນໃຫ້ທ່ານໄດ້ ເຊັ່ນ: ຄຳແນະນຳການອົບພະຍົບ, ໃນລະຫວ່າງທີ່ເກີດໄພພິບັດ. ບໍລິການນີ້ເປັນການເຮັດວຽກຮ່ວມກັນລະຫວ່າງລັດຖະບານເກົາຫຼີ, ຜູ້ໃຫ້ບໍລິການເຄືອຂ່າຍ ແລະ ຜູ້ຜະລິດອຸປະກອນ.\n\nທ່ານອາດບໍ່ໄດ້ຮັບການແຈ້ງເຕືອນຫາກອຸປະກອນຂອງທ່ານມີບັນຫາ ຫຼື ເຄືອຂ່າຍຢູ່ໃນສະພາວະທີ່ບໍ່ສະຖຽນ."</string>
 </resources>
diff --git a/res/values-mcc450-lt/strings.xml b/res/values-mcc450-lt/strings.xml
index 98602b56b..598e1ee14 100644
--- a/res/values-mcc450-lt/strings.xml
+++ b/res/values-mcc450-lt/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Įspėjimas apie kritinę padėtį"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Visuomenės saugumo įspėjimas"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER įspėjimas"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefonas gali siųsti jums įspėjimus, pvz., evakuacijos instrukcijas, įvykus nelaimei. Ši paslauga teikiama bendradarbiaujant Korėjos vyriausybei, tinklo teikėjams ir įrenginių gamintojams.\n\nGalite negauti įspėjimų, jei iškilo įrenginio problema arba prastas tinklo ryšys."</string>
 </resources>
diff --git a/res/values-mcc450-lv/strings.xml b/res/values-mcc450-lv/strings.xml
index ed9429de9..0f03a7c3b 100644
--- a/res/values-mcc450-lv/strings.xml
+++ b/res/values-mcc450-lv/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Ārkārtas brīdinājums"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Brīdinājums par sabiedrisko drošību"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER brīdinājums"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Katastrofu laikā varat tālrunī saņemt brīdinājumus, piemēram, evakuācijas norādījumus. Šo pakalpojumu nodrošina Korejas valdība sadarbībā ar tīkla operatoriem un ierīču ražotājiem.\n\nIespējams, nesaņemsiet brīdinājumus, ja kaut kas nebūs kārtībā ar ierīci vai tīkla apstākļi būs slikti."</string>
 </resources>
diff --git a/res/values-mcc450-mk/strings.xml b/res/values-mcc450-mk/strings.xml
index c8dbf4a55..0a9909174 100644
--- a/res/values-mcc450-mk/strings.xml
+++ b/res/values-mcc450-mk/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Предупредување за итни случаи"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Предупредување за јавна безбедност"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Предупредување AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"При катастрофи, вашиот телефон може да ви прикажува предупредувања, како на пр. упатства за евакуација. Услугава е соработка меѓу корејската влада, операторите и производителите на уреди.\n\nМожно е да не добиете предупредувања ако има проблем со уредот или ако мрежните услови се лоши."</string>
 </resources>
diff --git a/res/values-mcc450-ml/strings.xml b/res/values-mcc450-ml/strings.xml
index a6f264302..e3787bf93 100644
--- a/res/values-mcc450-ml/strings.xml
+++ b/res/values-mcc450-ml/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"അടിയന്തര മുന്നറിയിപ്പ്"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"പൊതു സുരക്ഷാ മുന്നറിയിപ്പ്"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"ആംബർ അലേർട്ട്"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"ദുരന്തങ്ങൾക്കിടയിൽ ഒഴിപ്പിക്കൽ നിർദ്ദേശങ്ങൾ പോലുള്ള മുന്നറിയിപ്പുകൾ അയയ്ക്കാൻ നിങ്ങളുടെ ഫോണിന് കഴിയും. ഈ സേവനം കൊറിയൻ സർക്കാർ, നെറ്റ്‍വർക്ക് സേവന ദാതാക്കൾ, ഉൽപ്പന്ന നിർമ്മാതാക്കൾ എന്നിവരുടെ സഹകരണത്തിന്റെ ഫലമാണ്.\n\nഉപകരണത്തിന് എന്തെങ്കിലും പ്രശ്‌നമുണ്ടെങ്കിലോ നെറ്റ്‌വർക്ക് സാഹചര്യങ്ങൾ മോശമാണെങ്കിലോ നിങ്ങൾക്ക് മുന്നറിയിപ്പുകൾ ലഭിച്ചേക്കില്ല."</string>
 </resources>
diff --git a/res/values-mcc450-mn/strings.xml b/res/values-mcc450-mn/strings.xml
index f519eb013..7f181a5c0 100644
--- a/res/values-mcc450-mn/strings.xml
+++ b/res/values-mcc450-mn/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Утасгүй яаралтай тусламжийн сэрэмжлүүлэг"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Олон нийтийн аюулгүй байдлын сэрэмжлүүлэг"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Amber сэрэмжлүүлэг"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Таны утас гамшгийн үеэр нүүлгэн шилжүүлэх зааварчилгаа зэрэг сэрэмжлүүлгийг танд илгээх боломжтой. Энэ үйлчилгээ нь Солонгос Улсын засгийн газар, сүлжээ нийлүүлэгч болон төхөөрөмж үйлдвэрлэгчийн хоорондох хамтын ажиллагаа юм.\n\nТаны төхөөрөмжтэй холбоотой асуудал байгаа эсвэл сүлжээний нөхцөл байдал муу байвал та сэрэмжлүүлэг авахгүй байж магадгүй."</string>
 </resources>
diff --git a/res/values-mcc450-mr/strings.xml b/res/values-mcc450-mr/strings.xml
index 24160c2c9..eb3aee15c 100644
--- a/res/values-mcc450-mr/strings.xml
+++ b/res/values-mcc450-mr/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"आणीबाणी सूचना"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"सार्वजनिक सुरक्षितता सूचना"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"अँबर सूचना"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"तुमचा फोन तुम्हाला आपत्तीच्या वेळी निर्वासनासंबंधित सूचनांसारखे इशारे पाठवू शकतो. ही सेवा कोरियन सरकार, नेटवर्क पुरवठादार आणि डिव्हाइस उत्पादक यांच्यामधील सहयोगाने काम करते.\n\n तुमच्या डिव्हाइसमध्ये काही समस्या असल्यास किंवा नेटवर्कची स्थिती वाईट असल्यास, तुम्हाला कदाचित इशारे मिळणार नाहीत."</string>
 </resources>
diff --git a/res/values-mcc450-ms/strings.xml b/res/values-mcc450-ms/strings.xml
index c8f67ba97..d2ab88823 100644
--- a/res/values-mcc450-ms/strings.xml
+++ b/res/values-mcc450-ms/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Amaran Kecemasan"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Makluman Keselamatan Awam"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Makluman Amber"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefon anda boleh menghantar amaran, seperti arahan pemindahan semasa bencana berlaku. Perkhidmatan ini merupakan kerjasama antara kerajaan Korea, penyedia rangkaian dan pengilang peranti.\n\nAnda mungkin tidak akan mendapat makluman jika terdapat masalah dengan peranti atau jika keadaan rangkaian lemah."</string>
 </resources>
diff --git a/res/values-mcc450-my/strings.xml b/res/values-mcc450-my/strings.xml
index ad0c95ae4..522ba7740 100644
--- a/res/values-mcc450-my/strings.xml
+++ b/res/values-mcc450-my/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"အရေးပေါ် သတိပေးချက်"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"လူထုလုံခြုံရေး သတိပေးချက်"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Amber သတိပေးချက်"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"ဘေးအန္တရာယ်များ ဖြစ်နေစဉ်တွင် သင့်ဖုန်းသည် ဘေးကင်းရာသို့ ရွှေ့ပြောင်းခြင်း ညွှန်ကြားချက်များကဲ့သို့ သတိပေးချက်များကို သင့်ထံ ပို့နိုင်သည်။ ဤဝန်ဆောင်မှုသည် ကိုရီးယားနိုင်ငံအစိုးရ၊ ကွန်ရက်ဝန်ဆောင်မှုပေးသူနှင့် စက်ပစ္စည်းထုတ်လုပ်သူများကြား ပူးတွဲလုပ်ကိုင်မှုဖြစ်သည်။\n\nစက်ပစ္စည်း၌ ပြဿနာရှိပါက (သို့) ကွန်ရက်အခြေအနေများ အားနည်းနေပါက သတိပေးချက်များ မရနိုင်ပါ။"</string>
 </resources>
diff --git a/res/values-mcc450-nb/strings.xml b/res/values-mcc450-nb/strings.xml
index ad0f534ed..180a575d7 100644
--- a/res/values-mcc450-nb/strings.xml
+++ b/res/values-mcc450-nb/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Nødvarsel"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Offentlig sikkerhetsvarsel"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER-varsel"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefonen kan sende deg varsler, for eksempel evakueringsinstruksjoner, under katastrofer. Denne tjenesten er et samarbeid mellom koreanske myndigheter, nettverksleverandører og enhetsprodusenter.\n\nDu får kanskje ikke varsler hvis det har oppstått et problem med enheten din, eller hvis nettverksforholdene er dårlige."</string>
 </resources>
diff --git a/res/values-mcc450-ne/strings.xml b/res/values-mcc450-ne/strings.xml
index 8d74fbed8..098bfb2a0 100644
--- a/res/values-mcc450-ne/strings.xml
+++ b/res/values-mcc450-ne/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"आपत्‌कालीन अलर्ट"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"सार्वजनिक सुरक्षासम्बन्धी अलर्ट"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER अलर्ट"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"तपाईंको फोनले तपाईंलाई प्राकृतिक प्रकोपका बेला जोखिमपूर्ण ठाउँबाट सुरक्षित रूपमा निस्कने निर्देशनहरू जस्ता अलर्टहरू पठाउन सक्छ। यो सेवा कोरियाली सरकार, नेटवर्क सेवा प्रदायक र डिभाइसका उत्पादकहरू बिचमा सहकार्य गरेर सुरु गरिएको हो।\n\nतपाईंको डिभाइसमा कुनै समस्या छ वा नेटवर्क राम्रो छैन भने तपाईं अलर्टहरू प्राप्त नगर्न पनि सक्नुहुन्छ।"</string>
 </resources>
diff --git a/res/values-mcc450-nl/strings.xml b/res/values-mcc450-nl/strings.xml
index 49d7a8cf1..e1d5324b5 100644
--- a/res/values-mcc450-nl/strings.xml
+++ b/res/values-mcc450-nl/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Noodmelding"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Openbare veiligheidsmelding"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER Alert"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Je telefoon kan je meldingen, zoals evacuatie-instructies, sturen tijdens rampen. Deze service is een samenwerking tussen de Koreaanse overheid, netwerkproviders en apparaatfabrikanten.\n\nMisschien krijg je geen melding als er een probleem is met je apparaat of als het netwerk niet goed werkt."</string>
 </resources>
diff --git a/res/values-mcc450-or/strings.xml b/res/values-mcc450-or/strings.xml
index fe43ecc75..063304648 100644
--- a/res/values-mcc450-or/strings.xml
+++ b/res/values-mcc450-or/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"ଜରୁରୀକାଳୀନ ଆଲର୍ଟ"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"ସାର୍ବଜନୀନ ସୁରକ୍ଷା ଆଲର୍ଟ"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"ଅମ୍ବର ଆଲର୍ଟ"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"ଆପଣଙ୍କ ଫୋନ ଦୁର୍ବିପାକ ସମୟରେ ସ୍ଥାନାନ୍ତର ନିର୍ଦ୍ଦେଶଗୁଡ଼ିକ ପରି ଆଲର୍ଟ ଆପଣଙ୍କୁ ପଠାଇପାରିବ। ଏହି ସେବା କୋରୀୟ ସରକାର, ନେଟୱାର୍କ ପ୍ରଦାନକାରୀ ଏବଂ ଡିଭାଇସ ନିର୍ମାତାମାନଙ୍କ ମଧ୍ୟରେ ଏକ ସହଯୋଗ ଅଟେ।\n\nଯଦି ଆପଣଙ୍କ ଡିଭାଇସରେ କୌଣସି ସମସ୍ୟା ଥାଏ କିମ୍ବା ନେଟୱାର୍କ ସ୍ଥିତି ଖରାପ ଥାଏ ତେବେ ଆପଣ ଆଲର୍ଟ ପାଇନପାରନ୍ତି।"</string>
 </resources>
diff --git a/res/values-mcc450-pa/strings.xml b/res/values-mcc450-pa/strings.xml
index c75f0e6a8..342b0c8cb 100644
--- a/res/values-mcc450-pa/strings.xml
+++ b/res/values-mcc450-pa/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"ਐਮਰਜੈਂਸੀ ਅਲਰਟ"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"ਜਨਤਕ ਸੁਰੱਖਿਆ ਅਲਰਟ"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER ਅਲਰਟ"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"ਆਫ਼ਤਾਂ ਦੌਰਾਨ ਤੁਹਾਡਾ ਫ਼ੋਨ ਤੁਹਾਨੂੰ ਸੁਚੇਤਨਾਵਾਂ, ਜਿਵੇਂ ਕਿ ਨਿਕਾਸ ਸੰਬੰਧੀ ਹਿਦਾਇਤਾਂ, ਭੇਜ ਸਕਦਾ ਹੈ। ਇਹ ਸੇਵਾ ਕੋਰੀਆ ਦੀ ਸਰਕਾਰ, ਨੈੱਟਵਰਕ ਪ੍ਰਦਾਨਕਾਂ ਅਤੇ ਡੀਵਾਈਸ ਨਿਰਮਾਤਾਵਾਂ ਵਿਚਲਾ ਸਹਿਯੋਗ ਹੈ।\n\nਤੁਹਾਡੇ ਡੀਵਾਈਸ ਵਿੱਚ ਸਮੱਸਿਆ ਹੋਣ \'ਤੇ ਜਾਂ ਖਰਾਬ ਨੈੱਟਵਰਕ ਹਾਲਾਤਾਂ ਹੋਣ ਕਾਰਨ ਸ਼ਾਇਦ ਤੁਹਾਨੂੰ ਸੁਚੇਤਨਾਵਾਂ ਪ੍ਰਾਪਤ ਨਾ ਹੋਣ।"</string>
 </resources>
diff --git a/res/values-mcc450-pl/strings.xml b/res/values-mcc450-pl/strings.xml
index 12e3582e3..d621a3290 100644
--- a/res/values-mcc450-pl/strings.xml
+++ b/res/values-mcc450-pl/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Alert o zagrożeniu"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Alert dotyczący bezpieczeństwa publicznego"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Alert AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Podczas klęsk żywiołowych telefon może wysyłać Ci alerty, na przykład instrukcje dotyczące ewakuacji. Ta usługa powstała we współpracy z rządem Korei, dostawcami usług sieciowych i producentami urządzeń.\n\nW przypadku problemów z urządzeniem lub złego stanu sieci alerty mogą być niedostępne."</string>
 </resources>
diff --git a/res/values-mcc450-pt-rPT/strings.xml b/res/values-mcc450-pt-rPT/strings.xml
index 9f86f332e..c91c90beb 100644
--- a/res/values-mcc450-pt-rPT/strings.xml
+++ b/res/values-mcc450-pt-rPT/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Alerta de emergência"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Alerta de segurança pública"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Alerta AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"O telemóvel pode enviar-lhe alertas, como instruções de evacuação, durante desastres. Este serviço é uma colaboração entre o governo coreano, os fornecedores de rede e os fabricantes de dispositivos.\n\nPode não receber alertas se houver um problema com o seu dispositivo ou se as condições de rede forem fracas."</string>
 </resources>
diff --git a/res/values-mcc450-pt/strings.xml b/res/values-mcc450-pt/strings.xml
index 3d9fe4d88..7820d2709 100644
--- a/res/values-mcc450-pt/strings.xml
+++ b/res/values-mcc450-pt/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Alerta de emergência"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Alerta de segurança pública"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Alerta AMBER (rapto de criança)"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Seu smartphone pode enviar alertas, como instruções de evacuação, durante desastres. Esse serviço é uma colaboração entre o governo da Coreia do Sul, operadoras de rede e fabricantes de dispositivos.\n\nTalvez você não receba alertas se houver algum problema com o dispositivo ou se as condições da rede estiverem ruins."</string>
 </resources>
diff --git a/res/values-mcc450-ro/strings.xml b/res/values-mcc450-ro/strings.xml
index e53447451..c9dd4a302 100644
--- a/res/values-mcc450-ro/strings.xml
+++ b/res/values-mcc450-ro/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Alertă de urgență"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Alertă privind siguranța publică"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Alertă AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefonul îți poate trimite alerte, de exemplu instrucțiuni de evacuare, în timpul dezastrelor naturale. Acest serviciu reprezintă o colaborare între guvernul coreean, furnizorii de rețele și producătorii de dispozitive.\n\nProbabil că nu vei primi alerte dacă există o problemă legată de dispozitiv sau condițiile rețelei nu sunt optime."</string>
 </resources>
diff --git a/res/values-mcc450-ru/strings.xml b/res/values-mcc450-ru/strings.xml
index b33c7c111..8abf2f303 100644
--- a/res/values-mcc450-ru/strings.xml
+++ b/res/values-mcc450-ru/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Экстренное оповещение"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Оповещение об угрозе общественной безопасности"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Оповещение AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Вы можете получать на телефон оповещения во время стихийных бедствий, например инструкции по эвакуации. Сервис работает при поддержке правительства Республики Корея, поставщиков сетевых услуг и производителей устройств.\n\nОповещения могут не приходить, если возникла проблема с устройством или сигнал сети слабый."</string>
 </resources>
diff --git a/res/values-mcc450-si/strings.xml b/res/values-mcc450-si/strings.xml
index 6e2b3caf7..5d20d9d32 100644
--- a/res/values-mcc450-si/strings.xml
+++ b/res/values-mcc450-si/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"හදිසි අවස්ථා ඇඟවීම"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"පොදු ආරක්ෂාව පිළිබඳ ඇඟවීම"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"ඇම්බර් ඇඟවීම"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"විපත්වලදී, ඔබේ දුරකථනය ඉවත් වීමේ උපදෙස් වැනි ඇඟවීම් ඔබට එවිය හැක. මෙම සේවය කොරියානු රජය, ජාල සැපයුම්කරුවන්, සහ උපාංග නිෂ්පාදකයින් අතර සහයෝගයකි.\n\nඔබේ උපාංගයේ ගැටලුවක් තිබේ නම් හෝ ජාල තත්ත්‍ව දුර්වල නම් ඔබට ඇඟවීම් ලැබේවි."</string>
 </resources>
diff --git a/res/values-mcc450-sk/strings.xml b/res/values-mcc450-sk/strings.xml
index 53f91448a..a279ff7bc 100644
--- a/res/values-mcc450-sk/strings.xml
+++ b/res/values-mcc450-sk/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Tiesňové varovanie"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Varovanie verejnej bezpečnosti"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Upozornenie Amber"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"V telefóne môžete v prípade katastrof dostávať varovania, napríklad pokyny na evakuáciu. Táto služba je výsledkom spolupráce kórejskej vlády, poskytovateľov sietí a výrobcov zariadení.\n\nVarovania nemusíte dostať, ak sa vyskytne problém so zariadením alebo kvalitou siete."</string>
 </resources>
diff --git a/res/values-mcc450-sl/strings.xml b/res/values-mcc450-sl/strings.xml
index 6b1b2e6e5..cc9663b02 100644
--- a/res/values-mcc450-sl/strings.xml
+++ b/res/values-mcc450-sl/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Nujno opozorilo"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Opozorilo za javno varnost"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Opozorilo AMBER"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefon vam lahko med katastrofami pošilja opozorila, na primer navodila za evakuacijo. To storitev je plod sodelovanja med korejsko vlado, operaterji omrežij in proizvajalci naprav.\n\nOpozoril morda ne boste mogli prejeti v primeru težav z napravo ali slabega signala omrežja."</string>
 </resources>
diff --git a/res/values-mcc450-sq/strings.xml b/res/values-mcc450-sq/strings.xml
index c518ea1d9..65b849d02 100644
--- a/res/values-mcc450-sq/strings.xml
+++ b/res/values-mcc450-sq/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Sinjalizim urgjence"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Sinjalizim i sigurisë publike"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Sinjalizimi Amber"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefoni yt mund të të dërgojë sinjalizime, si p.sh. udhëzime për evakuimet, gjatë katastrofave. Ky shërbim është një bashkëpunim mes qeverisë koreane, ofruesve të rrjetit dhe prodhuesve të pajisjeve.\n\nMund të mos marrësh sinjalizime nëse ka një problem me pajisjen tënde ose nëse kushtet e rrjetit janë të këqija."</string>
 </resources>
diff --git a/res/values-mcc450-sr/strings.xml b/res/values-mcc450-sr/strings.xml
index 0cb156f8d..076219a7a 100644
--- a/res/values-mcc450-sr/strings.xml
+++ b/res/values-mcc450-sr/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Упозорење о хитном случају"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Обавештење о јавној безбедности"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Amber упозорење"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Телефон може да вам шаље упозорења током катастрофа, нпр. упутства за евакуацију. Ова услуга представља сарадњу између Владе Кореје, провајдера и произвођача уређаја.\n\nМожда нећете добијати упозорења ако постоји проблем са уређајем или ако сигнал мреже није довољно јак."</string>
 </resources>
diff --git a/res/values-mcc450-sv/strings.xml b/res/values-mcc450-sv/strings.xml
index e1c2ef5f9..0b9330f48 100644
--- a/res/values-mcc450-sv/strings.xml
+++ b/res/values-mcc450-sv/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Varning om nödsituation"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Säkerhetsvarning till allmänheten"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER-varning"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefonen kan skicka varningar, till exempel evakueringsanvisningar, vid katastrofer. Den här tjänsten är ett samarbete mellan den sydkoreanska regeringen, operatörer och enhetstillverkare.\n\nDu kanske inte får varningar om det finns ett problem med enheten eller om nätverksanslutningen är dålig."</string>
 </resources>
diff --git a/res/values-mcc450-sw/strings.xml b/res/values-mcc450-sw/strings.xml
index 5f780354c..2b6671355 100644
--- a/res/values-mcc450-sw/strings.xml
+++ b/res/values-mcc450-sw/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Tahadhari ya Dharura"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Tahadhari ya Usalama kwa Umma"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Arifa ya Watoto Waliotekwa Nyara"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Simu yako inaweza kukutumia arifa, kama vile maagizo ya kuhama wakati wa majanga. Huduma hii inatokana na ushirikiano kati ya serikali ya Korea, watoa huduma za mtandao na watengenezaji wa vifaa.\n\nHuenda usipate arifa kifaa chako kikiwa na hitilafu au iwapo hali za muunganisho wa mtandao si thabiti."</string>
 </resources>
diff --git a/res/values-mcc450-ta/strings.xml b/res/values-mcc450-ta/strings.xml
index d6ac74b53..f917093ec 100644
--- a/res/values-mcc450-ta/strings.xml
+++ b/res/values-mcc450-ta/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"அவசரகால எச்சரிக்கை"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"பொதுப் பாதுகாப்பு எச்சரிக்கை"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER எச்சரிக்கை"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"பேரிடர்களின் போது வெளியேறும் வழிமுறைகள் போன்ற விழிப்பூட்டல்களை உங்கள் மொபைல் அனுப்பும். இந்தச் சேவையை கொரிய அரசாங்கமும் நெட்வொர்க் நிறுவனமும் சாதனத் தயாரிப்பாளர்களும் இணைந்து வழங்குகிறார்கள்.\n\nஉங்கள் சாதனத்தில் ஏதேனும் சிக்கல் இருந்தாலோ உங்கள் நெட்வொர்க் இணைப்பு சரியில்லை என்றாலோ விழிப்பூட்டல்களை நீங்கள் பெறமால் போகக்கூடும்."</string>
 </resources>
diff --git a/res/values-mcc450-te/strings.xml b/res/values-mcc450-te/strings.xml
index 25e8f3c7e..bf1ab802a 100644
--- a/res/values-mcc450-te/strings.xml
+++ b/res/values-mcc450-te/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"ఎమర్జెన్సీ అలర్ట్"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"పబ్లిక్ భద్రత అలర్ట్"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"యాంబర్ అలర్ట్"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"మీ ఫోన్ ప్రకృతి వైపరీత్యాలు సంభవించినప్పుడు తరలింపు సూచనలు లాంటి అలర్ట్‌లను మీకు పంపించగలదు. ఈ సర్వీస్ కొరియన్ ప్రభుత్వం, నెట్‌వర్క్ ప్రొవైడర్‌లు, పరికర తయారీదారుల మధ్య సహకారంతో అందించబడుతుంది.\n\nమీ పరికరంలో సమస్య ఉన్నట్లయితే లేదా నెట్‌వర్క్ పరిస్థితులు సరిగా లేనట్లయితే మీరు అలర్ట్‌లను పొందడం సాధ్యం కాదు."</string>
 </resources>
diff --git a/res/values-mcc450-th/strings.xml b/res/values-mcc450-th/strings.xml
index 1370a2891..1c587ce40 100644
--- a/res/values-mcc450-th/strings.xml
+++ b/res/values-mcc450-th/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"การแจ้งเตือนเหตุฉุกเฉิน"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"การแจ้งเตือนด้านความปลอดภัยสาธารณะ"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"การแจ้งเตือนเด็กหาย Amber Alert"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"โทรศัพท์จะส่งการแจ้งเตือนให้คุณ เช่น คำสั่งอพยพ ระหว่างเกิดภัยพิบัติ บริการนี้เป็นการทำงานร่วมกันระหว่างรัฐบาลเกาหลี ผู้ให้บริการเครือข่าย และผู้ผลิตอุปกรณ์\n\nคุณอาจไม่ได้รับการแจ้งเตือนหากอุปกรณ์มีปัญหาหรือเครือข่ายอยู่ในสภาวะที่ไม่เสถียร"</string>
 </resources>
diff --git a/res/values-mcc450-tl/strings.xml b/res/values-mcc450-tl/strings.xml
index 31f8445cb..65b300883 100644
--- a/res/values-mcc450-tl/strings.xml
+++ b/res/values-mcc450-tl/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Alertong Pang-emergency"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Alerto para sa Pampublikong Kaligtasan"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"AMBER Alert"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Puwede kang padalhan ng iyong telepono ng mga alerto, tulad ng mga tagubilin sa paglikas, kapag may mga sakuna. Ang serbisyong ito ay sama-samang pagsisikap ng pamahalaan ng Korea, mga network provider, at mga manufacturer ng device.\n\nBaka hindi ka makatanggap ng mga alerto kung may problema sa iyong device o kung hindi maganda ang mga kundisyon ng network."</string>
 </resources>
diff --git a/res/values-mcc450-tr/strings.xml b/res/values-mcc450-tr/strings.xml
index 03a82b8bb..516773b68 100644
--- a/res/values-mcc450-tr/strings.xml
+++ b/res/values-mcc450-tr/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Acil durum uyarısı"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Kamu güvenliği uyarısı"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Amber kayıp çocuk alarmı"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Telefonunuz doğal felaketler sırasında tahliye emirleri gibi uyarıları size gönderebilir. Bu hizmet Kore devleti, ağ sağlayıcılar ve cihaz üreticileri arasında işbirliğiyle sunulmaktadır.\n\nCihazınızda sorun olması veya ağ koşullarının kötü olması durumunda uyarı almayabilirsiniz."</string>
 </resources>
diff --git a/res/values-mcc450-uk/strings.xml b/res/values-mcc450-uk/strings.xml
index 6d4116cf0..59d60654d 100644
--- a/res/values-mcc450-uk/strings.xml
+++ b/res/values-mcc450-uk/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Екстрене сповіщення"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Сповіщення щодо громадської безпеки"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Сповіщення Amber"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Ви можете отримувати на телефон сповіщення під час стихійних лих (наприклад, інструкції з евакуації). Цей сервіс працює завдяки співробітництву між корейським урядом, операторами мереж і розробниками пристроїв.\n\nСповіщення можуть не надходити, якщо з пристроєм виникла проблема або мережа має слабкий сигнал."</string>
 </resources>
diff --git a/res/values-mcc450-ur/strings.xml b/res/values-mcc450-ur/strings.xml
index cc9acbdf8..85e0b0086 100644
--- a/res/values-mcc450-ur/strings.xml
+++ b/res/values-mcc450-ur/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"ایمرجنسی الرٹ"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"عوامی حفاظتی الرٹ"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"زرد الرٹ"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"آپ کا فون آفات کے دوران انخلائی ہدایات جیسے الرٹس آپ کو بھیج سکتا ہے۔ یہ سروس کوریائی حکومت، نیٹ ورک فراہم کنندگان، اور آلہ مینوفیکچررز کے درمیان ایک معاونت ہے۔\n\nاگر آپ کے آلہ میں کوئی مسئلہ ہو یا نیٹ ورک کے حالات خراب ہو تو ہو سکتا ہے کہ آپ کو الرٹس موصول نہ ہوں۔"</string>
 </resources>
diff --git a/res/values-mcc450-uz/strings.xml b/res/values-mcc450-uz/strings.xml
index 15e29698b..9e07550ce 100644
--- a/res/values-mcc450-uz/strings.xml
+++ b/res/values-mcc450-uz/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Favqulodda ogohlantirish"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Ommaviy xavfsizlik haqida ogohlantirish"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Amber ogohlantirishi"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Tabiiy ofatlar vaqtida telefoningiz evakuatsiya koʻrsatmalari kabi muhim xabarlarni chiqarishi mumkin. Bu xizmat Koreya hukumati, tarmoq operatorlari va qurilma ishlab chiqaruvchilari tomonidan birgalikda ishlab chiqilgan.\n\nQurilmada yoki tarmoqda muammolar boʻlsa, sizga muhim xabarlar kelmasligi mumkin."</string>
 </resources>
diff --git a/res/values-mcc450-vi/strings.xml b/res/values-mcc450-vi/strings.xml
index 82e1f3bbb..5ff9817e7 100644
--- a/res/values-mcc450-vi/strings.xml
+++ b/res/values-mcc450-vi/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Cảnh báo khẩn cấp"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Cảnh báo chung về an toàn"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Cảnh báo Amber"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Điện thoại có thể gửi cho bạn các cảnh báo, chẳng hạn như hướng dẫn sơ tán khi xảy ra thảm hoạ. Dịch vụ này là kết quả hợp tác giữa Chính phủ Hàn Quốc, nhà cung cấp dịch vụ mạng và nhà sản xuất thiết bị.\n\nCó thể bạn sẽ không nhận được cảnh báo nếu thiết bị gặp sự cố hoặc nếu kết nối mạng kém."</string>
 </resources>
diff --git a/res/values-mcc450-zh-rCN/strings.xml b/res/values-mcc450-zh-rCN/strings.xml
index 7f5892953..e054070f0 100644
--- a/res/values-mcc450-zh-rCN/strings.xml
+++ b/res/values-mcc450-zh-rCN/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"紧急警报"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"公共安全警报"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"安珀警报"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"您的手机可在灾害发生期间向您发出警报，例如疏散指示。这项服务是由韩国政府、网络提供商和设备制造商联合提供的。\n\n如果您的设备存在问题或网络条件欠佳，您可能会收不到警报。"</string>
 </resources>
diff --git a/res/values-mcc450-zh-rHK/strings.xml b/res/values-mcc450-zh-rHK/strings.xml
index fa0aa3d74..568f88360 100644
--- a/res/values-mcc450-zh-rHK/strings.xml
+++ b/res/values-mcc450-zh-rHK/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"緊急警示"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"公共安全警示"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"安珀警報"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"如果發生災難，手機就會向你傳送警示，例如疏散指示。此服務由南韓政府、網絡供應商和裝置製造商共同提供。\n\n如你的裝置發生問題或網絡連線欠佳，可能不會收到警示。"</string>
 </resources>
diff --git a/res/values-mcc450-zh-rTW/strings.xml b/res/values-mcc450-zh-rTW/strings.xml
index 25709c148..71b4352b2 100644
--- a/res/values-mcc450-zh-rTW/strings.xml
+++ b/res/values-mcc450-zh-rTW/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"緊急警報"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"公共安全警報"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"安珀警報"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"災難發生時，手機會收到避難指示等警報。這項服務是由韓國政府、網路服務供應商和裝置製造商共同提供。\n\n如果裝置有問題或網路訊號不佳，可能會收不到警報。"</string>
 </resources>
diff --git a/res/values-mcc450-zu/strings.xml b/res/values-mcc450-zu/strings.xml
index 5abb58e30..43bffac64 100644
--- a/res/values-mcc450-zu/strings.xml
+++ b/res/values-mcc450-zu/strings.xml
@@ -23,5 +23,7 @@
     <string name="enable_emergency_alerts_message_title" msgid="4898249233421369579">"Isexwayiso Esiphuthumayo"</string>
     <string name="enable_public_safety_messages_title" msgid="80797144239755093">"Isexwayiso Sokuphepha Esidlangalaleni"</string>
     <string name="enable_cmas_amber_alerts_title" msgid="6133775002476394948">"Isexwayiso se-Amber"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (747151502102840369) -->
+    <skip />
     <string name="alerts_header_summary" msgid="7325972887358335555">"Ifoni yakho ingakuthumela izexwayiso, njengemiyalelo yokuphuma, phakathi nezinhlekelele. Le sevisi iyinhlanganyelo phakathi kukahulumeni wase-Korea, abahlinzeki benethiwekhi, nabakhiqizi bedivayisi.\n\nUngahle ungazitholi izexwayiso uma kunenkinga ngedivayisi yakho noma uma izimo zenethiwekhi zingezinhle."</string>
 </resources>
diff --git a/res/values-mcc450/strings.xml b/res/values-mcc450/strings.xml
index 268f49f39..2ac4d8fc9 100644
--- a/res/values-mcc450/strings.xml
+++ b/res/values-mcc450/strings.xml
@@ -41,6 +41,9 @@
     <!-- Required Korean (ko) translation for this message: 실종 경보문자 -->
     <string name="enable_cmas_amber_alerts_title">Amber Alert</string>
 
+    <!-- Value of sms sender display name to be shown in SMS inbox for amber alerts -->
+    <string name="sms_cb_sender_name_amber">@string/sms_cb_sender_name_public_safety</string>
+
     <!-- Preference summary the "about cell broadcast messages" info required for some carriers.
       Required Korean (ko) translation for this message:
       "재난 발생 시 휴대전화에서 대피 안내와 같은 경고 알림을 받아볼 수 있습니다. 이 서비스는 정부, 네트워크 공급자, 기기 제조업체와의 공조로 제공됩니다.\n\n기기에 문제가 있거나 네트워크 상태가 좋지 않을 경우 알림을 받지 못할 수 있습니다." -->
diff --git a/res/values-mcc454-gu/strings.xml b/res/values-mcc454-gu/strings.xml
index 6c3f34a73..e04ad9b18 100644
--- a/res/values-mcc454-gu/strings.xml
+++ b/res/values-mcc454-gu/strings.xml
@@ -18,8 +18,8 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_presidential_level_alert" msgid="8798462930675572592">"અત્યંત ઇમર્જન્સી અલર્ટ"</string>
     <string name="cmas_extreme_alert" msgid="666310502927269524">"ઇમર્જન્સી અલર્ટ"</string>
-    <string name="cmas_required_monthly_test" msgid="3412608025684914213">"પરીક્ષણ માટેનો સંદેશ"</string>
+    <string name="cmas_required_monthly_test" msgid="3412608025684914213">"પરીક્ષણ માટેનો મેસેજ"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="8186076761036041808">"ઇમર્જન્સી અલર્ટ મેળવો"</string>
-    <string name="enable_cmas_test_alerts_title" msgid="4587011587057993053">"પરીક્ષણ માટેના સંદેશા"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="6148921520813876460">"પરીક્ષણ માટેના સંદેશા પ્રાપ્ત કરો"</string>
+    <string name="enable_cmas_test_alerts_title" msgid="4587011587057993053">"પરીક્ષણ માટેના મેસેજ"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="6148921520813876460">"પરીક્ષણ માટેના મેસેજ મેળવો"</string>
 </resources>
diff --git a/res/values-mcc466-gu/strings.xml b/res/values-mcc466-gu/strings.xml
index 3b8d7f9e5..65b3f838a 100644
--- a/res/values-mcc466-gu/strings.xml
+++ b/res/values-mcc466-gu/strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_presidential_level_alert" msgid="2072968896927919629">"રાષ્ટ્રપતિના લેવલ સંબંધિત અલર્ટ"</string>
     <string name="emergency_alert" msgid="5431770009291479378">"ઇમર્જન્સી અલર્ટ"</string>
-    <string name="public_safety_message" msgid="3043854916586710461">"અલર્ટ અંગેનો સંદેશ"</string>
+    <string name="public_safety_message" msgid="3043854916586710461">"અલર્ટ અંગેનો મેસેજ"</string>
     <string name="enable_cmas_test_alerts_title" msgid="4165080207837566277">"જરૂરી માસિક પરીક્ષણ"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="1339769389077152402">"સલામતી અલર્ટ સિસ્ટમ માટે પરીક્ષણ સંદેશા પ્રાપ્ત કરો"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="1339769389077152402">"સલામતી અલર્ટ સિસ્ટમ માટે પરીક્ષણ માટેનો મેસેજ પ્રાપ્ત કરો"</string>
 </resources>
diff --git a/res/values-mcc716-gu/strings.xml b/res/values-mcc716-gu/strings.xml
index 25d14bd9e..2a74ba24e 100644
--- a/res/values-mcc716-gu/strings.xml
+++ b/res/values-mcc716-gu/strings.xml
@@ -16,11 +16,11 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="public_safety_message" msgid="7237115648380675159">"માહિતીપ્રદ સંદેશ"</string>
-    <string name="enable_public_safety_messages_title" msgid="4037404034274507696">"માહિતીપ્રદ સંદેશ"</string>
+    <string name="public_safety_message" msgid="7237115648380675159">"માહિતીપ્રદ મેસેજ"</string>
+    <string name="enable_public_safety_messages_title" msgid="4037404034274507696">"માહિતીપ્રદ મેસેજ"</string>
     <string name="cmas_presidential_level_alert" msgid="8876632274257614262">"ઇમર્જન્સી અલર્ટ"</string>
-    <string name="cmas_required_monthly_test" msgid="9061179556831144678">"કટોકટીની ચેતવણી: પરીક્ષણ સંદેશ"</string>
-    <string name="cmas_exercise_alert" msgid="3061507852301643814">"ઇમર્જન્સી અલર્ટ: કસરત/વ્યાયામ સંબંધિત સંદેશ"</string>
+    <string name="cmas_required_monthly_test" msgid="9061179556831144678">"ઇમર્જન્સી અલર્ટ: પરીક્ષણ મેસેજ"</string>
+    <string name="cmas_exercise_alert" msgid="3061507852301643814">"ઇમર્જન્સી અલર્ટ: પરીક્ષણ/ડ્રિલ સંબંધિત મેસેજ"</string>
     <string name="pws_other_message_identifiers" msgid="3831917966117253553">"ઇમર્જન્સી અલર્ટ"</string>
     <string name="button_dismiss" msgid="5823921161712171097">"છુપાવો"</string>
 </resources>
diff --git a/res/values-mcc716-te/strings.xml b/res/values-mcc716-te/strings.xml
index 9cf3f0b30..9c2d83d97 100644
--- a/res/values-mcc716-te/strings.xml
+++ b/res/values-mcc716-te/strings.xml
@@ -20,7 +20,7 @@
     <string name="enable_public_safety_messages_title" msgid="4037404034274507696">"సమాచారాత్మక మెసేజ్‌"</string>
     <string name="cmas_presidential_level_alert" msgid="8876632274257614262">"ఎమర్జెన్సీ అలర్ట్"</string>
     <string name="cmas_required_monthly_test" msgid="9061179556831144678">"అత్యవసర హెచ్చరిక: పరీక్ష మెసేజ్‌"</string>
-    <string name="cmas_exercise_alert" msgid="3061507852301643814">"అత్యవసర అలర్ట్: అభ్యాసం/డ్రిల్ మెసేజ్‌"</string>
+    <string name="cmas_exercise_alert" msgid="3061507852301643814">"ఎమర్జెన్సీ అలర్ట్: ప్రాక్టీస్/డ్రిల్ మెసేజ్"</string>
     <string name="pws_other_message_identifiers" msgid="3831917966117253553">"ఎమర్జెన్సీ అలర్ట్"</string>
     <string name="button_dismiss" msgid="5823921161712171097">"దాచు"</string>
 </resources>
diff --git a/res/values-mcc722-mnc07/config.xml b/res/values-mcc722-mnc07/config.xml
index c1f2f2a68..b8fc585a2 100644
--- a/res/values-mcc722-mnc07/config.xml
+++ b/res/values-mcc722-mnc07/config.xml
@@ -19,6 +19,6 @@
     <bool name="emergency_alerts_enabled_default">false</bool>
     <!-- 50 -->
     <string-array name="emergency_alerts_channels_range_strings" translatable="false">
-        <item>0x032:rat=gsm, emergency=true, dialog_with_notification=true</item>
+        <item>0x032:rat=gsm, type=mute, emergency=true, dialog_with_notification=true</item>
     </string-array>
 </resources>
diff --git a/res/values-mcc724-be/strings.xml b/res/values-mcc724-be/strings.xml
index ce776171a..1844f157e 100644
--- a/res/values-mcc724-be/strings.xml
+++ b/res/values-mcc724-be/strings.xml
@@ -17,13 +17,13 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_extreme_alert" msgid="3751964445127743376">"Экстранная абвестка"</string>
-    <string name="cmas_severe_alert" msgid="4773544726385840011">"Абвестка пра сур\'ёзную пагрозу"</string>
+    <string name="cmas_severe_alert" msgid="4773544726385840011">"Абвестка пра сур’ёзную пагрозу"</string>
     <string name="cmas_required_monthly_test" msgid="5274965928258227096">"Тэставая абвестка"</string>
     <string name="cmas_exercise_alert" msgid="4971838389621550184">"Абвесткі ў рамках тэхнічных выпрабаванняў"</string>
     <string name="enable_cmas_extreme_threat_alerts_title" msgid="3095141156358640879">"Надзвычайныя пагрозы"</string>
     <string name="enable_cmas_extreme_threat_alerts_summary" msgid="6931853411327178941">"Надзвычайныя пагрозы для жыцця і маёмасці"</string>
-    <string name="enable_cmas_severe_threat_alerts_title" msgid="2603680055509729555">"Сур\'ёзныя пагрозы"</string>
-    <string name="enable_cmas_severe_threat_alerts_summary" msgid="405751015446465202">"Сур\'ёзныя пагрозы для жыцця і маёмасці"</string>
+    <string name="enable_cmas_severe_threat_alerts_title" msgid="2603680055509729555">"Сур’ёзныя пагрозы"</string>
+    <string name="enable_cmas_severe_threat_alerts_summary" msgid="405751015446465202">"Сур’ёзныя пагрозы для жыцця і маёмасці"</string>
     <string name="enable_cmas_test_alerts_title" msgid="5550182663333808054">"Дзяржаўныя і мясцовыя тэставыя паведамленні"</string>
     <string name="enable_cmas_test_alerts_summary" msgid="5713628754819156297">"Атрымліваць тэставыя паведамленні ад дзяржаўных і мясцовых органаў улады"</string>
     <string name="enable_exercise_test_alerts_title" msgid="1926178722994782168">"Абвесткі ў рамках тэхнічных выпрабаванняў"</string>
diff --git a/res/values-mcc730-gu/strings.xml b/res/values-mcc730-gu/strings.xml
index e11d32ea9..70ba3f81b 100644
--- a/res/values-mcc730-gu/strings.xml
+++ b/res/values-mcc730-gu/strings.xml
@@ -16,5 +16,5 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="cmas_required_monthly_test" msgid="530685628438270164">"પરીક્ષણ માટેનો સંદેશ"</string>
+    <string name="cmas_required_monthly_test" msgid="530685628438270164">"પરીક્ષણ માટેનો મેસેજ"</string>
 </resources>
diff --git a/res/values-mcc732-mnc123/config.xml b/res/values-mcc732-mnc123/config.xml
index 20e0d53d3..7dce22ce7 100644
--- a/res/values-mcc732-mnc123/config.xml
+++ b/res/values-mcc732-mnc123/config.xml
@@ -26,7 +26,7 @@
 
     <!-- 50 -->
     <string-array name="emergency_alerts_channels_range_strings" translatable="false">
-        <item>0x0032:rat=gsm, emergency=true, dialog_with_notification=true</item>
+        <item>0x0032:rat=gsm, type=mute, emergency=true, dialog_with_notification=true</item>
     </string-array>
 
     <!-- additional_cbs_channels_strings empty -->
diff --git a/res/values-mcc734-mnc04/config.xml b/res/values-mcc734-mnc04/config.xml
index 33b6f628c..03749275e 100644
--- a/res/values-mcc734-mnc04/config.xml
+++ b/res/values-mcc734-mnc04/config.xml
@@ -19,6 +19,6 @@
     <bool name="emergency_alerts_enabled_default">false</bool>
     <!-- 50 -->
     <string-array name="emergency_alerts_channels_range_strings" translatable="false">
-        <item>0x0032:rat=gsm, emergency=true, dialog_with_notification=true</item>
+        <item>0x0032:rat=gsm, type=mute, emergency=true, dialog_with_notification=true</item>
     </string-array>
 </resources>
diff --git a/res/values-mcc740-gu/strings.xml b/res/values-mcc740-gu/strings.xml
index 678c58db0..fca1b62ee 100644
--- a/res/values-mcc740-gu/strings.xml
+++ b/res/values-mcc740-gu/strings.xml
@@ -18,9 +18,9 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="cmas_presidential_level_alert" msgid="8832531644152117875">"સ્થાનિક ઇમર્જન્સી અલર્ટ"</string>
     <string name="button_dismiss" msgid="5975841666550833732">"બંધ કરો"</string>
-    <string name="cmas_required_monthly_test" msgid="2287926047457291638">"પરીક્ષણ માટેનો સંદેશ"</string>
-    <string name="cmas_exercise_alert" msgid="998005154407142100">"ઇમર્જન્સી અલર્ટ - વ્યાયામ / તાલીમ સંબંધિત સંદેશ"</string>
-    <string name="public_safety_message" msgid="6263179411117570932">"માહિતીપ્રદ સંદેશ"</string>
+    <string name="cmas_required_monthly_test" msgid="2287926047457291638">"પરીક્ષણ માટેનો મેસેજ"</string>
+    <string name="cmas_exercise_alert" msgid="998005154407142100">"ઇમર્જન્સી અલર્ટ - વ્યાયામ / તાલીમ સંબંધિત મેસેજ"</string>
+    <string name="public_safety_message" msgid="6263179411117570932">"માહિતીપ્રદ મેસેજ"</string>
     <!-- no translation found for enable_public_safety_messages_title (132836010129431792) -->
     <skip />
     <string name="enable_public_safety_messages_summary" msgid="5574351338788490055"></string>
diff --git a/res/values-mcc740-mnc00/config.xml b/res/values-mcc740-mnc00/config.xml
index 53b748737..d76403612 100644
--- a/res/values-mcc740-mnc00/config.xml
+++ b/res/values-mcc740-mnc00/config.xml
@@ -19,7 +19,7 @@
     <bool name="emergency_alerts_enabled_default">false</bool>
     <!-- 50 -->
     <string-array name="emergency_alerts_channels_range_strings" translatable="false">
-        <item>0x0032:rat=gsm, emergency=true, dialog_with_notification=true</item>
+        <item>0x0032:rat=gsm, type=mute, emergency=true, dialog_with_notification=true</item>
     </string-array>
     <string-array name="additional_cbs_channels_strings" translatable="false">
     </string-array>
diff --git a/res/values-mcc740-te/strings.xml b/res/values-mcc740-te/strings.xml
index 30cc67752..6a0a5e3b3 100644
--- a/res/values-mcc740-te/strings.xml
+++ b/res/values-mcc740-te/strings.xml
@@ -19,7 +19,7 @@
     <string name="cmas_presidential_level_alert" msgid="8832531644152117875">"స్థానిక ఎమర్జెన్సీ అలర్ట్"</string>
     <string name="button_dismiss" msgid="5975841666550833732">"షట్ డౌన్"</string>
     <string name="cmas_required_monthly_test" msgid="2287926047457291638">"టెస్ట్ మెసేజ్"</string>
-    <string name="cmas_exercise_alert" msgid="998005154407142100">"ఎమర్జెన్సీ అలర్ట్ వ్యాయామం / డ్రిల్ మెసేజ్"</string>
+    <string name="cmas_exercise_alert" msgid="998005154407142100">"ఎమర్జెన్సీ అలర్ట్ - ప్రాక్టీస్ / డ్రిల్ మెసేజ్"</string>
     <string name="public_safety_message" msgid="6263179411117570932">"సమాచారాత్మక మెసేజ్"</string>
     <!-- no translation found for enable_public_safety_messages_title (132836010129431792) -->
     <skip />
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 50d06717a..6fb3c5a18 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Безжични предупредувања за итни случаи"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Безжични предупредувања за итни случаи"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Информативно известување"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Поставките за безжичните предупредувања за итни случаи не се достапни за корисников"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Во ред"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Нема претходни предупредувања"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index b03a7fa94..91b75ab19 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"വയർലെസ് അടിയന്തര മുന്നറിയിപ്പുകൾ"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"വയർലെസ് അടിയന്തര മുന്നറിയിപ്പുകൾ"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"വിവരങ്ങളടങ്ങിയ അറിയിപ്പ്"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"ഈ ഉപയോക്താവിന് വയർലെസ് അടിയന്തിര അലേർട്ടുകളുടെ ക്രമീകരണം ലഭ്യമല്ല"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ശരി"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"മുമ്പ് അലേർട്ടുകളൊന്നുമില്ല"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index bf2daf4dd..305ea6bd5 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Утасгүй сүлжээний онцгой байдлын сэрэмжлүүлэг"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Утасгүй сүлжээний онцгой байдлын сэрэмжлүүлэг"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Мэдээллийн мэдэгдэл"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Энэ хэрэглэгчийн хувьд утасгүй сүлжээгээр дамжуулах гамшгийн аюулын дохионы тохиргоо боломжгүй байна"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Өмнөх сэрэмжлүүлэг алга"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index a0415abea..8f29a130c 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"आणीबाणीच्या वायरलेस सूचना"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"आणीबाणीच्या वायरलेस सूचना"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"माहितीपूर्ण सूचना"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"या वापरकर्त्यासाठी आणीबाणीमधील वायरलेस इशारा सेटिंग्ज उपलब्ध नाही"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ठीक आहे"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"यापूर्वीचे अलर्ट नाहीत"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 4338f56e1..18baa9d95 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Makluman kecemasan wayarles"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Makluman kecemasan wayarles"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Pemberitahuan mengenai maklumat"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Tetapan makluman kecemasan wayarles tidak tersedia untuk pengguna ini"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Tiada makluman terdahulu"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 16ea22cc3..35a2a6609 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"ကြိုးမဲ့ အရေးပေါ်သတိပေးချက်များ"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"ကြိုးမဲ့ အရေးပေါ်သတိပေးချက်များ"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"အသိပေးအကြောင်းကြားချက်"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"ဤအသုံးပြုသူအတွက် ကြိုးမဲ့ အရေးပေါ်သတိပေးချက် ဆက်တင်များ မရနိုင်ပါ"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"ယခင် သတိပေးချက်များ မရှိပါ"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index a3dcdffd8..dd7adebef 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Trådløse nødvarsler"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Trådløse nødvarsler"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informasjonsvarsel"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Innstillingene for trådløse nødvarsler er ikke tilgjengelige for denne brukeren"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Ingen tidligere varsler"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 3dd235f45..22ee1c235 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"आपत्‌कालीन वायरलेस अलर्टहरू"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"आपत्‌कालीन वायरलेस अलर्टहरू"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"जानकारीमूलक सूचना"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"यस प्रयोगकर्ताका लागि आपत्‌कालीन वायरलेस सतर्कतासम्बन्धी सेटिङहरू उपलब्ध छैनन्"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ठिक छ"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"पहिला कुनै एलर्ट आएको छैन"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index f53ec4001..4077821c0 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Mobiele noodmeldingen"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Mobiele noodmeldingen"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informatieve melding"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Instellingen voor noodwaarschuwingen zijn niet beschikbaar voor deze gebruiker"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Geen eerdere meldingen"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index d2b7a932f..43f60b28a 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"ୱାୟାରଲେସ ଜରୁରୀକାଳୀନ ଆଲର୍ଟଗୁଡ଼ିକ"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"ୱେୟାରଲେସ ଜରୁରୀକାଳୀନ ଆଲର୍ଟଗୁଡ଼ିକ"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"ସୂଚନାଭିତ୍ତିକ ବିଜ୍ଞପ୍ତି"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"ଏହି ଉପଯୋଗକର୍ତ୍ତାଙ୍କ ପାଇଁ ୱେୟାରଲେସ ଜରୁରୀକାଳୀନ ଆଲର୍ଟ ସେଟିଂସ ଉପଲବ୍ଧ ନାହିଁ"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ଠିକ ଅଛି"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"ପୂର୍ବର କୌଣସି ଆଲର୍ଟ ନାହିଁ"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 1134bf773..cbfefb01b 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"ਵਾਇਰਲੈੱਸ ਐਮਰਜੈਂਸੀ ਅਲਰਟ"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"ਵਾਇਰਲੈੱਸ ਐਮਰਜੈਂਸੀ ਅਲਰਟ"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"ਜਾਣਕਾਰੀ ਵਾਲੀ ਸੂਚਨਾ"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"ਇਸ ਵਰਤੋਂਕਾਰ ਲਈ ਵਾਇਰਲੈੱਸ ਐਮਰਜੈਂਸੀ ਅਲਰਟ ਸੰਬੰਧੀ ਸੈਟਿੰਗਾਂ ਉਪਲਬਧ ਨਹੀਂ ਹਨ"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ਠੀਕ"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"ਕੋਈ ਪਿਛਲੀ ਅਲਰਟ ਨਹੀਂ ਹੈ"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index c9e5ba642..d6d2bac85 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Alerty o zagrożeniu"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Alerty o zagrożeniu"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Powiadomienie informacyjne"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Ustawienia alertów o zagrożeniu są niedostępne dla tego użytkownika"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Brak wcześniejszych alertów"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 39128646b..572dccc4d 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Alertas de emergência sem fios"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Alertas de emergência sem fios"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notificação informativa"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"As definições de alertas de emergência não estão disponíveis para este utilizador."</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Não existem alertas anteriores"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index 3b430943a..61ea7d1a6 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Alertas de emergência sem fio"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Alertas de emergência sem fio"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notificação com informação"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Os alertas de emergência sem fio não estão disponíveis para este usuário"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Não há alertas anteriores"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index f4ba3cc6c..3397bf016 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Alerte de urgență wireless"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Alerte de urgență wireless"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notificare informativă"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Setările pentru alerte de urgență wireless nu sunt disponibile pentru acest utilizator"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Nu există alerte anterioare"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 44f6a162e..69de14c49 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Экстренные оповещения по беспроводным сетям"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Экстренные оповещения по беспроводным сетям"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Информационное уведомление"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Настройки экстренных оповещений по беспроводным сетям недоступны для этого пользователя."</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ОК"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Оповещений не было."</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 354e1c686..0a5ae5038 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"නොරැහැන් හදිසි අවස්ථා ඇඟවීම්"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"නොරැහැන් හදිසි අවස්ථා ඇඟවීම්"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"තොරතුරුමය දැනුම්දීම"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"නොරැහැන් හදිසි අවස්ථා ඇඟවීම් සැකසීම් මෙම පරිශීලකයා සඳහා ලබා ගත නොහැකිය"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"හරි"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"පෙර ඇඟවීම් නොමැත"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 8f1448ecb..eeb68cb38 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Bezdrôtové tiesňové varovania"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Bezdrôtové núdzové upozornenia"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informačné upozornenie"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Bezdrôtové tiesňové upozornenia nie sú pre tohto používateľa dostupné"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Žiadne predchádzajúce upozornenia"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index 5bb4cd060..2f073c7ef 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Brezžična nujna opozorila"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Brezžična nujna opozorila"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Obvestilo z informacijami"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Nastavitve brezžičnih nujnih opozoril niso na voljo za tega uporabnika"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"V redu"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Ni prejšnjih opozoril."</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 391d9ff90..50b3929d0 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Sinjalizimet wireless të urgjencës"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Sinjalizimet wireless të urgjencës"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Njoftim informues"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Cilësimet e sinjalizimeve wireless të urgjencës nuk ofrohen për këtë përdorues"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Në rregull"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Asnjë alarm i mëparshëm"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 014862fa6..f979cb449 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Бежична упозорења о хитним случајевима"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Бежична упозорења о хитним случајевима"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Информативно обавештење"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Подешавања бежичних обавештења о хитним случајевима нису доступна за овог корисника"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Потврди"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Нема претходних обавештења"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 4010ea4c5..d3e2ff611 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Trådlösa varningar vid nödsituationer"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Trådlösa varningar vid nödsituationer"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Informativ avisering"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Den här användaren har inte åtkomst till inställningarna för trådlösa varningar vid nödsituationer"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Inga tidigare varningar"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 4992cf068..3cd8ddc34 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Arifa za dharura kupitia vifaa visivyotumia waya"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Arifa za dharura kupitia vifaa visivyotumia waya"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Arifa ya maelezo"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Mipangilio ya arifa za dharura kupitia vifaa visivyotumia waya haipatikani kwa mtumiaji huyu"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Sawa"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Hakuna arifa za awali"</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 735e0023c..de6e0912f 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"வயர்லெஸ் அவசரகால விழிப்பூட்டல்கள்"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"வயர்லெஸ் அவசரகால விழிப்பூட்டல்கள்"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"தகவலளிக்கும் அறிவிப்பு"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"வயர்லெஸ் அவசரகால விழிப்பூட்டல் அமைப்புகளை இந்தப் பயனர் பயன்படுத்த இயலாது"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"சரி"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"முந்தைய அறிவிப்புகள் எதுவுமில்லை"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 9efb7e044..0a34f8493 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"వైర్‌లెస్ ఎమర్జెన్సీ అలర్ట్‌లు"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"వైర్‌లెస్ ఎమర్జెన్సీ అలర్ట్‌లు"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"సమాచారం అందించే నోటిఫికేషన్"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"ఈ వినియోగదారుకి వైర్‌లెస్ అత్యవసర హెచ్చరిక సెట్టింగ్‌లు అందుబాటులో లేవు"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"సరే"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"మునుపటి అలర్ట్‌లు లేవు"</string>
@@ -48,7 +50,7 @@
     <string name="cmas_severe_alert" msgid="4135809475315826913">"అత్యవసర హెచ్చరిక: తీవ్రం"</string>
     <string name="cmas_amber_alert" msgid="6154867710264778887">"పిల్లల అపహరణ (ఆంబర్ హెచ్చరిక)"</string>
     <string name="cmas_required_monthly_test" msgid="1890205712251132193">"నెలవారీ పరీక్ష అవసరం"</string>
-    <string name="cmas_exercise_alert" msgid="2892255514938370321">"అత్యవసర హెచ్చరిక (అభ్యాసం)"</string>
+    <string name="cmas_exercise_alert" msgid="2892255514938370321">"ఎమర్జెన్సీ అలర్ట్ (ప్రాక్టీస్)"</string>
     <string name="cmas_operator_defined_alert" msgid="8755372450810011476">"అత్యవసర హెచ్చరిక (ఆపరేటర్)"</string>
     <string name="cb_other_message_identifiers" msgid="5790068194529377210">"ప్రసార మెసేజ్‌లు"</string>
     <string name="public_safety_message" msgid="9119928798786998252">"ప్రజా భద్రత మెసేజ్‌"</string>
@@ -87,13 +89,13 @@
     <string name="enable_emergency_alerts_message_title" msgid="661894007489847468">"అత్యవసర హెచ్చరికలు"</string>
     <string name="enable_emergency_alerts_message_summary" msgid="7574617515441602546">"ప్రాణాంతకమైన సంఘటనల గురించి హెచ్చరించు"</string>
     <string name="enable_cmas_test_alerts_title" msgid="7194966927004755266">"టెస్ట్ అలర్ట్‌లు"</string>
-    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"భద్రతా అలర్ట్ సిస్టమ్ నుండి క్యారియర్ టెస్ట్‌లను, నెలవారీ టెస్ట్‌లను స్వీకరించండి"</string>
+    <string name="enable_cmas_test_alerts_summary" msgid="2083089933271720217">"సేఫ్టీ అలర్ట్ సిస్టమ్ పంపే క్యారియర్ టెస్ట్‌లను, నెలవారీ టెస్ట్‌లను పొందండి"</string>
     <!-- no translation found for enable_exercise_test_alerts_title (6030780598569873865) -->
     <skip />
-    <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"ఎమర్జెన్సీ అలర్ట్‌ను అందుకోండి: అభ్యాసం/డ్రిల్ మెసేజ్"</string>
+    <string name="enable_exercise_test_alerts_summary" msgid="4276766794979567304">"ఎమర్జెన్సీ అలర్ట్‌ను అందుకోండి: ప్రాక్టీస్/డ్రిల్ మెసేజ్"</string>
     <!-- no translation found for enable_operator_defined_test_alerts_title (7459219458579095832) -->
     <skip />
-    <string name="enable_operator_defined_test_alerts_summary" msgid="7856514354348843433">"ఎమర్జెన్సీ అలర్ట్‌ను స్వీకరించండి: ఆపరేటర్ నిర్వచించినవి"</string>
+    <string name="enable_operator_defined_test_alerts_summary" msgid="7856514354348843433">"ఎమర్జెన్సీ అలర్ట్‌ను అందుకోండి: ఆపరేటర్ సెట్ చేసినవి"</string>
     <string name="enable_alert_vibrate_title" msgid="5421032189422312508">"వైబ్రేషన్"</string>
     <string name="enable_alert_vibrate_summary" msgid="4733669825477146614"></string>
     <string name="override_dnd_title" msgid="5120805993144214421">"ఎల్లప్పుడూ పూర్తి వాల్యూమ్ వద్ద హెచ్చరించు"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index c80da71b6..25108d1af 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"การแจ้งเหตุฉุกเฉินแบบไร้สาย"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"การแจ้งเหตุฉุกเฉินแบบไร้สาย"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"การแจ้งเตือนข้อมูล"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"การตั้งค่าการแจ้งเหตุฉุกเฉินแบบไร้สายไม่พร้อมใช้งานสำหรับผู้ใช้รายนี้"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ตกลง"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"ไม่มีการแจ้งเตือนก่อนหน้านี้"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 7ba558a3a..31ed72a4b 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Mga wireless na alerto sa emergency"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Mga wireless na alerto sa emergency"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Notification ng impormasyon"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Hindi available ang mga wireless na alerto sa emergency para sa user na ito"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Walang nakaraang alerto"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index bdb54dcfd..6a70816d2 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Kablosuz acil durum uyarıları"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Kablosuz acil durum uyarıları"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Bilgilendirme amaçlı bildirim"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Kablosuz acil durum uyarısı ayarları bu kullanıcı için kullanılamaz"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"Tamam"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Henüz uyarı yok"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 4a6b7938c..771762a2d 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Бездротові екстрені сповіщення"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Бездротові екстрені сповіщення"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Інформаційне сповіщення"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Налаштування бездротових екстрених сповіщень недоступні для цього користувача"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Немає попередніх сповіщень"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index d3a36e416..5b4c23a38 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"وائرلیس ایمرجنسی الرٹس"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"وائرلیس ایمرجنسی الرٹس"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"معلوماتی اطلاع"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"اس صارف کے ليے وائرلیس ایمرجنسی الرٹ کی ترتیبات دستیاب نہیں ہیں"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"ٹھیک ہے"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"کوئی سابقہ الرٹس نہیں ہیں"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index 650b831c2..861595e69 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Aholini ogohlantirish"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Aholini ogohlantirish"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Axborotli bildirishnoma"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Simsiz tarmoqlar orqali favqulodda ogohlantirish sozlamalari bu foydalanuvchi uchun yopiq"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Hech qanday ogohlantirish topilmadi"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 72b25e182..f9cb37f61 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Cảnh báo khẩn cấp qua mạng không dây"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Cảnh báo khẩn cấp qua mạng không dây"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Thông báo cung cấp thông tin"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Người dùng này không được phép thay đổi các tùy chọn cài đặt cảnh báo khẩn cấp không dây"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"OK"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Không có cảnh báo nào trước đây"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 6a38e581f..210208cec 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"无线紧急警报"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"无线紧急警报"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"信息类通知"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"这位用户无法使用无线紧急警报设置"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"确定"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"还没有任何警报"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index c7c1b460a..99290efbe 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"無線緊急警示"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"無線緊急警示"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"資訊通知"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"此使用者無法使用無線緊急警示設定"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"確定"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"沒有任何過往警示"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 5b765fe5d..89eb76caf 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"無線緊急警報"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"無線緊急警報"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"資訊通知"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"這位使用者無法使用無線緊急警報設定"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"確定"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"先前沒有任何警報"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 09738df4d..de0a9f603 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -22,6 +22,8 @@
     <string name="sms_cb_sender_name_presidential" msgid="5302753979711319380">"Izexwayiso zesimo esiphuthumayo ezingenantambo"</string>
     <string name="sms_cb_sender_name_emergency" msgid="2937067842997478965">"Izexwayiso zesimo esiphuthumayo ezingenantambo"</string>
     <string name="sms_cb_sender_name_public_safety" msgid="5230033387708907922">"Isaziso esingokolwazi"</string>
+    <!-- no translation found for sms_cb_sender_name_amber (9124939966591107501) -->
+    <skip />
     <string name="cell_broadcast_settings_not_available" msgid="3908142962162375221">"Izilungiselelo zesexwayiso esingenantambo sesimo esiphuthumayo azitholakaleli lo msebenzisi"</string>
     <string name="button_dismiss" msgid="1234221657930516287">"KULUNGILE"</string>
     <string name="no_cell_broadcasts" msgid="7554779730107421769">"Azikho izexwayiso zangaphambilini"</string>
diff --git a/res/values/config.xml b/res/values/config.xml
index d678715e7..02f780419 100644
--- a/res/values/config.xml
+++ b/res/values/config.xml
@@ -300,4 +300,7 @@
     positive. If they are not specified or invalid, default value will be 1s. -->
     <integer-array name="default_pulsation_pattern">
     </integer-array>
+
+    <!-- Whether to restore the sub-toggle setting to carrier default -->
+    <bool name="restore_sub_toggle_to_carrier_default">false</bool>
 </resources>
diff --git a/res/values/overlayable.xml b/res/values/overlayable.xml
index eda799bb2..ae9168faf 100644
--- a/res/values/overlayable.xml
+++ b/res/values/overlayable.xml
@@ -118,6 +118,8 @@
             <item type="string" name="sms_cb_sender_name_emergency" />
             <!-- Value of sms sender display name to be shown in SMS inbox for public safety alerts -->
             <item type="string" name="sms_cb_sender_name_public_safety" />
+            <!-- Value of sms sender display name to be shown in SMS inbox for amber alerts -->
+            <item type="string" name="sms_cb_sender_name_amber" />
             <item type="bool" name="enable_write_alerts_to_sms_inbox" />
             <item type="bool" name="always_mark_sms_read" />
 
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 355db0cb4..eed229cc9 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -39,6 +39,9 @@
     <!-- Required Korean (kr) translation for this message: 안전 안내 문자-->
     <string name="sms_cb_sender_name_public_safety">Informational notification</string>
 
+    <!-- Value of sms sender display name to be shown in SMS inbox for amber alerts -->
+    <string name="sms_cb_sender_name_amber">@string/sms_cb_sender_name_default</string>
+
     <!-- Error message for users that aren't allowed to modify Cell broadcast settings [CHAR LIMIT=none] -->
     <string name="cell_broadcast_settings_not_available">Wireless emergency alert settings are not available for this user</string>
 
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertAudio.java b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertAudio.java
index ca09a1e61..47c9ffa97 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertAudio.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertAudio.java
@@ -51,7 +51,6 @@ import android.os.Message;
 import android.os.SystemClock;
 import android.os.VibrationEffect;
 import android.os.Vibrator;
-import android.preference.PreferenceManager;
 import android.provider.Settings;
 import android.speech.tts.TextToSpeech;
 import android.telephony.PhoneStateListener;
@@ -60,6 +59,8 @@ import android.telephony.TelephonyManager;
 import android.text.TextUtils;
 import android.util.Log;
 
+import androidx.preference.PreferenceManager;
+
 import com.android.cellbroadcastreceiver.CellBroadcastAlertService.AlertType;
 import com.android.internal.annotations.VisibleForTesting;
 
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertDialog.java b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertDialog.java
index eef1825b9..e2076d161 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertDialog.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertDialog.java
@@ -47,7 +47,6 @@ import android.os.Bundle;
 import android.os.Handler;
 import android.os.Message;
 import android.os.PowerManager;
-import android.preference.PreferenceManager;
 import android.provider.Telephony;
 import android.telephony.SmsCbCmasInfo;
 import android.telephony.SmsCbMessage;
@@ -75,6 +74,8 @@ import android.widget.ImageView;
 import android.widget.TextView;
 import android.widget.Toast;
 
+import androidx.preference.PreferenceManager;
+
 import com.android.cellbroadcastreceiver.CellBroadcastChannelManager.CellBroadcastChannelRange;
 import com.android.internal.annotations.VisibleForTesting;
 
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertReminder.java b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertReminder.java
index bb2cebeb5..7bdbe19d1 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertReminder.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertReminder.java
@@ -37,10 +37,11 @@ import android.os.IBinder;
 import android.os.SystemClock;
 import android.os.VibrationEffect;
 import android.os.Vibrator;
-import android.preference.PreferenceManager;
 import android.telephony.SubscriptionManager;
 import android.util.Log;
 
+import androidx.preference.PreferenceManager;
+
 import com.android.internal.annotations.VisibleForTesting;
 
 /**
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java
index ea0ec547d..4d896ae87 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java
@@ -59,7 +59,6 @@ import android.os.Looper;
 import android.os.PowerManager;
 import android.os.SystemProperties;
 import android.os.UserHandle;
-import android.preference.PreferenceManager;
 import android.provider.Telephony;
 import android.service.notification.StatusBarNotification;
 import android.telephony.PhoneStateListener;
@@ -70,6 +69,8 @@ import android.text.TextUtils;
 import android.util.Log;
 import android.view.Display;
 
+import androidx.preference.PreferenceManager;
+
 import com.android.cellbroadcastreceiver.CellBroadcastChannelManager.CellBroadcastChannelRange;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.modules.utils.build.SdkLevel;
@@ -78,6 +79,7 @@ import java.util.ArrayList;
 import java.util.List;
 import java.util.Locale;
 import java.util.Set;
+import java.util.UUID;
 
 /**
  * This service manages the display and animation of broadcast messages.
@@ -385,10 +387,13 @@ public class CellBroadcastAlertService extends Service {
 
         if (message.getMessageFormat() == MESSAGE_FORMAT_3GPP) {
             CellBroadcastReceiverMetrics.getInstance().logMessageReported(mContext,
-                    RPT_GSM, SRC_CBR, message.getSerialNumber(), message.getServiceCategory());
+                    RPT_GSM, SRC_CBR, message.getSerialNumber(), message.getServiceCategory(),
+                    CellBroadcastReceiver.getRoamingOperatorSupported(mContext),
+                    message.getLanguageCode());
         } else if (message.getMessageFormat() == MESSAGE_FORMAT_3GPP2) {
             CellBroadcastReceiverMetrics.getInstance().logMessageReported(mContext,
-                    RPT_CDMA, SRC_CBR, message.getSerialNumber(), message.getServiceCategory());
+                    RPT_CDMA, SRC_CBR, message.getSerialNumber(), message.getServiceCategory(),
+                    "", "");
         }
 
         if (!shouldDisplayMessage(message)) {
@@ -1055,6 +1060,9 @@ public class CellBroadcastAlertService extends Service {
      */
     static Intent createMarkAsReadIntent(Context context, long deliveryTime, int notificationId) {
         Intent deleteIntent = new Intent(context, CellBroadcastInternalReceiver.class);
+        // The extras are used rather than the data payload. The data payload only needs to
+        // ensure uniqueness of the intent to prevent overwriting a previous notification intent.
+        deleteIntent.setData(Uri.parse("cbr://notification/" + UUID.randomUUID()));
         deleteIntent.setAction(CellBroadcastReceiver.ACTION_MARK_AS_READ);
         deleteIntent.putExtra(CellBroadcastReceiver.EXTRA_DELIVERY_TIME, deliveryTime);
         deleteIntent.putExtra(CellBroadcastReceiver.EXTRA_NOTIF_ID, notificationId);
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastConfigService.java b/src/com/android/cellbroadcastreceiver/CellBroadcastConfigService.java
index 4615d3084..78e31b68b 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastConfigService.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastConfigService.java
@@ -31,7 +31,6 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.SharedPreferences;
 import android.content.res.Resources;
-import android.preference.PreferenceManager;
 import android.telephony.CellBroadcastIdRange;
 import android.telephony.SmsManager;
 import android.telephony.SubscriptionInfo;
@@ -42,6 +41,7 @@ import android.util.Log;
 import android.util.Pair;
 
 import androidx.annotation.NonNull;
+import androidx.preference.PreferenceManager;
 
 import com.android.cellbroadcastreceiver.CellBroadcastChannelManager.CellBroadcastChannelRange;
 import com.android.internal.annotations.VisibleForTesting;
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java b/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java
index 642cfd85a..7169117c1 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java
@@ -192,7 +192,7 @@ public class CellBroadcastReceiver extends BroadcastReceiver {
                     intent.getParcelableArrayListExtra("program_data");
 
             CellBroadcastReceiverMetrics.getInstance().logMessageReported(mContext,
-                    RPT_SPC, SRC_CBR, 0, 0);
+                    RPT_SPC, SRC_CBR, 0, 0, "", "");
 
             if (programDataList != null) {
                 handleCdmaSmsCbProgramData(programDataList);
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastReceiverMetrics.java b/src/com/android/cellbroadcastreceiver/CellBroadcastReceiverMetrics.java
index 411bcbc1d..a735380aa 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastReceiverMetrics.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastReceiverMetrics.java
@@ -537,17 +537,17 @@ public class CellBroadcastReceiverMetrics {
      * @param context  : Context
      * @param type     : radio type
      * @param source   : layer of reported message
-     * @param serialNo : unique identifier of message
+     * @param serialNo : set 0 as deprecated
      * @param msgId    : service_category of message
      */
-    void logMessageReported(Context context, int type, int source, int serialNo, int msgId) {
+    void logMessageReported(Context context, int type, int source, int serialNo, int msgId,
+            String roamingOperator, String languageIndicator) {
         if (VDBG) {
-            Log.d(TAG,
-                    "logMessageReported : " + type + " " + source + " " + serialNo + " "
-                            + msgId);
+            Log.d(TAG, "logMessageReported : " + type + " " + source + " " + 0 + " "
+                            + msgId + " " + roamingOperator + " " + languageIndicator);
         }
         CellBroadcastModuleStatsLog.write(CellBroadcastModuleStatsLog.CB_MESSAGE_REPORTED,
-                type, source, serialNo, msgId);
+                type, source, 0, msgId, roamingOperator, languageIndicator);
     }
 
     /**
@@ -559,11 +559,11 @@ public class CellBroadcastReceiverMetrics {
     void logMessageFiltered(int filterType, SmsCbMessage msg) {
         int ratType = msg.getMessageFormat() == MESSAGE_FORMAT_3GPP ? FILTER_GSM : FILTER_CDMA;
         if (VDBG) {
-            Log.d(TAG, "logMessageFiltered : " + ratType + " " + filterType + " "
-                    + msg.getSerialNumber() + " " + msg.getServiceCategory());
+            Log.d(TAG, "logMessageFiltered : " + ratType + " " + filterType + " " + 0 + " "
+                    + msg.getServiceCategory());
         }
         CellBroadcastModuleStatsLog.write(CellBroadcastModuleStatsLog.CB_MESSAGE_FILTERED,
-                ratType, filterType, msg.getSerialNumber(), msg.getServiceCategory());
+                ratType, filterType, 0, msg.getServiceCategory());
     }
 
     /**
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastResources.java b/src/com/android/cellbroadcastreceiver/CellBroadcastResources.java
index 61512048b..4bebc75be 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastResources.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastResources.java
@@ -320,6 +320,8 @@ public class CellBroadcastResources {
             return R.string.sms_cb_sender_name_emergency;
         } else if (resourcesKey == R.array.public_safety_messages_channels_range_strings) {
             return R.string.sms_cb_sender_name_public_safety;
+        } else if (resourcesKey == R.array.cmas_amber_alerts_channels_range_strings) {
+            return R.string.sms_cb_sender_name_amber;
         }
 
         return R.string.sms_cb_sender_name_default;
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastSearchIndexableProvider.java b/src/com/android/cellbroadcastreceiver/CellBroadcastSearchIndexableProvider.java
index 94ee90293..e6c5ec553 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastSearchIndexableProvider.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastSearchIndexableProvider.java
@@ -65,7 +65,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
     };
 
     @VisibleForTesting
-    public static final SearchIndexableResource[] INDEXABLE_RES = new SearchIndexableResource[] {
+    public static final SearchIndexableResource[] INDEXABLE_RES = new SearchIndexableResource[]{
             new SearchIndexableResource(1, R.xml.preferences,
                     CellBroadcastSettings.class.getName(),
                     R.mipmap.ic_launcher_cell_broadcast),
@@ -74,6 +74,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
     /**
      * this method is to make this class unit-testable, because super.getContext() is a final
      * method and therefore not mockable
+     *
      * @return context
      */
     @VisibleForTesting
@@ -84,6 +85,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
     /**
      * this method is to make this class unit-testable, because
      * CellBroadcastSettings.getResourcesForDefaultSubId() is a static method and cannot be stubbed.
+     *
      * @return resources
      */
     @VisibleForTesting
@@ -94,6 +96,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
     /**
      * this method is to make this class unit-testable, because
      * CellBroadcastSettings.isTestAlertsToggleVisible is a static method and therefore not mockable
+     *
      * @return true if test alerts toggle is Visible
      */
     @VisibleForTesting
@@ -101,6 +104,18 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
         return CellBroadcastSettings.isTestAlertsToggleVisible(getContextMethod());
     }
 
+    /**
+     * this method is to make this class unit-testable, because
+     * CellBroadcastSettings.isShowFullScreenMessageVisible is a static method and therefore not
+     * able to mock
+     *
+     * @return true if show full screen toggle is Visible
+     */
+    @VisibleForTesting
+    public boolean isShowFullScreenMessageVisible(Resources res) {
+        return CellBroadcastSettings.isShowFullScreenMessageVisible(getContextMethod(), res);
+    }
+
     @Override
     public boolean onCreate() {
         return true;
@@ -193,7 +208,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
         }
 
         if (!CellBroadcastSettings.getResources(getContextMethod(),
-                SubscriptionManager.DEFAULT_SUBSCRIPTION_ID)
+                        SubscriptionManager.DEFAULT_SUBSCRIPTION_ID)
                 .getBoolean(R.bool.show_alert_speech_setting)) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
@@ -268,7 +283,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
         if (!isTestAlertsToggleVisible()) {
             ref = new Object[1];
             ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
-                CellBroadcastSettings.KEY_ENABLE_TEST_ALERTS;
+                    CellBroadcastSettings.KEY_ENABLE_TEST_ALERTS;
             cursor.addRow(ref);
         }
 
@@ -288,11 +303,19 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
             cursor.addRow(ref);
         }
 
+        if (!isShowFullScreenMessageVisible(res)) {
+            ref = new Object[1];
+            ref[COLUMN_INDEX_NON_INDEXABLE_KEYS_KEY_VALUE] =
+                    CellBroadcastSettings.KEY_ENABLE_PUBLIC_SAFETY_MESSAGES_FULL_SCREEN;
+            cursor.addRow(ref);
+        }
+
         return cursor;
     }
 
     /**
      * Whether or not this is an Android Automotive platform.
+     *
      * @return true if the current platform is automotive
      */
     @VisibleForTesting
@@ -303,6 +326,7 @@ public class CellBroadcastSearchIndexableProvider extends SearchIndexablesProvid
 
     /**
      * Check disable Cell Broadcast resource.
+     *
      * @return true if Cell Broadcast disable configured by OEM.
      */
     @VisibleForTesting
diff --git a/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java b/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java
index f5484e24c..106a28406 100644
--- a/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java
+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastSettings.java
@@ -661,9 +661,7 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
             // public safety toggle is displayed.
             if (mPublicSafetyMessagesChannelFullScreenCheckBox != null) {
                 mPublicSafetyMessagesChannelFullScreenCheckBox.setVisible(
-                        res.getBoolean(R.bool.show_public_safety_full_screen_settings)
-                                && (mPublicSafetyMessagesChannelCheckBox != null
-                                && mPublicSafetyMessagesChannelCheckBox.isVisible()));
+                        isShowFullScreenMessageVisible(getContext(), res));
             }
 
             if (mTestCheckBox != null) {
@@ -823,50 +821,75 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
             }
         }
 
-        private void setAlertsEnabled(boolean alertsEnabled) {
+        /**
+         * Enable the toggles to set it on/off or carrier default.
+         */
+        @VisibleForTesting
+        public void setAlertsEnabled(boolean alertsEnabled) {
             Resources res = CellBroadcastSettings.getResourcesForDefaultSubId(getContext());
 
+            boolean resetCarrierDefault = res.getBoolean(
+                    R.bool.restore_sub_toggle_to_carrier_default);
+
             if (mSevereCheckBox != null) {
                 mSevereCheckBox.setEnabled(alertsEnabled);
-                mSevereCheckBox.setChecked(alertsEnabled);
+                mSevereCheckBox.setChecked(resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                        R.bool.severe_threat_alerts_enabled_default) : alertsEnabled);
             }
             if (!res.getBoolean(R.bool.disable_extreme_alert_settings)
                     && mExtremeCheckBox != null) {
                 mExtremeCheckBox.setEnabled(alertsEnabled);
-                mExtremeCheckBox.setChecked(alertsEnabled);
+                mExtremeCheckBox.setChecked(resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                        R.bool.extreme_threat_alerts_enabled_default) : alertsEnabled);
             }
             if (mAmberCheckBox != null) {
                 mAmberCheckBox.setEnabled(alertsEnabled);
-                mAmberCheckBox.setChecked(alertsEnabled);
+                mAmberCheckBox.setChecked(resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                        R.bool.amber_alerts_enabled_default) : alertsEnabled);
             }
             if (mAreaUpdateInfoCheckBox != null) {
                 mAreaUpdateInfoCheckBox.setEnabled(alertsEnabled);
-                mAreaUpdateInfoCheckBox.setChecked(alertsEnabled);
-                notifyAreaInfoUpdate(alertsEnabled);
+                mAreaUpdateInfoCheckBox.setChecked(
+                        resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                                R.bool.area_update_info_alerts_enabled_default) : alertsEnabled);
+                notifyAreaInfoUpdate(resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                        R.bool.area_update_info_alerts_enabled_default) : alertsEnabled);
             }
             if (mEmergencyAlertsCheckBox != null) {
                 mEmergencyAlertsCheckBox.setEnabled(alertsEnabled);
-                mEmergencyAlertsCheckBox.setChecked(alertsEnabled);
+                mEmergencyAlertsCheckBox.setChecked(
+                        resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                                R.bool.emergency_alerts_enabled_default) : alertsEnabled);
             }
             if (mPublicSafetyMessagesChannelCheckBox != null) {
                 mPublicSafetyMessagesChannelCheckBox.setEnabled(alertsEnabled);
-                mPublicSafetyMessagesChannelCheckBox.setChecked(alertsEnabled);
+                mPublicSafetyMessagesChannelCheckBox.setChecked(
+                        resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                                R.bool.public_safety_messages_enabled_default) : alertsEnabled);
             }
             if (mStateLocalTestCheckBox != null) {
                 mStateLocalTestCheckBox.setEnabled(alertsEnabled);
-                mStateLocalTestCheckBox.setChecked(alertsEnabled);
+                mStateLocalTestCheckBox.setChecked(
+                        resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                                R.bool.state_local_test_alerts_enabled_default) : alertsEnabled);
             }
             if (mTestCheckBox != null) {
                 mTestCheckBox.setEnabled(alertsEnabled);
-                mTestCheckBox.setChecked(alertsEnabled);
+                mTestCheckBox.setChecked(resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                        R.bool.test_alerts_enabled_default) : alertsEnabled);
             }
             if (mExerciseTestCheckBox != null) {
                 mExerciseTestCheckBox.setEnabled(alertsEnabled);
-                mExerciseTestCheckBox.setChecked(alertsEnabled);
+                mExerciseTestCheckBox.setChecked(
+                        resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                                R.bool.test_exercise_alerts_enabled_default) : alertsEnabled);
             }
             if (mOperatorDefinedCheckBox != null) {
                 mOperatorDefinedCheckBox.setEnabled(alertsEnabled);
-                mOperatorDefinedCheckBox.setChecked(alertsEnabled);
+                mOperatorDefinedCheckBox.setChecked(
+                        resetCarrierDefault ? alertsEnabled && res.getBoolean(
+                                R.bool.test_operator_defined_alerts_enabled_default)
+                                : alertsEnabled);
             }
         }
 
@@ -921,6 +944,29 @@ public class CellBroadcastSettings extends CollapsingToolbarBaseActivity {
         return isVibrationToggleVisible;
     }
 
+    /**
+     * Check whether show full screen message toggle is visible
+     *
+     * @param context Context
+     * @param res     resources
+     * @return {@code true} if it needs to show, {@code false} otherwise
+     */
+    public static boolean isShowFullScreenMessageVisible(Context context, Resources res) {
+        // The settings should be based on the config by the subscription
+        CellBroadcastChannelManager channelManager = new CellBroadcastChannelManager(
+                context, SubscriptionManager.getDefaultSubscriptionId(), null);
+
+        if (res.getBoolean(R.bool.show_public_safety_settings)
+                && !channelManager.getCellBroadcastChannelRanges(
+                R.array.public_safety_messages_channels_range_strings).isEmpty()
+                && res.getBoolean(R.bool.show_public_safety_full_screen_settings)) {
+            Log.d(TAG, "isShowFullScreenMessageVisible : true");
+            return true;
+        }
+        Log.d(TAG, "isShowFullScreenMessageVisible : false");
+        return false;
+    }
+
     public static boolean isTestAlertsToggleVisible(Context context) {
         return isTestAlertsToggleVisible(context, null);
     }
diff --git a/tests/compliancetests/Android.bp b/tests/compliancetests/Android.bp
index 60a5a68bd..22dd98576 100644
--- a/tests/compliancetests/Android.bp
+++ b/tests/compliancetests/Android.bp
@@ -20,10 +20,10 @@ package {
 java_defaults {
     name: "CellBroadcastTestCommonComplianceTest",
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "telephony-common",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
     static_libs: [
         "androidx.test.rules",
diff --git a/tests/compliancetests/assets/emergency_alert_channels.json b/tests/compliancetests/assets/emergency_alert_channels.json
index ea4bd3d81..fe2915b91 100644
--- a/tests/compliancetests/assets/emergency_alert_channels.json
+++ b/tests/compliancetests/assets/emergency_alert_channels.json
@@ -168,6 +168,11 @@
       "title": "Exercise", // 'Øvelse' == 'Exercise'
       "default_value": "false",
       "toggle_avail": "true"
+    },
+    "4400": {
+      "title": "",
+      "default_value": "true",
+      "toggle_avail": "false"
     }
   },
   "peru_entel": {
@@ -271,10 +276,11 @@
       "toggle_avail": "false",
       "warning_type": "02"
     },
-    "43016": {
+    "4356": {
       "title": "緊急速報メール", //"Emergency alert",
       "default_value": "true",
-      "toggle_avail": "false"
+      "toggle_avail": "false",
+      "warning_type": "08"
     },
     "4370": {
       "title": "国家レベルの警報", //"Presidential alert",
@@ -976,57 +982,57 @@
       "toggle_avail": "false"
     },
     "4370": {
-      "title": "Extreme Emergency Alert", //"위급 재난문자",
+      "title": "위급 재난문자", //"Extreme Emergency Alert",
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4383": {
-      "title": "Extreme Emergency Alert", //"위급 재난문자",
+      "title": "위급 재난문자", //"Extreme Emergency Alert",
       "default_value": "true",
       "toggle_avail": "false",
       "filter_language": "language_setting"
     },
     "4371": {
-      "title": "Emergency Alert", //"긴급 재난문자",
+      "title": "긴급 재난문자", //"Emergency Alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4384": {
-      "title": "Emergency Alert", //"긴급 재난문자",
+      "title": "긴급 재난문자", //"Emergency Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "filter_language": "language_setting"
     },
     "4372": {
-      "title": "Public Safety Alert", //"안전 안내문자",
+      "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4373": {
-      "title": "Public Safety Alert", //"안전 안내문자",
+      "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "4378"
     },
     "4385": {
-      "title": "Public Safety Alert", //"안전 안내문자",
+      "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "filter_language": "language_setting"
     },
     "4379": {
-      "title": "Amber Alert", //"실종 경보문자",
+      "title": "실종 경보문자", //"Amber Alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4392": {
-      "title": "Amber Alert", //"실종 경보문자",
+      "title": "실종 경보문자", //"Amber Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "filter_language": "language_setting"
     },
     "40960": {
-      "title": "Public Safety Alert", //"안전 안내문자",
+      "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "45055",
@@ -1051,57 +1057,57 @@
       "toggle_avail": "false"
     },
     "4370": {
-      "title": "Extreme Emergency Alert", //"위급 재난문자",
+      "title": "위급 재난문자", //"Extreme Emergency Alert",
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4383": {
-      "title": "Extreme Emergency Alert", //"위급 재난문자",
+      "title": "위급 재난문자", //"Extreme Emergency Alert",
       "default_value": "true",
       "toggle_avail": "false",
       "filter_language": "language_setting"
     },
     "4371": {
-      "title": "Emergency Alert", //"긴급 재난문자",
+      "title": "긴급 재난문자", //"Emergency Alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4384": {
-      "title": "Emergency Alert", //"긴급 재난문자",
+      "title": "긴급 재난문자", //"Emergency Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "filter_language": "language_setting"
     },
     "4372": {
-      "title": "Public Safety Alert", //"안전 안내문자",
+      "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4373": {
-      "title": "Public Safety Alert", //"안전 안내문자",
+      "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "4378"
     },
     "4379": {
-      "title": "Amber Alert", //"실종 경보문자",
+      "title": "실종 경보문자", //"Amber Alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4392": {
-      "title": "Amber Alert", //"실종 경보문자",
+      "title": "실종 경보문자", //"Amber Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "filter_language": "language_setting"
     },
     "4385": {
-      "title": "Public Safety Alert", //"안전 안내문자",
+      "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "filter_language": "language_setting"
     },
     "40960": {
-      "title": "Public Safety Message", //"안전 안내문자",
+      "title": "안전 안내문자", //"Public Safety Message",
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "45055",
@@ -1126,57 +1132,57 @@
       "toggle_avail": "false"
     },
     "4370": {
-      "title": "Extreme Emergency Alert", //"위급 재난문자",
+      "title": "위급 재난문자", //"Extreme Emergency Alert",
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4383": {
-      "title": "Extreme Emergency Alert", //"위급 재난문자",
+      "title": "위급 재난문자", //"Extreme Emergency Alert",
       "default_value": "true",
       "toggle_avail": "false",
       "filter_language": "language_setting"
     },
     "4371": {
-      "title": "Emergency Alert", //"긴급 재난문자",
+      "title": "긴급 재난문자", //"Emergency Alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4384": {
-      "title": "Emergency Alert", //"긴급 재난문자",
+      "title": "긴급 재난문자", //"Emergency Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "filter_language": "language_setting"
     },
     "4372": {
-      "title": "Public Safety Alert", //"안전 안내문자",
+      "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4373": {
-      "title": "Public Safety Alert", //"안전 안내문자",
+      "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "4378"
     },
     "4379": {
-      "title": "Amber Alert", //"실종 경보문자",
+      "title": "실종 경보문자", //"Amber Alert",
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4392": {
-      "title": "Amber Alert", //"실종 경보문자",
+      "title": "실종 경보문자", //"Amber Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "filter_language": "language_setting"
     },
     "4385": {
-      "title": "Public Safety Alert", //"안전 안내문자",
+      "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "filter_language": "language_setting"
     },
     "40960": {
-      "title": "Public Safety Alert", //"안전 안내문자",
+      "title": "안전 안내문자", //"Public Safety Alert",
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "45055",
@@ -1522,58 +1528,88 @@
   },
   "bulgaria": {
     "4370": {
-      "title": "BG-ALERT: Emergency Alert",
+      "title": "BG-ALERT: Emergency Alert",  // BG-ALERT: Внимание, опасност!
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4383": {
-      "title": "BG-ALERT: Emergency Alert",
+      "title": "BG-ALERT: Emergency Alert", // BG-ALERT: Внимание, опасност!
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4371": {
-      "title": "BG-ALERT: Warning",
+      "title": "BG-ALERT: Warning", // BG-ALERT: Предупреждение
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "4372"
     },
     "4384": {
-      "title": "BG-ALERT: Warning",
+      "title": "BG-ALERT: Warning", // BG-ALERT: Предупреждение
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "4385"
     },
     "4373": {
-      "title": "BG-ALERT: Information",
+      "title": "BG-ALERT: Information", // BG-ALERT: Информация
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "4378"
     },
     "4386": {
-      "title": "BG-ALERT: Information",
+      "title": "BG-ALERT: Information", // BG-ALERT: Информация
       "default_value": "true",
       "toggle_avail": "true",
       "end_channel": "4391"
     },
     "4379": {
-      "title": "BG-ALERT: Missing Person Alert",
+      "title": "BG-ALERT: Missing Person Alert", // BG-ALERT: Човек в неизвестност
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4392": {
-      "title": "BG-ALERT: Missing Person Alert",
+      "title": "BG-ALERT: Missing Person Alert", // BG-ALERT: Човек в неизвестност
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4380": {
-      "title": "BG-ALERT: Test alert",
+      "title": "BG-ALERT: Test alert", // BG-ALERT: Тестово съобщение
       "default_value": "false",
       "toggle_avail": "true"
     },
     "4393": {
-      "title": "BG-ALERT: Test alert",
+      "title": "BG-ALERT: Test alert", // BG-ALERT: Тестово съобщение
       "default_value": "false",
       "toggle_avail": "true"
+    },
+    "4381": {
+      "title": "BG-ALERT: Exercise", // BG-ALERT: Упражнение
+      "default_value": "false",
+      "toggle_avail": "false"
+    },
+    "4394": {
+      "title": "BG-ALERT: Exercise", // BG-ALERT: Упражнение
+      "default_value": "false",
+      "toggle_avail": "false"
+    },
+    "4382": {
+      "title": "BG-ALERT: Reserved", // BG-ALERT: Резервиран
+      "default_value": "false",
+      "toggle_avail": "false"
+    },
+    "4395": {
+      "title": "BG-ALERT: Reserved", // BG-ALERT: Резервиран
+      "default_value": "false",
+      "toggle_avail": "false"
+    },
+    "4398": {
+      "title": "BG-ALERT: Technical test", // BG-ALERT: Резервиран
+      "default_value": "false",
+      "toggle_avail": "false"
+    },
+    "4399": {
+      "title": "BG-ALERT: Technical test", // BG-ALERT: Технически тест
+      "default_value": "false",
+      "toggle_avail": "false"
     }
   },
   "estonia": {
@@ -2299,19 +2335,13 @@
     }
   },
   "saudiarabia": {
-    "4352": {
-      "title": "",
-      "default_value": "true",
-      "toggle_avail": "false",
-      "end_channel": "4354"
-    },
-    "4356": {
+    "4355": {
       "title": "",
-      "default_value": "true",
-      "toggle_avail": "false"
+      "default_value": "false",
+      "toggle_avail": "true"  // test_mode
     },
     "4370": {
-      "title": "تنبيهات على المستوى الوطني",
+      "title": "الرسائل التحذيرية الوطنية",
       "default_value": "true",
       "toggle_avail": "false"
     },
@@ -2321,7 +2351,7 @@
       "toggle_avail": "false"
     },
     "4371": {
-      "title": "تنبيهات طوارئ قصوى",
+      "title": "الرسائل التحذيرية الطارئة جدًا",
       "default_value": "true",
       "toggle_avail": "false",
       "end_channel": "4372"
@@ -2333,7 +2363,7 @@
       "end_channel": "4385"
     },
     "4373": {
-      "title": "تنبيهات الطوارئ",
+      "title": "الرسائل التحذيرية الطارئة",
       "default_value": "true",
       "toggle_avail": "false",
       "end_channel": "4378"
@@ -2345,7 +2375,7 @@
       "end_channel": "4391"
     },
     "4379": {
-      "title": "التنبيهات",
+      "title": "الرسائل التحذيرية",
       "default_value": "true",
       "toggle_avail": "true"
     },
@@ -2355,7 +2385,7 @@
       "toggle_avail": "true"
     },
     "4380": {
-      "title": "تنبيهات الاختبار",
+      "title": "الرسائل التجريبية",
       "default_value": "false",
       "toggle_avail": "true"
     },
@@ -2365,7 +2395,7 @@
       "toggle_avail": "true"
     },
     "4381": {
-      "title": "تدريبات",
+      "title": "تمارين",
       "default_value": "true",
       "toggle_avail": "false"
     },
@@ -4429,77 +4459,77 @@
   },
   "austria_tmobile": {
     "4370": {
-      "title": "Emergency alarm",
+      "title": "Emergency alert", //Notfallalarm
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4383": {
-      "title": "Emergency alarm",
+      "title": "Emergency alert", //Notfallalarm
       "default_value": "true",
       "toggle_avail": "false"
     },
     "919": {
-      "title": "Emergency alarm",
+      "title": "Emergency alert", //Notfallalarm
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4372": {
-      "title": "Extreme threat",
+      "title": "Extreme threat", //Extreme Gefahr
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4385": {
-      "title": "Extreme threat",
+      "title": "Extreme threat", //Extreme Gefahr
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4378": {
-      "title": "Severe threat",
+      "title": "Severe threat", //Erhebliche Gefahr
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4391": {
-      "title": "Severe threat",
+      "title": "Severe threat", //Erhebliche Gefahr
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4396": {
-      "title": "Threat information",
+      "title": "Threat information", // Gefahreninformation
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4397": {
-      "title": "Threat information",
+      "title": "Threat information", //Gefahreninformation
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4379": {
-      "title": "Search for missing person",
+      "title": "Search for missing person", //Suche nach abgängiger Person
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4392": {
-      "title": "Search for missing person",
+      "title": "Search for missing person", //Suche nach abgängiger Person
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4380": {
-      "title": "Cell Broadcast Test",
+      "title": "Cell Broadcast Test", //Cell Broadcast Test
       "default_value": "false",
       "toggle_avail": "false"
     },
     "4393": {
-      "title": "Cell Broadcast Test",
+      "title": "Cell Broadcast Test", //Cell Broadcast Test
       "default_value": "false",
       "toggle_avail": "false"
     },
     "4381": {
-      "title": "Test alarm",
+      "title": "Test alarm", //Übungsalarm
       "default_value": "false",
       "toggle_avail": "false"
     },
     "4394": {
-      "title": "Test alarm",
+      "title": "Test alarm", //Übungsalarm
       "default_value": "false",
       "toggle_avail": "false"
     }
@@ -4809,72 +4839,72 @@
   },
   "Luxembourg": {
     "4370": {
-      "title": "LU-Alert",
+      "title": "LU-Alert",  // LU-Alert
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4383": {
-      "title": "LU-Alert",
+      "title": "LU-Alert", // LU-Alert
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4371": {
-      "title": "LU-Alert",
+      "title": "LU-Alert", // LU-Alert
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4384": {
-      "title": "LU-Alert",
+      "title": "LU-Alert", // LU-Alert
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4375": {
-      "title": "LU-Alert",
+      "title": "LU-Alert", // LU-Alert
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4388": {
-      "title": "LU-Alert",
+      "title": "LU-Alert", // LU-Alert
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4396": {
-      "title": "LU-Alert",
+      "title": "LU-Alert", // LU-Alert
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4397": {
-      "title": "LU-Alert",
+      "title": "LU-Alert", // LU-Alert
       "default_value": "true",
       "toggle_avail": "false"
     },
     "4379": {
-      "title": "LU-Alert : Kidnapping alert",
+      "title": "LU-Alert : Kidnapping alert", // LU-Alert : Entführungswarnung
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4392": {
-      "title": "LU-Alert : Kidnapping alert",
+      "title": "LU-Alert : Kidnapping alert", // LU-Alert : Entführungswarnung
       "default_value": "true",
       "toggle_avail": "true"
     },
     "4380": {
-      "title": "LU-Alert Test",
+      "title": "LU-Alert Test", // LU-Alert Test
       "default_value": "false",
       "toggle_avail": "true"
     },
     "4393": {
-      "title": "LU-Alert Test",
+      "title": "LU-Alert Test", // LU-Alert Test
       "default_value": "false",
       "toggle_avail": "true"
     },
     "4381": {
-      "title": "LU-Alert Exercise",
+      "title": "LU-Alert Exercise", // LU-Alert Übung
       "default_value": "false",
       "toggle_avail": "true"
     },
     "4394": {
-      "title": "LU-Alert Exercise",
+      "title": "LU-Alert Exercise", // LU-Alert Übung
       "default_value": "false",
       "toggle_avail": "true"
     }
diff --git a/tests/compliancetests/assets/emergency_alert_settings.json b/tests/compliancetests/assets/emergency_alert_settings.json
index e89f5b191..6c85f06a9 100644
--- a/tests/compliancetests/assets/emergency_alert_settings.json
+++ b/tests/compliancetests/assets/emergency_alert_settings.json
@@ -412,59 +412,67 @@
     }
   },
   "korea": {
-    "Emergency Alert": { //"긴급 재난문자": {
+    "긴급 재난문자": { //"Emergency Alert"
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Public Safety Alert": { // "안전 안내문자": {
+    "안전 안내문자": { // "Public Safety Alert"
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Amber Alert": { // "실종 안내문자": {
+    "실종 경보문자": { // "Amber Alert"
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Vibration": { //"진동": {
+    "진동": { //"Vibration"
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Speak alert message": { //"경보 메시지를 음성으로 알림": {
+    "경보 메시지를 음성으로 알림": { //"Speak alert message"
       "default_value": "false",
       "toggle_avail": "true"
     }
   },
   "korea_skt": {
-    "Emergency Alert": { //"긴급 재난문자": {
+    "긴급 재난문자": { //"Emergency Alert"
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Amber Alert": { // "실종 안내문자": {
+    "안전 안내문자": { // "Public Safety Alert"
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Vibration": { //"진동": {
+    "실종 경보문자": { // "Amber Alert"
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Speak alert message": { //"경보 메시지를 음성으로 알림": {
+    "진동": { //"Vibration"
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "경보 메시지를 음성으로 알림": { //"Speak alert message"
       "default_value": "false",
       "toggle_avail": "true"
     }
   },
   "korea_lgu": {
-    "Emergency Alert": { //"긴급 재난문자": {
+    "긴급 재난문자": { //"Emergency Alert"
+      "default_value": "true",
+      "toggle_avail": "true"
+    },
+    "안전 안내문자": { // "Public Safety Alert"
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Amber Alert": { // "실종 안내문자": {
+    "실종 경보문자": { // "Amber Alert"
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Vibration": { //"진동": {
+    "진동": { //"Vibration"
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Speak alert message": { //"경보 메시지를 음성으로 알림": {
+    "경보 메시지를 음성으로 알림": { //"Speak alert message"
       "default_value": "false",
       "toggle_avail": "true"
     }
@@ -514,28 +522,40 @@
     }
   },
   "bulgaria": {
-    "Extreme and Severe Threats": {
+    "Extreme and Severe Threats": { // Сериозни опасности
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Information": {
+    "Information": { // Информация
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Missing Person Alerts": {
+    "Missing Person Alerts": { // Сигнали за човек в неизвестност
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "Test Alerts": {
+    "Test Alerts": { // Тестови сигнали
       "default_value": "false",
       "toggle_avail": "true"
     },
+    "Exercise Alerts": { // Сигнали за упражнения
+      "default_value": "false",
+      "toggle_avail": "false"
+    },
+    "EU-Reserved": { // EU-Reserved
+      "default_value": "false",
+      "toggle_avail": "false"
+    },
+    "Technical Test Alerts": { // Технически тестови сигнали
+      "default_value": "false",
+      "toggle_avail": "false"
+    },
     "Vibration": {
       "default_value": "true",
       "toggle_avail": "true"
     },
     "Speak alert message": {
-      "default_value": "true",
+      "default_value": "false",
       "toggle_avail": "true"
     }
   },
@@ -1331,19 +1351,19 @@
     }
   },
   "Luxembourg": {
-    "Kidnapping Alert": {
+    "Kidnapping alert": {  // Entführungswarnung
       "default_value": "true",
       "toggle_avail": "true"
     },
-    "LU-Alert Test": {
+    "LU-Alert Test": {  // LU-Alert Test
       "default_value": "false",
       "toggle_avail": "true"
     },
-    "LU-Alert Exercise": {
+    "LU-Alert Exercise": { // LU-Alert Übung
       "default_value": "false",
       "toggle_avail": "true"
     },
-    "Vibration": {
+    "Vibration": {  // Vibration
       "default_value": "true",
       "toggle_avail": "true"
     }
diff --git a/tests/compliancetests/assets/region_plmn_list.json b/tests/compliancetests/assets/region_plmn_list.json
index 3b25df339..79c500439 100644
--- a/tests/compliancetests/assets/region_plmn_list.json
+++ b/tests/compliancetests/assets/region_plmn_list.json
@@ -20,7 +20,7 @@
     "imsi": "424030123456789"
   },
   "japan_kddi": {
-    "mccmnc": ["44050", "44051", "44052"],
+    "mccmnc": ["44050", "44051", "44052", "44054"],
     "imsi": "440500123456789",
     "language": "ja",
     "check_setting_with_main_lang": "false",
@@ -105,15 +105,18 @@
   },
   "korea": {
     "mccmnc": ["45002"],
-    "imsi": "450020123456789"
+    "imsi": "450020123456789",
+    "language": "ko"
   },
   "korea_skt": {
     "mccmnc": ["45005"],
-    "imsi": "450050123456789"
+    "imsi": "450050123456789",
+    "language": "ko"
   },
   "korea_lgu": {
     "mccmnc": ["45006"],
-    "imsi": "450060123456789"
+    "imsi": "450060123456789",
+    "language": "ko"
   },
   "canada": {
     "mccmnc": ["302720"],
diff --git a/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java b/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java
index ab83c58ba..d805fc2e0 100644
--- a/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java
+++ b/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastBaseTest.java
@@ -20,6 +20,7 @@ import static org.junit.Assert.assertTrue;
 import static org.junit.Assume.assumeTrue;
 
 import android.app.Instrumentation;
+import android.app.UiAutomation;
 import android.content.BroadcastReceiver;
 import android.content.Context;
 import android.content.Intent;
@@ -31,6 +32,7 @@ import android.os.HandlerThread;
 import android.os.SystemProperties;
 import android.support.test.uiautomator.UiDevice;
 import android.telephony.ServiceState;
+import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyCallback;
 import android.telephony.TelephonyManager;
@@ -72,9 +74,7 @@ public class CellBroadcastBaseTest {
     protected static int sPreconditionError = 0;
     protected static final int ERROR_SDK_VERSION = 1;
     protected static final int ERROR_NO_TELEPHONY = 2;
-    protected static final int ERROR_MULTI_SIM = 3;
-    protected static final int ERROR_MOCK_MODEM_DISABLE = 4;
-    protected static final int ERROR_INVALID_SIM_SLOT_INDEX_ERROR = 5;
+    protected static final int ERROR_MOCK_MODEM_DISABLE = 3;
 
     protected static final String ALLOW_MOCK_MODEM_PROPERTY = "persist.radio.allow_mock_modem";
     protected static final boolean DEBUG = !"user".equals(Build.TYPE);
@@ -132,6 +132,7 @@ public class CellBroadcastBaseTest {
             if (sInputMccMnc != null && sInputMccMnc.equals(mccmnc)) {
                 sSetChannelIsDone.countDown();
                 logd("wait is released");
+                addSubIdToBeRemoved(SubscriptionManager.getDefaultSubscriptionId());
             }
         }
 
@@ -159,15 +160,6 @@ public class CellBroadcastBaseTest {
             return;
         }
 
-        TelephonyManager tm =
-                (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
-        boolean isMultiSim = tm != null && tm.getPhoneCount() > 1;
-        if (isMultiSim) {
-            Log.i(TAG, "Not support Multi-Sim");
-            sPreconditionError = ERROR_MULTI_SIM;
-            return;
-        }
-
         if (!isMockModemAllowed()) {
             Log.i(TAG, "Mock Modem is not allowed");
             sPreconditionError = ERROR_MOCK_MODEM_DISABLE;
@@ -190,6 +182,7 @@ public class CellBroadcastBaseTest {
                             if (sInputMccMnc != null && sInputMccMnc.equals(mccMncOfIntent)) {
                                 sSetChannelIsDone.countDown();
                                 logd("wait is released");
+                                addSubIdToBeRemoved(SubscriptionManager.getDefaultSubscriptionId());
                             }
                         }
                     }
@@ -239,6 +232,10 @@ public class CellBroadcastBaseTest {
     public static void afterAllTests() throws Exception {
         logd("CellBroadcastBaseTest#afterAllTests()");
 
+        if (sIccIdForDummySub != null) {
+            deleteDummySubscriptionIds();
+        }
+
         if (sReceiver != null) {
             getContext().unregisterReceiver(sReceiver);
         }
@@ -361,16 +358,10 @@ public class CellBroadcastBaseTest {
             case ERROR_NO_TELEPHONY:
                 errorMessage = "Not have Telephony Feature";
                 break;
-            case ERROR_MULTI_SIM:
-                errorMessage = "Multi-sim is not supported in Mock Modem";
-                break;
             case ERROR_MOCK_MODEM_DISABLE:
                 errorMessage = "Please enable mock modem to run the test! The option can be "
                         + "updated in Settings -> System -> Developer options -> Allow Mock Modem";
                 break;
-            case ERROR_INVALID_SIM_SLOT_INDEX_ERROR:
-                errorMessage = "Error with invalid sim slot index";
-                break;
         }
         return errorMessage;
     }
@@ -424,4 +415,54 @@ public class CellBroadcastBaseTest {
             // do nothing
         }
     }
+
+    private static int sSubIdForDummySub;
+    private static String sIccIdForDummySub;
+    private static int sSubTypeForDummySub;
+
+    private static void addSubIdToBeRemoved(int subId) {
+        logd("addSubIdToBeRemoved, subId = " + subId
+                + " subIdToBeRemoved = " + sSubIdForDummySub);
+        deleteDummySubscriptionIds();
+        UiAutomation uiAutomation = sInstrumentation.getUiAutomation();
+        uiAutomation.adoptShellPermissionIdentity();
+        try {
+            SubscriptionManager subManager =
+                    getContext().getSystemService(SubscriptionManager.class);
+            SubscriptionInfo subInfo = subManager.getActiveSubscriptionInfo(subId);
+            sSubIdForDummySub = subId;
+            sIccIdForDummySub = subInfo.getIccId();
+            sSubTypeForDummySub = subInfo.getSubscriptionType();
+            logd("addSubIdToBeRemoved, subId = " + sSubIdForDummySub
+                    + " iccId=" + sIccIdForDummySub + " subType=" + sSubTypeForDummySub);
+        } catch (SecurityException e) {
+            logd("runWithShellPermissionIdentity exception = " + e);
+        } finally {
+            uiAutomation.dropShellPermissionIdentity();
+        }
+    }
+
+    private static void deleteDummySubscriptionIds() {
+        if (sIccIdForDummySub != null) {
+            UiAutomation uiAutomation = sInstrumentation.getUiAutomation();
+            uiAutomation.adoptShellPermissionIdentity();
+            try {
+                SubscriptionManager subManager =
+                        getContext().getSystemService(SubscriptionManager.class);
+                logd("deleteDummySubscriptionIds "
+                        + " subId =" + sSubIdForDummySub
+                        + " iccId=" + sIccIdForDummySub
+                        + " subType=" + sSubTypeForDummySub);
+                subManager.removeSubscriptionInfoRecord(sIccIdForDummySub, sSubTypeForDummySub);
+            } catch (SecurityException e) {
+                logd("runWithShellPermissionIdentity exception = " + e);
+            } catch (IllegalArgumentException e) {
+                logd("catch IllegalArgumentException during removing subscriptionId = " + e);
+            } catch (NullPointerException e) {
+                logd("catch NullPointerException during removing subscriptionId = " + e);
+            } finally {
+                uiAutomation.dropShellPermissionIdentity();
+            }
+        }
+    }
 }
diff --git a/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastUiTest.java b/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastUiTest.java
index 65d0339ba..b76fd792b 100644
--- a/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastUiTest.java
+++ b/tests/compliancetests/src/com/android/cellbroadcastreceiver/compliancetests/CellBroadcastUiTest.java
@@ -69,6 +69,10 @@ public class CellBroadcastUiTest extends CellBroadcastBaseTest {
     private static final int MESSAGE_ID_ETWS_TYPE = 0x1100; // 4352
     private static final String CELL_BROADCAST_LIST_ACTIVITY =
             "com.android.cellbroadcastreceiver.CellBroadcastSettings";
+    private static final BySelector SYSUI_FULL_SCREEN_DIALOG =
+            By.res("com.android.systemui", "immersive_cling_title");
+    private static final BySelector SYSUI_CLOSE_BUTTON =
+            By.res("com.android.systemui", "ok");
     private static final BySelector FULL_SCREEN_DIALOG =
             By.res("android:id/immersive_cling_title");
     private static final BySelector CLOSE_BUTTON =
@@ -373,15 +377,28 @@ public class CellBroadcastUiTest extends CellBroadcastBaseTest {
         UiObject2 viewObject = sDevice.wait(Until.findObject(FULL_SCREEN_DIALOG),
                 UI_TIMEOUT);
         if (viewObject != null) {
-            logd("Found full screen dialog, dismissing.");
-            UiObject2 okButton = sDevice.wait(Until.findObject(CLOSE_BUTTON), UI_TIMEOUT);
-            if (okButton != null) {
-                okButton.click();
-                return true;
+            return dismissFullScreenGuide(CLOSE_BUTTON);
+        } else {
+            logd("check systemui's fullscreen guide");
+            viewObject = sDevice.wait(Until.findObject(SYSUI_FULL_SCREEN_DIALOG), UI_TIMEOUT);
+            if (viewObject != null) {
+                return dismissFullScreenGuide(SYSUI_CLOSE_BUTTON);
             } else {
-                logd("Unable to dismiss full screen dialog");
+                logd("failed to find fullscreen guide");
+                return false;
             }
         }
+    }
+
+    private boolean dismissFullScreenGuide(BySelector closeButton) {
+        logd("Found full screen dialog, dismissing.");
+        UiObject2 okButton = sDevice.wait(Until.findObject(closeButton), UI_TIMEOUT);
+        if (okButton != null) {
+            okButton.click();
+            return true;
+        } else {
+            logd("Unable to dismiss full screen dialog");
+        }
         return false;
     }
 
diff --git a/tests/testapp/Android.bp b/tests/testapp/Android.bp
index f3c624d0d..a5b48c028 100644
--- a/tests/testapp/Android.bp
+++ b/tests/testapp/Android.bp
@@ -22,9 +22,9 @@ android_test {
     name: "CellBroadcastReceiverTests",
     // We only want this apk build for tests.
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "telephony-common",
-        "android.test.base",
+        "android.test.base.stubs.system",
     ],
     static_libs: [
     "junit",
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index 12d4acace..d09d94b03 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -21,10 +21,10 @@ package {
 java_defaults {
     name: "CellBroadcastTestCommon",
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "telephony-common",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
     static_libs: [
         "androidx.test.rules",
@@ -32,6 +32,7 @@ java_defaults {
         "androidx.test.uiautomator_uiautomator",
         "mockito-target-minus-junit4",
         "truth",
+        "cellbroadcastreceiver_flags_lib",
     ],
     // Include all test java files.
     srcs: [":cellbroadcastreceiver-shared-srcs-test"],
@@ -68,6 +69,7 @@ android_test {
         "modules-utils-build_system",
         "cellbroadcast-java-proto-lite",
         "CellBroadcastCommon",
+        "cellbroadcastreceiver_flags_lib",
     ],
     min_sdk_version: "30",
 }
@@ -84,6 +86,7 @@ android_test {
     ],
     manifest: "AndroidManifest.xml",
     test_config: "AndroidTest.xml",
+    min_sdk_version: "30",
 }
 
 android_test {
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertAudioTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertAudioTest.java
index 3d59fd714..e92cd647e 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertAudioTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertAudioTest.java
@@ -24,6 +24,7 @@ import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.atLeastOnce;
+import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.inOrder;
 import static org.mockito.Mockito.mock;
@@ -438,6 +439,7 @@ public class CellBroadcastAlertAudioTest extends
                 TEST_VIBRATION_PATTERN);
         doReturn(AudioManager.RINGER_MODE_NORMAL).when(
                 mMockedAudioManager).getRingerMode();
+        doNothing().when(mMockedAlarmManager).setExact(anyInt(), anyLong(), any());
 
         PhoneStateListenerHandler phoneStateListenerHandler = new PhoneStateListenerHandler(
                 "testStartServiceStop",
@@ -513,13 +515,13 @@ public class CellBroadcastAlertAudioTest extends
 
         ArgumentCaptor<Long> capTime = ArgumentCaptor.forClass(Long.class);
         InOrder inOrder = inOrder(mockMediaPlayer, mockHandler);
-        long expTime = SystemClock.uptimeMillis() + duration;
         audio.handleStartIntent(intent);
 
         inOrder.verify(mockMediaPlayer).prepare();
         inOrder.verify(mockHandler).sendMessageAtTime(any(), capTime.capture());
         inOrder.verify(mockMediaPlayer).start();
-        assertTrue((capTime.getValue() - expTime) < tolerance);
+        long expTime = SystemClock.uptimeMillis() + duration;
+        assertTrue((expTime - capTime.getValue()) < tolerance);
     }
 
     public void testCallConnectedDuringPlayAlert() throws Throwable {
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertDialogTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertDialogTest.java
index 2e8f738b4..cfb896222 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertDialogTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertDialogTest.java
@@ -27,6 +27,7 @@ import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
 import android.app.ActivityManager;
+import android.app.ActivityOptions;
 import android.app.ContentProviderHolder;
 import android.app.IActivityManager;
 import android.app.Notification;
@@ -67,6 +68,7 @@ import com.android.cellbroadcastreceiver.CellBroadcastReceiverApp;
 import com.android.cellbroadcastreceiver.CellBroadcastSettings;
 import com.android.cellbroadcastreceiver.R;
 import com.android.internal.telephony.gsm.SmsCbConstants;
+import com.android.modules.utils.build.SdkLevel;
 
 import org.junit.After;
 import org.junit.Before;
@@ -154,36 +156,18 @@ public class CellBroadcastAlertDialogTest extends
         SubscriptionInfo mockSubInfo = mock(SubscriptionInfo.class);
         doReturn(mockSubInfo).when(mockSubManager).getActiveSubscriptionInfo(anyInt());
 
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
-
-        mMockedActivityManagerHelper = new MockedServiceManager();
-        mMockedActivityManagerHelper.replaceService("window", mWindowManagerService);
-        mMockedActivityManagerHelper.replaceInstance(ActivityManager.class,
-                "IActivityManagerSingleton", null, activityManagerSingleton);
-
         CellBroadcastSettings.resetResourcesCache();
         CellBroadcastChannelManager.clearAllCellBroadcastChannelRanges();
+        String[] values = new String[]{"0x1112-0x1112:rat=gsm, always_on=true"};
+        doReturn(values).when(mContext.getResources()).getStringArray(
+                eq(com.android.cellbroadcastreceiver.R.array
+                .cmas_presidential_alerts_channels_range_strings));
     }
 
     @After
     public void tearDown() throws Exception {
         CellBroadcastSettings.resetResourcesCache();
         CellBroadcastChannelManager.clearAllCellBroadcastChannelRanges();
-        mMockedActivityManagerHelper.restoreAllServices();
         super.tearDown();
     }
 
@@ -235,6 +219,8 @@ public class CellBroadcastAlertDialogTest extends
     }
 
     public void testAddToNotification() throws Throwable {
+        setUpMockActivityManager();
+
         doReturn(true).when(mContext.getResources()).getBoolean(R.bool.show_alert_title);
         doReturn(false).when(mContext.getResources()).getBoolean(
                 R.bool.disable_capture_alert_dialog);
@@ -256,18 +242,52 @@ public class CellBroadcastAlertDialogTest extends
         assertEquals(CellBroadcastAlertServiceTest.createMessage(98235).getMessageBody(),
                 b.getCharSequence(Notification.EXTRA_TEXT));
 
+        ArgumentCaptor<Bundle> bundleArgs = ArgumentCaptor.forClass(Bundle.class);
         verify(mMockedActivityManager, times(2))
                 .getIntentSenderWithFeature(anyInt(), any(), any(), any(), any(), anyInt(),
-                        any(), any(), mFlags.capture(), any(), anyInt());
+                        any(), any(), mFlags.capture(), bundleArgs.capture(), anyInt());
 
         assertTrue((PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE)
                 ==  mFlags.getAllValues().get(0));
         assertTrue((PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE)
                 ==  mFlags.getAllValues().get(1));
 
+        if (SdkLevel.isAtLeastU()) {
+            ActivityOptions activityOptions = new ActivityOptions(bundleArgs.getAllValues().get(0));
+            int startMode = activityOptions.getPendingIntentCreatorBackgroundActivityStartMode();
+            assertEquals(ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED, startMode);
+            activityOptions = new ActivityOptions(bundleArgs.getAllValues().get(1));
+            startMode = activityOptions.getPendingIntentCreatorBackgroundActivityStartMode();
+            assertEquals(ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED, startMode);
+        }
+
         Field field = ((Class) WindowManagerGlobal.class).getDeclaredField("sWindowManagerService");
         field.setAccessible(true);
         field.set(null, null);
+
+        mMockedActivityManagerHelper.restoreAllServices();
+    }
+
+    private void setUpMockActivityManager() throws Exception {
+        ProviderInfo providerInfo = new ProviderInfo();
+        providerInfo.authority = "test";
+        providerInfo.applicationInfo = new ApplicationInfo();
+        providerInfo.applicationInfo.uid = 999;
+        ContentProviderHolder holder = new ContentProviderHolder(providerInfo);
+        doReturn(holder).when(mMockedActivityManager)
+                .getContentProvider(any(), any(), any(), anyInt(), anyBoolean());
+        holder.provider = mock(IContentProvider.class);
+
+        Singleton<IActivityManager> activityManagerSingleton = new Singleton<IActivityManager>() {
+            @Override
+            protected IActivityManager create() {
+                return mMockedActivityManager;
+            }
+        };
+        mMockedActivityManagerHelper = new MockedServiceManager();
+        mMockedActivityManagerHelper.replaceService("window", mWindowManagerService);
+        mMockedActivityManagerHelper.replaceInstance(ActivityManager.class,
+                "IActivityManagerSingleton", null, activityManagerSingleton);
     }
 
     public void testAddToNotificationWithDifferentConfiguration() throws Throwable {
@@ -495,6 +515,7 @@ public class CellBroadcastAlertDialogTest extends
         doReturn(pattern).when(mContext.getResources()).getIntArray(
                 eq(com.android.cellbroadcastreceiver.R.array.default_pulsation_pattern));
 
+        CellBroadcastChannelManager.clearAllCellBroadcastChannelRanges();
         CellBroadcastAlertDialog activity = startActivity();
         waitForMs(100);
         activity.mPulsationHandler.mLayout = mMockLinearLayout;
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertReminderTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertReminderTest.java
index 074ebe547..2f74bfbd7 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertReminderTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertReminderTest.java
@@ -29,7 +29,8 @@ import android.content.SharedPreferences;
 import android.media.AudioAttributes;
 import android.media.AudioManager;
 import android.os.HandlerThread;
-import android.preference.PreferenceManager;
+
+import androidx.preference.PreferenceManager;
 
 import com.android.cellbroadcastreceiver.CellBroadcastAlertReminder;
 import com.android.cellbroadcastreceiver.CellBroadcastSettings;
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertServiceTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertServiceTest.java
index 7d619ecb3..a7f5df8e1 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertServiceTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastAlertServiceTest.java
@@ -450,7 +450,6 @@ public class CellBroadcastAlertServiceTest extends
                 .getSharedPreferences(anyString(), anyInt());
 
         sendMessage(1);
-        waitForServiceIntent();
         CellBroadcastAlertService cellBroadcastAlertService =
                 (CellBroadcastAlertService) getService();
 
@@ -496,7 +495,6 @@ public class CellBroadcastAlertServiceTest extends
                     "0x0034:rat=gsm, type=area, emergency=true"
                 });
         sendMessage(1);
-        waitForServiceIntent();
 
         CellBroadcastAlertService cellBroadcastAlertService =
                 (CellBroadcastAlertService) getService();
@@ -618,7 +616,6 @@ public class CellBroadcastAlertServiceTest extends
                     "0x1113:rat=gsm, emergency=true, always_on=true",
                 });
         sendMessage(1);
-        waitForServiceIntent();
         CellBroadcastAlertService cellBroadcastAlertService =
                 (CellBroadcastAlertService) getService();
         SmsCbMessage message = new SmsCbMessage(1, 2, 0, new SmsCbLocation(),
@@ -742,7 +739,6 @@ public class CellBroadcastAlertServiceTest extends
         enablePreference(CellBroadcastSettings.KEY_RECEIVE_CMAS_IN_SECOND_LANGUAGE);
 
         sendMessage(1);
-        waitForServiceIntent();
         CellBroadcastAlertService cellBroadcastAlertService =
                 (CellBroadcastAlertService) getService();
 
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastConfigServiceTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastConfigServiceTest.java
index 9749cca0c..86898cc77 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastConfigServiceTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastConfigServiceTest.java
@@ -34,19 +34,31 @@ import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
+import android.app.ActivityManager;
+import android.app.ActivityOptions;
+import android.app.IActivityManager;
+import android.app.Notification;
+import android.app.NotificationManager;
 import android.content.Context;
 import android.content.ContextWrapper;
 import android.content.Intent;
 import android.content.SharedPreferences;
+import android.content.pm.ApplicationInfo;
+import android.content.pm.PackageManager;
+import android.os.Bundle;
 import android.os.RemoteException;
 import android.telephony.CellBroadcastIdRange;
 import android.telephony.SmsCbMessage;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
+import android.util.DisplayMetrics;
+import android.util.Singleton;
+import android.view.IWindowManager;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.cellbroadcastreceiver.CellBroadcastAlertService;
 import com.android.cellbroadcastreceiver.CellBroadcastConfigService;
 import com.android.cellbroadcastreceiver.CellBroadcastSettings;
 import com.android.internal.telephony.ISms;
@@ -58,6 +70,7 @@ import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
 import org.mockito.ArgumentCaptor;
+import org.mockito.Captor;
 import org.mockito.Mock;
 
 import java.lang.reflect.Method;
@@ -86,6 +99,21 @@ public class CellBroadcastConfigServiceTest extends CellBroadcastTest {
 
     private CellBroadcastConfigService mConfigService;
 
+    @Mock
+    IWindowManager.Stub mWindowManagerService;
+
+    @Mock
+    private IActivityManager.Stub mMockedActivityManager;
+
+    @Mock
+    private NotificationManager mMockedNotificationManager;
+
+    @Captor
+    private ArgumentCaptor<Notification> mNotification;
+
+    @Captor
+    private ArgumentCaptor<Integer> mInt;
+
     @Before
     public void setUp() throws Exception {
         super.setUp(getClass().getSimpleName());
@@ -861,6 +889,7 @@ public class CellBroadcastConfigServiceTest extends CellBroadcastTest {
     @Test
     @SmallTest
     public void testEnableCellBroadcastRoamingChannelsAsNeeded() throws Exception {
+        CellBroadcastSettings.resetResourcesCache();
         setPreference(CellBroadcastSettings.KEY_ENABLE_ALERTS_MASTER_TOGGLE, true);
         setPreference(CellBroadcastSettings.KEY_ENABLE_CMAS_EXTREME_THREAT_ALERTS, false);
         setPreference(CellBroadcastSettings.KEY_ENABLE_CMAS_SEVERE_THREAT_ALERTS, false);
@@ -1491,4 +1520,66 @@ public class CellBroadcastConfigServiceTest extends CellBroadcastTest {
             verify(mConfigService, times(++c + aggregationCount)).resetAllPreferences();
         }
     }
+
+    /**
+     * Test updating settings and notification when carrier id is changed
+     */
+    @Test
+    public void testUpdateSettingsForCarrierChanged() throws Exception {
+        // set mock for test
+        PackageManager mockPackageManager = mock(PackageManager.class);
+        doReturn(false).when(mockPackageManager)
+                .hasSystemFeature(PackageManager.FEATURE_WATCH);
+        doReturn(mockPackageManager).when(mContext).getPackageManager();
+        doReturn(Context.NOTIFICATION_SERVICE).when(mContext)
+                .getSystemServiceName(NotificationManager.class);
+        doReturn(mMockedNotificationManager).when(mContext)
+                .getSystemService(Context.NOTIFICATION_SERVICE);
+        doReturn("testPackageName").when(mContext).getPackageName();
+        doReturn(new ApplicationInfo()).when(mContext).getApplicationInfo();
+        doReturn(mResources).when(mConfigService).getResources();
+        doReturn(new DisplayMetrics()).when(mResources).getDisplayMetrics();
+        Singleton<IActivityManager> activityManagerSingleton = new Singleton<IActivityManager>() {
+            @Override
+            protected IActivityManager create() {
+                return mMockedActivityManager;
+            }
+        };
+        mMockedServiceManager.replaceService("window", mWindowManagerService);
+        mMockedServiceManager.replaceInstance(ActivityManager.class,
+                "IActivityManagerSingleton", null, activityManagerSingleton);
+        doNothing().when(mConfigService).resetAllPreferences();
+        doReturn(CellBroadcastConfigService.ACTION_UPDATE_SETTINGS_FOR_CARRIER)
+                .when(mIntent).getAction();
+        doReturn(mResources).when(mConfigService).getResources(anyInt(), eq(null));
+
+        // set ANY_PREFERENCE_CHANGED_BY_USER to false
+        setPreference(CellBroadcastSettings.ANY_PREFERENCE_CHANGED_BY_USER, false);
+        Method method = CellBroadcastConfigService.class.getDeclaredMethod(
+                "onHandleIntent", new Class[]{Intent.class});
+        method.setAccessible(true);
+        method.invoke(mConfigService, mIntent);
+        verify(mConfigService, times(1)).resetAllPreferences();
+        verify(mMockedNotificationManager, never()).notify(mInt.capture(),
+                mNotification.capture());
+
+        // set ANY_PREFERENCE_CHANGED_BY_USER to true
+        setPreference(CellBroadcastSettings.ANY_PREFERENCE_CHANGED_BY_USER, true);
+        method.setAccessible(true);
+        method.invoke(mConfigService, mIntent);
+        verify(mConfigService, times(2)).resetAllPreferences();
+        verify(mMockedNotificationManager, times(1)).notify(mInt.capture(),
+                mNotification.capture());
+        assertEquals(CellBroadcastAlertService.SETTINGS_CHANGED_NOTIFICATION_ID,
+                (int) mInt.getValue());
+        if (SdkLevel.isAtLeastU()) {
+            ArgumentCaptor<Bundle> bundleArgs = ArgumentCaptor.forClass(Bundle.class);
+            verify(mMockedActivityManager, times(1))
+                    .getIntentSenderWithFeature(anyInt(), any(), any(), any(), any(), anyInt(),
+                            any(), any(), anyInt(), bundleArgs.capture(), anyInt());
+            ActivityOptions activityOptions = new ActivityOptions(bundleArgs.getAllValues().get(0));
+            int startMode = activityOptions.getPendingIntentCreatorBackgroundActivityStartMode();
+            assertEquals(ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED, startMode);
+        }
+    }
 }
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastResourcesTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastResourcesTest.java
index 5d7b011a8..a984d688a 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastResourcesTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastResourcesTest.java
@@ -212,26 +212,31 @@ public class CellBroadcastResourcesTest {
 
         final int[] expectedResources = {
                 R.string.sms_cb_sender_name_presidential, R.string.sms_cb_sender_name_emergency,
-                R.string.sms_cb_sender_name_public_safety, R.string.sms_cb_sender_name_default};
+                R.string.sms_cb_sender_name_public_safety, R.string.sms_cb_sender_name_default,
+                R.string.sms_cb_sender_name_amber};
         putResources(R.array.cmas_presidential_alerts_channels_range_strings,
                 new String[]{"0x1112:rat=gsm, emergency=true"});
         putResources(R.array.emergency_alerts_channels_range_strings,
-                new String[]{"0x111B:rat=gsm, emergency=true"});
+                new String[]{"0x1113:rat=gsm, emergency=true"});
         putResources(R.array.public_safety_messages_channels_range_strings,
-                new String[]{"0x112C:rat=gsm, emergency=true"});
+                new String[]{"0x1114:rat=gsm, emergency=true"});
         putResources(R.array.cmas_alert_extreme_channels_range_strings,
-                new String[]{"0x1113:rat=gsm, emergency=true"});
+                new String[]{"0x1120:rat=gsm, emergency=true"});
+        putResources(R.array.cmas_amber_alerts_channels_range_strings,
+                new String[]{"0x111B:rat=gsm, emergency=true"});
 
         final String[] expectedStrings = {
                 "Wireless emergency alerts(presidential)", "Wireless emergency alerts(emergency)",
-                "Informational notification", "Wireless emergency alerts(default)"};
+                "Informational notification", "Wireless emergency alerts(default)",
+                "Wireless emergency alerts(amber)"};
         doReturn(expectedStrings[0]).when(mResources).getText(eq(expectedResources[0]));
         doReturn(expectedStrings[1]).when(mResources).getText(eq(expectedResources[1]));
         doReturn(expectedStrings[2]).when(mResources).getText(eq(expectedResources[2]));
         doReturn(expectedStrings[3]).when(mResources).getText(eq(expectedResources[3]));
+        doReturn(expectedStrings[4]).when(mResources).getText(eq(expectedResources[4]));
 
         // check the sms sender address resource id and string
-        final int[] serviceCategory = {0x1112, 0x111B, 0x112C, 0x1113};
+        final int[] serviceCategory = {0x1112, 0x1113, 0x1114, 0x1120, 0x111B};
         for (int i = 0; i < serviceCategory.length; i++) {
             SmsCbMessage message = new SmsCbMessage(0, 0, 0, null,
                     serviceCategory[i], "", "", 0, null,
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSearchIndexableProviderTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSearchIndexableProviderTest.java
index 9447ddfc4..b34d4f00d 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSearchIndexableProviderTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSearchIndexableProviderTest.java
@@ -36,6 +36,7 @@ import org.mockito.Mock;
 
 public class CellBroadcastSearchIndexableProviderTest extends CellBroadcastTest {
     CellBroadcastSearchIndexableProvider mSearchIndexableProvider;
+
     @Before
     public void setUp() throws Exception {
         super.setUp(getClass().getSimpleName());
@@ -77,6 +78,7 @@ public class CellBroadcastSearchIndexableProviderTest extends CellBroadcastTest
         doReturn("test").when(mContext).getSystemServiceName(Vibrator.class);
         doReturn(mVibrator).when(mContext).getSystemService("test");
         doReturn(true).when(mVibrator).hasVibrator();
+        doReturn(false).when(mSearchIndexableProvider).isShowFullScreenMessageVisible(mResources);
         Cursor cursor = mSearchIndexableProvider.queryNonIndexableKeys(new String[]{""});
 
         //KEY_RECEIVE_CMAS_IN_SECOND_LANGUAGE
@@ -91,16 +93,21 @@ public class CellBroadcastSearchIndexableProviderTest extends CellBroadcastTest
         //KEY_ENABLE_CMAS_EXTREME_THREAT_ALERTS
         //KEY_ENABLE_ALERT_SPEECH
         //KEY_ENABLE_CMAS_PRESIDENTIAL_ALERTS
-        assertThat(cursor.getCount()).isEqualTo(12);
+        assertThat(cursor.getCount()).isEqualTo(13);
 
         doReturn(false).when(mVibrator).hasVibrator();
         //KEY_ENABLE_ALERT_VIBRATE
         cursor = mSearchIndexableProvider.queryNonIndexableKeys(new String[]{""});
-        assertThat(cursor.getCount()).isEqualTo(13);
+        assertThat(cursor.getCount()).isEqualTo(14);
 
         doReturn(true).when(mSearchIndexableProvider).isTestAlertsToggleVisible();
         //KEY_ENABLE_TEST_ALERTS
         cursor = mSearchIndexableProvider.queryNonIndexableKeys(new String[]{""});
+        assertThat(cursor.getCount()).isEqualTo(13);
+
+        doReturn(true).when(mSearchIndexableProvider).isShowFullScreenMessageVisible(mResources);
+        //KEY_ENABLE_TEST_ALERTS
+        cursor = mSearchIndexableProvider.queryNonIndexableKeys(new String[]{""});
         assertThat(cursor.getCount()).isEqualTo(12);
     }
 }
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastServiceTestCase.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastServiceTestCase.java
index 2efa71aea..ee5ecbb2a 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastServiceTestCase.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastServiceTestCase.java
@@ -22,6 +22,7 @@ import static org.mockito.Matchers.anyInt;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 
+import android.app.AlarmManager;
 import android.app.NotificationManager;
 import android.app.Service;
 import android.content.ComponentName;
@@ -79,6 +80,8 @@ public abstract class CellBroadcastServiceTestCase<T extends Service> extends Se
     protected Context mMockContextForRoaming;
     @Mock
     protected NotificationManager mMockedNotificationManager;
+    @Mock
+    protected AlarmManager mMockedAlarmManager;
     protected PowerManager mMockedPowerManager;
 
     protected Configuration mConfiguration;
@@ -168,6 +171,8 @@ public abstract class CellBroadcastServiceTestCase<T extends Service> extends Se
                     return mMockedVibrator;
                 case Context.NOTIFICATION_SERVICE:
                     return mMockedNotificationManager;
+                case Context.ALARM_SERVICE:
+                    return mMockedAlarmManager;
                 case Context.POWER_SERVICE:
                     if (mMockedPowerManager != null) {
                         return mMockedPowerManager;
diff --git a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java
index c39a2e842..7402059c9 100644
--- a/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java
+++ b/tests/unit/src/com/android/cellbroadcastreceiver/unit/CellBroadcastSettingsTest.java
@@ -475,4 +475,76 @@ public class CellBroadcastSettingsTest extends
                 break;
         }
     }
+
+    @Test
+    public void testResetToggle() throws Throwable {
+        doReturn(false).when(mContext.getResources()).getBoolean(
+                R.bool.restore_sub_toggle_to_carrier_default);
+        doReturn(true).when(mContext.getResources()).getBoolean(
+                R.bool.severe_threat_alerts_enabled_default);
+        doReturn(true).when(mContext.getResources()).getBoolean(
+                R.bool.amber_alerts_enabled_default);
+        doReturn(false).when(mContext.getResources()).getBoolean(
+                R.bool.test_alerts_enabled_default);
+
+        CellBroadcastSettings cellBroadcastSettingActivity = startActivity();
+
+        TwoStatePreference severeCheckBox =
+                cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_CMAS_SEVERE_THREAT_ALERTS);
+        TwoStatePreference amberCheckBox =
+                cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_CMAS_AMBER_ALERTS);
+        TwoStatePreference testCheckBox =
+                cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_TEST_ALERTS);
+
+        cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.setAlertsEnabled(false);
+
+        assertFalse(severeCheckBox.isChecked());
+        assertFalse(amberCheckBox.isChecked());
+        assertFalse(testCheckBox.isChecked());
+
+        cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.setAlertsEnabled(true);
+
+        assertTrue(severeCheckBox.isChecked());
+        assertTrue(amberCheckBox.isChecked());
+        assertTrue(testCheckBox.isChecked());
+    }
+
+    @Test
+    public void testRestoreToggleToCarrierDefault() throws Throwable {
+        doReturn(true).when(mContext.getResources()).getBoolean(
+                R.bool.restore_sub_toggle_to_carrier_default);
+        doReturn(true).when(mContext.getResources()).getBoolean(
+                R.bool.severe_threat_alerts_enabled_default);
+        doReturn(true).when(mContext.getResources()).getBoolean(
+                R.bool.amber_alerts_enabled_default);
+        doReturn(false).when(mContext.getResources()).getBoolean(
+                R.bool.test_alerts_enabled_default);
+
+        CellBroadcastSettings cellBroadcastSettingActivity = startActivity();
+
+        TwoStatePreference severeCheckBox =
+                cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_CMAS_SEVERE_THREAT_ALERTS);
+        TwoStatePreference amberCheckBox =
+                cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_CMAS_AMBER_ALERTS);
+        TwoStatePreference testCheckBox =
+                cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.findPreference(
+                        CellBroadcastSettings.KEY_ENABLE_TEST_ALERTS);
+
+        cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.setAlertsEnabled(false);
+
+        assertFalse(severeCheckBox.isChecked());
+        assertFalse(amberCheckBox.isChecked());
+        assertFalse(testCheckBox.isChecked());
+
+        cellBroadcastSettingActivity.mCellBroadcastSettingsFragment.setAlertsEnabled(true);
+
+        assertTrue(severeCheckBox.isChecked());
+        assertTrue(amberCheckBox.isChecked());
+        assertFalse(testCheckBox.isChecked());
+    }
 }
```

