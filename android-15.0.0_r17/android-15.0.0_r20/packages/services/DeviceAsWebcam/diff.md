```diff
diff --git a/Android.bp b/Android.bp
index fef678d..d1751a9 100644
--- a/Android.bp
+++ b/Android.bp
@@ -10,10 +10,14 @@ aconfig_declarations {
     srcs: ["device_as_webcam.aconfig"],
 }
 
-java_aconfig_library {
-    name: "device_as_webcam_flags_java_lib",
-    aconfig_declarations: "device_as_webcam_flags",
-}
+// Re-enable when adding flags.
+// Also add as a dependency to DeviceAsWebcam or libDeviceAsWebcam
+// as needed.
+//
+// java_aconfig_library {
+//     name: "device_as_webcam_flags_java_lib",
+//     aconfig_declarations: "device_as_webcam_flags",
+// }
 
 genrule {
     name: "camera-webcam-test",
diff --git a/device_as_webcam.aconfig b/device_as_webcam.aconfig
index fa4f5df..e4b01fe 100644
--- a/device_as_webcam.aconfig
+++ b/device_as_webcam.aconfig
@@ -1,9 +1,2 @@
 package: "com.android.deviceaswebcam.flags"
 container: "system"
-
-flag {
-    namespace: "camera_platform"
-    name: "high_quality_toggle"
-    description: "Allow users to turn on 'High Quality' mode"
-    bug: "313179507"
-}
\ No newline at end of file
diff --git a/impl/Android.bp b/impl/Android.bp
index f9efe64..6a37967 100644
--- a/impl/Android.bp
+++ b/impl/Android.bp
@@ -13,7 +13,6 @@ android_app {
         "androidx.core_core",
         "androidx.recyclerview_recyclerview",
         "androidx.window_window",
-        "device_as_webcam_flags_java_lib",
         "libDeviceAsWebcam",
     ],
 
diff --git a/impl/res/values-af/strings.xml b/impl/res/values-af/strings.xml
index 9850352..39b62e8 100644
--- a/impl/res/values-af/strings.xml
+++ b/impl/res/values-af/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"WAARSKUWING:"</u></b>" Langdurige gebruik teen hoë temperature kan \'n nadelige uitwerking hê op die langtermyn batterygesondheid van hierdie toestel."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Moenie weer wys nie"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Erken"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"hoë.gehaltemodus.is.geaktiveer"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"hoë.gehalte.waarskuwing.geaktiveer"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Agterste kamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Voorste kamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standaardkamera"</string>
diff --git a/impl/res/values-am/strings.xml b/impl/res/values-am/strings.xml
index 1fb6f12..e1b8ee0 100644
--- a/impl/res/values-am/strings.xml
+++ b/impl/res/values-am/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ማስጠንቀቂያ፦"</u></b>" በከፍተኛ ሙቀት ውስጥ ረዘም ላለ ጊዜ መጠቀም በዚህ መሣሪያ የባትሪ የረጅም ጊዜ ጤና ላይ አሉታዊ ተጽዕኖ ሊኖረው ይችላል።"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"ዳግም አታሳይ"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"እውቅና ስጥ"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"ከፍተኛ ጥራት ያለው ሁነታ ነቅቷል"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"ከፍተኛ.ጥራት.ማስጠንቀቂያ.ነቅቷል"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"የኋላ ካሜራ"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"የፊት ካሜራ"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"መደበኛ ካሜራ"</string>
diff --git a/impl/res/values-ar/strings.xml b/impl/res/values-ar/strings.xml
index ab15b53..4ef268a 100644
--- a/impl/res/values-ar/strings.xml
+++ b/impl/res/values-ar/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"تحذير:"</u></b>" قد يؤدي الاستخدام لفترات زمنية طويلة في درجات حرارة عالية إلى تأثير سلبي في حالة بطارية هذا الجهاز على المدى البعيد."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"عدم الإظهار مرة أخرى"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"إقرار"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"الكاميرا الخلفية"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"الكاميرا الأمامية"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"كاميرا عادية"</string>
diff --git a/impl/res/values-as/strings.xml b/impl/res/values-as/strings.xml
index 9cd833b..9c16d46 100644
--- a/impl/res/values-as/strings.xml
+++ b/impl/res/values-as/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"সকীয়নি:"</u></b>" উচ্চ তাপমানত দীঘলীয়া সময় ধৰি একেৰাহে ব্যৱহাৰ কৰিলে এই ডিভাইচটোৰ দীৰ্ঘম্যাদী বেটাৰীৰ স্বাস্থ্যৰ ওপৰত বিৰূপ প্ৰভাৱ পৰিব পাৰে।"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"পুনৰাই নেদেখুৱাব"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"স্বীকাৰ কৰক"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"উচ্চ গুণগত মানৰ সকীয়নি সক্ষম কৰা হৈছে"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"পিছফালৰ কেমেৰা"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"সন্মুখৰ কেমেৰা"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"মানক কেমেৰা"</string>
diff --git a/impl/res/values-az/strings.xml b/impl/res/values-az/strings.xml
index 76f6c90..73241c4 100644
--- a/impl/res/values-az/strings.xml
+++ b/impl/res/values-az/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"XƏBƏRDARLIQ:"</u></b>" Yüksək temperaturda uzun müddət istifadə etmək bu cihazın uzunmüddətli batareya tutumuna mənfi təsir edə bilər."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Təkrar göstərməyin"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Qəbul edin"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Arxa kamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Ön kamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standart kamera"</string>
diff --git a/impl/res/values-b+sr+Latn/strings.xml b/impl/res/values-b+sr+Latn/strings.xml
index 61e675b..93ad27f 100644
--- a/impl/res/values-b+sr+Latn/strings.xml
+++ b/impl/res/values-b+sr+Latn/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"UPOZORENJE:"</u></b>" Produženo korišćenje pri visokim temperaturama može dugoročno da ugrozi stanje baterije ovog uređaja."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Ne prikazuj ponovo"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Prihvati"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Zadnja kamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Prednja kamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standardna kamera"</string>
diff --git a/impl/res/values-be/strings.xml b/impl/res/values-be/strings.xml
index 41ef0cc..15324f2 100644
--- a/impl/res/values-be/strings.xml
+++ b/impl/res/values-be/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"УВАГА."</u></b>" Працяглае выкарыстанне прылады пры высокіх тэмпературах можа ў доўгатэрміновай перспектыве адмоўна паўплываць на стан акумулятара прылады."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Больш не паказваць"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Пацвердзіць"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Задняя камера"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Пярэдняя камера"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Стандартная камера"</string>
diff --git a/impl/res/values-bg/strings.xml b/impl/res/values-bg/strings.xml
index 5219088..5ce344c 100644
--- a/impl/res/values-bg/strings.xml
+++ b/impl/res/values-bg/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ПРЕДУПРЕЖДЕНИЕ"</u>":"</b>" Продължителното използване на устройството при високи температури може да има неблагоприятен ефект върху състоянието на батерията му в дългосрочен план."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Да не се показва отново"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Потвърждаване"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Задна камера"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Предна камера"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Стандартна камера"</string>
diff --git a/impl/res/values-bn/strings.xml b/impl/res/values-bn/strings.xml
index aac059e..65bf86b 100644
--- a/impl/res/values-bn/strings.xml
+++ b/impl/res/values-bn/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"সতর্কতা:"</u></b>"আপনার ডিভাইস যদি অনেক সময় ধরে বেশি তাপমাত্রায় ব্যবহার করা হয়, তাহলে ডিভাইসের ব্যাটারির পারফর্ম্যান্স প্রভাবিত হতে পারে।"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"আর দেখতে চাই না"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"সম্মতি দিন"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"পিছনের দিকের ক্যামেরা"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"সামনের ক্যামেরা"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"স্ট্যান্ডার্ড ক্যামেরা"</string>
diff --git a/impl/res/values-bs/strings.xml b/impl/res/values-bs/strings.xml
index da8341c..96ae7bf 100644
--- a/impl/res/values-bs/strings.xml
+++ b/impl/res/values-bs/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"UPOZORENJE:"</u></b>" duže korištenje pri visokim temperaturama može dugoročno ugroziti stanje baterije uređaja."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Ne prikazuj ponovo"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Potvrdite"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Zadnja kamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Prednja kamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standardna kamera"</string>
diff --git a/impl/res/values-ca/strings.xml b/impl/res/values-ca/strings.xml
index 62f0a94..4768e14 100644
--- a/impl/res/values-ca/strings.xml
+++ b/impl/res/values-ca/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ADVERTIMENT:"</u></b>" l\'ús prolongat a altes temperatures pot tenir un efecte advers en l\'estat de la bateria d\'aquest dispositiu a llarg termini."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"No ho tornis a mostrar"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Accepta"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Càmera posterior"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Càmera frontal"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Càmera estàndard"</string>
diff --git a/impl/res/values-cs/strings.xml b/impl/res/values-cs/strings.xml
index b89491e..f4dd934 100644
--- a/impl/res/values-cs/strings.xml
+++ b/impl/res/values-cs/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"UPOZORNĚNÍ:"</u></b>" Dlouhodobé používání při vysoké teplotě má neblahý vliv na životnost baterie v zařízení."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Už nezobrazovat"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Potvrdit"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Zadní fotoaparát"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Přední fotoaparát"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standardní fotoaparát"</string>
diff --git a/impl/res/values-da/strings.xml b/impl/res/values-da/strings.xml
index dfdd573..f44450a 100644
--- a/impl/res/values-da/strings.xml
+++ b/impl/res/values-da/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ADVARSEL!"</u></b>" Langvarig brug af enheden ved høje temperaturer kan gå ud over enhedens batteritilstand på sigt."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Vis ikke igen"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Acceptér"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Bagsidekamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Frontkamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standardkamera"</string>
diff --git a/impl/res/values-de/strings.xml b/impl/res/values-de/strings.xml
index d7885d6..2501dcc 100644
--- a/impl/res/values-de/strings.xml
+++ b/impl/res/values-de/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"WARNUNG"</u></b>": Eine längere Nutzung bei erhöhten Temperaturen kann sich negativ auf den langfristigen Akkuzustand dieses Geräts auswirken."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Nicht mehr anzeigen"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Bestätigen"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Kamera auf der Rückseite"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Frontkamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standardkamera"</string>
diff --git a/impl/res/values-el/strings.xml b/impl/res/values-el/strings.xml
index d68ab3a..949d3d8 100644
--- a/impl/res/values-el/strings.xml
+++ b/impl/res/values-el/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ΕΙΔΟΠΟΙΗΣΗ:"</u></b>" Η παρατεταμένη χρήση σε υψηλές θερμοκρασίες μπορεί να έχει αρνητικό αντίκτυπο μακροπρόθεσμα στην υγεία της μπαταρίας αυτής της συσκευής."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Να μην εμφανιστεί ξανά"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Επιβεβαίωση"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Πίσω κάμερα"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Μπροστινή κάμερα"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Βασική κάμερα"</string>
diff --git a/impl/res/values-en-rAU/strings.xml b/impl/res/values-en-rAU/strings.xml
index c7f4c4e..e02907e 100644
--- a/impl/res/values-en-rAU/strings.xml
+++ b/impl/res/values-en-rAU/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"WARNING:"</u></b>" Prolonged usage at high temperatures may have an adverse effect on the long-term battery health of this device."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Don\'t show again"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Acknowledge"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Back camera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Front camera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standard camera"</string>
diff --git a/impl/res/values-en-rCA/strings.xml b/impl/res/values-en-rCA/strings.xml
index d6bdd94..d195fe8 100644
--- a/impl/res/values-en-rCA/strings.xml
+++ b/impl/res/values-en-rCA/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"WARNING:"</u></b>" Prolonged usage at high temperatures may have an adverse effect on the long term battery health of this device."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Don\'t show again"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Acknowledge"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Back camera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Front camera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standard camera"</string>
diff --git a/impl/res/values-en-rGB/strings.xml b/impl/res/values-en-rGB/strings.xml
index c7f4c4e..e02907e 100644
--- a/impl/res/values-en-rGB/strings.xml
+++ b/impl/res/values-en-rGB/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"WARNING:"</u></b>" Prolonged usage at high temperatures may have an adverse effect on the long-term battery health of this device."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Don\'t show again"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Acknowledge"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Back camera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Front camera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standard camera"</string>
diff --git a/impl/res/values-en-rIN/strings.xml b/impl/res/values-en-rIN/strings.xml
index c7f4c4e..e02907e 100644
--- a/impl/res/values-en-rIN/strings.xml
+++ b/impl/res/values-en-rIN/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"WARNING:"</u></b>" Prolonged usage at high temperatures may have an adverse effect on the long-term battery health of this device."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Don\'t show again"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Acknowledge"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Back camera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Front camera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standard camera"</string>
diff --git a/impl/res/values-en-rXC/strings.xml b/impl/res/values-en-rXC/strings.xml
index 1c8ab4b..b69347c 100644
--- a/impl/res/values-en-rXC/strings.xml
+++ b/impl/res/values-en-rXC/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‎‏‏‎‎‏‎‏‏‎‏‎‎‎‎‏‎‏‎‎‎‏‎‏‏‏‏‏‎‏‏‎‏‎‎‏‎‏‎‏‏‎‎‎‎‏‎‎‎‎‏‎‏‎‏‎‏‏‏‎‎‎‏‎‎‏‏‎"<b>"‎‏‎‎‏‏‏‎‎‏‎‎‏‏‎"<u>"‎‏‎‎‏‏‏‎WARNING:‎‏‎‎‏‏‎"</u>"‎‏‎‎‏‏‏‎‎‏‎‎‏‏‎"</b>"‎‏‎‎‏‏‏‎ Prolonged usage at high temperatures may have an adverse effect on the long term battery health of this device.‎‏‎‎‏‎"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‏‎‏‎‏‎‎‏‏‏‏‏‏‎‏‎‏‏‎‏‏‎‎‏‎‎‎‏‏‎‎‏‏‎‏‏‏‏‏‏‎‏‎‎‎‏‎‎‎‎‎‏‏‏‏‎‎‎‏‏‏‎‎Don\'t show again‎‏‎‎‏‎"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‎‏‎‎‎‏‎‎‎‎‏‎‎‏‎‎‎‎‎‎‎‎‎‏‏‏‏‎‏‏‎‏‏‎‎‎‎‎‎‏‏‏‏‏‏‏‎‏‎‏‏‎‏‎‏‏‎‎‎‎‎‎Acknowledge‎‏‎‎‏‎"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‎‏‏‎‎‎‏‎‎‎‎‎‏‎‏‏‎‎‏‏‏‏‏‏‎‏‎‏‎‏‎‎‎‎‏‏‎‏‏‏‏‏‎‎‎‎‎‏‏‎‏‏‏‎‎‏‎‎‎‎‎com.android.DeviceAsWebcam.user.prefs‎‏‎‎‏‎"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‎‏‎‎‎‏‎‏‏‎‏‎‎‎‎‎‏‎‏‏‎‎‏‏‎‏‏‎‎‎‏‏‎‎‎‏‏‏‏‏‎‏‎‎‏‏‏‏‏‏‎‏‏‏‎‎‎‎‏‎‎‎‎camera.id‎‏‎‎‏‎"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‎‎‎‏‏‎‎‎‏‏‏‎‎‎‏‎‎‏‎‏‎‎‏‎‎‏‏‏‏‏‎‎‏‎‎‏‎‏‏‎‎‏‏‎‎‏‎‎‏‎‏‏‏‏‏‎‎‏‏‎‎‎back.camera.id‎‏‎‎‏‎"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‎‎‎‏‎‏‏‎‎‎‎‎‎‏‎‏‎‎‎‎‏‎‎‎‎‎‎‏‏‎‏‏‎‎‏‎‎‎‎‎‏‏‏‎‎‏‎‎‏‏‏‎‎‏‏‎‎‎‏‏‏‏‎front.camera.id‎‏‎‎‏‎"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‎‎‏‎‎‎‎‎‏‎‎‏‎‎‎‏‏‏‎‎‎‏‏‎‏‎‎‎‎‏‎‎‎‎‎‏‏‏‏‎‎‎‏‎‎‏‏‎‏‏‎‏‎‏‏‏‏‎‏‎‏‏‎zoom.ratio.%s‎‏‎‎‏‎"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‏‏‎‏‏‎‎‎‏‏‎‏‎‎‎‎‏‏‎‎‏‎‎‎‎‎‏‏‏‏‎‎‏‏‎‎‎‎‎‎‎‏‏‎‏‏‏‎‏‏‏‎‏‏‏‏‏‎‏‏‏‎‎‏‎high.quality.mode.enabled‎‏‎‎‏‎"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‏‎‏‎‏‏‎‏‏‎‎‎‏‏‏‏‎‎‏‏‏‎‎‎‎‏‎‏‎‎‎‎‎‏‏‏‎‏‏‎‏‏‏‏‎‏‎‎‎‏‏‏‏‏‏‎‏‎‏‎‏‎high.quality.warning.enabled‎‏‎‎‏‎"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‎‏‏‏‎‎‏‏‏‏‏‏‎‏‏‏‏‏‎‎‏‏‏‎‏‎‎‏‎‎‎‏‏‏‎‏‏‏‎‏‏‎‎‎‏‏‎‏‎‎‎‏‏‏‎‏‏‎‏‎‏‎Back camera‎‏‎‎‏‎"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‏‎‏‎‏‎‏‎‎‎‎‏‎‎‏‎‏‎‏‎‎‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‎‏‏‎‎‎‏‏‏‎‏‏‏‎‏‏‎‏‏‏‎‎‏‏‎Front camera‎‏‎‎‏‎"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‏‏‏‏‏‎‏‏‏‏‎‏‎‎‎‏‎‏‎‏‏‏‏‎‎‎‏‏‏‎‏‏‎‎‎‎‎‎‏‎‏‎‏‎‎‏‏‎‏‎‏‏‎‏‎‏‎‎‏‎‎‎‎‎‏‏‎‎‎Standard camera‎‏‎‎‏‎"</string>
diff --git a/impl/res/values-es-rUS/strings.xml b/impl/res/values-es-rUS/strings.xml
index 1e036dd..3bbbe2b 100644
--- a/impl/res/values-es-rUS/strings.xml
+++ b/impl/res/values-es-rUS/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ADVERTENCIA:"</u></b>" El uso prolongado a altas temperaturas puede perjudicar a largo plazo el estado de la batería de este dispositivo."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"No volver a mostrar"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Confirmar"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Cámara posterior"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Cámara frontal"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Cámara estándar"</string>
diff --git a/impl/res/values-es/strings.xml b/impl/res/values-es/strings.xml
index b1c463e..09fd934 100644
--- a/impl/res/values-es/strings.xml
+++ b/impl/res/values-es/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ADVERTENCIA:"</u></b>" El uso prolongado a altas temperaturas podría tener un efecto adverso en la vida útil de la batería del dispositivo."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"No volver a mostrar"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Aceptar"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Cámara trasera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Cámara frontal"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Cámara estándar"</string>
diff --git a/impl/res/values-et/strings.xml b/impl/res/values-et/strings.xml
index 4067497..b341c61 100644
--- a/impl/res/values-et/strings.xml
+++ b/impl/res/values-et/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"HOIATUS:"</u></b>" pikaajaline kasutamine kõrgetel temperatuuridel võib kahjustada selle seadme aku pikaajalist seisukorda."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Ära enam näita"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Kinnitan"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Tagakaamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Esikaamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Tavaline kaamera"</string>
diff --git a/impl/res/values-eu/strings.xml b/impl/res/values-eu/strings.xml
index 799af5e..6108b7b 100644
--- a/impl/res/values-eu/strings.xml
+++ b/impl/res/values-eu/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ABISUA:"</u></b>" gailua tenperatura altuetan denbora luzez erabiltzeak agian ondorio kaltegarriak izango ditu gailu honen bateriaren epe luzeko egoeran."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Ez erakutsi berriro"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Aitortu"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"kalitate.handiko.modua.gaituta"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Atzeko kamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Aurreko kamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Kamera arrunta"</string>
diff --git a/impl/res/values-fa/strings.xml b/impl/res/values-fa/strings.xml
index 6873e76..4ca53ec 100644
--- a/impl/res/values-fa/strings.xml
+++ b/impl/res/values-fa/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"هشدار:"</u></b>" استفاده طولانی‌مدت در دماهای بالا ممکن است تأثیر نامطلوب بر سلامت باتری این دستگاه داشته باشد."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"دیگر نشان داده نشود"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"تصدیق کردن"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"حالت.باکیفیت.بالا.فعال شد"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"هشدار.کیفیت.بالا.فعال.شد"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"دوربین پشت"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"دوربین جلو"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"دوربین استاندارد"</string>
diff --git a/impl/res/values-fi/strings.xml b/impl/res/values-fi/strings.xml
index ee23ac7..8cec78a 100644
--- a/impl/res/values-fi/strings.xml
+++ b/impl/res/values-fi/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"VAROITUS:"</u></b>" Laitteen käyttäminen pitkään korkeassa lämpötilassa voi vaikuttaa akun kuntoon pitkällä aikavälillä."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Älä näytä uudelleen"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Vahvista"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"Korkea laatu ‑tila käytössä"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Takakamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Etukamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Tavallinen kamera"</string>
diff --git a/impl/res/values-fr-rCA/strings.xml b/impl/res/values-fr-rCA/strings.xml
index d7e946d..fede396 100644
--- a/impl/res/values-fr-rCA/strings.xml
+++ b/impl/res/values-fr-rCA/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"AVERTISSEMENT :"</u></b>" Une utilisation prolongée à des températures élevées peut avoir une incidence négative sur l\'état de santé de la pile de cet appareil à long terme."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Ne plus afficher"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Accuser réception"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"mode.haute.qualité.activé"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Appareil photo arrière"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Appareil photo avant"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Appareil photo standard"</string>
diff --git a/impl/res/values-fr/strings.xml b/impl/res/values-fr/strings.xml
index 10f0fe5..5e1af11 100644
--- a/impl/res/values-fr/strings.xml
+++ b/impl/res/values-fr/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"AVERTISSEMENT"</u></b>" : une utilisation prolongée à des températures élevées peut avoir des conséquences négatives sur l\'état de la batterie de cet appareil à long terme."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Ne plus afficher"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Confirmer"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Caméra arrière"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Caméra avant"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Caméra standard"</string>
diff --git a/impl/res/values-gl/strings.xml b/impl/res/values-gl/strings.xml
index bd0bd58..3061316 100644
--- a/impl/res/values-gl/strings.xml
+++ b/impl/res/values-gl/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ADVERTENCIA:"</u></b>" O uso prolongado a temperaturas altas pode afectar negativamente ao estado da batería deste dispositivo a longo prazo."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Non volver mostrar"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Aceptar"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Cámara traseira"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Cámara dianteira"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Cámara estándar"</string>
diff --git a/impl/res/values-gu/strings.xml b/impl/res/values-gu/strings.xml
index 80b9710..4dfd46d 100644
--- a/impl/res/values-gu/strings.xml
+++ b/impl/res/values-gu/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ચેતવણી:"</u></b>" ઊંચા તાપમાને લાંબા સમય સુધી ઉપયોગ આ ડિવાઇસની બૅટરીની ક્ષમતા પર પ્રતિકૂળ અસર કરી શકે છે."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"ફરીથી બતાવશો નહીં"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"સ્વીકારો"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"ઉચ્ચ.ક્વૉલિટી.ચેતવણી.ચાલુ.કરી"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"બૅક કૅમેરા"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"ફ્રન્ટ કૅમેરા"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"સ્ટૅન્ડર્ડ કૅમેરા"</string>
diff --git a/impl/res/values-hi/strings.xml b/impl/res/values-hi/strings.xml
index 898102d..d5bfe19 100644
--- a/impl/res/values-hi/strings.xml
+++ b/impl/res/values-hi/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"चेतावनी:"</u></b>" अगर डिवाइस को लंबे समय तक ज़्यादा तापमान पर इस्तेमाल किया जाए, तो हो सकता है कि आपके डिवाइस की बैटरी की परफ़ॉर्मेंस पर असर पड़े."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"फिर से न दिखाएं"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"स्वीकार करें"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"अच्छी क्वालिटी से जुड़ी चेतावनी चालू कर दी गई है"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"बैक कैमरा"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"फ़्रंट कैमरा"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"स्टैंडर्ड कैमरा"</string>
diff --git a/impl/res/values-hr/strings.xml b/impl/res/values-hr/strings.xml
index 62d80e0..9cf1346 100644
--- a/impl/res/values-hr/strings.xml
+++ b/impl/res/values-hr/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"UPOZORENJE:"</u></b>" produljena upotreba na visokim temperaturama može imati negativan učinak na dugotrajno stanje baterije tog uređaja."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Ne prikazuj ponovno"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Potvrdi"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Stražnja kamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Prednja kamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standardna kamera"</string>
diff --git a/impl/res/values-hu/strings.xml b/impl/res/values-hu/strings.xml
index c189b71..d5ea4a3 100644
--- a/impl/res/values-hu/strings.xml
+++ b/impl/res/values-hu/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"FIGYELMEZTETÉS:"</u></b>" A tartósan magas hőmérsékleten történő használat hosszú távon negatív hatással lehet az eszköz akkumulátorának állapotára."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Ne jelenjen meg újra"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Elfogadás"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Hátlapi kamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Előlapi kamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Normál kamera"</string>
diff --git a/impl/res/values-hy/strings.xml b/impl/res/values-hy/strings.xml
index 4e5dddc..87683d4 100644
--- a/impl/res/values-hy/strings.xml
+++ b/impl/res/values-hy/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ՆԱԽԱԶԳՈՒՇԱՑՈՒՄ․"</u></b>" բարձր ջերմաստիճաններում երկարատև օգտագործումը կարող է ապագայում բացասական ազդեցություն ունենալ այս սարքի մարտկոցի վիճակի վրա։"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Այլևս ցույց չտալ"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Հաստատել"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Հիմնական տեսախցիկ"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Դիմային տեսախցիկ"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Ստանդարտ տեսախցիկ"</string>
diff --git a/impl/res/values-in/strings.xml b/impl/res/values-in/strings.xml
index cd8fa5c..329240f 100644
--- a/impl/res/values-in/strings.xml
+++ b/impl/res/values-in/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"PERINGATAN:"</u></b>" Penggunaan berkepanjangan pada suhu tinggi dapat menyebabkan dampak buruk pada kesehatan baterai perangkat ini dalam jangka panjang."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Jangan tampilkan lagi"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Konfirmasi"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"peringatan.kualitas.tinggi.diaktifkan"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Kamera belakang"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Kamera depan"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Kamera standar"</string>
diff --git a/impl/res/values-is/strings.xml b/impl/res/values-is/strings.xml
index cb92a0f..a11ec85 100644
--- a/impl/res/values-is/strings.xml
+++ b/impl/res/values-is/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"VIÐVÖRUN:"</u></b>" Langvarandi notkun við hátt hitastig getur haft skaðleg áhrif á langtímaástand rafhlöðu tækisins."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Ekki sýna aftur"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Staðfesta"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"hágæðaviðvörun.kveikt"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Aftari myndavél"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Fremri myndavél"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Stöðluð myndavél"</string>
diff --git a/impl/res/values-it/strings.xml b/impl/res/values-it/strings.xml
index 37bf813..fc52cce 100644
--- a/impl/res/values-it/strings.xml
+++ b/impl/res/values-it/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"AVVISO"</u></b>": l\'utilizzo prolungato ad alte temperature potrebbe compromettere l\'integrità della batteria nel tempo di questo dispositivo."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Non mostrare più"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Conferma"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Fotocamera posteriore"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Fotocamera anteriore"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Fotocamera standard"</string>
diff --git a/impl/res/values-iw/strings.xml b/impl/res/values-iw/strings.xml
index ef53100..cafb6e4 100644
--- a/impl/res/values-iw/strings.xml
+++ b/impl/res/values-iw/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"אזהרה:"</u></b>" שימוש ממושך בטמפרטורות גבוהות עשוי להשפיע לרעה על תקינות הסוללה של המכשיר הזה בטווח הארוך."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"לא להציג את זה שוב"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"אישור"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"איכות.גבוהה.הופעלה.אזהרה"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"מצלמה אחורית"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"מצלמה קדמית"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"מצלמה רגילה"</string>
diff --git a/impl/res/values-ja/strings.xml b/impl/res/values-ja/strings.xml
index d5171d9..5b5010f 100644
--- a/impl/res/values-ja/strings.xml
+++ b/impl/res/values-ja/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"警告:"</u></b>" 高い温度で長時間使い続けると、このデバイスの長期的なバッテリーの健全性に悪影響が及ぶことがあります。"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"次回から表示しない"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"承認"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"背面カメラ"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"前面カメラ"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"標準カメラ"</string>
diff --git a/impl/res/values-ka/strings.xml b/impl/res/values-ka/strings.xml
index 4d901a3..c743e09 100644
--- a/impl/res/values-ka/strings.xml
+++ b/impl/res/values-ka/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"შენიშვნა:"</u></b>" მაღალ ტემპერატურაზე ხანგრძლივმა გამოყენებამ გრძელვადიან პერსპექტივაში შეიძლება ამ მოწყობილობის ბატარეის მდგომარეობაზე უარყოფითი გავლენა მოახდინოს."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"აღარ მაჩვენო"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"დადასტურება"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"მაღალი ხარისხიი.გაფრთხილება.ჩართულია"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"უკანა კამერა"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"წინა კამერა"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"სტანდარტული კამერა"</string>
diff --git a/impl/res/values-kk/strings.xml b/impl/res/values-kk/strings.xml
index fe75c8a..2e01bda 100644
--- a/impl/res/values-kk/strings.xml
+++ b/impl/res/values-kk/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ЕСКЕРТУ:"</u></b>" жоғары температурада ұзақ пайдалану құрылғының батарея күйіне теріс әсер етуі мүмкін."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Қайта көрсетілмесін"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Растау"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Артқы камера"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Алдыңғы камера"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Стандартты камера"</string>
diff --git a/impl/res/values-km/strings.xml b/impl/res/values-km/strings.xml
index 9309dd7..d01658e 100644
--- a/impl/res/values-km/strings.xml
+++ b/impl/res/values-km/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"សូមប្រុងប្រយ័ត្ន៖"</u></b>" ការប្រើប្រាស់រយៈពេលយូរនៅសីតុណ្ហភាពខ្ពស់អាចមានផលអវិជ្ជមានចំពោះគុណភាព​ថ្មរបស់ឧបករណ៍នេះក្នុងរយៈពេលវែង។"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"កុំបង្ហាញម្ដងទៀត"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"ទទួល​ស្គាល់"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"កាមេរ៉ាខាងក្រោយ"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"កាមេរ៉ាខាងមុខ"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"កាមេរ៉ាស្តង់ដារ"</string>
diff --git a/impl/res/values-kn/strings.xml b/impl/res/values-kn/strings.xml
index 2990896..f726fb3 100644
--- a/impl/res/values-kn/strings.xml
+++ b/impl/res/values-kn/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ಎಚ್ಚರಿಕೆ:"</u></b>" ಹೆಚ್ಚಿನ ತಾಪಮಾನದಲ್ಲಿ ದೀರ್ಘಾವಧಿಯ ಬಳಕೆಯು ಈ ಸಾಧನದ ದೀರ್ಘಾಕಾಲೀನ ಬ್ಯಾಟರಿ ಹೆಲ್ತ್ ಮೇಲೆ ಪ್ರತಿಕೂಲ ಪರಿಣಾಮ ಬೀರಬಹುದು."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"ಮತ್ತೊಮ್ಮೆ ತೋರಿಸಬೇಡಿ"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"ಅಂಗೀಕರಿಸಿ"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"ಉನ್ನತ ಗುಣಮಟ್ಟದ ಎಚ್ಚರಿಕೆ ಸಕ್ರಿಯಗೊಳಿಸಲಾಗಿದೆ"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"ಹಿಂಬದಿ ಕ್ಯಾಮರಾ"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"ಮುಂಬದಿ ಕ್ಯಾಮರಾ"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"ಪ್ರಮಾಣಿತ ಕ್ಯಾಮರಾ"</string>
diff --git a/impl/res/values-ko/strings.xml b/impl/res/values-ko/strings.xml
index e7ad04f..8acc691 100644
--- a/impl/res/values-ko/strings.xml
+++ b/impl/res/values-ko/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"경고:"</u></b>" 과열된 상태로 오래 사용하면 기기의 장기 배터리 성능 상태에 악영향을 미칠 수 있습니다."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"다시 표시하지 않음"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"확인"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"고화질.경고.사용.설정됨"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"후면 카메라"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"전면 카메라"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"일반 카메라"</string>
diff --git a/impl/res/values-ky/strings.xml b/impl/res/values-ky/strings.xml
index 9b4c0f8..3fceac7 100644
--- a/impl/res/values-ky/strings.xml
+++ b/impl/res/values-ky/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ЭСКЕРТҮҮ:"</u></b>" Түзмөктү жогорку температурада колдонсоңуз, анын батареясынын абалы начарлашы мүмкүн."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Экинчи көрүнбөсүн"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Ырастоо"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Арткы камера"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Маңдайкы камера"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Кадимки камера"</string>
diff --git a/impl/res/values-lo/strings.xml b/impl/res/values-lo/strings.xml
index aeba265..4651297 100644
--- a/impl/res/values-lo/strings.xml
+++ b/impl/res/values-lo/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ຄຳເຕືອນ:"</u></b>" ການນຳໃຊ້ເປັນເວລາດົນໃນອຸນຫະພູມສູງອາດສົ່ງຜົນກະທົບທາງລົບຕໍ່ສຸຂະພາບແບັດເຕີຣີໃນໄລຍະຍາວຂອງອຸປະກອນນີ້."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"ບໍ່ຕ້ອງສະແດງອີກ"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"ຮັບຊາບ"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"ກ້ອງຖ່າຍຮູບຫຼັງ"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"ກ້ອງຖ່າຍຮູບໜ້າ"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"ກ້ອງຖ່າຍຮູບມາດຕະຖານ"</string>
diff --git a/impl/res/values-lt/strings.xml b/impl/res/values-lt/strings.xml
index add7fac..d37be5b 100644
--- a/impl/res/values-lt/strings.xml
+++ b/impl/res/values-lt/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"PERSPĖJIMAS:"</u></b>" ilgai naudojant esant aukštai temperatūrai tai gali neigiamai paveikti šio įrenginio akumuliatoriaus būseną per ilgą laiką."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Neberodyti"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Patvirtinti"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Galinis fotoaparatas"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Priekinis fotoaparatas"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standartinis fotoaparatas"</string>
diff --git a/impl/res/values-lv/strings.xml b/impl/res/values-lv/strings.xml
index bfdf3b7..f810ce7 100644
--- a/impl/res/values-lv/strings.xml
+++ b/impl/res/values-lv/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"BRĪDINĀJUMS!"</u></b>" Ilgstoša izmantošana lielā temperatūrā var negatīvi ietekmēt šīs ierīces akumulatora stāvokli ilgtermiņā."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Vairs nerādīt"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Apliecināt"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Aizmugures kamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Priekšējā kamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standarta kamera"</string>
diff --git a/impl/res/values-mk/strings.xml b/impl/res/values-mk/strings.xml
index 4e8738d..ec58ce4 100644
--- a/impl/res/values-mk/strings.xml
+++ b/impl/res/values-mk/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ПРЕДУПРЕДУВАЊЕ:"</u></b>" долготрајното користење високи температури може да влијае негативно врз состојбата на батеријата на уредов долгорочно."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Не прикажувај повторно"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Прифатете"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Задна камера"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Предна камера"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Стандардна камера"</string>
diff --git a/impl/res/values-ml/strings.xml b/impl/res/values-ml/strings.xml
index bee3aa8..e9e92ba 100644
--- a/impl/res/values-ml/strings.xml
+++ b/impl/res/values-ml/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"മുന്നറിയിപ്പ്:"</u></b>" ഉയർന്ന താപനിലയിൽ ദീർഘനേരത്തേക്ക് ഉപയോഗിക്കുന്നത്, ഈ ഉപകരണത്തിന്റെ ദീർഘകാല ബാറ്ററി ക്ഷമതയെ പ്രതികൂലമായി ബാധിച്ചേക്കാം."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"വീണ്ടും കാണിക്കരുത്"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"അംഗീകരിക്കുക"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"പിന്നിലെ ക്യാമറ"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"മുന്നിലെ ക്യാമറ"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"സ്‌റ്റാൻഡേർഡ് ക്യാമറ"</string>
diff --git a/impl/res/values-mn/strings.xml b/impl/res/values-mn/strings.xml
index 7e832af..9aa6be6 100644
--- a/impl/res/values-mn/strings.xml
+++ b/impl/res/values-mn/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"САНУУЛГА:"</u></b>" Өндөр температурт урт хугацаагаар ашиглах нь энэ төхөөрөмжийн батарейн барилтад урт хугацааны сөрөг нөлөө үзүүлж болно."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Дахиж бүү харуул"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Хүлээн зөвшөөрөх"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Арын камер"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Урд талын камер"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Стандарт камер"</string>
diff --git a/impl/res/values-mr/strings.xml b/impl/res/values-mr/strings.xml
index ba90d54..df35f1a 100644
--- a/impl/res/values-mr/strings.xml
+++ b/impl/res/values-mr/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"चेतावणी:"</u></b>" हे डिव्हाइस उच्च तापमानावर दीर्घकाळ वापरल्यास, त्याच्या बॅटरीच्या स्थितीवर दीर्घकालीन प्रतिकूल परिणाम होऊ शकतो."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"पुन्हा दाखवू नका"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"स्वीकारा"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"उच्च.गुणवत्ता.चेतावणी.सुरू केली आहे"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"बॅक कॅमेरा"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"फ्रंट कॅमेरा"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"साधारण कॅमेरा"</string>
diff --git a/impl/res/values-ms/strings.xml b/impl/res/values-ms/strings.xml
index d849dda..6f3b200 100644
--- a/impl/res/values-ms/strings.xml
+++ b/impl/res/values-ms/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"AMARAN:"</u></b>" Penggunaan yang berpanjangan pada suhu yang tinggi boleh memberikan kesan yang buruk terhadap kesihatan jangka panjang bateri bagi peranti ini."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Jangan tunjukkan lagi"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Perakui"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Kamera belakang"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Kamera depan"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Kamera standard"</string>
diff --git a/impl/res/values-my/strings.xml b/impl/res/values-my/strings.xml
index eb14964..de4f059 100644
--- a/impl/res/values-my/strings.xml
+++ b/impl/res/values-my/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"သတိပေးချက်-"</u></b>" မြင့်မားသောအပူချိန်တွင် ကြာရှည်စွာအသုံးပြုမှုသည် ဤစက်၏ ရေရှည်ဘက်ထရီအခြေအနေအပေါ် ဆိုးရွားသောသက်ရောက်မှု ရှိနိုင်သည်။"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"ထပ်မပြပါနှင့်"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"အသိအမှတ်ပြုရန်"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"နောက်ကင်မရာ"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"ရှေ့ကင်မရာ"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"ပုံမှန်ကင်မရာ"</string>
diff --git a/impl/res/values-nb/strings.xml b/impl/res/values-nb/strings.xml
index f497b04..1c2523b 100644
--- a/impl/res/values-nb/strings.xml
+++ b/impl/res/values-nb/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ADVARSEL:"</u></b>" Langvarig bruk ved høy temperatur kan ha negativ effekt på batteritilstanden til enheten på lang sikt."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Ikke vis igjen"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Bekreft"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Baksidekamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Frontkamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standardkamera"</string>
diff --git a/impl/res/values-ne/strings.xml b/impl/res/values-ne/strings.xml
index 394b77f..fda9220 100644
--- a/impl/res/values-ne/strings.xml
+++ b/impl/res/values-ne/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"चेतावनी:"</u></b>" लामो समयसम्म उच्च तापक्रममा प्रयोग गर्दा यो डिभाइसको ब्याट्रीको दीर्घकालीन अवस्थामा प्रतिकूल प्रभाव पर्न सक्छ।"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"फेरि नदेखाउनुहोस्"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"स्वीकार गर्नुहोस्"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"पछाडिको क्यामेरा"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"अगाडिको क्यामेरा"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"डिफल्ट क्यामेरा"</string>
diff --git a/impl/res/values-nl/strings.xml b/impl/res/values-nl/strings.xml
index 35ed5ab..7141752 100644
--- a/impl/res/values-nl/strings.xml
+++ b/impl/res/values-nl/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"WAARSCHUWING:"</u></b>" Langdurig gebruik bij hoge temperaturen kan een negatief effect hebben op de batterijconditie van dit apparaat op de lange termijn."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Niet meer tonen"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Bevestigen"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Camera aan achterkant"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Camera aan voorzijde"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standaardcamera"</string>
diff --git a/impl/res/values-or/strings.xml b/impl/res/values-or/strings.xml
index 4e35091..b8563f3 100644
--- a/impl/res/values-or/strings.xml
+++ b/impl/res/values-or/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ଚେତାବନୀ:"</u></b>" ଉଚ୍ଚ ତାପମାତ୍ରାରେ ଅଧିକ ସମୟ ପର୍ଯ୍ୟନ୍ତ ବ୍ୟବହାର ଏହି ଡିଭାଇସର ଦୀର୍ଘକାଳୀନ ବେଟେରୀ ହେଲ୍ଥ ଉପରେ ପ୍ରତିକୂଳ ପ୍ରଭାବ ପକାଇପାରେ।"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"ପୁଣି ଦେଖାନ୍ତୁ ନାହିଁ"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"ସ୍ୱୀକାର କରନ୍ତୁ"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"ଉଚ୍ଚ.ଗୁଣବତ୍ତା.ଚେତାବନୀ.ସକ୍ଷମ କରାଯାଇଛି"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"ପଛ କେମେରା"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"ସାମ୍ନା କେମେରା"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"ଷ୍ଟାଣ୍ଡାର୍ଡ କେମେରା"</string>
diff --git a/impl/res/values-pa/strings.xml b/impl/res/values-pa/strings.xml
index ab615d6..6cb4991 100644
--- a/impl/res/values-pa/strings.xml
+++ b/impl/res/values-pa/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ਚਿਤਾਵਨੀ:"</u></b>" ਉੱਚ ਤਾਪਮਾਨਾਂ \'ਤੇ ਜ਼ਿਆਦਾ ਸਮੇਂ ਲਈ ਵਰਤੋਂ ਕਰਨਾ ਇਸ ਡੀਵਾਈਸ ਦੀ ਲੰਬੇ ਸਮੇਂ ਦੀ ਬੈਟਰੀ ਦੀ ਹਾਲਤ \'ਤੇ ਪ੍ਰਤੀਕੂਲ ਪ੍ਰਭਾਵ ਪਾ ਸਕਦੀ ਹੈ।"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"ਦੁਬਾਰਾ ਨਾ ਦਿਖਾਓ"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"ਹਾਮੀ ਭਰੋ"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"ਪਿਛਲਾ ਕੈਮਰਾ"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"ਅਗਲਾ ਕੈਮਰਾ"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"ਮਿਆਰੀ ਕੈਮਰਾ"</string>
diff --git a/impl/res/values-pl/strings.xml b/impl/res/values-pl/strings.xml
index c9af307..1da7781 100644
--- a/impl/res/values-pl/strings.xml
+++ b/impl/res/values-pl/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"OSTRZEŻENIE:"</u></b>" korzystanie z urządzenia przez dłuższy czas przy wysokiej temperaturze może mieć niekorzystny wpływ na stan baterii w dłuższym okresie."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Nie pokazuj ponownie"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Potwierdzam"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"włączono.tryb.wysokiej.jakości"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Tylny aparat"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Przedni aparat"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standardowy aparat"</string>
diff --git a/impl/res/values-pt-rBR/strings.xml b/impl/res/values-pt-rBR/strings.xml
index 4ff1fdb..e3ebd56 100644
--- a/impl/res/values-pt-rBR/strings.xml
+++ b/impl/res/values-pt-rBR/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ALERTA"</u></b>": o uso prolongado em altas temperaturas pode ter um efeito adverso a longo prazo na integridade da bateria desse dispositivo."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Não mostrar de novo"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Confirmo"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Câmera traseira"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Câmera frontal"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Câmera padrão"</string>
diff --git a/impl/res/values-pt-rPT/strings.xml b/impl/res/values-pt-rPT/strings.xml
index a4787bc..d39a147 100644
--- a/impl/res/values-pt-rPT/strings.xml
+++ b/impl/res/values-pt-rPT/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"AVISO:"</u></b>" A utilização prolongada a temperaturas elevadas pode ter um efeito adverso no estado da bateria a longo prazo deste dispositivo."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Não mostrar novamente"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Confirmar"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Câmara traseira"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Câmara frontal"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Câmara padrão"</string>
diff --git a/impl/res/values-pt/strings.xml b/impl/res/values-pt/strings.xml
index 4ff1fdb..e3ebd56 100644
--- a/impl/res/values-pt/strings.xml
+++ b/impl/res/values-pt/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ALERTA"</u></b>": o uso prolongado em altas temperaturas pode ter um efeito adverso a longo prazo na integridade da bateria desse dispositivo."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Não mostrar de novo"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Confirmo"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Câmera traseira"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Câmera frontal"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Câmera padrão"</string>
diff --git a/impl/res/values-ro/strings.xml b/impl/res/values-ro/strings.xml
index 307f2a6..292f2a1 100644
--- a/impl/res/values-ro/strings.xml
+++ b/impl/res/values-ro/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"AVERTISMENT:"</u></b>" utilizarea prelungită la temperaturi mari poate avea un efect advers asupra stării pe termen lung a bateriei acestui dispozitiv."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Nu mai afișa"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Accept"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Camera foto posterioară"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Camera foto frontală"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Cameră foto standard"</string>
diff --git a/impl/res/values-ru/strings.xml b/impl/res/values-ru/strings.xml
index 22fbe90..7ef0255 100644
--- a/impl/res/values-ru/strings.xml
+++ b/impl/res/values-ru/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ПРЕДУПРЕЖДЕНИЕ."</u></b>" Длительное использование при высоких температурах в перспективе может отрицательно повлиять на состояние батареи устройства."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Больше не показывать"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Подтвердить"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Основная камера"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Фронтальная камера"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Обычная камера"</string>
diff --git a/impl/res/values-si/strings.xml b/impl/res/values-si/strings.xml
index 7b9d31c..3e377f3 100644
--- a/impl/res/values-si/strings.xml
+++ b/impl/res/values-si/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"අවවාදයයි:"</u></b>" අධික උෂ්ණත්වවලදී දීර්ඝ කාලීන භාවිතය මෙම උපාංගයේ දිගුකාලීන බැටරි සෞඛ්‍යයට අහිතකර බලපෑමක් ඇති කළ හැකි ය."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"නැවත නොපෙන්වන්න"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"පිළිගන්න"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"ඉහළ ගුණත්ව අවවාදය සබල කර ඇත"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"පිටුපස කැමරාව"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"ඉදිරිපස කැමරාව"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"සම්මත කැමරාව"</string>
diff --git a/impl/res/values-sk/strings.xml b/impl/res/values-sk/strings.xml
index 9e5ca62..1df951b 100644
--- a/impl/res/values-sk/strings.xml
+++ b/impl/res/values-sk/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"UPOZORNENIE:"</u></b>" Dlhotrvajúce používanie pri vysokých teplotách môže mať nepriaznivý účinok na dlhodobý stav batérie tohto zariadenia."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Už nezobrazovať"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Potvrdiť"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Zadná kamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Predná kamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Štandardná kamera"</string>
diff --git a/impl/res/values-sl/strings.xml b/impl/res/values-sl/strings.xml
index b0aee38..719fa96 100644
--- a/impl/res/values-sl/strings.xml
+++ b/impl/res/values-sl/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"OPOZORILO:"</u></b>" Dolgotrajna uporaba pri visokih temperaturah lahko negativno vpliva na dolgoročno stanje baterije v tej napravi."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Tega ne prikaži več"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Potrdi"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Hrbtni fotoaparat"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Sprednji fotoaparat"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standardni fotoaparat"</string>
diff --git a/impl/res/values-sq/strings.xml b/impl/res/values-sq/strings.xml
index 33f147f..ca51766 100644
--- a/impl/res/values-sq/strings.xml
+++ b/impl/res/values-sq/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"PARALAJMËRIM:"</u></b>" Përdorimi i zgjatur në temperatura të larta mund të ketë një efekt negativ në gjendjen afatgjatë të baterisë së kësaj pajisjeje."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Mos e shfaq më"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Pranoj"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"modaliteti me cilësi të lartë u aktivizua"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Kamera e pasme"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Kamera e përparme"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Kamera standarde"</string>
diff --git a/impl/res/values-sr/strings.xml b/impl/res/values-sr/strings.xml
index 65ab850..ab3cd94 100644
--- a/impl/res/values-sr/strings.xml
+++ b/impl/res/values-sr/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"УПОЗОРЕЊЕ:"</u></b>" Продужено коришћење при високим температурама може дугорочно да угрози стање батерије овог уређаја."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Не приказуј поново"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Прихвати"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Задња камера"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Предња камера"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Стандардна камера"</string>
diff --git a/impl/res/values-sv/strings.xml b/impl/res/values-sv/strings.xml
index cb863e2..f112a9b 100644
--- a/impl/res/values-sv/strings.xml
+++ b/impl/res/values-sv/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"VARNING!"</u></b>" Långvarig användning i höga temperaturer kan påverka enhetens batterihälsa negativt på lång sikt."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Visa inte igen"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Bekräfta"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Bakre kamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Främre kamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standardkamera"</string>
diff --git a/impl/res/values-sw/strings.xml b/impl/res/values-sw/strings.xml
index fdf4745..13f5897 100644
--- a/impl/res/values-sw/strings.xml
+++ b/impl/res/values-sw/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"TAHADHARI:"</u></b>" Ukitumia kifaa chako kikiwa katika halijoto ya kiwango cha juu kwa muda mrefu, huenda hali hiyo ikaathiri muda wa kudumu wa betri ya kifaa hiki."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Usionyeshe tena"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Thibitisha"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"hali ya ubora wa juu imewashwa"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"juu.ubora.tahadhari.imewashwa"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Kamera ya nyuma"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Kamera ya mbele"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Kamera ya kawaida"</string>
diff --git a/impl/res/values-ta/strings.xml b/impl/res/values-ta/strings.xml
index 507f47f..c3dd60a 100644
--- a/impl/res/values-ta/strings.xml
+++ b/impl/res/values-ta/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"எச்சரிக்கை:"</u></b>" அதிக வெப்பநிலைகளில் தொடர்ந்து பயன்படுத்தினால், இந்தச் சாதனத்தின் நீண்டகால பேட்டரி நிலையில் பாதகமான விளைவு ஏற்படக்கூடும்."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"மீண்டும் காட்டாதே"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"ஏற்கிறேன்"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"பின்பக்கக் கேமரா"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"முன்பக்கக் கேமரா"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"நிலையான கேமரா"</string>
diff --git a/impl/res/values-te/strings.xml b/impl/res/values-te/strings.xml
index 7d4c1d0..8b992b1 100644
--- a/impl/res/values-te/strings.xml
+++ b/impl/res/values-te/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"హెచ్చరిక:"</u></b>" అధిక ఉష్ణోగ్రతల వద్ద ఎక్కువసేపు ఉపయోగించడం వల్ల ఈ పరికర బ్యాటరీ స్థితిపై ప్రతికూల ప్రభావం ఉండవచ్చు."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"మళ్లీ చూపవద్దు"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"ధృవీకరించండి"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"వెనుక వైపు కెమెరా"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"ముందు వైపు కెమెరా"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"స్టాండర్డ్ కెమెరా"</string>
diff --git a/impl/res/values-th/strings.xml b/impl/res/values-th/strings.xml
index 75206d9..b36a7e8 100644
--- a/impl/res/values-th/strings.xml
+++ b/impl/res/values-th/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"คำเตือน:"</u></b>" การใช้งานขณะที่อุณหภูมิสูงเป็นเวลานานอาจส่งผลเสียต่อประสิทธิภาพแบตเตอรี่ของอุปกรณ์นี้ในระยะยาว"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"ไม่ต้องแสดงอีก"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"รับทราบ"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"กล้องหลัง"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"กล้องหน้า"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"กล้องมาตรฐาน"</string>
diff --git a/impl/res/values-tl/strings.xml b/impl/res/values-tl/strings.xml
index 1bd297b..a034373 100644
--- a/impl/res/values-tl/strings.xml
+++ b/impl/res/values-tl/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"BABALA:"</u></b>" Posibleng magdulot ng masamang epekto sa pangmatagalang kalagayan ng baterya ng device na ito ang matagal na paggamit nang may mataas na temperatura."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Huwag nang ipakita ulit"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Tanggapin"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Camera sa likod"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Camera sa harap"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standard na camera"</string>
diff --git a/impl/res/values-tr/strings.xml b/impl/res/values-tr/strings.xml
index a008e31..f4ec189 100644
--- a/impl/res/values-tr/strings.xml
+++ b/impl/res/values-tr/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"UYARI:"</u></b>" Yüksek sıcaklıklarda uzun süre kullanırsanız bu cihazın pil sağlığı uzun vadede olumsuz etkilenebilir."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Tekrar gösterme"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Onayla"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Arka kamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Ön kamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standart kamera"</string>
diff --git a/impl/res/values-uk/strings.xml b/impl/res/values-uk/strings.xml
index 993f144..3864685 100644
--- a/impl/res/values-uk/strings.xml
+++ b/impl/res/values-uk/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ПОПЕРЕДЖЕННЯ."</u></b>" Тривале користування пристроєм за високих температур може негативно вплинути на строк експлуатації його акумулятора."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Більше не показувати"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Підтверджую"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Задня камера"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Фронтальна камера"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Стандартна камера"</string>
diff --git a/impl/res/values-ur/strings.xml b/impl/res/values-ur/strings.xml
index 3efe325..bced182 100644
--- a/impl/res/values-ur/strings.xml
+++ b/impl/res/values-ur/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"وارننگ:"</u></b>" زیادہ درجہ حرارت پر طویل استعمال اس آلے کی طویل بیٹری کی صحت پر منفی اثر ڈال سکتا ہے۔"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"دوبارہ نہ دکھائیں"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"تسلیم کریں"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"بیک کیمرا"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"فرنٹ کیمرا"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"معیاری کیمرا"</string>
diff --git a/impl/res/values-uz/strings.xml b/impl/res/values-uz/strings.xml
index ed0e5c6..88f5916 100644
--- a/impl/res/values-uz/strings.xml
+++ b/impl/res/values-uz/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"OGOHLANTIRISH:"</u></b>" Yuqori haroratlarda uzoq muddat foydalanish qurilma batareya holatiga salbiy taʼsir koʻrsatishi mumkin."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Boshqa chiqmasin"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Tasdiqlash"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Orqa kamera"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Old kamera"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Standart kamera"</string>
diff --git a/impl/res/values-vi/strings.xml b/impl/res/values-vi/strings.xml
index f6afc3a..37a3593 100644
--- a/impl/res/values-vi/strings.xml
+++ b/impl/res/values-vi/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"CẢNH BÁO:"</u></b>" Việc sử dụng trong thời gian dài ở nhiệt độ cao có thể ảnh hưởng xấu đến tình trạng pin của thiết bị này về lâu dài."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Không hiện lại"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Xác nhận"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Camera sau"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Camera trước"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Camera chuẩn"</string>
diff --git a/impl/res/values-zh-rCN/strings.xml b/impl/res/values-zh-rCN/strings.xml
index ceeefb4..d8f6c47 100644
--- a/impl/res/values-zh-rCN/strings.xml
+++ b/impl/res/values-zh-rCN/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"警告："</u></b>"长时间在高温下使用可能会对此设备的长期电池健康度造成不利影响。"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"不再显示"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"确认"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"后置摄像头"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"前置摄像头"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"标准摄像头"</string>
diff --git a/impl/res/values-zh-rHK/strings.xml b/impl/res/values-zh-rHK/strings.xml
index 35222ac..91f9719 100644
--- a/impl/res/values-zh-rHK/strings.xml
+++ b/impl/res/values-zh-rHK/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"警告："</u></b>"在裝置溫度高時長時間使用，可能會對此裝置長遠的電池效能造成負面影響。"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"不要再顯示"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"確認"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"後置鏡頭"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"前置鏡頭"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"標準鏡頭"</string>
diff --git a/impl/res/values-zh-rTW/strings.xml b/impl/res/values-zh-rTW/strings.xml
index 432d5bf..0926a04 100644
--- a/impl/res/values-zh-rTW/strings.xml
+++ b/impl/res/values-zh-rTW/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"警告："</u></b>"在高溫下長時間使用，可能會對此裝置長期的電池健康度產生不利影響。"</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"不要再顯示"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"確認"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"high.quality.mode.enabled"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"high.quality.warning.enabled"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"後置鏡頭"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"前置鏡頭"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"標準鏡頭"</string>
diff --git a/impl/res/values-zu/strings.xml b/impl/res/values-zu/strings.xml
index ba4aa23..505e5cd 100644
--- a/impl/res/values-zu/strings.xml
+++ b/impl/res/values-zu/strings.xml
@@ -30,13 +30,6 @@
     <string name="hq_warning_dialog_content_2" msgid="3916465225973908142"><b><u>"ISEXWAYISO:"</u></b>" Ukusetshenziswa isikhathi eside emazingeni okushisa aphezulu kungase kube nomthelela omubi empilweni yebhethri yesikhathi eside yale divayisi."</string>
     <string name="hq_warning_dialog_dont_show_again" msgid="7673771228725839758">"Ungabonisi futhi"</string>
     <string name="hq_warning_dialog_button_ack" msgid="613756451667553632">"Vuma"</string>
-    <string name="prefs_file_name" msgid="1594472134069722000">"com.android.DeviceAsWebcam.user.prefs"</string>
-    <string name="prefs_camera_id_key" msgid="5865987824227186440">"camera.id"</string>
-    <string name="prefs_back_camera_id_key" msgid="2529978796301129676">"back.camera.id"</string>
-    <string name="prefs_front_camera_id_key" msgid="5008356857509132687">"front.camera.id"</string>
-    <string name="prefs_zoom_ratio_key" msgid="5198404806322533867">"zoom.ratio.%s"</string>
-    <string name="prefs_high_quality_mode_enabled" msgid="6399835233745563577">"imodi.yekhwalithi.ephezulu.ivuliwe"</string>
-    <string name="prefs_high_quality_warning_enabled" msgid="3869127585273122773">"isexwayiso.sekhwalithi ephezulu.sinikwe amandla"</string>
     <string name="list_item_text_back_camera" msgid="3350389854150173621">"Ikhamera engemuva"</string>
     <string name="list_item_text_front_camera" msgid="3031661498601814899">"Ikhamera engaphambili"</string>
     <string name="list_item_text_standard_camera" msgid="2095831547376259596">"Ikhamera evamile"</string>
diff --git a/impl/res/values/strings.xml b/impl/res/values/strings.xml
index 27c1713..1b1425b 100644
--- a/impl/res/values/strings.xml
+++ b/impl/res/values/strings.xml
@@ -39,13 +39,13 @@
     <string name="hq_warning_dialog_button_ack">Acknowledge</string>
 
     <!-- Strings for reading/writing user preferences to SharedPreferences -->
-    <string name="prefs_file_name">com.android.DeviceAsWebcam.user.prefs</string>
-    <string name="prefs_camera_id_key">camera.id</string>
-    <string name="prefs_back_camera_id_key">back.camera.id</string>
-    <string name="prefs_front_camera_id_key">front.camera.id</string>
-    <string name="prefs_zoom_ratio_key">zoom.ratio.%s</string>
-    <string name="prefs_high_quality_mode_enabled">high.quality.mode.enabled</string>
-    <string name="prefs_high_quality_warning_enabled">high.quality.warning.enabled</string>
+    <string name="prefs_file_name" translatable="false">com.android.DeviceAsWebcam.user.prefs</string>
+    <string name="prefs_camera_id_key" translatable="false">camera.id</string>
+    <string name="prefs_back_camera_id_key" translatable="false">back.camera.id</string>
+    <string name="prefs_front_camera_id_key" translatable="false">front.camera.id</string>
+    <string name="prefs_zoom_ratio_key" translatable="false">zoom.ratio.%s</string>
+    <string name="prefs_high_quality_mode_enabled" translatable="false">high.quality.mode.enabled</string>
+    <string name="prefs_high_quality_warning_enabled" translatable="false">high.quality.warning.enabled</string>
 
     <!-- Strings for switch camera selector dialog -->
     <string name="list_item_text_back_camera">Back camera</string>
diff --git a/impl/src/com/android/deviceaswebcam/CameraController.java b/impl/src/com/android/deviceaswebcam/CameraController.java
index bd20909..1578d6d 100644
--- a/impl/src/com/android/deviceaswebcam/CameraController.java
+++ b/impl/src/com/android/deviceaswebcam/CameraController.java
@@ -55,7 +55,6 @@ import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
 import com.android.DeviceAsWebcam.R;
-import com.android.deviceaswebcam.flags.Flags;
 import com.android.deviceaswebcam.utils.UserPrefs;
 
 import java.nio.ByteBuffer;
@@ -360,8 +359,7 @@ public class CameraController {
         mCameraManager.registerAvailabilityCallback(
                 mCameraCallbacksExecutor, mCameraAvailabilityCallbacks);
         mUserPrefs = new UserPrefs(mContext);
-        mHighQualityModeEnabled = Flags.highQualityToggle() &&
-                mUserPrefs.fetchHighQualityModeEnabled(/*defaultValue*/ false);
+        mHighQualityModeEnabled = mUserPrefs.fetchHighQualityModeEnabled(/*defaultValue*/ false);
         mRroCameraInfo = createVendorCameraPrefs(mHighQualityModeEnabled);
         refreshAvailableCameraIdList();
         refreshLensFacingCameraIds();
diff --git a/impl/src/com/android/deviceaswebcam/DeviceAsWebcamPreview.java b/impl/src/com/android/deviceaswebcam/DeviceAsWebcamPreview.java
index dbba26c..47f92da 100644
--- a/impl/src/com/android/deviceaswebcam/DeviceAsWebcamPreview.java
+++ b/impl/src/com/android/deviceaswebcam/DeviceAsWebcamPreview.java
@@ -70,7 +70,6 @@ import androidx.window.layout.WindowMetrics;
 import androidx.window.layout.WindowMetricsCalculator;
 
 import com.android.DeviceAsWebcam.R;
-import com.android.deviceaswebcam.flags.Flags;
 import com.android.deviceaswebcam.utils.UserPrefs;
 import com.android.deviceaswebcam.view.CameraPickerDialog;
 import com.android.deviceaswebcam.view.ZoomController;
@@ -651,10 +650,6 @@ public class DeviceAsWebcamPreview extends FragmentActivity {
             return WindowInsets.CONSUMED;
         });
 
-        if (!Flags.highQualityToggle()) {
-            mHighQualityToggleButton.setVisibility(View.GONE);
-        }
-
         bindService(
                 new Intent(this, DeviceAsWebcamFgServiceImpl.class),
                 0,
diff --git a/interface/res/values-iw/strings.xml b/interface/res/values-iw/strings.xml
index 0f1c473..aaabf5a 100644
--- a/interface/res/values-iw/strings.xml
+++ b/interface/res/values-iw/strings.xml
@@ -19,5 +19,5 @@
     <string name="notif_channel_name" msgid="6360649882588343016">"שירות שפועל בחזית"</string>
     <string name="notif_ticker" msgid="6915460822395652567">"מצלמת אינטרנט"</string>
     <string name="notif_title" msgid="802425098359640082">"מצלמת אינטרנט"</string>
-    <string name="notif_desc" msgid="2524105328454274946">"יש להקיש כדי לראות תצוגה מקדימה ולהגדיר את הפלט של מצלמת האינטרנט"</string>
+    <string name="notif_desc" msgid="2524105328454274946">"יש ללחוץ כדי לראות תצוגה מקדימה ולהגדיר את הפלט של מצלמת האינטרנט"</string>
 </resources>
diff --git a/interface/src/com/android/deviceaswebcam/DeviceAsWebcamReceiver.java b/interface/src/com/android/deviceaswebcam/DeviceAsWebcamReceiver.java
index f3cf1a2..15fd9f6 100644
--- a/interface/src/com/android/deviceaswebcam/DeviceAsWebcamReceiver.java
+++ b/interface/src/com/android/deviceaswebcam/DeviceAsWebcamReceiver.java
@@ -41,12 +41,15 @@ public abstract class DeviceAsWebcamReceiver extends BroadcastReceiver {
     public final void onReceive(Context context, Intent intent) {
         final String action = intent.getAction();
         Bundle extras = intent.getExtras();
+        if (extras == null) {
+            return;
+        }
         boolean uvcSelected = extras.getBoolean(UsbManager.USB_FUNCTION_UVC);
         if (VERBOSE) {
             Log.v(TAG, "Got broadcast with extras" + extras);
         }
         if (!UsbManager.isUvcSupportEnabled()) {
-            Log.e(TAG, "UVC support isn't enabled, why do we have DeviceAsWebcam installed ?");
+            Log.i(TAG, "UVC support isn't enabled. Returning early.");
             return;
         }
         if (UsbManager.ACTION_USB_STATE.equals(action) && uvcSelected) {
diff --git a/tests/run_webcam_test.py b/tests/run_webcam_test.py
index 2795598..9dac492 100644
--- a/tests/run_webcam_test.py
+++ b/tests/run_webcam_test.py
@@ -31,7 +31,9 @@ class DeviceAsWebcamTest(base_test.BaseTestClass):
   _ACTION_WEBCAM_RESULT = 'com.android.cts.verifier.camera.webcam.ACTION_WEBCAM_RESULT'
   _WEBCAM_RESULTS = 'camera.webcam.extra.RESULTS'
   _WEBCAM_TEST_ACTIVITY = 'com.android.cts.verifier/.camera.webcam.WebcamTestActivity'
-  _DAC_PREVIEW_ACTIVITY = 'com.android.DeviceAsWebcam/.DeviceAsWebcamPreview'
+  # TODO(373791776): Find a way to discover PreviewActivity for vendors that change
+  # the webcam service.
+  _DAC_PREVIEW_ACTIVITY = 'com.android.DeviceAsWebcam/com.android.deviceaswebcam.DeviceAsWebcamPreview'
   _ACTIVITY_START_WAIT = 1.5  # seconds
   _ADB_RESTART_WAIT = 9  # seconds
   _FPS_TOLERANCE = 0.15 # 15 percent
```

