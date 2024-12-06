```diff
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 24a8f05d..43613fd0 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -38,7 +38,7 @@
     <string name="wifi_required_title" msgid="7266700488421122218">"Спампоўка занадта вялікая для сеткі аператара"</string>
     <string name="wifi_required_body" msgid="4005023496578941958">"Каб завяршыць спампаванне файла памерам <xliff:g id="SIZE">%1$s </xliff:g>, патрабуецца падлучэнне да сеткi Wi-Fi. \n\nДакранiцеся да надпiсу <xliff:g id="QUEUE_TEXT">%2$s </xliff:g>, каб пачаць спампаванне, калi будзе даступна сетка Wi-Fi."</string>
     <string name="wifi_recommended_title" msgid="6488158053932133804">"Стаць у чаргу, каб спампаваць пазней?"</string>
-    <string name="wifi_recommended_body" msgid="8710820743211704403">"Спампаванне файла памерам <xliff:g id="SIZE">%1$s </xliff:g> можа скараціць тэрмін службы акумулятара або прывесці да празмернага выкарыстання мабільнага падлучэння дадзеных, за што вашым мабiльным аператарам можа спаганяцца дадатковая плата.\n\nДакранiцеся да надпiсу <xliff:g id="QUEUE_TEXT">%2$s</xliff:g>, каб пачаць спампаванне, калi з\'явiцца падлучэнне да сеткi Wi-Fi."</string>
+    <string name="wifi_recommended_body" msgid="8710820743211704403">"Спампаванне файла памерам <xliff:g id="SIZE">%1$s </xliff:g> можа скараціць тэрмін службы акумулятара або прывесці да празмернага выкарыстання мабільнага падлучэння дадзеных, за што вашым мабiльным аператарам можа спаганяцца дадатковая плата.\n\nДакранiцеся да надпiсу <xliff:g id="QUEUE_TEXT">%2$s</xliff:g>, каб пачаць спампаванне, калi з’явiцца падлучэнне да сеткi Wi-Fi."</string>
     <string name="button_queue_for_wifi" msgid="6650185573566994738">"Чарга"</string>
     <string name="button_cancel_download" msgid="4135046775536601831">"Скасаваць"</string>
     <string name="button_start_now" msgid="3817100969365441730">"Пачаць прама цяпер"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index b340e096..46089b2a 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -25,20 +25,20 @@
     <string name="permlab_downloadCompletedIntent" msgid="2674407390116052956">"Send download notifications."</string>
     <string name="permdesc_downloadCompletedIntent" msgid="3384693829639860032">"Allows the app to send notifications about completed downloads. Malicious apps can use this to confuse other apps that download files."</string>
     <string name="permlab_downloadCacheNonPurgeable" msgid="4538031250425141333">"Reserve space in the download cache"</string>
-    <string name="permdesc_downloadCacheNonPurgeable" msgid="3071381088686444674">"Allows the app to download files to the download cache, which can\'t be deleted automatically when the download manager needs more space."</string>
+    <string name="permdesc_downloadCacheNonPurgeable" msgid="3071381088686444674">"Allows the app to download files to the download cache, which can\'t be automatically deleted when the download manager needs more space."</string>
     <string name="permlab_downloadWithoutNotification" msgid="4877101864770265405">"download files without notification"</string>
-    <string name="permdesc_downloadWithoutNotification" msgid="7699189763226483523">"Allows the application to download files through the download manager without any notification being shown to the user."</string>
+    <string name="permdesc_downloadWithoutNotification" msgid="7699189763226483523">"Allows the app to download files through the download manager without any notification being shown to the user."</string>
     <string name="permlab_accessAllDownloads" msgid="8227356876527248611">"Access all system downloads"</string>
     <string name="permdesc_accessAllDownloads" msgid="7541731738152145079">"Allows the app to view and modify all downloads initiated by any app on the system."</string>
     <string name="download_unknown_title" msgid="1017800350818840396">"&lt;Untitled&gt;"</string>
     <string name="notification_download_complete" msgid="466652037490092787">"Download complete."</string>
     <string name="notification_download_failed" msgid="3932167763860605874">"Download unsuccessful."</string>
-    <string name="notification_need_wifi_for_size" msgid="4743443900432303646">"Download size requires Wi-Fi"</string>
-    <string name="notification_paused_in_background" msgid="6393408819031041778">"Paused in background"</string>
+    <string name="notification_need_wifi_for_size" msgid="4743443900432303646">"Download size requires Wi-Fi."</string>
+    <string name="notification_paused_in_background" msgid="6393408819031041778">"Paused in background."</string>
     <string name="wifi_required_title" msgid="7266700488421122218">"Download too large for operator network"</string>
-    <string name="wifi_required_body" msgid="4005023496578941958">"You must use Wi-Fi to complete this <xliff:g id="SIZE">%1$s </xliff:g> download. \n\nTouch <xliff:g id="QUEUE_TEXT">%2$s </xliff:g> to start this download the next time that you\'re connected to a Wi-Fi network."</string>
+    <string name="wifi_required_body" msgid="4005023496578941958">"You must use Wi-Fi to complete this <xliff:g id="SIZE">%1$s </xliff:g> download. \n\nTouch <xliff:g id="QUEUE_TEXT">%2$s </xliff:g> to start this download the next time you\'re connected to a Wi-Fi network."</string>
     <string name="wifi_recommended_title" msgid="6488158053932133804">"Queue for download later?"</string>
-    <string name="wifi_recommended_body" msgid="8710820743211704403">"Starting this <xliff:g id="SIZE">%1$s </xliff:g> download now may shorten your battery life and/or result in excessive usage of your mobile data connection, which can lead to charges by your mobile operator depending on your data plan.\n\n Touch <xliff:g id="QUEUE_TEXT">%2$s</xliff:g> to start this download the next time that you\'re connected to a Wi-Fi network."</string>
+    <string name="wifi_recommended_body" msgid="8710820743211704403">"Starting this <xliff:g id="SIZE">%1$s </xliff:g> download now may shorten your battery life and/or result in excessive usage of your mobile data connection, which can lead to charges by your mobile operator depending on your data plan.\n\n Touch <xliff:g id="QUEUE_TEXT">%2$s</xliff:g> to start this download the next time you\'re connected to a Wi-Fi network."</string>
     <string name="button_queue_for_wifi" msgid="6650185573566994738">"Queue"</string>
     <string name="button_cancel_download" msgid="4135046775536601831">"Cancel"</string>
     <string name="button_start_now" msgid="3817100969365441730">"Start now"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 8a055c47..93f40be9 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -30,7 +30,7 @@
     <string name="permdesc_downloadWithoutNotification" msgid="7699189763226483523">"‏به برنامه اجازه می‌دهد فایل‌ها را از طریق Download Manager، بدون نمایش اعلان به کاربر بارگیری کند."</string>
     <string name="permlab_accessAllDownloads" msgid="8227356876527248611">"دسترسی به همه بارگیری‌های سیستم"</string>
     <string name="permdesc_accessAllDownloads" msgid="7541731738152145079">"به برنامه اجازه می‌دهد تمام بارگیری‌های شروع شده توسط هر برنامه‌ای را در سیستم مشاهده کرده و تغییر دهد."</string>
-    <string name="download_unknown_title" msgid="1017800350818840396">"‏&lt;بدون عنوان&gt;"</string>
+    <string name="download_unknown_title" msgid="1017800350818840396">"‏&lt;بی‌عنوان&gt;"</string>
     <string name="notification_download_complete" msgid="466652037490092787">"بارگیری کامل شد."</string>
     <string name="notification_download_failed" msgid="3932167763860605874">"بارگیری ناموفق بود."</string>
     <string name="notification_need_wifi_for_size" msgid="4743443900432303646">"‏برای این حجم از بارگیری به Wi-Fi نیاز است."</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 51956737..c2ad8e5f 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -19,7 +19,7 @@
     <string name="app_label" msgid="5264040740662487684">"ಡೌನ್‌ಲೋಡ್ ಮ್ಯಾನೇಜರ್"</string>
     <string name="storage_description" msgid="169690279447532621">"ಡೌನ್‌ಲೋಡ್‌ಗಳು"</string>
     <string name="permlab_downloadManager" msgid="4241473724446132797">"ಡೌನ್‌ಲೋಡ್‌ ನಿರ್ವಾಹಕವನ್ನು ಪ್ರವೇಶಿಸಿ."</string>
-    <string name="permdesc_downloadManager" msgid="5562734314998369030">"ಡೌನ್‌ಲೋಡ್‌ ನಿರ್ವಾಹಕವನ್ನು ಪ್ರವೇಶಿಸಲು ಮತ್ತು ಡೌನ್‌ಲೋಡ್‌ ಫೈಲ್‌ಗಳನ್ನು ಬಳಸಲು ಅಪ್ಲಿಕೇಶನ್‌ ಅನುಮತಿ ನೀಡುತ್ತದೆ. ದುರುದ್ದೇಶಪೂರಿತ ಅಪ್ಲಿಕೇಶನ್‌ಗಳು, ಡೌನ್‌ಲೋಡ್‌ಗಳನ್ನು ಭಗ್ನಗೊಳಿಸಲು ಹಾಗೂ ಖಾಸಗಿ ಮಾಹಿತಿಯನ್ನು ಪ್ರವೇಶಿಸಲು ಇದನ್ನು ಬಳಸಿಕೊಳ್ಳಬಹುದು."</string>
+    <string name="permdesc_downloadManager" msgid="5562734314998369030">"ಡೌನ್‌ಲೋಡ್‌ ನಿರ್ವಾಹಕವನ್ನು ಪ್ರವೇಶಿಸಲು ಮತ್ತು ಡೌನ್‌ಲೋಡ್‌ ಫೈಲ್‌ಗಳನ್ನು ಬಳಸಲು ಆ್ಯಪ್‌ ಅನುಮತಿ ನೀಡುತ್ತದೆ. ದುರುದ್ದೇಶಪೂರಿತ ಆ್ಯಪ್‌ಗಳು, ಡೌನ್‌ಲೋಡ್‌ಗಳನ್ನು ಭಗ್ನಗೊಳಿಸಲು ಹಾಗೂ ಖಾಸಗಿ ಮಾಹಿತಿಯನ್ನು ಪ್ರವೇಶಿಸಲು ಇದನ್ನು ಬಳಸಿಕೊಳ್ಳಬಹುದು."</string>
     <string name="permlab_downloadManagerAdvanced" msgid="2225663947531460795">"ಸುಧಾರಿತ ಡೌನ್‌ಲೋಡ್‌ ನಿರ್ವಾಹಕ ಕಾರ್ಯಚಟುವಟಿಕೆಗಳು."</string>
     <string name="permdesc_downloadManagerAdvanced" msgid="3902478062563030716">"ಡೌನ್‌ಲೋಡ್‌ ನಿರ್ವಾಹಕದ ಸುಧಾರಿತ ಕಾರ್ಯಚಟುವಟಿಕೆಗಳನ್ನು ಪ್ರವೇಶಿಸಲು ಅಪ್ಲಿಕೇಶನ್‌‌ಗೆ ಅನುಮತಿ ನೀಡುತ್ತದೆ. ದುರುದ್ದೇಶಪೂರಿತ ಅಪ್ಲಿಕೇಶನ್‌ಗಳು, ಡೌನ್‌ಲೋಡ್‌ಗಳನ್ನು ಭಗ್ನಗೊಳಿಸಲು ಹಾಗೂ ಖಾಸಗಿ ಮಾಹಿತಿಯನ್ನು ಪ್ರವೇಶಿಸಲು ಇದನ್ನು ಬಳಸಿಕೊಳ್ಳಬಹುದು."</string>
     <string name="permlab_downloadCompletedIntent" msgid="2674407390116052956">"ಡೌನ್‌ಲೋಡ್‌ ಅಧಿಸೂಚನೆಗಳನ್ನು ಕಳುಹಿಸು."</string>
@@ -29,7 +29,7 @@
     <string name="permlab_downloadWithoutNotification" msgid="4877101864770265405">"ನೋಟಿಫಿಕೇಶನ್ ಇಲ್ಲದೆಯೇ ಫೈಲ್‌ಗಳನ್ನು ಡೌನ್‌ಲೋಡ್‌‌ ಮಾಡಿ"</string>
     <string name="permdesc_downloadWithoutNotification" msgid="7699189763226483523">"ಯಾವುದೇ ಅಧಿಸೂಚನೆಯನ್ನು ಬಳಕೆದಾರರಿಗೆ ತೋರಿಸದೇ ಡೌನ್‌ಲೋಡ್‌ ನಿರ್ವಾಹಕದ ಮೂಲಕ ಫೈಲ್‌ಗಳನ್ನು ಡೌನ್‌ಲೋಡ್‌ ಮಾಡಲು ಅಪ್ಲಿಕೇಶನ್‌‌ಗೆ ಅನುಮತಿ ನೀಡುತ್ತದೆ."</string>
     <string name="permlab_accessAllDownloads" msgid="8227356876527248611">"ಎಲ್ಲ ಸಿಸ್ಟಂನ ಡೌನ್‌ಲೋಡ್‌ಗಳನ್ನು ಪ್ರವೇಶಿಸಿ"</string>
-    <string name="permdesc_accessAllDownloads" msgid="7541731738152145079">"ಸಿಸ್ಟಂನಲ್ಲಿ ಯಾವುದೇ ಅಪ್ಲಿಕೇಶನ್‌ ಮೂಲಕ ಆರಂಭಿಸಲಾದ ಎಲ್ಲ ಡೌನ್‌ಲೋಡ್‌ಗಳನ್ನು ವೀಕ್ಷಿಸಲು ಮತ್ತು ಮಾರ್ಪಡಿಸಲು ಅಪ್ಲಿಕೇಶನ್‌‌ಗೆ ಅನುಮತಿ ನೀಡಲಾಗುತ್ತದೆ."</string>
+    <string name="permdesc_accessAllDownloads" msgid="7541731738152145079">"ಸಿಸ್ಟಂನಲ್ಲಿ ಯಾವುದೇ ಆ್ಯಪ್‌ ಮೂಲಕ ಆರಂಭಿಸಲಾದ ಎಲ್ಲ ಡೌನ್‌ಲೋಡ್‌ಗಳನ್ನು ವೀಕ್ಷಿಸಲು ಮತ್ತು ಮಾರ್ಪಡಿಸಲು ಆ್ಯಪ್‌ಗೆ ಅನುಮತಿ ನೀಡಲಾಗುತ್ತದೆ."</string>
     <string name="download_unknown_title" msgid="1017800350818840396">"&lt;ಶೀರ್ಷಿಕೆ ರಹಿತ&gt;"</string>
     <string name="notification_download_complete" msgid="466652037490092787">"ಡೌನ್‌ಲೋಡ್‌‌ ಪೂರ್ಣಗೊಂಡಿದೆ."</string>
     <string name="notification_download_failed" msgid="3932167763860605874">"ಡೌನ್‌ಲೋಡ್‌ ವಿಫಲಗೊಂಡಿದೆ."</string>
diff --git a/tests/Android.bp b/tests/Android.bp
index 481e6173..554cbb90 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -26,9 +26,9 @@ android_test {
     ],
 
     libs: [
-        "android.test.base",
-        "android.test.mock",
-        "android.test.runner",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+        "android.test.runner.stubs.system",
     ],
 
     static_libs: [
diff --git a/tests/AndroidManifest.xml b/tests/AndroidManifest.xml
index 56f67742..fe2f670f 100644
--- a/tests/AndroidManifest.xml
+++ b/tests/AndroidManifest.xml
@@ -29,8 +29,8 @@
     The test declared in this instrumentation can be run via this command
     "adb shell am instrument -w com.android.providers.downloads.tests/android.test.InstrumentationTestRunner"
     -->
-    <instrumentation android:name="android.test.InstrumentationTestRunner"
-                     android:targetPackage="com.android.providers.downloads"
-                     android:label="Tests for Download Manager"/>
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+        android:targetPackage="com.android.providers.downloads"
+        android:label="Tests for Download Manager"/>
 
 </manifest>
diff --git a/tests/AndroidTest.xml b/tests/AndroidTest.xml
index 35eb09f7..31b1d0a7 100644
--- a/tests/AndroidTest.xml
+++ b/tests/AndroidTest.xml
@@ -23,7 +23,7 @@
     <option name="test-tag" value="DownloadProviderTests" />
     <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
         <option name="package" value="com.android.providers.downloads.tests" />
-        <option name="runner" value="android.test.InstrumentationTestRunner" />
+        <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" />
         <option name="hidden-api-checks" value="false"/>
     </test>
 </configuration>
diff --git a/tests/permission/Android.bp b/tests/permission/Android.bp
index 7136f2c4..b147a55c 100644
--- a/tests/permission/Android.bp
+++ b/tests/permission/Android.bp
@@ -27,8 +27,8 @@ android_test {
     ],
 
     libs: [
-        "android.test.base",
-        "android.test.runner",
+        "android.test.base.stubs.system",
+        "android.test.runner.stubs.system",
     ],
 
     static_libs: [
diff --git a/tests/public_api_access/Android.bp b/tests/public_api_access/Android.bp
index 5975ed2f..f7f992d9 100644
--- a/tests/public_api_access/Android.bp
+++ b/tests/public_api_access/Android.bp
@@ -27,8 +27,8 @@ android_test {
     ],
 
     libs: [
-        "android.test.base",
-        "android.test.runner",
+        "android.test.base.stubs.system",
+        "android.test.runner.stubs.system",
     ],
 
     static_libs: [
diff --git a/ui/res/values-en-rCA/strings.xml b/ui/res/values-en-rCA/strings.xml
index e53ea60b..8a6c0e92 100644
--- a/ui/res/values-en-rCA/strings.xml
+++ b/ui/res/values-en-rCA/strings.xml
@@ -30,13 +30,13 @@
     <string name="dialog_title_not_available" msgid="7793272183758002416">"Couldn\'t download"</string>
     <string name="dialog_failed_body" msgid="4538779125597383173">"Do you want to retry downloading the file later or delete it from the queue?"</string>
     <string name="dialog_title_queued_body" msgid="7481231558376227012">"File in queue"</string>
-    <string name="dialog_queued_body" msgid="2374398802707010234">"This file is queued for future download, so isn\'t available yet."</string>
+    <string name="dialog_queued_body" msgid="2374398802707010234">"This file is queued for future download so isn\'t available yet."</string>
     <string name="dialog_file_missing_body" msgid="7896653198405160564">"Can\'t find the downloaded file."</string>
     <string name="dialog_insufficient_space_on_external" msgid="1847671628253287114">"Can\'t finish download. There isn\'t enough space on external storage."</string>
-    <string name="dialog_insufficient_space_on_cache" msgid="703074452633529558">"Cannot finish download. There is not enough space on internal download storage."</string>
+    <string name="dialog_insufficient_space_on_cache" msgid="703074452633529558">"Can\'t finish download. There isn\'t enough space on internal download storage."</string>
     <string name="dialog_cannot_resume" msgid="3101433441301206866">"Download was interrupted and can\'t be resumed."</string>
     <string name="dialog_file_already_exists" msgid="6849168874901909994">"Can\'t download. The destination file already exists."</string>
-    <string name="dialog_media_not_found" msgid="7376030905821161865">"Cannot download. The external media are not available."</string>
+    <string name="dialog_media_not_found" msgid="7376030905821161865">"Can\'t download. The external media isn\'t available."</string>
     <string name="download_no_application_title" msgid="1209223807604231431">"Can\'t open file"</string>
     <string name="remove_download" msgid="244394809285977300">"Remove"</string>
     <string name="delete_download" msgid="1861638125603383676">"Delete"</string>
```

