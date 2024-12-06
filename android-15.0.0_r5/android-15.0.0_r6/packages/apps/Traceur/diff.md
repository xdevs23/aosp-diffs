```diff
diff --git a/Android.bp b/Android.bp
index be6f100f..0a1a478d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -10,16 +10,14 @@ android_app {
         shrink_resources: true,
     },
     static_libs: [
-        "androidx.leanback_leanback",
-        "androidx.leanback_leanback-preference",
-        "androidx.legacy_legacy-preference-v14",
         "androidx.appcompat_appcompat",
         "androidx.preference_preference",
         "androidx.recyclerview_recyclerview",
         "androidx.legacy_legacy-support-v4",
         "TraceurCommon",
+        "Traceur-res",
     ],
-    resource_dirs: ["res"],
+    resource_dirs: [],
     srcs: ["src/**/*.java"],
     defaults: [
         "SettingsLibDefaults",
@@ -37,3 +35,17 @@ android_library {
     resource_dirs: [],
     srcs: ["src_common/**/*.java"],
 }
+
+// Allow other build targets to access Traceur resources
+android_library {
+    name: "Traceur-res",
+    use_resource_processor: true,
+    static_libs: [
+        "androidx.leanback_leanback",
+        "androidx.leanback_leanback-preference",
+        "androidx.legacy_legacy-preference-v14",
+    ],
+    manifest: "AndroidManifest-res.xml",
+    resource_dirs: ["res"],
+    srcs: [],
+}
diff --git a/AndroidManifest-res.xml b/AndroidManifest-res.xml
new file mode 100644
index 00000000..8897dd7e
--- /dev/null
+++ b/AndroidManifest-res.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+ * Copyright (C) 2024 Google Inc.
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
+ -->
+<manifest package="com.android.traceur.res">
+    <application/>
+</manifest>
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index b03618c5..b02b5c27 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -21,7 +21,7 @@
      android:versionCode="2"
      android:versionName="1.0">
     <uses-sdk android:minSdkVersion="26"
-         android:targetSdkVersion="33"/>
+         android:targetSdkVersion="34"/>
 
     <!--- Used to query for Betterbug. -->
     <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>
@@ -46,6 +46,7 @@
 
     <!-- Used for brief periods where the trace service is foregrounded. -->
     <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
+    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE"/>
 
     <!-- Used to post file-sending notification. -->
     <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
@@ -118,6 +119,7 @@
 
         <activity android:name=".MainWearActivity"
                   android:description="@string/record_system_activity"
+                  android:icon="@drawable/bugfood_icon"
                   android:label="@string/system_tracing"
                   android:theme="@style/WearTheme"
                   android:launchMode="singleTask"
@@ -132,7 +134,6 @@
 
         <receiver android:name=".Receiver"
              android:permission="android.permission.DUMP"
-             androidprv:systemUserOnly="true"
              android:exported="true">
             <intent-filter android:priority="2147483647">
                 <action android:name="android.intent.action.BOOT_COMPLETED"/>
@@ -141,21 +142,23 @@
             </intent-filter>
           </receiver>
 
-        <receiver android:name=".InternalReceiver"
-            androidprv:systemUserOnly="true"
-            android:exported="false">
-        </receiver>
-
         <service android:name=".StopTraceService"
-             android:exported="true"/>
+             android:exported="true"
+             android:foregroundServiceType="specialUse">
+            <property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
+                 android:value="Used for ensuring that Traceur isn't killed while starting or stopping traces."/>
+        </service>
 
         <service android:name=".BindableTraceService"
             android:permission="android.permission.CONTROL_UI_TRACING"
-            androidprv:systemUserOnly="true"
             android:exported="true"/>
 
         <service android:name=".TraceService"
-             android:exported="false"/>
+             android:exported="false"
+             android:foregroundServiceType="specialUse">
+            <property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
+                 android:value="Used for ensuring that Traceur isn't killed while starting or stopping traces."/>
+        </service>
 
         <service android:name=".TracingQsService"
              android:enabled="false"
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 4824a8f8..197f3e3b 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Neem hoopstorting op"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Dit vang ’n hoopstorting vas van die prosesse wat in \"Hoopstortingprosesse\" gekies is"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Kies minstens een proses in die \"Hoopstortingprosesse\" om hoopstortings te versamel"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Begin nuwe spoor"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Samel Winscope-spore in"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Sluit gedetailleerde UI-telemetriedata in (kan oponthoud veroorsaak)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Spoor ontfoutbare programme na"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Stoor tans hoopstorting"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Hoopstorting is gestoor"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Tik om jou opname te deel"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Heg tans spoor aan foutverslag"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Heg spoor aan foutverslag"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Tik om BetterBug oop te maak"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Stop nasporing"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Stop CPU-profielbepaling"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Sommige sporingkategorieë is onbeskikbaar"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Stop opnames vir foutverslae"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Beëindig aktiewe opnames wanneer ’n foutverslag begin word"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Heg opnames by foutverslae aan"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Stuur opnames wat besig is outomaties na BetterBug toe wanneer ’n foutverslag opgehaal word"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Stuur opnames wat besig is outomaties na BetterBug toe wanneer ’n foutverslag opgehaal word. Opnames sal daarna voortgesit word."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Bekyk gestoorde lêers"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Nasporinginstellings"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Gestoorde lêers"</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index f7a89535..938dbde3 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"የቆሻሻ ቁልል ይቅዱ"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"በ«የቆሻሻ ቁልል ሂደቶች» ውስጥ የተመረጡትን ሂደቶች የቆሻሻ ቁልልን ይቀርጻል"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"የቆሻሻ ቁልሎችን ለመሰብሰብ በ«የቆሻሻ ቁልል ሂደቶች» ውስጥ ቢያንስ አንድ ሂደት ይምረጡ"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"አዲስ መከታተያ ይጀምሩ"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope መከታተያን ስብስብ"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"የዩአይ ቴሌሜትሪ ውሂብ ዝርዝር ያካትታል (Jank ያስከትላል)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ሊታረሙ የሚችሉ መተግበሪያዎችን ዱካ ይከታተሉ"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"የቆሻሻ ቁልል በማስቀመጥ ላይ"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"የቆሻሻ ቁልል ተቀምጧል"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"የእርስዎን ቀረጻ ለማጋራት መታ ያድርጉ"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"በሳንካ ሪፖርት ላይ መከታተያን አባሪ እያደረገ ነው"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"በሳንካ ሪፖርት ላይ መከታተያን አባሪ አድርግ"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBugን ለመክፈት መታ ያድርጉ"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"መከታተል አቁም"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"የሲፒዩ መገለጫ ምዘናን ያቁሙ"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"አንዳንድ የመከታተያ ምድቦች አይገኙም፦"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"የሳንካ ሪፖርቶችን መቅረጽ ያቁሙ"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"የሳንካ ሪፖርት ሲጀመር ገቢር ቀረጻዎችን ያጠናቅቃል"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ቀረጻዎችን ወደ ሳንካ ሪፖርቶች አባሪ ያድርጉ"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"የሳንካ ሪፖርት በሚሰበሰብበት ጊዜ በሂደት ላይ ያሉ ቀረጻዎችን በራስ-ሰር ወደ BetterBug ይላኩ"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"የሳንካ ሪፖርት በሚሰበሰብበት ጊዜ በሂደት ላይ ያሉ ቀረጻዎችን በራስ-ሰር ወደ BetterBug ይላኩ። ከዚያ በኋላ ቀረጻዎች ይቀጥላሉ።"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"የተቀመጡ ፋይሎችን አሳይ"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ቅንብሮችን ይከታተሉ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"የተቀመጡ ፋይሎች"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index d8ffe6b2..f233cd60 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"تسجيل لقطة لأجزاء من الذاكرة"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"عند اختيار إحدى \"العمليات الخاصة بلقطات لأجزاء من الذاكرة\"، يتم تسجيل اللقطة الخاصة بها"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"يجب اختيار عملية واحدة على الأقل من \"العمليات الخاصة بلقطات لأجزاء من الذاكرة\" لجمع هذه اللقطات"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"بدء عملية تتبّع جديدة"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"‏جمْع آثار أنشطة أداة Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"يتم تضمين بيانات تفصيلية للقياس عن بعد لواجهة المستخدم (يمكن أن يتسبّب ذلك في إيقاف مؤقت لعرض واجهة المستخدم)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"تتبّع التطبيقات التي يمكن تصحيح الأخطاء بها"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"جارٍ حفظ لقطة لأجزاء من الذاكرة"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"تم حفظ لقطة لأجزاء من الذاكرة"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"انقر لمشاركة التسجيل."</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"جارٍ إرفاق آثار الأنشطة إلى تقرير الخطأ."</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"تم إرفاق آثار الأنشطة إلى تقرير الخطأ"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"‏انقر لفتح BetterBug."</string>
     <string name="stop_tracing" msgid="8916938308534164152">"أوقف التتبّع"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"‏إيقاف تحليل وحدة المعالجة المركزية (CPU)"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"بعض فئات التتبّع غير متاحة:"</string>
@@ -76,7 +72,7 @@
     <string name="ten_gb" msgid="4150452462544299276">"10 غيغابايت"</string>
     <string name="twenty_gb" msgid="5717308686812140465">"20 غيغابايت"</string>
     <string name="ten_minutes" msgid="7039181194343961324">"10 دقائق"</string>
-    <string name="thirty_minutes" msgid="2575810799813531395">"30 دقائق"</string>
+    <string name="thirty_minutes" msgid="2575810799813531395">"30 دقيقة"</string>
     <string name="one_hour" msgid="5219232935307966891">"ساعة واحدة"</string>
     <string name="eight_hours" msgid="3207620892104451552">"8 ساعات"</string>
     <string name="twelve_hours" msgid="4647143276394563496">"12 ساعة"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"إيقاف التسجيل لتقارير الأخطاء"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"لإنهاء التسجيلات النشطة عند بدء تقرير أخطاء"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"إرفاق التسجيلات بتقارير الأخطاء"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"‏يمكنك تلقائيًا إرسال التسجيلات الجاري تسجيلها إلى BetterBug عند جمع تقرير خطأ."</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"‏يمكنك تلقائيًا إرسال التسجيلات الجاري تسجيلها إلى BetterBug عند جمع تقرير خطأ. بعد ذلك، سيستمر التسجيل."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"عرض الملفات المحفوظة"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"إعدادات التتبُّع"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"الملفات المحفوظة"</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 575b9647..52b2d42f 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"হীপ ডাম্প ৰেকৰ্ড কৰক"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"হীপ ডাম্প প্ৰক্ৰিয়াসমূহ\"ত বাছনি কৰা প্ৰক্ৰিয়াসমূহৰ এটা হিপ ডাম্প কেপচাৰ কৰে"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"হীপ ডাম্প সংগ্ৰহ কৰিবলৈ \"হীপ ডাম্পৰ প্ৰক্ৰিয়াসমূহ\"ত অতি কমেও এটা বাছনি কৰক"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"নতুন ট্ৰে’চ আৰম্ভ কৰক"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscopeৰ ট্ৰে’চ সংগ্ৰহ কৰক"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"বিস্তৃত UIৰ টেলিমেট্ৰী ডেটা অন্তৰ্ভুক্ত কৰে (জাংকৰ সৃষ্টি কৰিব পাৰে)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ডিবাগ কৰিবলগীয়া এপ্লিকেশ্বনসমূহ ট্ৰে\'চ কৰক"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"হীপ ডাম্প ছেভ কৰি থকা হৈছে"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"হীপ ডাম্প ছেভ কৰা হৈছে"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"অপোনাৰ ৰেকৰ্ডিং শ্বেয়াৰ কৰিবলৈ টিপক"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"বাগ ৰিপ’ৰ্টৰ সৈতে ট্ৰে’চ সংলগ্ন কৰি থকা হৈছে"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"বাগ ৰিপ’ৰ্টৰ সৈতে ট্ৰে’চ সংলগ্ন কৰা হ’ল"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug খুলিবলৈ টিপক"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"ট্ৰে\'চ ৰেকৰ্ড কৰা কাৰ্য বন্ধ কৰক"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU প্ৰ’ফাইলিং বন্ধ কৰক"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"ট্ৰে\'চৰ কিছুমান শ্ৰেণী অনুপলব্ধ:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"বাগ ৰিপ’ৰ্টৰ বাবে ৰেকৰ্ড কৰাটো বন্ধ কৰক"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"এটা বাগ ৰিপ’ৰ্ট আৰম্ভ কৰিলে সক্ৰিয় ৰেকৰ্ডিংসমূহৰ অন্ত পৰে"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"বাগ ৰিপ’ৰ্টত ৰেকৰ্ডিংসমূহ সংলগ্ন কৰক"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"যেতিয়া এটা বাগ ৰিপ’ৰ্ট সংগ্ৰহ কৰা হয়, চলি থকা ৰেকৰ্ডিংসমূহ BetterBugলৈ স্বয়ংক্ৰিয়ভাৱে পঠিয়াওক"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"যেতিয়া এটা বাগ ৰিপ’ৰ্ট সংগ্ৰহ কৰা হয়, চলি থকা ৰেকৰ্ডিংসমূহ স্বয়ংক্ৰিয়ভাৱে BetterBugলৈ পঠিয়াওক। তাৰ পাছত ৰেকৰ্ডিং চলি থাকিব।"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"ছেভ কৰা ফাইলসমূহ চাওক"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ট্ৰে’চৰ ছেটিং"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ছেভ কৰি থোৱা ফাইল"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 8b129e49..6c36b878 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Snepşotu qeyd edin"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"Snepşot prosesləri\"ndə seçilmiş proseslərin snepşotunu çəkir"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Snepşotları toplamaq üçün \"Snepşot prosesləri\"ndə ən azı bir proses seçin"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Yeni fəaliyyət izini başladın"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope izlərinin toplanması"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Detallı UI telemetriya datası daxildir (ləngiməyə səbəb ola bilər)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Silinə bilən tətbiqləri izləyin"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Snepşot saxlanır"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Snepşot saxlandı"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Qeydəalmanı paylaşmaq üçün toxunun"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Baq hesabatına fəaliyyət izi əlavə edilir"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Baq hesabatına fəaliyyət izi əlavə edilib"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Toxunaraq BetterBug\'ı açın"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Fəaliyyəti izləməyi dayandırın"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU təhlilini dayandırın"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Bəzi izləmə kateqaoriyaları əlçatan deyil:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Baq hesabatları üçün qeydəalmanı dayandırın"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Baq hesabatı başladıldıqda aktiv qeydəalmalar başa çatır"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Qeydəalmaları baq hesabatlarına əlavə edin"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Baq hesabatı əldə edildikdə davam edən qeydəalmaları BetterBug-a avtomatik göndərin"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Baq hesabatı əldə edildikdə davam edən çəkilişləri BetterBug-a avtomatik göndərin. Çəkilişlər bundan sonra davam edəcək."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Saxlanmış fayllara baxın"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Fəaliyyət izi ayarları"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saxlanmış fayllar"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 17035e82..13e72524 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Snimaj dinamički deo memorije za proces"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Snima dinamički deo memorije za procese izabrane u delu Procesi za snimanje dinamičkog dela memorije"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Da biste prikupljali snimke dinamičkog dela memorije za procese, izaberite bar jedan proces u delu Procesi za snimanje dinamičkog dela memorije"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Pokreni novo praćenje"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Prikupljaj Winscope tragove"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Obuhvata detaljne telemetrijske podatke o korisničkom interfejsu (može da izazove seckanje)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Prati aplikacije sa funkcijom za otklanjanje grešaka"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Čuva se snimak dinamičkog dela memorije za proces"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Snimak dinamičkog dela memorije za proces je sačuvan"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Dodirnite da biste delili snimak"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Praćenje se prilaže izveštaju o grešci"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Praćenje je priloženo izveštaju o grešci"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Dodirnite da biste otvorili BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Zaustavite traganje"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Zaustavite profilisanje procesora"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Neke kategorije praćenja nisu dostupne:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Zaustavi snimanje za izveštaje o grešci"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Zaustavlja aktivna snimanja kad se započne izveštaj o grešci"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Priložite snimke u izveštaje o grešci"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Automatski šalji snimke u toku na BetterBug po dobijanju izveštaja o grešci"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatski šaljite BetterBug-u snimke dok je snimanje u toku kada se prikupi izveštaj o grešci. Snimanje će se zatim nastaviti."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Prikaži sačuvane fajlove"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Podešavanja praćenja"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Sačuvani fajlovi"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 4fd1fe24..88a794ee 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Запісваць дамп дынамічнай памяці"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Будзе стварацца дамп дынамічнай памяці для працэсаў, выбраных у спісе \"Працэсы для дампу дынамічнай памяці\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Каб ствараць дампы дынамічнай памяці, выберыце хаця б адзін працэс у спісе \"Працэсы для дампу дынамічнай памяці\""</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Запусціць новую трасіроўку"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Запісваць трасіроўкі Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Уключае падрабязныя тэлеметрычныя даныя пра карыстальніцкі інтэрфейс (можа выклікаць часовае завісанне)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Трасіраваць праграмы з магчымасцю адладкi"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Ідзе захаванне дампу дынамічнай памяці"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Дамп дынамічнай памяці захаваны"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Націсніце, каб абагуліць запіс"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Да справаздачы пра памылкі далучаецца трасіроўка"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Да справаздачы пра памылкі далучана трасіроўка"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Націсніце, каб адкрыць BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Спыніць трасіроўку"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Спыніць прафіліраванне ЦП"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Некаторыя катэгорыі трасіроўкі недаступныя:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Спыняць запіс, калі ствараюцца справаздачы пра памылкі"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Калі пачынаецца стварэнне справаздач пра памылкі, запіс спыняецца"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Далучаць запісы да справаздач пра памылкі"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Пры складанні справаздачы пра памылкі аўтаматычна адпраўляць у BetterBug бягучыя даныя"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Пры складанні справаздачы пра памылкі аўтаматычна адпраўляць у BetterBug бягучыя даныя Пасля гэтага запіс працягнецца."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Праглядзець захаваныя файлы"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Налады трасіроўкі"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Захаваныя файлы"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 71fa2f38..02521a44 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Създаване на моментна снимка на паметта"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Създава моментна снимка на паметта за процесите, посочени в „Процеси с моментна снимка на паметта“"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Изберете поне един процес в „Процеси с моментна снимка на паметта“, за да извличате моментни снимки на паметта"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Стартиране на ново трасиране"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Събиране на трасирания в Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Включва подробни телеметрични данни за ПИ (може да доведе до прекъсвания на изобразяването)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Трасиране на приложенията с възможност за отстраняване на грешки"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Моментната снимка на паметта се запазва"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Моментната снимка на паметта е запазена"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Докоснете за споделяне на записа"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Трасирането се прикачва към сигнала за програмна грешка"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Прикачено трасиране към сигнала за програмна грешка"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Докоснете за отваряне на BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Спиране на трасирането"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Спиране на профилирането на процесора"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Някои категории трасирания не са налични:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Спиране на записването за сигнали за програмни грешки"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Прекратява активните записвания при стартиране на сигнал за програмна грешка"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Прикачване на записите към сигналите за програмни грешки"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Автоматично изпращане до BetterBug на записите в ход при създаването на сигнал за програмна грешка"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Автоматично изпращане до BetterBug на текущите записи при създаването на сигнал за програмна грешка. Записите ще продължат след това."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Преглед на запазените файлове"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Настройки за трасирането"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Запазени файлове"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 8c003c23..26ef2136 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -10,8 +10,7 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"হিপ ডাম্প রেকর্ড করুন"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"হিপ ডাম্পের প্রসেসে\" বেছে নেওয়া প্রসেসের হিপ ডাম্প ক্য়াপচার করুন"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"হিপ ডাম্প সংগ্রহ করতে \"হিপ ডাম্পের প্রসেসে\" কমপক্ষে একটি প্রসেস বেছে নিন"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"নতুন ট্রেস চালু করুন"</string>
-    <string name="winscope_tracing" msgid="5818984791154837458">"Winscopeএর ট্রেস সংগ্রহ করুন"</string>
+    <string name="winscope_tracing" msgid="5818984791154837458">"Winscope-এর ট্রেস সংগ্রহ করুন"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"এর মধ্যে UI সম্পর্কিত টেলিমেট্রি ডেটা অন্তর্ভুক্ত (এর জন্য জ্যাঙ্কের সম্ভাবনা আছে)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ডিবাগযোগ্য অ্যাপ্লিকেশন ট্রেস করুন"</string>
     <string name="categories" msgid="2280163673538611008">"বিভাগ"</string>
@@ -32,7 +31,7 @@
     <string name="one_minute" msgid="4182508213840684258">"১ মিনিট"</string>
     <string name="applications" msgid="521776761270770549">"অ্যাপ্লিকেশন"</string>
     <string name="no_debuggable_apps" msgid="4386209254520471208">"কোনও ডিবাগযোগ্য অ্যাপ্লিকেশন উপলভ্য নেই"</string>
-    <string name="buffer_size" msgid="3944311026715111454">"সিপিইউ পিছু বাফার সাইজ"</string>
+    <string name="buffer_size" msgid="3944311026715111454">"CPU-পিছু বাফার সাইজ"</string>
     <string name="show_quick_settings_tile" msgid="3827556161191376500">"কুইক সেটিংস টাইলে ট্রেস করা দেখুন"</string>
     <string name="show_stack_sampling_quick_settings_tile" msgid="2142507886797788822">"কুইক সেটিংস টাইলে সিপিইউ প্রোফাইল করা দেখুন"</string>
     <string name="saving_trace" msgid="1468692734770800541">"ট্রেস সেভ করা হচ্ছে"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"হিপ ডাম্প সেভ করা হচ্ছে"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"হিপ ডাম্প সেভ করা হয়েছে"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"আপনার রেকর্ডিং শেয়ার করতে ট্যাপ করুন"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"ট্রেসকে সমস্যার রিপোর্টে অ্যাটাচ করা হচ্ছে"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"ট্রেসকে সমস্যার রিপোর্টে অ্যাটাচ করা হয়েছে"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug খুলতে ট্যাপ করুন"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"ট্রেস করা বন্ধ করুন"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"সিপিইউ প্রোফাইল করা বন্ধ করুন"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"ট্রেসিং এর কিছু বিভাগ অনুপলভ্য:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"সমস্যা সংক্রান্ত রিপোর্টের জন্য রেকর্ডিং বন্ধ করুন"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"সমস্যা সম্পর্কিত রিপোর্ট শুরু হলে, চালু থাকা ট্রেস রেকর্ডিং বন্ধ হয়ে যায়"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"সমস্যা সম্পর্কিত রিপোর্টে রেকর্ডিং অ্যাটাচ করুন"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"সমস্যা সম্পর্কিত রিপোর্ট সংগ্রহ করা হলে, কাজ চলছে এমন রেকর্ডিং সম্পর্কিত তথ্য অটোমেটিক BetterBug-কে পাঠান"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"সমস্যা সম্পর্কিত রিপোর্ট সংগ্রহ করা হলে, কাজ চলছে এমন রেকর্ডিং সম্পর্কিত তথ্য অটোমেটিক BetterBug-কে পাঠান। রেকর্ডিং পরেও চলতে থাকবে।"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"সেভ করা ফাইল দেখুন"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"\'ট্রেস\' সেটিংস"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"সেভ করা ফাইল"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 208e99c5..55eee2ba 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -10,10 +10,9 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Snimi snimak dinamičkog dijela memorije"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Snima snimak dinamičkog dijela memorije procesa odabranih u odjeljku \"Procesi snimka dinamičkog dijela memorije\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Odaberite najmanje jedan proces u odjeljku \"Procesi snimka dinamičkog dijela memorije\" da prikupite snimke dinamičkog dijela memorije"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Pokreni novi trag"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Prikupljaj Winscope tragove"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Uključuje detaljne telemetrijske podatke korisničkog interfejsa (može uzrokovati smetnje)"</string>
-    <string name="trace_debuggable_applications" msgid="7957069895298887899">"Pratite aplikacije u načinu rada za otklanjanje grešaka"</string>
+    <string name="trace_debuggable_applications" msgid="7957069895298887899">"Prati aplikacije u načinu rada za otklanjanje grešaka"</string>
     <string name="categories" msgid="2280163673538611008">"Kategorije"</string>
     <string name="restore_default_categories" msgid="5090536794637169521">"Vrati zadane kategorije"</string>
     <string name="default_categories_restored" msgid="6861683793680564181">"Zadane kategorije su vraćene"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Pohranjivanje snimka dinamičkog dijela memorije"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Snimak dinamičkog dijela memorije je sačuvan"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Dodirnite da podijelite snimak"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Prilaganje traga praćenja uz izvještaj o grešci"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Trag praćenja je priložen uz izvještaj o grešci"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Dodirnite da otvorite BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Zaustavi praćenje tragova"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Zaustavite profiliranje procesora"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Neke kategorije praćenja nisu dostupne:"</string>
@@ -66,8 +62,8 @@
     <string name="share" msgid="8443979083706282338">"Dijeli"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Ne prikazuj opet"</string>
     <string name="long_traces" msgid="5110949471775966329">"Dugi tragovi"</string>
-    <string name="long_traces_summary" msgid="419034282946761469">"Kontinuirano čuvano u pohranu uređaja"</string>
-    <string name="long_traces_summary_betterbug" msgid="445546400875135624">"Neprestano se pohranjuje u pohranu uređaja (neće se automatski priložiti izvještajima o grešci)"</string>
+    <string name="long_traces_summary" msgid="419034282946761469">"Kontinuirano se pohranjuje u pohranu na uređaju"</string>
+    <string name="long_traces_summary_betterbug" msgid="445546400875135624">"Neprestano se pohranjuje u pohranu na uređaju (neće se automatski priložiti izvještajima o grešci)"</string>
     <string name="max_long_trace_size" msgid="1943788179787181241">"Maksimalna veličina dugog traga"</string>
     <string name="max_long_trace_duration" msgid="8009837944364246785">"Maksimalno trajanje dugog traga"</string>
     <string name="two_hundred_mb" msgid="4950018549725084512">"200 MB"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Zaustavi snimanje za izvještaje o greškama"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Zaustavlja aktivne snimke kada se pokrene izvještaj o grešci"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Priloži snimke izvještajima o greškama"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Automatski šaljite snimke koji su u toku BetterBugu kada se prikupi izvještaj o grešci"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatski šaljite snimke koji su u toku BetterBugu kada se prikupi izvještaj o grešci. Snimke će se nastaviti nakon toga."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Prikaži sačuvane fajlove"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Postavke praćenja"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Sačuvani fajlovi"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 46a0f331..5c033782 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Grava l\'abocament de memòria en monticle"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captura un abocament de memòria en monticle dels processos seleccionats a \"Processos d\'abocament de memòria en monticle\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecciona un procés com a mínim a \"Processos d\'abocament de memòria en monticle\" per recollir abocaments de memòria en monticle"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Inicia una traça nova"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Recull traces de WinScope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inclou dades detallades de telemetria de la IU (pot produir inestabilitat)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Traça aplicacions que es puguin depurar"</string>
@@ -32,7 +31,7 @@
     <string name="one_minute" msgid="4182508213840684258">"1 minut"</string>
     <string name="applications" msgid="521776761270770549">"Aplicacions"</string>
     <string name="no_debuggable_apps" msgid="4386209254520471208">"No hi ha cap aplicació que es pugui depurar disponible"</string>
-    <string name="buffer_size" msgid="3944311026715111454">"Mida de la memòria cau per cada CPU"</string>
+    <string name="buffer_size" msgid="3944311026715111454">"Mida de la memòria cau per CPU"</string>
     <string name="show_quick_settings_tile" msgid="3827556161191376500">"Mostra la icona de configuració ràpida del rastreig"</string>
     <string name="show_stack_sampling_quick_settings_tile" msgid="2142507886797788822">"Mostra la icona de configuració ràpida de l\'elaboració de perfils de CPU"</string>
     <string name="saving_trace" msgid="1468692734770800541">"S\'està desant la traça"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"S\'està desant l\'abocament de memòria en monticle"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"S\'ha desat l\'abocament de memòria en monticle"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Toca per compartir la teva gravació"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"S\'està adjuntant una traça a l\'informe d\'errors"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"S\'ha adjuntat una traça a l\'informe d\'errors"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Toca per obrir BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Atura l\'enregistrament de la traça"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Atura l\'elaboració de perfils de CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Algunes categories de traça no estan disponibles:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Deixa de gravar per als informes d\'errors"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Finalitza les gravacions actives quan s\'inicia un informe d\'errors"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Adjunta gravacions als informes d\'errors"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Envia automàticament gravacions en curs a BetterBug quan es reculli un informe d\'errors"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Envia automàticament gravacions en curs a BetterBug quan es reculli un informe d\'errors. Les gravacions continuaran després."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Mostra els fitxers desats"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Configuració de traça"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Fitxers desats"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 22a8accd..e9c830d0 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Zaznamenat výpis haldy"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Pořídí výpis haldy pro procesy vybrané v sekci Procesy pro výpisy haldy"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Pokud chcete shromažďovat výpisy haldy, vyberte alespoň jeden proces v sekci Procesy pro výpisy haldy"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Spustit nové trasování"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Shromažďovat trasování Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Zahrnuje podrobná telemetrická data uživatelského rozhraní (může vést k zasekávání)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Trasovat aplikace k ladění"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Ukládání výpisu haldy"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Výpis haldy byl uložen"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Klepnutím sdílejte nahrávku"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Připojování záznamu aktivity ke zprávě o chybě"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Ke zprávě o chybě byl přidán záznam aktivity"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Klepnutím otevřete BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Ukončit trasování"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Zastavte profilování procesoru"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Některé kategorie zaznamenávání nejsou k dispozici:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Ukončit nahrávání pro zprávy o chybách"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Ukončí aktivní nahrávky, když je vytvořena chybová zpráva"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Přikládat ke zprávám o chybách nahrávky"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Při záznamu chyby automaticky odesílat probíhající nahrávky do nástroje BetterBug"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Při získávání zprávy o chybě automaticky odesílat probíhající nahrávky do nástroje BetterBug. Nahrávání bude pokračovat."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Zobrazit uložené soubory"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Nastavení trasování"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Uložené soubory"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index a2361467..835e1feb 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Registrer heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Registrerer et heap dump af de processer, der er valgt i \"Heap dump-processer\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Vælg mindst én proces i \"Heap dump-processer\" for at indsamle heap dumps"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Start ny registrering"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Inkluder sporing af Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Omfatter detaljerede telemetridata for brugerfladen (man medføre hak)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Registrer apps, der kan fejlrettes"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Gemmer heap dump"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Heap dump er gemt"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Tryk for at dele din registrering"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Vedhæfter registrering til fejlrapport"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Vedhæftet registrering til fejlrapport"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Tryk for at åbne BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Stands sporing"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Stop CPU-profilering"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Nogle sporingskategorier er ikke tilgængelige:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Stop registrering til fejlrapporter"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Afslutter aktive registreringer, når en fejlrapport startes"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Vedhæft registreringer i fejlrapporter"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Send automatisk løbende registreringer til BetterBug, når der indhentes en fejlrapport"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Send automatisk løbende registreringer til BetterBug, når der indhentes en fejlrapport. Optagelser fortsætter efterfølgende."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Se gemte filer"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Indstillinger for registrering"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Gemte filer"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index a29718ac..05d10627 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -10,8 +10,7 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Heap-Dump aufzeichnen"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Ein Heap-Dump der in „Heap-Dump-Prozesse“ ausgewählten Prozesse wird aufgezeichnet"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Wähle mindestens einen Prozess in „Heap-Dump-Prozesse“ aus, um Heap-Dumps aufzuzeichnen"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Neuen Trace starten"</string>
-    <string name="winscope_tracing" msgid="5818984791154837458">"Winscope-Traces erfassen"</string>
+    <string name="winscope_tracing" msgid="5818984791154837458">"WinScope-Traces erfassen"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Enthält detaillierte UI-Telemetriedaten (kann zu Verzögerung führen)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Debug-fähige Anwendungen in Trace aufnehmen"</string>
     <string name="categories" msgid="2280163673538611008">"Kategorien"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Heap-Dump wird gespeichert"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Heap-Dump gespeichert"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Zum Teilen deiner Aufzeichnung tippen"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Trace wird an Fehlerbericht angehängt"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Trace wurde an den Fehlerbericht angehängt"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Tippen, um BetterBug zu öffnen"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Tracing beenden"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU-Profilerstellung beenden"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Einige Tracing-Kategorien sind nicht verfügbar:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Aufzeichnen für Fehlerberichte beenden"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Aktive Aufzeichnungen werden beendet, wenn ein Fehlerbericht gestartet wird"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Aufzeichnungen an Fehlerberichte anhängen"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Laufende Aufzeichnungen automatisch an BetterBug senden, wenn ein Fehlerbericht abgerufen wird"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Laufende Aufzeichnungen automatisch an BetterBug senden, wenn ein Fehlerbericht erfasst wird. Die Aufzeichnung wird anschließend fortgesetzt."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Gespeicherte Dateien ansehen"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Trace-Einstellungen"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Gespeicherte Dateien"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index d54243d1..448c2dec 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Καταγραφή στιγμιότυπου μνήμης"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Καταγράφει ένα στιγμιότυπο μνήμης των διεργασιών που έχουν επιλεχθεί στη λίστα Διεργασίες στιγμιότυπου μνήμης"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Επιλέξτε τουλάχιστον μία διεργασία από τη λίστα Διεργασίες στιγμιότυπου μνήμης για να συλλέξετε στιγμιότυπα μνήμης"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Έναρξη νέου ίχνους"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Συγκέντρωση ιχνών Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Συμπεριλαμβάνει λεπτομερή δεδομένα τηλεμετρίας διεπαφής χρήστη (μπορεί να προκαλέσει παύση)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Ανίχνευση εφαρμογών με δυνατότητα εντοπισμού σφαλμάτων"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Αποθήκευση στιγμιότυπου μνήμης"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Το στιγμιότυπο μνήμης αποθηκεύτηκε"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Πατήστε για να μοιραστείτε την εγγραφή σας"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Πραγματοποιείται επισύναψη ίχνους στην αναφορά σφάλματος"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Το ίχνος επισυνάφθηκε στην αναφορά σφάλματος"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Πατήστε για άνοιγμα του BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Διακοπή ανίχνευσης"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Διακοπή δημιουργίας προφίλ CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Ορισμένες κατηγορίες εντοπισμού δεν είναι διαθέσιμες:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Διακοπή εγγραφής για αναφορές σφαλμάτων"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Τερματίζει τις ενεργές εγγραφές κατά την έναρξη μιας αναφοράς σφάλματος"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Επισύναψη εγγραφών σε αναφορές σφαλμάτων"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Αυτόματη αποστολή εγγραφών που βρίσκονται σε εξέλιξη στο BetterBug κατά τη συλλογή μιας αναφοράς σφάλματος"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Αυτόματη αποστολή εγγραφών που βρίσκονται σε εξέλιξη στο BetterBug κατά τη συλλογή μιας αναφοράς σφάλματος. Οι εγγραφές θα συνεχίσουν αμέσως μετά."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Προβολή αποθηκευμένων αρχείων"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Ρυθμίσεις ίχνους"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Αποθηκευμένα αρχεία"</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 10bd257d..6dc58ed6 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Record heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captures a heap dump of the processes selected in \'Heap dump processes\'"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Select at least one process in \'Heap dump processes\' to collect heap dumps"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Start new trace"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collect winscope traces"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Includes detailed UI telemetry data (can cause jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Trace debuggable applications"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Saving heap dump"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Heap dump saved"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Tap to share your recording"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Attaching trace to bug report"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Attached trace to bug report"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Tap to open BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Stop tracing"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Stop CPU profiling"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Some tracing categories are unavailable:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Stop recording for bug reports"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Ends active recordings when a bugreport is started"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Attach recordings to bug reports"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Automatically send in-progress recordings to BetterBug when a bug report is collected"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatically send in-progress recordings to BetterBug when a bug report is collected. Recordings will continue afterwards."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"View saved files"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Trace settings"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saved files"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 4c509d25..bb58f445 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Record heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captures a heap dump of the processes selected in \"Heap dump processes\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Select at least one process in \"Heap dump processes\" to collect heap dumps"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Start new trace"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collect Winscope traces"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Includes detailed UI telemetry data (can cause jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Trace debuggable applications"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Saving heap dump"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Heap dump saved"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Tap to share your recording"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Attaching trace to bug report"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Attached trace to bug report"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Tap to open BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Stop tracing"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Stop CPU profiling"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Some tracing categories are unavailable:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Stop recording for bug reports"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Ends active recordings when a bugreport is started"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Attach recordings to bug reports"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Automatically send in-progress recordings to BetterBug when a bug report is collected"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatically send in-progress recordings to BetterBug when a bug report is collected. Recordings will continue afterward."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"View saved files"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Trace settings"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saved files"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 10bd257d..6dc58ed6 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Record heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captures a heap dump of the processes selected in \'Heap dump processes\'"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Select at least one process in \'Heap dump processes\' to collect heap dumps"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Start new trace"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collect winscope traces"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Includes detailed UI telemetry data (can cause jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Trace debuggable applications"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Saving heap dump"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Heap dump saved"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Tap to share your recording"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Attaching trace to bug report"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Attached trace to bug report"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Tap to open BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Stop tracing"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Stop CPU profiling"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Some tracing categories are unavailable:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Stop recording for bug reports"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Ends active recordings when a bugreport is started"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Attach recordings to bug reports"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Automatically send in-progress recordings to BetterBug when a bug report is collected"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatically send in-progress recordings to BetterBug when a bug report is collected. Recordings will continue afterwards."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"View saved files"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Trace settings"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saved files"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index 10bd257d..6dc58ed6 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Record heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captures a heap dump of the processes selected in \'Heap dump processes\'"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Select at least one process in \'Heap dump processes\' to collect heap dumps"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Start new trace"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collect winscope traces"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Includes detailed UI telemetry data (can cause jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Trace debuggable applications"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Saving heap dump"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Heap dump saved"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Tap to share your recording"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Attaching trace to bug report"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Attached trace to bug report"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Tap to open BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Stop tracing"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Stop CPU profiling"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Some tracing categories are unavailable:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Stop recording for bug reports"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Ends active recordings when a bugreport is started"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Attach recordings to bug reports"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Automatically send in-progress recordings to BetterBug when a bug report is collected"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatically send in-progress recordings to BetterBug when a bug report is collected. Recordings will continue afterwards."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"View saved files"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Trace settings"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saved files"</string>
diff --git a/res/values-en-rXC/strings.xml b/res/values-en-rXC/strings.xml
index b46b5a45..b1435a80 100644
--- a/res/values-en-rXC/strings.xml
+++ b/res/values-en-rXC/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‎‏‏‎‏‏‏‎‏‏‎‏‏‏‎‏‏‏‎‏‏‏‏‎‏‏‏‏‎‏‏‎‎‎‎‏‎‏‏‏‎‏‏‎‎‏‏‎‎‎‎‎‏‏‏‎‎‎‏‏‎‎‎‎Record heap dump‎‏‎‎‏‎"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‎‎‎‏‎‏‏‏‏‎‏‏‎‎‏‏‏‏‏‎‎‎‎‏‏‏‎‎‏‏‎‏‎‎‎‎‎‏‎‏‎‎‏‏‎‎‏‏‎‎‏‎‏‏‏‎‎‏‎‎‎‏‎Captures a heap dump of the processes selected in \"Heap dump processes\"‎‏‎‎‏‎"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‎‎‎‎‎‎‎‏‏‎‎‏‎‏‏‎‏‏‏‎‎‏‏‏‎‏‏‎‎‏‎‏‎‎‎‏‏‏‎‏‎‎‏‎‏‏‏‎‏‎‎‎‏‏‎‏‎‏‏‏‏‏‎Select at least one process in \"Heap dump processes\" to collect heap dumps‎‏‎‎‏‎"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‏‏‎‎‎‏‎‏‏‏‏‎‏‏‎‎‎‎‎‎‎‎‏‏‎‎‏‎‏‏‎‎‎‏‏‏‎‏‏‏‏‏‎‏‎‎‎‎‏‎‏‏‎‏‏‏‏‏‎‎‎‏‎Start new trace‎‏‎‎‏‎"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‎‏‎‎‎‎‏‏‎‎‎‎‎‏‎‎‏‎‏‏‏‏‏‏‎‏‎‏‏‎‎‏‎‏‎‏‏‎‎‎‏‎‏‏‏‏‎‏‎‎‎‏‏‏‏‏‎‏‎‎‏‎‎Collect Winscope traces‎‏‎‎‏‎"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‏‎‎‎‎‏‏‎‏‏‎‏‎‏‎‎‎‎‏‏‏‏‎‎‎‏‎‎‎‎‏‎‏‎‏‎‏‎‏‏‎‎‎‎‏‎‎‏‎‏‏‎‏‎‏‏‏‏‎‏‏‎‎Includes detailed UI telemetry data (can cause jank)‎‏‎‎‏‎"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‏‎‏‏‏‎‎‏‏‎‏‏‎‏‎‎‏‏‎‎‎‎‏‏‏‎‏‎‎‏‎‏‎‏‎‎‏‎‎‎‏‏‏‏‏‎‏‎‏‏‎‎‎‎‏‏‎‏‏‎‏‏‎Trace debuggable applications‎‏‎‎‏‎"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‎‏‎‏‎‎‏‏‏‎‏‎‎‏‏‎‏‏‎‎‎‏‏‎‎‎‏‎‏‏‎‏‎‏‏‎‎‏‏‏‎‏‏‏‎‏‎‎‏‏‏‏‏‏‎‎‏‏‎‎‎‎‎Saving heap dump‎‏‎‎‏‎"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‎‏‏‏‎‏‎‏‎‎‎‏‎‎‎‏‎‎‏‏‏‎‏‏‎‎‎‎‎‏‏‎‏‎‎‎‎‎‏‎‎‏‏‏‎‎‎‎‎‎‎‏‏‎‎‏‎‎‏‎‏‎‎Heap dump saved‎‏‎‎‏‎"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‎‏‏‏‏‎‏‏‎‏‎‎‎‎‎‏‎‎‏‎‏‎‏‎‏‏‏‏‎‎‎‎‎‏‎‎‏‎‏‏‏‏‎‏‏‎‎‏‎‎‏‏‏‏‏‏‎‎‏‏‎‎‏‎Tap to share your recording‎‏‎‎‏‎"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‎‏‎‎‏‎‎‎‏‏‏‏‏‎‎‏‏‎‎‏‏‏‎‎‎‏‎‎‏‏‎‏‎‏‎‏‎‏‎‏‏‎‎‏‏‏‎‏‎‏‎‎‏‏‎‎‏‏‎‏‏‏‎‎Attaching trace to bug report‎‏‎‎‏‎"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‎‏‎‎‎‎‏‎‎‏‎‏‏‎‎‏‎‎‎‏‎‏‏‎‏‎‎‏‏‎‎‎‎‏‎‏‏‎‎‏‏‏‎‏‏‎‏‏‎‏‏‎‏‎‎‏‏‎‎‏‏‎‎Attached trace to bug report‎‏‎‎‏‎"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‏‎‏‎‏‎‎‏‏‎‎‎‎‏‏‏‏‏‎‎‏‏‎‏‏‏‏‏‏‏‏‏‎‏‏‎‎‏‎‎‎‏‏‏‏‏‎‎‏‏‎‎‏‎‎‎‏‏‏‎‏‏‎Tap to open BetterBug‎‏‎‎‏‎"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‏‏‏‎‏‏‏‎‏‏‏‏‏‏‎‏‎‏‎‏‎‎‎‎‏‎‎‏‎‏‏‏‎‎‏‏‎‎‎‏‎‎‎‎‎‎‎‏‎‏‏‎‏‎‏‎‏‏‏‎‎‎‎Stop tracing‎‏‎‎‏‎"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‎‎‏‎‏‏‏‏‎‎‎‏‏‎‏‎‏‎‏‏‏‏‎‏‎‏‏‏‎‏‎‎‎‎‎‏‏‎‎‏‎‎‏‎‏‏‏‎‏‎‎‏‎‏‏‏‏‎‏‏‎‏‎Stop CPU profiling‎‏‎‎‏‎"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‎‎‏‏‎‏‏‏‎‏‎‏‏‏‎‏‏‏‎‎‎‏‎‏‎‎‎‎‏‎‏‎‎‎‎‏‎‎‎‏‏‏‎‎‎‏‏‏‎‏‏‏‏‏‏‏‏‏‏‎‎‎‎Some tracing categories are unavailable:‎‏‎‎‏‎"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‎‏‏‏‏‏‏‏‎‏‏‏‎‎‏‎‏‏‏‎‏‏‏‎‏‏‎‏‎‏‏‏‏‏‏‎‎‏‎‏‎‏‎‎‏‏‎‎‏‎‏‏‏‎‏‎‎‎‏‎‏‏‎‎Stop recording for bug reports‎‏‎‎‏‎"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‎‏‏‎‏‏‎‎‎‏‏‏‎‏‎‏‏‎‏‏‏‎‎‎‏‎‏‎‎‏‎‏‎‏‎‎‏‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‎‏‏‎‏‏‏‎‏‎‏‎Ends active recordings when a bugreport is started‎‏‎‎‏‎"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‎‎‏‎‏‎‏‏‎‎‏‎‎‏‏‎‎‎‎‏‏‎‏‏‏‏‏‎‎‎‎‏‎‎‎‏‏‎‎‏‏‎‎‎‎‎‎‏‏‏‎‏‏‎‏‏‎‎‎‎‏‎‎Attach recordings to bug reports‎‏‎‎‏‎"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‎‏‏‏‎‏‎‎‏‏‏‏‎‏‎‎‎‏‎‏‏‎‏‏‎‏‎‏‏‎‏‎‏‎‏‏‏‎‎‏‏‏‏‏‏‎‏‏‎‏‎‏‎‎‎‎‏‎‎‎‎‏‎‎Automatically send in-progress recordings to BetterBug when a bug report is collected‎‏‎‎‏‎"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‎‎‏‎‎‏‎‏‏‎‎‏‏‏‎‏‎‏‎‎‏‏‎‎‎‎‎‏‏‎‏‎‎‎‏‎‏‏‏‎‎‏‏‏‏‏‏‎‎‏‏‎‏‏‎‏‎‎‏‏‏‎‎Automatically send in-progress recordings to BetterBug when a bug report is collected. Recordings will continue afterward.‎‏‎‎‏‎"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‎‏‏‎‎‏‏‎‏‏‏‏‏‏‎‎‏‏‏‎‎‏‏‏‏‎‏‏‏‎‎‎‎‏‎‏‏‏‎‏‏‏‏‏‎‏‎‏‎‎‏‏‎‏‏‎‏‎‎‏‎‏‎‎View saved files‎‏‎‎‏‎"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‏‏‏‎‏‏‎‏‎‎‏‎‎‏‏‏‏‎‏‏‎‏‎‎‎‏‏‏‏‏‎‎‏‎‏‏‎‏‎‏‎‏‏‏‎‎‏‏‏‎‎‎‏‎‎‎‏‎‏‎‏‏‏‎‎‎Trace settings‎‏‎‎‏‎"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‏‎‏‏‏‏‎‏‏‎‏‎‎‏‎‎‎‎‎‎‏‎‎‎‏‏‎‏‎‏‎‎‏‏‎‎‏‏‏‏‎‎‎‎‏‏‎‎‎‏‎‎‏‎‎‏‎‎‏‎‎‏‏‏‎‏‎‏‏‎Saved files‎‏‎‎‏‎"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index ee64ba73..73b2c890 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -10,8 +10,7 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Registrar volcado de montón"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captura un volcado de montón del proceso seleccionado en \"Procesos del volcado de montón\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecciona al menos un proceso en \"Procesos del volcado de montón\" para recolectar volcados de montón"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Iniciar un nuevo registro"</string>
-    <string name="winscope_tracing" msgid="5818984791154837458">"Recolectar registros de WinScope"</string>
+    <string name="winscope_tracing" msgid="5818984791154837458">"Recopilar registros de WinScope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Incluye datos detallados de la telemetría de la IU (puede producir bloqueos)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Registrar aplicaciones depurables"</string>
     <string name="categories" msgid="2280163673538611008">"Categorías"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Guardando volcado de montón"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Se guardó el volcado de montón"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Presiona para compartir tu grabación"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Adjuntando registro al informe de errores"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Se adjuntó el registro al informe de errores"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Presiona para abrir BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Detener registro"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Detener la generación de perfiles del CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Algunas categorías de seguimiento no están disponibles:"</string>
@@ -88,8 +84,8 @@
     <string name="sixtyfive_thousand_kb" msgid="8168144138598305306">"65536 KB"</string>
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Dejar de grabar para los informes de errores"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Finaliza las grabaciones activas cuando se inicia un informe de errores"</string>
-    <string name="attach_to_bug_report" msgid="5388986830016247490">"Adjunta grabaciones a los informes de errores"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Envía las grabaciones en curso automáticamente a BetterBug cuando se recopila un informe de errores"</string>
+    <string name="attach_to_bug_report" msgid="5388986830016247490">"Adjuntar grabaciones a los informes de errores"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Envía los registros en curso automáticamente a BetterBug cuando se recopila un informe de errores. Los registros continuarán después."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Ver los archivos guardados"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Configuración del registro"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Archivos guardados"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 9598b072..cda3ce67 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -10,14 +10,13 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Registrar volcado de montículo"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captura un volcado de montículo de los procesos seleccionados en \"Procesos de volcado de montículo\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecciona al menos un proceso en \"Procesos de volcado de montículo\" para recopilar volcados de montículo"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Iniciar traza nueva"</string>
-    <string name="winscope_tracing" msgid="5818984791154837458">"Recoger rastro de Winscope"</string>
+    <string name="winscope_tracing" msgid="5818984791154837458">"Recoger trazas de Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Incluye datos detallados de telemetría de UI (puede causar tirones)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Rastrear aplicaciones que se puedan depurar"</string>
     <string name="categories" msgid="2280163673538611008">"Categorías"</string>
     <string name="restore_default_categories" msgid="5090536794637169521">"Restaurar categorías predeterminadas"</string>
     <string name="default_categories_restored" msgid="6861683793680564181">"Se han restaurado las categorías predeterminadas"</string>
-    <string name="default_categories" msgid="2117679794687799407">"Predeterminado"</string>
+    <string name="default_categories" msgid="2117679794687799407">"Predeterminadas"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# seleccionada}other{# seleccionadas}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Procesos de volcado de montículo"</string>
     <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Se debe seleccionar al menos un proceso"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Guardando volcado de montículo"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Volcado de montículo guardado"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Toca para compartir tu grabación"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Adjuntando traza al informe de errores"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Traza adjunta al informe de errores"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Toca para abrir BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Deja de guardar rastros"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Dejar de elaborar perfiles de CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Algunas categorías de captura no están disponibles:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Dejar de grabar para los informes de errores"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Finaliza las grabaciones activas cuando se inicia un informe de errores"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Adjuntar las grabaciones en los informes de errores"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Adjunta automáticamente las grabaciones en curso en los informes de errores que se envían a BetterBug"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Adjunta automáticamente las grabaciones en curso en los informes de errores que se envían a BetterBug. Las grabaciones continuarán después."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Ver los archivos guardados"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Ajustes de rastreo"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Archivos guardados"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index daec3d94..fe80a326 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -10,8 +10,7 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Salvesta mälutõmmis"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Jäädvustab jaotises „Mälutõmmise protsessid” valitud protsessidest mälutõmmise"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Mälutõmmiste kogumiseks valige jaotises „Mälutõmmise protsessid” vähemalt üks protsess"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Alusta uut jälgimist"</string>
-    <string name="winscope_tracing" msgid="5818984791154837458">"Koguge Winscope\'i jälgi"</string>
+    <string name="winscope_tracing" msgid="5818984791154837458">"Kogu Winscope\'i jälgi"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Sisaldab üksikasjalikke kasutajaliidese telemeetriaandmeid (võib põhjustada tõrkeid)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Silutavate rakenduste jälgimine"</string>
     <string name="categories" msgid="2280163673538611008">"Kategooriad"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Mälutõmmise salvestamine"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Mälutõmmis on salvestatud"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Salvestise jagamiseks puudutage"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Jälje manustamine veaaruandesse"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Jälg manustati veaaruandesse"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Puudutage laienduse BetterBug avamiseks"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Lõpetage jälgimine"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Lõpetage protsessori profiilimine"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Teatud jälgimiskategooriad ei ole saadaval:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Lõpeta veaaruannete jaoks jäädvustamine"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Lõpetab veaaruande alustamise korral aktiivsed salvestised"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Manusta salvestised veaaruannetele"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Saada pooleliolevad salvestised veaaruande koostamisel automaatselt BetterBugile"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Pooleliolevad salvestised saadetakse veaaruande koostamisel automaatselt BetterBugile. Salvestamine jätkub pärast seda."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Kuva salvestatud failid"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Jälgimise seaded"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Salvestatud failid"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 4852c4d2..9f69332c 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -10,8 +10,7 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Erregistratu memoria-iraulketaren txostena"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"Memoria-iraulketaren txostenarekin lotutako prozesuak\" atalean hautatutako prozesuen memoria-iraulketaren txosten bat egiten du"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Memoria-iraulketaren txostenak biltzeko, hautatu gutxienez prozesu bat \"Memoria-iraulketaren txostenarekin lotutako prozesuak\" atalean"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Hasi beste arrasto bat"</string>
-    <string name="winscope_tracing" msgid="5818984791154837458">"Bildu Winscope-ko aztarnak"</string>
+    <string name="winscope_tracing" msgid="5818984791154837458">"Bildu Winscope-ko arrastoak"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Erabiltzaile-interfazeari buruzko datu telemetriko xeheak ditu (baliteke etenak eragitea)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Egin aratz daitezkeen aplikazioen segimendua"</string>
     <string name="categories" msgid="2280163673538611008">"Kategoriak"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Memoria-iraulketaren txostena gordetzen"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Gorde da memoria-iraulketaren txostena"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Erregistroa partekatzeko, sakatu hau"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Arrastoa eransten akatsen txostena egiteko"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Arrasto bat erantsi da akatsen txostena egiteko"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Sakatu BetterBug irekitzeko"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Utzi arrastoa gordetzeari"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Utzi PUZaren errendimendua analizatzeari"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Arrastoaren kategoria batzuk ez daude erabilgarri:"</string>
@@ -88,8 +84,8 @@
     <string name="sixtyfive_thousand_kb" msgid="8168144138598305306">"65.536 kB"</string>
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Utzi akatsen txostenak erregistratzeari"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Akatsen txosten bat erregistratzen hastean, erregistro aktiboak biltzeari uzten dio"</string>
-    <string name="attach_to_bug_report" msgid="5388986830016247490">"Sartu erregistroak akatsen txostenetan"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Bidali automatikoki abian diren erregistroak BetterBug-era akatsen txosten bat sortzen denean"</string>
+    <string name="attach_to_bug_report" msgid="5388986830016247490">"Sartu grabaketak akatsen txostenetan"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Bidali automatikoki abian diren erregistroak BetterBug-era akatsen txosten bat sortzen denean. Erregistroek aurrera egingo dute."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Ikusi gordetako fitxategiak"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Arrastoen ezarpenak"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Gordetako fitxategiak"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index beb8ce40..f112a897 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ضبط رونوشت پشته"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"رونوشت پشته را برای پردازش‌های انتخاب‌شده در «پردازش‌های رونوشت پشته» را ضبط می‌کند"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"برای جمع‌آوری رونوشت‌های پشته، حداقل یک پردازش را در «پردازش‌های رونوشت پشته» انتخاب کنید"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"شروع ردیابی جدید"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"‏جمع‌آوری ردپاهای Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"شامل داده‌های دورسنجی دقیق واسط کاربر می‌شود (ممکن است باعث قطع اتصال شود)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"برنامه‌هایی با قابلیت اشکال‌زدایی ردیابی"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"درحال ذخیره کردن رونوشت پشته"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"رونوشت پشته ذخیره شد"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"برای هم‌رسانی قطعه ضبط‌شده، تک‌ضرب بزنید"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"درحال پیوست کردن رد به گزارش اشکال"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"رد به گزارش اشکال پیوست شد"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"‏برای باز کردن BetterBug تک‌ضرب بزنید"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"پایان ردیابی"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"توقف تحلیل واحد پردازش مرکزی"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"بعضی از دسته‌های ردیابی دردسترس نیستند:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"توقف ضبط برای گزارش‌های اشکال"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"وقتی گزارش اشکال شروع می‌شود، ضبط‌های فعال به‌پایان می‌رسند"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"پیوست کردن قطعه‌های ضبط‌شده به گزارش اشکال"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"‏هنگام جمع‌آوری گزارش اشکال، ضبط‌های درحال انجام به‌طور خودکار به BetterBug ارسال می‌شود"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"‏هنگام جمع‌آوری گزارش اشکال، ضبط‌های درجریان به‌طور خودکار به BetterBug ارسال می‌شود. پس‌از آن، ضبط ادامه پیدا خواهد کرد."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"مشاهده فایل‌های ذخیره‌شده"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"تنظیمات ردیابی"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"فایل‌های ذخیره‌شده"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 08b49ee6..28c47e04 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Tallenna keon vedos"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Tallentaa kohdasta \"Keon vedos ‑prosessit\" valitun vedoksen"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Valitse ainakin yksi keon vedos ‑prosessi, jotta voit kerätä vedoksia"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Aloita uusi jälki"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Kerää Winscope-jälkiä"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Sisällyttää yksityiskohtaista UI-telemetriadataa (voi aiheuttaa katkoja)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Tallenna viankorjausta tukevien sovellusten jäljet"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Keon vedosta tallennetaan"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Keon vedos tallennettu"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Jaa tallenne napauttamalla"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Jäljitystä liitetään virheraporttiin"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Jäljitys liitetty virheraporttiin"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Avaa BetterBug napauttamalla"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Lopeta jälkien tallentaminen"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Lopeta CPU-profilointi"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Osa jälkiluokista ei ole käytettävissä:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Lopeta tallennus virheraporttien aikana"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Lopettaa aktiiviset tallenteet, kun virheraportti luodaan"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Liitä tallenteet virheraportteihin"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Lähetä keskeneräiset tallenteet BetterBugille automaattisesti virheraportin keräyksen yhteydessä"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Lähetä keskeneräiset tallenteet BetterBugille automaattisesti virheraportin keräyksen yhteydessä. Tallenteet jatkuvat sen jälkeen."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Katso tallennetut tiedostot"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Jäljittämisasetukset"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Tallennetut tiedostot"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index f5a75563..00f0f1b8 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Enregistrer l\'empreinte de mémoire"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Capture une empreinte de mémoire des processus sélectionnés dans « Processus d\'empreinte de mémoire »"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Sélectionnez au moins un processus dans « Processus d\'empreinte de mémoire » pour collecter des empreintes de mémoire."</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Commencer une nouvelle trace"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collecter les traces Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Comprend les données télémétriques détaillées de l\'IU (pouvant provoquer une IU lente)."</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Enregistrer les traces d\'applis débogables"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Enregistrement d\'une empreinte de mémoire en cours…"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Empreinte de mémoire enregistrée"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Touchez pour partager votre enregistrement"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Ajout en pièce jointe d\'une trace à un rapport de bogue"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Trace jointe au rapport de bogue"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Touchez pour ouvrir BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Arrêter le traçage"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Arrêter le profilage du processeur"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Certaines catégories de trace ne sont pas accessibles :"</string>
@@ -68,7 +64,7 @@
     <string name="long_traces" msgid="5110949471775966329">"Traces longues"</string>
     <string name="long_traces_summary" msgid="419034282946761469">"Enregistrement continuel vers l\'espace de stockage de l\'appareil"</string>
     <string name="long_traces_summary_betterbug" msgid="445546400875135624">"Enregistrement continu dans l\'espace de stockage de l\'appareil (sans ajout automatique aux rapports de bogue)"</string>
-    <string name="max_long_trace_size" msgid="1943788179787181241">"Taille maximale pour la trace longue"</string>
+    <string name="max_long_trace_size" msgid="1943788179787181241">"Taille maximale des traces longues"</string>
     <string name="max_long_trace_duration" msgid="8009837944364246785">"Durée maximale des traces longues"</string>
     <string name="two_hundred_mb" msgid="4950018549725084512">"200 Mo"</string>
     <string name="one_gb" msgid="590396985168692037">"1 Go"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Arrêt de l\'enregistrement pour les rapports de bogues"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Met fin aux enregistrements actifs lorsqu\'un rapport de bogue est lancé"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Joindre les enregistrements aux rapports de bogue"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Envoyer automatiquement les enregistrements en cours à BetterBug lorsqu\'un rapport de bogue est recueilli"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Envoyer automatiquement les enregistrements en cours à BetterBug lorsqu\'un rapport de bogue est recueilli. Les enregistrements se poursuivront par la suite."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Afficher les fichiers enregistrés"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Paramètres de traçage"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Fichiers enregistrés"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index e1c3e711..e843d27e 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Enregistrer l\'empreinte de la mémoire"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Capture une empreinte de la mémoire parmi les processus sélectionnés dans \"Processus de l\'empreinte de la mémoire\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Pour collecter des empreintes de la mémoire, sélectionnez au moins un processus dans \"Processus de l\'empreinte de la mémoire\""</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Commencer une nouvelle trace"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collecter les traces Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Comprend les données télémétriques détaillées de l\'UI (peut causer des à-coups)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Tracer les applications pouvant être déboguées"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Sauvegarde de l\'empreinte de la mémoire en cours"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Empreinte de la mémoire sauvegardée"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Appuyez pour partager votre enregistrement"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Ajout de la trace au rapport de bug…"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Trace jointe au rapport de bug"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Appuyez pour ouvrir BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Arrêter le traçage"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Arrêter le profilage du processeur"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Certaines catégories de traçage ne sont pas disponibles :"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Mettre fin à l\'enregistrement pour les rapports de bug"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Met fin aux enregistrements actifs lorsqu\'un rapport de bug est lancé"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Joindre les enregistrements aux rapports de bug"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Envoyer automatiquement les enregistrements en cours à BetterBug quand un rapport de bug est collecté"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Envoyer automatiquement les enregistrements en cours à BetterBug lorsqu\'un rapport de bug est collecté. Les enregistrements se poursuivront par la suite."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Afficher les fichiers enregistrés"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Paramètres de traçage"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Fichiers enregistrés"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 9851a7da..6456916e 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Gravar baleirado da zona de memoria dinámica"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captura un baleirado da zona de memoria dinámica dos procesos seleccionados en Procesos de baleirado da zona de memoria dinámica"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Para recompilar baleirados, selecciona polo menos un proceso en Procesos de baleirado da zona de memoria dinámica"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Iniciar novo rastro"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Recompilar rastros de Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inclúe datos telemétricos detallados da IU (pode diminuír a velocidade de resposta)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Gardar rastros de aplicacións que se poidan depurar"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Gardando baleirado da zona de memoria dinámica"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Gardouse o baleirado da zona de memoria dinámica"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Toca para compartir a gravación"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Anexando rastro ao informe de erros"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Anexouse o rastro ao informe de erros"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Toca para abrir BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Deixa de gardar rastros"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Detén a elaboración de perfís de CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Algunhas categorías de rastros non están dispoñibles:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Deixar de gravar ao iniciar informes de erros"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Remata as gravacións activas cando se inicia un informe de erros"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Anexar gravacións aos informes de erros"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Envía automaticamente gravacións en curso a BetterBug cando se recompile un informe de erros"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Envía automaticamente rexistros de gravacións en curso a BetterBug cando se recompile un informe de erros. As gravacións continuarán tendo lugar despois."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Ver ficheiros gardados"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Configuración de rastro"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Ficheiros gardados"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index ca6f0dfc..262e5555 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"હીપ ડમ્પ રેકોર્ડ કરો"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"હીપ ડમ્પની પ્રક્રિયાઓ\"માંથી પસંદ કરવામાં આવેલી પ્રક્રિયાઓના હીપ ડમ્પને કૅપ્ચર કરે છે"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"હીપ ડમ્પ એકત્રિત કરવા માટે, \"હીપ ડમ્પની પ્રક્રિયાઓ\"માં ઓછામાં ઓછી એક પ્રક્રિયા પસંદ કરો"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"નવેસરથી ટ્રેસ કરો"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope ટ્રેસ એકત્રિત કરો"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"વિગતવાર UI ટેલિમિટ્રિ ડેટાનો સમાવેશ થાય છે (જંકનું કારણ બની શકે છે)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ડિબગ કરી શકાય તેવી ઍપ્લિકેશનોને ટ્રેસ કરો"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"હીપ ડમ્પને સાચવી રહ્યાં છીએ"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"હીપ ડમ્પ સાચવવામાં આવ્યો"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"તમારું રેકોર્ડિંગ શેર કરવા માટે ટૅપ કરો"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"બગ રિપોર્ટમાં ટ્રેસ જોડી રહ્યાં છીએ"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"બગ રિપોર્ટમાં ટ્રેસ જોડવામાં આવ્યું"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug ખોલવા માટે ટૅપ કરો"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"ટ્રેસ કરવાનું બંધ કરો"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU પ્રોફાઇલ બનાવવાનું રોકો"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"ટ્રેસ કરવાની અમુક કૅટેગરીઓ અનુપલબ્ધ છે:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"બગ રિપોર્ટ માટે રેકોર્ડ કરવાનું રોકો"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"જ્યારે કોઈ બગ રિપોર્ટ શરૂ કરવામાં આવે, ત્યારે સક્રિય રેકોર્ડિંગ સમાપ્ત થાય છે"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"બગ રિપોર્ટમાં રેકોર્ડિંગને જોડો"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"જ્યારે કોઈ બગ રિપોર્ટ એકત્રિત કરવામાં આવે, ત્યારે BetterBugને ઑટોમૅટિક રીતે ચાલુ પ્રક્રિયાના રેકોર્ડિંગ મોકલો"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"જ્યારે કોઈ બગ રિપોર્ટ એકત્રિત કરવામાં આવે, ત્યારે BetterBugને ચાલુ પ્રક્રિયાના રેકોર્ડિંગ ઑટોમૅટિક રીતે મોકલો. રેકોર્ડિંગની પ્રક્રિયા પછીથી ચાલુ રહેશે."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"સાચવેલી ફાઇલો જુઓ"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ટ્રેસિંગ સંબંધી સેટિંગ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"સાચવેલી ફાઇલો"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index d5091698..ed2da99e 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -10,11 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"हीप डंप को रिकॉर्ड करें"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"हीप डंप की प्रोसेस\" में चुनी गई प्रोसेस के हीप डंप को कैप्चर करें"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"हीप डंप को इकट्ठा करने के लिए \"हीप डंप की प्रोसेस\" में कम से कम एक प्रोसेस चुनें"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"नया ट्रेस शुरू करें"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"WinScope के ट्रेस इकट्ठा करें"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"इसमें यूज़र इंटरफ़ेस से जुड़ा टेलीमेट्री डेटा शामिल है (इससे जैंक होने की संभावना है)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"डीबग करने के लिए ऐप्लिकेशन ट्रेस करें"</string>
-    <string name="categories" msgid="2280163673538611008">"ट्रेस श्रेणियां"</string>
+    <string name="categories" msgid="2280163673538611008">"कैटगरी"</string>
     <string name="restore_default_categories" msgid="5090536794637169521">"डिफ़ॉल्ट श्रेणियां बहाल करें"</string>
     <string name="default_categories_restored" msgid="6861683793680564181">"डिफ़ॉल्ट श्रेणियां बहाल की गईं"</string>
     <string name="default_categories" msgid="2117679794687799407">"डिफ़ॉल्ट"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"हीप डंप को सेव किया जा रहा है"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"हीप डंप को सेव किया गया"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"अपनी रिकॉर्डिंग शेयर करने के लिए टैप करें"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"ट्रेस को गड़बड़ी की रिपोर्ट में अटैच किया जा रहा है"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"ट्रेस को गड़बड़ी की रिपोर्ट में अटैच किया गया"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug खोलने के लिए टैप करें"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"ट्रेस करना बंद करें"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"सीपीयू प्रोफ़ाइलिंग बंद करें"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"ट्रेस करने की कुछ श्रेणियां उपलब्ध नहीं हैं:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"गड़बड़ी की रिपोर्ट के लिए रिकॉर्डिंग करना बंद करें"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"यह मोड चालू होने पर, गड़बड़ी की रिपोर्ट के शुरू होने के बाद, रिकॉर्डिंग बंद हो जाती है"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"रिकॉर्डिंग को गड़बड़ी की रिपोर्ट में अटैच करें"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"गड़बड़ी की रिपोर्ट मिलने पर, BetterBug को पहले से चल रही रिकॉर्डिंग की जानकारी अपने-आप भेज दी जाती है"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"गड़बड़ी की रिपोर्ट मिलने पर, BetterBug को पहले से चल रही रिकॉर्डिंग अपने-आप भेजी जाती हैं. रिकॉर्डिंग बाद में भी जारी रहेंगी."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"सेव की गई फ़ाइलें देखें"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ट्रेस करने की सेटिंग"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"सेव की गई फ़ाइलें"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 0a73a60b..7ace7cdd 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Izrada snimke memorije procesa"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Izrađuje snimku memorije procesa za procese koji su odabrani u procesima snimke memorije procesa"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Odaberite barem jedan proces u procesima snimke memorije procesa da biste prikupili snimke memorije procesa"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Pokreni novo praćenje"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Prikupljanje Winscope tragova"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Uključuje detaljne telemetrijske podatke korisničkog sučelja (može uzrokovati zastoj)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Prati aplikacije iz kojih se mogu uklanjati pogreške"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Spremanje snimke memorije procesa"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Snimka memorije procesa je spremljena"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Dodirnite da biste podijelili snimku"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Prilaganje praćenja izvješću o programskoj pogrešci"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Praćenje je priloženo izvješću o programskoj pogrešci"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Dodirnite da bi se otvorio BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Zaustavite bilježenje tragova"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Zaustavite profiliranje procesora"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Neke kategorije praćenja nisu dostupne:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Zaustavljanje snimanja za izvješća o programskim pogreškama"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Zaustavlja aktivna snimanja kad se pokrene izrada izvješća o programskim pogreškama"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Priloži snimke izvješćima o programskim pogreškama"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Automatski pošaljite BetterBugu snimke u tijeku kad se prikupi izvješće o programskoj pogrešci"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatski pošaljite BetterBugu snimke u tijeku kad se prikupi izvješće o programskoj pogrešci. Snimanje će se nastaviti kasnije."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Prikaz spremljenih datoteka"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Postavke praćenja"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Spremljene datoteke"</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 546c6429..de00d6f2 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Halommemória-pillanatkép rögzítése"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Rögzíti a „Halommemória-pillanatkép folyamatai” lehetőségnél kijelölt folyamatokhoz tartozó halommemória-pillanatképet"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Halommemória-pillanatképek kijelöléséhez válasszon ki legalább egy folyamatot a „Halommemória-pillanatkép folyamatai” lehetőségnél"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Új nyom indítása"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Gyűjtsön Winscope-nyomokat"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Részletes UI telemetriai adatokat tartalmaz (akadozást okozhat)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Hibaelhárítást igénylő alkalmazások nyomon követése"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Halommemória-pillanatkép mentése…"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Halommemória-pillanatkép mentve"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Koppintson a felvétel megosztásához"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Nyom csatolása a hibajelentéshez"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Nyom csatolva a hibajelentéshez"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Koppintson a BetterBug megnyitásához"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Nyomkövetés leállítása"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU-profilalkotás leállítása"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Egyes nyomon követési kategóriák nem állnak rendelkezésre:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Hibajelentésekhez való felvétel leállítása"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Hibajelentés elindítása után az aktív felvételek befejeződnek"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Felvételek csatolása a hibajelentésekhez"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Folyamatban lévő felvételek automatikus küldése a BetterBugnak hibajelentés begyűjtésekor"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Folyamatban lévő felvételek automatikus küldése a BetterBugnak hibajelentés begyűjtésekor. Az elküldést követően folytatódnak a felvételek."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Mentett fájlok megtekintése"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Követési beállítások"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Mentett fájlok"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index ca63bd9b..ad2e6317 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Գրանցել գործընթացի դինամիկ հիշողության տվյալները"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Գրանցում է գործընթացների դինամիկ հիշողության տվյալները, որոնք ընտրվել են «Դինամիկ հիշողության տվյալների գործընթացներ» բաժնում"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Գործընթացի դինամիկ հիշողության տվյալները հավաքելու համար ընտրեք առնվազն մեկ գործընթաց «Դինամիկ հիշողության տվյալների գործընթացներ» բաժնում"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Սկսել նոր հետագծում"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Հավաքել Winscope-ի հետագծումները"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Ներառում է հեռուստամետրիայի միջերեսային մանրամասն տվյալներ (կարող է աղբ ավելացնել)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Հետագծել վրիպազերծման ենթակա հավելվածները"</string>
@@ -32,7 +31,7 @@
     <string name="one_minute" msgid="4182508213840684258">"1 րոպե"</string>
     <string name="applications" msgid="521776761270770549">"Հավելվածներ"</string>
     <string name="no_debuggable_apps" msgid="4386209254520471208">"Վրիպազերծման ենթակա հավելվածներ չկան"</string>
-    <string name="buffer_size" msgid="3944311026715111454">"Մեկ CPU-ի պահնակի չափը"</string>
+    <string name="buffer_size" msgid="3944311026715111454">"Մեկ CPU-ի բուֆերի չափսը"</string>
     <string name="show_quick_settings_tile" msgid="3827556161191376500">"Ցույց տալ հետագծման «Արագ կարգավորումներ» սալիկը"</string>
     <string name="show_stack_sampling_quick_settings_tile" msgid="2142507886797788822">"Ցույց տալ CPU-ի պրոֆիլավորման «Արագ կարգավորումներ» սալիկը"</string>
     <string name="saving_trace" msgid="1468692734770800541">"Հետագծումը պահվում է"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Գործընթացի դինամիկ հիշողության տվյալները պահվում են"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Գործընթացի դինամիկ հիշողության տվյալները պահվել են"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Հպեք՝ գրանցումով կիսվելու համար"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Հետագծման ֆայլը կցվում է վրիպակի մասին զեկույցին"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Հետագծման ֆայլը կցվեց վրիպակի մասին զեկույցին"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Հպեք՝ BetterBug-ը բացելու համար"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Դադարեցրեք հետագծումը"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Կանգնեցնել CPU-ի պրոֆիլավորումը"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Հետագծման հետևյալ կատեգորիաներն անհասանելի են`"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Կանգնեցնել գրանցումները, երբ ստեղծվում են վրիպակների մասին հաղորդումներ"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Ավարտում է ակտիվ գրանցումները, երբ մեկնարկում է վրիպակների մասին հաղորդումների ստեղծումը"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Գրանցումները կցել վրիպակների մասին հաղորդումներին"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Ավտոմատ ուղարկել ընթացիկ գրանցումների տվյալները BetterBug-ին, երբ վրիպակի մասին հաղորդում է ստեղծվում"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Ավտոմատ ուղարկել ընթացիկ ձայնագրությունները BetterBug-ին, երբ վրիպակի մասին հաղորդում է ստեղծվում։ Որից հետո ձայնագրությունները կշարունակվեն։"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Դիտել պահված ֆայլերը"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Հետագծման կարգավորումներ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Պահված ֆայլեր"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 7abefc1c..d3db2bb8 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Rekam heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Merekam proses heap dump yang dipilih di \"Proses heap dump\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Pilih minimal satu proses di \"Proses heap dump\" untuk mengumpulkan heap dump"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Mulai rekaman aktivitas baru"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Kumpulkan rekaman aktivitas Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Menyertakan data telemetri UI yang mendetail (dapat menyebabkan jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Lacak aplikasi yang dapat di-debug"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Menyimpan heap dump"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Heap dump disimpan"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Ketuk untuk membagikan rekaman Anda"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Melampirkan rekaman aktivitas ke laporan bug"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Rekaman aktivitas dilampirkan ke laporan bug"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Ketuk untuk membuka BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Hentikan pelacakan"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Hentikan pembuatan profil CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Beberapa kategori pelacakan tidak tersedia:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Berhenti merekam untuk laporan bug"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Mengakhiri perekaman yang aktif saat laporan bug dimulai"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Lampirkan rekaman ke laporan bug"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Otomatis mengirim rekaman yang sedang berlangsung ke BetterBug saat laporan bug dikumpulkan"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Otomatis mengirim rekaman yang sedang berlangsung ke BetterBug saat laporan bug dikumpulkan. Rekaman akan dilanjutkan setelahnya."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Lihat file tersimpan"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Setelan perekaman aktivitas"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"File tersimpan"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index afbdb60c..846d935f 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Skrá minnisgögn"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Skáir minnisgögn úr þeirri úrvinnslu sem er valin í „Úrvinnsla minnisgagna“"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Veldu a.m.k. eina úrvinnslu í „Úrvinnsla minnisgagna“ til að safna minnisgögnum"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Hefja nýja rakningu"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Safna Winscope-sporum"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inniheldur ítarleg fjarmælingargögn notendaviðmóts (getur valdið óstöðugleika)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Rekja forrit sem hægt er að villuleita"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Vistar minnisgögn"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Minnisgögn voru vistuð"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Ýttu til að deila upptökunni"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Festir spor við villutilkynningu"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Festi spor við villutilkynningu"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Ýttu til að opna BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Ljúka rakningu"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Stöðva vöktun örgjörva"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Einhverjir flokkar spora eru ekki til staðar:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Stöðva upptöku villutilkynninga"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Stöðvar virkar upptökur þegar villuskýrsla hefst"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Hengja upptökur við villutilkynningar"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Senda upptökur í vinnslu sjálfkrafa til BetterBug þegar villutilkynning er skráð"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Sendu annála sjálfkrafa til BetterBug þegar villutilkynning er skráð. Annálaskráning mun halda áfram að því loknu."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Skoða vistaðar skrár"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Rakningarstillingar"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Vistaðar skrár"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index b445c536..38379a53 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Registra dump dell\'heap"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Acquisisce un dump dell\'heap dei processi selezionati in \"Processi dump dell\'heap\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Seleziona almeno un processo in \"Processi dump dell\'heap\" per raccogliere i dump dell\'heap"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Avvia nuova traccia"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Raccogli tracce Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Include dati di telemetria dell\'UI dettagliati (può causare jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Monitora app di cui è possibile eseguire il debug"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Salvataggio dump dell\'heap in corso…"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Dump dell\'heap salvato"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Tocca per condividere la tua registrazione"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Aggiunta della traccia alla segnalazione di bug in corso…"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Traccia aggiunta alla segnalazione di bug"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Tocca per aprire BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Interrompi tracciamento"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Interrompi profilazione CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Alcune categorie di traccia non sono disponibili:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Interrompi la registrazione per le segnalazioni di bug"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Consente di interrompere le registrazioni attive quando viene iniziata una segnalazione di bug"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Allega le registrazioni alle segnalazioni di bug"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Invia automaticamente le registrazioni in corso a BetterBug quando viene raccolta una segnalazione di bug"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Invia automaticamente le registrazioni in corso a BetterBug quando viene raccolta una segnalazione di bug. Le registrazioni continueranno in seguito."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Visualizza i file salvati"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Impostazioni monitoraggio"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"File salvati"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 1cb61c31..5080b4b2 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"הקלטה של תמונת מצב של הזיכרון"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"תיעוד תמונת מצב של הזיכרון של התהליכים שנבחרו ב\'תהליכים של תמונת מצב של הזיכרון\'"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"כדי לאסוף תמונת מצב של הזיכרון, צריך לבחור לפחות תהליך אחד ב\'תהליכים של תמונת מצב של הזיכרון\'"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"התחלת מעקב חדש"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"‏איסוף עקבות Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"‏כולל נתונים טלמטריים מפורטים של ממשק המשתמש (יכול לגרום לבעיות בממשק (jank))"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ניהול מעקב אחר אפליקציות שניתן לנפות בהן באגים"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"שמירת תמונת מצב של הזיכרון"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"תמונת מצב של הזיכרון נשמרה"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"ניתן להקיש כדי לשתף את ההקלטה"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"מתבצע צירוף של נתוני מעקב לדוח על באג"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"נתוני מעקב צורפו לדוח על באג"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"‏יש להקיש כדי לפתוח את BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"הפסקת המעקב"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"‏הפסקת פרופיילינג של המעבד (CPU)"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"חלק מקטגוריות המעקב אינן זמינות:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"הפסקת ההקלטה לדוחות איתור באגים"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"כאשר מופעל דוח על באג, נפסקות כל ההקלטות הפעילות"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"צירוף ההקלטות לדוחות איתור באגים"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"‏שליחה אוטומטית של הקלטות בתהליך אל BetterBug כאשר מתבצע איסוף של דוח על באג"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"‏כשמתבצע איסוף של דוח על באג, אפשר לשלוח אוטומטית רישומי נתונים שלא הסתיימו אל BetterBug. הנתונים ימשיכו להירשם לאחר מכן."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"הצגת הקבצים שנשמרו"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"הגדרות איתור"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"קבצים שנשמרו"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 8ebcc288..1739e67c 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -10,8 +10,7 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ヒープダンプを記録"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"[ヒープダンプ プロセス] で選択されたプロセスのヒープダンプを取得します"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ヒープダンプを収集するには、[ヒープダンプ プロセス] でプロセスを 1 つ以上選択してください"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"新しいトレースを開始"</string>
-    <string name="winscope_tracing" msgid="5818984791154837458">"Winscope トレースの収集"</string>
+    <string name="winscope_tracing" msgid="5818984791154837458">"Winscope トレースを収集する"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"詳細な UI テレメトリー データを含める（ジャンクが発生することがあります）"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"デバッグ可能なアプリをトレース"</string>
     <string name="categories" msgid="2280163673538611008">"カテゴリ"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"ヒープダンプを保存しています"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"ヒープダンプを保存しました"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"記録を共有するにはタップしてください"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"トレースをバグレポートに添付します"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"トレースをバグレポートに添付しました"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"タップすると、BetterBug が開きます"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"トレースを停止します"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU プロファイリングを停止"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"利用できないトレース カテゴリがあります。"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"バグレポートの間は記録を停止する"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"バグレポートを開始したら、有効な記録を終了します"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"バグレポートに記録を添付する"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"バグレポートの収集時に、処理中の記録を BetterBug に自動的に送信します"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"バグレポートの収集時に、処理中の記録を BetterBug に自動的に送信します。その後も記録は継続されます。"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"保存したファイルを表示"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"トレース設定"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"保存したファイル"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index a52264bc..458eeb61 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"გროვის ამონაწერის ჩაწერა"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"„გროვის ამონაწერის პროცესებიდან“ არჩეული პროცესის გროვის ამონაწერის აღბეჭდვა"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"გროვის ამონაწერის შესაგროვებლად აირჩიეთ, სულ მცირე, ერთი პროცესი „გროვის ამონაწერის პროცესებიდან“"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"ახალი დაკვირვების დაწყება"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope-ის კვალის შეგროვება"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"შეიცავს მომხმარებლის ინტერფეისის ტელემეტრიის მონაცემებს (შეიძლება გამოიწვიოს შეფერხება)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"გამართვადი აპლიკაციების კვალის მიდევნება"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"გროვის ამონაწერის შენახვა"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"გროვის ამონაწერი შენახულია"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"შეეხეთ თქვენი ჩანაწერის გასაზიარებლად"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"მიმდინარეობს კვალის სისტემის ხარვეზის ანგარიშზე დართვა"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"კვალი დართულია სისტემის ხარვეზის ანგარიშზე"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"შეეხეთ BetterBug-ის გასახსნელად"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"კვალის მიდევნების შეწყვეტა"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU-ს პროფილირების შეწყვეტა"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"კვალის ზოგიერთი კატეგორია მიუწვდომელია:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"სისტემის ხარვეზის ანგარიშებისთვის ჩაწერის შეწყვეტა"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"დაასრულებს კვალის მიდევნების აქტიურ ჩაწერას, როდესაც სისტემის ხარვეზის ანგარიშის წარმოება დაიწყება"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ჩანაწერების დართვა სისტემის ხარვეზის ანგარიშებზე"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"შესრულების პროცესში მყოფი ჩანაწერები ავტომატურად ეგზავნება BetterBug-ს სისტემის ხარვეზის ანგარიშის მიღებისას"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"შესრულების პროცესში მყოფი ჩანაწერები ავტომატურად ეგზავნება BetterBug-ს სისტემის ხარვეზის ანგარიშის მიღებისას. ჩანაწერები გაგრძელდება."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"შენახული ფაილების ნახვა"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"პარამეტრებისთვის თვალის დევნება"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"შენახული ფაილები"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 397c2e09..8f7e8b68 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Дамп файлын жазу"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"Дамп файлы процестері\" бөлімінде таңдалған процестердің дамп файлын суретке түсіреді."</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Дамп файлдарын жинау үшін \"Дамп файлы процестері\" бөлімінде кемінде бір процесті таңдаңыз."</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Жаңа трассаны бастау"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope трассаларын жинау"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Пайдаланушы интерфейсінің толық телеметрия деректері бар (интерфейс жұмысының нашарлауына әкелуі мүмкін)."</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Трассасын түзетуге болатын қолданбалар"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Дамп файлы сақталып жатыр"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Дамп файлы сақталды"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Жазбаны бөлісу үшін түртіңіз."</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Трасса қате туралы есепке тіркелуде"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Трасса қате туралы есепке тіркелді"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug қызметін ашу үшін түртіңіз."</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Трассалауды тоқтату"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Орталық процессор профильдеуін тоқтату"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Кейбір трассалау санаттары қолжетімді емес:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Қате туралы есептерді жазуды тоқтату"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Қате туралы есеп басталғанда, қосулы жазбаларды тоқтатады."</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Қате туралы есептерге жазбаларды тіркеу"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Қате туралы есеп жиналған кезде, ағымдағы жазбаларды BetterBug қызметіне автоматты түрде жіберу"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Қате туралы есеп жиналған кезде, ағымдағы жазбаларды BetterBug қызметіне автоматты түрде жіберіңіз. Содан кейін жазба жалғасады."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Сақталған файлдарды көру"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Трассалау параметрлері"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Сақталған файлдар"</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 4d34ee0e..4340cad3 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ថតហ៊ីបដាំ"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"ចាប់យកហ៊ីបដាំនៃដំណើរការដែលបានជ្រើសរើសនៅក្នុង \"ដំណើរការហ៊ីបដាំ\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ជ្រើសរើសដំណើរការយ៉ាងហោចណាស់មួយនៅក្នុង \"ដំណើរការហ៊ីបដាំ\" ដើម្បីប្រមូលហ៊ីបដាំ"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"ចាប់ផ្ដើម​ដានថ្មី"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"ប្រមូលដាន Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"រួមបញ្ចូលទិន្នន័យទូរមាត្រ UI លម្អិត (អាចបណ្ដាលឱ្យដំណើរការអាក់ៗ)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"តាម​ដាន​កម្មវិធី​ដែល​អាច​ជួសជុល​បាន"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"កំពុងរក្សាទុកហ៊ីបដាំ"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"បានរក្សាទុកហ៊ីបដាំ"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"ចុចដើម្បីចែករំលែក​សំឡេងថតរបស់អ្នក"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"កំពុងភ្ជាប់ដានទៅក្នុងរបាយការណ៍អំពីបញ្ហា"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"បានភ្ជាប់ដានទៅក្នុងរបាយការណ៍អំពីបញ្ហា"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"ចុច​ដើម្បី​បើក BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"បញ្ឈប់​ការតាមដាន"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"បញ្ឈប់ការពិនិត្យកម្រងព័ត៌មាន CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"មិនមាន​ប្រភេទ​ដាន​មួយ​ចំនួន​ទេ៖"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"បញ្ឈប់ការថត ដើម្បីរាយការណ៍អំពីបញ្ហា"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"បញ្ចប់ការថតសកម្ម នៅពេល​ចាប់ផ្ដើម​របាយការណ៍​អំពីបញ្ហា"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ភ្ជាប់សំឡេងថត​ទៅរបាយការណ៍អំពីបញ្ហា"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"បញ្ជូនសំឡេងថត​ដែលកំពុងដំណើរការដោយស្វ័យប្រវត្តិទៅ BetterBug នៅពេលប្រមូល​របាយការណ៍អំពីបញ្ហា"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"បញ្ជូនសំឡេងថត​ដែលកំពុងដំណើរការដោយស្វ័យប្រវត្តិទៅ BetterBug នៅពេលប្រមូល​របាយការណ៍អំពីបញ្ហា។ ការថតនឹងបន្តនៅពេលក្រោយ។"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"មើលឯកសារ​ដែលបានរក្សាទុក"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ការកំណត់ដាន"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ឯកសារដែលបានរក្សាទុក"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 0a4e2676..764f3183 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ರೆಕಾರ್ಡ್ ಮಾಡಿ"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"ಹೀಪ್ ಡಂಪ್ ಪ್ರಕ್ರಿಯೆಗಳಲ್ಲಿ\" ಆಯ್ಕೆಮಾಡಿದ ಪ್ರಕ್ರಿಯೆಗಳ ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ಸೆರೆಹಿಡಿಯುತ್ತದೆ"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ಹೀಪ್ ಡಂಪ್‌ಗಳನ್ನು ಸಂಗ್ರಹಿಸಲು \"ಹೀಪ್ ಡಂಪ್ ಪ್ರಕ್ರಿಯೆಗಳಲ್ಲಿ\" ಕನಿಷ್ಠ ಒಂದು ಪ್ರಕ್ರಿಯೆಯನ್ನು ಆಯ್ಕೆಮಾಡಿ"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"ಹೊಸ ಟ್ರೇಸ್ ಅನ್ನು ಪ್ರಾರಂಭಿಸಿ"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"ವಿನ್ಸ್‌ಕೋಪ್‌ ಟ್ರೇಸ್‌ಗಳನ್ನು ಸಂಗ್ರಹಿಸಿ"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"ವಿವರವಾದ UI ಟೆಲಿಮೆಟ್ರಿ ಡೇಟಾವನ್ನು ಒಳಗೊಂಡಿದೆ (ಜಂಕ್ ಮಾಡಬಹುದು)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ಡೀಬಗ್‌ ಮಾಡುವಂತಹ ಅಪ್ಲಿಕೇಶನ್‌ಗಳ ಜಾಡು ಹಿಡಿಯಿರಿ"</string>
@@ -35,16 +34,13 @@
     <string name="buffer_size" msgid="3944311026715111454">"ಪ್ರತಿ-CPU ನ ಬಫರ್ ಗಾತ್ರ"</string>
     <string name="show_quick_settings_tile" msgid="3827556161191376500">"ತ್ವರಿತ ಸೆಟ್ಟಿಂಗ್‌ಗಳ ಟೈಲ್ ಅನ್ನು ಪತ್ತೆಹಚ್ಚುವುದನ್ನು ತೋರಿಸಿ"</string>
     <string name="show_stack_sampling_quick_settings_tile" msgid="2142507886797788822">"CPU ಪ್ರೊಫೈಲಿಂಗ್ ತ್ವರಿತ ಸೆಟ್ಟಿಂಗ್‌ಗಳ ಟೈಲ್ ಅನ್ನು ತೋರಿಸಿ"</string>
-    <string name="saving_trace" msgid="1468692734770800541">"ಟ್ರೇಸ್ ಅನ್ನು ಉಳಿಸಲಾಗುತ್ತಿದೆ"</string>
+    <string name="saving_trace" msgid="1468692734770800541">"ಟ್ರೇಸ್ ಅನ್ನು ಸೇವ್ ಮಾಡಲಾಗುತ್ತಿದೆ"</string>
     <string name="trace_saved" msgid="5869970594780992309">"ಟ್ರೇಸ್ ಅನ್ನು ಸೇವ್ ಮಾಡಲಾಗಿದೆ"</string>
-    <string name="saving_stack_samples" msgid="8174915522390525221">"ಸ್ಟ್ಯಾಕ್‌ ಮಾದರಿಗಳನ್ನು ಉಳಿಸಲಾಗುತ್ತಿದೆ"</string>
+    <string name="saving_stack_samples" msgid="8174915522390525221">"ಸ್ಟ್ಯಾಕ್‌ ಮಾದರಿಗಳನ್ನು ಸೇವ್ ಮಾಡಲಾಗುತ್ತಿದೆ"</string>
     <string name="stack_samples_saved" msgid="8863295751647724616">"ಸ್ಟ್ಯಾಕ್‌ ಮಾದರಿಗಳನ್ನು ಸೇವ್ ಮಾಡಲಾಗಿದೆ"</string>
     <string name="saving_heap_dump" msgid="6118616780825771824">"ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ಸೇವ್‌ ಮಾಡಲಾಗುತ್ತಿದೆ"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ಸೇವ್ ಮಾಡಲಾಗಿದೆ"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"ನಿಮ್ಮ ರೆಕಾರ್ಡಿಂಗ್‌ ಅನ್ನು ಹಂಚಿಕೊಳ್ಳಲು ಟ್ಯಾಪ್‌ ಮಾಡಿ"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"ಬಗ್ ವರದಿಗೆ ಟ್ರೇಸ್ ಅನ್ನು ಲಗತ್ತಿಸಲಾಗುತ್ತಿದೆ"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"ಬಗ್ ವರದಿಗೆ ಟ್ರೇಸ್ ಅನ್ನು ಲಗತ್ತಿಸಲಾಗಿದೆ"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug ತೆರೆಯಲು ಟ್ಯಾಪ್ ಮಾಡಿ"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"ಟ್ರೇಸಿಂಗ್ ಅನ್ನು ನಿಲ್ಲಿಸಿ"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU ಪ್ರೊಫೈಲಿಂಗ್ ಅನ್ನು ನಿಲ್ಲಿಸಿ"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"ಕೆಲವು ಟ್ರೇಸಿಂಗ್ ವಿಭಾಗಗಳು ಲಭ್ಯವಿಲ್ಲ:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"ಬಗ್ ವರದಿಗಳಿಗಾಗಿ ರೆಕಾರ್ಡಿಂಗ್‌ ಅನ್ನು ನಿಲ್ಲಿಸಿ"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"ಬಗ್ ವರದಿಮಾಡುವಿಕೆ ಪ್ರಾರಂಭವಾದಾಗ ಸಕ್ರಿಯವಾಗಿರುವ ರೆಕಾರ್ಡಿಂಗ್‌ಗಳನ್ನು ಕೊನೆಗೊಳಿಸುತ್ತದೆ"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ಬಗ್ ವರದಿಗಳಿಗೆ ರೆಕಾರ್ಡಿಂಗ್‌ಗಳನ್ನು ಲಗತ್ತಿಸಿ"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"ಬಗ್ ವರದಿಯನ್ನು ಸಂಗ್ರಹಿಸಿದ ನಂತರ ಸ್ವಯಂಚಾಲಿತವಾಗಿ ಪ್ರಗತಿಯಲ್ಲಿರುವ ರೆಕಾರ್ಡಿಂಗ್‌ಗಳನ್ನು BetterBug ಗೆ ಕಳುಹಿಸಿ"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ಬಗ್ ವರದಿ ಮಾಡುವಿಕೆಯನ್ನು ಸಂಗ್ರಹಿಸಿದಾಗ ಸ್ವಯಂಚಾಲಿತವಾಗಿ ಪ್ರಗತಿಯಲ್ಲಿರುವ ರೆಕಾರ್ಡಿಂಗ್‌ಗಳನ್ನು BetterBug ಗೆ ಕಳುಹಿಸಿ. ರೆಕಾರ್ಡಿಂಗ್‌ಗಳು ನಂತರ ಮುಂದುವರಿಯುತ್ತವೆ."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"ಉಳಿಸಿದ ಫೈಲ್‌ಗಳನ್ನು ವೀಕ್ಷಿಸಿ"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ಜಾಡು ಸೆಟ್ಟಿಂಗ್‌ಗಳು"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ಉಳಿಸಲಾದ ಫೈಲ್‌ಗಳು"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index d25ed993..b1bcdfff 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"힙 덤프 기록"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\'힙 덤프 프로세스\'에서 선택한 프로세스의 힙 덤프를 캡처합니다"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"힙 덤프를 수집하려면 \'힙 덤프 프로세스\'에서 프로세스를 하나 이상 선택하세요"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"새 트레이스 시작"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope 트레이스 수집"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"상세한 UI 원격 분석 데이터 포함(버벅거림이 발생할 수 있음)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"디버그 가능한 애플리케이션 추적"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"힙 덤프 저장 중"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"힙 덤프 저장됨"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"탭하여 녹화 파일 공유"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"버그 신고에 트레이스 첨부 중"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"버그 신고에 트레이스 첨부됨"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"탭하여 BetterBug 열기"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"추적 중지"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU 프로파일링 중지"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"일부 추적 카테고리를 사용할 수 없습니다"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"버그 신고를 위한 기록 중단"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"버그 신고가 시작되면 진행 중인 기록을 종료합니다."</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"버그 신고에 녹화 파일 첨부"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"버그 신고 수집 시 진행 중인 녹화 파일을 자동으로 BetterBug에 전송"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"버그 신고 수집 시 진행 중인 녹화 파일을 자동으로 BetterBug에 전송합니다. 이후 녹화는 계속됩니다."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"저장된 파일 보기"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"트레이스 설정"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"저장된 파일"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 483669a9..1d28f579 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Үймө дампын жаздыруу"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"Үймө дампы процесстеринен\" тандалган процесстердин үймө дампын тартат"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Үймө дампыларды топтоо үчүн \"Үймө дампы процесстеринен\" кеминде бир процессти тандаңыз"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Жаңы аракеттерди жаздырууну баштоо"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope аракеттерин жыйноо"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Колдонуучу интерфейси толук телеметрия маалыматын камтыйт (бул интерфейстин начарлашына алып келиши мүмкүн)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Мүчүлүштүктөрү оңдоло турган колдонмолордун аракеттерин жаздыруу"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Үймө дампы сакталууда"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Үймө дампы сакталды"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Жаздырууну бөлүшүү үчүн таптап коюңуз"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Мүчүлүштүк тууралуу кабарларга жаздырылган аракеттер тиркелүүдө"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Мүчүлүштүк тууралуу кабарларга жаздырылган аракеттер тиркелди"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug\'ды ачуу үчүн таптаңыз"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Көз салууну токтотуу"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Процессорду профилдөөнү токтотуу"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Телефондо аткарылган аракеттердин айрым категориялары жеткиликсиз:"</string>
@@ -88,8 +84,8 @@
     <string name="sixtyfive_thousand_kb" msgid="8168144138598305306">"65536 Кб"</string>
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Мүчүлүштүк тууралуу кабар үчүн жаздырууну токтотуу"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Мүчүлүштүк тууралуу кабарлоо башталганда, жаздыруулар токтотулат"</string>
-    <string name="attach_to_bug_report" msgid="5388986830016247490">"Мүчүлүштүк тууралуу кабарга жаздырууларды тиркеңиз"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Мүчүлүштүк тууралуу кабар чогултулганда, жаздырылган аракеттерди BetterBug кызматына автоматтык түрдө жөнөтүү"</string>
+    <string name="attach_to_bug_report" msgid="5388986830016247490">"Мүчүлүштүк тууралуу кабарларга жаздырууларды тиркөө"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Мүчүлүштүк тууралуу кабар чогултулганда, жаздырылган аракеттерди BetterBug кызматына автоматтык түрдө жөнөтүңүз. Андан кийин жаздыруу улантылат."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Сакталган файлдарды көрүү"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Аракеттерди жаздыруу параметрлери"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Сакталган файлдар"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index c36e8777..398d8bd4 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ບັນທຶກ heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"ຖ່າຍ heap dump ຂອງຂະບວນການທີ່ເລືອກໃນ \"ຂະບວນການ heap dump\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ເລືອກຢ່າງໜ້ອຍ 1 ຂະບວນການໃນ \"ຂະບວນການ heap dump\" ເພື່ອຮວບຮວມ heap dump"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"ເລີ່ມການຕິດຕາມໃໝ່"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"ຮວບຮວມການຕິດຕາມ Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"ມີຂໍ້ມູນຈາກທາງໄກຂອງສ່ວນຕິດຕໍ່ຜູ້ໃຊ້ແບບລະອຽດ (ສາມາດເຮັດໃຫ້ເກີດການຂັດຂ້ອງໄດ້)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ຕິດຕາມແອັບພລິເຄຊັນທີ່ດີບັກໄດ້."</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"ກຳລັງບັນທຶກ heap dump"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"ບັນທຶກ heap dump ແລ້ວ"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"ແຕະເພື່ອແບ່ງປັນການບັນທຶກຂອງທ່ານ"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"ກຳລັງແນບການຕິດຕາມໃສ່ລາຍງານຂໍ້ຜິດພາດ"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"ແນບການຕິດຕາມໃສ່ລາຍງານຂໍ້ຜິດພາດແລ້ວ"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"ແຕະເພື່ອເປີດ BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Stop tracing"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"ຢຸດການສ້າງໂປຣໄຟລ໌ CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"ບໍ່ສາມາດໃຊ້ໝວດໝູ່ການຕິດຕາມບາງຢ່າງໄດ້:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"ຢຸດການບັນທຶກສຳລັບລາຍງານຂໍ້ຜິດພາດ"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"ສິ້ນສຸດການບັນທຶກທີ່ກຳລັງດຳເນີນການເມື່ອເລີ່ມລາຍງານຂໍ້ຜິດພາດ"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ແນບການບັນທຶກໃນລາຍງານຂໍ້ຜິດພາດ"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"ສົ່ງການບັນທຶກທີ່ກຳລັງດຳເນີນຢູ່ໄປໃຫ້ BetterBug ໂດຍອັດຕະໂນມັດເມື່ອເກັບກຳລາຍງານຂໍ້ຜິດພາດ"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ສົ່ງການບັນທຶກທີ່ກຳລັງດຳເນີນຢູ່ໄປໃຫ້ BetterBug ໂດຍອັດຕະໂນມັດເມື່ອຮວບຮວມລາຍງານຂໍ້ຜິດພາດ. ການບັນທຶກຈະສືບຕໍ່ຫຼັງຈາກນັ້ນ."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"ເບິ່ງໄຟລ໌ທີ່ບັນທຶກໄວ້"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ຕິດຕາມການຕັ້ງຄ່າ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ໄຟລ໌ທີ່ບັນທຶກໄວ້"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index 7c6ab7f8..5f05c52f 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Įrašyti atminties išklotinę"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Fiksuojama procesų, pasirinktų skiltyje „Atminties išklotinės procesai“, atminties išklotinė"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Pasirinkite bent vieną procesą skiltyje „Atminties išklotinės procesai“, kad galėtumėte rinkti atminties išklotines"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Pradėti naują pėdsaką"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Rinkti „Winscope“ pėdsakus"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Įtraukiami išsamūs NS telemetrijos duomenys (gali įvykti pateikimo pauzė)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Žymėti derinamas programas"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Išsaugoma atminties išklotinė"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Atminties išklotinė išsaugota"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Jei norite bendrinti įrašą, palieskite"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Pridedamas pėdsakas prie pranešimo apie riktą"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Pridėtas pėdsakas prie pranešimo apie riktą"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Palieskite, kad atidarytumėte „BetterBug“"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Nebežymėti"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Nebeprofiliuoti centrinio procesoriaus"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Kai kurios pėdsakų įrašymo kategorijos nepasiekiamos:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Nebeįrašyti pranešimams apie riktus"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Užbaigiami aktyvūs įrašymo seansai, kai pradedamas generuoti pranešimas apie riktą"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Pridėkite įrašų prie pranešimų apie riktus"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Automatiškai siųsti vykdomos veiklos įrašus į sistemą „BetterBug“, kai gaunamas pranešimas apie riktą"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatiškai siųsti vykdomos veiklos įrašus į sistemą „BetterBug“, kai gaunamas pranešimas apie riktą. Įrašymas bus tęsiamas vėliau."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Žr. išsaugotus failus"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Sekimo nustatymai"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Išsaugoti failai"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 45f23f9c..619b0d19 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Ierakstīt grēdas izrakstu"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Ieraksta sadaļā “Grēdas izrakstu procesi” atlasīto procesu grēdas izrakstu"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Lai vāktu grēdas izrakstus, sadaļā “Grēdas izrakstu procesi” atlasiet vismaz vienu procesu"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Sākt jaunu trasējumu"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Vākt Winscope izsekošanas datus"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Ietver detalizētus lietotāja saskarnes telemetrijas datus (var izraisīt reaģēšanas pauzi)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Izsekot atkļūdošanas lietojumprogrammas"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Notiek grēdas izraksta saglabāšana"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Grēdas izraksts ir saglabāts"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Pieskarieties, lai kopīgotu reģistrētos datus"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Notiek izsekošanas datu pievienošana kļūdas pārskatam…"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Izsekošanas dati ir pievienoti kļūdas pārskatam"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Pieskarieties, lai atvērtu rīku BetterBug."</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Apturiet izsekošanu"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Apturēt centrālā procesora profilēšanu"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Noteiktas izsekošanas kategorijas nav pieejamas:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Apturēt datu reģistrēšanu, sākot kļūdas pārskata izveidi"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Kad tiek sākta kļūdas pārskata izveide, tiek apturēta aktīvā reģistrēšana."</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Kļūdu pārskatiem pievienot reģistrētos datus"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Automātiski sūtīt pašreizējos reģistrētos datus uz rīku BetterBug kopā ar kļūdas pārskatu"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Varat automātiski sūtīt pašreizējos reģistrētos datus uz rīku BetterBug kopā ar kļūdas pārskatu. Reģistrēšana pēc tam tiks turpināta."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Skatīt saglabātos failus"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Izsekošanas iestatījumi"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saglabātie faili"</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 76f90e1d..5739a1e3 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Снимање слика од меморијата"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Снима слика од меморијата од процесите избрани во „Процеси на слики од меморијата“"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Изберете најмалку еден процес во „Процеси на слики од меморијата“ за да ги приберете сликите од меморијата"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Започни нова трага"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Собирајте траги од Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Опфаќа детални податоци за телеметрија на корисничкиот интерфејс (може да предизвика заглавување)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Трагај по апликации со грешки за отстранување"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Се зачувува слика од меморијата"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Сликата од меморијата е зачувана"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Допрете за да ја споделите снимката"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Се прикачува трага во извештајот за грешка"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Прикачена трага во извештај за грешка"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Допрете за отворање BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Запрете го следењето"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Сопрете со профилирање на CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Некои категории на траги се недостапни:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Престани со снимање за извештаите за грешки"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Ги завршува активните снимки кога ќе се започне извештај за грешки"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Прикачете ги снимките во извештаите за грешки"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Автоматски испраќај снимки во тек во BetterBug кога ќе се прибере извештај за грешки"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Автоматски испраќај снимки во тек до BetterBug кога ќе се прибере извештај за грешки. Снимањата ќе продолжат потоа."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Прикажи ги зачуваните датотеки"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Поставки за трага"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Зачувани апликации"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 0e8553bc..abcfc8cd 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ഹീപ്പ് ഡംപ് റെക്കോർഡ് ചെയ്യുക"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"ഹീപ്പ് ഡംപ് പ്രോസസുകളിൽ\" തിരഞ്ഞെടുത്ത പ്രോസസുകളുടെ ഒരു ഹീപ്പ് ഡംപ് ക്യാപ്ചർ ചെയ്യുന്നു"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ഹീപ്പ് ഡംപുകൾ ശേഖരിക്കാൻ \"ഹീപ്പ് ഡംപ് പ്രോസസുകളിൽ\" ഒരു പ്രോസസ് എങ്കിലും തിരഞ്ഞെടുക്കുക"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"പുതിയ ട്രെയ്‌സ് ആരംഭിക്കുക"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"വിൻസ്‌കോപ്പ് അടയാളങ്ങൾ ശേഖരിക്കുക"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"വിശദമായ UI ടെലിമെട്രി ഡാറ്റ ഉൾപ്പെടുന്നു (ജങ്ക് ഉണ്ടാക്കാം)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ഡീബഗ്ഗ് ചെയ്യാവുന്ന അപ്ലിക്കേഷനുകള്‍ ഫോളോ ചെയ്യുക"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"ഹീപ്പ് ഡംപ് സംരക്ഷിക്കുന്നു"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"ഹീപ്പ് ഡംപ് സംരക്ഷിച്ചു"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"നിങ്ങളുടെ റെക്കോർഡിഗ് പങ്കിടാൻ ടാപ്പ് ചെയ്യുക"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"ബഗ് റിപ്പോർട്ടിന് അടയാളം അറ്റാച്ച് ചെയ്യുന്നു"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"ബഗ് റിപ്പോർട്ടിന് അടയാളം അറ്റാച്ച് ചെയ്‌തു"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug തുറക്കാൻ ടാപ്പ് ചെയ്യുക"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"ട്രെയ്‌സിംഗ് നിർത്തുക"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU പ്രൊഫെെലിംഗ് നിർത്തുക"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"ചില ട്രെയ്‌സിംഗ് വിഭാഗങ്ങൾ ലഭ്യമല്ല:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"ബഗ് റിപ്പോർട്ടുകൾക്കായി, റെക്കോർഡ് ചെയ്യുന്നത് അവസാനിപ്പിക്കുക"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"ബഗ് റിപ്പോർട്ട് ആരംഭിക്കുമ്പോൾ, സജീവമായ റെക്കോർഡിംഗുകൾ അവസാനിപ്പിക്കുന്നു"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ബഗ് റിപ്പോർട്ടുകളിലേക്ക് റെക്കോർഡിംഗുകൾ അറ്റാച്ച് ചെയ്യുക"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"ബഗ് റിപ്പോർട്ട് ശേഖരിച്ചാൽ, പുരോഗതിയിലുള്ള റെക്കോർഡിംഗുകൾ BetterBug-ലേക്ക് സ്വയമേവ അയയ്ക്കുക"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ബഗ് റിപ്പോർട്ട് ശേഖരിച്ചാൽ, പുരോഗതിയിലുള്ള റെക്കോർഡിംഗുകൾ BetterBug-ലേക്ക് സ്വയമേവ അയയ്ക്കുക. റെക്കോർഡ് ചെയ്യലുകൾ പിന്നീട് തുടരും."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"സംരക്ഷിച്ച ഫയലുകൾ കാണുക"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ട്രേസ് ചെയ്യൽ ക്രമീകരണം"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"സംരക്ഷിച്ച ഫയലുകൾ"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index eaf29a51..62432d74 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Санах ойн агшин зургийг бүртгэх"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"Санах ойн агшин зургийн явцууд\" хэсэгт сонгосон явцуудын санах ойн агшин зургийг авна"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Санах ойн агшин зургуудыг цуглуулахын тулд \"Санах ойн агшин зургийн явцууд\"-аас дор хаяж нэг явц сонгоно уу"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Шинэ ул мөр эхлүүлэх"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope-н ул мөрүүдийг цуглуулах"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"UI-н телеметрийн нарийвчилсан өгөгдөл багтана (чанар муудахад хүргэх боломжтой)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Дебаг хийх боломжтой аппуудын ул мөрийг дагах"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Санах ойн агшин зургийг хадгалж байна"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Санах ойн агшин зургийг хадгалсан"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Бичлэгээ хуваалцахын тулд товшино уу"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Алдааны мэдээнд ул мөр хавсаргаж байна"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Алдааны мэдээнд ул мөр хавсаргасан"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug-г нээхийн тулд товшино уу"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Мөрдөхийг зогсоох"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Төв процессорын нэгжийн үнэлгээг зогсоох"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Зарим мөрийн ангилал боломжгүй байна:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Алдааны мэдээнүүдэд зориулж бичихийг зогсоох"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Алдааны мэдээг эхлүүлсэн үед идэвхтэй бичлэгүүдийг зогсооно"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Алдааны мэдээнд бичлэгүүд хавсаргах"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Алдааны мэдээг цуглуулсан үед хийгдэж буй бичлэгүүдийг BetterBug руу автоматаар илгээх"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Алдааны мэдээг цуглуулсан үед хийгдэж буй бичлэгийг BetterBug-д автоматаар илгээнэ үү. Бичлэгийг дараа нь үргэлжлүүлнэ."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Хадгалсан файлуудыг харах"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Ул мөрийн тохиргоо"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Хадгалсан файлууд"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index c3859316..5ab11853 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"हीप डंप रेकॉर्ड करा"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"हीप डंप प्रक्रिया\" यामध्ये निवडलेल्या प्रक्रियांचा हीप डंप कॅप्चर करते"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"हीप डंप गोळा करण्यासाठी \"हीप डंपसंबंधित प्रक्रिया\" यामधून किमान एक प्रक्रिया निवडा"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"नवीन ट्रेस सुरू करा"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope ट्रेस गोळा करा"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"तपशीलवार UI टेलीमेट्री डेटाचा समावेश आहे (जॅंक होऊ शकते)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"डीबग करण्यायोग्य ॲप्लिकेशन ट्रेस करा"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"हीप डंप सेव्ह करत आहे"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"हीप डंप सेव्ह केला आहे"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"तुमचे रेकॉर्डिंग शेअर करण्यासाठी टॅप करा"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"बग रिपोर्टला ट्रेस अटॅच करत आहे"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"बग रिपोर्टला ट्रेस अटॅच करा"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug उघडण्यासाठी टॅप करा"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"माग काढणे थांबवा"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU प्रोफायलिंग थांबवा"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"माग काढण्याच्या काही वर्गवार्‍या अनुपलब्ध आहेत:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"बग रिपोर्टसाठी रेकॉर्ड करणे बंद करा"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"बगरिपोर्ट सुरू झाल्यावर अ‍ॅक्टिव्ह असलेली रेकॉर्डिंग बंद करते"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"बग रिपोर्टना रेकॉर्डिंग जोडा"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"बग रिपोर्ट गोळा केला जातो, तेव्हा प्रगतीपथावरील रेकॉर्डिंग BetterBug ला आपोआप पाठवा"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"बग रिपोर्ट गोळा केला जातो, तेव्हा सुरू असलेल्या रेकॉर्डिंग BetterBug ला आपोआप पाठवा. रेकॉर्डिंग नंतर सुरू राहतील."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"सेव्ह केलेल्या फाइल पहा"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"सेटिंग्जचा माग ठेवा"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"सेव्ह केलेल्या फाइल"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 38e0a43a..643f2ddf 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Rakam longgokan timbunan"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Menangkap longgokan timbunan untuk proses yang dipilih dalam \"Proses longgokan timbunan\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Pilih sekurang-kurangnya satu proses dalam \"Proses longgokan timbunan\" untuk mengumpulkan longgokan timbunan"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Mulakan surih baharu"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Kumpulkan surih Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Termasuk data telemetri UI terperinci (boleh menyebabkan jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Surih aplikasi yang boleh dinyahpepijat"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Menyimpan longgokan timbunan"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Longgokan timbunan disimpan"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Ketik untuk berkongsi rakaman anda"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Melampirkan surih pada laporan pepijat"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Surih dilampirkan pada laporan pepijat"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Ketik untuk membuka BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Berhenti menyurih"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Hentikan pemprofilan CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Sesetengah kategori surihan tidak tersedia"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Hentikan rakaman untuk laporan pepijat"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Menamatkan rakaman aktif apabila laporan pepijat dimulakan"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Lampirkan rakaman pada laporan pepijat"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Hantar rakaman dalam proses kepada BetterBug secara automatik apabila laporan pepijat dikumpulkan"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Hantar rakaman yang sedang diproses kepada BetterBug secara automatik apabila laporan pepijat dikumpulkan. Rakan akan diteruskan selepas itu."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Lihat fail yang disimpan"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Tetapan surih"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Fail yang disimpan"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index 2be67bbb..e9aa969e 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"လျှပ်တစ်ပြက် မှတ်ဉာဏ်ကို ရိုက်ကူးရန်"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"“လျှပ်တစ်ပြက် မှတ်ဉာဏ် လုပ်ငန်းစဉ်များ” တွင် ရွေးထားသည့် လုပ်ငန်းစဉ်များ၏ လျှပ်တစ်ပြက် မှတ်ဉာဏ်ကို ရိုက်ကူးပါ"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"လျှပ်တစ်ပြက် မှတ်ဉာဏ်များ စုဆောင်းရန် “လျှပ်တစ်ပြက် မှတ်ဉာဏ် လုပ်ငန်းစဉ်များ” တွင် အနည်းဆုံး လုပ်ငန်းစဉ်တစ်ခုကို ရွေးပါ"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"လုပ်ဆောင်ချက်မှတ်တမ်းသစ် စတင်ရန်"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope လုပ်ဆောင်ချက်မှတ်တမ်းများကို စုစည်းရန်"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"အသေးစိတ်ကျသော UI တယ်လီတိုင်းတာမှု ဒေတာပါဝင်သည် (ရပ်တန့်စေနိုင်သည်)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"အမှားရှာပြင်နိုင်သည့် အပလီကေးရှင်းများကို မှတ်တမ်းတင်ရန်"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"လျှပ်တစ်ပြက် မှတ်ဉာဏ်ကို သိမ်းနေသည်"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"လျှပ်တစ်ပြက် မှတ်ဉာဏ် သိမ်းလိုက်ပါပြီ"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"သင့်မှတ်တမ်းတင်မှုကို မျှဝေရန် တို့ပါ"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"ချွတ်ယွင်းချက်အစီရင်ခံစာတွင် လုပ်ဆောင်ချက်မှတ်တမ်းကို ပူးတွဲနေသည်"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"ချွတ်ယွင်းချက်အစီရင်ခံစာတွင် လုပ်ဆောင်ချက်မှတ်တမ်းကို ပူးတွဲလိုက်သည်"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug ကို ဖွင့်ရန် တို့ပါ"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"လုပ်ဆောင်ချက်မှတ်တမ်းပြုခြင်းကို ရပ်ရန်"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU ပုဂ္ဂိုလ်အကြောင်း သုံးသပ်ပုံဖော်ခြင်းကို ရပ်ပါ"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"အချို့ မှတ်တမ်း အမျိုးအစားများ မရရှိနိုင်ပါ-"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"ချွတ်ယွင်းချက်အစီရင်ခံစာများကို မှတ်တမ်းတင်ခြင်း ရပ်ရန်"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"ချွတ်ယွင်းချက်အစီရင်ခံစာကို စတင်ချိန်တွင် လက်ရှိ မှတ်တမ်းတင်မှုများကို ရပ်သည်"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"မှတ်တမ်းများကို ချွတ်ယွင်းချက်အစီရင်ခံစာတွင် ပူးတွဲရန်"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"ချွတ်ယွင်းချက်အစီရင်ခံစာကို စုစည်းရာတွင် ဆောင်ရွက်နေဆဲ မှတ်တမ်းများကို BetterBug သို့ အလိုအလျောက်ပို့သည်"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ချွတ်ယွင်းမှုအစီရင်ခံစာကို စုစည်းသောအခါ ဆောင်ရွက်နေဆဲ အသံဖမ်းချက်များကို BetterBug သို့ အလိုအလျောက် ပို့နိုင်သည်။ ထို့နောက် အသံဖမ်းချက်များကို ဆက်လုပ်မည်။"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"သိမ်းထားသောဖိုင်များ ကြည့်ရန်"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"လုပ်ဆောင်ချက်မှတ်တမ်း ဆက်တင်များ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"သိမ်းထားသော ဖိုင်များ"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index a253266c..f659d8e0 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Utfør minnedump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Utfører en minnedump av prosessene som er valgt i «Minnedumpprosesser»"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Velg minst én prosess i «Minnedumpprosesser» for å utføre minnedumper"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Start ny registrering"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Samle Winscope-spor"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inkluderer detaljerte UI-telemetridata (kan forårsake gjengivelsespause)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Spor feilsøkbare apper"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Lagrer minnedumpen"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Minnedumpen er lagret"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Trykk for å dele opptaket"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Legger ved sporet til feilrapporten"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Sporet er lagt ved i feilrapporten"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Trykk for å åpne BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Stopp sporingen"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Stopp prosessorprofilering"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Noen sporkategorier er utilgjengelige:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Stopp opptak for feilrapporter"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Avslutter aktive opptak når en feilrapport er startet"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Legg ved opptak i feilrapporter"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Send automatisk pågående opptak til BetterBug når en feilrapport samles inn"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Send automatisk aktive opptak til BetterBug når det samles inn feilrapporter. Opptakene fortsetter etterpå."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Se lagrede filer"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Innstillinger for sporing"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Lagrede filer"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 208b72a5..e5d35af2 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"हिप डम्प रेकर्ड गर्नुहोस्"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"हिप डम्पका प्रोसेसहरू\" मा चयन गरिएका प्रोसेसहरूको हिप डम्प रेकर्ड गर्छ"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"हिप डम्पहरू सङ्कलन गर्न \"हिप डम्पका प्रोसेसहरू\" मा कम्तीमा पनि एउटा प्रोसेस चयन गर्नुहोस्"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"नयाँ ट्रेस सुरु गर्नुहोस्"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collect Winscope का ट्रेसहरू सङ्कलन गर्नुहोस्"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"यसमा UI टेलिमेट्रीको विस्तृत डेटा (ज्याङ्क हुन सक्छ) समावेश गरिएको हुन्छ"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"डिबग गर्न मिल्ने एपहरू पत्ता लगाउनुहोस्"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"हिप डम्प सेभ गरिँदै छ"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"हिप डम्प सेभ गरियो"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"आफ्नो रेकर्डिङ सेयर गर्न ट्याप गर्नुहोस्"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"बग रिपोर्टमा ट्रेस एट्याच गरिँदै छ"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"बग रिपोर्टमा ट्रेस एट्याच गरियो"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug खोल्न ट्याप गर्नुहोस्"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"ट्रेस गर्न छोड्नुहोस्"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU प्रोफाइलिङ गर्ने कार्य रोक्नुहोस्"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"ट्रेसिङका केही कोटिहरू अनुपलब्ध छन्:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"त्रुटिसम्बन्धी रिपोर्ट बनाउने प्रक्रिया सुरु हुँदा रेकर्ड गर्न छाड्नुहोस्"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"त्रुटिसम्बन्धी रिपोर्ट बनाउने प्रक्रिया सुरु हुँदा रेकर्ड गर्न छाडिन्छ"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"त्रुटिसम्बन्धी रिपोर्टहरूमा रेकर्डिङहरू एट्याच गर्नुहोस्"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"त्रुटिसम्बन्धी रिपोर्ट सङ्कलन गरिँदा प्रक्रियामा रहेका रेकर्डिङहरू BetterBug मा स्वतः पठाइयोस्"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"त्रुटिसम्बन्धी रिपोर्ट सङ्कलन गरिँदा जारी रहेका रेकर्डिङहरू BetterBug मा स्वतः पठाउनुहोस्। त्यसपछि रेकर्ड गर्ने क्रम जारी रहने छ।"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"सेभ गरिएका फाइलहरू हेर्नुहोस्"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ट्रेससम्बन्धी सेटिङ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"सेभ गरिएका फाइलहरू"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index 990a1464..8d1e4b37 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Heap dump opnemen"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Legt een heap dump vast van de processen die zijn geselecteerd in Heap dumprocessen"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecteer ten minste één proces in Heap dump-processen om heap dumps te verzamelen"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Nieuwe tracering starten"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope-sporen verzamelen"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Omvat gedetailleerde UI-telemetriegegevens (kan een onderbreking in de weergave veroorzaken)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Beschikbare apps voor foutopsporing traceren"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Heap dump opslaan"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Heap dump opgeslagen"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Tik om je opname te delen"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Tracering bijvoegen bij bugrapport"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Tracering bijgevoegd bij bugrapport"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Tik om BetterBug te openen"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Traceren stoppen"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU-profilering stoppen"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Sommige spoorcategorieën zijn niet beschikbaar:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Opnamen voor bugrapporten stoppen"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Beëindigt actieve opnamen als een bugrapport is gestart"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Opnamen toevoegen aan bugrapporten"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Lopende opnamen automatisch naar BetterBug sturen als een bugrapport wordt verzameld"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Stuur lopende opnamen automatisch naar BetterBug als een bugrapport wordt verzameld. De opnamen gaan gewoon verder."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Opgeslagen bestanden bekijken"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Traceringsinstellingen"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Opgeslagen bestanden"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index c85bb3b7..4cecc1ac 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -10,10 +10,9 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ହିପ ଡମ୍ପ ରେକର୍ଡ କରନ୍ତୁ"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"ହିପ ଡମ୍ପ ପ୍ରକ୍ରିୟା\"ରେ ଚୟନିତ ପ୍ରକ୍ରିୟାଗୁଡ଼ିକର ଏକ ହିପ ଡମ୍ପକୁ କେପଚର କରେ"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ହିପ ଡମ୍ପ ସଂଗ୍ରହ କରିବାକୁ \"ହିପ ଡମ୍ପ ପ୍ରକ୍ରିୟାଗୁଡ଼ିକ\"ରୁ ଅତି କମରେ ଗୋଟିଏ ପ୍ରକ୍ରିୟା ଚୟନ କରନ୍ତୁ"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"ନୂଆ ଟ୍ରେସ୍ ଆରମ୍ଭ କରନ୍ତୁ"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope ଟ୍ରେସ ସଂଗ୍ରହ କରନ୍ତୁ"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"ସବିଶେଷ UI ଟେଲିମେଟ୍ରି ଡାଟା ଅନ୍ତର୍ଭୁକ୍ତ କରେ (ଜଙ୍କ ସୃଷ୍ଟି କରିପାରେ)"</string>
-    <string name="trace_debuggable_applications" msgid="7957069895298887899">"ଡିବଗ୍‌ଯୋଗ୍ୟ ଆପ୍‌ଗୁଡ଼ିକୁ ଟ୍ରେସ୍ କରନ୍ତୁ"</string>
+    <string name="trace_debuggable_applications" msgid="7957069895298887899">"ଡିବଗଯୋଗ୍ୟ ଆପ୍ଲିକେସନକୁ ଟ୍ରେସ କରନ୍ତୁ"</string>
     <string name="categories" msgid="2280163673538611008">"ବର୍ଗ"</string>
     <string name="restore_default_categories" msgid="5090536794637169521">"ଡିଫଲ୍ଟ ବର୍ଗଗୁଡ଼ିକୁ ରିଷ୍ଟୋର୍ କରନ୍ତୁ"</string>
     <string name="default_categories_restored" msgid="6861683793680564181">"ଡିଫଲ୍ଟ ବର୍ଗଗୁଡ଼ିକ ରିଷ୍ଟୋର୍ ହୋଇଛି"</string>
@@ -32,7 +31,7 @@
     <string name="one_minute" msgid="4182508213840684258">"1 ମିନିଟ"</string>
     <string name="applications" msgid="521776761270770549">"ଆପ୍ଲିକେଶନ୍‌"</string>
     <string name="no_debuggable_apps" msgid="4386209254520471208">"କୌଣସି ଡିବଗ୍‌ଯୋଗ୍ୟ ଆପ୍‌ ଉପଲବ୍ଧ ନାହିଁ"</string>
-    <string name="buffer_size" msgid="3944311026715111454">"ପ୍ରତି CPU ପିଛା ବଫର୍‍ର ଆକାର"</string>
+    <string name="buffer_size" msgid="3944311026715111454">"ପ୍ରତି CPU ପିଛା ବଫରର ଆକାର"</string>
     <string name="show_quick_settings_tile" msgid="3827556161191376500">"କୁଇକ ସେଟିଂସ ଟାଇଲ ପାଇଁ ଟ୍ରେସିଂ ଦେଖାନ୍ତୁ"</string>
     <string name="show_stack_sampling_quick_settings_tile" msgid="2142507886797788822">"କୁଇକ ସେଟିଂସ ଟାଇଲ ପାଇଁ CPU ପ୍ରୋଫାଇଲିଂ ଦେଖାନ୍ତୁ"</string>
     <string name="saving_trace" msgid="1468692734770800541">"ଟ୍ରେସ୍‌କୁ ସେଭ୍ କରନ୍ତୁ"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"ହିପ ଡମ୍ପ ସେଭ କରାଯାଉଛି"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"ହିପ ଡମ୍ପ ସେଭ କରାଯାଇଛି"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"ଆପଣଙ୍କ ରେକର୍ଡିଂ ସେୟାର କରିବାକୁ ଟାପ କରନ୍ତୁ"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"ବଗ୍ ରିପୋର୍ଟ ସହିତ ଟ୍ରେସ୍ ଆଟାଚ୍ କରାଯାଉଛି"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"ବଗ୍ ରିପୋର୍ଟ ସହିତ ଟ୍ରେସ୍ ଆଟାଚ୍ କରାଯାଇଛି"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug ଖୋଲିବାକୁ ଟାପ୍ କରନ୍ତୁ"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"ଟ୍ରେସିଙ୍ଗ ବନ୍ଦ କରନ୍ତୁ"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU ପ୍ରୋଫାଇଲିଂ ବନ୍ଦ କରନ୍ତୁ"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"ଟ୍ରେସିଙ୍ଗର କିଛି ବର୍ଗ ଉପଲବ୍ଧ ନାହିଁ:"</string>
@@ -65,7 +61,7 @@
     <string name="system_trace_sensitive_data" msgid="3069389866696009549">"ସିଷ୍ଟମ୍‍ ଟ୍ରେସିଂ ଫାଇଲ୍‍ଗୁଡିକ ହୁଏତ ସମ୍ବେଦନଶୀଳ ସିଷ୍ଟମ୍‍ ଏବଂ ଆପ୍‍ ଡାଟା (ଯେପରି କି ଆପ୍‍ ବ୍ୟବହାର) ଅନ୍ତର୍ଭୁକ୍ତ କରିପାରେ। ସିଷ୍ଟମ୍‍ ଟ୍ରେସ୍‍ କେବଳ ଆପଣ ବିଶ୍ବାସ କରୁଥିବା ଲୋକ ଏବଂ ଆପ୍ସ ସହ ସେୟାର୍‍ କରନ୍ତୁ।"</string>
     <string name="share" msgid="8443979083706282338">"ସେୟାର୍‍ କରନ୍ତୁ"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"ପୁଣି ଦେଖାନ୍ତୁ ନାହିଁ"</string>
-    <string name="long_traces" msgid="5110949471775966329">"ଲମ୍ବା ଟ୍ରେସ୍"</string>
+    <string name="long_traces" msgid="5110949471775966329">"ଲମ୍ବା ଟ୍ରେସ"</string>
     <string name="long_traces_summary" msgid="419034282946761469">"ଡିଭାଇସ୍ ଷ୍ଟୋରେଜ୍ ପାଇଁ ବାରମ୍ବାର ସେଭ୍ କରନ୍ତୁ"</string>
     <string name="long_traces_summary_betterbug" msgid="445546400875135624">"ଡିଭାଇସ୍ ଷ୍ଟୋରେଜରେ କ୍ରମାଗତ ଭାବେ ସେଭ୍ କରାଯାଏ (ବଗ୍ ରିପୋର୍ଟରେ ସ୍ୱଚାଳିତ ଭାବେ ଆଟାଚ୍ ହେବ ନାହିଁ)"</string>
     <string name="max_long_trace_size" msgid="1943788179787181241">"ସର୍ବାଧିକ ଲମ୍ବା ଟ୍ରେସ୍ ଆକାର"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"ବଗ ରିପୋର୍ଟଗୁଡ଼ିକ ପାଇଁ ରେକର୍ଡିଂକୁ ବନ୍ଦ କରନ୍ତୁ"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"ଏକ ବଗରିପୋର୍ଟ ଆରମ୍ଭ ହେଲେ ସକ୍ରିୟ ରେକର୍ଡିଂଗୁଡ଼ିକ ସମାପ୍ତ ହୁଏ"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ବଗ ରିପୋର୍ଟଗୁଡ଼ିକରେ ରେକର୍ଡିଂ ଆଟାଚ କରନ୍ତୁ"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"ଯେତେବେଳେ ଏକ ବଗ ରିପୋର୍ଟ ସଂଗ୍ରହ କରାଯାଏ ସେତେବେଳେ BetterBugକୁ ପ୍ରଗତିରେ-ଥିବା ରେକର୍ଡିଂ ସ୍ୱତଃ ପଠାନ୍ତୁ"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ଏକ ବଗ ରିପୋର୍ଟ ସଂଗ୍ରହ ହେଲେ BetterBugକୁ ରେକର୍ଡିଂ ସ୍ୱତଃ ପଠାଯାଏ। ଏହାପରେ ରେକର୍ଡିଂ ଜାରି ରହିବ।"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"ସେଭ କରାଯାଇଥିବା ଫାଇଲଗୁଡ଼ିକୁ ଦେଖନ୍ତୁ"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ଟ୍ରେସ ସେଟିଂସ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ସେଭ କରାଯାଇଥିବା ଫାଇଲଗୁଡ଼ିକ"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index b21d448c..46281128 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ਹੀਪ ਡੰਪ ਨੂੰ ਰਿਕਾਰਡ ਕਰੋ"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"ਹੀਪ ਡੰਪ ਪ੍ਰਕਿਰਿਆਵਾਂ\" ਵਿੱਚ ਚੁਣੀਆਂ ਗਈਆਂ ਪ੍ਰਕਿਰਿਆਵਾਂ ਦੇ ਹੀਪ ਡੰਪ ਨੂੰ ਕੈਪਚਰ ਕਰਦਾ ਹੈ"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ਹੀਪ ਡੰਪ ਇਕੱਤਰ ਕਰਨ ਲਈ \"ਹੀਪ ਡੰਪ ਪ੍ਰਕਿਰਿਆਵਾਂ\" ਵਿੱਚ ਘੱਟੋ-ਘੱਟ ਇੱਕ ਪ੍ਰਕਿਰਿਆ ਚੁਣੋ"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"ਨਵਾਂ ਟ੍ਰੇਸ ਚਾਲੂ ਕਰੋ"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope ਟ੍ਰੇਸਾਂ ਨੂੰ ਇਕੱਤਰ ਕਰੋ"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"ਇਸ ਵਿੱਚ ਵੇਰਵੇ ਸਹਿਤ UI ਟੈਲੀਮੈਟਰੀ ਡਾਟਾ ਸ਼ਾਮਲ ਹੈ (ਇਹ ਜੈਂਕ ਦਾ ਕਾਰਨ ਬਣ ਸਕਦਾ ਹੈ)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ਡੀਬੱਗਯੋਗ ਐਪਲੀਕੇਸ਼ਨਾਂ ਟ੍ਰੇਸ ਕਰੋ"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"ਹੀਪ ਡੰਪ ਨੂੰ ਰੱਖਿਅਤ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"ਹੀਪ ਡੰਪ ਨੂੰ ਰੱਖਿਅਤ ਕੀਤਾ ਗਿਆ"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"ਆਪਣੀ ਰਿਕਾਰਡਿੰਗ ਨੂੰ ਸਾਂਝਾ ਕਰਨ ਲਈ ਟੈਪ ਕਰੋ"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"ਟ੍ਰੇਸ ਨੂੰ ਬੱਗ ਰਿਪੋਰਟ ਵਿੱਚ ਨੱਥੀ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"ਟ੍ਰੇਸ ਨੂੰ ਬੱਗ ਰਿਪੋਰਟ ਵਿੱਚ ਨੱਥੀ ਕੀਤਾ ਗਿਆ"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug ਨੂੰ ਖੋਲ੍ਹਣ ਲਈ ਟੈਪ ਕਰੋ"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"ਟ੍ਰੇਸਿੰਗ ਬੰਦ ਕਰੋ"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU ਪ੍ਰੋਫਾਈਲਿੰਗ ਬੰਦ ਕਰੋ"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"ਕੁਝ ਟ੍ਰੇਸਿੰਗ ਸ਼੍ਰੇਣੀਆਂ ਉਪਲਬਧ ਨਹੀਂ ਹਨ:"</string>
@@ -69,7 +65,7 @@
     <string name="long_traces_summary" msgid="419034282946761469">"ਡੀਵਾਈਸ ਸਟੋਰੇਜ ਵਿੱਚ ਲਗਾਤਾਰ ਰੱਖਿਅਤ ਕੀਤਾ ਗਿਆ"</string>
     <string name="long_traces_summary_betterbug" msgid="445546400875135624">"ਡੀਵਾਈਸ ਸਟੋਰੇਜ ਵਿੱਚ ਲਗਾਤਾਰ ਰੱਖਿਅਤ ਕੀਤਾ ਗਿਆ (ਬੱਗ ਰਿਪੋਰਟਾਂ ਨਾਲ ਸਵੈਚਲਿਤ ਤੌਰ \'ਤੇ ਨੱਥੀ ਨਹੀਂ ਹੋਵੇਗਾ)"</string>
     <string name="max_long_trace_size" msgid="1943788179787181241">"ਸਭ ਤੋਂ ਲੰਮੀ ਟ੍ਰੇਸ ਦਾ ਆਕਾਰ"</string>
-    <string name="max_long_trace_duration" msgid="8009837944364246785">"ਸਭ ਤੋਂ ਲੰਮੀ ਟ੍ਰੇਸ ਮਿਆਦ"</string>
+    <string name="max_long_trace_duration" msgid="8009837944364246785">"ਸਭ ਤੋਂ ਲੰਮੀ ਟ੍ਰੇਸ ਦੀ ਮਿਆਦ"</string>
     <string name="two_hundred_mb" msgid="4950018549725084512">"200 MB"</string>
     <string name="one_gb" msgid="590396985168692037">"1 GB"</string>
     <string name="five_gb" msgid="7883941043220621649">"5 GB"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"ਬੱਗ ਰਿਪੋਰਟਾਂ ਲਈ ਰਿਕਾਰਡਿੰਗਾਂ ਬੰਦ ਕਰੋ"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"ਬੱਗ ਰਿਪੋਰਟ ਚਾਲੂ ਹੋਣ \'ਤੇ ਕਿਰਿਆਸ਼ੀਲ ਰਿਕਾਰਡਿੰਗਾਂ ਸਮਾਪਤ ਹੁੰਦੀਆਂ ਹਨ"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ਬੱਗ ਰਿਪੋਰਟਾਂ ਨਾਲ ਰਿਕਾਰਡਿੰਗਾਂ ਨੱਥੀ ਕਰੋ"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"ਬੱਗ ਰਿਪੋਰਟ ਇਕੱਤਰ ਹੋ ਜਾਣ \'ਤੇ ਪ੍ਰਕਿਰਿਆ-ਅਧੀਨ ਰਿਕਾਰਡਿੰਗਾਂ ਨੂੰ ਸਵੈਚਲਿਤ ਤੌਰ \'ਤੇ BetterBug ਨੂੰ ਭੇਜੋ"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ਬੱਗ ਰਿਪੋਰਟ ਇਕੱਤਰ ਹੋ ਜਾਣ \'ਤੇ ਪ੍ਰਕਿਰਿਆ-ਅਧੀਨ ਰਿਕਾਰਡਿੰਗਾਂ ਨੂੰ ਸਵੈਚਲਿਤ ਤੌਰ \'ਤੇ BetterBug ਨੂੰ ਭੇਜੋ। ਰਿਕਾਰਡਿੰਗਾਂ ਇਸ ਤੋਂ ਬਾਅਦ ਵੀ ਜਾਰੀ ਰਹਿਣਗੀਆਂ।"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"ਰੱਖਿਅਤ ਕੀਤੀਆਂ ਫ਼ਾਈਲਾਂ ਦੇਖੋ"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ਟ੍ਰੇਸ ਸੈਟਿੰਗਾਂ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ਰੱਖਿਅਤ ਕੀਤੀਆਂ ਗਈਆਂ ਫ਼ਾਈਲਾਂ"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 5b4d5284..2f7e4b6e 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Rejestruj zrzut stosu"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Przechwytuje zrzut stosu procesów wybranych w ramach „Procesy zrzutu stosu”."</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Wybierz co najmniej 1 proces w ramach „Procesy zrzutu stosu”, aby zapisywać zrzuty stosu"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Rozpocznij nowe śledzenie"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Zbieraj ślady Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Obejmuje szczegółowe dane telemetryczne interfejsu użytkownika (może powodować zacinanie)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Śledź aplikacje z możliwością debugowania"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Zapisuję zrzut stosu"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Zrzut stosu zapisany"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Kliknij nagranie, aby je udostępnić"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Dołączam log do raportu o błędzie"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Dołączono log do raportu o błędzie"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Kliknij, by otworzyć BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Zatrzymaj śledzenie"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Zatrzymaj profilowanie procesora"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Niektóre kategorie śledzenia są niedostępne:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Zatrzymaj nagrywanie na potrzeby raportów o błędach"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Kończy aktywne sesje nagrywania, gdy rozpoczyna się tworzenie raportu o błędzie"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Załączaj nagrania do raportów o błędach"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Automatycznie przesyłaj przetwarzanie nagrania do BetterBug podczas tworzenia raportu o błędzie"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatycznie przesyłaj przetwarzane nagrania do BetterBug podczas tworzenia raportu o błędzie. Po przesłaniu danych nagranie będzie kontynuowane."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Wyświetl zapisane pliki"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Ustawienia monitorowania"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Zapisane pliki"</string>
diff --git a/res/values-pt-rBR/strings.xml b/res/values-pt-rBR/strings.xml
index f590c67f..5bc5b914 100644
--- a/res/values-pt-rBR/strings.xml
+++ b/res/values-pt-rBR/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Gravar heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captura um heap dump dos processos selecionados em \"Processos de heap dump\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecionar pelo menos um dos processos em \"Processos de heap dump\" para coletar heap dumps"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Iniciar novo rastro"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Coletar rastros do Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inclui dados detalhados de telemetria da interface e pode causar instabilidade"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Rastrear aplicativos depuráveis"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Salvando heap dump"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Heap dump salvo"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Toque para compartilhar as gravações"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Anexando rastro ao relatório do bug"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Rastro anexado ao relatório do bug"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Toque para abrir o BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Parar de rastrear"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Parar de criar perfis de CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Algumas categorias de rastro estão indisponíveis:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Parar a gravação para executar relatórios de bugs"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Encerra as gravações ativas quando um relatório de bug é iniciado"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Anexar gravações ao relatório do bug"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Enviar gravações em andamento ao BetterBug automaticamente quando um relatório de bug for coletado"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Enviar gravações em andamento automaticamente ao BetterBug quando um relatório de bug for coletado. As gravações vão continuar em seguida."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Ver arquivos salvos"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Configurações de rastreamento"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Arquivos salvos"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index b093020d..5d8c212c 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Registar captura da área dinâmica para dados"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Faz uma captura da área dinâmica para dados dos processos selecionados nos \"Processos de captura da área dinâmica para dados\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecione, pelo menos, um processo em \"Processos da captura da área dinâmica para dados\" para recolher capturas da área dinâmica para dados"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Iniciar novo rastreio"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Recolher rastreios do Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inclui dados de telemetria da IU detalhados (pode provocar uma pausa percetível)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Rastrear aplicações disponíveis para depuração"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"A guardar captura da área dinâmica para dados"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Captura da área dinâmica para dados guardada"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Toque para partilhar a sua gravação"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"A anexar o rastreio ao relatório de erro…"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Rastreio anexado ao relatório de erro"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Toque para abrir o BetterBug."</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Parar rastreio"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Pare a criação de perfis da CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Algumas categorias de rastreio não estão disponíveis:"</string>
@@ -88,8 +84,8 @@
     <string name="sixtyfive_thousand_kb" msgid="8168144138598305306">"65 536 kB"</string>
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Pare a gravação de relatórios de erros"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Termina as gravações ativas quando é iniciado um relatório de erro"</string>
-    <string name="attach_to_bug_report" msgid="5388986830016247490">"Anexe gravações aos relatórios de erros"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Envie automaticamente gravações em curso para o BetterBug quando é recolhido um relatório de erro"</string>
+    <string name="attach_to_bug_report" msgid="5388986830016247490">"Anexar gravações aos relatórios de erros"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Envie automaticamente gravações em curso para o BetterBug quando é recolhido um relatório de erro. As gravações continuam depois disso."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Veja ficheiros guardados"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Definições de rastreio"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Ficheiros guardados"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index f590c67f..5bc5b914 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Gravar heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captura um heap dump dos processos selecionados em \"Processos de heap dump\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecionar pelo menos um dos processos em \"Processos de heap dump\" para coletar heap dumps"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Iniciar novo rastro"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Coletar rastros do Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inclui dados detalhados de telemetria da interface e pode causar instabilidade"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Rastrear aplicativos depuráveis"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Salvando heap dump"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Heap dump salvo"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Toque para compartilhar as gravações"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Anexando rastro ao relatório do bug"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Rastro anexado ao relatório do bug"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Toque para abrir o BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Parar de rastrear"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Parar de criar perfis de CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Algumas categorias de rastro estão indisponíveis:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Parar a gravação para executar relatórios de bugs"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Encerra as gravações ativas quando um relatório de bug é iniciado"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Anexar gravações ao relatório do bug"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Enviar gravações em andamento ao BetterBug automaticamente quando um relatório de bug for coletado"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Enviar gravações em andamento automaticamente ao BetterBug quando um relatório de bug for coletado. As gravações vão continuar em seguida."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Ver arquivos salvos"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Configurações de rastreamento"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Arquivos salvos"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 7ea5193c..d5563740 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Înregistrează datele privind memoria heap"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Surprinde o serie de date privind memoria heap din procesele selectate în Procese de date privind memoria heap"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selectează cel puțin un proces de date privind memoria heap ca să colectezi datele privind memoria heap"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Începe o urmă nouă"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Adună urmele Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Include date de telemetrie IU detaliate (poate cauza jankuri)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Urmărește aplicațiile care pot fi depanate"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Se salvează datele privind memoria heap"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Date privind memoria heap salvate"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Atinge pentru a trimite înregistrarea"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Se atașează urma la raportul de eroare"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Urma a fost atașată la raportul de eroare"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Atinge pentru a deschide BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Oprește urmărirea"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Oprește crearea de profiluri CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Unele categorii de urmărire nu sunt disponibile:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Oprește înregistrarea pentru rapoartele de eroare"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Încheie înregistrările active când este inițiat un raport de eroare"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Atașează înregistrări la rapoartele de eroare"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Activează trimiterea automată a înregistrărilor în desfășurare la BetterBug când se execută un raport de eroare"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Activează trimiterea automată a înregistrărilor în desfășurare la BetterBug când se execută un raport de eroare. Înregistrările vor continua."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Vezi fișierele salvate"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Setări pentru urmărire"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Fișiere salvate"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 24b09730..512c6ad6 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Создать дамп кучи"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Записывает дамп кучи для процессов, выбранных в списке \"Процессы с дампом кучи\"."</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Чтобы создать дампы кучи, выберите хотя бы один элемент в списке \"Процессы с дампом кучи\"."</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Начать трассировку"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Собирать трассировки Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Включает подробные данные телеметрии интерфейса (может вызвать временное зависание)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Записывать действия приложений, доступных для отладки"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Сохранение дампа кучи"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Дамп кучи сохранен"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Нажмите, чтобы поделиться записью."</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Прикрепление данных трассировки к отчету об ошибке…"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"К отчету об ошибке прикреплены данные трассировки"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Нажмите, чтобы открыть BetterBug."</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Остановить запись"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Остановить запись профиля ЦП"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Некоторые категории недоступны:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Останавливать запись, когда формируются отчеты об ошибках"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Когда начинается формирование отчета об ошибке, запись прекращается"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Прикреплять записи к отчетам об ошибках"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Автоматически отправлять данные выполняемой записи в BetterBug вместе с отчетом об ошибке"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Автоматически отправлять данные выполняемой записи в BetterBug вместе с отчетом об ошибке. После этого запись продолжится."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Показать сохраненные файлы"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Настройки трассировки"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Сохраненные файлы"</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index f5a59b17..e6af4549 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"සංච නික්‍ෂේපය වාර්තා කරන්න"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"සංච නික්‍ෂේප ක්‍රියාවලි\" තුළ තෝරා ගත් ක්‍රියාවලිවල සංච නික්‍ෂේපයක් ග්‍රහණය කරයි"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"සංච නික්‍ෂේපය එකතු කිරීමට \"සංච නික්‍ෂේප ක්‍රියාවලි\" තුළ අවම වශයෙන් එක් ක්‍රියාවලියක් තෝරන්න"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"නව හඹා යාම ආරම්භ කරන්න"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope හෝඩුවා එකතු කරන්න"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"සවිස්තරාත්මක UI දුරස්ථමාන දත්ත ඇතුළත් වේ (ජැන්ක් ඇති කළ හැක)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"දෝෂහරණය කළ හැකි යෙදුම් හඹා යන්න"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"සංච නික්‍ෂේපය සුරැකීම"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"සංච නික්‍ෂේපය සුරැකිණි"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"ඔබේ පටිගත කිරීම බෙදා ගැනීමට තට්ටු කරන්න"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"දෝෂ වාර්තාවට හෝඩුවාව අමුණමින්"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"දෝෂ වාර්තාවට හෝඩුවාව අමුණන ලදි"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug විවෘත කිරීමට තට්ටු කරන්න"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"හෝඩුවාව නතර කරන්න"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU පැතිකඩ ඇගයීම නවත්වන්න"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"සමහර හඹා යාම් ප්‍රවර්ග ලබා ගත නොහැකිය:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"දෝෂ වාර්තා සඳහා පටිගත කිරීම නවත්වන්න"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"දෝෂ වාර්තාවක් ආරම්භ කළ විට සක්‍රීය පටිගත කිරීම් අවසන් කරයි"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"දෝෂ වාර්තාවලට පටිගත කිරීම් අමුණන්න"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"දෝෂ වාර්තාවක් එක් කළ විට ප්‍රගතිය පටිගත කිරීම් ස්වයංක්‍රීයව BetterBug වෙත යවන්න"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"දෝෂ වාර්තාවක් එක් කළ විට ප්‍රගතිය පටිගත කිරීම් ස්වයංක්‍රීයව BetterBug වෙත යවන්න. පසුව පටිගත කිරීම් දිගටම කරගෙන යනු ඇත."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"සුරකින ලද ගොනු බලන්න"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"හඹා යාමේ සැකසීම්"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"සුරැකි ගොනු"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 466d09ee..aab3bb0f 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Zaznamenávať výpis haldy"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Budú sa zaznamenávať procesy výpisu haldy vybrané v sekcii Procesy výpisu haldy"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Ak chcete zhromažďovať výpisy haldy, vyberte aspoň jeden proces v sekcii Procesy výpisu haldy"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Spustiť nové trasovanie"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Zhromažďovať stopy Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Zahŕňa podrobné údaje o telemetrii používateľského rozhrania (môže spôsobiť spomalené vykresľovanie)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Sledovať aplikácie na ladenie"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Výpis haldy sa ukladá"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Výpis haldy bol uložený"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Nahrávku zdieľajte klepnutím"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"K hláseniu chyby sa prikladá stopa"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"K hláseniu chyby bola priložená stopa"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Klepnutím otvorte BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Zastaviť trasovanie"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Zastavte profilovanie procesora"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Niektoré kategórie trasovania nie sú k dispozícii:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Zastaviť nahrávanie hlásení chýb"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Aktívne nahrávania sa ukončia po spustení hlásení chyby"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Prikladať nahrávky k hláseniam chýb"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Pri zhromažďovaní hlásení chýb automaticky odosielať prebiehajúce nahrávky do služby BetterBug"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Pri zhromažďovaní hlásení chýb automaticky odosielať prebiehajúce nahrávky službe BetterBug. Nahrávky budú následne pokračovať."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Zobraziť uložené súbory"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Nastavenia stopy"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Uložené súbory"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index a9aa48c5..a785f64b 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -10,8 +10,7 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Zapisuj izvoz kopice"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Zajame izvoz kopice za procese, izbrane v razdelku »Procesi za izvoz kopice«"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Če želite zbirati izvoze kopice, izberite vsaj en proces v razdelku »Procesi za izvoz kopice«"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Začni novo sledenje"</string>
-    <string name="winscope_tracing" msgid="5818984791154837458">"Zbiranje sledov Winscope"</string>
+    <string name="winscope_tracing" msgid="5818984791154837458">"Zbiranje sledi Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Vključuje podrobne telemetrične podatke o uporabniškem vmesniku (lahko povzroči zatikanje)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Sledenje aplikacijam, v katerih je mogoče odpravljati napake"</string>
     <string name="categories" msgid="2280163673538611008">"Kategorije"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Shranjevanje izvoza kopice"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Izvoz kopice je shranjen"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Dotaknite se, da delite zapis."</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Prilaganje sledi poročilu o napakah"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Sled je bila priložena poročilu o napakah."</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Dotaknite se, da odprete orodje BetterBug."</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Ustavite sledenje"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Ustavite profiliranje CPE-ja"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Nekatere kategorije sledenja niso na voljo:"</string>
@@ -88,8 +84,8 @@
     <string name="sixtyfive_thousand_kb" msgid="8168144138598305306">"65536 KB"</string>
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Ustavi zapisovanje za poročila o napakah"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Konča aktivna zapisovanja ob zagonu poročila o napakah."</string>
-    <string name="attach_to_bug_report" msgid="5388986830016247490">"Zapise priloži poročilom o napakah"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Samodejno pošiljanje vmesnih zapisov v orodje BetterBug ob zbiranju poročila o napakah"</string>
+    <string name="attach_to_bug_report" msgid="5388986830016247490">"Prilaganje posnetkov poročilom o napakah"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Samodejno pošiljanje posnetkov v teku v orodje BetterBug pri zbiranju poročila o napakah. Snemanje se bo nato nadaljevalo."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Prikaži shranjene datoteke"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Nastavitve sledenja"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Shranjene datoteke"</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 52db26e2..ef787856 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Regjistro stivën e skedarëve fiktivë"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Regjistron një stivë të skedarëve fiktivë të proceseve të zgjedhura te \"Proceset e stivës së skedarëve fiktivë\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Zgjidh të paktën një proces te \"Proceset e stivës së skedarëve fiktivë\" për të mbledhur stivat e skedarëve fiktivë"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Nis një gjurmim të ri"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Mblidh gjurmët e Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Përfshin të dhëna të detajuara të telemetrisë së ndërfaqes së përdoruesit (mund të shkaktojë defekte)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Gjurmo aplikacionet e gjurmueshme"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Stiva e skedarëve fiktivë po ruhet"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Stiva e skedarëve fiktivë u ruajt"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Trokit për të ndarë regjistrimin tënd"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Po bashkëngjit gjurmimin në raportin e defektit në kod"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"U bashkëngjit gjurmimi në raportin e defektit në kod"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Trokit për të hapur BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Ndalo gjurmimin"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Ndalo profilizimin e CPU-së"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Disa kategori gjurme nuk ofrohen:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Ndalon regjistrimin për raporte të defekteve në kod"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Përfundon regjistrimet aktive kur fillon një raport defekti në kod"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Bashkëngjit regjistrimet te raportet e defekteve në kod"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Dërgo automatikisht regjistrimet në vazhdim te BetterBug kur merret një raport defektesh në kod"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Dërgo automatikisht regjistrimet në vazhdim te BetterBug kur merret një raport defektesh në kod. Regjistrimet do të vazhdojnë më pas."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Shiko skedarët e ruajtur"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Gjurmo cilësimet"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Skedarët e ruajtur"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index b95a14b4..c8083d5f 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Снимај динамички део меморије за процес"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Снима динамички део меморије за процесе изабране у делу Процеси за снимање динамичког дела меморије"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Да бисте прикупљали снимке динамичког дела меморије за процесе, изаберите бар један процес у делу Процеси за снимање динамичког дела меморије"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Покрени ново праћење"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Прикупљај Winscope трагове"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Обухвата детаљне телеметријске податке о корисничком интерфејсу (може да изазове сецкање)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Прати апликације са функцијом за отклањање грешака"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Чува се снимак динамичког дела меморије за процес"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Снимак динамичког дела меморије за процес је сачуван"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Додирните да бисте делили снимак"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Праћење се прилаже извештају о грешци"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Праћење је приложено извештају о грешци"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Додирните да бисте отворили BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Зауставите трагање"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Зауставите профилисање процесора"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Неке категорије праћења нису доступне:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Заустави снимање за извештаје о грешци"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Зауставља активна снимања кад се започне извештај о грешци"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Приложите снимке у извештаје о грешци"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Аутоматски шаљи снимке у току на BetterBug по добијању извештаја о грешци"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Аутоматски шаљите BetterBug-у снимке док је снимање у току када се прикупи извештај о грешци. Снимање ће се затим наставити."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Прикажи сачуване фајлове"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Подешавања праћења"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Сачувани фајлови"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index 9d93dec5..f9904e91 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Spela in minnesdump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Spelar in en minnesdump av processerna som har valts i Minnedumpprocesser"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Välj minst en process i Minnesdumpprocesser för att samla in minnesdumpar"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Starta ny spårning"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Samla in Winscope-spår"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inkluderar detaljerad telemetridata för användargränssnittet (kan orsaka jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Spåra felsökningsbara appar"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Sparar minnesdump"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Minnesdump har sparats"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Tryck för att dela inspelningen"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Spår bifogas i felrapporten"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Spår har bifogats i felrapporten"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Tryck för att öppna BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Stoppa spårningen"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Stoppa CPU-profilering"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Vissa spårningskategorier är inte tillgängliga:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Sluta spela in till felrapporter"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Avslutar aktiv inspelning när felrapportering startas"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Bifoga inspelningar i felrapporter"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Skicka automatiskt inspelningar från pågående session till BetterBug när en felrapport samlas in"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Skicka automatiskt inspelningar från pågående session till BetterBug när en felrapport samlas in. Inspelningarna fortsätter efteråt."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Visa sparade filer"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Spåra inställningar"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Sparade filer"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index aee4290f..0bb7e900 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Rekodi picha ya hifadhi"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Hunasa picha ya hifadhi ya michakato iliyochaguliwa katika \"Michakato ya kurekodi picha ya hifadhi\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Chagua angalau mchakato mmoja katika \"Michakato ya kurekodi picha ya hifadhi\" ili ukusanye picha za hifadhi"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Anzisha historia mpya ya shughuli"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Kusanya historia ya shughuli kwenye Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inajumuisha data ya kina ya kiolesura inayorekodiwa na kutumwa kutoka mbali (inaweza kusababisha matatizo ya ubora)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Tafuta programu zinazoweza kutatuliwa"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Inahifadhi picha ya hifadhi"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Picha ya hifadhi imehifadhiwa"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Gusa ili ushiriki rekodi yako"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Inaambatisha historia ya shughuli kwenye ripoti ya hitilafu"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Historia ya shughuli imeambatishwa kwenye ripoti ya hitilafu"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Gusa ili ufungue BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Acha kurekodi"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Komesha uchanganuzi wa kiini cha kompyuta (CPU)"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Baadhi ya aina za nyayo hazipatikani:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Acha kurekodi ripoti za hitilafu"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Hukatisha rekodi zinazoendelea ripoti ya hitilafu inapoanzishwa"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Ambatisha rekodi kwenye ripoti za hitilafu"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Tuma kiotomatiki rekodi za shughuli zinazoendelea kwenye BetterBug wakati ripoti ya hitilafu inakusanywa"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Tuma kiotomatiki rekodi ya matukio yanayoendelea kwa BetterBug wakati ripoti ya hitilafu inakusanywa. Rekodi ya matukio itaendelea baadaye."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Angalia faili zilizohifadhiwa"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Mipangilio ya ufuatiliaji"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Faili zilizohifadhiwa"</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 8be13047..bc2fb355 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -10,10 +10,9 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ஹீப் டம்ப்பை ரெக்கார்டு செய்தல்"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\'ஹீப் டம்ப் செயல்முறைகளில்\' தேர்ந்தெடுக்கப்பட்ட செயல்முறைகளின் ஹீப் டம்ப்பைப் பதிவுசெய்கிறது"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ஹீப் டம்ப்களைச் சேகரிக்க \'ஹீப் டம்ப் செயல்முறைகளில்\' குறைந்தது ஒரு செயல்முறையாவது தேர்ந்தெடுங்கள்"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"புதிய டிரேஸைத் தொடங்கு"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"வின்ஸ்கோப் டிரேஸ்களைச் சேகரித்தல்"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"விரிவான UI டெலிமெட்ரி தரவும் அடங்கும் (மந்தமான செயல்பாட்டை உண்டாக்கலாம்)"</string>
-    <string name="trace_debuggable_applications" msgid="7957069895298887899">"பிழை திருத்தக்கூடிய ஆப்ஸை டிரேஸ் செய்"</string>
+    <string name="trace_debuggable_applications" msgid="7957069895298887899">"பிழை திருத்தக்கூடிய ஆப்ஸை டிரேஸ் செய்தல்"</string>
     <string name="categories" msgid="2280163673538611008">"வகைகள்"</string>
     <string name="restore_default_categories" msgid="5090536794637169521">"இயல்புநிலை வகைகளை மீட்டமை"</string>
     <string name="default_categories_restored" msgid="6861683793680564181">"இயல்புநிலை வகைகள் மீட்டமைக்கப்பட்டன"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"ஹீப் டம்ப்பைச் சேமிக்கிறது"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"ஹீப் டம்ப் சேமிக்கப்பட்டது"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"உங்கள் ரெக்கார்டிங்கைப் பகிர தட்டுங்கள்"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"பிழை அறிக்கையுடன் டிரேஸை இணைக்கிறது"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"பிழை அறிக்கையுடன் டிரேஸ் இணைக்கப்பட்டது"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug கருவியைத் திறக்க தட்டவும்"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"டிரேஸ் செய்வதை நிறுத்தவும்"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU ப்ரொஃபைலிங்கை நிறுத்தவும்"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"கிடைக்காத டிரேஸ் வகைகள்:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"பிழை அறிக்கைக்காக ரெக்கார்டிங்கை நிறுத்துதல்"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"பிழை அறிக்கை தொடங்கியதும் செயலிலுள்ள ரெக்கார்டிங்குகளை நிறுத்திவிடும்"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"பிழை அறிக்கைகளில் ரெக்கார்டிங்குகளை இணைத்தல்"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"பிழை அறிக்கை சேகரிக்கப்பட்டதும் செயலிலுள்ள ரெக்கார்டிங்குகள் தானாகவே BetterBug கருவிக்கு அனுப்பப்படும்"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"பிழை அறிக்கை சேகரிக்கப்பட்டதும் செயலிலுள்ள ரெக்கார்டிங்குகள் தானாகவே BetterBug கருவிக்கு அனுப்பப்படும். அதன்பிறகு ரெக்கார்டிங்குகள் தொடரும்."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"சேமிக்கப்பட்ட ஃபைல்களைப் பாருங்கள்"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"அமைப்புகளை டிரேஸ் செய்யுங்கள்"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"சேமித்த ஃபைல்கள்"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index d1a353f6..dabe37f0 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -10,10 +10,9 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"హీప్ డంప్‌ను రికార్డ్ చేయండి"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"హీప్ డంప్ ప్రాసెస్‌ల\"లో ఎంచుకున్న ప్రాసెస్‌ల హీప్ డంప్‌ను క్యాప్చర్ చేస్తుంది"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"హీప్ డంప్‌లను సేకరించడానికి \"హీప్ డంప్ ప్రాసెస్‌ల\"లో కనీసం ఒక ప్రాసెస్‌ను ఎంచుకోండి"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"కొత్త ట్రేస్‌ను ప్రారంభించండి"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope ట్రేస్‌లను సేకరించండి"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"వివరణాత్మక UI టెలిమెట్రీ డేటా ఉంటుంది (ఈ ప్రాసెస్ జంక్‌ను క్రియేట్ చేయవచ్చు)"</string>
-    <string name="trace_debuggable_applications" msgid="7957069895298887899">"డీబగ్ చేయగల అప్లికేషన్‌ల స్థితిగతి కనుగొనండి"</string>
+    <string name="trace_debuggable_applications" msgid="7957069895298887899">"డీబగ్ చేయగల అప్లికేషన్‌ల స్టేటస్‌ను ట్రేస్ చేయండి"</string>
     <string name="categories" msgid="2280163673538611008">"కేటగిరీలు"</string>
     <string name="restore_default_categories" msgid="5090536794637169521">"ఆటోమేటిక్ కేటగిరీలను రీస్టోర్ చేయండి"</string>
     <string name="default_categories_restored" msgid="6861683793680564181">"ఆటోమేటిక్ కేటగిరీలు రీస్టోర్ అయ్యాయి"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"హీప్ డంప్‌ను సేవ్ చేస్తోంది"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"హీప్ డంప్ సేవ్ చేయబడింది"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"మీ రికార్డింగ్‌ను షేర్ చేయడానికి ట్యాప్ చేయండి"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"బగ్ రిపోర్ట్‌కు ట్రేస్‌ను అటాచ్ చేయడం"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"బగ్ రిపోర్ట్‌కు అటాచ్ చేయబడిన ట్రేస్"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBugను తెరవడానికి ట్యాప్ చేయండి"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"స్థితిగతిని కనుగొనడం ఆపివేయి"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU ప్రొఫైలింగ్‌ను ఆపివేయండి"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"కొన్ని స్థితిగతి కేటగిరీలు అందుబాటులో లేవు:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"బగ్ రిపోర్ట్‌ల కోసం రికార్డింగ్‌ను ఆపివేయండి"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"బగ్ రిపోర్ట్ ప్రాసెస్ ప్రారంభమైనప్పుడు, యాక్టివ్‌గా ఉన్న ట్రేస్ రికార్డింగ్‌లను ఆపివేస్తుంది"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"బగ్ రిపోర్ట్‌లకు రికార్డింగ్‌లను అటాచ్ చేయండి"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"బగ్ రిపోర్ట్ కలెక్ట్ చేయబడినప్పుడు ప్రోగెస్‌లో ఉన్న రికార్డింగ్‌లను ఆటోమేటిక్‌గా BetterBugకు పంపండి"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"బగ్ రిపోర్ట్ కలెక్ట్ చేయబడినప్పుడు ప్రోగెస్‌లో ఉన్న రికార్డింగ్‌లను ఆటోమేటిక్‌గా BetterBugకు పంపండి. సంబంధిత వ్యవధి తర్వాత, రికార్డింగ్‌లు కొనసాగుతాయి."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"సేవ్ చేసిన ఫైల్స్‌ను చూడండి"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ట్రేస్ సెట్టింగ్‌లు"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"సేవ్ చేసిన ఫైల్స్"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 3da1f337..64150fb8 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"บันทึกฮีปดัมป์"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"บันทึกฮีปดัมป์ของกระบวนการที่เลือกใน \"กระบวนการฮีปดัมป์\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"เลือกอย่างน้อย 1 กระบวนการใน \"กระบวนการฮีปดัมป์\" เพื่อรวบรวมฮีปดัมป์"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"เริ่มการติดตามใหม่"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"รวบรวมการติดตาม Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"รวมข้อมูลจากระยะไกลของ UI โดยละเอียด (อาจทำให้เกิดการกระตุกได้)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ติดตามแอปพลิเคชันที่แก้ไขข้อบกพร่องได้"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"กำลังบันทึกฮีปดัมป์"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"บันทึกฮีปดัมป์แล้ว"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"แตะเพื่อแชร์การบันทึก"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"กำลังแนบการติดตามในรายงานข้อบกพร่อง"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"แนบการติดตามในรายงานข้อบกพร่องแล้ว"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"แตะเพื่อเปิด BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"หยุดติดตาม"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"หยุดทำโปรไฟล์ CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"การติดตามบางหมวดหมู่ไม่พร้อมใช้งาน:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"หยุดการบันทึกสำหรับรายงานข้อบกพร่อง"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"ยุติการบันทึกที่ทำงานอยู่เมื่อเริ่มรายงานข้อบกพร่อง"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"แนบการบันทึกในรายงานข้อบกพร่อง"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"ส่งการบันทึกที่กำลังดำเนินการไปยัง BetterBug โดยอัตโนมัติเมื่อรวบรวมรายงานข้อบกพร่อง"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ส่งการบันทึกที่กำลังดำเนินการไปยัง BetterBug โดยอัตโนมัติเมื่อรวบรวมรายงานข้อบกพร่อง การบันทึกจะดำเนินการต่อหลังจากนั้น"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"ดูไฟล์ที่บันทึกไว้"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"การตั้งค่าการติดตาม"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ไฟล์ที่บันทึกไว้"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 5812a15c..d083e1ba 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"I-record ang heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Nagka-capture ng heap dump ng mga prosesong pinili sa \"Mga proseso ng heap dump\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Pumili ng kahit isang proseso man lang sa \"Mga proseso ng heap dump\" para mangolekta ng mga heap dump"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Magsimula ng bagong trace"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Kolektahin ang mga trace ng Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Kasama ang detalyadong data ng UI telemetry (posibleng magdulot ng jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Mag-trace ng mga nade-debug na application"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Sine-save ang heap dump"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Na-save ang heap dump"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"I-tap para ibahagi ang iyong recording"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Nag-a-attach ng trace sa ulat ng bug"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Nag-attach ng trace sa ulat ng bug"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"I-tap para buksan ang BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Ihinto ang pag-trace"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Ihinto ang pag-profile ng CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Hindi available ang ilang kategorya ng pag-trace:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Ihinto ang pag-record para sa mga ulat ng bug"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Wawakasan ang mga aktibong pag-record kapag nagsimula ng ulat ng bug"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"I-attach ang mga recording sa mga ulat ng bug"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Awtomatikong magpadala ng mga kasalukuyang isinasagawang recording sa BetterBug kapag nangolekta ng ulat ng bug"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Awtomatikong magpadala ng mga kasalukuyang pag-record sa BetterBug kapag may nakolektang ulat ng bug. Magpapatuloy ang mga pag-record pagkatapos nito."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Tingnan ang mga naka-save na file"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Mga setting ng pag-trace"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Mga naka-save na file"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 3bd5511b..9b1f7f5b 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Yığın dökümünü kaydet"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"Yığın dökümü işlemleri\" bölümünde seçilen işlemlerin yığın dökümünü yakalar"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Yığın dökümlerini toplamak için \"Yığın dökümü işlemleri\" bölümünde en az bir işlem seçin"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Yeni iz başlat"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope izlerini topla"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Ayrıntılı kullanıcı arayüzü telemetri verileri içerir (duraklamaya neden olabilir)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Hata ayıklaması yapılabilecek uygulamaları izle"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Yığın dökümü kaydediliyor"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Yığın dökümü kaydedildi"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Kaydınızı paylaşmak için dokunun"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Hata raporuna iz ekleniyor"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Hata raporuna iz eklendi"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBug\'ı açmak için dokunun"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"İzlemeyi durdur"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU profili oluşturmayı durdur"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Bazı izleme kategorileri kullanılamıyor:"</string>
@@ -88,8 +84,8 @@
     <string name="sixtyfive_thousand_kb" msgid="8168144138598305306">"65.536 KB"</string>
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Hata raporları için kaydı durdurun"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Hata raporu başlatıldığında etkin izleme kayıtlarını sonlandırır"</string>
-    <string name="attach_to_bug_report" msgid="5388986830016247490">"Hata raporlarına kayıt ekleyin"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Hata raporu alındığında devam etmekte olan kayıtları otomatik olarak BetterBug\'a gönder"</string>
+    <string name="attach_to_bug_report" msgid="5388986830016247490">"Hata raporlarına kayıt ekle"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Hata raporu alındığında devam etmekte olan kayıtları otomatik olarak BetterBug\'a gönder Sonrasında kayıtlar devam eder."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Kayıtlı dosyaları göster"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"İzleme ayarları"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Kayıtlı dosyalar"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 15dfb2e6..158e5fce 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Записати дамп пам’яті"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Записує дамп пам’яті для процесів, вибраних у списку \"Процеси для дампу пам’яті\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Щоб записувати дампи пам’яті, виберіть принаймні один пункт у списку \"Процеси дампу пам’яті\""</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Почати нове трасування"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Збирати журнали трасування Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Містить детальні телеметричні дані інтерфейсу (може спричиняти підвисання)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Трасувати додатки для налагодження"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Зберігання дампу пам’яті"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Дамп пам’яті збережено"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Торкніться, щоб поділитися записом"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Трасування долучається до звіту про помилки"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Трасування долучено до звіту про помилки"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Натисніть, щоб відкрити BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Припинити трасування"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Зупиніть профілювання ЦП"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Деякі категорії трасування недоступні:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Зупиняти запис для звітів про помилки"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Коли починає формуватися звіт про помилки, активні записи припинятимуться"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Долучати записи до звітів про помилки"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Автоматично надсилати активні записи в BetterBug під час формування звіту про помилку"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Автоматично надсилати активні записи в BetterBug під час формування звіту про помилку. Після цього записування продовжиться."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Переглянути збережені файли"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Налаштування трасування"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Збережені файли"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index cb64dbff..600f69ba 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ہیپ ڈمپ ریکارڈ کریں"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"ہیپ ڈمپ پروسیسز\" میں سے منتخب کردہ پروسیسز کے ہیپ ڈمپ کو کیپچر کرتا ہے"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ہیپ ڈمپس جمع کرنے کے لیے \"ہیپ ڈمپ کے پروسیسز\" میں کم از کم ایک پروسیس منتخب کریں"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"نیا ٹریس شروع کریں"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"‏Winscope کے ٹریسز جمع کریں"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"‏تفصیلی UI ٹیلی میٹری ڈیٹا پر مشتمل ہے (جنک کا سبب بن سکتی ہے)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ڈیبگ کے لائق ایپلیکیشنز ٹریس کریں"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"ہیپ ڈمپ کو محفوظ کیا جا رہا ہے"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"ہیپ ڈمپ محفوظ کیا گیا"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"اپنی ریکارڈنگ کا اشتراک کرنے کے لیے تھپتھپائیں"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"بگ رپورٹ پر ٹریس کو منسلک کیا جارہا ہے"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"بگ رپورٹ پر ٹریس منسلک کی گئی"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"‏BetterBug کو کھولنے کے لیے تھپتھپائیں"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"ٹریس کرنا بند کریں"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"‏CPU پروفائلنگ اسٹاپ کریں"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"ٹریس کرنے کے کچھ زمرے دستیاب نہیں ہیں:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"بگ رپورٹس کے لیے ریکارڈنگ بند کریں"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"بگ رپورٹس شروع ہونے پر فعال ریکارڈنگز ختم ہو جاتی ہیں"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"بگ رپورٹس کے ساتھ ریکارڈنگز منسلک کریں"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"‏بگ رپورٹ جمع ہونے پر خودکار طور پر جاری ریکارڈنگز BetterBug کو بھیجیں"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"‏بگ رپورٹ جمع ہونے پر خودکار طور پر جاری ریکارڈنگز BetterBug کو بھیج دی جاتی ہیں۔ اس کے بعد ریکارڈنگز جاری رہیں گی۔"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"محفوظ کردہ فائلز دیکھیں"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ٹریس کی ترتیبات"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"محفوظ کردہ فائلز"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index 3bd0b38b..49d66bcd 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Hip-dampni yozib olish"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"“Hip-damp jarayonlari”da tanlangan jarayonlarning hip-damplarini oladi"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Hip-damplarni olish uchun “Hip-damp jarayonlari” qismida kamida bitta jarayonni tanlang"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Yangi trassirovkani boshlash"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope trassirovkasini jamlash"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Batafsil UI telemetriya maʼlumotlari bilan birga (kechikishga olib kelishi mumkin)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Tuzatishga ruxsati bor ilovalarning harakatlarni yozib olish"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Hip-damp saqlanmoqda"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Hip-damp saqlandi"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Yozuvni ulashish uchun bosing"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Xatolik hisobotiga trassirovka axborotini biriktirish"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Xatolik hisobotiga trassirovka axboroti biriktirilgan"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"BetterBugni ochish uchun bosing"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Trassirovkani to‘xtatish"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"CPU profaylingni toʻxtatish"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Ayrim trassirovka turkumlari mavjud emas:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Xatoliklar hisobotida yozib olishlarni toʻxtatish"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Xatoliklar hisobotini boshlanganda faol yozuvlar toʻxtatiladi"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Xatolik hisobotiga yozuvlarni biriktirish"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Xatolik haqidagi axborot jamlansa, BetterBug xizmatiga amaldagi yozuvlar avtomatik yuborilsin"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Xatolik haqidagi axborot jamlansa, BetterBug xizmatiga amaldagi yozuvlar avtomatik yuborilsin. Yozuvlar keyinroq davom etadi."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Saqlangan fayllarni ochish"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Trassirovka sozlamalari"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saqlangan fayllar"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 1f5420b3..26505e93 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Ghi tệp báo lỗi"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Thu thập một tệp báo lỗi của những quy trình được chọn trong \"Quy trình tệp báo lỗi\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Chọn ít nhất một quy trình trong \"Quy trình tệp báo lỗi\" để thu thập tệp báo lỗi"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Bắt đầu ghi lại dấu vết mới"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Thu thập dấu vết Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Gồm cả dữ liệu chi tiết được đo từ xa về giao diện người dùng (có thể gây ra hiện tượng giật)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Theo dõi ứng dụng có thể gỡ lỗi"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Đang lưu tệp báo lỗi"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"Đã lưu tệp báo lỗi"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Nhấn để chia sẻ bản ghi của bạn"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Đang đính kèm dấu vết vào báo cáo lỗi"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Đã đính kèm dấu vết vào báo cáo lỗi"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Nhấn để mở BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Dừng theo dõi"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Dừng phân tích CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Một số danh mục theo dấu không có sẵn:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Dừng ghi khi báo cáo lỗi được tạo"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Kết thúc các phiên ghi đang diễn ra khi một báo cáo lỗi được tạo"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Đính kèm bản ghi vào báo cáo lỗi"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Tự động gửi các bản ghi đang xử lý đến BetterBug khi một báo cáo lỗi được thu thập"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Tự động gửi các bản ghi đang xử lý đến BetterBug khi một báo cáo lỗi được thu thập. Sau đó, quá trình ghi sẽ tiếp tục."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Xem tệp đã lưu"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Cài đặt hoạt động theo dõi"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Tệp đã lưu"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 31c91a82..655b2c02 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"记录堆转储"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"根据“堆转储进程”部分中的所选进程捕获堆转储"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"在“堆转储进程”部分中选择至少 1 个进程后才能收集堆转储"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"开始新的轨迹"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"收集 Winscope 跟踪记录"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"包括详细的界面遥测数据（可能会导致卡顿）"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"跟踪可调试的应用"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"正在保存堆转储"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"已保存堆转储"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"点按即可分享录制内容"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"正在将跟踪记录附加到错误报告"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"已将跟踪记录附加到错误报告"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"点按即可打开 BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"停止跟踪"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"停止分析 CPU 性能"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"某些跟踪记录类别不可用："</string>
@@ -65,11 +61,11 @@
     <string name="system_trace_sensitive_data" msgid="3069389866696009549">"系统跟踪文件可能包含敏感的系统数据和应用数据（例如应用使用情况信息）。请务必只与您信任的人和应用分享系统跟踪文件。"</string>
     <string name="share" msgid="8443979083706282338">"分享"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"不再显示"</string>
-    <string name="long_traces" msgid="5110949471775966329">"长期轨迹"</string>
+    <string name="long_traces" msgid="5110949471775966329">"长期跟踪记录"</string>
     <string name="long_traces_summary" msgid="419034282946761469">"持续保存到设备存储空间"</string>
     <string name="long_traces_summary_betterbug" msgid="445546400875135624">"持续保存到设备存储空间（不会自动附加到错误报告）"</string>
-    <string name="max_long_trace_size" msgid="1943788179787181241">"最大长期轨迹大小"</string>
-    <string name="max_long_trace_duration" msgid="8009837944364246785">"最大长期轨迹时长"</string>
+    <string name="max_long_trace_size" msgid="1943788179787181241">"最大长期跟踪记录大小"</string>
+    <string name="max_long_trace_duration" msgid="8009837944364246785">"最大长期跟踪记录时长"</string>
     <string name="two_hundred_mb" msgid="4950018549725084512">"200 MB"</string>
     <string name="one_gb" msgid="590396985168692037">"1 GB"</string>
     <string name="five_gb" msgid="7883941043220621649">"5 GB"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"停止记录错误报告"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"启动错误报告时结束进行中的录制内容"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"在错误报告中附加录制内容"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"收集错误报告后，自动将处理中的录制内容发送到 BetterBug"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"收集错误报告后，自动将处理中的录制内容发送到 BetterBug。之后，系统将继续录制。"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"查看已保存的文件"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"跟踪设置"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"已保存的文件"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 38b3c99b..47808190 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"記錄堆轉儲"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"擷取「堆轉儲程序」中所選程序的堆轉儲"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"請至少選取「堆轉儲程序」中的其中一個程序以收集堆轉儲"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"開始新的追蹤"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"收集 Winscope 追蹤記錄"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"加入詳細的使用者介面遙測資料 (可能會造成資源浪費)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"追蹤可偵錯的應用程式"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"正在儲存堆轉儲"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"已儲存堆轉儲"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"輕按即可分享記錄"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"正在將追蹤記錄附加至錯誤報告"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"已將追蹤記錄附加至錯誤報告"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"輕按即可開啟 BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"停止追蹤"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"停止 CPU 資料剖析"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"無法使用部分追蹤記錄類別："</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"停止用於錯誤報告的記錄"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"錯誤報告開始後結束進行中的記錄"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"在錯誤報告中附加記錄"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"收集到錯誤報告後，自動將處理中的記錄傳送到 BetterBug"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"收集到錯誤報告後，自動將處理中的記錄傳送到 BetterBug。系統之後會繼續記錄內容。"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"查看已儲存的檔案"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"追蹤記錄設定"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"已儲存的檔案"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 1ae2eb78..78394d46 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -10,7 +10,6 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"記錄記憶體快照資料"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"擷取「記憶體快照資料處理程序」中所選處理程序的記憶體快照資料"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"如要收集記憶體快照資料，請至少選取「記憶體快照資料處理程序」中的其中一個處理程序"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"開始新的追蹤記錄"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"收集 Winscope 追蹤記錄"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"加入詳細的 UI 遙測資料 (可能會導致卡頓)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"追蹤可偵錯的應用程式"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"正在儲存記憶體快照資料"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"已儲存記憶體快照資料"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"輕觸即可分享記錄檔"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"正在將追蹤記錄附加到錯誤報告"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"已將追蹤記錄附加到錯誤報告"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"輕觸即可開啟 BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"停止追蹤"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"停止 CPU 剖析"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"無法使用部分追蹤記錄類別："</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"停止用於錯誤報告的記錄工作階段"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"錯誤報告開始後結束進行中的記錄作業"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"在錯誤報告中附上記錄檔"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"收集到錯誤報告後，自動將處理中的記錄檔傳送到 BetterBug"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"收集到錯誤報告後，自動將處理中的記錄檔傳送到 BetterBug。之後，系統會繼續記錄。"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"查看已儲存的檔案"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"追蹤記錄設定"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"儲存的檔案"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index b8de352f..634b555e 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -10,10 +10,9 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Rekhoda i-heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Ithatha i-heap dump yezinqubo ezikhethiwe \"kuzinqubo ze-heap dump\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Khetha okungenani inqubo eyodwa kokuthi \"Izinqubo ze-heap dump\" ukuze uqoqe ama-heap dump"</string>
-    <string name="start_new_trace" msgid="8177130420802170353">"Qala ukulandelela okusha"</string>
-    <string name="winscope_tracing" msgid="5818984791154837458">"Qoqa Ukulandelela kwe-Winscope"</string>
+    <string name="winscope_tracing" msgid="5818984791154837458">"Qoqa Ukulandelela kweWinscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Kuhlanganisa okuningilizwe Idatha ye-UI ye-telemetry (kungaba yimbangela ye-jank)"</string>
-    <string name="trace_debuggable_applications" msgid="7957069895298887899">"Landela izinhlelo zokusebenza ze-debuggable"</string>
+    <string name="trace_debuggable_applications" msgid="7957069895298887899">"Landela izinhlelo zokusebenza zedebuggable"</string>
     <string name="categories" msgid="2280163673538611008">"Izigaba"</string>
     <string name="restore_default_categories" msgid="5090536794637169521">"Buyisela izigaba ezizenzakalelayo"</string>
     <string name="default_categories_restored" msgid="6861683793680564181">"Izigaba ezizenzakalelayo zibuyiselwe"</string>
@@ -42,9 +41,6 @@
     <string name="saving_heap_dump" msgid="6118616780825771824">"Ilondoloza i-heap dump"</string>
     <string name="heap_dump_saved" msgid="6720583137473857098">"I-heap dump ilondoloziwe"</string>
     <string name="tap_to_share" msgid="4440713575852187545">"Thepha ukuze wabelane ngokurekhoda kwakho"</string>
-    <string name="attaching_to_report" msgid="2629202947947275886">"Ukunamathisela ukulandelela kumbiko wesiphazamisi"</string>
-    <string name="attached_to_report" msgid="5806905349184608870">"Inamathisele ukulandelela kumbiko wesiphazamisi"</string>
-    <string name="attached_to_report_summary" msgid="7665675771190391355">"Thepha ukuze uvule i-BetterBug"</string>
     <string name="stop_tracing" msgid="8916938308534164152">"Yeka ukulandela"</string>
     <string name="stop_stack_sampling" msgid="848558393878357485">"Misa ukwenza iphrofayela ye-CPU"</string>
     <string name="tracing_categories_unavailable" msgid="5609076391417077752">"Ezinye izigaba zokulandelela azitholakali:"</string>
@@ -89,7 +85,7 @@
     <string name="stop_on_bugreport" msgid="4591832600597126422">"Misa ukuqopha imibiko yesiphazamisi"</string>
     <string name="stop_on_bugreport_summary" msgid="1601834864982891381">"Iqeda ukurekhodwa kokulandelela okusebenzayo uma kuqaliswe umbiko wesiphazamisi"</string>
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Namathisela okurekhodiwe emibikweni yesiphazamisi"</string>
-    <string name="attach_to_bug_report_summary" msgid="4213730623971240002">"Thumela ngokuzenzekelayo ukurekhoda okuqhubekayo ku-BetterBug lapho kuqoqwe umbiko wesiphazamisi"</string>
+    <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Thumela ngokuzenzakalelayo ukurekhoda okuqhubekayo kuBetterBug lapho kuqoqwe umbiko wesiphazamisi. Okurekhodiwe kuzoqhubeka kamuva."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Buka amafayela alondoloziwe"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Amasethingi okulandelela"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Amafayela alondoloziwe"</string>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 7496cc80..a6ad8e36 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -24,9 +24,6 @@
     <!-- This is the subtitle for the "Record heap dump" button if heap dumps are disabled. -->
     <string name="record_heap_dump_summary_disabled">Select at least one process in \"Heap dump processes\" to collect heap dumps</string>
 
-    <!-- This is the label for the button to start a new trace from a notification. -->
-    <string name="start_new_trace">Start new trace</string>
-
     <!-- This is the text for a toggle that will let the user choose whether to include Winscope traces in the trace they are collecting. -->
     <string name="winscope_tracing">Collect Winscope traces</string>
     <string name="winscope_tracing_summary">Includes detailed UI telemetry data (can cause jank)</string>
@@ -100,13 +97,6 @@
     <!-- This is the subtitle for a notification that appears after a recording was saved. Tapping it will open the 'share sheet' that will appear at the bottom of the screen and will allow the user to share the recording, for example to email. -->
     <string name="tap_to_share">Tap to share your recording</string>
 
-    <!-- This is the title for a notification that appears when Traceur is handling saving a trace to a bug report. -->
-    <string name="attaching_to_report">Attaching trace to bug report</string>
-    <!-- This is the title for a notification that appears after a trace was saved to a bug report. -->
-    <string name="attached_to_report">Attached trace to bug report</string>
-    <!-- This is the subtitle for a notification that appears after a trace was saved to a bug report. -->
-    <string name="attached_to_report_summary">Tap to open BetterBug</string>
-
     <!-- This is a message prompting the user to stop tracing. -->
     <string name="stop_tracing">Stop tracing</string>
     <!-- This is a message prompting the user to stop CPU sampling. -->
@@ -204,7 +194,7 @@
 
     <!-- When enabled, the tracing service can take the in-progress recording session and attach it to a bug report. -->
     <string name="attach_to_bug_report">Attach recordings to bug reports</string>
-    <string name="attach_to_bug_report_summary">Automatically send in-progress recordings to BetterBug when a bug report is collected</string>
+    <string name="attach_to_bug_report_summary">Automatically send in-progress recordings to BetterBug when a bug report is collected. Recordings will continue afterward.</string>
 
     <!-- On click, takes the user to the directory containing on-device Traceur files. -->
     <string name="link_to_traces">View saved files</string>
diff --git a/src/com/android/traceur/InternalReceiver.java b/src/com/android/traceur/InternalReceiver.java
deleted file mode 100644
index 918d0056..00000000
--- a/src/com/android/traceur/InternalReceiver.java
+++ /dev/null
@@ -1,39 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-package com.android.traceur;
-
-import android.content.BroadcastReceiver;
-import android.content.Context;
-import android.content.Intent;
-import android.content.SharedPreferences;
-import android.preference.PreferenceManager;
-
-public class InternalReceiver extends BroadcastReceiver {
-
-    public static final String START_ACTION = "com.android.traceur.START";
-
-    @Override
-    public void onReceive(Context context, Intent intent) {
-        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
-
-        if (START_ACTION.equals(intent.getAction())) {
-            prefs.edit().putBoolean(
-                    context.getString(R.string.pref_key_tracing_on), true).commit();
-            Receiver.updateTracing(context);
-        }
-    }
-}
diff --git a/src/com/android/traceur/MainFragment.java b/src/com/android/traceur/MainFragment.java
index 39d2a5fc..1686e6e1 100644
--- a/src/com/android/traceur/MainFragment.java
+++ b/src/com/android/traceur/MainFragment.java
@@ -30,7 +30,6 @@ import android.content.pm.PackageManager;
 import android.icu.text.MessageFormat;
 import android.net.Uri;
 import android.os.Bundle;
-import android.util.Log;
 import android.view.LayoutInflater;
 import android.view.Menu;
 import android.view.MenuInflater;
@@ -376,7 +375,7 @@ public class MainFragment extends PreferenceFragment {
             mTags.setEntries(entries.toArray(new String[0]));
             mTags.setEntryValues(values.toArray(new String[0]));
             if (restoreDefaultTags || !mPrefs.contains(context.getString(R.string.pref_key_tags))) {
-                mTags.setValues(PresetTraceConfigs.getDefaultTags());
+                mTags.setValues(PresetTraceConfigs.getDefaultConfig().getTags());
             }
             mHeapDumpProcesses.setEntries(sortedProcesses.toArray(new String[0]));
             mHeapDumpProcesses.setEntryValues(sortedProcesses.toArray(new String[0]));
@@ -409,7 +408,7 @@ public class MainFragment extends PreferenceFragment {
                 Locale.getDefault());
         Map<String, Object> arguments = new HashMap<>();
         arguments.put("count", categories.size());
-        mTags.setSummary(PresetTraceConfigs.getDefaultTags().equals(categories)
+        mTags.setSummary(PresetTraceConfigs.getDefaultConfig().getTags().equals(categories)
                          ? context.getString(R.string.default_categories)
                          : msgFormat.format(arguments));
 
diff --git a/src/com/android/traceur/Receiver.java b/src/com/android/traceur/Receiver.java
index 12b421a3..936848e9 100644
--- a/src/com/android/traceur/Receiver.java
+++ b/src/com/android/traceur/Receiver.java
@@ -24,11 +24,11 @@ import android.content.BroadcastReceiver;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
+import android.content.IntentFilter;
 import android.content.SharedPreferences;
 import android.content.pm.PackageManager;
 import android.database.ContentObserver;
 import android.net.Uri;
-import android.os.Build;
 import android.os.Handler;
 import android.os.RemoteException;
 import android.os.ServiceManager;
@@ -36,13 +36,10 @@ import android.os.UserManager;
 import android.preference.PreferenceManager;
 import android.provider.Settings;
 import android.text.TextUtils;
-import android.util.ArraySet;
 import android.util.Log;
 
 import com.android.internal.statusbar.IStatusBarService;
 
-import java.util.Arrays;
-import java.util.List;
 import java.util.Set;
 
 public class Receiver extends BroadcastReceiver {
@@ -68,6 +65,9 @@ public class Receiver extends BroadcastReceiver {
 
         if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
             Log.i(TAG, "Received BOOT_COMPLETE");
+            // USER_FOREGROUND and USER_BACKGROUND can only be received by explicitly registered
+            // receivers; manifest-declared receivers are not sufficient.
+            registerUserSwitchReceiver(context, this);
             createNotificationChannels(context);
             updateDeveloperOptionsWatcher(context, /* fromBootIntent */ true);
             // We know that Perfetto won't be tracing already at boot, so pass the
@@ -75,8 +75,15 @@ public class Receiver extends BroadcastReceiver {
             updateTracing(context, /* assumeTracingIsOff= */ true);
             TraceUtils.cleanupOlderFiles();
         } else if (Intent.ACTION_USER_FOREGROUND.equals(intent.getAction())) {
-            updateStorageProvider(context, isTraceurAllowed(context));
-        } else if (STOP_ACTION.equals(intent.getAction())) {
+            boolean traceurAllowed = isTraceurAllowed(context);
+            updateStorageProvider(context, traceurAllowed);
+            if (!traceurAllowed) {
+                // We don't need to check for ongoing traces to stop because if
+                // ACTION_USER_FOREGROUND is received, there should be no ongoing traces.
+                removeQuickSettingsTiles(context);
+            }
+        } else if (Intent.ACTION_USER_BACKGROUND.equals(intent.getAction()) ||
+                STOP_ACTION.equals(intent.getAction())) {
             // Only one of these should be enabled, but they all use the same path for stopping and
             // saving, so set them all to false.
             prefs.edit().putBoolean(
@@ -229,6 +236,20 @@ public class Receiver extends BroadcastReceiver {
         updateQuickSettingsPanel(context, stackSamplingQsEnabled, StackSamplingQsService.class);
     }
 
+    private static void removeQuickSettingsTiles(Context context) {
+        SharedPreferences prefs =
+            PreferenceManager.getDefaultSharedPreferences(context);
+        prefs.edit().putBoolean(
+            context.getString(R.string.pref_key_tracing_quick_setting), false)
+            .commit();
+        prefs.edit().putBoolean(
+            context.getString(
+                R.string.pref_key_stack_sampling_quick_setting), false)
+            .commit();
+        updateTracingQuickSettings(context);
+        updateStackSamplingQuickSettings(context);
+    }
+
     /*
      * When Developer Options are toggled, also toggle the Storage Provider that
      * shows "System traces" in Files.
@@ -249,17 +270,7 @@ public class Receiver extends BroadcastReceiver {
                         boolean traceurAllowed = isTraceurAllowed(context);
                         updateStorageProvider(context, traceurAllowed);
                         if (!traceurAllowed) {
-                            SharedPreferences prefs =
-                                PreferenceManager.getDefaultSharedPreferences(context);
-                            prefs.edit().putBoolean(
-                                context.getString(R.string.pref_key_tracing_quick_setting), false)
-                                .commit();
-                            prefs.edit().putBoolean(
-                                context.getString(
-                                    R.string.pref_key_stack_sampling_quick_setting), false)
-                                .commit();
-                            updateTracingQuickSettings(context);
-                            updateStackSamplingQuickSettings(context);
+                            removeQuickSettingsTiles(context);
                             // Stop an ongoing trace if one exists.
                             if (TraceUtils.isTracingOn()) {
                                 TraceService.stopTracingWithoutSaving(context);
@@ -341,9 +352,16 @@ public class Receiver extends BroadcastReceiver {
         notificationManager.createNotificationChannel(saveTraceChannel);
     }
 
+    private static void registerUserSwitchReceiver(Context context, BroadcastReceiver receiver) {
+        IntentFilter filter = new IntentFilter();
+        filter.addAction(Intent.ACTION_USER_FOREGROUND);
+        filter.addAction(Intent.ACTION_USER_BACKGROUND);
+        context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED);
+    }
+
     public static Set<String> getActiveTags(Context context, SharedPreferences prefs, boolean onlyAvailable) {
         Set<String> tags = prefs.getStringSet(context.getString(R.string.pref_key_tags),
-                PresetTraceConfigs.getDefaultTags());
+                PresetTraceConfigs.getDefaultConfig().getTags());
         Set<String> available = TraceUtils.listCategories().keySet();
 
         if (onlyAvailable) {
@@ -356,7 +374,7 @@ public class Receiver extends BroadcastReceiver {
 
     public static Set<String> getActiveUnavailableTags(Context context, SharedPreferences prefs) {
         Set<String> tags = prefs.getStringSet(context.getString(R.string.pref_key_tags),
-                PresetTraceConfigs.getDefaultTags());
+                PresetTraceConfigs.getDefaultConfig().getTags());
         Set<String> available = TraceUtils.listCategories().keySet();
 
         tags.removeAll(available);
diff --git a/src/com/android/traceur/StopTraceService.java b/src/com/android/traceur/StopTraceService.java
index c5aaaaab..3baf3269 100644
--- a/src/com/android/traceur/StopTraceService.java
+++ b/src/com/android/traceur/StopTraceService.java
@@ -44,8 +44,7 @@ public class StopTraceService extends TraceService {
         // Ensures that only intents that pertain to stopping a trace and need to be accessed from
         // outside Traceur are passed to TraceService through StopTraceService.
         String intentAction = intent.getAction();
-        if (!intentAction.equals(TraceService.INTENT_ACTION_NOTIFY_SESSION_STOLEN) &&
-            !intentAction.equals(TraceService.INTENT_ACTION_NOTIFY_SESSION_STOPPED)) {
+        if (!intentAction.equals(TraceService.INTENT_ACTION_NOTIFY_SESSION_STOPPED)) {
             return;
         }
         SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
diff --git a/src/com/android/traceur/TraceController.java b/src/com/android/traceur/TraceController.java
index d80d95d4..75ab6afc 100644
--- a/src/com/android/traceur/TraceController.java
+++ b/src/com/android/traceur/TraceController.java
@@ -33,11 +33,14 @@ import android.util.Log;
 
 import androidx.core.content.FileProvider;
 
+import java.io.BufferedOutputStream;
 import java.io.File;
 import java.io.FileOutputStream;
 import java.io.IOException;
 import java.nio.file.Files;
+import java.util.ArrayList;
 import java.util.List;
+import java.util.Map;
 import java.util.zip.ZipEntry;
 import java.util.zip.ZipOutputStream;
 
@@ -56,8 +59,7 @@ public class TraceController extends Handler {
     public void handleMessage(Message msg) {
         switch (msg.what) {
             case MessageConstants.START_WHAT:
-                TraceUtils.presetTraceStart(mContext, msg.getData().getSerializable(
-                    INTENT_EXTRA_TRACE_TYPE, TraceUtils.PresetTraceType.class));
+                startTracingSafely(mContext, msg.getData());
                 break;
             case MessageConstants.STOP_WHAT:
                 TraceUtils.traceStop(mContext);
@@ -65,11 +67,45 @@ public class TraceController extends Handler {
             case MessageConstants.SHARE_WHAT:
                 shareFiles(mContext, msg.replyTo);
                 break;
+            case MessageConstants.TAGS_WHAT:
+                provideTags(msg.replyTo);
+                break;
             default:
                 throw new IllegalArgumentException("received unknown msg.what: " + msg.what);
         }
     }
 
+    private static void startTracingSafely(Context context, @Nullable Bundle data) {
+        TraceConfig config;
+        if (data == null) {
+            Log.w(TAG, "bundle containing Input trace config is not present, using default "
+                + "trace configuration.");
+            config = PresetTraceConfigs.getDefaultConfig();
+        } else {
+            data.setClassLoader(TraceConfig.class.getClassLoader());
+            config = data.getParcelable(INTENT_EXTRA_TRACE_TYPE, TraceConfig.class);
+            if (config == null) {
+                Log.w(TAG, "Input trace config could not be read, using default trace "
+                    + "configuration.");
+                config = PresetTraceConfigs.getDefaultConfig();
+            }
+        }
+        TraceUtils.traceStart(context, config);
+    }
+
+    private static void replyToClient(Messenger replyTo, int what, Bundle data) {
+        Message msg = Message.obtain();
+        msg.what = what;
+        msg.setData(data);
+
+        try {
+            replyTo.send(msg);
+        } catch (RemoteException e) {
+            Log.e(TAG, "failed to send msg back to client", e);
+            throw new RuntimeException(e);
+        }
+    }
+
     // Files are kept on private storage, so turn into Uris that we can
     // grant temporary permissions for. We then share them, usually with BetterBug, via Intents
     private static void shareFiles(Context context, Messenger replyTo) {
@@ -98,16 +134,7 @@ public class TraceController extends Handler {
                 data.putParcelable(MessageConstants.EXTRA_WINSCOPE, winscopeUri);
             }
 
-            Message msg = Message.obtain();
-            msg.what = MessageConstants.SHARE_WHAT;
-            msg.setData(data);
-
-            try {
-                replyTo.send(msg);
-            } catch (RemoteException e) {
-                Log.e(TAG, "failed to send msg back to client", e);
-                throw new RuntimeException(e);
-            }
+            replyToClient(replyTo, MessageConstants.SHARE_WHAT, data);
         });
     }
 
@@ -125,7 +152,8 @@ public class TraceController extends Handler {
             Log.e(TAG, "Failed to create zip file for files.", e);
             return null;
         }
-        try (ZipOutputStream os = new ZipOutputStream(new FileOutputStream(outZip))) {
+        try (ZipOutputStream os = new ZipOutputStream(
+                new BufferedOutputStream(new FileOutputStream(outZip)))) {
             files.forEach(file -> {
                 try {
                     os.putNextEntry(new ZipEntry(file.getName()));
@@ -141,4 +169,14 @@ public class TraceController extends Handler {
             return null;
         }
     }
+
+    private static void provideTags(Messenger replyTo) {
+        Map<String, String> categoryMap = TraceUtils.listCategories();
+        Bundle data = new Bundle();
+        data.putStringArrayList(MessageConstants.BUNDLE_KEY_TAGS,
+            new ArrayList<>(categoryMap.keySet()));
+        data.putStringArrayList(MessageConstants.BUNDLE_KEY_TAG_DESCRIPTIONS,
+            new ArrayList<>(categoryMap.values()));
+        replyToClient(replyTo, MessageConstants.TAGS_WHAT, data);
+    }
 }
diff --git a/src/com/android/traceur/TraceService.java b/src/com/android/traceur/TraceService.java
index 71c8b7ef..ddb89e98 100644
--- a/src/com/android/traceur/TraceService.java
+++ b/src/com/android/traceur/TraceService.java
@@ -16,6 +16,8 @@
 
 package com.android.traceur;
 
+import static android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE;
+
 import android.app.IntentService;
 import android.app.Notification;
 import android.app.NotificationManager;
@@ -43,9 +45,6 @@ public class TraceService extends IntentService {
      * or limited storage capacity. */
     static String INTENT_ACTION_NOTIFY_SESSION_STOPPED =
             "com.android.traceur.NOTIFY_SESSION_STOPPED";
-    /* Indicates a Traceur-associated tracing session has been attached to a bug report */
-    static String INTENT_ACTION_NOTIFY_SESSION_STOLEN =
-            "com.android.traceur.NOTIFY_SESSION_STOLEN";
     private static String INTENT_ACTION_STOP_TRACING = "com.android.traceur.STOP_TRACING";
     private static String INTENT_ACTION_START_TRACING = "com.android.traceur.START_TRACING";
     private static String INTENT_ACTION_START_STACK_SAMPLING =
@@ -147,12 +146,9 @@ public class TraceService extends IntentService {
             startStackSamplingInternal();
         } else if (intent.getAction().equals(INTENT_ACTION_START_HEAP_DUMP)) {
             startHeapDumpInternal();
-        } else if (intent.getAction().equals(INTENT_ACTION_STOP_TRACING)) {
-            stopTracingInternal(TraceUtils.getOutputFilename(type), false);
-        } else if (intent.getAction().equals(INTENT_ACTION_NOTIFY_SESSION_STOPPED)) {
-            stopTracingInternal(TraceUtils.getOutputFilename(type), false);
-        } else if (intent.getAction().equals(INTENT_ACTION_NOTIFY_SESSION_STOLEN)) {
-            stopTracingInternal("", true);
+        } else if (intent.getAction().equals(INTENT_ACTION_STOP_TRACING) ||
+                intent.getAction().equals(INTENT_ACTION_NOTIFY_SESSION_STOPPED)) {
+            stopTracingInternal(TraceUtils.getOutputFilename(type));
         }
     }
 
@@ -197,7 +193,8 @@ public class TraceService extends IntentService {
                 .setContentIntent(PendingIntent.getBroadcast(context, 0, stopIntent,
                           PendingIntent.FLAG_IMMUTABLE));
 
-        startForeground(TRACE_NOTIFICATION, notification.build());
+        startForeground(TRACE_NOTIFICATION, notification.build(),
+                FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
 
         if (TraceUtils.traceStart(this, tags, bufferSizeKb, winscopeTracing,
                 appTracing, longTrace, attachToBugreport, maxLongTraceSizeMb,
@@ -240,7 +237,8 @@ public class TraceService extends IntentService {
                 .setContentIntent(PendingIntent.getBroadcast(context, 0, stopIntent,
                           PendingIntent.FLAG_IMMUTABLE));
 
-        startForeground(TRACE_NOTIFICATION, notification.build());
+        startForeground(TRACE_NOTIFICATION, notification.build(),
+                FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
 
         if (TraceUtils.stackSampleStart(attachToBugreport)) {
             stopForeground(Service.STOP_FOREGROUND_DETACH);
@@ -289,7 +287,8 @@ public class TraceService extends IntentService {
                 .setContentIntent(PendingIntent.getBroadcast(context, 0, stopIntent,
                           PendingIntent.FLAG_IMMUTABLE));
 
-        startForeground(TRACE_NOTIFICATION, notification.build());
+        startForeground(TRACE_NOTIFICATION, notification.build(),
+                FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
 
         if (TraceUtils.heapDumpStart(processes, continuousDump, dumpIntervalSeconds,
                 attachToBugreport)) {
@@ -308,7 +307,7 @@ public class TraceService extends IntentService {
                 context.getString(R.string.pref_key_recording_was_stack_samples), false).commit();
     }
 
-    private void stopTracingInternal(String outputFilename, boolean sessionStolen) {
+    private void stopTracingInternal(String outputFilename) {
         Context context = getApplicationContext();
         SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
         NotificationManager notificationManager =
@@ -331,53 +330,17 @@ public class TraceService extends IntentService {
                 break;
         }
         Notification.Builder notification = getTraceurNotification(context.getString(
-                sessionStolen ? R.string.attaching_to_report : savingTextResId),
-                null, Receiver.NOTIFICATION_CHANNEL_OTHER);
+                savingTextResId), null, Receiver.NOTIFICATION_CHANNEL_OTHER);
         notification.setProgress(1, 0, true);
 
-        startForeground(SAVING_TRACE_NOTIFICATION, notification.build());
+        startForeground(SAVING_TRACE_NOTIFICATION, notification.build(),
+                FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
 
         notificationManager.cancel(TRACE_NOTIFICATION);
 
-        if (sessionStolen) {
-            Notification.Builder notificationAttached = getTraceurNotification(
-                    context.getString(R.string.attached_to_report), null,
-                    Receiver.NOTIFICATION_CHANNEL_OTHER);
-            notification.setAutoCancel(true);
-
-            Intent openIntent =
-                    getPackageManager().getLaunchIntentForPackage(BETTERBUG_PACKAGE_NAME);
-            if (openIntent != null) {
-                // Add "Tap to open BetterBug" to notification only if intent is non-null.
-                notificationAttached.setContentText(getString(
-                        R.string.attached_to_report_summary));
-                notificationAttached.setContentIntent(PendingIntent.getActivity(
-                        context, 0, openIntent, PendingIntent.FLAG_ONE_SHOT
-                                | PendingIntent.FLAG_CANCEL_CURRENT
-                                | PendingIntent.FLAG_IMMUTABLE));
-            }
-
-            // Adds an action button to the notification for starting a new trace. This is only
-            // enabled for standard traces.
-            if (type == TraceUtils.RecordingType.TRACE) {
-                Intent restartIntent = new Intent(context, InternalReceiver.class);
-                restartIntent.setAction(InternalReceiver.START_ACTION);
-                PendingIntent restartPendingIntent = PendingIntent.getBroadcast(context, 0,
-                        restartIntent, PendingIntent.FLAG_ONE_SHOT
-                                | PendingIntent.FLAG_CANCEL_CURRENT
-                                | PendingIntent.FLAG_IMMUTABLE);
-                Notification.Action action = new Notification.Action.Builder(
-                        R.drawable.bugfood_icon, context.getString(R.string.start_new_trace),
-                        restartPendingIntent).build();
-                notificationAttached.addAction(action);
-            }
-
-            NotificationManager.from(context).notify(0, notificationAttached.build());
-        } else {
-            Optional<List<File>> files = TraceUtils.traceDump(this, outputFilename);
-            if (files.isPresent()) {
-                postFileSharingNotification(getApplicationContext(), files.get());
-            }
+        Optional<List<File>> files = TraceUtils.traceDump(this, outputFilename);
+        if (files.isPresent()) {
+            postFileSharingNotification(getApplicationContext(), files.get());
         }
 
         stopForeground(Service.STOP_FOREGROUND_REMOVE);
@@ -402,7 +365,7 @@ public class TraceService extends IntentService {
         // the above file-sharing intent.
         final Intent intent = new Intent(context, UserConsentActivityDialog.class);
         intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_RECEIVER_FOREGROUND);
-        intent.putExtra(Intent.EXTRA_INTENT, sendIntent);
+        intent.putExtra(Intent.EXTRA_INTENT, Intent.createChooser(sendIntent, null));
 
         TraceUtils.RecordingType type = getRecentTraceType(context);
         int titleResId;
@@ -421,10 +384,9 @@ public class TraceService extends IntentService {
         }
         final Notification.Builder builder = getTraceurNotification(context.getString(titleResId),
                 context.getString(R.string.tap_to_share), Receiver.NOTIFICATION_CHANNEL_OTHER)
-                        .setContentIntent(PendingIntent.getActivity(context,
-                                traceUris.get(0).hashCode(), intent,PendingIntent.FLAG_ONE_SHOT
-                                        | PendingIntent.FLAG_CANCEL_CURRENT
-                                        | PendingIntent.FLAG_IMMUTABLE))
+                        .setContentIntent(PendingIntent.getActivity(
+                                context, traceUris.get(0).hashCode(), intent,
+                                PendingIntent.FLAG_CANCEL_CURRENT | PendingIntent.FLAG_IMMUTABLE))
                         .setAutoCancel(true);
         NotificationManager.from(context).notify(files.get(0).getName(), 0, builder.build());
     }
diff --git a/src_common/com/android/traceur/MessageConstants.java b/src_common/com/android/traceur/MessageConstants.java
index 80f96bb9..1b0b882a 100644
--- a/src_common/com/android/traceur/MessageConstants.java
+++ b/src_common/com/android/traceur/MessageConstants.java
@@ -21,6 +21,7 @@ public final class MessageConstants {
     public static final int START_WHAT = 0;
     public static final int STOP_WHAT = 1;
     public static final int SHARE_WHAT = 2;
+    public static final int TAGS_WHAT = 3;
 
     // Package / Service names so Traceur and SystemUI can interact with each other
     // and grant URI permissions accordingly
@@ -36,4 +37,11 @@ public final class MessageConstants {
     // Trace type is used during trace start to tell Traceur which type of trace the user has
     // selected (battery, performance, ui, thermal, etc.)
     public static final String INTENT_EXTRA_TRACE_TYPE = TRACING_APP_PACKAGE_NAME + ".trace_type";
+
+    // Available tags are only retrievable via Traceur due to SELinux constraints. These are the
+    // Bundle data keys used to pass the data from Traceur to System UI
+    public static final String BUNDLE_KEY_TAGS = TRACING_APP_PACKAGE_NAME
+        + ".tags";
+    public static final String BUNDLE_KEY_TAG_DESCRIPTIONS = TRACING_APP_PACKAGE_NAME
+        + ".tag_descriptions";
 }
diff --git a/src_common/com/android/traceur/PerfettoUtils.java b/src_common/com/android/traceur/PerfettoUtils.java
index 2dc78ebf..4124c772 100644
--- a/src_common/com/android/traceur/PerfettoUtils.java
+++ b/src_common/com/android/traceur/PerfettoUtils.java
@@ -77,6 +77,7 @@ public class PerfettoUtils {
     private static final String SYS_STATS_TAG = "sys_stats";
     private static final String LOG_TAG = "logs";
     private static final String CPU_TAG = "cpu";
+    public static final String WINDOW_MANAGER_TAG = "wm";
 
     public String getName() {
         return NAME;
@@ -130,12 +131,28 @@ public class PerfettoUtils {
         appendTraceBuffer(config, targetBuffer1Kb);
 
         appendFtraceConfig(config, tags, apps);
+
+        appendSystemPropertyConfig(config, tags);
         appendProcStatsConfig(config, tags, /* targetBuffer = */ 1);
         appendAdditionalDataSources(config, tags, winscope, longTrace, /* targetBuffer = */ 1);
 
         return startPerfettoWithTextConfig(config.toString());
     }
 
+    private void appendSystemPropertyConfig(StringBuilder config, Collection<String> tags) {
+        if (tags.contains(WINDOW_MANAGER_TAG)) {
+            config.append("data_sources: {\n")
+                    .append("  config { \n")
+                    .append("    name: \"android.system_property\"\n")
+                    .append("    target_buffer: 0\n")
+                    .append("    android_system_property_config {\n")
+                    .append("      property_name: \"debug.tracing.desktop_mode_visible_tasks\"\n")
+                    .append("    }\n")
+                    .append("  }\n")
+                    .append("}\n");
+        }
+    }
+
     public boolean stackSampleStart(boolean attachToBugreport) {
         if (isTracingOn()) {
             Log.e(TAG, "Attemping to start stack sampling but perfetto is already active");
@@ -449,7 +466,7 @@ public class PerfettoUtils {
 
         // These parameters affect only the kernel trace buffer size and how
         // frequently it gets moved into the userspace buffer defined above.
-        config.append("      buffer_size_kb: 8192\n")
+        config.append("      buffer_size_kb: 16384\n")
             .append("    }\n")
             .append("  }\n")
             .append("}\n")
@@ -663,8 +680,6 @@ public class PerfettoUtils {
                 .append("      mode: MODE_ACTIVE\n")
                 .append("      trace_flags: TRACE_FLAG_INPUT\n")
                 .append("      trace_flags: TRACE_FLAG_COMPOSITION\n")
-                .append("      trace_flags: TRACE_FLAG_HWC\n")
-                .append("      trace_flags: TRACE_FLAG_BUFFERS\n")
                 .append("      trace_flags: TRACE_FLAG_VIRTUAL_DISPLAYS\n")
                 .append("    }\n")
                 .append("  }\n")
@@ -703,6 +718,40 @@ public class PerfettoUtils {
                 .append("    target_buffer: " + targetBuffer + "\n")
                 .append("  }\n")
                 .append("}\n");
+
+            config.append("data_sources: {\n")
+                .append("  config {\n")
+                .append("    name: \"android.windowmanager\"\n")
+                .append("    target_buffer: " + targetBuffer + "\n")
+                .append("  }\n")
+                .append("}\n");
+
+            config.append("data_sources {\n")
+                .append("  config {\n")
+                .append("    name: \"android.input.inputevent\"\n")
+                .append("    target_buffer: 1\n")
+                .append("    android_input_event_config {\n")
+                .append("      mode: TRACE_MODE_USE_RULES\n")
+                .append("      rules {\n")
+                .append("        trace_level: TRACE_LEVEL_NONE\n")
+                .append("        match_secure: true\n")
+                .append("      }\n")
+                .append("      rules {\n")
+                .append("        trace_level: TRACE_LEVEL_COMPLETE\n")
+                .append("        match_all_packages: \"com.android.shell\"\n")
+                .append("        match_all_packages: \"com.android.systemui\"\n")
+                .append("        match_all_packages: \"com.android.launcher3\"\n")
+                .append("        match_all_packages: \"com.android.settings\"\n")
+                .append("        match_ime_connection_active: false\n")
+                .append("      }\n")
+                .append("      rules {\n")
+                .append("        trace_level: TRACE_LEVEL_REDACTED\n")
+                .append("      }\n")
+                .append("      trace_dispatcher_input_events: true\n")
+                .append("      trace_dispatcher_window_dispatch: true\n")
+                .append("    }\n")
+                .append("  }\n")
+                .append("}\n");
         }
     }
 }
diff --git a/src_common/com/android/traceur/PresetTraceConfigs.java b/src_common/com/android/traceur/PresetTraceConfigs.java
index e083db9e..b38b66a4 100644
--- a/src_common/com/android/traceur/PresetTraceConfigs.java
+++ b/src_common/com/android/traceur/PresetTraceConfigs.java
@@ -53,44 +53,44 @@ public class PresetTraceConfigs {
     private static Set<String> mThermalTagList = null;
     private static Set<String> mUiTagList = null;
 
-    public static Set<String> getDefaultTags() {
+    public static TraceConfig getDefaultConfig() {
         if (mDefaultTagList == null) {
-            mDefaultTagList = new ArraySet<String>(DEFAULT_TRACE_TAGS);
+            mDefaultTagList = new ArraySet<>(DEFAULT_TRACE_TAGS);
             updateTagsIfUserBuild(mDefaultTagList);
         }
-        return mDefaultTagList;
+        return new TraceConfig(DEFAULT_TRACE_OPTIONS, mDefaultTagList);
     }
 
-    public static Set<String> getPerformanceTags() {
+    public static TraceConfig getPerformanceConfig() {
         if (mPerformanceTagList == null) {
-            mPerformanceTagList = new ArraySet<String>(PERFORMANCE_TRACE_TAGS);
+            mPerformanceTagList = new ArraySet<>(PERFORMANCE_TRACE_TAGS);
             updateTagsIfUserBuild(mPerformanceTagList);
         }
-        return mPerformanceTagList;
+        return new TraceConfig(PERFORMANCE_TRACE_OPTIONS, mPerformanceTagList);
     }
 
-    public static Set<String> getBatteryTags() {
+    public static TraceConfig getBatteryConfig() {
         if (mBatteryTagList == null) {
-            mBatteryTagList = new ArraySet<String>(BATTERY_TRACE_TAGS);
+            mBatteryTagList = new ArraySet<>(BATTERY_TRACE_TAGS);
             updateTagsIfUserBuild(mBatteryTagList);
         }
-        return mBatteryTagList;
+        return new TraceConfig(BATTERY_TRACE_OPTIONS, mBatteryTagList);
     }
 
-    public static Set<String> getThermalTags() {
+    public static TraceConfig getThermalConfig() {
         if (mThermalTagList == null) {
-            mThermalTagList = new ArraySet<String>(THERMAL_TRACE_TAGS);
+            mThermalTagList = new ArraySet<>(THERMAL_TRACE_TAGS);
             updateTagsIfUserBuild(mThermalTagList);
         }
-        return mThermalTagList;
+        return new TraceConfig(THERMAL_TRACE_OPTIONS, mThermalTagList);
     }
 
-    public static Set<String> getUiTags() {
+    public static TraceConfig getUiConfig() {
         if (mUiTagList == null) {
-            mUiTagList = new ArraySet<String>(UI_TRACE_TAGS);
+            mUiTagList = new ArraySet<>(UI_TRACE_TAGS);
             updateTagsIfUserBuild(mUiTagList);
         }
-        return mUiTagList;
+        return new TraceConfig(UI_TRACE_OPTIONS, mUiTagList);
     }
 
     private static void updateTagsIfUserBuild(Collection<String> tags) {
@@ -99,16 +99,16 @@ public class PresetTraceConfigs {
         }
     }
 
-    static class TraceOptions {
-        final int bufferSizeKb;
-        final boolean winscope;
-        final boolean apps;
-        final boolean longTrace;
-        final boolean attachToBugreport;
-        final int maxLongTraceSizeMb;
-        final int maxLongTraceDurationMinutes;
+    public static class TraceOptions {
+        public final int bufferSizeKb;
+        public final boolean winscope;
+        public final boolean apps;
+        public final boolean longTrace;
+        public final boolean attachToBugreport;
+        public final int maxLongTraceSizeMb;
+        public final int maxLongTraceDurationMinutes;
 
-        TraceOptions(int bufferSizeKb, boolean winscope, boolean apps, boolean longTrace,
+        public TraceOptions(int bufferSizeKb, boolean winscope, boolean apps, boolean longTrace,
                 boolean attachToBugreport, int maxLongTraceSizeMb,
                 int maxLongTraceDurationMinutes) {
             this.bufferSizeKb = bufferSizeKb;
@@ -170,25 +170,4 @@ public class PresetTraceConfigs {
                     /* attachToBugreport */ true,
                     DEFAULT_MAX_LONG_TRACE_SIZE_MB,
                     DEFAULT_MAX_LONG_TRACE_DURATION_MINUTES);
-
-    public static TraceOptions getDefaultOptions() {
-        return DEFAULT_TRACE_OPTIONS;
-    }
-
-    public static TraceOptions getPerformanceOptions() {
-        return PERFORMANCE_TRACE_OPTIONS;
-    }
-
-    public static TraceOptions getBatteryOptions() {
-        return BATTERY_TRACE_OPTIONS;
-    }
-
-    public static TraceOptions getThermalOptions() {
-        return THERMAL_TRACE_OPTIONS;
-    }
-
-    public static TraceOptions getUiOptions() {
-        return UI_TRACE_OPTIONS;
-    }
-
 }
diff --git a/src_common/com/android/traceur/TraceConfig.java b/src_common/com/android/traceur/TraceConfig.java
new file mode 100644
index 00000000..c7534866
--- /dev/null
+++ b/src_common/com/android/traceur/TraceConfig.java
@@ -0,0 +1,184 @@
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
+package com.android.traceur;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+
+import java.util.Set;
+
+public class TraceConfig implements Parcelable {
+
+    private final int bufferSizeKb;
+    private final boolean winscope;
+    private final boolean apps;
+    private final boolean longTrace;
+    private final boolean attachToBugreport;
+    private final int maxLongTraceSizeMb;
+    private final int maxLongTraceDurationMinutes;
+    private final Set<String> tags;
+
+    public TraceConfig(int bufferSizeKb, boolean winscope, boolean apps, boolean longTrace,
+            boolean attachToBugreport, int maxLongTraceSizeMb, int maxLongTraceDurationMinutes,
+            Set<String> tags) {
+        this.bufferSizeKb = bufferSizeKb;
+        this.winscope = winscope;
+        this.apps = apps;
+        this.longTrace = longTrace;
+        this.attachToBugreport = attachToBugreport;
+        this.maxLongTraceSizeMb = maxLongTraceSizeMb;
+        this.maxLongTraceDurationMinutes = maxLongTraceDurationMinutes;
+        this.tags = tags;
+    }
+
+    public TraceConfig(PresetTraceConfigs.TraceOptions options, Set<String> tags) {
+        this(
+            options.bufferSizeKb,
+            options.winscope,
+            options.apps,
+            options.longTrace,
+            options.attachToBugreport,
+            options.maxLongTraceSizeMb,
+            options.maxLongTraceDurationMinutes,
+            tags
+        );
+    }
+
+    public PresetTraceConfigs.TraceOptions getOptions() {
+        return new PresetTraceConfigs.TraceOptions(
+            bufferSizeKb,
+            winscope,
+            apps,
+            longTrace,
+            attachToBugreport,
+            maxLongTraceSizeMb,
+            maxLongTraceDurationMinutes
+        );
+    }
+
+    public int getBufferSizeKb() {
+        return bufferSizeKb;
+    }
+
+    public boolean getWinscope() {
+        return winscope;
+    }
+
+    public boolean getApps() {
+        return apps;
+    }
+
+    public boolean getLongTrace() {
+        return longTrace;
+    }
+
+    public boolean getAttachToBugreport() {
+        return attachToBugreport;
+    }
+
+    public int getMaxLongTraceSizeMb() {
+        return maxLongTraceSizeMb;
+    }
+
+    public int getMaxLongTraceDurationMinutes() {
+        return maxLongTraceDurationMinutes;
+    }
+
+    public Set<String> getTags() {
+        return tags;
+    }
+
+    @Override
+    public int describeContents() {
+        return 0;
+    }
+
+    @Override
+    public void writeToParcel(Parcel parcel, int i) {
+        parcel.writeInt(bufferSizeKb);
+        parcel.writeBoolean(winscope);
+        parcel.writeBoolean(apps);
+        parcel.writeBoolean(longTrace);
+        parcel.writeBoolean(attachToBugreport);
+        parcel.writeInt(maxLongTraceSizeMb);
+        parcel.writeInt(maxLongTraceDurationMinutes);
+        parcel.writeStringArray(tags.toArray(String[]::new));
+    }
+
+    public static Parcelable.Creator<TraceConfig> CREATOR = new Creator<>() {
+        @Override
+        public TraceConfig createFromParcel(Parcel parcel) {
+            return new TraceConfig(
+                parcel.readInt(),
+                parcel.readBoolean(),
+                parcel.readBoolean(),
+                parcel.readBoolean(),
+                parcel.readBoolean(),
+                parcel.readInt(),
+                parcel.readInt(),
+                Set.of(parcel.readStringArray())
+            );
+        }
+
+        @Override
+        public TraceConfig[] newArray(int i) {
+            return new TraceConfig[i];
+        }
+    };
+
+    public static class Builder {
+        public int bufferSizeKb;
+        public boolean winscope;
+        public boolean apps;
+        public boolean longTrace;
+        public boolean attachToBugreport;
+        public int maxLongTraceSizeMb;
+        public int maxLongTraceDurationMinutes;
+        public Set<String> tags;
+
+        public Builder(TraceConfig traceConfig) {
+            this(
+                traceConfig.getBufferSizeKb(),
+                traceConfig.getWinscope(),
+                traceConfig.getApps(),
+                traceConfig.getLongTrace(),
+                traceConfig.getAttachToBugreport(),
+                traceConfig.getMaxLongTraceSizeMb(),
+                traceConfig.getMaxLongTraceDurationMinutes(),
+                traceConfig.getTags()
+            );
+        }
+
+        private Builder(int bufferSizeKb, boolean winscope, boolean apps, boolean longTrace,
+                boolean attachToBugreport, int maxLongTraceSizeMb, int maxLongTraceDurationMinutes,
+                Set<String> tags) {
+            this.bufferSizeKb = bufferSizeKb;
+            this.winscope = winscope;
+            this.apps = apps;
+            this.longTrace = longTrace;
+            this.attachToBugreport = attachToBugreport;
+            this.maxLongTraceSizeMb = maxLongTraceSizeMb;
+            this.maxLongTraceDurationMinutes = maxLongTraceDurationMinutes;
+            this.tags = tags;
+        }
+
+        public TraceConfig build() {
+            return new TraceConfig(bufferSizeKb, winscope, apps, longTrace, attachToBugreport,
+                    maxLongTraceSizeMb, maxLongTraceDurationMinutes, tags);
+        }
+    }
+}
diff --git a/src_common/com/android/traceur/TraceUtils.java b/src_common/com/android/traceur/TraceUtils.java
index 739d7677..5faed9d8 100644
--- a/src_common/com/android/traceur/TraceUtils.java
+++ b/src_common/com/android/traceur/TraceUtils.java
@@ -17,7 +17,6 @@
 package com.android.traceur;
 
 import android.app.ActivityManager;
-import android.content.ContentResolver;
 import android.content.Context;
 import android.os.Build;
 import android.os.FileUtils;
@@ -47,8 +46,6 @@ import java.util.concurrent.FutureTask;
 import java.util.concurrent.TimeUnit;
 import java.util.stream.Collectors;
 
-import perfetto.protos.TraceConfigOuterClass.TraceConfig;
-
 /**
  * Utility functions for tracing.
  */
@@ -72,50 +69,18 @@ public class TraceUtils {
         UNKNOWN, TRACE, STACK_SAMPLES, HEAP_DUMP
     }
 
-    public enum PresetTraceType {
-        UNSET, PERFORMANCE, BATTERY, THERMAL, UI
-    }
-
-    public static boolean presetTraceStart(Context context, PresetTraceType type) {
-        Set<String> tags;
-        PresetTraceConfigs.TraceOptions options;
-        Log.v(TAG, "Using preset of type " + type.toString());
-        switch (type) {
-            case PERFORMANCE:
-                tags = PresetTraceConfigs.getPerformanceTags();
-                options = PresetTraceConfigs.getPerformanceOptions();
-                break;
-            case BATTERY:
-                tags = PresetTraceConfigs.getBatteryTags();
-                options = PresetTraceConfigs.getBatteryOptions();
-                break;
-            case THERMAL:
-                tags = PresetTraceConfigs.getThermalTags();
-                options = PresetTraceConfigs.getThermalOptions();
-                break;
-            case UI:
-                tags = PresetTraceConfigs.getUiTags();
-                options = PresetTraceConfigs.getUiOptions();
-                break;
-            case UNSET:
-            default:
-                tags = PresetTraceConfigs.getDefaultTags();
-                options = PresetTraceConfigs.getDefaultOptions();
-        }
-        return traceStart(context, tags, options.bufferSizeKb, options.winscope,
-            options.apps, /* options.longTrace --> b/343538743 */ false, options.attachToBugreport,
-            options.maxLongTraceSizeMb, options.maxLongTraceDurationMinutes);
-    }
-
-    public static boolean traceStart(Context context, TraceConfig config, boolean winscope) {
-        // 'winscope' isn't passed to traceStart because the TraceConfig should specify any
-        // winscope-related data sources to be recorded using Perfetto. Winscope data that isn't yet
-        // available in Perfetto is captured using WinscopeUtils instead.
-        if (!mTraceEngine.traceStart(config)) {
-            return false;
-        }
-        WinscopeUtils.traceStart(context, winscope);
-        return true;
+    public static boolean traceStart(Context context, TraceConfig config) {
+        return traceStart(
+            context,
+            config.getTags(),
+            config.getBufferSizeKb(),
+            config.getWinscope(),
+            config.getApps(),
+            config.getLongTrace(),
+            config.getAttachToBugreport(),
+            config.getMaxLongTraceSizeMb(),
+            config.getMaxLongTraceDurationMinutes()
+        );
     }
 
     public static boolean traceStart(Context context, Collection<String> tags,
```

