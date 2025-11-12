```diff
diff --git a/Android.bp b/Android.bp
index 0a1a478d..a65cc532 100644
--- a/Android.bp
+++ b/Android.bp
@@ -30,6 +30,7 @@ android_library {
         "androidx.appcompat_appcompat",
         "androidx.legacy_legacy-support-v4",
         "perfetto_config_java_protos",
+        "traceur-flags-aconfig-java-lib",
     ],
     manifest: "AndroidManifest-common.xml",
     resource_dirs: [],
@@ -49,3 +50,17 @@ android_library {
     resource_dirs: ["res"],
     srcs: [],
 }
+
+aconfig_declarations {
+    name: "traceur-flags-aconfig",
+    package: "com.android.traceur.flags",
+    container: "system",
+    srcs: [
+        "flags.aconfig",
+    ],
+}
+
+java_aconfig_library {
+    name: "traceur-flags-aconfig-java-lib",
+    aconfig_declarations: "traceur-flags-aconfig",
+}
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 19619601..460d9d76 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -63,6 +63,9 @@
     <!-- Used to get a list of apps for heap dumps. -->
     <uses-permission android:name="android.permission.REAL_GET_TASKS" />
 
+    <!-- Used to run AM heap dump. -->
+    <uses-permission android:name="android.permission.SET_ACTIVITY_WATCHER" />
+
     <!-- Declare Android TV support. -->
     <uses-feature android:name="android.software.leanback"
          android:required="false"/>
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
deleted file mode 100644
index 0ffa6515..00000000
--- a/PREUPLOAD.cfg
+++ /dev/null
@@ -1,2 +0,0 @@
-[Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} ${PREUPLOAD_FILES}
diff --git a/flags.aconfig b/flags.aconfig
new file mode 100644
index 00000000..3c980338
--- /dev/null
+++ b/flags.aconfig
@@ -0,0 +1,9 @@
+package: "com.android.traceur.flags"
+container: "system"
+
+flag {
+    name: "bitmaps_in_traceur"
+    namespace: "system_performance"
+    description: "Enables heap dump collection and bitmap extraction"
+    bug: "412425223"
+}
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 197f3e3b..32ec1411 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Neem hoopstorting op"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Dit vang ’n hoopstorting vas van die prosesse wat in \"Hoopstortingprosesse\" gekies is"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Kies minstens een proses in die \"Hoopstortingprosesse\" om hoopstortings te versamel"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Neem AM-hoopstorting met bitmaps op"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Versamel ’n hoopstorting van die proses wat in “Hoopstortingprosesse” gekies is en onttrek bitmap-prente"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Kies slegs een proses in “Hoopstortingprosesse”"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Kies ’n proses in “Hoopstortingprosesse”"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Samel Winscope-spore in"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Sluit gedetailleerde UI-telemetriedata in (kan oponthoud veroorsaak)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Spoor ontfoutbare programme na"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Verstek"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# gekies}other{# gekies}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Hoopstortingprosesse"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Minstens een proses moet gekies word"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Hierdie keuses is op beide Perfetto en ActivityManager van toepassing"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Vee hoopstortingprosesse uit"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Proseslys is uitgevee"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Deurlopende hoopprofiel"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Vang ’n hoopstorting vas een keer per gespesifiseerde interval"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Vang ’n hoopstorting vas een keer per gespesifiseerde interval. Slegs van toepassing op Perfetto-hoopstortings."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Hoopstortinginterval"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekondes"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekondes"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Tik om stapelvoorbeeldneming te stop"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Hoopstorting word opgeneem"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Tik om hoopstorting te stop"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM-hoopstorting word opgeneem"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Vee gestoorde lêers uit"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Opnames word ná een maand uitgevee"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Vee gestoorde lêers uit?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Alle opnames in /data/local/traces sal uitgevee word"</string>
     <string name="clear" msgid="5484761795406948056">"Vee uit"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Stelselspore"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, spoor na, werkverrigting"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, spoor na, nasporing, prestasie, profiel, profielbepaling, cpu, callstack, stapel, hoop"</string>
     <string name="share_file" msgid="1982029143280382271">"Deel lêer?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Stelselnasporinglêers kan sensitiewe stelsel- en programdata (soos programgebruik) insluit. Deel stelselspore net met mense en programme wat jy vertrou."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Stelselnasporinglêers kan sensitiewe stelsel- en appdata (soos appgebruik of prente in ’n app se geheue) insluit. Deel stelselnasporings of hoopstortings slegs met mense en apps wat jy vertrou."</string>
     <string name="share" msgid="8443979083706282338">"Deel"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Moenie weer wys nie"</string>
     <string name="long_traces" msgid="5110949471775966329">"Lang spore"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Heg opnames by foutverslae aan"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Stuur opnames wat besig is outomaties na BetterBug toe wanneer ’n foutverslag opgehaal word. Opnames sal daarna voortgesit word."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Bekyk gestoorde lêers"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Spore kan na ui.perfetto.dev toe opgelaai word vir analise"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Hoopstortings kan met AHAT ondersoek word"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Nasporinginstellings"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Gestoorde lêers"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Diverse"</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index 938dbde3..93c22756 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"የቆሻሻ ቁልል ይቅዱ"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"በ«የቆሻሻ ቁልል ሂደቶች» ውስጥ የተመረጡትን ሂደቶች የቆሻሻ ቁልልን ይቀርጻል"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"የቆሻሻ ቁልሎችን ለመሰብሰብ በ«የቆሻሻ ቁልል ሂደቶች» ውስጥ ቢያንስ አንድ ሂደት ይምረጡ"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"AM የቆሻሻ ቁልል በbitmaps ይቅዱ"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"«የቆሻሻ ቁልል ሂደቶች» ውስጥ አንድ የተመረጠው ሂደት የቆሻሻ ቁልል ይሰበስባል እና bitmap ምስሎችን ያወጣል"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"«የቆሻሻ ቁልል ሂደቶች» ውስጥ አንድ ሂደት ብቻ ይምረጡ"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"«የቆሻሻ ቁልል ሂደቶች» ውስጥ አንድ ሂደት ይምረጡ"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope መከታተያን ስብስብ"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"የዩአይ ቴሌሜትሪ ውሂብ ዝርዝር ያካትታል (Jank ያስከትላል)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ሊታረሙ የሚችሉ መተግበሪያዎችን ዱካ ይከታተሉ"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ነባሪ"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# ተመርጧል}one{# ተመርጧል}other{# ተመርጠዋል}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"የቆሻሻ ቁልል ሂደቶች"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"ቢያንስ አንድ ሂደት መመረጥ አለበት"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"እነዚህ ምርጫዎች በሁለቱም Perfetto እና ActivityManager ላይ ይተገበራሉ"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"የቆሻሻ ቁልል ሂደቶችን አጽዳ"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"የሂደት ዝርዝር ጸድቷል"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"ቀጣይነት ያለው የቁልል መገለጫ"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"በተጠቀሰው ጊዜ ውስጥ አንድ ጊዜ የቆሻሻ ቁልል ይቅረጹ"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"በተጠቀሰው ጊዜ ውስጥ አንድ ጊዜ የቆሻሻ ቁልል ይቅረጹ። Perfetto የቆሻሻ ቁልል ላይ ብቻ ይተገበራል።"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"የቆሻሻ ቁልል ክፍተት"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 ሰከንዶች"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 ሰከንዶች"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"የቁልሎች ናሙና መውሰድን ለማስቆም መታ ያድርጉ"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"የቆሻሻ ቁልል እየተቀዳ ነው"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"የቆሻሻ ቁልል ለማቆም መታ ያድርጉ"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM የቆሻሻ ቁልል እየተቀዳ ነው"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"የተቀመጡ ፋይሎችን አጽዳ"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ቀረጻዎች ከአንድ ወር በኋላ ይጸዳሉ"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"የተቀመጡ ፋይሎች ይጸዱ?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"ሁሉም ቀረጻዎች ከ/data/local/traces ይሰረዛሉ"</string>
     <string name="clear" msgid="5484761795406948056">"አጽዳ"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"የስርዓት ዱካዎች"</string>
-    <string name="keywords" msgid="736547007949049535">"የሥርዓት ክትትል፣ ክትትል፣ አፈጻጸም"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace፣ traceur፣ perfetto፣ winscope፣ መከታተያ፣ በመከታተል ላይ፣ አፈጻጸም፣ መገለጫ፣ መገለጫ መስጠት፣ ሲፒዩ፣ የጥሪ ቁልል፣ ቁልል፣ ክምር"</string>
     <string name="share_file" msgid="1982029143280382271">"ፋይል ይጋራ?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"የሥርዓት ዱካ መከታተያ ፋይሎች አደጋን ሊያስከትሉ የሚችሉ የሥርዓት እና የመተግበሪያ ውሂብ (እንደ የመተግበሪያ አጠቃቀም) ያለ ሊያካትት ይችላል። ከሚያምኗቸው ሰዎች ጋር ብቻ የሥርዓት ዱካ መከታተያዎችን ያጋሩ።"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"ሥርዓት መከታተያ ፋይሎች ልዩ ጥንቃቄ የሚያስፈልገው የሥርዓት እና የመተግበሪያ ውሂብ ሊያካትቱ ይችላሉ (የመተግበሪያ አጠቃቀም ወይም በመተግበሪያ ማህደረ ትውስታ ውስጥ እንዳሉ ምስሎች ዓይነት)። የሥርዓት መከታተያዎችን ወይም የቆሻሻ ቁልሎችን ከሚያምኗቸው ሰዎች እና መተግበሪያዎች ጋር ብቻ ያጋሩ።"</string>
     <string name="share" msgid="8443979083706282338">"አጋራ"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"ዳግም አታሳይ"</string>
     <string name="long_traces" msgid="5110949471775966329">"ረጅን ዱካዎች"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ቀረጻዎችን ወደ ሳንካ ሪፖርቶች አባሪ ያድርጉ"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"የሳንካ ሪፖርት በሚሰበሰብበት ጊዜ በሂደት ላይ ያሉ ቀረጻዎችን በራስ-ሰር ወደ BetterBug ይላኩ። ከዚያ በኋላ ቀረጻዎች ይቀጥላሉ።"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"የተቀመጡ ፋይሎችን አሳይ"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"መከታተያዎች ለትንታኔ ወደ ui.perfetto.dev ሊሰቀሉ ይችላሉ"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"የቆሻሻ ቁልሎች በAHAT ሊመረመሩ ይችላሉ"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ቅንብሮችን ይከታተሉ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"የተቀመጡ ፋይሎች"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"የተለያዩ"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index f233cd60..abfaab42 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -3,15 +3,19 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="system_tracing" msgid="4719188511746319848">"تتبّع النظام"</string>
     <string name="record_system_activity" msgid="4339462312915377825">"تسجيل نشاط النظام وتحليله لاحقًا لتحسين الأداء"</string>
-    <string name="record_trace" msgid="6416875085186661845">"تسجيل آثار الأنشطة"</string>
-    <string name="record_trace_summary" msgid="6705357754827849292">"تسجيل تتبُّع النظام باستخدام مجموعة الإعدادات في \"إعدادات التتبُّع\""</string>
+    <string name="record_trace" msgid="6416875085186661845">"تسجيل عمليات تتبّع الأنشطة"</string>
+    <string name="record_trace_summary" msgid="6705357754827849292">"يتم تسجيل عمليات تتبُّع النظام باستخدام مجموعة الإعدادات في \"إعدادات التتبُّع\""</string>
     <string name="record_stack_samples" msgid="3498368637185702335">"‏تسجيل محلّل وحدة المعالجة المركزية (CPU)"</string>
     <string name="record_stack_samples_summary" msgid="7827953921526410478">"‏يمكن أيضًا تفعيل جمع عيّنات تكدس الاستدعاءات في أنشطة التتبُّع عن طريق وضع علامة في مربّع فئة \"cpu\"."</string>
     <string name="record_heap_dump" msgid="1688550222066812696">"تسجيل لقطة لأجزاء من الذاكرة"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"عند اختيار إحدى \"العمليات الخاصة بلقطات لأجزاء من الذاكرة\"، يتم تسجيل اللقطة الخاصة بها"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"يجب اختيار عملية واحدة على الأقل من \"العمليات الخاصة بلقطات لأجزاء من الذاكرة\" لجمع هذه اللقطات"</string>
-    <string name="winscope_tracing" msgid="5818984791154837458">"‏جمْع آثار أنشطة أداة Winscope"</string>
-    <string name="winscope_tracing_summary" msgid="7040550156722395894">"يتم تضمين بيانات تفصيلية للقياس عن بعد لواجهة المستخدم (يمكن أن يتسبّب ذلك في إيقاف مؤقت لعرض واجهة المستخدم)"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"‏تسجيل لقطة لأجزاء من الذاكرة في AM باستخدام صور نقطية"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"يتم جمع لقطة لأجزاء من الذاكرة للعمليات المحددة في \"العمليات الخاصة بلقطات لأجزاء من الذاكرة\" واستخراج صور نقطية"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"يمكن اختيار عملية واحدة فقط من \"العمليات الخاصة بلقطات لأجزاء من الذاكرة\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"يمكنك اختيار عملية من \"العمليات الخاصة بلقطات لأجزاء من الذاكرة\""</string>
+    <string name="winscope_tracing" msgid="5818984791154837458">"‏جمع عمليات تتبّع أنشطة Winscope"</string>
+    <string name="winscope_tracing_summary" msgid="7040550156722395894">"بما في ذلك بيانات تفصيلية عن قياس واجهة المستخدم عن بعد (قد يؤدي ذلك إلى إيقاف عرض واجهة المستخدم مؤقتًا)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"تتبّع التطبيقات التي يمكن تصحيح الأخطاء بها"</string>
     <string name="categories" msgid="2280163673538611008">"الفئات"</string>
     <string name="restore_default_categories" msgid="5090536794637169521">"استعادة الفئات التلقائية"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"تلقائي"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{تمّ اختيار #.}zero{تمّ اختيار #.}two{تمّ اختيار #.}few{تمّ اختيار #.}many{تمّ اختيار #.}other{تمّ اختيار #.}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"العمليات الخاصة بلقطات لأجزاء من الذاكرة"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"يجب اختيار عملية واحدة على الأقل"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"‏تنطبق هذه الاختيارات على كل من Perfetto وActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"محو العمليات الخاصة بلقطات لأجزاء من الذاكرة"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"تم محو قائمة العمليات"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"لقطة مستمرة لعناصر متعدّدة"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"تسجيل لقطة لأجزاء من الذاكرة مرّة واحدة في كل فاصل محدَّد"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"‏يعمل هذا الإعداد على تسجيل لقطة لأجزاء من الذاكرة مرّة واحدة في كل فاصل محدَّد، وينطبق فقط على لقطات Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"فاصل تسجيل لقطات لأجزاء من الذاكرة"</string>
     <string name="five_seconds" msgid="7018465440929299712">"‫٥ ثوانٍ"</string>
     <string name="ten_seconds" msgid="863416601384309033">"‫١٠ ثوانٍ"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"انقر لإيقاف جمع عيّنات التكدس."</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"جارٍ تسجيل لقطة لأجزاء من الذاكرة"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"انقر لإيقاف تسجيل لقطة لأجزاء من الذاكرة"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"‏جارٍ تسجيل لقطة لأجزاء من الذاكرة في AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"محو الملفات المحفوظة"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"يتم محو التسجيلات بعد شهر واحد."</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"هل تريد محو الملفات المحفوظة؟"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"‏سيتم حذف التسجيلات من /data/local/traces."</string>
     <string name="clear" msgid="5484761795406948056">"محو"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"عمليات تتبُّع النظام"</string>
-    <string name="keywords" msgid="736547007949049535">"‏systrace، التتبّع، الأداء"</string>
+    <string name="keywords" msgid="255681926397897100">"‏‫systrace، ‏traceur، ‏perfetto، ‏winscope، تتبُّع، أداء، الملف الشخصي، تحديد المواصفات الشخصية لصاحب البيانات، وحدة المعالجة المركزية (CPU)، callstack، حزمة، عناصر متعددة"</string>
     <string name="share_file" msgid="1982029143280382271">"هل تريد مشاركة الملف؟"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"قد تشتمل ملفات \"تتبُّع النظام\" على بيانات حساسة عن النظام والتطبيقات (مثل إحصاءات استخدام التطبيقات). يُرجى عدم مشاركة ملفات تتبُّع النظام إلا مع الأشخاص والتطبيقات التي تثق فيها."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"قد تتضمّن ملفات \"تتبّع النظام\" بيانات حساسة للنظام والتطبيقات (مثل بيانات استخدام التطبيق أو الصور في ذاكرة التطبيق). لذا يُرجى عدم مشاركة عمليات تتبّع النظام أو اللقطات لأجزاء من الذاكرة إلا مع الأشخاص والتطبيقات الموثوقة."</string>
     <string name="share" msgid="8443979083706282338">"مشاركة"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"عدم الإظهار مرة أخرى"</string>
     <string name="long_traces" msgid="5110949471775966329">"آثار الأنشطة طويلة المدة"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"إرفاق التسجيلات بتقارير الأخطاء"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"‏يمكنك تلقائيًا إرسال التسجيلات الجاري تسجيلها إلى BetterBug عند جمع تقرير خطأ. بعد ذلك، سيستمر التسجيل."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"عرض الملفات المحفوظة"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"‏يمكن تحميل عمليات التتبّع إلى ui.perfetto.dev لتحليلها"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"‏يمكن فحص اللقطات لأجزاء من الذاكرة باستخدام AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"إعدادات التتبُّع"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"الملفات المحفوظة"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"خيارات متنوعة"</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 52b2d42f..82bdb73a 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"হীপ ডাম্প ৰেকৰ্ড কৰক"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"হীপ ডাম্প প্ৰক্ৰিয়াসমূহ\"ত বাছনি কৰা প্ৰক্ৰিয়াসমূহৰ এটা হিপ ডাম্প কেপচাৰ কৰে"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"হীপ ডাম্প সংগ্ৰহ কৰিবলৈ \"হীপ ডাম্পৰ প্ৰক্ৰিয়াসমূহ\"ত অতি কমেও এটা বাছনি কৰক"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"বিটমেপৰ জৰিয়তে AM হীপ ডাম্প ৰেকৰ্ড কৰক"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"হীপ ডাম্পৰ প্ৰক্ৰিয়াসমূহ\"ত বাছনি কৰা প্ৰক্ৰিয়াটোৰ এটা হীপ ডাম্প সংগ্ৰহ কৰে আৰু বিটমেপৰ প্ৰতিচ্ছবি আহৰণ কৰে"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"হীপ ডাম্পৰ প্ৰক্ৰিয়াসমূহ\"ত কেৱল এটা প্ৰক্ৰিয়া বাছনি কৰক"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"হীপ ডাম্পৰ প্ৰক্ৰিয়াসমূহ\"ত এটা প্ৰক্ৰিয়া বাছনি কৰক"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscopeৰ ট্ৰে’চ সংগ্ৰহ কৰক"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"বিস্তৃত UIৰ টেলিমেট্ৰী ডেটা অন্তৰ্ভুক্ত কৰে (জাংকৰ সৃষ্টি কৰিব পাৰে)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ডিবাগ কৰিবলগীয়া এপ্লিকেশ্বনসমূহ ট্ৰে\'চ কৰক"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ডিফ’ল্ট"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# টা বাছনি কৰা হৈছে}one{# টা বাছনি কৰা হৈছে}other{# টা বাছনি কৰা হৈছে}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"হীপ ডাম্পৰ প্ৰক্ৰিয়াসমূহ"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"অতি কমেও এটা প্ৰক্ৰিয়া বাছনি কৰিবই লাগিব"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"এই বাছনিসমূহ Perfetto আৰু ActivityManager দুয়োটাতে প্ৰযোজ্য"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"হীপ ডাম্পৰ প্ৰক্ৰিয়াকৰণ মচক"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"প্ৰক্ৰিয়াকৰণৰ সূচী মচা হ’ল"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"অবিৰত হীপ প্ৰ’ফাইল"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"প্ৰতিটো নিৰ্দিষ্ট বিৰতিৰ পাছত এটা হীপ ডাম্প কেচপাৰ কৰক"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"প্ৰতিটো নিৰ্দিষ্ট বিৰতিৰ পাছত এটা হীপ ডাম্প কেচপাৰ কৰক। কেৱল Perfetto হীপ ডাম্পৰ ক্ষেত্ৰত প্ৰযোজ্য।"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"হীপ ডাম্পৰ বিৰতি"</string>
     <string name="five_seconds" msgid="7018465440929299712">"৫ ছেকেণ্ড"</string>
     <string name="ten_seconds" msgid="863416601384309033">"১০ ছেকেণ্ড"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"ষ্টেকৰ ছেম্পলিং বন্ধ কৰিবলৈ টিপক"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"হীপ ডাম্প ৰেকৰ্ড কৰি থকা হৈছে"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"হীপ ডাম্প বন্ধ কৰিবলৈ টিপক"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM হীপ ডাম্প ৰেকৰ্ড কৰি থকা হৈছে"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"ছেভ কৰা ফাইলসমূহ মচক"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"এমাহৰ পাছত ৰেকৰ্ডিংসমূহ মচি পেলোৱা হয়"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"ছেভ কৰা ফাইলসমূহ মচিবনে?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"আটাইবোৰ ৰেকৰ্ডিং /ডেটা/স্থানীয়/ট্ৰে’চৰ পৰা মচা হ’ব"</string>
     <string name="clear" msgid="5484761795406948056">"মচক"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"ছিষ্টেম ট্ৰেচ"</string>
-    <string name="keywords" msgid="736547007949049535">"ছিষ্ট্ৰেচ, ট্ৰেচ, প্ৰদৰ্শন"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ট্ৰে’চ, ট্ৰেকিং, পাৰদৰ্শিতা, প্ৰ’ফাইল, ডেটাৰ প্ৰদৰ্শন মূল্যায়ন কৰা কাৰ্য, cpu, কলষ্টেক, ষ্টেক, হীপ"</string>
     <string name="share_file" msgid="1982029143280382271">"ফাইল শ্বেয়াৰ কৰিবনে?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"ছিষ্টেমে ট্রে\'চ কৰা ফাইলত ছিষ্টেম আৰু এপৰ সংবেদনশীল ডেটা (যেনে- এপে ব্যৱহাৰ কৰা ডেটা) থাকিব পাৰে। আপুনি বিশ্বাস কৰা ব্যক্তি আৰু এপৰ সৈতেহে ছিষ্টেম ট্রে\'চ শ্বেয়াৰ কৰক।"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"ছিষ্টেমে ট্রে’চ কৰা ফাইলত সংবেদনশীল ছিষ্টেম আৰু এপ্ ডেটা (যেনে- এপে ব্যৱহাৰ কৰা ডেটা বা কোনো এপৰ মেম’ৰীত থকা প্ৰতিচ্ছবি) থাকিব পাৰে। কেৱল আপুনি বিশ্বাস কৰা লোক আৰু এপৰ সৈতে ছিষ্টেমৰ ট্ৰে’চ বা হীপ ডাম্প শ্বেয়াৰ কৰক।"</string>
     <string name="share" msgid="8443979083706282338">"শ্বেয়াৰ কৰক"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"পুনৰাই নেদেখুৱাব"</string>
     <string name="long_traces" msgid="5110949471775966329">"দীঘল ট্ৰে\'চ"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"বাগ ৰিপ’ৰ্টত ৰেকৰ্ডিংসমূহ সংলগ্ন কৰক"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"যেতিয়া এটা বাগ ৰিপ’ৰ্ট সংগ্ৰহ কৰা হয়, চলি থকা ৰেকৰ্ডিংসমূহ স্বয়ংক্ৰিয়ভাৱে BetterBugলৈ পঠিয়াওক। তাৰ পাছত ৰেকৰ্ডিং চলি থাকিব।"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"ছেভ কৰা ফাইলসমূহ চাওক"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"ট্ৰে’চসমূহ বিশ্লেষণৰ বাবে ui.perfetto.devত আপল’ড কৰিব পাৰি"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"হীপ ডাম্প AHATৰ জৰিয়তে পৰীক্ষা কৰিব পাৰি"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ট্ৰে’চৰ ছেটিং"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ছেভ কৰি থোৱা ফাইল"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"সানমিহলি"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 6c36b878..89f5aaaa 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Snepşotu qeyd edin"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"Snepşot prosesləri\"ndə seçilmiş proseslərin snepşotunu çəkir"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Snepşotları toplamaq üçün \"Snepşot prosesləri\"ndə ən azı bir proses seçin"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"AM snepşotlarını bitmap ilə qeydə alın"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"Snepşot proseslərində\" seçilmiş prosesin snepşotunu toplayır və bitmap şəkillərini çıxarır"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"Snepşot proseslərində\" yalnız bir proses seçin"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"Snepşot proseslərində\" proses seçin"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope izlərinin toplanması"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Detallı UI telemetriya datası daxildir (ləngiməyə səbəb ola bilər)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Silinə bilən tətbiqləri izləyin"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Defolt"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# kateqoriya seçilib}other{# kateqoriya seçilib}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Snepşot prosesləri"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Ən azı bir proses seçilməlidir"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Bu seçimlər həm Perfetto, həm də ActivityManager üçün tətbiq olunur"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Snepşot proseslərini silin"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Proses siyahısı silindi"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Davam edən qalaq profili"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Müəyyən intervalda bir dəfə snepşot çəkin"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Müəyyən intervalda bir dəfə snepşot çəkin. Sadəcə Perfetto snepşotlarına tətbiq olunur."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Snepşot intervalı"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 saniyə"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 saniyə"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Yığından nümunə götürülməsini dayandırmaq üçün toxunun"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Snepşot qeydə alınır"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Snepşotu dayandırmaq üçün toxunun"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM snepşotu qeydə alınır"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Saxlanmış faylları silin"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Qeydəalmalar bir aydan sonra silinir"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Saxlanmış fayllar silinsin?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Bütün qeydəalmalar /data/local/traces bölməsindən silinəcək"</string>
     <string name="clear" msgid="5484761795406948056">"Silin"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Sistem izləri"</string>
-    <string name="keywords" msgid="736547007949049535">"sistem fəaliyyəti, izləmə, performans"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, iz, izləmək, performans, profil, profilləşdirmə, cpu, sorğu yığını, yığın, toplu"</string>
     <string name="share_file" msgid="1982029143280382271">"Fayl paylaşılsın?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Sistemin Fəaliyyətini İzləyən fayllara mühüm sistem və tətbiq datası (tətbiq istifadəsi kimi) aid edilə bilər. Sistem tarixçəsini yalnız etibar etdiyiniz istifadəçi və tətbiqlərlə paylaşın."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Sistemin Fəaliyyətini İzləyən fayllara mühüm sistem və tətbiq datası (məsələn, tətbiq istifadəsi və ya tətbiqin yaddaşındakı şəkillər) daxil ola bilər. Sistem izlərini və ya snepşotları yalnız etibar etdiyiniz şəxslər və tətbiqlərlə paylaşın."</string>
     <string name="share" msgid="8443979083706282338">"Paylaşın"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Göstərilməsin"</string>
     <string name="long_traces" msgid="5110949471775966329">"Uzun izlər"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Qeydəalmaları baq hesabatlarına əlavə edin"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Baq hesabatı əldə edildikdə davam edən çəkilişləri BetterBug-a avtomatik göndərin. Çəkilişlər bundan sonra davam edəcək."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Saxlanmış fayllara baxın"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Təhlil üçün fəaliyyət izləri ui.perfetto.dev saytına yüklənə bilər"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Snepşotlar AHAT ilə yoxlanıla bilər"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Fəaliyyət izi ayarları"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saxlanmış fayllar"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Müxtəlif"</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 13e72524..9a21cfa8 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Snimaj dinamički deo memorije za proces"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Snima dinamički deo memorije za procese izabrane u delu Procesi za snimanje dinamičkog dela memorije"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Da biste prikupljali snimke dinamičkog dela memorije za procese, izaberite bar jedan proces u delu Procesi za snimanje dinamičkog dela memorije"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Snimi dinamički deo memorije za proces aplikacije AM pomoću bit mapa"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Prikuplja snimak dinamičkog dela memorije za proces izabran u delu Procesi za snimanje dinamičkog dela memorije, pa izdvaja slike bit mapa."</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Izaberite samo jedan proces u delu Procesi za snimanje dinamičkog dela memorije"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Izaberite proces u delu Procesi za snimanje dinamičkog dela memorije"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Prikupljaj Winscope tragove"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Obuhvata detaljne telemetrijske podatke o korisničkom interfejsu (može da izazove seckanje)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Prati aplikacije sa funkcijom za otklanjanje grešaka"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Podrazumevano"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Izabrana je #}one{Izabrana je #}few{Izabrane su #}other{Izabrano je #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Procesi za snimanje dinamičkog dela memorije"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Morate da izaberete bar jedan proces"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Ovi izbori važe za Perfetto i ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Obriši procese izabrane za snimanje dinamičkog dela memorije"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Lista procesa je obrisana"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Neprekidno profilisanje dinamičkog dela memorije"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Snima dinamički deo memorije za proces jednom po navedenom intervalu"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Snima dinamički deo memorije za proces jednom po navedenom intervalu. Važi samo za Perfetto snimke dinamičkog dela memorije za proces."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Interval snimanja dinamičkog dela memorije za proces"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekundi"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekundi"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Dodirnite da biste zaustavili grupno uzorkovanje"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Pravi se snimak dinamičkog dela memorije za proces"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Dodirnite da biste zaustavili snimanje dinamičkog dela memorije za proces"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Pravi se snimak dinamičkog dela memorije za proces aplikacije AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Obriši sačuvane fajlove"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Snimci se brišu posle mesec dana"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Želite da obrišete sačuvane fajlove?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Svi snimci će biti izbrisani sa /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Obriši"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Praćenja sistema"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, praćenje, učinak"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, trag, praćenje, performanse, profil, profilisanje, procesor, grupa poziva, grupa, dinamički deo memorije"</string>
     <string name="share_file" msgid="1982029143280382271">"Želite da delite fajl?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Datoteke praćenja sistema mogu da sadrže osetljive podatke o sistemu i aplikacijama (na primer, o korišćenju aplikacije). Delite praćenja sistema samo sa pouzdanim ljudima i aplikacijama."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Fajlovi praćenja sistema mogu da sadrže osetljive sistemske podatke i podatke aplikacija (kao što su korišćenje aplikacije ili slike u memoriji aplikacije). Praćenja sistema ili snimke dinamičkog dela memorije za proces delite samo sa pouzdanim ljudima i aplikacijama."</string>
     <string name="share" msgid="8443979083706282338">"Deli"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Ne prikazuj ponovo"</string>
     <string name="long_traces" msgid="5110949471775966329">"Dugi tragovi"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Priložite snimke u izveštaje o grešci"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatski šaljite BetterBug-u snimke dok je snimanje u toku kada se prikupi izveštaj o grešci. Snimanje će se zatim nastaviti."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Prikaži sačuvane fajlove"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Praćenja mogu da se otpreme na ui.perfetto.dev radi analize"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Snimak dinamičkog dela memorije za proces može da se pregleda pomoću AHAT-a"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Podešavanja praćenja"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Sačuvani fajlovi"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Razno"</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 88a794ee..55cf804f 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Запісваць дамп дынамічнай памяці"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Будзе стварацца дамп дынамічнай памяці для працэсаў, выбраных у спісе \"Працэсы для дампу дынамічнай памяці\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Каб ствараць дампы дынамічнай памяці, выберыце хаця б адзін працэс у спісе \"Працэсы для дампу дынамічнай памяці\""</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Запісаць дамп дынамічнай памяці з растравымі выявамі з дапамогай AM"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Збірае дамп дынамічнай памяці працэсу, выбранага са спіса \"Працэсы для дампу дынамічнай памяці\", і вымае відарысы растравых выяў"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Выберыце толькі адзін варыянт са спіса \"Працэсы для дампу дынамічнай памяці\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Выберыце варыянт са спіса \"Працэсы для дампу дынамічнай памяці\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Запісваць трасіроўкі Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Уключае падрабязныя тэлеметрычныя даныя пра карыстальніцкі інтэрфейс (можа выклікаць часовае завісанне)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Трасіраваць праграмы з магчымасцю адладкi"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Стандартна"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Вылучана: #}one{Вылучана: #}few{Вылучана: #}many{Вылучана: #}other{Вылучана: #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Працэсы для дампу дынамічнай памяці"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Выберыце як мінімум адзін працэс"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Гэтыя варыянты выбару прымяняюцца да Perfetto і ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Ачысціць працэсы для дампу дынамічнай памяці"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Спіс працэсаў ачышчаны"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Бесперапыннае стварэнне профілю кучы"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Ствараць дамп дынамічнай памяці праз указаны інтэрвал часу"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Ствараць дамп дынамічнай памяці праз указаны інтэрвал часу. Прымяняецца толькі для дампаў Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Інтэрвал стварэння дампу дынамічнай памяці"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 секунд"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 секунд"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Націсніце, каб спыніць запіс стэкаў"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Ідзе запіс дампу дынамічнай памяці"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Націсніце, каб спыніць стварэнне дампу дынамічнай памяці"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Запісваецца дамп дынамічнай памяці з дапамогай праграмы AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Выдаліць захаваныя файлы"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Запісы выдаляюцца праз адзін месяц"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Выдаліць захаваныя файлы?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Усе запісы будуць выдалены з /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Выдаліць"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Трасіроўка сістэмы"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, трасіроўка, прадукцыйнасць"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, трасіроўка, трасіраваць, эфектыўнасць, профіль, прафіліраванне, ЦП, стэк выклікаў, стэк, дынамічная памяць"</string>
     <string name="share_file" msgid="1982029143280382271">"Абагуліць файл?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Файлы трасіроўкі сістэмы могуць утрымліваць канфідэнцыяльныя даныя пра сістэму і праграмы (напрыклад, пра выкарыстанне праграм). Абагульвайце іх толькі з тымі карыстальнікамі і праграмамі, якім давяраеце."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Файлы трасіроўкі сістэмы могуць змяшчаць канфідэнцыяльныя даныя пра сістэму і праграмы (напрыклад, даныя пра выкарыстанне праграм або відарысы ў памяці праграмы). Абагульвайце файлы трасіроўкі сістэмы і дампы дынамічнай памяці толькі з тымі карыстальнікамі і праграмамі, якім давяраеце."</string>
     <string name="share" msgid="8443979083706282338">"Абагуліць"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Больш не паказваць"</string>
     <string name="long_traces" msgid="5110949471775966329">"Доўгія трасіроўкі"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Далучаць запісы да справаздач пра памылкі"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Пры складанні справаздачы пра памылкі аўтаматычна адпраўляць у BetterBug бягучыя даныя Пасля гэтага запіс працягнецца."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Праглядзець захаваныя файлы"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Файлы трасіроўкі можна запампоўваць для аналізу на ui.perfetto.dev"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Дампы дынамічнай памяці можна аналізаваць з дапамогай AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Налады трасіроўкі"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Захаваныя файлы"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Рознае"</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 02521a44..17a6ab70 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Създаване на моментна снимка на паметта"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Създава моментна снимка на паметта за процесите, посочени в „Процеси с моментна снимка на паметта“"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Изберете поне един процес в „Процеси с моментна снимка на паметта“, за да извличате моментни снимки на паметта"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Създаване на моментна снимка на паметта с растерни изображения чрез AM"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Създава моментна снимка на паметта за процеса, избран в „Процеси с моментна снимка на паметта“, и извлича растерни изображения"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Изберете само един процес в „Процеси с моментна снимка на паметта“"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Изберете процес в „Процеси с моментна снимка на паметта“"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Събиране на трасирания в Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Включва подробни телеметрични данни за ПИ (може да доведе до прекъсвания на изобразяването)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Трасиране на приложенията с възможност за отстраняване на грешки"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Стандартни"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Избрахте #}other{Избрахте #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Процеси с моментна снимка на паметта"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Трябва да изберете поне един процес"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Избраните опции важат както за Perfetto, така и за ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Изчистване на процесите с моментна снимка на паметта"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Списъкът с процеси е изчистен"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Непрекъснато създаване на моментни снимки на разпределената памет"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Създаване на моментна снимка на паметта веднъж на определен интервал"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Създаване на моментна снимка на паметта веднъж на определен интервал. Отнася се само за моментни снимки от Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Интервал на създаване на моментни снимки на паметта"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 секунди"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 секунди"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Докоснете за спиране на семплирането на стека"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Създава се моментна снимка на паметта"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Докоснете, за да спрете моментната снимка на паметта"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Създава се моментна снимка на паметта чрез AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Изчистване на запазените файлове"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Записите се изчистват след един месец"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Да се изчистят ли запазените файлове?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Всички записи ще бъдат изтрити от /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Изчистване"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Системни трасирания"</string>
-    <string name="keywords" msgid="736547007949049535">"системно трасиране, трасиране, ефективност"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, трасиране, ефективност, потребителски профил, профилиране, процесор, извиквания на стека, стек, разпределена памет"</string>
     <string name="share_file" msgid="1982029143280382271">"Да се сподели ли файлът?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Файловете за системно трасиране може да включват поверителни данни за системата и приложенията (като например за използването на приложенията). Споделяйте системните трасирания само с хора и приложения, на които имате доверие."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Файловете от System Tracing може да включват поверителни данни за системата и приложенията (като например за използването на приложенията или изображения в паметта им). Споделяйте системните трасирания или моментните снимки на паметта само с хора и приложения, на които имате доверие."</string>
     <string name="share" msgid="8443979083706282338">"Споделяне"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Да не се показва отново"</string>
     <string name="long_traces" msgid="5110949471775966329">"Продължителни трасирания"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Прикачване на записите към сигналите за програмни грешки"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Автоматично изпращане до BetterBug на текущите записи при създаването на сигнал за програмна грешка. Записите ще продължат след това."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Преглед на запазените файлове"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Трасиранията могат да бъдат качени в ui.perfetto.dev за анализ"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Моментните снимки на паметта могат да се преглеждат с AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Настройки за трасирането"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Запазени файлове"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Други"</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 26ef2136..287ec0a2 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -10,8 +10,12 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"হিপ ডাম্প রেকর্ড করুন"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"হিপ ডাম্পের প্রসেসে\" বেছে নেওয়া প্রসেসের হিপ ডাম্প ক্য়াপচার করুন"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"হিপ ডাম্প সংগ্রহ করতে \"হিপ ডাম্পের প্রসেসে\" কমপক্ষে একটি প্রসেস বেছে নিন"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"বিটম্যাপের সাহায্যে AM হিপ ডাম্প রেকর্ড করুন"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"এটি \"হিপ ডাম্প প্রসেসে\" বেছে নেওয়া প্রসেসের হিপ ডাম্প সংগ্রহ করে এবং বিট ম্যাপ ছবি সরায়"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"হিপ ডাম্পের প্রসেসে\" শুধুমাত্র একটি প্রসেস বেছে নিন"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"হিপ ডাম্পের প্রসেসে\" কোনও একটি প্রসেস বেছে নিন"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope-এর ট্রেস সংগ্রহ করুন"</string>
-    <string name="winscope_tracing_summary" msgid="7040550156722395894">"এর মধ্যে UI সম্পর্কিত টেলিমেট্রি ডেটা অন্তর্ভুক্ত (এর জন্য জ্যাঙ্কের সম্ভাবনা আছে)"</string>
+    <string name="winscope_tracing_summary" msgid="7040550156722395894">"এর মধ্যে UI সম্পর্কিত বিস্তারিত টেলিমেট্রি ডেটা অন্তর্ভুক্ত (জ্যাঙ্কের সম্ভাবনা আছে)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ডিবাগযোগ্য অ্যাপ্লিকেশন ট্রেস করুন"</string>
     <string name="categories" msgid="2280163673538611008">"বিভাগ"</string>
     <string name="restore_default_categories" msgid="5090536794637169521">"ডিফল্ট বিভাগগুলিকে ফিরিয়ে আনুন"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ডিফল্ট"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{#টি বেছে নেওয়া হয়েছে}one{#টি বেছে নেওয়া হয়েছে}other{#টি বেছে নেওয়া হয়েছে}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"হিপ ডাম্পের প্রসেস"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"কমপক্ষে একটি প্রসেস বেছে নিতে হবে"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"এইসব বিভাগ Perfetto ও ActivityManager দুটিতেই প্রযোজ্য হয়"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"হিপ ডাম্প প্রসেস মুছে ফেলুন"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"প্রসেস লিস্টের তালিকা মুছে ফেলা হয়েছে"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"হিপ প্রোফাইল চালু রাখুন"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"কোনও বিশেষ ইন্টার্ভেলের জন্য হিপ ডাম্প ক্যাপচার করুন"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"কোনও বিশেষ ইন্টার্ভেলের জন্য হিপ ডাম্প ক্যাপচার করুন। শুধুমাত্র Perfetto হিপ ডাম্পে প্রযোজ্য হয়।"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"হিপ ডাম্প ইন্টার্ভেল"</string>
     <string name="five_seconds" msgid="7018465440929299712">"৫ সেকেন্ড"</string>
     <string name="ten_seconds" msgid="863416601384309033">"১০ সেকেন্ড"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"স্ট্যাক স্যাম্পেলিং বন্ধ করতে ট্যাপ করুন"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"হিপ ডাম্প রেকর্ড করা হচ্ছে"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"হিপ ডাম্প বন্ধ করতে ট্যাপ করুন"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM হিপ ডাম্প রেকর্ড করা হচ্ছে"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"সেভ করা ফাইল মুছুন"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"এক মাস পরে রেকর্ডিং মুছে ফেলা হয়েছে"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"সেভ করা ফাইল মুছবেন?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"সব রেকর্ডিং /data/local/traces থেকে মুছে ফেলা হবে"</string>
     <string name="clear" msgid="5484761795406948056">"মুছুন"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"সিস্টেম ট্রেস"</string>
-    <string name="keywords" msgid="736547007949049535">"সিস্ট্রেস, ট্রেস, পারফরম্যান্স"</string>
+    <string name="keywords" msgid="255681926397897100">"Systrace, Traceur, Perfetto, Winscope, ট্রেস, ট্রেসিং, পারফর্ম্যান্স, প্রোফাইল, প্রোফাইলিং, সিপিইউ, কলস্ট্যাক, স্ট্যাক, হিপ"</string>
     <string name="share_file" msgid="1982029143280382271">"ফাইল শেয়ার করবেন?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"সিস্টেম ট্রেসিং ফাইলে অতি গোপনীয় সিস্টেম এবং অ্যাপ ডেটা থাকতে পারে (যেমন অ্যাপের জন্য ডেটার ব্যবহার)। কেবলমাত্র আপনার বিশ্বস্ত লোকজন এবং অ্যাপের সঙ্গে সিস্টেম ট্রেস শেয়ার করুন।"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"সিস্টেম ট্রেসিং ফাইলে সিস্টেম ও অ্যাপ সম্পর্কিত ডেটা (যেমন অ্যাপের ব্যবহার সম্পর্কিত ডেটা বা অ্যাপের মেমরিতে থাকা ছবি) থাকতে পারে। সিস্টেম ট্রেস করা বা হিপ ডাম্প শুধুমাত্র সেইসব লোকজন ও অ্যাপের সাথে শেয়ার করুন যাদের বিশ্বাস করেন।"</string>
     <string name="share" msgid="8443979083706282338">"শেয়ার করুন"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"আর দেখাবেন না"</string>
     <string name="long_traces" msgid="5110949471775966329">"লম্বা ট্রেস"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"সমস্যা সম্পর্কিত রিপোর্টে রেকর্ডিং অ্যাটাচ করুন"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"সমস্যা সম্পর্কিত রিপোর্ট সংগ্রহ করা হলে, কাজ চলছে এমন রেকর্ডিং সম্পর্কিত তথ্য অটোমেটিক BetterBug-কে পাঠান। রেকর্ডিং পরেও চলতে থাকবে।"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"সেভ করা ফাইল দেখুন"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"বিশ্লেষণের জন্য ui.perfetto.dev-এ ট্রেস আপলোড করা যাবে"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"AHAT-এর সাহায্যে হিপ ডাম্প পরীক্ষা করা যেতে পারে"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"\'ট্রেস\' সেটিংস"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"সেভ করা ফাইল"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"বিবিধ"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 55eee2ba..09b5776f 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Snimi snimak dinamičkog dijela memorije"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Snima snimak dinamičkog dijela memorije procesa odabranih u odjeljku \"Procesi snimka dinamičkog dijela memorije\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Odaberite najmanje jedan proces u odjeljku \"Procesi snimka dinamičkog dijela memorije\" da prikupite snimke dinamičkog dijela memorije"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Pravljenje AM snimka dinamičkog dijela memorije s bitmapama"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Prikuplja snimak dinamičkog dijela memorije procesa koji je odabran u odjeljku \"Procesi snimka dinamičkog dijela memorije\" i izdvaja slike bitmapa"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Odaberite samo jedan proces u odjeljku \"Procesi snimka dinamičkog dijela memorije\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Odaberite proces u odjeljku \"Procesi snimka dinamičkog dijela memorije\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Prikupljaj Winscope tragove"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Uključuje detaljne telemetrijske podatke korisničkog interfejsa (može uzrokovati smetnje)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Prati aplikacije u načinu rada za otklanjanje grešaka"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Zadano"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# odabrana}one{# odabrana}few{# odabrene}other{# odabranih}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Procesi snimka dinamičkog dijela memorije"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Morate odabrati najmanje jedan proces"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Ovi odabiri se primjenjuju na Perfetto i ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Obriši procese snimka dinamičkog dijela memorije"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Obrisana je lista procesa"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Kontinuirani profil dinamičkog dijela memorije"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Snimanje snimka dinamičkog dijela memorije jedanput po određenom intervalu"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Napravite snimak dinamičkog dijela memorije jednom u određenom intervalu. Primjenjuje se samo na Perfetto snimke dinamičkog dijela memorije."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Interval snimka dinamičkog dijela memorije"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekundi"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekundi"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Dodirnite da zaustavite uzorkovanje stogova"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Snima se snimak dinamičkog dijela memorije"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Dodirnite da zaustavite snimak dinamičkog dijela memorije"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM snimak dinamičkog dijela memorije se pravi"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Obriši sačuvane fajlove"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Snimci će se obrisati nakon jednog mjeseca"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Obrisati sačuvane fajlove?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Svi snimci će se izbrisati iz foldera /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Obriši"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Tragovi sistema"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, praćenje, performanse"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, trag, praćenje, performanse, profil, profiliranje, procesor, pozivni stog, grupa, dinamički dio memorije"</string>
     <string name="share_file" msgid="1982029143280382271">"Podijeliti fajl?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Fajlovi praćenja sistema mogu sadržavati osjetljive podatke o sistemu i aplikaciji (kao što je korištenje aplikacije). Praćenje sistema dijelite samo sa osobama i aplikacijama kojima vjerujete."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Fajlovi praćenja sistema mogu sadržavati osjetljive podatke o sistemu i aplikaciji (kao što su korištenje aplikacije ili slike iz memorije aplikacije). Podatke o praćenju sistema ili snimke dinamičkog dijela memorije dijelite samo s osobama i aplikacijama kojima vjerujete."</string>
     <string name="share" msgid="8443979083706282338">"Dijeli"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Ne prikazuj opet"</string>
     <string name="long_traces" msgid="5110949471775966329">"Dugi tragovi"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Priloži snimke izvještajima o greškama"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatski šaljite snimke koji su u toku BetterBugu kada se prikupi izvještaj o grešci. Snimke će se nastaviti nakon toga."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Prikaži sačuvane fajlove"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Tragovi se mogu otpremiti na ui.perfetto.dev radi analize"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Snimci dinamičkog dijela memorije se mogu pregledati koristeći AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Postavke praćenja"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Sačuvani fajlovi"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Razno"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 5c033782..0e4975d3 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Grava l\'abocament de memòria en monticle"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captura un abocament de memòria en monticle dels processos seleccionats a \"Processos d\'abocament de memòria en monticle\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecciona un procés com a mínim a \"Processos d\'abocament de memòria en monticle\" per recollir abocaments de memòria en monticle"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Grava l\'abocament de memòria en monticle d\'AM amb mapes de bits"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Recull un abocament de memòria en monticle del procés seleccionat a \"Processos d\'abocament de memòria en monticle\" i extreu imatges de mapa de bits"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Selecciona només un procés a \"Processos d\'abocament de memòria en monticle\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Selecciona un procés a \"Processos d\'abocament de memòria en monticle\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Recull traces de WinScope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inclou dades detallades de telemetria de la IU (pot produir inestabilitat)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Traça aplicacions que es puguin depurar"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Predeterminat"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# tipus seleccionat}other{# tipus seleccionats}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Processos d\'abocament de memòria en monticle"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Cal seleccionar un procés com a mínim"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Aquestes seleccions s\'apliquen tant a Perfetto com a ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Esborra els processos d\'abocament de memòria en monticle"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"S\'ha esborrat la llista de processos"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Perfil de memòria en monticle continu"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Captura un abocament de memòria en monticle per cada interval especificat"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Captura un abocament de memòria en monticle per cada interval especificat. Només s\'aplica als abocaments de memòria en monticle de Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Interval d\'abocament de memòria en monticle"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 segons"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 segons"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Toca per aturar l\'extracció de mostres de la pila"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"S\'està gravant l\'abocament de memòria en monticle"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Toca per posar en pausa l\'abocament de memòria en monticle"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"S\'està gravant l\'abocament de memòria en monticle d\'AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Esborra els fitxers desats"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Les gravacions s\'esborren al cap d\'un mes"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Vols esborrar els fitxers desats?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Se suprimiran totes les gravacions de /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Esborra"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Traces del sistema"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, traça, rendiment"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, traça, traçar, rendiment, perfil, elaboració de perfils, cpu, extracció de la pila, pila, memòria en monticle"</string>
     <string name="share_file" msgid="1982029143280382271">"Vols compartir el fitxer?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Els fitxers de Traçabilitat del sistema poden incloure dades sensibles del sistema i de les aplicacions (com ara l\'ús de les aplicacions). Comparteix les traces del sistema només amb aplicacions i persones de confiança."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Els fitxers de Traçabilitat del sistema poden incloure dades sensibles del sistema i de les aplicacions (com ara l\'ús de les aplicacions o les imatges de la memòria d\'una aplicació). Comparteix les traces del sistema o els abocaments de memòria en monticle només amb aplicacions i persones de confiança."</string>
     <string name="share" msgid="8443979083706282338">"Comparteix"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"No ho tornis a mostrar"</string>
     <string name="long_traces" msgid="5110949471775966329">"Traces llargues"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Adjunta gravacions als informes d\'errors"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Envia automàticament gravacions en curs a BetterBug quan es reculli un informe d\'errors. Les gravacions continuaran després."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Mostra els fitxers desats"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Les traces es poden penjar a ui.perfetto.dev per analitzar-les"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Els abocaments de memòria en monticle es poden inspeccionar amb AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Configuració de traça"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Fitxers desats"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Miscel·lània"</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index e9c830d0..bdf2ef5d 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Zaznamenat výpis haldy"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Pořídí výpis haldy pro procesy vybrané v sekci Procesy pro výpisy haldy"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Pokud chcete shromažďovat výpisy haldy, vyberte alespoň jeden proces v sekci Procesy pro výpisy haldy"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Zaznamenat výpis haldy aplikace AM s rastrovými obrázky"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Shromáždí výpis haldy procesu vybraného v části Procesy pro výpisy haldy a extrahuje rastrové obrázky"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"V části Procesy pro výpisy haldy vyberte jen jeden proces"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Vyberte proces v části Procesy pro výpisy haldy"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Shromažďovat trasování Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Zahrnuje podrobná telemetrická data uživatelského rozhraní (může vést k zasekávání)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Trasovat aplikace k ladění"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Výchozí"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Je vybrána # kategorie}few{Jsou vybrány # kategorie}many{Je vybráno # kategorie}other{Je vybráno # kategorií}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Procesy pro výpisy haldy"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Je potřeba vybrat alespoň jeden proces"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Tento výběr platí pro aplikaci Perfetto i ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Vymazat procesy pro výpisy haldy"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Seznam procesů byl vymazán"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Průběžný profil haldy"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Pořídit výpis haldy jednou za zadaný interval"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Jednou za zadaný interval pořídit výpis haldy. Platí jen pro výpisy haldy aplikace Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Interval výpisu haldy"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekund"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekund"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Klepnutím ukončíte vytváření ukázek sady"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Zaznamenává se výpis haldy"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Klepnutím výpis haldy zastavíte"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Probíhá zaznamenávání výpisu haldy aplikace AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Vymazat uložené soubory"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Nahrávky jsou po měsíci vymazány"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Vymazat uložené soubory?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Všechny nahrávky v umístění /data/local/traces budou smazány"</string>
     <string name="clear" msgid="5484761795406948056">"Vymazat"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Trasování systému"</string>
-    <string name="keywords" msgid="736547007949049535">"systémové trasování, trasování, výkon"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, sledování, výkon, profil, profilování, procesor, callstack, stack, halda"</string>
     <string name="share_file" msgid="1982029143280382271">"Sdílet soubor?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Soubory Trasování systému mohou obsahovat citlivá data o systému a aplikacích (například využití aplikací). Tyto soubory sdílejte jen s lidmi a aplikacemi, kterým důvěřujete."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Soubory nástroje System Tracing mohou zahrnovat citlivá data o systému a aplikacích (například informace o využití aplikací nebo obrázky v paměti aplikace). Trasování systému nebo výpisy haldy sdílejte jen s lidmi a aplikacemi, kterým důvěřujete."</string>
     <string name="share" msgid="8443979083706282338">"Sdílet"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Tuto zprávu již nezobrazovat"</string>
     <string name="long_traces" msgid="5110949471775966329">"Dlouhá trasování"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Přikládat ke zprávám o chybách nahrávky"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Při získávání zprávy o chybě automaticky odesílat probíhající nahrávky do nástroje BetterBug. Nahrávání bude pokračovat."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Zobrazit uložené soubory"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Trasování je možné nahrát na ui.perfetto.dev pro analýzu"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Výpisy haldy lze prozkoumat pomocí nástroje AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Nastavení trasování"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Uložené soubory"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Různé"</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 835e1feb..e713671c 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Registrer heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Registrerer et heap dump af de processer, der er valgt i \"Heap dump-processer\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Vælg mindst én proces i \"Heap dump-processer\" for at indsamle heap dumps"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Registrer AM-heap dump med bitmaps"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Indsamler et heap dump af den proces, der er valgt i \"Heap dump-processer\", og udtrækker bitmapbilleder"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Vælg kun én proces i \"Heap dump-processer\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Vælg en proces i \"Heap dump-processer\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Inkluder sporing af Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Omfatter detaljerede telemetridata for brugerfladen (man medføre hak)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Registrer apps, der kan fejlrettes"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Standard"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# er valgt}one{# selected}other{# er valgt}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Heap dump-processer"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Du skal vælge mindst én process"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Disse valg gælder for både Perfetto og ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Ryd heap dump-processer"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Proceslisten er ryddet"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Kontinuerlig heap-profil"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Tag et heap dump én gang pr. angivet interval"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Tag et heap dump én gang pr. angivet interval. Gælder kun for Perfetto-heap dumps."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Heap dump-interval"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekunder"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekunder"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Tryk for at stoppe stakuddrag"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Heap dump registreres"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Tryk for at standse heap dump"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM-heap dump registreres"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Ryd gemte filer"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Registreringer ryddes efter én måned"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Vil du rydde de gemte filer?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Alle registreringer slettes fra /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Ryd"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Systemregistreringer"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, trace, ydeevne"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, spor, sporing, ydeevne, profil, profilering, cpu, kaldstak, stak, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Vil du dele filen?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Systemregistreringsfiler kan indeholde følsomme system- og appdata (f.eks. appforbrug). Del kun systemregistreringer med personer og apps, du har tillid til."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Systemsporingsfiler kan indeholde følsomme system- og appdata (f.eks. appbrug eller billeder i en apps hukommelse). Del kun systemsporinger eller heap dumps med personer og apps, du har tillid til."</string>
     <string name="share" msgid="8443979083706282338">"Del"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Vis ikke igen"</string>
     <string name="long_traces" msgid="5110949471775966329">"Lange registreringer"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Vedhæft registreringer i fejlrapporter"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Send automatisk løbende registreringer til BetterBug, når der indhentes en fejlrapport. Optagelser fortsætter efterfølgende."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Se gemte filer"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Registreringer kan uploades til ui.perfetto.dev med henblik på analyse"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Heap dumps kan undersøges med AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Indstillinger for registrering"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Gemte filer"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Diverse"</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 05d10627..dd69dcdf 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Heap-Dump aufzeichnen"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Ein Heap-Dump der in „Heap-Dump-Prozesse“ ausgewählten Prozesse wird aufgezeichnet"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Wähle mindestens einen Prozess in „Heap-Dump-Prozesse“ aus, um Heap-Dumps aufzuzeichnen"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"AM‑Heap-Dump mit Bitmaps speichern"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Erfasst einen Heap-Dump des in „Heap-Dump-Prozesse“ ausgewählten Prozesses und extrahiert Bitmap-Bilder"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Wähle nur einen Prozess in „Heap-Dump-Prozesse“ aus"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Wähle einen Prozess in „Heap-Dump-Prozesse“ aus"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"WinScope-Traces erfassen"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Enthält detaillierte UI-Telemetriedaten (kann zu Verzögerung führen)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Debug-fähige Anwendungen in Trace aufnehmen"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Standard"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# ausgewählt}other{# ausgewählt}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Heap-Dump-Prozesse"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Mindestens ein Prozess muss ausgewählt werden"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Diese Auswahl gilt sowohl für Perfetto als auch ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Heap-Dump-Prozesse löschen"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Prozessliste gelöscht"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Fortlaufendes Heap-Profil"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Heap-Dump einmal pro festgelegtem Intervall aufzeichnen"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Heap-Dump wird einmal pro festgelegtem Intervall gespeichert. Gilt nur für Perfetto-Heap-Dumps."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Heap-Dump-Intervall"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 Sekunden"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 Sekunden"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Zum Beenden der Erfassung von Stackproben tippen"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Heap-Dump wird aufgezeichnet"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Zum Beenden des Heap-Dumps tippen"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM‑Heap-Dump wird gespeichert"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Gespeicherte Dateien löschen"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Aufzeichnungen werden nach einem Monat gelöscht"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Gespeicherte Dateien löschen?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Alle Aufzeichnungen werden aus /data/local/traces gelöscht"</string>
     <string name="clear" msgid="5484761795406948056">"Löschen"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"System-Traces"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, trace, leistung"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, trace, tracing, leistung, profil, profiling, cpu, aufrufstack, stack, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Datei teilen?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"System-Tracing-Dateien beinhalten unter Umständen vertrauliche System- und App-Daten (z. B. App-Nutzung). Teile System-Traces nur mit Personen und App, denen du vertraust."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"System-Tracing-Dateien beinhalten unter Umständen vertrauliche System- und App-Daten (z. B. zur App-Nutzung oder Bilder im Arbeitsspeicher einer App). Teile System-Traces oder Heap-Dumps nur mit vertrauenswürdigen Personen und Apps."</string>
     <string name="share" msgid="8443979083706282338">"Teilen"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Nicht mehr anzeigen"</string>
     <string name="long_traces" msgid="5110949471775966329">"Lange Traces"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Aufzeichnungen an Fehlerberichte anhängen"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Laufende Aufzeichnungen automatisch an BetterBug senden, wenn ein Fehlerbericht erfasst wird. Die Aufzeichnung wird anschließend fortgesetzt."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Gespeicherte Dateien ansehen"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Traces können zur Analyse auf ui.perfetto.dev hochgeladen werden"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Heap-Dumps können mit AHAT geprüft werden"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Trace-Einstellungen"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Gespeicherte Dateien"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Sonstiges"</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index 448c2dec..bf4dabe9 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Καταγραφή στιγμιότυπου μνήμης"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Καταγράφει ένα στιγμιότυπο μνήμης των διεργασιών που έχουν επιλεχθεί στη λίστα Διεργασίες στιγμιότυπου μνήμης"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Επιλέξτε τουλάχιστον μία διεργασία από τη λίστα Διεργασίες στιγμιότυπου μνήμης για να συλλέξετε στιγμιότυπα μνήμης"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Καταγραφή στιγμιότυπου μνήμης από την εφαρμογή AM με χάρτη bit"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Συλλέγει ένα στιγμιότυπο μνήμης από τη διεργασία που έχει επιλεχθεί από τη λίστα Διεργασίες στιγμιότυπου μνήμης και εξαγάγει εικόνες χάρτη bit"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Επιλέξτε μόνο μία διεργασία από τη λίστα Διεργασίες στιγμιότυπου μνήμης"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Επιλέξτε μια διεργασία από τη λίστα Διεργασίες στιγμιότυπου μνήμης"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Συγκέντρωση ιχνών Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Συμπεριλαμβάνει λεπτομερή δεδομένα τηλεμετρίας διεπαφής χρήστη (μπορεί να προκαλέσει παύση)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Ανίχνευση εφαρμογών με δυνατότητα εντοπισμού σφαλμάτων"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Προεπιλογή"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Επιλέχθηκε #}other{Επιλέχθηκαν #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Διεργασίες στιγμιότυπου μνήμης"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Πρέπει να επιλεχθεί τουλάχιστον μία διεργασία"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Αυτές οι επιλογές ισχύουν τόσο για την εφαρμογή Perfetto όσο και για την εφαρμογή ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Εκκαθάριση διεργασιών στιγμιότυπου μνήμης"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Η εκκαθάριση της λίστα διεργασιών ολοκληρώθηκε"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Συνεχές προφίλ σωρού"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Καταγραφή στιγμιότυπου μνήμης μία φορά ανά καθορισμένο διάστημα"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Καταγραφή στιγμιότυπου μνήμης μία φορά ανά καθορισμένο διάστημα. Ισχύει μόνο για τα στιγμιότυπα μνήμης από την εφαρμογή Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Διάστημα για το στιγμιότυπο μνήμης"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 δευτερόλεπτα"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 δευτερόλεπτα"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Πατήστε για διακοπή της δειγματοληψίας"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Γίνεται καταγραφή του στιγμιότυπου μνήμης"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Πατήστε για να διακόψετε το στιγμιότυπο μνήμης"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Πραγματοποιείται καταγραφή του στιγμιότυπου μνήμης από την εφαρμογή AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Διαγραφή αποθηκευμένων αρχείων"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Οι εγγραφές διαγράφονται μετά από έναν μήνα"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Διαγραφή αποθηκευμένων αρχείων;"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Θα διαγραφούν όλες οι εγγραφές από τη διαδρομή /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Διαγραφή"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Ίχνη συστήματος"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, ανίχνευση, απόδοση"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ιχνηλάτηση, ανίχνευση, απόδοση, προφίλ, δημιουργία προφίλ, cpu, στοίβα κλήσης, στοίβα, μνήμη"</string>
     <string name="share_file" msgid="1982029143280382271">"Κοινοποίηση του αρχείου;"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Τα αρχεία ιχνηλάτησης συστήματος μπορεί να περιλαμβάνουν ευαίσθητα δεδομένα συστήματος και εφαρμογών (όπως χρήση εφαρμογών). Κοινοποιείτε τα ίχνη συστήματος μόνο σε άτομα και εφαρμογές που εμπιστεύεστε."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Τα αρχεία ανίχνευσης συστήματος ενδέχεται να περιλαμβάνουν ευαίσθητα δεδομένα συστήματος και εφαρμογών (όπως χρήση εφαρμογών ή εικόνες στη μνήμη μιας εφαρμογής). Να μοιράζεστε ίχνη συστήματος ή στιγμιότυπα μνήμης μόνο με άτομα και εφαρμογές που εμπιστεύεστε."</string>
     <string name="share" msgid="8443979083706282338">"Κοινοποίηση"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Να μην εμφανιστεί ξανά"</string>
     <string name="long_traces" msgid="5110949471775966329">"Μεγάλα ίχνη"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Επισύναψη εγγραφών σε αναφορές σφαλμάτων"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Αυτόματη αποστολή εγγραφών που βρίσκονται σε εξέλιξη στο BetterBug κατά τη συλλογή μιας αναφοράς σφάλματος. Οι εγγραφές θα συνεχίσουν αμέσως μετά."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Προβολή αποθηκευμένων αρχείων"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Τα ίχνη μπορούν να μεταφορτωθούν στο ui.perfetto.dev για ανάλυση"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Η επιθεώρηση στιγμιότυπων μνήμης μπορεί να γίνει με το AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Ρυθμίσεις ίχνους"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Αποθηκευμένα αρχεία"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Διάφορα"</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 6dc58ed6..bab80760 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Record heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captures a heap dump of the processes selected in \'Heap dump processes\'"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Select at least one process in \'Heap dump processes\' to collect heap dumps"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Record AM heap dump with bitmaps"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Collects a heap dump of the process selected in \'Heap dump processes\' and extracts bitmap images"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Select only one process in \'Heap dump processes\'"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Select a process in \'Heap dump processes\'"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collect winscope traces"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Includes detailed UI telemetry data (can cause jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Trace debuggable applications"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Default"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# selected}other{# selected}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Heap dump processes"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"At least one process must be selected"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"These selections apply to both Perfetto and ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Clear heap dump processes"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Process list cleared"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Continuous heap profile"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Capture a heap dump once per specified interval"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Capture a heap dump once per specified interval. Only applies to Perfetto heap dumps."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Heap dump interval"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 seconds"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 seconds"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Tap to stop stack sampling"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Heap dump is being recorded"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Tap to stop heap dump"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM heap dump is being recorded"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Clear saved files"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Recordings are cleared after one month"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Clear saved files?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"All recordings will be deleted from /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Clear"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"System traces"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, trace, performance"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, trace, tracing, performance, profile, profiling, cpu, callstack, stack, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Share file?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"System tracing files may include sensitive system and app data (such as app usage). Only share system traces with people and apps that you trust."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"System Tracing files may include sensitive system and app data (such as app usage or images in an app\'s memory). Only share system traces or heap dumps with people and apps that you trust."</string>
     <string name="share" msgid="8443979083706282338">"Share"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Don\'t show again"</string>
     <string name="long_traces" msgid="5110949471775966329">"Long traces"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Attach recordings to bug reports"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatically send in-progress recordings to BetterBug when a bug report is collected. Recordings will continue afterwards."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"View saved files"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Traces can be uploaded to ui.perfetto.dev for analysis"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Heap dumps can be inspected with AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Trace settings"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saved files"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Miscellaneous"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index bb58f445..d0e4edd0 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Record heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captures a heap dump of the processes selected in \"Heap dump processes\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Select at least one process in \"Heap dump processes\" to collect heap dumps"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Record AM heap dump with bitmaps"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Collects a heap dump of the process selected in \"Heap dump processes\" and extracts bitmap images"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Select only one process in \"Heap dump processes\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Select a process in \"Heap dump processes\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collect Winscope traces"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Includes detailed UI telemetry data (can cause jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Trace debuggable applications"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Default"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# selected}other{# selected}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Heap dump processes"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"At least one process must be selected"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"These selections apply to both Perfetto and ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Clear heap dump processes"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Process list cleared"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Continuous heap profile"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Capture a heap dump once per specified interval"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Capture a heap dump once per specified interval. Only applies to Perfetto heap dumps."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Heap dump interval"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 seconds"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 seconds"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Tap to stop stack sampling"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Heap dump is being recorded"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Tap to stop heap dump"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM heap dump is being recorded"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Clear saved files"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Recordings are cleared after one month"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Clear saved files?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"All recordings will be deleted from /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Clear"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"System traces"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, trace, performance"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, trace, tracing, performance, profile, profiling, cpu, callstack, stack, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Share file?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"System Tracing files may include sensitive system and app data (such as app usage). Only share system traces with people and apps you trust."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"System Tracing files may include sensitive system and app data (such as app usage or images in an app\'s memory). Only share system traces or heap dumps with people and apps you trust."</string>
     <string name="share" msgid="8443979083706282338">"Share"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Don\'t show again"</string>
     <string name="long_traces" msgid="5110949471775966329">"Long traces"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Attach recordings to bug reports"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatically send in-progress recordings to BetterBug when a bug report is collected. Recordings will continue afterward."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"View saved files"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Traces can be uploaded to ui.perfetto.dev for analysis"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Heap dumps can be inspected with AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Trace settings"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saved files"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Miscellaneous"</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 6dc58ed6..bab80760 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Record heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captures a heap dump of the processes selected in \'Heap dump processes\'"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Select at least one process in \'Heap dump processes\' to collect heap dumps"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Record AM heap dump with bitmaps"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Collects a heap dump of the process selected in \'Heap dump processes\' and extracts bitmap images"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Select only one process in \'Heap dump processes\'"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Select a process in \'Heap dump processes\'"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collect winscope traces"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Includes detailed UI telemetry data (can cause jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Trace debuggable applications"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Default"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# selected}other{# selected}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Heap dump processes"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"At least one process must be selected"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"These selections apply to both Perfetto and ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Clear heap dump processes"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Process list cleared"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Continuous heap profile"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Capture a heap dump once per specified interval"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Capture a heap dump once per specified interval. Only applies to Perfetto heap dumps."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Heap dump interval"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 seconds"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 seconds"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Tap to stop stack sampling"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Heap dump is being recorded"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Tap to stop heap dump"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM heap dump is being recorded"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Clear saved files"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Recordings are cleared after one month"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Clear saved files?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"All recordings will be deleted from /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Clear"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"System traces"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, trace, performance"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, trace, tracing, performance, profile, profiling, cpu, callstack, stack, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Share file?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"System tracing files may include sensitive system and app data (such as app usage). Only share system traces with people and apps that you trust."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"System Tracing files may include sensitive system and app data (such as app usage or images in an app\'s memory). Only share system traces or heap dumps with people and apps that you trust."</string>
     <string name="share" msgid="8443979083706282338">"Share"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Don\'t show again"</string>
     <string name="long_traces" msgid="5110949471775966329">"Long traces"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Attach recordings to bug reports"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatically send in-progress recordings to BetterBug when a bug report is collected. Recordings will continue afterwards."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"View saved files"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Traces can be uploaded to ui.perfetto.dev for analysis"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Heap dumps can be inspected with AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Trace settings"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saved files"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Miscellaneous"</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index 6dc58ed6..bab80760 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Record heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captures a heap dump of the processes selected in \'Heap dump processes\'"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Select at least one process in \'Heap dump processes\' to collect heap dumps"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Record AM heap dump with bitmaps"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Collects a heap dump of the process selected in \'Heap dump processes\' and extracts bitmap images"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Select only one process in \'Heap dump processes\'"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Select a process in \'Heap dump processes\'"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collect winscope traces"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Includes detailed UI telemetry data (can cause jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Trace debuggable applications"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Default"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# selected}other{# selected}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Heap dump processes"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"At least one process must be selected"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"These selections apply to both Perfetto and ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Clear heap dump processes"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Process list cleared"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Continuous heap profile"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Capture a heap dump once per specified interval"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Capture a heap dump once per specified interval. Only applies to Perfetto heap dumps."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Heap dump interval"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 seconds"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 seconds"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Tap to stop stack sampling"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Heap dump is being recorded"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Tap to stop heap dump"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM heap dump is being recorded"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Clear saved files"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Recordings are cleared after one month"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Clear saved files?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"All recordings will be deleted from /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Clear"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"System traces"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, trace, performance"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, trace, tracing, performance, profile, profiling, cpu, callstack, stack, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Share file?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"System tracing files may include sensitive system and app data (such as app usage). Only share system traces with people and apps that you trust."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"System Tracing files may include sensitive system and app data (such as app usage or images in an app\'s memory). Only share system traces or heap dumps with people and apps that you trust."</string>
     <string name="share" msgid="8443979083706282338">"Share"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Don\'t show again"</string>
     <string name="long_traces" msgid="5110949471775966329">"Long traces"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Attach recordings to bug reports"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatically send in-progress recordings to BetterBug when a bug report is collected. Recordings will continue afterwards."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"View saved files"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Traces can be uploaded to ui.perfetto.dev for analysis"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Heap dumps can be inspected with AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Trace settings"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saved files"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Miscellaneous"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 73b2c890..ae4e1c54 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -2,7 +2,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="system_tracing" msgid="4719188511746319848">"Registro del sistema"</string>
-    <string name="record_system_activity" msgid="4339462312915377825">"Registra y analiza la actividad del sistema para mejorar el rendimiento"</string>
+    <string name="record_system_activity" msgid="4339462312915377825">"Registra la actividad del sistema para que puedas analizarla más tarde y mejorar el rendimiento"</string>
     <string name="record_trace" msgid="6416875085186661845">"Registrar seguimiento"</string>
     <string name="record_trace_summary" msgid="6705357754827849292">"Captura un registro del sistema con la configuración establecida en \"Configuración de registro\""</string>
     <string name="record_stack_samples" msgid="3498368637185702335">"Grabar el Generador de perfiles de CPU"</string>
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Registrar volcado de montón"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captura un volcado de montón del proceso seleccionado en \"Procesos del volcado de montón\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecciona al menos un proceso en \"Procesos del volcado de montón\" para recolectar volcados de montón"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Registrar volcado de montón de AM con mapas de bits"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Recopila un volcado de montón del proceso seleccionado en \"Procesos del volcado de montón\" y extrae imágenes de mapa de bits"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Selecciona solo un proceso en \"Procesos del volcado de montón\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Selecciona un proceso en \"Procesos del volcado de montón\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Recopilar registros de WinScope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Incluye datos detallados de la telemetría de la IU (puede producir bloqueos)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Registrar aplicaciones depurables"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Valor predeterminado"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# seleccionada}other{# seleccionadas}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Procesos del volcado de montón"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Se debe seleccionar al menos un proceso"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Estas selecciones se aplican a Perfetto y ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Limpiar los procesos de volcado de montón"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Se limpió la lista de procesos"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Perfil del montón continuo"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Captura un volcado de montón por cada intervalo especificado"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Captura un volcado de montón por cada intervalo especificado. Solo se aplica a los volcados de montón de Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Intervalo del volcado de montón"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 segundos"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 segundos"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Presiona para detener el muestreo de pila"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Se está registrando el volcado de montón"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Presiona para detener el volcado de montón"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Se está registrando el volcado de montón de AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Borrar los archivos guardados"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"La grabaciones se borran después de un mes"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"¿Quieres borrar los archivos guardados?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Se borrarán todas las grabaciones de /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Borrar"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Registros del sistema"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, seguimiento, rendimiento"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, registro, registrar, rendimiento, perfil, generación de perfiles, CPU, pila de llamadas, pila, montón"</string>
     <string name="share_file" msgid="1982029143280382271">"¿Quieres compartir el archivo?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Los archivos de Registro del sistema podrían incluir datos sensibles del sistema y de la app (como información sobre el uso de la app). Comparte los registros del sistema únicamente con personas y apps de confianza."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Los archivos de seguimiento del sistema pueden incluir datos sensibles del sistema y de la app (como el uso de la app o las imágenes en la memoria de una app). Comparte los registros del sistema o los volcados de montón solo con personas y apps de confianza."</string>
     <string name="share" msgid="8443979083706282338">"Compartir"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"No volver a mostrar"</string>
     <string name="long_traces" msgid="5110949471775966329">"Registros largos"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Adjuntar grabaciones a los informes de errores"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Envía los registros en curso automáticamente a BetterBug cuando se recopila un informe de errores. Los registros continuarán después."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Ver los archivos guardados"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Los registros se pueden subir a ui.perfetto.dev para su análisis"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Los volcados de montón se pueden inspeccionar con AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Configuración del registro"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Archivos guardados"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Varios"</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index cda3ce67..08977f52 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Registrar volcado de montículo"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captura un volcado de montículo de los procesos seleccionados en \"Procesos de volcado de montículo\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecciona al menos un proceso en \"Procesos de volcado de montículo\" para recopilar volcados de montículo"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Grabar volcado de montículo de AM con mapas de bits"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Recopila un volcado de montículo del proceso que hayas seleccionado en \"Procesos de volcado de montículo\" y extrae imágenes de mapa de bits"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Selecciona solo un proceso en \"Procesos de volcado de montículo\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Selecciona un proceso en \"Procesos de volcado de montículo\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Recoger trazas de Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Incluye datos detallados de telemetría de UI (puede causar tirones)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Rastrear aplicaciones que se puedan depurar"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Predeterminadas"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# seleccionada}other{# seleccionadas}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Procesos de volcado de montículo"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Se debe seleccionar al menos un proceso"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Estas selecciones se aplican tanto a Perfetto como a ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Borrar procesos de volcado de montículo"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Lista de procesos borrada"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Perfil de montículo continuo"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Captura un volcado de montículo por cada intervalo especificado"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Captura un volcado de montículo por cada intervalo especificado. Solo se aplica a los volcados de montículo de Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Intervalo del volcado de montículo"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 segundos"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 segundos"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Toca para detener las muestras de la pila"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"El volcado de montículo se está registrando"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Toca para detener el volcado de montículo"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"El volcado de montículo de AM se está grabando"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Borrar los archivos guardados"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Las grabaciones se borrarán al cabo de un mes"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"¿Borrar los archivos guardados?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Se eliminarán todas las grabaciones de /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Borrar"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Trazas del sistema"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, traza, rendimiento"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, rastrear, seguimiento, rendimiento, perfil, elaboración de perfiles, CPU, pila de llamadas, pila, montículo"</string>
     <string name="share_file" msgid="1982029143280382271">"¿Compartir archivo?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Es posible que los archivos de Trazado del sistema incluyan datos sensibles del sistema y de aplicaciones (como información sobre el uso de las aplicaciones). Comparte las trazas del sistema únicamente con usuarios y aplicaciones en los que confíes."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Es posible que los archivos de Trazado del sistema incluyan datos sensibles del sistema y de aplicaciones (como información sobre el uso de las aplicaciones o imágenes de la memoria de una aplicación). Comparte las trazas del sistema o los volcados de montículo únicamente con personas y aplicaciones de confianza."</string>
     <string name="share" msgid="8443979083706282338">"Compartir"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"No volver a mostrar"</string>
     <string name="long_traces" msgid="5110949471775966329">"Trazas largas"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Adjuntar las grabaciones en los informes de errores"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Adjunta automáticamente las grabaciones en curso en los informes de errores que se envían a BetterBug. Las grabaciones continuarán después."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Ver los archivos guardados"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Las trazas se pueden subir a ui.perfetto.dev para llevar a cabo análisis"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Los volcados de montículo se pueden inspeccionar con AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Ajustes de rastreo"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Archivos guardados"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Otras opciones"</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index fe80a326..f0ef6b4a 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Salvesta mälutõmmis"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Jäädvustab jaotises „Mälutõmmise protsessid” valitud protsessidest mälutõmmise"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Mälutõmmiste kogumiseks valige jaotises „Mälutõmmise protsessid” vähemalt üks protsess"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Salvesta AM-i mälutõmmis bittrastriga"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Võtab jaotise „Mälutõmmise protsessid” alt valitud protsessist mälutõmmise ja ekstraktib sellest rasterpildid"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Jaotises „Mälutõmmise protsessid” ainult ühe protsessi valimine"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Jaotises „Mälutõmmise protsessid” ühe protsessi valimine"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Kogu Winscope\'i jälgi"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Sisaldab üksikasjalikke kasutajaliidese telemeetriaandmeid (võib põhjustada tõrkeid)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Silutavate rakenduste jälgimine"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Vaikeseade"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# on valitud}other{# on valitud}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Mälutõmmise protsessid"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Valitud peab olema vähemalt üks protsess"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Need valikud kehtivad nii Perfetto kui ka ActivityManageri suhtes"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Kustuta mälutõmmise protsessid"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Protsessiloend on kustutatud"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Pidev kuhja profiil"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Jäädvustage mälutõmmis määratud ajavahemiku jooksul üks kord"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Jäädvustage mälutõmmis määratud ajavahemiku jooksul üks kord. Kehtib ainult Perfetto mälutõmmiste suhtes."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Mälutõmmise ajavahemik"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekundit"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekundit"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Pinu näidisevõtu lõpetamiseks puudutage"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Mälutõmmis salvestatakse"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Puudutage mälutõmmise peatamiseks"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM-i mälutõmmist salvestatakse"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Kustuta salvestatud failid"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Salvestised kustutatakse pärast ühe kuu möödumist"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Kas kustutada salvestatud failid?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Kõik salvestised kustutatakse asukohast /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Kustuta"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Süsteemi jäljed"</string>
-    <string name="keywords" msgid="736547007949049535">"süsteemijälg, jälg, toimivus"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, jälg, jälgimine, toimivus, profiil, profiilimine, protsessor, kutsepinu, virn, mälu"</string>
     <string name="share_file" msgid="1982029143280382271">"Kas jagada faili?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Süsteemi jälgimise failid võivad hõlmata tundlikke süsteemi- ja rakenduseandmeid (nt rakenduse kasutust). Jagage süsteemijälgi ainult usaldusväärsete inimeste ja rakendustega."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Süsteemi jälgimise failid võivad hõlmata delikaatseid süsteemi- ja rakenduste andmeid (nt rakenduse kasutust või rakenduse mälus olevaid pilte). Jagage süsteemi jälgi või mälutõmmiseid ainult inimeste ja rakendustega, keda või mida usaldate."</string>
     <string name="share" msgid="8443979083706282338">"Jaga"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Ära enam kuva"</string>
     <string name="long_traces" msgid="5110949471775966329">"Pikad jäljed"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Manusta salvestised veaaruannetele"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Pooleliolevad salvestised saadetakse veaaruande koostamisel automaatselt BetterBugile. Salvestamine jätkub pärast seda."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Kuva salvestatud failid"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Jäljed saab analüüsimiseks üles laadida saidile ui.perfetto.dev"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Mälutõmmiseid saab AHAT-iga kontrollida"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Jälgimise seaded"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Salvestatud failid"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Mitmesugust"</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 9f69332c..cff24bac 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -3,13 +3,17 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="system_tracing" msgid="4719188511746319848">"Sistemaren arrastoa"</string>
     <string name="record_system_activity" msgid="4339462312915377825">"Erregistratu sistemaren jarduerak eta analiza itzazu geroago errendimendua hobetzeko"</string>
-    <string name="record_trace" msgid="6416875085186661845">"Erregistroaren jarraipena"</string>
+    <string name="record_trace" msgid="6416875085186661845">"Erregistratu arrastoa"</string>
     <string name="record_trace_summary" msgid="6705357754827849292">"Sistemaren arrasto bat kapturatzen du Arrastoen ezarpenak atalean ezarritako konfigurazioa erabilita"</string>
     <string name="record_stack_samples" msgid="3498368637185702335">"Erregistratu PUZaren profil bat"</string>
     <string name="record_stack_samples_summary" msgid="7827953921526410478">"Dei pilen laginketa arrastoetan ere gai daiteke CPU kategoria markatuta"</string>
     <string name="record_heap_dump" msgid="1688550222066812696">"Erregistratu memoria-iraulketaren txostena"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"Memoria-iraulketaren txostenarekin lotutako prozesuak\" atalean hautatutako prozesuen memoria-iraulketaren txosten bat egiten du"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Memoria-iraulketaren txostenak biltzeko, hautatu gutxienez prozesu bat \"Memoria-iraulketaren txostenarekin lotutako prozesuak\" atalean"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Erregistratu AM-en memoria-iraulketaren txostenak bit-mapen bidez"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Memoria-iraulketaren txostenarekin lotutako prozesuetan hautatutako prozesuaren memoria-iraulketaren txosten bat biltzen du, eta bit-mapa bidezko irudiak erauzten ditu"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Hautatu prozesu bat soilik memoria-iraulketaren txostenarekin lotutako prozesuetan"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Hautatu prozesu bat memoria-iraulketaren txostenarekin lotutako prozesuetan"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Bildu Winscope-ko arrastoak"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Erabiltzaile-interfazeari buruzko datu telemetriko xeheak ditu (baliteke etenak eragitea)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Egin aratz daitezkeen aplikazioen segimendua"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Lehenetsia"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# hautatu da}other{# hautatu dira}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Memoria-iraulketaren txostenarekin lotutako prozesuak"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Prozesu bat hautatu behar da gutxienez"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Hautapen hauek Perfetto-n eta ActivityManager-en aplikatzen dira"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Garbitu memoria-iraulketaren txostenarekin lotutako prozesuak"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Garbitu da prozesuen zerrenda"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Memoriaren esleipen-analisi etengabea"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Egin memoria-iraulketaren txosten bat zehaztutako tartea igarotzen den aldi bakoitzean"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Egin memoria-iraulketaren txosten bat zehaztutako tartea igarotzen den aldi bakoitzean. Perfetto-ren memoria-iraulketaren txostenetan soilik aplikatzen da."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Memoria-iraulketaren txostenen tartea"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 segundo"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 segundo"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Pilen laginketa gelditzeko, sakatu hau"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Memoria-iraulketaren txostena erregistratzen ari da"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Sakatu memoria-iraulketaren txostena gelditzeko"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM-en memoria-iraulketaren txostena grabatzen ari da"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Garbitu gordetako fitxategiak"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Erregistroak hilabete baten buruan garbitzen dira"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Gordetako fitxategiak garbitu nahi dituzu?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Erregistro guztiak /data/local/traces karpetatik ezabatuko dira"</string>
     <string name="clear" msgid="5484761795406948056">"Garbitu"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Sistemaren arrastoak"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, arrastoa, errendimendua"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, arrastoa, jarraipena, errendimendua, profila, analisia, PUZa, dei pila, pila, txostena"</string>
     <string name="share_file" msgid="1982029143280382271">"Fitxategia gorde nahi duzu?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Sistemaren jarraipena direktorioko fitxategiek sistemaren eta aplikazioen kontuzko datuak izan ditzakete (adibidez, aplikazioen erabilera). Partekatu sistemaren arrastoak fidagarritzat jotzen dituzun pertsona eta aplikazioekin soilik."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Sistemaren jarraipena direktorioko fitxategiek sistemaren eta aplikazioen kontuzko datuak izan ditzakete (adibidez, aplikazioen erabilera). Partekatu sistemaren arrastoak edo memoria-iraulketaren txostenak fidagarritzat jotzen dituzun pertsona eta aplikazioekin soilik."</string>
     <string name="share" msgid="8443979083706282338">"Partekatu"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Ez erakutsi berriro"</string>
     <string name="long_traces" msgid="5110949471775966329">"Arrasto luzeak"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Sartu grabaketak akatsen txostenetan"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Bidali automatikoki abian diren erregistroak BetterBug-era akatsen txosten bat sortzen denean. Erregistroek aurrera egingo dute."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Ikusi gordetako fitxategiak"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Arrastoak ui.perfetto.dev-era karga daitezke haiek aztertzeko"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Memoria-iraulketaren txostenak AHAT bidez azter daitezke"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Arrastoen ezarpenak"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Gordetako fitxategiak"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Askotarikoak"</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index f112a897..9cd6ac4f 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ضبط رونوشت پشته"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"رونوشت پشته را برای پردازش‌های انتخاب‌شده در «پردازش‌های رونوشت پشته» را ضبط می‌کند"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"برای جمع‌آوری رونوشت‌های پشته، حداقل یک پردازش را در «پردازش‌های رونوشت پشته» انتخاب کنید"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"‏ضبط رونوشت پشته AM با بیت‌مپ"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"رونوشت پشته را برای پردازش‌های انتخاب‌شده در «پردازش‌های رونوشت پشته» جمع‌آوری می‌کند و تصاویر بیت‌مپ را استخراج می‌کند"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"فقط یک پردازش در «پردازش‌های رونوشت پشته» انتخاب می‌شود"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"پردازشی در «پردازش‌های رونوشت پشته» انتخاب می‌شود"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"‏جمع‌آوری ردپاهای Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"شامل داده‌های دورسنجی دقیق واسط کاربر می‌شود (ممکن است باعث قطع اتصال شود)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"برنامه‌هایی با قابلیت اشکال‌زدایی ردیابی"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"پیش‌فرض"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# دسته انتخاب شده است}one{# دسته انتخاب شده است}other{# دسته انتخاب شده است}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"پردازش‌های رونوشت پشته"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"حداقل یک پردازش باید انتخاب شود"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"‏این انتخاب‌ها هم برای Perfetto و هم برای ActivityManager اعمال می‌شود"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"پاک کردن پردازش‌های رونوشت پشته"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"فهرست پردازش پاک شد"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"تحلیل پشته پیوسته"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"رونوشت پشته در هر فاصله زمانی مشخص یک‌بار ضبط می‌شود"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"‏رونوشت پشته یک‌بار در هر فاصله زمانی مشخص ضبط می‌شود. این مورد فقط برای رونوشت‌های پشته Perfetto اعمال می‌شود."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"فاصله زمانی رونوشت پشته"</string>
     <string name="five_seconds" msgid="7018465440929299712">"۵ ثانیه"</string>
     <string name="ten_seconds" msgid="863416601384309033">"۱۰ ثانیه"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"برای توقف نمونه‌گیری از پشته، تک‌ضرب بزنید"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"رونوشت پشته درحال ضبط شدن است"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"برای متوقف کردن رونوشت پشته، تک‌ضرب بزنید"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"‏رونوشت پشته AM درحال ضبط شدن است"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"پاک کردن فایل‌های ذخیره‌شده"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"قطعه‌های ضبط‌شده بعداز یک ماه پاک می‌شود"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"فایل‌های ذخیره‌شده پاک شود؟"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"‏همه قطعه‌های ضبط‌شده از ‎/data/local/traces حذف می‌شوند"</string>
     <string name="clear" msgid="5484761795406948056">"پاک کردن"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"ردهای سیستم"</string>
-    <string name="keywords" msgid="736547007949049535">"رد سیستم، رد، عملکرد"</string>
+    <string name="keywords" msgid="255681926397897100">"‏‫systrace،‏ traceur،‏ perfetto،‏ winscope، ردیابی کردن، ردیابی، عملکرد، نمایه، نمایه‌سازی، واحد پردازش مرکزی، CPU، فراخوانی پشته، پشته‌ها، پشته"</string>
     <string name="share_file" msgid="1982029143280382271">"فایل هم‌رسانی شود؟"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"ممکن است فایل‌های «ردیابی سیستم» حاوی داده‌های حساس سیستم و برنامه (مثل میزان مصرف برنامه) باشد. ردیابی‌های سیستم را فقط با افراد و برنامه‌هایی هم‌رسانی کنید که به آن‌ها اعتماد دارید."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"ممکن است فایل‌های «ردیابی سیستم» حاوی داده‌های حساس سیستم و برنامه (مثل میزان مصرف برنامه یا تصاویری در حافظه برنامه) باشد. ردیابی‌های سیستم یا رونوشت‌های پشته را فقط با افراد و برنامه‌هایی هم‌رسانی کنید که به آن‌ها اعتماد دارید."</string>
     <string name="share" msgid="8443979083706282338">"هم‌رسانی"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"دیگر نشان داده نشود"</string>
     <string name="long_traces" msgid="5110949471775966329">"ردهای طولانی"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"پیوست کردن قطعه‌های ضبط‌شده به گزارش اشکال"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"‏هنگام جمع‌آوری گزارش اشکال، ضبط‌های درجریان به‌طور خودکار به BetterBug ارسال می‌شود. پس‌از آن، ضبط ادامه پیدا خواهد کرد."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"مشاهده فایل‌های ذخیره‌شده"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"‏ردیابی‌ها را می‌توان برای تحلیل در ui.perfetto.dev بارگذاری کرد"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"‏رونوشت‌های پشته را می‌توان با AHAT بررسی کرد"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"تنظیمات ردیابی"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"فایل‌های ذخیره‌شده"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"متفرقه"</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 28c47e04..2a790edd 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Tallenna keon vedos"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Tallentaa kohdasta \"Keon vedos ‑prosessit\" valitun vedoksen"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Valitse ainakin yksi keon vedos ‑prosessi, jotta voit kerätä vedoksia"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Tallenna AM:n keon vedos bittikartoilla"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Kerää keon vedoksen kohdasta \"Keon vedos ‑prosessit\" valitusta prosessista ja poimii bittikarttakuvia"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Valitse vain yksi keon vedos ‑prosessi"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Valitse prosessi kohdasta \"Keon vedos ‑prosessit\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Kerää Winscope-jälkiä"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Sisällyttää yksityiskohtaista UI-telemetriadataa (voi aiheuttaa katkoja)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Tallenna viankorjausta tukevien sovellusten jäljet"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Oletus"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# valittu}other{# valittu}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Keon vedos ‑prosessit"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Valitse vähintään yksi prosessi"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Nämä valinnat koskevat sekä Perfettoa että ActivityManageria"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Tyhjennä keon vedos ‑prosessit"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Prosessit tyhjennetty"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Jatkuvan keon profiili"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Tallenna keon vedos kerran valitun jakson aikana"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Tallenna keon vedos kerran valitun jakson aikana. Koskee vain Perfetto -keon vedosta."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Keon vedoksen ajanjakso"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekuntia"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekuntia"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Lopeta pinon näytteenotto napauttamalla"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Keon vedosta tallennetaan"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Keskeytä keon vedos napauttamalla"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM:n keon vedosta tallennetaan"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Poista tallennetut tiedostot"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Tallenteet poistetaan kuukauden päästä"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Poistetaanko tallennetut tiedostot?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Kaikki tallenteet poistetaan paikasta /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Poista"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Järjestelmän jäljitystiedostot"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, jälki, suorituskyky"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, jäljitä, jäljitys, suorituskyky, profiili, profilointi, suoritin, kutsupino, pino, keko"</string>
     <string name="share_file" msgid="1982029143280382271">"Jaetaanko tiedosto?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Järjestelmän jäljitystiedostoissa voi olla arkaluontoista järjestelmä- ja sovellusdataa (esim. sovellusten käytöstä). Jaa jäljitystiedostoja vain luotettavien ihmisten ja sovellusten kanssa."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Järjestelmän seurantatiedostot voivat sisältää arkaluontoista järjestelmä- ja sovellusdataa (esimerkiksi sovelluksen käyttöä tai sovelluksen muistissa olevia kuvia). Jaa järjestelmän seuranta tai keon vedokset vain ihmisille ja sovelluksille, joihin luotat."</string>
     <string name="share" msgid="8443979083706282338">"Jaa"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Älä näytä uudelleen"</string>
     <string name="long_traces" msgid="5110949471775966329">"Pitkät jäljet"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Liitä tallenteet virheraportteihin"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Lähetä keskeneräiset tallenteet BetterBugille automaattisesti virheraportin keräyksen yhteydessä. Tallenteet jatkuvat sen jälkeen."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Katso tallennetut tiedostot"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Jäljet voidaan ladata tänne analysoitaviksi: ui.perfetto.dev"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Keon vedokset voi tarkastaa AHATilla"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Jäljittämisasetukset"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Tallennetut tiedostot"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Muut"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 00f0f1b8..63a2aaff 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Enregistrer l\'empreinte de mémoire"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Capture une empreinte de mémoire des processus sélectionnés dans « Processus d\'empreinte de mémoire »"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Sélectionnez au moins un processus dans « Processus d\'empreinte de mémoire » pour collecter des empreintes de mémoire."</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Enregistrer l\'empreinte de mémoire AM avec des tables de bits"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Collecte une empreinte de mémoire du processus sélectionné dans « Processus d\'empreinte de mémoire » et extrait des images de tables de bits"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Sélectionnez un seul processus dans « Processus d\'empreinte de mémoire »"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Sélectionnez un processus dans « Processus d\'empreinte de mémoire »"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collecter les traces Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Comprend les données télémétriques détaillées de l\'IU (pouvant provoquer une IU lente)."</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Enregistrer les traces d\'applis débogables"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Par défaut"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# sélectionnée}one{# sélectionnée}other{# sélectionnées}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Processus d\'empreinte de mémoire"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Vous devez sélectionner au moins un processus"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Ces sélections s\'appliquent à la fois à Perfetto et à ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Effacer les processus d\'empreinte de mémoire"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Liste des processus effacée"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Profil de tas continu"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Capturer une empreinte de mémoire une fois par intervalle précisé"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Capturez une empreinte de mémoire une fois par intervalle précisé S\'applique uniquement aux empreintes de mémoire Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Intervalle d\'empreinte de mémoire"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 secondes"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 secondes"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Touchez pour interrompre l\'échantillonnage de la pile"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"L\'empreinte de mémoire est en cours d\'enregistrement"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Touchez ici pour arrêter l\'enregistrement de l\'empreinte de mémoire"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"L\'empreinte de mémoire AM est en cours d\'enregistrement"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Effacer les fichiers enregistrés"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Les enregistrements sont effacés après un mois"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Effacer les fichiers enregistrés?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Tous les enregistrements seront supprimés de /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Effacer"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Traces du système"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, suivre, performance"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, trace, traçage, performance, profil, profilage, processeur, pile d\'appels, pile, tas"</string>
     <string name="share_file" msgid="1982029143280382271">"Partager le fichier?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Les fichiers de suivi système peuvent comprendre des données sensibles concernant le système et les applis (par exemple, l\'utilisation des applis). Prenez soin de les partager uniquement avec les gens et les appli en qui vous avez confiance."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Les fichiers de suivi système peuvent comprendre des données sensibles concernant le système et les données de l\'appli (par exemple, l\'utilisation de l\'appli ou des images dans la mémoire d\'une appli). Prenez soin de partager les traces du système ou les empreintes de mémoire uniquement avec les gens et les applis en qui vous avez confiance."</string>
     <string name="share" msgid="8443979083706282338">"Partager"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Ne plus afficher"</string>
     <string name="long_traces" msgid="5110949471775966329">"Traces longues"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Joindre les enregistrements aux rapports de bogue"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Envoyer automatiquement les enregistrements en cours à BetterBug lorsqu\'un rapport de bogue est recueilli. Les enregistrements se poursuivront par la suite."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Afficher les fichiers enregistrés"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Les traces peuvent être téléversées sur ui.perfetto.dev aux fins d\'analyse"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Les empreintes de mémoire peuvent être inspectées avec AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Paramètres de traçage"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Fichiers enregistrés"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Divers"</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index e843d27e..6d1484e2 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Enregistrer l\'empreinte de la mémoire"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Capture une empreinte de la mémoire parmi les processus sélectionnés dans \"Processus de l\'empreinte de la mémoire\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Pour collecter des empreintes de la mémoire, sélectionnez au moins un processus dans \"Processus de l\'empreinte de la mémoire\""</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Enregistrer l\'empreinte de la mémoire d\'AM avec des bitmaps"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Collecte une empreinte de la mémoire du processus sélectionné dans \"Processus de l\'empreinte de la mémoire\" et extrait des images bitmap"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Sélectionnez un seul processus dans \"Processus de l\'empreinte de la mémoire\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Sélectionnez un processus dans \"Processus de l\'empreinte de la mémoire\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collecter les traces Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Comprend les données télémétriques détaillées de l\'UI (peut causer des à-coups)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Tracer les applications pouvant être déboguées"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Par défaut"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# sélectionnée}one{# sélectionnée}other{# sélectionnées}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Processus de l\'empreinte de la mémoire"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Vous devez sélectionner au moins un processus"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Ces sélections s\'appliquent à la fois à Perfetto et à ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Supprimer les processus de l\'empreinte de la mémoire"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Liste des processus effacée"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Profil du tas continu"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Capturer une empreinte de la mémoire à chaque intervalle spécifié"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Capturez une empreinte de la mémoire à chaque intervalle spécifié. S\'applique uniquement aux empreintes de la mémoire de Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Intervalle de l\'empreinte de la mémoire"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 secondes"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 secondes"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Appuyez pour arrêter l\'échantillonnage de pile"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"L\'empreinte de la mémoire est en cours d\'enregistrement"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Appuyez pour arrêter l\'enregistrement de l\'empreinte de la mémoire"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"L\'empreinte de la mémoire d\'AM est en cours d\'enregistrement"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Effacer les fichiers enregistrés"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Les enregistrements sont effacés après un mois"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Effacer les fichiers enregistrés ?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Tous les enregistrements seront supprimés de /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Effacer"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Traces du système"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, trace, performances"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, trace, traçage, performances, profil, profilage, processeur, pile d\'appels, pile, tas de mémoire"</string>
     <string name="share_file" msgid="1982029143280382271">"Partager le fichier ?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Les fichiers de traçage système peuvent inclure des données sensibles sur le système et les applications (telles que la consommation par application). Nous vous recommandons de ne partager des traces système qu\'avec des personnes et des applications que vous estimez fiables."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Les fichiers de traçage système peuvent inclure des données sensibles sur le système et les applis (comme l\'utilisation des applis ou les images stockées dans la mémoire des applis). Ne partagez les traces système ou les empreintes de la mémoire qu\'avec des personnes et des applis de confiance."</string>
     <string name="share" msgid="8443979083706282338">"Partager"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Ne plus afficher"</string>
     <string name="long_traces" msgid="5110949471775966329">"Traces allongées"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Joindre les enregistrements aux rapports de bug"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Envoyer automatiquement les enregistrements en cours à BetterBug lorsqu\'un rapport de bug est collecté. Les enregistrements se poursuivront par la suite."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Afficher les fichiers enregistrés"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Les traces peuvent être importées sur ui.perfetto.dev pour analyse"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Les empreintes de la mémoire peuvent être inspectées avec AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Paramètres de traçage"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Fichiers enregistrés"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Divers"</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 6456916e..3f44250a 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -4,12 +4,16 @@
     <string name="system_tracing" msgid="4719188511746319848">"Seguimento do sistema"</string>
     <string name="record_system_activity" msgid="4339462312915377825">"Rexistra a actividade do sistema e analízaa máis tarde para mellorar o rendemento"</string>
     <string name="record_trace" msgid="6416875085186661845">"Rexistrar rastro"</string>
-    <string name="record_trace_summary" msgid="6705357754827849292">"Captura un rastro do sistema usando as opcións definidas en Configuración de rastro"</string>
+    <string name="record_trace_summary" msgid="6705357754827849292">"Captura un rastro do sistema usando as opcións definidas en Configuración de rastros"</string>
     <string name="record_stack_samples" msgid="3498368637185702335">"Gravar perfil da CPU"</string>
     <string name="record_stack_samples_summary" msgid="7827953921526410478">"Tamén podes activar a toma de mostras de pilas de chamadas nos rastros seleccionando a categoría CPU"</string>
     <string name="record_heap_dump" msgid="1688550222066812696">"Gravar baleirado da zona de memoria dinámica"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captura un baleirado da zona de memoria dinámica dos procesos seleccionados en Procesos de baleirado da zona de memoria dinámica"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Para recompilar baleirados, selecciona polo menos un proceso en Procesos de baleirado da zona de memoria dinámica"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Gravar baleirado da zona de memoria dinámica de AM con mapas de bits"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Recompila un baleirado da zona de memoria dinámica do proceso seleccionado en Procesos de baleirado da zona de memoria dinámica e extrae as imaxes dos mapas de bits"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Selecciona só un proceso en Procesos de baleirado da zona de memoria dinámica"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Selecciona un proceso en Procesos de baleirado da zona de memoria dinámica"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Recompilar rastros de Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inclúe datos telemétricos detallados da IU (pode diminuír a velocidade de resposta)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Gardar rastros de aplicacións que se poidan depurar"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Categorías predeterminadas"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# seleccionada}other{# seleccionadas}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Procesos de baleirado da zona de memoria dinámica"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Cómpre seleccionar polo menos un proceso"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Esta selección aplicarase tanto a Perfetto como a ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Borrar procesos de baleirado da zona de memoria dinámica"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Borrouse a lista de procesos"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Perfil do baleirado continuo da zona de memoria dinámica"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Captura un baleirado da zona de memoria dinámica cada intervalo especificado"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Captura un baleirado da zona de memoria dinámica cada intervalo especificado. Só se aplicará aos baleirados da zona de memoria dinámica de Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Intervalo do baleirado da zona de memoria dinámica"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 segundos"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 segundos"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Toca para deter a toma de mostras de pillas"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Estase gravando o baleirado da zona de memoria dinámica"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Toca para deter o baleirado da zona de memoria dinámica"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Estase gravando o baleirado da zona de memoria dinámica de AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Borrar ficheiros gardados"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"As gravacións bórranse ao cabo dun mes"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Queres borrar os ficheiros gardados?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Eliminaranse todas as gravacións de /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Borrar"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Rastros do sistema"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, rastro, rendemento"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, rastrexo, rastrexar, rendemento, perfil, elaboración de perfís, cpu, pilla de chamadas, pilla, estrutura de datos"</string>
     <string name="share_file" msgid="1982029143280382271">"Queres compartir o ficheiro?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Os ficheiros de rastro do sistema poden incluír datos sensibles sobre o sistema e as aplicacións (como o uso das aplicacións). Comparte os rastros do sistema con persoas e aplicacións de confianza."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"É posible que os ficheiros de rastro do sistema inclúan datos confidenciais sobre o sistema e as aplicacións (como o uso das aplicacións ou imaxes da memoria dunha aplicación). Comparte os rastros do sistema con persoas e aplicacións de confianza."</string>
     <string name="share" msgid="8443979083706282338">"Compartir"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Non mostrar outra vez"</string>
     <string name="long_traces" msgid="5110949471775966329">"Rastros longos"</string>
@@ -87,7 +92,11 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Anexar gravacións aos informes de erros"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Envía automaticamente rexistros de gravacións en curso a BetterBug cando se recompile un informe de erros. As gravacións continuarán tendo lugar despois."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Ver ficheiros gardados"</string>
-    <string name="pref_category_trace_settings" msgid="6507535407023329628">"Configuración de rastro"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Pódense cargar rastros en ui.perfetto.dev para analizar"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Os baleirados da zona de memoria dinámica pódense inspeccionar con AHAT"</string>
+    <string name="pref_category_trace_settings" msgid="6507535407023329628">"Configuración de rastros"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Ficheiros gardados"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Outras opcións"</string>
     <string name="pref_category_heap_dump_settings" msgid="2234681064312605310">"Configuración do baleirado da zona de memoria dinámica"</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 262e5555..30f85264 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -1,8 +1,8 @@
 <?xml version="1.0" encoding="UTF-8"?>
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="system_tracing" msgid="4719188511746319848">"સિસ્ટમ ટ્રેસ કરી રહ્યાં છીએ"</string>
-    <string name="record_system_activity" msgid="4339462312915377825">"સિસ્ટમ પ્રવૃત્તિને રેકોર્ડ કરો અને પર્ફોર્મન્સને બહેતર બનાવવા માટે થોડા સમય પછી તેનું વિશ્લેષણ કરો"</string>
+    <string name="system_tracing" msgid="4719188511746319848">"System Tracing"</string>
+    <string name="record_system_activity" msgid="4339462312915377825">"સિસ્ટમ ઍક્ટિવિટીને રેકોર્ડ કરો અને પર્ફોર્મન્સને બહેતર બનાવવા માટે થોડા સમય પછી તેનું વિશ્લેષણ કરો"</string>
     <string name="record_trace" msgid="6416875085186661845">"ટ્રેસને રેકોર્ડ કરો"</string>
     <string name="record_trace_summary" msgid="6705357754827849292">"\"ટ્રેસ સેટિંગ\"માં સેટ કરેલા કન્ફિગ્યુરેશન વડે કોઈ સિસ્ટમ ટ્રેસને કૅપ્ચર કરે છે"</string>
     <string name="record_stack_samples" msgid="3498368637185702335">"CPUની પ્રોફાઇલ રેકોર્ડ કરો"</string>
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"હીપ ડમ્પ રેકોર્ડ કરો"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"હીપ ડમ્પની પ્રક્રિયાઓ\"માંથી પસંદ કરવામાં આવેલી પ્રક્રિયાઓના હીપ ડમ્પને કૅપ્ચર કરે છે"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"હીપ ડમ્પ એકત્રિત કરવા માટે, \"હીપ ડમ્પની પ્રક્રિયાઓ\"માં ઓછામાં ઓછી એક પ્રક્રિયા પસંદ કરો"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"AM હીપ ડમ્પને બિટમૅપ વડે રેકોર્ડ કરો"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"હીપ ડમ્પની પ્રક્રિયાઓ\"માં પસંદ કરેલી પ્રક્રિયાના હીપ ડમ્પને એકત્રિત કરે છે અને બિટમૅપ છબીઓને એક્સટ્રેક્ટ કરે છે"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"હીપ ડમ્પની પ્રક્રિયાઓ\"માં ફક્ત એક પ્રક્રિયા પસંદ કરો"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"હીપ ડમ્પની પ્રક્રિયાઓ\"માં એક પ્રક્રિયા પસંદ કરો"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope ટ્રેસ એકત્રિત કરો"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"વિગતવાર UI ટેલિમિટ્રિ ડેટાનો સમાવેશ થાય છે (જંકનું કારણ બની શકે છે)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ડિબગ કરી શકાય તેવી ઍપ્લિકેશનોને ટ્રેસ કરો"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ડિફૉલ્ટ"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# પસંદ કરી}one{# પસંદ કરી}other{# પસંદ કરી}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"હીપ ડમ્પની પ્રક્રિયાઓ"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"ઓછામાં ઓછી એક પ્રક્રિયા પસંદ કરવી આવશ્યક છે"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"આ પસંદગીઓ Perfetto અને ActivityManager બંને પર લાગુ થાય છે"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"હીપ ડમ્પની પ્રક્રિયાઓ સાફ કરો"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"પ્રક્રિયાની સૂચિ સાફ કરવામાં આવી"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"સતત ચાલુ રહેતી હીપ પ્રોફાઇલ"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"ઉલ્લેખિત ઇન્ટરવલ દીઠ એકવાર હીપ ડમ્પ કૅપ્ચર કરો"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"ઉલ્લેખિત ઇન્ટરવલ દીઠ એકવાર હીપ ડમ્પ કૅપ્ચર કરો. ફક્ત Perfetto હીપ ડમ્પ પર લાગુ થાય છે."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"હીપ ડમ્પ ઇન્ટરવલ"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 સેકન્ડ"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 સેકન્ડ"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"સ્ટૅક સેમ્પલિંગ રોકવા માટે ટૅપ કરો"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"હીપ ડમ્પનું રેકોર્ડિંગ કરવામાં આવી રહ્યું છે"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"હીપ ડમ્પને રોકવા માટે ટૅપ કરો"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM હીપ ડમ્પ રેકોર્ડ કરવામાં આવી રહ્યો છે"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"સાચવેલી ફાઇલો સાફ કરો"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"રેકોર્ડિંગને એક મહિના પછી સાફ કરવામાં આવે છે"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"શું સાચવેલી ફાઇલો સાફ કરીએ?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"તમામ રેકોર્ડિંગને /data/local/tracesમાંથી ડિલીટ કરવામાં આવશે"</string>
     <string name="clear" msgid="5484761795406948056">"સાફ કરો"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"સિસ્ટમ ટ્રેસ"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, ટ્રેસ, કાર્યપ્રદર્શન"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ટ્રેસ, ટ્રેસિંગ, પર્ફોર્મન્સ, પ્રોફાઇલ, પ્રોફાઇલ બનાવવાની સુવિધા, cpu, કૉલસ્ટૅક, સ્ટૅક, હીપ"</string>
     <string name="share_file" msgid="1982029143280382271">"શું ફાઇલ શેર કરીએ?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"સિસ્ટમ ટ્રેસ કરવાની ફાઇલોમાં સંવેદનશીલ સિસ્ટમ અને ઍપ ડેટા (જેમ કે ઍપ વપરાશ) શામેલ હોઈ શકે છે. તમે વિશ્વાસ કરો છો માત્ર તે લોકો અને ઍપ સાથે જ સિસ્ટમ ટ્રેસ શેર કરો."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"સિસ્ટમ ટ્રેસ કરવાની ફાઇલોમાં સંવેદનશીલ સિસ્ટમ અને ઍપનો ડેટા (જેમ કે ઍપનો વપરાશ અથવા ઍપની મેમરીમાં રહેલી છબીઓ) શામેલ હોઈ શકે છે. સિસ્ટમ ટ્રેસ અથવા હીપ ડમ્પને ફક્ત તમે વિશ્વાસ કરતા હો તે લોકો અને ઍપ સાથે જ શેર કરો."</string>
     <string name="share" msgid="8443979083706282338">"શેર કરો"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"ફરી બતાવશો નહીં"</string>
     <string name="long_traces" msgid="5110949471775966329">"લાંબા ટ્રેસ"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"બગ રિપોર્ટમાં રેકોર્ડિંગને જોડો"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"જ્યારે કોઈ બગ રિપોર્ટ એકત્રિત કરવામાં આવે, ત્યારે BetterBugને ચાલુ પ્રક્રિયાના રેકોર્ડિંગ ઑટોમૅટિક રીતે મોકલો. રેકોર્ડિંગની પ્રક્રિયા પછીથી ચાલુ રહેશે."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"સાચવેલી ફાઇલો જુઓ"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"ટ્રેસને વિશ્લેષણ માટે ui.perfetto.dev પર અપલોડ કરી શકાય છે"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"હીપ ડમ્પનું નિરીક્ષણ AHAT વડે કરી શકાય છે"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ટ્રેસિંગ સંબંધી સેટિંગ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"સાચવેલી ફાઇલો"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"વિવિધ"</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index ed2da99e..55c92055 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -4,14 +4,18 @@
     <string name="system_tracing" msgid="4719188511746319848">"सिस्टम ट्रेस करने वाला टूल"</string>
     <string name="record_system_activity" msgid="4339462312915377825">"यह सिस्टम की गतिविधि रिकॉर्ड करता है और परफ़ॉर्मेंस बेहतर बनाने के लिए, बाद में इसका विश्लेषण करता है"</string>
     <string name="record_trace" msgid="6416875085186661845">"ट्रेस रिकॉर्ड करें"</string>
-    <string name="record_trace_summary" msgid="6705357754827849292">"\"ट्रेस सेटिंग\" में सेट किए गए कॉन्फ़िगरेशन की मदद से, सिस्टम ट्रेस करने की प्रक्रिया कैप्चर करें"</string>
+    <string name="record_trace_summary" msgid="6705357754827849292">"\"ट्रेस करने से जुड़ी सेटिंग\" में सेट किए गए कॉन्फ़िगरेशन की मदद से, सिस्टम के ट्रेस को रिकॉर्ड करता है"</string>
     <string name="record_stack_samples" msgid="3498368637185702335">"सीपीयू प्रोफ़ाइल रिकॉर्ड करें"</string>
     <string name="record_stack_samples_summary" msgid="7827953921526410478">"ट्रेस में जाकर \"सीपीयू\" कैटगरी को चुनकर, कॉलस्टैक सैंपलिंग चालू की जा सकती है"</string>
     <string name="record_heap_dump" msgid="1688550222066812696">"हीप डंप को रिकॉर्ड करें"</string>
-    <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"हीप डंप की प्रोसेस\" में चुनी गई प्रोसेस के हीप डंप को कैप्चर करें"</string>
+    <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"इससे \"हीप डंप की प्रोसेस\" में चुनी गई प्रोसेस के हीप डंप को रिकॉर्ड करने में मदद मिलती है"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"हीप डंप को इकट्ठा करने के लिए \"हीप डंप की प्रोसेस\" में कम से कम एक प्रोसेस चुनें"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"बिट मैप की मदद से, AM का हीप डंप रिकॉर्ड करें"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"इससे \"हीप डंप की प्रोसेस\" में चुनी गई प्रोसेस का हीप डंप इकट्ठा करने और बिटमैप इमेज को निकालने में मदद मिलती है"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"हीप डंप की प्रोसेस\" में जाकर सिर्फ़ एक प्रोसेस को चुनें"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"हीप डंप की प्रोसेस\" में जाकर कोई प्रोसेस चुनें"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"WinScope के ट्रेस इकट्ठा करें"</string>
-    <string name="winscope_tracing_summary" msgid="7040550156722395894">"इसमें यूज़र इंटरफ़ेस से जुड़ा टेलीमेट्री डेटा शामिल है (इससे जैंक होने की संभावना है)"</string>
+    <string name="winscope_tracing_summary" msgid="7040550156722395894">"इसमें यूज़र इंटरफ़ेस से जुड़ा टेलीमेट्री डेटा शामिल है (इससे जैंक होने की संभावना रहती है)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"डीबग करने के लिए ऐप्लिकेशन ट्रेस करें"</string>
     <string name="categories" msgid="2280163673538611008">"कैटगरी"</string>
     <string name="restore_default_categories" msgid="5090536794637169521">"डिफ़ॉल्ट श्रेणियां बहाल करें"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"डिफ़ॉल्ट"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# चुनी गई}one{# चुनी गई}other{# चुनी गईं}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"हीप डंप की प्रोसेस"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"कम से कम एक प्रोसेस को चुनें"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"ये सेटिंग, Perfetto और ActivityManager, दोनों पर लागू होती हैं"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"हीप डंप की प्रोसेस मिटाएं"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"प्रोसेस की सूची मिटाई गई"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"हीप प्रोफ़ाइल को जारी रखें"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"किसी खास इंटरवल के लिए एक बार हीप डंप को कैप्चर करें"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"किसी खास इंटरवल के लिए एक बार हीप डंप को कैप्चर करें. यह सेटिंग सिर्फ़ Perfetto के हीप डंप पर लागू होती है."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"हीप डंप इंटरवल"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 सेकंड"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 सेकंड"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"स्टैक सैंपलिंग रोकने के लिए टैप करें"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"हीप डंप को रिकॉर्ड किया जा रहा है"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"हीप डंप को रोकने के लिए टैप करें"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM के हीप डंप को रिकॉर्ड किया जा रहा है"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"सेव की गई फ़ाइलें मिटाएं"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"एक महीने के बाद रिकॉर्डिंग मिट जाती हैं"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"क्या आपको सेव की गई फ़ाइलें मिटानी हैं?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces से सभी रिकॉर्डिंग मिटा दिए जाएंगे"</string>
     <string name="clear" msgid="5484761795406948056">"मिटाएं"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"सिस्टम ट्रेस"</string>
-    <string name="keywords" msgid="736547007949049535">"सिसट्रेस, ट्रेस, परफ़ॉर्मेंस"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ट्रेस, ट्रेसिंग, परफ़ॉर्मेंस, प्रोफ़ाइल, प्रोफ़ाइलिंग, सीपीयू, कॉलस्टैक, स्टैक, हीप"</string>
     <string name="share_file" msgid="1982029143280382271">"क्या आपको फ़ाइल शेयर करनी है?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"सिस्टम ट्रेसिंग फ़ाइलों में संवेदनशील सिस्टम और ऐप्लिकेशन डेटा (जैसे कि ऐप्लिकेशन का इस्तेमाल) शामिल हो सकता है. सिस्टम ट्रेस उन्हीं लोगों और ऐप्लिकेशन से शेयर करें जिन पर आपको भरोसा है."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"सिस्टम ट्रेस करने से जुड़ी फ़ाइलों में, सिस्टम और ऐप्लिकेशन का संवेदनशील डेटा शामिल हो सकता है. जैसे, ऐप्लिकेशन के इस्तेमाल या उसकी मेमोरी में मौजूद इमेज का डेटा. सिस्टम ट्रेस करने की प्रोसेस या हीप डंप, सिर्फ़ उन लोगों और ऐप्लिकेशन के साथ शेयर करें जिन पर आपको भरोसा है."</string>
     <string name="share" msgid="8443979083706282338">"शेयर करें"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"फिर से न दिखाएं"</string>
     <string name="long_traces" msgid="5110949471775966329">"लंबे ट्रेस"</string>
@@ -87,7 +92,11 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"रिकॉर्डिंग को गड़बड़ी की रिपोर्ट में अटैच करें"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"गड़बड़ी की रिपोर्ट मिलने पर, BetterBug को पहले से चल रही रिकॉर्डिंग अपने-आप भेजी जाती हैं. रिकॉर्डिंग बाद में भी जारी रहेंगी."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"सेव की गई फ़ाइलें देखें"</string>
-    <string name="pref_category_trace_settings" msgid="6507535407023329628">"ट्रेस करने की सेटिंग"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"विश्लेषण करने के लिए, ट्रेस को ui.perfetto.dev पर अपलोड किया जा सकता है"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"AHAT की मदद से हीप डंप की जांच की जा सकती है"</string>
+    <string name="pref_category_trace_settings" msgid="6507535407023329628">"ट्रेस करने से जुड़ी सेटिंग"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"सेव की गई फ़ाइलें"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"अन्य विकल्प"</string>
     <string name="pref_category_heap_dump_settings" msgid="2234681064312605310">"हीप डंप की सेटिंग"</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index 7ace7cdd..d0311496 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -2,7 +2,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="system_tracing" msgid="4719188511746319848">"Praćenje sustava"</string>
-    <string name="record_system_activity" msgid="4339462312915377825">"Bilježenje aktivnosti sustava i njihova analiza radi poboljšanja izvedbe"</string>
+    <string name="record_system_activity" msgid="4339462312915377825">"Taj alat bilježi aktivnosti sustava i naknadno ih analizira radi poboljšanja izvedbe"</string>
     <string name="record_trace" msgid="6416875085186661845">"Snimanje traga"</string>
     <string name="record_trace_summary" msgid="6705357754827849292">"Snima trag sustava pomoću konfiguracije u postavkama traga"</string>
     <string name="record_stack_samples" msgid="3498368637185702335">"Snimanje profila procesora"</string>
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Izrada snimke memorije procesa"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Izrađuje snimku memorije procesa za procese koji su odabrani u procesima snimke memorije procesa"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Odaberite barem jedan proces u procesima snimke memorije procesa da biste prikupili snimke memorije procesa"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Izradi snimku memorije procesa aplikacije AM s bitmapama"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Prikuplja snimku memorije procesa koji je odabran u procesima snimke memorije procesa i izdvaja slike bitmape"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Odaberite samo jedan proces u procesima snimke memorije procesa"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Odaberite proces u procesima snimke memorije procesa"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Prikupljanje Winscope tragova"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Uključuje detaljne telemetrijske podatke korisničkog sučelja (može uzrokovati zastoj)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Prati aplikacije iz kojih se mogu uklanjati pogreške"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Zadano"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# odabrana}one{# odabrana}few{# odabrane}other{# odabrano}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Procesi snimke memorije procesa"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Mora biti odabran najmanje jedan proces"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Ti se odabiri primjenjuju na Perfetto i ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Izbriši procese snimke memorije procesa"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Popis procesa je izbrisan"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Profil gomile podataka – trajni"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Napravite snimku memorije procesa jednom u određenom intervalu"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Izradite snimku memorije procesa jednom po navedenom intervalu. Primjenjuje se samo na snimke memorije procesa aplikacije Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Profil gomile podataka – interval"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekundi"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekundi"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Dodirnite da biste zaustavili uzorkovanje snopa"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"U tijeku je izrada snimke memorije procesa"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Dodirnite da biste zaustavili snimku memorije procesa"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"U tijeku je izrada snimke memorije procesa aplikacije AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Izbriši spremljene datoteke"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Snimke se brišu nakon mjesec dana"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Želite li izbrisati spremljene datoteke?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Izbrisat će se svi tragovi iz /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Ukloni"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Praćenja sustava"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, praćenje, izvedba"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, prati, praćenje, izvedba, profil, profiliranje, procesor, stog poziva, fiksna memorija, dinamička memorija"</string>
     <string name="share_file" msgid="1982029143280382271">"Želite li podijeliti datoteku?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Datoteke praćenja sustava mogu sadržavati osjetljive podatke o sustavu i aplikacijama (na primjer o upotrebi aplikacija). Praćenja sustava dijelite samo s osobama i aplikacijama koje smatrate pouzdanima."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Datoteke praćenja sustava mogu sadržavati osjetljive podatke sustava i aplikacije (na primjer upotrebu aplikacije ili slike u memoriji aplikacije). Praćenja sustava ili snimke memorije procesa dijelite samo s pouzdanim aplikacijama i osobama."</string>
     <string name="share" msgid="8443979083706282338">"Dijeli"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Ne prikazuj ponovo"</string>
     <string name="long_traces" msgid="5110949471775966329">"Duga praćenja"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Priloži snimke izvješćima o programskim pogreškama"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatski pošaljite BetterBugu snimke u tijeku kad se prikupi izvješće o programskoj pogrešci. Snimanje će se nastaviti kasnije."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Prikaz spremljenih datoteka"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Praćenja se mogu prenijeti na ui.perfetto.dev radi analize"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Snimke memorije procesa mogu se pregledati pomoću AHAT-a"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Postavke praćenja"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Spremljene datoteke"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Razno"</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index de00d6f2..3c4878d1 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -2,7 +2,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="system_tracing" msgid="4719188511746319848">"Rendszerkövetés"</string>
-    <string name="record_system_activity" msgid="4339462312915377825">"Rögzítheti a rendszertevékenységeket, és később ellenőrizheti őket a teljesítmény javítása érdekében"</string>
+    <string name="record_system_activity" msgid="4339462312915377825">"Rögzítheti a rendszertevékenységeket, és később ellenőrizheti őket a teljesítmény javítása érdekében."</string>
     <string name="record_trace" msgid="6416875085186661845">"Nyom rögzítése"</string>
     <string name="record_trace_summary" msgid="6705357754827849292">"Rendszerkövetést rögzít a „Követési beállítások” menüpontban megadott konfiguráció használatával"</string>
     <string name="record_stack_samples" msgid="3498368637185702335">"CPU-profil rögzítése"</string>
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Halommemória-pillanatkép rögzítése"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Rögzíti a „Halommemória-pillanatkép folyamatai” lehetőségnél kijelölt folyamatokhoz tartozó halommemória-pillanatképet"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Halommemória-pillanatképek kijelöléséhez válasszon ki legalább egy folyamatot a „Halommemória-pillanatkép folyamatai” lehetőségnél"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"AM-halommemória-pillanatkép rögzítése bittérképekkel"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Halommemória-pillanatképet készít a „Halommemória-pillanatkép folyamatai” lehetőségnél kiválasztott folyamatról, és kinyer bittérképképeket"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Csak egy folyamatot válasszon ki a „Halommemória-pillanatkép folyamatai” lehetőségnél"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Válasszon ki egy folyamatot a „Halommemória-pillanatkép folyamatai” lehetőségnél"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Gyűjtsön Winscope-nyomokat"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Részletes UI telemetriai adatokat tartalmaz (akadozást okozhat)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Hibaelhárítást igénylő alkalmazások nyomon követése"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Alapértelmezett"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# kiválasztva}other{# kiválasztva}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Halommemória-pillanatkép folyamatai"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Legalább egy folyamatot ki kell jelölnie"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Ezek a választások a Perfetto és az ActivityManager esetében is érvényesek"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Halommemória-pillanatkép folyamatainak törlése"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Folyamatlista törölve"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Folyamatos memóriaprofil"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Halommemória-pillanatkép rögzítése a megadott időközönként egyszer"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Halommemória-pillanatkép rögzítése a megadott időközönként egyszer. Csak a Perfetto-halommemória-pillanatképekre vonatkozik."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Halommemória-pillanatkép időköze"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 másodperc"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 másodperc"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Koppintson a verem mintavételezésének leállításához"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"A halommemória-pillanatkép rögzítése folyamatban van"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Koppintson a halommemória-pillanatkép leállításához"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Az AM-halommemória-pillanatkép rögzítése folyamatban van"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Mentett fájlok törlése"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"A felvételek egy hónap után törlődnek"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Törli a mentett fájlokat?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Az összes felvétel törlődik a /data/local/traces mappából"</string>
     <string name="clear" msgid="5484761795406948056">"Törlés"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Rendszerkövetési információk"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, követés, teljesítmény"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, nyom, nyomkövetés, teljesítmény, profil, profilalkotás, cpu, hívásverem, verem, memória"</string>
     <string name="share_file" msgid="1982029143280382271">"Szeretné megosztani a fájlt?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"A rendszerkövetési fájlok bizalmas rendszer- és alkalmazásadatokat tartalmazhatnak (például az alkalmazáshasználatról). Csak megbízható személyekkel és alkalmazásokkal osszon meg rendszerkövetési információkat."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"A rendszerkövetési fájlok bizalmas rendszer- és alkalmazásadatokat tartalmazhatnak (például az alkalmazáshasználatról vagy az alkalmazás memóriájában lévő képekről). Csak megbízható személyekkel és alkalmazásokkal osszon meg rendszerkövetési információkat és halommemória-pillanatképeket."</string>
     <string name="share" msgid="8443979083706282338">"Megosztás"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Ne jelenjen meg többé"</string>
     <string name="long_traces" msgid="5110949471775966329">"Hosszú nyomkövetések"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Felvételek csatolása a hibajelentésekhez"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Folyamatban lévő felvételek automatikus küldése a BetterBugnak hibajelentés begyűjtésekor. Az elküldést követően folytatódnak a felvételek."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Mentett fájlok megtekintése"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"A nyomok elemzés céljából feltölthetők a ui.perfetto.dev webhelyre"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"A halommemória-pillanatképek az AHAT segítségével ellenőrizhetők"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Követési beállítások"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Mentett fájlok"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Egyéb"</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index ad2e6317..27920171 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Գրանցել գործընթացի դինամիկ հիշողության տվյալները"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Գրանցում է գործընթացների դինամիկ հիշողության տվյալները, որոնք ընտրվել են «Դինամիկ հիշողության տվյալների գործընթացներ» բաժնում"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Գործընթացի դինամիկ հիշողության տվյալները հավաքելու համար ընտրեք առնվազն մեկ գործընթաց «Դինամիկ հիշողության տվյալների գործընթացներ» բաժնում"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Գրանցել AM հավելվածի գործընթացի դինամիկ հիշողության տվյալները Bitmap ձևաչափով"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Հավաքում է ընտրված գործընթացի դինամիկ հիշողության տվյալները «Դինամիկ հիշողության տվյալների գործընթացներ» բաժնում և արտածում է Bitmap պատկերներ"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Ընտրեք միայն մեկ գործընթաց «Դինամիկ հիշողության տվյալների գործընթացներ» բաժնում"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Ընտրեք գործընթաց «Դինամիկ հիշողության տվյալների գործընթացներ» բաժնում"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Հավաքել Winscope-ի հետագծումները"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Ներառում է հեռուստամետրիայի միջերեսային մանրամասն տվյալներ (կարող է աղբ ավելացնել)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Հետագծել վրիպազերծման ենթակա հավելվածները"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Կանխադրված"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Ընտրվել է # կատեգորիա}one{Ընտրվել է # կատեգորիա}other{Ընտրվել է # կատեգորիա}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Դինամիկ հիշողության տվյալների գործընթացներ"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Առնվազն մեկ գործընթաց պետք է ընտրված լինի"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Այս ընտրությունը կիրառվում է Perfetto և ActivityManager հավելվածների համար"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Մաքրել դինամիկ հիշողության տվյալների գործընթացները"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Գործընթացների ցանկը մաքրվեց"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Շարունակական դինամիկ հիշողության պրոֆիլ"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Գրանցել գործընթացի դինամիկ հիշողության տվյալները ժամանակային որոշակի միջակայքերով պարբերականությամբ"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Գրանցել գործընթացի դինամիկ հիշողության տվյալները ժամանակային որոշակի միջակայքերով պարբերականությամբ։ Կիրառվում է միայն Perfetto հավելվածի գործընթացի դինամիկ հիշողության տվյալների համար։"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"գործընթացի դինամիկ հիշողության տվյալների միջակայքը"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 վայրկյան"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 վայրկյան"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Հպեք՝ սթեքի նմուշների ստեղծումը կանգնեցնելու համար"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Գործընթացի դինամիկ հիշողության տվյալները գրանցվում են"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Հպեք՝ գործընթացի դինամիկ հիշողության տվյալների գրանցումը կանգնեցնելու համար"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM հավելվածի գործընթացի դինամիկ հիշողության տվյալները գրանցվում են"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Մաքրել պահված ֆայլերը"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Գրանցումները մեկ ամիս անց մաքրվում են"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Մաքրե՞լ պահված ֆայլերը"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Բոլոր գրանցումները /data/local/traces պանակից կջնջվեն"</string>
     <string name="clear" msgid="5484761795406948056">"Ջնջել"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Համակարգի հետագծման ֆայլեր"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, հետագծում, արդյունավետություն"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, հետագծել, հետագծում, արտադրողականություն, պրոֆիլ, պրոֆիլավորում, cpu, կանչերի սթեք, խմբավորում, դինամիկ հիշողություն"</string>
     <string name="share_file" msgid="1982029143280382271">"Կիսվե՞լ ֆայլով"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Հետագծման ֆայլերը տրամադրեք միայն վստահելի մարդկանց և հավելվածներին, քանի որ դրանք կարող են պարունակել համակարգի և հավելվածի մասին գաղտնի տեղեկություններ (օրինակ՝ տվյալներ հավելվածի օգտագործման մասին):"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Համակարգի հետագծման ֆայլերը կարող են պարունակել համակարգի և հավելվածի մասին գաղտնի տեղեկություններ (օրինակ՝ տվյալներ հավելվածի օգտագործման մասին կամ պատկերներ հավելվածի հիշողության մեջ)։ Համակարգի հետագծման կամ գործընթացի դինամիկ հիշողության տվյալներով կիսվեք միայն վստահելի մարդկանց և հավելվածների հետ։"</string>
     <string name="share" msgid="8443979083706282338">"Ուղարկել"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Այլևս ցույց չտալ"</string>
     <string name="long_traces" msgid="5110949471775966329">"Երկար հետագծումներ"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Գրանցումները կցել վրիպակների մասին հաղորդումներին"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Ավտոմատ ուղարկել ընթացիկ ձայնագրությունները BetterBug-ին, երբ վրիպակի մասին հաղորդում է ստեղծվում։ Որից հետո ձայնագրությունները կշարունակվեն։"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Դիտել պահված ֆայլերը"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Հետագծերը վերլուծելու համար կարող եք դրանք վերբեռնել ui.perfetto.dev կայք"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Գործընթացի դինամիկ հիշողության տվյալները կարելի է ստանալ AHAT-ի միջոցով"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Հետագծման կարգավորումներ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Պահված ֆայլեր"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Այլ"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index d3db2bb8..a41d08cf 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Rekam heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Merekam proses heap dump yang dipilih di \"Proses heap dump\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Pilih minimal satu proses di \"Proses heap dump\" untuk mengumpulkan heap dump"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Rekam heap dump AM dengan bitmap"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Mengumpulkan heap dump dari proses yang dipilih di \"Proses heap dump\" dan mengekstrak gambar bitmap"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Pilih hanya satu proses di \"Proses heap dump\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Pilih proses di \"Proses heap dump\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Kumpulkan rekaman aktivitas Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Menyertakan data telemetri UI yang mendetail (dapat menyebabkan jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Lacak aplikasi yang dapat di-debug"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Default"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# dipilih}other{# dipilih}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Proses heap dump"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Minimal satu proses harus dipilih"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Pilihan ini berlaku untuk Perfetto dan ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Hapus proses heap dump"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Daftar proses dihapus"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Profil heap berkelanjutan"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Merekam heap dump sekali per interval yang ditentukan"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Merekam heap dump sekali per interval yang ditentukan. Hanya berlaku untuk dump heap Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Interval heap dump"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 detik"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 detik"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Ketuk untuk menghentikan pengambilan sampel stack"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Heap dump sedang direkam"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Ketuk untuk menghentikan heap dump"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Heap dump AM sedang direkam"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Hapus file tersimpan"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Rekaman dihapus setelah satu bulan"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Hapus file tersimpan?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Semua rekaman akan dihapus dari /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Hapus"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Rekaman aktivitas sistem"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, jejak, performa"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, rekaman aktivitas, perekaman aktivitas, performa, profil, pembuatan profil, cpu, callstack, stack, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Bagikan file?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"File System Tracing dapat mencakup data sistem dan aplikasi yang sensitif (seperti penggunaan aplikasi). Bagikan rekaman aktivitas sistem hanya kepada orang dan aplikasi yang Anda percayai."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"File Pelacakan Sistem mungkin menyertakan data sistem dan aplikasi yang sensitif (seperti penggunaan aplikasi atau gambar di memori aplikasi). Hanya bagikan rekaman aktivitas sistem atau head dump kepada orang dan aplikasi yang Anda percayai."</string>
     <string name="share" msgid="8443979083706282338">"Bagikan"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Jangan tampilkan lagi"</string>
     <string name="long_traces" msgid="5110949471775966329">"Rekaman aktivitas panjang"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Lampirkan rekaman ke laporan bug"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Otomatis mengirim rekaman yang sedang berlangsung ke BetterBug saat laporan bug dikumpulkan. Rekaman akan dilanjutkan setelahnya."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Lihat file tersimpan"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Rekaman aktivitas dapat diupload ke ui.perfetto.dev untuk analisis"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Heap dump dapat diperiksa dengan AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Setelan perekaman aktivitas"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"File tersimpan"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Lain-lain"</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 846d935f..73268c1f 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Skrá minnisgögn"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Skáir minnisgögn úr þeirri úrvinnslu sem er valin í „Úrvinnsla minnisgagna“"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Veldu a.m.k. eina úrvinnslu í „Úrvinnsla minnisgagna“ til að safna minnisgögnum"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Taka AM-minnisgögn upp með punktamyndum"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Safnar minnisgögnum úrvinnslunnar sem valin er í „Úrvinnsla minnisgagna“ og dregur fram punktamyndir"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Veldu aðeins eina úrvinnslu í „Úrvinnsla minnisgagna“"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Veldu úrvinnslu í „Úrvinnsla minnisgagna“"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Safna Winscope-sporum"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inniheldur ítarleg fjarmælingargögn notendaviðmóts (getur valdið óstöðugleika)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Rekja forrit sem hægt er að villuleita"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Sjálfgefið"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Valið: #}one{Valið: #}other{Valið: #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Úrvinnsla minnisgagna"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Þú þarft að velja a.m.k. eina úrvinnslu"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Þessir valkostir gilda bæði um Perfetto og ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Eyða úrvinnslu minnisgagna"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Úrvinnslulista var eytt"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Samfelld minnisvöktun"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Skrá minnisgögn einu sinni á tilgreindu millibili"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Skrá minnisgögn einu sinni á tilgreindu millibili. Gildir aðeins um Perfetto-minnisgögn."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Millibil minnisgagna"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekúndur"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekúndur"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Ýttu til að stöðva staflasömplun"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Verið er að skrá minnisgögn"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Ýttu til að hætta að skrá minnisgögn"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Verið er að taka AM-minnisgögn upp"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Eyða vistuðum skrám"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Upptökum er eytt eftir einn mánuð"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Eyða vistuðum skrám?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Öllum upptökum verður eytt úr „/data/local/traces“"</string>
     <string name="clear" msgid="5484761795406948056">"Hreinsa"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Kerfisrakningar"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, rakning, afköst"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, spor, rakning, afköst, prófíll, vöktun, örgjörvi, ákallastafli, stafli, hrúga"</string>
     <string name="share_file" msgid="1982029143280382271">"Deila skrá?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Kerfisrakningarskrár kunna að innihalda viðkvæm kerfis- og forritagögn (t.d. forritanotkun). Deildu aðeins kerfisrakningum með fólki og forritum sem þú treystir."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Kerfisrakningarskrár kunna að innihalda viðkvæm kerfis- og forritagögn (t.d. forritanotkun eða myndir í minni forrits). Deildu kerfisrakningum eða minnisgögnum aðeins með fólki og forritum sem þú treystir."</string>
     <string name="share" msgid="8443979083706282338">"Deila"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Ekki sýna þetta aftur"</string>
     <string name="long_traces" msgid="5110949471775966329">"Langar rakningar"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Hengja upptökur við villutilkynningar"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Sendu annála sjálfkrafa til BetterBug þegar villutilkynning er skráð. Annálaskráning mun halda áfram að því loknu."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Skoða vistaðar skrár"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Hægt er að hlaða rakningu upp í ui.perfetto.dev til greiningar"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Hægt er að kanna minnisgögn með AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Rakningarstillingar"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Vistaðar skrár"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Ýmislegt"</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 38379a53..d39ca1b2 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Registra dump dell\'heap"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Acquisisce un dump dell\'heap dei processi selezionati in \"Processi dump dell\'heap\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Seleziona almeno un processo in \"Processi dump dell\'heap\" per raccogliere i dump dell\'heap"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Registra il dump dell\'heap di AM con bitmap"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Raccoglie un dump dell\'heap del processo selezionato in \"Processi dump dell\'heap\" ed estrae le immagini bitmap"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Seleziona un solo processo in \"Processi dump dell\'heap\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Seleziona un processo in \"Processi dump dell\'heap\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Raccogli tracce Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Include dati di telemetria dell\'UI dettagliati (può causare jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Monitora app di cui è possibile eseguire il debug"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Predefinite"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# categoria selezionata}other{# categorie selezionate}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Processi dump dell\'heap"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Seleziona almeno un processo"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Queste selezioni si applicano a Perfetto e ad ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Cancella i processi di dump dell\'heap"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Elenco di processi cancellato"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Profilo heap continuo"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Acquisisci un dump dell\'heap una volta per intervallo specificato"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Acquisisci un dump dell\'heap una volta per intervallo specificato. Si applica solo ai dump dell\'heap di Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Intervallo dump dell\'heap"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 secondi"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 secondi"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Tocca per interrompere il campionamento degli stack"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Il dump dell\'heap è in fase di registrazione"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Tocca per interrompere dump dell\'heap"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"È in corso la registrazione del dump dell\'heap di AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Cancella i file salvati"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Le registrazioni vengono cancellate dopo un mese"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Cancellare i file salvati?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Tutte le registrazioni verranno eliminate da /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Cancella"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Tracce di sistema"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, traccia, prestazioni"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, traccia, tracciamento, prestazioni, profilo, profilazione, cpu, stack di chiamate, stack, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Condividere il file?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"I file di Tracciamento del sistema potrebbero includere dati sensibili sul sistema e sulle app (ad esempio sull\'utilizzo delle app). Condividi le tracce di sistema soltanto con persone e app attendibili."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"I file di Tracciamento del sistema potrebbero includere dati sensibili di sistema e dell\'app (ad esempio dati sull\'uso dell\'app o le immagini nella memoria dell\'app). Condividi tracce del sistema o dump dell\'heap solo con persone e app di cui ti fidi."</string>
     <string name="share" msgid="8443979083706282338">"Condividi"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Non mostrare più"</string>
     <string name="long_traces" msgid="5110949471775966329">"Tracce lunghe"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Allega le registrazioni alle segnalazioni di bug"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Invia automaticamente le registrazioni in corso a BetterBug quando viene raccolta una segnalazione di bug. Le registrazioni continueranno in seguito."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Visualizza i file salvati"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Le tracce possono essere caricate su ui.perfetto.dev per l\'analisi"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"I dump dell\'heap possono essere esaminati con AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Impostazioni monitoraggio"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"File salvati"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Varie"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index b2f7078f..78e9a5b2 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -4,12 +4,16 @@
     <string name="system_tracing" msgid="4719188511746319848">"עקבות המערכת"</string>
     <string name="record_system_activity" msgid="4339462312915377825">"אפשר לתעד את פעילות המערכת ולנתח אותה מאוחר יותר כדי לשפר את הביצועים"</string>
     <string name="record_trace" msgid="6416875085186661845">"הקלטת מעקב"</string>
-    <string name="record_trace_summary" msgid="6705357754827849292">"הפונקציה מבצעת את תיעוד עקבות המערכת באמצעות התצורה שהוגדרה ב\'הגדרות נתוני המעקב\'"</string>
+    <string name="record_trace_summary" msgid="6705357754827849292">"הפונקציה מבצעת את תיעוד עקבות המערכת באמצעות התצורה שהוגדרה ב\"הגדרות נתוני המעקב\""</string>
     <string name="record_stack_samples" msgid="3498368637185702335">"‏הקלטה של כלי לניתוח ביצועי ה-CPU"</string>
-    <string name="record_stack_samples_summary" msgid="7827953921526410478">"‏ניתן גם להפעיל את דגימת ה-Callstack בנתוני המעקב באמצעות סימון הקטגוריה \'cpu\'"</string>
+    <string name="record_stack_samples_summary" msgid="7827953921526410478">"‏ניתן גם להפעיל את דגימת ה-Callstack בנתוני המעקב באמצעות סימון הקטגוריה \"cpu\""</string>
     <string name="record_heap_dump" msgid="1688550222066812696">"הקלטה של תמונת מצב של הזיכרון"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"תיעוד תמונת מצב של הזיכרון של התהליכים שנבחרו ב\'תהליכים של תמונת מצב של הזיכרון\'"</string>
-    <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"כדי לאסוף תמונת מצב של הזיכרון, צריך לבחור לפחות תהליך אחד ב\'תהליכים של תמונת מצב של הזיכרון\'"</string>
+    <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"כדי לאסוף תמונת מצב של הזיכרון, צריך לבחור לפחות תהליך אחד ב\"תהליכים של תמונת מצב של הזיכרון\""</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"‏הקלטת תמונת מצב של הזיכרון ב-AM עם מפת סיביות (bitmap)"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"‏המערכת אוספת תמונת מצב של הזיכרון של התהליך שנבחר ב\"תהליכי תמונת מצב של הזיכרון\", ומחלצת תמונות במפת סיביות (bitmap)"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"צריך לבחור תהליך אחד בלבד ב\"תהליכי תמונת מצב של הזיכרון\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"צריך לבחור תהליך ב\"תהליכי תמונת מצב של הזיכרון\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"‏איסוף עקבות Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"‏כולל נתונים טלמטריים מפורטים של ממשק המשתמש (יכול לגרום לבעיות בממשק (jank))"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ניהול מעקב אחר אפליקציות שניתן לנפות בהן באגים"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ברירת מחדל"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{נבחרה קטגוריה אחת}one{נבחרו # קטגוריות}two{נבחרו # קטגוריות}other{נבחרו # קטגוריות}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"תהליכים של תמונת מצב של הזיכרון"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"צריך לבחור תהליך אחד לפחות"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"‏האפשרויות שנבחרו רלוונטיות גם ל-Perfetto וגם ל-ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"מחיקת תהליכים של תמונת מצב של הזיכרון"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"רשימת התהליכים נמחקה"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"תמונת מצב רציפה של ערימה"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"צילום של תמונת מצב של הזיכרון פעם אחת במרווח ספציפי"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"‏המערכת מצלמת תמונת מצב של הזיכרון פעם אחת במרווח ספציפי. רלוונטי רק לתמונות מצב של הזיכרון ב-Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"מרווח של תמונת מצב של הזיכרון"</string>
     <string name="five_seconds" msgid="7018465440929299712">"‫5 שניות"</string>
     <string name="ten_seconds" msgid="863416601384309033">"‫10 שניות"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"אפשר ללחוץ כדי להפסיק לקבץ דגימות"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"מתבצעת הקלטה של תמונת מצב של הזיכרון"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"אפשר ללחוץ כדי לעצור את ההקלטה של תמונת המצב של הזיכרון"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"‏בתהליך הקלטה של תמונת המצב של הזיכרון ב-AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"ניקוי הקבצים שנשמרו"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ההקלטות נמחקות כעבור חודש"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"לנקות את הקבצים שנשמרו?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"‏כל נתוני ההקלטות יימחקו מ-‎/data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"ניקוי"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"נתוני מעקב של המערכת"</string>
-    <string name="keywords" msgid="736547007949049535">"‏systrace, מעקב, ביצועים"</string>
+    <string name="keywords" msgid="255681926397897100">"‏‫systrace,‏ traceur,‏ perfetto,‏ winscope, נתוני מעקב, מעקב, ביצוע, פרופיל, פרופיילינג, CPU, ‏Callstack, סטאק, ערימה (heap)"</string>
     <string name="share_file" msgid="1982029143280382271">"לשתף את הקובץ?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"קבצים של נתוני המעקב מהמערכת עשויים לכלול נתונים רגישים של המערכת ושל האפליקציה (למשל, נתוני שימוש באפליקציה). יש לשתף את נתוני המעקב של המערכת רק עם אנשים ואפליקציות שיש לך אמון בהם."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"קובצי עקבות המערכת עשויים לכלול נתונים רגישים של המערכת והאפליקציות (למשל שימוש באפליקציות או תמונות בזיכרון של אפליקציה). יש לשתף עקבות מערכת או תמונות מצב של הזיכרון רק עם אפליקציות ואנשים מהימנים."</string>
     <string name="share" msgid="8443979083706282338">"שיתוף"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"אני לא רוצה לראות זאת שוב"</string>
     <string name="long_traces" msgid="5110949471775966329">"מעקבים ארוכים"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"צירוף ההקלטות לדוחות איתור באגים"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"‏כשמתבצע איסוף של דוח על באג, אפשר לשלוח אוטומטית רישומי נתונים שלא הסתיימו אל BetterBug. הנתונים ימשיכו להירשם לאחר מכן."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"הצגת הקבצים שנשמרו"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"‏אפשר להעלות את נתוני המעקב אל ui.perfetto.dev כדי לנתח אותם"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"‏אפשר לבדוק את תמונות המצב של הזיכרון באמצעות AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"הגדרות איתור"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"קבצים שנשמרו"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"שונות"</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 1739e67c..8a6d407e 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ヒープダンプを記録"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"[ヒープダンプ プロセス] で選択されたプロセスのヒープダンプを取得します"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ヒープダンプを収集するには、[ヒープダンプ プロセス] でプロセスを 1 つ以上選択してください"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"ビットマップを使用して AM のヒープダンプを記録する"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"[ヒープダンプ プロセス] で選択されたプロセスのヒープダンプを収集し、ビットマップ画像を抽出します"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"[ヒープダンプ プロセス] でプロセスを 1 つだけ選択してください"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"[ヒープダンプ プロセス] でプロセスを選択してください"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope トレースを収集する"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"詳細な UI テレメトリー データを含める（ジャンクが発生することがあります）"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"デバッグ可能なアプリをトレース"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"デフォルト"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# 種類選択中}other{# 種類選択中}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"ヒープダンプ プロセス"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"プロセスを 1 つ以上選択してください"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"これらの選択内容は、Perfetto と ActivityManager の両方に適用されます"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"ヒープダンプ プロセスを消去"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"プロセスリストを消去しました"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"連続ヒープ プロファイル"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"指定した間隔おきに 1 回、ヒープダンプを取得します"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"指定した間隔ごとに 1 回、ヒープダンプを取得します。Perfetto ヒープダンプにのみ適用されます。"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"ヒープダンプ間隔"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 秒"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 秒"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"スタック サンプリングを終了するにはタップしてください"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"ヒープダンプを記録しています"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"タップするとヒープダンプが停止します"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM ヒープダンプを記録しています"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"保存したファイルを消去"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"記録は 1 か月後に消去されます"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"保存したファイルを消去しますか？"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces からすべての記録を削除します"</string>
     <string name="clear" msgid="5484761795406948056">"消去"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"システム トレース"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, トレース, パフォーマンス"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, トレース, トレーシング, パフォーマンス, プロファイル, プロファイリング, cpu, コールスタック, スタック, ヒープ"</string>
     <string name="share_file" msgid="1982029143280382271">"ファイルを共有しますか？"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"システム トレース ファイルには、他人に知られたくないシステムやアプリのデータ（アプリの使用状況など）が含まれている場合があります。システム トレースの共有は、信頼できる人やアプリとのみ行ってください。"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"システム トレース ファイルには、機密性の高いシステム情報やアプリデータ（アプリの使用状況やアプリのメモリ内の画像など）が含まれている可能性があります。システム トレースやヒープ ダンプの共有は、信頼できる人やアプリとのみ行ってください。"</string>
     <string name="share" msgid="8443979083706282338">"共有"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"次回から表示しない"</string>
     <string name="long_traces" msgid="5110949471775966329">"長期トレース"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"バグレポートに記録を添付する"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"バグレポートの収集時に、処理中の記録を BetterBug に自動的に送信します。その後も記録は継続されます。"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"保存したファイルを表示"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"トレースを ui.perfetto.dev にアップロードして分析できます"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"AHAT でヒープダンプを検査できます"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"トレース設定"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"保存したファイル"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"その他"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index 458eeb61..cbe64903 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"გროვის ამონაწერის ჩაწერა"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"„გროვის ამონაწერის პროცესებიდან“ არჩეული პროცესის გროვის ამონაწერის აღბეჭდვა"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"გროვის ამონაწერის შესაგროვებლად აირჩიეთ, სულ მცირე, ერთი პროცესი „გროვის ამონაწერის პროცესებიდან“"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"AM-ის გროვის ამონაწერის bitmaps-ით ჩაწერა"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"აგროვებს „გროვის ამონაწერის პროცესებიდან“ არჩეული პროცესის გროვის ამონაწერს და ამოიღებს bitmap სურათებს"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"„გროვის ამონაწერის პროცესებიდან“ აირჩიეთ მხოლოდ ერთი"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"„გროვის ამონაწერის პროცესებიდან“ აირჩიეთ პროცესი"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope-ის კვალის შეგროვება"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"შეიცავს მომხმარებლის ინტერფეისის ტელემეტრიის მონაცემებს (შეიძლება გამოიწვიოს შეფერხება)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"გამართვადი აპლიკაციების კვალის მიდევნება"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ნაგულისხმევი"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{არჩეულია #}other{არჩეულია #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"გროვის ამონაწერის პროცესები"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"არჩეული უნდა იყოს, სულ მცირე, ერთი პროცესი"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"ეს არჩევანი ვრცელდება Perfetto-სა და ActivityManager-ზე"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"გროვის ამონაწერის პროცესების გასუფთავება"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"პროცესების სია გასუფთავებულია"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"უწყვეტი გროვის პროფილი"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"გროვის ამონაწერის აღბეჭდვა მითითებულ ინტერვალში ერთხელ"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"გროვის ამონაწერის აღბეჭდვა მითითებულ ინტერვალში ერთხელ. ვრცელდება მხოლოდ Perfetto-ს გროვის ამონაწერებზე."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"გროვის ამონაწერის ინტერვალი"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 წამი"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 წამი"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"შეეხეთ დასტის ნიმუშების ჩაწერის შესაწყვეტად"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"მიმდინარეობს გროვის ამონაწერის ჩაწერა"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"შეეხეთ გროვის ამონაწერის შესაწყვეტად"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"მიმდინარეობს AM-ის გროვის ამონაწერის ჩაწერა"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"შენახული ფაილების ამოშლა"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ჩანაწერები სუფთავდება ერთი თვის შემდეგ"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"გსურთ შენახული ფაილების ამოშლა?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"ყველა ჩანაწერი წაიშლება აქედან: /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"გასუფთავება"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"სისტემის კვლები"</string>
-    <string name="keywords" msgid="736547007949049535">"სისტემის კვალი, კვალი, შესრულება"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, კვალი, კვალის დატოვება, ეფექტურობა, პროფილი, პროფილირება, CPU, გამოძახება, დასტა, გროვა"</string>
     <string name="share_file" msgid="1982029143280382271">"გსურთ ფაილის გაზიარება?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"სისტემის ტრასირების ფაილები შეიძლება შეიცავდეს სისტემისა და აპების სენსიტიურ მონაცემებს (როგორიცაა აპების გამოყენება). გირჩევთ, სისტემის ტრასირებები გაუზიაროთ მხოლო იმ ადამიანებსა და აპებს, რომლებსაც ენდობით."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"სისტემის კვალის მიდევნების ფაილები შეიძლება შეიცავდეს სისტემისა და აპების სენსიტიურ მონაცემებს (როგორიცაა აპების გამოყენება ან აპის მეხსიერებაში არსებული სურათები). სისტემის კვალი ან გროვის ამონაწერები გაუზიარეთ მხოლოდ თქვენთვის სანდო პირებსა და აპებს."</string>
     <string name="share" msgid="8443979083706282338">"გაზიარება"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"აღარ გამოჩნდეს"</string>
     <string name="long_traces" msgid="5110949471775966329">"გრძელი ტრასირებები"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ჩანაწერების დართვა სისტემის ხარვეზის ანგარიშებზე"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"შესრულების პროცესში მყოფი ჩანაწერები ავტომატურად ეგზავნება BetterBug-ს სისტემის ხარვეზის ანგარიშის მიღებისას. ჩანაწერები გაგრძელდება."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"შენახული ფაილების ნახვა"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"გასაანალიზებლად კვალის ატვირთვა შესაძლებელია ბმულზე: ui.perfetto.dev"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"გროვის ამონაწერის შემოწმება შესაძლებელია AHAT-ით"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"პარამეტრებისთვის თვალის დევნება"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"შენახული ფაილები"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"სხვადასხვა"</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 8f7e8b68..1d70fa3e 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Дамп файлын жазу"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"Дамп файлы процестері\" бөлімінде таңдалған процестердің дамп файлын суретке түсіреді."</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Дамп файлдарын жинау үшін \"Дамп файлы процестері\" бөлімінде кемінде бір процесті таңдаңыз."</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"AM дамп файлын биттер карталарымен жазу"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"Дамп файлы процестерінен\" таңдалған процестің дамп файлын жинап, биттер картасының суреттерін шығарып алады."</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"Дамп файлы процестерінен\" тек бір процесс таңдаңыз."</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"Дамп файлы процестерінен\" процесс таңдаңыз."</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope трассаларын жинау"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Пайдаланушы интерфейсінің толық телеметрия деректері бар (интерфейс жұмысының нашарлауына әкелуі мүмкін)."</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Трассасын түзетуге болатын қолданбалар"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Әдепкі"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# таңдалды}other{# таңдалды}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Дамп файлы процестері"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Кемінде бір процесті таңдау керек."</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Бұл таңдаулар Perfetto және ActivityManager екеуіне де қолданылады."</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Дамп файлы процестерін өшіру"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Процестер тізімі өшірілді."</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Үздіксіз жинақ профилі"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Белгіленген аралықта дамп файлы бір рет суретке түсіріледі."</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Белгіленген аралықта дамп файлы бір рет алынады. Perfetto дамп файлдарына ғана қолданылады."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Дамп файлы аралығы"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 секунд"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 секунд"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Стэк үлгісін жасауды тоқтату үшін түртіңіз."</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Дамп файлы жазылып жатыр"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Дамп файлын тоқтату үшін түртіңіз."</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM дамп файлы жазылып жатыр"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Сақталған файлдарды өшіру"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Жазбалар бір айдан кейін өшіріледі."</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Сақталған файлдарды өшіру керек пе?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces қалтасындағы жазбалардың барлығы жойылады."</string>
     <string name="clear" msgid="5484761795406948056">"Өшіру"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Жүйе трассалары"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, трасса, жұмыс өнімділігі"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, трасса, трассалау, өнімділік, профиль, профильдеу, орталық процессор, шақыру стэгі, стэк, дамп файлы"</string>
     <string name="share_file" msgid="1982029143280382271">"Файлды бөлісу керек пе?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Жүйе трассасы файлдарына маңызды жүйе және қолданба деректері (мысалы, қолданбаны пайдалану туралы) жатуы мүмкін. Оларды тек сенімді адамдармен ғана бөлісіңіз."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Жүйе трассасы файлдарына құпия жүйе және қолданба деректері (қолданбаның пайдаланылуы немесе қолданба жадындағы суреттер сияқты) жатуы мүмкін. Жүйе трассаларын немесе дамп файлдарын тек сенімді адамдармен және қолданбалармен бөлісіңіз."</string>
     <string name="share" msgid="8443979083706282338">"Бөлісу"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Қайта көрсетпеу"</string>
     <string name="long_traces" msgid="5110949471775966329">"Ұзын трассалар"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Қате туралы есептерге жазбаларды тіркеу"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Қате туралы есеп жиналған кезде, ағымдағы жазбаларды BetterBug қызметіне автоматты түрде жіберіңіз. Содан кейін жазба жалғасады."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Сақталған файлдарды көру"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Трассаларды талдау үшін ui.perfetto.dev құралына жүктеп салуға болады"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Дамп файлдарын AHAT арқылы тексеруге болады."</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Трассалау параметрлері"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Сақталған файлдар"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Әртүрлі"</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 4340cad3..1c112a01 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ថតហ៊ីបដាំ"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"ចាប់យកហ៊ីបដាំនៃដំណើរការដែលបានជ្រើសរើសនៅក្នុង \"ដំណើរការហ៊ីបដាំ\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ជ្រើសរើសដំណើរការយ៉ាងហោចណាស់មួយនៅក្នុង \"ដំណើរការហ៊ីបដាំ\" ដើម្បីប្រមូលហ៊ីបដាំ"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"ថតហ៊ីបដាំ AM តាមរយៈ bitmap"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"ប្រមូលហ៊ីបដាំនៃដំណើរ​ការដែលបានជ្រើសរើសនៅក្នុង \"ដំណើរ​ការហ៊ីបដាំ\" និងដកស្រង់រូបភាព bitmap"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"ជ្រើសរើសដំណើរ​ការតែមួយប៉ុណ្ណោះនៅក្នុង \"ដំណើរ​ការហ៊ីបដាំ\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"ជ្រើសរើសដំណើរ​ការមួយនៅក្នុង \"ដំណើរ​ការហ៊ីបដាំ\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"ប្រមូលដាន Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"រួមបញ្ចូលទិន្នន័យទូរមាត្រ UI លម្អិត (អាចបណ្ដាលឱ្យដំណើរការអាក់ៗ)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"តាម​ដាន​កម្មវិធី​ដែល​អាច​ជួសជុល​បាន"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"លំនាំដើម"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{បាន​ជ្រើសរើស #}other{បាន​ជ្រើសរើស #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"ដំណើរការហ៊ីបដាំ"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"ត្រូវតែជ្រើសរើសដំណើរការយ៉ាងហោចណាស់មួយ"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"ការជ្រើសរើសទាំងនេះអនុវត្តចំពោះ Perfetto និង ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"សម្អាតដំណើរការហ៊ីបដាំ"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"បានសម្អាតបញ្ជីដំណើរការ"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"កម្រងព័ត៌មាន​ហ៊ីបបន្តបន្ទាប់"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"ចាប់យកហ៊ីបដាំម្ដងក្នុងចន្លោះពេលដែលបានបញ្ជាក់មួយ"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"ចាប់យកហ៊ីបដាំម្ដងក្នុងចន្លោះពេលដែលបានបញ្ជាក់មួយ។ អនុវត្តចំពោះហ៊ីបដាំ Perfetto តែប៉ុណ្ណោះ។"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"ចន្លោះពេលហ៊ីបដាំ"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 វិនាទី"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 វិនាទី"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"ចុចដើម្បីបញ្ឈប់សំណាកជង់"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"ហ៊ីបដាំកំពុងត្រូវបានថត"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"ចុចដើម្បីបញ្ឈប់ហ៊ីបដាំ"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"ហ៊ីបដាំ AM កំពុងត្រូវបានថត"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"សម្អាតឯកសារ​ដែលបានរក្សាទុក"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"សំឡេងថត​ត្រូវបានសម្អាត បន្ទាប់ពីរយៈពេលមួយខែ"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"សម្អាតឯកសារ​ដែលបានរក្សាទុកឬ?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"សំឡេងថត​ទាំងអស់​នឹងត្រូវបាន​លុបចេញពី /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"សម្អាត"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"ដាន​ប្រព័ន្ធ"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, ដាន, ប្រតិបត្តិការ"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ដាន, ការតាមដាន, ប្រតិបត្តិការ, កម្រងព័ត៌មាន, ការពិនិត្យកម្រងព័ត៌មាន, cpu, callstack, គំនរ, ពំនូក"</string>
     <string name="share_file" msgid="1982029143280382271">"ចែករំលែក​ឯកសារឬ?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"ឯកសារ​តាមដាន​ប្រព័ន្ធ​អាច​រួមមាន ទិន្នន័យ​កម្មវិធី និង​ប្រព័ន្ធ​រសើប (ដូចជា​ការប្រើប្រាស់​កម្មវិធី)។ ចែករំលែក​ដាន​ប្រព័ន្ធ​ជាមួយ​មនុស្ស ​និង​កម្មវិធី​ដែលអ្នកជឿ​ទុកចិត្ត​តែ​ប៉ុណ្ណោះ។"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"ឯកសារតាមដានប្រព័ន្ធអាចរួមមានទិន្នន័យកម្មវិធី និងប្រព័ន្ធរសើប (ដូចជា​ការប្រើប្រាស់កម្មវិធី ឬរូបភាពនៅក្នុងអង្គចងចាំរបស់កម្មវិធី)។ ចែករំលែកដានប្រព័ន្ធ ឬហ៊ីបដាំជាមួយមនុស្ស និងកម្មវិធីដែលអ្នកទុកចិត្តតែប៉ុណ្ណោះ។"</string>
     <string name="share" msgid="8443979083706282338">"ចែករំលែក"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"កុំបង្ហាញម្ដងទៀត"</string>
     <string name="long_traces" msgid="5110949471775966329">"ដានវែង"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ភ្ជាប់សំឡេងថត​ទៅរបាយការណ៍អំពីបញ្ហា"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"បញ្ជូនសំឡេងថត​ដែលកំពុងដំណើរការដោយស្វ័យប្រវត្តិទៅ BetterBug នៅពេលប្រមូល​របាយការណ៍អំពីបញ្ហា។ ការថតនឹងបន្តនៅពេលក្រោយ។"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"មើលឯកសារ​ដែលបានរក្សាទុក"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"អាចបង្ហោះដានទៅកាន់ ui.perfetto.dev សម្រាប់ធ្វើការវិភាគ"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"អាចពិនិត្យហ៊ីបដាំបានតាមរយៈ AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ការកំណត់ដាន"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ឯកសារដែលបានរក្សាទុក"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"ផ្សេងៗ"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 764f3183..14cf141b 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ರೆಕಾರ್ಡ್ ಮಾಡಿ"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"ಹೀಪ್ ಡಂಪ್ ಪ್ರಕ್ರಿಯೆಗಳಲ್ಲಿ\" ಆಯ್ಕೆಮಾಡಿದ ಪ್ರಕ್ರಿಯೆಗಳ ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ಸೆರೆಹಿಡಿಯುತ್ತದೆ"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ಹೀಪ್ ಡಂಪ್‌ಗಳನ್ನು ಸಂಗ್ರಹಿಸಲು \"ಹೀಪ್ ಡಂಪ್ ಪ್ರಕ್ರಿಯೆಗಳಲ್ಲಿ\" ಕನಿಷ್ಠ ಒಂದು ಪ್ರಕ್ರಿಯೆಯನ್ನು ಆಯ್ಕೆಮಾಡಿ"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"ಬಿಟ್‌ಮ್ಯಾಪ್‌ಗಳ ಮೂಲಕ AM ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ರೆಕಾರ್ಡ್ ಮಾಡಿ"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"ಹೀಪ್ ಡಂಪ್ ಪ್ರಕ್ರಿಯೆಗಳು\" ನಲ್ಲಿ ಆಯ್ಕೆ ಮಾಡಲಾದ ಪ್ರಕ್ರಿಯೆಯ ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ಸಂಗ್ರಹಿಸುತ್ತದೆ ಮತ್ತು ಬಿಟ್‌ಮ್ಯಾಪ್ ಚಿತ್ರಗಳನ್ನು ಹೊರತೆಗೆಯುತ್ತದೆ."</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"ಹೀಪ್ ಡಂಪ್ ಪ್ರಕ್ರಿಯೆಗಳು\" ನಲ್ಲಿ ಒಂದೇ ಒಂದು ಪ್ರಕ್ರಿಯೆಯನ್ನು ಆಯ್ಕೆಮಾಡಿ."</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"ಹೀಪ್ ಡಂಪ್ ಪ್ರಕ್ರಿಯೆಗಳು\" ನಲ್ಲಿ ಪ್ರಕ್ರಿಯೆಯನ್ನು ಆಯ್ಕೆಮಾಡಿ."</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"ವಿನ್ಸ್‌ಕೋಪ್‌ ಟ್ರೇಸ್‌ಗಳನ್ನು ಸಂಗ್ರಹಿಸಿ"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"ವಿವರವಾದ UI ಟೆಲಿಮೆಟ್ರಿ ಡೇಟಾವನ್ನು ಒಳಗೊಂಡಿದೆ (ಜಂಕ್ ಮಾಡಬಹುದು)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ಡೀಬಗ್‌ ಮಾಡುವಂತಹ ಅಪ್ಲಿಕೇಶನ್‌ಗಳ ಜಾಡು ಹಿಡಿಯಿರಿ"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ಡೀಫಾಲ್ಟ್"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# ವರ್ಗಗಳನ್ನು ಆಯ್ಕೆಮಾಡಲಾಗಿದೆ}one{# ವರ್ಗಗಳನ್ನು ಆಯ್ಕೆಮಾಡಲಾಗಿದೆ}other{# ವರ್ಗಗಳನ್ನು ಆಯ್ಕೆಮಾಡಲಾಗಿದೆ}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"ಹೀಪ್ ಡಂಪ್ ಪ್ರಕ್ರಿಯೆಗಳು"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"ಕನಿಷ್ಠ ಒಂದು ಪ್ರಕ್ರಿಯೆಯನ್ನಾದರೂ ಆಯ್ಕೆ ಮಾಡಿಕೊಳ್ಳಬೇಕು"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"ಈ ಆಯ್ಕೆಗಳು Perfetto ಮತ್ತು ActivityManager ಎರಡಕ್ಕೂ ಅನ್ವಯಿಸುತ್ತವೆ."</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"ಹೀಪ್ ಡಂಪ್ ಪ್ರಕ್ರಿಯೆಗಳನ್ನು ತೆರವುಗೊಳಿಸಿ"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"ಪ್ರಕ್ರಿಯೆ ಪಟ್ಟಿಯನ್ನು ತೆರವುಗೊಳಿಸಲಾಗಿದೆ"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"ನಿರಂತರ ಹೀಪ್ ಪ್ರೊಫೈಲ್"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"ಪ್ರತಿ ನಿಗದಿತ ಮಧ್ಯಂತರಕ್ಕೆ ಒಮ್ಮೆ ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ಸೆರೆಹಿಡಿಯಿರಿ"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"ಪ್ರತಿ ನಿಗದಿತ ಮಧ್ಯಂತರಕ್ಕೆ ಒಮ್ಮೆ ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ಸೆರೆಹಿಡಿಯಿರಿ. Perfetto ಹೀಪ್ ಡಂಪ್‌ಗಳಿಗೆ ಮಾತ್ರ ಅನ್ವಯಿಸುತ್ತದೆ."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"ಹೀಪ್ ಡಂಪ್ ಮಧ್ಯಂತರ"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 ಸೆಕೆಂಡ್‌ಗಳು"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 ಸೆಕೆಂಡ್‌ಗಳು"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"ಸ್ಟ್ಯಾಕ್‌ ಮಾದರಿಗಳನ್ನು ನಿಲ್ಲಿಸಲು ಟ್ಯಾಪ್ ಮಾಡಿ"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ರೆಕಾರ್ಡ್ ಮಾಡಲಾಗುತ್ತಿದೆ"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ನಿಲ್ಲಿಸಲು ಟ್ಯಾಪ್ ಮಾಡಿ"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM ಹೀಪ್ ಡಂಪ್ ಅನ್ನು ರೆಕಾರ್ಡ್ ಮಾಡಲಾಗುತ್ತಿದೆ."</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"ಉಳಿಸಿದ ಫೈಲ್‌ಗಳನ್ನು ತೆರವುಗೊಳಿಸಿ"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ಒಂದು ತಿಂಗಳ ನಂತರ ರೆಕಾರ್ಡ್‌ಗಳನ್ನು ತೆರವುಗೊಳಿಸಲಾಗಿದೆ"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"ಉಳಿಸಿದ ಫೈಲ್‌ಗಳನ್ನು ತೆರವುಗೊಳಿಸಬೇಕೆ?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"ಎಲ್ಲಾ ರೆಕಾರ್ಡಿಂಗ್‌ಗಳನ್ನು /data/local/traces ನಿಂದ ಅಳಿಸಲಾಗುತ್ತದೆ"</string>
     <string name="clear" msgid="5484761795406948056">"ತೆರವು ಮಾಡಿ"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"ಸಿಸ್ಟಂ ಜಾಡುಗಳು"</string>
-    <string name="keywords" msgid="736547007949049535">"ಸಿಸ್ಟ್ರೇಸ್, ಟ್ರೇಸ್, ಕಾರ್ಯಕ್ಷಮತೆ"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ಟ್ರೇಸ್, ಟ್ರೇಸಿಂಗ್, ಪರ್ಫಾರ್ಮೆನ್ಸ್, ಪ್ರೊಫೈಲ್, ಪ್ರೊಫೈಲಿಂಗ್, CPU, ಕಾಲ್‌ಸ್ಟ್ಯಾಕ್, ಸ್ಟ್ಯಾಕ್, ಹೀಪ್"</string>
     <string name="share_file" msgid="1982029143280382271">"ಫೈಲ್ ಅನ್ನು ಹಂಚಬೇಕೆ?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"ಸಿಸ್ಟಂ ಟ್ರೇಸಿಂಗ್ ಫೈಲ್‌ಗಳು (ಆ್ಯಪ್ ಬಳಕೆಯಂತಹ) ಸೂಕ್ಷ್ಮವಾದ ಸಿಸ್ಟಂ ಅನ್ನು ಮತ್ತು ಆ್ಯಪ್ ಡೇಟಾವನ್ನು ಒಳಗೊಂಡಿರಬಹುದು. ನೀವು ನಂಬುವ ಜನರು ಮತ್ತು ಆ್ಯಪ್‌ಗಳೊಂದಿಗೆ ಮಾತ್ರ ಸಿಸ್ಟಂ ಟ್ರೇಸ್‌ಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಿ."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"ಸಿಸ್ಟಂ ಟ್ರೇಸಿಂಗ್ ಫೈಲ್‌ಗಳು ಸೂಕ್ಷ್ಮ ಸಿಸ್ಟಂ ಮತ್ತು ಆ್ಯಪ್‌ ಡೇಟಾವನ್ನು ಒಳಗೊಂಡಿರಬಹುದು (ಉದಾಹರಣೆಗೆ ಆ್ಯಪ್ ಬಳಕೆ ಅಥವಾ ಆ್ಯಪ್‌ನ ಮೊರಿಯಲ್ಲಿರುವ ಚಿತ್ರಗಳು). ನೀವು ನಂಬುವ ಜನರು ಮತ್ತು ಆ್ಯಪ್‌ಗಳ ಜೊತೆಗೆ ಮಾತ್ರ ಸಿಸ್ಟಮ್ ಟ್ರೇಸ್‌ಗಳು ಅಥವಾ ಹೀಪ್ ಡಂಪ್‌ಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಿ."</string>
     <string name="share" msgid="8443979083706282338">"ಹಂಚಿಕೊಳ್ಳಿ"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"ಮತ್ತೊಮ್ಮೆ ತೋರಿಸಬೇಡಿ"</string>
     <string name="long_traces" msgid="5110949471775966329">"ದೀರ್ಘ ಟ್ರೇಸ್‌ಗಳು"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ಬಗ್ ವರದಿಗಳಿಗೆ ರೆಕಾರ್ಡಿಂಗ್‌ಗಳನ್ನು ಲಗತ್ತಿಸಿ"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ಬಗ್ ವರದಿ ಮಾಡುವಿಕೆಯನ್ನು ಸಂಗ್ರಹಿಸಿದಾಗ ಸ್ವಯಂಚಾಲಿತವಾಗಿ ಪ್ರಗತಿಯಲ್ಲಿರುವ ರೆಕಾರ್ಡಿಂಗ್‌ಗಳನ್ನು BetterBug ಗೆ ಕಳುಹಿಸಿ. ರೆಕಾರ್ಡಿಂಗ್‌ಗಳು ನಂತರ ಮುಂದುವರಿಯುತ್ತವೆ."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"ಉಳಿಸಿದ ಫೈಲ್‌ಗಳನ್ನು ವೀಕ್ಷಿಸಿ"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"ವಿಶ್ಲೇಷಣೆಗಾಗಿ ಟ್ರೇಸಸ್‌ಗಳನ್ನು ui.perfetto.dev ಗೆ ಅಪ್‌ಲೋಡ್ ಮಾಡಬಹುದು."</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"AHAT ಮೂಲಕ ಹೀಪ್ ಡಂಪ್‌ಗಳನ್ನು ಪರಿಶೀಲಿಸಬಹುದು."</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ಜಾಡು ಸೆಟ್ಟಿಂಗ್‌ಗಳು"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ಉಳಿಸಲಾದ ಫೈಲ್‌ಗಳು"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"ಇತರೆ"</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index b1bcdfff..6c98d581 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"힙 덤프 기록"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\'힙 덤프 프로세스\'에서 선택한 프로세스의 힙 덤프를 캡처합니다"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"힙 덤프를 수집하려면 \'힙 덤프 프로세스\'에서 프로세스를 하나 이상 선택하세요"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"비트맵으로 AM 힙 덤프 기록"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\'힙 덤프 프로세스\'에서 선택한 프로세스의 힙 덤프를 수집하고, 비트맵 이미지를 추출합니다"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\'힙 덤프 프로세스\'에서 하나의 프로세스만 선택하세요"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\'힙 덤프 프로세스\'에서 프로세스를 선택하세요"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope 트레이스 수집"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"상세한 UI 원격 분석 데이터 포함(버벅거림이 발생할 수 있음)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"디버그 가능한 애플리케이션 추적"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"기본"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{#개 선택됨}other{#개 선택됨}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"힙 덤프 프로세스"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"프로세스를 하나 이상 선택해야 합니다"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"이 선택 사항은 Perfetto와 ActivityManager 모두에 적용됩니다"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"힙 덤프 프로세스 삭제"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"프로세스 목록 삭제됨"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"연속 힙 프로필"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"지정된 간격마다 한 번씩 힙 덤프를 캡처합니다."</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"지정된 간격마다 한 번씩 힙 덤프를 캡처합니다. Perfetto 힙 덤프에만 적용됩니다."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"힙 덤프 간격"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5초"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10초"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"탭하여 스택 샘플링 중단"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"힙 덤프를 기록하는 중"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"힙 덤프를 중지하려면 탭하세요"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM 힙 덤프를 기록하는 중"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"저장된 파일 삭제"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"녹화 파일은 1개월 후에 삭제됩니다."</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"저장된 파일을 삭제할까요?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces에서 모든 녹화 파일이 삭제됩니다."</string>
     <string name="clear" msgid="5484761795406948056">"삭제"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"시스템 트레이스"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, 트레이스, 성능"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, 트레이스, 트레이싱, 성능, 프로필, 프로파일링, cpu, 호출 스택, 스택, 힙"</string>
     <string name="share_file" msgid="1982029143280382271">"파일을 공유할까요?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"시스템 추적 파일에는 민감한 시스템 및 앱 데이터(예: 앱 사용)가 포함되어 있을 수 있습니다. 신뢰할 수 있는 앱 및 사용자에게만 공유하세요."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"시스템 추적 파일에는 민감한 시스템 및 앱 데이터(예: 앱 사용량 또는 앱 메모리의 이미지)가 포함될 수 있습니다. 신뢰할 수 있는 사용자 및 앱에만 시스템 트레이스 또는 힙 덤프를 공유하세요."</string>
     <string name="share" msgid="8443979083706282338">"공유"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"다시 표시 안함"</string>
     <string name="long_traces" msgid="5110949471775966329">"장기 트레이스"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"버그 신고에 녹화 파일 첨부"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"버그 신고 수집 시 진행 중인 녹화 파일을 자동으로 BetterBug에 전송합니다. 이후 녹화는 계속됩니다."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"저장된 파일 보기"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"분석을 위해 ui.perfetto.dev에 트레이스를 업로드할 수 있습니다"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"AHAT를 사용하여 힙 덤프를 검사할 수 있습니다"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"트레이스 설정"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"저장된 파일"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"기타"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 1d28f579..4cb8f11f 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Үймө дампын жаздыруу"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"Үймө дампы процесстеринен\" тандалган процесстердин үймө дампын тартат"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Үймө дампыларды топтоо үчүн \"Үймө дампы процесстеринен\" кеминде бир процессти тандаңыз"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Бит картасы менен AM үймө дампын жаздырыңыз"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"Үймө дампы процесстеринен\" процесстин үймө дампын тандап, бит карта сүрөтүн чыгарат"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"Үймө дампы процесстеринен\" бир гана процессти тандаңыз."</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"Үймө дампы процесстеринен\" процессти тандаңыз."</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope аракеттерин жыйноо"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Колдонуучу интерфейси толук телеметрия маалыматын камтыйт (бул интерфейстин начарлашына алып келиши мүмкүн)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Мүчүлүштүктөрү оңдоло турган колдонмолордун аракеттерин жаздыруу"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Демейки"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# тандалды}other{# тандалды}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Үймө дампы процесстери"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Кеминде бир процесс тандалышы керек"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Бул тандоолор Perfetto жана ActivityManager үчүн колдонулат"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Үймө дампы процесстерин тазалоо"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Процесс тизмеси тазаланды"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Үзгүлтүксүз үймөк профили"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Үймө дампын ар бир белгиленген интервалда тартуу"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Үймө дампын ар бир белгиленген интервалда тартуу. Perfetto үймө дампына карата гана колдонулат."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Үймө дампынын итервалы"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 секунд"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 секунд"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Топтомдун үлгүсүн түзүүнү токтотуу үчүн таптап коюңуз"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Үймө дампы жаздырылууда"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Үймө дампын токтоуу үчүн таптап коюңуз"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM үймө дампы жаздырылууда"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Сакталган файлдарды өчүрүү"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Жаздырылган нерселер бир айдан кийин тазаланат"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Сакталган файлдар өчүрүлсүнбү?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces бөлүмүндөгү бардык жаздырылган нерселер өчүрүлөт"</string>
     <string name="clear" msgid="5484761795406948056">"Тазалоо"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Системанын аракеттерин жаздыруу"</string>
-    <string name="keywords" msgid="736547007949049535">"системага көз салуу, аракеттерди жаздыруу, иштин майнаптуулугу"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, көз салуу, көз салынууда, майнаптуулук, профиль, профиль түзүү, процессор, чалуу чыпкасы, чыпка, үймөк"</string>
     <string name="share_file" msgid="1982029143280382271">"Файлды бөлүшөсүзбү?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Системага көз салуу файлдары тутумдагы жана колдонмодогу купуя маалыматтарды (мисалы, колдонмонун пайдаланылышы) камтышы мүмкүн. Системага көз салуудан алынган маалыматты ишенимдүү байланыштар жана колдонмолор менен гана бөлүшүңүз."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Системага көз салуу файлдары тутумдагы жана колдонмодогу купуя маалыматтарды (мисалы, колдонмонун же сүрөттөрдүн пайдаланылышын камтышы мүмкүн. Системага көз салууну же үймө дамптарын сиз шенген адамдар жана колдонмолор менен бөлүңүз"</string>
     <string name="share" msgid="8443979083706282338">"Бөлүшүү"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Экинчи көрүнбөсүн"</string>
     <string name="long_traces" msgid="5110949471775966329">"Узун аракеттер"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Мүчүлүштүк тууралуу кабарларга жаздырууларды тиркөө"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Мүчүлүштүк тууралуу кабар чогултулганда, жаздырылган аракеттерди BetterBug кызматына автоматтык түрдө жөнөтүңүз. Андан кийин жаздыруу улантылат."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Сакталган файлдарды көрүү"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Издерди талдоо үчүн ui.perfetto.dev сайтына жүктөөгө болот"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Үймө дамптарын AHAT менен текшерүүгө болот"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Аракеттерди жаздыруу параметрлери"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Сакталган файлдар"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Аралаш"</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 398d8bd4..93108825 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ບັນທຶກ heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"ຖ່າຍ heap dump ຂອງຂະບວນການທີ່ເລືອກໃນ \"ຂະບວນການ heap dump\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ເລືອກຢ່າງໜ້ອຍ 1 ຂະບວນການໃນ \"ຂະບວນການ heap dump\" ເພື່ອຮວບຮວມ heap dump"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"ບັນທຶກ AM heap dump ດ້ວຍ bitmaps"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"ຮວບຮວມ heap dump ຂອງຂະບວນການທີ່ເລືອກໃນ \"ຂະບວນການ heap dump\" ແລະ ແຍກຮູບ bitmap"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"ເລືອກພຽງໜຶ່ງຂະບວນການໃນ \"ຂະບວນການ heap dump\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"ເລືອກຂະບວນການໃນ \"ຂະບວນການ heap dump\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"ຮວບຮວມການຕິດຕາມ Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"ມີຂໍ້ມູນຈາກທາງໄກຂອງສ່ວນຕິດຕໍ່ຜູ້ໃຊ້ແບບລະອຽດ (ສາມາດເຮັດໃຫ້ເກີດການຂັດຂ້ອງໄດ້)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ຕິດຕາມແອັບພລິເຄຊັນທີ່ດີບັກໄດ້."</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ຄ່າເລີ່ມຕົ້ນ"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{ເລືອກ # ລາຍການແລ້ວ}other{ເລືອກ # ລາຍການແລ້ວ}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"ຂະບວນການ heap dump"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"ຕ້ອງເລືອກຢ່າງໜ້ອຍ 1 ຂະບວນການ"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"ການເລືອກເຫຼົ່ານີ້ໃຊ້ກັບທັງ Perfetto ແລະ ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"ລຶບລ້າງຂະບວນການ heap dump"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"ລຶບລ້າງລາຍຊື່ຂອງຂະບວນການແລ້ວ"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"ໂປຣໄຟລ໌ heap ແບບຕໍ່ເນື່ອງ"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"ຖ່າຍ heap dump 1 ຄັ້ງຕໍ່ຊ່ວງເວລາທີ່ລະບຸ"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"ຖ່າຍ heap dump 1 ຄັ້ງຕໍ່ຊ່ວງເວລາທີ່ລະບຸ. ນຳໃຊ້ກັບ Perfetto heap dumps ເທົ່ານັ້ນ."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"ຊ່ວງເວລາຂອງ heap dump"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 ວິນາທີ"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 ວິນາທີ"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"ແຕະເພື່ອຢຸດການສຸ່ມຕົວຢ່າງສະແຕັກ"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"ກຳລັງບັນທຶກ heap dump"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"ແຕະເພື່ອຢຸດ heap dump"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM heap dump ກຳລັງຖືກບັນທຶກ"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"ລຶບລ້າງໄຟລ໌ທີ່ບັນທຶກໄວ້"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ລະບົບຈະລຶບລ້າງການບັນທຶກຫຼັງຈາກຜ່ານໄປ 1 ເດືອນ"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"ລຶບລ້າງໄຟລ໌ທີ່ບັນທຶກໄວ້ບໍ?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"ລະບົບຈະລຶບການບັນທຶກທັງໝົດອອກຈາກ /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"ລຶບ"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"ການຕິດຕາມລະບົບ"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, ຕິດຕາມ, ປະສິດທິພາບ"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ຕິດຕາມ, ການຕິດຕາມ, ປະສິດທິພາບ, ໂປຣໄຟລ໌, ການສ້າງໂປຣໄຟລ໌, CPU, callstack, ວາງຊ້ອນກັນ, ກອງ"</string>
     <string name="share_file" msgid="1982029143280382271">"ແບ່ງປັນໄຟລ໌ບໍ?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"ໄຟລ໌ການຕິດຕາມລະບົບອາດມີຂໍ້ມູນແອັບ ແລະ ຂໍ້ມູນລະບົບທີ່ອ່ອນໄຫວ (ເຊັ່ນ: ການນຳໃຊ້ແອັບ). ທ່ານຄວນແບ່ງປັນການຕິດຕາມລະບົບໃຫ້ກັບຄົນ ແລະ ແອັບທີ່ທ່ານເຊື່ອຖືເທົ່ານັ້ນ."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"ໄຟລ໌ການຕິດຕາມລະບົບອາດຮວມເອົາຂໍ້ມູນລະອຽດອ່ອນຂອງລະບົບ ແລະ ຂໍ້ມູນແອັບ (ເຊັ່ນ: ການໃຊ້ແອັບ ຫຼື ຮູບໃນໜ່ວຍຄວາມຈຳຂອງແອັບ). ແບ່ງປັນການຕິດຕາມລະບົບ ຫຼື heap dump ກັບຄົນ ແລະ ແອັບທີ່ທ່ານເຊື່ອຖືເທົ່ານັ້ນ."</string>
     <string name="share" msgid="8443979083706282338">"ແບ່ງປັນ"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"ບໍ່ຕ້ອງສະແດງອີກ"</string>
     <string name="long_traces" msgid="5110949471775966329">"ການຕິດຕາມຍາວ"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ແນບການບັນທຶກໃນລາຍງານຂໍ້ຜິດພາດ"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ສົ່ງການບັນທຶກທີ່ກຳລັງດຳເນີນຢູ່ໄປໃຫ້ BetterBug ໂດຍອັດຕະໂນມັດເມື່ອຮວບຮວມລາຍງານຂໍ້ຜິດພາດ. ການບັນທຶກຈະສືບຕໍ່ຫຼັງຈາກນັ້ນ."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"ເບິ່ງໄຟລ໌ທີ່ບັນທຶກໄວ້"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"ສາມາດອັບໂຫຼດການຕິດຕາມໄປຫາ ui.perfetto.dev ເພື່ອການວິເຄາະໄດ້"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"ສາມາດກວດສອບ heap dump ໄດ້ດ້ວຍ AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ຕິດຕາມການຕັ້ງຄ່າ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ໄຟລ໌ທີ່ບັນທຶກໄວ້"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"ອື່ນໆ"</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index 5f05c52f..aaaedbe9 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Įrašyti atminties išklotinę"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Fiksuojama procesų, pasirinktų skiltyje „Atminties išklotinės procesai“, atminties išklotinė"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Pasirinkite bent vieną procesą skiltyje „Atminties išklotinės procesai“, kad galėtumėte rinkti atminties išklotines"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Įrašyti AM atminties išklotinę su taškine grafika"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Renka proceso, pasirinkto skiltyje „Atminties išklotinės procesai“, atminties išklotinę ir išgauna taškinės grafikos vaizdus"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Pasirinkite tik vieną procesą skiltyje „Atminties išklotinės procesai“"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Pasirinkite procesą skiltyje „Atminties išklotinės procesai“"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Rinkti „Winscope“ pėdsakus"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Įtraukiami išsamūs NS telemetrijos duomenys (gali įvykti pateikimo pauzė)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Žymėti derinamas programas"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Numatytoji"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Pasirinkta: #}one{Pasirinkta: #}few{Pasirinkta: #}many{Pasirinkta: #}other{Pasirinkta: #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Atminties išklotinės procesai"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Turite pasirinkti bent vieną procesą"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Šie pasirinkimai taikomi ir „Perfetto“, ir „ActivityManager“"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Išvalyti atminties išklotinės procesus"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Procesų sąrašas išvalytas"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Nuolatinė glausta atminties informacija"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Fiksuoti atminties išklotinę vieną kartą per nurodytą intervalą"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Fiksuoti atminties išklotinę vieną kartą per nurodytą intervalą Taikoma tik „Perfetto“ atminties išklotinėms."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Atminties išklotinės intervalas"</string>
     <string name="five_seconds" msgid="7018465440929299712">"Penkios sekundės"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekundžių"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Jei norite sustabdyti dėklo pavyzdžių rinkimą, palieskite"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Atminties išklotinė įrašoma"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Palieskite, kad sustabdytumėte atminties išklotinę"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM atminties išklotinė įrašoma"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Išvalyti išsaugotus failus"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Įrašai išvalomi po vieno mėnesio"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Išvalyti išsaugotus failus?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Visi įrašai bus ištrinti iš /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Išvalyti"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Sistemos pėdsakai"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, pėdsakas, našumas"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, sekti, sekimas, našumas, profilis, profiliavimas, centrinis procesorius, dėklai, dėklas, krūva"</string>
     <string name="share_file" msgid="1982029143280382271">"Bendrinti failą?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Sistemos pėdsakų failuose gali būti neskelbtinų sistemos ir programų duomenų (pvz., programų naudojimo duomenų). Sistemos pėdsakų failus bendrinkite tik su patikimomis programomis ir žmonėmis."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Sistemos žymėjimo failuose gali būti neskelbtinos sistemos informacijos ir programų duomenų (pvz., programos naudojimo duomenų ar vaizdų programos atmintyje). Sistemos žymėjimą arba atminties išklotines bendrinkite tik su žmonėmis ir programomis, kuriais pasitikite."</string>
     <string name="share" msgid="8443979083706282338">"Bendrinti"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Daugiau neberodyti"</string>
     <string name="long_traces" msgid="5110949471775966329">"Ilgalaikio stebėjimo duomenys"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Pridėkite įrašų prie pranešimų apie riktus"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatiškai siųsti vykdomos veiklos įrašus į sistemą „BetterBug“, kai gaunamas pranešimas apie riktą. Įrašymas bus tęsiamas vėliau."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Žr. išsaugotus failus"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Pėdsakus galima įkelti į ui.perfetto.dev, kad būtų galima analizuoti"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Atminties išklotines galima tikrinti naudojant AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Sekimo nustatymai"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Išsaugoti failai"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Įvairūs"</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 619b0d19..9e59af76 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Ierakstīt grēdas izrakstu"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Ieraksta sadaļā “Grēdas izrakstu procesi” atlasīto procesu grēdas izrakstu"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Lai vāktu grēdas izrakstus, sadaļā “Grēdas izrakstu procesi” atlasiet vismaz vienu procesu"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Izveidot AM grēdas izrakstu ar bitkartēm"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Vāc sadaļā “Grēdas izrakstu procesi” atlasītā procesa grēdas izrakstu un iegūst bitkartes attēlus"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Sadaļā “Grēdas izrakstu procesi” atlasiet tikai vienu procesu"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Sadaļā “Grēdas izrakstu procesi” atlasiet procesu"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Vākt Winscope izsekošanas datus"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Ietver detalizētus lietotāja saskarnes telemetrijas datus (var izraisīt reaģēšanas pauzi)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Izsekot atkļūdošanas lietojumprogrammas"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Noklusējums"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# atlasīta}zero{# atlasītu}one{# atlasīta}other{# atlasītas}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Grēdas izrakstu procesi"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Ir jāatlasa vismaz viens process"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Šī atlases attiecas gan uz Perfetto, gan uz ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Notīrīt grēdas izrakstu procesus"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Procesu saraksts notīrīts"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Pastāvīgs grēdas profils"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Ierakstīt grēdas izrakstu vienu reizi norādītajā intervālā"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Veikt grēdas izrakstu vienu reizi norādītajā intervālā. Attiecas tikai uz Perfetto grēdas izrakstiem."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Grēdas izrakstu intervāls"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekundes"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekundes"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Pieskarieties, lai apturētu steka paraugu reģistrēšanu"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Notiek grēdas izraksta ierakstīšana"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Pieskarieties, lai pārtrauktu grēdas izraksta ierakstīšanu"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Tiek veidots AM grēdas izraksts"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Notīrīt saglabātos failus"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Reģistrētie dati tiek dzēsti pēc viena mēneša."</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Vai notīrīt saglabātos failus?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Visi reģistrētie dati tiks izdzēsti no mapes /data/local/traces."</string>
     <string name="clear" msgid="5484761795406948056">"Notīrīt"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Sistēmas izsekošanas dati"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, izsekošana, veiktspēja"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, izsekot, izsekošana, veiktspēja, profils, profilēšana, centrālais procesors, izsaukuma steks, kopa, grēda"</string>
     <string name="share_file" msgid="1982029143280382271">"Vai kopīgot failu?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Sistēmas trasējuma failos var būt iekļauti sensitīvi sistēmas un lietotņu dati (piemēram, par lietotņu izmantošanu). Kopīgojiet sistēmas trasējumus tikai ar uzticamām personām un lietotnēm."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Sistēmas izsekošanas failos var būt ietverti sensitīvi sistēmas un lietotnes dati (piemēram, lietotņu izmantošanas vai attēlu dati lietotnes atmiņā). Kopīgojiet sistēmas izsekošanas datus vai grēdas izrakstus tikai ar lietotājiem un lietotnēm, kam uzticaties."</string>
     <string name="share" msgid="8443979083706282338">"Kopīgot"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Vairs nerādīt"</string>
     <string name="long_traces" msgid="5110949471775966329">"Ilgtermiņa izsekošanas dati"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Kļūdu pārskatiem pievienot reģistrētos datus"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Varat automātiski sūtīt pašreizējos reģistrētos datus uz rīku BetterBug kopā ar kļūdas pārskatu. Reģistrēšana pēc tam tiks turpināta."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Skatīt saglabātos failus"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Izsekošanas datus var augšupielādēt analīzei vietnē ui.perfetto.dev"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Grēdas izrakstus var pārbaudīt, izmantojot AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Izsekošanas iestatījumi"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saglabātie faili"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Dažādi"</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 5739a1e3..28ef2410 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Снимање слика од меморијата"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Снима слика од меморијата од процесите избрани во „Процеси на слики од меморијата“"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Изберете најмалку еден процес во „Процеси на слики од меморијата“ за да ги приберете сликите од меморијата"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Сними слика од меморијата на AM со растерни слики"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Снима слика од меморијата за процесот избран во „Процеси со слика од меморијата“ и извлекува растерни слики"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Изберете само еден процес во „Процеси со слика од меморијата“"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Изберете процес во „Процеси со слика од меморијата“"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Собирајте траги од Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Опфаќа детални податоци за телеметрија на корисничкиот интерфејс (може да предизвика заглавување)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Трагај по апликации со грешки за отстранување"</string>
@@ -18,12 +22,12 @@
     <string name="default_categories_restored" msgid="6861683793680564181">"Вратени се стандардните категории"</string>
     <string name="default_categories" msgid="2117679794687799407">"Стандардни"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Избрано е #}one{Избрани се #}other{Избрани се #}}"</string>
-    <string name="heap_dump_processes" msgid="2500105180344901939">"Процеси на слики од меморијата"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Мора да се избере најмалку еден процес"</string>
+    <string name="heap_dump_processes" msgid="2500105180344901939">"Процеси со слика од меморијата"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Овие избори важат и за Perfetto и за ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Бришење на процесите за сликите од меморијата"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Списокот со процеси е избришан"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Постојан профил на меморијата за блокови"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Снимете по една слика од меморија на секој конкретен интервал"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Снимете по една слика од меморија на секој наведен интервал. Важи само за слики од меморијата на Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Интервал на слики од меморијата"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 секунди"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 секунди"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Допрете за да го запрете семплирањето на купчето"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Се снима слика од меморијата"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Допрете за да ја сопрете сликата од меморијата"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Се снима слика од меморијата на AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Избриши ги зачуваните датотеки"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Снимките се бришат по еден месец"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Да се избришат зачуваните датотеки?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Ќе се избришат сите снимки од /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Избриши"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Системски траги"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, следење, изведба"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, трага, следење, изведба, профил, профилирање, CPU, семплирање, групирање, слика"</string>
     <string name="share_file" msgid="1982029143280382271">"Да се сподели датотеката?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Датотеките за следење на системот може да вклучуваат чувствителни системски и апликациски податоци (како што е користење на апликациите). Споделувајте датотеки за следење на системот само со луѓе и апликации во кои имате доверба."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Датотеките за следење на системот може да содржат чувствителни податоци за системот и податоци од апликациите (како што е употребата на апликацијата или сликите во меморијата на апликацијата). Споделувајте системски траги или слики од меморија само со лица и апликации на кои им верувате."</string>
     <string name="share" msgid="8443979083706282338">"Сподели"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Не прикажувај повторно"</string>
     <string name="long_traces" msgid="5110949471775966329">"Долги траги"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Прикачете ги снимките во извештаите за грешки"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Автоматски испраќај снимки во тек до BetterBug кога ќе се прибере извештај за грешки. Снимањата ќе продолжат потоа."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Прикажи ги зачуваните датотеки"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Трагите може да се прикачат на ui.perfetto.dev за анализа"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Сликите од меморијата може да се проверат со AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Поставки за трага"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Зачувани апликации"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Разно"</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index abcfc8cd..010284c4 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ഹീപ്പ് ഡംപ് റെക്കോർഡ് ചെയ്യുക"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"ഹീപ്പ് ഡംപ് പ്രോസസുകളിൽ\" തിരഞ്ഞെടുത്ത പ്രോസസുകളുടെ ഒരു ഹീപ്പ് ഡംപ് ക്യാപ്ചർ ചെയ്യുന്നു"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ഹീപ്പ് ഡംപുകൾ ശേഖരിക്കാൻ \"ഹീപ്പ് ഡംപ് പ്രോസസുകളിൽ\" ഒരു പ്രോസസ് എങ്കിലും തിരഞ്ഞെടുക്കുക"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"ബിറ്റ്മാപ്പുകൾ ഉപയോഗിച്ച് AM ഹീപ്പ് ഡംപുകൾ റെക്കോർഡ് ചെയ്യുക"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"ഹീപ്പ് ഡംപ് പ്രോസസുകളിൽ\" തിരഞ്ഞെടുത്ത ഒരു പ്രോസസിന്റെ ഹീപ്പ് ഡംപ് ശേഖരിച്ച് ബിറ്റ്മാപ്പ് ചിത്രങ്ങൾ വേർതിരിച്ചെടുക്കുന്നു"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"ഹീപ്പ് ഡംപ് പ്രോസസുകളിൽ\" ഒരു പ്രോസസ് മാത്രം തിരഞ്ഞെടുക്കുക"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"ഹീപ്പ് ഡംപ് പ്രോസസുകളിൽ\" ഒരു പ്രോസസ് തിരഞ്ഞെടുക്കുക"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"വിൻസ്‌കോപ്പ് അടയാളങ്ങൾ ശേഖരിക്കുക"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"വിശദമായ UI ടെലിമെട്രി ഡാറ്റ ഉൾപ്പെടുന്നു (ജങ്ക് ഉണ്ടാക്കാം)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ഡീബഗ്ഗ് ചെയ്യാവുന്ന അപ്ലിക്കേഷനുകള്‍ ഫോളോ ചെയ്യുക"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ഡിഫോൾട്ട്"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# എണ്ണം തിരഞ്ഞെടുത്തു}other{# എണ്ണം തിരഞ്ഞെടുത്തു}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"ഹീപ്പ് ഡംപ് പ്രോസസുകൾ"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"ഒരു പ്രോസസ് എങ്കിലും തിരഞ്ഞെടുത്തിരിക്കണം"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"ഈ തിരഞ്ഞെടുപ്പുകൾ Perfetto, ActivityManager എന്നീ രണ്ട് ആപ്പുകൾക്കും ബാധകമാണ്"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"\'ഹീപ്പ് ഡംപ് പ്രോസസുകൾ\' മായ്ക്കുക"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"പ്രോസസ് ലിസ്റ്റ് മായ്ച്ചു"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"തുടർച്ചയായ ഹീപ്പ് പ്രൊഫൈൽ"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"ഒരു നിശ്ചിത ഇടവേളയിൽ ഒരു തവണ ഹീപ്പ് ഡംപ് ക്യാപ്‌ചർ ചെയ്യുക"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"ഒരു നിശ്ചിത ഇടവേളയിൽ ഒരു തവണ ഹീപ്പ് ഡംപ് ക്യാപ്‌ചർ ചെയ്യുക. Perfetto ഹീപ്പ് ഡംപുകൾക്ക് മാത്രം ബാധകം."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"ഹീപ്പ് ഡംപ് ഇടവേള"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 സെക്കൻഡ്"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 സെക്കൻഡ്"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"സ്റ്റാക്ക് സാംപ്ലിംഗ് അവസാനിപ്പിക്കാൻ ടാപ്പ് ചെയ്യുക"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"ഹീപ്പ് ഡംപ് റെക്കോർഡ് ചെയ്യുകയാണ്"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"ഹീപ്പ് ഡംപ് നിർത്താൻ ടാപ്പ് ചെയ്യുക"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM ഹീപ്പ് ഡംപുകൾ റെക്കോർഡ് ചെയ്യുന്നു"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"സംരക്ഷിച്ച ഫയലുകൾ മായ്ക്കുക"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ഒരു മാസത്തിന് ശേഷം റെക്കോർഡിംഗുകൾ മായ്ക്കുന്നു"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"സംരക്ഷിച്ച ഫയലുകൾ മായ്ക്കണോ?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces എന്നതിൽ നിന്ന് എല്ലാ റെക്കോർഡിംഗുകളും ഇല്ലാതാക്കും"</string>
     <string name="clear" msgid="5484761795406948056">"മായ്ക്കുക"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"സിസ്‌റ്റം അടയാളങ്ങൾ"</string>
-    <string name="keywords" msgid="736547007949049535">"സിസ്ട്രേസ്, ട്രേസ്, പ്രകടനം"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, തിരയുക, തിരയുന്നു, പ്രകടനം, പ്രൊഫൈൽ, പ്രൊഫൈലിംഗ്, cpu, കോൾസ്‌റ്റാക്ക്, സ്‌റ്റാക്ക്, ഹീപ്പ്"</string>
     <string name="share_file" msgid="1982029143280382271">"ഫയൽ പങ്കിടണോ?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"സിസ്‌റ്റം ട്രെയ്‌സിംഗ് ഫയലുകളിൽ സൂക്ഷ്‌മമായി കൈകാര്യം ചെയ്യേണ്ട സിസ്‌റ്റം, ആപ്പ് ഡാറ്റ (ആപ്പ് ഉപയോഗം പോലുള്ളവ) എന്നിവ ഉൾപ്പെട്ടേക്കാം. നിങ്ങൾ വിശ്വസിക്കുന്ന ആളുകൾ, ആപ്പുകൾ എന്നിവയുമായി മാത്രം സിസ്‌റ്റം ട്രെയ്‌സുകൾ പങ്കിടുക."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"സിസ്റ്റം ട്രെയ്‌സിംഗ് ഫയലുകളിൽ സൂക്ഷ്‌മമായി കൈകാര്യം ചെയ്യേണ്ട സിസ്റ്റം, ആപ്പ് ഡാറ്റ (ആപ്പ് ഉപയോഗം അല്ലെങ്കിൽ ആപ്പിന്റെ മെമ്മറിയിലെ ചിത്രങ്ങൾ എന്നിവ പോലുള്ളവ) എന്നിവ ഉൾപ്പെട്ടേക്കാം. നിങ്ങൾക്ക് വിശ്വാസമുള്ള ആളുകളുമായി മാത്രം ട്രെയ്‌സുകളും ഹീപ്പ് ഡംപുകളും പങ്കിടുക."</string>
     <string name="share" msgid="8443979083706282338">"പങ്കിടുക"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"വീണ്ടും കാണിക്കരുത്"</string>
     <string name="long_traces" msgid="5110949471775966329">"ദൈർഘ്യമുള്ള ട്രെയ്‌സുകൾ"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ബഗ് റിപ്പോർട്ടുകളിലേക്ക് റെക്കോർഡിംഗുകൾ അറ്റാച്ച് ചെയ്യുക"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ബഗ് റിപ്പോർട്ട് ശേഖരിച്ചാൽ, പുരോഗതിയിലുള്ള റെക്കോർഡിംഗുകൾ BetterBug-ലേക്ക് സ്വയമേവ അയയ്ക്കുക. റെക്കോർഡ് ചെയ്യലുകൾ പിന്നീട് തുടരും."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"സംരക്ഷിച്ച ഫയലുകൾ കാണുക"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"വിശകലനത്തിനായി ui.perfetto.dev എന്നതിലേക്ക് ട്രെയ്‌സുകൾ അപ്‌ലോഡ് ചെയ്യാം"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"AHAT ഉപയോഗിച്ച് ഹീപ്പ് ഡംപുകൾ പരിശോധിക്കാം"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ട്രേസ് ചെയ്യൽ ക്രമീകരണം"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"സംരക്ഷിച്ച ഫയലുകൾ"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"മറ്റുള്ളവ"</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 62432d74..3b74c834 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Санах ойн агшин зургийг бүртгэх"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"Санах ойн агшин зургийн явцууд\" хэсэгт сонгосон явцуудын санах ойн агшин зургийг авна"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Санах ойн агшин зургуудыг цуглуулахын тулд \"Санах ойн агшин зургийн явцууд\"-аас дор хаяж нэг явц сонгоно уу"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Бит газрын зургаар AM-н санах ойн агшин зургийг бүртгэх"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"Санах ойн агшин зургийн процессууд\"-аас сонгосон процессын санах ойн агшин зургийг цуглуулж, бит газрын зургийн зургийг задална"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"Санах ойн агшин зургийн процессууд\"-аас нэг л процесс сонгоно"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"Санах ойн агшин зургийн процессууд\"-аас нэг процесс сонгоно"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope-н ул мөрүүдийг цуглуулах"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"UI-н телеметрийн нарийвчилсан өгөгдөл багтана (чанар муудахад хүргэх боломжтой)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Дебаг хийх боломжтой аппуудын ул мөрийг дагах"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Өгөгдмөл"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{#-г сонгосон}other{#-г сонгосон}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Санах ойн агшин зургийн явцууд"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Дор хаяж нэг явцыг сонгосон байх ёстой"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Эдгээр сонголт Perfetto, ActivityManager-н аль алинд хэрэгждэг"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Санах ойн агшин зургийн явцуудыг арилгах"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Явцын жагсаалтыг арилгасан"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Тасралтгүй heap профайл"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Заасан интервал бүрд нэг удаа санах ойн агшин зураг авах"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Заасан интервал бүрд нэг удаа санах ойн агшин зураг авна. Зөвхөн Perfetto-н санах ойн агшин зурагт хэрэгжинэ."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Санах ойн агшин зургийн интервал"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 секунд"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 секунд"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Стекийн түүвэрлэлтийг зогсоохын тулд товшино уу"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Санах ойн агшин зургийг бүртгэж байна"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Санах ойн агшин зургийг зогсоохын тулд товшино уу"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM-н санах ойн агшин зургийг бичиж байна"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Хадгалсан файлуудыг арилгах"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Бичлэгүүдийг нэг сарын дараа арилгадаг"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Хадгалсан файлуудыг арилгах уу?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Бүх бичлэгийг /өгөгдөл/дотоод/ул мөрөөс устгана"</string>
     <string name="clear" msgid="5484761795406948056">"Устгах"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Системийн ул мөр"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, ул мөр, гүйцэтгэл"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ул мөр, ул мөр мөшгөх, гүйцэтгэл, профайл, үнэлгээ, төв процессорын нэгж, callstack, өрөлт, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Файл хуваалцах уу?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Системийн мөрдлөгийн файлд систем болон аппын мэдрэг өгөгдлийг (апп ашиглалт зэрэг) агуулж болзошгүй. Та системийн ул мөрийг зөвхөн итгэдэг хүмүүс болон аппуудтайгаа хуваалцана уу."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Системийн ул мөрийн файлд систем, аппын эмзэг өгөгдөл (аппын ашиглалт, аппын санах ой дахь зураг зэрэг) багтаж болно. Системийн ул мөр, санах ойн агшин зургийг зөвхөн итгэдэг хүн, апптайгаа хуваалцаарай."</string>
     <string name="share" msgid="8443979083706282338">"Хуваалцах"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Дахиж бүү харуул"</string>
     <string name="long_traces" msgid="5110949471775966329">"Урт ул мөр"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Алдааны мэдээнд бичлэгүүд хавсаргах"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Алдааны мэдээг цуглуулсан үед хийгдэж буй бичлэгийг BetterBug-д автоматаар илгээнэ үү. Бичлэгийг дараа нь үргэлжлүүлнэ."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Хадгалсан файлуудыг харах"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Задлан шинжлэх зорилгоор ул мөрийг ui.perfetto.dev-д байршуулж болно"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Санах ойн агшин зургийг AHAT-р шалгах боломжтой"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Ул мөрийн тохиргоо"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Хадгалсан файлууд"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Бусад"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index 140a8aeb..974ae86b 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"हीप डंप रेकॉर्ड करा"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"हीप डंप प्रक्रिया\" यामध्ये निवडलेल्या प्रक्रियांचा हीप डंप कॅप्चर करते"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"हीप डंप गोळा करण्यासाठी \"हीप डंपसंबंधित प्रक्रिया\" यामधून किमान एक प्रक्रिया निवडा"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"बिटमॅपसह AM हीप डंप रेकॉर्ड करा"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"हीप डंप प्रक्रिया\" यामध्ये निवडलेल्या प्रक्रियेचा हीप डंप गोळा करते आणि बिटमॅप इमेज एक्सट्रॅक्ट करते"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"हीप डंप प्रक्रिया\" यामध्ये फक्त एक प्रक्रिया निवडा"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"हीप डंप प्रक्रिया\" यामध्ये प्रक्रिया निवडा"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope ट्रेस गोळा करा"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"तपशीलवार UI टेलीमेट्री डेटाचा समावेश आहे (जॅंक होऊ शकते)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"डीबग करण्यायोग्य ॲप्लिकेशन ट्रेस करा"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"डीफॉल्ट"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# निवडली}other{# निवडल्या}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"हीप डंपसंबंधित प्रक्रिया"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"किमान एक प्रक्रिया निवडणे आवश्‍यक आहे"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"या निवडी Perfetto आणि ActivityManager दोन्हींना लागू होतात"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"हीप डंपसंबंधित प्रक्रिया साफ करा"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"प्रक्रियेची सूची साफ केली आहे"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"सातत्यपूर्ण हीप प्रोफाइल"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"नमूद केलेल्या प्रत्येक मध्यांतरामध्ये हीप डंप एकदा कॅप्चर करा"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"नमूद केलेल्या प्रत्येक मध्यांतरामध्ये हीप डंप एकदा कॅप्चर करा. फक्त Perfetto हीप डंपवर लागू होते."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"हीप डंपमधील मध्यांतर"</string>
     <string name="five_seconds" msgid="7018465440929299712">"५ सेकंद"</string>
     <string name="ten_seconds" msgid="863416601384309033">"१० सेकंद"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"स्टॅकचा नमुना घेणे बंद करण्यासाठी टॅप करा"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"हीप डंप रेकॉर्ड केला जात आहे"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"हीप डंप थांबवण्यासाठी टॅप करा"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM हीप डंप रेकॉर्ड केल जात आहे"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"सेव्ह केलेल्या फाइल साफ करा"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"एका महिन्यानंतर रेकॉर्डिंग साफ केली जातात"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"सेव्ह केलेल्या फाइल साफ करायच्या का?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces मधून सर्व रेकॉर्डिंग हटवली जातील"</string>
     <string name="clear" msgid="5484761795406948056">"साफ करा"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"सिस्टीम ट्रेस"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, माग काढणे, कामगिरी"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, माग ठेवा, माग ठेवणे, परफॉर्मन्स, प्रोफाइल, प्रोफायलिंग, सीपीयू, कॉलस्टॅक, स्टॅक, हीप"</string>
     <string name="share_file" msgid="1982029143280382271">"फाइल शेअर करायची का?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"सिस्टीम ट्रेसिंग फाइलमध्ये संवेदनशील सिस्टीम आणि अ‍ॅप डेटा (जसे की अ‍ॅप वापर) यांचा समावेश असू शकतो. ज्या लोकांवर आणि अ‍ॅपवर तुमचा विश्वास आहे केवळ त्यांच्यासह हा सिस्टीमचे ट्रेस शेअर करा."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"सिस्टीम ट्रेसिंग फाइलमध्ये संवेदनशील सिस्टीम आणि अ‍ॅप डेटा (जसे की अ‍ॅप वापर किंवा अ‍ॅप मेमरीमधील इमेज) यांचा समावेश असू शकतो. ज्या लोकांवर आणि अ‍ॅपवर तुमचा विश्वास आहे केवळ त्यांच्यासह हा सिस्टीम ट्रेस किंवा हीप डंप शेअर करा."</string>
     <string name="share" msgid="8443979083706282338">"शेअर करा"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"पुन्हा दाखवू नका"</string>
     <string name="long_traces" msgid="5110949471775966329">"मोठे ट्रेस"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"बग रिपोर्टना रेकॉर्डिंग जोडा"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"बग रिपोर्ट गोळा केला जातो, तेव्हा सुरू असलेल्या रेकॉर्डिंग BetterBug ला आपोआप पाठवा. रेकॉर्डिंग नंतर सुरू राहतील."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"सेव्ह केलेल्या फाइल पहा"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"विश्लेषणासाठी ट्रेस ui.perfetto.dev वर अपलोड केले जाऊ शकतात"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"हीप डंपची तपासणी AHAT सह करता येते"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"सेटिंग्जचा माग ठेवा"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"सेव्ह केलेल्या फाइल"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"संकीर्ण"</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 643f2ddf..301c339e 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Rakam longgokan timbunan"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Menangkap longgokan timbunan untuk proses yang dipilih dalam \"Proses longgokan timbunan\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Pilih sekurang-kurangnya satu proses dalam \"Proses longgokan timbunan\" untuk mengumpulkan longgokan timbunan"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Rekodkan longgokan timbunan AM dengan bitmap"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Mengumpulkan longgokan timbunan proses yang dipilih dalam \"Proses longgokan timbunan\" dan mengekstrak imej bitmap"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Pilih hanya satu proses dalam \"Proses longgokan timbunan\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Pilih proses dalam \"Proses longgokan timbunan\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Kumpulkan surih Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Termasuk data telemetri UI terperinci (boleh menyebabkan jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Surih aplikasi yang boleh dinyahpepijat"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Lalai"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# dipilih}other{# dipilih}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Proses longgokan timbunan"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Sekurang-kurangnya satu proses perlu dipilih"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Pilihan ini digunakan untuk Perfetto dan ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Kosongkan proses longgokan timbunan"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Senarai proses dikosongkan"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Profil timbunan berterusan"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Tangkap longgokan timbunan sekali untuk setiap selang yang dinyatakan"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Rekodkan longgokan timbunan sekali bagi setiap sela yang dinyatakan. Hanya digunakan untuk longgokan timbunan Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Selang longgokan timbunan"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 saat"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 saat"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Ketik untuk menghentikan pensampelan tindanan"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Longgokan timbunan sedang dirakam"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Ketik untuk menghentikan longgokan timbunan"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Longgokan timbunan AM sedang direkodkan"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Kosongkan fail yang disimpan"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Rakaman dikosongkan selepas satu bulan"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Kosongkan fail yang disimpan?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Semua rakaman akan dipadamkan daripada /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Kosongkan"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Surih sistem"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, surih, prestasi"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, surih, penjejakan, prestasi, profil, pemprofilan, cpu, tindanan panggilan, tindanan, timbunan"</string>
     <string name="share_file" msgid="1982029143280382271">"Kongsi fail?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Fail Penyurihan Sistem mungkin termasuk data sistem dan apl yang sensitif (seperti penggunaan apl). Kongsikan surihan sistem dengan orang dan apl yang anda percayai sahaja."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Fail Penyurihan Sistem mungkin mengandungi data sistem dan apl yang sensitif (seperti penggunaan apl atau imej dalam memori apl). Kongsi surih sistem atau longgokan timbunan dengan pengguna dan apl yang anda percayai sahaja."</string>
     <string name="share" msgid="8443979083706282338">"Kongsi"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Jangan tunjukkan lagi"</string>
     <string name="long_traces" msgid="5110949471775966329">"Surih panjang"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Lampirkan rakaman pada laporan pepijat"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Hantar rakaman yang sedang diproses kepada BetterBug secara automatik apabila laporan pepijat dikumpulkan. Rakan akan diteruskan selepas itu."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Lihat fail yang disimpan"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Surih boleh dimuat naik kepada ui.perfetto.dev untuk analisis"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Longgokan timbunan boleh diperiksa dengan AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Tetapan surih"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Fail yang disimpan"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Pelbagai"</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index e9aa969e..bea27bd3 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"လျှပ်တစ်ပြက် မှတ်ဉာဏ်ကို ရိုက်ကူးရန်"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"“လျှပ်တစ်ပြက် မှတ်ဉာဏ် လုပ်ငန်းစဉ်များ” တွင် ရွေးထားသည့် လုပ်ငန်းစဉ်များ၏ လျှပ်တစ်ပြက် မှတ်ဉာဏ်ကို ရိုက်ကူးပါ"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"လျှပ်တစ်ပြက် မှတ်ဉာဏ်များ စုဆောင်းရန် “လျှပ်တစ်ပြက် မှတ်ဉာဏ် လုပ်ငန်းစဉ်များ” တွင် အနည်းဆုံး လုပ်ငန်းစဉ်တစ်ခုကို ရွေးပါ"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Bitmap များပါသော AM လျှပ်တစ်ပြက် မှတ်ဉာဏ်ကို ဖမ်းယူရန်"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"“လျှပ်တစ်ပြက် မှတ်ဉာဏ် လုပ်ငန်းစဉ်များ” ရှိ ရွေးထားသော လုပ်ငန်းစဉ်၏ လျှပ်တစ်ပြက် မှတ်ဉာဏ်ကို စုစည်းပြီး Bitmap ပုံများ ထုတ်ယူသည်"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"“လျှပ်တစ်ပြက် မှတ်ဉာဏ် လုပ်ငန်းစဉ်များ” ရှိ လုပ်ငန်းစဉ်တစ်ခုကိုသာ ရွေးပါ"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"“လျှပ်တစ်ပြက် မှတ်ဉာဏ် လုပ်ငန်းစဉ်များ” ရှိ လုပ်ငန်းစဉ်ကို ရွေးပါ"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope လုပ်ဆောင်ချက်မှတ်တမ်းများကို စုစည်းရန်"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"အသေးစိတ်ကျသော UI တယ်လီတိုင်းတာမှု ဒေတာပါဝင်သည် (ရပ်တန့်စေနိုင်သည်)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"အမှားရှာပြင်နိုင်သည့် အပလီကေးရှင်းများကို မှတ်တမ်းတင်ရန်"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"မူလ"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# ခု ရွေးထားသည်}other{# ခု ရွေးထားသည်}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"လျှပ်တစ်ပြက် မှတ်ဉာဏ် လုပ်ငန်းစဉ်များ"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"အနည်းဆုံး လုပ်ငန်းစဉ်တစ်ခု ရွေးရမည်"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"ဤရွေးချယ်မှုများသည် Perfetto နှင့် ActivityManager နှစ်ခုစလုံးအတွက် အကျုံးဝင်သည်"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"လျှပ်တစ်ပြက် မှတ်ဉာဏ် လုပ်ငန်းစဉ်များ ရှင်းထုတ်ရန်"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"လုပ်ငန်းစဉ်စာရင်းကို ရှင်းထုတ်လိုက်ပါပြီ"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"ကျပန်းမှတ်ဉာဏ် ပရိုဖိုင် ဆက်တိုက်ရိုက်ခြင်း"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"သတ်မှတ်အချိန်အပိုင်းအခြား တစ်ခုလျှင် လျှပ်တစ်ပြက် မှတ်ဉာဏ်တစ်ခု ရိုက်ကူးသည်"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"သတ်မှတ်အချိန်အပိုင်းအခြား တစ်ခုလျှင် လျှပ်တစ်ပြက် မှတ်ဉာဏ်တစ်ခု ဖမ်းယူသည်။ Perfetto လျှပ်တစ်ပြက် မှတ်ဉာဏ်မျာအတွက်သာ အကျုံးဝင်သည်။"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"လျှပ်တစ်ပြက် မှတ်ဉာဏ် အချိန်အပိုင်းအခြား"</string>
     <string name="five_seconds" msgid="7018465440929299712">"၅ စက္ကန့်"</string>
     <string name="ten_seconds" msgid="863416601384309033">"၁၀ စက္ကန့်"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"အထပ်နမူနာယူခြင်းကို ရပ်ရန် တို့ပါ"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"လျှပ်တစ်ပြက် မှတ်ဉာဏ်ကို ရိုက်ကူးနေသည်"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"လျှပ်တစ်ပြက် မှတ်ဉာဏ်ကို ရပ်ရန် တို့ပါ"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM လျှပ်တစ်ပြက် မှတ်ဉာဏ်ကို ဖမ်းယူနေသည်"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"သိမ်းထားသောဖိုင်များ ရှင်းထုတ်ရန်"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"မှတ်တမ်းများကို တစ်လကြာပြီးနောက် ရှင်းထုတ်သည်"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"သိမ်းထားသော ဖိုင်များကို ရှင်းထုတ်မလား။"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"မှတ်တမ်းအာလုံးကို /data/local/traces မှ ဖျက်လိုက်ပါမည်"</string>
     <string name="clear" msgid="5484761795406948056">"ရှင်းလင်းရန်"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"စနစ် လုပ်ဆောင်ချက်မှတ်တမ်းများ"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace၊ လုပ်ဆောင်ချက်မှတ်တမ်း၊ စွမ်းဆောင်ရည်"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace၊ traceur၊ perfetto၊ winscope၊ လုပ်ဆောင်ချက်မှတ်တမ်း၊ လုပ်ဆောင်ချက်မှတ်တမ်း၊ စွမ်းဆောင်ရည်၊ ပရိုဖိုင်၊ ပရိုဖိုင်လုပ်ခြင်း၊ CPU၊ callstack၊ stack၊ heap"</string>
     <string name="share_file" msgid="1982029143280382271">"ဖိုင်မျှဝေမလား။"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"စနစ် \'လုပ်ဆောင်ချက်မှတ်တမ်း\' ဖိုင်များတွင် အရေးကြီးသောစနစ်နှင့် အက်ပ်ဒေတာများ (အက်ပ်အသုံးပြုမှုကဲ့သို့) ပါဝင်နိုင်သည်။ စနစ်လုပ်ဆောင်ချက်မှတ်တမ်းများကို သင်ယုံကြည့်သည့် လူများ၊ အက်ပ်များနှင့်သာ မျှဝေပါ။"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"‘စနစ် လုပ်ဆောင်ချက်မှတ်တမ်းယူခြင်း’ ဖိုင်များတွင် သတိထားရမည့် စနစ်နှင့် အက်ပ်ဒေတာများ (အက်ပ်အသုံးပြုမှု (သို့) အက်ပ်၏မှတ်ဉာဏ်ရှိ ပုံများ ကဲ့သို့) ပါဝင်နိုင်သည်။ စနစ်လုပ်ဆောင်ချက်မှတ်တမ်း (သို့) လျှပ်တစ်ပြက် မှတ်ဉာဏ်များကို သင်ယုံကြည်သော လူများ၊ အက်ပ်များနှင့်သာ မျှဝေပါ။"</string>
     <string name="share" msgid="8443979083706282338">"မျှဝေရန်"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"ထပ်မပြပါနှင့်"</string>
     <string name="long_traces" msgid="5110949471775966329">"ရှည်ကြာသော လုပ်ဆောင်ချက်မှတ်တမ်းများ"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"မှတ်တမ်းများကို ချွတ်ယွင်းချက်အစီရင်ခံစာတွင် ပူးတွဲရန်"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ချွတ်ယွင်းမှုအစီရင်ခံစာကို စုစည်းသောအခါ ဆောင်ရွက်နေဆဲ အသံဖမ်းချက်များကို BetterBug သို့ အလိုအလျောက် ပို့နိုင်သည်။ ထို့နောက် အသံဖမ်းချက်များကို ဆက်လုပ်မည်။"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"သိမ်းထားသောဖိုင်များ ကြည့်ရန်"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"လုပ်ဆောင်ချက်မှတ်တမ်းများကို ui.perfetto.dev သို့ အပ်လုဒ်လုပ်ပြီး စိတ်ဖြာလေ့လာနိုင်သည်"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"လျှပ်တစ်ပြက် မှတ်ဉာဏ်များကို AHAT ဖြင့် စစ်ဆေးနိုင်သည်"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"လုပ်ဆောင်ချက်မှတ်တမ်း ဆက်တင်များ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"သိမ်းထားသော ဖိုင်များ"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"အထွေထွေ"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index f659d8e0..864ee962 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Utfør minnedump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Utfører en minnedump av prosessene som er valgt i «Minnedumpprosesser»"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Velg minst én prosess i «Minnedumpprosesser» for å utføre minnedumper"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Registrer AM-minnedump med punktgrafikk"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Samler inn en minnedump av prosessen som er valgt i «Minnedumpprosesser», og trekker ut punktgrafikkbilder"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Velg bare én prosess i «Minnedumpprosesser»"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Velg en prosess i «Minnedumpprosesser»"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Samle Winscope-spor"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inkluderer detaljerte UI-telemetridata (kan forårsake gjengivelsespause)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Spor feilsøkbare apper"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Standard"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# er valgt}other{# er valgt}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Minnedumpprosesser"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Du må velge minst én prosess"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Disse valgene gjelder for både Perfetto og ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Fjern minnedumpprosesser"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Prosesslisten er tømt"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Kontinuerlig minneprofil"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Ta en minnedump én gang per spesifisert intervall"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Ta en minnedump én gang per spesifisert intervall. Gjelder bare for Perfetto-minnedumper."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Intervall for minnedump"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekunder"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekunder"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Trykk for å stoppe stabelsampling"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Minnedumpen utføres"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Trykk for å stoppe minnedumpen"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM-minnedumpen registreres"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Fjern lagrede filer"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Opptak fjernes etter én måned"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Vil du fjerne lagrede filer?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Alle opptak slettes fra /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Fjern"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Systemspor"</string>
-    <string name="keywords" msgid="736547007949049535">"sysspor, spor, ytelse"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, spor, sporing, ytelse, profil, profilering, prosessor, callstack, stabel, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Vil du dele filen?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Systemsporingsfiler kan inneholde sensitive system- og appdata (for eksempel appbruk). Du bør bare dele systemsporingsfiler med personer og apper du stoler på."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Systemsporingsfiler kan inneholde sensitive system- og appdata (for eksempel appbruk eller bilder i en apps minne). Du bør bare dele systemspor eller minnedumper med personer og apper du stoler på."</string>
     <string name="share" msgid="8443979083706282338">"Del"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Ikke vis igjen"</string>
     <string name="long_traces" msgid="5110949471775966329">"Lange spor"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Legg ved opptak i feilrapporter"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Send automatisk aktive opptak til BetterBug når det samles inn feilrapporter. Opptakene fortsetter etterpå."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Se lagrede filer"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Spor kan lastes opp til ui.perfetto.dev for analyse"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Minnedumper kan inspiseres med AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Innstillinger for sporing"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Lagrede filer"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Diverse"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index e5d35af2..575c7f97 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"हिप डम्प रेकर्ड गर्नुहोस्"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"हिप डम्पका प्रोसेसहरू\" मा चयन गरिएका प्रोसेसहरूको हिप डम्प रेकर्ड गर्छ"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"हिप डम्पहरू सङ्कलन गर्न \"हिप डम्पका प्रोसेसहरू\" मा कम्तीमा पनि एउटा प्रोसेस चयन गर्नुहोस्"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"बिटम्यापहरू प्रयोग गरी AM हिप डम्प रेकर्ड गर्नुहोस्"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"हिप डम्पका प्रोसेसहरू\" मा चयन गरिएका प्रोसेसहरूको हिप डम्प सङ्कलन गर्छ र बिटम्याप फोटोहरू एक्स्ट्रयाक्ट गर्छ"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"हिप डम्पका प्रोसेसहरू\" मा एउटा प्रोसेस मात्र चयन गर्नुहोस्"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"हिप डम्पका प्रोसेसहरू\" मा कुनै प्रोसेस चयन गर्नुहोस्"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Collect Winscope का ट्रेसहरू सङ्कलन गर्नुहोस्"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"यसमा UI टेलिमेट्रीको विस्तृत डेटा (ज्याङ्क हुन सक्छ) समावेश गरिएको हुन्छ"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"डिबग गर्न मिल्ने एपहरू पत्ता लगाउनुहोस्"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"डिफल्ट"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# वटा चयन गरिएका छन्}other{# वटा चयन गरिएका छन्}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"हिप डम्पका प्रोसेसहरू"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"कम्तीमा पनि एउटा प्रोसेस अनिवार्य रूपमा चयन गर्नु पर्छ"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"चयन गरिएका यी सेटिङ Perfetto र ActivityManager दुवैमा लागू हुन्छन्"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"हिप डम्पका प्रोसेसहरू हटाउनुहोस्"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"सूचीमा भएका प्रोसेसहरू हटाइए"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"निरन्तरको हिप प्रोफाइल"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"तोकिएको अन्तरालमा एक पटकमा एउटा हिप डम्प रेकर्ड गर्नुहोस्"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"तोकिएको अन्तरालमा एक पटकमा एउटा हिप डम्प रेकर्ड गर्नुहोस्। यो कुरा Perfetto हिप डम्पमा मात्र लागू हुन्छ।"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"हिप डम्पको अन्तराल"</string>
     <string name="five_seconds" msgid="7018465440929299712">"५ सेकेन्ड"</string>
     <string name="ten_seconds" msgid="863416601384309033">"१० सेकेन्ड"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"स्ट्याक स्याम्पलिङ रोक्न ट्याप गर्नुहोस्"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"हिप डम्प रेकर्ड गरिँदै छ"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"हिप डम्प रेकर्ड गर्ने कार्य रोक्न ट्याप गर्नुहोस्"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM हिप डम्प रेकर्ड गरिँदै छ"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"सेभ गरिएका फाइलहरू हटाउनुहोस्"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"रेकर्डिङहरू एक महिनापछि स्वतः हटाइन्छन्"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"सेभ गरिएका फाइलहरू हटाउने हो?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces मा रहेका सबै रेकर्डिङहरू मेटाइने छन्"</string>
     <string name="clear" msgid="5484761795406948056">"खाली गर्नुहोस्"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"प्रणालीका ट्रेसहरू"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, ट्रेस, कार्यसम्पादन"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ट्रेस, ट्रेसिङ, पर्फर्मेन्स, प्रोफाइल, प्रोफाइलिङ, CPU, कलस्ट्याक, स्ट्याक, हिप"</string>
     <string name="share_file" msgid="1982029143280382271">"यो फाइल सेयर गर्ने हो?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"प्रणालीले पत्ता लगाएको फाइलहरूमा संवेदनशील प्रणाली र एप डेटा (जस्तै एपको उपयोग) समावेश हुन सक्छ। तपाईंले विश्वास गर्ने मान्छेहरूलाई मात्र प्रणालीले पत्ता लगाएको फाइलहरू सेयर गर्नुहोस्‌।"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"सिस्टम ट्रेसिङ फाइलमा सिस्टम तथा एपसम्बन्धी संवेदनशील डेटा (जस्तै, एपको प्रयोगसम्बन्धी डेटा वा एपको मेमोरीमा भएका फोटोहरू) समावेश हुन सक्छन्। विश्वसनीय मान्छे र एपहरूसँग मात्र सिस्टमका ट्रेस वा हिप डम्पहरू सेयर गर्नुहोस्।"</string>
     <string name="share" msgid="8443979083706282338">"सेयर गर्नुहोस्"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"फेरि नदेखाउनुहोस्"</string>
     <string name="long_traces" msgid="5110949471775966329">"लामो ट्रेसहरू"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"त्रुटिसम्बन्धी रिपोर्टहरूमा रेकर्डिङहरू एट्याच गर्नुहोस्"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"त्रुटिसम्बन्धी रिपोर्ट सङ्कलन गरिँदा जारी रहेका रेकर्डिङहरू BetterBug मा स्वतः पठाउनुहोस्। त्यसपछि रेकर्ड गर्ने क्रम जारी रहने छ।"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"सेभ गरिएका फाइलहरू हेर्नुहोस्"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"विश्लेषण गर्ने प्रयोजनका लागि ट्रेसहरू ui.perfetto.dev मा अपलोड गरिन सकिन्छ"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"AHAT प्रयोग गरी हिप डम्पहरू जाँच्न सकिन्छ"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ट्रेससम्बन्धी सेटिङ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"सेभ गरिएका फाइलहरू"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"विविध"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index 8d1e4b37..4e6931b0 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Heap dump opnemen"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Legt een heap dump vast van de processen die zijn geselecteerd in Heap dumprocessen"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecteer ten minste één proces in Heap dump-processen om heap dumps te verzamelen"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Heap dump van AM met bitmaps opnemen"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Verzamelt een heap dump van het proces dat is geselecteerd in Heap dump-processen en haalt bitmapafbeeldingen op"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Selecteer maar één proces in Heap dump-processen"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Selecteer een proces in Heap dump-processen"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope-sporen verzamelen"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Omvat gedetailleerde UI-telemetriegegevens (kan een onderbreking in de weergave veroorzaken)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Beschikbare apps voor foutopsporing traceren"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Standaard"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# geselecteerd}other{# geselecteerd}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Heap dump-processen"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Er moet ten minste één proces zijn geselecteerd."</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Deze selecties zijn van toepassing op zowel Perfetto als ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Heap dump-processen wissen"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Proceslijst gewist"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Continu heapprofiel"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Leg eenmaal per gespecificeerd interval een heap dump vast"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Leg eenmaal per aangegeven interval een heap dump vast. Geldt alleen voor heap dumps van Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Interval voor heap dump"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 seconden"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 seconden"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Tik om stack-sampling te stoppen"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Heap dump wordt opgenomen"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Tikken om heap dump te stoppen"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Heap dump van AM wordt opgenomen"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Opgeslagen bestanden wissen"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Opnamen worden na één maand gewist"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Opgeslagen bestanden wissen?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Alle opnamen worden verwijderd uit /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Wissen"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Systeemsporen"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, trace, prestaties"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, trace, tracering, prestaties, profiel, profilering, cpu, callstack, stack, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Bestand delen?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Bestanden voor systeemtracering kunnen gevoelige systeem- en app-gegevens bevatten (bijvoorbeeld over app-gebruik). Deel alleen systeemtraceringen met mensen en apps die je vertrouwt."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"System Tracing-bestanden kunnen gevoelige systeem- en app-gegevens bevatten (bijvoorbeeld app-gebruik of afbeeldingen in het geheugen van een app). Deel systeemtraceringen of heap dumps alleen met mensen en apps die je vertrouwt."</string>
     <string name="share" msgid="8443979083706282338">"Delen"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Niet meer tonen"</string>
     <string name="long_traces" msgid="5110949471775966329">"Lange traces"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Opnamen toevoegen aan bugrapporten"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Stuur lopende opnamen automatisch naar BetterBug als een bugrapport wordt verzameld. De opnamen gaan gewoon verder."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Opgeslagen bestanden bekijken"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Traceringen kunnen worden geüpload naar ui.perfetto.dev voor analyse"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Heap dumps kunnen worden geïnspecteerd met AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Traceringsinstellingen"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Opgeslagen bestanden"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Overig"</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 4cecc1ac..aa6b9e94 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ହିପ ଡମ୍ପ ରେକର୍ଡ କରନ୍ତୁ"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"ହିପ ଡମ୍ପ ପ୍ରକ୍ରିୟା\"ରେ ଚୟନିତ ପ୍ରକ୍ରିୟାଗୁଡ଼ିକର ଏକ ହିପ ଡମ୍ପକୁ କେପଚର କରେ"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ହିପ ଡମ୍ପ ସଂଗ୍ରହ କରିବାକୁ \"ହିପ ଡମ୍ପ ପ୍ରକ୍ରିୟାଗୁଡ଼ିକ\"ରୁ ଅତି କମରେ ଗୋଟିଏ ପ୍ରକ୍ରିୟା ଚୟନ କରନ୍ତୁ"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"ବିଟମେପ ସହିତ AM ହିପ ଡମ୍ପକୁ ରେକର୍ଡ କରନ୍ତୁ"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"ହିପ ଡମ୍ପ ପ୍ରକ୍ରିୟାଗୁଡ଼ିକ\"ରେ ଚୟନ କରାଯାଇଥିବା ପ୍ରକ୍ରିୟାର ଏକ ହିପ ଡମ୍ପ ସଂଗ୍ରହ କରେ ଏବଂ ବିଟମେପ ଇମେଜ ଏକ୍ସଟ୍ରାକ୍ଟ କରେ"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"ହିପ ଡମ୍ପ ପ୍ରକ୍ରିୟାଗୁଡ଼ିକ\"ରେ କେବଳ ଗୋଟିଏ ପ୍ରକ୍ରିୟା ଚୟନ କରନ୍ତୁ"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"ହିପ ଡମ୍ପ ପ୍ରକ୍ରିୟାଗୁଡ଼ିକ\"ରେ ଗୋଟିଏ ପ୍ରକ୍ରିୟା ଚୟନ କରନ୍ତୁ"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope ଟ୍ରେସ ସଂଗ୍ରହ କରନ୍ତୁ"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"ସବିଶେଷ UI ଟେଲିମେଟ୍ରି ଡାଟା ଅନ୍ତର୍ଭୁକ୍ତ କରେ (ଜଙ୍କ ସୃଷ୍ଟି କରିପାରେ)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ଡିବଗଯୋଗ୍ୟ ଆପ୍ଲିକେସନକୁ ଟ୍ରେସ କରନ୍ତୁ"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ଡିଫଲ୍ଟ"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{#ଟି ବର୍ଗ ଚୟନ କରାଯାଇଛି}other{#ଟି ବର୍ଗ ଚୟନ କରାଯାଇଛି}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"ହିପ ଡମ୍ପ ପ୍ରକ୍ରିୟାଗୁଡ଼ିକ"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"ଅତି କମରେ ଗୋଟିଏ ପ୍ରକ୍ରିୟା ଚୟନ କରାଯିବା ଆବଶ୍ୟକ"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"ଏହି ଚୟନଗୁଡ଼ିକ ଉଭୟ Perfetto ଏବଂ ActivityManager ପାଇଁ ପ୍ରଯୁଜ୍ୟ"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"ହିପ ଡମ୍ପ ପ୍ରକ୍ରିୟାଗୁଡ଼ିକ ଖାଲି କରନ୍ତୁ"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"ପ୍ରକ୍ରିୟା ତାଲିକା ଖାଲି କରାଯାଇଛି"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"ଅବିରତ ହିପ ପ୍ରୋଫାଇଲ"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"ପ୍ରତି ନିର୍ଦ୍ଦିଷ୍ଟ ଅବଧି ପାଇଁ ଏକ ହିପ ଡମ୍ପ କେପଚର କରନ୍ତୁ"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"ପ୍ରତି ନିର୍ଦ୍ଦିଷ୍ଟ ବ୍ୟବଧାନରେ ଥରେ ଏକ ହିପ ଡମ୍ପ କେପଚର କରନ୍ତୁ। କେବଳ Perfetto ହିପ ଡମ୍ପ ପାଇଁ ପ୍ରଯୁଜ୍ୟ।"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"ହିପ ଡମ୍ପର ଅବଧି"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 ସେକେଣ୍ଡ"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 ସେକେଣ୍ଡ"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"ଷ୍ଟାକ ସାମ୍ପଲିଂ ବନ୍ଦ କରିବାକୁ ଟାପ କରନ୍ତୁ"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"ହିପ ଡମ୍ପ ରେକର୍ଡ କରାଯାଉଛି"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"ହିପ ଡମ୍ପ ବନ୍ଦ କରିବା ପାଇଁ ଟାପ କରନ୍ତୁ"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM ହିପ ଡମ୍ପକୁ ରେକର୍ଡ କରାଯାଉଛି"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"ସେଭ କରାଯାଇଥିବା ଫାଇଲଗୁଡ଼ିକୁ ଖାଲି କରନ୍ତୁ"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ଗୋଟିଏ ମାସ ପରେ ରେକର୍ଡିଂଗୁଡ଼ିକୁ ଖାଲି କରାଯାଏ"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"ସେଭ କରାଯାଇଥିବା ଫାଇଲଗୁଡ଼ିକୁ ଖାଲି କରିବେ?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/ଡାଟା/ସ୍ଥାନୀୟ/ଟ୍ରେସଗୁଡ଼ିକରୁ ସମସ୍ତ ରେକର୍ଡିଂ ଡିଲିଟ ହୋଇଯିବ"</string>
     <string name="clear" msgid="5484761795406948056">"ଖାଲି କରନ୍ତୁ"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"ସିଷ୍ଟମ୍‍ ଟ୍ରେସ୍‍‍‍‍‍‍‍‍‍ଗୁଡିକ"</string>
-    <string name="keywords" msgid="736547007949049535">"ସିଷ୍ଟ୍ରେସ୍, ଏସ୍, ପରଫର୍ମାନ୍ସ"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ଟ୍ରେସ, ଟ୍ରେସିଂ, ପରଫରମାନ୍ସ, ପ୍ରୋଫାଇଲ, ପ୍ରୋଫାଇଲିଂ, CPU, କଲଷ୍ଟାକ, ଷ୍ଟାକ, ହିପ"</string>
     <string name="share_file" msgid="1982029143280382271">"ଫାଇଲ ସେୟାର କରିବେ?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"ସିଷ୍ଟମ୍‍ ଟ୍ରେସିଂ ଫାଇଲ୍‍ଗୁଡିକ ହୁଏତ ସମ୍ବେଦନଶୀଳ ସିଷ୍ଟମ୍‍ ଏବଂ ଆପ୍‍ ଡାଟା (ଯେପରି କି ଆପ୍‍ ବ୍ୟବହାର) ଅନ୍ତର୍ଭୁକ୍ତ କରିପାରେ। ସିଷ୍ଟମ୍‍ ଟ୍ରେସ୍‍ କେବଳ ଆପଣ ବିଶ୍ବାସ କରୁଥିବା ଲୋକ ଏବଂ ଆପ୍ସ ସହ ସେୟାର୍‍ କରନ୍ତୁ।"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"ସିଷ୍ଟମ ଟ୍ରେସିଂ ଫାଇଲଗୁଡ଼ିକରେ ସମ୍ବେଦନଶୀଳ ସିଷ୍ଟମ ଏବଂ ଆପ ଡାଟା (ଯେପରି ଆପ ବ୍ୟବହାର କିମ୍ବା ଆପର ମେମୋରୀରେ ଥିବା ଇମେଜ) ଅନ୍ତର୍ଭୁକ୍ତ ହୋଇପାରେ। କେବଳ ଆପଣ ବିଶ୍ୱାସ କରୁଥିବା ଲୋକ ଏବଂ ଆପ୍ସ ସହିତ ସିଷ୍ଟମ ଟ୍ରେସ କିମ୍ବା ହିପ ଡମ୍ପ ସେୟାର କରନ୍ତୁ।"</string>
     <string name="share" msgid="8443979083706282338">"ସେୟାର୍‍ କରନ୍ତୁ"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"ପୁଣି ଦେଖାନ୍ତୁ ନାହିଁ"</string>
     <string name="long_traces" msgid="5110949471775966329">"ଲମ୍ବା ଟ୍ରେସ"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ବଗ ରିପୋର୍ଟଗୁଡ଼ିକରେ ରେକର୍ଡିଂ ଆଟାଚ କରନ୍ତୁ"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ଏକ ବଗ ରିପୋର୍ଟ ସଂଗ୍ରହ ହେଲେ BetterBugକୁ ରେକର୍ଡିଂ ସ୍ୱତଃ ପଠାଯାଏ। ଏହାପରେ ରେକର୍ଡିଂ ଜାରି ରହିବ।"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"ସେଭ କରାଯାଇଥିବା ଫାଇଲଗୁଡ଼ିକୁ ଦେଖନ୍ତୁ"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"ବିଶ୍ଳେଷଣ ପାଇଁ ଟ୍ରେସଗୁଡ଼ିକୁ ui.perfetto.devରେ ଅପଲୋଡ କରାଯାଇପାରିବ"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"AHAT ସାହାଯ୍ୟରେ ହିପ ଡମ୍ପଗୁଡ଼ିକୁ ଯାଞ୍ଚ କରାଯାଇପାରିବ"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ଟ୍ରେସ ସେଟିଂସ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ସେଭ କରାଯାଇଥିବା ଫାଇଲଗୁଡ଼ିକ"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"ବିବିଧ"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 46281128..9273588d 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -2,7 +2,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="system_tracing" msgid="4719188511746319848">"ਸਿਸਟਮ ਟ੍ਰੇਸਿੰਗ"</string>
-    <string name="record_system_activity" msgid="4339462312915377825">"ਕਾਰਗੁਜ਼ਾਰੀ ਨੂੰ ਬਿਹਤਰ ਬਣਾਉਣ ਲਈ ਸਿਸਟਮ ਸਰਗਰਮੀ ਰਿਕਾਰਡ ਕਰਕੇ ਬਾਅਦ ਵਿੱਚ ਇਸਦਾ ਵਿਸ਼ਲੇਸ਼ਣ ਕਰੋ"</string>
+    <string name="record_system_activity" msgid="4339462312915377825">"ਕਾਰਗੁਜ਼ਾਰੀ ਨੂੰ ਬਿਹਤਰ ਬਣਾਉਣ ਲਈ ਸਿਸਟਮ ਸਰਗਰਮੀ ਰਿਕਾਰਡ ਕਰ ਕੇ ਬਾਅਦ ਵਿੱਚ ਇਸਦਾ ਵਿਸ਼ਲੇਸ਼ਣ ਕਰੋ"</string>
     <string name="record_trace" msgid="6416875085186661845">"ਟ੍ਰੇਸ ਰਿਕਾਰਡ ਕਰੋ"</string>
     <string name="record_trace_summary" msgid="6705357754827849292">"\"ਟ੍ਰੇਸ ਸੈਟਿੰਗਾਂ\" ਵਿੱਚ ਸੰਰੂਪਣ ਸੈੱਟ ਦੀ ਵਰਤੋਂ ਕਰ ਕੇ ਇੱਕ ਸਿਸਟਮ ਟ੍ਰੇਸ ਨੂੰ ਕੈਪਚਰ ਕਰਦਾ ਹੈ"</string>
     <string name="record_stack_samples" msgid="3498368637185702335">"CPU ਪ੍ਰੋਫਾਈਲ ਨੂੰ ਰਿਕਾਰਡ ਕਰੋ"</string>
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ਹੀਪ ਡੰਪ ਨੂੰ ਰਿਕਾਰਡ ਕਰੋ"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"ਹੀਪ ਡੰਪ ਪ੍ਰਕਿਰਿਆਵਾਂ\" ਵਿੱਚ ਚੁਣੀਆਂ ਗਈਆਂ ਪ੍ਰਕਿਰਿਆਵਾਂ ਦੇ ਹੀਪ ਡੰਪ ਨੂੰ ਕੈਪਚਰ ਕਰਦਾ ਹੈ"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ਹੀਪ ਡੰਪ ਇਕੱਤਰ ਕਰਨ ਲਈ \"ਹੀਪ ਡੰਪ ਪ੍ਰਕਿਰਿਆਵਾਂ\" ਵਿੱਚ ਘੱਟੋ-ਘੱਟ ਇੱਕ ਪ੍ਰਕਿਰਿਆ ਚੁਣੋ"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"ਬਿਟ ਮੈਪਾਂ ਨਾਲ AM ਹੀਪ ਡੰਪ ਰਿਕਾਰਡ ਕਰੋ"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"ਇਸ ਨਾਲ \"ਹੀਪ ਡੰਪ ਪ੍ਰਕਿਰਿਆਵਾਂ\" ਵਿੱਚ ਚੁਣੀ ਗਈ ਪ੍ਰਕਿਰਿਆ ਦਾ ਹੀਪ ਡੰਪ ਇਕੱਤਰ ਕਰਨ ਅਤੇ ਬਿਟਮੈਪ ਚਿੱਤਰਾਂ ਨੂੰ ਐਕਸਟਰੈਕਟ ਕਰਨ ਵਿੱਚ ਮਦਦ ਮਿਲਦੀ ਹੈ"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"ਹੀਪ ਡੰਪ ਪ੍ਰਕਿਰਿਆਵਾਂ\" ਵਿੱਚ ਜਾ ਕੇ ਸਿਰਫ਼ ਇੱਕ ਪ੍ਰਕਿਰਿਆ ਨੂੰ ਚੁਣੋ"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"ਹੀਪ ਡੰਪ ਪ੍ਰਕਿਰਿਆਵਾਂ\" ਵਿੱਚ ਜਾ ਕੇ ਕੋਈ ਪ੍ਰਕਿਰਿਆ ਨੂੰ ਚੁਣੋ"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope ਟ੍ਰੇਸਾਂ ਨੂੰ ਇਕੱਤਰ ਕਰੋ"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"ਇਸ ਵਿੱਚ ਵੇਰਵੇ ਸਹਿਤ UI ਟੈਲੀਮੈਟਰੀ ਡਾਟਾ ਸ਼ਾਮਲ ਹੈ (ਇਹ ਜੈਂਕ ਦਾ ਕਾਰਨ ਬਣ ਸਕਦਾ ਹੈ)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ਡੀਬੱਗਯੋਗ ਐਪਲੀਕੇਸ਼ਨਾਂ ਟ੍ਰੇਸ ਕਰੋ"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ਪੂਰਵ-ਨਿਰਧਾਰਿਤ"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# ਚੁਣੀ ਗਈ}one{# ਚੁਣੀ ਗਈ}other{# ਚੁਣੀਆਂ ਗਈਆਂ}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"ਹੀਪ ਡੰਪ ਪ੍ਰਕਿਰਿਆਵਾਂ"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"ਘੱਟੋ-ਘੱਟ ਇੱਕ ਪ੍ਰਕਿਰਿਆ ਨੂੰ ਚੁਣਨਾ ਲਾਜ਼ਮੀ ਹੈ"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"ਇਹ ਚੋਣਾਂ Perfetto ਅਤੇ ActivityManager, ਦੋਵਾਂ \'ਤੇ ਲਾਗੂ ਹੁੰਦੀਆਂ ਹਨ"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"ਹੀਪ ਡੰਪ ਪ੍ਰਕਿਰਿਆਵਾਂ ਨੂੰ ਕਲੀਅਰ ਕਰੋ"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"ਪ੍ਰਕਿਰਿਆ ਦੀ ਸੂਚੀ ਨੂੰ ਕਲੀਅਰ ਕੀਤਾ ਗਿਆ"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"ਲਗਾਤਾਰ ਜਾਰੀ ਹੀਪ ਪ੍ਰੋਫਾਈਲ"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"ਪ੍ਰਤੀ ਨਿਰਧਾਰਿਤ ਕੀਤੇ ਅੰਤਰਾਲ ਵਿੱਚ ਇੱਕ ਵਾਰ ਹੀਪ ਡੰਪ ਨੂੰ ਕੈਪਚਰ ਕਰੋ"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"ਪ੍ਰਤੀ ਨਿਰਧਾਰਿਤ ਕੀਤੇ ਅੰਤਰਾਲ ਵਿੱਚ ਇੱਕ ਵਾਰ ਹੀਪ ਡੰਪ ਨੂੰ ਕੈਪਚਰ ਕਰੋ। ਸਿਰਫ਼ Perfetto ਦੇ ਹੀਪ ਡੰਪਾਂ \'ਤੇ ਲਾਗੂ ਹੁੰਦੀ ਹੈ।"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"ਹੀਪ ਡੰਪ ਅੰਤਰਾਲ"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 ਸਕਿੰਟ"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 ਸਕਿੰਟ"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"ਸਟੈਕ ਸੈਂਪਲਿੰਗ ਨੂੰ ਰੋਕਣ ਲਈ ਟੈਪ ਕਰੋ"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"ਹੀਪ ਡੰਪ ਨੂੰ ਰਿਕਾਰਡ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"ਹੀਪ ਡੰਪ ਨੂੰ ਬੰਦ ਕਰਨ ਲਈ ਟੈਪ ਕਰੋ"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM ਦੇ ਹੀਪ ਡੰਪ ਨੂੰ ਰਿਕਾਰਡ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"ਰੱਖਿਅਤ ਕੀਤੀਆਂ ਫ਼ਾਈਲਾਂ ਨੂੰ ਕਲੀਅਰ ਕਰੋ"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ਇੱਕ ਮਹੀਨੇ ਬਾਅਦ ਰਿਕਾਰਡਿੰਗਾਂ ਕਲੀਅਰ ਹੋ ਜਾਂਦੀਆਂ ਹਨ"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"ਕੀ ਰੱਖਿਅਤ ਕੀਤੀਆਂ ਫ਼ਾਈਲਾਂ ਨੂੰ ਕਲੀਅਰ ਕਰਨਾ ਹੈ?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"ਸਾਰੀਆਂ ਰਿਕਾਰਡਿੰਗਾਂ ਨੂੰ /ਡਾਟਾ/ਸਥਾਨਕ/ਟ੍ਰੇਸਾਂ ਵਿੱਚੋਂ ਮਿਟਾਇਆ ਜਾਵੇਗਾ"</string>
     <string name="clear" msgid="5484761795406948056">"ਕਲੀਅਰ ਕਰੋ"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"ਸਿਸਟਮ ਟ੍ਰੇਸਾਂ"</string>
-    <string name="keywords" msgid="736547007949049535">"ਸਿਸਟ੍ਰੇਸ, ਟ੍ਰੇਸ, ਪ੍ਰਦਰਸ਼ਨ"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ਟ੍ਰੇਸ, ਟ੍ਰੇਸਿੰਗ, ਕਾਰਗੁਜ਼ਾਰੀ, ਪ੍ਰੋਫਾਈਲ, ਪ੍ਰੋਫਾਈਲਿੰਗ, cpu, ਕਾਲਸਟੈਕ, ਸਟੈਕ, ਹੀਪ"</string>
     <string name="share_file" msgid="1982029143280382271">"ਕੀ ਫ਼ਾਈਲ ਸਾਂਝੀ ਕਰਨੀ ਹੈ?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"ਸਿਸਟਮ ਟ੍ਰੇਸਿੰਗ ਫ਼ਾਈਲਾਂ ਵਿੱਚ ਸੰਵੇਦਨਸ਼ੀਲ ਸਿਸਟਮ ਅਤੇ ਐਪ ਡਾਟਾ (ਜਿਵੇਂ ਕਿ ਐਪ ਵਰਤੋਂ) ਸ਼ਾਮਲ ਹੋ ਸਕਦਾ ਹੈ। ਸਿਸਟਮ ਟ੍ਰੇਸਾਂ ਨੂੰ ਸਿਰਫ਼ ਆਪਣੇ ਭਰੋਸੇਯੋਗ ਲੋਕਾਂ ਅਤੇ ਐਪਾਂ ਨਾਲ ਸਾਂਝਾ ਕਰੋ।"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"ਸਿਸਟਮ ਟ੍ਰੇਸਿੰਗ ਫ਼ਾਈਲਾਂ ਵਿੱਚ ਸੰਵੇਦਨਸ਼ੀਲ ਸਿਸਟਮ ਅਤੇ ਐਪ ਡਾਟਾ (ਜਿਵੇਂ ਕਿ ਐਪ ਵਰਤੋਂ ਜਾਂ ਐਪ ਦੀ ਮੈਮੋਰੀ ਵਿੱਚ ਚਿੱਤਰ) ਸ਼ਾਮਲ ਹੋ ਸਕਦਾ ਹੈ। ਸਿਸਟਮ ਟ੍ਰੇਸਾਂ ਜਾਂ ਹੀਪ ਡੰਪਾਂ ਨੂੰ ਸਿਰਫ਼ ਆਪਣੇ ਭਰੋਸੇਯੋਗ ਲੋਕਾਂ ਅਤੇ ਐਪਾਂ ਨਾਲ ਸਾਂਝਾ ਕਰੋ।"</string>
     <string name="share" msgid="8443979083706282338">"ਸਾਂਝਾ ਕਰੋ"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"ਦੁਬਾਰਾ ਨਾ ਦਿਖਾਓ"</string>
     <string name="long_traces" msgid="5110949471775966329">"ਲੰਮੀਆਂ ਟ੍ਰੇਸਾਂ"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"ਬੱਗ ਰਿਪੋਰਟਾਂ ਨਾਲ ਰਿਕਾਰਡਿੰਗਾਂ ਨੱਥੀ ਕਰੋ"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ਬੱਗ ਰਿਪੋਰਟ ਇਕੱਤਰ ਹੋ ਜਾਣ \'ਤੇ ਪ੍ਰਕਿਰਿਆ-ਅਧੀਨ ਰਿਕਾਰਡਿੰਗਾਂ ਨੂੰ ਸਵੈਚਲਿਤ ਤੌਰ \'ਤੇ BetterBug ਨੂੰ ਭੇਜੋ। ਰਿਕਾਰਡਿੰਗਾਂ ਇਸ ਤੋਂ ਬਾਅਦ ਵੀ ਜਾਰੀ ਰਹਿਣਗੀਆਂ।"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"ਰੱਖਿਅਤ ਕੀਤੀਆਂ ਫ਼ਾਈਲਾਂ ਦੇਖੋ"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"ਵਿਸ਼ਲੇਸ਼ਣ ਲਈ ਟ੍ਰੇਸ ui.perfetto.dev \'ਤੇ ਅੱਪਲੋਡ ਕੀਤੇ ਜਾ ਸਕਦੇ ਹਨ"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"ਹੀਪ ਡੰਪਾਂ ਦੀ ਜਾਂਚ AHAT ਨਾਲ ਕੀਤੀ ਜਾ ਸਕਦੀ ਹੈ"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ਟ੍ਰੇਸ ਸੈਟਿੰਗਾਂ"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ਰੱਖਿਅਤ ਕੀਤੀਆਂ ਗਈਆਂ ਫ਼ਾਈਲਾਂ"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"ਫੁਟਕਲ"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 2f7e4b6e..88fd3202 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Rejestruj zrzut stosu"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Przechwytuje zrzut stosu procesów wybranych w ramach „Procesy zrzutu stosu”."</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Wybierz co najmniej 1 proces w ramach „Procesy zrzutu stosu”, aby zapisywać zrzuty stosu"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Rejestruj zrzuty stosu aplikacji AM z bitmapami"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Zbiera zrzut stosu procesu wybranego w sekcji „Procesy zrzutu stosu” i wyodrębnia obrazy bitmapowe"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Wybierz tylko 1 proces w sekcji „Procesy zrzutu stosu”"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Wybierz proces w sekcji „Procesy zrzutu stosu”"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Zbieraj ślady Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Obejmuje szczegółowe dane telemetryczne interfejsu użytkownika (może powodować zacinanie)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Śledź aplikacje z możliwością debugowania"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Domyślne"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{wybrano #}few{wybrano #}many{wybrano #}other{wybrano #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Procesy zrzutu stosu"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Wybierz co najmniej proces"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Wybrane ustawienia dotyczą zarówno aplikacji Perfetto, jak i ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Wyczyść procesy zrzutu stosu"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Lista procesów wyczyszczona"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Ciągły profil stosu"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Przechwyć zrzut stosu raz na określony interwał"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Przechwytuj zrzut stosu z określoną częstotliwością. Dotyczy to tylko zrzutów stosu aplikacji Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Interwał zrzutu stosu"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekund"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekund"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Kliknij, aby zatrzymać próbkowanie stosu"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Zrzut stosu jest rejestrowany"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Kliknij, aby zatrzymać zrzut stosu"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Trwa rejestrowanie zrzutu stosu aplikacji AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Usuń zapisane pliki"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Nagrania są usuwane po miesiącu"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Usunąć zapisane pliki?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Wszystkie nagrania zostaną usunięte z katalogu /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Wyczyść"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Ślady systemu"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, śledzenie, wydajność"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ślad, śledzenie, wydajność, profil, profilowanie, procesor, stos wywołań, stos, sterta"</string>
     <string name="share_file" msgid="1982029143280382271">"Udostępnić plik?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Pliki śledzenia systemu mogą zawierać poufne dane dotyczące systemu i aplikacji (np. o użyciu aplikacji). Śledzenie systemu i aplikacji udostępniaj tylko zaufanym osobom."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Pliki śledzenia systemu mogą zawierać poufne dane dotyczące systemu i aplikacji (np. informacje o korzystaniu z nich lub obrazy w ich pamięci). Udostępniaj ślady systemowe lub zrzuty stosu tylko osobom i aplikacjom, którym ufasz."</string>
     <string name="share" msgid="8443979083706282338">"Udostępnij"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Nie pokazuj ponownie"</string>
     <string name="long_traces" msgid="5110949471775966329">"Długie ślady"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Załączaj nagrania do raportów o błędach"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Automatycznie przesyłaj przetwarzane nagrania do BetterBug podczas tworzenia raportu o błędzie. Po przesłaniu danych nagranie będzie kontynuowane."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Wyświetl zapisane pliki"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Ślady można przesyłać do ui.perfetto.dev w celu przeprowadzenia analizy"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Zrzuty stosu można sprawdzać za pomocą AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Ustawienia monitorowania"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Zapisane pliki"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Inne"</string>
diff --git a/res/values-pt-rBR/strings.xml b/res/values-pt-rBR/strings.xml
index 5bc5b914..95f934ed 100644
--- a/res/values-pt-rBR/strings.xml
+++ b/res/values-pt-rBR/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Gravar heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captura um heap dump dos processos selecionados em \"Processos de heap dump\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecionar pelo menos um dos processos em \"Processos de heap dump\" para coletar heap dumps"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Gravar o heap dump do AM com bitmaps"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Coleta um heap dump do item selecionado em \"Processos de heap dump\" e extrai imagens de bitmap"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Selecione apenas um item em \"Processos de heap dump\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Selecione um item em \"Processos de heap dump\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Coletar rastros do Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inclui dados detalhados de telemetria da interface e pode causar instabilidade"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Rastrear aplicativos depuráveis"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Padrão"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# selecionada}one{# selecionada}other{# selecionadas}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Processos de heap dump"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Pelo menos um processo precisa ser selecionado"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Essas seleções são válidas apenas para o Perfetto e o ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Limpar processos de heap dump"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Lista de processos apagada"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Perfil contínuo de alocação heap"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Capturar um heap dump uma vez por intervalo especificado"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Captura um heap dump uma vez por intervalo especificado. Só é válido para heap dumps do Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Intervalo de heap dump"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 segundos"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 segundos"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Toque para parar a amostragem"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"O heap dump está sendo gravado"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Toque para interromper o heap dump"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"O heap dump do AM está sendo gravado"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Apagar arquivos salvos"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"As gravações são apagadas depois de um mês"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Apagar os arquivos salvos?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Todas as gravações serão excluídas de /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Limpar"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Rastros do sistema"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, trace, desempenho"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, rastro, rastreamento, desempenho, perfil, criação de perfil, cpu, pilha de chamadas, pilha, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Compartilhar arquivo?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Os arquivos de rastreamento do sistema podem incluir dados confidenciais do sistema e do app (como o uso). Compartilhe rastros do sistema apenas com pessoas e apps confiáveis."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Os arquivos de Rastreamento do Sistema podem incluir dados sensíveis do sistema e do app, como o uso do aplicativo ou imagens na memória dele. Só compartilhe rastros do sistema e heap dumps com pessoas e apps de confiança."</string>
     <string name="share" msgid="8443979083706282338">"Compartilhar"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Não mostrar novamente"</string>
     <string name="long_traces" msgid="5110949471775966329">"Traços longos"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Anexar gravações ao relatório do bug"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Enviar gravações em andamento automaticamente ao BetterBug quando um relatório de bug for coletado. As gravações vão continuar em seguida."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Ver arquivos salvos"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Você pode fazer upload dos rastros para analisá-los em ui.perfetto.dev"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Os heap dumps podem ser inspecionados com o AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Configurações de rastreamento"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Arquivos salvos"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Diversos"</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 5d8c212c..95011a99 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Registar captura da área dinâmica para dados"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Faz uma captura da área dinâmica para dados dos processos selecionados nos \"Processos de captura da área dinâmica para dados\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecione, pelo menos, um processo em \"Processos da captura da área dinâmica para dados\" para recolher capturas da área dinâmica para dados"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Registar captura da área dinâmica para dados da app AM com mapas de bits"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Recolhe uma captura da área dinâmica para dados do processo selecionado em \"Processos de captura da área dinâmica para dados\" e extrai imagens de mapas de bits"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Selecione apenas um processo em \"Processos de captura da área dinâmica para dados\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Selecione um processo em \"Processos de captura da área dinâmica para dados\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Recolher rastreios do Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inclui dados de telemetria da IU detalhados (pode provocar uma pausa percetível)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Rastrear aplicações disponíveis para depuração"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Predefinição"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# selecionada}other{# selecionadas}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Processos da captura da área dinâmica para dados"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Tem de selecionar, pelo menos, um processo"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Estas seleções aplicam-se às apps Perfetto e ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Limpar processos de captura da área dinâmica para dados"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Lista de processos limpa"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Perfil de memória contínuo"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Faça uma captura da área dinâmica para dados uma vez por intervalo especificado"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Faça uma captura da área dinâmica para dados uma vez por intervalo especificado. Aplica-se apenas a capturas da área dinâmica para dados da app Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Intervalo de captura da área dinâmica para dados"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 segundos"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 segundos"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Toque para parar a amostragem de pilhas"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"A captura da área dinâmica para dados está a ser registada"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Toque para parar a captura da área dinâmica para dados"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"A captura da área dinâmica para dados da app AM está a ser registada"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Limpar ficheiros guardados"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"As gravações são limpas após um mês"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Limpar ficheiros guardados?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Todas as gravações vão ser apagadas de /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Limpar"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Rastreios do sistema"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, rastreio, desempenho"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, rastrear, rastreio, desempenho, perfil, criação de perfis, cpu, pilha de chamadas, pilha, memória"</string>
     <string name="share_file" msgid="1982029143280382271">"Partilhar ficheiro?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Os ficheiros de rastreio do sistema podem incluir dados confidenciais do sistema e de aplicações (por exemplo, a utilização de aplicações). Partilhe os rastreios do sistema apenas com pessoas e aplicações de confiança."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Os ficheiros de rastreio do sistema podem incluir dados confidenciais do sistema e da app (como a utilização da app ou imagens na memória da app). Partilhe apenas rastreios do sistema ou capturas da área dinâmica para dados com apps fidedignas e pessoas em quem confia."</string>
     <string name="share" msgid="8443979083706282338">"Partilhar"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Não mostrar de novo"</string>
     <string name="long_traces" msgid="5110949471775966329">"Rastreios longos"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Anexar gravações aos relatórios de erros"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Envie automaticamente gravações em curso para o BetterBug quando é recolhido um relatório de erro. As gravações continuam depois disso."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Veja ficheiros guardados"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Os rastreios podem ser carregados para ui.perfetto.dev para análise"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"As capturas da área dinâmica para dados podem ser inspecionadas com o AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Definições de rastreio"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Ficheiros guardados"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Diversos"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index 5bc5b914..95f934ed 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Gravar heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Captura um heap dump dos processos selecionados em \"Processos de heap dump\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selecionar pelo menos um dos processos em \"Processos de heap dump\" para coletar heap dumps"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Gravar o heap dump do AM com bitmaps"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Coleta um heap dump do item selecionado em \"Processos de heap dump\" e extrai imagens de bitmap"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Selecione apenas um item em \"Processos de heap dump\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Selecione um item em \"Processos de heap dump\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Coletar rastros do Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inclui dados detalhados de telemetria da interface e pode causar instabilidade"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Rastrear aplicativos depuráveis"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Padrão"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# selecionada}one{# selecionada}other{# selecionadas}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Processos de heap dump"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Pelo menos um processo precisa ser selecionado"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Essas seleções são válidas apenas para o Perfetto e o ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Limpar processos de heap dump"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Lista de processos apagada"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Perfil contínuo de alocação heap"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Capturar um heap dump uma vez por intervalo especificado"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Captura um heap dump uma vez por intervalo especificado. Só é válido para heap dumps do Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Intervalo de heap dump"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 segundos"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 segundos"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Toque para parar a amostragem"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"O heap dump está sendo gravado"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Toque para interromper o heap dump"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"O heap dump do AM está sendo gravado"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Apagar arquivos salvos"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"As gravações são apagadas depois de um mês"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Apagar os arquivos salvos?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Todas as gravações serão excluídas de /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Limpar"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Rastros do sistema"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, trace, desempenho"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, rastro, rastreamento, desempenho, perfil, criação de perfil, cpu, pilha de chamadas, pilha, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Compartilhar arquivo?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Os arquivos de rastreamento do sistema podem incluir dados confidenciais do sistema e do app (como o uso). Compartilhe rastros do sistema apenas com pessoas e apps confiáveis."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Os arquivos de Rastreamento do Sistema podem incluir dados sensíveis do sistema e do app, como o uso do aplicativo ou imagens na memória dele. Só compartilhe rastros do sistema e heap dumps com pessoas e apps de confiança."</string>
     <string name="share" msgid="8443979083706282338">"Compartilhar"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Não mostrar novamente"</string>
     <string name="long_traces" msgid="5110949471775966329">"Traços longos"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Anexar gravações ao relatório do bug"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Enviar gravações em andamento automaticamente ao BetterBug quando um relatório de bug for coletado. As gravações vão continuar em seguida."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Ver arquivos salvos"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Você pode fazer upload dos rastros para analisá-los em ui.perfetto.dev"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Os heap dumps podem ser inspecionados com o AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Configurações de rastreamento"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Arquivos salvos"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Diversos"</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index d5563740..5a2aa39c 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Înregistrează datele privind memoria heap"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Surprinde o serie de date privind memoria heap din procesele selectate în Procese de date privind memoria heap"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Selectează cel puțin un proces de date privind memoria heap ca să colectezi datele privind memoria heap"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Înregistrează date privind memoria heap AM folosind imagini bitmap"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Colectează date privind memoria heap din procesul selectat în Procese de date privind memoria heap și extrage imagini bitmap"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Selectează un singur proces în Procese de date privind memoria heap"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Selectează un proces în Procese de date privind memoria heap"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Adună urmele Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Include date de telemetrie IU detaliate (poate cauza jankuri)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Urmărește aplicațiile care pot fi depanate"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Prestabilit"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# selectată}few{# selectate}other{# selectate}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Procese de date privind memoria heap"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Trebuie să fie selectat cel puțin un proces"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Aceste selecții se aplică atât pentru Perfetto, cât și pentru ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Șterge procesele de date privind memoria heap"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"S-a șters lista de procese"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Profil de memorie heap continuu"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Surprinde o serie de date privind memoria heap, o dată per interval"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Înregistrează date privind memoria heap o dată pentru fiecare interval specificat. Se aplică numai pentru datele privind memoria heap Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Interval de date privind memoria heap"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 secunde"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 secunde"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Atinge pentru a opri eșantionarea stivei"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Se înregistrează date privind memoria heap"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Atinge pentru a opri datele privind memoria heap"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Se înregistrează date privind memoria heap AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Șterge fișierele salvate"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Înregistrările sunt șterse după o lună"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Ștergi fișierele salvate?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Toate înregistrările vor fi șterse din /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Șterge"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Urme de sistem"</string>
-    <string name="keywords" msgid="736547007949049535">"urmă de sistem, urmă, performanță"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, urmă, urmărire, performanță, profil, creare de profiluri, cpu, stivă de apelări, stivă, memorie heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Trimiți fișierul?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Fișierele de urmărire a sistemului pot include date sensibile ale sistemului și ale aplicațiilor (cum ar fi utilizarea aplicațiilor). Permiți accesul la fișierele de urmărire a sistemului numai persoanelor și aplicațiilor în care ai încredere."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Fișierele de urmărire a sistemului pot include date sensibile ale sistemului și ale aplicațiilor (cum ar fi utilizarea aplicațiilor sau imaginile din memoria unei aplicații). Trimite date despre urmărirea sistemului sau date privind memoria heap numai persoanelor și aplicațiilor în care ai încredere."</string>
     <string name="share" msgid="8443979083706282338">"Permite accesul"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Nu mai afișa"</string>
     <string name="long_traces" msgid="5110949471775966329">"Urme lungi"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Atașează înregistrări la rapoartele de eroare"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Activează trimiterea automată a înregistrărilor în desfășurare la BetterBug când se execută un raport de eroare. Înregistrările vor continua."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Vezi fișierele salvate"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Urmele pot fi încărcate pe ui.perfetto.dev pentru analiză"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Datele privind memoria heap pot fi inspectate cu AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Setări pentru urmărire"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Fișiere salvate"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Diverse"</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 512c6ad6..0d922e47 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Создать дамп кучи"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Записывает дамп кучи для процессов, выбранных в списке \"Процессы с дампом кучи\"."</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Чтобы создать дампы кучи, выберите хотя бы один элемент в списке \"Процессы с дампом кучи\"."</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Записать дамп кучи с битовыми картами, используя AM"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Будет собран дамп кучи для выбранного процесса из списка \"Процессы с дампом кучи\" и извлечены растровые изображения"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Выберите один процесс из списка \"Процессы с дампом кучи\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Выберите процесс из списка \"Процессы с дампом кучи\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Собирать трассировки Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Включает подробные данные телеметрии интерфейса (может вызвать временное зависание)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Записывать действия приложений, доступных для отладки"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"По умолчанию"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Выбрано: #}one{Выбрано: #}few{Выбрано: #}many{Выбрано: #}other{Выбрано: #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Процессы с дампом кучи"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Необходимо выбрать по крайней мере один процесс."</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Ваш выбор учитывается в Perfetto и ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Очистить список процессов с дампом кучи"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Список процессов очищен."</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Непрерывный профиль кучи"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Создавать дамп кучи через указанный промежуток времени"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Создавать дамп кучи через указанный промежуток времени. Только для дампов кучи Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Интервал создания дампа кучи"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 секунд"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 секунд"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Нажмите, чтобы остановить создание образцов стека."</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Идет запись дампа кучи"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Нажмите, чтобы остановить запись дампа кучи."</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Дамп кучи записывается с помощью AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Удалить сохраненные файлы"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Записи удаляются спустя месяц"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Удалить сохраненные файлы?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Все записи из папки /data/local/traces будут удалены."</string>
     <string name="clear" msgid="5484761795406948056">"Удалить"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Системные записи действий"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, отслеживание, производительность"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, трассировка, отслеживание, производительность, профиль, профилирование, цп, стек вызовов, стек, куча"</string>
     <string name="share_file" msgid="1982029143280382271">"Поделиться файлом?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"В файлах трассировки может содержаться конфиденциальная информация о системе и приложении (например, данные о его использовании). Открывайте доступ к ним только надежным пользователям и приложениям."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"В файлах трассировки может содержаться конфиденциальная информация о системе и приложении, например данные о его использовании или сохраненных изображениях. Открывайте доступ к дампам кучи и трассировкам только пользователям и приложениям, которым вы доверяете."</string>
     <string name="share" msgid="8443979083706282338">"Поделиться"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Больше не показывать"</string>
     <string name="long_traces" msgid="5110949471775966329">"Длинные трассировки"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Прикреплять записи к отчетам об ошибках"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Автоматически отправлять данные выполняемой записи в BetterBug вместе с отчетом об ошибке. После этого запись продолжится."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Показать сохраненные файлы"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Файлы трассировки можно загружать для анализа на сайт ui.perfetto.dev"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Дампы кучи можно посмотреть с помощью AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Настройки трассировки"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Сохраненные файлы"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Другое"</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index e6af4549..41d93169 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"සංච නික්‍ෂේපය වාර්තා කරන්න"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"සංච නික්‍ෂේප ක්‍රියාවලි\" තුළ තෝරා ගත් ක්‍රියාවලිවල සංච නික්‍ෂේපයක් ග්‍රහණය කරයි"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"සංච නික්‍ෂේපය එකතු කිරීමට \"සංච නික්‍ෂේප ක්‍රියාවලි\" තුළ අවම වශයෙන් එක් ක්‍රියාවලියක් තෝරන්න"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"බිට්මැප් සමඟ AM සංච නික්‍ෂේපය පටිගත කරන්න"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"සංච නික්‍ෂේප ක්‍රියාවලි\" තුළ තෝරාගත් ක්‍රියාවලියේ සංච නික්‍ෂේපයක් එක් කර bitmap රූප උපුටා ගනී"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"සංච නික්‍ෂේප ක්‍රියාවලි\" තුළ එක් ක්‍රියාවලියක් පමණක් තෝරන්න"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"සංච නික්‍ෂේප ක්‍රියාවලි\" තුළ ක්‍රියාවලියක් තෝරන්න"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope හෝඩුවා එකතු කරන්න"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"සවිස්තරාත්මක UI දුරස්ථමාන දත්ත ඇතුළත් වේ (ජැන්ක් ඇති කළ හැක)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"දෝෂහරණය කළ හැකි යෙදුම් හඹා යන්න"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"පෙරනිමි"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{#ක් තෝරා ගන්නා ලදී}one{#ක් තෝරා ගන්නා ලදී}other{#ක් තෝරා ගන්නා ලදී}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"සංච නික්‍ෂේප ක්‍රියාවලි"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"අඩු තරමින් එක් මිතිකයක් තේරිය යුතු ය"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"මෙම තේරීම් Perfetto සහ ActivityManager යන දෙකටම අදාළ වේ."</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"සංච නික්‍ෂේප ක්‍රියාවලි පැහැදිලි කරන්න"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"ක්‍රියාවලි ලැයිස්තුව හිස් කරන ලදි"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"අඛණ්ඩ Heap පැතිකඩ"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"නිශ්චිත කාල පරතරයකට වරක් සංච නික්‍ෂේපය අල්ලා ගන්න"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"නිශ්චිත කාල පරතරයකට වරක් සංච නික්‍ෂේපය අල්ලා ගන්න. පර්ෆෙටෝ සංච නික්‍ෂේප සඳහා පමණක් අදාළ වේ."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"සංච නික්‍ෂේප කාල පරතරය"</string>
     <string name="five_seconds" msgid="7018465440929299712">"තත්පර 5"</string>
     <string name="ten_seconds" msgid="863416601384309033">"තත්පර 10"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"තොග නියැදිකරණය නැවැත්වීමට තට්ටු කරන්න"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"සංච නික්‍ෂේපය පටිගත වෙමින් පවතී"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"සංච නික්‍ෂේපය නැවැත්වීමට තට්ටු කරන්න"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM සංච නික්‍ෂේපය පටිගත වෙමින් පවතී"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"සුරකින ලද ගොනු හිස් කරන්න"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"මාසයකට පසු පටිගත කිරීම් ඉවත් කෙරේ"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"සුරැකි ගොනු හිස් කරන්න ද?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces වෙතින් සියලුම පටිගත කිරීම් මකනු ලැබේ"</string>
     <string name="clear" msgid="5484761795406948056">"හිස් කරන්න"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"පද්ධති ලුහුබැඳීම්"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, හඹා යාම, කාර්ය සාධනය"</string>
+    <string name="keywords" msgid="255681926397897100">"සිස්ට්‍රේස්, ට්‍රේසර්, පර්ෆෙටෝ, වින්ස්කෝප්, ලුහුබැඳීම, හඹා යාම, කාර්ය සාධනය, පැතිකඩ, පැතිකඩ ගැන්වීම, cpu, ඇමතුම් ගොඩ, ගොඩ, රාශිය"</string>
     <string name="share_file" msgid="1982029143280382271">"ගොනුව බෙදා ගන්න ද?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"පද්ධති හඹා යාම් ගොනුවලට සංවේදී පද්ධති සහ යෙදුම් දත්ත ඇතුළත් විය හැකිය (යෙදුම් භාවිතය වැනි). ඔබ විශ්වාස කරන පුද්ගලයන් සහ යෙදුම් සමඟ පමණක් පද්ධති හඹා යාම් බෙදා ගන්න."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"පද්ධති ලුහුබැඳීමේ ගොනුවලට සංවේදී පද්ධති සහ යෙදුම් දත්ත (යෙදුම් භාවිතය හෝ යෙදුමක මතකයේ ඇති රූප වැනි) ඇතුළත් විය හැකිය. ඔබ විශ්වාස කරන පුද්ගලයින් සහ යෙදුම් සමඟ පමණක් පද්ධති හෝඩුවාවන් හෝ සංච නික්‍ෂේපයන් බෙදා ගන්න."</string>
     <string name="share" msgid="8443979083706282338">"බෙදා ගන්න"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"නැවත නොපෙන්වන්න"</string>
     <string name="long_traces" msgid="5110949471775966329">"දීර්ඝ හඹා යෑම්"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"දෝෂ වාර්තාවලට පටිගත කිරීම් අමුණන්න"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"දෝෂ වාර්තාවක් එක් කළ විට ප්‍රගතිය පටිගත කිරීම් ස්වයංක්‍රීයව BetterBug වෙත යවන්න. පසුව පටිගත කිරීම් දිගටම කරගෙන යනු ඇත."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"සුරකින ලද ගොනු බලන්න"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"විශ්ලේෂණය සඳහා හෝඩුවාවන් ui.perfetto.dev වෙත උඩුගත කළ හැක"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"AHAT සමඟින් සංච නික්‍ෂේප පරීක්ෂා කළ හැක."</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"හඹා යාමේ සැකසීම්"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"සුරැකි ගොනු"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"විවිධ"</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index aab3bb0f..d54fa9d7 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Zaznamenávať výpis haldy"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Budú sa zaznamenávať procesy výpisu haldy vybrané v sekcii Procesy výpisu haldy"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Ak chcete zhromažďovať výpisy haldy, vyberte aspoň jeden proces v sekcii Procesy výpisu haldy"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Zaznamenať výpis haldy s bitmapami aplikácie AM"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Zhromažďuje výpisy haldy procesu vybraného v sekcii Procesy výpisu haldy a extrahuje obrázky bitmapy"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"V sekcii Procesy výpisu haldy vyberte iba jeden proces"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"V sekcii Procesy výpisu haldy vyberte proces"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Zhromažďovať stopy Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Zahŕňa podrobné údaje o telemetrii používateľského rozhrania (môže spôsobiť spomalené vykresľovanie)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Sledovať aplikácie na ladenie"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Predvolené"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# vybraná kategória}few{# vybrané kategórie}many{# selected}other{# vybraných kategórií}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Procesy výpisu haldy"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Musí byť vybraný aspoň jeden proces"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Tieto výbery platia pre aplikácie Perfetto a ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Vymazať procesy výpisu haldy"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Zoznam procesov bol vymazaný"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Nepretržité zaznamenávanie profilu haldy"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Výpis haldy sa zaznamená raz za stanovený interval"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Výpis haldy sa zaznamená raz za stanovený interval. Platí iba pre výpisy haldy aplikácie Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Interval výpisu haldy"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekúnd"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekúnd"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Vzorkovanie zásobníka ukončite klepnutím"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Výpis haldy sa zaznamenáva"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Klepnutím zastavíte zaznamenávanie výpisu haldy"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Výpis haldy aplikácie AM sa zaznamenáva"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Vymazať uložené súbory"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Nahrávky sa po mesiaci vymazávajú"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Chcete uložené súbory vymazať?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Všetky nahrávky v umiestnení /data/local/traces budú odstránené"</string>
     <string name="clear" msgid="5484761795406948056">"Vymazať"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Stopy v systéme"</string>
-    <string name="keywords" msgid="736547007949049535">"systémové trasovanie, trasovanie, výkonnosť"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, sledovať, sledovanie, výkon, profile, procesor, zásobník volaní, zásobník, halda"</string>
     <string name="share_file" msgid="1982029143280382271">"Chcete zdieľať súbor?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Záznamy migrácie systému môžu obsahovať citlivé údaje o systéme a aplikáciách (napríklad využívanie aplikácií). Záznamy migrácie systému zdieľajte len s dôveryhodnými osobami a aplikáciami."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Súbory sledovania systému môžu zahŕňať citlivé údaje o systéme a aplikácii (napríklad údaje o používaní aplikácie alebo obrázky v jej pamäti). Stopy systému alebo výpisy haldy zdieľajte iba s ľuďmi a aplikáciami, ktorým dôverujete."</string>
     <string name="share" msgid="8443979083706282338">"Zdieľať"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Nabudúce nezobrazovať"</string>
     <string name="long_traces" msgid="5110949471775966329">"Dlhé stopy"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Prikladať nahrávky k hláseniam chýb"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Pri zhromažďovaní hlásení chýb automaticky odosielať prebiehajúce nahrávky službe BetterBug. Nahrávky budú následne pokračovať."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Zobraziť uložené súbory"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Stopy je možné na analýzu nahrať na ui.perfetto.dev"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Výpisy haldy je možné skontrolovať pomocou nástroja AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Nastavenia stopy"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Uložené súbory"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Rôzne"</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index a785f64b..c1058b5c 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Zapisuj izvoz kopice"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Zajame izvoz kopice za procese, izbrane v razdelku »Procesi za izvoz kopice«"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Če želite zbirati izvoze kopice, izberite vsaj en proces v razdelku »Procesi za izvoz kopice«"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Beleženje izvoza kopice aplikacije AM z bitnimi slikami"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Zbere izvoz kopice za proces, izbran v razdelku »Procesi za izvoz kopice«, in ekstrahira bitne slike"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Izberite samo en proces v razdelku »Procesi za izvoz kopice«"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Izberite proces v razdelku »Procesi za izvoz kopice«"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Zbiranje sledi Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Vključuje podrobne telemetrične podatke o uporabniškem vmesniku (lahko povzroči zatikanje)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Sledenje aplikacijam, v katerih je mogoče odpravljati napake"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Privzeto"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# izbrana}one{# izbrana}two{# izbrani}few{# izbrane}other{# izbranih}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Procesi za izvoz kopice"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Izbran mora biti vsaj en proces"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Izbrano velja za aplikaciji Perfetto in ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Počisti procese izvoza kopice"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Seznam procesov je počiščen"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Profil neprekinjene kopice"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Zajem izvoza kopice enkrat na določeni interval"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Zajem izvoza kopice enkrat na določeni interval. Velja samo za izvoze kopice aplikacije Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Interval izvoza kopice"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekund"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekund"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Dotaknite se, da ustavite vzorčenje sklada."</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Poteka zapisovanje izvoza kopice"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Dotaknite se, da ustavite izvoz kopice"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Poteka beleženje izvoza kopice aplikacije AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Izbriši shranjene datoteke"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Zapisi so izbrisani po enem mesecu."</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Želite izbrisati shranjene datoteke?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Vsi zapisi v imeniku /data/local/traces bodo izbrisani."</string>
     <string name="clear" msgid="5484761795406948056">"Izbriši"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Sledi sistema"</string>
-    <string name="keywords" msgid="736547007949049535">"sled sistema, sled, učinkovitost delovanja"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, sled, sledenje, učinkovitost delovanja, profil, profiliranje, cpe, procesor, sklad priklicev, sklad, kopica"</string>
     <string name="share_file" msgid="1982029143280382271">"Želite deliti datoteko?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Datoteke za sledenje sistema morda vključujejo občutljive podatke o sistemu in aplikacijah (na primer o uporabi aplikacij). Sistemske sledi delite samo z ljudmi in aplikacijami, ki jim zaupate."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Datoteke za sledenje sistema morda vključujejo občutljive podatke o sistemu in aplikacijah (na primer podatke o uporabi aplikacij ali slike v pomnilniku aplikacije). Sistemske sledi ali izvoze kopice delite samo z osebami in aplikacijami, ki jim zaupate."</string>
     <string name="share" msgid="8443979083706282338">"Deli"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Tega ne prikaži več"</string>
     <string name="long_traces" msgid="5110949471775966329">"Dolge sledi"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Prilaganje posnetkov poročilom o napakah"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Samodejno pošiljanje posnetkov v teku v orodje BetterBug pri zbiranju poročila o napakah. Snemanje se bo nato nadaljevalo."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Prikaži shranjene datoteke"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Sledi je mogoče naložiti v ui.perfetto.dev za analizo"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Izvoze kopice je mogoče pregledati z orodjem AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Nastavitve sledenja"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Shranjene datoteke"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Razno"</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index ef787856..503dc33c 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Regjistro stivën e skedarëve fiktivë"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Regjistron një stivë të skedarëve fiktivë të proceseve të zgjedhura te \"Proceset e stivës së skedarëve fiktivë\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Zgjidh të paktën një proces te \"Proceset e stivës së skedarëve fiktivë\" për të mbledhur stivat e skedarëve fiktivë"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Regjistro stivën e skedarëve fiktivë të AM me bitmaps"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Mbledh një stivë të skedarëve fiktivë të zgjedhur në \"Proceset e stivës së skedarëve fiktivë\" dhe nxjerr imazhe të bitmap"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Zgjidh vetëm një proces në \"Proceset e stivës së skedarëve fiktivë\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Zgjidh një proces në \"Proceset e stivës së skedarëve fiktivë\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Mblidh gjurmët e Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Përfshin të dhëna të detajuara të telemetrisë së ndërfaqes së përdoruesit (mund të shkaktojë defekte)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Gjurmo aplikacionet e gjurmueshme"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"E parazgjedhur"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Zgjedhur: #}other{Zgjedhur: #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Proceset e stivës së skedarëve fiktivë"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Duhet të zgjidhet të paktën një proces"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Këto zgjedhje zbatohen si për Perfetto, ashtu edhe për ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Pastro proceset e stivës së skedarëve fiktivë"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Lista e proceseve u pastrua"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Profili i vazhdueshëm i grumbullit"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Regjistro një stivë të skedarëve fiktivë një herë për çdo interval të specifikuar"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Regjistro një stivë të skedarëve fiktivë një herë për çdo interval të specifikuar. Zbatohet vetëm për stivat e skedarëve fiktivë të Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Intervali i stivës së skedarëve fiktivë"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekonda"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekonda"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Trokit për të ndaluar kampionimin e grumbujve"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Stiva e skedarëve fiktivë po regjistrohet"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Trokit për të ndaluar stivën e skedarëve fiktivë"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Stiva e skedarëve fiktivë të AM po regjistrohet"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Fshi skedarët e ruajtur"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Regjistrimet fshihen pas një muaji"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Të fshihen skedarët e ruajtur?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Të gjitha regjistrimet do të fshihen nga /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Pastro"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Gjurmët e sistemit"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, gjurmimi, cilësia e funksionimit"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, gjurmo, gjurmim, performancë, profil, profilizim, cpu, grumbull thirrjesh, grumbull, stivë"</string>
     <string name="share_file" msgid="1982029143280382271">"Të ndahet skedari?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Skedarët e gjurmimit të sistemit mund të përfshijnë të dhëna delikate të sistemit dhe të aplikacioneve (si p.sh. të përdorimit të aplikacioneve). Ndaji gjurmët e sistemit vetëm me personat dhe aplikacionet te të cilët ke besim."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Skedarët e gjurmimit të sistemit mund të përfshijnë të dhëna delikate të sistemit dhe të aplikacioneve (si p.sh. të përdorimit të aplikacioneve ose imazheve në memorien e një aplikacioni). Ndaji gjurmët e sistemit ose stivat e skedarëve fiktivë vetëm me personat dhe aplikacionet të cilave u beson."</string>
     <string name="share" msgid="8443979083706282338">"Ndaj"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Mos e shfaq përsëri"</string>
     <string name="long_traces" msgid="5110949471775966329">"Gjurmët e gjata"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Bashkëngjit regjistrimet te raportet e defekteve në kod"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Dërgo automatikisht regjistrimet në vazhdim te BetterBug kur merret një raport defektesh në kod. Regjistrimet do të vazhdojnë më pas."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Shiko skedarët e ruajtur"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Gjurmët mund të ngarkohen në ui.perfetto.dev për analiza"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Stivat e skedarëve fiktivë mund të inspektohen me AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Gjurmo cilësimet"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Skedarët e ruajtur"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Të ndryshme"</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index c8083d5f..aeb26db7 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Снимај динамички део меморије за процес"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Снима динамички део меморије за процесе изабране у делу Процеси за снимање динамичког дела меморије"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Да бисте прикупљали снимке динамичког дела меморије за процесе, изаберите бар један процес у делу Процеси за снимање динамичког дела меморије"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Сними динамички део меморије за процес апликације AM помоћу бит мапа"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Прикупља снимак динамичког дела меморије за процес изабран у делу Процеси за снимање динамичког дела меморије, па издваја слике бит мапа."</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Изаберите само један процес у делу Процеси за снимање динамичког дела меморије"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Изаберите процес у делу Процеси за снимање динамичког дела меморије"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Прикупљај Winscope трагове"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Обухвата детаљне телеметријске податке о корисничком интерфејсу (може да изазове сецкање)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Прати апликације са функцијом за отклањање грешака"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Подразумевано"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Изабрана је #}one{Изабрана је #}few{Изабране су #}other{Изабрано је #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Процеси за снимање динамичког дела меморије"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Морате да изаберете бар један процес"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Ови избори важе за Perfetto и ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Обриши процесе изабране за снимање динамичког дела меморије"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Листа процеса је обрисана"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Непрекидно профилисање динамичког дела меморије"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Снима динамички део меморије за процес једном по наведеном интервалу"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Снима динамички део меморије за процес једном по наведеном интервалу. Важи само за Perfetto снимке динамичког дела меморије за процес."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Интервал снимања динамичког дела меморије за процес"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 секунди"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 секунди"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Додирните да бисте зауставили групно узорковање"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Прави се снимак динамичког дела меморије за процес"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Додирните да бисте зауставили снимање динамичког дела меморије за процес"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Прави се снимак динамичког дела меморије за процес апликације AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Обриши сачуване фајлове"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Снимци се бришу после месец дана"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Желите да обришете сачуване фајлове?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Сви снимци ће бити избрисани са /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Обриши"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Праћења система"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, праћење, учинак"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, траг, праћење, перформансе, профил, профилисање, процесор, група позива, група, динамички део меморије"</string>
     <string name="share_file" msgid="1982029143280382271">"Желите да делите фајл?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Датотеке праћења система могу да садрже осетљиве податке о систему и апликацијама (на пример, о коришћењу апликације). Делите праћења система само са поузданим људима и апликацијама."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Фајлови праћења система могу да садрже осетљиве системске податке и податке апликација (као што су коришћење апликације или слике у меморији апликације). Праћења система или снимке динамичког дела меморије за процес делите само са поузданим људима и апликацијама."</string>
     <string name="share" msgid="8443979083706282338">"Дели"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Не приказуј поново"</string>
     <string name="long_traces" msgid="5110949471775966329">"Дуги трагови"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Приложите снимке у извештаје о грешци"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Аутоматски шаљите BetterBug-у снимке док је снимање у току када се прикупи извештај о грешци. Снимање ће се затим наставити."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Прикажи сачуване фајлове"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Праћења могу да се отпреме на ui.perfetto.dev ради анализе"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Снимак динамичког дела меморије за процес може да се прегледа помоћу AHAT-а"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Подешавања праћења"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Сачувани фајлови"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Разно"</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index f9904e91..b4456ee2 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -6,10 +6,14 @@
     <string name="record_trace" msgid="6416875085186661845">"Spela in spårning"</string>
     <string name="record_trace_summary" msgid="6705357754827849292">"Spelar in systemspårning med konfigurationen som angetts i Spåra inställningar"</string>
     <string name="record_stack_samples" msgid="3498368637185702335">"Spela in CPU-profil"</string>
-    <string name="record_stack_samples_summary" msgid="7827953921526410478">"Du kan även aktivera utdrag från anropsstacken i spår genom att markera kategorin CPU."</string>
+    <string name="record_stack_samples_summary" msgid="7827953921526410478">"Du kan även aktivera utdrag från anropsstacken i spår genom att markera kategorin CPU"</string>
     <string name="record_heap_dump" msgid="1688550222066812696">"Spela in minnesdump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Spelar in en minnesdump av processerna som har valts i Minnedumpprocesser"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Välj minst en process i Minnesdumpprocesser för att samla in minnesdumpar"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Spela in AM-minnesdump med bitmaps"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Samlar in en minnesdump av processen som har valts i Minnesdumpprocesser och extraherar bitmapbilder"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Välj bara en process i Minnesdumpprocesser"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Välj en process i Minnesdumpprocesser"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Samla in Winscope-spår"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inkluderar detaljerad telemetridata för användargränssnittet (kan orsaka jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Spåra felsökningsbara appar"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Standard"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# vald}other{# valda}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Minnesdumpprocesser"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Du måste välja minst en process"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Dessa val gäller för både Perfetto och ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Rensa minnesdumpprocesser"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Processlistan har rensats"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Kontinuerlig minnesprofil"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Spela in en minnesdump en gång per specificerat intervall"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Spela in en minnesdump en gång per specificerat intervall. Gäller endast Perfetto-minnesdumpar."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Minnesdumpintervall"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 sekunder"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 sekunder"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Tryck för att stoppa stackutdrag"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Minnesdump spelas in"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Tryck för att stoppa minnesdump"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM-minnesdump spelas in"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Rensa sparade filer"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Alla inspelningar rensas efter en månad"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Vill du rensa sparade filer?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Alla inspelningar raderas från /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Rensa"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Systemspårning"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, spårning, prestanda"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, spåra, spårning, prestanda, profil, profilering, cpu, anropsstack, stack, minne"</string>
     <string name="share_file" msgid="1982029143280382271">"Vill du dela filen?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Systemspårningsfilerna kan innehålla känslig data om system och appar (t.ex. hur appar används). Dela bara systemspårningsfiler med personer och appar du litar på."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Systemspårningsfiler kan innehålla känslig system- och appdata (till exempel appanvändning eller bilder i en apps minne). Dela bara systemspår eller minnesdumpar med personer och appar du litar på."</string>
     <string name="share" msgid="8443979083706282338">"Dela"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Visa inte igen"</string>
     <string name="long_traces" msgid="5110949471775966329">"Långtidsspårningar"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Bifoga inspelningar i felrapporter"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Skicka automatiskt inspelningar från pågående session till BetterBug när en felrapport samlas in. Inspelningarna fortsätter efteråt."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Visa sparade filer"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Spår kan laddas upp till ui.perfetto.dev för analys"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"Aktivitetshanteraren"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Minnesdumpar kan granskas med AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Spåra inställningar"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Sparade filer"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Övrigt"</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 0bb7e900..28ad86a4 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Rekodi picha ya hifadhi"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Hunasa picha ya hifadhi ya michakato iliyochaguliwa katika \"Michakato ya kurekodi picha ya hifadhi\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Chagua angalau mchakato mmoja katika \"Michakato ya kurekodi picha ya hifadhi\" ili ukusanye picha za hifadhi"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Rekodi picha ya hifadhi ya AM ukitumia taswidoti"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Hukusanya picha ya hifadhi ya mchakato uliochagua katika \"Michakato ya picha ya hifadhi\" na kudondoa picha za taswidoti"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Chagua mchakato mmoja pekee katika \"Michakato ya picha ya hifadhi\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Chagua mchakato katika \"Michakato ya picha ya hifadhi\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Kusanya historia ya shughuli kwenye Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Inajumuisha data ya kina ya kiolesura inayorekodiwa na kutumwa kutoka mbali (inaweza kusababisha matatizo ya ubora)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Tafuta programu zinazoweza kutatuliwa"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Chaguomsingi"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Umechagua #}other{Umechagua #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Michakato ya picha ya hifadhi"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Lazima uchague angalau mchakato mmoja"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Chaguo hizi hutumika kwenye Perfetto na ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Futa michakato ya kurekodi picha ya hifadhi"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Imefuta orodha ya mchakato"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Kijipicha endelevu cha mgao wa hifadhi"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Nasa picha ya hifadhi mara moja baina ya kipindi cha muda uliowekwa"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Piga picha ya hifadhi mara moja kwa kila kipindi kilichobainishwa. Hutumika tu katika picha za hifadhi za Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Muda baina ya matukio ya kurekodi picha ya hifadhi"</string>
     <string name="five_seconds" msgid="7018465440929299712">"Sekunde 5"</string>
     <string name="ten_seconds" msgid="863416601384309033">"Sekunde 10"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Gusa ili usimamishe sampuli za rafu"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Picha ya hifadhi inarekodiwa"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Gusa ili usimamishe mchakato wa kurekodi picha ya hifadhi"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Inarekodi picha ya hifadhi ya AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Futa faili zilizohifadhiwa"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Rekodi hufutwa baada ya mwezi mmoja"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Ungependa kufuta faili zilizohifadhiwa?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Rekodi zote zitafutwa kwenye /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Futa"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Historia ya shughuli kwenye mfumo"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, fuatilia, utendaji"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, historia ya shughuli, kufuatilia shughuli, utendaji, wasifu, kuchanganua maelezo, kiini cha kompyuta (cpu), rafu ya utekelezaji, rafu, mgao wa hifadhi"</string>
     <string name="share_file" msgid="1982029143280382271">"Ungependa kushiriki faili?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Faili za Kufuatilia Mfumo zinaweza kujumuisha data nyeti ya mfumo na programu (kama vile matumizi ya programu). Shiriki historia ya shughuli za mfumo na watu na programu unazoamini pekee."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Huenda faili za Historia za Shughuli za Mfumo zikajumuisha data nyeti ya mfumo na programu (kama vile matumizi ya programu au picha kwenye hifadhi ya programu). Tuma tu historia za shughuli za mfumo au picha ya hifadhi kwa watu au programu unazoziamini."</string>
     <string name="share" msgid="8443979083706282338">"Shiriki"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Usionyeshe tena"</string>
     <string name="long_traces" msgid="5110949471775966329">"Historia ndefu ya shughuli"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Ambatisha rekodi kwenye ripoti za hitilafu"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Tuma kiotomatiki rekodi ya matukio yanayoendelea kwa BetterBug wakati ripoti ya hitilafu inakusanywa. Rekodi ya matukio itaendelea baadaye."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Angalia faili zilizohifadhiwa"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Historia za shughuli zinaweza kupakiwa katika ui.perfetto.dev kwa uchanganuzi"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Picha za skrini zinaweza kukaguliwa kwa kutumia AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Mipangilio ya ufuatiliaji"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Faili zilizohifadhiwa"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Zinginezo"</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index bc2fb355..7182014a 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ஹீப் டம்ப்பை ரெக்கார்டு செய்தல்"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\'ஹீப் டம்ப் செயல்முறைகளில்\' தேர்ந்தெடுக்கப்பட்ட செயல்முறைகளின் ஹீப் டம்ப்பைப் பதிவுசெய்கிறது"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ஹீப் டம்ப்களைச் சேகரிக்க \'ஹீப் டம்ப் செயல்முறைகளில்\' குறைந்தது ஒரு செயல்முறையாவது தேர்ந்தெடுங்கள்"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"பிட்மேப்ஸ் மூலம் AM ஹீப் டம்ப்பைப் பதிவுசெய்தல்"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"ஹீப் டம்ப் செயல்முறைகளில்\" தேர்ந்தெடுக்கப்பட்ட செயல்முறையின் ஹீப் டம்ப்பைச் சேகரித்து, பிட்மேப் படங்களைப் பிரித்தெடுக்கிறது"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"ஹீப் டம்ப் செயல்முறைகளில்\" இருந்து ஒரு செயல்முறையை மட்டும் தேர்ந்தெடுக்கவும்"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"ஹீப் டம்ப் செயல்முறைகளில்\" இருந்து ஒரு செயல்முறையைத் தேர்ந்தெடுக்கவும்"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"வின்ஸ்கோப் டிரேஸ்களைச் சேகரித்தல்"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"விரிவான UI டெலிமெட்ரி தரவும் அடங்கும் (மந்தமான செயல்பாட்டை உண்டாக்கலாம்)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"பிழை திருத்தக்கூடிய ஆப்ஸை டிரேஸ் செய்தல்"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"இயல்புநிலை"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# தேர்ந்தெடுக்கப்பட்டது}other{# தேர்ந்தெடுக்கப்பட்டன}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"ஹீப் டம்ப் செயல்முறைகள்"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"குறைந்தது ஒரு செயல்முறையாவது தேர்ந்தெடுக்கப்பட வேண்டும்"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"இந்தத் தேர்வுகள் Perfetto, ActivityManager ஆகிய இரண்டிற்கும் பொருந்தும்"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"ஹீப் டம்ப் செயல்முறைகளை அழி"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"செயல்முறைப் பட்டியல் அழிக்கப்பட்டது"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"தொடர்ச்சியான ஹீப் ப்ரொஃபைல்"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"ஒரு குறிப்பிட்ட இடைவெளிக்கு ஒருமுறை ஹீப் டம்ப்பைப் பதிவுசெய்யும்"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"குறிப்பிட்ட இடைவெளிக்கு ஒருமுறை ஹீப் டம்ப்பைப் பதிவுசெய்யும். Perfetto ஹீப் டம்ப்களுக்கு மட்டுமே பொருந்தும்."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"ஹீப் டம்ப் இடைவெளி"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 வினாடிகள்"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 வினாடிகள்"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"ஸ்டாக் சாம்பிளிங்கை நிறுத்த தட்டுங்கள்"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"ஹீப் டம்ப் ரெக்கார்டு செய்யப்படுகிறது"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"ஹீப் டம்ப்பை நிறுத்த தட்டுங்கள்"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM ஹீப் டம்ப் ரெக்கார்டு செய்யப்படுகிறது"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"சேமிக்கப்பட்ட ஃபைல்களை அழி"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ஒரு மாதத்திற்குப் பிறகு ரெக்கார்டிங்குகள் அழிக்கப்படும்"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"சேமிக்கப்பட்ட ஃபைல்களை அழிக்கவா?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces இலிருந்து அனைத்து ரெக்கார்டிங்குகளும் நீக்கப்படும்"</string>
     <string name="clear" msgid="5484761795406948056">"அழி"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"சிஸ்டம் டிரேஸ்கள்"</string>
-    <string name="keywords" msgid="736547007949049535">"சிஸ்டிரேஸ், டிரேஸ், செயல்திறன்"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, டிரேஸ், டிரேஸிங், செயல்திறன், சுயவிவரம், ப்ரொஃபைலிங், cpu, கால்ஸ்டேக், ஸ்டேக் மற்றும் ஹீப்"</string>
     <string name="share_file" msgid="1982029143280382271">"ஃபைலைப் பகிரவா?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"சிஸ்டம் டிரேஸிங் ஃபைல்களில் பாதுகாக்கவேண்டிய சிஸ்டம் மற்றும் ஆப்ஸ் தரவு (ஆப்ஸ் உபயோக விவரம் போன்றவை) இருக்கலாம். உங்களுக்கு நம்பகமானவர்களுடனும் ஆப்ஸுடனும் மட்டுமே பகிரவும்."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"சிஸ்டம் டிரேஸிங் ஃபைல்களில் பாதுகாக்க வேண்டிய சிஸ்டம் மற்றும் ஆப்ஸ் தரவு (ஆப்ஸ் உபயோகம், ஆப்ஸின் நினைவகத்தில் உள்ள படங்கள் போன்றவை) இருக்கக்கூடும். நீங்கள் நம்பும் நபர்கள் மற்றும் ஆப்ஸுடன் மட்டுமே சிஸ்டம் டிரேஸ்களையும் ஹீப் டம்ப்களையும் பகிரவும்."</string>
     <string name="share" msgid="8443979083706282338">"பகிர்"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"மீண்டும் காட்டாதே"</string>
     <string name="long_traces" msgid="5110949471775966329">"நீண்ட டிரேஸ்கள்"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"பிழை அறிக்கைகளில் ரெக்கார்டிங்குகளை இணைத்தல்"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"பிழை அறிக்கை சேகரிக்கப்பட்டதும் செயலிலுள்ள ரெக்கார்டிங்குகள் தானாகவே BetterBug கருவிக்கு அனுப்பப்படும். அதன்பிறகு ரெக்கார்டிங்குகள் தொடரும்."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"சேமிக்கப்பட்ட ஃபைல்களைப் பாருங்கள்"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"பகுப்பாய்வுக்காக டிரேஸ்களை ui.perfetto.dev பக்கத்தில் பதிவேற்றலாம்"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"AHAT மூலம் ஹீப் டம்ப்களை ஆய்வு செய்யலாம்"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"அமைப்புகளை டிரேஸ் செய்யுங்கள்"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"சேமித்த ஃபைல்கள்"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"மற்றவை"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index dabe37f0..9f8eb0df 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -3,13 +3,17 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="system_tracing" msgid="4719188511746319848">"సిస్టమ్ ట్రేసింగ్"</string>
     <string name="record_system_activity" msgid="4339462312915377825">"సిస్టమ్ యాక్టివిటీని రికార్డ్ చేయి, ఆ తర్వాత దానిని విశ్లేషించి సిస్టమ్ పనితీరును మెరుగుపరచు"</string>
-    <string name="record_trace" msgid="6416875085186661845">"స్థితిగతిని రికార్డ్ చేయండి"</string>
+    <string name="record_trace" msgid="6416875085186661845">"ట్రేస్‌ను రికార్డ్ చేయండి"</string>
     <string name="record_trace_summary" msgid="6705357754827849292">"\"ట్రేస్ సెట్టింగ్‌ల\"లో సెట్ చేయబడిన కాన్ఫిగరేషన్‌ను ఉపయోగించి సిస్టమ్ ట్రేసింగ్ ప్రాసెస్‌ను క్యాప్చర్ చేస్తుంది"</string>
     <string name="record_stack_samples" msgid="3498368637185702335">"CPU ప్రొఫైల్‌ను రికార్డ్ చేయండి"</string>
     <string name="record_stack_samples_summary" msgid="7827953921526410478">"ట్రేస్‌లలోని \"CPU\" కేటగిరీని ఎంచుకోవడం ద్వారా కూడా కాల్‌స్ట్యాక్ శాంప్లింగ్‌ను ఎనేబుల్ చేయవచ్చు"</string>
     <string name="record_heap_dump" msgid="1688550222066812696">"హీప్ డంప్‌ను రికార్డ్ చేయండి"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"హీప్ డంప్ ప్రాసెస్‌ల\"లో ఎంచుకున్న ప్రాసెస్‌ల హీప్ డంప్‌ను క్యాప్చర్ చేస్తుంది"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"హీప్ డంప్‌లను సేకరించడానికి \"హీప్ డంప్ ప్రాసెస్‌ల\"లో కనీసం ఒక ప్రాసెస్‌ను ఎంచుకోండి"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"బిట్‌మ్యాప్‌లతో AM హీప్ డంప్‌ను రికార్డ్ చేయండి"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"హీప్ డంప్ ప్రాసెస్‌ల\"లో ఎంచుకున్న ప్రాసెస్‌కు సంబంధించిన హీప్ డంప్‌ను కలెక్ట్ చేస్తుంది, బిట్‌మ్యాప్ ఇమేజ్‌లను సంగ్రహిస్తుంది"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"హీప్ డంప్ ప్రాసెస్‌ల\"లో ఒక ప్రాసెస్‌ను మాత్రమే ఎంచుకోండి"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"హీప్ డంప్ ప్రాసెస్‌ల\"లో ఒక ప్రాసెస్‌ను ఎంచుకోండి"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope ట్రేస్‌లను సేకరించండి"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"వివరణాత్మక UI టెలిమెట్రీ డేటా ఉంటుంది (ఈ ప్రాసెస్ జంక్‌ను క్రియేట్ చేయవచ్చు)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"డీబగ్ చేయగల అప్లికేషన్‌ల స్టేటస్‌ను ట్రేస్ చేయండి"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ఆటోమేటిక్"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# ఎంచుకోబడింది}other{# ఎంచుకోబడింది}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"హీప్ డంప్ ప్రాసెస్‌లు"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"కనీసం ఒక ప్రాసెస్‌ను ఎంచుకోవాలి"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"ఈ ఎంపికలు Perfetto, ActivityManager రెండింటికీ వర్తిస్తాయి"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"హీప్ డంప్ ప్రాసెస్‌లను క్లియర్ చేయండి"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"ప్రాసెస్ లిస్ట్ క్లియర్ చేయబడింది"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"నిరంతర హీప్ ప్రొఫైల్"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"పేర్కొన్న ఇంట‌ర్‌వెల్‌కు ఒకసారి హీప్ డంప్‌ను క్యాప్చర్ చేయండి"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"పేర్కొన్న ఇంటర్‌వెల్‌కు ఒకసారి హీప్ డంప్‌ను క్యాప్చర్ చేయండి. Perfetto హీప్ డంప్‌లకు మాత్రమే వర్తిస్తుంది."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"హీప్ డంప్ ఇంట‌ర్‌వెల్"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 సెకన్లు"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 సెకన్లు"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"స్ట్యాక్ శాంప్లింగ్‌ను ఆపివేయడానికి ట్యాప్ చేయండి"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"హీప్ డంప్ రికార్డ్ చేయబడుతోంది"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"హీప్ డంప్‌ను ఆపడానికి ట్యాప్ చేయండి"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM హీప్ డంప్ రికార్డ్ చేయబడుతోంది"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"సేవ్ చేసిన ఫైల్స్‌ను క్లియర్ చేయండి"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ఒక నెల తర్వాత రికార్డింగ్‌లు క్లియర్ చేయబడతాయి"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"సేవ్ చేసిన ఫైల్స్‌ను క్లియర్ చేయాలా?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces నుండి రికార్డింగ్‌లన్నీ తొలగించబడతాయి"</string>
     <string name="clear" msgid="5484761795406948056">"క్లియర్ చేయండి"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"సిస్టమ్ స్థితిగతులు"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, trace, performance"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ట్రేస్, ట్రేసింగ్, పనితీరు, ప్రొఫైల్, ప్రొఫైలింగ్, cpu, కాల్‌స్ట్యాక్, స్ట్యాక్, హీప్"</string>
     <string name="share_file" msgid="1982029143280382271">"ఫైల్‌ను షేర్ చేయాలనుకుంటున్నారా?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"సిస్టమ్ స్థితిగతిని కనుగొనే ఫైళ్లు- గోప్యమైన సిస్టమ్, యాప్ డేటాను (యాప్ వినియోగం వంటివి) కలిగి ఉండవచ్చు. కేవలం మీకు నమ్మకం ఉన్న వ్యక్తుల‌కు, యాప్‌లకు మాత్రమే సిస్టమ్ స్థితిగతులను షేర్ చేయండి."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"సిస్టమ్ ట్రేసింగ్ ఫైల్స్‌లో గోప్యమైన సిస్టమ్, యాప్ డేటా (యాప్ వినియోగం లేదా యాప్ మెమరీలోని ఇమేజ్‌లు వంటివి) ఉండవచ్చు. మీరు విశ్వసించే వ్యక్తులు, యాప్‌లతో మాత్రమే సిస్టమ్ ట్రేస్‌లను లేదా హీప్ డంప్‌లను షేర్ చేయండి."</string>
     <string name="share" msgid="8443979083706282338">"షేర్ చేయండి"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"మళ్లీ చూపవద్దు"</string>
     <string name="long_traces" msgid="5110949471775966329">"ఎక్కువ నిడివి స్థితిగతి"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"బగ్ రిపోర్ట్‌లకు రికార్డింగ్‌లను అటాచ్ చేయండి"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"బగ్ రిపోర్ట్ కలెక్ట్ చేయబడినప్పుడు ప్రోగెస్‌లో ఉన్న రికార్డింగ్‌లను ఆటోమేటిక్‌గా BetterBugకు పంపండి. సంబంధిత వ్యవధి తర్వాత, రికార్డింగ్‌లు కొనసాగుతాయి."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"సేవ్ చేసిన ఫైల్స్‌ను చూడండి"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"విశ్లేషణ కోసం ట్రేస్‌లను ui.perfetto.devకు అప్‌లోడ్ చేయవచ్చు"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"AHATతో హీప్ డంప్‌లను చెక్ చేయవచ్చు"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ట్రేస్ సెట్టింగ్‌లు"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"సేవ్ చేసిన ఫైల్స్"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"ఇతరాలు"</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 64150fb8..d4fe6207 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -1,7 +1,7 @@
 <?xml version="1.0" encoding="UTF-8"?>
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="system_tracing" msgid="4719188511746319848">"ติดตามระบบ"</string>
+    <string name="system_tracing" msgid="4719188511746319848">"System Tracing"</string>
     <string name="record_system_activity" msgid="4339462312915377825">"บันทึกกิจกรรมของระบบและนำไปวิเคราะห์ในภายหลังเพื่อปรับปรุงประสิทธิภาพให้ดีขึ้น"</string>
     <string name="record_trace" msgid="6416875085186661845">"บันทึกการติดตาม"</string>
     <string name="record_trace_summary" msgid="6705357754827849292">"จับภาพการติดตามของระบบโดยใช้การกำหนดค่าที่ตั้งไว้ใน \"การตั้งค่าการติดตาม\""</string>
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"บันทึกฮีปดัมป์"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"บันทึกฮีปดัมป์ของกระบวนการที่เลือกใน \"กระบวนการฮีปดัมป์\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"เลือกอย่างน้อย 1 กระบวนการใน \"กระบวนการฮีปดัมป์\" เพื่อรวบรวมฮีปดัมป์"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"บันทึกฮีปดัมป์ AM ด้วยบิตแมป"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"รวบรวมฮีปดัมป์ของกระบวนการที่เลือกใน \"กระบวนการฮีปดัมป์\" และดึงข้อมูลรูปภาพบิตแมป"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"เลือกเพียง 1 กระบวนการใน \"กระบวนการฮีปดัมป์\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"เลือกกระบวนการใน \"กระบวนการฮีปดัมป์\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"รวบรวมการติดตาม Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"รวมข้อมูลจากระยะไกลของ UI โดยละเอียด (อาจทำให้เกิดการกระตุกได้)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ติดตามแอปพลิเคชันที่แก้ไขข้อบกพร่องได้"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ค่าเริ่มต้น"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{เลือกแล้ว # รายการ}other{เลือกแล้ว # รายการ}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"กระบวนการฮีปดัมป์"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"ต้องเลือกอย่างน้อย 1 กระบวนการ"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"ตัวเลือกเหล่านี้มีผลกับทั้ง Perfetto และ ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"ล้างกระบวนการฮีปดัมป์"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"ล้างกระบวนการต่างๆ แล้ว"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"โปรไฟล์ฮีปแบบต่อเนื่อง"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"บันทึกฮีปดัมป์ครั้งเดียวต่อช่วงเวลาที่ระบุ"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"บันทึกฮีปดัมป์ครั้งเดียวต่อช่วงเวลาที่ระบุ มีผลกับฮีปดัมป์ Perfetto เท่านั้น"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"ช่วงเวลาของฮีปดัมป์"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 วินาที"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 วินาที"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"แตะเพื่อหยุดการสุ่มตัวอย่างสแต็ก"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"กำลังบันทึกฮีปดัมป์"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"แตะเพื่อหยุดฮีปดัมป์"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"กำลังบันทึกฮีปดัมป์ AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"ล้างไฟล์ที่บันทึกไว้"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ระบบจะล้างการบันทึกหลังจากผ่านไปแล้ว 1 เดือน"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"ล้างไฟล์ที่บันทึกไว้ใช่ไหม"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"ระบบจะลบการบันทึกทั้งหมดออกจาก /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"ล้าง"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"การติดตามระบบ"</string>
-    <string name="keywords" msgid="736547007949049535">"Systrace, การติดตาม, ประสิทธิภาพ"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, ร่องรอย, การติดตาม, ประสิทธิภาพ, โปรไฟล์, การกำหนดโปรไฟล์, cpu, callstack, สแต็ก, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"แชร์ไฟล์ใช่ไหม"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"ไฟล์การติดตามระบบอาจมีข้อมูลระบบและแอปที่ละเอียดอ่อน (เช่น การใช้งานแอป) โปรดแชร์ไฟล์การติดตามระบบกับแอปและบุคคลที่คุณเชื่อถือเท่านั้น"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"ไฟล์การติดตามระบบอาจรวมถึงข้อมูลระบบและแอปที่มีความละเอียดอ่อน (เช่น การใช้งานแอปหรือรูปภาพในหน่วยความจำของแอป) โปรดแชร์การติดตามระบบหรือฮีปดัมป์กับบุคคลและแอปที่คุณไว้วางใจเท่านั้น"</string>
     <string name="share" msgid="8443979083706282338">"แชร์"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"ไม่ต้องแสดงอีก"</string>
     <string name="long_traces" msgid="5110949471775966329">"การติดตามแบบยาว"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"แนบการบันทึกในรายงานข้อบกพร่อง"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"ส่งการบันทึกที่กำลังดำเนินการไปยัง BetterBug โดยอัตโนมัติเมื่อรวบรวมรายงานข้อบกพร่อง การบันทึกจะดำเนินการต่อหลังจากนั้น"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"ดูไฟล์ที่บันทึกไว้"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"อัปโหลดการติดตามไปยัง ui.perfetto.dev เพื่อการวิเคราะห์ได้"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"ฮีปดัมป์สามารถตรวจสอบได้ด้วย AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"การตั้งค่าการติดตาม"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"ไฟล์ที่บันทึกไว้"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"เบ็ดเตล็ด"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index d083e1ba..01bbed1e 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"I-record ang heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Nagka-capture ng heap dump ng mga prosesong pinili sa \"Mga proseso ng heap dump\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Pumili ng kahit isang proseso man lang sa \"Mga proseso ng heap dump\" para mangolekta ng mga heap dump"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Mag-record ng heap dump ng AM nang may mga bitmap"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Nangongolekta ng heap dump ng prosesong napili sa \"Mga proseso ng heap dump\" at nag-e-extract ng mga bitmap na larawan"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Isang proseso lang ang piliin sa \"Mga proseso ng heap dump\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Pumili ng proseso sa \"Mga proseso ng heap dump\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Kolektahin ang mga trace ng Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Kasama ang detalyadong data ng UI telemetry (posibleng magdulot ng jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Mag-trace ng mga nade-debug na application"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Default"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# ang pinili}one{# ang pinili}other{# ang pinili}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Mga proseso ng heap dump"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Dapat pumili ng kahit isang proseso man lang"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Nalalapat ang mga pagpiling ito sa parehong Perfetto at ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"I-clear ang mga proseso ng heap dump"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Na-clear ang listahan ng proseso"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Tuloy-tuloy na heap profile"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Mag-capture ng heap dump isang beses kada natukoy na interval"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Mag-capture ng heap dump isang beses bawat itinakdang interval. Sa mga heap dump ng Perfetto lang nalalapat."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Interval ng heap dump"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 segundo"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 segundo"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"I-tap para ihinto ang pag-sample ng stack"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Nire-record ang heap dump"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"I-tap para ihinto ang heap dump"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Nire-record ang heap dump ng AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"I-clear ang mga na-save na file"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Maki-clear ang mga recording pagkalipas ng isang buwan"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"I-clear ang mga na-save na file?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Made-delete ang lahat ng recording sa /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"I-clear"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Mga trace ng system"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, trace, performance"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, trace, pag-trace, performance, profile, pag-profile, cpu, callstack, stack, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Ibahagi ang file?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Ang mga file ng Pag-trace ng System ay maaaring may sensitibong data ng system at app (gaya ng paggamit ng app). Ibahagi lang ang mga trace ng system sa mga tao at app na pinakakatiwalaan mo."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Ang mga file ng Pag-trace ng System ay posibleng may sensitibong data ng system at app (gaya ng paggamit ng app o mga larawan sa memory ng isang app). Sa mga tao at app na pinagkakatiwalaan mo lang mag-share ng mga trace ng system o heap dump."</string>
     <string name="share" msgid="8443979083706282338">"Ibahagi"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Huwag ipakitang muli"</string>
     <string name="long_traces" msgid="5110949471775966329">"Mga long trace"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"I-attach ang mga recording sa mga ulat ng bug"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Awtomatikong magpadala ng mga kasalukuyang pag-record sa BetterBug kapag may nakolektang ulat ng bug. Magpapatuloy ang mga pag-record pagkatapos nito."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Tingnan ang mga naka-save na file"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Puwedeng i-upload sa ui.perfetto.dev ang mga trace para masuri"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Puwedeng siyasatin gamit ang AHAT ang mga heap dump"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Mga setting ng pag-trace"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Mga naka-save na file"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Miscellaneous"</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 9b1f7f5b..d487582c 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Yığın dökümünü kaydet"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"Yığın dökümü işlemleri\" bölümünde seçilen işlemlerin yığın dökümünü yakalar"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Yığın dökümlerini toplamak için \"Yığın dökümü işlemleri\" bölümünde en az bir işlem seçin"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Bit eşlemlerle ActivityManager yığın dökümü kaydet"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"Yığın dökümü işlemleri\" bölümünde seçilen işlemin yığın dökümünü toplar ve bit eşlem resimleri çıkarır"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"Yığın dökümü işlemleri\" bölümünde yalnızca bir işlem seçin"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"Yığın dökümü işlemleri\" bölümünde bir işlem seçin"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope izlerini topla"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Ayrıntılı kullanıcı arayüzü telemetri verileri içerir (duraklamaya neden olabilir)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Hata ayıklaması yapılabilecek uygulamaları izle"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Varsayılan"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# seçildi}other{# seçildi}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Yığın dökümü işlemleri"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"En az bir video seçilmelidir"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Bu seçimler hem Perfetto hem de ActivityManager için geçerlidir"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Yığın dökümü işlemlerini temizle"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"İşlem listesi temizlendi"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Sürekli öbek profili"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Yığın dökümünü, belirtilen aralığa göre bir kez yakalayın"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Yığın dökümünü, belirtilen aralığa göre bir kez yakalayın. Yalnızca Perfetto yığın dökümleri için geçerlidir."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Yığın dökümü aralığı"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 saniye"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 saniye"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Yığın örneklemeyi durdurmak için dokunun"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Yığın dökümü kaydediliyor"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Yığın dökümünü durdurmak için dokunun"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM yığın dökümü kaydediliyor"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Kayıtlı dosyaları temizle"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Kayıtlar bir ay sonra temizlenir"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Kayıtlı dosyalar temizlensin mi?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"/data/local/traces konumundaki tüm kayıtlar silinecek"</string>
     <string name="clear" msgid="5484761795406948056">"Sil"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Sistem izleri"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, izleme, performans"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, iz, izleme, performans, profil, profil oluşturma, cpu, çağrı yığını, yığın, yığın bellek"</string>
     <string name="share_file" msgid="1982029143280382271">"Dosya paylaşılsın mı?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Sistem İzleme dosyaları hassas sistem ve uygulama verileri (uygulama kullanımı gibi) içerebilir. Sistem izlemeyi sadece güvendiğiniz kişilerle ve uygulamalarla paylaşın."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"System Tracing dosyaları, hassas sistem ve uygulama verileri (uygulama kullanımı veya uygulama belleğindeki resimler gibi) içerebilir. Sistem izlemeyi veya yığın dökümlerini yalnızca güvendiğiniz kişi ve uygulamalarla paylaşın."</string>
     <string name="share" msgid="8443979083706282338">"Paylaş"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Bir daha gösterme"</string>
     <string name="long_traces" msgid="5110949471775966329">"Uzun izler"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Hata raporlarına kayıt ekle"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Hata raporu alındığında devam etmekte olan kayıtları otomatik olarak BetterBug\'a gönder Sonrasında kayıtlar devam eder."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Kayıtlı dosyaları göster"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"İzler, analiz için ui.perfetto.dev\'e yüklenebilir"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Yığın dökümleri AHAT ile incelenebilir"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"İzleme ayarları"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Kayıtlı dosyalar"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Çeşitli"</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 158e5fce..75a2f04b 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Записати дамп пам’яті"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Записує дамп пам’яті для процесів, вибраних у списку \"Процеси для дампу пам’яті\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Щоб записувати дампи пам’яті, виберіть принаймні один пункт у списку \"Процеси дампу пам’яті\""</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Записати дамп пам’яті AM із бітовими картами"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Збирає дамп пам’яті для процесу, вибраного в списку \"Процеси для дампу пам’яті\", і отримує бітові карти зображень"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Виберіть лише один процес у списку \"Процеси для дампу пам’яті\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Виберіть процес у списку \"Процеси для дампу пам’яті\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Збирати журнали трасування Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Містить детальні телеметричні дані інтерфейсу (може спричиняти підвисання)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Трасувати додатки для налагодження"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"За умовчанням"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Вибрано #}one{Вибрано #}few{Вибрано #}many{Вибрано #}other{Вибрано #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Процеси для дампу пам’яті"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Виберіть принаймні один процес"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Ці налаштування застосовуються до додатків Perfecto й ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Очистити процеси для дампу пам’яті"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Список процесів очищено"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Безперервний профіль даних"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Записувати дампи пам’яті з указаним інтервалом"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Записувати дампи пам’яті з указаним інтервалом. Застосовується лише до дампів пам’яті Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Інтервал запису дампів пам’яті"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 секунд"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 секунд"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Торкніться, щоб зупинити вибірку стеків"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Записується дамп пам’яті"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Натисніть, щоб зупинити запис дампу пам’яті"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Записується дамп пам’яті AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Видалити збережені файли"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Записи видаляються через місяць"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Видалити збережені файли?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Усі записи буде видалено з папки /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Очистити"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Трасування системи"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, відстеження, продуктивність"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, трасувати, трасування, продуктивність, профіль, профілювання, ЦП, стек викликів, стек, динамічна пам’ять"</string>
     <string name="share_file" msgid="1982029143280382271">"Поділитися файлом?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Файли трасування можуть містити конфіденційні дані про систему й додатки (як-от використання додатка). Діліться ними лише з людьми та в додатках, яким довіряєте."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Файли трасування можуть містити конфіденційні дані про систему й додатки (наприклад, про використання додатка або зображення в його сховищі). Діліться файлами трасування й дампами пам’яті лише з тими користувачами й додатками, яким довіряєте."</string>
     <string name="share" msgid="8443979083706282338">"Поділитися"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Більше не показувати"</string>
     <string name="long_traces" msgid="5110949471775966329">"Довгі трасування"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Долучати записи до звітів про помилки"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Автоматично надсилати активні записи в BetterBug під час формування звіту про помилку. Після цього записування продовжиться."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Переглянути збережені файли"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Файли трасування можна завантажити на сайт ui.perfetto.dev для аналізу"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Дампи пам’яті можна перевіряти за допомогою AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Налаштування трасування"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Збережені файли"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Інше"</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 600f69ba..9aa2b174 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"ہیپ ڈمپ ریکارڈ کریں"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"\"ہیپ ڈمپ پروسیسز\" میں سے منتخب کردہ پروسیسز کے ہیپ ڈمپ کو کیپچر کرتا ہے"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"ہیپ ڈمپس جمع کرنے کے لیے \"ہیپ ڈمپ کے پروسیسز\" میں کم از کم ایک پروسیس منتخب کریں"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"‏بٹ میپس کے ساتھ AM ہیپ ڈمپ کو ریکارڈ کریں"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"\"ہیپ ڈمپ پروسیسز\" میں منتخب پروسیس کا ایک ہیپ ڈمپ جمع کرتا ہے اور بٹ میپ کی تصاویر کو نکالتا ہے"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"\"ہیپ ڈمپ کے پروسیسز\" میں صرف ایک پروسیس منتخب کریں"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"\"ہیپ ڈمپ کے پروسیسز\" میں ایک پروسیس کو منتخب کریں"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"‏Winscope کے ٹریسز جمع کریں"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"‏تفصیلی UI ٹیلی میٹری ڈیٹا پر مشتمل ہے (جنک کا سبب بن سکتی ہے)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"ڈیبگ کے لائق ایپلیکیشنز ٹریس کریں"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"ڈیفالٹ"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# کو منتخب کیا گیا}other{# کو منتخب کیا گیا}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"ہیپ ڈمپ کے پروسیسز"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"کم از کم ایک پروسیس منتخب کرنا لازمی ہے"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"‏یہ انتخابات Perfetto اور ActivityManager دونوں پر لاگو ہوتے ہیں"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"ہیپ ڈمپ پروسیسز کو صاف کریں"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"پروسیس کی فہرست صاف کی گئی"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"جاری ہیپ پروفائل"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"ایک ہیپ ڈمپ کو فی مخصوص وقفہ پر ایک بار کیپچر کریں"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"‏ایک ہیپ ڈمپ کو فی مخصوص وقفہ پر ایک بار کیپچر کریں۔ صرف Perfetto ہیپ ڈمپ پر لاگو ہوتا ہے۔"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"ہیپ ڈمپ وقفہ"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 سیکنڈ"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 سیکنڈ"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"اسٹیک کے نمونے کو روکنے کے لیے تھپتھپائیں"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"ہیپ ڈمپ کو ریکارڈ کیا جا رہا ہے"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"ہیپ ڈمپ روکنے کیلئے تھپتھپائیں"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"‏‫AM ہیپ ڈمپ کو ریکارڈ کیا جا رہا ہے"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"محفوظ کردہ فائلز صاف کریں"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"ریکارڈنگز ایک ماہ بعد صاف کی جاتی ہے"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"محفوظ کردہ فائلز صاف کریں؟"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"سبھی ریکارڈنگز کو /ڈیٹا/لوکل/ٹریسز/ سے ہٹا دیا جائے گا"</string>
     <string name="clear" msgid="5484761795406948056">"صاف کریں"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"سسٹم ٹریسز"</string>
-    <string name="keywords" msgid="736547007949049535">"‏systrace، ٹریس، کارکردگی"</string>
+    <string name="keywords" msgid="255681926397897100">"‏‫systrace, traceur, perfetto, winscope، ٹریس، ٹریسنگ، کارکردگی، پروفائل، پروفائلنگ، CPU، کال اسٹیک، اسٹیک، ہیپ"</string>
     <string name="share_file" msgid="1982029143280382271">"فائل کا اشتراک کریں؟"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"سسٹم ٹریسنگ کی فائلز حساس سسٹم وار ایپ ڈیٹا (جیسے کہ ایپ کا استعمال) شامل ہو سکتی ہیں۔ صرف سسٹم ٹریسز بھروسے مند ایپس کا لوگوں کے ساتھ اشتراک کریں۔"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"سسٹم ٹریسنگ کی فائلز حساس سسٹم وار ایپ ڈیٹا (جیسے کہ ایپ کا استعمال اور ایپ کی میموری میں تصاویر) شامل ہو سکتی ہیں۔ صرف سسٹم ٹریسز بھروسے مند ایپس کا لوگوں کے ساتھ اشتراک کریں۔ صرف ان لوگوں اور ایپس کے ساتھ سسٹم ٹریسز یا ہیپ ڈمپس کا اشتراک کریں جن پر آپ اعتماد کرتے ہیں۔"</string>
     <string name="share" msgid="8443979083706282338">"اشتراک کریں"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"دوبارہ نہ دکھائیں"</string>
     <string name="long_traces" msgid="5110949471775966329">"لمبے ٹریسز"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"بگ رپورٹس کے ساتھ ریکارڈنگز منسلک کریں"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"‏بگ رپورٹ جمع ہونے پر خودکار طور پر جاری ریکارڈنگز BetterBug کو بھیج دی جاتی ہیں۔ اس کے بعد ریکارڈنگز جاری رہیں گی۔"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"محفوظ کردہ فائلز دیکھیں"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"‏تجزیے کے لیے ٹریسز ui.perfetto.dev پر اپ لوڈ کیے جا سکتے ہیں"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"‏‫AHAT کے ساتھ ہیپ ڈمپ کا معائنہ کیا جا سکتا ہے"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"ٹریس کی ترتیبات"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"محفوظ کردہ فائلز"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"متفرقات"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index 49d66bcd..92ce860c 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Hip-dampni yozib olish"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"“Hip-damp jarayonlari”da tanlangan jarayonlarning hip-damplarini oladi"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Hip-damplarni olish uchun “Hip-damp jarayonlari” qismida kamida bitta jarayonni tanlang"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"AM hip-dampni bitmaplar bilan yozib olish"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"“Hip-damp jarayonlari” ruknida tanlangan jarayonning hip-dampini toʻplaydi va bitmap rasmlarini ajratadi"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"“Hip-damp jarayonlari” ruknida faqat bitta jarayonni tanlang"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"“Hip-damp jarayonlari” ruknida bitta jarayonni tanlang"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Winscope trassirovkasini jamlash"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Batafsil UI telemetriya maʼlumotlari bilan birga (kechikishga olib kelishi mumkin)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Tuzatishga ruxsati bor ilovalarning harakatlarni yozib olish"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Asosiy"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{# ta belgilandi}other{# ta belgilandi}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Hip-damp jarayonlari"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Kamida bitta jarayon tanlanishi lozim"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Bu tanlovlar Perfetto va ActivityManager uchun amal qiladi"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Hip-damp jarayonlarini tozalash"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Jarayonlar tozalandi"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Davomiy uyma profili"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Belgilangan intervalda bir marta hip-dampni yozish"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Belgilangan intervalda bir marta hip-dampni yozing. Faqat Perfetto hip-damplari uchun amal qiladi."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Hip-damp intervali"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 soniya"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 soniya"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Trassirovkadan namuna olishni toʻxtatish uchun bosing"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Hip-damp yozib olinmoqda"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Hip-dampni toʻxtatish uchun bosing"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"AM hip-damp yozib olinmoqda"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Saqlangan fayllarni tozalash"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Yozuvlar bir oydan keyin tozalanadi"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Saqlangan fayllar tozalansinmi?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Barcha yozuvlar /data/local/traces jildidan oʻchirib tashlanadi"</string>
     <string name="clear" msgid="5484761795406948056">"Tozalash"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Harakatlarning tizim yozuvlari"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, kuzatish, unumdorlik"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, trace, trassirovka, unumdorlik, profil, profayling, cpu, callstack, stek, hip"</string>
     <string name="share_file" msgid="1982029143280382271">"Fayl ulashilsinmi?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Tizim trassirovkasi fayllari ichiga maxfiy tizim va ilovaga oid axborot (masalan, ilovadan foydalanish) kirishi mumkin. Tizim trassirovkasini faqat ishonchli foydalanuvchilargagina ulashing."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Tizim trassirovkasi fayllari ichiga maxfiy tizim va ilova maʼlumotlari (masalan, ilovadan foydalanish) yoki ilova xotirasidagi rasmlar kirishi mumkin. Tizim trassirovkalari yoki hip-damplarni faqat ishonchli odamlar va ilovalar bilan ulashing."</string>
     <string name="share" msgid="8443979083706282338">"Ulashish"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Boshqa ko‘rsatilmasin"</string>
     <string name="long_traces" msgid="5110949471775966329">"Uzun trassirovka"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Xatolik hisobotiga yozuvlarni biriktirish"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Xatolik haqidagi axborot jamlansa, BetterBug xizmatiga amaldagi yozuvlar avtomatik yuborilsin. Yozuvlar keyinroq davom etadi."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Saqlangan fayllarni ochish"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Trassirovkalarni tahlil uchun ui.perfetto.dev sahifasiga yuklash mumkin"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Hip-damplar AHAT yordamida tekshirilishi mumkin"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Trassirovka sozlamalari"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Saqlangan fayllar"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Boshqa"</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 26505e93..a53482fd 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -4,12 +4,16 @@
     <string name="system_tracing" msgid="4719188511746319848">"Theo dõi hệ thống"</string>
     <string name="record_system_activity" msgid="4339462312915377825">"Ghi lại hoạt động của hệ thống và phân tích hoạt động vào thời điểm khác nhằm cải thiện hiệu suất"</string>
     <string name="record_trace" msgid="6416875085186661845">"Ghi dấu vết"</string>
-    <string name="record_trace_summary" msgid="6705357754827849292">"Ghi lại hoạt động theo dõi hệ thống thông qua cấu hình được thiết lập trong phần \"Cài đặt theo dõi\""</string>
-    <string name="record_stack_samples" msgid="3498368637185702335">"Ghi lại hồ sơ CPU"</string>
+    <string name="record_trace_summary" msgid="6705357754827849292">"Ghi lại dấu vết hệ thống thông qua cấu hình được thiết lập trong phần \"Cài đặt dấu vết\""</string>
+    <string name="record_stack_samples" msgid="3498368637185702335">"Ghi cấu hình CPU"</string>
     <string name="record_stack_samples_summary" msgid="7827953921526410478">"Bạn cũng có thể chọn danh mục \"cpu\" để bật tính năng lấy mẫu ngăn xếp lệnh gọi trong các dấu vết"</string>
     <string name="record_heap_dump" msgid="1688550222066812696">"Ghi tệp báo lỗi"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Thu thập một tệp báo lỗi của những quy trình được chọn trong \"Quy trình tệp báo lỗi\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Chọn ít nhất một quy trình trong \"Quy trình tệp báo lỗi\" để thu thập tệp báo lỗi"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Ghi tệp báo lỗi của AM bằng bitmap"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Thu thập một tệp báo lỗi của quy trình được chọn trong \"Quy trình tệp báo lỗi\" và trích xuất hình ảnh bitmap"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Chỉ chọn một quy trình trong \"Quy trình tệp báo lỗi\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Chọn một quy trình trong \"Quy trình tệp báo lỗi\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Thu thập dấu vết Winscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Gồm cả dữ liệu chi tiết được đo từ xa về giao diện người dùng (có thể gây ra hiện tượng giật)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Theo dõi ứng dụng có thể gỡ lỗi"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Mặc định"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{Đã chọn #}other{Đã chọn #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Quy trình tệp báo lỗi"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Phải chọn ít nhất một quy trình"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Các lựa chọn này áp dụng cho cả Perfetto và ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Xoá quy trình tệp báo lỗi"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Đã xoá danh sách quy trình"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Hồ sơ ảnh chụp nhanh của vùng nhớ khối xếp liên tục"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Ghi tệp báo lỗi sau mỗi khoảng thời gian được chỉ định"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Ghi tệp báo lỗi sau mỗi khoảng thời gian được chỉ định. Chỉ áp dụng cho tệp báo lỗi của Perfetto."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Khoảng thời gian của tệp báo lỗi"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 giây"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 giây"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Nhấn để dừng lấy mẫu ngăn xếp"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"Tệp báo lỗi đang được ghi"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Nhấn để dừng tệp báo lỗi"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"Đang ghi tệp báo lỗi của AM"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Xoá tệp đã lưu"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Các bản ghi sẽ bị xoá sau một tháng"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Xoá tệp đã lưu?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Mọi bản ghi sẽ bị xoá khỏi đường dẫn /data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Xóa"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Dấu vết hệ thống"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, nhật ký hoạt động, hiệu suất"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, dấu vết, theo dõi, hiệu suất, hồ sơ, lập hồ sơ, cpu, ngăn xếp lệnh gọi, ngăn xếp, vùng nhớ khối xếp"</string>
     <string name="share_file" msgid="1982029143280382271">"Chia sẻ tệp?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Các tệp Theo dõi hệ thống có thể bao gồm dữ liệu ứng dụng và dữ liệu hệ thống nhạy cảm (chẳng hạn như mức sử dụng ứng dụng). Chỉ chia sẻ dấu vết hệ thống với những người và ứng dụng mà bạn tin tưởng."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Các tệp Theo dõi hệ thống có thể bao gồm dữ liệu nhạy cảm trên hệ thống và trong ứng dụng (chẳng hạn như mức sử dụng ứng dụng hoặc các hình ảnh trong bộ nhớ của một ứng dụng). Chỉ chia sẻ dấu vết hệ thống hoặc tệp báo lỗi với những người và ứng dụng mà bạn tin tưởng."</string>
     <string name="share" msgid="8443979083706282338">"Chia sẻ"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Không hiện lại"</string>
     <string name="long_traces" msgid="5110949471775966329">"Dấu vết dài"</string>
@@ -87,7 +92,11 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Đính kèm bản ghi vào báo cáo lỗi"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Tự động gửi các bản ghi đang xử lý đến BetterBug khi một báo cáo lỗi được thu thập. Sau đó, quá trình ghi sẽ tiếp tục."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Xem tệp đã lưu"</string>
-    <string name="pref_category_trace_settings" msgid="6507535407023329628">"Cài đặt hoạt động theo dõi"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Bạn có thể tải vết lên ui.perfetto.dev để phân tích"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Bạn có thể kiểm tra tệp báo lỗi bằng AHAT"</string>
+    <string name="pref_category_trace_settings" msgid="6507535407023329628">"Cài đặt dấu vết"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Tệp đã lưu"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"Tuỳ chọn khác"</string>
     <string name="pref_category_heap_dump_settings" msgid="2234681064312605310">"Cài đặt tệp báo lỗi"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 655b2c02..831cff7c 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -1,7 +1,7 @@
 <?xml version="1.0" encoding="UTF-8"?>
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="system_tracing" msgid="4719188511746319848">"系统跟踪"</string>
+    <string name="system_tracing" msgid="4719188511746319848">"System Tracing"</string>
     <string name="record_system_activity" msgid="4339462312915377825">"记录系统活动并在稍后分析以提升性能"</string>
     <string name="record_trace" msgid="6416875085186661845">"录制轨迹"</string>
     <string name="record_trace_summary" msgid="6705357754827849292">"使用“跟踪设置”中的配置可捕捉系统轨迹"</string>
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"记录堆转储"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"根据“堆转储进程”部分中的所选进程捕获堆转储"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"在“堆转储进程”部分中选择至少 1 个进程后才能收集堆转储"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"记录包含位图的 AM 堆转储"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"收集“堆转储进程”部分中所选进程的堆转储，并提取位图图片"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"在“堆转储进程”部分中仅选择一个进程"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"在“堆转储进程”部分中选择一个进程"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"收集 Winscope 跟踪记录"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"包括详细的界面遥测数据（可能会导致卡顿）"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"跟踪可调试的应用"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"默认"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{已选择 # 种}other{已选择 # 种}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"堆转储进程"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"必须选择至少 1 个进程"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"这些选项适用于 Perfetto 和 ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"清除堆转储进程"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"已清除进程列表"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"持续记录堆转储"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"每当达到指定的间隔，就捕获 1 次堆转储"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"每当达到指定的间隔，就捕获 1 次堆转储。仅适用于 Perfetto 堆转储。"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"堆转储记录间隔"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 秒"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 秒"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"点按即可停止堆栈采样"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"正在记录堆转储"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"点按即可停止堆转储"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"正在记录 AM 堆转储"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"清除已保存的文件"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"录制内容会在 1 个月后清除"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"要清除已保存的文件吗？"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"系统将删除 /data/local/traces 中的所有录制内容"</string>
     <string name="clear" msgid="5484761795406948056">"清除"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"系统跟踪记录"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, 跟踪, 性能"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, 轨迹, 跟踪, 性能, 个人资料, 分析, cpu, 调用堆栈, 堆栈, 堆, trace, tracing, performance, profile, profiling, cpu, callstack, stack, heap"</string>
     <string name="share_file" msgid="1982029143280382271">"要分享文件吗？"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"系统跟踪文件可能包含敏感的系统数据和应用数据（例如应用使用情况信息）。请务必只与您信任的人和应用分享系统跟踪文件。"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"系统跟踪文件可能包含敏感的系统和应用数据，例如应用使用情况或应用内存中的图片。请务必仅与您信任的人和应用分享系统跟踪文件或堆转储。"</string>
     <string name="share" msgid="8443979083706282338">"分享"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"不再显示"</string>
     <string name="long_traces" msgid="5110949471775966329">"长期跟踪记录"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"在错误报告中附加录制内容"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"收集错误报告后，自动将处理中的录制内容发送到 BetterBug。之后，系统将继续录制。"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"查看已保存的文件"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"可以将轨迹上传到 ui.perfetto.dev 进行分析"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"可以使用 AHAT 检查堆转储"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"跟踪设置"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"已保存的文件"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"其他"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 47808190..3499ffb5 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"記錄堆轉儲"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"擷取「堆轉儲程序」中所選程序的堆轉儲"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"請至少選取「堆轉儲程序」中的其中一個程序以收集堆轉儲"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"記錄包含點陣圖的 AM 堆轉儲"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"收集所選取「堆轉儲程序」的堆轉儲並擷取點陣圖圖片"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"請只選取「堆轉儲程序」中的其中一個程序"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"請選取「堆轉儲程序」中的其中一個程序"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"收集 Winscope 追蹤記錄"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"加入詳細的使用者介面遙測資料 (可能會造成資源浪費)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"追蹤可偵錯的應用程式"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"預設"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{已選取 # 個}other{已選取 # 個}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"堆轉儲程序"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"必須選取至少一個程序"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"所選項目適用於 Perfetto 和 ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"清除堆轉儲程序"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"已清除程序清單"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"連續堆資料分析"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"每隔特定間隔時間擷取堆轉儲一次"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"每隔特定間隔時間擷取堆轉儲一次。只適用於 Perfetto 堆轉儲。"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"堆轉儲間隔"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 秒"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 秒"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"輕按即可停止堆疊取樣"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"正在記錄堆轉儲"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"輕按即可停止堆轉儲"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"正在記錄 AM 堆轉儲"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"清除已儲存的檔案"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"系統會在一個月後清除記錄"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"要清除已儲存的檔案嗎？"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"系統將刪除 /data/local/traces 中的所有記錄"</string>
     <string name="clear" msgid="5484761795406948056">"清除"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"系統追蹤記錄"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, 追蹤, 效能"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, 追蹤, 效能, 設定檔, 資料剖析, cpu, 調用堆疊, 堆疊, 堆轉儲"</string>
     <string name="share_file" msgid="1982029143280382271">"要分享檔案嗎？"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"「系統追蹤」檔案可能包含敏感的系統和應用程式資料 (例如應用程式使用情況)。因此，請只與你信任的人和應用程式分享系統追蹤記錄。"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"「系統追蹤」檔案可能包含敏感的系統和應用程式資料 (例如應用程式使用情況或應用程式記憶體中的圖片)。因此，請只與你信任的人和應用程式分享系統追蹤記錄。"</string>
     <string name="share" msgid="8443979083706282338">"分享"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"不要再顯示"</string>
     <string name="long_traces" msgid="5110949471775966329">"長追蹤記錄"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"在錯誤報告中附加記錄"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"收集到錯誤報告後，自動將處理中的記錄傳送到 BetterBug。系統之後會繼續記錄內容。"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"查看已儲存的檔案"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"可上載追蹤記錄到 ui.perfetto.dev 進行分析"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"你可使用 AHAT 檢查堆轉儲"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"追蹤記錄設定"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"已儲存的檔案"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"其他"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 78394d46..6005a8b9 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"記錄記憶體快照資料"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"擷取「記憶體快照資料處理程序」中所選處理程序的記憶體快照資料"</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"如要收集記憶體快照資料，請至少選取「記憶體快照資料處理程序」中的其中一個處理程序"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"記錄包含點陣圖的 AM 記憶體快照資料"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"收集「記憶體快照資料處理程序」中所選處理程序的記憶體快照資料，並擷取點陣圖"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"只能選取「記憶體快照資料處理程序」中的一個處理程序"</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"請選取「記憶體快照資料處理程序」中的處理程序"</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"收集 Winscope 追蹤記錄"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"加入詳細的 UI 遙測資料 (可能會導致卡頓)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"追蹤可偵錯的應用程式"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"預設"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{已選取 # 個類別}other{已選取 # 個類別}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"記憶體快照資料處理程序"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"至少必須選取一個處理程序"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"這些選項會適用於 Perfetto 和 ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"清除記憶體快照資料處理程序"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"已清除處理程序清單"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"連續記憶體堆積快照"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"每隔特定間隔時間擷取記憶體快照資料一次"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"每隔特定間隔時間擷取記憶體快照資料一次，這項設定僅適用於 Perfetto 記憶體快照資料。"</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"記憶體快照資料間隔"</string>
     <string name="five_seconds" msgid="7018465440929299712">"5 秒"</string>
     <string name="ten_seconds" msgid="863416601384309033">"10 秒"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"輕觸即可停止堆疊取樣"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"正在記錄記憶體快照資料"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"輕觸即可停止記錄記憶體快照資料"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"正在記錄 AM 記憶體快照資料"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"清除已儲存的檔案"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"系統會在一個月後清除記錄檔"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"要清除已儲存的檔案嗎？"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"系統將刪除 /data/local/traces 中的所有記錄檔"</string>
     <string name="clear" msgid="5484761795406948056">"清除"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"系統追蹤記錄"</string>
-    <string name="keywords" msgid="736547007949049535">"systrace, 追蹤, 效能"</string>
+    <string name="keywords" msgid="255681926397897100">"systrace, traceur, perfetto, winscope, 追蹤記錄, 追蹤, 效能, 設定檔, 剖析, cpu, 呼叫堆疊, 堆疊, 堆積"</string>
     <string name="share_file" msgid="1982029143280382271">"要分享檔案嗎？"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"系統追蹤檔可能包含敏感的系統和應用程式資料 (例如應用程式使用情形)。請務必只與你信任的使用者和應用程式分享系統追蹤檔。"</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"系統追蹤檔可能包含敏感的系統和應用程式資料，例如應用程式使用情形或應用程式記憶體中的圖片。請務必確認你信任對方和應用程式，再分享系統追蹤檔或記憶體快照資料。"</string>
     <string name="share" msgid="8443979083706282338">"分享"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"不要再顯示"</string>
     <string name="long_traces" msgid="5110949471775966329">"長期追蹤記錄"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"在錯誤報告中附上記錄檔"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"收集到錯誤報告後，自動將處理中的記錄檔傳送到 BetterBug。之後，系統會繼續記錄。"</string>
     <string name="link_to_traces" msgid="1404687523304348490">"查看已儲存的檔案"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"Perfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"追蹤記錄可上傳到 ui.perfetto.dev 進行分析"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"AHAT 可用於檢查記憶體快照資料"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"追蹤記錄設定"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"儲存的檔案"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"其他"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 634b555e..a1996fa8 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -10,6 +10,10 @@
     <string name="record_heap_dump" msgid="1688550222066812696">"Rekhoda i-heap dump"</string>
     <string name="record_heap_dump_summary_enabled" msgid="5038675257021221777">"Ithatha i-heap dump yezinqubo ezikhethiwe \"kuzinqubo ze-heap dump\""</string>
     <string name="record_heap_dump_summary_disabled" msgid="4640319333930345311">"Khetha okungenani inqubo eyodwa kokuthi \"Izinqubo ze-heap dump\" ukuze uqoqe ama-heap dump"</string>
+    <string name="record_am_heap_dump" msgid="5012983869757648802">"Rekhoda i-AM heap dump ngama-bitmap"</string>
+    <string name="record_am_heap_dump_summary_enabled" msgid="5198382489516464944">"Iqoqa i-heap dump yenqubo ekhethwe kwelithi \"Izinqubo ze-heap dump\" bese ikhipha izithombe zama-bitmap"</string>
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected" msgid="2977555944190489590">"Khetha inqubo eyodwa kuphela kwelithi \"Izinqubo ze-heap dump\""</string>
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected" msgid="805044012304241085">"Khetha inqubo kwelithi \"Izinqubo ze-heap dump\""</string>
     <string name="winscope_tracing" msgid="5818984791154837458">"Qoqa Ukulandelela kweWinscope"</string>
     <string name="winscope_tracing_summary" msgid="7040550156722395894">"Kuhlanganisa okuningilizwe Idatha ye-UI ye-telemetry (kungaba yimbangela ye-jank)"</string>
     <string name="trace_debuggable_applications" msgid="7957069895298887899">"Landela izinhlelo zokusebenza zedebuggable"</string>
@@ -19,11 +23,11 @@
     <string name="default_categories" msgid="2117679794687799407">"Okuzenzekelayo"</string>
     <string name="num_categories_selected" msgid="5772630335027553995">"{count,plural, =1{okukhethiwe #}one{okukhethiwe #}other{okukhethiwe #}}"</string>
     <string name="heap_dump_processes" msgid="2500105180344901939">"Izinqubo ze-heap dump"</string>
-    <string name="heap_dump_processes_summary" msgid="4570434268024622765">"Okungenani inqubo eyodwa kufanele ikhethwe"</string>
+    <string name="heap_dump_processes_summary" msgid="496329155430447095">"Lokhu kusebenza kuPerfetto naku-ActivityManager"</string>
     <string name="clear_heap_dump_processes" msgid="295101454741555286">"Sula izinqubo ze-heap dump"</string>
     <string name="clear_heap_dump_processes_toast" msgid="3658510557596150797">"Uhlu lwezinqubo lusuliwe"</string>
     <string name="continuous_heap_dump" msgid="390369382946204224">"Iphrofayela yezinhlelo ezihlukahlukene eqhubekayo"</string>
-    <string name="continuous_heap_dump_summary" msgid="4581643248161659581">"Thatha i-heap dump kanye ngokwesikhawu ngasinye esishiwo"</string>
+    <string name="continuous_heap_dump_summary" msgid="4324725780071430593">"Thatha i-heap dump kube kanye ngezikhathi ezithile Kusebenza kuphela kuPerfetto heap dumps."</string>
     <string name="continuous_heap_dump_interval" msgid="842533896492001433">"Isikhawu se-heap dump"</string>
     <string name="five_seconds" msgid="7018465440929299712">"Imizuzwana emi-5"</string>
     <string name="ten_seconds" msgid="863416601384309033">"Imizuzwana engu-10"</string>
@@ -50,15 +54,16 @@
     <string name="tap_to_stop_stack_sampling" msgid="5911317684139059415">"Thepha ukuze umise ukusampula kwesitaki"</string>
     <string name="heap_dump_is_being_recorded" msgid="3789315106110524969">"I-heap dump iyarekhodwa"</string>
     <string name="tap_to_stop_heap_dump" msgid="6475699275834526902">"Thepha ukuze umise i-heap dump"</string>
+    <string name="am_heap_dump_is_being_recorded" msgid="7679311408393495981">"I-AM heap dump iyarekhodwa"</string>
     <string name="clear_saved_files" msgid="9156079311231446825">"Sula amafayela alondoloziwe"</string>
     <string name="clear_saved_files_summary" msgid="109751867417553670">"Ukurekhoda kusulwa ngemva kwenyanga eyodwa"</string>
     <string name="clear_saved_files_question" msgid="8586686617760838834">"Sula amafayela alondoloziwe?"</string>
     <string name="all_recordings_will_be_deleted" msgid="7731693738485947891">"Konke ukurekhoda kuzosuswa ku-/data/local/traces"</string>
     <string name="clear" msgid="5484761795406948056">"Sula"</string>
     <string name="system_traces_storage_title" msgid="8294090839883366871">"Ukulandela kwesistimu"</string>
-    <string name="keywords" msgid="736547007949049535">"i-systrace, ukulandelela, ukusebenza"</string>
+    <string name="keywords" msgid="255681926397897100">"i-systrace, i-traceur, i-perfetto, i-winscope, landelela, ukulandelela, ukusebenza, iphrofayela, ukwenza iphrofayela, i-cpu, i-callstack, izitaki, i-heap"</string>
     <string name="share_file" msgid="1982029143280382271">"Yabelana ngefayela?"</string>
-    <string name="system_trace_sensitive_data" msgid="3069389866696009549">"Amafayela okulandelela isistimu angafaka idatha ezwelayo yesistimu neyohlelo lokusebenza (efana nokusetshenziswa kohlelo lokusebenza). Yabelana kuphela ngokulandelela kwesistimu nabantu nezinhlelo zokusebenza ozithembayo."</string>
+    <string name="system_trace_sensitive_data" msgid="1479213054797221656">"Amafayela Alandelelwa isistimu angase ahlanganise isistimu ezwelayo nedatha ye-app (njengokusetshenziswa kwe-app noma izithombe iziku-app). Hlanganyela okulandelelwa isistimu noma ama-heap dump nabantu nama-app owathembayo kuphela"</string>
     <string name="share" msgid="8443979083706282338">"Yabelana"</string>
     <string name="dont_show_again" msgid="6662492041164390600">"Ungabonisi futhi"</string>
     <string name="long_traces" msgid="5110949471775966329">"Ukulandela okude"</string>
@@ -87,6 +92,10 @@
     <string name="attach_to_bug_report" msgid="5388986830016247490">"Namathisela okurekhodiwe emibikweni yesiphazamisi"</string>
     <string name="attach_to_bug_report_summary" msgid="5289287574947339086">"Thumela ngokuzenzakalelayo ukurekhoda okuqhubekayo kuBetterBug lapho kuqoqwe umbiko wesiphazamisi. Okurekhodiwe kuzoqhubeka kamuva."</string>
     <string name="link_to_traces" msgid="1404687523304348490">"Buka amafayela alondoloziwe"</string>
+    <string name="pref_category_perfetto_title" msgid="6666944431707303646">"IPerfetto"</string>
+    <string name="pref_category_perfetto_summary" msgid="3553304890055871620">"Ukulandelela kungalayishwa kokuthi ui.perfetto.dev ukuze kuhlaziywe"</string>
+    <string name="pref_category_other_tools_title" msgid="4005958504576983766">"I-ActivityManager"</string>
+    <string name="pref_category_other_tools_summary" msgid="8548744690364563186">"Ama-heap dump angase ahlolwe nge-AHAT"</string>
     <string name="pref_category_trace_settings" msgid="6507535407023329628">"Amasethingi okulandelela"</string>
     <string name="pref_category_saved_files" msgid="1477491400970413291">"Amafayela alondoloziwe"</string>
     <string name="pref_category_misc" msgid="6217624054980014683">"I-Miscellaneous"</string>
diff --git a/res/values/preference_keys.xml b/res/values/preference_keys.xml
index 6816f2e8..5ac982ba 100644
--- a/res/values/preference_keys.xml
+++ b/res/values/preference_keys.xml
@@ -4,6 +4,7 @@
     <string name="pref_key_tracing_on">tracing_on</string>
     <string name="pref_key_stack_sampling_on">stack_sampling_on</string>
     <string name="pref_key_heap_dump_on">heap_dump_on</string>
+    <string name="pref_key_am_heap_dump_on">am_heap_dump_on</string>
     <string name="pref_key_recording_was_trace">recording_was_trace</string>
     <string name="pref_key_recording_was_stack_samples">recording_was_stack_samples</string>
     <string name="pref_key_tags">current_tags_11</string>
@@ -20,4 +21,7 @@
     <string name="pref_key_heap_dump_processes">heap_dump_processes</string>
     <string name="pref_key_continuous_heap_dump">continuous_heap_dump</string>
     <string name="pref_key_continuous_heap_dump_interval">continuous_heap_dump_interval</string>
+
+    <!-- This key is used to guard the visibility of the AM heap dump feature. -->
+    <string name="pref_category_other_tools">category_other_tools</string>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index a6ad8e36..15d410dc 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -24,6 +24,15 @@
     <!-- This is the subtitle for the "Record heap dump" button if heap dumps are disabled. -->
     <string name="record_heap_dump_summary_disabled">Select at least one process in \"Heap dump processes\" to collect heap dumps</string>
 
+    <!-- This is the label for a button. When the button is pressed, we will record one "heap dump" through AM ("ActivityManager") on the user's device. "AM" is an app name and should not be translated. -->
+    <string name="record_am_heap_dump">Record AM heap dump with bitmaps</string>
+    <!-- This is the subtitle for the "Record AM heap dump" button if it is enabled. -->
+    <string name="record_am_heap_dump_summary_enabled">Collects a heap dump of the process selected in \"Heap dump processes\" and extracts bitmap images </string>
+    <!-- This is the subtitle for the "Record AM heap dump" button if it is disabled due to multiple processes being selected. -->
+    <string name="record_am_heap_dump_summary_disabled_multiple_procs_selected">Select only one process in \"Heap dump processes\"</string>
+    <!-- This is the subtitle for the "Record AM heap dump" button if it is disabled due to no processes being selected. -->
+    <string name="record_am_heap_dump_summary_disabled_no_procs_selected">Select a process in \"Heap dump processes\"</string>
+
     <!-- This is the text for a toggle that will let the user choose whether to include Winscope traces in the trace they are collecting. -->
     <string name="winscope_tracing">Collect Winscope traces</string>
     <string name="winscope_tracing_summary">Includes detailed UI telemetry data (can cause jank)</string>
@@ -47,16 +56,16 @@
 
     <!-- This is the label for a button. When this button is pressed, a checklist is opened that allows the user to select process names. -->
     <string name="heap_dump_processes">Heap dump processes</string>
-    <!-- This is the subtitle for the "Heap dump processes" button. -->
-    <string name="heap_dump_processes_summary">At least one process must be selected</string>
+    <!-- This is the subtitle for the "Heap dump processes" button. "Perfetto" and "ActivityManager" are app names and should not be translated. -->
+    <string name="heap_dump_processes_summary">These selections apply to both Perfetto and ActivityManager</string>
     <!-- This is the label for a button that will clear the processes that were previously selected by the user in "Heap dump processes". -->
     <string name="clear_heap_dump_processes">Clear heap dump processes</string>
     <!-- This is the text for a pop-up notification when user-input processes are cleared with "Clear heap dump processes". -->
     <string name="clear_heap_dump_processes_toast">Process list cleared</string>
     <!-- This is the label for a toggle that will cause heap dumps to be taken continuously. -->
     <string name="continuous_heap_dump">Continuous heap profile</string>
-    <!-- This is the summary for the "Continuous heap profile" toggle that explains that a heap dump will be taken every specified interval. .-->
-    <string name="continuous_heap_dump_summary">Capture a heap dump once per specified interval</string>
+    <!-- This is the summary for the "Continuous heap profile" toggle that explains that a heap dump will be taken every specified interval. "Perfetto" is an app name and should not be translated. -->
+    <string name="continuous_heap_dump_summary">Capture a heap dump once per specified interval. Only applies to Perfetto heap dumps.</string>
     <!-- This is the label for a picker that will let the user specify the interval at which to continuously record heap dumps. -->
     <string name="continuous_heap_dump_interval">Heap dump interval</string>
 
@@ -120,6 +129,9 @@
     <!-- This is the subtitle for a notification that appears while a heap dump is being recorded. Tapping the notification will stop the recording. -->
     <string name="tap_to_stop_heap_dump">Tap to stop heap dump</string>
 
+    <!-- This is the title for a notification that briefly appears while a heap dump is being recorded. "AM" is an app name and should not be translated. -->
+    <string name="am_heap_dump_is_being_recorded">AM heap dump is being recorded</string>
+
     <!-- This is the label for a button that will clear all of the saved recordings, removing them all from the directory they are saved to. There will be a confirmation dialog after this button is tapped, but clearing the traces after confirming is not reversible. -->
     <string name="clear_saved_files">Clear saved files</string>
     <string name="clear_saved_files_summary">Recordings are cleared after one month</string>
@@ -134,14 +146,14 @@
     <!-- This is the title for the directory holding the system traces. The user sees this when using a directory browsing app like the Files app. -->
     <string name="system_traces_storage_title">System traces</string>
 
-    <!-- These are keywords that the user can use to search for this app. 'systrace' should not be translated, as it is an app name. -->
-    <string name="keywords">systrace, trace, performance</string>
+    <!-- These are keywords that the user can use to search for this app. 'systrace', 'traceur', 'perfetto', and 'winscope' should not be translated, as they are app names. -->
+    <string name="keywords">systrace, traceur, perfetto, winscope, trace, tracing, performance, profile, profiling, cpu, callstack, stack, heap</string>
 
     <!-- Title of a dialog asking the user to confirm whether they want to share the recorded file. -->
     <string name="share_file">Share file?</string>
 
     <!-- Text informing user about contents of a trace file. This string appears when users share a trace file or reveal the System Traces directory in a directory browsing app like Files. -->
-    <string name="system_trace_sensitive_data">System Tracing files may include sensitive system and app data (such as app usage). Only share system traces with people and apps you trust.</string>
+    <string name="system_trace_sensitive_data">System Tracing files may include sensitive system and app data (such as app usage or images in an app\'s memory). Only share system traces or heap dumps with people and apps you trust.</string>
 
     <!-- Button on a dialog asking the user to confirm whether they want to share the trace. Clicking this button confirms that the user does want to share the trace. -->
     <string name="share">Share</string>
@@ -199,6 +211,13 @@
     <!-- On click, takes the user to the directory containing on-device Traceur files. -->
     <string name="link_to_traces">View saved files</string>
 
+    <!-- This is the title for the list of recordings handled by Perfetto. "Perfetto" is an app name and should not be translated. -->
+    <string name="pref_category_perfetto_title">Perfetto</string>
+    <string name="pref_category_perfetto_summary">Traces can be uploaded to ui.perfetto.dev for analysis</string>
+    <!-- This is the title for the list of recordings handled by ActivityManager. "ActivityManager" is an app name and should not be translated. -->
+    <string name="pref_category_other_tools_title">ActivityManager</string>
+    <string name="pref_category_other_tools_summary">Heap dumps can be inspected with AHAT</string>
+
     <!-- This is the title for the list of settings related to tracing. -->
     <string name="pref_category_trace_settings">Trace settings</string>
     <!-- This is the title for the options related to viewing or deleting saved Traceur files. -->
diff --git a/res/xml/main.xml b/res/xml/main.xml
index 8a06fcaa..2487e033 100644
--- a/res/xml/main.xml
+++ b/res/xml/main.xml
@@ -16,18 +16,31 @@
   -->
 
 <androidx.preference.PreferenceScreen xmlns:android="http://schemas.android.com/apk/res/android">
-    <androidx.preference.SwitchPreference
-        android:key="@string/pref_key_tracing_on"
-        android:title="@string/record_trace"
-        android:summary="@string/record_trace_summary" />
-    <androidx.preference.SwitchPreference
-        android:key="@string/pref_key_stack_sampling_on"
-        android:title="@string/record_stack_samples"
-        android:summary="@string/record_stack_samples_summary" />
-    <androidx.preference.SwitchPreference
-        android:key="@string/pref_key_heap_dump_on"
-        android:title="@string/record_heap_dump"
-        android:summary="@string/record_heap_dump_summary_disabled" />
+    <androidx.preference.PreferenceCategory
+        android:title="@string/pref_category_perfetto_title"
+        android:summary="@string/pref_category_perfetto_summary" >
+        <androidx.preference.SwitchPreference
+            android:key="@string/pref_key_tracing_on"
+            android:title="@string/record_trace"
+            android:summary="@string/record_trace_summary" />
+        <androidx.preference.SwitchPreference
+            android:key="@string/pref_key_stack_sampling_on"
+            android:title="@string/record_stack_samples"
+            android:summary="@string/record_stack_samples_summary" />
+        <androidx.preference.SwitchPreference
+            android:key="@string/pref_key_heap_dump_on"
+            android:title="@string/record_heap_dump"
+            android:summary="@string/record_heap_dump_summary_disabled" />
+    </androidx.preference.PreferenceCategory>
+    <androidx.preference.PreferenceCategory
+        android:key="@string/pref_category_other_tools"
+        android:title="@string/pref_category_other_tools_title"
+        android:summary="@string/pref_category_other_tools_summary" >
+        <androidx.preference.Preference
+            android:key="@string/pref_key_am_heap_dump_on"
+            android:title="@string/record_am_heap_dump"
+            android:summary="@string/record_am_heap_dump_summary_disabled_no_procs_selected" />
+    </androidx.preference.PreferenceCategory>
     <androidx.preference.PreferenceCategory
         android:title="@string/pref_category_trace_settings" >
         <androidx.preference.SwitchPreference
diff --git a/src/com/android/traceur/DumpHeapUtils.java b/src/com/android/traceur/DumpHeapUtils.java
new file mode 100644
index 00000000..04c758df
--- /dev/null
+++ b/src/com/android/traceur/DumpHeapUtils.java
@@ -0,0 +1,619 @@
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
+ * limitations under the License
+ */
+
+package com.android.traceur;
+
+import android.app.ActivityManager;
+import android.content.Context;
+import android.graphics.Bitmap;
+import android.graphics.BitmapFactory;
+import android.os.Bundle;
+import android.os.ParcelFileDescriptor;
+import android.os.RemoteCallback;
+import android.os.RemoteException;
+import android.system.ErrnoException;
+import android.system.Os;
+import android.util.Log;
+
+import java.io.ByteArrayInputStream;
+import java.io.File;
+import java.io.FileOutputStream;
+import java.io.InputStream;
+import java.io.IOException;
+import java.io.OutputStream;
+import java.nio.ByteBuffer;
+import java.nio.file.Paths;
+import java.nio.channels.FileChannel;
+import java.nio.charset.StandardCharsets;
+import java.nio.file.StandardOpenOption;
+import java.text.SimpleDateFormat;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.Date;
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Locale;
+import java.util.Map;
+import java.util.Set;
+import java.util.concurrent.CountDownLatch;
+
+/**
+ * Functions for calling AM's heap dump with bitmaps.
+ */
+public class DumpHeapUtils {
+
+    static final String TAG = "Traceur";
+
+    private static final String TRACE_DIRECTORY = "/data/local/traces";
+    private static final String DATE_FORMAT = "yyyy-MM-dd-HH-mm-ss";
+
+    private static final String TEMP_HPROF_NAME = ".heapdump.in-progress";
+    private static final String COMPLETED_HPROF_NAME = "dump-%s.hprof";
+
+    private static final String BITMAP_CLASSNAME = "android.graphics.Bitmap";
+    private static final String DUMPDATA_CLASSNAME = "android.graphics.Bitmap$DumpData";
+
+    public static boolean dumpHeapWithAM(Context context, String process) {
+        try {
+            String date = new SimpleDateFormat(DATE_FORMAT, Locale.US).format(new Date());
+            File outputDirectory = new File(getOutputDirectory(date));
+            outputDirectory.mkdir();
+            File file = new File(outputDirectory, TEMP_HPROF_NAME);
+            file.createNewFile();
+
+            final CountDownLatch latch = new CountDownLatch(1);
+            final RemoteCallback finishCallback = new RemoteCallback(
+                    new RemoteCallback.OnResultListener() {
+                        @Override
+                        public void onResult(Bundle result) {
+                            Log.i(TAG, "dumpHeap() complete");
+                            latch.countDown();
+                        }
+                    }, null);
+
+            Log.i(TAG, "Starting AM dumpHeap()");
+            ActivityManager am = context.getSystemService(ActivityManager.class);
+            am.getService().dumpHeap(process, /* userId = */ context.getUserId(),
+                    /* managed = */ true, /* mallocInfo = */ false, /* runGc = */ false,
+                    /* dumpBitmaps = */ "png", /* path = */ file.toString(),
+                    /* fd = */ ParcelFileDescriptor.open(file,
+                        ParcelFileDescriptor.MODE_READ_WRITE),
+                    /* finishCallback = */ finishCallback);
+            latch.await();
+
+            File completedHeapDump = new File(outputDirectory,
+                    String.format(COMPLETED_HPROF_NAME, date));
+            Os.rename(file.getCanonicalPath(), completedHeapDump.getCanonicalPath());
+
+            parseHprofForBitmaps(completedHeapDump);
+        } catch (IOException | RemoteException | InterruptedException | ErrnoException e) {
+            Log.e(TAG, e.toString());
+        }
+        return true;
+    }
+
+    // Scans through the input hprof file and outputs bitmap images as .pngs in
+    // /data/local/traces/<hprof subdirectory>.
+    private static void parseHprofForBitmaps(File file) throws IOException {
+        FileChannel channel = FileChannel.open(file.toPath(), StandardOpenOption.READ);
+        ByteBuffer byteBuffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());
+        channel.close();
+
+        StringBuilder format = new StringBuilder();
+        HprofBuffer buf = new HprofBuffer(byteBuffer);
+
+        int b;
+        while ((b = buf.getU1()) != 0) {
+            format.append((char)b);
+        }
+
+        int idSize = buf.getU4();
+        boolean idSize8 = false;
+        if (idSize == 8) {
+            idSize8 = true;
+        } else if (idSize != 4) {
+            Log.e(TAG, "Id size " + idSize + " not supported.");
+            return;
+        }
+
+        int hightime = buf.getU4();
+        int lowtime = buf.getU4();
+
+        // Map of string IDs to Strings.
+        Map<Long, String> strings = new HashMap<>();
+
+        // Map of class object IDs to class name string IDs.
+        Map<Long, Long> classes = new HashMap<>();
+
+        // android.graphics.Bitmap instance fields.
+        List<Field> bitmapFields = new ArrayList<>();
+
+        // android.graphics.Bitmap$DumpData instance fields.
+        List<Field> dumpDataFields = new ArrayList<>();
+
+        int startPosition = buf.position();
+
+        // In the first pass through the heap dump, we record strings, class names, and class dumps.
+        while (buf.hasRemaining()) {
+            int tag = buf.getU1();
+            int time = buf.getU4();
+            int recordLength = buf.getU4();
+            if (tag == 0x01) { // STRING
+                long id = buf.getId(idSize8);
+                byte[] bytes = new byte[recordLength - idSize];
+                buf.getBytes(bytes);
+
+                String string = new String(bytes, StandardCharsets.UTF_8);
+                if (isRelevantString(string)) {
+                    strings.put(id, string);
+                }
+            } else if (tag == 0x02) { // LOAD CLASS
+                int classSerialNumber = buf.getU4();
+                long objectId = buf.getId(idSize8);
+                int stackSerialNumber = buf.getU4();
+                long classNameStringId = buf.getId(idSize8);
+
+                if (isRelevantString(strings.get(classNameStringId))) {
+                    classes.put(objectId, classNameStringId);
+                }
+            } else if (tag == 0x0C || tag == 0x1C) {
+                int endOfRecord = buf.position() + recordLength;
+                while (buf.position() < endOfRecord) {
+                    int subtag = buf.getU1();
+                    if (handleIrrelevantSubtags(subtag, buf, idSize8, idSize)) {
+                        // Nothing to do here.
+                    } else if (handlePossiblyRelevantSubtags(subtag, buf, idSize8, idSize,
+                            /* firstPass = */ true)) {
+                        // Nothing to do here.
+                    } else if (subtag == 0x20) { // CLASS DUMP
+                        long objectId = buf.getId(idSize8);
+                        int stackSerialNumber = buf.getU4();
+                        long superClassId = buf.getId(idSize8);
+                        long classLoaderId = buf.getId(idSize8);
+                        long signersId = buf.getId(idSize8);
+                        long protectionId = buf.getId(idSize8);
+                        long reserved1 = buf.getId(idSize8);
+                        long reserved2 = buf.getId(idSize8);
+                        int instanceSize = buf.getU4();
+
+                        int constantPoolSize = buf.getU2();
+                        for (int i = 0; i < constantPoolSize; i++) {
+                            int index = buf.getU2();
+                            Type type = buf.getType();
+                            buf.skip(type.size(idSize));
+                        }
+
+                        int numStaticFields = buf.getU2();
+                        for (int i = 0; i < numStaticFields; i++) {
+                            long nameId = buf.getId(idSize8);
+                            Type type = buf.getType();
+                            buf.skip(type.size(idSize));
+                        }
+
+                        String className = strings.get(classes.get(objectId));
+                        boolean isBitmapClass = BITMAP_CLASSNAME.equals(className);
+                        boolean isDumpDataClass = DUMPDATA_CLASSNAME.equals(className);
+
+                        int numInstanceFields = buf.getU2();
+                        for (int i = 0; i < numInstanceFields; i++) {
+                            long nameId = buf.getId(idSize8);
+                            Type type = buf.getType();
+                            if (isBitmapClass) {
+                                bitmapFields.add(new Field(strings.get(nameId), type));
+                            } else if (isDumpDataClass) {
+                                dumpDataFields.add(new Field(strings.get(nameId), type));
+                            }
+                        }
+                    } else {
+                        Log.e(TAG, String.format("subtag %x not found", subtag));
+                    }
+                }
+            } else {
+                buf.skip(recordLength);
+            }
+        }
+
+        if (bitmapFields.isEmpty()) {
+            Log.e(TAG, "Never found Bitmap class dump.");
+        }
+        if (dumpDataFields.isEmpty()) {
+            Log.e(TAG, "Never found DumpData class dump.");
+        }
+
+        // ID of the android.graphics.Bitmap$DumpData's 'buffers' field. This points to an array of
+        // IDs, each of which represents a byte[] (that a Bitmap object can be produced from).
+        long dumpDataBuffersId = -1;
+        List<Long> bitmapBufferRefs = new ArrayList<>();
+        Map<Long, byte[]> bitmapBuffers = new HashMap<>();
+
+        // ID of the android.graphics.Bitmap$DumpData's 'natives' field. This points to an array of
+        // longs, each of which uniquely identifies a bitmap.
+        long dumpDataNativesId = -1;
+        List<Long> nativePtrs = new ArrayList<>();
+
+        // ID of the android.graphics.Bitmap$DumpData's 'sizes' field. This points to an array of
+        // longs, each of which holds a Bitmap object's size (as calculated by
+        // Bitmap.getAllocationByteCount()).
+        long dumpDataSizesId = -1;
+        List<Integer> sizes = new ArrayList<>();
+
+        // Map of nativePtrs to bitmap dimensions.
+        Map<Long, Dimensions> dimensions = new HashMap<>();
+
+        // In the second pass through the heap dump, we record Bitmap/DumpData instances and their
+        // fields that we care about.
+        buf.seek(startPosition);
+        while (buf.hasRemaining()) {
+            int tag = buf.getU1();
+            int time = buf.getU4();
+            int recordLength = buf.getU4();
+            if (tag == 0x0C || tag == 0x1C) {
+                int endOfRecord = buf.position() + recordLength;
+                while (buf.position() < endOfRecord) {
+                    int subtag = buf.getU1();
+                    if (handleIrrelevantSubtags(subtag, buf, idSize8, idSize)) {
+                        // Nothing to do here.
+                    } else if (handlePossiblyRelevantSubtags(subtag, buf, idSize8, idSize,
+                            /* firstPass = */ false)) {
+                        // Nothing to do here.
+                    } else if (subtag == 0x21) { // INSTANCE DUMP
+                        long objectId = buf.getId(idSize8);
+                        int stackSerialNumber = buf.getU4();
+                        long classId = buf.getId(idSize8);
+                        int numBytes = buf.getU4();
+
+                        // We check for null first because we can't cast a null value to long.
+                        long stringId = classes.get(classId) != null ? classes.get(classId) : -1;
+                        int originalPosition = buf.position();
+
+                        // We use field names instead of relying on the alphabetical field order,
+                        // since it's less likely that an existing field name will be changed than
+                        // a new field added.
+                        String className = strings.get(stringId);
+                        if (DUMPDATA_CLASSNAME.equals(className)) {
+                            for (Field field : dumpDataFields) {
+                                if ("buffers".equals(field.name)) {
+                                    // Used in OBJECT ARRAY DUMP.
+                                    dumpDataBuffersId = buf.getId(idSize8);
+                                } else if ("natives".equals(field.name)) {
+                                    // Used in PRIMITIVE ARRAY DUMP.
+                                    dumpDataNativesId = buf.getId(idSize8);
+                                } else if ("sizes".equals(field.name)) {
+                                    // Used in PRIMITIVE ARRAY DUMP.
+                                    dumpDataSizesId = buf.getId(idSize8);
+                                } else {
+                                    handleIrrelevantField(field, buf, idSize8);
+                                }
+                            }
+                        } else if (BITMAP_CLASSNAME.equals(className)) {
+                            int height = -1;
+                            int width = -1;
+                            long nativePtr = -1;
+                            for (Field field : bitmapFields) {
+                                if ("mHeight".equals(field.name)) {
+                                    height = buf.getInt();
+                                } else if ("mWidth".equals(field.name)) {
+                                    width = buf.getInt();
+                                } else if ("mNativePtr".equals(field.name)) {
+                                    nativePtr = buf.getLong();
+                                } else {
+                                    handleIrrelevantField(field, buf, idSize8);
+                                }
+                            }
+                            dimensions.put(nativePtr, new Dimensions(width, height));
+                        }
+                        buf.seek(originalPosition + numBytes);
+                    } else if (subtag == 0x22) { // OBJECT ARRAY DUMP
+                        long objectId = buf.getId(idSize8);
+                        int stackSerialNumber = buf.getU4();
+                        int length = buf.getU4();
+                        long classId = buf.getId(idSize8);
+
+                        // We check for null first because we can't cast a null value to long.
+                        long stringId = classes.get(classId) != null ? classes.get(classId) : -1;
+
+                        if (objectId == dumpDataBuffersId) {
+                            for (int i = 0; i < length; i++) {
+                                long referenceId = buf.getId(idSize8);
+                                bitmapBufferRefs.add(referenceId);
+                            }
+                        } else {
+                            buf.skip(length * idSize);
+                        }
+                    } else if (subtag == 0x23) { // PRIMITIVE ARRAY DUMP
+                        long objectId = buf.getId(idSize8);
+                        int stackSerialNumber = buf.getU4();
+                        int length = buf.getU4();
+                        Type type = buf.getType();
+
+                        // These array dumps always seem to be encountered after the IDs
+                        // representing them have been found, including the entire set of IDs for
+                        // bitmapBufferRefs. If this assumption ever fails, it will be logged below.
+                        if (bitmapBufferRefs.contains(objectId)) {
+                            byte[] byteArray = new byte[length];
+                            buf.getBytes(byteArray);
+                            bitmapBuffers.put(objectId, byteArray);
+                        } else if (objectId == dumpDataNativesId) {
+                            for (int i = 0; i < length; i++) {
+                                long nativePtr = buf.getLong();
+                                nativePtrs.add(nativePtr);
+                            }
+                        } else if (objectId == dumpDataSizesId) {
+                            for (int i = 0; i < length; i++) {
+                                int size = buf.getInt();
+                                sizes.add(size);
+                            }
+                        } else {
+                            buf.skip(length * type.size(idSize));
+                        }
+                    } else {
+                        Log.e(TAG, String.format("subtag %x not found", subtag));
+                    }
+                }
+            } else {
+                buf.skip(recordLength);
+            }
+        }
+
+        // This case shouldn't occur as DumpData arrays should be of the same length.
+        if (nativePtrs.size() != bitmapBufferRefs.size() ||
+                nativePtrs.size() != sizes.size()) {
+            Log.e(TAG, "Some bitmap info is missing; no bitmaps will be dumped. Item counts:");
+            Log.e(TAG, String.format("nativePtrs: %d, bitmapBufferRefs: %d, sizes: %d",
+                    nativePtrs.size(), bitmapBufferRefs.size(), sizes.size()));
+        } else {
+            if (bitmapBuffers.size() != nativePtrs.size()) {
+                Log.w(TAG, String.format("%d bitmaps were found on the heap, but DumpData " +
+                        "contains info for %d bitmaps.", bitmapBuffers.size(), nativePtrs.size()));
+            }
+            // nativePtrs, sizes, and bitmapBufferRefs are arrays held by DumpData and can be
+            // traversed in order. bitmapBuffers is populated in the order that instances were
+            // encountered in the heap dump, so must be indexed into using bitmapBufferRefs.
+            for (int i = 0; i < nativePtrs.size(); i++) {
+                Dimensions dim = dimensions.getOrDefault(nativePtrs.get(i), new Dimensions(0, 0));
+                byte[] buffer = bitmapBuffers.get(bitmapBufferRefs.get(i));
+                if (buffer != null) {
+                    writeBitmap(file.getParent(), i, dim, sizes.get(i), BitmapFactory.decodeStream(
+                            new ByteArrayInputStream(buffer)));
+                }
+            }
+        }
+    }
+
+    // Writes the input Bitmap as a PNG to the input directory.
+    private static boolean writeBitmap(String dir, int index, Dimensions dimensions, int size,
+            Bitmap bitmap) {
+        String path = String.format("%s/bitmap-%d-(%dx%d)-(%dB).png", dir, index, dimensions.width,
+                dimensions.height, size);
+        Log.i(TAG, "Writing bitmap to " + path);
+        try (OutputStream os = new FileOutputStream(new File(path))) {
+            bitmap.compress(Bitmap.CompressFormat.PNG, 100, os);
+            os.flush();
+            return true;
+        } catch (Exception e) {
+            Log.i(TAG, "Failed to write bitmap to " + path);
+            return false;
+        }
+    }
+
+    // These Types are used to identify object types during heap dump parsing.
+    enum Type {
+        OBJECT("Object", 0),
+        BOOLEAN("boolean", 1),
+        CHAR("char", 2),
+        FLOAT("float", 4),
+        DOUBLE("double", 8),
+        BYTE("byte", 1),
+        SHORT("short", 2),
+        INT("int", 4),
+        LONG("long", 8);
+
+        public final String name;
+        private final int size;
+
+        int size(int refSize) {
+            return (size == 0) ? refSize : size;
+        }
+
+        Type(String name, int size) {
+            this.name = name;
+            this.size = size;
+        }
+
+        @Override
+        public String toString() {
+            return name;
+        }
+    }
+
+    static Type[] TYPES = new Type[] {
+        null, null, Type.OBJECT, null, Type.BOOLEAN, Type.CHAR, Type.FLOAT, Type.DOUBLE,
+        Type.BYTE, Type.SHORT, Type.INT, Type.LONG
+    };
+
+    // Given some irrelevant subtag for HEAP DUMP and HEAP DUMP SEGMENT, skip the appropriate number
+    // of bytes in the buffer. Returns true if the subtag was processed.
+    private static boolean handleIrrelevantSubtags(int subtag, HprofBuffer buf, boolean idSize8,
+            int idSize) {
+        if (subtag == 0x01) { // ROOT JNI GLOBAL
+            long objectId = buf.getId(idSize8);
+            long refId = buf.getId(idSize8);
+        } else if (subtag == 0x02) { // ROOT JNI LOCAL
+            long objectId = buf.getId(idSize8);
+            int threadSerialNumber = buf.getU4();
+            int frameNumber = buf.getU4();
+        } else if (subtag == 0x03) { // ROOT JAVA FRAME
+            long objectId = buf.getId(idSize8);
+            int threadSerialNumber = buf.getU4();
+            int frameNumber = buf.getU4();
+        } else if (subtag == 0x04) { // ROOT NATIVE STACK
+            long objectId = buf.getId(idSize8);
+            int threadSerialNumber = buf.getU4();
+        } else if (subtag == 0x05) { // ROOT STICKY CLASS
+            long objectId = buf.getId(idSize8);
+        } else if (subtag == 0x06) { // ROOT THREAD BLOCK
+            long objectId = buf.getId(idSize8);
+            int threadSerialNumber = buf.getU4();
+        } else if (subtag == 0x07) { // ROOT MONITOR USED
+            long objectId = buf.getId(idSize8);
+        } else if (subtag == 0x08) { // ROOT THREAD OBJECT
+            long objectId = buf.getId(idSize8);
+            int threadSerialNumber = buf.getU4();
+            int stackSerialNumber = buf.getU4();
+        } else if (subtag == 0x89) { // ROOT INTERNED STRING
+            long objectId = buf.getId(idSize8);
+        } else if (subtag == 0x8a) { // ROOT FINALIZING
+            long objectId = buf.getId(idSize8);
+        } else if (subtag == 0x8b) { // ROOT DEBUGGER
+            long objectId = buf.getId(idSize8);
+        } else if (subtag == 0x8d) { // ROOT VM INTERNAL
+            long objectId = buf.getId(idSize8);
+        } else if (subtag == 0x8e) { // ROOT JNI MONITOR
+            long objectId = buf.getId(idSize8);
+            int threadSerialNumber = buf.getU4();
+            int frameNumber = buf.getU4();
+        } else if (subtag == 0xfe) { // HEAP DUMP INFO
+            int type = buf.getU4();
+            long stringId = buf.getId(idSize8);
+        } else if (subtag == 0xff) { // ROOT UNKNOWN
+            long objectId = buf.getId(idSize8);
+        } else {
+            return false;
+        }
+        return true;
+    }
+
+    // Given some subtag, skip the appropriate number of bytes in the buffer if the subtag isn't
+    // relevant for the current pass. Returns true if the subtag was processed.
+    private static boolean handlePossiblyRelevantSubtags(int subtag, HprofBuffer buf,
+            boolean idSize8, int idSize, boolean firstPass) {
+        if (firstPass && subtag == 0x21) { // INSTANCE DUMP
+            long objectId = buf.getId(idSize8);
+            int stackSerialNumber = buf.getU4();
+            long classId = buf.getId(idSize8);
+            int numBytes = buf.getU4();
+            buf.skip(numBytes);
+        } else if (firstPass && subtag == 0x22) { // OBJECT ARRAY DUMP
+            long objectId = buf.getId(idSize8);
+            int stackSerialNumber = buf.getU4();
+            int length = buf.getU4();
+            long classId = buf.getId(idSize8);
+            buf.skip(length * idSize);
+        } else if (firstPass && subtag == 0x23) { // PRIMITIVE ARRAY DUMP
+            long objectId = buf.getId(idSize8);
+            int stackSerialNumber = buf.getU4();
+            int length = buf.getU4();
+            Type type = buf.getType();
+            buf.skip(length * type.size(idSize));
+        } else if (!firstPass && subtag == 0x20) { // CLASS DUMP
+            long objectId = buf.getId(idSize8);
+            int stackSerialNumber = buf.getU4();
+            long superClassId = buf.getId(idSize8);
+            long classLoaderId = buf.getId(idSize8);
+            long signersId = buf.getId(idSize8);
+            long protectionId = buf.getId(idSize8);
+            long reserved1 = buf.getId(idSize8);
+            long reserved2 = buf.getId(idSize8);
+            int instanceSize = buf.getU4();
+
+            int constantPoolSize = buf.getU2();
+            for (int i = 0; i < constantPoolSize; i++) {
+                int index = buf.getU2();
+                Type type = buf.getType();
+                buf.skip(type.size(idSize));
+            }
+
+            int numStaticFields = buf.getU2();
+            for (int i = 0; i < numStaticFields; i++) {
+                long nameId = buf.getId(idSize8);
+                Type type = buf.getType();
+                buf.skip(type.size(idSize));
+            }
+
+            int numInstanceFields = buf.getU2();
+            for (int i = 0; i < numInstanceFields; i++) {
+                long nameId = buf.getId(idSize8);
+                Type type = buf.getType();
+            }
+        } else {
+            return false;
+        }
+        return true;
+    }
+
+    // Convenience class for representing the names and types of android.graphics.Bitmap and
+    // android.graphics.Bitmap$DumpData instance fields.
+    private static class Field {
+        String name;
+        Type type;
+        Field(String name, Type type) {
+            this.name = name;
+            this.type = type;
+        }
+    }
+
+    // Given some instance field, skip the appropriate number of bytes. android.graphics.Bitmap and
+    // android.graphics.Bitmap$DumpData are only expected to have ints, longs, and booleans as
+    // irrelevant fields.
+    private static void handleIrrelevantField(Field field, HprofBuffer buf, boolean idSize8) {
+        switch (field.type) {
+            case Type.INT: {
+                buf.getInt();
+                break;
+            }
+            case Type.LONG: {
+                buf.getLong();
+                break;
+            }
+            case Type.BOOLEAN: {
+                buf.getBool();
+                break;
+            }
+            case Type.OBJECT: {
+                buf.getId(idSize8);
+                break;
+            }
+            default:
+                Log.e(TAG, String.format("Instance field %s is of unexpected type %s", field.name,
+                        field.type));
+        }
+    }
+
+    // Convenience class for storing bitmap dimensions.
+    private static class Dimensions {
+        int width;
+        int height;
+        Dimensions(int width, int height) {
+            this.width = width;
+            this.height = height;
+        }
+    }
+
+    private static final Set<String> RELEVANT_STRINGS = new HashSet<>(Arrays.asList(
+            new String[]{
+                BITMAP_CLASSNAME, DUMPDATA_CLASSNAME,
+                "buffers", "natives", "sizes",
+                "mHeight", "mWidth", "mNativePtr"}));
+    private static boolean isRelevantString(String string) {
+        return string != null && RELEVANT_STRINGS.contains(string);
+    }
+
+    private static String getOutputDirectory(String date) {
+        return String.format("%s/am-heap-dump-%s", TRACE_DIRECTORY, date);
+    }
+
+}
diff --git a/src/com/android/traceur/HprofBuffer.java b/src/com/android/traceur/HprofBuffer.java
new file mode 100644
index 00000000..c4f55ccc
--- /dev/null
+++ b/src/com/android/traceur/HprofBuffer.java
@@ -0,0 +1,92 @@
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
+ * limitations under the License
+ */
+
+package com.android.traceur;
+
+import static com.android.traceur.DumpHeapUtils.Type;
+
+import java.nio.ByteBuffer;
+
+/**
+ * Utility class for reading a ByteBuffer that represents the contents of a .hprof file.
+ * .hprof files are binary representations of heap dumps.
+ */
+public class HprofBuffer {
+
+    ByteBuffer buf;
+
+    HprofBuffer(ByteBuffer buf) {
+        this.buf = buf;
+    }
+
+    // getU1, U2, and U4 return the next 1, 2, or 4 unsigned bytes.
+    int getU1() {
+        return buf.get() & 0xFF;
+    }
+    int getU2() {
+        return buf.getShort() & 0xFFFF;
+    }
+    int getU4() {
+        return buf.getInt();
+    }
+    long getId(boolean idSize8) {
+        return idSize8 ? getLong() : (getInt() & 0xFFFFFFFFL);
+    }
+    boolean getBool() {
+        return buf.get() != 0;
+    }
+    char getChar() {
+        return buf.getChar();
+    }
+    float getFloat() {
+        return buf.getFloat();
+    }
+    double getDouble() {
+        return buf.getDouble();
+    }
+    byte getByte() {
+        return buf.get();
+    }
+    void getBytes(byte[] bytes) {
+        buf.get(bytes);
+    }
+    short getShort() {
+        return buf.getShort();
+    }
+    int getInt() {
+        return buf.getInt();
+    }
+    long getLong() {
+        return buf.getLong();
+    }
+    Type getType() {
+        int id = getU1();
+        Type type = id < DumpHeapUtils.TYPES.length ? DumpHeapUtils.TYPES[id] : null;
+        return type;
+    }
+    boolean hasRemaining() {
+        return buf.hasRemaining();
+    }
+    int position() {
+        return buf.position();
+    }
+    void seek(int position) {
+        buf.position(position);
+    }
+    void skip(int delta) {
+        seek(buf.position() + delta);
+    }
+}
diff --git a/src/com/android/traceur/MainFragment.java b/src/com/android/traceur/MainFragment.java
index 1686e6e1..0d7164ed 100644
--- a/src/com/android/traceur/MainFragment.java
+++ b/src/com/android/traceur/MainFragment.java
@@ -44,6 +44,7 @@ import androidx.preference.PreferenceManager;
 import androidx.preference.SwitchPreference;
 
 import com.android.settingslib.HelpUtils;
+import com.android.traceur.flags.Flags;
 
 import java.util.ArrayList;
 import java.util.Collections;
@@ -71,6 +72,7 @@ public class MainFragment extends PreferenceFragment {
     private SwitchPreference mTracingOn;
     private SwitchPreference mStackSamplingOn;
     private SwitchPreference mHeapDumpOn;
+    private Preference mAmHeapDumpOn;
 
     private AlertDialog mAlertDialog;
     private SharedPreferences mPrefs;
@@ -106,6 +108,16 @@ public class MainFragment extends PreferenceFragment {
         mHeapDumpOn = (SwitchPreference) findPreference(
                 getActivity().getString(R.string.pref_key_heap_dump_on));
 
+        Preference mAmHeapDumpCategory = findPreference(
+                getActivity().getString(R.string.pref_category_other_tools));
+        if (Flags.bitmapsInTraceur()) {
+            mAmHeapDumpCategory.setVisible(true);
+            mAmHeapDumpOn = findPreference(
+                getActivity().getString(R.string.pref_key_am_heap_dump_on));
+        } else {
+            mAmHeapDumpCategory.setVisible(false);
+        }
+
         mTracingOn.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
             @Override
             public boolean onPreferenceClick(Preference preference) {
@@ -139,6 +151,20 @@ public class MainFragment extends PreferenceFragment {
             }
         });
 
+        if (Flags.bitmapsInTraceur()) {
+            mAmHeapDumpOn.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
+                @Override
+                public boolean onPreferenceClick(Preference preference) {
+                    // We don't have a way of calling back from AM heap dump completion to
+                    // enable/disable other trace collection toggles while a heap dump is in
+                    // progress. However, this might be okay because Perfetto technically can be run
+                    // while an AM heap dump is ongoing.
+                    Receiver.captureAmHeapDump(getContext());
+                    return true;
+                }
+            });
+        }
+
         mHeapDumpProcesses = (MultiSelectListPreference) findPreference(
                 getContext().getString(R.string.pref_key_heap_dump_processes));
 
@@ -394,13 +420,26 @@ public class MainFragment extends PreferenceFragment {
         mStackSamplingOn.setEnabled(!(mTracingOn.isChecked() || mHeapDumpOn.isChecked()));
 
         // Disallow heap dumps if no process is selected, or if tracing/stack sampling is active.
-        boolean heapDumpProcessSelected = mHeapDumpProcesses.getValues().size() > 0;
+        int heapDumpProcessCount = mHeapDumpProcesses.getValues().size();
+        boolean heapDumpProcessSelected = heapDumpProcessCount > 0;
         mHeapDumpOn.setEnabled(heapDumpProcessSelected &&
                 !(mTracingOn.isChecked() || mStackSamplingOn.isChecked()));
         mHeapDumpOn.setSummary(heapDumpProcessSelected
                 ? context.getString(R.string.record_heap_dump_summary_enabled)
                 : context.getString(R.string.record_heap_dump_summary_disabled));
 
+        if (Flags.bitmapsInTraceur()) {
+            boolean amHeapDumpProcessAvailable = heapDumpProcessCount == 1;
+            mAmHeapDumpOn.setEnabled(amHeapDumpProcessAvailable);
+            mAmHeapDumpOn.setSummary(amHeapDumpProcessAvailable
+                ? context.getString(R.string.record_am_heap_dump_summary_enabled)
+                : (heapDumpProcessCount > 1)
+                    ? context.getString(
+                        R.string.record_am_heap_dump_summary_disabled_multiple_procs_selected)
+                    : context.getString(
+                        R.string.record_am_heap_dump_summary_disabled_no_procs_selected));
+        }
+
         // Update subtitles on this screen.
         Set<String> categories = mTags.getValues();
         MessageFormat msgFormat = new MessageFormat(
diff --git a/src/com/android/traceur/Receiver.java b/src/com/android/traceur/Receiver.java
index 936848e9..ba43b19b 100644
--- a/src/com/android/traceur/Receiver.java
+++ b/src/com/android/traceur/Receiver.java
@@ -193,6 +193,10 @@ public class Receiver extends BroadcastReceiver {
         TraceService.updateAllQuickSettingsTiles();
     }
 
+    public static void captureAmHeapDump(Context context) {
+        TraceService.startAmHeapDump(context);
+    }
+
     /*
      * Updates the input Quick Settings tile state based on the current state of preferences.
      */
diff --git a/src/com/android/traceur/StorageProvider.java b/src/com/android/traceur/StorageProvider.java
index c64113f0..ee1d4f09 100644
--- a/src/com/android/traceur/StorageProvider.java
+++ b/src/com/android/traceur/StorageProvider.java
@@ -44,7 +44,8 @@ public class StorageProvider extends FileSystemProvider{
 
     private static final String DOC_ID_ROOT = "traces";
     private static final String ROOT_DIR = "/data/local/traces";
-    private static final String MIME_TYPE = "application/vnd.android.systrace";
+    private static final String MIME_TYPE_TRACE = "application/vnd.android.systrace";
+    private static final String MIME_TYPE_IMAGE_PNG = "image/png";
 
     private static final String[] DEFAULT_ROOT_PROJECTION = new String[] {
             Root.COLUMN_ROOT_ID,
@@ -76,16 +77,20 @@ public class StorageProvider extends FileSystemProvider{
         if (!Receiver.isTraceurAllowed(getContext())) {
             return null;
         }
+        includeRootWithMimeType(result, MIME_TYPE_TRACE);
+        includeRootWithMimeType(result, MIME_TYPE_IMAGE_PNG);
+        return result;
+    }
 
+    private void includeRootWithMimeType(MatrixCursor result, String mimeType) {
         final MatrixCursor.RowBuilder row = result.newRow();
         row.add(Root.COLUMN_ROOT_ID, DOC_ID_ROOT);
         row.add(Root.COLUMN_FLAGS, Root.FLAG_LOCAL_ONLY);
-        row.add(Root.COLUMN_MIME_TYPES, MIME_TYPE);
+        row.add(Root.COLUMN_MIME_TYPES, mimeType);
         row.add(Root.COLUMN_ICON, R.drawable.bugfood_icon_green);
         row.add(Root.COLUMN_TITLE,
             getContext().getString(R.string.system_traces_storage_title));
         row.add(Root.COLUMN_DOCUMENT_ID, DOC_ID_ROOT);
-        return result;
     }
 
     @Override
@@ -101,7 +106,9 @@ public class StorageProvider extends FileSystemProvider{
             mimeType = Document.MIME_TYPE_DIR;
         } else {
             file = getFileForDocId(documentId);
-            mimeType = MIME_TYPE;
+            mimeType = documentId.endsWith(".png")
+                    ? MIME_TYPE_IMAGE_PNG
+                    : MIME_TYPE_TRACE;
         }
 
         row.add(Document.COLUMN_DOCUMENT_ID, documentId);
@@ -156,7 +163,7 @@ public class StorageProvider extends FileSystemProvider{
 
     @Override
     protected String getDocIdForFile(File file) {
-        return DOC_ID_ROOT + ":" + file.getName();
+        return DOC_ID_ROOT + ":" + file.toString();
     }
 
     @Override
@@ -167,11 +174,10 @@ public class StorageProvider extends FileSystemProvider{
         } else {
             final int splitIndex = documentId.indexOf(':', 1);
             final String name = documentId.substring(splitIndex + 1);
-            if (splitIndex == -1 || !DOC_ID_ROOT.equals(documentId.substring(0, splitIndex)) ||
-                    !FileUtils.isValidExtFilename(name)) {
+            if (splitIndex == -1 || !DOC_ID_ROOT.equals(documentId.substring(0, splitIndex))) {
                 throw new FileNotFoundException("Invalid document ID: " + documentId);
             }
-            final File file = new File(ROOT_DIR, name);
+            final File file = new File(name);
             if (!file.exists()) {
                 throw new FileNotFoundException("File not found: " + documentId);
             }
diff --git a/src/com/android/traceur/TraceService.java b/src/com/android/traceur/TraceService.java
index 7e5d49e4..963d462f 100644
--- a/src/com/android/traceur/TraceService.java
+++ b/src/com/android/traceur/TraceService.java
@@ -29,6 +29,7 @@ import android.content.SharedPreferences;
 import android.content.pm.PackageManager;
 import android.net.Uri;
 import android.preference.PreferenceManager;
+import android.util.Log;
 
 import java.io.File;
 import java.util.ArrayList;
@@ -39,6 +40,7 @@ import java.util.Set;
 import java.util.Optional;
 
 public class TraceService extends IntentService {
+    static final String TAG = "Traceur";
     // Authority used to share trace files from Traceur to other apps
     static final String AUTHORITY = "com.android.traceur.files";
     /* Indicates Perfetto has stopped tracing due to either the supplied long trace limitations
@@ -51,6 +53,8 @@ public class TraceService extends IntentService {
             "com.android.traceur.START_STACK_SAMPLING";
     private static String INTENT_ACTION_START_HEAP_DUMP =
             "com.android.traceur.START_HEAP_DUMP";
+    private static String INTENT_ACTION_START_AM_HEAP_DUMP =
+            "com.android.traceur.START_AM_HEAP_DUMP";
 
     private static String INTENT_EXTRA_TAGS= "tags";
     private static String INTENT_EXTRA_BUFFER = "buffer";
@@ -92,6 +96,12 @@ public class TraceService extends IntentService {
         context.startForegroundService(intent);
     }
 
+    public static void startAmHeapDump(final Context context) {
+        Intent intent = new Intent(context, TraceService.class);
+        intent.setAction(INTENT_ACTION_START_AM_HEAP_DUMP);
+        context.startForegroundService(intent);
+    }
+
     public static void stopTracing(final Context context) {
         Intent intent = new Intent(context, TraceService.class);
         intent.setAction(INTENT_ACTION_STOP_TRACING);
@@ -146,6 +156,8 @@ public class TraceService extends IntentService {
             startStackSamplingInternal();
         } else if (intent.getAction().equals(INTENT_ACTION_START_HEAP_DUMP)) {
             startHeapDumpInternal();
+        } else if (intent.getAction().equals(INTENT_ACTION_START_AM_HEAP_DUMP)) {
+            startAmHeapDumpInternal();
         } else if (intent.getAction().equals(INTENT_ACTION_STOP_TRACING) ||
                 intent.getAction().equals(INTENT_ACTION_NOTIFY_SESSION_STOPPED)) {
             stopTracingInternal(TraceUtils.getOutputFilename(type));
@@ -307,6 +319,32 @@ public class TraceService extends IntentService {
                 context.getString(R.string.pref_key_recording_was_stack_samples), false).commit();
     }
 
+    private void startAmHeapDumpInternal() {
+        Context context = getApplicationContext();
+        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
+
+        Set<String> processes = prefs.getStringSet(
+                context.getString(R.string.pref_key_heap_dump_processes), Collections.emptySet());
+        if (processes.size() != 1) {
+            // This shouldn't happen because the heap dump button is disabled if the number of
+            // processes selected isn't 1, but we exit here just in case.
+            Log.e(TAG, "The number of processes is not 1. No heap dump will be collected.");
+            return;
+        }
+        String process = processes.iterator().next();
+
+        Notification.Builder notification = getTraceurNotification(
+                context.getString(R.string.am_heap_dump_is_being_recorded),
+                null, Receiver.NOTIFICATION_CHANNEL_TRACING);
+
+        startForeground(TRACE_NOTIFICATION, notification.build(),
+                FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
+
+        DumpHeapUtils.dumpHeapWithAM(context, process);
+
+        stopForeground(Service.STOP_FOREGROUND_REMOVE);
+    }
+
     private void stopTracingInternal(String outputFilename) {
         Context context = getApplicationContext();
         SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
diff --git a/src_common/com/android/traceur/TraceUtils.java b/src_common/com/android/traceur/TraceUtils.java
index 5faed9d8..933824f2 100644
--- a/src_common/com/android/traceur/TraceUtils.java
+++ b/src_common/com/android/traceur/TraceUtils.java
@@ -137,10 +137,11 @@ public class TraceUtils {
     }
 
     public static void clearSavedTraces() {
-        String cmd = "rm -f " + TRACE_DIRECTORY + "trace-*.*trace " +
+        String cmd = "rm -rf " + TRACE_DIRECTORY + "trace-*.*trace " +
                 TRACE_DIRECTORY + "recovered-trace*.*trace " +
                 TRACE_DIRECTORY + "stack-samples*.*trace " +
-                TRACE_DIRECTORY + "heap-dump*.*trace";
+                TRACE_DIRECTORY + "heap-dump*.*trace " +
+                TRACE_DIRECTORY + "am-heap-dump-*";
 
         Log.v(TAG, "Clearing trace directory: " + cmd);
         try {
```

